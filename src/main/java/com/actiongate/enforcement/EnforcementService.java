package com.actiongate.enforcement;

import com.actiongate.audit.AuditEntry;
import com.actiongate.audit.AuditLog;
import com.actiongate.authentication.AuthResult;
import com.actiongate.authentication.AuthStatus;
import com.actiongate.authentication.AuthenticationProvider;
import com.actiongate.authentication.Availability;
import com.actiongate.model.ApprovalStatus;
import com.actiongate.model.CommandRequest;
import com.actiongate.model.EnforcementDecision;
import com.actiongate.model.EnforcementDecision.Verdict;
import com.actiongate.model.MatchedRule;
import com.actiongate.model.RiskAssessment;
import com.actiongate.model.RiskLevel;
import com.actiongate.policy.BiometricUnavailableBehavior;
import com.actiongate.policy.PolicyDecision;
import com.actiongate.policy.PolicyEngine;
import com.actiongate.policy.PolicyHolder;
import com.actiongate.policy.SecurityPolicy;
import com.actiongate.risk.RiskEngine;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * Pre-execution enforcement: analyse -> apply policy -> approval / Windows Hello -> decision -> audit.
 * Every failure path (exceptions, audit failure, missing approval service output, mock auth in production) denies.
 */
public final class EnforcementService {
    private record Entry(String digest, CompletableFuture<EnforcementDecision> future, Instant at) {}

    private final PolicyHolder policyHolder;
    private final RiskEngine riskEngine;
    private final PolicyEngine policyEngine;
    private final ApprovalService approvalService;
    private final AuthenticationProvider auth;
    private final AuditLog audit;
    private final Clock clock;
    private final Map<String, Entry> seen = new ConcurrentHashMap<>();
    private final List<Consumer<EnforcementDecision>> listeners = new CopyOnWriteArrayList<>();
    private final List<Consumer<CommandRequest>> requestListeners = new CopyOnWriteArrayList<>();

    public EnforcementService(PolicyHolder policyHolder, RiskEngine riskEngine, PolicyEngine policyEngine,
                              ApprovalService approvalService, AuthenticationProvider auth, AuditLog audit,
                              Clock clock, boolean allowMockAuthentication) {
        if (auth.isMock() && !allowMockAuthentication)
            throw new IllegalStateException("Mock authentication providers are not permitted in production mode");
        this.policyHolder = policyHolder;
        this.riskEngine = riskEngine;
        this.policyEngine = policyEngine;
        this.approvalService = approvalService;
        this.auth = auth;
        this.audit = audit;
        this.clock = clock;
    }

    public void addListener(Consumer<EnforcementDecision> l) { listeners.add(l); }
    public void addRequestListener(Consumer<CommandRequest> l) { requestListeners.add(l); }
    public AuthenticationProvider authenticationProvider() { return auth; }

    /** Evaluates a request. Idempotent per requestId; reusing an id with different content is denied. */
    public EnforcementDecision evaluate(CommandRequest request) {
        String digest = CommandDigest.of(request);
        CompletableFuture<EnforcementDecision> mine = new CompletableFuture<>();
        Entry prev = seen.putIfAbsent(request.requestId(), new Entry(digest, mine, clock.instant()));
        if (prev != null) {
            if (!prev.digest().equals(digest)) {
                return failClosed(request, digest, "Request id reused with different content", ApprovalStatus.NOT_REQUESTED, true);
            }
            try {
                return prev.future().get(15, TimeUnit.MINUTES);
            } catch (Exception e) {
                if (e instanceof InterruptedException) Thread.currentThread().interrupt();
                return failClosed(request, digest, "Duplicate request could not be resolved", ApprovalStatus.ERROR, true);
            }
        }
        EnforcementDecision decision;
        try {
            for (Consumer<CommandRequest> l : requestListeners) safe(() -> l.accept(request));
            decision = doEvaluate(request, digest);
        } catch (Throwable t) {
            decision = failClosed(request, digest, "Internal error during enforcement; denied (fail closed)", ApprovalStatus.ERROR, true);
        }
        mine.complete(decision);
        prune();
        EnforcementDecision fin = decision;
        for (Consumer<EnforcementDecision> l : listeners) safe(() -> l.accept(fin));
        return decision;
    }

    /**
     * Evaluates and, only for an ALLOW decision whose authorization is valid, releases the operation to the boundary.
     */
    public EnforcementDecision process(CommandRequest request, ExecutionBoundary boundary) {
        EnforcementDecision d = evaluate(request);
        if (!d.allowed()) return d;
        return release(request, d, boundary);
    }

    public EnforcementDecision release(CommandRequest request, EnforcementDecision d, ExecutionBoundary boundary) {
        AuthorizedOperation op = d.authorization();
        if (!d.allowed() || op == null || !op.consume(CommandDigest.of(request), clock.instant())) {
            recordQuietly(request, d.assessment(), "RELEASE_REFUSED", "DENY", d.approvalStatus(), d.biometricResult(), "WITHHELD");
            return new EnforcementDecision(request.requestId(), Verdict.DENY,
                    "Authorization is missing, expired, already used, or does not match this exact operation",
                    d.assessment(), d.approvalStatus(), d.biometricResult(), CommandDigest.of(request), null);
        }
        boundary.release(request, op);
        return d;
    }

    private EnforcementDecision doEvaluate(CommandRequest request, String digest) throws Exception {
        SecurityPolicy policy = policyHolder.get();
        RiskAssessment assessment = riskEngine.analyze(request, policy);
        PolicyDecision pd = policyEngine.decide(request, assessment, policy);
        String reasons = String.join("; ", pd.reasons());

        if (pd.outcome() == PolicyDecision.Outcome.DENY) {
            return finish(request, digest, assessment, Verdict.DENY, reasons + ". " + assessment.explanation(),
                    ApprovalStatus.NOT_REQUESTED, AuthResult.notRequired(), policy);
        }

        ApprovalStatus approval = ApprovalStatus.NOT_REQUIRED;
        AuthResult bio = AuthResult.notRequired();

        if (pd.outcome() == PolicyDecision.Outcome.REQUIRE_APPROVAL) {
            ApprovalResult res;
            try {
                res = approvalService.requestApproval(new ApprovalRequest(request, assessment, pd, digest,
                        pd.biometricRequired(), policy.approvalTimeoutSeconds()));
            } catch (RuntimeException e) {
                res = new ApprovalResult(ApprovalStatus.ERROR, null);
            }
            if (res == null) res = new ApprovalResult(ApprovalStatus.ERROR, null);
            if (res.status() != ApprovalStatus.APPROVED) {
                return finish(request, digest, assessment, Verdict.DENY, "Not approved (" + res.status() + ")",
                        res.status(), bio, policy);
            }
            // TOCTOU guard: the approval must be for exactly this operation
            if (!digest.equals(res.approvedDigest()) || !digest.equals(CommandDigest.of(request))) {
                return finish(request, digest, assessment, Verdict.DENY, "Approval does not match the operation (changed after approval)",
                        ApprovalStatus.DIGEST_MISMATCH, bio, policy);
            }
            approval = ApprovalStatus.APPROVED;

            if (pd.biometricRequired()) {
                Availability av = auth.checkAvailability();
                if (av != Availability.AVAILABLE) {
                    bio = new AuthResult(AuthStatus.UNAVAILABLE, "Windows Hello unavailable: " + av);
                    if (policy.biometricUnavailable() != BiometricUnavailableBehavior.FALLBACK_TO_APPROVAL) {
                        return finish(request, digest, assessment, Verdict.DENY,
                                "Windows Hello verification is required but unavailable (" + av + "); denied (fail closed)", approval, bio, policy);
                    }
                } else {
                    String prompt = "ActionGate " + assessment.level() + " risk operation " + digest.substring(0, 8);
                    try {
                        bio = auth.authenticate(prompt);
                    } catch (RuntimeException e) {
                        bio = new AuthResult(AuthStatus.ERROR, "authentication provider failed");
                    }
                    if (bio == null || !bio.success()) {
                        return finish(request, digest, assessment, Verdict.DENY,
                                "Windows Hello verification did not succeed (" + (bio == null ? "ERROR" : bio.status()) + ")",
                                approval, bio == null ? new AuthResult(AuthStatus.ERROR, "") : bio, policy);
                    }
                }
                if (!digest.equals(CommandDigest.of(request)))
                    return finish(request, digest, assessment, Verdict.DENY, "Operation changed during verification",
                            ApprovalStatus.DIGEST_MISMATCH, bio, policy);
            }
        }
        return finish(request, digest, assessment, Verdict.ALLOW, reasons, approval, bio, policy);
    }

    private EnforcementDecision finish(CommandRequest request, String digest, RiskAssessment assessment, Verdict verdict,
                                       String reason, ApprovalStatus approval, AuthResult bio, SecurityPolicy policy) {
        String rules = assessment.matchedRules().stream().filter(r -> r.level() != RiskLevel.LOW)
                .map(MatchedRule::id).collect(Collectors.joining(","));
        try {
            audit.append(new AuditEntry("COMMAND_DECISION", request.agentId(), request.command(), request.workingDirectory(),
                    assessment.level().name(), rules, verdict.name(), approval.name(), String.valueOf(bio),
                    verdict == Verdict.ALLOW ? "PERMITTED_TO_PROCEED" : "WITHHELD"));
        } catch (Exception e) {
            return new EnforcementDecision(request.requestId(), Verdict.DENY, "Audit log unavailable; denied (fail closed)",
                    assessment, approval, bio, digest, null);
        }
        AuthorizedOperation op = null;
        if (verdict == Verdict.ALLOW) {
            op = new AuthorizedOperation(digest, request.requestId(), clock.instant().plusSeconds(policy.approvalValiditySeconds()));
        }
        return new EnforcementDecision(request.requestId(), verdict, reason, assessment, approval, bio, digest, op);
    }

    private EnforcementDecision failClosed(CommandRequest request, String digest, String reason, ApprovalStatus status, boolean log) {
        RiskAssessment a = null;
        try {
            a = riskEngine.analyze(request, policyHolder.get());
        } catch (RuntimeException ignored) {
            // fall through
        }
        if (log) recordQuietly(request, a, "COMMAND_DECISION", "DENY", status, AuthResult.notRequired(), "WITHHELD");
        return new EnforcementDecision(request.requestId(), Verdict.DENY, reason, a, status, AuthResult.notRequired(), digest, null);
    }

    private void recordQuietly(CommandRequest r, RiskAssessment a, String type, String decision, ApprovalStatus ap, AuthResult bio, String exec) {
        try {
            audit.append(new AuditEntry(type, r.agentId(), r.command(), r.workingDirectory(),
                    a == null ? "UNKNOWN" : a.level().name(), a == null ? "" : a.matchedRules().stream().map(MatchedRule::id).collect(Collectors.joining(",")),
                    decision, ap == null ? "-" : ap.name(), String.valueOf(bio), exec));
        } catch (Exception ignored) {
            // audit failure on an already-denied path cannot make things less safe
        }
    }

    private void prune() {
        if (seen.size() < 2000) return;
        Instant cutoff = clock.instant().minusSeconds(900);
        seen.entrySet().removeIf(e -> e.getValue().future().isDone() && e.getValue().at().isBefore(cutoff));
    }

    private static void safe(Runnable r) {
        try {
            r.run();
        } catch (RuntimeException ignored) {
            // a faulty UI listener must never affect enforcement
        }
    }
}
