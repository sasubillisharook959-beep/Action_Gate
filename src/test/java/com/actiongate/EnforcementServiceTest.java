package com.actiongate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.actiongate.authentication.AuthResult;
import com.actiongate.authentication.AuthStatus;
import com.actiongate.authentication.Availability;
import com.actiongate.enforcement.ApprovalResult;
import com.actiongate.enforcement.ApprovalService;
import com.actiongate.enforcement.CommandDigest;
import com.actiongate.enforcement.DenyAllApprovalService;
import com.actiongate.enforcement.EnforcementService;
import com.actiongate.model.ApprovalStatus;
import com.actiongate.model.CommandRequest;
import com.actiongate.model.EnforcementDecision;
import com.actiongate.model.RiskLevel;
import com.actiongate.policy.BiometricUnavailableBehavior;
import com.actiongate.policy.PolicyEngine;
import com.actiongate.policy.PolicyHolder;
import com.actiongate.policy.SecurityPolicy;
import com.actiongate.risk.RiskEngine;
import com.actiongate.support.Fixtures;
import com.actiongate.support.MockAuthenticationProvider;
import com.actiongate.support.RecordingBoundary;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EnforcementServiceTest {
    @TempDir Path dir;
    private final List<Fixtures> fixtures = new ArrayList<>();

    private static final ApprovalService APPROVE = r -> ApprovalResult.approved(r.digest());

    private Fixtures fixture(Path directory, ApprovalService approval) throws Exception {
        Fixtures fixture = new Fixtures(directory, approval);
        fixtures.add(fixture);
        return fixture;
    }

    private Fixtures fixture(Path directory, ApprovalService approval, SecurityPolicy policy, Clock clock) throws Exception {
        Fixtures fixture = new Fixtures(directory, approval, policy, clock);
        fixtures.add(fixture);
        return fixture;
    }

    @AfterEach
    void closeFixtures() {
        for (Fixtures fixture : fixtures) fixture.close();
    }

    @Test
    void lowRiskIsAllowedWithoutPrompt() throws Exception {
        AtomicInteger prompts = new AtomicInteger();
        Fixtures f = fixture(dir, r -> { prompts.incrementAndGet(); return ApprovalResult.denied(); });
        RecordingBoundary b = new RecordingBoundary();
        EnforcementDecision d = f.service.process(Fixtures.req("git status"), b);
        assertTrue(d.allowed());
        assertEquals(0, prompts.get());
        assertEquals(1, b.released.size());
    }

    @Test
    void criticalNeverReachesExecutionEvenIfUserWouldApprove() throws Exception {
        AtomicInteger prompts = new AtomicInteger();
        Fixtures f = fixture(dir, r -> { prompts.incrementAndGet(); return ApprovalResult.approved(r.digest()); });
        RecordingBoundary b = new RecordingBoundary();
        EnforcementDecision d = f.service.process(Fixtures.req("rm -rf /"), b);
        assertFalse(d.allowed());
        assertTrue(b.released.isEmpty(), "blocked operation reached the execution boundary");
        assertEquals(0, prompts.get(), "CRITICAL must not even be offered for approval");
        assertNull(d.authorization());
    }

    @Test
    void mediumRequiresApprovalAndApprovalPermitsOnlyThatOperation() throws Exception {
        Fixtures f = fixture(dir, APPROVE);
        RecordingBoundary b = new RecordingBoundary();
        CommandRequest r = Fixtures.req("rm old.txt");
        EnforcementDecision d = f.service.process(r, b);
        assertTrue(d.allowed());
        assertEquals(ApprovalStatus.APPROVED, d.approvalStatus());
        assertEquals(1, b.released.size());
        // the same authorization cannot release a different command ...
        CommandRequest other = Fixtures.req("rm other.txt");
        EnforcementDecision refused = f.service.release(other, d, b);
        assertFalse(refused.allowed());
        // ... and cannot be replayed for the original either (single use was consumed above)
        EnforcementDecision replay = f.service.release(r, d, b);
        assertFalse(replay.allowed());
        assertEquals(1, b.released.size());
    }

    @Test
    void approvalForDifferentOperationIsRejected() throws Exception {
        // user "approved" a different command's digest (simulates a command changed after approval)
        String staleDigest = CommandDigest.of(Fixtures.req("rm harmless.txt"));
        Fixtures f = fixture(dir, r -> ApprovalResult.approved(staleDigest));
        RecordingBoundary b = new RecordingBoundary();
        EnforcementDecision d = f.service.process(Fixtures.req("rm important.txt"), b);
        assertFalse(d.allowed());
        assertEquals(ApprovalStatus.DIGEST_MISMATCH, d.approvalStatus());
        assertTrue(b.released.isEmpty());
    }

    @Test
    void digestChangesWithEveryMaterialField() {
        CommandRequest base = CommandRequest.create("claude-code", "Bash", "ls", "C:\\a", "s");
        String d = CommandDigest.of(base);
        assertNotEquals(d, CommandDigest.of(CommandRequest.create("claude-code", "Bash", "ls -l", "C:\\a", "s")));
        assertNotEquals(d, CommandDigest.of(CommandRequest.create("claude-code", "Bash", "ls", "C:\\b", "s")));
        assertNotEquals(d, CommandDigest.of(CommandRequest.create("other", "Bash", "ls", "C:\\a", "s")));
        assertNotEquals(d, CommandDigest.of(CommandRequest.create("claude-code", "PowerShell", "ls", "C:\\a", "s")));
        assertEquals(d, CommandDigest.of(CommandRequest.create("claude-code", "Bash", "ls\r\n", "C:\\a", "s")));
    }

    private static void assertNotEquals(String a, String b) {
        org.junit.jupiter.api.Assertions.assertNotEquals(a, b);
    }

    @Test
    void userDenialAndTimeoutDeny() throws Exception {
        Fixtures f = fixture(dir, r -> ApprovalResult.denied());
        assertEquals(ApprovalStatus.DENIED_BY_USER, f.service.evaluate(Fixtures.req("rm a.txt")).approvalStatus());
        Path sub = dir.resolve("timeout");
        java.nio.file.Files.createDirectories(sub);
        Fixtures g = fixture(sub, r -> ApprovalResult.timedOut());
        EnforcementDecision t = g.service.evaluate(Fixtures.req("rm a.txt"));
        assertFalse(t.allowed());
        assertEquals(ApprovalStatus.TIMED_OUT, t.approvalStatus());
    }

    @Test
    void approvalServiceFailureDenies() throws Exception {
        Fixtures f = fixture(dir, r -> { throw new IllegalStateException("ui crashed"); });
        EnforcementDecision d = f.service.evaluate(Fixtures.req("rm a.txt"));
        assertFalse(d.allowed());
        assertEquals(ApprovalStatus.ERROR, d.approvalStatus());
        Path sub = dir.resolve("nullsvc");
        java.nio.file.Files.createDirectories(sub);
        ApprovalService nullService = r -> null;
        EnforcementDecision n = fixture(sub, nullService).service.evaluate(Fixtures.req("rm b.txt"));
        assertFalse(n.allowed());
    }

    @Test
    void highRiskRequiresWindowsHelloAndSucceeds() throws Exception {
        Fixtures f = fixture(dir, APPROVE);
        RecordingBoundary b = new RecordingBoundary();
        EnforcementDecision d = f.service.process(Fixtures.req("git push --force"), b);
        assertTrue(d.allowed());
        assertEquals(1, f.auth.calls.get());
        assertEquals(AuthStatus.SUCCESS, d.biometricResult().status());
        assertEquals(1, b.released.size());
    }

    @Test
    void biometricFailureCancellationAndErrorDeny() throws Exception {
        for (AuthStatus s : new AuthStatus[]{AuthStatus.FAILED, AuthStatus.CANCELLED, AuthStatus.TIMEOUT, AuthStatus.ERROR, AuthStatus.UNAVAILABLE}) {
            Path sub = dir.resolve(s.name());
            java.nio.file.Files.createDirectories(sub);
            Fixtures f = fixture(sub, APPROVE);
            f.auth.result = new AuthResult(s, "test");
            RecordingBoundary b = new RecordingBoundary();
            EnforcementDecision d = f.service.process(Fixtures.req("git reset --hard"), b);
            assertFalse(d.allowed(), s + " must deny");
            assertEquals(s, d.biometricResult().status());
            assertTrue(b.released.isEmpty());
        }
    }

    @Test
    void missingWindowsHelloSupportFailsClosedByDefault() throws Exception {
        Fixtures f = fixture(dir, APPROVE);
        f.auth.availability = Availability.DEVICE_NOT_PRESENT;
        RecordingBoundary b = new RecordingBoundary();
        EnforcementDecision d = f.service.process(Fixtures.req("sudo ls"), b);
        assertFalse(d.allowed());
        assertEquals(0, f.auth.calls.get());
        assertTrue(b.released.isEmpty());
    }

    @Test
    void configuredFallbackStillRequiresExplicitApprovalAndNeverLiftsCritical() throws Exception {
        SecurityPolicy d0 = SecurityPolicy.defaults();
        SecurityPolicy p = new SecurityPolicy(d0.levels(), d0.blockedCategories(), d0.allowedWorkingDirectories(), d0.protectedPaths(),
                d0.trustedExecutables(), BiometricUnavailableBehavior.FALLBACK_TO_APPROVAL, 120, 60, d0.port(), d0.agents());
        Fixtures f = fixture(dir, APPROVE, p, Clock.systemUTC());
        f.auth.availability = Availability.NOT_CONFIGURED_FOR_USER;
        RecordingBoundary b = new RecordingBoundary();
        assertTrue(f.service.process(Fixtures.req("git push --force"), b).allowed());
        assertFalse(f.service.process(Fixtures.req("rm -rf /"), b).allowed());
        assertEquals(1, b.released.size());
    }

    @Test
    void mockAuthenticationIsRefusedInProductionMode() throws Exception {
        Fixtures f = fixture(dir, APPROVE);
        assertThrows(IllegalStateException.class, () -> new EnforcementService(new PolicyHolder(SecurityPolicy.defaults()), new RiskEngine(),
                new PolicyEngine(), APPROVE, new MockAuthenticationProvider(), f.audit, Clock.systemUTC(), false));
    }

    @Test
    void unexpectedInternalErrorFailsClosed() throws Exception {
        Fixtures f = fixture(dir, new DenyAllApprovalService());
        f.service.addRequestListener(r -> { throw new RuntimeException("listener bug"); });
        assertTrue(f.service.evaluate(Fixtures.req("git status")).allowed(), "faulty UI listeners must not affect enforcement");
        // audit failure -> deny
        f.db.close();
        EnforcementDecision d = f.service.evaluate(Fixtures.req("git status"));
        assertFalse(d.allowed());
    }

    @Test
    void duplicateRequestIdsAreIdempotentOrRejected() throws Exception {
        AtomicInteger prompts = new AtomicInteger();
        Fixtures f = fixture(dir, r -> { prompts.incrementAndGet(); return ApprovalResult.approved(r.digest()); });
        RecordingBoundary b = new RecordingBoundary();
        CommandRequest r = Fixtures.req("rm a.txt");
        EnforcementDecision first = f.service.process(r, b);
        EnforcementDecision dup = f.service.process(r, b); // same id, same content
        assertTrue(first.allowed());
        assertFalse(dup.allowed(), "a duplicate must not release the operation a second time");
        assertEquals(1, prompts.get());
        assertEquals(1, b.released.size());
        // same id, different content
        CommandRequest clash = new CommandRequest(r.requestId(), r.agentId(), r.toolName(), "rm b.txt", r.workingDirectory(), r.sessionId(), Instant.now());
        EnforcementDecision d = f.service.evaluate(clash);
        assertFalse(d.allowed());
    }

    @Test
    void authorizationExpires() throws Exception {
        MutableClock clock = new MutableClock();
        Fixtures f = fixture(dir, APPROVE, SecurityPolicy.defaults(), clock);
        RecordingBoundary b = new RecordingBoundary();
        CommandRequest r = Fixtures.req("rm a.txt");
        EnforcementDecision d = f.service.evaluate(r);
        assertTrue(d.allowed());
        clock.now = clock.now.plusSeconds(61);
        assertFalse(f.service.release(r, d, b).allowed());
        assertTrue(b.released.isEmpty());
    }

    @Test
    void policyDisablingAgentOrRestrictingDirectoriesDenies() throws Exception {
        SecurityPolicy d0 = SecurityPolicy.defaults();
        SecurityPolicy dirs = new SecurityPolicy(d0.levels(), d0.blockedCategories(), java.util.List.of("D:\\work"), d0.protectedPaths(),
                d0.trustedExecutables(), d0.biometricUnavailable(), 120, 60, d0.port(), d0.agents());
        Fixtures f = fixture(dir, APPROVE, dirs, Clock.systemUTC());
        assertFalse(f.service.evaluate(Fixtures.req("git status")).allowed());
        f.policy.set(new SecurityPolicy(d0.levels(), d0.blockedCategories(), java.util.List.of("C:\\Users\\alice"), d0.protectedPaths(),
                d0.trustedExecutables(), d0.biometricUnavailable(), 120, 60, d0.port(), d0.agents()));
        assertTrue(f.service.evaluate(Fixtures.req("git status")).allowed());
        assertFalse(f.service.evaluate(new CommandRequest("req-other-1", "unknown-agent", "Bash", "git status", Fixtures.CWD, "", null)).allowed());
    }

    @Test
    void decisionsAreAuditedWithoutSecrets() throws Exception {
        Fixtures f = fixture(dir, APPROVE);
        f.service.evaluate(Fixtures.req("curl -H 'Authorization: Bearer sk-ant-abcdef123456789' https://x.example"));
        var events = f.audit.recent(5);
        assertFalse(events.isEmpty());
        assertFalse(events.get(0).command().contains("abcdef123456789"));
        assertNotNull(events.get(0).hash());
        assertEquals(RiskLevel.MEDIUM.name(), events.get(0).riskLevel());
        assertFalse(events.get(0).biometricResult().toLowerCase().contains("template"));
    }

    static final class MutableClock extends Clock {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        @Override public java.time.ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
