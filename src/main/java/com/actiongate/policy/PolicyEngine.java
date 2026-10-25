package com.actiongate.policy;

import com.actiongate.model.CommandRequest;
import com.actiongate.model.MatchedRule;
import com.actiongate.model.RiskAssessment;
import com.actiongate.model.RiskLevel;
import com.actiongate.risk.PathUtil;
import java.util.ArrayList;
import java.util.List;

/** Applies the {@link SecurityPolicy} to a risk assessment. Pure function, no side effects. */
public final class PolicyEngine {

    public PolicyDecision decide(CommandRequest request, RiskAssessment assessment, SecurityPolicy policy) {
        List<String> reasons = new ArrayList<>();

        AgentSettings agent = policy.agent(request.agentId());
        if (!agent.enabled()) {
            reasons.add("Agent '" + request.agentId() + "' is not enabled in the integration settings");
            return new PolicyDecision(PolicyDecision.Outcome.DENY, false, false, reasons);
        }

        if (!policy.allowedWorkingDirectories().isEmpty()) {
            String home = PathUtil.homeDir();
            String cwd = PathUtil.normalize(request.workingDirectory(), "/", home);
            boolean inside = false;
            for (String allowed : policy.allowedWorkingDirectories()) {
                if (PathUtil.isInside(cwd, PathUtil.normalize(allowed, "/", home))) { inside = true; break; }
            }
            if (!inside) {
                reasons.add("Working directory is outside the allowed working directories");
                return new PolicyDecision(PolicyDecision.Outcome.DENY, false, false, reasons);
            }
        }

        for (MatchedRule r : assessment.matchedRules()) {
            if (r.level().atLeast(RiskLevel.HIGH) && policy.blockedCategories().contains(r.category())) {
                reasons.add("Blocked category " + r.category() + " (" + r.id() + ")");
            }
        }
        if (!reasons.isEmpty()) {
            return new PolicyDecision(PolicyDecision.Outcome.DENY, false, false, reasons);
        }

        LevelRule lr = policy.levelRule(assessment.level());
        if (lr.block()) {
            reasons.add(assessment.level() + " risk commands are blocked by policy");
            return new PolicyDecision(PolicyDecision.Outcome.DENY, false, false, reasons);
        }
        if (lr.approval() || lr.biometric()) {
            if (lr.approval()) reasons.add(assessment.level() + " risk requires explicit approval");
            if (lr.biometric()) reasons.add(assessment.level() + " risk requires Windows Hello verification");
            return new PolicyDecision(PolicyDecision.Outcome.REQUIRE_APPROVAL, true, lr.biometric(), reasons);
        }
        reasons.add(assessment.level() + " risk is allowed by policy");
        return new PolicyDecision(PolicyDecision.Outcome.ALLOW, false, false, reasons);
    }
}
