package com.actiongate.model;

import java.util.List;

/** Structured result of command risk analysis. */
public record RiskAssessment(
        RiskLevel level,
        String explanation,
        List<MatchedRule> matchedRules,
        RecommendedAction recommendedAction,
        boolean approvalRequired,
        boolean biometricRequired,
        boolean ambiguous) {

    public RiskAssessment {
        matchedRules = List.copyOf(matchedRules);
    }
}
