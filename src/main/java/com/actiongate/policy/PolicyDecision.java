package com.actiongate.policy;

import java.util.List;

/** Policy outcome for one assessed request. */
public record PolicyDecision(Outcome outcome, boolean approvalRequired, boolean biometricRequired, List<String> reasons) {
    public enum Outcome { ALLOW, DENY, REQUIRE_APPROVAL }

    public PolicyDecision {
        reasons = List.copyOf(reasons);
    }
}
