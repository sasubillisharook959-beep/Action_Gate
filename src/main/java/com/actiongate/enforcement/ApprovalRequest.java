package com.actiongate.enforcement;

import com.actiongate.model.CommandRequest;
import com.actiongate.model.RiskAssessment;
import com.actiongate.policy.PolicyDecision;

public record ApprovalRequest(CommandRequest request, RiskAssessment assessment, PolicyDecision policy, String digest,
                              boolean biometricRequired, int timeoutSeconds) {}
