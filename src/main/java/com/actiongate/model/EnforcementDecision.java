package com.actiongate.model;

import com.actiongate.authentication.AuthResult;
import com.actiongate.enforcement.AuthorizedOperation;
import java.util.Optional;

/** Final outcome of evaluating one request. Only an ALLOW decision carries an {@link AuthorizedOperation}. */
public record EnforcementDecision(
        String requestId,
        Verdict verdict,
        String reason,
        RiskAssessment assessment,
        ApprovalStatus approvalStatus,
        AuthResult biometricResult,
        String digest,
        AuthorizedOperation authorization) {

    public enum Verdict { ALLOW, DENY }

    public boolean allowed() {
        return verdict == Verdict.ALLOW;
    }

    public Optional<AuthorizedOperation> authorizationOpt() {
        return Optional.ofNullable(authorization);
    }
}
