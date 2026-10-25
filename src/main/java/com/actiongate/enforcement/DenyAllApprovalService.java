package com.actiongate.enforcement;

/** Headless default: nobody can approve, so every operation needing approval is denied. */
public final class DenyAllApprovalService implements ApprovalService {
    @Override
    public ApprovalResult requestApproval(ApprovalRequest request) {
        return ApprovalResult.denied();
    }
}
