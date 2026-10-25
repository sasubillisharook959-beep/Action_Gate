package com.actiongate.enforcement;

/** Obtains an explicit user decision for one operation. Must block until decided or timed out. */
public interface ApprovalService {
    ApprovalResult requestApproval(ApprovalRequest request);
}
