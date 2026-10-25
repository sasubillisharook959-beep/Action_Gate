package com.actiongate.enforcement;

import com.actiongate.model.ApprovalStatus;

/** @param approvedDigest the digest the user actually saw and approved (compared against the live request) */
public record ApprovalResult(ApprovalStatus status, String approvedDigest) {
    public static ApprovalResult approved(String digest) { return new ApprovalResult(ApprovalStatus.APPROVED, digest); }
    public static ApprovalResult denied() { return new ApprovalResult(ApprovalStatus.DENIED_BY_USER, null); }
    public static ApprovalResult timedOut() { return new ApprovalResult(ApprovalStatus.TIMED_OUT, null); }
}
