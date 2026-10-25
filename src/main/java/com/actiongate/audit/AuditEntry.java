package com.actiongate.audit;

/** Data supplied by callers when appending an audit event (hashes and ids are added by the log). */
public record AuditEntry(
        String eventType,
        String agentId,
        String command,
        String workingDir,
        String riskLevel,
        String matchedRules,
        String decision,
        String approvalStatus,
        String biometricResult,
        String executionResult) {

    public static AuditEntry system(String type, String detail) {
        return new AuditEntry(type, "actiongate", detail, "-", "-", "-", "RECORDED", "-", "-", "-");
    }
}
