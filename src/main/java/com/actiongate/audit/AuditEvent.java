package com.actiongate.audit;

import java.time.Instant;

/** One persisted, hash-chained audit record. */
public record AuditEvent(
        long seq,
        String eventId,
        Instant timestamp,
        String eventType,
        String agentId,
        String command,
        String workingDir,
        String riskLevel,
        String matchedRules,
        String decision,
        String approvalStatus,
        String biometricResult,
        String executionResult,
        String prevHash,
        String hash) {}
