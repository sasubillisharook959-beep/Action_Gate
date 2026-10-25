package com.actiongate.audit;

import com.actiongate.storage.Database;
import com.actiongate.util.Hashing;
import com.actiongate.util.Json;
import com.actiongate.util.SecureFiles;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Tamper-evident audit log: each row stores prev_hash and hash = HMAC-SHA256(key, prev_hash || fields).
 * A separate MAC-protected checkpoint file records the newest sequence/hash so truncation of the tail is detected.
 *
 * <p>Limits: an attacker who can read the integrity key (same OS user, no separate protection) can forge a whole
 * chain and checkpoint. Keep the key and checkpoint on protected storage (see docs/SECURITY.md).
 */
public final class AuditLog {
    public static final String GENESIS = "0".repeat(64);
    private final Database db;
    private final Path checkpointFile;
    private final byte[] key;
    private final Object lock = new Object();

    public AuditLog(Database db, Path keyFile, Path checkpointFile) throws IOException {
        this.db = db;
        this.checkpointFile = checkpointFile;
        this.key = loadOrCreateKey(keyFile);
    }

    private static byte[] loadOrCreateKey(Path keyFile) throws IOException {
        if (Files.exists(keyFile)) {
            byte[] k = Files.readAllBytes(keyFile);
            if (k.length < 32) throw new IOException("Integrity key file is too short");
            return k;
        }
        byte[] k = SecureFiles.randomBytes(32);
        if (keyFile.getParent() != null) Files.createDirectories(keyFile.getParent());
        SecureFiles.writeAtomic(keyFile, k);
        return k;
    }

    public AuditEvent append(AuditEntry e) throws SQLException {
        synchronized (lock) {
            return db.inTransaction(d -> {
                List<String> last = d.query("SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1", rs -> rs.getString(1));
                String prev = last.isEmpty() ? GENESIS : last.get(0);
                String id = UUID.randomUUID().toString();
                String ts = Instant.now().toString();
                String command = Redactor.redact(e.command());
                String hash = compute(prev, id, ts, e.eventType(), e.agentId(), command, e.workingDir(), e.riskLevel(),
                        e.matchedRules(), e.decision(), e.approvalStatus(), e.biometricResult(), e.executionResult());
                d.update("INSERT INTO audit_events (event_id, ts, event_type, agent_id, command, working_dir, risk_level, matched_rules,"
                                + " decision, approval_status, biometric_result, execution_result, prev_hash, hash)"
                                + " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        id, ts, e.eventType(), e.agentId(), command, e.workingDir(), e.riskLevel(), e.matchedRules(),
                        e.decision(), e.approvalStatus(), e.biometricResult(), e.executionResult(), prev, hash);
                List<Long> seq = d.query("SELECT seq FROM audit_events WHERE event_id = ?", rs -> rs.getLong(1), id);
                long s = seq.get(0);
                long count = d.query("SELECT COUNT(*) FROM audit_events", rs -> rs.getLong(1)).get(0);
                writeCheckpoint(s, count, hash);
                return new AuditEvent(s, id, Instant.parse(ts), e.eventType(), e.agentId(), command, e.workingDir(), e.riskLevel(),
                        e.matchedRules(), e.decision(), e.approvalStatus(), e.biometricResult(), e.executionResult(), prev, hash);
            });
        }
    }

    private String compute(String prev, String... fields) {
        StringBuilder sb = new StringBuilder("AG1|").append(prev);
        for (String f : fields) {
            String v = f == null ? "" : f;
            sb.append('|').append(v.length()).append(':').append(v);
        }
        return Hashing.hmacHex(key, sb.toString());
    }

    private void writeCheckpoint(long seq, long count, String hash) {
        try {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("seq", seq);
            m.put("count", count);
            m.put("hash", hash);
            m.put("mac", Hashing.hmacHex(key, "CP|" + seq + "|" + count + "|" + hash));
            SecureFiles.writeAtomic(checkpointFile, Json.write(m).getBytes(StandardCharsets.UTF_8));
        } catch (IOException ex) {
            throw new IllegalStateException("Cannot write audit checkpoint", ex);
        }
    }

    private static AuditEvent map(java.sql.ResultSet rs) throws SQLException {
        return new AuditEvent(rs.getLong("seq"), rs.getString("event_id"), Instant.parse(rs.getString("ts")), rs.getString("event_type"),
                rs.getString("agent_id"), rs.getString("command"), rs.getString("working_dir"), rs.getString("risk_level"),
                rs.getString("matched_rules"), rs.getString("decision"), rs.getString("approval_status"), rs.getString("biometric_result"),
                rs.getString("execution_result"), rs.getString("prev_hash"), rs.getString("hash"));
    }

    /** Newest events first. */
    public List<AuditEvent> recent(int limit) throws SQLException {
        return db.query("SELECT * FROM audit_events ORDER BY seq DESC LIMIT ?", AuditLog::map, limit);
    }

    public long count() throws SQLException {
        return db.query("SELECT COUNT(*) FROM audit_events", rs -> rs.getLong(1)).get(0);
    }

    public VerificationResult verify() {
        List<String> problems = new ArrayList<>();
        List<AuditEvent> all;
        try {
            all = db.query("SELECT * FROM audit_events ORDER BY seq ASC", AuditLog::map);
        } catch (SQLException ex) {
            return new VerificationResult(false, 0, List.of("Cannot read audit table: " + ex.getMessage()));
        }
        String prev = GENESIS;
        for (AuditEvent e : all) {
            if (!e.prevHash().equals(prev)) {
                problems.add("Chain broken before seq " + e.seq() + " (a record was deleted, inserted or reordered)");
            }
            String expect = compute(e.prevHash(), e.eventId(), e.timestamp().toString(), e.eventType(), e.agentId(), e.command(),
                    e.workingDir(), e.riskLevel(), e.matchedRules(), e.decision(), e.approvalStatus(), e.biometricResult(),
                    e.executionResult());
            if (!Hashing.constantTimeEquals(expect, e.hash())) {
                problems.add("Record seq " + e.seq() + " was modified (hash mismatch)");
            }
            prev = e.hash();
        }
        checkCheckpoint(all, problems);
        return new VerificationResult(problems.isEmpty(), all.size(), problems);
    }

    private void checkCheckpoint(List<AuditEvent> all, List<String> problems) {
        if (!Files.exists(checkpointFile)) {
            if (!all.isEmpty()) problems.add("Checkpoint file is missing; deletion of the newest records cannot be ruled out");
            return;
        }
        try {
            Map<String, Object> m = Json.parseObject(Files.readString(checkpointFile, StandardCharsets.UTF_8));
            long seq = ((Number) m.get("seq")).longValue();
            long count = ((Number) m.get("count")).longValue();
            String hash = (String) m.get("hash");
            String mac = (String) m.get("mac");
            if (!Hashing.constantTimeEquals(Hashing.hmacHex(key, "CP|" + seq + "|" + count + "|" + hash), mac)) {
                problems.add("Checkpoint failed its integrity check");
                return;
            }
            if (all.isEmpty()) {
                if (count > 0) problems.add("All audit records were deleted (checkpoint expects " + count + ")");
                return;
            }
            AuditEvent last = all.get(all.size() - 1);
            if (last.seq() < seq) {
                problems.add("Newest records were deleted (checkpoint expects seq " + seq + ", log ends at " + last.seq() + ")");
            } else if (last.seq() == seq) {
                if (!last.hash().equals(hash)) problems.add("Newest record does not match the checkpoint");
            } else {
                // a record was appended after the checkpoint (crash window): acceptable only if it chains from the checkpoint
                boolean chained = all.stream().anyMatch(e -> e.seq() == seq && e.hash().equals(hash));
                if (!chained) problems.add("Log does not contain the checkpointed record");
            }
        } catch (IOException | RuntimeException ex) {
            problems.add("Checkpoint unreadable or malformed");
        }
    }
}
