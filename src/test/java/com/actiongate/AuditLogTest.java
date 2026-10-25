package com.actiongate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.actiongate.audit.AuditEntry;
import com.actiongate.audit.AuditLog;
import com.actiongate.audit.Redactor;
import com.actiongate.audit.VerificationResult;
import com.actiongate.storage.Database;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AuditLogTest {
    @TempDir Path dir;
    Database db;
    AuditLog log;

    @BeforeEach
    void setUp() throws Exception {
        db = new Database(dir.resolve("a.db"));
        log = new AuditLog(db, dir.resolve("k"), dir.resolve("cp"));
    }

    @AfterEach
    void tearDown() {
        db.close();
    }

    private void add(int n) throws Exception {
        for (int i = 0; i < n; i++)
            log.append(new AuditEntry("COMMAND_DECISION", "claude-code", "cmd " + i, "C:\\p", "LOW", "", "ALLOW", "NOT_REQUIRED", "NOT_REQUIRED", "PERMITTED_TO_PROCEED"));
    }

    @Test
    void emptyAndIntactChainsVerify() throws Exception {
        assertTrue(log.verify().valid());
        add(5);
        VerificationResult v = log.verify();
        assertTrue(v.valid(), v.toString());
        assertEquals(5, v.eventsChecked());
    }

    @Test
    void eventsAreChained() throws Exception {
        add(3);
        var ev = log.recent(10);
        assertEquals(AuditLog.GENESIS, ev.get(2).prevHash());
        assertEquals(ev.get(2).hash(), ev.get(1).prevHash());
        assertEquals(ev.get(1).hash(), ev.get(0).prevHash());
        assertEquals(64, ev.get(0).hash().length());
    }

    @Test
    void modifiedRecordIsDetected() throws Exception {
        add(4);
        db.update("UPDATE audit_events SET decision = 'ALLOW', command = 'tampered' WHERE seq = 2");
        VerificationResult v = log.verify();
        assertFalse(v.valid());
        assertTrue(v.problems().stream().anyMatch(p -> p.contains("seq 2") && p.contains("modified")), v.toString());
    }

    @Test
    void deletedMiddleRecordIsDetected() throws Exception {
        add(5);
        db.update("DELETE FROM audit_events WHERE seq = 3");
        VerificationResult v = log.verify();
        assertFalse(v.valid());
        assertTrue(v.problems().stream().anyMatch(p -> p.contains("Chain broken")), v.toString());
    }

    @Test
    void deletedNewestRecordsAreDetectedViaCheckpoint() throws Exception {
        add(5);
        db.update("DELETE FROM audit_events WHERE seq > 3");
        VerificationResult v = log.verify();
        assertFalse(v.valid());
        assertTrue(v.problems().stream().anyMatch(p -> p.contains("deleted")), v.toString());
    }

    @Test
    void deletingEverythingIsDetected() throws Exception {
        add(2);
        db.update("DELETE FROM audit_events");
        assertFalse(log.verify().valid());
    }

    @Test
    void forgedCheckpointAndMissingCheckpointAreDetected() throws Exception {
        add(3);
        Path cp = dir.resolve("cp");
        String good = Files.readString(cp);
        Files.writeString(cp, good.replace("\"seq\":3", "\"seq\":1"));
        assertFalse(log.verify().valid());
        Files.delete(cp);
        assertFalse(log.verify().valid());
    }

    @Test
    void reorderedRecordsAreDetected() throws Exception {
        add(3);
        db.update("UPDATE audit_events SET prev_hash = hash WHERE seq = 3");
        assertFalse(log.verify().valid());
    }

    @Test
    void persistenceSurvivesReopenAndChainContinues() throws Exception {
        add(3);
        try {
            db.close();
            try (Database db2 = new Database(dir.resolve("a.db"))) {
                AuditLog log2 = new AuditLog(db2, dir.resolve("k"), dir.resolve("cp"));
                assertEquals(3, log2.count());
                log2.append(AuditEntry.system("APP_START", "restart"));
                assertTrue(log2.verify().valid(), log2.verify().toString());
                assertEquals(4, log2.count());
            }
        } finally {
            db.close();
        }
    }

    @Test
    void wrongIntegrityKeyCannotVerify() throws Exception {
        add(2);
        Files.delete(dir.resolve("k"));
        AuditLog other = new AuditLog(db, dir.resolve("k"), dir.resolve("cp"));
        assertFalse(other.verify().valid(), "a regenerated key must not validate old records");
    }

    @Test
    void secretsAreRedacted() {
        assertFalse(Redactor.redact("curl -H 'Authorization: Bearer abc.def.ghi' x").contains("abc.def.ghi"));
        assertFalse(Redactor.redact("mysql --password=hunter2 -u root").contains("hunter2"));
        assertFalse(Redactor.redact("export API_KEY=supersecretvalue").contains("supersecretvalue"));
        assertFalse(Redactor.redact("git clone https://user:pa55w0rd@github.com/x/y").contains("pa55w0rd"));
        assertFalse(Redactor.redact("echo ghp_abcdefghijklmnop1234").contains("ghp_abcdefghijklmnop1234"));
        assertEquals("git status", Redactor.redact("git status"));
        assertTrue(Redactor.redact("x".repeat(9000)).length() < 4100);
    }

    @Test
    void storedCommandIsRedacted() throws Exception {
        log.append(new AuditEntry("COMMAND_DECISION", "a", "deploy --token=abcd1234efgh", "C:\\", "LOW", "", "ALLOW", "-", "-", "-"));
        assertFalse(log.recent(1).get(0).command().contains("abcd1234efgh"));
        assertTrue(log.verify().valid());
    }
}
