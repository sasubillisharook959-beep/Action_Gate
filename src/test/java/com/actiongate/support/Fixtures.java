package com.actiongate.support;

import com.actiongate.audit.AuditLog;
import com.actiongate.enforcement.ApprovalService;
import com.actiongate.enforcement.EnforcementService;
import com.actiongate.model.CommandRequest;
import com.actiongate.policy.PolicyEngine;
import com.actiongate.policy.PolicyHolder;
import com.actiongate.policy.SecurityPolicy;
import com.actiongate.risk.RiskEngine;
import com.actiongate.storage.Database;
import java.nio.file.Path;
import java.time.Clock;

public final class Fixtures implements AutoCloseable {
    public static final String HOME = "c:/users/alice";
    public static final String CWD = "C:\\Users\\alice\\proj";

    public final Database db;
    public final AuditLog audit;
    public final PolicyHolder policy;
    public final MockAuthenticationProvider auth = new MockAuthenticationProvider();
    public final EnforcementService service;

    public Fixtures(Path dir, ApprovalService approval, SecurityPolicy p, Clock clock) throws Exception {
        db = new Database(dir.resolve("t.db"));
        audit = new AuditLog(db, dir.resolve("k.key"), dir.resolve("cp.json"));
        policy = new PolicyHolder(p);
        service = new EnforcementService(policy, new RiskEngine(HOME), new PolicyEngine(), approval, auth, audit, clock, true);
    }

    public Fixtures(Path dir, ApprovalService approval) throws Exception {
        this(dir, approval, SecurityPolicy.defaults(), Clock.systemUTC());
    }

    @Override
    public void close() {
        db.close();
    }

    public static CommandRequest req(String command) {
        return CommandRequest.create("claude-code", "Bash", command, CWD, "sess1");
    }
}
