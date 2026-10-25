package com.actiongate;

import com.actiongate.audit.AuditEntry;
import com.actiongate.audit.AuditLog;
import com.actiongate.authentication.AuthenticationProvider;
import com.actiongate.authentication.AuthenticationProviders;
import com.actiongate.configuration.ConfigManager;
import com.actiongate.enforcement.ApprovalRequest;
import com.actiongate.enforcement.ApprovalResult;
import com.actiongate.enforcement.ApprovalService;
import com.actiongate.enforcement.DenyAllApprovalService;
import com.actiongate.enforcement.EnforcementService;
import com.actiongate.integration.AgentAdapter;
import com.actiongate.integration.ClaudeCodeAdapter;
import com.actiongate.integration.CopilotAdapter;
import com.actiongate.integration.LoopbackServer;
import com.actiongate.policy.PolicyEngine;
import com.actiongate.policy.PolicyHolder;
import com.actiongate.policy.SecurityPolicy;
import com.actiongate.risk.RiskEngine;
import com.actiongate.security.IpcCredentials;
import com.actiongate.storage.Database;
import com.actiongate.util.AppPaths;
import java.time.Clock;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/** Wires all modules together (workflow steps 2-4: load config, init audit + auth, start the integration endpoint). */
public final class AppContext implements AutoCloseable {
    public final AppPaths paths;
    public final PolicyHolder policy;
    public final Database db;
    public final AuditLog audit;
    public final ConfigManager config;
    public final AuthenticationProvider auth;
    public final EnforcementService enforcement;
    public final IpcCredentials credentials;
    public final LoopbackServer server;
    private final AtomicReference<ApprovalService> approval = new AtomicReference<>(new DenyAllApprovalService());

    private AppContext(AppPaths paths, PolicyHolder policy, Database db, AuditLog audit, ConfigManager config,
                       AuthenticationProvider auth, EnforcementService enforcement, IpcCredentials credentials, LoopbackServer server) {
        this.paths = paths;
        this.policy = policy;
        this.db = db;
        this.audit = audit;
        this.config = config;
        this.auth = auth;
        this.enforcement = enforcement;
        this.credentials = credentials;
        this.server = server;
    }

    public void setApprovalService(ApprovalService s) { approval.set(s); }

    public static AppContext start(AppPaths paths, AuthenticationProvider auth, boolean allowMockAuth) throws Exception {
        paths.ensure();
        SecurityPolicy loaded = ConfigManager.load(paths.policyFile());
        PolicyHolder holder = new PolicyHolder(loaded, java.util.List.of(paths.home().toString()));
        Database db = new Database(paths.databaseFile());
        AuditLog audit = new AuditLog(db, paths.integrityKeyFile(), paths.checkpointFile());
        ConfigManager cfg = new ConfigManager(paths.policyFile(), holder, audit);
        AtomicReference<ApprovalService> ref = new AtomicReference<>(new DenyAllApprovalService());
        AppContext[] self = new AppContext[1];
        ApprovalService delegating = new ApprovalService() {
            @Override
            public ApprovalResult requestApproval(ApprovalRequest r) {
                return self[0].approval.get().requestApproval(r);
            }
        };
        EnforcementService enf = new EnforcementService(holder, new RiskEngine(), new PolicyEngine(), delegating, auth, audit,
                Clock.systemUTC(), allowMockAuth);
        IpcCredentials creds = IpcCredentials.generate(loaded.port());
        Map<String, AgentAdapter> adapters = Map.of(
                ClaudeCodeAdapter.ID, new ClaudeCodeAdapter(),
                CopilotAdapter.ID, new CopilotAdapter());
        LoopbackServer server = new LoopbackServer(loaded.port(), creds.token(), adapters, enf, holder);
        // publish the credentials of the actual server (the token must match the one the server checks)
        creds.publishWithPort(paths.ipcFile(), server.port(), holder.get().approvalTimeoutSeconds());
        server.start();
        AppContext ctx = new AppContext(paths, holder, db, audit, cfg, auth, enf, creds, server);
        self[0] = ctx;
        audit.append(AuditEntry.system("APP_START", "ActionGate started; endpoint 127.0.0.1:" + server.port() + "; auth provider: " + auth.name()));
        return ctx;
    }

    public static AppContext start(AppPaths paths) throws Exception {
        return start(paths, AuthenticationProviders.createDefault(), false);
    }

    @Override
    public void close() {
        try {
            server.close();
        } finally {
            IpcCredentials.remove(paths.ipcFile());
            db.close();
        }
    }
}
