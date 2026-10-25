package com.actiongate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.actiongate.audit.AuditLog;
import com.actiongate.configuration.ConfigManager;
import com.actiongate.model.RiskLevel;
import com.actiongate.policy.LevelRule;
import com.actiongate.policy.PolicyDecision;
import com.actiongate.policy.PolicyEngine;
import com.actiongate.policy.PolicyHolder;
import com.actiongate.policy.PolicyValidationException;
import com.actiongate.policy.SecurityPolicy;
import com.actiongate.risk.RiskEngine;
import com.actiongate.storage.Database;
import com.actiongate.support.Fixtures;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.EnumMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConfigAndPolicyTest {
    @TempDir Path dir;

    @Test
    void defaultsAreSafe() {
        SecurityPolicy p = SecurityPolicy.defaults();
        assertTrue(p.levelRule(RiskLevel.CRITICAL).block());
        assertTrue(p.levelRule(RiskLevel.HIGH).approval() && p.levelRule(RiskLevel.HIGH).biometric());
        assertTrue(p.levelRule(RiskLevel.MEDIUM).approval());
        assertFalse(p.levelRule(RiskLevel.LOW).approval());
        assertEquals("DENY", p.biometricUnavailable().name());
    }

    @Test
    void jsonRoundTrip() {
        SecurityPolicy p = SecurityPolicy.defaults();
        SecurityPolicy q = ConfigManager.fromJson(ConfigManager.toJson(p));
        assertEquals(p.levels(), q.levels());
        assertEquals(p.protectedPaths(), q.protectedPaths());
        assertEquals(p.port(), q.port());
        assertEquals(p.agents(), q.agents());
    }

    @Test
    void copilotIntegrationIsEnabledByDefaultAndMigratedIntoExistingAgentPolicies() {
        SecurityPolicy migrated = ConfigManager.fromJson(
                "{\"agents\":{\"claude-code\":{\"enabled\":false,\"explicitAllowLowRisk\":true}}}");
        assertFalse(migrated.agent("claude-code").enabled());
        assertTrue(migrated.agent("claude-code").explicitAllowLowRisk());
        assertTrue(migrated.agent("github-copilot").enabled());
        assertFalse(migrated.agent("github-copilot").explicitAllowLowRisk());

        SecurityPolicy explicitlyDisabled = ConfigManager.fromJson(
                "{\"agents\":{\"github-copilot\":{\"enabled\":false,\"explicitAllowLowRisk\":false}}}");
        assertFalse(explicitlyDisabled.agent("github-copilot").enabled());
    }

    @Test
    void criticalCannotBeUnblocked() {
        String json = "{\"levels\":{\"CRITICAL\":{\"approval\":true,\"biometric\":false,\"block\":false}}}";
        PolicyValidationException e = assertThrows(PolicyValidationException.class, () -> ConfigManager.fromJson(json));
        assertTrue(e.getMessage().contains("CRITICAL"));
    }

    @Test
    void enforcementCannotBeDisabledThroughPolicy() {
        assertThrows(PolicyValidationException.class, () -> ConfigManager.fromJson("{\"enforcementEnabled\": false}"));
        assertThrows(PolicyValidationException.class, () -> ConfigManager.fromJson("{\"enforcement\": {\"mode\": \"off\"}}"));
    }

    @Test
    void invalidValuesAreRejected() {
        assertThrows(PolicyValidationException.class, () -> ConfigManager.fromJson("not json"));
        assertThrows(PolicyValidationException.class, () -> ConfigManager.fromJson("{\"port\": 80}"));
        assertThrows(PolicyValidationException.class, () -> ConfigManager.fromJson("{\"approvalTimeoutSeconds\": 1}"));
        assertThrows(PolicyValidationException.class, () -> ConfigManager.fromJson("{\"approvalValiditySeconds\": 99999}"));
        assertThrows(PolicyValidationException.class, () -> ConfigManager.fromJson("{\"biometricUnavailable\": \"ALLOW\"}"));
        assertThrows(PolicyValidationException.class, () -> ConfigManager.fromJson("{\"levels\": {\"EXTREME\": {}}}"));
        assertThrows(PolicyValidationException.class, () -> ConfigManager.fromJson("{\"levels\": {\"HIGH\": {\"approval\": false, \"biometric\": false, \"block\": false}}}"));
        assertThrows(PolicyValidationException.class, () -> ConfigManager.fromJson("{\"trustedExecutables\": [\"rm; echo\"]}"));
        assertThrows(PolicyValidationException.class, () -> ConfigManager.fromJson("{\"agents\": {}}"));
        assertThrows(PolicyValidationException.class, () -> ConfigManager.fromJson("{\"protectedPaths\": [5]}"));
    }

    @Test
    void loadCreatesDefaultsAndRejectsBrokenFileInsteadOfFallingBack() throws Exception {
        Path f = dir.resolve("policy.json");
        SecurityPolicy p = ConfigManager.load(f);
        assertTrue(Files.exists(f));
        assertEquals(SecurityPolicy.defaults().port(), p.port());
        Files.writeString(f, "{ broken");
        assertThrows(PolicyValidationException.class, () -> ConfigManager.load(f));
    }

    @Test
    void policyChangesAreValidatedPersistedAndAudited() throws Exception {
        try (Database db = new Database(dir.resolve("c.db"))) {
            AuditLog audit = new AuditLog(db, dir.resolve("k"), dir.resolve("cp"));
            PolicyHolder holder = new PolicyHolder(SecurityPolicy.defaults());
            Path file = dir.resolve("policy.json");
            ConfigManager cm = new ConfigManager(file, holder, audit);
            SecurityPolicy d = SecurityPolicy.defaults();
            EnumMap<RiskLevel, LevelRule> lv = new EnumMap<>(d.levels());
            lv.put(RiskLevel.MEDIUM, new LevelRule(false, false, false));
            cm.apply(new SecurityPolicy(lv, d.blockedCategories(), d.allowedWorkingDirectories(), d.protectedPaths(), d.trustedExecutables(),
                    d.biometricUnavailable(), 120, 60, d.port(), d.agents()), "test");
            assertFalse(holder.get().levelRule(RiskLevel.MEDIUM).approval());
            assertFalse(ConfigManager.load(file).levelRule(RiskLevel.MEDIUM).approval());
            var last = audit.recent(1).get(0);
            assertEquals("POLICY_CHANGE", last.eventType());
            assertTrue(last.command().contains("MEDIUM"));
            assertTrue(audit.verify().valid());
        }
    }

    @Test
    void ownDataDirectoryIsAlwaysProtected() throws Exception {
        PolicyHolder h = new PolicyHolder(SecurityPolicy.defaults(), java.util.List.of("c:/users/alice/appdata/local/actiongate"));
        var a = new RiskEngine(Fixtures.HOME).analyze(Fixtures.req("rm C:\\Users\\alice\\AppData\\Local\\ActionGate\\policy.json"), h.get());
        assertEquals(RiskLevel.CRITICAL, a.level());
        h.set(SecurityPolicy.defaults()); // replacing the policy must keep the extra protection
        assertTrue(h.get().protectedPaths().contains("c:/users/alice/appdata/local/actiongate"));
    }

    @Test
    void policyEngineAppliesRulesInOrder() {
        SecurityPolicy p = SecurityPolicy.defaults();
        PolicyEngine pe = new PolicyEngine();
        RiskEngine re = new RiskEngine(Fixtures.HOME);
        var low = Fixtures.req("git status");
        assertEquals(PolicyDecision.Outcome.ALLOW, pe.decide(low, re.analyze(low, p), p).outcome());
        var med = Fixtures.req("rm a.txt");
        PolicyDecision m = pe.decide(med, re.analyze(med, p), p);
        assertEquals(PolicyDecision.Outcome.REQUIRE_APPROVAL, m.outcome());
        assertTrue(m.approvalRequired());
        assertFalse(m.biometricRequired());
        var high = Fixtures.req("git push --force");
        PolicyDecision h = pe.decide(high, re.analyze(high, p), p);
        assertTrue(h.approvalRequired() && h.biometricRequired());
        var crit = Fixtures.req("rm -rf /");
        assertEquals(PolicyDecision.Outcome.DENY, pe.decide(crit, re.analyze(crit, p), p).outcome());
        // blocked category denies even when the level alone would only need approval
        var curl = Fixtures.req("sudo apt install x");
        assertEquals(PolicyDecision.Outcome.REQUIRE_APPROVAL, pe.decide(curl, re.analyze(curl, p), p).outcome());
    }
}
