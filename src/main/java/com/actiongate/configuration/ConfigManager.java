package com.actiongate.configuration;

import com.actiongate.audit.AuditEntry;
import com.actiongate.audit.AuditLog;
import com.actiongate.model.RiskLevel;
import com.actiongate.policy.AgentSettings;
import com.actiongate.policy.BiometricUnavailableBehavior;
import com.actiongate.policy.LevelRule;
import com.actiongate.policy.PolicyHolder;
import com.actiongate.policy.PolicyValidationException;
import com.actiongate.policy.SecurityPolicy;
import com.actiongate.util.Json;
import com.actiongate.util.SecureFiles;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Loads, validates, saves and audits the JSON security policy. */
public final class ConfigManager {
    private final Path file;
    private final PolicyHolder holder;
    private final AuditLog audit;

    public ConfigManager(Path file, PolicyHolder holder, AuditLog audit) {
        this.file = file;
        this.holder = holder;
        this.audit = audit;
    }

    /** Loads the policy file; writes defaults if it does not exist. Invalid files are rejected (no silent fallback to weaker rules). */
    public static SecurityPolicy load(Path file) throws IOException {
        if (!Files.exists(file)) {
            SecurityPolicy d = SecurityPolicy.defaults();
            save(file, d);
            return d;
        }
        return fromJson(Files.readString(file, StandardCharsets.UTF_8));
    }

    public static SecurityPolicy fromJson(String json) {
        Map<String, Object> m;
        try {
            m = Json.parseObject(json);
        } catch (IllegalArgumentException e) {
            throw new PolicyValidationException(List.of("Policy file is not valid JSON: " + e.getMessage()));
        }
        List<String> problems = new ArrayList<>();
        if (m.containsKey("enforcementEnabled") || m.containsKey("enforcement")) {
            problems.add("Pre-execution enforcement cannot be configured or disabled through policy");
        }
        SecurityPolicy d = SecurityPolicy.defaults();
        EnumMap<RiskLevel, LevelRule> levels = new EnumMap<>(RiskLevel.class);
        levels.putAll(d.levels());
        Map<String, Object> lv = Json.asObject(m.get("levels"));
        if (lv != null) {
            for (Map.Entry<String, Object> e : lv.entrySet()) {
                RiskLevel level;
                try {
                    level = RiskLevel.valueOf(e.getKey());
                } catch (IllegalArgumentException ex) {
                    problems.add("Unknown risk level: " + e.getKey());
                    continue;
                }
                Map<String, Object> r = Json.asObject(e.getValue());
                if (r == null) { problems.add("Level " + e.getKey() + " must be an object"); continue; }
                levels.put(level, new LevelRule(bool(r, "approval", problems), bool(r, "biometric", problems), bool(r, "block", problems)));
            }
        }
        Set<String> blocked = strSet(m, "blockedCategories", d.blockedCategories(), problems);
        List<String> allowed = strList(m, "allowedWorkingDirectories", d.allowedWorkingDirectories(), problems);
        List<String> prot = strList(m, "protectedPaths", d.protectedPaths(), problems);
        Set<String> trusted = strSet(m, "trustedExecutables", d.trustedExecutables(), problems);
        BiometricUnavailableBehavior bub = d.biometricUnavailable();
        if (m.containsKey("biometricUnavailable")) {
            try {
                bub = BiometricUnavailableBehavior.valueOf(String.valueOf(m.get("biometricUnavailable")));
            } catch (IllegalArgumentException e) {
                problems.add("biometricUnavailable must be DENY or FALLBACK_TO_APPROVAL");
            }
        }
        int timeout = integer(m, "approvalTimeoutSeconds", d.approvalTimeoutSeconds(), problems);
        int validity = integer(m, "approvalValiditySeconds", d.approvalValiditySeconds(), problems);
        int port = integer(m, "port", d.port(), problems);
        Map<String, AgentSettings> agents = new LinkedHashMap<>(d.agents());
        Map<String, Object> ag = Json.asObject(m.get("agents"));
        if (ag != null) {
            agents.clear();
            if (!ag.isEmpty()) agents.put("github-copilot", d.agent("github-copilot"));
            for (Map.Entry<String, Object> e : ag.entrySet()) {
                Map<String, Object> a = Json.asObject(e.getValue());
                if (a == null) { problems.add("Agent " + e.getKey() + " must be an object"); continue; }
                agents.put(e.getKey(), new AgentSettings(bool(a, "enabled", problems), a.get("explicitAllowLowRisk") instanceof Boolean b && b));
            }
        }
        if (!problems.isEmpty()) throw new PolicyValidationException(problems);
        return new SecurityPolicy(levels, blocked, allowed, prot, trusted, bub, timeout, validity, port, agents);
    }

    public static String toJson(SecurityPolicy p) {
        Map<String, Object> m = new LinkedHashMap<>();
        Map<String, Object> lv = new LinkedHashMap<>();
        for (RiskLevel l : RiskLevel.values()) {
            LevelRule r = p.levelRule(l);
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("approval", r.approval());
            o.put("biometric", r.biometric());
            o.put("block", r.block());
            lv.put(l.name(), o);
        }
        m.put("levels", lv);
        m.put("blockedCategories", new ArrayList<>(p.blockedCategories()));
        m.put("allowedWorkingDirectories", p.allowedWorkingDirectories());
        m.put("protectedPaths", p.protectedPaths());
        m.put("trustedExecutables", new ArrayList<>(p.trustedExecutables()));
        m.put("biometricUnavailable", p.biometricUnavailable().name());
        m.put("approvalTimeoutSeconds", p.approvalTimeoutSeconds());
        m.put("approvalValiditySeconds", p.approvalValiditySeconds());
        m.put("port", p.port());
        Map<String, Object> ag = new LinkedHashMap<>();
        p.agents().forEach((k, v) -> {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("enabled", v.enabled());
            o.put("explicitAllowLowRisk", v.explicitAllowLowRisk());
            ag.put(k, o);
        });
        m.put("agents", ag);
        return Json.writePretty(m);
    }

    public static void save(Path file, SecurityPolicy p) throws IOException {
        if (file.getParent() != null) Files.createDirectories(file.getParent());
        SecureFiles.writeAtomic(file, toJson(p).getBytes(StandardCharsets.UTF_8));
    }

    /** Validates (already done by SecurityPolicy's constructor), persists, applies and audits a policy change. */
    public void apply(SecurityPolicy newPolicy, String source) throws IOException {
        SecurityPolicy old = holder.base();
        save(file, newPolicy);
        holder.set(newPolicy);
        try {
            audit.append(AuditEntry.system("POLICY_CHANGE", "Policy changed via " + source + ": " + diff(old, newPolicy)));
        } catch (Exception e) {
            throw new IOException("Policy applied but audit entry failed: " + e.getMessage(), e);
        }
    }

    static String diff(SecurityPolicy a, SecurityPolicy b) {
        List<String> d = new ArrayList<>();
        for (RiskLevel l : RiskLevel.values()) if (!a.levelRule(l).equals(b.levelRule(l))) d.add("level " + l + " " + a.levelRule(l) + " -> " + b.levelRule(l));
        if (!a.blockedCategories().equals(b.blockedCategories())) d.add("blockedCategories");
        if (!a.allowedWorkingDirectories().equals(b.allowedWorkingDirectories())) d.add("allowedWorkingDirectories");
        if (!a.protectedPaths().equals(b.protectedPaths())) d.add("protectedPaths");
        if (!a.trustedExecutables().equals(b.trustedExecutables())) d.add("trustedExecutables");
        if (a.biometricUnavailable() != b.biometricUnavailable()) d.add("biometricUnavailable " + a.biometricUnavailable() + " -> " + b.biometricUnavailable());
        if (a.approvalTimeoutSeconds() != b.approvalTimeoutSeconds()) d.add("approvalTimeoutSeconds");
        if (a.approvalValiditySeconds() != b.approvalValiditySeconds()) d.add("approvalValiditySeconds");
        if (a.port() != b.port()) d.add("port " + a.port() + " -> " + b.port());
        if (!a.agents().equals(b.agents())) d.add("agents");
        return d.isEmpty() ? "no effective change" : String.join("; ", d);
    }

    private static boolean bool(Map<String, Object> m, String k, List<String> problems) {
        Object v = m.get(k);
        if (v == null) return false;
        if (v instanceof Boolean b) return b;
        problems.add(k + " must be true or false");
        return false;
    }

    private static int integer(Map<String, Object> m, String k, int def, List<String> problems) {
        Object v = m.get(k);
        if (v == null) return def;
        if (v instanceof Long l && l >= Integer.MIN_VALUE && l <= Integer.MAX_VALUE) return l.intValue();
        problems.add(k + " must be an integer");
        return def;
    }

    private static List<String> strList(Map<String, Object> m, String k, List<String> def, List<String> problems) {
        if (!m.containsKey(k)) return def;
        List<Object> a = Json.asArray(m.get(k));
        if (a == null) { problems.add(k + " must be an array of strings"); return def; }
        List<String> out = new ArrayList<>();
        for (Object o : a) {
            if (o instanceof String s) out.add(s);
            else problems.add(k + " must contain only strings");
        }
        return out;
    }

    private static Set<String> strSet(Map<String, Object> m, String k, Set<String> def, List<String> problems) {
        if (!m.containsKey(k)) return def;
        return new LinkedHashSet<>(strList(m, k, new ArrayList<>(def), problems));
    }
}
