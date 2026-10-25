package com.actiongate.policy;

import com.actiongate.model.RiskLevel;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Immutable, validated security policy. Pre-execution enforcement itself is not a policy option. */
public final class SecurityPolicy {
    public static final int MIN_PORT = 1024;
    public static final int MAX_PORT = 65535;

    private final Map<RiskLevel, LevelRule> levels;
    private final Set<String> blockedCategories;
    private final List<String> allowedWorkingDirectories;
    private final List<String> protectedPaths;
    private final Set<String> trustedExecutables;
    private final BiometricUnavailableBehavior biometricUnavailable;
    private final int approvalTimeoutSeconds;
    private final int approvalValiditySeconds;
    private final int port;
    private final Map<String, AgentSettings> agents;

    public SecurityPolicy(Map<RiskLevel, LevelRule> levels, Set<String> blockedCategories,
                          List<String> allowedWorkingDirectories, List<String> protectedPaths,
                          Set<String> trustedExecutables, BiometricUnavailableBehavior biometricUnavailable,
                          int approvalTimeoutSeconds, int approvalValiditySeconds, int port,
                          Map<String, AgentSettings> agents) {
        EnumMap<RiskLevel, LevelRule> l = new EnumMap<>(RiskLevel.class);
        l.putAll(levels);
        this.levels = Collections.unmodifiableMap(l);
        this.blockedCategories = Collections.unmodifiableSet(new LinkedHashSet<>(blockedCategories));
        this.allowedWorkingDirectories = List.copyOf(allowedWorkingDirectories);
        this.protectedPaths = List.copyOf(protectedPaths);
        this.trustedExecutables = Collections.unmodifiableSet(new LinkedHashSet<>(trustedExecutables));
        this.biometricUnavailable = biometricUnavailable;
        this.approvalTimeoutSeconds = approvalTimeoutSeconds;
        this.approvalValiditySeconds = approvalValiditySeconds;
        this.port = port;
        this.agents = Collections.unmodifiableMap(new LinkedHashMap<>(agents));
        List<String> problems = validate();
        if (!problems.isEmpty()) throw new PolicyValidationException(problems);
    }

    /** @return human-readable problems; empty when valid. */
    public List<String> validate() {
        List<String> p = new ArrayList<>();
        for (RiskLevel lv : RiskLevel.values()) {
            if (!levels.containsKey(lv)) p.add("Missing rule for level " + lv);
        }
        if (levels.size() == RiskLevel.values().length) {
            if (!levels.get(RiskLevel.CRITICAL).block())
                p.add("CRITICAL commands must always be blocked; this cannot be overridden");
            LevelRule high = levels.get(RiskLevel.HIGH);
            if (!high.block() && !high.approval())
                p.add("HIGH commands must be blocked or require approval");
            for (RiskLevel lv : RiskLevel.values()) {
                LevelRule r = levels.get(lv);
                if (r.biometric() && !r.approval() && !r.block())
                    p.add(lv + ": biometric verification requires approval to be enabled");
            }
            if (levels.get(RiskLevel.MEDIUM).block() == false && !levels.get(RiskLevel.MEDIUM).approval()
                    && levels.get(RiskLevel.HIGH).approval() == false && !levels.get(RiskLevel.HIGH).block())
                p.add("MEDIUM and HIGH cannot both be allowed without approval");
        }
        if (approvalTimeoutSeconds < 10 || approvalTimeoutSeconds > 600) p.add("approvalTimeoutSeconds must be 10..600");
        if (approvalValiditySeconds < 5 || approvalValiditySeconds > 300) p.add("approvalValiditySeconds must be 5..300");
        if (port < MIN_PORT || port > MAX_PORT) p.add("port must be " + MIN_PORT + ".." + MAX_PORT);
        if (biometricUnavailable == null) p.add("biometricUnavailable must be set");
        if (agents.isEmpty()) p.add("At least one agent entry is required");
        for (String a : agents.keySet()) {
            if (!a.matches("[A-Za-z0-9._-]{1,64}")) p.add("Invalid agent id: " + a);
        }
        for (String s : protectedPaths) {
            if (s == null || s.isBlank() || s.indexOf('\0') >= 0) p.add("Invalid protected path entry");
        }
        for (String s : allowedWorkingDirectories) {
            if (s == null || s.isBlank() || s.indexOf('\0') >= 0) p.add("Invalid allowed working directory entry");
        }
        for (String s : trustedExecutables) {
            if (s == null || !s.matches("[A-Za-z0-9._+-]{1,64}")) p.add("Invalid trusted executable name: " + s);
        }
        return p;
    }

    public static SecurityPolicy defaults() {
        EnumMap<RiskLevel, LevelRule> l = new EnumMap<>(RiskLevel.class);
        l.put(RiskLevel.LOW, new LevelRule(false, false, false));
        l.put(RiskLevel.MEDIUM, new LevelRule(true, false, false));
        l.put(RiskLevel.HIGH, new LevelRule(true, true, false));
        l.put(RiskLevel.CRITICAL, new LevelRule(false, false, true));
        Set<String> blocked = new LinkedHashSet<>(List.of(
                "FILESYSTEM_DESTRUCTION", "DISK_DESTRUCTION", "SECURITY_TAMPER", "DOWNLOAD_EXEC",
                "OBFUSCATED_EXECUTION", "ACCOUNT_MANIPULATION", "EXFILTRATION", "PROTECTED_PATH"));
        List<String> protectedPaths = new ArrayList<>(List.of(
                "C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)", "C:\\ProgramData\\Microsoft",
                "~/.ssh", "~/.gnupg", "~/.aws",
                "/etc", "/usr", "/bin", "/sbin", "/boot", "/lib", "/var/lib", "/system", "/library"));
        Set<String> trusted = new LinkedHashSet<>();
        Map<String, AgentSettings> agents = new LinkedHashMap<>();
        agents.put("claude-code", new AgentSettings(true, false));
        agents.put("github-copilot", new AgentSettings(true, false));
        return new SecurityPolicy(l, blocked, List.of(), protectedPaths, trusted,
                BiometricUnavailableBehavior.DENY, 120, 60, 47615, agents);
    }

    public LevelRule levelRule(RiskLevel level) { return levels.get(level); }
    public Map<RiskLevel, LevelRule> levels() { return levels; }
    public Set<String> blockedCategories() { return blockedCategories; }
    public List<String> allowedWorkingDirectories() { return allowedWorkingDirectories; }
    public List<String> protectedPaths() { return protectedPaths; }
    public Set<String> trustedExecutables() { return trustedExecutables; }
    public BiometricUnavailableBehavior biometricUnavailable() { return biometricUnavailable; }
    public int approvalTimeoutSeconds() { return approvalTimeoutSeconds; }
    public int approvalValiditySeconds() { return approvalValiditySeconds; }
    public int port() { return port; }
    public Map<String, AgentSettings> agents() { return agents; }

    public AgentSettings agent(String id) {
        return agents.getOrDefault(id, new AgentSettings(false, false));
    }

    /** Returns a copy with extra protected paths appended (used to protect ActionGate's own data directory). */
    public SecurityPolicy withExtraProtectedPaths(List<String> extra) {
        List<String> all = new ArrayList<>(protectedPaths);
        for (String e : extra) if (!all.contains(e)) all.add(e);
        return new SecurityPolicy(levels, blockedCategories, allowedWorkingDirectories, all, trustedExecutables,
                biometricUnavailable, approvalTimeoutSeconds, approvalValiditySeconds, port, agents);
    }
}
