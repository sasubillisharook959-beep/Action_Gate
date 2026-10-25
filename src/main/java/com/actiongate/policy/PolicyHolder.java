package com.actiongate.policy;

import java.util.List;

/**
 * Thread-safe holder so the policy can be replaced at runtime. {@link #get()} returns the effective policy, which
 * includes extra protected paths that are always enforced (ActionGate's own data directory) and are never user-removable.
 */
public final class PolicyHolder {
    private final List<String> extraProtected;
    private volatile SecurityPolicy base;
    private volatile SecurityPolicy effective;

    public PolicyHolder(SecurityPolicy initial) {
        this(initial, List.of());
    }

    public PolicyHolder(SecurityPolicy initial, List<String> extraProtected) {
        this.extraProtected = List.copyOf(extraProtected);
        set(initial);
    }

    /** Effective policy used for enforcement. */
    public SecurityPolicy get() { return effective; }

    /** The policy as configured by the user (without the built-in extra protected paths). */
    public SecurityPolicy base() { return base; }

    public void set(SecurityPolicy p) {
        this.base = p;
        this.effective = extraProtected.isEmpty() ? p : p.withExtraProtectedPaths(extraProtected);
    }
}
