package com.actiongate.policy;

public enum BiometricUnavailableBehavior {
    /** Fail closed: deny operations that require Windows Hello when it cannot be used. (default) */
    DENY,
    /** Fall back to the explicit approval dialog only. Never applies to CRITICAL (always blocked). */
    FALLBACK_TO_APPROVAL
}
