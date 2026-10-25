package com.actiongate.authentication;

/** Isolated boundary to the operating system's user-verification service. */
public interface AuthenticationProvider {
    String name();

    /** Mock providers exist only for automated tests; the enforcement service refuses them in production mode. */
    boolean isMock();

    Availability checkAvailability();

    /**
     * Asks the OS to verify the current user. Must return SUCCESS only when the OS reports success.
     * Must never throw for ordinary failures; return FAILED/CANCELLED/UNAVAILABLE/ERROR instead.
     */
    AuthResult authenticate(String promptMessage);
}
