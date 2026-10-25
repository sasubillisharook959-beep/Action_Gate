package com.actiongate.authentication;

/** Used where Windows Hello cannot exist (non-Windows). Always fails closed. */
public final class UnavailableAuthenticationProvider implements AuthenticationProvider {
    private final String reason;

    public UnavailableAuthenticationProvider(String reason) {
        this.reason = reason;
    }

    @Override public String name() { return "Unavailable (" + reason + ")"; }
    @Override public boolean isMock() { return false; }
    @Override public Availability checkAvailability() { return Availability.UNSUPPORTED_PLATFORM; }
    @Override public AuthResult authenticate(String promptMessage) { return new AuthResult(AuthStatus.UNAVAILABLE, reason); }
}
