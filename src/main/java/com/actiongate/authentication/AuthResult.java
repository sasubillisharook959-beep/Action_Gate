package com.actiongate.authentication;

/** Outcome of an OS-managed verification. Never contains biometric data. */
public record AuthResult(AuthStatus status, String detail) {
    public boolean success() {
        return status == AuthStatus.SUCCESS;
    }

    public static AuthResult notRequired() {
        return new AuthResult(AuthStatus.NOT_REQUIRED, "Biometric verification not required");
    }

    @Override
    public String toString() {
        return status + (detail == null || detail.isEmpty() ? "" : " (" + detail + ")");
    }
}
