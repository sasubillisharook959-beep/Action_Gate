package com.actiongate.authentication;

import java.io.IOException;
import java.time.Duration;
import java.util.Locale;
import java.util.concurrent.CancellationException;

/**
 * Real Windows Hello / Windows "user consent verification" through the OS-managed WinRT API
 * {@code UserConsentVerifier}. Windows itself shows the credential prompt (face, fingerprint or the user's
 * Windows Hello PIN, depending on what the user enrolled) and tells us only the outcome. ActionGate never sees
 * or stores biometric data, templates or PINs.
 *
 * <p>Note: UserConsentVerifier does not let an app insist on biometrics only; if the user has a Hello PIN they can
 * use it. See docs/SECURITY.md.
 */
public final class WindowsHelloProvider implements AuthenticationProvider {
    private static final String CHECK_PREFIX = "ACTIONGATE_AVAILABILITY=";
    private static final String RESULT_PREFIX = "ACTIONGATE_RESULT=";
    private static final String ERROR_PREFIX = "ACTIONGATE_ERROR=";

    private final ScriptRunner runner;
    private final boolean windows;
    private final Duration timeout;

    public WindowsHelloProvider() {
        this(new PowerShellScriptRunner(), System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win"), Duration.ofSeconds(120));
    }

    public WindowsHelloProvider(ScriptRunner runner, boolean isWindows, Duration timeout) {
        this.runner = runner;
        this.windows = isWindows;
        this.timeout = timeout;
    }

    @Override public String name() { return "Windows Hello (UserConsentVerifier)"; }
    @Override public boolean isMock() { return false; }

    @Override
    public Availability checkAvailability() {
        if (!windows) return Availability.UNSUPPORTED_PLATFORM;
        try {
            String out = runner.run("check", "", Duration.ofSeconds(30));
            String v = find(out, CHECK_PREFIX);
            if (v == null) return Availability.UNKNOWN;
            switch (v) {
                case "Available": return Availability.AVAILABLE;
                case "DeviceNotPresent": return Availability.DEVICE_NOT_PRESENT;
                case "NotConfiguredForUser": return Availability.NOT_CONFIGURED_FOR_USER;
                case "DisabledByPolicy": return Availability.DISABLED_BY_POLICY;
                case "DeviceBusy": return Availability.DEVICE_BUSY;
                default: return Availability.UNKNOWN;
            }
        } catch (IOException | CancellationException e) {
            return Availability.UNKNOWN;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Availability.UNKNOWN;
        }
    }

    @Override
    public AuthResult authenticate(String promptMessage) {
        if (!windows) return new AuthResult(AuthStatus.UNAVAILABLE, "Windows Hello requires Windows");
        String prompt = sanitize(promptMessage);
        try {
            String out = runner.run("verify", prompt, timeout);
            String res = find(out, RESULT_PREFIX);
            if (res == null) {
                String err = find(out, ERROR_PREFIX);
                return new AuthResult(AuthStatus.ERROR, err != null ? "bridge error: " + err : "no result from Windows");
            }
            switch (res) {
                case "Verified": return new AuthResult(AuthStatus.SUCCESS, "Verified by Windows");
                case "Canceled": return new AuthResult(AuthStatus.CANCELLED, "User cancelled");
                case "RetriesExhausted": return new AuthResult(AuthStatus.FAILED, "Too many failed attempts");
                case "DeviceNotPresent": return new AuthResult(AuthStatus.UNAVAILABLE, "No Windows Hello device");
                case "NotConfiguredForUser": return new AuthResult(AuthStatus.UNAVAILABLE, "Windows Hello not set up for this user");
                case "DisabledByPolicy": return new AuthResult(AuthStatus.UNAVAILABLE, "Disabled by policy");
                case "DeviceBusy": return new AuthResult(AuthStatus.UNAVAILABLE, "Device busy");
                default: return new AuthResult(AuthStatus.ERROR, "Unexpected result: " + res);
            }
        } catch (CancellationException e) {
            return new AuthResult(AuthStatus.TIMEOUT, "Verification timed out");
        } catch (IOException e) {
            return new AuthResult(AuthStatus.ERROR, "Cannot start Windows PowerShell bridge");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new AuthResult(AuthStatus.ERROR, "Interrupted");
        }
    }

    private static String find(String out, String prefix) {
        if (out == null) return null;
        for (String line : out.split("\\R")) {
            String t = line.trim();
            if (t.startsWith(prefix)) return t.substring(prefix.length()).trim();
        }
        return null;
    }

    static String sanitize(String s) {
        if (s == null) return "ActionGate verification";
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (c >= 0x20 && c < 0x7f) sb.append(c);
            if (sb.length() >= 180) break;
        }
        return sb.length() == 0 ? "ActionGate verification" : sb.toString();
    }
}
