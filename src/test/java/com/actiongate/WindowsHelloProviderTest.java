package com.actiongate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.actiongate.authentication.AuthResult;
import com.actiongate.authentication.AuthStatus;
import com.actiongate.authentication.Availability;
import com.actiongate.authentication.ScriptRunner;
import com.actiongate.authentication.UnavailableAuthenticationProvider;
import com.actiongate.authentication.WindowsHelloProvider;
import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.CancellationException;
import org.junit.jupiter.api.Test;

/**
 * These tests exercise ActionGate's handling of the bridge's output with a fake ScriptRunner. They do NOT prove
 * that Windows Hello works; that needs a manual test on Windows (docs/TESTING.md).
 */
class WindowsHelloProviderTest {
    private static WindowsHelloProvider with(ScriptRunner r) {
        return new WindowsHelloProvider(r, true, Duration.ofSeconds(5));
    }

    @Test
    void verifiedMapsToSuccessOnlyForVerified() {
        assertEquals(AuthStatus.SUCCESS, with((m, p, t) -> "ACTIONGATE_RESULT=Verified\n").authenticate("x").status());
        assertTrue(with((m, p, t) -> "noise\r\nACTIONGATE_RESULT=Verified\r\n").authenticate("x").success());
    }

    @Test
    void everyNonVerifiedOutcomeDenies() {
        assertEquals(AuthStatus.CANCELLED, with((m, p, t) -> "ACTIONGATE_RESULT=Canceled").authenticate("x").status());
        assertEquals(AuthStatus.FAILED, with((m, p, t) -> "ACTIONGATE_RESULT=RetriesExhausted").authenticate("x").status());
        assertEquals(AuthStatus.UNAVAILABLE, with((m, p, t) -> "ACTIONGATE_RESULT=DeviceNotPresent").authenticate("x").status());
        assertEquals(AuthStatus.UNAVAILABLE, with((m, p, t) -> "ACTIONGATE_RESULT=NotConfiguredForUser").authenticate("x").status());
        assertEquals(AuthStatus.UNAVAILABLE, with((m, p, t) -> "ACTIONGATE_RESULT=DisabledByPolicy").authenticate("x").status());
        assertEquals(AuthStatus.ERROR, with((m, p, t) -> "ACTIONGATE_RESULT=SomethingNew").authenticate("x").status());
        assertEquals(AuthStatus.ERROR, with((m, p, t) -> "").authenticate("x").status());
        assertEquals(AuthStatus.ERROR, with((m, p, t) -> "ACTIONGATE_ERROR=TypeLoadException").authenticate("x").status());
        assertEquals(AuthStatus.ERROR, with((m, p, t) -> { throw new IOException("no powershell"); }).authenticate("x").status());
        assertEquals(AuthStatus.TIMEOUT, with((m, p, t) -> { throw new CancellationException("t"); }).authenticate("x").status());
        // output that merely mentions "Verified" without the protocol prefix must not authorise
        assertFalse(with((m, p, t) -> "Verified").authenticate("x").success());
        assertFalse(with((m, p, t) -> "foo ACTIONGATE_RESULT=Verified").authenticate("x").success());
    }

    @Test
    void availabilityMapping() {
        assertEquals(Availability.AVAILABLE, with((m, p, t) -> "ACTIONGATE_AVAILABILITY=Available").checkAvailability());
        assertEquals(Availability.DEVICE_NOT_PRESENT, with((m, p, t) -> "ACTIONGATE_AVAILABILITY=DeviceNotPresent").checkAvailability());
        assertEquals(Availability.NOT_CONFIGURED_FOR_USER, with((m, p, t) -> "ACTIONGATE_AVAILABILITY=NotConfiguredForUser").checkAvailability());
        assertEquals(Availability.DISABLED_BY_POLICY, with((m, p, t) -> "ACTIONGATE_AVAILABILITY=DisabledByPolicy").checkAvailability());
        assertEquals(Availability.UNKNOWN, with((m, p, t) -> "garbage").checkAvailability());
    }

    @Test
    void nonWindowsPlatformIsUnavailableAndNeverRunsTheBridge() {
        WindowsHelloProvider p = new WindowsHelloProvider((m, pr, t) -> { throw new AssertionError("must not run"); }, false, Duration.ofSeconds(1));
        assertEquals(Availability.UNSUPPORTED_PLATFORM, p.checkAvailability());
        assertEquals(AuthStatus.UNAVAILABLE, p.authenticate("x").status());
        AuthResult u = new UnavailableAuthenticationProvider("test").authenticate("x");
        assertEquals(AuthStatus.UNAVAILABLE, u.status());
    }

    @Test
    void promptIsSanitisedBeforeLeavingTheJvm() {
        String[] seen = new String[1];
        with((m, p, t) -> { seen[0] = p; return "ACTIONGATE_RESULT=Canceled"; }).authenticate("evil\"; Remove-Item C:\\ #\n\u0000é" + "x".repeat(500));
        assertTrue(seen[0].length() <= 180);
        assertFalse(seen[0].contains("\n"));
        assertFalse(seen[0].contains("\u0000"));
    }

    @Test
    void realProviderIsNotMock() {
        assertFalse(new WindowsHelloProvider().isMock());
    }
}
