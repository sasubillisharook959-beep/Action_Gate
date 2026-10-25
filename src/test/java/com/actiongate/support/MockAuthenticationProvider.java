package com.actiongate.support;

import com.actiongate.authentication.AuthResult;
import com.actiongate.authentication.AuthStatus;
import com.actiongate.authentication.AuthenticationProvider;
import com.actiongate.authentication.Availability;
import java.util.concurrent.atomic.AtomicInteger;

/** TEST-ONLY provider. It is not on the production classpath and is refused by EnforcementService in production mode. */
public final class MockAuthenticationProvider implements AuthenticationProvider {
    public volatile Availability availability = Availability.AVAILABLE;
    public volatile AuthResult result = new AuthResult(AuthStatus.SUCCESS, "MOCK verified");
    public final AtomicInteger calls = new AtomicInteger();

    @Override public String name() { return "MOCK (tests only)"; }
    @Override public boolean isMock() { return true; }
    @Override public Availability checkAvailability() { return availability; }
    @Override public AuthResult authenticate(String promptMessage) {
        calls.incrementAndGet();
        return result;
    }
}
