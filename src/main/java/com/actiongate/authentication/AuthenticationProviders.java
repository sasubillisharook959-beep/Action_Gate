package com.actiongate.authentication;

import java.util.Locale;

public final class AuthenticationProviders {
    private AuthenticationProviders() {}

    public static AuthenticationProvider createDefault() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("win")) return new WindowsHelloProvider();
        return new UnavailableAuthenticationProvider("Windows Hello is only available on Windows");
    }
}
