package com.actiongate.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Locations of ActionGate's per-user data. Override with -Dactiongate.home=... (used by tests). */
public final class AppPaths {
    private final Path home;

    public AppPaths(Path home) {
        this.home = home.toAbsolutePath().normalize();
    }

    public static AppPaths defaultPaths() {
        String override = System.getProperty("actiongate.home");
        if (override == null || override.isBlank()) override = System.getenv("ACTIONGATE_HOME");
        if (override != null && !override.isBlank()) return new AppPaths(Path.of(override));
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("win")) {
            String la = System.getenv("LOCALAPPDATA");
            Path base = la != null && !la.isBlank() ? Path.of(la) : Path.of(System.getProperty("user.home"), "AppData", "Local");
            return new AppPaths(base.resolve("ActionGate"));
        }
        return new AppPaths(Path.of(System.getProperty("user.home"), ".actiongate"));
    }

    public Path home() { return home; }
    public Path policyFile() { return home.resolve("policy.json"); }
    public Path databaseFile() { return home.resolve("actiongate.db"); }
    public Path integrityKeyFile() { return home.resolve("integrity.key"); }
    public Path checkpointFile() { return home.resolve("audit.checkpoint"); }
    public Path ipcFile() { return home.resolve("ipc.json"); }

    public AppPaths ensure() throws IOException {
        Files.createDirectories(home);
        SecureFiles.restrictToOwner(home);
        return this;
    }
}
