package com.actiongate.security;

import com.actiongate.util.Hashing;
import com.actiongate.util.Json;
import com.actiongate.util.SecureFiles;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/** Per-run random bearer token for the loopback endpoint, published in an owner-only file for the hook client. */
public final class IpcCredentials {
    private final String token;
    private final int port;

    private IpcCredentials(String token, int port) {
        this.token = token;
        this.port = port;
    }

    public static IpcCredentials generate(int port) {
        return new IpcCredentials(Hashing.hex(SecureFiles.randomBytes(32)), port);
    }

    public String token() { return token; }
    public int port() { return port; }

    public void publish(Path file, int approvalTimeoutSeconds) throws IOException {
        publishWithPort(file, port, approvalTimeoutSeconds);
    }

    public void publishWithPort(Path file, int actualPort, int approvalTimeoutSeconds) throws IOException {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("port", actualPort);
        m.put("token", token);
        m.put("approvalTimeoutSeconds", approvalTimeoutSeconds);
        SecureFiles.writeAtomic(file, Json.write(m).getBytes(StandardCharsets.UTF_8));
    }

    public static void remove(Path file) {
        try {
            Files.deleteIfExists(file);
        } catch (IOException ignored) {
            // best effort
        }
    }
}
