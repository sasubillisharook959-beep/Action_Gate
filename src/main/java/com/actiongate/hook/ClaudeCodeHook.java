package com.actiongate.hook;

import com.actiongate.util.AppPaths;
import com.actiongate.util.Json;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;

/**
 * Claude Code PreToolUse hook command (JDK-only, no JavaFX). Claude Code starts this process before every matching
 * tool call and passes the tool call as JSON on stdin.
 *
 * <p>Exit codes (Claude Code semantics): 0 = decision JSON on stdout; 2 = BLOCK, stderr is returned to Claude.
 * Any other exit code is a non-blocking error in Claude Code, so this class only ever exits 0 or 2, and every
 * failure (ActionGate not running, bad token, timeout, unexpected exception) exits 2: fail closed.
 */
public final class ClaudeCodeHook {
    private ClaudeCodeHook() {}

    public static void main(String[] args) {
        int code;
        try {
            code = run(System.in, System.out, System.err, AppPaths.defaultPaths().ipcFile());
        } catch (Throwable t) {
            System.err.println("ActionGate hook failed unexpectedly; blocking (fail closed).");
            code = 2;
        }
        System.out.flush();
        System.err.flush();
        Runtime.getRuntime().halt(code == 0 ? 0 : 2);
    }

    static int run(InputStream in, PrintStream out, PrintStream err, Path ipcFile) {
        try {
            byte[] body = readLimited(in, 1_048_576);
            if (!Files.exists(ipcFile)) {
                err.println("ActionGate is not running (no endpoint file). Blocked: fail closed. Start ActionGate and retry.");
                return 2;
            }
            Map<String, Object> ipc = Json.parseObject(Files.readString(ipcFile, StandardCharsets.UTF_8));
            int port = ((Number) ipc.get("port")).intValue();
            String token = (String) ipc.get("token");
            int approvalTimeout = ipc.get("approvalTimeoutSeconds") instanceof Number n ? n.intValue() : 120;
            HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
            HttpRequest req = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/v1/evaluate/claude-code"))
                    .timeout(Duration.ofSeconds(approvalTimeout + 60L))
                    .header("Authorization", "Bearer " + token)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                    .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (resp.statusCode() != 200) {
                err.println("ActionGate rejected or could not process the request (HTTP " + resp.statusCode() + "). Blocked: fail closed.");
                return 2;
            }
            Json.parseObject(resp.body()); // must be a JSON object, otherwise block
            out.print(resp.body());
            return 0;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            err.println("ActionGate hook interrupted. Blocked: fail closed.");
            return 2;
        } catch (IOException | RuntimeException e) {
            err.println("ActionGate is unavailable or returned an invalid response. Blocked: fail closed.");
            return 2;
        }
    }

    private static byte[] readLimited(InputStream in, int max) throws IOException {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            o.write(buf, 0, n);
            if (o.size() > max) throw new IOException("stdin too large");
        }
        return o.toByteArray();
    }
}
