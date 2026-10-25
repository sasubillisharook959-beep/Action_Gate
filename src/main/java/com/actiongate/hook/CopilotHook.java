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
import java.util.LinkedHashMap;
import java.util.Map;

/** GitHub Copilot preToolUse command hook; forwards the event to the authenticated local ActionGate server. */
public final class CopilotHook {
    private CopilotHook() {}

    public static void main(String[] args) {
        try {
            run(System.in, System.out, System.err, AppPaths.defaultPaths().ipcFile());
        } catch (Throwable t) {
            deny(System.out, System.err, "ActionGate hook failed unexpectedly.");
        }
        System.out.flush();
        System.err.flush();
    }

    static int run(InputStream in, PrintStream out, PrintStream err, Path ipcFile) {
        try {
            byte[] body = readLimited(in, 1_048_576);
            if (!Files.exists(ipcFile)) return deny(out, err, "ActionGate is not running.");
            Map<String, Object> ipc = Json.parseObject(Files.readString(ipcFile, StandardCharsets.UTF_8));
            Object portValue = ipc.get("port");
            String token = Json.asString(ipc.get("token"));
            if (!(portValue instanceof Number portNumber) || portNumber.intValue() < 1 || portNumber.intValue() > 65535
                    || token == null || token.isBlank()) {
                return deny(out, err, "ActionGate endpoint credentials are invalid.");
            }
            int approvalTimeout = ipc.get("approvalTimeoutSeconds") instanceof Number n ? n.intValue() : 120;
            HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
            HttpRequest request = HttpRequest.newBuilder(URI.create(
                            "http://127.0.0.1:" + portNumber.intValue() + "/v1/evaluate/github-copilot"))
                    .timeout(Duration.ofSeconds(Math.max(30, approvalTimeout + 60L)))
                    .header("Authorization", "Bearer " + token)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() != 200) {
                err.println("ActionGate endpoint returned HTTP status " + response.statusCode() + ".");
                return deny(out, err, "ActionGate rejected or could not process the request.");
            }

            Map<String, Object> result = Json.parseObject(response.body());
            if (result.isEmpty()) {
                out.print("{}");
                return 0;
            }
            String decision = Json.asString(result.get("permissionDecision"));
            if (!"allow".equals(decision) && !"deny".equals(decision))
                return deny(out, err, "ActionGate returned an invalid decision.");
            out.print(response.body());
            return 0;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return deny(out, err, "ActionGate request was interrupted.");
        } catch (IOException | RuntimeException e) {
            return deny(out, err, "ActionGate is unavailable or returned an invalid response.");
        }
    }

    private static int deny(PrintStream out, PrintStream err, String reason) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("permissionDecision", "deny");
        response.put("permissionDecisionReason", reason);
        err.println(reason);
        out.print(Json.write(response));
        return 0;
    }

    private static byte[] readLimited(InputStream in, int max) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int count;
        while ((count = in.read(buffer)) > 0) {
            out.write(buffer, 0, count);
            if (out.size() > max) throw new IOException("stdin too large");
        }
        return out.toByteArray();
    }

}
