package com.actiongate.hook;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.actiongate.enforcement.ApprovalResult;
import com.actiongate.integration.AgentAdapter;
import com.actiongate.integration.ClaudeCodeAdapter;
import com.actiongate.integration.LoopbackServer;
import com.actiongate.security.IpcCredentials;
import com.actiongate.support.Fixtures;
import com.actiongate.util.Json;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** End-to-end through the real hook client, the real loopback server and the real enforcement pipeline. */
class ClaudeCodeHookTest {
    @TempDir Path dir;

    private static String payload(String cmd) {
        return com.actiongate.IntegrationTest.payload("Bash", cmd);
    }

    private int runHook(String stdin, Path ipc, ByteArrayOutputStream out, ByteArrayOutputStream err) {
        return ClaudeCodeHook.run(new ByteArrayInputStream(stdin.getBytes(StandardCharsets.UTF_8)),
                new PrintStream(out, true, StandardCharsets.UTF_8), new PrintStream(err, true, StandardCharsets.UTF_8), ipc);
    }

    @Test
    void failsClosedWhenActionGateIsNotRunning() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int code = runHook(payload("git status"), dir.resolve("missing-ipc.json"), out, err);
        assertEquals(2, code);
        assertEquals(0, out.size());
        assertTrue(err.toString(StandardCharsets.UTF_8).contains("fail closed"));
    }

    @Test
    void failsClosedWhenEndpointIsStaleOrBroken() throws Exception {
        Path ipc = dir.resolve("ipc.json");
        Files.writeString(ipc, "{\"port\": 1, \"token\": \"x\", \"approvalTimeoutSeconds\": 10}");
        assertEquals(2, runHook(payload("git status"), ipc, new ByteArrayOutputStream(), new ByteArrayOutputStream()));
        Files.writeString(ipc, "garbage");
        assertEquals(2, runHook(payload("git status"), ipc, new ByteArrayOutputStream(), new ByteArrayOutputStream()));
    }

    @Test
    void fullPipelineAllowDenyAndBadToken() throws Exception {
        Fixtures f = new Fixtures(dir, r -> ApprovalResult.approved(r.digest()));
        try (f) {
            IpcCredentials creds = IpcCredentials.generate(0);
            try (LoopbackServer s = new LoopbackServer(0, creds.token(), Map.<String, AgentAdapter>of("claude-code", new ClaudeCodeAdapter()), f.service, f.policy)) {
                s.start();
                Path ipc = dir.resolve("ipc.json");
                creds.publishWithPort(ipc, s.port(), 30);

                ByteArrayOutputStream out = new ByteArrayOutputStream();
                assertEquals(0, runHook(payload("rm old.txt"), ipc, out, new ByteArrayOutputStream()));
                assertEquals("allow", Json.asObject(Json.parseObject(out.toString(StandardCharsets.UTF_8)).get("hookSpecificOutput")).get("permissionDecision"));

                out = new ByteArrayOutputStream();
                assertEquals(0, runHook(payload("rm -rf /"), ipc, out, new ByteArrayOutputStream()));
                assertEquals("deny", Json.asObject(Json.parseObject(out.toString(StandardCharsets.UTF_8)).get("hookSpecificOutput")).get("permissionDecision"));

                out = new ByteArrayOutputStream();
                assertEquals(2, runHook("{broken", ipc, out, new ByteArrayOutputStream()), "invalid payload must block, not pass");

                IpcCredentials other = IpcCredentials.generate(0);
                other.publishWithPort(ipc, s.port(), 30);
                assertEquals(2, runHook(payload("git status"), ipc, new ByteArrayOutputStream(), new ByteArrayOutputStream()), "wrong token must block");
            }
        }
    }
}
