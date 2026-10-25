package com.actiongate.hook;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.actiongate.enforcement.ApprovalResult;
import com.actiongate.integration.AgentAdapter;
import com.actiongate.integration.CopilotAdapter;
import com.actiongate.integration.HookSettingsGenerator;
import com.actiongate.integration.LoopbackServer;
import com.actiongate.support.Fixtures;
import com.actiongate.util.Json;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CopilotHookTest {
    private static final String TOKEN = "copilot-test-token";
    @TempDir Path dir;
    private Fixtures fixtures;
    private LoopbackServer server;
    private Path ipcFile;

    @BeforeEach
    void setUp() throws Exception {
        fixtures = new Fixtures(dir, request -> ApprovalResult.approved(request.digest()));
        server = new LoopbackServer(0, TOKEN, Map.<String, AgentAdapter>of(CopilotAdapter.ID, new CopilotAdapter()),
                fixtures.service, fixtures.policy);
        server.start();
        ipcFile = dir.resolve("ipc.json");
        credentials(TOKEN);
    }

    @AfterEach
    void tearDown() {
        try {
            if (server != null) server.close();
        } finally {
            if (fixtures != null) fixtures.close();
        }
    }

    @Test
    void harmlessTerminalCommandReturnsNoOpinion() {
        Map<String, Object> response = invoke(event("runInTerminal", Map.of("command", "echo hello")));
        assertFalse(response.containsKey("permissionDecision"), response.toString());
    }

    @Test
    void dangerousTerminalCommandIsDenied() {
        Map<String, Object> response = invoke(event("runInTerminal", Map.of("command", "rm -rf /")));
        assertEquals("deny", response.get("permissionDecision"));
    }

    @Test
    void approvedCommandReturnsCopilotAllowFormat() {
        Map<String, Object> response = invoke(event("runInTerminal", Map.of("command", "rm old.txt")));
        assertEquals("allow", response.get("permissionDecision"));
        assertTrue(response.containsKey("permissionDecisionReason"));
        assertFalse(response.containsKey("hookSpecificOutput"));
    }

    @Test
    void malformedJsonFailsClosed() {
        Map<String, Object> response = invoke("{broken");
        assertEquals("deny", response.get("permissionDecision"));
    }

    @Test
    void unrelatedToolsReceiveNoOpinion() {
        Map<String, Object> response = invoke(event("readFile", Map.of()));
        assertTrue(response.isEmpty(), response.toString());
    }

    @Test
    void missingTerminalArgumentsFailClosed() {
        Map<String, Object> response = invoke(event("runInTerminal", Map.of()));
        assertEquals("deny", response.get("permissionDecision"));
    }

    @Test
    void authenticationFailureFailsClosedWithoutExposingToken() {
        String presentedToken = "wrong-sensitive-test-token";
        String sensitiveCommand = "sensitive-command-test-value";
        credentials(presentedToken);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        CopilotHook.run(new ByteArrayInputStream(event("runInTerminal", Map.of("command", sensitiveCommand))
                        .getBytes(StandardCharsets.UTF_8)),
                new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8), ipcFile);
        String output = out.toString(StandardCharsets.UTF_8);
        String error = err.toString(StandardCharsets.UTF_8);
        assertEquals("deny", Json.parseObject(output).get("permissionDecision"));
        assertFalse(output.contains(TOKEN));
        assertTrue(error.contains("HTTP status 401"));
        assertFalse(error.contains(TOKEN));
        assertFalse(error.contains(presentedToken));
        assertFalse(error.contains(sensitiveCommand));
    }

    @Test
    void hookSnippetUsesCopilotPersonalHookProtocol() {
        String snippet = HookSettingsGenerator.copilotSnippet(Path.of("C:\\ActionGate\\actiongate-1.0.0-hook.jar"), 120);
        Map<String, Object> root = Json.parseObject(snippet);
        Map<String, Object> hooks = Json.asObject(root.get("hooks"));
        var preToolUse = Json.asArray(hooks.get("preToolUse"));
        Map<String, Object> entry = Json.asObject(preToolUse.get(0));
        assertEquals("command", entry.get("type"));
        assertEquals(210, ((Number) entry.get("timeoutSec")).intValue());
        assertTrue(((String) entry.get("command")).endsWith("\" copilot"));
    }

    private Map<String, Object> invoke(String body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int result = CopilotHook.run(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)),
                new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8), ipcFile);
        assertEquals(0, result);
        return Json.parseObject(out.toString(StandardCharsets.UTF_8));
    }

    private String event(String toolName, Map<String, Object> args) {
        return Json.write(Map.of("toolName", toolName, "toolArgs", args, "cwd", Fixtures.CWD, "sessionId", "copilot-test"));
    }

    private void credentials(String token) {
        Map<String, Object> document = Map.of("port", server.port(), "token", token, "approvalTimeoutSeconds", 120);
        try {
            java.nio.file.Files.writeString(ipcFile, Json.write(document), StandardCharsets.UTF_8);
        } catch (java.io.IOException e) {
            throw new AssertionError("Could not write test IPC credentials", e);
        }
    }
}
