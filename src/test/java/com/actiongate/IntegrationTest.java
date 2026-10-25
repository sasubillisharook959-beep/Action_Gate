package com.actiongate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.actiongate.enforcement.ApprovalResult;
import com.actiongate.enforcement.ApprovalService;
import com.actiongate.integration.AgentAdapter;
import com.actiongate.integration.ClaudeCodeAdapter;
import com.actiongate.integration.CopilotAdapter;
import com.actiongate.integration.LoopbackServer;
import com.actiongate.model.CommandRequest;
import com.actiongate.model.InvalidRequestException;
import com.actiongate.support.Fixtures;
import com.actiongate.util.Json;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class IntegrationTest {
    @TempDir Path dir;
    static final String TOKEN = "t0ken-t0ken-t0ken-t0ken-t0ken-t0ken-t0ken-t0ken";
    LoopbackServer server;
    Fixtures f;
    final AtomicInteger approvals = new AtomicInteger();
    final HttpClient http = HttpClient.newHttpClient();

    @BeforeEach
    void setUp() throws Exception {
        ApprovalService approve = r -> { approvals.incrementAndGet(); return ApprovalResult.approved(r.digest()); };
        f = new Fixtures(dir, approve);
        server = new LoopbackServer(0, TOKEN, Map.<String, AgentAdapter>of(
                ClaudeCodeAdapter.ID, new ClaudeCodeAdapter(), CopilotAdapter.ID, new CopilotAdapter()), f.service, f.policy);
        server.start();
    }

    @AfterEach
    void tearDown() {
        try {
            if (server != null) server.close();
        } finally {
            if (f != null) f.close();
        }
    }

    public static String payload(String tool, String command) {
        Map<String, Object> input = new java.util.LinkedHashMap<>();
        input.put("command", command);
        Map<String, Object> m = new java.util.LinkedHashMap<>();
        m.put("session_id", "abc123");
        m.put("hook_event_name", "PreToolUse");
        m.put("tool_name", tool);
        m.put("tool_input", input);
        m.put("cwd", Fixtures.CWD);
        return Json.write(m);
    }

    HttpResponse<String> post(String path, String body, String token) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.port() + path))
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (token != null) b.header("Authorization", "Bearer " + token);
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void adapterParsesDocumentedClaudeCodePayload() {
        ClaudeCodeAdapter a = new ClaudeCodeAdapter();
        CommandRequest r = a.parse(payload("Bash", "git status")).orElseThrow();
        assertEquals("git status", r.command());
        assertEquals("claude-code", r.agentId());
        assertEquals(Fixtures.CWD, r.workingDirectory());
        assertTrue(a.parse(payload("Write", "ignored")).isEmpty(), "non-shell tools are out of scope");
    }

    @Test
    void adapterRejectsMalformedPayloads() {
        ClaudeCodeAdapter a = new ClaudeCodeAdapter();
        for (String bad : new String[]{"", "not json", "[]", "{}", "{\"tool_name\":\"Bash\"}",
                "{\"tool_name\":\"Bash\",\"tool_input\":{},\"cwd\":\"C:\\\\\"}",
                "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"\"},\"cwd\":\"C:\\\\\"}",
                "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"ls\"}}",
                "{\"hook_event_name\":\"PostToolUse\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"ls\"},\"cwd\":\"C:\\\\\"}",
                "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"a\\u0000b\"},\"cwd\":\"C:\\\\\"}"}) {
            assertThrows(InvalidRequestException.class, () -> a.parse(bad), bad);
        }
        assertThrows(InvalidRequestException.class, () -> a.parse(payload("Bash", "x".repeat(CommandRequest.MAX_COMMAND_LENGTH + 1))));
    }

    @Test
    void requestValidation() {
        assertThrows(InvalidRequestException.class, () -> CommandRequest.create("bad agent!", "Bash", "ls", "C:\\", ""));
        assertThrows(InvalidRequestException.class, () -> CommandRequest.create("a", "Bash", "ls", "", ""));
        assertThrows(InvalidRequestException.class, () -> CommandRequest.create("a", "Bash", "   ", "C:\\", ""));
        assertThrows(InvalidRequestException.class, () -> new CommandRequest("short", "a", "Bash", "ls", "C:\\", "", null));
    }

    @Test
    void endpointRequiresTheBearerToken() throws Exception {
        assertEquals(401, post("/v1/evaluate/claude-code", payload("Bash", "git status"), null).statusCode());
        assertEquals(401, post("/v1/evaluate/claude-code", payload("Bash", "git status"), "wrong").statusCode());
        assertEquals(401, post("/v1/evaluate/claude-code", payload("Bash", "git status"), TOKEN + "x").statusCode());
        assertEquals(0, approvals.get());
    }

    @Test
    void endpointRejectsBrowserOriginsBadHostsAndWrongMethods() throws Exception {
        HttpRequest withOrigin = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.port() + "/v1/evaluate/claude-code"))
                .header("Authorization", "Bearer " + TOKEN).header("Origin", "http://evil.example")
                .POST(HttpRequest.BodyPublishers.ofString(payload("Bash", "ls"))).build();
        assertEquals(403, http.send(withOrigin, HttpResponse.BodyHandlers.ofString()).statusCode());
        HttpRequest get = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.port() + "/v1/evaluate/claude-code"))
                .header("Authorization", "Bearer " + TOKEN).GET().build();
        assertEquals(405, http.send(get, HttpResponse.BodyHandlers.ofString()).statusCode());
        try (Socket s = new Socket(InetAddress.getByAddress(new byte[]{127, 0, 0, 1}), server.port())) {
            OutputStream o = s.getOutputStream();
            o.write(("GET /v1/health HTTP/1.1\r\nHost: evil.example\r\nAuthorization: Bearer " + TOKEN + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            o.flush();
            InputStream in = s.getInputStream();
            String resp = new String(in.readAllBytes(), StandardCharsets.US_ASCII);
            assertTrue(resp.startsWith("HTTP/1.1 403"), resp);
        }
        assertEquals(404, post("/v1/evaluate/other-agent", payload("Bash", "ls"), TOKEN).statusCode());
    }

    @Test
    void endpointOnlyListensOnLoopback() {
        assertEquals("127.0.0.1", server.address().getAddress().getHostAddress());
    }

    @Test
    void malformedAndOversizedBodiesAreRejected() throws Exception {
        assertEquals(400, post("/v1/evaluate/claude-code", "{nope", TOKEN).statusCode());
        assertEquals(400, post("/v1/evaluate/claude-code", "{}", TOKEN).statusCode());
        assertEquals(413, post("/v1/evaluate/claude-code", "x".repeat(1_100_000), TOKEN).statusCode());
    }

    @Test
    void lowRiskIsNoOpinionByDefaultSoTheAgentKeepsItsOwnRules() throws Exception {
        HttpResponse<String> r = post("/v1/evaluate/claude-code", payload("Bash", "git status"), TOKEN);
        assertEquals(200, r.statusCode());
        assertEquals("{}", r.body());
    }

    @Test
    void approvedOperationIsAnExplicitAllow() throws Exception {
        HttpResponse<String> r = post("/v1/evaluate/claude-code", payload("Bash", "rm old.txt"), TOKEN);
        Map<String, Object> out = Json.asObject(Json.parseObject(r.body()).get("hookSpecificOutput"));
        assertEquals("allow", out.get("permissionDecision"));
        assertEquals(1, approvals.get());
    }

    @Test
    void blockedOperationGetsDenyAndNeverAllow() throws Exception {
        HttpResponse<String> r = post("/v1/evaluate/claude-code", payload("Bash", "rm -rf /"), TOKEN);
        Map<String, Object> out = Json.asObject(Json.parseObject(r.body()).get("hookSpecificOutput"));
        assertEquals("deny", out.get("permissionDecision"));
        assertTrue(((String) out.get("permissionDecisionReason")).startsWith("ActionGate blocked"));
        assertEquals(0, approvals.get());
    }

    @Test
    void nonShellToolsGetNoOpinion() throws Exception {
        assertEquals("{}", post("/v1/evaluate/claude-code", payload("Read", "x"), TOKEN).body());
    }

    @Test
    void auditLogRecordsEndpointDecisions() throws Exception {
        post("/v1/evaluate/claude-code", payload("Bash", "rm -rf /"), TOKEN);
        post("/v1/evaluate/claude-code", payload("Bash", "git status"), TOKEN);
        assertEquals(2, f.audit.count());
        assertTrue(f.audit.verify().valid());
        assertFalse(f.audit.recent(2).get(1).decision().equals("ALLOW"));
    }
}
