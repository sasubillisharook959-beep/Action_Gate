package com.actiongate.integration;

import com.actiongate.enforcement.AuthorizedOperation;
import com.actiongate.enforcement.EnforcementService;
import com.actiongate.enforcement.ExecutionBoundary;
import com.actiongate.model.CommandRequest;
import com.actiongate.model.EnforcementDecision;
import com.actiongate.model.InvalidRequestException;
import com.actiongate.policy.PolicyHolder;
import com.actiongate.util.Hashing;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Loopback-only (127.0.0.1) authenticated endpoint used by the agent pre-execution hooks.
 * POST /v1/evaluate/{agentId}  with  Authorization: Bearer &lt;token&gt;.
 * It evaluates commands; it has no endpoint that executes anything.
 */
public final class LoopbackServer implements AutoCloseable {
    static final int MAX_BODY = 1_048_576;
    private final HttpServer server;
    private final ExecutorService pool;
    private final String token;
    private final int port;
    private final Map<String, AgentAdapter> adapters;
    private final EnforcementService enforcement;
    private final PolicyHolder policy;

    public LoopbackServer(int port, String token, Map<String, AgentAdapter> adapters, EnforcementService enforcement, PolicyHolder policy) throws IOException {
        this.token = token;
        this.adapters = Map.copyOf(adapters);
        this.enforcement = enforcement;
        this.policy = policy;
        InetAddress loopback = InetAddress.getByAddress(new byte[]{127, 0, 0, 1});
        this.server = HttpServer.create(new InetSocketAddress(loopback, port), 32);
        this.port = server.getAddress().getPort();
        this.pool = Executors.newFixedThreadPool(16, r -> {
            Thread t = new Thread(r, "actiongate-http");
            t.setDaemon(true);
            return t;
        });
        server.setExecutor(pool);
        server.createContext("/v1/evaluate/", this::handleEvaluate);
        server.createContext("/v1/health", this::handleHealth);
    }

    public int port() { return port; }

    public InetSocketAddress address() { return server.getAddress(); }

    public void start() { server.start(); }

    @Override
    public void close() {
        server.stop(0);
        pool.shutdownNow();
    }

    private boolean guard(HttpExchange ex, String method) throws IOException {
        String host = ex.getRequestHeaders().getFirst("Host");
        if (host == null || !(host.equals("127.0.0.1:" + port) || host.equals("localhost:" + port))) {
            send(ex, 403, "{\"error\":\"bad host\"}");
            return false;
        }
        if (ex.getRequestHeaders().containsKey("Origin") || ex.getRequestHeaders().containsKey("Sec-Fetch-Site")) {
            send(ex, 403, "{\"error\":\"browser requests are not accepted\"}");
            return false;
        }
        String auth = ex.getRequestHeaders().getFirst("Authorization");
        String presented = auth != null && auth.startsWith("Bearer ") ? auth.substring(7).trim() : "";
        if (!Hashing.constantTimeEquals(token, presented)) {
            try { Thread.sleep(150); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
            send(ex, 401, "{\"error\":\"unauthorized\"}");
            return false;
        }
        if (!ex.getRequestMethod().equals(method)) {
            send(ex, 405, "{\"error\":\"method not allowed\"}");
            return false;
        }
        return true;
    }

    private void handleHealth(HttpExchange ex) throws IOException {
        try (ex) {
            if (!guard(ex, "GET")) return;
            send(ex, 200, "{\"status\":\"ok\"}");
        }
    }

    private void handleEvaluate(HttpExchange ex) throws IOException {
        try (ex) {
            if (!guard(ex, "POST")) return;
            String path = ex.getRequestURI().getPath();
            String agentId = path.substring("/v1/evaluate/".length());
            AgentAdapter adapter = adapters.get(agentId);
            if (adapter == null) { send(ex, 404, "{\"error\":\"unknown agent\"}"); return; }
            String body;
            try {
                body = readBody(ex.getRequestBody());
            } catch (IOException e) {
                send(ex, 413, "{\"error\":\"body too large\"}");
                return;
            }
            Optional<CommandRequest> parsed;
            try {
                parsed = adapter.parse(body);
            } catch (InvalidRequestException e) {
                send(ex, 400, "{\"error\":\"invalid request\"}");
                return;
            }
            if (parsed.isEmpty()) { send(ex, 200, adapter.noOpinionResponse()); return; }

            AtomicReference<AuthorizedOperation> released = new AtomicReference<>();
            ExecutionBoundary boundary = (req, op) -> released.set(op);
            EnforcementDecision d = enforcement.process(parsed.get(), boundary);
            if (released.get() != null && d.allowed()) {
                send(ex, 200, adapter.allowResponse(d, policy.get()));
            } else {
                send(ex, 200, adapter.denyResponse(d.reason()));
            }
        } catch (RuntimeException e) {
            send(ex, 500, "{\"error\":\"internal error\"}");
        }
    }

    private static String readBody(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
            if (out.size() > MAX_BODY) throw new IOException("too large");
        }
        return out.toString(StandardCharsets.UTF_8);
    }

    private static void send(HttpExchange ex, int code, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(code, b.length);
        ex.getResponseBody().write(b);
    }
}
