package com.actiongate.integration;

import com.actiongate.model.ApprovalStatus;
import com.actiongate.model.CommandRequest;
import com.actiongate.model.EnforcementDecision;
import com.actiongate.model.InvalidRequestException;
import com.actiongate.policy.SecurityPolicy;
import com.actiongate.util.Json;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Adapter for Claude Code's documented PreToolUse hook: the hook command receives JSON on stdin
 * (tool_name, tool_input.command, cwd, session_id, ...) and answers with JSON
 * {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow|deny|ask", ...}} (exit 0)
 * or blocks with exit code 2 and a stderr message.
 */
public final class ClaudeCodeAdapter implements AgentAdapter {
    public static final String ID = "claude-code";
    private static final Set<String> SHELL_TOOLS = Set.of("Bash", "PowerShell");

    @Override
    public String agentId() { return ID; }

    @Override
    public Optional<CommandRequest> parse(String body) {
        Map<String, Object> root;
        try {
            root = Json.parseObject(body);
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException("Malformed hook payload");
        }
        Object ev = root.get("hook_event_name");
        if (ev != null && !"PreToolUse".equals(ev)) throw new InvalidRequestException("Unsupported hook event");
        String tool = Json.asString(root.get("tool_name"));
        if (tool == null) throw new InvalidRequestException("tool_name missing");
        if (!SHELL_TOOLS.contains(tool)) return Optional.empty();
        Map<String, Object> input = Json.asObject(root.get("tool_input"));
        if (input == null) throw new InvalidRequestException("tool_input missing");
        String command = Json.asString(input.get("command"));
        String cwd = Json.asString(root.get("cwd"));
        String session = Json.asString(root.get("session_id"));
        if (command == null) throw new InvalidRequestException("command missing");
        if (cwd == null) throw new InvalidRequestException("cwd missing");
        return Optional.of(new CommandRequest(UUID.randomUUID().toString(), ID, tool, command, cwd, session == null ? "" : session, null));
    }

    @Override
    public String allowResponse(EnforcementDecision d, SecurityPolicy policy) {
        boolean userApproved = d.approvalStatus() == ApprovalStatus.APPROVED;
        if (!userApproved && !policy.agent(ID).explicitAllowLowRisk()) return noOpinionResponse();
        return hookJson("allow", userApproved ? "Approved in ActionGate (" + d.assessment().level() + " risk)"
                : "Allowed by ActionGate policy (" + d.assessment().level() + " risk)");
    }

    @Override
    public String denyResponse(String reason) {
        return hookJson("deny", "ActionGate blocked this command: " + clean(reason));
    }

    @Override
    public String noOpinionResponse() { return "{}"; }

    private static String hookJson(String decision, String reason) {
        Map<String, Object> inner = new LinkedHashMap<>();
        inner.put("hookEventName", "PreToolUse");
        inner.put("permissionDecision", decision);
        inner.put("permissionDecisionReason", reason);
        Map<String, Object> outer = new LinkedHashMap<>();
        outer.put("hookSpecificOutput", inner);
        return Json.write(outer);
    }

    static String clean(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : (s == null ? "" : s).toCharArray()) {
            if (c >= 0x20 && c != 0x7f) sb.append(c);
            if (sb.length() >= 500) break;
        }
        return sb.toString();
    }
}
