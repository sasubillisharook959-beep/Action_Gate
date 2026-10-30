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
import java.util.UUID;

/** Adapter for GitHub Copilot's preToolUse hook event. */
public final class CopilotAdapter implements AgentAdapter {
    public static final String ID = "github-copilot";
    private static final String VS_CODE_TERMINAL_TOOL = "runInTerminal";
    private static final String CLI_TERMINAL_TOOL = "powershell";

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
        String tool = Json.asString(root.get("toolName"));
        if (tool == null) throw new InvalidRequestException("toolName missing");
              if (!VS_CODE_TERMINAL_TOOL.equals(tool)
                && !CLI_TERMINAL_TOOL.equals(tool)) {
            return Optional.empty();
        }

        Map<String, Object> args = Json.asObject(root.get("toolArgs"));
        if (args == null) throw new InvalidRequestException("toolArgs missing");
        String command = Json.asString(args.get("command"));
        String cwd = Json.asString(root.get("cwd"));
        if (command == null) throw new InvalidRequestException("toolArgs.command missing");
        if (cwd == null) throw new InvalidRequestException("cwd missing");
        String session = Json.asString(root.get("sessionId"));
        return Optional.of(new CommandRequest(UUID.randomUUID().toString(), ID, tool, command, cwd,
                session == null ? "" : session, null));
    }

    @Override
    public String allowResponse(EnforcementDecision decision, SecurityPolicy policy) {
        boolean userApproved = decision.approvalStatus() == ApprovalStatus.APPROVED;
        if (!userApproved && !policy.agent(ID).explicitAllowLowRisk()) return noOpinionResponse();
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("permissionDecision", "allow");
        response.put("permissionDecisionReason", userApproved
                ? "Approved in ActionGate (" + decision.assessment().level() + " risk)"
                : "Allowed by ActionGate policy (" + decision.assessment().level() + " risk)");
        return Json.write(response);
    }

    @Override
    public String denyResponse(String reason) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("permissionDecision", "deny");
        response.put("permissionDecisionReason", "ActionGate blocked this command: " + clean(reason));
        return Json.write(response);
    }

    @Override
    public String noOpinionResponse() { return "{}"; }

    private static String clean(String value) {
        StringBuilder result = new StringBuilder();
        for (char c : (value == null ? "" : value).toCharArray()) {
            if (c >= 0x20 && c != 0x7f) result.append(c);
            if (result.length() >= 500) break;
        }
        return result.toString();
    }
}
