package com.actiongate.model;

import java.time.Instant;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * A proposed terminal command, as reported by an agent's pre-execution hook.
 * Immutable and validated on construction. This object is data only: nothing in ActionGate executes it.
 */
public record CommandRequest(
        String requestId,
        String agentId,
        String toolName,
        String command,
        String workingDirectory,
        String sessionId,
        Instant receivedAt) {

    public static final int MAX_COMMAND_LENGTH = 16_384;
    public static final int MAX_PATH_LENGTH = 1_024;
    private static final Pattern ID = Pattern.compile("[A-Za-z0-9_.-]{1,64}");
    private static final Pattern REQ_ID = Pattern.compile("[A-Za-z0-9_-]{8,64}");

    public CommandRequest {
        if (requestId == null || !REQ_ID.matcher(requestId).matches())
            throw new InvalidRequestException("Invalid request id");
        if (agentId == null || !ID.matcher(agentId).matches())
            throw new InvalidRequestException("Invalid agent id");
        if (toolName == null || !ID.matcher(toolName).matches())
            throw new InvalidRequestException("Invalid tool name");
        if (command == null || command.isBlank())
            throw new InvalidRequestException("Command is empty");
        if (command.length() > MAX_COMMAND_LENGTH)
            throw new InvalidRequestException("Command exceeds " + MAX_COMMAND_LENGTH + " characters");
        for (int i = 0; i < command.length(); i++) {
            char c = command.charAt(i);
            if (c == 0 || (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f)
                throw new InvalidRequestException("Command contains control characters");
        }
        if (workingDirectory == null || workingDirectory.isBlank() || workingDirectory.length() > MAX_PATH_LENGTH)
            throw new InvalidRequestException("Invalid working directory");
        for (int i = 0; i < workingDirectory.length(); i++) {
            if (workingDirectory.charAt(i) < 0x20)
                throw new InvalidRequestException("Working directory contains control characters");
        }
        if (sessionId == null) sessionId = "";
        if (sessionId.length() > 128 || !sessionId.matches("[A-Za-z0-9_.:-]*"))
            throw new InvalidRequestException("Invalid session id");
        if (receivedAt == null) receivedAt = Instant.now();
    }

    public static CommandRequest create(String agentId, String toolName, String command, String cwd, String sessionId) {
        return new CommandRequest(UUID.randomUUID().toString(), agentId, toolName, command, cwd, sessionId, Instant.now());
    }

    /** Command with normalised line endings and surrounding whitespace removed. */
    public String canonicalCommand() {
        return command.replace("\r\n", "\n").replace('\r', '\n').strip();
    }
}
