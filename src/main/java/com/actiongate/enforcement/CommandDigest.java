package com.actiongate.enforcement;

import com.actiongate.model.CommandRequest;
import com.actiongate.util.Hashing;

/** Canonical SHA-256 digest binding an approval to one exact operation (agent, tool, directory, session, command). */
public final class CommandDigest {
    private CommandDigest() {}

    public static String of(CommandRequest r) {
        StringBuilder sb = new StringBuilder("ActionGate-op-v1");
        field(sb, r.agentId());
        field(sb, r.toolName());
        field(sb, r.workingDirectory().strip());
        field(sb, r.sessionId());
        field(sb, r.canonicalCommand());
        return Hashing.sha256Hex(sb.toString());
    }

    private static void field(StringBuilder sb, String v) {
        sb.append('\n').append(v.length()).append(':').append(v);
    }
}
