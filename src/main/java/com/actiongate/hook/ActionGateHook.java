package com.actiongate.hook;

/** Dispatches the standalone hook jar to its backward-compatible Claude or Copilot entry point. */
public final class ActionGateHook {
    private ActionGateHook() {}

    public static void main(String[] args) {
        if (args.length == 0) {
            ClaudeCodeHook.main(args);
            return;
        }
        if (args.length == 1 && args[0].equals("copilot")) {
            CopilotHook.main(new String[0]);
            return;
        }
        System.err.println("Usage: java -jar actiongate-hook.jar [copilot]");
        Runtime.getRuntime().halt(2);
    }
}
