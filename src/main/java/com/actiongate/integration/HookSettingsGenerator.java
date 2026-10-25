package com.actiongate.integration;

import com.actiongate.util.Json;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Produces user settings snippets that register ActionGate's agent hooks. */
public final class HookSettingsGenerator {
    private HookSettingsGenerator() {}

    /** Best-effort location of the hook jar next to the main jar (target/actiongate-1.0.0-hook.jar). */
    public static Path locateHookJar() {
        try {
            Path code = Path.of(HookSettingsGenerator.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            if (code.toString().endsWith(".jar")) {
                String n = code.getFileName().toString().replace(".jar", "-hook.jar");
                return code.resolveSibling(n).toAbsolutePath();
            }
            return code.getParent().resolve("actiongate-1.0.0-hook.jar").toAbsolutePath();
        } catch (URISyntaxException | RuntimeException e) {
            return Path.of("target", "actiongate-1.0.0-hook.jar").toAbsolutePath();
        }
    }

    public static String snippet(Path hookJar, int approvalTimeoutSeconds) {
        Map<String, Object> hook = new LinkedHashMap<>();
        hook.put("type", "command");
        hook.put("command", "java -jar \"" + hookJar + "\"");
        hook.put("timeout", approvalTimeoutSeconds + 90);
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("matcher", "Bash|PowerShell");
        entry.put("hooks", List.of(hook));
        Map<String, Object> hooks = new LinkedHashMap<>();
        hooks.put("PreToolUse", List.of(entry));
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("hooks", hooks);
        return Json.writePretty(root);
    }

    public static String copilotSnippet(Path hookJar, int approvalTimeoutSeconds) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("type", "command");
        entry.put("command", "java -jar \"" + hookJar + "\" copilot");
        entry.put("timeoutSec", approvalTimeoutSeconds + 90);
        Map<String, Object> hooks = new LinkedHashMap<>();
        hooks.put("preToolUse", List.of(entry));
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("version", 1);
        root.put("hooks", hooks);
        return Json.writePretty(root);
    }
}
