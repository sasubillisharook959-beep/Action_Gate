# Agent integration

## Selected agent: Claude Code (PreToolUse hook)
Claude Code runs the configured hook command before a matching tool call. The command receives JSON on stdin
(`tool_name`, `tool_input.command`, `cwd`, `session_id`, `hook_event_name`). It answers with exit code **2** (block; stderr is shown to Claude)
or exit code **0** plus JSON `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow|deny|ask","permissionDecisionReason":"..."}}`.
**Any other exit code is a non-blocking error in Claude Code**, so ActionGate's hook exits only with 0 or 2 and always exits 2 on failure.

## Configure
1. `mvn clean verify` -> `target\actiongate-1.0.0-hook.jar`.
2. Add to `%USERPROFILE%\.claude\settings.json` (the dashboard's *Agent integration* tab prints this with your real path):
```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash|PowerShell",
        "hooks": [ { "type": "command", "command": "java -jar \"C:\\path\\to\\ActionGate\\target\\actiongate-1.0.0-hook.jar\"", "timeout": 210 } ] }
    ]
  }
}
```
`timeout` must be larger than ActionGate's approval timeout (default 120 s) plus margin.
3. Start ActionGate, start Claude Code, run `/hooks` to confirm the hook is loaded, then run a harmless command.

Prefer **user-level or managed** settings. A project-level `.claude/settings.json` can be edited by the agent itself.
Also add Claude Code permission deny rules for editing `~/.claude/settings.json`, `.claude/settings*.json` and ActionGate's directory.

## Response mapping
| ActionGate result | Hook output |
|---|---|
| Blocked / not approved / Hello failed | `deny` JSON + reason (exit 0) |
| Approved by the user (and Hello if required) | `allow` JSON |
| LOW risk | `{}` (no opinion: Claude Code's own permission rules still apply). Opt in to explicit `allow` per agent in the dashboard |
| Non-shell tool, wrong event | `{}` |
| ActionGate not running, bad token, timeout, malformed payload, HTTP error | exit 2 (block) |

## Status of this integration
Implemented against Claude Code's documented hook protocol and tested end-to-end here with the real hook jar and a Claude-Code-shaped payload.
**Not tested against a live Claude Code installation in the build environment.** Verify on your machine with `/hooks`.
Hooks cover only the tools matched (Bash/PowerShell). File-editing tools and MCP tools are outside ActionGate's view.

## GitHub Copilot in VS Code (preToolUse hook, Preview)
VS Code's Copilot harness supports command hooks from personal JSON files in `%USERPROFILE%\.copilot\hooks\` (or
`$COPILOT_HOME\hooks\` when `COPILOT_HOME` is set). For example, save this as
`%USERPROFILE%\.copilot\hooks\actiongate.json`, changing the jar path if needed:

```json
{
  "version": 1,
  "hooks": {
    "preToolUse": [
      {
        "type": "command",
        "command": "java -jar \"C:\\path\\to\\ActionGate\\target\\actiongate-1.0.0-hook.jar\" copilot",
        "timeoutSec": 210
      }
    ]
  }
}
```

The dashboard's Agent integration tab generates a snippet using the current approval timeout plus 90 seconds.
The Copilot adapter currently evaluates only `toolName: "runInTerminal"` events whose `toolArgs.command` is a string.
It requires the event's `cwd`; unknown tools return `{}` so the agent's normal permissions apply. The hook sends the
original event to `POST /v1/evaluate/github-copilot` with the bearer token from ActionGate's owner-only IPC file.
Responses use Copilot's top-level `permissionDecision` (`allow` or `deny`); LOW-risk commands return `{}` unless
explicit LOW-risk allow is enabled in policy.

VS Code documents hooks as Preview and states that a command-hook timeout falls through to normal permission
handling. The configured timeout is therefore a margin for ActionGate's approval prompt, not a guarantee that a
timed-out command is blocked. Start ActionGate, select the Copilot session target, inspect `/hooks`, and test a
harmless terminal command before relying on the integration. This installation has not been verified through a
live Copilot agent session.

## Adding another agent
Implement `AgentAdapter` (parse the agent's payload into a `CommandRequest`, format allow/deny), register it in `AppContext`, add an entry under `agents`
in `policy.json`, and provide that agent's pre-execution hook that calls `POST /v1/evaluate/<agentId>`. There is no universal hook; each agent
needs a documented pre-execution mechanism.
