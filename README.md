# ActionGate

A Java 21 / JavaFX desktop security layer that checks terminal commands proposed by an AI coding agent **before they execute**.
Reference integration: **Claude Code** (its documented `PreToolUse` hook). Other agents need their own adapter (see `docs/AGENT_INTEGRATION.md`).

Every proposed command is analysed, matched against a policy and then **allowed**, **blocked**, or sent for **explicit approval** (with
optional **Windows Hello** verification). Every decision goes into a **hash-chained SQLite audit log**.

```
Agent proposes command -> hook (java -jar actiongate-hook.jar) -> 127.0.0.1 token-authenticated endpoint
  -> risk engine -> policy -> [approval dialog -> Windows Hello] -> digest re-check -> decision -> audit -> agent gets allow/deny
```

## Quick start (Windows, PowerShell, VS Code terminal)
```powershell
java -version        # needs 21+
mvn -version         # needs 3.9+
mvn clean verify     # compiles, runs all tests, builds target\actiongate-1.0.0.jar and target\actiongate-1.0.0-hook.jar
mvn javafx:run       # starts the dashboard
```
Then register the hook (Agent integration tab shows the exact snippet) in `%USERPROFILE%\.claude\settings.json`. Details: `docs/INSTALLATION.md`.

## What it does / does not do
* Does: structured command analysis, policy enforcement before execution, exact-operation approvals, fail-closed behaviour, tamper-evident audit.
* Does **not**: sandbox the agent, see commands the agent runs through tools you did not hook (Edit/Write tools, MCP tools), or understand what a script file does.
  Read `docs/SECURITY.md` for residual risks before relying on it.

Docs: `docs/ARCHITECTURE.md`, `SECURITY.md`, `INSTALLATION.md`, `TESTING.md`, `AGENT_INTEGRATION.md`.
