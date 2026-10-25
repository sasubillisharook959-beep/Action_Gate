# Architecture

| Package | Responsibility |
|---|---|
| `ui` | JavaFX dashboard, approval dialog (`FxApprovalService`), observable state |
| `model` | Immutable data: `CommandRequest`, `RiskAssessment`, `EnforcementDecision`, enums |
| `risk` | `ShellParser` (quote-aware tokenizer), `RiskEngine` (rules), `PathUtil`, `SensitivePaths` |
| `policy` | `SecurityPolicy` (validated, immutable), `PolicyEngine`, `PolicyHolder` |
| `enforcement` | `EnforcementService` (pipeline), `CommandDigest`, `AuthorizedOperation`, `ApprovalService`, `ExecutionBoundary` |
| `authentication` | `AuthenticationProvider`, `WindowsHelloProvider` (+ PowerShell bridge), unavailable provider |
| `integration` | `AgentAdapter`, `ClaudeCodeAdapter`, `LoopbackServer`, settings generator |
| `hook` | `ClaudeCodeHook`: JDK-only hook client (separate jar) |
| `audit`, `storage` | Hash-chained SQLite audit log, redaction, JDBC wrapper |
| `configuration`, `security`, `util` | JSON policy I/O, IPC credentials, JSON/hash/file helpers |

## Enforcement flow
1. Hook posts the agent payload to `127.0.0.1:<port>/v1/evaluate/claude-code` with `Authorization: Bearer <token>`.
2. `LoopbackServer` checks Host, Origin, token, method, size; the adapter validates and builds an immutable `CommandRequest`.
3. `EnforcementService.evaluate`: digest -> `RiskEngine` -> `PolicyEngine`.
4. DENY -> audit -> deny response. ALLOW -> audit -> `AuthorizedOperation`. REQUIRE_APPROVAL -> `ApprovalService` (dialog) -> digest re-check -> Windows Hello if required -> audit.
5. Only `process()`/`release()` can call `ExecutionBoundary.release`, and only after consuming a valid, unexpired, single-use `AuthorizedOperation` whose digest matches the request. In production the boundary is the "allow" response; ActionGate never runs commands itself.
6. UI listeners are notified; failures in listeners never affect the decision.

Everything not explicitly allowed is denied: exceptions, audit-write failure, approval-service failure, mock auth in production, duplicate id with different content.

## Risk engine
Tokenise (quotes, `;` `&&` `||` `|` `&`, newlines, redirections, `$()`/backticks/process substitution) -> resolve wrappers (`sudo`, `env`, `cmd /c`, `powershell -Command/-EncodedCommand`, `bash -c`, `wsl`, `xargs` ...)
-> recursive analysis (depth 3) -> per-command rules (delete/move/write, git, package managers, network, disk, registry, services, credentials, tampering) -> path classification
(root/home, protected, secret files, outside working dir) -> highest level wins. Unparseable or dynamic constructs raise the level.
Levels: LOW / MEDIUM / HIGH / CRITICAL. Default policy: LOW allow, MEDIUM approval, HIGH approval + Windows Hello, CRITICAL blocked (cannot be changed).
Blocked categories (default) additionally deny HIGH+ rules in categories such as DOWNLOAD_EXEC, SECURITY_TAMPER, EXFILTRATION.

## Limitations of the risk engine
Static analysis of a string. It cannot see script contents, runtime variable values, aliases/functions defined elsewhere, or what a program does internally; unknown programs are MEDIUM, not safe.
It does not catch every malicious command; treat it as one layer.
