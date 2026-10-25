# Security notes

## Guarantees (and their conditions)
* A command matched by the configured hook is not released by ActionGate unless risk analysis, policy, approval and (if required) Windows Hello all pass; failures deny.
* Approvals bind to a SHA-256 digest of agent, tool, working directory, session and canonical command, are single-use and expire (default 60 s). A changed command needs a new approval.
* CRITICAL is always blocked; the policy validator rejects configs that unblock it, and rejects any attempt to configure enforcement off.
* The loopback endpoint binds to 127.0.0.1, requires a random 256-bit bearer token (constant-time compared, owner-only file), rejects wrong Host/Origin/oversize bodies, and has no execution endpoint.
* The hook fails closed (exit 2) when ActionGate is unreachable, slow, or answers badly.

## Windows Hello
Implemented with the WinRT `UserConsentVerifier` through a fixed, bundled script run in Windows PowerShell 5.1 (`powershell.exe`, script on stdin, prompt in an environment variable).
Windows shows the prompt and returns only an outcome; ActionGate stores no biometric data. Success is reported only for `Verified`.
Caveats: (1) `UserConsentVerifier` accepts the user's Hello PIN as well as face/fingerprint; apps cannot force biometrics only. (2) The prompt can appear behind other windows. (3) **Not tested on real Windows/Hello hardware in the build environment**: parsing and fail-closed logic are unit-tested with a fake runner; run the manual test in `TESTING.md`.

## Audit log
`hash = HMAC-SHA256(integrity.key, prev_hash || fields)`; a MAC-protected checkpoint file records the newest sequence/hash so tail truncation is detected. Detects modification, deletion, reordering, tail truncation.
**Does not stop** an attacker who can read `integrity.key` (same user account) from rewriting the database, the chain and the checkpoint together. For stronger protection keep the key/checkpoint on separately protected storage (another account, DPAPI-protected, or periodically export the latest hash to a remote/append-only place).
Command text is redacted for common secret patterns (best effort).

## Residual risks
* Same-user malware can read the token file, spoof requests (cannot self-approve), kill ActionGate (then the hook blocks) or edit the hook settings. Use user/managed settings and deny rules.
* Commands not routed through the hook (other tools, other terminals, MCP servers, scripts the agent writes and later runs: those are MEDIUM "unknown program" at best) are not covered.
* Risk analysis is heuristic (see ARCHITECTURE.md). Obfuscation not recognised can be under-rated.
* Approval dialog shows what was analysed; a very long command is shown in full but users may not read it.
* If `java` is missing/not on PATH for the hook, Claude Code treats the failure as non-blocking (exit 127): keep Java on PATH.
* Audit failure denies commands (fail closed), which can be an availability issue.
* Not a sandbox: an approved command runs with the agent's full privileges.
