# Testing

```powershell
mvn test
```
Automated (JUnit 5, no real destructive commands: commands are only analysed as strings; the execution boundary is a recording fake; tests use temp directories):
risk classification (safe/destructive/chained/obfuscated/malformed/ambiguous), policy evaluation and validation, approval matching and invalidation, single-use/expiry,
duplicate requests, biometric failure/cancel/timeout/unavailable, fail-closed paths, blocked commands never reaching the boundary, audit chain + tamper/deletion/truncation,
SQLite persistence, redaction, loopback authentication/Host/Origin/size checks, adapter validation, and an end-to-end run of the real hook client against the real server.
The mock authentication provider lives only under `src/test` and is refused by the production `EnforcementService`.

## Manual tests that need Windows
1. Windows Hello set up (PIN/face/fingerprint). Start ActionGate: *Authentication* card shows "Windows Hello ready".
2. Hook installed; in Claude Code ask it to run `git push --force origin main` in a scratch repo: approval dialog -> Approve -> Windows prompt -> success -> Claude Code receives `allow`.
3. Cancel the Windows prompt: command denied, audit shows `CANCELLED`.
4. Disable Hello / use a machine without it: HIGH-risk commands are denied (default policy).
5. Quit ActionGate, run any shell command in Claude Code: it must be blocked (fail closed).
6. Audit history tab -> *Verify integrity* shows intact; edit a row with a SQLite tool and verify again: failure reported.
