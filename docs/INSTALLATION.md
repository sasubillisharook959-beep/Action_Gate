# Installation (Windows 10/11, VS Code)

## Prerequisites
| Tool | Version | Check |
|---|---|---|
| JDK | 21 LTS (Temurin etc.) | `java -version` |
| Maven | 3.9+ | `mvn -version` |
| VS Code | + "Extension Pack for Java" | |
| Windows Hello | optional, needed only for HIGH-risk verification | Settings > Accounts > Sign-in options |

Normal user rights are enough. **Do not run ActionGate as administrator.**

## Build and run (PowerShell)
```powershell
cd ActionGate
java -version
mvn -version
mvn clean verify          # build + unit tests + package (also copies runtime jars to target\lib)
mvn test                  # tests only
mvn javafx:run            # dashboard
java -cp "target\actiongate-1.0.0.jar;target\lib\*" com.actiongate.App --headless   # no UI; approvals are auto-denied
```
Packaging an .exe/.msi installer (`jpackage`) is not configured in this project; the jars above are the supported artefacts.
In VS Code: open the folder, use the *Maven* side bar (`javafx:run`) or the *Run* configuration "ActionGate (dashboard)"
(set `PATH_TO_FX` to a JavaFX SDK `lib` folder if you launch outside Maven).

## Data location
`%LOCALAPPDATA%\ActionGate\` holds `policy.json`, `actiongate.db`, `integrity.key`, `audit.checkpoint`, `ipc.json` (port + token, deleted on exit).
Override with `-Dactiongate.home=...` or env `ACTIONGATE_HOME`. This directory is always a protected path for the risk engine.

## Hook registration
See `AGENT_INTEGRATION.md`. ActionGate must be running; otherwise the hook blocks (fail closed).

## Alternative launch without the Maven plugin
After `mvn clean verify` all runtime jars (JavaFX, SQLite) are in `target\lib`:
```powershell
java --module-path target\lib --add-modules javafx.controls -cp "target\actiongate-1.0.0.jar;target\lib\*" com.actiongate.App
```
