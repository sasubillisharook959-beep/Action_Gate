package com.actiongate.risk;

import static com.actiongate.model.RiskLevel.CRITICAL;
import static com.actiongate.model.RiskLevel.HIGH;
import static com.actiongate.model.RiskLevel.LOW;
import static com.actiongate.model.RiskLevel.MEDIUM;

import com.actiongate.model.CommandRequest;
import com.actiongate.model.MatchedRule;
import com.actiongate.model.RecommendedAction;
import com.actiongate.model.RiskAssessment;
import com.actiongate.model.RiskLevel;
import com.actiongate.policy.LevelRule;
import com.actiongate.policy.SecurityPolicy;
import com.actiongate.risk.ShellParser.Parsed;
import com.actiongate.risk.ShellParser.Redirect;
import com.actiongate.risk.ShellParser.Segment;
import com.actiongate.risk.ShellParser.Word;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Structured, rule-based command risk analysis.
 *
 * <p>The engine tokenizes the command (quotes, operators, redirection, substitutions), resolves the real executable
 * behind wrappers such as sudo/env/cmd /c/powershell -Command, recursively analyses nested commands, classifies
 * every path argument against the working directory, protected paths and secret-file patterns, and reports the
 * highest risk found. Anything it cannot parse or resolve raises the level (conservative by design).
 *
 * <p>LIMITATIONS: this is heuristic static analysis of a string. It cannot know what a script file does, what a
 * variable contains at run time, or what a program does internally. It does not identify every malicious command
 * and must be used as one layer of defence together with approval and least privilege.
 */
public final class RiskEngine {
    static final int MAX_DEPTH = 3;
    private final String home;

    public RiskEngine() {
        this(PathUtil.homeDir());
    }

    /** @param home normalised home directory, e.g. "c:/users/alice" (injectable for tests) */
    public RiskEngine(String home) {
        this.home = home;
    }

    public RiskAssessment analyze(CommandRequest req, SecurityPolicy policy) {
        Run run = new Run(req, policy);
        try {
            run.analyzeCommand(req.canonicalCommand(), 0);
        } catch (RuntimeException e) {
            run.ambiguous = true;
            run.add("ANALYSIS_ERROR", "AMBIGUOUS_COMMAND", HIGH, "Analysis failed internally; conservative policy applied");
        }
        return run.result();
    }

    // ---------------------------------------------------------------- vocabulary

    private static Set<String> set(String... s) { return Set.of(s); }

    private static final Set<String> DELETERS = set("rm", "del", "erase", "rmdir", "rd", "remove-item", "ri", "rimraf", "unlink");
    private static final Set<String> MOVERS_WRITERS = set("tee", "touch", "mkdir", "md", "new-item", "ni", "set-content",
            "add-content", "ac", "out-file", "truncate", "mv", "move", "ren", "rename", "move-item", "mi", "cp", "copy",
            "xcopy", "robocopy", "copy-item", "cpi", "install", "ln", "mklink", "chmod", "chown", "icacls", "takeown",
            "attrib", "rename-item", "rni", "cacls", "chgrp", "expand-archive", "tar", "unzip", "7z", "rsync", "dd");
    private static final Set<String> PRIV = set("sudo", "doas", "gsudo", "runas", "su", "pkexec", "psexec", "psexec64");
    private static final Set<String> SHELLS = set("bash", "sh", "zsh", "dash", "ksh", "fish", "csh", "tcsh");
    private static final Set<String> INTERPRETERS = set("bash", "sh", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "python",
            "python3", "py", "perl", "ruby", "node", "php", "pwsh", "powershell", "cmd", "iex", "invoke-expression", "lua",
            "deno", "osascript", "wscript", "cscript", "mshta");
    private static final Set<String> DOWNLOADERS = set("curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod",
            "start-bitstransfer", "bitsadmin", "aria2c", "fetch");
    private static final Set<String> DECODERS = set("base64", "xxd", "openssl", "certutil", "convertfrom-base64");
    private static final Set<String> NON_CONTENT = set("ls", "dir", "gci", "get-childitem", "tree", "test-path", "stat", "file",
            "pwd", "cd", "chdir", "pushd", "popd", "set-location", "sl", "where", "which", "gl", "get-location", "du");
    private static final Set<String> READONLY_VIEW = set("ls", "dir", "cat", "type", "head", "tail", "less", "more", "grep",
            "egrep", "fgrep", "rg", "findstr", "select-string", "sls", "get-content", "gc", "get-childitem", "gci", "wc",
            "stat", "file", "tree", "find", "git", "diff", "cmp", "echo");
    private static final Set<String> READONLY_SAFE = set("ls", "dir", "pwd", "cd", "chdir", "pushd", "popd", "echo", "printf",
            "cat", "type", "head", "tail", "wc", "grep", "egrep", "fgrep", "rg", "findstr", "select-string", "sls", "where",
            "which", "whoami", "hostname", "date", "tree", "stat", "file", "sort", "uniq", "diff", "cmp", "less", "more",
            "basename", "dirname", "get-childitem", "gci", "get-content", "gc", "get-location", "gl", "set-location", "sl",
            "test-path", "get-item", "gi", "write-output", "write-host", "true", "false", "sleep", "uname", "id", "realpath",
            "readlink", "du", "df", "ps", "tasklist", "ver", "get-date", "get-process", "get-command", "gcm", "select-object",
            "measure-object", "format-table", "ft", "cut", "tr", "jq", "awk", "sed", "nproc", "free", "uptime", "test", "[",
            "base64", "sha256sum", "md5sum", "shasum", "xxd", "od", "hexdump", "strings", "tsc", "eslint", "prettier", "javac", "pytest", "rustfmt", "gofmt", "clang-format", "start-sleep", "export",
            "set-strictmode", "clear", "cls", "history", "man", "help", "get-help");
    private static final Map<String, Set<String>> SAFE_SUB = Map.ofEntries(
            Map.entry("mvn", set("compile", "test", "verify", "package", "clean", "install", "-v", "--version", "validate",
                    "test-compile", "site", "dependency:tree", "help:effective-pom")),
            Map.entry("mvnw", set("compile", "test", "verify", "package", "clean", "install", "-v", "--version")),
            Map.entry("gradle", set("build", "test", "check", "clean", "assemble", "tasks", "--version", "-v", "classes")),
            Map.entry("gradlew", set("build", "test", "check", "clean", "assemble", "tasks", "--version", "-v", "classes")),
            Map.entry("npm", set("test", "t", "ls", "list", "outdated", "audit", "view", "info", "--version", "-v", "help", "pack", "explain", "why", "root", "prefix")),
            Map.entry("pnpm", set("test", "ls", "list", "outdated", "audit", "--version", "-v", "why")),
            Map.entry("yarn", set("test", "list", "outdated", "audit", "--version", "-v", "why", "info")),
            Map.entry("cargo", set("build", "check", "test", "fmt", "clippy", "doc", "--version", "-v", "tree", "bench")),
            Map.entry("go", set("build", "test", "vet", "fmt", "version", "env", "list")),
            Map.entry("dotnet", set("build", "test", "--version", "--info", "restore", "list", "--list-sdks")),
            Map.entry("node", set("--version", "-v")),
            Map.entry("python", set("--version", "-v")),
            Map.entry("python3", set("--version", "-v")),
            Map.entry("py", set("--version", "-v")),
            Map.entry("java", set("-version", "--version")),
            Map.entry("pip", set("list", "show", "freeze", "--version", "check", "help", "-v")),
            Map.entry("pip3", set("list", "show", "freeze", "--version", "check", "help")),
            Map.entry("code", set("--version", "-v")),
            Map.entry("docker", set("ps", "images", "version", "--version", "info", "logs", "inspect")));
    private static final Set<String> GIT_READ = set("status", "diff", "log", "show", "ls-files", "blame", "rev-parse", "describe",
            "shortlog", "rev-list", "ls-tree", "cat-file", "grep", "whatchanged", "version", "--version", "help", "add",
            "commit", "init", "fetch", "ls-remote", "show-ref", "diff-tree", "name-rev", "count-objects", "fsck", "remote");
    private static final Set<String> GIT_MODIFY = set("checkout", "switch", "restore", "stash", "merge", "pull", "cherry-pick",
            "revert", "rebase", "am", "apply", "clone", "submodule", "worktree", "mv", "rm", "bisect", "tag", "branch", "config",
            "reset", "clean", "push", "notes", "format-patch", "archive", "bundle", "sparse-checkout");
    private static final Set<String> SYSTEM_PM = set("winget", "choco", "scoop", "apt", "apt-get", "yum", "dnf", "brew", "pacman",
            "zypper", "apk", "snap", "nix-env", "port", "msiexec");
    private static final Set<String> NODE_PM = set("npm", "pnpm", "yarn", "bun");
    private static final Set<String> OTHER_PM = set("pip", "pip3", "pipx", "uv", "poetry", "conda", "mamba", "cargo", "go", "gem",
            "composer", "dotnet", "nuget", "bundle", "mix", "pub", "flutter", "dart", "swift", "cabal", "stack", "opam", "bower");
    private static final Pattern SECRET_VAR = Pattern.compile(
            "(?i)(\\$\\{?(env:)?\\w*(key|token|secret|passw(or)?d|credential|private)\\w*\\}?|%\\w*(key|token|secret|passw(or)?d|credential|private)\\w*%)");
    private static final Pattern URL = Pattern.compile("(?i)^[a-z][a-z0-9+.-]*://.*");
    private static final Pattern ASSIGN = Pattern.compile("^[A-Za-z_][A-Za-z0-9_]*=.*");
    private static final Pattern HIDDEN_CHARS = Pattern.compile("[\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2069\\uFEFF]");
    private static final Pattern INLINE_DANGER = Pattern.compile(
            "(?i)(os\\.system|subprocess|shutil\\.rmtree|os\\.remove|os\\.unlink|child_process|rmSync|rmdirSync|unlinkSync|fs\\.rm|"
                    + "exec\\(|spawn\\(|popen|rm -rf|remove-item|system\\(|eval\\(|urlopen|requests\\.|fetch\\()");

    // ---------------------------------------------------------------- run state

    private final class Run {
        final CommandRequest req;
        final SecurityPolicy policy;
        final List<MatchedRule> rules = new ArrayList<>();
        final Set<String> seen = new HashSet<>();
        final List<String> protectedNorm = new ArrayList<>();
        final List<String> downloaded = new ArrayList<>();
        final String projectRoot;
        String curDir;
        boolean curDirKnown = true;
        RiskLevel level = LOW;
        boolean ambiguous = false;
        boolean sawDownload = false;
        boolean execCapableSeen = false;

        Run(CommandRequest req, SecurityPolicy policy) {
            this.req = req;
            this.policy = policy;
            this.projectRoot = PathUtil.normalize(req.workingDirectory(), "/", home);
            this.curDir = projectRoot;
            for (String p : policy.protectedPaths()) protectedNorm.add(PathUtil.normalize(p, "/", home));
        }

        void add(String id, String category, RiskLevel lvl, String desc) {
            if (!seen.add(id + "|" + desc)) return;
            rules.add(new MatchedRule(id, category, lvl, desc));
            level = RiskLevel.max(level, lvl);
        }

        RiskAssessment result() {
            if (rules.isEmpty()) add("NO_RISK_INDICATORS", "NONE", LOW, "No risk indicators found");
            List<MatchedRule> sorted = new ArrayList<>(rules);
            sorted.sort(Comparator.comparing((MatchedRule r) -> r.level().ordinal()).reversed());
            StringBuilder ex = new StringBuilder();
            int shown = 0;
            for (MatchedRule r : sorted) {
                if (shown == 3) break;
                if (shown > 0) ex.append("; ");
                ex.append(r.description());
                shown++;
            }
            if (sorted.size() > shown) ex.append(" (+").append(sorted.size() - shown).append(" more indicators)");
            LevelRule lr = policy.levelRule(level);
            RecommendedAction act = lr.block() ? RecommendedAction.BLOCK
                    : lr.biometric() ? RecommendedAction.REQUIRE_BIOMETRIC
                    : lr.approval() ? RecommendedAction.REQUIRE_APPROVAL : RecommendedAction.ALLOW;
            return new RiskAssessment(level, ex.toString(), sorted, act, lr.approval() && !lr.block(),
                    lr.biometric() && !lr.block(), ambiguous);
        }

        // ------------------------------------------------------------ command level

        void analyzeCommand(String cmd, int depth) {
            if (depth > MAX_DEPTH) {
                ambiguous = true;
                add("NESTING_DEPTH", "AMBIGUOUS_COMMAND", HIGH, "Commands are nested too deeply to analyse");
                return;
            }
            if (HIDDEN_CHARS.matcher(cmd).find()) {
                ambiguous = true;
                add("HIDDEN_CHARACTERS", "OBFUSCATED_EXECUTION", HIGH, "Command contains invisible or bidirectional-control characters");
            }
            Parsed pc = ShellParser.parse(cmd);
            if (pc.malformed()) {
                ambiguous = true;
                add("PARSE_AMBIGUOUS", "AMBIGUOUS_COMMAND", HIGH, "Command could not be fully parsed (" + String.join(", ", pc.notes()) + ")");
            }
            if (pc.heredoc()) {
                ambiguous = true;
                add("HEREDOC", "AMBIGUOUS_COMMAND", MEDIUM, "Here-document content is only partially analysed");
            }
            List<Segment> segs = pc.segments();
            if (segs.size() > 1) add("CHAINED_COMMANDS", "CHAINING", LOW, "Command chains " + segs.size() + " operations; highest risk applies");
            boolean savedDownload = sawDownload;
            boolean savedExec = execCapableSeen;
            sawDownload = false;
            execCapableSeen = false;
            for (int i = 0; i < segs.size(); i++) {
                analyzeSegment(segs.get(i), i + 1 < segs.size() ? segs.get(i + 1) : null, depth);
            }
            if (sawDownload && execCapableSeen) {
                ambiguous = true;
                add("DOWNLOAD_EXEC_COMBINED", "DOWNLOAD_EXEC", CRITICAL, "Command both downloads content and evaluates text with eval/Invoke-Expression");
            }
            sawDownload = savedDownload || sawDownload;
            execCapableSeen = savedExec || execCapableSeen;
        }

        // ------------------------------------------------------------ segment level

        void analyzeSegment(Segment seg, Segment next, int depth) {
            int before = rules.size();
            boolean nestedDownload = false;
            for (String sub : seg.nested()) {
                add("COMMAND_SUBSTITUTION", "AMBIGUOUS_COMMAND", MEDIUM, "Contains command/process substitution (inner command analysed separately)");
                boolean saved = sawDownload;
                sawDownload = false;
                analyzeCommand(sub, depth + 1);
                nestedDownload |= sawDownload;
                sawDownload = saved || sawDownload;
            }
            List<Word> ws = new ArrayList<>(seg.words());
            while (!ws.isEmpty() && ASSIGN.matcher(ws.get(0).text()).matches() && !ws.get(0).variable()) ws.remove(0);
            analyzeRedirects(seg);
            if (ws.isEmpty()) {
                finish(before);
                return;
            }

            String exe = "";
            boolean dynamic = false;
            int guard = 0;
            while (!ws.isEmpty() && guard++ < 8) {
                Word ew = ws.get(0);
                exe = exeName(ew);
                if (ew.substitution() || ew.variable()) {
                    dynamic = true;
                    ambiguous = true;
                    add("DYNAMIC_EXECUTABLE", "AMBIGUOUS_COMMAND", HIGH, "Executable is built from a variable or substitution and cannot be determined");
                    break;
                }
                if (PRIV.contains(exe)) {
                    add("PRIVILEGE_ESCALATION", "PRIVILEGE_ESCALATION", HIGH, "Runs with elevated privileges (" + exe + ")");
                    ws.remove(0);
                    if (exe.equals("runas") || exe.equals("su") || exe.equals("pkexec") || exe.startsWith("psexec")) {
                        for (Word x : ws) if (x.text().indexOf(' ') >= 0) analyzeCommand(x.text(), depth + 1);
                        if (!exe.equals("runas") && !exe.equals("su")) { guard = 0; continue; }
                        finish(before);
                        return;
                    }
                    skipOptions(ws, set("-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-T", "-U", "--user", "--group", "--chdir"));
                    continue;
                }
                if (exe.equals("env")) {
                    ws.remove(0);
                    while (!ws.isEmpty() && (isFlag(ws.get(0)) || ASSIGN.matcher(ws.get(0).text()).matches())) {
                        Word f = ws.remove(0);
                        if ((f.text().equals("-u") || f.text().equals("-C") || f.text().equals("-S")) && !ws.isEmpty()) ws.remove(0);
                    }
                    if (ws.isEmpty()) {
                        add("ENV_DUMP", "CREDENTIAL_EXPOSURE", HIGH, "Prints the whole environment, which may contain secrets");
                    }
                    continue;
                }
                if (set("nohup", "time", "builtin", "exec", "call", "setsid", "ionice", "stdbuf", "nice", "timeout", "start",
                        "xargs", "wsl", "command", "chronic", "sg", "unbuffer").contains(exe)) {
                    ws.remove(0);
                    if (exe.equals("command") && !ws.isEmpty() && (ws.get(0).text().equals("-v") || ws.get(0).text().equals("-V"))) {
                        add("COMMAND_LOOKUP", "NONE", LOW, "Looks up a command name");
                        finish(before);
                        return;
                    }
                    if (exe.equals("xargs")) add("XARGS", "AMBIGUOUS_COMMAND", MEDIUM, "xargs runs a command on piped input whose targets are unknown");
                    stripWrapperArgs(exe, ws);
                    continue;
                }
                break;
            }
            if (ws.isEmpty()) {
                finish(before);
                return;
            }
            List<Word> args = new ArrayList<>(ws.subList(1, ws.size()));
            List<String> a = lower(args);
            if (exe.equals("iex") || exe.equals("invoke-expression") || exe.equals("eval")) execCapableSeen = true;
            if (!dynamic) downloadThenExec(ws.get(0), exe, args);

            if (!dynamic) {
                if (inlineExecution(exe, args, a, depth)) {
                    // handled via nested analysis
                } else {
                    dispatch(exe, args, a, seg, next, depth);
                }
                if (nestedDownload && (INTERPRETERS.contains(exe) || exe.equals("eval") || exe.equals("source") || exe.equals("."))) {
                    add("DOWNLOAD_EXEC_SUBST", "DOWNLOAD_EXEC", CRITICAL, "Executes content downloaded inside a substitution");
                }
                if (exe.equals("eval") || exe.equals("source") || exe.equals(".")) {
                    add("DYNAMIC_EVAL", "AMBIGUOUS_COMMAND", HIGH, "'" + exe + "' executes text that cannot be analysed statically");
                    ambiguous = true;
                }
            }
            scanArgs(exe, args, dynamic);
            tamperScan(exe, args);
            pipeRules(exe, a, seg, next);
            trackCd(exe, args);
            finish(before);
        }

        void downloadThenExec(Word exeWord, String exe, List<Word> args) {
            if (downloaded.isEmpty()) return;
            boolean runner = INTERPRETERS.contains(exe) || set("chmod", "start", "ii", "invoke-item", "rundll32", "regsvr32", "msiexec", "source", ".", "call").contains(exe);
            List<String> cands = new ArrayList<>();
            if (!exeWord.text().isEmpty() && (exeWord.text().indexOf('/') >= 0 || exeWord.text().indexOf('\\') >= 0 || exeWord.text().startsWith("."))) cands.add(exeWord.text());
            if (runner) for (Word w : args) if (!isFlag(w) && !w.text().isEmpty() && !URL.matcher(w.text()).matches()) cands.add(w.text());
            for (String c : cands) {
                if (PathUtil.hasUnresolved(c, home)) continue;
                if (downloaded.contains(PathUtil.normalize(c, curDir, home))) {
                    ambiguous = true;
                    add("DOWNLOAD_THEN_EXEC", "DOWNLOAD_EXEC", CRITICAL, "Runs a file that was downloaded earlier in the same command (" + c + ")");
                    return;
                }
            }
        }

        void finish(int before) {
            // no rule at all for this segment (e.g. only variable assignments): nothing to add
        }

        void skipOptions(List<Word> ws, Set<String> withValue) {
            while (!ws.isEmpty() && isFlag(ws.get(0))) {
                Word f = ws.remove(0);
                if (withValue.contains(f.text()) && !ws.isEmpty()) ws.remove(0);
            }
        }

        void stripWrapperArgs(String wrapper, List<Word> ws) {
            switch (wrapper) {
                case "timeout":
                    skipOptions(ws, set("-k", "-s", "--kill-after", "--signal"));
                    if (!ws.isEmpty()) ws.remove(0); // duration
                    break;
                case "nice":
                    skipOptions(ws, set("-n", "--adjustment"));
                    break;
                case "start":
                    while (!ws.isEmpty() && (ws.get(0).text().startsWith("/") && ws.get(0).text().length() <= 8 || isFlag(ws.get(0)))) ws.remove(0);
                    if (!ws.isEmpty() && ws.get(0).quoted() && ws.size() > 1) ws.remove(0);
                    break;
                case "xargs":
                    skipOptions(ws, set("-I", "-n", "-P", "-d", "-L", "-E", "-s", "-a"));
                    break;
                case "wsl":
                    skipOptions(ws, set("-d", "-u", "--distribution", "--user", "--cd"));
                    if (!ws.isEmpty() && ws.get(0).text().equals("--")) ws.remove(0);
                    break;
                case "ionice":
                    skipOptions(ws, set("-c", "-n", "-p"));
                    break;
                default:
                    skipOptions(ws, set());
            }
        }

        // ------------------------------------------------------------ names / flags

        String exeName(Word w) {
            String t = w.text();
            if (w.obfuscated()) {
                ambiguous = true;
                add("OBFUSCATED_EXECUTABLE", "OBFUSCATED_EXECUTION", HIGH, "Executable name is built with escape sequences");
            }
            String name = baseName(t);
            String stripped = t.replace("\\", "").replace("^", "").replace("\"", "");
            if (!stripped.equals(t)) {
                String cand = baseName(stripped);
                boolean known = DELETERS.contains(cand) || MOVERS_WRITERS.contains(cand) || PRIV.contains(cand) || SHELLS.contains(cand)
                        || DOWNLOADERS.contains(cand) || INTERPRETERS.contains(cand) || set("format", "diskpart", "shutdown", "reg", "sc", "net").contains(cand);
                if (known && !cand.equals(name)) {
                    ambiguous = true;
                    add("OBFUSCATED_EXECUTABLE", "OBFUSCATED_EXECUTION", HIGH, "Executable name uses escape characters to disguise '" + cand + "'");
                    return cand;
                }
            }
            return name;
        }

        String baseName(String t) {
            String n = t.toLowerCase(Locale.ROOT);
            int s = Math.max(n.lastIndexOf('/'), n.lastIndexOf('\\'));
            if (s >= 0) n = n.substring(s + 1);
            for (String ext : new String[]{".exe", ".cmd", ".bat", ".ps1", ".com", ".sh"}) {
                if (n.endsWith(ext) && n.length() > ext.length()) { n = n.substring(0, n.length() - ext.length()); break; }
            }
            return n;
        }

        boolean isFlag(Word w) {
            String t = w.text();
            return t.length() > 1 && t.charAt(0) == '-';
        }

        /** cmd.exe style flags like /s /q /y /a:h */
        boolean isCmdFlag(String t) {
            return t.matches("/[a-zA-Z?](:\\S*)?") ;
        }

        List<String> lower(List<Word> ws) {
            List<String> l = new ArrayList<>();
            for (Word w : ws) l.add(w.text().toLowerCase(Locale.ROOT));
            return l;
        }

        // ------------------------------------------------------------ inline shells

        boolean inlineExecution(String exe, List<Word> args, List<String> a, int depth) {
            if (SHELLS.contains(exe)) {
                for (int i = 0; i < a.size(); i++) {
                    String f = a.get(i);
                    if (f.startsWith("-") && !f.startsWith("--") && f.contains("c") && i + 1 < args.size()) {
                        add("SHELL_INLINE", "AMBIGUOUS_COMMAND", MEDIUM, "Runs an inline " + exe + " command (analysed recursively)");
                        analyzeCommand(args.get(i + 1).text(), depth + 1);
                        return true;
                    }
                }
                return false;
            }
            if (exe.equals("cmd")) {
                for (int i = 0; i < a.size(); i++) {
                    String f = a.get(i);
                    if (f.equals("/c") || f.equals("/k") || f.equals("/r")) {
                        add("SHELL_INLINE", "AMBIGUOUS_COMMAND", MEDIUM, "Runs an inline cmd.exe command (analysed recursively)");
                        StringBuilder sb = new StringBuilder();
                        for (int j = i + 1; j < args.size(); j++) sb.append(args.get(j).text()).append(' ');
                        analyzeCommand(sb.toString().trim(), depth + 1);
                        return true;
                    }
                }
                return false;
            }
            if (exe.equals("powershell") || exe.equals("pwsh")) {
                boolean handled = false;
                for (int i = 0; i < a.size(); i++) {
                    String f = a.get(i);
                    if (f.equals("-windowstyle") || f.equals("-w")) {
                        if (i + 1 < a.size() && a.get(i + 1).equals("hidden")) {
                            add("HIDDEN_WINDOW", "OBFUSCATED_EXECUTION", HIGH, "Runs PowerShell in a hidden window");
                        }
                    }
                    if (f.equals("-encodedcommand") || f.equals("-enc") || f.equals("-e") || f.equals("-ec")) {
                        ambiguous = true;
                        add("ENCODED_COMMAND", "OBFUSCATED_EXECUTION", HIGH, "PowerShell -EncodedCommand hides the real command");
                        if (i + 1 < args.size()) {
                            String decoded = decodeBase64Utf16(args.get(i + 1).text());
                            if (decoded == null) add("ENCODED_UNDECODABLE", "OBFUSCATED_EXECUTION", CRITICAL, "Encoded command could not be decoded");
                            else analyzeCommand(decoded, depth + 1);
                        }
                        handled = true;
                    } else if (f.equals("-command") || f.equals("-c") || f.equals("-commandwithargs")) {
                        add("SHELL_INLINE", "AMBIGUOUS_COMMAND", MEDIUM, "Runs an inline PowerShell command (analysed recursively)");
                        StringBuilder sb = new StringBuilder();
                        for (int j = i + 1; j < args.size(); j++) sb.append(args.get(j).text()).append(' ');
                        analyzeCommand(sb.toString().trim(), depth + 1);
                        handled = true;
                    } else if (f.equals("-file") || f.equals("-f")) {
                        add("SCRIPT_FILE", "UNKNOWN_COMMAND", MEDIUM, "Runs a PowerShell script file whose content is not analysed");
                        handled = true;
                    } else if (f.equals("-executionpolicy") || f.equals("-ep")) {
                        if (i + 1 < a.size() && (a.get(i + 1).equals("bypass") || a.get(i + 1).equals("unrestricted")))
                            add("EXECUTION_POLICY_BYPASS", "SECURITY_TAMPER", MEDIUM, "Bypasses the PowerShell execution policy");
                    }
                    if (handled) break;
                }
                return handled;
            }
            if (exe.equals("python") || exe.equals("python3") || exe.equals("py") || exe.equals("node") || exe.equals("perl")
                    || exe.equals("ruby") || exe.equals("php") || exe.equals("deno")) {
                for (int i = 0; i < a.size(); i++) {
                    String f = a.get(i);
                    boolean inline = f.equals("-c") || f.equals("-e") || f.equals("--eval") || f.equals("-p") || f.equals("-r");
                    if (inline && i + 1 < args.size()) {
                        String code = args.get(i + 1).text();
                        if (INLINE_DANGER.matcher(code).find()) {
                            add("INLINE_CODE_DANGEROUS", "AMBIGUOUS_COMMAND", HIGH, "Inline " + exe + " code calls process, network or file-removal APIs");
                            ambiguous = true;
                        } else {
                            add("INLINE_CODE", "UNKNOWN_COMMAND", MEDIUM, "Runs inline " + exe + " code");
                        }
                        return true;
                    }
                }
                if (a.size() >= 2 && a.get(0).equals("-m")) {
                    String mod = a.get(1);
                    if (mod.equals("pytest") || mod.equals("unittest")) {
                        add("TEST_RUNNER", "NONE", LOW, "Runs a test runner");
                        return true;
                    }
                    if (mod.equals("pip")) {
                        pipRule(args.subList(2, args.size()));
                        return true;
                    }
                    if (mod.equals("venv") || mod.equals("http.server")) {
                        add("PYTHON_MODULE", "UNKNOWN_COMMAND", MEDIUM, "Runs python -m " + mod);
                        return true;
                    }
                }
            }
            return false;
        }

        String decodeBase64Utf16(String b64) {
            try {
                byte[] raw = Base64.getDecoder().decode(b64.trim());
                String s = new String(raw, StandardCharsets.UTF_16LE);
                for (int i = 0; i < s.length(); i++) if (s.charAt(i) < 9) return null;
                return s;
            } catch (IllegalArgumentException e) {
                return null;
            }
        }

        // ------------------------------------------------------------ dispatch by executable

        void dispatch(String exe, List<Word> args, List<String> a, Segment seg, Segment next, int depth) {
            int before = rules.size();
            if (DELETERS.contains(exe)) deleteRule(exe, args, a);
            else if (MOVERS_WRITERS.contains(exe)) writeRule(exe, args, a);
            else if (exe.equals("sed") && hasAny(a, "-i", "--in-place") || exe.startsWith("sed") && a.stream().anyMatch(x -> x.startsWith("-i"))) writeRule(exe, args, a);
            else if (exe.equals("find")) findRule(args, a, depth);
            else if (DOWNLOADERS.contains(exe) || exe.equals("certutil") || exe.equals("scp") || exe.equals("nc") || exe.equals("ncat")
                    || exe.equals("netcat") || exe.equals("ssh") || exe.equals("ftp") || exe.equals("sftp") || exe.equals("telnet")) netRule(exe, args, a, next);
            else if (exe.equals("git")) gitRule(args, a);
            else if (NODE_PM.contains(exe) || exe.equals("npx") || exe.equals("bunx")) nodePmRule(exe, args, a);
            else if (exe.equals("pip") || exe.equals("pip3")) pipRule(args);
            else if (SYSTEM_PM.contains(exe)) systemPmRule(exe, a);
            else if (OTHER_PM.contains(exe)) otherPmRule(exe, a);
            else if (exe.equals("iex") || exe.equals("invoke-expression")) iexRule(args);
            else systemRule(exe, args, a);
            if (rules.size() == before) baseline(exe, args, a);
        }

        boolean hasAny(List<String> a, String... flags) {
            for (String f : flags) if (a.contains(f)) return true;
            return false;
        }

        void baseline(String exe, List<Word> args, List<String> a) {
            if (policy.trustedExecutables().contains(exe)) {
                add("TRUSTED_EXECUTABLE", "NONE", LOW, "'" + exe + "' is listed as trusted in the policy");
                return;
            }
            Set<String> safe = SAFE_SUB.get(exe);
            if (safe != null) {
                String sub = firstNonFlag(a);
                if (sub == null && a.isEmpty()) sub = "";
                boolean ok = (sub != null && safe.contains(sub)) || (a.size() == 1 && safe.contains(a.get(0)));
                if (ok) { add("KNOWN_SAFE_COMMAND", "NONE", LOW, "Known low-impact " + exe + " command"); return; }
                if (exe.equals("mvn") || exe.equals("mvnw") || exe.equals("gradle") || exe.equals("gradlew")) {
                    if (a.stream().anyMatch(x -> x.equals("deploy") || x.equals("publish") || x.equals("release:perform"))) {
                        add("PUBLISH", "PACKAGE_CHANGE", HIGH, "Publishes artifacts to a remote repository");
                        return;
                    }
                }
                add("PROJECT_SCRIPT", "UNKNOWN_COMMAND", MEDIUM, "Runs a project-defined task or an unclassified " + exe + " command");
                return;
            }
            if (READONLY_SAFE.contains(exe)) {
                if (exe.equals("awk") && a.stream().anyMatch(x -> x.contains("system(") || x.contains("| getline"))) {
                    add("AWK_EXEC", "AMBIGUOUS_COMMAND", MEDIUM, "awk program can run commands");
                    return;
                }
                add("KNOWN_SAFE_COMMAND", "NONE", LOW, "Read-only or low-impact command");
                return;
            }
            add("UNKNOWN_EXECUTABLE", "UNKNOWN_COMMAND", MEDIUM, "'" + exe + "' is not a recognised low-risk command; it may run arbitrary code");
        }

        String firstNonFlag(List<String> a) {
            for (String s : a) if (!s.startsWith("-")) return s;
            return null;
        }

        // ------------------------------------------------------------ path classification

        final class PathInfo {
            String norm;
            boolean wildcard, unresolved, rootLike, protectedHit, ancestorOfProtected, sensitive, outside, isCwd, isProjectRoot;
        }

        PathInfo classify(String raw) {
            PathInfo pi = new PathInfo();
            String r = raw;
            if (r.startsWith("@")) r = r.substring(1);
            int eq = r.indexOf('=');
            if (r.startsWith("--") && eq > 0) r = r.substring(eq + 1);
            pi.wildcard = PathUtil.hasWildcard(r);
            pi.unresolved = PathUtil.hasUnresolved(r, home) || !curDirKnown && !isAbsolute(r);
            String base = pi.wildcard ? PathUtil.wildcardDir(r) : r;
            pi.norm = PathUtil.normalize(base, curDir, home);
            pi.isCwd = pi.norm.equals(curDir);
            pi.isProjectRoot = pi.norm.equals(projectRoot);
            String homeN = PathUtil.normalize(home, "/", home);
            pi.rootLike = PathUtil.isRoot(pi.norm) || pi.norm.equals(homeN) || PathUtil.isInside(homeN, pi.norm);
            for (String p : protectedNorm) {
                if (PathUtil.isInside(pi.norm, p)) pi.protectedHit = true;
                else if (PathUtil.isInside(p, pi.norm)) pi.ancestorOfProtected = true;
            }
            pi.sensitive = SensitivePaths.isSensitive(pi.norm);
            pi.outside = !PathUtil.isInside(pi.norm, projectRoot);
            return pi;
        }

        boolean isAbsolute(String r) {
            String e = PathUtil.expandVars(r, home).replace('\\', '/');
            return e.startsWith("/") || e.startsWith("~") || e.matches("(?i)^[a-z]:.*");
        }

        List<Word> targets(String exe, List<Word> args) {
            List<Word> t = new ArrayList<>();
            boolean endOpts = false;
            boolean cmdStyle = set("del", "erase", "rd", "rmdir", "copy", "xcopy", "move", "ren", "rename", "robocopy", "attrib",
                    "icacls", "takeown", "cacls", "mklink", "md", "mkdir").contains(exe);
            for (Word w : args) {
                String s = w.text();
                if (!endOpts && s.equals("--")) { endOpts = true; continue; }
                if (!endOpts && isFlag(w)) {
                    int eq = s.indexOf('=');
                    if (s.startsWith("--") && eq > 0) t.add(new Word(s.substring(eq + 1), w.quoted(), w.substitution(), w.variable(), false));
                    continue;
                }
                if (!endOpts && cmdStyle && isCmdFlag(s)) continue;
                if (s.isEmpty() || URL.matcher(s).matches()) continue;
                t.add(w);
            }
            return t;
        }

        boolean recursive(String exe, List<String> a) {
            for (String f : a) {
                if (f.startsWith("--")) { if (f.equals("--recursive") || f.equals("--recurse")) return true; continue; }
                if (f.startsWith("-") && f.length() > 1) {
                    if (f.equals("-recurse") || f.equals("-r") && exe.equals("remove-item") || f.equals("-recursive")) return true;
                    if (!exe.equals("remove-item") && !exe.equals("ri") && f.substring(1).matches("[a-zA-Z]+") && (f.contains("r"))) return true;
                }
                if (f.equals("/s")) return true;
            }
            return exe.equals("rimraf");
        }

        // ------------------------------------------------------------ rules

        void deleteRule(String exe, List<Word> args, List<String> a) {
            boolean rec = recursive(exe, a);
            List<Word> tg = targets(exe, args);
            if (tg.isEmpty()) {
                add("DELETE_UNKNOWN_TARGET", "FILESYSTEM_CHANGE", HIGH, "Deletion with no explicit target (targets come from piped input or defaults)");
                return;
            }
            for (Word w : tg) {
                PathInfo pi = classify(w.text());
                if (pi.rootLike || pi.ancestorOfProtected) {
                    add("DELETE_ROOT_OR_HOME", "FILESYSTEM_DESTRUCTION", CRITICAL, "Deletes a drive root, home directory, system area or one of their parents (" + w.text() + ")");
                } else if (pi.protectedHit) {
                    add("DELETE_PROTECTED_PATH", "PROTECTED_PATH", CRITICAL, "Deletes inside a protected path (" + w.text() + ")");
                } else if (pi.unresolved || w.variable() || w.substitution()) {
                    ambiguous = true;
                    add("DELETE_UNRESOLVED_TARGET", "AMBIGUOUS_COMMAND", HIGH, "Deletion target depends on a variable or substitution (" + w.text() + ")");
                } else if (pi.sensitive) {
                    add("DELETE_SENSITIVE", "CREDENTIAL_EXPOSURE", HIGH, "Deletes a credential or secret file (" + w.text() + ")");
                } else if (pi.outside) {
                    add("DELETE_OUTSIDE_WORKDIR", "FILESYSTEM_CHANGE", HIGH, "Deletes outside the working directory (" + w.text() + ")");
                } else if (rec && (pi.wildcard || pi.isProjectRoot || pi.isCwd)) {
                    add("DELETE_RECURSIVE_WILDCARD", "FILESYSTEM_CHANGE", HIGH, "Recursive deletion of the whole working directory or a wildcard (" + w.text() + ")");
                } else if (rec) {
                    add("DELETE_RECURSIVE", "FILESYSTEM_CHANGE", MEDIUM, "Recursive deletion inside the working directory (" + w.text() + ")");
                } else {
                    add("DELETE_FILE", "FILESYSTEM_CHANGE", MEDIUM, "Deletes files (" + w.text() + ")");
                }
            }
        }

        void writeRule(String exe, List<Word> args, List<String> a) {
            if (exe.equals("dd")) {
                for (String x : a) {
                    if (x.startsWith("of=/dev/") || x.startsWith("of=\\\\.\\")) {
                        add("RAW_DEVICE_WRITE", "DISK_DESTRUCTION", CRITICAL, "dd writes to a raw device");
                        return;
                    }
                }
            }
            if (exe.equals("robocopy") && a.stream().anyMatch(x -> x.equals("/mir") || x.equals("/purge"))) {
                add("MIRROR_DELETES", "FILESYSTEM_CHANGE", HIGH, "robocopy /MIR or /PURGE deletes files at the destination");
            }
            boolean perms = set("chmod", "chown", "chgrp", "icacls", "takeown", "cacls", "attrib").contains(exe);
            boolean rec = recursive(exe, a) || a.contains("/t");
            List<Word> tg = targets(exe, args);
            if (tg.isEmpty() && !exe.equals("tee")) return;
            for (Word w : tg) {
                if (exe.equals("chmod") && w.text().matches("[0-7]{3,4}|[ugoa]*[+=-][rwxXst]+")) continue;
                if (exe.equals("chown") && w.text().matches("[\\w.-]*:[\\w.-]*|[\\w.-]+") && tg.indexOf(w) == 0) continue;
                PathInfo pi = classify(w.text());
                if (pi.protectedHit || pi.ancestorOfProtected && perms) {
                    add("WRITE_PROTECTED_PATH", "PROTECTED_PATH", CRITICAL, "Modifies a protected path (" + w.text() + ")");
                } else if (perms && (pi.rootLike)) {
                    add("PERMISSION_CHANGE_ROOT", "FILESYSTEM_DESTRUCTION", CRITICAL, "Changes permissions/ownership on a root or home directory (" + w.text() + ")");
                } else if (pi.unresolved || w.variable() || w.substitution()) {
                    ambiguous = true;
                    add("WRITE_UNRESOLVED_TARGET", "AMBIGUOUS_COMMAND", MEDIUM, "Write target depends on a variable or substitution (" + w.text() + ")");
                } else if (pi.sensitive) {
                    add("WRITE_SENSITIVE", "CREDENTIAL_EXPOSURE", HIGH, "Touches a credential or secret file (" + w.text() + ")");
                } else if (perms && (rec || pi.outside)) {
                    add("PERMISSION_CHANGE", "FILESYSTEM_CHANGE", HIGH, "Recursive or out-of-project permission/ownership change (" + w.text() + ")");
                } else if (pi.outside) {
                    add("WRITE_OUTSIDE_WORKDIR", "FILESYSTEM_WRITE", MEDIUM, "Writes outside the working directory (" + w.text() + ")");
                } else if (perms) {
                    add("PERMISSION_CHANGE_LOCAL", "FILESYSTEM_WRITE", MEDIUM, "Changes permissions inside the working directory");
                } else {
                    add("WRITE_IN_WORKDIR", "NONE", LOW, "Creates or modifies files inside the working directory");
                }
            }
        }

        void findRule(List<Word> args, List<String> a, int depth) {
            boolean del = a.contains("-delete");
            int exec = -1;
            for (int i = 0; i < a.size(); i++) if (a.get(i).equals("-exec") || a.get(i).equals("-execdir") || a.get(i).equals("-ok")) { exec = i; break; }
            List<Word> paths = new ArrayList<>();
            for (Word w : args) {
                String s = w.text();
                if (s.startsWith("-") || s.equals("(") || s.equals("!")) break;
                paths.add(w);
            }
            if (paths.isEmpty()) paths.add(new Word(".", false, false, false, false));
            if (del) {
                for (Word w : paths) {
                    PathInfo pi = classify(w.text());
                    if (pi.rootLike || pi.ancestorOfProtected || pi.protectedHit)
                        add("FIND_DELETE_ROOT", "FILESYSTEM_DESTRUCTION", CRITICAL, "find -delete over a root, home or protected path (" + w.text() + ")");
                    else add("FIND_DELETE", "FILESYSTEM_CHANGE", HIGH, "find -delete removes every match (" + w.text() + ")");
                }
            }
            if (exec >= 0) {
                StringBuilder sb = new StringBuilder();
                for (int j = exec + 1; j < args.size(); j++) {
                    String t = args.get(j).text();
                    if (t.equals(";") || t.equals("+")) break;
                    sb.append(t).append(' ');
                }
                add("FIND_EXEC", "AMBIGUOUS_COMMAND", MEDIUM, "find runs a command for each match (analysed recursively)");
                analyzeCommand(sb.toString().trim(), depth + 1);
            }
            if (!del && exec < 0) add("KNOWN_SAFE_COMMAND", "NONE", LOW, "Read-only find");
        }

        void netRule(String exe, List<Word> args, List<String> a, Segment next) {
            if (exe.equals("nc") || exe.equals("ncat") || exe.equals("netcat")) {
                if (a.stream().anyMatch(x -> x.equals("-e") || x.equals("-c") || x.contains("--exec") || x.equals("--sh-exec"))) {
                    add("REVERSE_SHELL", "DOWNLOAD_EXEC", CRITICAL, "netcat with command execution can create a remote shell");
                    return;
                }
                add("NETWORK_RAW", "NETWORK_ACCESS", HIGH, "Raw network connection");
                return;
            }
            if (set("ssh", "scp", "ftp", "sftp", "telnet").contains(exe)) {
                add("REMOTE_ACCESS", "NETWORK_ACCESS", HIGH, "Connects to or copies files to a remote host");
                return;
            }
            sawDownload = true;
            boolean certutilDownload = exe.equals("certutil") && (a.contains("-urlcache") || a.contains("-verifyctl") || a.contains("-decode") || a.contains("-decodehex"));
            if (exe.equals("certutil") && !certutilDownload) {
                add("KNOWN_SAFE_COMMAND", "NONE", LOW, "certutil without download/decode");
                sawDownload = false;
                return;
            }
            RiskLevel lvl = MEDIUM;
            String desc = "Network download or request";
            boolean upload = false;
            boolean uploadSensitive = false;
            for (int i = 0; i < args.size(); i++) {
                String t = a.get(i);
                String raw = args.get(i).text();
                boolean uploadFlag = t.equals("-d") || t.equals("--data") || t.equals("--data-binary") || t.equals("--data-raw")
                        || t.equals("-f") && exe.equals("curl") || t.equals("--form") || t.equals("-t") || t.equals("--upload-file")
                        || t.equals("--post-file") || t.equals("-infile") || t.equals("-body") || t.equals("-inputobject");
                String val = null;
                if (uploadFlag && i + 1 < args.size()) val = args.get(i + 1).text();
                if (t.startsWith("--data") && t.indexOf('=') > 0) val = raw.substring(raw.indexOf('=') + 1);
                if (val != null && (val.startsWith("@") || t.equals("-t") || t.equals("--upload-file") || t.equals("--post-file") || t.equals("-infile"))) {
                    upload = true;
                    PathInfo pi = classify(val.startsWith("@") ? val.substring(1) : val);
                    if (pi.sensitive || pi.protectedHit || pi.rootLike) uploadSensitive = true;
                }
                if (val != null && SECRET_VAR.matcher(val).find()) uploadSensitive = true;
                if ((t.equals("-o") || t.equals("--output") || t.equals("-outfile") || t.equals("-o")) && i + 1 < args.size()) {
                    PathInfo pi = classify(args.get(i + 1).text());
                    downloaded.add(pi.norm);
                    if (pi.protectedHit) add("DOWNLOAD_TO_PROTECTED", "PROTECTED_PATH", CRITICAL, "Downloads into a protected path");
                    else if (pi.outside) add("DOWNLOAD_OUTSIDE_WORKDIR", "FILESYSTEM_WRITE", HIGH, "Downloads a file outside the working directory");
                }
                if (exe.equals("wget") && (t.equals("-o") || raw.equals("-O")) && i + 1 < args.size()) {
                    downloaded.add(classify(args.get(i + 1).text()).norm);
                }
                if (raw.equals("-O") && exe.equals("curl")) { /* remote-name: file named by URL */ }
            }
            if (uploadSensitive) {
                add("EXFILTRATION", "EXFILTRATION", CRITICAL, "Sends a credential/secret file or secret value to a remote server");
                return;
            }
            if (upload || a.contains("-x") && exe.equals("curl") || a.contains("post") || a.contains("-method") && a.contains("post")) {
                lvl = HIGH;
                desc = "Uploads data or files to a remote server";
            }
            add("NET_DOWNLOAD", "NETWORK_ACCESS", lvl, desc);
        }

        void pipeRules(String exe, List<String> a, Segment seg, Segment next) {
            if (next == null || !seg.opAfter().equals("|")) return;
            String nextExe = peekExe(next);
            if (nextExe == null) return;
            boolean nextInterp = INTERPRETERS.contains(nextExe) || nextExe.equals("source") || nextExe.equals("eval");
            if (!nextInterp) return;
            boolean nextHasScript = false;
            for (Word w : next.words().subList(Math.min(1, next.words().size()), next.words().size())) {
                String t = w.text();
                if (!t.startsWith("-") && !t.isEmpty()) { nextHasScript = true; break; }
                if (t.equals("-c") || t.equals("-command")) { nextHasScript = true; break; }
            }
            boolean readsStdin = !nextHasScript || next.words().stream().anyMatch(w -> w.text().equals("-"));
            if (!readsStdin) return;
            if (DOWNLOADERS.contains(exe) || sawDownload && DOWNLOADERS.contains(exe)) {
                add("DOWNLOAD_PIPE_EXEC", "DOWNLOAD_EXEC", CRITICAL, "Downloads content and pipes it straight into an interpreter (" + nextExe + ")");
            } else if (DECODERS.contains(exe) && (hasAny(a, "-d", "--decode", "-decode", "-r", "-d")) || exe.equals("convertfrom-base64")) {
                ambiguous = true;
                add("DECODE_PIPE_EXEC", "OBFUSCATED_EXECUTION", CRITICAL, "Decodes content and pipes it into an interpreter (" + nextExe + ")");
            } else {
                ambiguous = true;
                add("PIPE_TO_INTERPRETER", "AMBIGUOUS_COMMAND", HIGH, "Pipes generated text into an interpreter (" + nextExe + "); the executed content cannot be analysed");
            }
        }

        String peekExe(Segment s) {
            List<Word> ws = new ArrayList<>(s.words());
            int g = 0;
            while (!ws.isEmpty() && g++ < 6) {
                String t = ws.get(0).text();
                String e = baseNameQuiet(t);
                if (ASSIGN.matcher(t).matches()) { ws.remove(0); continue; }
                if (PRIV.contains(e) || set("env", "nohup", "time", "command", "exec", "nice").contains(e)) {
                    ws.remove(0);
                    while (!ws.isEmpty() && (ws.get(0).text().startsWith("-") || ASSIGN.matcher(ws.get(0).text()).matches())) ws.remove(0);
                    continue;
                }
                return e;
            }
            return null;
        }

        String baseNameQuiet(String t) {
            return baseName(t.replace("\\", "/").contains("/") ? t : t.replace("\\", "").replace("^", ""));
        }

        void iexRule(List<Word> args) {
            StringBuilder sb = new StringBuilder();
            for (Word w : args) sb.append(w.text().toLowerCase(Locale.ROOT)).append(' ');
            String all = sb.toString();
            boolean dl = sawDownload || all.contains("iwr") || all.contains("irm") || all.contains("invoke-webrequest")
                    || all.contains("invoke-restmethod") || all.contains("downloadstring") || all.contains("curl") || all.contains("wget") || all.contains("http");
            if (dl) add("DOWNLOAD_EXEC_IEX", "DOWNLOAD_EXEC", CRITICAL, "Invoke-Expression on downloaded content");
            else add("INVOKE_EXPRESSION", "AMBIGUOUS_COMMAND", HIGH, "Invoke-Expression executes text that cannot be analysed statically");
            ambiguous = true;
        }

        void gitRule(List<Word> args, List<String> a) {
            for (int i = 0; i < a.size(); i++) {
                String t = a.get(i);
                if ((t.equals("-c") || t.startsWith("--config-env")) && i + 1 < a.size()) {
                    String v = a.get(i + 1);
                    if (v.contains("sshcommand") || v.contains("hookspath") || v.contains("editor") || v.contains("credential.helper")
                            || v.startsWith("alias.") || v.contains("ext.allow") || v.contains("pager") || v.contains("fsmonitor")) {
                        add("GIT_CODE_EXEC", "AMBIGUOUS_COMMAND", HIGH, "Git configuration override can execute arbitrary commands");
                    }
                }
                if (t.startsWith("--upload-pack") || t.startsWith("--receive-pack") || t.startsWith("--exec=")) {
                    add("GIT_CODE_EXEC", "AMBIGUOUS_COMMAND", HIGH, "Git option can execute arbitrary commands");
                }
            }
            String sub = null;
            int idx = -1;
            for (int i = 0; i < a.size(); i++) {
                String t = a.get(i);
                if (t.equals("-c") || t.equals("-C") || t.equals("--git-dir") || t.equals("--work-tree") || t.equals("--namespace")) { i++; continue; }
                if (t.startsWith("-")) continue;
                sub = t;
                idx = i;
                break;
            }
            if (sub == null) {
                add("GIT_READONLY", "NONE", LOW, "git without a modifying subcommand");
                return;
            }
            List<String> rest = a.subList(idx + 1, a.size());
            boolean force = rest.stream().anyMatch(x -> x.equals("-f") || x.equals("--force") || x.startsWith("--force-with-lease") || x.equals("--delete") || x.startsWith("+") || x.startsWith(":") && x.length() > 1);
            switch (sub) {
                case "push":
                    if (force) add("GIT_PUSH_FORCE", "FILESYSTEM_CHANGE", HIGH, "git push that can rewrite or delete remote history");
                    else add("GIT_PUSH", "NETWORK_ACCESS", MEDIUM, "git push sends commits to a remote");
                    break;
                case "reset":
                    if (rest.contains("--hard") || rest.contains("--merge")) add("GIT_RESET_HARD", "FILESYSTEM_CHANGE", HIGH, "git reset --hard discards uncommitted work");
                    else add("GIT_MODIFY", "NONE", MEDIUM, "git reset changes the index or HEAD");
                    break;
                case "clean":
                    if (rest.contains("-n") || rest.contains("--dry-run")) add("GIT_READONLY", "NONE", LOW, "git clean dry run");
                    else add("GIT_CLEAN", "FILESYSTEM_CHANGE", HIGH, "git clean deletes untracked files");
                    break;
                case "branch":
                    if (rest.contains("-d") && !rest.contains("--force") && !rest.contains("-D")) add("GIT_MODIFY", "NONE", MEDIUM, "Deletes a merged branch");
                    else if (rest.contains("-D") || rest.contains("--delete") || rest.contains("--force")) add("GIT_BRANCH_DELETE", "FILESYSTEM_CHANGE", HIGH, "Force-deletes a branch");
                    else if (rest.stream().anyMatch(x -> x.equals("-m") || x.equals("-M"))) add("GIT_MODIFY", "NONE", MEDIUM, "Renames a branch");
                    else add("GIT_READONLY", "NONE", LOW, "Lists or creates a branch");
                    break;
                case "config":
                    if (rest.contains("--global") || rest.contains("--system")) add("GIT_CONFIG_GLOBAL", "CONFIG_CHANGE", HIGH, "Changes global or system git configuration");
                    else if (rest.contains("--get") || rest.contains("--list") || rest.contains("-l") || rest.contains("--get-all"))
                        add("GIT_CONFIG_READ", "CREDENTIAL_EXPOSURE", MEDIUM, "Reading git configuration may reveal credentials");
                    else add("GIT_MODIFY", "NONE", MEDIUM, "Changes repository git configuration");
                    break;
                case "filter-branch": case "filter-repo": case "reflog": case "gc": case "prune":
                    add("GIT_HISTORY_REWRITE", "FILESYSTEM_CHANGE", HIGH, "git " + sub + " can permanently rewrite or delete history");
                    break;
                case "tag":
                    if (rest.contains("-d") || rest.contains("--delete") || rest.contains("-f")) add("GIT_MODIFY", "NONE", MEDIUM, "Deletes or moves a tag");
                    else add("GIT_READONLY", "NONE", LOW, "git tag");
                    break;
                case "remote":
                    if (rest.stream().anyMatch(x -> x.equals("add") || x.equals("set-url") || x.equals("remove") || x.equals("rm")))
                        add("GIT_MODIFY", "NONE", MEDIUM, "Changes git remotes");
                    else add("GIT_READONLY", "NONE", LOW, "Lists git remotes");
                    break;
                default:
                    if (GIT_READ.contains(sub)) add("GIT_READONLY", "NONE", LOW, "Low-impact git command (" + sub + ")");
                    else if (GIT_MODIFY.contains(sub)) add("GIT_MODIFY", "NONE", MEDIUM, "git " + sub + " modifies the working tree, history or remotes");
                    else add("GIT_UNKNOWN", "UNKNOWN_COMMAND", MEDIUM, "Unrecognised git subcommand '" + sub + "'");
            }
        }

        void nodePmRule(String exe, List<Word> args, List<String> a) {
            String sub = firstNonFlag(a);
            boolean global = a.contains("-g") || a.contains("--global") || a.contains("-global");
            if (exe.equals("npx") || exe.equals("bunx") || "dlx".equals(sub) || "exec".equals(sub) || "x".equals(sub) || "create".equals(sub)) {
                boolean remoteUrl = a.stream().anyMatch(x -> x.startsWith("http") || x.startsWith("git+") || x.contains("github:"));
                add("PACKAGE_RUN_REMOTE", "PACKAGE_CHANGE", remoteUrl ? HIGH : MEDIUM, "Downloads and runs a package from the registry" + (remoteUrl ? " via a URL or git source" : ""));
                return;
            }
            if (sub == null) {
                if (a.contains("--version") || a.contains("-v")) { add("KNOWN_SAFE_COMMAND", "NONE", LOW, "Version query"); return; }
                add("PACKAGE_UNKNOWN", "UNKNOWN_COMMAND", MEDIUM, "Unclassified " + exe + " command");
                return;
            }
            switch (sub) {
                case "install": case "i": case "add": case "update": case "upgrade": case "up": case "uninstall": case "remove": case "rm":
                case "ci": case "link": case "unlink": case "import": case "dedupe": case "rebuild":
                    if (global) add("PACKAGE_GLOBAL", "PACKAGE_CHANGE", HIGH, "Global package installation or removal");
                    else if (a.stream().anyMatch(x -> x.startsWith("http") || x.startsWith("git+") || x.contains("github:") || x.startsWith("--registry")))
                        add("PACKAGE_UNTRUSTED_SOURCE", "PACKAGE_CHANGE", HIGH, "Installs from a URL, git source or custom registry");
                    else add("PACKAGE_INSTALL", "PACKAGE_CHANGE", MEDIUM, "Installs or changes dependencies (runs lifecycle scripts)");
                    break;
                case "publish": case "login": case "adduser": case "token": case "owner": case "deprecate": case "unpublish":
                    add("PACKAGE_PUBLISH", "PACKAGE_CHANGE", HIGH, "Publishes or changes registry credentials/ownership");
                    break;
                case "config":
                    if (a.contains("set") || a.contains("delete")) add("PACKAGE_CONFIG", "CONFIG_CHANGE", HIGH, "Changes package manager configuration (registry, credentials)");
                    else add("PACKAGE_CONFIG_READ", "CREDENTIAL_EXPOSURE", MEDIUM, "Reads package manager configuration");
                    break;
                case "run": case "run-script": case "start": case "build": case "dev": case "serve": case "lint": case "format":
                    add("PROJECT_SCRIPT", "UNKNOWN_COMMAND", MEDIUM, "Runs a project-defined script (content not analysed)");
                    break;
                default:
                    Set<String> safe = SAFE_SUB.get(exe);
                    if (safe != null && safe.contains(sub)) add("KNOWN_SAFE_COMMAND", "NONE", LOW, "Known low-impact " + exe + " command");
                    else add("PACKAGE_UNKNOWN", "UNKNOWN_COMMAND", MEDIUM, "Unclassified " + exe + " command");
            }
        }

        void pipRule(List<Word> args) {
            List<String> a = lower(args);
            String sub = firstNonFlag(a);
            if (sub == null) { add("KNOWN_SAFE_COMMAND", "NONE", LOW, "pip without subcommand"); return; }
            switch (sub) {
                case "install": case "uninstall": case "download": case "wheel":
                    boolean untrusted = a.stream().anyMatch(x -> x.startsWith("--index-url") || x.equals("-i") || x.startsWith("--extra-index-url")
                            || x.startsWith("--trusted-host") || x.startsWith("git+") || x.startsWith("http") || x.equals("--break-system-packages")
                            || x.equals("--user") && false);
                    if (untrusted) add("PACKAGE_UNTRUSTED_SOURCE", "PACKAGE_CHANGE", HIGH, "pip installs from a URL, git source, custom index or overrides system protection");
                    else add("PACKAGE_INSTALL", "PACKAGE_CHANGE", MEDIUM, "Installs or removes Python packages");
                    break;
                case "config":
                    add("PACKAGE_CONFIG", "CONFIG_CHANGE", HIGH, "Changes pip configuration");
                    break;
                case "list": case "show": case "freeze": case "check": case "help": case "search": case "inspect":
                    add("KNOWN_SAFE_COMMAND", "NONE", LOW, "Read-only pip command");
                    break;
                default:
                    add("PACKAGE_UNKNOWN", "UNKNOWN_COMMAND", MEDIUM, "Unclassified pip command");
            }
        }

        void systemPmRule(String exe, List<String> a) {
            String sub = firstNonFlag(a);
            Set<String> readOnly = set("list", "search", "show", "info", "--version", "-v", "version", "--info", "query", "outdated", "-q", "-qi", "-ss", "-s");
            if (sub == null || readOnly.contains(sub)) {
                add("KNOWN_SAFE_COMMAND", "NONE", LOW, "Read-only " + exe + " command");
            } else {
                add("PACKAGE_SYSTEM", "PACKAGE_CHANGE", HIGH, "System-wide package installation, upgrade or removal (" + exe + " " + sub + ")");
            }
        }

        void otherPmRule(String exe, List<String> a) {
            String sub = firstNonFlag(a);
            Set<String> safe = SAFE_SUB.getOrDefault(exe, Set.of());
            if (sub == null) {
                add("KNOWN_SAFE_COMMAND", "NONE", LOW, "Query without subcommand");
                return;
            }
            if (safe.contains(sub)) { add("KNOWN_SAFE_COMMAND", "NONE", LOW, "Known low-impact " + exe + " command"); return; }
            Set<String> inst = set("install", "add", "remove", "uninstall", "update", "upgrade", "get", "require", "sync", "tool", "restore", "mod", "lock", "init");
            if (inst.contains(sub)) {
                boolean global = a.contains("-g") || a.contains("--global") || a.contains("--system");
                boolean remote = a.stream().anyMatch(x -> x.startsWith("http") || x.startsWith("git+") || x.startsWith("--index-url") || x.startsWith("--git"));
                add("PACKAGE_INSTALL", "PACKAGE_CHANGE", global || remote ? HIGH : MEDIUM, "Installs or changes dependencies with " + exe);
            } else if (set("publish", "push", "upload", "login").contains(sub)) {
                add("PACKAGE_PUBLISH", "PACKAGE_CHANGE", HIGH, "Publishes packages or changes registry credentials");
            } else {
                add("PROJECT_SCRIPT", "UNKNOWN_COMMAND", MEDIUM, "Unclassified " + exe + " command (may run project code)");
            }
        }

        void systemRule(String exe, List<Word> args, List<String> a) {
            String joined = String.join(" ", a);
            switch (exe) {
                case "format": case "mkfs": case "diskpart": case "fdisk": case "parted": case "wipefs": case "sfdisk": case "gdisk":
                case "format-volume": case "clear-disk": case "remove-partition": case "initialize-disk": case "sdelete": case "shred":
                    if (exe.equals("shred") && !a.stream().anyMatch(x -> x.startsWith("/dev/") )) {
                        add("SECURE_DELETE", "FILESYSTEM_CHANGE", HIGH, "shred irreversibly destroys file contents");
                    } else add("DISK_FORMAT", "DISK_DESTRUCTION", CRITICAL, "Formats, partitions or wipes disks (" + exe + ")");
                    return;
                default:
            }
            if (exe.startsWith("mkfs")) { add("DISK_FORMAT", "DISK_DESTRUCTION", CRITICAL, "Creates a filesystem (destroys existing data)"); return; }
            if (exe.equals("cipher") && a.stream().anyMatch(x -> x.startsWith("/w"))) { add("DISK_WIPE", "DISK_DESTRUCTION", CRITICAL, "cipher /w wipes free disk space"); return; }
            if (exe.equals("vssadmin") && joined.contains("delete") || exe.equals("wbadmin") && joined.contains("delete")
                    || exe.equals("wmic") && joined.contains("shadowcopy") && joined.contains("delete")
                    || exe.equals("bcdedit") || exe.equals("diskshadow") && joined.contains("delete")) {
                add("BACKUP_DESTRUCTION", "DISK_DESTRUCTION", CRITICAL, "Deletes backups/shadow copies or alters boot configuration");
                return;
            }
            if (exe.equals("wevtutil") && (a.contains("cl") || a.contains("clear-log")) || exe.equals("clear-eventlog") || exe.equals("auditpol") && joined.contains("/clear")) {
                add("CLEAR_LOGS", "SECURITY_TAMPER", CRITICAL, "Clears security or event logs");
                return;
            }
            if (exe.equals("set-mppreference") || exe.equals("add-mppreference")) {
                if (joined.contains("disable") || joined.contains("exclusion")) {
                    add("DISABLE_DEFENDER", "SECURITY_TAMPER", CRITICAL, "Disables or weakens Microsoft Defender");
                    return;
                }
            }
            if ((exe.equals("sc") || exe.equals("net") || exe.equals("net1") || exe.equals("stop-service") || exe.equals("set-service") || exe.equals("systemctl") || exe.equals("service"))
                    && (joined.contains("windefend") || joined.contains("sense") || joined.contains("mpssvc") || joined.contains("wscsvc")
                    || joined.contains("eventlog") || joined.contains("wuauserv") && joined.contains("disabled") || joined.contains("firewalld") || joined.contains("ufw") || joined.contains("apparmor") || joined.contains("auditd"))
                    && (joined.contains("stop") || joined.contains("disable") || joined.contains("config") || joined.contains("delete") || joined.contains("mask"))) {
                add("DISABLE_SECURITY_SERVICE", "SECURITY_TAMPER", CRITICAL, "Stops or disables a security service");
                return;
            }
            if (exe.equals("netsh") && (joined.contains("advfirewall") || joined.contains("firewall")) && (joined.contains("off") || joined.contains("disable") || joined.contains("add rule") && joined.contains("allow") || joined.contains("delete"))) {
                add("DISABLE_FIREWALL", "SECURITY_TAMPER", CRITICAL, "Disables or weakens the Windows firewall");
                return;
            }
            if (exe.equals("ufw") && joined.contains("disable") || exe.equals("setenforce") && joined.contains("0") || exe.equals("iptables") && (joined.contains("-f") || joined.contains("--flush"))) {
                add("DISABLE_FIREWALL", "SECURITY_TAMPER", CRITICAL, "Disables or flushes host firewall/enforcement");
                return;
            }
            if (exe.equals("set-executionpolicy")) {
                add("EXECUTION_POLICY", "CONFIG_CHANGE", joined.contains("bypass") || joined.contains("unrestricted") ? HIGH : MEDIUM, "Changes the PowerShell execution policy");
                return;
            }
            if (exe.equals("reg") || exe.equals("regedit") || exe.equals("reg.exe") || exe.equals("set-itemproperty") || exe.equals("new-itemproperty") || exe.equals("remove-itemproperty")) {
                boolean write = joined.contains("add") || joined.contains("delete") || joined.contains("import") || joined.contains("copy") || exe.contains("itemproperty") || exe.equals("regedit");
                boolean secKey = joined.contains("defender") || joined.contains("disableantispyware") || joined.contains("policies\\microsoft") || joined.contains("policies/microsoft") || joined.contains("\\currentversion\\run") || joined.contains("lsa");
                boolean save = joined.contains(" save ") || joined.startsWith("save ") || joined.contains("hklm\\sam") || joined.contains("hklm\\security");
                if (save) add("CREDENTIAL_DUMP", "EXFILTRATION", CRITICAL, "Exports credential-bearing registry hives");
                else if (write && secKey) add("REGISTRY_SECURITY", "SECURITY_TAMPER", CRITICAL, "Modifies registry security or startup settings");
                else if (write) add("REGISTRY_WRITE", "SYSTEM_CONFIG", HIGH, "Modifies the Windows registry");
                else add("REGISTRY_READ", "NONE", MEDIUM, "Reads the Windows registry");
                return;
            }
            if (exe.equals("net") || exe.equals("net1") || exe.equals("net.exe") || exe.equals("new-localuser") || exe.equals("add-localgroupmember") || exe.equals("useradd") || exe.equals("usermod") || exe.equals("passwd") || exe.equals("chpasswd")) {
                if (joined.contains("user") && (joined.contains("/add") || joined.contains("/delete")) || joined.contains("localgroup") && joined.contains("administrators")
                        || exe.equals("new-localuser") || exe.equals("add-localgroupmember") || exe.equals("useradd") || exe.equals("usermod") || exe.equals("passwd") || exe.equals("chpasswd")) {
                    add("ACCOUNT_CHANGE", "ACCOUNT_MANIPULATION", CRITICAL, "Creates, deletes or elevates user accounts or passwords");
                    return;
                }
                add("NET_COMMAND", "NETWORK_ACCESS", MEDIUM, "Windows net command");
                return;
            }
            if (exe.equals("schtasks") || exe.equals("register-scheduledtask") || exe.equals("new-service") || exe.equals("crontab") || exe.equals("at") || exe.equals("launchctl")
                    || exe.equals("sc") && (joined.contains("create") || joined.contains("config"))) {
                if (exe.equals("crontab") && a.contains("-l")) { add("KNOWN_SAFE_COMMAND", "NONE", LOW, "Lists cron jobs"); return; }
                add("PERSISTENCE", "SECURITY_TAMPER", HIGH, "Creates scheduled tasks or services (persistence mechanism)");
                return;
            }
            if (set("shutdown", "restart-computer", "stop-computer", "reboot", "halt", "poweroff", "init").contains(exe)) {
                add("POWER_CONTROL", "SYSTEM_CONTROL", HIGH, "Shuts down or restarts the machine");
                return;
            }
            if (set("taskkill", "pkill", "kill", "killall", "stop-process").contains(exe)) {
                if (joined.contains("actiongate") || joined.contains("java")) {
                    add("KILL_ACTIONGATE", "SECURITY_TAMPER", CRITICAL, "Attempts to terminate ActionGate or its Java runtime");
                } else {
                    add("KILL_PROCESS", "SYSTEM_CONTROL", MEDIUM, "Terminates processes");
                }
                return;
            }
            if (set("mimikatz", "procdump", "lazagne", "secretsdump", "hashcat", "john", "nmap", "masscan", "metasploit", "msfconsole", "responder").contains(exe)) {
                add("HACKING_TOOL", "EXFILTRATION", CRITICAL, "Credential-dumping or offensive-security tool (" + exe + ")");
                return;
            }
            if (set("printenv", "env").contains(exe) || exe.equals("set") && a.isEmpty() || exe.equals("export") && a.contains("-p") || exe.equals("get-childitem") && joined.contains("env:") || exe.equals("gci") && joined.contains("env:")) {
                if (!(exe.equals("get-childitem") || exe.equals("gci")) || joined.contains("env:")) {
                    add("ENV_DUMP", "CREDENTIAL_EXPOSURE", HIGH, "Prints environment variables, which may contain secrets");
                    return;
                }
            }
            if (exe.equals("cmdkey") && joined.contains("/list") || exe.equals("vaultcmd") || exe.equals("security") && joined.contains("find-generic-password") || exe.equals("secret-tool")) {
                add("CREDENTIAL_STORE", "CREDENTIAL_EXPOSURE", HIGH, "Reads stored credentials");
                return;
            }
            if (exe.equals("start-process") || exe.equals("saps")) {
                if (joined.contains("runas")) add("PRIVILEGE_ESCALATION", "PRIVILEGE_ESCALATION", HIGH, "Start-Process -Verb RunAs requests elevation");
                else add("START_PROCESS", "UNKNOWN_COMMAND", MEDIUM, "Starts another process");
                return;
            }
            if (exe.equals("docker") || exe.equals("podman") || exe.equals("kubectl")) {
                if (joined.contains("--privileged") || joined.contains("-v /:") || joined.contains("--pid=host") || joined.contains("system prune") || joined.contains("rm -f") || joined.contains(" delete ")) {
                    add("CONTAINER_RISK", "SYSTEM_CONTROL", HIGH, "Privileged container, host mount or destructive container operation");
                }
            }
        }

        // ------------------------------------------------------------ generic scans

        void scanArgs(String exe, List<Word> args, boolean dynamic) {
            boolean mutating = DELETERS.contains(exe) || MOVERS_WRITERS.contains(exe);
            for (Word w : args) {
                String t = w.text();
                if (SECRET_VAR.matcher(t).find()) {
                    add("SECRET_VARIABLE", "CREDENTIAL_EXPOSURE", HIGH, "References an environment variable that looks like a secret (" + t + ")");
                }
                if (t.startsWith("-") || t.isEmpty() || URL.matcher(t).matches()) continue;
                String test = t.startsWith("@") ? t.substring(1) : t;
                if (!looksLikePath(test) && !mutating) continue;
                if (NON_CONTENT.contains(exe)) continue;
                if (PathUtil.hasUnresolved(test, home)) continue;
                PathInfo pi = classify(test);
                if (pi.sensitive && !mutating) {
                    add("SENSITIVE_FILE_ACCESS", "CREDENTIAL_EXPOSURE", HIGH, "Accesses a file that commonly holds credentials or secrets (" + t + ")");
                }
            }
            if (!dynamic && args.isEmpty() && set("history", "get-history").contains(exe)) {
                add("HISTORY_READ", "CREDENTIAL_EXPOSURE", MEDIUM, "Shell history can contain secrets");
            }
        }

        boolean looksLikePath(String t) {
            return t.indexOf('/') >= 0 || t.indexOf('\\') >= 0 || t.startsWith("~") || t.startsWith(".") || t.matches("(?i)^[a-z]:.*")
                    || SensitivePaths.isSensitive(PathUtil.normalize(t, "/", home));
        }

        void tamperScan(String exe, List<Word> args) {
            if (!DELETERS.contains(exe) && !MOVERS_WRITERS.contains(exe)) return;
            for (Word w : targets(exe, args)) {
                if (isTamper(w.text())) {
                    add("ACTIONGATE_TAMPER", "SECURITY_TAMPER", CRITICAL, "Modifies ActionGate or the agent's hook configuration (" + w.text() + ")");
                    return;
                }
            }
        }

        boolean isTamper(String rawPath) {
            String path = PathUtil.normalize(rawPath, curDir, home);
            if (isAtOrBelowPath(path, "/.claude/hooks") || isAtOrBelowPath(path, "/.cursor/hooks")
                    || path.endsWith("/.claude/settings.json") || path.endsWith("/.claude.json") || path.endsWith("/.claude")) {
                return true;
            }
            for (String protectedPath : protectedNorm) {
                if (PathUtil.isInside(path, protectedPath) && hasActionGateSegment(protectedPath)) return true;
            }
            return false;
        }

        boolean isAtOrBelowPath(String path, String suffix) {
            int index = path.lastIndexOf(suffix);
            int end = index + suffix.length();
            return index >= 0 && (end == path.length() || path.charAt(end) == '/');
        }

        boolean hasActionGateSegment(String path) {
            for (String segment : path.split("/")) {
                if (segment.equals("actiongate") || segment.equals(".actiongate")) return true;
            }
            return false;
        }

        void analyzeRedirects(Segment seg) {
            for (Redirect r : seg.redirects()) {
                String op = r.op();
                String tgt = r.target();
                String low = tgt.toLowerCase(Locale.ROOT);
                if (op.endsWith("&") && tgt.matches("-?\\d+")) continue;
                if (op.endsWith("<") || op.equals("<")) {
                    if (!r.targetDynamic()) {
                        PathInfo pi = classify(tgt);
                        if (pi.sensitive) add("SENSITIVE_FILE_ACCESS", "CREDENTIAL_EXPOSURE", HIGH, "Reads a credential or secret file via redirection (" + tgt + ")");
                    }
                    continue;
                }
                if (op.contains("<")) continue;
                if (low.equals("/dev/null") || low.equals("nul") || low.equals("$null") || low.equals("/dev/stdout") || low.equals("/dev/stderr") || low.startsWith("&")) continue;
                if (low.startsWith("/dev/") || low.startsWith("\\\\.\\") || low.startsWith("//./")) {
                    add("RAW_DEVICE_WRITE", "DISK_DESTRUCTION", CRITICAL, "Redirects output to a raw device (" + tgt + ")");
                    continue;
                }
                if (isTamper(tgt)) {
                    add("ACTIONGATE_TAMPER", "SECURITY_TAMPER", CRITICAL, "Redirection writes to ActionGate or agent hook configuration (" + tgt + ")");
                    continue;
                }
                if (r.targetDynamic() || PathUtil.hasUnresolved(tgt, home)) {
                    ambiguous = true;
                    add("REDIRECT_DYNAMIC", "AMBIGUOUS_COMMAND", MEDIUM, "Redirection target depends on a variable or substitution (" + tgt + ")");
                    continue;
                }
                PathInfo pi = classify(tgt);
                if (pi.protectedHit || pi.ancestorOfProtected && pi.norm.equals(pi.norm) && false) {
                    add("REDIRECT_PROTECTED_PATH", "PROTECTED_PATH", CRITICAL, "Redirection writes into a protected path (" + tgt + ")");
                } else if (pi.sensitive) {
                    add("REDIRECT_SENSITIVE", "CREDENTIAL_EXPOSURE", HIGH, "Redirection writes to a credential or secret file (" + tgt + ")");
                } else if (pi.outside) {
                    add("REDIRECT_OUTSIDE_WORKDIR", "FILESYSTEM_WRITE", MEDIUM, "Redirection writes outside the working directory (" + tgt + ")");
                } else {
                    add("REDIRECT_IN_WORKDIR", "NONE", LOW, "Redirection writes inside the working directory");
                }
            }
        }

        void trackCd(String exe, List<Word> args) {
            if (!set("cd", "chdir", "pushd", "set-location", "sl").contains(exe)) return;
            List<Word> t = new ArrayList<>();
            for (Word w : args) if (!isFlag(w) && !(exe.equals("cd") && w.text().equalsIgnoreCase("/d"))) t.add(w);
            if (t.isEmpty()) { curDir = PathUtil.normalize(home, "/", home); return; }
            Word w = t.get(0);
            if (w.variable() || w.substitution() || PathUtil.hasUnresolved(w.text(), home)) { curDirKnown = false; return; }
            if (w.text().equals("-")) { curDirKnown = false; return; }
            curDir = PathUtil.normalize(w.text(), curDir, home);
        }
    }
}
