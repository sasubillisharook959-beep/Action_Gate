package com.actiongate.risk;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Platform-independent path normalisation used for risk analysis. Output is lower-case, uses '/', and is
 * either "/..." or "x:/...". It never touches the filesystem, so it behaves identically in tests on any OS.
 */
public final class PathUtil {
    private PathUtil() {}

    private static final Pattern VAR = Pattern.compile(
            "(?i)\\$\\{?env:(\\w+)\\}?|\\$\\{(\\w+)\\}|\\$(\\w+)|%(\\w+)%");
    private static final Pattern DRIVE = Pattern.compile("^([a-z]):(/.*)?$");
    private static final Pattern WSL = Pattern.compile("^/mnt/([a-z])(/.*)?$");
    private static final Pattern GITBASH = Pattern.compile("^/([a-z])(/.*)?$");

    public static String homeDir() {
        return normalize(System.getProperty("user.home", "/"), "/", "/");
    }

    /** Expands well-known variables (HOME, USERPROFILE, APPDATA, ...). Unknown variables are left in place. */
    public static String expandVars(String raw, String home) {
        Matcher m = VAR.matcher(raw);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String name = null;
            for (int g = 1; g <= 4; g++) if (m.group(g) != null) { name = m.group(g); break; }
            String val = lookup(name == null ? "" : name.toLowerCase(Locale.ROOT), home);
            m.appendReplacement(sb, Matcher.quoteReplacement(val != null ? val : m.group()));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private static String lookup(String name, String home) {
        switch (name) {
            case "home": case "userprofile": case "homepath": return home;
            case "appdata": return home + "/appdata/roaming";
            case "localappdata": return home + "/appdata/local";
            case "temp": case "tmp": return home + "/appdata/local/temp";
            case "systemroot": case "windir": return "c:/windows";
            case "programfiles": return "c:/program files";
            case "programdata": return "c:/programdata";
            case "systemdrive": return "c:";
            default: return null;
        }
    }

    /** True if, after expansion, the text still depends on an unknown variable or substitution. */
    public static boolean hasUnresolved(String raw, String home) {
        String e = expandVars(raw, home);
        return e.indexOf('$') >= 0 || e.indexOf('`') >= 0 || Pattern.compile("%\\w+%").matcher(e).find();
    }

    /** Directory part of a wildcard path ("C:\\Users\\*" -> "C:\\Users\\"); the input itself when there is no wildcard. */
    public static String wildcardDir(String raw) {
        int w = -1;
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == '*' || c == '?') { w = i; break; }
        }
        if (w < 0) return raw;
        String head = raw.substring(0, w);
        int sep = Math.max(head.lastIndexOf('/'), head.lastIndexOf('\\'));
        return sep < 0 ? "" : head.substring(0, sep + 1);
    }

    public static boolean hasWildcard(String raw) {
        return raw.indexOf('*') >= 0 || raw.indexOf('?') >= 0;
    }

    /** @param cwd an already-normalised absolute directory (use "/" when unknown) */
    public static String normalize(String raw, String cwd, String home) {
        String p = expandVars(raw.trim(), home).replace('\\', '/');
        if (p.equals("~")) p = home;
        else if (p.startsWith("~/")) p = home + p.substring(1);
        p = p.toLowerCase(Locale.ROOT);
        Matcher wsl = WSL.matcher(p);
        if (wsl.matches()) {
            p = wsl.group(1) + ":" + (wsl.group(2) == null ? "/" : wsl.group(2));
        } else {
            Matcher gb = GITBASH.matcher(p);
            if (gb.matches() && gb.group(2) != null) p = gb.group(1) + ":" + gb.group(2);
        }
        boolean absolute = DRIVE.matcher(p).matches() || p.startsWith("/");
        if (!absolute) p = (cwd == null || cwd.isEmpty() ? "/" : cwd) + "/" + p;
        String prefix;
        String rest;
        Matcher d = DRIVE.matcher(p);
        if (d.matches()) {
            prefix = d.group(1) + ":/";
            rest = d.group(2) == null ? "" : d.group(2);
        } else {
            prefix = "/";
            rest = p;
        }
        Deque<String> parts = new ArrayDeque<>();
        for (String seg : rest.split("/")) {
            if (seg.isEmpty() || seg.equals(".")) continue;
            if (seg.equals("..")) {
                if (!parts.isEmpty()) parts.removeLast();
                continue;
            }
            parts.addLast(seg);
        }
        return prefix + String.join("/", parts);
    }

    public static boolean isRoot(String n) {
        return n.equals("/") || n.matches("[a-z]:/");
    }

    /** child == parent or child is below parent. */
    public static boolean isInside(String child, String parent) {
        if (parent.endsWith("/")) return child.startsWith(parent);
        return child.equals(parent) || child.startsWith(parent + "/");
    }
}
