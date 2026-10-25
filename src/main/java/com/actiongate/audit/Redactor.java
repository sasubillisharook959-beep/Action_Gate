package com.actiongate.audit;

import java.util.regex.Pattern;

/** Removes obvious secrets from command text before it is stored or displayed. Best effort, not a guarantee. */
public final class Redactor {
    private Redactor() {}

    private static final int MAX_LEN = 4000;
    private static final Pattern AUTH = Pattern.compile("(?i)(authorization:\\s*(?:bearer|basic|token)\\s+)\\S+");
    private static final Pattern KV = Pattern.compile(
            "(?i)\\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|private[_-]?key)(\\s*[=:]\\s*)(\"[^\"]*\"|'[^']*'|\\S+)");
    private static final Pattern FLAG = Pattern.compile(
            "(?i)(--?(?:password|passwd|token|secret|api-key|apikey|access-key)[ =])(\"[^\"]*\"|'[^']*'|\\S+)");
    private static final Pattern URL_CRED = Pattern.compile("://([^/\\s:@]+):([^/\\s@]+)@");
    private static final Pattern TOKENS = Pattern.compile(
            "\\b(?:ghp_|gho_|ghs_|github_pat_|sk-ant-|sk-|xox[abp]-|AKIA|AIza)[A-Za-z0-9_\\-]{8,}");

    public static String redact(String s) {
        if (s == null) return "";
        String r = s;
        r = AUTH.matcher(r).replaceAll("$1[REDACTED]");
        r = KV.matcher(r).replaceAll("$1$2[REDACTED]");
        r = FLAG.matcher(r).replaceAll("$1[REDACTED]");
        r = URL_CRED.matcher(r).replaceAll("://$1:[REDACTED]@");
        r = TOKENS.matcher(r).replaceAll("[REDACTED]");
        if (r.length() > MAX_LEN) r = r.substring(0, MAX_LEN) + "...[truncated]";
        return r;
    }
}
