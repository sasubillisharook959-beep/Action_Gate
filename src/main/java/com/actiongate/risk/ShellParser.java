package com.actiongate.risk;

import java.util.ArrayList;
import java.util.List;

/**
 * Quote-aware command tokenizer shared by POSIX shells, cmd.exe and PowerShell (best effort).
 * It splits on ; && || | & and newlines, extracts redirections, and pulls out command/process substitutions
 * so they can be analysed recursively. It is deliberately conservative: anything it cannot interpret is
 * reported via {@link Parsed#malformed()} rather than guessed.
 */
public final class ShellParser {
    private ShellParser() {}

    public record Word(String text, boolean quoted, boolean substitution, boolean variable, boolean obfuscated) {}

    public record Redirect(String op, String target, boolean targetDynamic) {}

    /** @param opAfter operator that follows this segment: ";", "&&", "||", "|", "&" or "" */
    public record Segment(List<Word> words, List<Redirect> redirects, List<String> nested, String opAfter) {}

    public record Parsed(List<Segment> segments, boolean malformed, List<String> notes, boolean heredoc) {}

    public static Parsed parse(String input) {
        return new State(input).run();
    }

    private static final class State {
        final String in;
        final int n;
        int i = 0;
        final List<Segment> segs = new ArrayList<>();
        final List<String> notes = new ArrayList<>();
        boolean malformed = false;
        boolean heredoc = false;

        List<Word> words = new ArrayList<>();
        List<Redirect> redirects = new ArrayList<>();
        List<String> nested = new ArrayList<>();

        final StringBuilder w = new StringBuilder();
        boolean inWord, quoted, subst, var, obf;
        String pendingRedir = null;

        State(String in) {
            this.in = in;
            this.n = in.length();
        }

        void bad(String note) {
            malformed = true;
            if (!notes.contains(note)) notes.add(note);
        }

        void start() { inWord = true; }

        void endWord() {
            if (!inWord) return;
            Word wd = new Word(w.toString(), quoted, subst, var, obf);
            if (pendingRedir != null) {
                redirects.add(new Redirect(pendingRedir, wd.text(), wd.substitution() || wd.variable()));
                pendingRedir = null;
            } else {
                words.add(wd);
            }
            w.setLength(0);
            inWord = quoted = subst = var = obf = false;
        }

        void endSegment(String op) {
            endWord();
            if (pendingRedir != null) {
                bad("redirection without target");
                pendingRedir = null;
            }
            if (!words.isEmpty() || !redirects.isEmpty() || !nested.isEmpty()) {
                segs.add(new Segment(words, redirects, nested, op));
            } else if (!segs.isEmpty() && !op.isEmpty()) {
                // operator after an empty segment: keep the latest operator on the previous segment
                Segment last = segs.get(segs.size() - 1);
                if (last.opAfter().isEmpty() || op.equals("|"))
                    segs.set(segs.size() - 1, new Segment(last.words(), last.redirects(), last.nested(), op));
            }
            words = new ArrayList<>();
            redirects = new ArrayList<>();
            nested = new ArrayList<>();
        }

        int matchParen(int open) {
            int depth = 0;
            char q = 0;
            for (int j = open; j < n; j++) {
                char c = in.charAt(j);
                if (q != 0) {
                    if (c == q) q = 0;
                    continue;
                }
                if (c == '\'' || c == '"') { q = c; continue; }
                if (c == '(') depth++;
                else if (c == ')') {
                    depth--;
                    if (depth == 0) return j;
                }
            }
            return -1;
        }

        Parsed run() {
            while (i < n) {
                char c = in.charAt(i);
                if (c == ' ' || c == '\t') { endWord(); i++; continue; }
                if (c == '\n' || c == '\r') {
                    endSegment(";");
                    i++;
                    if (c == '\r' && i < n && in.charAt(i) == '\n') i++;
                    continue;
                }
                if (c == '\'') { singleQuote(); continue; }
                if (c == '"') { doubleQuote(); continue; }
                if (c == '\\') { backslash(); continue; }
                if (c == '`') { backtick(); continue; }
                if (c == '$') { dollar(); continue; }
                if ((c == '<' || c == '>') && i + 1 < n && in.charAt(i + 1) == '(') { procSubst(); continue; }
                if (c == '<' || c == '>') { redirect(); continue; }
                if (c == ';') { endSegment(";"); i++; continue; }
                if (c == '&') {
                    if (i + 1 < n && in.charAt(i + 1) == '&') { endSegment("&&"); i += 2; }
                    else if (i + 1 < n && in.charAt(i + 1) == '>') { endWord(); pendingRedir = "&>"; i += 2; if (i < n && in.charAt(i) == '>') { pendingRedir = "&>>"; i++; } }
                    else { endSegment("&"); i++; }
                    continue;
                }
                if (c == '|') {
                    if (i + 1 < n && in.charAt(i + 1) == '|') { endSegment("||"); i += 2; }
                    else if (i + 1 < n && in.charAt(i + 1) == '&') { endSegment("|"); i += 2; }
                    else { endSegment("|"); i++; }
                    continue;
                }
                if (c == '(' || c == ')') { endSegment(""); i++; continue; }
                if (c == '%') {
                    start();
                    int j = in.indexOf('%', i + 1);
                    if (j > i + 1 && in.substring(i + 1, j).matches("\\w+")) var = true;
                    w.append(c);
                    i++;
                    continue;
                }
                start();
                w.append(c);
                i++;
            }
            endSegment("");
            return new Parsed(segs, malformed, notes, heredoc);
        }

        void singleQuote() {
            int j = in.indexOf('\'', i + 1);
            start();
            quoted = true;
            if (j < 0) {
                bad("unterminated single quote");
                w.append(in, i + 1, n);
                i = n;
                return;
            }
            w.append(in, i + 1, j);
            i = j + 1;
        }

        void doubleQuote() {
            start();
            quoted = true;
            int j = i + 1;
            while (true) {
                if (j >= n) { bad("unterminated double quote"); i = n; return; }
                char c = in.charAt(j);
                if (c == '"') { i = j + 1; return; }
                if (c == '\\' && j + 1 < n) {
                    char d = in.charAt(j + 1);
                    if (d == '"' || d == '\\' || d == '$' || d == '`') { w.append(d); j += 2; continue; }
                    w.append(c);
                    j++;
                    continue;
                }
                if (c == '$' && j + 1 < n && in.charAt(j + 1) == '(') {
                    int e = matchParen(j + 1);
                    if (e < 0) { bad("unterminated command substitution"); i = n; return; }
                    if (in.startsWith("$((", j)) { var = true; } else { nested.add(in.substring(j + 2, e)); subst = true; }
                    w.append("$(...)");
                    j = e + 1;
                    continue;
                }
                if (c == '`') {
                    int e = in.indexOf('`', j + 1);
                    if (e < 0) { bad("unterminated backtick"); w.append(c); j++; continue; }
                    nested.add(in.substring(j + 1, e));
                    subst = true;
                    w.append("`...`");
                    j = e + 1;
                    continue;
                }
                if (c == '$' && j + 1 < n && (Character.isLetter(in.charAt(j + 1)) || in.charAt(j + 1) == '_' || in.charAt(j + 1) == '{')) var = true;
                w.append(c);
                j++;
            }
        }

        void backslash() {
            if (i + 1 >= n) { start(); w.append('\\'); i++; return; }
            char d = in.charAt(i + 1);
            if (d == '\n') { i += 2; return; }
            if (d == '\r') { i += 2; if (i < n && in.charAt(i) == '\n') i++; return; }
            if (" ;&|()<>$\"'`\\".indexOf(d) >= 0) {
                start();
                w.append(d);
                i += 2;
                return;
            }
            start();
            w.append('\\');
            i++;
        }

        void backtick() {
            int j = in.indexOf('`', i + 1);
            start();
            if (j < 0) {
                bad("unterminated backtick");
                w.append('`');
                i++;
                return;
            }
            nested.add(in.substring(i + 1, j));
            subst = true;
            w.append("`...`");
            i = j + 1;
        }

        void dollar() {
            if (i + 1 < n && in.charAt(i + 1) == '(') {
                int e = matchParen(i + 1);
                start();
                if (e < 0) { bad("unterminated command substitution"); w.append(in, i, n); i = n; return; }
                if (in.startsWith("$((", i)) { var = true; } else { nested.add(in.substring(i + 2, e)); subst = true; }
                w.append("$(...)");
                i = e + 1;
                return;
            }
            if (i + 1 < n && in.charAt(i + 1) == '\'') { ansiC(); return; }
            start();
            if (i + 1 < n) {
                char d = in.charAt(i + 1);
                if (Character.isLetter(d) || d == '_' || d == '{' || d == '?' || d == '@' || d == '*') var = true;
            }
            w.append('$');
            i++;
        }

        /** $'...' ANSI-C quoting: decode escapes, flag as obfuscated. */
        void ansiC() {
            int j = i + 2;
            StringBuilder out = new StringBuilder();
            while (true) {
                if (j >= n) { bad("unterminated $'...' string"); i = n; break; }
                char c = in.charAt(j);
                if (c == '\'') { j++; break; }
                if (c == '\\' && j + 1 < n) {
                    char d = in.charAt(j + 1);
                    if (d == 'x' && j + 3 < n + 0 && isHex(in, j + 2, 2)) { out.append((char) Integer.parseInt(in.substring(j + 2, j + 4), 16)); j += 4; continue; }
                    if (d >= '0' && d <= '7') {
                        int k = j + 1;
                        int len = 0;
                        while (k < n && len < 3 && in.charAt(k) >= '0' && in.charAt(k) <= '7') { k++; len++; }
                        out.append((char) Integer.parseInt(in.substring(j + 1, k), 8));
                        j = k;
                        continue;
                    }
                    switch (d) {
                        case 'n': out.append('\n'); break;
                        case 't': out.append('\t'); break;
                        case 'r': out.append('\r'); break;
                        case '\\': out.append('\\'); break;
                        case '\'': out.append('\''); break;
                        case '"': out.append('"'); break;
                        default: out.append(d);
                    }
                    j += 2;
                    continue;
                }
                out.append(c);
                j++;
            }
            start();
            quoted = true;
            obf = true;
            w.append(out);
            if (i < n) i = j;
        }

        boolean isHex(String s, int from, int len) {
            if (from + len > s.length()) return false;
            for (int k = from; k < from + len; k++) if (Character.digit(s.charAt(k), 16) < 0) return false;
            return true;
        }

        void procSubst() {
            int e = matchParen(i + 1);
            start();
            if (e < 0) { bad("unterminated process substitution"); i = n; return; }
            nested.add(in.substring(i + 2, e));
            subst = true;
            w.append(in.charAt(i)).append("(...)");
            i = e + 1;
        }

        void redirect() {
            char c = in.charAt(i);
            String fd = "";
            if (inWord && w.length() > 0 && w.toString().matches("\\d{1,2}") && !quoted) {
                fd = w.toString();
                w.setLength(0);
                inWord = quoted = subst = var = obf = false;
            } else {
                endWord();
            }
            String op;
            int j = i + 1;
            if (c == '>') {
                op = ">";
                if (j < n && in.charAt(j) == '>') { op = ">>"; j++; }
                else if (j < n && in.charAt(j) == '|') { op = ">|"; j++; }
                else if (j < n && in.charAt(j) == '&') { op = ">&"; j++; }
            } else {
                op = "<";
                if (in.startsWith("<<<", i)) { op = "<<<"; j = i + 3; }
                else if (in.startsWith("<<", i)) { op = "<<"; j = i + 2; heredoc = true; if (j < n && in.charAt(j) == '-') j++; }
                else if (j < n && in.charAt(j) == '&') { op = "<&"; j++; }
            }
            pendingRedir = fd + op;
            i = j;
        }
    }
}
