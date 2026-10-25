package com.actiongate.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Minimal, strict JSON reader/writer (no external dependency, so the hook jar stays tiny). */
public final class Json {
    private Json() {}

    public static Object parse(String s) {
        if (s == null) throw new IllegalArgumentException("JSON input is null");
        P p = new P(s);
        p.ws();
        Object v = p.value();
        p.ws();
        if (p.i != s.length()) throw p.err("trailing data");
        return v;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String s) {
        Object o = parse(s);
        if (!(o instanceof Map)) throw new IllegalArgumentException("JSON object expected");
        return (Map<String, Object>) o;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> asObject(Object o) {
        return o instanceof Map ? (Map<String, Object>) o : null;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> asArray(Object o) {
        return o instanceof List ? (List<Object>) o : null;
    }

    public static String asString(Object o) {
        return o instanceof String ? (String) o : null;
    }

    public static String write(Object o) {
        StringBuilder sb = new StringBuilder();
        write(sb, o, false, 0);
        return sb.toString();
    }

    public static String writePretty(Object o) {
        StringBuilder sb = new StringBuilder();
        write(sb, o, true, 0);
        return sb.toString();
    }

    private static void indent(StringBuilder sb, int n) {
        for (int i = 0; i < n; i++) sb.append("  ");
    }

    private static void write(StringBuilder sb, Object o, boolean pretty, int lvl) {
        if (o == null) {
            sb.append("null");
        } else if (o instanceof String) {
            quote(sb, (String) o);
        } else if (o instanceof Number || o instanceof Boolean) {
            sb.append(o);
        } else if (o instanceof Map) {
            Map<?, ?> m = (Map<?, ?>) o;
            if (m.isEmpty()) { sb.append("{}"); return; }
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                if (pretty) { sb.append('\n'); indent(sb, lvl + 1); }
                quote(sb, String.valueOf(e.getKey()));
                sb.append(pretty ? ": " : ":");
                write(sb, e.getValue(), pretty, lvl + 1);
            }
            if (pretty) { sb.append('\n'); indent(sb, lvl); }
            sb.append('}');
        } else if (o instanceof Iterable) {
            boolean any = false;
            sb.append('[');
            for (Object e : (Iterable<?>) o) {
                if (any) sb.append(',');
                any = true;
                if (pretty) { sb.append('\n'); indent(sb, lvl + 1); }
                write(sb, e, pretty, lvl + 1);
            }
            if (any && pretty) { sb.append('\n'); indent(sb, lvl); }
            sb.append(']');
        } else {
            quote(sb, o.toString());
        }
    }

    private static void quote(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        sb.append('"');
    }

    private static final class P {
        final String s;
        int i = 0;
        int depth = 0;

        P(String s) { this.s = s; }

        IllegalArgumentException err(String m) {
            return new IllegalArgumentException("Invalid JSON at offset " + i + ": " + m);
        }

        void ws() {
            while (i < s.length() && " \t\r\n".indexOf(s.charAt(i)) >= 0) i++;
        }

        Object value() {
            if (i >= s.length()) throw err("unexpected end");
            if (++depth > 64) throw err("nesting too deep");
            try {
                char c = s.charAt(i);
                switch (c) {
                    case '{': return obj();
                    case '[': return arr();
                    case '"': return str();
                    case 't': lit("true"); return Boolean.TRUE;
                    case 'f': lit("false"); return Boolean.FALSE;
                    case 'n': lit("null"); return null;
                    default: return num();
                }
            } finally {
                depth--;
            }
        }

        void lit(String w) {
            if (!s.startsWith(w, i)) throw err("expected " + w);
            i += w.length();
        }

        Map<String, Object> obj() {
            Map<String, Object> m = new LinkedHashMap<>();
            i++;
            ws();
            if (i < s.length() && s.charAt(i) == '}') { i++; return m; }
            while (true) {
                ws();
                if (i >= s.length() || s.charAt(i) != '"') throw err("expected string key");
                String k = str();
                ws();
                if (i >= s.length() || s.charAt(i) != ':') throw err("expected ':'");
                i++;
                ws();
                m.put(k, value());
                ws();
                if (i >= s.length()) throw err("unexpected end");
                char c = s.charAt(i++);
                if (c == '}') return m;
                if (c != ',') throw err("expected ',' or '}'");
            }
        }

        List<Object> arr() {
            List<Object> l = new ArrayList<>();
            i++;
            ws();
            if (i < s.length() && s.charAt(i) == ']') { i++; return l; }
            while (true) {
                ws();
                l.add(value());
                ws();
                if (i >= s.length()) throw err("unexpected end");
                char c = s.charAt(i++);
                if (c == ']') return l;
                if (c != ',') throw err("expected ',' or ']'");
            }
        }

        String str() {
            StringBuilder sb = new StringBuilder();
            i++;
            while (true) {
                if (i >= s.length()) throw err("unterminated string");
                char c = s.charAt(i++);
                if (c == '"') return sb.toString();
                if (c < 0x20) throw err("control character in string");
                if (c != '\\') { sb.append(c); continue; }
                if (i >= s.length()) throw err("bad escape");
                char e = s.charAt(i++);
                switch (e) {
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case '/': sb.append('/'); break;
                    case 'b': sb.append('\b'); break;
                    case 'f': sb.append('\f'); break;
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case 'u':
                        if (i + 4 > s.length()) throw err("bad unicode escape");
                        try {
                            sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        } catch (NumberFormatException ex) {
                            throw err("bad unicode escape");
                        }
                        i += 4;
                        break;
                    default: throw err("bad escape");
                }
            }
        }

        Object num() {
            int st = i;
            if (i < s.length() && s.charAt(i) == '-') i++;
            while (i < s.length() && "0123456789.eE+-".indexOf(s.charAt(i)) >= 0) i++;
            String t = s.substring(st, i);
            if (t.isEmpty() || t.equals("-")) throw err("unexpected character");
            try {
                if (t.indexOf('.') >= 0 || t.indexOf('e') >= 0 || t.indexOf('E') >= 0) return Double.parseDouble(t);
                return Long.parseLong(t);
            } catch (NumberFormatException ex) {
                throw err("bad number");
            }
        }
    }
}
