package com.actiongate.risk;

import java.util.Set;

/** Heuristics for files that commonly hold credentials or secrets. Input must be normalised (lower-case, '/'). */
public final class SensitivePaths {
    private SensitivePaths() {}

    private static final Set<String> DIRS = Set.of(".ssh", ".aws", ".azure", ".gnupg", ".kube", ".docker");
    private static final Set<String> NAMES = Set.of(
            ".npmrc", ".pypirc", ".netrc", "_netrc", ".git-credentials", "credentials", "credentials.json",
            ".bash_history", ".zsh_history", "consolehost_history.txt", "ntuser.dat", "wallet.dat",
            "secrets.json", "secrets.yml", "secrets.yaml", ".htpasswd", "logins.json", "key4.db",
            "application_default_credentials.json", "service-account.json", "terraform.tfvars", ".vault-token");
    private static final String[] EXTS = {".pem", ".pfx", ".p12", ".key", ".kdbx", ".keystore", ".jks", ".ppk"};
    private static final Set<String> ENV_SAFE_SUFFIX = Set.of("example", "sample", "template", "dist", "defaults");

    public static boolean isSensitive(String n) {
        if (n == null || n.isEmpty()) return false;
        String base = n.substring(n.lastIndexOf('/') + 1);
        for (String seg : n.split("/")) if (DIRS.contains(seg)) return true;
        if (n.contains("/.config/gcloud") || n.contains("/appdata/roaming/gcloud")) return true;
        if (n.contains("/windows/system32/config/")) return true;
        if (base.equals(".env")) return true;
        if (base.startsWith(".env.")) {
            String suffix = base.substring(5);
            return !ENV_SAFE_SUFFIX.contains(suffix);
        }
        if (NAMES.contains(base)) return true;
        if (base.startsWith("id_rsa") || base.startsWith("id_ed25519") || base.startsWith("id_ecdsa") || base.startsWith("id_dsa"))
            return !base.endsWith(".pub");
        for (String e : EXTS) if (base.endsWith(e)) return true;
        if ((base.equals("login data") || base.equals("cookies") || base.equals("web data"))
                && (n.contains("/google/chrome/") || n.contains("/microsoft/edge/") || n.contains("/mozilla/firefox/")
                || n.contains("/bravesoftware/")))
            return true;
        return false;
    }
}
