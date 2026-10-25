package com.actiongate.util;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.security.SecureRandom;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/** Best-effort owner-only file protection for key, token and checkpoint files. */
public final class SecureFiles {
    private SecureFiles() {}

    private static final SecureRandom RNG = new SecureRandom();

    public static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    /** @return true if an owner-only restriction was applied. */
    public static boolean restrictToOwner(Path p) {
        try {
            if (Files.getFileStore(p).supportsFileAttributeView("posix")) {
                Set<PosixFilePermission> perms = Files.isDirectory(p)
                        ? EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE)
                        : EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
                Files.setPosixFilePermissions(p, perms);
                return true;
            }
            AclFileAttributeView acl = Files.getFileAttributeView(p, AclFileAttributeView.class);
            if (acl != null) {
                UserPrincipal owner = Files.getOwner(p);
                AclEntry entry = AclEntry.newBuilder()
                        .setType(AclEntryType.ALLOW)
                        .setPrincipal(owner)
                        .setPermissions(EnumSet.allOf(AclEntryPermission.class))
                        .build();
                acl.setAcl(List.of(entry));
                return true;
            }
        } catch (IOException | UnsupportedOperationException | SecurityException e) {
            // best effort
        }
        return false;
    }

    /** Atomically write a small file, then restrict it to the owner. */
    public static void writeAtomic(Path target, byte[] data) throws IOException {
        Path tmp = target.resolveSibling(target.getFileName() + ".tmp");
        Files.write(tmp, data);
        restrictToOwner(tmp);
        try {
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}
