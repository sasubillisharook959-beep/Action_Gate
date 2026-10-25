package com.actiongate.enforcement;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Single-use permission to release exactly one operation. Only this package can create instances, so the only way
 * to obtain one is through {@link EnforcementService}. It is bound to a digest, expires, and can be consumed once.
 */
public final class AuthorizedOperation {
    private final String digest;
    private final String requestId;
    private final Instant expiresAt;
    private final AtomicBoolean consumed = new AtomicBoolean(false);

    AuthorizedOperation(String digest, String requestId, Instant expiresAt) {
        this.digest = digest;
        this.requestId = requestId;
        this.expiresAt = expiresAt;
    }

    public String digest() { return digest; }
    public String requestId() { return requestId; }
    public Instant expiresAt() { return expiresAt; }
    public boolean consumed() { return consumed.get(); }

    /** @return true only if the digest matches, the grant has not expired and it has not been used before. */
    boolean consume(String presentedDigest, Instant now) {
        if (!digest.equals(presentedDigest)) return false;
        if (now.isAfter(expiresAt)) return false;
        return consumed.compareAndSet(false, true);
    }
}
