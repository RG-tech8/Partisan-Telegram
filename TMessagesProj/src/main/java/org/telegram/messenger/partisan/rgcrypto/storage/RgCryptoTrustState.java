package org.telegram.messenger.partisan.rgcrypto.storage;

public final class RgCryptoTrustState {
    public static final int UNKNOWN = 0;
    public static final int UNTRUSTED = 1;
    public static final int TRUSTED = 2;
    public static final int REVOKED = 3;

    private RgCryptoTrustState() {
    }
}
