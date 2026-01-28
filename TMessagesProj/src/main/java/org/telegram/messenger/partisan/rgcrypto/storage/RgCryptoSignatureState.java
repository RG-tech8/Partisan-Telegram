package org.telegram.messenger.partisan.rgcrypto.storage;

public final class RgCryptoSignatureState {
    public static final int UNKNOWN = 0;
    public static final int VALID = 1;
    public static final int INVALID = 2;

    private RgCryptoSignatureState() {
    }
}
