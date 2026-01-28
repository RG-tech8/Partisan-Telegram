package org.telegram.messenger.partisan.rgcrypto;

import com.google.crypto.tink.KeysetHandle;

public final class RgCryptoRecipientPublic {
    public final int keyId;
    public final KeysetHandle publicKeyset;
    public final String kid;

    public RgCryptoRecipientPublic(int keyId, KeysetHandle publicKeyset) {
        this(keyId, publicKeyset, null);
    }

    public RgCryptoRecipientPublic(int keyId, KeysetHandle publicKeyset, String kid) {
        this.keyId = keyId;
        this.publicKeyset = publicKeyset;
        this.kid = kid;
    }
}
