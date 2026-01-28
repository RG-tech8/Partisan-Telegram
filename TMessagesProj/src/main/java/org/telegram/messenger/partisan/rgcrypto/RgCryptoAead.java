package org.telegram.messenger.partisan.rgcrypto;

import com.google.crypto.tink.subtle.AesGcmJce;

import java.security.GeneralSecurityException;

public final class RgCryptoAead {
    private RgCryptoAead() {
    }

    public static byte[] encrypt(byte[] key, byte[] plaintext, byte[] aad) throws GeneralSecurityException {
        AesGcmJce aead = new AesGcmJce(key);
        return aead.encrypt(plaintext, aad);
    }

    public static byte[] decrypt(byte[] key, byte[] ciphertext, byte[] aad) throws GeneralSecurityException {
        AesGcmJce aead = new AesGcmJce(key);
        return aead.decrypt(ciphertext, aad);
    }
}
