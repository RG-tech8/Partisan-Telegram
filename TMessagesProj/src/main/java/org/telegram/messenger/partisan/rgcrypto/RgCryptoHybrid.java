package org.telegram.messenger.partisan.rgcrypto;

import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

public final class RgCryptoHybrid {
    private static final byte[] CONTEXT_PREFIX = "rg-crypto/v1".getBytes(StandardCharsets.UTF_8);

    private RgCryptoHybrid() {
    }

    public static byte[] wrapDek(byte[] dek, KeysetHandle recipientPublicKeyset, String recipientKid, String senderSigningKid)
            throws GeneralSecurityException {
        HybridEncrypt encrypt = recipientPublicKeyset.getPrimitive(RegistryConfiguration.get(), HybridEncrypt.class);
        return encrypt.encrypt(dek, contextInfo(recipientKid, senderSigningKid));
    }

    public static byte[] unwrapDek(byte[] wrapped, KeysetHandle recipientPrivateKeyset, String recipientKid, String senderSigningKid)
            throws GeneralSecurityException {
        HybridDecrypt decrypt = recipientPrivateKeyset.getPrimitive(RegistryConfiguration.get(), HybridDecrypt.class);
        return decrypt.decrypt(wrapped, contextInfo(recipientKid, senderSigningKid));
    }

    private static byte[] contextInfo(String recipientKid, String senderSigningKid) throws GeneralSecurityException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(CONTEXT_PREFIX);
            if (recipientKid != null) {
                digest.update(recipientKid.getBytes(StandardCharsets.UTF_8));
            }
            digest.update((byte) 0x1F);
            if (senderSigningKid != null) {
                digest.update(senderSigningKid.getBytes(StandardCharsets.UTF_8));
            }
            return digest.digest();
        } catch (Exception e) {
            throw new GeneralSecurityException("contextInfo failed", e);
        }
    }
}
