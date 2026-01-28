package org.telegram.messenger.partisan.rgcrypto;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.signature.Ed25519Parameters;

import java.security.GeneralSecurityException;

public final class RgCryptoKeys {
    private RgCryptoKeys() {
    }

    public static KeysetHandle generateHpkeKeyset() throws GeneralSecurityException {
        return KeysetHandle.generateNew(hpkeParameters());
    }

    public static KeysetHandle generateSigningKeyset() throws GeneralSecurityException {
        return KeysetHandle.generateNew(ed25519Parameters());
    }

    public static int primaryKeyId(KeysetHandle handle) {
        return handle.getPrimary().getId();
    }

    public static String serializePublicKeyset(KeysetHandle handle) throws GeneralSecurityException {
        byte[] data = TinkProtoKeysetFormat.serializeKeysetWithoutSecret(handle.getPublicKeysetHandle());
        return RgCryptoBase64.encode(data);
    }

    public static KeysetHandle parsePublicKeyset(String json) throws GeneralSecurityException {
        byte[] data = RgCryptoBase64.decode(json);
        return TinkProtoKeysetFormat.parseKeysetWithoutSecret(data);
    }

    public static HpkeParameters hpkeParameters() throws GeneralSecurityException {
        return HpkeParameters.builder()
                .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
                .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
                .setAeadId(HpkeParameters.AeadId.AES_256_GCM)
                .setVariant(HpkeParameters.Variant.TINK)
                .build();
    }

    public static Ed25519Parameters ed25519Parameters() {
        return Ed25519Parameters.create(Ed25519Parameters.Variant.TINK);
    }

    public static KeyTemplate hpkeKeyTemplate() throws GeneralSecurityException {
        return KeyTemplate.createFrom(hpkeParameters());
    }

    public static KeyTemplate ed25519KeyTemplate() throws GeneralSecurityException {
        return KeyTemplate.createFrom(ed25519Parameters());
    }

    public static String kidFromKeyset(KeysetHandle publicKeyset) throws GeneralSecurityException {
        byte[] data = TinkProtoKeysetFormat.serializeKeysetWithoutSecret(publicKeyset);
        return kidFromBytes(data);
    }

    public static String kidFromBytes(byte[] data) throws GeneralSecurityException {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            return RgCryptoBase64.encode(digest.digest(data));
        } catch (Exception e) {
            throw new GeneralSecurityException("kid failed", e);
        }
    }

    public static RgCryptoRecipientPublic recipientFromPrivateKeyset(KeysetHandle privateKeyset)
            throws GeneralSecurityException {
        return recipientFromPublicKeyset(privateKeyset.getPublicKeysetHandle());
    }

    public static RgCryptoRecipientPublic recipientFromPublicKeyset(KeysetHandle publicKeyset) {
        try {
            return new RgCryptoRecipientPublic(primaryKeyId(publicKeyset), publicKeyset, kidFromKeyset(publicKeyset));
        } catch (GeneralSecurityException e) {
            return new RgCryptoRecipientPublic(primaryKeyId(publicKeyset), publicKeyset, null);
        }
    }
}
