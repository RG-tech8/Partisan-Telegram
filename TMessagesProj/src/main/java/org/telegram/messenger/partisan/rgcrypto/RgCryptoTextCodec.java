package org.telegram.messenger.partisan.rgcrypto;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.RegistryConfiguration;

import org.telegram.messenger.partisan.rgcrypto.storage.RgCryptoKeyringStore;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.List;

public final class RgCryptoTextCodec {
    private RgCryptoTextCodec() {
    }

    public interface SigningKeyProvider {
        KeysetHandle getSigningKeyset(String senderId, String signingKid) throws Exception;
    }

    public static String packText(String plaintext, String dialogScope, String senderId,
                                  KeysetHandle senderSigKeyset, List<RgCryptoRecipientPublic> recipients)
            throws GeneralSecurityException {
        if (plaintext == null) {
            throw new GeneralSecurityException("plaintext is null");
        }
        if (recipients == null || recipients.isEmpty()) {
            throw new GeneralSecurityException("recipients empty");
        }
        RgCryptoEnvelope envelope = RgCryptoEnvelope.packText(plaintext, dialogScope, senderId, senderSigKeyset,
                recipients);
        try {
            return envelope.encodeForTransport();
        } catch (Exception e) {
            throw new GeneralSecurityException("encode failed", e);
        }
    }

    public static RgCryptoDecryptResult unpackText(String tgeeString, String dialogScope,
                                                   KeysetHandle myHpkePrivKeyset,
                                                   RgCryptoKeyringStore keyringStore) {
        return unpackText(tgeeString, dialogScope, myHpkePrivKeyset, keyringStore == null ? null :
                (senderId, signingKid) -> keyringStore.getSigningKeyset(senderId, signingKid));
    }

    public static RgCryptoDecryptResult unpackText(String tgeeString, String dialogScope,
                                                   KeysetHandle myHpkePrivKeyset,
                                                   SigningKeyProvider signingKeyProvider) {
        RgCryptoEnvelope envelope;
        try {
            envelope = RgCryptoEnvelope.decodeFromTransport(tgeeString);
        } catch (Exception e) {
            return RgCryptoDecryptResult.error(RgCryptoDecryptResult.Status.PARSE_FAIL, null,
                    RgCryptoDecryptResult.SignatureState.UNKNOWN);
        }
        return unpackEnvelope(envelope, dialogScope, myHpkePrivKeyset, signingKeyProvider);
    }

    public static RgCryptoDecryptResult unpackEnvelope(RgCryptoEnvelope envelope, String dialogScope,
                                                       KeysetHandle myHpkePrivKeyset,
                                                       SigningKeyProvider signingKeyProvider) {
        if (envelope == null) {
            return RgCryptoDecryptResult.error(RgCryptoDecryptResult.Status.PARSE_FAIL, null,
                    RgCryptoDecryptResult.SignatureState.UNKNOWN);
        }

        if (dialogScope != null && envelope.dialogScope != null && !dialogScope.equals(envelope.dialogScope)) {
            if (RgCryptoDialogScope.isCompatibleUserScope(dialogScope, envelope.dialogScope, envelope.senderId)) {
                // allow legacy user scope "u:<senderId>" for this dialog
            } else {
                return RgCryptoDecryptResult.error(RgCryptoDecryptResult.Status.PARSE_FAIL, envelope.senderId,
                        RgCryptoDecryptResult.SignatureState.UNKNOWN);
            }
        }

        RgCryptoDecryptResult.SignatureState signatureState = RgCryptoDecryptResult.SignatureState.UNKNOWN;
        KeysetHandle senderSigningKeyset = null;
        if (signingKeyProvider != null && envelope.senderId != null && envelope.senderSigningKid != null) {
            try {
                senderSigningKeyset = signingKeyProvider.getSigningKeyset(envelope.senderId, envelope.senderSigningKid);
            } catch (Exception ignored) {
                senderSigningKeyset = null;
            }
        }

        if (senderSigningKeyset != null) {
            try {
                PublicKeyVerify verify = senderSigningKeyset.getPrimitive(RegistryConfiguration.get(),
                        PublicKeyVerify.class);
                verify.verify(RgCryptoBase64.decode(envelope.signature), envelope.headerBytes());
                signatureState = RgCryptoDecryptResult.SignatureState.VERIFIED;
            } catch (Exception e) {
                signatureState = RgCryptoDecryptResult.SignatureState.UNVERIFIED;
                return RgCryptoDecryptResult.error(RgCryptoDecryptResult.Status.BAD_SIGNATURE, envelope.senderId,
                        signatureState);
            }
        }

        try {
            envelope.verifyCiphertextHash();
        } catch (Exception e) {
            return RgCryptoDecryptResult.error(RgCryptoDecryptResult.Status.BAD_HASH, envelope.senderId,
                    signatureState);
        }

        String myKid = null;
        try {
            myKid = RgCryptoKeys.kidFromKeyset(myHpkePrivKeyset.getPublicKeysetHandle());
        } catch (Exception ignored) {
            myKid = null;
        }
        try {
            byte[] plaintext = envelope.decryptPayload(myHpkePrivKeyset);
            return RgCryptoDecryptResult.ok(new String(plaintext, StandardCharsets.UTF_8),
                    envelope.senderId, signatureState);
        } catch (GeneralSecurityException e) {
            String message = e.getMessage();
            if (message != null && message.contains("Recipient not found")) {
                return RgCryptoDecryptResult.needKey(myKid, envelope.senderId, signatureState);
            }
            return RgCryptoDecryptResult.error(RgCryptoDecryptResult.Status.DECRYPT_FAIL, envelope.senderId,
                    signatureState);
        } catch (Exception e) {
            return RgCryptoDecryptResult.error(RgCryptoDecryptResult.Status.DECRYPT_FAIL, envelope.senderId,
                    signatureState);
        }
    }
}
