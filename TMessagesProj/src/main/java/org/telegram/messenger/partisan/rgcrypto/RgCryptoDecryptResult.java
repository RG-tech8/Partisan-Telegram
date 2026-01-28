package org.telegram.messenger.partisan.rgcrypto;

public final class RgCryptoDecryptResult {
    public enum Status {
        OK,
        NEED_KEY,
        BAD_SIGNATURE,
        BAD_HASH,
        DECRYPT_FAIL,
        PARSE_FAIL
    }

    public enum SignatureState {
        VERIFIED,
        UNVERIFIED,
        UNKNOWN
    }

    public Status status;
    public String plaintext;
    public String senderId;
    public SignatureState signatureState;
    public String missingKid;

    public static RgCryptoDecryptResult ok(String plaintext, String senderId, SignatureState signatureState) {
        RgCryptoDecryptResult result = new RgCryptoDecryptResult();
        result.status = Status.OK;
        result.plaintext = plaintext;
        result.senderId = senderId;
        result.signatureState = signatureState;
        return result;
    }

    public static RgCryptoDecryptResult needKey(String missingKid, String senderId, SignatureState signatureState) {
        RgCryptoDecryptResult result = new RgCryptoDecryptResult();
        result.status = Status.NEED_KEY;
        result.missingKid = missingKid;
        result.senderId = senderId;
        result.signatureState = signatureState;
        return result;
    }

    public static RgCryptoDecryptResult error(Status status, String senderId, SignatureState signatureState) {
        RgCryptoDecryptResult result = new RgCryptoDecryptResult();
        result.status = status;
        result.senderId = senderId;
        result.signatureState = signatureState;
        return result;
    }
}
