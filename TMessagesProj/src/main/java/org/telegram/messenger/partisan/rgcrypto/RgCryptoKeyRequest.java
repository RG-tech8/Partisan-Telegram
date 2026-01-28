package org.telegram.messenger.partisan.rgcrypto;

import com.fasterxml.jackson.annotation.JsonProperty;

public final class RgCryptoKeyRequest {
    @JsonProperty("v")
    public int version;

    @JsonProperty("requester_id")
    public String requesterId;

    @JsonProperty("nonce")
    public String nonce;

    public static String pack(String requesterId) throws Exception {
        RgCryptoKeyRequest req = new RgCryptoKeyRequest();
        req.version = RgCryptoConstants.VERSION;
        req.requesterId = requesterId;
        req.nonce = RgCryptoBase64.encode(RgCrypto.randomBytes(16));
        byte[] json = RgCryptoJson.toBytes(req);
        return RgCryptoConstants.KEYREQ_PREFIX + RgCryptoBase64.encode(json);
    }

    public static RgCryptoKeyRequest unpack(String text) throws Exception {
        if (text == null || !text.startsWith(RgCryptoConstants.KEYREQ_PREFIX)) {
            throw new IllegalArgumentException("Missing RGKEYREQ prefix");
        }
        String base64 = text.substring(RgCryptoConstants.KEYREQ_PREFIX.length());
        byte[] json = RgCryptoBase64.decode(base64);
        return RgCryptoJson.fromBytes(json, RgCryptoKeyRequest.class);
    }
}
