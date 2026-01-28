package org.telegram.messenger.partisan.rgcrypto;

public final class RgCryptoKeyCardCodec {
    private RgCryptoKeyCardCodec() {
    }

    public static String pack(RgCryptoKeyCard card) throws Exception {
        byte[] json = RgCryptoJson.toBytes(card);
        return RgCryptoConstants.KEYCARD_PREFIX + RgCryptoBase64.encode(json);
    }

    public static RgCryptoKeyCard unpack(String text) throws Exception {
        if (text == null || !text.startsWith(RgCryptoConstants.KEYCARD_PREFIX)) {
            throw new IllegalArgumentException("Missing RGKEY prefix");
        }
        String base64 = text.substring(RgCryptoConstants.KEYCARD_PREFIX.length());
        byte[] json = RgCryptoBase64.decode(base64);
        return RgCryptoKeyCard.fromBytes(json);
    }
}
