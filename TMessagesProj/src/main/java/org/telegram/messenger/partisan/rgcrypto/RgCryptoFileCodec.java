package org.telegram.messenger.partisan.rgcrypto;

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public final class RgCryptoFileCodec {
    private static final byte[] MAGIC = new byte[]{'R', 'G', 'C', 'F'};
    private static final int VERSION = 2;

    private RgCryptoFileCodec() {
    }

    public static byte[] encodeV2(RgCryptoEnvelope envelope) throws GeneralSecurityException {
        if (envelope == null) {
            throw new GeneralSecurityException("envelope missing");
        }
        byte[] payload = envelope.encodeBinary();
        ByteArrayOutputStream out = new ByteArrayOutputStream(MAGIC.length + 1 + payload.length);
        out.write(MAGIC, 0, MAGIC.length);
        out.write(VERSION);
        out.write(payload, 0, payload.length);
        return out.toByteArray();
    }

    public static RgCryptoEnvelope decodeV2(byte[] data) throws GeneralSecurityException {
        if (data == null || data.length < MAGIC.length + 1) {
            throw new GeneralSecurityException("invalid file");
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (data[i] != MAGIC[i]) {
                throw new GeneralSecurityException("invalid magic");
            }
        }
        int version = data[MAGIC.length] & 0xFF;
        if (version != VERSION) {
            throw new GeneralSecurityException("unsupported version");
        }
        byte[] payload = Arrays.copyOfRange(data, MAGIC.length + 1, data.length);
        return RgCryptoEnvelope.decodeBinary(payload);
    }
}
