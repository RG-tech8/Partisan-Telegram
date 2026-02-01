package org.telegram.messenger.partisan.rgcrypto;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public final class RgCryptoFileCodec {
    private static final byte[] MAGIC = new byte[]{'R', 'G', 'C', 'F'};
    private static final int VERSION = 2;
    public static final int STREAM_VERSION = 3;
    private static final int MAX_HEADER_BYTES = 1024 * 1024;

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

    public static void writeStreamingHeader(OutputStream out, RgCryptoEnvelope envelope)
            throws GeneralSecurityException, IOException {
        if (out == null) {
            throw new GeneralSecurityException("output missing");
        }
        if (envelope == null) {
            throw new GeneralSecurityException("envelope missing");
        }
        byte[] payload = envelope.encodeBinary();
        DataOutputStream dos = new DataOutputStream(out);
        dos.write(MAGIC);
        dos.writeByte(STREAM_VERSION);
        dos.writeInt(payload.length);
        dos.write(payload);
        dos.flush();
    }

    public static int readVersion(InputStream in) throws GeneralSecurityException, IOException {
        if (in == null) {
            throw new GeneralSecurityException("input missing");
        }
        DataInputStream dis = new DataInputStream(in);
        byte[] magic = new byte[MAGIC.length];
        dis.readFully(magic);
        for (int i = 0; i < MAGIC.length; i++) {
            if (magic[i] != MAGIC[i]) {
                throw new GeneralSecurityException("invalid magic");
            }
        }
        int version = dis.read();
        if (version < 0) {
            throw new GeneralSecurityException("missing version");
        }
        return version & 0xFF;
    }

    public static RgCryptoEnvelope readStreamingEnvelope(InputStream in) throws GeneralSecurityException, IOException {
        if (in == null) {
            throw new GeneralSecurityException("input missing");
        }
        DataInputStream dis = new DataInputStream(in);
        int length = dis.readInt();
        if (length <= 0 || length > MAX_HEADER_BYTES) {
            throw new GeneralSecurityException("invalid header size");
        }
        byte[] payload = new byte[length];
        dis.readFully(payload);
        return RgCryptoEnvelope.decodeBinary(payload);
    }
}
