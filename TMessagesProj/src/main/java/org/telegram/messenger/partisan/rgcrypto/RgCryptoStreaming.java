package org.telegram.messenger.partisan.rgcrypto;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.streamingaead.PredefinedStreamingAeadParameters;
import com.google.crypto.tink.BinaryKeysetReader;
import com.google.crypto.tink.BinaryKeysetWriter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

public final class RgCryptoStreaming {
    private RgCryptoStreaming() {
    }

    public static KeysetHandle generateStreamingKeyset() throws GeneralSecurityException {
        return KeysetHandle.generateNew(PredefinedStreamingAeadParameters.AES256_GCM_HKDF_4KB);
    }

    public static byte[] serializeKeyset(KeysetHandle keyset) throws GeneralSecurityException, IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        CleartextKeysetHandle.write(keyset, BinaryKeysetWriter.withOutputStream(out));
        return out.toByteArray();
    }

    public static KeysetHandle parseKeyset(byte[] data) throws GeneralSecurityException, IOException {
        return CleartextKeysetHandle.read(BinaryKeysetReader.withInputStream(new ByteArrayInputStream(data)));
    }

    public static OutputStream encryptingStream(KeysetHandle keyset, OutputStream output, byte[] aad)
            throws GeneralSecurityException, IOException {
        StreamingAead streamingAead = keyset.getPrimitive(RegistryConfiguration.get(), StreamingAead.class);
        return streamingAead.newEncryptingStream(output, aad);
    }

    public static InputStream decryptingStream(KeysetHandle keyset, InputStream input, byte[] aad)
            throws GeneralSecurityException, IOException {
        StreamingAead streamingAead = keyset.getPrimitive(RegistryConfiguration.get(), StreamingAead.class);
        return streamingAead.newDecryptingStream(input, aad);
    }
}
