package org.telegram.messenger.partisan.rgcrypto;

import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.hybrid.HybridConfig;
import com.google.crypto.tink.signature.SignatureConfig;
import com.google.crypto.tink.streamingaead.StreamingAeadConfig;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public final class RgCrypto {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static boolean initialized;

    private RgCrypto() {
    }

    public static synchronized void initialize() throws GeneralSecurityException {
        if (initialized) {
            return;
        }
        AeadConfig.register();
        HybridConfig.register();
        SignatureConfig.register();
        StreamingAeadConfig.register();
        initialized = true;
    }

    public static byte[] randomBytes(int size) {
        byte[] out = new byte[size];
        RANDOM.nextBytes(out);
        return out;
    }
}
