package org.telegram.messenger.partisan.rgcrypto;

public final class RgCryptoConstants {
    public static final int VERSION = 1;
    public static final String PREFIX = "RGCRYPT:";
    public static final String KEYCARD_PREFIX = "RGKEY:";
    public static final String KEYREQ_PREFIX = "RGKEYREQ:";
    public static final String PREF_AUTO_DECRYPT = "rgcrypt_auto_decrypt";
    public static final String FILE_EXT = ".rgcrypt";
    public static final String FILE_MIME = "application/octet-stream";
    public static final int MAX_FILE_BYTES = 1024 * 1024;
    public static final String CONTENT_AUTHORITY_SUFFIX = ".rgcrypt";
    public static final String CONTENT_PATH = "rgcrypt";
    public static final String HPKE_TEMPLATE = "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM";
    public static final String SIGNING_TEMPLATE = "ED25519";
    public static final String AEAD_ALG = "AES256_GCM";
    public static final String STREAMING_AEAD_TEMPLATE = "AES256_GCM_HKDF_4KB";

    private RgCryptoConstants() {
    }
}
