package org.telegram.messenger.partisan.rgcrypto;

import android.util.Base64;

public final class RgCryptoBase64 {
    private static final int FLAGS = Base64.NO_WRAP | Base64.URL_SAFE;

    private RgCryptoBase64() {
    }

    public static String encode(byte[] data) {
        return Base64.encodeToString(data, FLAGS);
    }

    public static byte[] decode(String data) {
        try {
            return Base64.decode(data, FLAGS);
        } catch (IllegalArgumentException e) {
            String cleaned = sanitize(data);
            return Base64.decode(cleaned, FLAGS);
        }
    }

    private static String sanitize(String data) {
        if (data == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(data.length());
        for (int i = 0; i < data.length(); i++) {
            char c = data.charAt(i);
            if ((c >= 'A' && c <= 'Z') ||
                    (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') ||
                    c == '-' || c == '_' || c == '=' ) {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
