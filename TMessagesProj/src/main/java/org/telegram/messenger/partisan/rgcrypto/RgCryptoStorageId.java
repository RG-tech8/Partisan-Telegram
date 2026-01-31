package org.telegram.messenger.partisan.rgcrypto;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import org.telegram.messenger.UserConfig;

import java.security.MessageDigest;
import java.security.SecureRandom;

public final class RgCryptoStorageId {
    private static final String PREFS = "rgcrypto";
    private static final String SALT_KEY = "rgcrypto_storage_salt_v1";
    private static final int SALT_BYTES = 16;

    private RgCryptoStorageId() {
    }

    public static String getStorageId(Context context, int account) {
        if (context == null) {
            return "k0";
        }
        long userId = UserConfig.getInstance(account).getClientUserId();
        byte[] salt = getOrCreateSalt(context.getApplicationContext());
        byte[] digest = sha256(userId, salt);
        return "k" + toHex(digest);
    }

    private static byte[] getOrCreateSalt(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String encoded = prefs.getString(SALT_KEY, null);
        if (encoded != null) {
            try {
                byte[] decoded = Base64.decode(encoded, Base64.NO_WRAP);
                if (decoded != null && decoded.length >= 8) {
                    return decoded;
                }
            } catch (Exception ignore) {
            }
        }
        byte[] salt = new byte[SALT_BYTES];
        new SecureRandom().nextBytes(salt);
        prefs.edit().putString(SALT_KEY, Base64.encodeToString(salt, Base64.NO_WRAP)).apply();
        return salt;
    }

    private static byte[] sha256(long userId, byte[] salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(longToBytes(userId));
            digest.update((byte) ':');
            if (salt != null) {
                digest.update(salt);
            }
            return digest.digest();
        } catch (Exception e) {
            return longToBytes(userId);
        }
    }

    private static byte[] longToBytes(long value) {
        byte[] out = new byte[8];
        for (int i = 7; i >= 0; i--) {
            out[i] = (byte) (value & 0xFF);
            value >>= 8;
        }
        return out;
    }

    private static String toHex(byte[] data) {
        if (data == null || data.length == 0) {
            return "0";
        }
        char[] out = new char[data.length * 2];
        int i = 0;
        for (byte b : data) {
            int v = b & 0xFF;
            out[i++] = hex(v >>> 4);
            out[i++] = hex(v & 0x0F);
        }
        return new String(out);
    }

    private static char hex(int v) {
        return (char) (v < 10 ? ('0' + v) : ('a' + (v - 10)));
    }
}
