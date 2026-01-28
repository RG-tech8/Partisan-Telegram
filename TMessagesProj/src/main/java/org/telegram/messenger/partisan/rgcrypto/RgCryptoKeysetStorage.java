package org.telegram.messenger.partisan.rgcrypto;

import android.content.Context;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.integration.android.AndroidKeysetManager;

import java.io.IOException;
import java.security.GeneralSecurityException;

public final class RgCryptoKeysetStorage {
    private static final String MASTER_KEY_URI = "android-keystore://rgcrypto_master_key";
    private static final String PREF_FILE = "rgcrypto_keysets";

    private RgCryptoKeysetStorage() {
    }

    public static KeysetHandle getOrCreateSigningKeyset(Context context, int account, String deviceId)
            throws GeneralSecurityException, IOException {
        String keysetName = keysetName("signing", account, deviceId);
        return new AndroidKeysetManager.Builder()
                .withSharedPref(context.getApplicationContext(), keysetName, PREF_FILE)
                .withKeyTemplate(RgCryptoKeys.ed25519KeyTemplate())
                .withMasterKeyUri(MASTER_KEY_URI)
                .build()
                .getKeysetHandle();
    }

    public static KeysetHandle getOrCreateHpkeKeyset(Context context, int account, String deviceId)
            throws GeneralSecurityException, IOException {
        String keysetName = keysetName("hpke", account, deviceId);
        return new AndroidKeysetManager.Builder()
                .withSharedPref(context.getApplicationContext(), keysetName, PREF_FILE)
                .withKeyTemplate(RgCryptoKeys.hpkeKeyTemplate())
                .withMasterKeyUri(MASTER_KEY_URI)
                .build()
                .getKeysetHandle();
    }

    public static void resetKeysets(Context context, int account, String deviceId) {
        String signingKey = keysetName("signing", account, deviceId);
        String hpkeKey = keysetName("hpke", account, deviceId);
        context.getApplicationContext()
                .getSharedPreferences(PREF_FILE, Context.MODE_PRIVATE)
                .edit()
                .remove(signingKey)
                .remove(hpkeKey)
                .apply();
    }

    private static String keysetName(String kind, int account, String deviceId) {
        String safeDeviceId = deviceId == null ? "default" : deviceId;
        return "rgcrypto_" + kind + "_" + account + "_" + safeDeviceId;
    }
}
