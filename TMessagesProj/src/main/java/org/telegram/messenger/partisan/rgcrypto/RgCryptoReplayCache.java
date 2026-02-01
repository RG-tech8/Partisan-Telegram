package org.telegram.messenger.partisan.rgcrypto;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.SparseArray;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.LinkedHashMap;
import java.util.Map;

public final class RgCryptoReplayCache {
    private static final String PREFS = "rgcrypt_replay_cache";
    private static final int MAX_ENTRIES = 256;
    private static final SparseArray<ReplayStore> stores = new SparseArray<>();

    private static final class ReplayStore {
        final LinkedHashMap<String, Integer> cache =
                new LinkedHashMap<String, Integer>(MAX_ENTRIES, 0.75f, true) {
                    @Override
                    protected boolean removeEldestEntry(Map.Entry<String, Integer> eldest) {
                        return size() > MAX_ENTRIES;
                    }
                };
        boolean loaded;
    }

    private RgCryptoReplayCache() {
    }

    public static boolean markSeen(Context context, int account, String key, int messageId) {
        if (context == null || key == null) {
            return false;
        }
        synchronized (RgCryptoReplayCache.class) {
            ReplayStore store = getStore(account);
            loadIfNeeded(context, store, account);
            Integer existing = store.cache.get(key);
            boolean replay;
            boolean changed = false;
            if (existing == null) {
                store.cache.put(key, messageId);
                replay = false;
                changed = true;
            } else if (existing != messageId) {
                store.cache.put(key, messageId);
                replay = true;
                changed = true;
            } else {
                replay = false;
            }
            if (changed) {
                save(context, store, account);
            }
            return replay;
        }
    }

    private static ReplayStore getStore(int account) {
        ReplayStore store = stores.get(account);
        if (store == null) {
            store = new ReplayStore();
            stores.put(account, store);
        }
        return store;
    }

    private static void loadIfNeeded(Context context, ReplayStore store, int account) {
        if (store.loaded) {
            return;
        }
        store.loaded = true;
        SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String json = prefs.getString(keyName(account), null);
        if (json == null || json.isEmpty()) {
            return;
        }
        try {
            JSONArray array = new JSONArray(json);
            for (int i = 0; i < array.length(); i++) {
                JSONObject obj = array.optJSONObject(i);
                if (obj == null) {
                    continue;
                }
                String key = obj.optString("k", null);
                if (key == null) {
                    continue;
                }
                int value = obj.optInt("v", 0);
                store.cache.put(key, value);
            }
        } catch (Exception ignore) {
            store.cache.clear();
        }
    }

    private static void save(Context context, ReplayStore store, int account) {
        JSONArray array = new JSONArray();
        for (Map.Entry<String, Integer> entry : store.cache.entrySet()) {
            JSONObject obj = new JSONObject();
            try {
                obj.put("k", entry.getKey());
                obj.put("v", entry.getValue());
                array.put(obj);
            } catch (Exception ignore) {
            }
        }
        SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        prefs.edit().putString(keyName(account), array.toString()).apply();
    }

    private static String keyName(int account) {
        return "a" + account;
    }
}
