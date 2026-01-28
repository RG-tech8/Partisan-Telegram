package org.telegram.messenger.partisan.rgcrypto.storage;

import android.content.Context;
import android.util.SparseArray;

import androidx.annotation.NonNull;
import androidx.room.Database;
import androidx.room.Room;
import androidx.room.RoomDatabase;
import androidx.room.migration.Migration;
import androidx.sqlite.db.SupportSQLiteDatabase;

@Database(entities = {RgCryptoKeyringEntry.class}, version = 3, exportSchema = false)
public abstract class RgCryptoKeyringDatabase extends RoomDatabase {
    private static final Object LOCK = new Object();
    private static final SparseArray<RgCryptoKeyringDatabase> INSTANCES = new SparseArray<>();

    public abstract RgCryptoKeyringDao keyringDao();

    public static RgCryptoKeyringDatabase getInstance(Context context, int account) {
        synchronized (LOCK) {
            RgCryptoKeyringDatabase instance = INSTANCES.get(account);
            if (instance == null) {
                instance = buildDatabase(context.getApplicationContext(), account);
                INSTANCES.put(account, instance);
            }
            return instance;
        }
    }

    private static RgCryptoKeyringDatabase buildDatabase(Context context, int account) {
        String dbName = "rgcrypto_keyring_" + account + ".db";
        return Room.databaseBuilder(context, RgCryptoKeyringDatabase.class, dbName)
                .addMigrations(MIGRATION_1_2, MIGRATION_2_3)
                .build();
    }

    public static final Migration MIGRATION_1_2 = new Migration(1, 2) {
        @Override
        public void migrate(@NonNull SupportSQLiteDatabase db) {
            db.execSQL("ALTER TABLE rgcrypto_keyring ADD COLUMN signature_valid INTEGER NOT NULL DEFAULT 0");
            db.execSQL("ALTER TABLE rgcrypto_keyring ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0");
        }
    };

    public static final Migration MIGRATION_2_3 = new Migration(2, 3) {
        @Override
        public void migrate(@NonNull SupportSQLiteDatabase db) {
            db.execSQL("ALTER TABLE rgcrypto_keyring ADD COLUMN signing_kid TEXT");
            db.execSQL("ALTER TABLE rgcrypto_keyring ADD COLUMN encryption_kid TEXT");
        }
    };
}
