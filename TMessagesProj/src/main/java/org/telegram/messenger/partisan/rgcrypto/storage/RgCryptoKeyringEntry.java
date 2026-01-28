package org.telegram.messenger.partisan.rgcrypto.storage;

import androidx.annotation.NonNull;
import androidx.room.ColumnInfo;
import androidx.room.Entity;
import androidx.room.Index;

import com.google.crypto.tink.KeysetHandle;

import org.telegram.messenger.partisan.rgcrypto.RgCryptoIds;
import org.telegram.messenger.partisan.rgcrypto.RgCryptoKeyCard;
import org.telegram.messenger.partisan.rgcrypto.RgCryptoKeys;

@Entity(
        tableName = "rgcrypto_keyring",
        primaryKeys = {"peer_id", "device_id", "signing_key_id", "encryption_key_id"},
        indices = {
                @Index(value = {"peer_id"}),
                @Index(value = {"signing_key_id"}),
                @Index(value = {"encryption_key_id"})
        }
)
public class RgCryptoKeyringEntry {
    @NonNull
    @ColumnInfo(name = "peer_id")
    public String peerId;

    @NonNull
    @ColumnInfo(name = "device_id")
    public String deviceId;

    @ColumnInfo(name = "signing_key_id")
    public int signingKeyId;

    @ColumnInfo(name = "signing_kid")
    public String signingKid;

    @ColumnInfo(name = "encryption_key_id")
    public int encryptionKeyId;

    @ColumnInfo(name = "encryption_kid")
    public String encryptionKid;

    @NonNull
    @ColumnInfo(name = "signing_keyset_json")
    public String signingKeysetJson;

    @NonNull
    @ColumnInfo(name = "encryption_keyset_json")
    public String encryptionKeysetJson;

    @ColumnInfo(name = "keycard_json")
    public String keycardJson;

    @ColumnInfo(name = "trust_state")
    public int trustState;

    @ColumnInfo(name = "signature_valid")
    public int signatureValid;

    @ColumnInfo(name = "created_at")
    public long createdAt;

    @ColumnInfo(name = "updated_at")
    public long updatedAt;

    public RgCryptoKeyringEntry() {
    }

    public static RgCryptoKeyringEntry fromKeyCard(String peerId, RgCryptoKeyCard keyCard, int trustState,
                                                   int signatureValid, long now) throws Exception {
        RgCryptoKeyringEntry entry = new RgCryptoKeyringEntry();
        entry.peerId = RgCryptoIds.normalizePeerId(peerId);
        entry.deviceId = RgCryptoIds.normalizeDeviceId(keyCard.deviceId);
        entry.signingKeyId = keyCard.signingKeyId;
        entry.signingKid = keyCard.signingKid;
        KeysetHandle enc = RgCryptoKeys.parsePublicKeyset(keyCard.encryptionKeysetJson);
        entry.encryptionKeyId = RgCryptoKeys.primaryKeyId(enc);
        entry.encryptionKid = keyCard.encryptionKid;
        if (entry.signingKid == null && keyCard.signingKeysetJson != null) {
            entry.signingKid = RgCryptoKeys.kidFromKeyset(RgCryptoKeys.parsePublicKeyset(keyCard.signingKeysetJson));
        }
        if (entry.encryptionKid == null) {
            entry.encryptionKid = RgCryptoKeys.kidFromKeyset(enc);
        }
        entry.signingKeysetJson = keyCard.signingKeysetJson;
        entry.encryptionKeysetJson = keyCard.encryptionKeysetJson;
        entry.keycardJson = keyCard.toJson();
        entry.trustState = trustState;
        entry.signatureValid = signatureValid;
        entry.createdAt = now;
        entry.updatedAt = now;
        return entry;
    }
}
