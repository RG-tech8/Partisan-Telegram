package org.telegram.messenger.partisan.rgcrypto.storage;

import androidx.room.Dao;
import androidx.room.Insert;
import androidx.room.OnConflictStrategy;
import androidx.room.Query;

import java.util.List;

@Dao
public interface RgCryptoKeyringDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    void upsert(RgCryptoKeyringEntry entry);

    @Query("SELECT * FROM rgcrypto_keyring WHERE peer_id = :peerId ORDER BY updated_at DESC")
    List<RgCryptoKeyringEntry> getByPeer(String peerId);

    @Query("SELECT * FROM rgcrypto_keyring WHERE peer_id = :peerId AND signing_key_id = :signingKeyId ORDER BY updated_at DESC LIMIT 1")
    RgCryptoKeyringEntry getByPeerAndSigningKeyId(String peerId, int signingKeyId);

    @Query("SELECT * FROM rgcrypto_keyring WHERE peer_id = :peerId AND signing_kid = :signingKid ORDER BY updated_at DESC LIMIT 1")
    RgCryptoKeyringEntry getByPeerAndSigningKid(String peerId, String signingKid);

    @Query("SELECT * FROM rgcrypto_keyring WHERE peer_id = :peerId AND device_id = :deviceId AND signing_key_id = :signingKeyId AND encryption_key_id = :encryptionKeyId LIMIT 1")
    RgCryptoKeyringEntry getByKeyIds(String peerId, String deviceId, int signingKeyId, int encryptionKeyId);

    @Query("SELECT * FROM rgcrypto_keyring WHERE peer_id = :peerId AND device_id = :deviceId AND signing_kid = :signingKid AND encryption_kid = :encryptionKid LIMIT 1")
    RgCryptoKeyringEntry getByKids(String peerId, String deviceId, String signingKid, String encryptionKid);

    @Query("UPDATE rgcrypto_keyring SET trust_state = :trustState, updated_at = :updatedAt WHERE peer_id = :peerId AND device_id = :deviceId AND signing_key_id = :signingKeyId AND encryption_key_id = :encryptionKeyId")
    int updateTrustState(String peerId, String deviceId, int signingKeyId, int encryptionKeyId, int trustState, long updatedAt);

    @Query("UPDATE rgcrypto_keyring SET signature_valid = :signatureValid, updated_at = :updatedAt WHERE peer_id = :peerId AND device_id = :deviceId AND signing_key_id = :signingKeyId AND encryption_key_id = :encryptionKeyId")
    int updateSignatureState(String peerId, String deviceId, int signingKeyId, int encryptionKeyId, int signatureValid, long updatedAt);

    @Query("UPDATE rgcrypto_keyring SET trust_state = :trustState, updated_at = :updatedAt WHERE peer_id = :peerId AND device_id = :deviceId AND NOT (signing_kid = :signingKid AND encryption_kid = :encryptionKid)")
    int revokeOtherDeviceKeys(String peerId, String deviceId, String signingKid, String encryptionKid, int trustState, long updatedAt);

    @Query("DELETE FROM rgcrypto_keyring WHERE peer_id = :peerId AND device_id = :deviceId AND signing_key_id = :signingKeyId AND encryption_key_id = :encryptionKeyId")
    int deleteByKeyIds(String peerId, String deviceId, int signingKeyId, int encryptionKeyId);

    @Query("DELETE FROM rgcrypto_keyring")
    void clearAll();
}
