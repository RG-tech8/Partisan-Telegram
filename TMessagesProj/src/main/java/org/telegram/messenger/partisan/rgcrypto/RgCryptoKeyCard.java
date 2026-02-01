package org.telegram.messenger.partisan.rgcrypto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.RegistryConfiguration;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;

public final class RgCryptoKeyCard {
    @JsonProperty("v")
    public int version;

    @JsonProperty("device_id")
    public String deviceId;

    @JsonProperty("signing_key_id")
    public int signingKeyId;

    @JsonProperty("signing_kid")
    public String signingKid;

    @JsonProperty("signing_keyset")
    public String signingKeysetJson;

    @JsonProperty("encryption_kid")
    public String encryptionKid;

    @JsonProperty("encryption_keyset")
    public String encryptionKeysetJson;

    @JsonProperty("signature")
    public String signature;

    public RgCryptoKeyCard() {
    }

    public static RgCryptoKeyCard create(KeysetHandle signingPrivate, KeysetHandle encryptionPrivate, String deviceId)
            throws GeneralSecurityException {
        RgCryptoKeyCard card = new RgCryptoKeyCard();
        card.version = RgCryptoConstants.VERSION;
        card.deviceId = RgCryptoIds.normalizeDeviceId(deviceId);
        card.signingKeyId = RgCryptoKeys.primaryKeyId(signingPrivate);
        card.signingKeysetJson = RgCryptoKeys.serializePublicKeyset(signingPrivate);
        card.encryptionKeysetJson = RgCryptoKeys.serializePublicKeyset(encryptionPrivate);
        card.signingKid = RgCryptoKeys.kidFromKeyset(signingPrivate.getPublicKeysetHandle());
        card.encryptionKid = RgCryptoKeys.kidFromKeyset(encryptionPrivate.getPublicKeysetHandle());
        card.signature = signCard(card, signingPrivate);
        return card;
    }

    public boolean verifySelf() throws GeneralSecurityException {
        KeysetHandle signingPublic = RgCryptoKeys.parsePublicKeyset(signingKeysetJson);
        PublicKeyVerify verify = signingPublic.getPrimitive(RegistryConfiguration.get(), PublicKeyVerify.class);
        byte[] data = signatureInput();
        verify.verify(RgCryptoBase64.decode(signature), data);
        return true;
    }

    public KeysetHandle signingPublicKeyset() throws GeneralSecurityException {
        return RgCryptoKeys.parsePublicKeyset(signingKeysetJson);
    }

    public KeysetHandle encryptionPublicKeyset() throws GeneralSecurityException {
        return RgCryptoKeys.parsePublicKeyset(encryptionKeysetJson);
    }

    @JsonIgnore
    public String toJson() throws Exception {
        return RgCryptoJson.toJson(this);
    }

    public static RgCryptoKeyCard fromJson(String json) throws Exception {
        return RgCryptoJson.fromJson(json, RgCryptoKeyCard.class);
    }

    public static RgCryptoKeyCard fromBytes(byte[] json) throws Exception {
        return RgCryptoJson.fromBytes(json, RgCryptoKeyCard.class);
    }

    @JsonIgnore
    public static RgCryptoKeyCard parseAndVerify(String json) throws Exception {
        RgCryptoKeyCard card = fromJson(json);
        card.verifySelf();
        return card;
    }

    @JsonIgnore
    private static String signCard(RgCryptoKeyCard card, KeysetHandle signingPrivate) throws GeneralSecurityException {
        PublicKeySign signer = signingPrivate.getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);
        byte[] data = card.signatureInput();
        return RgCryptoBase64.encode(signer.sign(data));
    }

    @JsonIgnore
    public byte[] signatureInput() throws GeneralSecurityException {
        try {
            return RgCryptoJson.canonicalBytes(unsignedMap());
        } catch (Exception e) {
            throw new GeneralSecurityException("Failed to build signature input", e);
        }
    }

    @JsonIgnore
    public String fingerprintSha256() throws GeneralSecurityException {
        return RgCryptoBase64.encode(fingerprintBytes());
    }

    @JsonIgnore
    public String safetyNumber() throws GeneralSecurityException {
        try {
            byte[] hash = fingerprintBytes();
            BigInteger num = new BigInteger(1, hash);
            BigInteger mod = BigInteger.TEN.pow(60);
            String digits = num.mod(mod).toString();
            StringBuilder padded = new StringBuilder(60);
            for (int i = digits.length(); i < 60; i++) {
                padded.append('0');
            }
            padded.append(digits);
            String value = padded.toString();
            StringBuilder out = new StringBuilder(80);
            int group = 0;
            for (int i = 0; i < value.length(); i += 10) {
                if (i > 0) {
                    if (group == 3) {
                        out.append('\n');
                        group = 0;
                    } else {
                        out.append(' ');
                    }
                }
                out.append(value, i, i + 10);
                group++;
            }
            return out.toString();
        } catch (Exception e) {
            throw new GeneralSecurityException("safety number failed", e);
        }
    }

    @JsonIgnore
    private byte[] fingerprintBytes() throws GeneralSecurityException {
        try {
            byte[] data = (signingKeysetJson + "|" + encryptionKeysetJson).getBytes(StandardCharsets.UTF_8);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (Exception e) {
            throw new GeneralSecurityException("fingerprint failed", e);
        }
    }

    @JsonIgnore
    private Map<String, Object> unsignedMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("v", version);
        if (deviceId != null) {
            map.put("device_id", deviceId);
        }
        map.put("signing_key_id", signingKeyId);
        if (signingKid != null) {
            map.put("signing_kid", signingKid);
        }
        map.put("signing_keyset", signingKeysetJson);
        if (encryptionKid != null) {
            map.put("encryption_kid", encryptionKid);
        }
        map.put("encryption_keyset", encryptionKeysetJson);
        return map;
    }
}
