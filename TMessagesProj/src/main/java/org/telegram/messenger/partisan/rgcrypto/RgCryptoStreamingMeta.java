package org.telegram.messenger.partisan.rgcrypto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public final class RgCryptoStreamingMeta {
    public static final int VERSION = 1;

    @JsonProperty("v")
    public int version;

    @JsonProperty("keyset")
    public String keyset;

    @JsonProperty("name")
    public String name;

    @JsonProperty("mime")
    public String mime;

    public RgCryptoStreamingMeta() {
    }

    public static RgCryptoStreamingMeta create(byte[] keysetBytes, String name, String mime) {
        RgCryptoStreamingMeta meta = new RgCryptoStreamingMeta();
        meta.version = VERSION;
        meta.keyset = RgCryptoBase64.encode(keysetBytes);
        meta.name = name;
        meta.mime = mime;
        return meta;
    }

    public static RgCryptoStreamingMeta fromPayload(byte[] payload) throws Exception {
        return RgCryptoJson.fromBytes(payload, RgCryptoStreamingMeta.class);
    }

    public static RgCryptoStreamingMeta fromPayloadOrLegacy(byte[] payload) throws Exception {
        if (payload == null || payload.length == 0) {
            throw new IllegalArgumentException("missing payload");
        }
        try {
            RgCryptoStreamingMeta meta = fromPayload(payload);
            if (meta != null && meta.keyset != null && !meta.keyset.isEmpty()) {
                return meta;
            }
        } catch (Exception ignored) {
        }
        RgCryptoStreamingMeta legacy = new RgCryptoStreamingMeta();
        legacy.version = 0;
        legacy.keyset = RgCryptoBase64.encode(payload);
        return legacy;
    }

    @JsonIgnore
    public byte[] toPayload() throws Exception {
        return RgCryptoJson.toBytes(this);
    }

    @JsonIgnore
    public byte[] keysetBytes() throws Exception {
        if (keyset == null || keyset.isEmpty()) {
            throw new IllegalArgumentException("missing keyset");
        }
        return RgCryptoBase64.decode(keyset);
    }
}
