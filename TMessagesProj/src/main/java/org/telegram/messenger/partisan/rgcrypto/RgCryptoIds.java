package org.telegram.messenger.partisan.rgcrypto;

public final class RgCryptoIds {
    public static final String DEFAULT_DEVICE_ID = "default";

    private RgCryptoIds() {
    }

    public static String normalizePeerId(String peerId) {
        if (peerId == null) {
            throw new IllegalArgumentException("peerId is null");
        }
        String trimmed = peerId.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("peerId is empty");
        }
        return trimmed;
    }

    public static String normalizeDeviceId(String deviceId) {
        if (deviceId == null) {
            return DEFAULT_DEVICE_ID;
        }
        String trimmed = deviceId.trim();
        return trimmed.isEmpty() ? DEFAULT_DEVICE_ID : trimmed;
    }
}
