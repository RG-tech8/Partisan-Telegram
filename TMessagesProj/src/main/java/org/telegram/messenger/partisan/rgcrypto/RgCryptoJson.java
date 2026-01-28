package org.telegram.messenger.partisan.rgcrypto;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.IOException;
import java.util.Map;

public final class RgCryptoJson {
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    private static final ObjectWriter CANONICAL_WRITER = MAPPER.writer();

    private RgCryptoJson() {
    }

    public static String toJson(Object value) throws JsonProcessingException {
        return CANONICAL_WRITER.writeValueAsString(value);
    }

    public static byte[] toBytes(Object value) throws JsonProcessingException {
        return CANONICAL_WRITER.writeValueAsBytes(value);
    }

    public static <T> T fromJson(String json, Class<T> type) throws IOException {
        return MAPPER.readValue(json, type);
    }

    public static <T> T fromBytes(byte[] json, Class<T> type) throws IOException {
        return MAPPER.readValue(json, type);
    }

    public static byte[] canonicalBytes(Map<String, Object> map) throws JsonProcessingException {
        return CANONICAL_WRITER.writeValueAsBytes(map);
    }
}
