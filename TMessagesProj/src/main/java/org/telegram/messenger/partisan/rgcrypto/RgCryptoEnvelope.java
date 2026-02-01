package org.telegram.messenger.partisan.rgcrypto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.protobuf.CodedInputStream;
import com.google.protobuf.CodedOutputStream;
import com.google.protobuf.WireFormat;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class RgCryptoEnvelope {
    @JsonProperty("v")
    public int version;

    @JsonProperty("type")
    public String type;

    @JsonProperty("dialog_scope")
    public String dialogScope;

    @JsonProperty("sender_id")
    public String senderId;

    @JsonProperty("sender_signing_key_id")
    public int senderSigningKeyId;

    @JsonProperty("sender_signing_kid")
    public String senderSigningKid;

    @JsonProperty("sender_signing_keyset")
    public String senderSigningKeysetJson;

    @JsonProperty("recipients")
    public List<RecipientEntry> recipients;

    @JsonProperty("aead_alg")
    public String aeadAlg;

    @JsonProperty("hpke_alg")
    public String hpkeAlg;

    @JsonProperty("ciphertext")
    public String ciphertext;

    @JsonProperty("msg_nonce")
    public String msgNonce;

    @JsonProperty("created_at_ms")
    public long createdAtMs;

    @JsonProperty("ciphertext_sha256")
    public String ciphertextSha256;

    @JsonProperty("signature")
    public String signature;

    public RgCryptoEnvelope() {
    }

    public static RgCryptoEnvelope packText(String plaintext, String dialogScope, String senderId,
                                            KeysetHandle signingPrivate,
                                            List<RgCryptoRecipientPublic> recipientPublicKeys)
            throws GeneralSecurityException {
        return packBytes("TEXT", plaintext.getBytes(StandardCharsets.UTF_8), dialogScope, senderId, signingPrivate,
                recipientPublicKeys);
    }

    public static RgCryptoEnvelope packBytes(String type, byte[] payload, String dialogScope, String senderId,
                                             KeysetHandle signingPrivate,
                                             List<RgCryptoRecipientPublic> recipientPublicKeys)
            throws GeneralSecurityException {
        RgCryptoEnvelope envelope = new RgCryptoEnvelope();
        envelope.version = RgCryptoConstants.VERSION;
        envelope.type = type;
        envelope.dialogScope = dialogScope;
        envelope.senderId = senderId;
        envelope.senderSigningKeyId = RgCryptoKeys.primaryKeyId(signingPrivate);
        envelope.senderSigningKid = RgCryptoKeys.kidFromKeyset(signingPrivate.getPublicKeysetHandle());
        envelope.aeadAlg = RgCryptoConstants.AEAD_ALG;
        envelope.hpkeAlg = RgCryptoConstants.HPKE_TEMPLATE;
        envelope.msgNonce = RgCryptoBase64.encode(RgCrypto.randomBytes(16));
        envelope.createdAtMs = System.currentTimeMillis();

        byte[] msgKey = RgCrypto.randomBytes(32);
        envelope.recipients = wrapRecipients(msgKey, recipientPublicKeys, envelope.senderSigningKid);
        byte[] aad = envelope.aadBytes();
        byte[] ciphertext = RgCryptoAead.encrypt(msgKey, payload, aad);
        envelope.ciphertext = RgCryptoBase64.encode(ciphertext);
        envelope.ciphertextSha256 = RgCryptoBase64.encode(sha256(ciphertext));
        envelope.signature = signEnvelope(envelope, signingPrivate);
        return envelope;
    }

    public String decryptText(KeysetHandle recipientPrivate, KeysetHandle senderSigningPublic)
            throws GeneralSecurityException {
        byte[] data = decryptBytes(recipientPrivate, senderSigningPublic);
        return new String(data, StandardCharsets.UTF_8);
    }

    public byte[] decryptBytes(KeysetHandle recipientPrivate, KeysetHandle senderSigningPublic)
            throws GeneralSecurityException {
        verifyCiphertextHash();
        verifySignature(senderSigningPublic);
        return decryptPayload(recipientPrivate);
    }

    public boolean verifySignature(KeysetHandle senderSigningPublic) throws GeneralSecurityException {
        PublicKeyVerify verify = senderSigningPublic.getPrimitive(RegistryConfiguration.get(), PublicKeyVerify.class);
        verify.verify(RgCryptoBase64.decode(signature), headerBytes());
        return true;
    }

    public String encodeForTransport() throws Exception {
        return RgCryptoConstants.PREFIX + RgCryptoBase64.encode(RgCryptoJson.toBytes(this));
    }

    public static RgCryptoEnvelope decodeFromTransport(String text) throws Exception {
        if (text == null) {
            throw new IllegalArgumentException("Missing RGCRYPT prefix");
        }
        String normalized = text.trim();
        int idx = normalized.indexOf(RgCryptoConstants.PREFIX);
        if (idx < 0) {
            throw new IllegalArgumentException("Missing RGCRYPT prefix");
        }
        String base64 = normalized.substring(idx + RgCryptoConstants.PREFIX.length());
        byte[] json = RgCryptoBase64.decode(base64);
        return RgCryptoJson.fromBytes(json, RgCryptoEnvelope.class);
    }

    public byte[] encodeBinary() throws GeneralSecurityException {
        try {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            CodedOutputStream output = CodedOutputStream.newInstance(out);
            output.writeInt32(1, version);
            if (type != null) {
                output.writeString(2, type);
            }
            output.writeInt32(3, senderSigningKeyId);
            if (recipients != null) {
                for (RecipientEntry entry : recipients) {
                    byte[] bytes = recipientEntryBinaryBytes(entry);
                    output.writeTag(4, WireFormat.WIRETYPE_LENGTH_DELIMITED);
                    output.writeUInt32NoTag(bytes.length);
                    output.writeRawBytes(bytes);
                }
            }
            if (aeadAlg != null) {
                output.writeString(5, aeadAlg);
            }
            if (hpkeAlg != null) {
                output.writeString(6, hpkeAlg);
            }
            if (ciphertextSha256 != null) {
                output.writeByteArray(7, RgCryptoBase64.decode(ciphertextSha256));
            }
            if (dialogScope != null) {
                output.writeString(8, dialogScope);
            }
            if (senderId != null) {
                output.writeString(9, senderId);
            }
            if (senderSigningKid != null) {
                output.writeString(10, senderSigningKid);
            }
            if (msgNonce != null) {
                output.writeByteArray(11, RgCryptoBase64.decode(msgNonce));
            }
            if (createdAtMs != 0) {
                output.writeInt64(12, createdAtMs);
            }
            if (ciphertext != null) {
                output.writeByteArray(13, RgCryptoBase64.decode(ciphertext));
            }
            if (signature != null) {
                output.writeByteArray(14, RgCryptoBase64.decode(signature));
            }
            if (senderSigningKeysetJson != null) {
                output.writeString(15, senderSigningKeysetJson);
            }
            output.flush();
            return out.toByteArray();
        } catch (Exception e) {
            throw new GeneralSecurityException("Failed to encode binary envelope", e);
        }
    }

    public static RgCryptoEnvelope decodeBinary(byte[] data) throws GeneralSecurityException {
        if (data == null) {
            throw new GeneralSecurityException("missing data");
        }
        RgCryptoEnvelope envelope = new RgCryptoEnvelope();
        try {
            CodedInputStream input = CodedInputStream.newInstance(data);
            while (!input.isAtEnd()) {
                int tag = input.readTag();
                if (tag == 0) {
                    break;
                }
                int fieldNumber = WireFormat.getTagFieldNumber(tag);
                switch (fieldNumber) {
                    case 1:
                        envelope.version = input.readInt32();
                        break;
                    case 2:
                        envelope.type = input.readString();
                        break;
                    case 3:
                        envelope.senderSigningKeyId = input.readInt32();
                        break;
                    case 4:
                        RecipientEntry entry = recipientEntryFromBinary(input.readByteArray());
                        if (envelope.recipients == null) {
                            envelope.recipients = new ArrayList<>();
                        }
                        envelope.recipients.add(entry);
                        break;
                    case 5:
                        envelope.aeadAlg = input.readString();
                        break;
                    case 6:
                        envelope.hpkeAlg = input.readString();
                        break;
                    case 7:
                        envelope.ciphertextSha256 = RgCryptoBase64.encode(input.readByteArray());
                        break;
                    case 8:
                        envelope.dialogScope = input.readString();
                        break;
                    case 9:
                        envelope.senderId = input.readString();
                        break;
                    case 10:
                        envelope.senderSigningKid = input.readString();
                        break;
                    case 11:
                        envelope.msgNonce = RgCryptoBase64.encode(input.readByteArray());
                        break;
                    case 12:
                        envelope.createdAtMs = input.readInt64();
                        break;
                    case 13:
                        envelope.ciphertext = RgCryptoBase64.encode(input.readByteArray());
                        break;
                    case 14:
                        envelope.signature = RgCryptoBase64.encode(input.readByteArray());
                        break;
                    case 15:
                        envelope.senderSigningKeysetJson = input.readString();
                        break;
                    default:
                        input.skipField(tag);
                        break;
                }
            }
        } catch (Exception e) {
            throw new GeneralSecurityException("Failed to decode binary envelope", e);
        }
        return envelope;
    }

    @JsonIgnore
    public byte[] signatureInput() throws GeneralSecurityException {
        return headerBytes();
    }

    @JsonIgnore
    public byte[] headerBytes() throws GeneralSecurityException {
        return headerBytesInternal(true);
    }

    @JsonIgnore
    public byte[] aadBytes() throws GeneralSecurityException {
        return headerBytesInternal(false);
    }

    @JsonIgnore
    private byte[] headerBytesInternal(boolean includeCiphertextHash) throws GeneralSecurityException {
        try {
            byte[] cipherHash = null;
            if (includeCiphertextHash) {
                if (ciphertextSha256 == null) {
                    throw new GeneralSecurityException("ciphertext_sha256 missing");
                }
                cipherHash = RgCryptoBase64.decode(ciphertextSha256);
            }

            List<byte[]> recipientBytes = new ArrayList<>();
            int recipientsSize = 0;
            if (recipients != null) {
                for (RecipientEntry entry : recipients) {
                    byte[] bytes = recipientEntryBytes(entry);
                    recipientBytes.add(bytes);
                    recipientsSize += CodedOutputStream.computeTagSize(4)
                            + CodedOutputStream.computeUInt32SizeNoTag(bytes.length)
                            + bytes.length;
                }
            }

            int size = 0;
            size += CodedOutputStream.computeInt32Size(1, version);
            size += CodedOutputStream.computeStringSize(2, type);
            size += CodedOutputStream.computeInt32Size(3, senderSigningKeyId);
            size += recipientsSize;
            if (senderSigningKid != null) {
                size += CodedOutputStream.computeStringSize(10, senderSigningKid);
            }
            if (dialogScope != null) {
                size += CodedOutputStream.computeStringSize(8, dialogScope);
            }
            if (senderId != null) {
                size += CodedOutputStream.computeStringSize(9, senderId);
            }
            if (aeadAlg != null) {
                size += CodedOutputStream.computeStringSize(5, aeadAlg);
            }
            if (hpkeAlg != null) {
                size += CodedOutputStream.computeStringSize(6, hpkeAlg);
            }
            if (msgNonce != null) {
                size += CodedOutputStream.computeByteArraySize(11, RgCryptoBase64.decode(msgNonce));
            }
            if (createdAtMs != 0) {
                size += CodedOutputStream.computeInt64Size(12, createdAtMs);
            }
            if (cipherHash != null) {
                size += CodedOutputStream.computeByteArraySize(7, cipherHash);
            }

            byte[] buffer = new byte[size];
            CodedOutputStream output = CodedOutputStream.newInstance(buffer);
            output.writeInt32(1, version);
            output.writeString(2, type);
            output.writeInt32(3, senderSigningKeyId);
            for (byte[] bytes : recipientBytes) {
                output.writeTag(4, WireFormat.WIRETYPE_LENGTH_DELIMITED);
                output.writeUInt32NoTag(bytes.length);
                output.writeRawBytes(bytes);
            }
            if (senderSigningKid != null) {
                output.writeString(10, senderSigningKid);
            }
            if (dialogScope != null) {
                output.writeString(8, dialogScope);
            }
            if (senderId != null) {
                output.writeString(9, senderId);
            }
            if (aeadAlg != null) {
                output.writeString(5, aeadAlg);
            }
            if (hpkeAlg != null) {
                output.writeString(6, hpkeAlg);
            }
            if (msgNonce != null) {
                output.writeByteArray(11, RgCryptoBase64.decode(msgNonce));
            }
            if (createdAtMs != 0) {
                output.writeInt64(12, createdAtMs);
            }
            if (cipherHash != null) {
                output.writeByteArray(7, cipherHash);
            }
            output.flush();
            return buffer;
        } catch (Exception e) {
            throw new GeneralSecurityException("Failed to build header bytes", e);
        }
    }

    @JsonIgnore
    private Map<String, Object> unsignedMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("v", version);
        map.put("type", type);
        if (dialogScope != null) {
            map.put("dialog_scope", dialogScope);
        }
        if (senderId != null) {
            map.put("sender_id", senderId);
        }
        map.put("sender_signing_key_id", senderSigningKeyId);
        if (senderSigningKid != null) {
            map.put("sender_signing_kid", senderSigningKid);
        }
        if (senderSigningKeysetJson != null) {
            map.put("sender_signing_keyset", senderSigningKeysetJson);
        }
        map.put("recipients", recipients);
        map.put("aead_alg", aeadAlg);
        map.put("hpke_alg", hpkeAlg);
        map.put("ciphertext", ciphertext);
        map.put("ciphertext_sha256", ciphertextSha256);
        return map;
    }

    private static String signEnvelope(RgCryptoEnvelope envelope, KeysetHandle signingPrivate)
            throws GeneralSecurityException {
        PublicKeySign signer = signingPrivate.getPrimitive(RegistryConfiguration.get(), PublicKeySign.class);
        return RgCryptoBase64.encode(signer.sign(envelope.signatureInput()));
    }

    private static List<RecipientEntry> wrapRecipients(byte[] msgKey, List<RgCryptoRecipientPublic> recipients,
                                                       String senderSigningKid) throws GeneralSecurityException {
        List<RgCryptoRecipientPublic> sorted = new ArrayList<>(recipients);
        sorted.sort(Comparator.comparingInt(r -> r.keyId));
        List<RecipientEntry> entries = new ArrayList<>(sorted.size());
        for (RgCryptoRecipientPublic recipient : sorted) {
            RecipientEntry entry = new RecipientEntry();
            entry.recipientKeyId = recipient.keyId;
            entry.recipientKid = recipient.kid;
            byte[] wrapped = RgCryptoHybrid.wrapDek(msgKey, recipient.publicKeyset, recipient.kid, senderSigningKid);
            entry.wrappedKey = RgCryptoBase64.encode(wrapped);
            entries.add(entry);
        }
        return entries;
    }

    private byte[] unwrapForRecipient(KeysetHandle recipientPrivate) throws GeneralSecurityException {
        String recipientKid = RgCryptoKeys.kidFromKeyset(recipientPrivate.getPublicKeysetHandle());
        RecipientEntry entry = null;
        if (recipients != null) {
            for (RecipientEntry candidate : recipients) {
                if (recipientKid != null && recipientKid.equals(candidate.recipientKid)) {
                    entry = candidate;
                    break;
                }
            }
        }
        if (entry == null) {
            throw new GeneralSecurityException("Recipient not found");
        }
        return RgCryptoHybrid.unwrapDek(RgCryptoBase64.decode(entry.wrappedKey), recipientPrivate,
                recipientKid, senderSigningKid);
    }

    public void verifyCiphertextHash() throws GeneralSecurityException {
        if (ciphertextSha256 == null) {
            throw new GeneralSecurityException("ciphertext_sha256 missing");
        }
        byte[] actual = sha256(RgCryptoBase64.decode(ciphertext));
        byte[] expected = RgCryptoBase64.decode(ciphertextSha256);
        if (!constantTimeEquals(actual, expected)) {
            throw new GeneralSecurityException("ciphertext_sha256 mismatch");
        }
    }

    public byte[] decryptPayload(KeysetHandle recipientPrivate) throws GeneralSecurityException {
        byte[] msgKey = unwrapForRecipient(recipientPrivate);
        return RgCryptoAead.decrypt(msgKey, RgCryptoBase64.decode(ciphertext), aadBytes());
    }

    private static byte[] sha256(byte[] data) throws GeneralSecurityException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (Exception e) {
            throw new GeneralSecurityException("SHA-256 failed", e);
        }
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }

    private static byte[] recipientEntryBytes(RecipientEntry entry) throws GeneralSecurityException {
        if (entry == null) {
            throw new GeneralSecurityException("Recipient entry missing");
        }
        byte[] wrapped = entry.wrappedKey == null ? null : RgCryptoBase64.decode(entry.wrappedKey);
        if (wrapped == null) {
            throw new GeneralSecurityException("Recipient wrapped key missing");
        }
        int size = 0;
        size += CodedOutputStream.computeInt32Size(1, entry.recipientKeyId);
        size += CodedOutputStream.computeByteArraySize(2, wrapped);
        if (entry.recipientKid != null) {
            size += CodedOutputStream.computeStringSize(3, entry.recipientKid);
        }
        byte[] buffer = new byte[size];
        CodedOutputStream output = CodedOutputStream.newInstance(buffer);
        try {
            output.writeInt32(1, entry.recipientKeyId);
            output.writeByteArray(2, wrapped);
            if (entry.recipientKid != null) {
                output.writeString(3, entry.recipientKid);
            }
            output.flush();
            return buffer;
        } catch (Exception e) {
            throw new GeneralSecurityException("Failed to build recipient bytes", e);
        }
    }

    private static byte[] recipientEntryBinaryBytes(RecipientEntry entry) throws GeneralSecurityException {
        if (entry == null) {
            throw new GeneralSecurityException("Recipient entry missing");
        }
        if (entry.wrappedKey == null) {
            throw new GeneralSecurityException("Recipient wrapped key missing");
        }
        try {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            CodedOutputStream output = CodedOutputStream.newInstance(out);
            output.writeInt32(1, entry.recipientKeyId);
            output.writeByteArray(2, RgCryptoBase64.decode(entry.wrappedKey));
            if (entry.recipientKid != null) {
                output.writeString(3, entry.recipientKid);
            }
            output.flush();
            return out.toByteArray();
        } catch (Exception e) {
            throw new GeneralSecurityException("Failed to build recipient bytes", e);
        }
    }

    private static RecipientEntry recipientEntryFromBinary(byte[] data) throws GeneralSecurityException {
        if (data == null) {
            throw new GeneralSecurityException("Recipient entry missing");
        }
        RecipientEntry entry = new RecipientEntry();
        try {
            CodedInputStream input = CodedInputStream.newInstance(data);
            while (!input.isAtEnd()) {
                int tag = input.readTag();
                if (tag == 0) {
                    break;
                }
                int fieldNumber = WireFormat.getTagFieldNumber(tag);
                switch (fieldNumber) {
                    case 1:
                        entry.recipientKeyId = input.readInt32();
                        break;
                    case 2:
                        entry.wrappedKey = RgCryptoBase64.encode(input.readByteArray());
                        break;
                    case 3:
                        entry.recipientKid = input.readString();
                        break;
                    default:
                        input.skipField(tag);
                        break;
                }
            }
        } catch (Exception e) {
            throw new GeneralSecurityException("Failed to parse recipient bytes", e);
        }
        return entry;
    }

    public static final class RecipientEntry {
        @JsonProperty("recipient_key_id")
        public int recipientKeyId;

        @JsonProperty("recipient_kid")
        public String recipientKid;

        @JsonProperty("wrapped_key")
        public String wrappedKey;

        public RecipientEntry() {
        }
    }
}
