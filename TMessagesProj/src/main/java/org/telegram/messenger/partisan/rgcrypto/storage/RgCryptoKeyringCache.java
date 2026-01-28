package org.telegram.messenger.partisan.rgcrypto.storage;

import android.content.Context;
import android.util.SparseArray;

import com.google.crypto.tink.KeysetHandle;

import org.telegram.messenger.partisan.rgcrypto.RgCryptoIds;
import org.telegram.messenger.partisan.rgcrypto.RgCryptoKeys;
import org.telegram.messenger.partisan.rgcrypto.RgCryptoRecipientPublic;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class RgCryptoKeyringCache {
    private static final Object LOCK = new Object();
    private static final SparseArray<RgCryptoKeyringCache> INSTANCES = new SparseArray<>();

    private final Context context;
    private final int account;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final ConcurrentHashMap<String, List<RgCryptoRecipientPublic>> recipientsByPeer = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, KeysetHandle> signingByPeerAndKid = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Set<String>> signingKidsByPeer = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Set<String>> peersBySigningKid = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Set<String>> trustKeysByPeer = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Integer> trustByPeerAndKid = new ConcurrentHashMap<>();

    private RgCryptoKeyringCache(Context context, int account) {
        this.context = context.getApplicationContext();
        this.account = account;
    }

    public static RgCryptoKeyringCache get(Context context, int account) {
        synchronized (LOCK) {
            RgCryptoKeyringCache instance = INSTANCES.get(account);
            if (instance == null) {
                instance = new RgCryptoKeyringCache(context, account);
                INSTANCES.put(account, instance);
            }
            return instance;
        }
    }

    public void refreshForPeers(List<String> peerIds) {
        if (peerIds == null || peerIds.isEmpty()) {
            return;
        }
        executor.execute(() -> {
            RgCryptoKeyringStore store = new RgCryptoKeyringStore(context, account);
            for (String peerId : peerIds) {
                String normalizedPeer = RgCryptoIds.normalizePeerId(peerId);
                List<RgCryptoKeyringEntry> entries = store.getByPeer(normalizedPeer);
                List<RgCryptoRecipientPublic> recipients = new ArrayList<>();
                Set<String> newSigningKids = new HashSet<>();
                Set<String> newTrustKeys = new HashSet<>();
                if (entries != null) {
                    for (RgCryptoKeyringEntry entry : entries) {
                        try {
                            String signingKid = entry.signingKid;
                            if (entry.signingKeysetJson != null) {
                                KeysetHandle signing = RgCryptoKeys.parsePublicKeyset(entry.signingKeysetJson);
                                if (signingKid == null) {
                                    try {
                                        signingKid = RgCryptoKeys.kidFromKeyset(signing);
                                    } catch (Exception ignored) {
                                        signingKid = null;
                                    }
                                }
                                if (signingKid != null) {
                                    signingByPeerAndKid.put(signingKeyKey(normalizedPeer, signingKid), signing);
                                    newSigningKids.add(signingKid);
                                }
                            }
                            String encryptionKid = entry.encryptionKid;
                            if (encryptionKid == null && entry.encryptionKeysetJson != null) {
                                try {
                                    KeysetHandle encPublic = RgCryptoKeys.parsePublicKeyset(entry.encryptionKeysetJson);
                                    encryptionKid = RgCryptoKeys.kidFromKeyset(encPublic);
                                } catch (Exception ignored) {
                                    encryptionKid = null;
                                }
                            }
                            if (signingKid != null) {
                                String trustKey = trustKey(normalizedPeer, signingKid, encryptionKid);
                                trustByPeerAndKid.put(trustKey, entry.trustState);
                                newTrustKeys.add(trustKey);
                            }
                            if (entry.trustState != RgCryptoTrustState.REVOKED &&
                                    entry.signatureValid == RgCryptoSignatureState.VALID) {
                                KeysetHandle enc = RgCryptoKeys.parsePublicKeyset(entry.encryptionKeysetJson);
                                String encKid = encryptionKid;
                                if (encKid == null) {
                                    try {
                                        encKid = RgCryptoKeys.kidFromKeyset(enc);
                                    } catch (Exception ignored) {
                                        encKid = null;
                                    }
                                }
                                recipients.add(new RgCryptoRecipientPublic(entry.encryptionKeyId, enc, encKid));
                            }
                        } catch (Exception ignored) {
                        }
                    }
                }
                recipientsByPeer.put(normalizedPeer, recipients);
                updateSigningKidIndex(normalizedPeer, newSigningKids);
                updateTrustKeys(normalizedPeer, newTrustKeys);
            }
        });
    }

    public List<RgCryptoRecipientPublic> getRecipientsForPeers(List<String> peerIds) {
        if (peerIds == null || peerIds.isEmpty()) {
            return Collections.emptyList();
        }
        ArrayList<RgCryptoRecipientPublic> out = new ArrayList<>();
        for (String peerId : peerIds) {
            String normalized = RgCryptoIds.normalizePeerId(peerId);
            List<RgCryptoRecipientPublic> list = recipientsByPeer.get(normalized);
            if (list != null) {
                out.addAll(list);
            }
        }
        return out;
    }

    public KeysetHandle getSigningKeyset(String peerId, String signingKid) {
        if (peerId == null) {
            return null;
        }
        return signingByPeerAndKid.get(signingKeyKey(RgCryptoIds.normalizePeerId(peerId), signingKid));
    }

    public boolean hasAnySigningKeys(String peerId) {
        if (peerId == null) {
            return false;
        }
        Set<String> kids = signingKidsByPeer.get(RgCryptoIds.normalizePeerId(peerId));
        return kids != null && !kids.isEmpty();
    }

    public boolean hasSigningKid(String peerId, String signingKid) {
        if (peerId == null || signingKid == null) {
            return false;
        }
        Set<String> kids = signingKidsByPeer.get(RgCryptoIds.normalizePeerId(peerId));
        return kids != null && kids.contains(signingKid);
    }

    public void clearAll() {
        executor.execute(() -> {
            recipientsByPeer.clear();
            signingByPeerAndKid.clear();
            signingKidsByPeer.clear();
            peersBySigningKid.clear();
            trustKeysByPeer.clear();
            trustByPeerAndKid.clear();
        });
    }

    public int getTrustState(String peerId, String signingKid, String encryptionKid) {
        if (peerId == null || signingKid == null) {
            return RgCryptoTrustState.UNKNOWN;
        }
        Integer trust = trustByPeerAndKid.get(trustKey(RgCryptoIds.normalizePeerId(peerId), signingKid, encryptionKid));
        return trust != null ? trust : RgCryptoTrustState.UNKNOWN;
    }

    public boolean isSigningKidReusedByOtherPeer(String peerId, String signingKid) {
        if (signingKid == null) {
            return false;
        }
        Set<String> peers = peersBySigningKid.get(signingKid);
        if (peers == null || peers.isEmpty()) {
            return false;
        }
        if (peerId == null) {
            return peers.size() > 0;
        }
        String normalized = RgCryptoIds.normalizePeerId(peerId);
        return peers.size() > 1 || !peers.contains(normalized);
    }

    private String signingKeyKey(String peerId, String signingKid) {
        return peerId + "#" + signingKid;
    }

    private String trustKey(String peerId, String signingKid, String encryptionKid) {
        return peerId + "#" + signingKid + "#" + (encryptionKid != null ? encryptionKid : "");
    }

    private void updateSigningKidIndex(String peerId, Set<String> newKids) {
        Set<String> oldKids = signingKidsByPeer.put(peerId, newKids);
        if (oldKids != null) {
            for (String oldKid : oldKids) {
                Set<String> peers = peersBySigningKid.get(oldKid);
                if (peers != null) {
                    peers.remove(peerId);
                    if (peers.isEmpty()) {
                        peersBySigningKid.remove(oldKid);
                    }
                }
            }
        }
        if (newKids != null) {
            for (String kid : newKids) {
                peersBySigningKid.computeIfAbsent(kid, k -> ConcurrentHashMap.newKeySet()).add(peerId);
            }
        }
    }

    private void updateTrustKeys(String peerId, Set<String> newKeys) {
        Set<String> oldKeys = trustKeysByPeer.put(peerId, newKeys);
        if (oldKeys != null) {
            for (String oldKey : oldKeys) {
                if (newKeys == null || !newKeys.contains(oldKey)) {
                    trustByPeerAndKid.remove(oldKey);
                }
            }
        }
    }
}
