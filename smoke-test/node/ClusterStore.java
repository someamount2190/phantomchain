package com.phantomchain.debug;

/**
 * Phase 3 — RS-sharded intra-cluster ledger (spec §9.3): "Each contributing device holds a shard of the
 * cluster's ledger partition using Reed-Solomon erasure coding. No single device holds the complete
 * ledger ... a single device in isolation holds an encrypted fragment that is cryptographically useless
 * alone."
 *
 * Mechanism: the cluster's partition is ENCRYPTED under a cluster key (ChaCha20-Poly1305), then the
 * ciphertext is RS(k,n)-erasure-coded into n shards — one per member device. Any k members reconstruct
 * the partition (k-of-n availability); fewer than k cannot; and because every shard is a fragment of
 * ciphertext (not plaintext), a single shard reveals nothing on its own.
 *
 * The cluster key here is a shared cluster secret (honest interim). A distributed-key-generation (DKG)
 * ceremony so the key is never assembled on one device is the documented frontier — same trust boundary
 * the spec calls out for the bridge custodian set.
 */
public class ClusterStore {
    static byte[] storeKey(byte[] clusterSecret) { return PhantomCrypto.hkdf(clusterSecret, null, PhantomCrypto.utf8("pc-cluster-store-key"), 32); }
    static byte[] storeNonce(byte[] clusterSecret, long version) { return PhantomCrypto.hkdf(clusterSecret, null, PhantomCrypto.utf8("pc-cluster-store-nonce|" + version), 12); }

    /** Encrypt the partition, then RS(k,n)-shard the ciphertext into n member shards (member i holds shards[i]). */
    public static byte[][] shard(byte[] partition, byte[] clusterSecret, long version, int k, int n) {
        byte[] ct = PhantomCrypto.aead(true, storeKey(clusterSecret), storeNonce(clusterSecret, version), partition);
        return new ReedSolomon(k, n).encode(ReedSolomon.split(ct, k));
    }

    /** Reconstruct the partition from any >=k present member shards (throws if <k, tampered, or wrong key). */
    public static byte[] reconstruct(byte[][] shards, boolean[] present, byte[] clusterSecret, long version, int k, int n) {
        int len = -1; for (int i = 0; i < n; i++) if (present[i] && shards[i] != null) { len = shards[i].length; break; }
        if (len < 0) throw new RuntimeException("no shards present");
        byte[] ct = ReedSolomon.join(new ReedSolomon(k, n).decode(shards, present, len));
        return PhantomCrypto.aead(false, storeKey(clusterSecret), storeNonce(clusterSecret, version), ct);   // AEAD verifies integrity + key
    }

    /** Reconstruct the cluster store key from a DKG ceremony using any k present member shares.
     *  The key is never stored on one device — it is reconstructed from k shares each time the
     *  cluster must seal or rotate (see {@link Dkg}). Returns the 32-byte clusterSecret that
     *  {@link #shard}/{@link #reconstruct} consume. */
    public static byte[] clusterSecretFromCeremony(Dkg.Ceremony cy, int[] presentMembers) {
        Dkg.Share[] shares = new Dkg.Share[presentMembers.length];
        for (int j = 0; j < presentMembers.length; j++) shares[j] = cy.shares[presentMembers[j]];
        return Dkg.storeKeyFromSecret(Dkg.combine(shares));
    }
}
