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
    private static final java.security.SecureRandom RNG = new java.security.SecureRandom();
    // version domain-separates the KEY; the AEAD nonce is FRESH-RANDOM per encryption (prepended to the
    // ciphertext) instead of derived from `version`, so confidentiality/integrity no longer depend on a
    // version being unique — re-sealing the same version with different content can no longer cause a
    // catastrophic ChaCha20-Poly1305 nonce reuse (crypto audit finding).
    static byte[] storeKey(byte[] clusterSecret, long version) { return PhantomCrypto.hkdf(clusterSecret, null, PhantomCrypto.utf8("pc-cluster-store-key|" + version), 32); }

    /** Encrypt the partition (fresh random nonce, prepended), then RS(k,n)-shard the framed ciphertext. */
    public static byte[][] shard(byte[] partition, byte[] clusterSecret, long version, int k, int n) {
        byte[] nonce = new byte[12]; RNG.nextBytes(nonce);
        byte[] ct = PhantomCrypto.aead(true, storeKey(clusterSecret, version), nonce, partition);
        byte[] framed = new byte[12 + ct.length];
        System.arraycopy(nonce, 0, framed, 0, 12); System.arraycopy(ct, 0, framed, 12, ct.length);
        return new ReedSolomon(k, n).encode(ReedSolomon.split(framed, k));
    }

    /** Reconstruct the partition from any >=k present member shards (throws if <k, tampered, or wrong key). */
    public static byte[] reconstruct(byte[][] shards, boolean[] present, byte[] clusterSecret, long version, int k, int n) {
        int len = -1; for (int i = 0; i < n; i++) if (present[i] && shards[i] != null) { len = shards[i].length; break; }
        if (len < 0) throw new RuntimeException("no shards present");
        byte[] framed = ReedSolomon.join(new ReedSolomon(k, n).decode(shards, present, len));
        byte[] nonce = java.util.Arrays.copyOfRange(framed, 0, 12);
        byte[] ct = java.util.Arrays.copyOfRange(framed, 12, framed.length);
        return PhantomCrypto.aead(false, storeKey(clusterSecret, version), nonce, ct);   // AEAD verifies integrity + key
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
