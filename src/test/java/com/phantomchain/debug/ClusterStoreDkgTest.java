package com.phantomchain.debug;

import static com.phantomchain.debug.TestKit.*;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * End-to-end: the cluster store key is produced by a DKG ceremony (no single device holds it),
 * and the partition still round-trips through the RS-sharded store with k-of-n enforced on BOTH
 * the key layer (DKG) and the data layer (Reed-Solomon). Exercises the ClusterStore ↔ Dkg seam.
 */
public class ClusterStoreDkgTest {

    public static void main(String[] a) throws Exception {
        SecureRandom rnd = new SecureRandom();
        int k = 2, n = 3;
        byte[] partition = new byte[1200]; rnd.nextBytes(partition);
        long version = 0;

        // 1. DKG ceremony: N member devices jointly generate a key no single device holds
        Dkg.Ceremony cy = Dkg.ceremony(k, n, rnd);

        // 2. any k-of-n member set reconstructs the SAME cluster key (quorum-stable)
        byte[] key01 = ClusterStore.clusterSecretFromCeremony(cy, new int[]{0, 1});
        byte[] key12 = ClusterStore.clusterSecretFromCeremony(cy, new int[]{1, 2});
        byte[] key02 = ClusterStore.clusterSecretFromCeremony(cy, new int[]{0, 2});
        ok("any k-of-n member set reconstructs the SAME cluster key", Arrays.equals(key01, key12) && Arrays.equals(key01, key02));

        // 3. a LONE member cannot derive the real key (k-1 reveals nothing about the secret)
        Dkg.Share[] lone = { cy.shares[0] };
        byte[] bogusKey = Dkg.storeKeyFromSecret(Dkg.combine(lone));
        ok("a lone member's share does NOT derive the real cluster key", !Arrays.equals(bogusKey, key01));

        // 4. shard the partition under the ceremony key; one RS shard lands per device
        byte[][] shards = ClusterStore.shard(partition, key01, version, k, n);

        // 5. a different k-member quorum re-derives the key from THEIR shares and reconstructs the data
        boolean[] p01 = {true, true, false}, p12 = {false, true, true};
        byte[] got01 = ClusterStore.reconstruct(shards, p01, key01, version, k, n);
        byte[] got12 = ClusterStore.reconstruct(shards, p12, key12, version, k, n);
        ok("members {0,1} reconstruct the exact partition under the ceremony key", Arrays.equals(got01, partition));
        ok("members {1,2} (different quorum) reconstruct the same partition", Arrays.equals(got12, partition));

        // 6. k-of-n on the DATA layer: a single member's shard cannot reconstruct
        boolean[] pSingle = {true, false, false};
        boolean singleDataFails = false;
        try { ClusterStore.reconstruct(shards, pSingle, key01, version, k, n); } catch (Exception e) { singleDataFails = true; }
        ok("a single member cannot reconstruct the partition (k-of-n on the data layer)", singleDataFails);

        // 7. a key reconstructed from a sub-threshold set cannot unseal the k-shard data (AEAD rejects)
        boolean unsealWrongKey = false;
        try { ClusterStore.reconstruct(shards, p01, bogusKey, version, k, n); } catch (Exception e) { unsealWrongKey = true; }
        ok("a sub-threshold-derived key cannot unseal the partition (AEAD rejects)", unsealWrongKey);

        System.out.println("\nClusterStoreDkgTest: " + pass + " passed, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }
}
