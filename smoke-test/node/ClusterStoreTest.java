package com.phantomchain.debug;

import java.util.*;

/**
 * RS-sharded intra-cluster ledger (spec §9.3). A 2-of-3 cluster shards its (encrypted) ledger partition
 * across its 3 member devices: any 2 reconstruct, 1 cannot, every single shard is useless alone, and a
 * wrong key or a tampered shard is rejected.
 */
public class ClusterStoreTest {
    static int pass = 0, fail = 0;
    static void ok(String n, boolean c) { if (c) { pass++; System.out.println("  PASS " + n); } else { fail++; System.out.println("  ** FAIL ** " + n); } }
    static boolean contains(byte[] hay, byte[] needle) {
        outer: for (int i = 0; i + needle.length <= hay.length; i++) { for (int j = 0; j < needle.length; j++) if (hay[i + j] != needle[j]) continue outer; return true; }
        return false;
    }
    static boolean reconstructs(byte[][] shards, boolean[] present, byte[] secret, int k, int n, byte[] expect) {
        try { return Arrays.equals(ClusterStore.reconstruct(shards, present, secret, 0, k, n), expect); }
        catch (Exception e) { return false; }
    }

    public static void main(String[] a) throws Exception {
        int k = 2, n = 3;                                  // a 2-of-3 cluster: 3 member devices, any 2 reconstruct
        byte[] marker = PhantomCrypto.utf8("TOPSECRET-LEDGER-PARTITION");
        Random rnd = new Random(11);
        byte[] partition = new byte[1200]; rnd.nextBytes(partition);
        System.arraycopy(marker, 0, partition, 64, marker.length);   // embed a recognizable marker in the cleartext
        byte[] clusterSecret = new byte[32]; rnd.nextBytes(clusterSecret);

        byte[][] shards = ClusterStore.shard(partition, clusterSecret, 0, k, n);
        System.out.println("partition=" + partition.length + "B  ->  " + n + " member shards of " + shards[0].length + "B each (2-of-3)\n");

        ok("produced one shard per member device", shards.length == n);
        ok("no single device holds the full ledger (shard < partition)", shards[0].length < partition.length);

        // any k=2 of n=3 reconstruct
        int[][] subsets = {{0, 1}, {0, 2}, {1, 2}};
        boolean allK = true;
        for (int[] sub : subsets) {
            boolean[] p = new boolean[n]; for (int i : sub) p[i] = true;
            allK &= reconstructs(shards, p, clusterSecret, k, n, partition);
        }
        ok("ANY 2 of 3 member shards reconstruct the partition exactly", allK);

        // every single shard alone fails (k-1 < k) AND leaks no plaintext
        boolean singleFails = true, singleNoLeak = true;
        for (int i = 0; i < n; i++) {
            boolean[] p = new boolean[n]; p[i] = true;
            singleFails &= !reconstructs(shards, p, clusterSecret, k, n, partition);
            singleNoLeak &= !contains(shards[i], marker);     // a single shard is ciphertext fragment, not plaintext
        }
        ok("a single member shard CANNOT reconstruct (needs k)", singleFails);
        ok("a single member shard leaks no plaintext (cryptographically useless alone, §9.3)", singleNoLeak);

        // wrong cluster key -> AEAD auth fails even with k shards
        byte[] wrongSecret = new byte[32]; rnd.nextBytes(wrongSecret);
        boolean[] two = new boolean[n]; two[0] = true; two[1] = true;
        ok("wrong cluster key rejected (AEAD auth) even with 2 shards", !reconstructs(shards, two, wrongSecret, k, n, partition));

        // tampered shard -> reconstruction rejected (integrity)
        byte[][] tampered = new byte[n][]; for (int i = 0; i < n; i++) tampered[i] = shards[i] == null ? null : shards[i].clone();
        tampered[0][5] ^= 0x40;
        ok("a tampered shard is rejected (AEAD integrity)", !reconstructs(tampered, two, clusterSecret, k, n, partition));

        // versioning: a different version derives a different keystream (no nonce reuse across partition versions)
        byte[][] v1 = ClusterStore.shard(partition, clusterSecret, 1, k, n);
        ok("different version -> different shards (no nonce reuse)", !Arrays.equals(v1[0], shards[0]));
        boolean[] t2 = new boolean[n]; t2[1] = true; t2[2] = true;
        ok("version-1 shards reconstruct under version 1", Arrays.equals(ClusterStore.reconstruct(v1, t2, clusterSecret, 1, k, n), partition));

        System.out.println("\nClusterStoreTest: " + pass + " passed, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }
}
