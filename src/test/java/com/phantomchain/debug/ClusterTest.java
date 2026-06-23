package com.phantomchain.debug;

import static com.phantomchain.debug.TestKit.*;

import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;

/**
 * Cluster mining (spec §9): a cluster of M-of-N enrolled member devices acts as ONE validator, and
 * epoch rewards are distributed DIRECTLY to each member identity — no operator intermediary (§9.6).
 *
 * Verifies: formation (pooled-stake floor, member-pubkey binding, initiator auth), the M-of-N block
 * "signature" (threshold met, sub-threshold rejected, forged/duplicate/non-member sigs rejected),
 * the cluster's weight as one validator, direct per-member reward split, and state-root coverage +
 * backward compatibility (an empty-cluster chain hashes exactly as before).
 */
public class ClusterTest {

    static MLDSAPrivateKeyParameters key() { return PhantomCrypto.randomDeviceKey(); }

    static Ledger genesis(MLDSAPrivateKeyParameters[] vk, String[] vid) throws Exception {
        LinkedHashMap<String, Long> alloc = new LinkedHashMap<>(); List<String> vals = new ArrayList<>();
        Map<String, Long> stk = new HashMap<>(), idn = new HashMap<>(); Set<String> ver = new HashSet<>(); Map<String, String> vp = new HashMap<>();
        for (int i = 0; i < vk.length; i++) {
            vk[i] = key(); vid[i] = Keys.idOf(vk[i]);
            alloc.put(vid[i], 1_000_000L); vals.add(vid[i]); stk.put(vid[i], 1_000_000L); idn.put(vid[i], 1L); ver.add(vid[i]); vp.put(vid[i], Keys.pubHex(vk[i]));
        }
        Ledger L = new Ledger(); L.genesisEcon("pc-cluster", alloc, vals, stk, idn, ver, vp, 0);
        L.beacon = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8("seed")));
        return L;
    }

    static JSONObject voteEntry(String mid, MLDSAPrivateKeyParameters k, String hash) throws Exception {
        return new JSONObject().put("m", mid).put("sig", PhantomCrypto.hex(PhantomCrypto.sign(k, PhantomCrypto.utf8(hash))));
    }

    public static void main(String[] a) throws Exception {
        System.out.println("==== cluster formation ====");
        MLDSAPrivateKeyParameters[] vk = new MLDSAPrivateKeyParameters[2]; String[] vid = new String[2];
        Ledger L = genesis(vk, vid);

        // 3 member devices, each pre-bonded 200k -> pooled 600k >= minValidatorStake (500k)
        int M = 3; MLDSAPrivateKeyParameters[] mk = new MLDSAPrivateKeyParameters[M]; String[] mid = new String[M];
        List<String> members = new ArrayList<>(); Map<String, String> mpub = new HashMap<>();
        for (int i = 0; i < M; i++) { mk[i] = key(); mid[i] = Keys.idOf(mk[i]); members.add(mid[i]); mpub.put(mid[i], Keys.pubHex(mk[i])); L.stake.put(mid[i], 200_000L); }
        String clusterId = "cluster-alpha"; int threshold = 2;
        String commit0 = Ledger.beaconCommit0For(mk[0].getEncoded());

        JSONObject form = L.buildClusterFormTx(clusterId, members, mpub, threshold, mk[0], commit0);
        ok("valid form accepted", L.verifyClusterForm(form));

        // negatives
        JSONObject badThresh = L.buildClusterFormTx("c2", members, mpub, 4, mk[0], commit0);   // threshold > members
        ok("threshold > N rejected", !L.verifyClusterForm(badThresh));
        Map<String, String> underPub = new HashMap<>(mpub);
        List<String> two = members.subList(0, 2);                                              // 2 members * 200k = 400k < floor
        JSONObject underBond = L.buildClusterFormTx("c3", new ArrayList<>(two), underPub, 2, mk[0], commit0);
        ok("under-bonded cluster rejected", !L.verifyClusterForm(underBond));
        JSONObject wrongInit = L.buildClusterFormTx("c4", members, mpub, 2, key(), commit0);    // initiator not a member
        ok("non-member initiator rejected", !L.verifyClusterForm(wrongInit));

        ok("apply registers the cluster", L.applyClusterForm(form));
        ok("cluster is now a validator", L.validators.contains(clusterId) && L.isCluster(clusterId));
        ok("cluster identity weight = #members (§9.4)", L.identity.get(clusterId) == M);
        ok("cluster_total_stake = pooled member stake (§9.4)", L.stake.get(clusterId) == 600_000L);
        ok("cannot re-form same cluster", !L.applyClusterForm(form));

        System.out.println("\n==== M-of-N block signature (the cluster's one 'signature') ====");
        String hash = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8("block-77")));
        JSONArray two_of_3 = new JSONArray().put(voteEntry(mid[0], mk[0], hash)).put(voteEntry(mid[1], mk[1], hash));
        ok("2-of-3 reaches threshold -> valid", L.verifyClusterVote(clusterId, hash, two_of_3));
        JSONArray three_of_3 = new JSONArray(two_of_3.toString()).put(voteEntry(mid[2], mk[2], hash));
        ok("3-of-3 valid", L.verifyClusterVote(clusterId, hash, three_of_3));
        JSONArray one = new JSONArray().put(voteEntry(mid[0], mk[0], hash));
        ok("1-of-3 below threshold -> invalid", !L.verifyClusterVote(clusterId, hash, one));
        JSONArray dup = new JSONArray().put(voteEntry(mid[0], mk[0], hash)).put(voteEntry(mid[0], mk[0], hash));
        ok("duplicate member counted once -> invalid", !L.verifyClusterVote(clusterId, hash, dup));
        JSONArray forged = new JSONArray().put(voteEntry(mid[0], mk[0], hash)).put(voteEntry(mid[2], key(), hash));   // claims mid[2] but wrong key
        ok("forged member sig discarded -> invalid", !L.verifyClusterVote(clusterId, hash, forged));
        JSONArray stranger = new JSONArray().put(voteEntry(mid[0], mk[0], hash)).put(voteEntry(Keys.idOf(key()), key(), hash));
        ok("non-member sig discarded -> invalid", !L.verifyClusterVote(clusterId, hash, stranger));
        JSONArray wrongHash = new JSONArray().put(voteEntry(mid[0], mk[0], "other")).put(voteEntry(mid[1], mk[1], "other"));
        ok("sigs over a different hash -> invalid for this block", !L.verifyClusterVote(clusterId, hash, wrongHash));

        System.out.println("\n==== direct per-member reward split (§9.6) ====");
        long[] before = new long[M]; for (int i = 0; i < M; i++) before[i] = L.balanceOf(mid[i]);
        L.creditEarner(clusterId, 10);                                  // 10 / 3 = 3 r1 -> 4,3,3
        ok("remainder split deterministic (4,3,3)", L.balanceOf(mid[0]) - before[0] == 4 && L.balanceOf(mid[1]) - before[1] == 3 && L.balanceOf(mid[2]) - before[2] == 3);
        ok("cluster account itself is NOT credited (no operator)", L.balanceOf(clusterId) == 0);

        // epoch reward: cluster (validator index 2) proposes + co-signs 3 blocks; reward must fan out to members
        int cidx = L.validators.indexOf(clusterId);
        L.chain.clear();
        L.chain.add(new JSONObject().put("proposer", -1));             // index 0 placeholder (genesis)
        for (int h = 1; h <= Ledger.EPOCH_LEN; h++)
            L.chain.add(new JSONObject().put("proposer", cidx).put("qc", new JSONArray()
                    .put(new JSONObject().put("i", cidx)).put(new JSONObject().put("i", 0))));
        long[] memBefore = new long[M]; for (int i = 0; i < M; i++) memBefore[i] = L.balanceOf(mid[i]);
        long val0Before = L.balanceOf(vid[0]), clBefore = L.balanceOf(clusterId), mintedBefore = L.totalMinted;
        L.maybeEpochReward();
        // units: per block cluster=+3 (propose 2 + qc 1), val0=+1 ; *3 blocks -> cluster 9, val0 3, total 12
        // pool = 100*3 = 300 -> cluster 225 (->75/member), val0 75
        long perMember = 0; for (int i = 0; i < M; i++) perMember += L.balanceOf(mid[i]) - memBefore[i];
        ok("epoch reward fanned out to members (225 total / 75 each)",
                (L.balanceOf(mid[0]) - memBefore[0]) == 75 && (L.balanceOf(mid[1]) - memBefore[1]) == 75 && (L.balanceOf(mid[2]) - memBefore[2]) == 75);
        ok("normal validator earns to its own account (75)", L.balanceOf(vid[0]) - val0Before == 75);
        ok("cluster account stays empty (rewards bypass it)", L.balanceOf(clusterId) == clBefore);
        ok("emission accounting intact (300 minted)", L.totalMinted - mintedBefore == 300);

        System.out.println("\n==== state-root coverage + backward compatibility ====");
        String r1 = L.stateRoot();
        L.clusters.get(clusterId).put("threshold", 1);
        ok("stateRoot commits to cluster config", !r1.equals(L.stateRoot()));
        L.clusters.get(clusterId).put("threshold", 2);
        ok("stateRoot restored when config restored", r1.equals(L.stateRoot()));

        MLDSAPrivateKeyParameters[] vk2 = new MLDSAPrivateKeyParameters[2]; String[] vid2 = new String[2];
        Ledger L0 = genesis(vk2, vid2);
        String e0 = L0.stateRoot();                                    // no clusters
        L0.clusters.put("x", new JSONObject().put("members", new JSONArray().put("a")).put("threshold", 1));
        String e1 = L0.stateRoot();                                    // with a cluster
        L0.clusters.clear();
        String e2 = L0.stateRoot();                                    // back to empty
        ok("empty-cluster chain hashes exactly as before (backward compatible)", e0.equals(e2) && !e0.equals(e1));

        System.out.println("\nClusterTest: " + pass + " passed, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }
}
