package com.phantomchain.debug;

import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;

/**
 * Phase 2 — a cluster mining in REAL consensus (in-process driver, real engine).
 *
 * Drives the actual Ledger through real block production: weighted commit-reveal proposer election,
 * RANDAO beacon reveals, state-root/shard-root commitment, the same QC check NetNode runs — but with
 * one validator being a CLUSTER whose vote is an M-of-N member-sig bundle. Demonstrates the cluster
 * proposing + co-signing live, committing real blocks, M-of-N liveness (any threshold subset of members
 * signs, one can be offline), and epoch rewards fanning out DIRECTLY to each member (§9.6).
 */
public class ClusterConsensus {
    static int pass = 0, fail = 0;
    static void ok(String n, boolean c) { if (c) { pass++; System.out.println("  PASS " + n); } else { fail++; System.out.println("  ** FAIL ** " + n); } }
    static MLDSAPrivateKeyParameters key() { return PhantomCrypto.randomDeviceKey(); }
    static byte[] secret(MLDSAPrivateKeyParameters k, long c) { return Ledger.beaconSecretFor(k.getEncoded(), c); }

    /** The exact QC rule NetNode.verifyQC enforces: scheduled proposer + a committee quorum of valid sigs,
     *  where a cluster validator's "sig" is an M-of-N member bundle. */
    static boolean verifyQC(Ledger L, JSONObject blk, Map<String, MLDSAPublicKeyParameters> pubById) throws Exception {
        String hash = blk.getString("hash"); int height = blk.getInt("height");
        if (blk.optInt("proposer", -1) != L.proposerFor(blk.getString("prevHash"), height, blk.optInt("view", 0))) return false;
        Set<Integer> committee = new HashSet<>(L.committeeFor(height));
        Set<Integer> okv = new HashSet<>();
        JSONArray qc = blk.getJSONArray("qc");
        for (int i = 0; i < qc.length(); i++) {
            JSONObject v = qc.getJSONObject(i); int idx = v.getInt("i");
            if (idx < 0 || idx >= L.validators.size() || !committee.contains(idx)) continue;
            String vid = L.validators.get(idx);
            if (L.isCluster(vid)) { if (L.verifyClusterVote(vid, hash, v.optJSONArray("bundle"))) okv.add(idx); }
            else { MLDSAPublicKeyParameters p = pubById.get(vid);
                if (p != null && PhantomCrypto.verify(p, PhantomCrypto.utf8(hash), PhantomCrypto.unhex(v.getString("sig")))) okv.add(idx); }
        }
        return okv.size() >= L.committeeQuorum(height);
    }

    public static void main(String[] a) throws Exception {
        // genesis: 2 single-key validators
        LinkedHashMap<String, Long> alloc = new LinkedHashMap<>(); List<String> vals = new ArrayList<>();
        Map<String, Long> stk = new HashMap<>(), idn = new HashMap<>(); Set<String> ver = new HashSet<>(); Map<String, String> vp = new HashMap<>();
        MLDSAPrivateKeyParameters[] vk = new MLDSAPrivateKeyParameters[2]; String[] vid = new String[2];
        Map<String, MLDSAPublicKeyParameters> pubById = new HashMap<>();
        for (int i = 0; i < 2; i++) {
            vk[i] = key(); vid[i] = Keys.idOf(vk[i]);
            alloc.put(vid[i], 1_000_000L); vals.add(vid[i]); stk.put(vid[i], 1_000_000L); idn.put(vid[i], 1L); ver.add(vid[i]); vp.put(vid[i], Keys.pubHex(vk[i]));
            pubById.put(vid[i], vk[i].getPublicKeyParameters());
        }
        Ledger L = new Ledger(); L.genesisEcon("pc-clustercons", alloc, vals, stk, idn, ver, vp, 0);
        L.beacon = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8("genesis-beacon")));

        // form a cluster of 3 members (each pre-bonded 250k -> 750k pooled), threshold 2; lead member = beacon key
        int M = 3, threshold = 2;
        MLDSAPrivateKeyParameters[] mk = new MLDSAPrivateKeyParameters[M]; String[] mid = new String[M];
        List<String> members = new ArrayList<>(); Map<String, String> mpub = new HashMap<>();
        for (int i = 0; i < M; i++) { mk[i] = key(); mid[i] = Keys.idOf(mk[i]); members.add(mid[i]); mpub.put(mid[i], Keys.pubHex(mk[i])); L.stake.put(mid[i], 250_000L); }
        String clusterId = "cluster-alpha";
        String commit0 = Ledger.beaconCommit0For(mk[0].getEncoded());   // cluster's beacon is keyed by its lead member
        L.applyClusterForm(L.buildClusterFormTx(clusterId, members, mpub, threshold, mk[0], commit0));
        int cidx = L.validators.indexOf(clusterId);
        System.out.println("cluster joined as validator index " + cidx + " (members=" + M + " threshold=" + threshold + ", pooled stake=" + L.stake.get(clusterId) + ")");
        System.out.println("validators: val0, val1, CLUSTER\n");

        // beacon counters per proposer key id
        Map<String, Long> ctr = new HashMap<>();
        long[] memBefore = new long[M];
        boolean clusterProposed = false, clusterCommitted = false;
        Set<String> subsetsUsed = new HashSet<>();
        int epochs = 0, blocks = 0;

        for (int round = 0; round < 40 && !(clusterProposed && epochs >= 3); round++) {
            int h = L.chain.size();
            int proposer = L.proposerFor(L.lastHash(), h, 0);
            String pid = L.validators.get(proposer);
            JSONObject blk = L.buildProposal(proposer, h * 1000L);
            blk.put("view", 0);

            // proposer's RANDAO reveal (cluster reveals via its lead member key)
            MLDSAPrivateKeyParameters bkey = L.isCluster(pid) ? mk[0] : vk[proposer];
            long c = ctr.getOrDefault(pid, 0L);
            blk.put("reveal", PhantomCrypto.hex(secret(bkey, c)))
               .put("commit", PhantomCrypto.hex(PhantomCrypto.sha3_256(secret(bkey, c + 1))));

            // assemble the QC: every committee validator signs (N=3 -> quorum 3). The cluster signs with a
            // 2-of-3 member subset (rotating which member is "offline" -> proves M-of-N liveness).
            String hash = blk.getString("hash");
            JSONArray qc = new JSONArray();
            for (int idx : L.committeeFor(h)) {
                String v = L.validators.get(idx);
                if (L.isCluster(v)) {
                    int off = h % M;                                   // one member rotates "offline" each block
                    JSONArray bundle = new JSONArray(); StringBuilder sub = new StringBuilder();
                    for (int j = 0; j < M; j++) { if (j == off) continue;
                        bundle.put(new JSONObject().put("m", mid[j]).put("sig", PhantomCrypto.hex(PhantomCrypto.sign(mk[j], PhantomCrypto.utf8(hash)))));
                        sub.append(j); }
                    subsetsUsed.add(sub.toString());
                    qc.put(new JSONObject().put("i", idx).put("bundle", bundle));
                } else {
                    qc.put(new JSONObject().put("i", idx).put("sig", PhantomCrypto.hex(PhantomCrypto.sign(vk[idx], PhantomCrypto.utf8(hash)))));
                }
            }
            blk.put("qc", qc);

            if (!verifyQC(L, blk, pubById)) { System.out.println("  ** QC verify failed at h=" + h + " (proposer " + proposer + ")"); fail++; break; }
            String r = L.commitBlock(blk, pubById);
            if (!"appended".equals(r)) { System.out.println("  ** commit failed at h=" + h + ": " + r); fail++; break; }

            ctr.put(pid, c + 1);
            blocks++;
            if (L.isCluster(pid)) { clusterProposed = true; clusterCommitted = true; }
            if (h % Ledger.EPOCH_LEN == 0) epochs++;   // an epoch reward was distributed at this commit
            System.out.println("  committed h=" + h + " proposer=" + (L.isCluster(pid) ? "CLUSTER" : ("val" + proposer))
                    + " clusterMemberBal=[" + L.balanceOf(mid[0]) + "," + L.balanceOf(mid[1]) + "," + L.balanceOf(mid[2]) + "]");
        }

        System.out.println("\n==== assertions ====");
        ok("cluster co-signed and committed real blocks via M-of-N", clusterCommitted && blocks >= 6);
        ok("cluster was elected proposer at least once (weighted by stake+identity)", clusterProposed);
        ok("M-of-N liveness: >1 distinct 2-of-3 member subset signed (a member can be offline)", subsetsUsed.size() >= 2);
        long m0 = L.balanceOf(mid[0]), m1 = L.balanceOf(mid[1]), m2 = L.balanceOf(mid[2]);
        ok("epoch rewards fanned out DIRECTLY to each member (§9.6)", m0 > 0 && m1 > 0 && m2 > 0);
        ok("members earned ~equally (cluster has no operator skim)", Math.abs(m0 - m1) <= 2 && Math.abs(m1 - m2) <= 2);
        ok("cluster account itself holds nothing (rewards bypass it)", L.balanceOf(clusterId) == 0);
        long totalToMembers = m0 + m1 + m2;
        System.out.println("  cluster lifetime earnings -> members: " + totalToMembers + " (m0=" + m0 + " m1=" + m1 + " m2=" + m2 + "), minted=" + L.totalMinted);

        // negative: a sub-threshold cluster vote (1-of-3) must fail the QC -> the cluster cannot sign while degraded
        JSONObject probe = L.buildProposal(L.proposerFor(L.lastHash(), L.chain.size(), 0), 999_000L);
        String ph = probe.getString("hash");
        JSONArray badQc = new JSONArray();
        for (int idx : L.committeeFor(L.chain.size())) {
            String v = L.validators.get(idx);
            if (L.isCluster(v)) badQc.put(new JSONObject().put("i", idx).put("bundle",
                    new JSONArray().put(new JSONObject().put("m", mid[0]).put("sig", PhantomCrypto.hex(PhantomCrypto.sign(mk[0], PhantomCrypto.utf8(ph)))))));   // only 1-of-3
            else badQc.put(new JSONObject().put("i", idx).put("sig", PhantomCrypto.hex(PhantomCrypto.sign(vk[idx], PhantomCrypto.utf8(ph)))));
        }
        probe.put("view", 0).put("qc", badQc);
        ok("sub-threshold cluster vote (1-of-3) fails the QC -> safety preserved", !verifyQC(L, probe, pubById));

        System.out.println("\nClusterConsensus: " + pass + " passed, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }
}
