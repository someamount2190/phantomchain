package com.phantomchain.debug;

import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

/**
 * Large-scale, in-process consensus simulation. Drives the REAL state machine + consensus path
 * (weighted RANDAO proposerFor → committeeFor sortition → ML-DSA quorum certificate → verifyQC →
 * commitBlock with state-root / shards-root / beacon-reveal checks) at validator counts the live
 * multi-process net can't reach, and reports throughput + decentralization + the §9.4 10% cap and
 * geo-premium behaving at scale.
 *
 * Usage: LargeScaleSim [N] [committeeSize] [heights] [txPerBlock] [srVersion]
 */
public class LargeScaleSim {

    static MLDSAPrivateKeyParameters[] keys;
    static String[] ids;
    static long[] ctr;                                   // per-validator RANDAO reveal counter
    static Map<String, MLDSAPublicKeyParameters> pubById = new HashMap<>();

    public static void main(String[] a) throws Exception {
        // scenarios: {N, committeeSize, heights, txPerBlock, srVersion}
        if (a.length >= 3) {
            run(Integer.parseInt(a[0]), Integer.parseInt(a[1]), Integer.parseInt(a[2]),
                a.length > 3 ? Integer.parseInt(a[3]) : 25, a.length > 4 ? a[4] : "full");
            return;
        }
        run(100, 0,  30, 25, "full");   // A: full-set BFT at N=100 (cap + geo engaged), every validator signs
        run(500, 64, 30, 25, "full");   // B: committee sortition at N=500 (bounded signing)
        run(1000, 64, 20, 25, "m1");    // C: N=1000 + authenticated Merkle state root (srVersion=m1) at scale
    }

    static void run(int N, int committeeSize, int heights, int txPerBlock, String srVersion) throws Exception {
        System.out.println("\n================ SCENARIO  N=" + N + "  committeeSize=" + committeeSize
                + "  heights=" + heights + "  tx/block=" + txPerBlock + "  srVersion=" + srVersion + " ================");
        Random rnd = new Random(42L + N);
        long t0 = System.currentTimeMillis();

        // ---- keygen + genesis spec ----
        keys = new MLDSAPrivateKeyParameters[N]; ids = new String[N]; ctr = new long[N];
        pubById.clear();
        LinkedHashMap<String, Long> alloc = new LinkedHashMap<>();
        List<String> vals = new ArrayList<>();
        Map<String, Long> stk = new HashMap<>(), idn = new HashMap<>();
        Set<String> verified = new HashSet<>();
        Map<String, String> valPubs = new HashMap<>(), beaconCommits = new HashMap<>();
        for (int i = 0; i < N; i++) {
            keys[i] = PhantomCrypto.randomDeviceKey();
            byte[] enc = keys[i].getEncoded();
            String pub = PhantomCrypto.hex(keys[i].getPublicKeyParameters().getEncoded());
            ids[i] = PhantomCrypto.hex(PhantomCrypto.sha3_256(keys[i].getPublicKeyParameters().getEncoded()));
            pubById.put(ids[i], new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, keys[i].getPublicKeyParameters().getEncoded()));
            // stake distribution: one whale (to make the 10% cap bite) + a heavy-tailed rest
            long stake = (i == 0) ? 50_000_000L : (long) (500_000 + Math.pow(rnd.nextDouble(), 3) * 5_000_000);
            alloc.put(ids[i], 1_000_000L); vals.add(ids[i]); stk.put(ids[i], stake); idn.put(ids[i], 1L);
            verified.add(ids[i]); valPubs.put(ids[i], pub);
            beaconCommits.put(ids[i], Ledger.beaconCommit0For(enc));
        }
        long tKey = System.currentTimeMillis();

        Ledger L = new Ledger();
        L.srVersion = srVersion;
        L.genesisEcon("pc-large-" + N, alloc, vals, stk, idn, verified, valPubs, beaconCommits, 1700000000000L);
        L.committeeSize = committeeSize;
        // geo: put 8% of validators into a single sparse region to exercise the coverage premium
        int sparse = Math.max(1, N / 12);
        for (int i = N - sparse; i < N; i++) L.regions.put(ids[i], "sparse-AS");

        // ---- drive consensus ----
        int[] proposerCount = new int[N];
        long totalTxApplied = 0, totalSigs = 0;
        long tConsensus0 = System.currentTimeMillis();
        for (int h = 1; h <= heights; h++) {
            // inject txs
            for (int t = 0; t < txPerBlock; t++) {
                int from = rnd.nextInt(N), to = rnd.nextInt(N);
                JSONObject tx = L.buildTxProjected(ids[from], ids[to], 1 + rnd.nextInt(100), 1, keys[from]);
                L.addToMempool(tx, pubById);
            }
            int proposer = L.proposerFor(L.lastHash(), h, 0);
            proposerCount[proposer]++;
            JSONObject blk = L.buildProposal(proposer, 1700000000000L + h);
            blk.put("view", 0);
            blk.put("reveal", PhantomCrypto.hex(Ledger.beaconSecretFor(keys[proposer].getEncoded(), ctr[proposer])));
            blk.put("commit", PhantomCrypto.hex(PhantomCrypto.sha3_256(Ledger.beaconSecretFor(keys[proposer].getEncoded(), ctr[proposer] + 1))));
            String hash = blk.getString("hash");

            // committee signs -> QC
            List<Integer> committee = L.committeeFor(h);
            int needed = L.committeeQuorum(h);
            JSONArray qc = new JSONArray();
            for (int j : committee) {
                if (qc.length() >= needed) break;
                qc.put(new JSONObject().put("i", j).put("sig",
                        PhantomCrypto.hex(PhantomCrypto.sign(keys[j], PhantomCrypto.utf8(hash)))));
            }
            blk.put("qc", qc);
            totalSigs += qc.length();

            if (!verifyQC(L, blk, N)) { System.out.println("  ** QC verify FAILED at height " + h); return; }
            int txCount = blk.getJSONArray("txs").length();
            String res = L.commitBlock(blk, pubById);
            if (!"appended".equals(res)) { System.out.println("  ** commit FAILED at height " + h + ": " + res); return; }
            ctr[proposer]++;
            totalTxApplied += txCount;
            L.mempool.clear();   // applied txs done; refill next height
        }
        long tEnd = System.currentTimeMillis();

        // ---- metrics ----
        Map<Integer, Double> wm = L.weightMap();
        double maxW = 0; int maxIdx = -1;
        for (int i = 0; i < N; i++) { double w = wm.getOrDefault(i, 0.0); if (w > maxW) { maxW = w; maxIdx = i; } }
        int distinctProposers = 0; for (int c : proposerCount) if (c > 0) distinctProposers++;
        double consSec = (tEnd - tConsensus0) / 1000.0;

        System.out.printf(Locale.US, "  setup: %d keygen in %.1fs, genesis ready%n", N, (tKey - t0) / 1000.0);
        System.out.printf(Locale.US, "  consensus: %d blocks, %d txs applied in %.2fs  ->  %.1f blocks/s, %.0f tx/s%n",
                heights, totalTxApplied, consSec, heights / consSec, totalTxApplied / consSec);
        System.out.printf(Locale.US, "  QC: avg %.0f sigs/block (committee=%d, quorum=%d of live %d)%n",
                (double) totalSigs / heights, committeeFor_size(L), L.committeeQuorum(1), L.liveIdx().size());
        System.out.printf(Locale.US, "  decentralization: %d/%d distinct proposers in %d heights%n",
                distinctProposers, N, heights);
        System.out.printf(Locale.US, "  §9.4 cap: whale stake=%d (%.1f%% of stake) -> capped weight %.2f%% (max any validator %.2f%%, cap=%.0f%%)%n",
                stk.get(ids[0]), 100.0 * stk.get(ids[0]) / totalStake(stk), 100 * wm.getOrDefault(0, 0.0),
                100 * maxW, 100 * ValidatorSelection.WEIGHT_CAP);
        // geo: report the coverage MULTIPLIER directly (the premium), not an avg-vs-avg ratio confounded by
        // each validator's differing base stake. A sparse-region validator (idx N-1) vs a no-region one (idx 0).
        System.out.printf(Locale.US, "  geo-premium: %d-validator sparse region -> coverage multiplier %.4fx (vs 1.0000x for no-region validators; applied to weight before the cap)%n",
                sparse, L.coverageMultiplier(N - 1));
        System.out.printf(Locale.US, "  state: %d accounts, height %d, stateRoot=%s...%n",
                L.accounts.size(), L.height(), L.stateRoot().substring(0, 16));
        // authenticated proof spot-check at scale
        JSONObject proof = L.accountProof(ids[N / 2]);
        System.out.printf(Locale.US, "  authenticated proof for a mid account: present=%b verified=%b depth=%d%n",
                proof.optBoolean("present"), Ledger.verifyAccountProof(proof),
                proof.optJSONArray("siblings") == null ? 0 : proof.getJSONArray("siblings").length());
        System.out.printf(Locale.US, "  TOTAL wall-clock %.1fs%n", (tEnd - t0) / 1000.0);
    }

    static int committeeFor_size(Ledger L) { return L.committeeFor(1).size(); }
    static long totalStake(Map<String, Long> stk) { long s = 0; for (long v : stk.values()) s += v; return s; }

    /** Faithful replica of NetNode.verifyQC: proposer legitimacy + committee membership + ML-DSA sigs + quorum. */
    static boolean verifyQC(Ledger L, JSONObject b, int N) throws Exception {
        JSONArray qc = b.optJSONArray("qc"); if (qc == null) return false;
        String hash = b.getString("hash");
        int h = b.getInt("height");
        int legit = L.proposerFor(b.getString("prevHash"), h, b.optInt("view", 0));
        if (b.optInt("proposer", -1) != legit || L.excluded(L.validators.get(legit))) return false;
        Set<Integer> committee = new HashSet<>(L.committeeFor(h));
        Set<Integer> ok = new HashSet<>();
        for (int i = 0; i < qc.length(); i++) {
            JSONObject v = qc.getJSONObject(i); int idx = v.getInt("i");
            if (idx < 0 || idx >= N || L.excluded(L.validators.get(idx)) || !committee.contains(idx)) continue;
            MLDSAPublicKeyParameters pub = pubById.get(L.validators.get(idx));
            if (pub != null && PhantomCrypto.verify(pub, PhantomCrypto.utf8(hash), PhantomCrypto.unhex(v.getString("sig")))) ok.add(idx);
        }
        return ok.size() >= L.committeeQuorum(h);
    }
}
