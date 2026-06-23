package com.phantomchain.debug;

import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

/**
 * GOVERNANCE adversarial testing of the two-phase param-change lifecycle (snapshot-weighted voting ->
 * turnout quorum -> timelocked clamped execution). Attacks: non-whitelisted params, duplicate proposals,
 * votes by non-snapshot actors, votes after the deadline, execution before the timelock, sub-quorum
 * turnout, and disabling slashing via governance (floor). Drives the REAL engine end-to-end.
 */
public class GovernanceAttackTest {
    static int pass = 0, fail = 0;
    static void ok(String n, boolean c) { System.out.println((c ? "  PASS " : "  ** FAIL ** ") + n); if (c) pass++; else fail++; }
    static int N; static MLDSAPrivateKeyParameters[] keys; static String[] ids; static long[] ctr;
    static Map<String, MLDSAPublicKeyParameters> pub = new HashMap<>();
    static Ledger L;
    static MLDSAPrivateKeyParameters outKey; static String outId;   // a funded NON-validator

    public static void main(String[] a) throws Exception {
        System.out.println("==== GOVERNANCE adversarial (propose/vote/timelock) ====\n");
        int n = 5;
        outKey = PhantomCrypto.randomDeviceKey(); outId = Ledger.idOf(PhantomCrypto.hex(outKey.getPublicKeyParameters().getEncoded()));
        keys = new MLDSAPrivateKeyParameters[n]; ids = new String[n]; ctr = new long[n]; pub.clear();
        LinkedHashMap<String, Long> alloc = new LinkedHashMap<>();
        List<String> vals = new ArrayList<>(); Map<String, Long> stk = new HashMap<>(), idn = new HashMap<>();
        Set<String> ver = new HashSet<>(); Map<String, String> vp = new HashMap<>(), bc = new HashMap<>();
        for (int i = 0; i < n; i++) {
            keys[i] = PhantomCrypto.randomDeviceKey();
            ids[i] = PhantomCrypto.hex(PhantomCrypto.sha3_256(keys[i].getPublicKeyParameters().getEncoded()));
            pub.put(ids[i], new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, keys[i].getPublicKeyParameters().getEncoded()));
            alloc.put(ids[i], 1_000_000L); vals.add(ids[i]); stk.put(ids[i], 1_000_000L); idn.put(ids[i], 1L);
            ver.add(ids[i]); vp.put(ids[i], PhantomCrypto.hex(keys[i].getPublicKeyParameters().getEncoded()));
            bc.put(ids[i], Ledger.beaconCommit0For(keys[i].getEncoded()));
        }
        alloc.put(outId, 1_000_000L);
        L = new Ledger(); L.genesisEcon("pc-gov2", alloc, vals, stk, idn, ver, vp, bc, 1700000000000L);
        L.committeeSize = 0;
        pub.put(outId, new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, outKey.getPublicKeyParameters().getEncoded()));

        // G1 — a non-whitelisted parameter cannot be proposed (effect is a no-op)
        propose(ids[0], keys[0], "g1", "totalMinted", 999);   // not in GOV_PARAMS
        ok("G1 a proposal for a non-whitelisted param is not created", !L.proposals.containsKey("g1"));

        // G2 — duplicate proposal id can't overwrite an existing proposal
        propose(ids[0], keys[0], "g2", "feeBurnBps", 1000);
        propose(ids[1], keys[1], "g2", "feeBurnBps", 9999);   // same id, different value
        ok("G2 a duplicate proposal id does not overwrite the original", L.proposals.containsKey("g2") && L.proposals.get("g2").getLong("value") == 1000);

        // G3 — only SNAPSHOT validators can vote; a non-validator's vote is ignored
        vote(outId, outKey, "g2", true);
        ok("G3 a vote by a non-snapshot (non-validator) actor is ignored", !L.proposals.get("g2").getJSONObject("votes").has(outId));

        // G4 — votes after the deadline are ignored
        long g2deadline = L.proposals.get("g2").getLong("deadline");
        advanceTo(g2deadline + 1);
        vote(ids[3], keys[3], "g2", true);
        ok("G4 a vote after the deadline is ignored", !L.proposals.get("g2").getJSONObject("votes").has(ids[3]));

        // G5 — a passing proposal applies ONLY after the timelock
        int before = L.feeBurnBps;
        propose(ids[0], keys[0], "g5", "feeBurnBps", 1234);
        for (int i = 0; i < 5; i++) vote(ids[i], keys[i], "g5", true);   // unanimous -> turnout 100%, yes>no
        commitPending();
        long applyAt = L.proposals.get("g5").getLong("applyAt"), deadline = L.proposals.get("g5").getLong("deadline");
        advanceTo(deadline + 1);                                          // tally fires here
        ok("G5a a passed proposal is NOT applied before the timelock (feeBurnBps still " + before + ")", L.feeBurnBps == before);
        advanceTo(applyAt + 1);                                           // timelocked execution
        ok("G5b applied only after the timelock (feeBurnBps -> 1234)", L.feeBurnBps == 1234);

        // G6 — sub-quorum turnout cannot pass (only 1 of 5 votes -> ~20% < 33.34%)
        int feeBefore = L.feeBurnBps;
        propose(ids[0], keys[0], "g6", "feeBurnBps", 2222);
        vote(ids[0], keys[0], "g6", true);
        long g6applyAt = L.proposals.get("g6").getLong("applyAt");
        advanceTo(g6applyAt + 1);
        ok("G6 a sub-quorum-turnout proposal does NOT pass (feeBurnBps unchanged)", L.feeBurnBps == feeBefore && !L.proposals.get("g6").getBoolean("passed"));

        // G7 — governance cannot disable slashing (clamped to the floor)
        propose(ids[0], keys[0], "g7", "slashBps", 0);
        for (int i = 0; i < 5; i++) vote(ids[i], keys[i], "g7", true);
        commitPending();
        long g7applyAt = L.proposals.get("g7").getLong("applyAt");
        advanceTo(g7applyAt + 1);
        ok("G7 disabling slashing via governance is clamped to the floor (slashBps=" + L.slashBps + " >= 100, passed=" + L.proposals.get("g7").getBoolean("passed") + ")",
                L.proposals.get("g7").getBoolean("passed") && L.slashBps >= 100);

        System.out.println("\n==== GovernanceAttackTest: " + pass + " passed, " + fail + " failed ====");
        System.exit(fail == 0 ? 0 : 1);
    }

    static void propose(String actor, MLDSAPrivateKeyParameters key, String pid, String param, long value) throws Exception {
        add(L.buildProposeTx(actor, pid, param, value, L.projectedNonce(actor), key)); commitPending();
    }
    static void vote(String actor, MLDSAPrivateKeyParameters key, String pid, boolean choice) throws Exception {
        add(L.buildVoteTx(actor, pid, choice, L.projectedNonce(actor), key)); commitPending();
    }
    static void add(JSONObject tx) throws Exception { L.addToMempool(tx, pub); }
    static void advanceTo(long targetHeight) throws Exception { while (L.chain.size() <= targetHeight) commitPending(); }

    /** Commit a block on the head including any mempool txs, then clear the mempool. */
    static void commitPending() throws Exception {
        int h = L.chain.size(); int p = L.proposerFor(L.lastHash(), h, 0);
        JSONObject b = L.buildProposal(p, 1700000000000L + h);
        b.put("view", 0).put("reveal", PhantomCrypto.hex(Ledger.beaconSecretFor(keys[p].getEncoded(), ctr[p])))
         .put("commit", PhantomCrypto.hex(PhantomCrypto.sha3_256(Ledger.beaconSecretFor(keys[p].getEncoded(), ctr[p] + 1))));
        JSONArray qc = new JSONArray();
        for (int s = 0; s < L.committeeQuorum(h); s++) qc.put(new JSONObject().put("i", s).put("sig", PhantomCrypto.hex(PhantomCrypto.sign(keys[s], PhantomCrypto.utf8(b.getString("hash"))))));
        b.put("qc", qc);
        String r = L.commitBlock(b, pub);
        if (!"appended".equals(r)) throw new IllegalStateException("commit failed: " + r);
        ctr[p]++; L.mempool.clear();
    }
}
