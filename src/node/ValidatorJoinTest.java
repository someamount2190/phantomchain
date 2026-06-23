package com.phantomchain.debug;

import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

/**
 * VALIDATOR-SET ADMISSION (VALJOIN) adversarial testing. The set is append-only and entry is gated by a
 * sufficient bond + a signed beacon commitment. We attack that: unbonded/under-bonded joins, duplicate
 * joins, forged signatures, and a commitment the joiner didn't sign are all rejected; a properly bonded
 * key joins (control).
 */
public class ValidatorJoinTest {
    static int pass = 0, fail = 0;
    static void ok(String n, boolean c) { System.out.println((c ? "  PASS " : "  ** FAIL ** ") + n); if (c) pass++; else fail++; }
    static int N; static MLDSAPrivateKeyParameters[] keys; static String[] ids; static long[] ctr;
    static Map<String, MLDSAPublicKeyParameters> pub = new HashMap<>();

    public static void main(String[] a) throws Exception {
        System.out.println("==== VALIDATOR-SET ADMISSION (VALJOIN) adversarial ====\n");
        int n = 5;
        // candidate keys created up-front so we can pre-fund their accounts at genesis
        MLDSAPrivateKeyParameters good = PhantomCrypto.randomDeviceKey();   // will bond enough -> should join
        MLDSAPrivateKeyParameters poor = PhantomCrypto.randomDeviceKey();   // bonds too little -> rejected
        String goodId = Ledger.idOf(PhantomCrypto.hex(good.getPublicKeyParameters().getEncoded()));
        String poorId = Ledger.idOf(PhantomCrypto.hex(poor.getPublicKeyParameters().getEncoded()));

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
        alloc.put(goodId, 1_000_000L); alloc.put(poorId, 1_000_000L);   // fund the candidates so they can bond
        Ledger L = new Ledger();
        L.genesisEcon("pc-vjoin", alloc, vals, stk, idn, ver, vp, bc, 1700000000000L);
        L.committeeSize = 0;
        // register the candidate pubkeys so their self-sovereign txs verify
        pub.put(goodId, new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, good.getPublicKeyParameters().getEncoded()));
        pub.put(poorId, new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, poor.getPublicKeyParameters().getEncoded()));

        // ---- mempool-level VALJOIN guards (verifyValJoin in txCheck) ----
        ok("V1 VALJOIN from an UNBONDED key (stake < min) is rejected",
                !accepted(L, L.buildValJoinTx(good)));   // good hasn't bonded yet
        ok("V2 VALJOIN from an EXISTING validator (duplicate) is rejected",
                !accepted(L, L.buildValJoinTx(keys[0])));
        // forged signature
        JSONObject forged = L.buildValJoinTx(good); forged.put("sig", "00");
        ok("V3 VALJOIN with a forged signature is rejected", !accepted(L, forged));
        // a commitment the joiner didn't sign (swap in another key's commit0)
        JSONObject swapped = L.buildValJoinTx(good).put("beaconCommit0", Ledger.beaconCommit0For(keys[1].getEncoded()));
        ok("V4 VALJOIN carrying someone else's beaconCommit0 (sig mismatch) is rejected", !accepted(L, swapped));

        // ---- bond enough, then join (control), and the append-only / floor effect ----
        commit(L, L.buildBondTx(goodId, 600_000, 0, false, good));   // bond >= minValidatorStake (500k)
        commit(L, L.buildBondTx(poorId, 100_000, 0, false, poor));   // bond too little
        ok("V5 after bonding < min, the under-bonded key's VALJOIN is still rejected",
                !accepted(L, L.buildValJoinTx(poor)));
        boolean joinAccepted = accepted(L, L.buildValJoinTx(good));
        commit(L, null);   // commit the pending VALJOIN
        boolean inSet = L.validators.contains(goodId);
        ok("V6 control: a sufficiently-bonded key with a valid commitment JOINS the validator set", joinAccepted && inSet);
        ok("V7 the under-bonded key never entered the validator set (bond floor enforced)", !L.validators.contains(poorId));

        System.out.println("\n==== ValidatorJoinTest: " + pass + " passed, " + fail + " failed ====");
        System.exit(fail == 0 ? 0 : 1);
    }

    static boolean accepted(Ledger L, JSONObject tx) throws Exception { return "accepted".equals(L.addToMempool(tx, pub)); }
    /** Commit a block on the current head (including any mempool txs); pass an extra tx to add first, or null. */
    static void commit(Ledger L, JSONObject extra) throws Exception {
        if (extra != null) { String r = L.addToMempool(extra, pub); if (!"accepted".equals(r)) throw new IllegalStateException("setup tx rejected: " + r); }
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
