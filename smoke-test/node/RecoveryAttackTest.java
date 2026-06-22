package com.phantomchain.debug;

import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

/**
 * GUARDIAN RECOVERY adversarial testing (M-of-N social recovery of a lost device key). Recovery must
 * require >= threshold DISTINCT registered-guardian approvals, be replay-protected by rotNonce, and only
 * the root may (re)set guardians. We attack: sub-threshold, duplicate-guardian, non-guardian, forged-sig,
 * wrong-rotNonce, replay-after-recovery, and non-root SETGUARDIANS.
 */
public class RecoveryAttackTest {
    static int pass = 0, fail = 0;
    static void ok(String n, boolean c) { System.out.println((c ? "  PASS " : "  ** FAIL ** ") + n); if (c) pass++; else fail++; }
    static final String CID = "pc-recovery";
    static int N; static MLDSAPrivateKeyParameters[] keys; static String[] ids; static long[] ctr;
    static Map<String, MLDSAPublicKeyParameters> pub = new HashMap<>();
    static Ledger L;

    public static void main(String[] a) throws Exception {
        System.out.println("==== GUARDIAN RECOVERY adversarial (M-of-N social recovery) ====\n");
        L = genesis(5);

        // identities: owner + two guardians + one non-guardian
        MLDSAPrivateKeyParameters rootO = key(), devO = key(), rootG1 = key(), devG1 = key(),
                                  rootG2 = key(), devG2 = key(), rootH = key(), devH = key();
        String ownerId = Ledger.idOf(hex(rootO)), g1 = Ledger.idOf(hex(rootG1)), g2 = Ledger.idOf(hex(rootG2)), h = Ledger.idOf(hex(rootH));
        commit(L.buildRegisterTx(rootO, devO));
        commit(L.buildRegisterTx(rootG1, devG1));
        commit(L.buildRegisterTx(rootG2, devG2));
        commit(L.buildRegisterTx(rootH, devH));
        // owner sets guardians {g1,g2}, threshold 2 (root-authorized)
        commit(L.buildSetGuardiansTx(ownerId, rootO, new JSONArray().put(g1).put(g2), 2, 0));
        long rn = L.identities.get(ownerId).getLong("rotNonce");   // == 1 after SETGUARDIANS
        String newDev = hex(key());

        // R1 — sub-threshold (1 of 2)
        ok("R1 recovery with sub-threshold approvals (1 of 2) is rejected", !accepted(
                L.buildRecoverTx(ownerId, newDev, rn, new JSONArray().put(L.recoverApproval(g1, devG1, ownerId, newDev, rn)))));
        // R2 — duplicate guardian counted once
        ok("R2 duplicate-guardian approvals don't reach threshold", !accepted(
                L.buildRecoverTx(ownerId, newDev, rn, new JSONArray()
                        .put(L.recoverApproval(g1, devG1, ownerId, newDev, rn))
                        .put(L.recoverApproval(g1, devG1, ownerId, newDev, rn)))));
        // R3 — a NON-guardian's approval doesn't count
        ok("R3 a non-guardian approval is not counted", !accepted(
                L.buildRecoverTx(ownerId, newDev, rn, new JSONArray()
                        .put(L.recoverApproval(g1, devG1, ownerId, newDev, rn))
                        .put(L.recoverApproval(h, devH, ownerId, newDev, rn)))));
        // R4 — forged guardian signature
        JSONObject badAppr = L.recoverApproval(g2, devG2, ownerId, newDev, rn).put("sig", "00");
        ok("R4 a forged guardian signature is not counted", !accepted(
                L.buildRecoverTx(ownerId, newDev, rn, new JSONArray().put(L.recoverApproval(g1, devG1, ownerId, newDev, rn)).put(badAppr))));
        // R5 — wrong rotNonce (replay-protection); approvals signed for the wrong nonce too
        ok("R5 recovery with the wrong rotNonce is rejected (replay-protected)", !accepted(
                L.buildRecoverTx(ownerId, newDev, 99, new JSONArray()
                        .put(L.recoverApproval(g1, devG1, ownerId, newDev, 99))
                        .put(L.recoverApproval(g2, devG2, ownerId, newDev, 99)))));
        // R6 — non-root SETGUARDIANS (signed by a device key, not the root)
        JSONArray gs = new JSONArray().put(h);
        JSONObject badSG = new JSONObject().put("from", "SETGUARDIANS").put("id", ownerId).put("guardians", gs)
                .put("threshold", 1).put("rotNonce", rn).put("cid", CID)
                .put("sig", PhantomCrypto.hex(PhantomCrypto.sign(devO, PhantomCrypto.utf8("setguardians|" + CID + "|" + ownerId + "|" + gs + "|1|" + rn))));
        ok("R6 SETGUARDIANS signed by a device key (not root) is rejected", !accepted(badSG));

        // R7 — control: 2 valid distinct guardian approvals recover the account
        JSONObject good = L.buildRecoverTx(ownerId, newDev, rn, new JSONArray()
                .put(L.recoverApproval(g1, devG1, ownerId, newDev, rn))
                .put(L.recoverApproval(g2, devG2, ownerId, newDev, rn)));
        boolean recOk = accepted(good); commit(null);
        JSONObject idn = L.identities.get(ownerId);
        boolean rotated = idn.getJSONArray("devices").length() == 1 && idn.getJSONArray("devices").getString(0).equals(newDev)
                && idn.getLong("rotNonce") == rn + 1;
        ok("R7 control: 2-of-2 valid guardian approvals recover the device (rotNonce advances)", recOk && rotated);
        // R8 — replay the exact same recovery after it succeeded (rotNonce has advanced)
        ok("R8 replaying the successful recovery tx is rejected (rotNonce advanced)", !accepted(good));

        System.out.println("\n==== RecoveryAttackTest: " + pass + " passed, " + fail + " failed ====");
        System.exit(fail == 0 ? 0 : 1);
    }

    static MLDSAPrivateKeyParameters key() { return PhantomCrypto.randomDeviceKey(); }
    static String hex(MLDSAPrivateKeyParameters k) { return PhantomCrypto.hex(k.getPublicKeyParameters().getEncoded()); }
    static boolean accepted(JSONObject tx) throws Exception { return "accepted".equals(L.addToMempool(tx, pub)); }

    static Ledger genesis(int n) throws Exception {
        N = n; keys = new MLDSAPrivateKeyParameters[n]; ids = new String[n]; ctr = new long[n]; pub.clear();
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
        Ledger g = new Ledger(); g.genesisEcon(CID, alloc, vals, stk, idn, ver, vp, bc, 1700000000000L);
        g.committeeSize = 0; return g;
    }
    static void commit(JSONObject extra) throws Exception {
        if (extra != null) { String r = L.addToMempool(extra, pub); if (!"accepted".equals(r)) throw new IllegalStateException("setup tx: " + r); }
        int hh = L.chain.size(); int p = L.proposerFor(L.lastHash(), hh, 0);
        JSONObject b = L.buildProposal(p, 1700000000000L + hh);
        b.put("view", 0).put("reveal", PhantomCrypto.hex(Ledger.beaconSecretFor(keys[p].getEncoded(), ctr[p])))
         .put("commit", PhantomCrypto.hex(PhantomCrypto.sha3_256(Ledger.beaconSecretFor(keys[p].getEncoded(), ctr[p] + 1))));
        JSONArray qc = new JSONArray();
        for (int s = 0; s < L.committeeQuorum(hh); s++) qc.put(new JSONObject().put("i", s).put("sig", PhantomCrypto.hex(PhantomCrypto.sign(keys[s], PhantomCrypto.utf8(b.getString("hash"))))));
        b.put("qc", qc);
        String r = L.commitBlock(b, pub);
        if (!"appended".equals(r)) throw new IllegalStateException("commit: " + r);
        ctr[p]++; L.mempool.clear();
    }
}
