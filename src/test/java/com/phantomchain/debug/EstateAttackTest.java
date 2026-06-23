package com.phantomchain.debug;

import static com.phantomchain.debug.TestKit.*;

import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

/**
 * ESTATE / INHERITANCE (CLAIM) adversarial testing. A beneficiary may claim an account only after a
 * sustained inactivity window, and ONLY outgoing actions reset that clock. We attack the timing:
 * premature claims, claims with no beneficiary, claims of a drained account (double-claim), the
 * activity-reset rule, and the incoming-doesn't-reset nuance.
 */
public class EstateAttackTest {
    static int N; static MLDSAPrivateKeyParameters[] keys; static String[] ids; static long[] ctr;
    static Map<String, MLDSAPublicKeyParameters> pub = new HashMap<>();
    static Ledger L;

    public static void main(String[] a) throws Exception {
        System.out.println("==== ESTATE / INHERITANCE (CLAIM) adversarial ====\n");
        L = genesis(5);
        long W = L.estateInactivity;   // = 10
        System.out.println("[estateInactivity = " + W + " blocks]\n");

        // owner ids[0] names beneficiary ids[1]  (SETBENEFICIARY is an outgoing action -> resets the clock)
        commit(L.buildSetBeneficiaryTx(ids[0], ids[1], L.projectedNonce(ids[0]), keys[0]));

        // E1 — premature claim (clock just reset by SETBENEFICIARY)
        ok("E1 a claim before the inactivity window is rejected", !accepted(claim(ids[0])));
        // E2 — claim of an account with no beneficiary
        ok("E2 a claim of an account with no beneficiary is rejected", !accepted(claim(ids[2])));

        // advance past the inactivity window with empty blocks (no activity from ids[0])
        advance((int) W + 2);
        long benefBefore = L.balanceOf(ids[1]); long estate = L.balanceOf(ids[0]);

        // E3 — control: after the window, the beneficiary can claim the estate
        boolean claimOk = accepted(claim(ids[0])); commit(null);
        boolean moved = L.balanceOf(ids[0]) == 0 && L.balanceOf(ids[1]) == benefBefore + estate;
        ok("E3 control: after sustained inactivity the estate transfers to the beneficiary", claimOk && moved);
        // E4 — double-claim a now-drained account
        ok("E4 a second claim of the drained account is rejected (balance 0)", !accepted(claim(ids[0])));

        // E5 — the inactivity clock is reset by an OUTGOING action
        Ledger M = genesis(5);
        commit(M, M.buildSetBeneficiaryTx(ids[0], ids[1], M.projectedNonce(ids[0]), keys[0]));
        advance(M, (int) M.estateInactivity - 2);                       // almost expired
        commit(M, M.buildTxProjected(ids[0], ids[2], 10, 1, keys[0]));  // owner acts -> clock resets
        advance(M, 3);                                                  // a few more blocks, but < a fresh full window
        ok("E5 an outgoing action resets the inactivity clock (claim blocked)", !accepted(M, claim(M, ids[0])));

        // E6 — INCOMING transfers do NOT reset the clock (only outgoing do)
        Ledger K = genesis(5);
        commit(K, K.buildSetBeneficiaryTx(ids[3], ids[4], K.projectedNonce(ids[3]), keys[3]));
        advance(K, (int) K.estateInactivity - 2);
        commit(K, K.buildTxProjected(ids[0], ids[3], 500, 1, keys[0]));  // ids[3] RECEIVES (incoming) -> must NOT reset its clock
        advance(K, 3);
        ok("E6 an incoming transfer does NOT reset the recipient's clock (still claimable)", accepted(K, claim(K, ids[3])));

        System.out.println("\n==== EstateAttackTest: " + pass + " passed, " + fail + " failed ====");
        System.exit(fail == 0 ? 0 : 1);
    }

    // ---- harness ----
    static Ledger genesis(int n) throws Exception {
        ConsensusFixture f = ConsensusFixture.genesis(n, "pc-estate");
        N = n; keys = f.keys; ids = f.ids; ctr = new long[n]; pub.clear(); pub.putAll(f.pub);
        f.L.blockReward = 0;   // no emission -> exact balance assertions (estate transfer)
        return f.L;
    }
    static JSONObject claim(String acct) throws Exception { return claim(L, acct); }
    static JSONObject claim(Ledger g, String acct) throws Exception { return g.buildClaimTx(acct, (long) (Math.random() * 1e9)); }
    static boolean accepted(JSONObject tx) throws Exception { return accepted(L, tx); }
    static boolean accepted(Ledger g, JSONObject tx) throws Exception { return "accepted".equals(g.addToMempool(tx, pub)); }
    static void commit(JSONObject extra) throws Exception { commit(L, extra); }
    static void advance(int n) throws Exception { advance(L, n); }
    static void advance(Ledger g, int n) throws Exception { for (int i = 0; i < n; i++) commit(g, null); }
    static void commit(Ledger g, JSONObject extra) throws Exception {
        if (extra != null) { String r = g.addToMempool(extra, pub); if (!"accepted".equals(r)) throw new IllegalStateException("setup tx: " + r); }
        int h = g.chain.size(); int p = g.proposerFor(g.lastHash(), h, 0);
        JSONObject b = g.buildProposal(p, 1700000000000L + h);
        b.put("view", 0).put("reveal", PhantomCrypto.hex(Ledger.beaconSecretFor(keys[p].getEncoded(), ctr[p])))
         .put("commit", PhantomCrypto.hex(PhantomCrypto.sha3_256(Ledger.beaconSecretFor(keys[p].getEncoded(), ctr[p] + 1))));
        JSONArray qc = new JSONArray();
        for (int s = 0; s < g.committeeQuorum(h); s++) qc.put(new JSONObject().put("i", s).put("sig", PhantomCrypto.hex(PhantomCrypto.sign(keys[s], PhantomCrypto.utf8(b.getString("hash"))))));
        b.put("qc", qc);
        String r = g.commitBlock(b, pub);
        if (!"appended".equals(r)) throw new IllegalStateException("commit: " + r);
        ctr[p]++; g.mempool.clear();
    }
}
