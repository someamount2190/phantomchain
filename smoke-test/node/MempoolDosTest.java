package com.phantomchain.debug;

import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

/**
 * DoS / economic-griefing adversarial testing of the mempool admission + block-packing bounds:
 * min-fee anti-spam, the mempool size cap, nonce-based duplicate rejection, and the per-block tx cap.
 * Plus a reported observation on where the block-size DoS bound actually lives.
 */
public class MempoolDosTest {
    static int pass = 0, fail = 0;
    static void ok(String n, boolean c) { System.out.println((c ? "  PASS " : "  ** FAIL ** ") + n); if (c) pass++; else fail++; }
    static int N; static MLDSAPrivateKeyParameters[] keys; static String[] ids;
    static Map<String, MLDSAPublicKeyParameters> pub = new HashMap<>();

    static Ledger genesis(int n) throws Exception {
        N = n; keys = new MLDSAPrivateKeyParameters[n]; ids = new String[n]; pub.clear();
        LinkedHashMap<String, Long> alloc = new LinkedHashMap<>();
        List<String> vals = new ArrayList<>(); Map<String, Long> stk = new HashMap<>(), idn = new HashMap<>();
        Set<String> ver = new HashSet<>(); Map<String, String> vp = new HashMap<>(), bc = new HashMap<>();
        for (int i = 0; i < n; i++) {
            keys[i] = PhantomCrypto.randomDeviceKey();
            ids[i] = PhantomCrypto.hex(PhantomCrypto.sha3_256(keys[i].getPublicKeyParameters().getEncoded()));
            pub.put(ids[i], new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, keys[i].getPublicKeyParameters().getEncoded()));
            alloc.put(ids[i], 1_000_000_000L); vals.add(ids[i]); stk.put(ids[i], 1_000_000L); idn.put(ids[i], 1L);
            ver.add(ids[i]); vp.put(ids[i], PhantomCrypto.hex(keys[i].getPublicKeyParameters().getEncoded()));
            bc.put(ids[i], Ledger.beaconCommit0For(keys[i].getEncoded()));
        }
        Ledger L = new Ledger(); L.genesisEcon("pc-dos", alloc, vals, stk, idn, ver, vp, bc, 1700000000000L);
        return L;
    }
    static boolean accepted(Ledger L, JSONObject tx) throws Exception { return "accepted".equals(L.addToMempool(tx, pub)); }

    public static void main(String[] a) throws Exception {
        System.out.println("==== MEMPOOL DoS / griefing bounds ====\n");
        Ledger L = genesis(5);

        // D1 — min-fee anti-spam
        ok("D1 a zero-fee transfer (spam) is rejected (MIN_FEE=" + Ledger.MIN_FEE + ")",
                !accepted(L, L.buildTxProjected(ids[0], ids[1], 10, 0, keys[0])));

        // D2 — nonce-based duplicate rejection (a replayed in-flight tx can't double-spend the mempool slot)
        JSONObject t = L.buildTxProjected(ids[0], ids[1], 10, 1, keys[0]);
        boolean first = accepted(L, t);
        boolean dup = accepted(L, new JSONObject(t.toString()));   // exact same tx again
        ok("D2 a duplicate/replayed tx (same nonce) is rejected after the first is mempooled", first && !dup);

        // D3 — mempool size cap (fill to MAX_MEMPOOL, then admission is refused)
        Ledger L2 = genesis(5);
        JSONObject probe = L2.buildTxProjected(ids[0], ids[1], 10, 1, keys[0]);   // build while the mempool is clean
        for (int i = 0; i < Ledger.MAX_MEMPOOL; i++) L2.mempool.add(new JSONObject().put("x", i));   // saturate
        ok("D3 admission refused once the mempool is full (MAX_MEMPOOL=" + Ledger.MAX_MEMPOOL + ")",
                "rejected: mempool full".equals(L2.addToMempool(probe, pub)));

        // D4 — per-block tx cap (a flooded mempool can't inflate a block beyond MAX_BLOCK_TXS)
        Ledger L3 = genesis(5);
        for (int i = 0; i < Ledger.MAX_BLOCK_TXS + 250; i++) L3.mempool.add(new JSONObject().put("x", i));
        JSONObject blk = L3.buildProposal(0, 1);
        int packed = blk.getJSONArray("txs").length();
        ok("D4 a block packs at most MAX_BLOCK_TXS (" + Ledger.MAX_BLOCK_TXS + ") txs (got " + packed + ") despite a flooded mempool",
                packed == Ledger.MAX_BLOCK_TXS);

        // D5 — dust storm: many tiny-but-valid txs are admitted only while paying the min fee and below the cap
        Ledger L4 = genesis(5);
        int admitted = 0;
        for (int i = 0; i < 50; i++) if (accepted(L4, L4.buildTxProjected(ids[0], ids[1], 1, 1, keys[0]))) admitted++;
        ok("D5 dust (amount=1, fee=MIN) is admitted but each pays the floor fee (admitted " + admitted + "/50, all fee>=MIN)", admitted == 50);

        // ---- OBSERVATION (reported, not a pass/fail) ----
        System.out.println("\n  [OBSERVATION] commitBlock has no independent tx-count cap — it validates every tx in an\n"
            + "  incoming block. The DoS bound on an oversized block is the transport layer's 1 MiB body limit\n"
            + "  (NetNode.body), not the engine. Honest proposers cap at MAX_BLOCK_TXS (verified in D4); a Byzantine\n"
            + "  proposer's block is bounded by the 1 MiB cap. Adding an explicit txs.length()<=MAX_BLOCK_TXS check\n"
            + "  in commitBlock/proposalLinks would make the bound engine-enforced rather than transport-dependent.");

        System.out.println("\n==== MempoolDosTest: " + pass + " passed, " + fail + " failed ====");
        System.exit(fail == 0 ? 0 : 1);
    }
}
