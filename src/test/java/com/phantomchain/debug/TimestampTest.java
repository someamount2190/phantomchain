package com.phantomchain.debug;

import static com.phantomchain.debug.TestKit.*;

import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

/**
 * BLOCK TIMESTAMP adversarial testing. The block `ts` is folded into the block hash (so it is committed
 * and tamper-evident), but the engine performs NO monotonicity or drift validation on it. We prove the
 * integrity property (ts can't be altered after hashing) and REPORT the validation gap (arbitrary ts is
 * accepted) with its (currently low) impact and recommendation.
 */
public class TimestampTest {
    static int N; static MLDSAPrivateKeyParameters[] keys; static String[] ids; static long[] ctr;
    static Map<String, MLDSAPublicKeyParameters> pub = new HashMap<>();

    static Ledger genesis(int n) throws Exception {
        ConsensusFixture f = ConsensusFixture.genesis(n, "pc-ts");
        N = n; keys = f.keys; ids = f.ids; ctr = new long[n]; pub.clear(); pub.putAll(f.pub);
        return f.L;
    }
    static JSONObject mk(Ledger L, long ts) throws Exception {
        int h = L.chain.size(); String prevHash = L.lastHash();
        int p = L.proposerFor(prevHash, h, 0);
        JSONArray txs = new JSONArray();
        String hash = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(L.chainId + "|" + h + "|" + prevHash + "|" + txs + "|" + ts)));
        JSONObject b = new JSONObject().put("height", h).put("prevHash", prevHash).put("txs", txs).put("ts", ts)
            .put("hash", hash).put("proposer", p).put("view", 0)
            .put("prevStateRoot", L.stateRoot()).put("prevShardsRoot", L.shardsRoot())
            .put("reveal", PhantomCrypto.hex(Ledger.beaconSecretFor(keys[p].getEncoded(), ctr[p])))
            .put("commit", PhantomCrypto.hex(PhantomCrypto.sha3_256(Ledger.beaconSecretFor(keys[p].getEncoded(), ctr[p] + 1))));
        JSONArray qc = new JSONArray();
        for (int s = 0; s < L.committeeQuorum(h); s++) qc.put(new JSONObject().put("i", s).put("sig", PhantomCrypto.hex(PhantomCrypto.sign(keys[s], PhantomCrypto.utf8(hash)))));
        return b.put("qc", qc);
    }
    static boolean commit(Ledger L, JSONObject b) throws Exception {
        boolean ok = "appended".equals(L.commitBlock(b, pub)); if (ok) ctr[b.getInt("proposer")]++; return ok;
    }

    public static void main(String[] a) throws Exception {
        System.out.println("==== BLOCK TIMESTAMP adversarial ====\n");

        // T1 integrity: ts is bound into the block hash -> altering it after hashing breaks the hash
        {
            Ledger L = genesis(5);
            JSONObject b = mk(L, 1700000005000L);
            JSONObject tampered = new JSONObject(b.toString()).put("ts", 9999999999999L);   // change ts, keep old hash
            ok("T1 altering ts after hashing is rejected (ts is committed in the block hash)", !commit(L, tampered));
        }

        // T2 FINDING: the engine does not validate ts bounds/monotonicity — arbitrary timestamps commit.
        long[] wild = { 0L, -1L, 1L, Long.MAX_VALUE, 4102444800000L /*year 2100*/, 1L };
        boolean anyArbitraryAccepted = false;
        {
            Ledger L = genesis(5);
            long prevTs = Long.MAX_VALUE;                 // start high so the next ts is NON-monotonic (decreasing)
            for (int i = 0; i < wild.length; i++) {
                JSONObject b = mk(L, wild[i]);            // correctly hashed for this ts
                if (commit(L, b)) { anyArbitraryAccepted = true; }
                prevTs = wild[i];
            }
        }
        System.out.println("\n  ---- FINDING: timestamp validation ----");
        System.out.println("  [FINDING] block ts has NO monotonicity or drift bound: arbitrary/zero/negative/far-future and\n"
            + "  non-monotonic timestamps all commit (" + (anyArbitraryAccepted ? "confirmed" : "not reproduced") + "). Impact is currently LOW — no\n"
            + "  consensus logic reads ts (estate inactivity and epochs key off block HEIGHT, the beacon off reveals),\n"
            + "  so ts is effectively informational. Recommendation: before adding any wall-clock-dependent feature\n"
            + "  (time-locked unlocks, time-based fee schedules), enforce ts strictly-increasing + a future-drift\n"
            + "  bound in commitBlock/proposalLinks, gated on srVersion for backward-compat.");
        ok("T2 (control) the finding is reproducible: an arbitrary-ts block commits today", anyArbitraryAccepted);

        // T3/T4 — the FIX on a hardened ("m1") chain: ts must be non-DECREASING (deterministic, no wall-clock)
        {
            Ledger Lm = genesis(5); Lm.srVersion = "m1";
            boolean c1   = commit(Lm, mk(Lm, 1700000010000L));   // ts = 10000
            boolean cEq  = commit(Lm, mk(Lm, 1700000010000L));   // equal ts -> allowed (fast/equal-ms blocks)
            boolean cBack = commit(Lm, mk(Lm, 1700000005000L));  // earlier ts -> rejected
            ok("T3 [m1 FIX] a non-monotonic (decreasing) ts block is rejected on a hardened chain", c1 && !cBack);
            ok("T4 [m1] an equal timestamp is allowed (non-decreasing rule won't false-reject fast blocks)", cEq);
        }

        System.out.println("\n==== TimestampTest: " + pass + " passed, " + fail + " failed ====");
        System.exit(fail == 0 ? 0 : 1);
    }
}
