package com.phantomchain.debug;

import static com.phantomchain.debug.TestKit.*;

import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

/**
 * LIVENESS & CENSORSHIP under view-change, against the REAL engine. Byzantine/dead proposers must not be
 * able to stall the chain or permanently censor a transaction, and view-change must not enable a
 * double-commit. Cases:
 *   L1 dead proposer  -> the view-1 proposer takes over and commits (chain advances).
 *   L2 view-change safety -> a view-1 block can't ALSO reach quorum at a height already decided in view 0
 *      (validators sign <=1 block/height), so view-change never double-commits.
 *   L3 censorship resistance -> a proposer can omit a pending tx from ITS block, but the tx survives in the
 *      mempool and the next (honest) proposer includes it (censorship of one block != losing the tx).
 *   L4 fault tolerance -> with exactly f Byzantine validators down, the remaining N-f == quorum still
 *      commits; with one more down it correctly CANNOT (halts rather than commits unsafely).
 */
public class LivenessTest {

    static int N;
    static MLDSAPrivateKeyParameters[] keys;
    static String[] ids;
    static long[] ctr;
    static Map<String, MLDSAPublicKeyParameters> pub = new HashMap<>();

    static Ledger genesis(int n) throws Exception {
        ConsensusFixture f = ConsensusFixture.genesis(n, "pc-live");
        N = n; keys = f.keys; ids = f.ids; ctr = new long[n]; pub.clear(); pub.putAll(f.pub);
        return f.L;
    }

    /** Build a block for (height, view) by `proposer`, including `txs`, signed by `signers`. */
    static JSONObject mk(Ledger L, int proposer, int view, JSONArray txs, int[] signers, long ts) throws Exception {
        int h = L.chain.size(); String prevHash = L.lastHash();
        String preimage = L.chainId + "|" + h + "|" + prevHash + "|" + txs.toString() + "|" + ts;
        String hash = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(preimage)));
        JSONObject b = new JSONObject().put("height", h).put("prevHash", prevHash).put("txs", txs).put("ts", ts)
            .put("hash", hash).put("proposer", proposer).put("view", view)
            .put("prevStateRoot", L.stateRoot()).put("prevShardsRoot", L.shardsRoot())
            .put("reveal", PhantomCrypto.hex(Ledger.beaconSecretFor(keys[proposer].getEncoded(), ctr[proposer])))
            .put("commit", PhantomCrypto.hex(PhantomCrypto.sha3_256(Ledger.beaconSecretFor(keys[proposer].getEncoded(), ctr[proposer] + 1))));
        JSONArray qc = new JSONArray();
        for (int s : signers) qc.put(new JSONObject().put("i", s).put("sig", PhantomCrypto.hex(PhantomCrypto.sign(keys[s], PhantomCrypto.utf8(hash)))));
        return b.put("qc", qc);
    }
    static boolean verifyQC(Ledger L, JSONObject b) throws Exception { return ConsensusFixture.verifyQC(L, pub, b); }
    static int[] all(int n) { int[] r = new int[n]; for (int i = 0; i < n; i++) r[i] = i; return r; }
    static int[] subset(int[] xs, int k) { return Arrays.copyOf(xs, k); }
    static boolean commit(Ledger L, JSONObject b) throws Exception {
        if (!verifyQC(L, b)) return false;
        boolean ok = "appended".equals(L.commitBlock(b, pub));
        if (ok) ctr[b.getInt("proposer")]++;
        return ok;
    }

    public static void main(String[] a) throws Exception {
        System.out.println("==== LIVENESS & CENSORSHIP under view-change (real engine) ====\n");

        // L1 — dead view-0 proposer: the view-1 proposer takes over and commits.
        {
            Ledger L = genesis(5);
            int h = L.chain.size();                          // the NEXT block's height
            int p0 = L.proposerFor(L.lastHash(), h, 0);      // the scheduled proposer "goes dark" (never proposes)
            int view = 1, p1 = p0;                            // advance the view until a DIFFERENT validator is the proposer
            while (view < 50 && (p1 = L.proposerFor(L.lastHash(), h, view)) == p0) view++;
            JSONObject vc = mk(L, p1, view, new JSONArray(), all(5), System.currentTimeMillis());
            boolean advanced = commit(L, vc) && L.chain.size() == h + 1 && p1 != p0;
            ok("L1 dead view-0 proposer -> a DIFFERENT proposer takes over at view " + view + " and commits (no stall) [p0=" + p0 + " p" + view + "=" + p1 + "]", advanced);
        }

        // L2 — view-change cannot double-commit at one height (validators sign <=1 block/height).
        {
            Ledger L = genesis(7);                            // quorum = 5
            int q = L.committeeQuorum(L.height());
            int p0 = L.proposerFor(L.lastHash(), L.chain.size(), 0);
            int p1 = L.proposerFor(L.lastHash(), L.chain.size(), 1);
            JSONObject A = mk(L, p0, 0, new JSONArray(), subset(all(7), q), 111);          // view-0 block: signers 0..q-1
            // view-1 block B can only be signed by validators that did NOT already sign A (the rest: q..N-1)
            int[] rest = Arrays.copyOfRange(all(7), q, 7);
            JSONObject B = mk(L, p1, 1, new JSONArray(), rest, 222);
            boolean aOk = verifyQC(L, A), bRejected = !verifyQC(L, B);
            ok("L2a view-0 block reaches quorum", aOk);
            ok("L2b conflicting view-1 block (only non-overlapping signers) CANNOT reach quorum -> no double-commit", bRejected);
        }

        // L3 — censorship resistance: a proposer omits a pending tx, but it survives and the next block includes it.
        {
            Ledger L = genesis(5);
            JSONObject tx = L.buildTxProjected(ids[0], ids[3], 777, 1, keys[0]);   // pending tx T (node0 -> node3)
            L.addToMempool(tx, pub);
            long before = L.balanceOf(ids[3]);
            // censoring proposer builds an EMPTY block (omits T) at the current height
            int pc = L.proposerFor(L.lastHash(), L.chain.size(), 0);
            boolean censoredCommitted = commit(L, mk(L, pc, 0, new JSONArray(), all(5), 1));
            boolean stillPending = (L.balanceOf(ids[3]) == before);                // T not applied by the censoring block
            // next height: an honest proposer includes T (it's still in the mempool)
            int pn = L.proposerFor(L.lastHash(), L.chain.size(), 0);
            JSONArray withT = new JSONArray(); for (JSONObject t : L.mempool) withT.put(t);
            boolean included = commit(L, mk(L, pn, 0, withT, all(5), 2));
            boolean applied = (L.balanceOf(ids[3]) >= before + 777);   // >= : if pn==recipient it also collects the +1 proposer fee
            ok("L3a a censoring proposer CAN omit a pending tx from its own block", censoredCommitted && stillPending);
            ok("L3b the censored tx survives and the NEXT proposer commits it (censorship-resistant)", included && applied);
        }

        // L4 — fault tolerance: exactly f down still commits; one more down halts (safety over liveness).
        {
            Ledger L = genesis(7);                            // f = 2, quorum = 5
            int q = L.committeeQuorum(L.height());            // 5
            // honest = {0..4}, byzantine/down = {5,6}; find a view whose proposer is honest
            int view = 0, prop; while (true) { prop = L.proposerFor(L.lastHash(), L.chain.size(), view); if (prop < q) break; view++; }
            JSONObject withQuorum = mk(L, prop, view, new JSONArray(), subset(all(7), q), 1);     // exactly N-f honest sign
            JSONObject oneShort   = mk(L, prop, view, new JSONArray(), subset(all(7), q - 1), 2); // one fewer
            ok("L4a with exactly f=2 validators down, the remaining N-f=quorum still commits", verifyQC(L, withQuorum));
            ok("L4b with one MORE down (quorum-1), it correctly CANNOT commit (halts, not unsafe)", !verifyQC(L, oneShort));
        }

        System.out.println("\n==== LivenessTest: " + pass + " passed, " + fail + " failed ====");
        System.exit(fail == 0 ? 0 : 1);
    }
}
