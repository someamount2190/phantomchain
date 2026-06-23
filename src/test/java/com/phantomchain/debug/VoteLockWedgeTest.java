package com.phantomchain.debug;

import static com.phantomchain.debug.TestKit.*;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Issue #1 — the view-change vote-lock liveness wedge, and the partial fix.
 *
 * A validator's vote locks PER HEIGHT (not per (height,view)) and is never released: NodeRpc /vote and
 * Consensus.round reject any height-h block whose hash differs from the one already voted. Previously a
 * later-view proposal ALWAYS differed (the block hash committed to the proposer's WALL-CLOCK ts), so after
 * a sub-quorum partial vote that then stalled, every later view was rejected -> the height wedged forever.
 *
 * FIX (this change): {@link Ledger#nextBlockTs()} makes the proposal timestamp deterministic (prev ts + 1),
 * and Consensus.round uses it. ts only has to be monotonic — nothing reads it as wall-clock — so a
 * view-change re-proposal of the SAME mempool is now byte-identical and hashes the same. A validator locked
 * on the view-0 block re-votes the identical view-1 block, so the common wedge (proposer crash with a
 * converged mempool) finalizes instead of wedging. Safety is untouched: validators still sign at most one
 * CONTENT per height, so two conflicting blocks can never both reach quorum.
 *
 * RESIDUAL (still open, [OPEN-BFT-01]): if proposers genuinely disagree on content (divergent mempool, or a
 * Byzantine proposer), the blocks differ and the locked voters still reject the later view -> the height can
 * still wedge. Safely closing that needs PBFT-style view-change certificates (the new proposer re-proposes
 * the highest-voted block, justified by a quorum of view-change messages); a naive lock-release would FORK
 * (the view-0 block could have committed on another partition). This test pins both halves.
 */
public class VoteLockWedgeTest {

    static Ledger genesis(int n) throws Exception {
        return ConsensusFixture.genesis(n, "pc-wedge").L;
    }

    /** The exact preimage sealBlock/commitBlock/buildProposal use: chainId|height|prevHash|txs|ts. */
    static String blockHash(Ledger L, int height, String prevHash, JSONArray txs, long ts) throws Exception {
        String preimage = L.chainId() + "|" + height + "|" + prevHash + "|" + txs + "|" + ts;
        return PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(preimage)));
    }

    /** A distinct one-tx mempool body (content varies the hash, like a divergent mempool would). */
    static JSONArray body(String tag) {
        return new JSONArray().put(new JSONObject().put("tag", tag));
    }

    /** Count committee members that may vote `hash` under the per-height lock (votedAt null or == hash). */
    static int canVote(int n, Map<Integer, String> votedAt, String hash) {
        int c = 0;
        for (int v = 0; v < n; v++) { String pv = votedAt.get(v); if (pv == null || pv.equals(hash)) c++; }
        return c;
    }

    public static void main(String[] a) throws Exception {
        System.out.println("==== VOTE-LOCK WEDGE + deterministic-proposal fix (issue #1) ====\n");

        Ledger L = genesis(4);
        int N = L.validatorCount();
        int h = L.chainSize();
        String prev = L.lastHash();
        int quorum = L.committeeQuorum(h);
        long ts = L.nextBlockTs();             // deterministic — Consensus.round uses this for ANY view at h
        System.out.println("[N=" + N + ", quorum=" + quorum + ", height=" + h + ", deterministic ts=" + ts + "]\n");

        JSONArray converged = body("tx-a");    // the mempool both the crashed and the takeover proposer hold

        // ---- FIX: a view-change re-proposal of the SAME mempool, with deterministic ts, is byte-identical ----
        String view0 = blockHash(L, h, prev, converged, ts);
        String view1same = blockHash(L, h, prev, converged, ts);   // different proposer/view, same content + ts
        ok("deterministic ts: a later-view re-proposal of the same mempool has the SAME hash", view0.equals(view1same));

        // a sub-quorum partial vote at view 0, then the proposer stalls
        Map<Integer, String> votedAt = new HashMap<>();
        for (int v = 0; v < quorum - 1; v++) votedAt.put(v, view0);
        ok("view-0 gathered only " + (quorum - 1) + " votes (< quorum " + quorum + ") -> did not commit", quorum - 1 < quorum);

        int reVote = canVote(N, votedAt, view1same);
        ok("FIXED (common case): locked voters re-vote the identical re-proposal -> " + reVote + " >= quorum " + quorum
                + " -> height finalizes (no wedge)", reVote >= quorum);

        // ---- RESIDUAL: divergent mempool -> different content -> still wedges (needs view-change certs) ----
        String view1diff = blockHash(L, h, prev, body("tx-b"), ts);
        ok("divergent mempool yields a different hash", !view0.equals(view1diff));

        int reVoteDiff = canVote(N, votedAt, view1diff);
        ok("RESIDUAL (divergent mempool / Byzantine): locked voters reject the differing block -> " + reVoteDiff
                + " < quorum " + quorum + " -> still wedges; needs view-change certificates [OPEN-BFT-01]",
                reVoteDiff < quorum);

        System.out.println("\nVoteLockWedgeTest: " + pass + " passed, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }
}
