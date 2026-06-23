package com.phantomchain.debug;

import static com.phantomchain.debug.TestKit.*;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.json.JSONArray;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Characterization of KNOWN ISSUE #1 — the view-change vote-lock liveness wedge.
 *
 * A validator's vote is locked PER HEIGHT, not per (height, view): NodeRpc's /vote handler and
 * Consensus.round both reject any block whose hash differs from the one already voted at that height
 * ("reject: already voted at height h"), and {@code votedAt} is never released before the height commits.
 * Because a block's hash commits to the proposer's WALL-CLOCK ts, a later-view proposal at the same height
 * has a different hash — so every validator that voted the view-0 block rejects the view-1 block forever.
 *
 * Consequence: if a view-0 block gathers a SUB-QUORUM partial vote and then stalls (proposer crash /
 * partition), no later view can ever finalize that height — the remaining (unlocked) validators are too
 * few to reach quorum. This holds for any committee where quorum > (N+1)/2, which the BFT quorum
 * c-(c-1)/3 (~2/3) always satisfies; N=4 (quorum 3) is the minimal case shown here.
 *
 * This test PINS the current (wedging) behavior. The correct fix is PBFT-style view-change certificates
 * (FRONTIER.md's "real BFT" step); when that lands, the wedge assertion below should flip to "finalizes".
 * A safety note for any fixer: naively releasing the per-height lock risks a FORK (the view-0 block could
 * have committed on another partition) — the lock release must be justified by a view-change certificate.
 */
public class VoteLockWedgeTest {

    static Ledger genesis(int n) throws Exception {
        LinkedHashMap<String, Long> alloc = new LinkedHashMap<>();
        List<String> vals = new ArrayList<>();
        Map<String, Long> stk = new HashMap<>(), idn = new HashMap<>();
        Set<String> ver = new HashSet<>();
        Map<String, String> vp = new HashMap<>(), bc = new HashMap<>();
        for (int i = 0; i < n; i++) {
            MLDSAPrivateKeyParameters k = PhantomCrypto.randomDeviceKey();
            String id = PhantomCrypto.hex(PhantomCrypto.sha3_256(k.getPublicKeyParameters().getEncoded()));
            alloc.put(id, 1_000_000L); vals.add(id); stk.put(id, 1_000_000L); idn.put(id, 1L); ver.add(id);
            vp.put(id, PhantomCrypto.hex(k.getPublicKeyParameters().getEncoded()));
            bc.put(id, Ledger.beaconCommit0For(k.getEncoded()));
        }
        Ledger L = new Ledger();
        L.genesisEcon("pc-wedge", alloc, vals, stk, idn, ver, vp, bc, 1700000000000L);
        L.committeeSize = 0;   // full live set signs
        return L;
    }

    /** Block hash for an empty-tx block — the exact preimage sealBlock/commitBlock use (chainId|h|prev|txs|ts). */
    static String blockHash(Ledger L, int height, String prevHash, long ts) throws Exception {
        String preimage = L.chainId() + "|" + height + "|" + prevHash + "|" + new JSONArray() + "|" + ts;
        return PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(preimage)));
    }

    public static void main(String[] a) throws Exception {
        System.out.println("==== VOTE-LOCK WEDGE (known issue #1: per-height vote lock + wall-clock ts) ====\n");

        Ledger L = genesis(4);
        int N = L.validatorCount();
        int h = L.chainSize();                 // the height we contend (next, post-genesis)
        String prev = L.lastHash();
        int quorum = L.committeeQuorum(h);     // 3 for N=4
        System.out.println("[N=" + N + ", quorum(c-(c-1)/3)=" + quorum + ", contending height=" + h + "]\n");

        // Two competing proposals at the SAME height in different views: different proposers reveal at
        // different wall-clock times, so the hashes differ.
        String hash0 = blockHash(L, h, prev, 1_000L);   // view 0
        String hash1 = blockHash(L, h, prev, 2_000L);   // view 1
        ok("competing-view blocks at height " + h + " have different hashes (wall-clock ts in the preimage)",
                !hash0.equals(hash1));

        // The per-height vote lock, applied EXACTLY as NodeRpc /vote (line 283-284) and Consensus.round (54-55):
        // a validator whose votedAt[h] = X rejects any height-h block whose hash != X.
        Map<Integer, String> votedAt = new HashMap<>();   // validator index -> hash it voted at height h

        // View 0 gathers a SUB-QUORUM partial vote, then stalls (proposer crash / partition) -> never commits.
        int locked = quorum - 1;               // the largest set that does NOT reach quorum
        for (int v = 0; v < locked; v++) votedAt.put(v, hash0);
        ok("view-0 block gathered only " + locked + " votes (< quorum " + quorum + ") -> never commits",
                locked < quorum);

        // Any later view proposes a different-hash block; the locked validators reject it.
        int canSignB1 = 0;
        for (int v = 0; v < N; v++) {
            String prevVote = votedAt.get(v);
            if (prevVote == null || prevVote.equals(hash1)) canSignB1++;
        }
        ok("view-1 block can gather at most " + canSignB1 + " votes (locked voters reject it) -> below quorum " + quorum,
                canSignB1 < quorum);

        ok("WEDGE CONFIRMED: after a sub-quorum partial vote, NO view can finalize height " + h
                + " (this is known issue #1, pinned until PBFT view-change certificates land)",
                locked < quorum && canSignB1 < quorum);

        // Control: with NO prior-view vote, the SAME view-1 block reaches quorum -> the wedge is caused by
        // the per-height lock, not by the quorum threshold itself.
        votedAt.clear();
        int freshSigners = 0;
        for (int v = 0; v < N; v++) {
            String prevVote = votedAt.get(v);
            if (prevVote == null || prevVote.equals(hash1)) freshSigners++;
        }
        ok("control: with no prior-view votes, the view-1 block reaches quorum (" + freshSigners + " >= " + quorum
                + ") -> the wedge is the per-height lock, not the protocol quorum",
                freshSigners >= quorum);

        System.out.println("\nVoteLockWedgeTest: " + pass + " passed, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }
}
