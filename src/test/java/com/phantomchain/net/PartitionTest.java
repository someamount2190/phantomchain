package com.phantomchain.net;

import static com.phantomchain.debug.TestKit.*;

import com.phantomchain.debug.*;

import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

/**
 * PARTITION / LONG-RANGE / SYNC adversarial testing against the REAL engine + a faithful replica of the
 * NetNode.syncFromPeers accept-gate (verifyQC each block, then commitBlock must return "appended").
 * PhantomChain has single-slot deterministic finality (no fork-choice), so committed history is immutable.
 * We attack that:
 *   P1 reorg immunity      -> a block targeting an already-committed height, or a fork off an earlier block,
 *                             is rejected (committed history can't be replaced).
 *   P2 forged-peer sync    -> a peer offering blocks with a forged / sub-quorum / missing QC is rejected.
 *   P3 long-range attack   -> a self-consistent alternate chain from genesis can't be adopted: a node past
 *                             that height rejects it (bad height/prevHash), and an attacker holding <=f keys
 *                             can't form a quorum on any alternate block anyway.
 *   P4 partition safety    -> a minority partition (< quorum) cannot commit, so on heal there is no
 *                             conflicting committed block to reconcile (safety over liveness).
 *   P5 equivocation @ heal -> the only way two partitions both commit at one height is a validator signing
 *                             both, which is detectable slashable evidence; and once one side commits, the
 *                             other's block is rejected as stale.
 */
public class PartitionTest {

    static int N;
    static MLDSAPrivateKeyParameters[] keys;
    static String[] ids;
    static long[] ctr;
    static Map<String, MLDSAPublicKeyParameters> pub = new HashMap<>();

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
        Ledger L = new Ledger(); L.genesisEcon("pc-part", alloc, vals, stk, idn, ver, vp, bc, 1700000000000L);
        L.committeeSize = 0; return L;
    }

    /** Forge a block with EXPLICIT height/prevHash (for reorg/long-range attacks), signed by `signers`. */
    static JSONObject forge(Ledger L, int height, String prevHash, int proposer, int view, int[] signers, long ts) throws Exception {
        JSONArray txs = new JSONArray();
        String preimage = L.chainId + "|" + height + "|" + prevHash + "|" + txs + "|" + ts;
        String hash = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(preimage)));
        JSONObject b = new JSONObject().put("height", height).put("prevHash", prevHash).put("txs", txs).put("ts", ts)
            .put("hash", hash).put("proposer", proposer).put("view", view)
            .put("prevStateRoot", L.stateRoot()).put("prevShardsRoot", L.shardsRoot())
            .put("reveal", PhantomCrypto.hex(Ledger.beaconSecretFor(keys[proposer].getEncoded(), ctr[proposer])))
            .put("commit", PhantomCrypto.hex(PhantomCrypto.sha3_256(Ledger.beaconSecretFor(keys[proposer].getEncoded(), ctr[proposer] + 1))));
        JSONArray qc = new JSONArray();
        for (int s : signers) qc.put(new JSONObject().put("i", s).put("sig", PhantomCrypto.hex(PhantomCrypto.sign(keys[s], PhantomCrypto.utf8(hash)))));
        return b.put("qc", qc);
    }
    /** A well-formed next block on the current head (the honest path). */
    static JSONObject next(Ledger L, int[] signers, long ts) throws Exception {
        int h = L.chain.size(); int p = L.proposerFor(L.lastHash(), h, 0);
        return forge(L, h, L.lastHash(), p, 0, signers, ts);
    }
    static boolean verifyQC(Ledger L, JSONObject b) throws Exception {
        JSONArray qc = b.optJSONArray("qc"); if (qc == null) return false;
        String hash = b.getString("hash"); int h = b.getInt("height");
        int legit = L.proposerFor(b.getString("prevHash"), h, b.optInt("view", 0));
        if (b.optInt("proposer", -1) != legit || L.excluded(L.validators.get(legit))) return false;
        Set<Integer> committee = new HashSet<>(L.committeeFor(h)), ok = new HashSet<>();
        for (int i = 0; i < qc.length(); i++) {
            JSONObject v = qc.getJSONObject(i); int idx = v.getInt("i");
            if (idx < 0 || idx >= N || L.excluded(L.validators.get(idx)) || !committee.contains(idx)) continue;
            MLDSAPublicKeyParameters p = pub.get(L.validators.get(idx));
            if (p != null && PhantomCrypto.verify(p, PhantomCrypto.utf8(hash), PhantomCrypto.unhex(v.getString("sig")))) ok.add(idx);
        }
        return ok.size() >= L.committeeQuorum(h);
    }
    /** Mirrors NetNode.syncFromPeers: accept a peer block only if verifyQC passes AND it cleanly appends. */
    static boolean syncAccepts(Ledger L, JSONObject b) throws Exception {
        if (b.has("error") || !verifyQC(L, b)) return false;
        boolean ok = "appended".equals(L.commitBlock(b, pub));
        if (ok) ctr[b.getInt("proposer")]++;
        return ok;
    }
    static int[] all(int n) { int[] r = new int[n]; for (int i = 0; i < n; i++) r[i] = i; return r; }

    public static void main(String[] a) throws Exception {
        System.out.println("==== PARTITION / LONG-RANGE / SYNC (real engine + sync accept-gate) ====\n");

        // build an honest chain to height 3 (chain.size()==4)
        Ledger L = genesis(7);
        for (int i = 0; i < 3; i++) { boolean c = syncAccepts(L, next(L, all(7), 100 + i)); if (!c) { System.out.println("setup commit failed"); return; } }
        int head = L.chain.size();                       // next height
        String headHash = L.chain.get(head - 1).getString("hash");
        String genHash  = L.chain.get(0).getString("hash");
        System.out.println("[honest chain built to height " + (head - 1) + "]\n");

        // P1 — reorg immunity (single-slot finality)
        ok("P1a a block targeting an already-committed height (1) is rejected (no reorg of committed history)",
                !syncAccepts(L, forge(L, 1, genHash, L.proposerFor(genHash, 1, 0), 0, all(7), 1)));
        ok("P1b a fork off an earlier block (head height, but prevHash = genesis) is rejected (no fork adoption)",
                !syncAccepts(L, forge(L, head, genHash, L.proposerFor(genHash, head, 0), 0, all(7), 2)));
        ok("P1c control: the correct next block on the head DOES append",
                syncAccepts(L, next(L, all(7), 3)));
        head = L.chain.size(); headHash = L.chain.get(head - 1).getString("hash");

        // P2 — forged-peer sync (the /sync verifyQC gate)
        ok("P2a a peer block with a SUB-QUORUM QC (f=2 sigs) is rejected",
                !syncAccepts(L, forge(L, head, headHash, L.proposerFor(headHash, head, 0), 0, new int[]{5, 6}, 4)));
        ok("P2b a peer block with NO qc is rejected",
                !syncAccepts(L, stripQc(forge(L, head, headHash, L.proposerFor(headHash, head, 0), 0, all(7), 5))));
        ok("P2c a peer block flagged {error} is rejected by the sync gate",
                !syncAccepts(L, new JSONObject().put("error", "no height")));

        // P3 — long-range attack (alternate chain from genesis)
        ok("P3a a fully-signed ALTERNATE genesis-rooted block can't replace committed history (bad height)",
                !syncAccepts(L, forge(L, 1, genHash, L.proposerFor(genHash, 1, 0), 0, all(7), 6)));
        ok("P3b an attacker holding only <=f keys can't form a quorum on any alternate head block",
                !syncAccepts(L, forge(L, head, headHash, L.proposerFor(headHash, head, 0), 0, new int[]{0, 1}, 7)));

        // P4 — partition safety: a minority partition (< quorum) cannot commit
        {
            Ledger M = genesis(7);                       // fresh chain; quorum = 5
            int h = M.chain.size();
            int[] p1 = {0, 1, 2, 3};                     // partition A: 4 validators
            int[] p2 = {4, 5, 6};                        // partition B: 3 validators
            int prop = M.proposerFor(M.lastHash(), h, 0);
            ok("P4a majority-but-still-sub-quorum partition (4 of 7) cannot commit",
                    !syncAccepts(M, forge(M, h, M.lastHash(), prop, 0, p1, 1)));
            ok("P4b minority partition (3 of 7) cannot commit -> no divergent commit during a split",
                    !syncAccepts(M, forge(M, h, M.lastHash(), prop, 0, p2, 2)));
            ok("P4c on heal the quorum (5) commits normally", syncAccepts(M, forge(M, h, M.lastHash(), prop, 0, all(5), 3)));
        }

        // P5 — equivocation across a partition heal
        {
            Ledger E = genesis(7);
            int h = E.chain.size(); String prev = E.lastHash();
            int prop = E.proposerFor(prev, h, 0);
            JSONObject A = forge(E, h, prev, prop, 0, all(5), 10);          // block A (partition 1's view)
            JSONObject B = forge(E, h, prev, prop, 1, new int[]{2,3,4,5,6}, 20);   // block B (partition 2's view, diff)
            // overlapping signers (2,3,4) signed BOTH A and B -> equivocation evidence is slashable
            String hA = A.getString("hash"), hB = B.getString("hash");
            JSONObject ev = new JSONObject().put("from", "SLASH").put("valId", ids[2])
                .put("ha", hA).put("sa", PhantomCrypto.hex(PhantomCrypto.sign(keys[2], PhantomCrypto.utf8(hA))))
                .put("hb", hB).put("sb", PhantomCrypto.hex(PhantomCrypto.sign(keys[2], PhantomCrypto.utf8(hB))));
            ok("P5a a validator that signed both partitions' blocks yields slashable equivocation evidence", Ledger.verifySlash(ev, pub));
            // once one side commits, the other's same-height block is stale -> rejected
            boolean aCommitted = syncAccepts(E, A);
            boolean bRejected = !syncAccepts(E, B);
            ok("P5b after one partition's block commits, the other's same-height block is rejected (stale)", aCommitted && bRejected);
        }

        System.out.println("\n==== PartitionTest: " + pass + " passed, " + fail + " failed ====");
        System.exit(fail == 0 ? 0 : 1);
    }

    static JSONObject stripQc(JSONObject b) { b.remove("qc"); return b; }
}
