package com.phantomchain.debug;

import static com.phantomchain.debug.TestKit.*;

import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

/**
 * METAMORPHIC & DIFFERENTIAL TESTING against the REAL engine — the bug class that compilation and
 * static analysis (SpotBugs / -Xlint) CANNOT catch: functional/logic mistakes. The technique is the
 * one the literature recommends for AI-generated code (see "A Survey of Bugs in AI-Generated Code",
 * arXiv:2512.05239): apply semantics-preserving transformations and assert the outcome is unchanged,
 * plus check fundamental invariants that any correct ledger must uphold.
 *
 *   MR1 DETERMINISM        identical block sequences -> identical state commitment (no hidden nondeterminism).
 *   MR2 ORDER-INDEPENDENCE the state root is canonical: shuffling account INSERTION order doesn't change it.
 *   MR3 CONSERVATION       sum(balances)+sum(stake)+sum(unbonding) == genesisSupply + minted - burned, at EVERY block.
 *   MR4 REORDER            two INDEPENDENT transfers commit to the same balances in either order.
 *   MR5 REPLAY-IDEMPOTENCE re-including an already-committed tx is rejected; committed state is unchanged.
 *   MR6 MERKLE-CONSISTENCY every account's proof verifies and its root equals the account Merkle root.
 *   MR7 OVERFLOW-SAFETY    a transfer that would overflow amount+fee is rejected; state unchanged.
 *   MR8 AVALANCHE          a one-unit balance perturbation changes the account Merkle root (no ignored state).
 */
public class MetamorphicTest {

    static int N;
    static MLDSAPrivateKeyParameters[] keys;
    static String[] ids;
    static long[] ctr;
    static Map<String, MLDSAPublicKeyParameters> pub = new HashMap<>();

    /** Build a genesis ledger over n freshly-keyed validators; `m1` selects the hardened state-root version. */
    static Ledger genesis(int n, boolean m1) throws Exception {
        N = n; keys = new MLDSAPrivateKeyParameters[n]; ids = new String[n]; ctr = new long[n];
        for (int i = 0; i < n; i++) {
            keys[i] = PhantomCrypto.randomDeviceKey();
            ids[i] = PhantomCrypto.hex(PhantomCrypto.sha3_256(keys[i].getPublicKeyParameters().getEncoded()));
        }
        return genesisFrom(keys, ids, m1, false);
    }

    /**
     * Build a genesis ledger from a FIXED key set, registering the static keys/ids/ctr/pub.
     * Validator LIST order is always 0..n-1 (it is consensus-relevant, committed in the state root);
     * `insertReversed` only flips the INSERTION order of the genesis maps (which the state root sorts),
     * so that MR2 can prove the commitment is insertion-order-free without disturbing validator order.
     */
    static Ledger genesisFrom(MLDSAPrivateKeyParameters[] k, String[] id, boolean m1, boolean insertReversed) throws Exception {
        int n = k.length; N = n; keys = k; ids = id; ctr = new long[n]; pub.clear();
        for (int i = 0; i < n; i++) pub.put(id[i], new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, k[i].getPublicKeyParameters().getEncoded()));
        int[] mapOrder = new int[n]; for (int i = 0; i < n; i++) mapOrder[i] = insertReversed ? n - 1 - i : i;
        LinkedHashMap<String, Long> alloc = new LinkedHashMap<>();
        Map<String, Long> stk = new LinkedHashMap<>(), idn = new LinkedHashMap<>();
        Set<String> ver = new LinkedHashSet<>(); Map<String, String> vp = new LinkedHashMap<>(), bc = new LinkedHashMap<>();
        for (int o : mapOrder) {
            alloc.put(id[o], 1_000_000L); stk.put(id[o], 1_000_000L); idn.put(id[o], 1L);
            ver.add(id[o]); vp.put(id[o], PhantomCrypto.hex(k[o].getPublicKeyParameters().getEncoded()));
            bc.put(id[o], Ledger.beaconCommit0For(k[o].getEncoded()));
        }
        List<String> vals = new ArrayList<>(); for (int i = 0; i < n; i++) vals.add(id[i]);   // validator order fixed
        Ledger L = new Ledger();
        L.genesisEcon("pc-mr", alloc, vals, stk, idn, ver, vp, bc, 1700000000000L);
        L.committeeSize = 0; L.srVersion = m1 ? "m1" : "full";
        return L;
    }
    static MLDSAPrivateKeyParameters[] freshKeys(int n) {
        MLDSAPrivateKeyParameters[] k = new MLDSAPrivateKeyParameters[n];
        for (int i = 0; i < n; i++) k[i] = PhantomCrypto.randomDeviceKey();
        return k;
    }
    static String[] idsOf(MLDSAPrivateKeyParameters[] k) {
        String[] id = new String[k.length];
        for (int i = 0; i < k.length; i++) id[i] = PhantomCrypto.hex(PhantomCrypto.sha3_256(k[i].getPublicKeyParameters().getEncoded()));
        return id;
    }

    /** Build a block for `height` by `proposer`, carrying `txs`, signed by `signers`. */
    static JSONObject mk(Ledger L, int proposer, JSONArray txs, int[] signers, long ts) throws Exception {
        int h = L.chain.size(); String prevHash = L.lastHash();
        String preimage = L.chainId + "|" + h + "|" + prevHash + "|" + txs.toString() + "|" + ts;
        String hash = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(preimage)));
        JSONObject b = new JSONObject().put("height", h).put("prevHash", prevHash).put("txs", txs).put("ts", ts)
            .put("hash", hash).put("proposer", proposer).put("view", 0)
            .put("prevStateRoot", L.stateRoot()).put("prevShardsRoot", L.shardsRoot())
            .put("reveal", PhantomCrypto.hex(Ledger.beaconSecretFor(keys[proposer].getEncoded(), ctr[proposer])))
            .put("commit", PhantomCrypto.hex(PhantomCrypto.sha3_256(Ledger.beaconSecretFor(keys[proposer].getEncoded(), ctr[proposer] + 1))));
        JSONArray qc = new JSONArray();
        for (int s : signers) qc.put(new JSONObject().put("i", s).put("sig", PhantomCrypto.hex(PhantomCrypto.sign(keys[s], PhantomCrypto.utf8(hash)))));
        return b.put("qc", qc);
    }
    static int[] all(int n) { int[] r = new int[n]; for (int i = 0; i < n; i++) r[i] = i; return r; }
    static boolean commit(Ledger L, JSONObject b) throws Exception {
        boolean ok = "appended".equals(L.commitBlock(b, pub));
        if (ok) ctr[b.getInt("proposer")]++;
        return ok;
    }
    /** Commit one block proposed by the height's legitimate proposer, signed by everyone. */
    static boolean step(Ledger L, JSONArray txs, long ts) throws Exception {
        int p = L.proposerFor(L.lastHash(), L.chain.size(), 0);
        return commit(L, mk(L, p, txs, all(N), ts));
    }

    /** total live tokens = balances + bonded stake + pending unbondings. */
    static long totalTokens(Ledger L) {
        long t = 0;
        for (Ledger.Account a : L.accounts.values()) t += a.balance;
        for (long s : L.stake.values()) t += s;
        for (JSONObject u : L.unbonding) t += u.getLong("amount");
        return t;
    }
    static String stateFingerprint(Ledger L) throws Exception {
        return L.stateRoot() + "|" + L.accountsMerkleRoot() + "|" + L.totalMinted + "|" + L.burned + "|" + L.chain.size();
    }

    public static void main(String[] a) throws Exception {
        System.out.println("==== METAMORPHIC & DIFFERENTIAL TESTS (real engine) ====\n");

        // ───── MR1 — DETERMINISM: the same block sequence yields the same state commitment. ─────
        System.out.println("-- MR1 determinism (no hidden nondeterminism) --");
        {
            MLDSAPrivateKeyParameters[] k = freshKeys(4); String[] id = idsOf(k);
            Ledger L1 = genesisFrom(k, id, true, false);
            List<JSONObject> blocks = new ArrayList<>();
            for (long t = 1; t <= 4; t++) {
                JSONArray txs = new JSONArray();
                txs.put(L1.buildTxProjected(id[0], id[1], 100, 1, k[0]));
                int p = L1.proposerFor(L1.lastHash(), L1.chain.size(), 0);
                JSONObject b = mk(L1, p, txs, all(4), 1700000000000L + t);
                if (!commit(L1, b)) { ok("MR1 setup commit", false); break; }
                blocks.add(new JSONObject(b.toString()));
            }
            String fp1 = stateFingerprint(L1);
            // replay the EXACT same blocks onto a fresh ledger from the SAME keys
            Ledger L2 = genesisFrom(k, id, true, false);
            boolean replayed = true;
            for (JSONObject b : blocks) replayed &= "appended".equals(L2.commitBlock(b, pub));
            ok("MR1 the same block sequence replays and reaches the IDENTICAL state fingerprint",
                    replayed && fp1.equals(stateFingerprint(L2)));
        }

        // ───── MR2 — INSERTION-ORDER INDEPENDENCE: the state root sorts its maps, so genesis map insertion
        //            order must not move it (validator LIST order is held fixed — it is legitimately committed). ─────
        System.out.println("\n-- MR2 insertion-order independence of the canonical state commitment --");
        {
            MLDSAPrivateKeyParameters[] k = freshKeys(5); String[] id = idsOf(k);
            Ledger fwd = genesisFrom(k, id, true, false); String rFwd = fwd.stateRoot() + "|" + fwd.accountsMerkleRoot();
            Ledger rev = genesisFrom(k, id, true, true);  String rRev = rev.stateRoot() + "|" + rev.accountsMerkleRoot();
            ok("MR2 reversing genesis map INSERTION order leaves the state root + account root identical (sorted/canonical)",
                    rFwd.equals(rRev));
        }

        // ───── MR3 — CONSERVATION: tokens are neither created nor destroyed except by minting/burning. ─────
        System.out.println("\n-- MR3 money conservation across blocks (incl. fees + epoch emission) --");
        {
            Ledger L = genesis(4, true);
            long S0 = totalTokens(L);              // genesis supply (minted=0, burned=0)
            boolean conserved = (totalTokens(L) == S0 + L.totalMinted - L.burned);
            // drive several blocks with fee-paying transfers; EPOCH_LEN=3 so emission fires within the run
            for (long t = 1; t <= 9 && conserved; t++) {
                JSONArray txs = new JSONArray();
                txs.put(L.buildTxProjected(ids[(int) (t % 4)], ids[(int) ((t + 1) % 4)], 500, 3, keys[(int) (t % 4)]));
                if (!step(L, txs, 1700000000000L + t)) { ok("MR3 block commit", false); break; }
                conserved = (totalTokens(L) == S0 + L.totalMinted - L.burned);
            }
            ok("MR3 sum(balances+stake+unbonding) == genesisSupply + minted - burned, at every block", conserved);
            ok("MR3b emission actually fired (minted > 0) and burn occurred (burned > 0) during the run",
                    L.totalMinted > 0 && L.burned > 0);
        }

        // ───── MR4 — REORDER of independent transfers commutes (SAME keys -> SAME proposer -> full state must match). ─────
        System.out.println("\n-- MR4 independent transfers commute (order-independence of disjoint txs) --");
        {
            MLDSAPrivateKeyParameters[] k = freshKeys(4); String[] id = idsOf(k);
            // build both txs once against a reference ledger so the (nonce, sig) bytes are identical in both runs
            Ledger ref = genesisFrom(k, id, true, false);
            JSONObject t01 = ref.buildTxProjected(id[0], id[1], 250, 2, k[0]);   // node0 -> node1
            JSONObject t23 = ref.buildTxProjected(id[2], id[3], 400, 2, k[2]);   // node2 -> node3 (disjoint accounts)
            Ledger X = genesisFrom(k, id, true, false);
            step(X, new JSONArray().put(new JSONObject(t01.toString())).put(new JSONObject(t23.toString())), 1700000000001L);
            Ledger Y = genesisFrom(k, id, true, false);
            step(Y, new JSONArray().put(new JSONObject(t23.toString())).put(new JSONObject(t01.toString())), 1700000000001L);
            ok("MR4 reordering two disjoint transfers yields the IDENTICAL full state (commutativity)",
                    stateFingerprint(X).equals(stateFingerprint(Y)));
        }

        // ───── MR5 — REPLAY of an included tx is rejected and changes nothing. ─────
        System.out.println("\n-- MR5 replay/nonce idempotence --");
        {
            Ledger L = genesis(4, true);
            JSONObject tx = L.buildTxProjected(ids[0], ids[1], 123, 1, keys[0]);
            JSONArray one = new JSONArray().put(tx);
            step(L, one, 1700000000001L);
            long recipBefore = L.balanceOf(ids[1]);
            String fp = stateFingerprint(L);
            // try to commit a NEW block that re-includes the very same (now stale-nonce) tx
            boolean rejected = !step(L, new JSONArray().put(new JSONObject(tx.toString())), 1700000000002L);
            ok("MR5 a block re-including an already-spent (nonce) tx is REJECTED", rejected);
            ok("MR5b committed state is unchanged by the rejected replay", L.balanceOf(ids[1]) == recipBefore && fp.equals(stateFingerprint(L)));
        }

        // ───── MR6 — MERKLE proof consistency for every account. ─────
        System.out.println("\n-- MR6 account Merkle proof consistency --");
        {
            Ledger L = genesis(5, true);
            JSONArray txs = new JSONArray();
            txs.put(L.buildTxProjected(ids[0], ids[1], 777, 1, keys[0]));
            step(L, txs, 1700000000001L);
            boolean allProofs = true; String root = L.accountsMerkleRoot();
            for (String id : L.sortedAccountIds()) {
                JSONObject p = L.accountProof(id);
                allProofs &= Ledger.verifyAccountProof(p) && root.equals(p.getString("root"));
            }
            ok("MR6 every account's Merkle proof verifies and pins the SAME account root", allProofs);
        }

        // ───── MR7 — OVERFLOW safety: amount+fee that overflows long is rejected, state unchanged. ─────
        System.out.println("\n-- MR7 integer-overflow safety --");
        {
            Ledger L = genesis(4, true);
            String fp = stateFingerprint(L);
            // hand-craft a transfer with amount==Long.MAX_VALUE and fee>=1 so amount+fee overflows
            long nonce = 1L;
            String canon = Ledger.txCanon(L.chainId, ids[0], ids[1], Long.MAX_VALUE, 1, nonce);
            JSONObject tx = new JSONObject().put("from", ids[0]).put("to", ids[1]).put("amount", Long.MAX_VALUE)
                    .put("fee", 1).put("nonce", nonce).put("pub", PhantomCrypto.hex(keys[0].getPublicKeyParameters().getEncoded()))
                    .put("sig", PhantomCrypto.hex(PhantomCrypto.sign(keys[0], PhantomCrypto.utf8(canon))));
            boolean rejected = !step(L, new JSONArray().put(tx), 1700000000001L);
            ok("MR7 a transfer whose amount+fee overflows a long is REJECTED (Math.addExact guard)", rejected);
            ok("MR7b state is unchanged after the rejected overflow tx", fp.equals(stateFingerprint(L)));
        }

        // ───── MR8 — AVALANCHE: a 1-unit balance change moves the account Merkle root. ─────
        System.out.println("\n-- MR8 state-commitment avalanche (no ignored balances) --");
        {
            Ledger L = genesis(4, true);
            String before = L.accountsMerkleRoot();
            L.accounts.get(ids[0]).balance += 1;     // perturb one account by one unit
            String after = L.accountsMerkleRoot();
            ok("MR8 a single 1-unit balance change alters the account Merkle root (balance is bound)", !before.equals(after));
        }

        System.out.println("\n==== MetamorphicTest: " + pass + " passed, " + fail + " failed ====");
        System.exit(fail == 0 ? 0 : 1);
    }
}
