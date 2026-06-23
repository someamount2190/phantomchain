package com.phantomchain.debug;

import static com.phantomchain.debug.TestKit.*;

import com.phantomchain.debug.*;

import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

/**
 * ADVANCED adversarial testing against the REAL engine (Ledger.commitBlock / txCheck + a faithful
 * NetNode.verifyQC replica). Each case mounts a concrete attack and asserts the defense holds (the attack
 * is REJECTED). A failing line means a real hole. Categories:
 *   A  consensus safety + quorum-certificate forgery
 *   B  block integrity (hash / state-root / beacon-reveal / height / prevHash)
 *   C  economic + transaction integrity (overspend, overflow, nonce, replay, forgery, double-spend)
 *   D  emission / supply integrity (no mint past the cap)
 *   E  governance bounds (param clamps + slashing floor cannot be disabled)
 *   F  identity (revoked-key spend, non-root rotation, recovery threshold)
 * Cluster M-of-N forgery is covered by ClusterTest (25/25); equivocation->SLASH by AdversaryTest.
 */
public class AdvAdversaryTest {

    static int N;
    static MLDSAPrivateKeyParameters[] keys;
    static String[] ids;
    static long[] ctr;
    static Map<String, MLDSAPublicKeyParameters> pub = new HashMap<>();

    static Ledger genesis(int n) throws Exception {
        return genesis(n, new LinkedHashMap<>());
    }
    static Ledger genesis(int n, LinkedHashMap<String, Long> extra) throws Exception {
        ConsensusFixture f = ConsensusFixture.genesis(n, "pc-adv", 1_000_000L, extra);
        N = n; keys = f.keys; ids = f.ids; ctr = new long[n]; pub.clear(); pub.putAll(f.pub);
        return f.L;
    }

    /** Build a valid proposal at the current height, with beacon reveal/commit and a QC from `signers`. */
    static JSONObject block(Ledger L, int proposer, int[] signers, long ts) throws Exception {
        JSONObject b = L.buildProposal(proposer, ts);
        b.put("view", 0);
        b.put("reveal", PhantomCrypto.hex(Ledger.beaconSecretFor(keys[proposer].getEncoded(), ctr[proposer])));
        b.put("commit", PhantomCrypto.hex(PhantomCrypto.sha3_256(Ledger.beaconSecretFor(keys[proposer].getEncoded(), ctr[proposer] + 1))));
        String hash = b.getString("hash");
        JSONArray qc = new JSONArray();
        for (int s : signers) qc.put(new JSONObject().put("i", s).put("sig", PhantomCrypto.hex(PhantomCrypto.sign(keys[s], PhantomCrypto.utf8(hash)))));
        b.put("qc", qc);
        return b;
    }

    /** Faithful NetNode.verifyQC: proposer legitimacy + committee membership + ML-DSA sigs + quorum. */
    static boolean verifyQC(Ledger L, JSONObject b) throws Exception { return ConsensusFixture.verifyQC(L, pub, b); }

    static int[] range(int a, int b) { int[] r = new int[b - a]; for (int i = a; i < b; i++) r[i - a] = i; return r; }
    static int proposerAt(Ledger L, int h) throws Exception { return L.proposerFor(L.lastHash(), h, 0); }

    public static void main(String[] a) throws Exception {
        System.out.println("==== ADVANCED ADVERSARIAL TESTING (real engine) ====\n");

        // =================== A. consensus safety + QC forgery ===================
        System.out.println("-- A. consensus safety + quorum-certificate forgery --");
        {
            Ledger L = genesis(7);                       // quorum = 7 - (6/3) = 5
            int q = L.committeeQuorum(1); int p = proposerAt(L, 1);
            ok("A0 control: legit block with full QC verifies", verifyQC(L, block(L, p, range(0, 7), 1)));
            ok("A1 QC one signer short of quorum is rejected", !verifyQC(L, block(L, p, range(0, q - 1), 2)));
            // A2 duplicate signer can't fake quorum (set collapses dupes)
            JSONObject dup = block(L, p, new int[]{0}, 3);
            JSONObject sig0 = dup.getJSONArray("qc").getJSONObject(0);
            JSONArray padded = new JSONArray(); for (int i = 0; i < q; i++) padded.put(new JSONObject(sig0.toString()));
            dup.put("qc", padded);
            ok("A2 duplicate-signer padding does NOT reach quorum", !verifyQC(L, dup));
            // A3 signatures over a DIFFERENT message
            JSONObject real = block(L, p, new int[]{}, 4);
            real.put("qc", sigsOver(PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8("bogus-hash"))), range(0, q)));
            ok("A3 signatures over a different block-hash are rejected", !verifyQC(L, real));
            // A4 off-schedule proposer
            JSONObject offsched = block(L, p, range(0, 7), 5);
            offsched.put("proposer", (p + 1) % 7);
            ok("A4 off-schedule proposer (wrong proposerFor) is rejected", !verifyQC(L, offsched));
            // A5 excluded (tombstoned) signer's vote doesn't count toward quorum
            Ledger L2 = genesis(7); int p2 = proposerAt(L2, 1);
            JSONObject blk = block(L2, p2, range(0, 5), 6);                 // exactly quorum (5) signers: 0..4
            L2.slashed.add(ids[2]);                                         // tombstone one of the 5 signers
            ok("A5 a tombstoned validator's signature is not counted (drops below quorum)", !verifyQC(L2, blk));
            // A6 proposer itself tombstoned
            Ledger L3 = genesis(7); int p3 = proposerAt(L3, 1);
            JSONObject blk3 = block(L3, p3, range(0, 7), 7);
            L3.slashed.add(ids[p3]);
            ok("A6 a block from a tombstoned proposer is rejected", !verifyQC(L3, blk3));
        }
        // A7 conflicting-commit safety: two distinct blocks at one height cannot BOTH reach quorum without equivocation
        {
            Ledger L = genesis(7); int q = L.committeeQuorum(1); int p = proposerAt(L, 1);
            JSONObject A = block(L, p, range(0, 7), 100);                   // honest block, signers 0..6
            JSONObject B = block(L, p, range(5, 7), 200);                   // conflicting block, only the f=2 Byzantine (5,6) sign it
            boolean aOk = verifyQC(L, A), bRejected = !verifyQC(L, B);
            ok("A7a honest block reaches quorum", aOk);
            ok("A7b conflicting block from <=f Byzantine canNOT reach quorum (safety)", bRejected);
            // and IF an honest validator double-signs both, that's slashable equivocation evidence
            String hA = A.getString("hash"), hB = block(L, p, new int[]{}, 200).getString("hash");
            JSONObject ev = new JSONObject().put("from", "SLASH").put("valId", ids[0])
                .put("ha", hA).put("sa", PhantomCrypto.hex(PhantomCrypto.sign(keys[0], PhantomCrypto.utf8(hA))))
                .put("hb", hB).put("sb", PhantomCrypto.hex(PhantomCrypto.sign(keys[0], PhantomCrypto.utf8(hB))));
            ok("A7c equivocation (signing both) is detectable slashable evidence", Ledger.verifySlash(ev, pub));
        }

        // =================== B. block integrity ===================
        System.out.println("\n-- B. block integrity (commitBlock guards) --");
        {
            Ledger L = genesis(5);
            // seed a transfer so the block has a body to tamper
            L.addToMempool(L.buildTxProjected(ids[0], ids[1], 100, 1, keys[0]), pub);
            int p = proposerAt(L, 1);
            ok("B1 tampered tx body with stale hash is rejected", reject(L, mutate(block(L, p, range(0,5), 1), b -> b.getJSONArray("txs").getJSONObject(0).put("amount", 999999))));
            ok("B2 forged prevStateRoot (app-hash divergence) is rejected", reject(L, mutate(block(L, p, range(0,5), 2), b -> b.put("prevStateRoot", "deadbeef"))));
            ok("B3 wrong prevHash (not building on head) is rejected", reject(L, mutate(block(L, p, range(0,5), 3), b -> b.put("prevHash", "00ff"))));
            ok("B4 bad beacon reveal (doesn't match commitment) is rejected", reject(L, mutate(block(L, p, range(0,5), 4), b -> b.put("reveal", PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8("forged")))))));
            ok("B5 wrong height is rejected", reject(L, mutate(block(L, p, range(0,5), 5), b -> b.put("height", 9))));
            ok("B0 control: the untouched valid block commits", "appended".equals(L.commitBlock(block(L, p, range(0,5), 6), pub)));
        }

        // =================== C. economic + transaction integrity ===================
        System.out.println("\n-- C. economic + transaction integrity (txCheck) --");
        {
            Ledger L = genesis(5);
            ok("C1 overspend (amount > balance) is rejected", !accepted(L, L.buildTxProjected(ids[0], ids[1], 2_000_000, 1, keys[0])));
            ok("C2 zero-amount transfer is rejected", !accepted(L, L.buildTxProjected(ids[0], ids[1], 0, 1, keys[0])));
            ok("C3 negative fee is rejected", !accepted(L, craftTransfer(L, 0, 1, 10, -1, 0, keys[0])));
            ok("C4 amount overflow (Long.MAX + fee) is rejected by addExact", !accepted(L, craftTransfer(L, 0, 1, Long.MAX_VALUE, 1, 0, keys[0])));
            ok("C6 nonce gap (future nonce) is rejected", !accepted(L, craftTransfer(L, 0, 1, 10, 1, 5, keys[0])));
            // C8 forged sender: attacker signs claiming someone else's id
            JSONObject forged = craftTransfer(L, 0, 1, 10, 1, 0, keys[2]);   // from=ids[0] but signed by keys[2]
            ok("C8 transfer for victim's id signed with attacker's key is rejected", !accepted(L, forged));
            // C7 cross-chain replay: a tx validly signed for a DIFFERENT chainId
            Ledger other = new Ledger(); other.chainId = "other-chain";
            JSONObject xchain = other.buildTxProjected(ids[0], ids[1], 10, 1, keys[0]);  // signed for "other-chain"
            ok("C7 cross-chain replay (foreign chainId) is rejected", !accepted(L, xchain));
            // C5 nonce replay: commit a valid tx then resubmit the same nonce
            JSONObject t0 = L.buildTxProjected(ids[0], ids[1], 10, 1, keys[0]);
            L.addToMempool(t0, pub); int p = proposerAt(L, 1); L.commitBlock(block(L, p, range(0,5), 1), pub); L.mempool.clear();
            ok("C5 nonce replay (reuse a committed nonce) is rejected", !accepted(L, craftTransfer(L, 0, 1, 10, 1, 0, keys[0])));
            // C9 intra-block double-spend via mempool projection
            Ledger L9 = genesis(5);
            boolean first = accepted(L9, L9.buildTxProjected(ids[0], ids[1], 600_000, 1, keys[0]));
            boolean second = accepted(L9, L9.buildTxProjected(ids[0], ids[2], 600_000, 1, keys[0]));  // 1.2M > 1M balance
            ok("C9 intra-block double-spend (2nd tx) is rejected by projection", first && !second);
        }

        // =================== D. emission / supply integrity ===================
        System.out.println("\n-- D. emission / supply integrity --");
        {
            Ledger L = genesis(5);
            L.maxSupply = 10;                                  // tiny cap; blockReward default 100, EPOCH_LEN 3
            boolean everExceeded = false;
            for (int h = 1; h <= 9; h++) {
                L.addToMempool(L.buildTxProjected(ids[h % 5], ids[(h + 1) % 5], 10, 1, keys[h % 5]), pub);
                int p = proposerAt(L, h);
                L.commitBlock(block(L, p, range(0, 5), 1000 + h), pub); ctr[p]++; L.mempool.clear();
                if (L.totalMinted > L.maxSupply) everExceeded = true;
            }
            ok("D1 emission never exceeds maxSupply cap (minted " + L.totalMinted + " <= 10)", !everExceeded && L.totalMinted <= 10);
        }

        // =================== E. governance bounds ===================
        System.out.println("\n-- E. governance parameter bounds --");
        {
            Ledger L = genesis(5);
            for (int h = 1; h <= 3; h++) { int p = proposerAt(L, h); L.commitBlock(block(L, p, range(0, 5), 2000 + h), pub); ctr[p]++; }  // mint some supply
            L.applyParam("feeBurnBps", 99_999);
            ok("E1 feeBurnBps clamped to <=10000 (got " + L.feeBurnBps + ")", L.feeBurnBps == 10000);
            L.applyParam("slashBps", 0);
            ok("E2 slashing floor: slashBps cannot be set to 0 (got " + L.slashBps + ")", L.slashBps >= 100);
            long minted = L.totalMinted; L.applyParam("maxSupply", 1);
            ok("E3 maxSupply cannot be set below already-minted (" + minted + ")", minted > 0 && L.maxSupply >= minted);
        }

        // =================== F. identity ===================
        System.out.println("\n-- F. identity (key rotation / recovery) --");
        {
            MLDSAPrivateKeyParameters root = PhantomCrypto.randomDeviceKey();
            MLDSAPrivateKeyParameters dev = PhantomCrypto.randomDeviceKey();
            MLDSAPrivateKeyParameters dev2 = PhantomCrypto.randomDeviceKey();
            String rootPub = PhantomCrypto.hex(root.getPublicKeyParameters().getEncoded());
            String id = Ledger.idOf(rootPub);
            String devPub = PhantomCrypto.hex(dev.getPublicKeyParameters().getEncoded());
            String dev2Pub = PhantomCrypto.hex(dev2.getPublicKeyParameters().getEncoded());
            LinkedHashMap<String, Long> extra = new LinkedHashMap<>(); extra.put(id, 1_000_000L);
            Ledger L = genesis(5, extra);
            // register identity (root binds the first device), then commit it
            commit(L, L.buildRegisterTx(root, dev));
            ok("F0 control: spend with the bound device key works", accepted(L, idTransfer(L, id, devPub, dev, ids[0], 10, 0)));
            // rotate to a new device (root-authorized), commit
            commit(L, L.buildRotateTx(id, root, dev2Pub, 0));
            ok("F1 spend with the REVOKED (rotated-out) device key is rejected", !accepted(L, idTransfer(L, id, devPub, dev, ids[0], 10, L.projectedNonce(id))));
            ok("F1b control: spend with the NEW device key works", accepted(L, idTransfer(L, id, dev2Pub, dev2, ids[0], 10, L.projectedNonce(id))));
            // F2 non-root rotation: ROTATE canonical signed by a DEVICE key, not root
            String newDev = PhantomCrypto.hex(PhantomCrypto.randomDeviceKey().getPublicKeyParameters().getEncoded());
            long rn = L.identities.get(id).getLong("rotNonce");
            JSONObject badRot = new JSONObject().put("from", "ROTATE").put("id", id).put("newDevice", newDev).put("rotNonce", rn).put("cid", "pc-adv")
                .put("sig", PhantomCrypto.hex(PhantomCrypto.sign(dev2, PhantomCrypto.utf8("rotate|pc-adv|" + id + "|" + newDev + "|" + rn))));
            ok("F2 rotation signed by a device key (not root) is rejected", !accepted(L, badRot));
            // F3 recovery below threshold (no valid guardian approvals)
            JSONObject badRec = L.buildRecoverTx(id, newDev, rn, new JSONArray());
            ok("F3 guardian recovery with no/insufficient approvals is rejected", !accepted(L, badRec));
        }

        System.out.println("\n==== AdvAdversaryTest: " + pass + " passed, " + fail + " failed ====");
        System.exit(fail == 0 ? 0 : 1);
    }

    // ---- helpers ----
    interface Mut { void run(JSONObject b); }
    // deep-copy first: buildProposal shares tx refs with the mempool, so mutating in place would corrupt
    // the mempool (in production a proposal is serialized over the wire, i.e. copied, before anyone sees it).
    static JSONObject mutate(JSONObject b, Mut m) { JSONObject c = new JSONObject(b.toString()); m.run(c); return c; }
    static JSONArray sigsOver(String hash, int[] signers) throws Exception {
        JSONArray qc = new JSONArray();
        for (int s : signers) qc.put(new JSONObject().put("i", s).put("sig", PhantomCrypto.hex(PhantomCrypto.sign(keys[s], PhantomCrypto.utf8(hash)))));
        return qc;
    }
    static boolean accepted(Ledger L, JSONObject tx) throws Exception { return "accepted".equals(L.addToMempool(tx, pub)); }
    static boolean reject(Ledger L, JSONObject blk) throws Exception { return !"appended".equals(L.commitBlock(blk, pub)); }

    /** A transfer with arbitrary amount/fee/nonce, signed by `key` but claiming from=ids[from]. */
    static JSONObject craftTransfer(Ledger L, int from, int to, long amount, long fee, long nonce, MLDSAPrivateKeyParameters key) throws Exception {
        String f = ids[from], t = ids[to];
        byte[] sig = PhantomCrypto.sign(key, PhantomCrypto.utf8(Ledger.txCanon("pc-adv", f, t, amount, fee, nonce)));
        return new JSONObject().put("from", f).put("to", t).put("amount", amount).put("cid", "pc-adv")
            .put("fee", fee).put("nonce", nonce).put("pub", PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded())).put("sig", PhantomCrypto.hex(sig));
    }
    /** A transfer FROM a registered identity, carrying a device pub and signed by its key. */
    static JSONObject idTransfer(Ledger L, String id, String devPub, MLDSAPrivateKeyParameters devKey, String to, long amount, long nonce) throws Exception {
        byte[] sig = PhantomCrypto.sign(devKey, PhantomCrypto.utf8(Ledger.txCanon("pc-adv", id, to, amount, 1, nonce)));
        return new JSONObject().put("from", id).put("to", to).put("amount", amount).put("cid", "pc-adv")
            .put("fee", 1).put("nonce", nonce).put("pub", devPub).put("sig", PhantomCrypto.hex(sig));
    }
    /** Add one tx, commit a block from the scheduled proposer, clear mempool. */
    static void commit(Ledger L, JSONObject tx) throws Exception {
        String r = L.addToMempool(tx, pub);
        if (!"accepted".equals(r)) throw new IllegalStateException("setup tx rejected: " + r);
        int p = proposerAt(L, L.height());
        String cr = L.commitBlock(block(L, p, range(0, N), System.currentTimeMillis()), pub);
        if (!"appended".equals(cr)) throw new IllegalStateException("setup commit failed: " + cr);
        ctr[p]++; L.mempool.clear();
    }
}
