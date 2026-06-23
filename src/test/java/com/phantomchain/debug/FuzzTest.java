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
 * INPUT-ROBUSTNESS FUZZING of the consensus message-handling layer — the surface a Byzantine peer can
 * feed over the wire (/gossip/tx -> addToMempool, /commit & /sync -> commitBlock, /vote -> proposalLinks
 * + txsValid, /gossip/slash -> verifySlash, snapshot load -> fromJson). For thousands of malformed /
 * random / bit-flipped inputs we assert the SAFETY INVARIANTS:
 *   (1) no garbage is ever ACCEPTED (addToMempool) or APPENDED (commitBlock);
 *   (2) committed state is never mutated (stateRoot + height + accounts unchanged across the whole run);
 *   (3) the read-only validators never return TRUE for garbage (verifyQC / proposalLinks / verifySlash);
 *   (4) nothing escapes as an unhandled crash — every entry point either returns a rejection or throws an
 *       exception that the production NetNode.serve()/sync wraps (we count both, to show where validation
 *       relies on the outer guard vs. rejects cleanly).
 */
public class FuzzTest {
    static int N;
    static MLDSAPrivateKeyParameters[] keys;
    static String[] ids;
    static Map<String, MLDSAPublicKeyParameters> pub = new HashMap<>();
    static Random R = new Random(1234567L);

    static Ledger genesis(int n) throws Exception {
        ConsensusFixture f = ConsensusFixture.genesis(n, "pc-fuzz");
        N = n; keys = f.keys; ids = f.ids; pub.clear(); pub.putAll(f.pub);
        return f.L;
    }

    // ---- random value/JSON generators ----
    static final String[] KNOWN = {"height","prevHash","hash","txs","qc","from","to","amount","fee","nonce",
            "cid","sig","proposer","reveal","commit","view","valId","ha","hb","sa","sb","i","actor","root",
            "device","newDevice","rotNonce","id","approvals","members","threshold","bundle"};
    static Object rndVal(int depth) {
        switch (R.nextInt(depth <= 0 ? 6 : 9)) {
            case 0: return R.nextInt();
            case 1: return R.nextLong();
            case 2: return R.nextBoolean();
            case 3: return rndStr();
            case 4: return JSONObject.NULL;
            case 5: return R.nextBoolean() ? Long.MAX_VALUE : Long.MIN_VALUE;
            case 6: return rndObj(depth - 1);
            case 7: { JSONArray a = new JSONArray(); int k = R.nextInt(5); for (int i = 0; i < k; i++) a.put(rndVal(depth - 1)); return a; }
            default: return rndStr();
        }
    }
    static String rndStr() {
        int kind = R.nextInt(5);
        if (kind == 0) return "";
        if (kind == 1) { int n = R.nextInt(64); char[] c = new char[n]; for (int i = 0; i < n; i++) c[i] = "0123456789abcdef".charAt(R.nextInt(16)); return new String(c); }  // hex-ish
        if (kind == 2) { int n = 1 + R.nextInt(2000); char[] c = new char[n]; Arrays.fill(c, 'A'); return new String(c); }   // long
        if (kind == 3) return new String(new char[]{(char) R.nextInt(0x10000)});                                            // odd unicode
        return Long.toString(R.nextLong());
    }
    static JSONObject rndObj(int depth) {
        JSONObject o = new JSONObject();
        int k = R.nextInt(8);
        for (int i = 0; i < k; i++) {
            String key = R.nextBoolean() ? KNOWN[R.nextInt(KNOWN.length)] : rndStr();
            o.put(key.isEmpty() ? "k" + i : key, rndVal(depth));
        }
        return o;
    }

    /** A valid block at the current height (for bit-flip / single-field mutation fuzzing). */
    static JSONObject validBlock(Ledger L) throws Exception {
        int p = L.proposerFor(L.lastHash(), L.height(), 0);
        JSONObject b = L.buildProposal(p, System.currentTimeMillis());
        b.put("view", 0).put("reveal", PhantomCrypto.hex(Ledger.beaconSecretFor(keys[p].getEncoded(), 0)))
         .put("commit", PhantomCrypto.hex(PhantomCrypto.sha3_256(Ledger.beaconSecretFor(keys[p].getEncoded(), 1))));
        JSONArray qc = new JSONArray();
        for (int s = 0; s < L.committeeQuorum(L.height()); s++)
            qc.put(new JSONObject().put("i", s).put("sig", PhantomCrypto.hex(PhantomCrypto.sign(keys[s], PhantomCrypto.utf8(b.getString("hash"))))));
        return b.put("qc", qc);
    }
    // Corrupt a CONSENSUS-CRITICAL field (always checked) so the result is GUARANTEED invalid — this makes
    // "never accepted/appended/true" a sound oracle. (Corrupting a non-critical field like `view` would
    // leave a still-valid input that legitimately commits, which is correct, not a bug.)
    // (note: "pub" is NOT here — a validator's pubkey is known via genesis/pubById, so a tx that omits it
    //  still verifies; that's correct by design, not a forgery. Corrupting any SIGNED field below invalidates.)
    // prevStateRoot/prevShardsRoot are deliberately NOT here: the engine reads them with optString(...,null)
    // and SKIPS the check when absent/JSON-null (the documented FINDING below), so corrupting them isn't
    // guaranteed-invalid. The fields kept here are always-checked, so any corruption is a sound rejection.
    static final String[] TXCRIT   = {"sig","amount","from","to","nonce","cid"};
    static final String[] BLKCRIT  = {"hash","height","prevHash","reveal","txs"};
    static final String[] LINKCRIT = {"height","prevHash","hash","reveal"};
    // Replace a chosen consensus-critical field with a value GUARANTEED to differ and invalidate (a random
    // value can collide — e.g. replacing an already-empty txs with another empty array is a no-op — which
    // would make a still-valid block, not a sound negative test). Each case below provably breaks validation.
    static JSONObject corruptCrit(JSONObject valid, String[] crit, Ledger L) {
        JSONObject c = new JSONObject(valid.toString());
        String k = crit[R.nextInt(crit.length)];
        switch (k) {
            case "hash": case "prevHash": case "prevStateRoot": case "prevShardsRoot": c.put(k, "00"); break;
            case "height":  c.put(k, L.height() + 1000); break;
            case "reveal":  c.put(k, PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8("not-the-secret")))); break;
            case "txs":     c.put(k, new JSONArray().put(new JSONObject().put("from", "NOBODY").put("to", "x")
                                .put("amount", 1).put("nonce", 0).put("cid", "x").put("sig", "00"))); break;
            case "sig":     c.put(k, "00"); break;
            case "amount":  c.put(k, c.optLong("amount", 1) + 1); break;     // signed value changes -> sig mismatch
            case "from":    c.put(k, "NOBODY-" + R.nextInt()); break;
            case "to":      c.put(k, c.optString("to", "") + "X"); break;    // signed value changes
            case "nonce":   c.put(k, c.optLong("nonce", 0) + 999); break;
            case "cid":     c.put(k, "wrong-chain"); break;
            default:        c.put(k, rndVal(2));
        }
        return c;
    }

    public static void main(String[] a) throws Exception {
        int ITERS = a.length > 0 ? Integer.parseInt(a[0]) : 8000;
        Ledger L = genesis(5);
        // commit two valid blocks so committed state is non-trivial
        for (int h = 1; h <= 2; h++) {
            L.addToMempool(L.buildTxProjected(ids[0], ids[1], 100, 1, keys[0]), pub);
            JSONObject b = validBlock(L); L.commitBlock(b, pub); L.mempool.clear();
            // note: validBlock uses ctr=0; after a commit the proposer's commitment advances, but each
            // height here is proposed by whoever proposerFor picks at ctr 0 of the genesis-seeded commit — to
            // keep setup simple we only need *some* committed state, and the first two commits succeed.
        }
        String baseRoot = L.stateRoot();
        int baseHeight = L.height();
        String baseAccts = L.accounts.toString();

        long accepted = 0, appended = 0, falseTrue = 0, threw = 0, cleanReject = 0, total = 0;

        for (int it = 0; it < ITERS; it++) {
            int route = R.nextInt(8);
            total++;
            try {
                switch (route) {
                    case 0: { // pure-garbage tx -> addToMempool
                        if ("accepted".equals(L.addToMempool(rndObj(3), pub))) accepted++; else cleanReject++;
                        break;
                    }
                    case 1: { // valid tx with a CONSENSUS-CRITICAL field corrupted -> addToMempool (guaranteed invalid)
                        JSONObject t = L.buildTxProjected(ids[R.nextInt(N)], ids[R.nextInt(N)], 1 + R.nextInt(1000), 1, keys[R.nextInt(N)]);
                        if ("accepted".equals(L.addToMempool(corruptCrit(t, TXCRIT, L), pub))) accepted++; else cleanReject++;
                        break;
                    }
                    case 2: { // pure-garbage block -> commitBlock
                        if ("appended".equals(L.commitBlock(rndObj(3), pub))) appended++; else cleanReject++;
                        break;
                    }
                    case 3: { // valid block with a critical field corrupted -> commitBlock (guaranteed invalid)
                        if ("appended".equals(L.commitBlock(corruptCrit(validBlock(L), BLKCRIT, L), pub))) appended++; else cleanReject++;
                        break;
                    }
                    case 4: { // garbage/critically-corrupt block -> proposalLinks (must never be true)
                        if (L.proposalLinks(R.nextBoolean() ? rndObj(3) : corruptCrit(validBlock(L), LINKCRIT, L))) falseTrue++; else cleanReject++;
                        break;
                    }
                    case 5: { // garbage slash evidence -> verifySlash (must never be true)
                        if (Ledger.verifySlash(rndObj(3), pub)) falseTrue++; else cleanReject++;
                        break;
                    }
                    case 6: { // garbage -> txsValid (block of random txs)
                        JSONObject blk = new JSONObject(); JSONArray txs = new JSONArray();
                        int k = R.nextInt(6); for (int i = 0; i < k; i++) txs.put(rndObj(2));
                        blk.put("txs", txs);
                        if (L.txsValid(blk, pub)) { /* all-random txs valid would be a forgery */ if (k > 0) falseTrue++; } else cleanReject++;
                        break;
                    }
                    default: { // garbage snapshot -> fromJson on a throwaway ledger (must not corrupt L)
                        Ledger tmp = new Ledger();
                        try { tmp.fromJson(rndObj(3).toString()); } catch (Exception e) { /* expected */ }
                        cleanReject++;
                        break;
                    }
                }
            } catch (Exception e) {
                threw++;   // handled in production by NetNode.serve()'s try/catch (-> HTTP 500, node stays up)
            }
        }

        // ---- FINDINGS: targeted hardening probes (reported, not safety failures) ----
        // app-hash bypass-by-OMISSION: commitBlock/proposalLinks read prevStateRoot/prevShardsRoot with
        // optString(...,null) and SKIP the agreement check when the field is ABSENT (present-but-wrong is
        // correctly rejected). A proposer can omit prevStateRoot to dodge the state-root cross-check.
        // Safety still holds (commitBlock re-executes every tx deterministically, so honest nodes can't be
        // forced to a divergent state, and a QC is still required), but the app-hash tripwire is defeatable.
        // legacy "full" chain: app-hash omission is still tolerated (can't retroactively require it without
        // breaking historical-block sync). hardened "m1" chain: omission is now REJECTED (the fix).
        Ledger Lfull = genesis(5);
        JSONObject ofull = new JSONObject(validBlock(Lfull).toString()); ofull.remove("prevStateRoot"); ofull.remove("prevShardsRoot");
        boolean fullOmitAccepted = false;
        try { fullOmitAccepted = "appended".equals(Lfull.commitBlock(new JSONObject(ofull.toString()), pub)); } catch (Exception e) {}
        Ledger Lm1 = genesis(5); Lm1.srVersion = "m1";
        JSONObject om1 = new JSONObject(validBlock(Lm1).toString()); om1.remove("prevStateRoot"); om1.remove("prevShardsRoot");
        boolean m1OmitLinks = true, m1OmitCommit = true;
        try { m1OmitLinks = Lm1.proposalLinks(om1); } catch (Exception e) { m1OmitLinks = false; }
        try { m1OmitCommit = "appended".equals(Lm1.commitBlock(new JSONObject(om1.toString()), pub)); } catch (Exception e) { m1OmitCommit = false; }
        System.out.println("\n  ---- FINDING + FIX: app-hash bypass-by-omission ----");
        System.out.println("  [legacy 'full'] block omitting prevStateRoot/prevShardsRoot -> " + (fullOmitAccepted ? "accepted (tolerated for historical-block sync)" : "rejected"));
        System.out.println((!m1OmitLinks && !m1OmitCommit ? "  PASS " : "  ** FAIL ** ")
                + "[hardened 'm1'] block omitting the app-hash is REJECTED (proposalLinks=" + m1OmitLinks + ", commitBlock=" + m1OmitCommit + ")");
        boolean fixOk = !m1OmitLinks && !m1OmitCommit;

        // ---- invariants ----
        boolean noAccept = (accepted == 0);
        boolean noAppend = (appended == 0);
        boolean noFalseTrue = (falseTrue == 0);
        boolean stateIntact = baseRoot.equals(L.stateRoot()) && baseHeight == L.height() && baseAccts.equals(L.accounts.toString());

        System.out.println("==== FUZZ: " + total + " malformed inputs across 8 entry points ====");
        System.out.printf(java.util.Locale.US, "  outcomes: cleanly rejected %d, threw (caught by outer guard) %d, accepted %d, false-true %d%n",
                cleanReject, threw, accepted, falseTrue);
        System.out.println((noAccept ? "  PASS " : "  ** FAIL ** ") + "no malformed tx was ACCEPTED");
        System.out.println((noAppend ? "  PASS " : "  ** FAIL ** ") + "no malformed block was APPENDED");
        System.out.println((noFalseTrue ? "  PASS " : "  ** FAIL ** ") + "verifiers never returned TRUE for garbage (proposalLinks/verifySlash/txsValid)");
        System.out.println((stateIntact ? "  PASS " : "  ** FAIL ** ") + "committed state (stateRoot/height/accounts) never mutated by fuzzing");
        System.out.printf(java.util.Locale.US, "  note: %.1f%% of inputs were rejected cleanly; %.1f%% threw a type/parse exception that the%n",
                100.0 * cleanReject / total, 100.0 * threw / total);
        System.out.println("        production HTTP handler catches (node stays up) — a candidate for stricter up-front validation.");

        boolean allPass = noAccept && noAppend && noFalseTrue && stateIntact && fixOk;
        System.out.println("\nFuzzTest: " + (allPass ? "PASS (all safety invariants held)" : "FAIL"));
        System.exit(allPass ? 0 : 1);
    }
}
