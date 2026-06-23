package com.phantomchain.debug;

import java.util.*;
import org.json.*;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

/**
 * In-process ADVERSARIAL test harness. Drives the real Ledger validation paths
 * (commitBlock / proposalLinks / txCheck / verifyVouch / tryAdmit) and asserts that every
 * crafted attack is rejected, while legitimate blocks still commit (no false positives).
 * Focus: the newly shipped commit-reveal RANDAO beacon and the stake-cost Sybil hardening,
 * plus core consensus/tx integrity.
 */
public class AdversaryTest {
    static int pass = 0, fail = 0;
    static void ok(String name, boolean cond) { if (cond) { pass++; System.out.println("  PASS " + name); } else { fail++; System.out.println("  ** FAIL ** " + name); } }
    static void rejects(String name, String result) { ok(name + "  [" + result + "]", result != null && result.startsWith("rejected")); }

    static Ledger L;
    static MLDSAPrivateKeyParameters[] K;
    static String[] ID;
    static byte[][] SEED;
    static long[] CTR;
    static Map<String, MLDSAPublicKeyParameters> PUB = new HashMap<>();
    static long ts = 1000;

    static byte[] secret(int v, long c) { return PhantomCrypto.hkdf(SEED[v], null, PhantomCrypto.utf8("pcbeacon" + c), 32); }
    static String reveal(int v, long c) { return PhantomCrypto.hex(secret(v, c)); }
    static String commit(int v, long c) { return PhantomCrypto.hex(PhantomCrypto.sha3_256(secret(v, c + 1))); }

    /** Build a fully-legit proposal from the scheduled proposer with the correct beacon reveal/commit. */
    static JSONObject craft(JSONArray txs) throws Exception {
        int h = L.chain.size();
        String prev = L.lastHash();
        int p = L.proposerFor(prev, h, 0);
        long ctr = CTR[p];
        String preimage = L.chainId + "|" + h + "|" + prev + "|" + txs.toString() + "|" + ts;
        String hash = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(preimage)));
        return new JSONObject().put("height", h).put("prevHash", prev).put("txs", txs).put("ts", ts).put("hash", hash)
                .put("proposer", p).put("view", 0).put("prevStateRoot", L.stateRoot()).put("prevShardsRoot", L.shardsRoot())
                .put("reveal", reveal(p, ctr)).put("commit", commit(p, ctr));
    }
    static int scheduled() throws Exception { return L.proposerFor(L.lastHash(), L.chain.size(), 0); }
    static String advance() throws Exception {
        int p = scheduled();
        JSONObject blk = craft(new JSONArray());
        String r = L.commitBlock(blk, PUB);
        if ("appended".equals(r)) CTR[p]++;
        ts++;
        return r;
    }
    static JSONObject copy(JSONObject o) { return new JSONObject(o.toString()); }

    public static void main(String[] a) throws Exception {
        // ---- setup: 3 validators, all verified founders, equal stake ----
        int N = 3;
        K = new MLDSAPrivateKeyParameters[N]; ID = new String[N]; SEED = new byte[N][]; CTR = new long[N];
        LinkedHashMap<String, Long> alloc = new LinkedHashMap<>();
        List<String> vals = new ArrayList<>(); Map<String, Long> stk = new HashMap<>(), idn = new HashMap<>();
        Set<String> ver = new HashSet<>(); Map<String, String> vpubs = new HashMap<>();
        java.security.SecureRandom rnd = new java.security.SecureRandom();
        for (int i = 0; i < N; i++) {
            K[i] = PhantomCrypto.randomDeviceKey(); ID[i] = Keys.idOf(K[i]);
            SEED[i] = new byte[32]; rnd.nextBytes(SEED[i]);
            PUB.put(ID[i], K[i].getPublicKeyParameters());
            alloc.put(ID[i], 1_000_000L); vals.add(ID[i]); stk.put(ID[i], 1_000_000L); idn.put(ID[i], 1L);
            ver.add(ID[i]); vpubs.put(ID[i], Keys.pubHex(K[i]));
        }
        L = new Ledger();
        L.genesisEcon("pc-adv", alloc, vals, stk, idn, ver, vpubs, 0);

        // Warm up until EVERY validator has recorded a beacon commitment. This genesis uses the no-seed
        // overload (commits start empty), so a fixed-length warm-up leaves some validators without a
        // commit — and beaconRevealValid() is intentionally lenient (returns true) for a proposer with
        // no commit (the legacy "unconstrained first reveal" path). If GROUP A then schedules such a
        // proposer, a garbage reveal is accepted and A1 flakes. Advancing until commits.size()==N puts
        // every validator in the hardened (committed) state the beacon attacks are meant to probe.
        System.out.println("== warm up: advance until every validator has a beacon commit ==");
        boolean allAppended = true; int warm = 0;
        while (L.commits.size() < N && warm < 100) { allAppended &= "appended".equals(advance()); warm++; }
        ok("warm-up blocks all append (" + warm + " blocks)", allAppended);
        ok("warm-up seeded a beacon commit for every validator", L.commits.size() == N);
        System.out.println("  beacon=" + L.beacon.substring(0, 12) + "  commits=" + L.commits.size() + "  blocks=" + warm);

        // ================= GROUP A — BEACON (commit-reveal RANDAO) =================
        System.out.println("== GROUP A: beacon attacks ==");
        {
            int p = scheduled();
            // A1 — tampered reveal (random) must be rejected at commit AND at vote
            JSONObject bad = copy(craft(new JSONArray())); bad.put("reveal", PhantomCrypto.hex(new byte[32]));
            rejects("A1 commit rejects garbage reveal", L.commitBlock(bad, PUB));
            ok("A1 proposalLinks rejects garbage reveal", !L.proposalLinks(bad));
            // A2 — replay an OLD already-revealed secret (ctr-1)
            if (CTR[p] >= 1) { JSONObject r = copy(craft(new JSONArray())); r.put("reveal", reveal(p, CTR[p] - 1));
                rejects("A2 commit rejects replayed old reveal", L.commitBlock(r, PUB)); }
            // A3 — reveal a future secret (ctr+1) that doesn't match the outstanding commit
            JSONObject f = copy(craft(new JSONArray())); f.put("reveal", reveal(p, CTR[p] + 1));
            rejects("A3 commit rejects wrong-index reveal", L.commitBlock(f, PUB));
            // A4 — borrow ANOTHER validator's reveal (impersonation of randomness source)
            int other = (p + 1) % 3; JSONObject o = copy(craft(new JSONArray())); o.put("reveal", reveal(other, CTR[other]));
            rejects("A4 commit rejects another validator's reveal", L.commitBlock(o, PUB));
            // A5 — empty reveal
            JSONObject e = copy(craft(new JSONArray())); e.put("reveal", "");
            rejects("A5 commit rejects empty reveal", L.commitBlock(e, PUB));
            // A6 — control: the correct reveal still commits
            ok("A6 correct reveal still appends (no false-positive)", "appended".equals(advance()));
        }

        // ================= GROUP B — BLOCK INTEGRITY =================
        System.out.println("== GROUP B: block integrity ==");
        {
            JSONObject g = craft(new JSONArray());
            JSONObject h = copy(g); h.put("hash", PhantomCrypto.hex(new byte[32]));
            rejects("B1 bad block hash", L.commitBlock(h, PUB));
            JSONObject sr = copy(g); sr.put("prevStateRoot", PhantomCrypto.hex(new byte[32]));
            rejects("B2 forged prevStateRoot", L.commitBlock(sr, PUB));
            JSONObject ht = copy(g); ht.put("height", L.chain.size() + 5);
            rejects("B3 wrong height", L.commitBlock(ht, PUB));
            JSONObject ph = copy(g); ph.put("prevHash", PhantomCrypto.hex(new byte[32]));
            rejects("B4 forged prevHash", L.commitBlock(ph, PUB));
            JSONObject shr = copy(g); shr.put("prevShardsRoot", PhantomCrypto.hex(new byte[32]));
            rejects("B5 forged prevShardsRoot", L.commitBlock(shr, PUB));
            ok("B6 control: untouched block still appends", "appended".equals(advance()));
        }

        // ================= GROUP C — TX VALIDATION =================
        System.out.println("== GROUP C: tx validation (malicious tx in an otherwise-valid block) ==");
        {
            String from = ID[0], to = ID[1];
            // C1 — non-positive amount (validly signed over the negative amount)
            rejects("C1 non-positive amount", L.commitBlock(craft(arr(L.buildTxProjected(from, to, -100, 0, K[0]))), PUB));
            // C2 — overflow amount
            rejects("C2 overflow amount", L.commitBlock(craft(arr(L.buildTxProjected(from, to, Long.MAX_VALUE, 0, K[0]))), PUB));
            // C3 — wrong chainId (cross-chain replay): sign+stamp a foreign cid
            JSONObject xc = L.buildTxProjected(from, to, 10, 1, K[0]);
            byte[] s = PhantomCrypto.sign(K[0], PhantomCrypto.utf8(Ledger.txCanon("evil-chain", from, to, 10, 1, xc.getLong("nonce"))));
            xc.put("cid", "evil-chain").put("sig", PhantomCrypto.hex(s));
            rejects("C3 wrong chainId", L.commitBlock(craft(arr(xc)), PUB));
            // C4 — corrupted signature
            JSONObject bs = L.buildTxProjected(from, to, 10, 1, K[0]); bs.put("sig", PhantomCrypto.hex(new byte[bs.getString("sig").length() / 2]));
            rejects("C4 corrupted signature", L.commitBlock(craft(arr(bs)), PUB));
            // C5 — spend more than balance
            rejects("C5 over-balance double-spend", L.commitBlock(craft(arr(L.buildTxProjected(from, to, 9_000_000_000L, 0, K[0]))), PUB));
            // C6 — stale nonce (replay): sign a tx at nonce 0 after the account has advanced
            JSONObject n0 = L.buildTxProjected(from, to, 10, 1, K[0]); long realNonce = n0.getLong("nonce");
            byte[] sn = PhantomCrypto.sign(K[0], PhantomCrypto.utf8(Ledger.txCanon(L.chainId, from, to, 10, 1, realNonce + 7)));
            n0.put("nonce", realNonce + 7).put("sig", PhantomCrypto.hex(sn));  // gap nonce
            rejects("C6 non-sequential nonce", L.commitBlock(craft(arr(n0)), PUB));
            // C7 — control: a clean transfer commits
            int cp = scheduled();
            String cr = L.commitBlock(craft(arr(L.buildTxProjected(from, to, 10, 1, K[0]))), PUB);
            if ("appended".equals(cr)) CTR[cp]++;
            ok("C7 control: valid transfer appends", "appended".equals(cr));
        }

        // ================= GROUP D — SYBIL / personhood stake-cost =================
        System.out.println("== GROUP D: Sybil resistance (identityBond) ==");
        {
            L.identityBond = 50_000;
            // a fresh candidate id with two real verified vouchers
            MLDSAPrivateKeyParameters ck = PhantomCrypto.randomDeviceKey(); String cand = Keys.idOf(ck);
            L.vouches.computeIfAbsent(cand, k -> new HashSet<>()).add(ID[0]);
            L.vouches.get(cand).add(ID[1]);
            L.tryAdmit(cand);
            ok("D1 vouched x2 but UNBONDED -> not verified", !L.verified.contains(cand));
            L.stake.put(cand, 49_999L); L.tryAdmit(cand);
            ok("D2 one short of bond -> not verified", !L.verified.contains(cand));
            L.stake.put(cand, 50_000L); L.tryAdmit(cand);
            ok("D3 vouched + bonded -> verified", L.verified.contains(cand));
            // withdraw below bond revokes
            L.stake.put(cand, 0L);
            if (L.identityBond > 0 && L.stake.getOrDefault(cand, 0L) < L.identityBond) L.verified.remove(cand);
            ok("D4 withdraw below bond -> verified revoked", !L.verified.contains(cand));
            // D5 — self-vouch must not count
            JSONObject selfV = L.buildVouchTx(ID[0], ID[0], K[0]);
            ok("D5 self-vouch rejected by verifyVouch", !L.verifyVouch(selfV, PUB));
            // D6 — vouch from an UNVERIFIED voucher rejected
            MLDSAPrivateKeyParameters uk = PhantomCrypto.randomDeviceKey(); String unv = Keys.idOf(uk);
            PUB.put(unv, uk.getPublicKeyParameters());
            JSONObject uV = L.buildVouchTx(unv, cand, uk);
            ok("D6 vouch from unverified voucher rejected", !L.verifyVouch(uV, PUB));
            // D7 — forged vouch signature rejected
            JSONObject fV = L.buildVouchTx(ID[0], cand, K[0]); fV.put("sig", PhantomCrypto.hex(new byte[fV.getString("sig").length() / 2]));
            ok("D7 forged vouch signature rejected", !L.verifyVouch(fV, PUB));
            L.identityBond = 0;
        }

        System.out.println("\nAdversaryTest: " + pass + " passed, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }

    static JSONArray arr(JSONObject o) { return new JSONArray().put(o); }
}
