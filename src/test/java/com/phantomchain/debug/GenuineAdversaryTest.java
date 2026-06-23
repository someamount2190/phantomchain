package com.phantomchain.debug;

import static com.phantomchain.debug.TestKit.*;

import java.util.*;
import org.json.*;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

/**
 * GENUINE adversarial discovery (not gate-confirmation). Attacks emergent invariants where there may
 * be NO guard:
 *   PART 1 — stateRoot completeness: mutate each consensus-relevant field and report which mutations
 *            are NOT reflected in stateRoot (= a state a node could diverge on WITHOUT the app-hash
 *            catching it; the exact class of silent-fork bug).
 *   PART 2 — beacon unbiasability: measure whether a proposer can GRIND an unconstrained reveal to
 *            control the next proposer election (the security property a VRF would provide).
 * Prints findings honestly; does not assert "pass" — the point is to discover, then judge severity.
 */
public class GenuineAdversaryTest {
    static Ledger L;
    static MLDSAPrivateKeyParameters[] K; static String[] ID; static byte[][] SEED; static long[] CTR;
    static Map<String, MLDSAPublicKeyParameters> PUB = new HashMap<>();
    static long ts = 1000;
    static byte[] secret(int v, long c) { return PhantomCrypto.hkdf(SEED[v], null, PhantomCrypto.utf8("pcbeacon" + c), 32); }
    static String reveal(int v, long c) { return PhantomCrypto.hex(secret(v, c)); }
    static String commit(int v, long c) { return PhantomCrypto.hex(PhantomCrypto.sha3_256(secret(v, c + 1))); }
    static int scheduled() throws Exception { return L.proposerFor(L.lastHash(), L.chain.size(), 0); }
    static String advance() throws Exception {
        int p = scheduled(); int h = L.chain.size(); String prev = L.lastHash();
        JSONArray txs = new JSONArray();
        String preimage = L.chainId + "|" + h + "|" + prev + "|" + txs + "|" + ts;
        String hash = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(preimage)));
        JSONObject blk = new JSONObject().put("height", h).put("prevHash", prev).put("txs", txs).put("ts", ts).put("hash", hash)
                .put("proposer", p).put("view", 0).put("prevStateRoot", L.stateRoot()).put("prevShardsRoot", L.shardsRoot())
                .put("reveal", reveal(p, CTR[p])).put("commit", commit(p, CTR[p]));
        String r = L.commitBlock(blk, PUB); if ("appended".equals(r)) CTR[p]++; ts++; return r;
    }

    static int N = 4;
    public static void main(String[] a) throws Exception {
        K = new MLDSAPrivateKeyParameters[N]; ID = new String[N]; SEED = new byte[N][]; CTR = new long[N];
        LinkedHashMap<String, Long> alloc = new LinkedHashMap<>(); List<String> vals = new ArrayList<>();
        Map<String, Long> stk = new HashMap<>(), idn = new HashMap<>(); Set<String> ver = new HashSet<>(); Map<String, String> vp = new HashMap<>();
        java.security.SecureRandom rnd = new java.security.SecureRandom();
        for (int i = 0; i < N; i++) { K[i] = PhantomCrypto.randomDeviceKey(); ID[i] = Keys.idOf(K[i]); SEED[i] = new byte[32]; rnd.nextBytes(SEED[i]);
            PUB.put(ID[i], K[i].getPublicKeyParameters()); alloc.put(ID[i], 1_000_000L); vals.add(ID[i]); stk.put(ID[i], 1_000_000L); idn.put(ID[i], 1L); ver.add(ID[i]); vp.put(ID[i], Keys.pubHex(K[i])); }
        // bind each validator's first reveal: seed commits[id] = sha3(secret(i,0)) (the fix under test)
        Map<String, String> bc = new HashMap<>();
        for (int i = 0; i < N; i++) bc.put(ID[i], PhantomCrypto.hex(PhantomCrypto.sha3_256(secret(i, 0))));
        L = new Ledger(); L.genesisEcon("pc-genuine", alloc, vals, stk, idn, ver, vp, bc, 0);
        for (int i = 0; i < 8; i++) advance();

        // ===================== PART 1: stateRoot completeness audit =====================
        System.out.println("==== PART 1: stateRoot completeness (does the app-hash actually cover each field?) ====");
        System.out.println("    A field whose mutation is UNDETECTED = a state two honest nodes can silently diverge on.\n");
        audit("accounts.balance (control, must detect)", () -> L.accounts.get(ID[0]).balance += 1, () -> L.accounts.get(ID[0]).balance -= 1);
        audit("stake (control, must detect)",            () -> L.stake.merge(ID[0], 1L, Long::sum), () -> L.stake.merge(ID[0], -1L, Long::sum));
        audit("jailed (control, must detect)",           () -> L.jailed.put("victimJ", 99L), () -> L.jailed.remove("victimJ"));
        audit("verified (control, must detect)",         () -> L.verified.add("ghostV"), () -> L.verified.remove("ghostV"));
        audit("beacon (control, must detect)",           () -> L.beacon = "ff" + L.beacon.substring(2), () -> {});
        // suspected GAPS:
        audit("slashed  [tombstone -> excludes from quorum/weight]", () -> L.slashed.add("victimS"), () -> L.slashed.remove("victimS"));
        audit("vouches  [accrues toward verified admission]",        () -> L.vouches.put("c", new HashSet<>(Arrays.asList("a", "b"))), () -> L.vouches.remove("c"));
        audit("proposals[governance, executes params at timelock]",  () -> L.proposals.put("p", new JSONObject().put("param", "slashBps").put("value", 5000)), () -> L.proposals.remove("p"));

        // ===================== PART 2: is the first-reveal grind CLOSED by commit0 binding? =====================
        System.out.println("\n==== PART 2: beacon grind closed? (first reveal bound by commit0) ====");
        // The grind only works if a proposer can freely CHOOSE its reveal (beacon=sha3(prev|reveal)).
        // Demonstrate that with commit0 binding, a fresh validator's first reveal is NOT free.
        // Build a brand-new validator whose first reveal is bound by a seeded commit0:
        byte[] aseed = new byte[32]; rnd.nextBytes(aseed);
        String aid = "attacker_" + PhantomCrypto.hex(aseed).substring(0, 8);
        L.validators.add(aid); L.valPubs.put(aid, "deadbeef");
        L.commits.put(aid, PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.hkdf(aseed, null, PhantomCrypto.utf8("pcbeacon0"), 32))));
        int aidx = L.validators.indexOf(aid);
        String boundReveal = PhantomCrypto.hex(PhantomCrypto.hkdf(aseed, null, PhantomCrypto.utf8("pcbeacon0"), 32));
        // honest: the bound reveal passes
        JSONObject good = new JSONObject().put("proposer", aidx).put("reveal", boundReveal);
        System.out.println("    bound (committed) first reveal accepted: " + L.beaconRevealValid(good));
        // attacker: try 20000 freely-chosen reveals to grind the next election — ALL must be rejected
        int accepted = 0, tried = 0;
        for (int t = 0; t < 20_000; t++) {
            String r = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8("grind" + t)));
            if (r.equals(boundReveal)) continue;
            tried++;
            JSONObject blk = new JSONObject().put("proposer", aidx).put("reveal", r);
            if (L.beaconRevealValid(blk)) accepted++;
        }
        System.out.println("    grinded (freely chosen) first reveals: " + tried + " tried, " + accepted + " accepted");
        System.out.println(accepted == 0
                ? "    => GRIND CLOSED: a fresh validator cannot choose its first reveal; it is bound to commit0."
                : "    => ** STILL GRINDABLE ** : " + accepted + " chosen reveals were accepted.");
        System.out.println("    (residual: a founder could still key-grind its OWN commit0 at the genesis ceremony before");
        System.out.println("    the initial beacon is fixed — trusted-setup assumption; untrusted VALJOINers cannot, since");
        System.out.println("    they commit before knowing the beacon at their future first-proposal height.)");

        System.out.println("\n==== done ====");
    }

    interface Mut { void run(); }
    static void audit(String name, Mut apply, Mut revert) throws Exception {
        String before = L.stateRoot();
        apply.run();
        String after = L.stateRoot();
        revert.run();
        boolean detected = !before.equals(after);
        System.out.println((detected ? "  [covered]   " : "  ** GAP **   ") + name + (detected ? "" : "  <- mutation NOT reflected in stateRoot"));
    }
}
