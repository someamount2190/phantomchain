package com.phantomchain.debug;

import java.util.*;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;

/**
 * Golden state-root vectors — the safety net for decomposing Ledger's serialization.
 *
 * Builds deterministic ledgers (fixed seeds -> fixed ML-DSA keys -> fixed ids) and pins
 * stateRoot()/accountsMerkleRoot() for every srVersion (v1/v2/full/m1) across a few
 * states. ANY change to the canonical byte layout — e.g. a field moved or reordered
 * while extracting StateRootCodec — flips these from green to a precise red, so a
 * silent consensus fork can't slip through a refactor.
 *
 * Run with arg "capture" to print the current roots (used to (re)pin GOLDEN).
 */
public class GoldenStateRootTest {
    static int pass = 0, fail = 0;

    static Ledger build(String ver, boolean mutate) throws Exception {
        int n = 3;
        MLDSAPrivateKeyParameters[] k = new MLDSAPrivateKeyParameters[n];
        String[] id = new String[n];
        for (int i = 0; i < n; i++) {
            byte[] seed = PhantomCrypto.sha3_256(PhantomCrypto.utf8("golden-seed-" + i));
            k[i] = PhantomCrypto.deviceKeyFromSeed(seed);
            id[i] = PhantomCrypto.hex(PhantomCrypto.sha3_256(k[i].getPublicKeyParameters().getEncoded()));
        }
        LinkedHashMap<String, Long> alloc = new LinkedHashMap<>();
        Map<String, Long> stk = new LinkedHashMap<>(), idn = new LinkedHashMap<>();
        Set<String> verfd = new LinkedHashSet<>();
        Map<String, String> vp = new LinkedHashMap<>(), bc = new LinkedHashMap<>();
        List<String> vals = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            alloc.put(id[i], 1_000_000L + i);
            stk.put(id[i], 1_000_000L);
            idn.put(id[i], 1L);
            verfd.add(id[i]);
            vp.put(id[i], PhantomCrypto.hex(k[i].getPublicKeyParameters().getEncoded()));
            bc.put(id[i], Ledger.beaconCommit0For(k[i].getEncoded()));
            vals.add(id[i]);
        }
        Ledger L = new Ledger();
        L.genesisEcon("pc-golden", alloc, vals, stk, idn, verfd, vp, bc, 1700000000000L);
        L.committeeSize = 0;
        L.srVersion = ver;
        if (mutate) {
            // exercise more of the tail deterministically: move a balance/nonce, add an unbond,
            // a beneficiary, a tombstone, and bump the supply counters.
            Ledger.Account a = L.accounts.get(id[0]); a.balance -= 123; a.nonce = 7;
            L.accounts.get(id[1]).balance += 123;
            L.stake.put(id[2], 750_000L);
            L.beneficiary.put(id[0], id[1]);
            L.slashed.add(id[2]);
            L.totalMinted += 4242; L.burned += 17;
        }
        return L;
    }

    static void check(String name, String got, String want) {
        if (want != null && want.equals(got)) { pass++; }
        else { fail++; System.out.println("  FAIL " + name + "\n    want=" + want + "\n    got =" + got); }
    }

    public static void main(String[] args) throws Exception {
        boolean capture = args.length > 0 && "capture".equals(args[0]);
        String[] vers = { "v1", "v2", "full", "m1" };
        for (String ver : vers) {
            for (boolean mut : new boolean[]{ false, true }) {
                String key = ver + (mut ? "/mutated" : "/genesis");
                Ledger L = build(ver, mut);
                String sr = L.stateRoot();
                String amr = L.accountsMerkleRoot();
                String shr = L.shardsRoot();
                if (capture) {
                    System.out.println("        GOLDEN.put(\"sr:" + key + "\", \"" + sr + "\");");
                    System.out.println("        GOLDEN.put(\"amr:" + key + "\", \"" + amr + "\");");
                    System.out.println("        GOLDEN.put(\"shr:" + key + "\", \"" + shr + "\");");
                } else {
                    check("stateRoot " + key, sr, GOLDEN.get("sr:" + key));
                    check("accountsMerkleRoot " + key, amr, GOLDEN.get("amr:" + key));
                    check("shardsRoot " + key, shr, GOLDEN.get("shr:" + key));
                }
                // toJson <-> fromJson round-trip invariant: a reloaded ledger reproduces the exact roots.
                if (!capture) {
                    Ledger L2 = new Ledger();
                    L2.fromJson(L.toJson());
                    check("roundtrip.stateRoot " + key, L2.stateRoot(), sr);
                    check("roundtrip.shardsRoot " + key, L2.shardsRoot(), shr);
                }
            }
        }
        if (capture) { System.out.println("(capture mode — paste the above into GOLDEN)"); return; }
        System.out.println("==== GoldenStateRootTest: " + pass + " passed, " + fail + " failed ====");
        if (fail > 0) System.exit(1);
    }

    static final Map<String, String> GOLDEN = new HashMap<>();
    static {
        // PINNED against the pre-decomposition code via `GoldenStateRootTest capture`.
        GOLDEN.put("sr:v1/genesis", "cdf4ddeba5080e526b04121fd560193dc336e40a3b89fe9a140712efb78bf128");
        GOLDEN.put("amr:v1/genesis", "3d0bc1b2648d933c001a7bd588f8ef0cc7ee0a2896f535f393e7986dba0a0f55");
        GOLDEN.put("sr:v1/mutated", "fc65932761ec37deda613c609e140f4a2c62271b7d8e7ac6d48d3def5f74f5b7");
        GOLDEN.put("amr:v1/mutated", "adbf57c1767729a0fdd5e2b64787ccb7737f1ff70852ee08746acfc70a378574");
        GOLDEN.put("sr:v2/genesis", "3e147899faf8d7401aff7a318b6ab41c7587acd123b6de0968a71e70071569b5");
        GOLDEN.put("amr:v2/genesis", "3d0bc1b2648d933c001a7bd588f8ef0cc7ee0a2896f535f393e7986dba0a0f55");
        GOLDEN.put("sr:v2/mutated", "d5cf7d37a9dbad4e617c79e9cf49216103deeb2402fdd0d857a96109f6af49c4");
        GOLDEN.put("amr:v2/mutated", "adbf57c1767729a0fdd5e2b64787ccb7737f1ff70852ee08746acfc70a378574");
        GOLDEN.put("sr:full/genesis", "5e0c958b8dfd3a39194b1a4fa4d191e33dcc6e62d108a979fbb850cb10a129a6");
        GOLDEN.put("amr:full/genesis", "3d0bc1b2648d933c001a7bd588f8ef0cc7ee0a2896f535f393e7986dba0a0f55");
        GOLDEN.put("sr:full/mutated", "4491d8b4bca5264420a98c9ac694587034eb175f47e7ca8a5aac4f90b2406b56");
        GOLDEN.put("amr:full/mutated", "adbf57c1767729a0fdd5e2b64787ccb7737f1ff70852ee08746acfc70a378574");
        GOLDEN.put("sr:m1/genesis", "2c5b560f4993a67e060add842491c34ca5db4a423e190d17d6fd2d341a9b0ea8");
        GOLDEN.put("amr:m1/genesis", "3d0bc1b2648d933c001a7bd588f8ef0cc7ee0a2896f535f393e7986dba0a0f55");
        GOLDEN.put("sr:m1/mutated", "16c625b06e467e7a51f71666aeed170cd14648a9353b3ae3704e6db49bc92266");
        GOLDEN.put("amr:m1/mutated", "adbf57c1767729a0fdd5e2b64787ccb7737f1ff70852ee08746acfc70a378574");
        GOLDEN.put("shr:v1/genesis", "bcdd3cfe778cb9a721eeae05a652e17d0ebd50ba155da80a32bf7a14cb1504f2");
        GOLDEN.put("shr:v1/mutated", "04e231d0c7b043879bb1327f4857897e58909462fac5a01fca18ee2d268b18a5");
        GOLDEN.put("shr:v2/genesis", "bcdd3cfe778cb9a721eeae05a652e17d0ebd50ba155da80a32bf7a14cb1504f2");
        GOLDEN.put("shr:v2/mutated", "04e231d0c7b043879bb1327f4857897e58909462fac5a01fca18ee2d268b18a5");
        GOLDEN.put("shr:full/genesis", "bcdd3cfe778cb9a721eeae05a652e17d0ebd50ba155da80a32bf7a14cb1504f2");
        GOLDEN.put("shr:full/mutated", "04e231d0c7b043879bb1327f4857897e58909462fac5a01fca18ee2d268b18a5");
        GOLDEN.put("shr:m1/genesis", "bcdd3cfe778cb9a721eeae05a652e17d0ebd50ba155da80a32bf7a14cb1504f2");
        GOLDEN.put("shr:m1/mutated", "04e231d0c7b043879bb1327f4857897e58909462fac5a01fca18ee2d268b18a5");
    }
}
