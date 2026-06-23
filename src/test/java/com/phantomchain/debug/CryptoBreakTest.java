package com.phantomchain.debug;

import static com.phantomchain.debug.TestKit.*;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

/**
 * ADVANCED crypto-breaking methods — attacks beyond the basic audit:
 *   A. Merkle tree forgery (CVE-2012-2459 duplicate-last) — confirm the RAW tree collides, and that the
 *      hardened count-bound account root + index-range check defeats the forgery.
 *   B. ML-DSA signature malleability / encoding (append, truncate, bit-flip) — all rejected.
 *   C. Cross-domain signature reuse — a signature valid for one canonical doesn't verify for another type.
 *   D. AEAD nonce-reuse PLAINTEXT RECOVERY — with a reused (key,nonce) and one known plaintext, the other
 *      is fully recovered (the deep reason the ClusterStore fix matters).
 *   E. Feldman VSS edge cases — an identity (zero) commitment, and a tampered commitment, are handled.
 */
public class CryptoBreakTest {
    static final SecureRandom RND = new SecureRandom();
    static Map<String, MLDSAPublicKeyParameters> PUB = new HashMap<>();

    public static void main(String[] a) throws Exception {
        System.out.println("==== ADVANCED CRYPTO-BREAKING METHODS ====\n");

        // ───── A. Merkle CVE-2012-2459 (duplicate-last collision) ─────
        System.out.println("-- A. Merkle duplicate-last forgery (CVE-2012-2459) --");
        byte[] A = Ledger.accountLeaf("a", 1, 0), B = Ledger.accountLeaf("b", 2, 0), C = Ledger.accountLeaf("c", 3, 0);
        byte[] raw3 = Ledger.merkleRoot(Arrays.asList(A, B, C));
        byte[] raw4 = Ledger.merkleRoot(Arrays.asList(A, B, C, C));   // duplicate the last leaf
        ok("A1 [break] the RAW Merkle root of [A,B,C] == [A,B,C,C] (duplicate-last collision exists)", Arrays.equals(raw3, raw4));
        // the hardened account root binds the leaf COUNT, so the two sets no longer collide
        String bound3 = PhantomCrypto.hex(Ledger.boundMerkleRoot(3, raw3));
        String bound4 = PhantomCrypto.hex(Ledger.boundMerkleRoot(4, raw4));
        ok("A2 [fixed] count-bound roots differ (3 leaves vs 4) -> forgery defeated", !bound3.equals(bound4));
        // and a real ledger's proof can't be forged onto a duplicated index
        Ledger L = ledgerWith("aaaa", "bbbb", "cccc");
        JSONObject proof = L.accountProof("cccc");
        ok("A3 a valid account proof verifies against the count-bound root", Ledger.verifyAccountProof(proof));
        JSONObject dupIdx = new JSONObject(proof.toString()).put("index", proof.getInt("count"));   // claim the duplicated position
        ok("A4 [break attempt] a proof at a duplicated/out-of-range index is rejected", !Ledger.verifyAccountProof(dupIdx));
        JSONObject inflated = new JSONObject(proof.toString()).put("count", proof.getInt("count") + 1);
        ok("A5 [break attempt] inflating the leaf count breaks the bound root (rejected)", !Ledger.verifyAccountProof(inflated));

        // ───── B. ML-DSA signature malleability / encoding ─────
        System.out.println("\n-- B. ML-DSA signature malleability / encoding --");
        MLDSAPrivateKeyParameters k = PhantomCrypto.randomDeviceKey();
        MLDSAPublicKeyParameters pk = k.getPublicKeyParameters();
        byte[] m = PhantomCrypto.utf8("vote-over-block-hash");
        byte[] sig = PhantomCrypto.sign(k, m);
        ok("B1 a signature with an APPENDED byte is rejected (no trailing-garbage malleability)", !verify(pk, m, append(sig, (byte) 0)));
        ok("B2 a TRUNCATED signature is rejected", !verify(pk, m, Arrays.copyOf(sig, sig.length - 1)));
        ok("B3 a zero-length signature is rejected", !verify(pk, m, new byte[0]));
        byte[] flipHi = sig.clone(); flipHi[sig.length - 1] ^= 0x80;
        ok("B4 a high-bit flip in the signature is rejected (no bit-level malleability)", !verify(pk, m, flipHi));
        ok("B5 an all-zero signature of the right length is rejected", !verify(pk, m, new byte[sig.length]));

        // ───── C. Cross-domain signature reuse ─────
        System.out.println("\n-- C. cross-domain / cross-type signature reuse --");
        // a transfer signature must NOT verify as a different canonical (bond / vouch / wrong field)
        byte[] transferCanon = PhantomCrypto.utf8(Ledger.txCanon("pc", "alice", "bob", 100, 1, 0));
        byte[] tsig = PhantomCrypto.sign(k, transferCanon);
        ok("C1 a transfer signature does NOT verify as a BOND action (distinct canonical prefix)",
                !verify(pk, PhantomCrypto.utf8("bond|pc|alice|100|0"), tsig));
        ok("C2 a transfer signature does NOT verify for a different amount (signed-field binding)",
                !verify(pk, PhantomCrypto.utf8(Ledger.txCanon("pc", "alice", "bob", 999, 1, 0)), tsig));
        ok("C3 a transfer signature does NOT verify on a different chainId (replay-resistance)",
                !verify(pk, PhantomCrypto.utf8(Ledger.txCanon("OTHER", "alice", "bob", 100, 1, 0)), tsig));

        // ───── D. AEAD nonce-reuse plaintext recovery ─────
        System.out.println("\n-- D. AEAD nonce-reuse plaintext recovery --");
        byte[] key = rnd(32), nonce = rnd(12);
        byte[] known = PhantomCrypto.utf8("BALANCE: alice=100 "), secret = PhantomCrypto.utf8("BALANCE: alice=999 ");
        byte[] cKnown = PhantomCrypto.aead(true, key, nonce, known);
        byte[] cSecret = PhantomCrypto.aead(true, key, nonce, secret);     // SAME key+nonce reused
        // attacker knows `known` and both ciphertexts -> recovers `secret` = cSecret ^ cKnown ^ known
        byte[] recovered = new byte[secret.length];
        for (int i = 0; i < secret.length; i++) recovered[i] = (byte) (cSecret[i] ^ cKnown[i] ^ known[i]);
        ok("D1 [break] nonce reuse fully recovers a secret plaintext from a known one (why the CS fix matters)", Arrays.equals(recovered, secret));
        // the fixed ClusterStore never reuses a nonce: two seals of the same data differ
        byte[] sec = rnd(32), part = rnd(300);
        ok("D2 [fixed] ClusterStore uses a fresh random nonce per seal (no reuse even at same version)",
                !Arrays.equals(ClusterStore.shard(part, sec, 0, 2, 3)[0], ClusterStore.shard(part, sec, 0, 2, 3)[0]));

        // ───── E. Feldman VSS edge cases ─────
        System.out.println("\n-- E. Feldman VSS edge cases --");
        // identity (zero) commitment: a dealer contributing 0 produces shares that still Feldman-verify
        Dkg.Deal zero = Dkg.deal(3, 5, BigInteger.ZERO, RND);
        ok("E1 a zero-secret dealer's shares still verify (handled; adds 0 entropy, not a forgery)", Dkg.verify(zero.shares[0], zero.commitments));
        // a forged commitment (replace C_0 with a different point) makes shares fail verification
        ECPoint[] forged = zero.commitments.clone(); forged[0] = Dkg.G.multiply(BigInteger.valueOf(12345)).normalize();
        ok("E2 substituting a commitment makes the shares FAIL Feldman verification", !Dkg.verify(zero.shares[1], forged));
        // a dealer whose share is consistent with commitments but encodes a DIFFERENT polynomial can't pass
        Dkg.Deal d = Dkg.deal(3, 5, new BigInteger(200, RND).mod(Dkg.N), RND);
        Dkg.Share swapped = new Dkg.Share(d.shares[0].x, d.shares[1].y);   // wrong y for this x
        ok("E3 a share with a mismatched (x,y) fails Feldman (can't smuggle a different evaluation)", !Dkg.verify(swapped, d.commitments));

        System.out.println("\n==== CryptoBreakTest: " + pass + " passed, " + fail + " failed ====");
        System.exit(fail == 0 ? 0 : 1);
    }

    static boolean verify(MLDSAPublicKeyParameters pk, byte[] m, byte[] sig) { try { return PhantomCrypto.verify(pk, m, sig); } catch (Exception e) { return false; } }
    static byte[] rnd(int n) { byte[] b = new byte[n]; RND.nextBytes(b); return b; }
    static byte[] append(byte[] b, byte x) { byte[] c = Arrays.copyOf(b, b.length + 1); c[b.length] = x; return c; }
    static Ledger ledgerWith(String... ids) throws Exception {
        LinkedHashMap<String, Long> alloc = new LinkedHashMap<>();
        List<String> vals = new ArrayList<>(); Map<String, Long> stk = new HashMap<>(), idn = new HashMap<>();
        Set<String> ver = new HashSet<>(); Map<String, String> vp = new HashMap<>(), bc = new HashMap<>();
        for (String id : ids) {
            MLDSAPrivateKeyParameters key = PhantomCrypto.randomDeviceKey();
            String vid = Keys.idOf(key);
            alloc.put(id, 1000L); alloc.put(vid, 1000L); vals.add(vid); stk.put(vid, 1L); idn.put(vid, 1L);
            ver.add(vid); vp.put(vid, Keys.pubHex(key)); bc.put(vid, Ledger.beaconCommit0For(key.getEncoded()));
        }
        Ledger L = new Ledger(); L.genesisEcon("pc", alloc, vals, stk, idn, ver, vp, bc, 1700000000000L);
        return L;
    }
}
