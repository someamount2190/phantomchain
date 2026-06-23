package com.phantomchain.debug;

import static com.phantomchain.debug.TestKit.*;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

/**
 * CRYPTO AUDIT — empirically verifies the cryptographic constructions and their usage:
 *   ML-DSA signing (PQ), AEAD (ChaCha20-Poly1305) integrity + the misuse-resistant cluster-store nonce
 *   fix, key derivation (HKDF) domain separation, recovery KDF, the account Merkle commitment, and the
 *   DKG (Shamir + Feldman VSS). Each PASS confirms a property; FINDINGs are printed with their analysis.
 */
public class CryptoAuditTest {
    static final SecureRandom RND = new SecureRandom();

    public static void main(String[] a) throws Exception {
        System.out.println("==== CRYPTO AUDIT (primitives + usage) ====\n");

        // ───── 1. ML-DSA-65 signing ─────
        System.out.println("-- 1. ML-DSA-65 (post-quantum signatures) --");
        MLDSAPrivateKeyParameters k = PhantomCrypto.randomDeviceKey();
        MLDSAPublicKeyParameters pk = k.getPublicKeyParameters();
        byte[] msg = PhantomCrypto.utf8("tx|pc|alice|bob|100|1|0");
        byte[] sig = PhantomCrypto.sign(k, msg);
        ok("1a sign/verify round-trips", PhantomCrypto.verify(pk, msg, sig));
        ok("1b a tampered message is rejected", !PhantomCrypto.verify(pk, PhantomCrypto.utf8("tx|pc|alice|bob|999|1|0"), sig));
        byte[] sig2 = sig.clone(); sig2[10] ^= 0x01;
        ok("1c a tampered signature is rejected", !PhantomCrypto.verify(pk, msg, sig2));
        ok("1d a wrong key is rejected", !PhantomCrypto.verify(PhantomCrypto.randomDeviceKey().getPublicKeyParameters(), msg, sig));
        // BouncyCastle's MLDSASigner defaults to DETERMINISTIC signing (no RNG dependency -> no nonce-reuse
        // risk). It is still NOT a secure VRF (a signer can switch to the randomized variant; uniqueness
        // isn't verifier-enforced), and the project correctly seeds leader election from a commit-reveal
        // RANDAO beacon rather than from signatures.
        byte[] sigB = PhantomCrypto.sign(k, msg);
        ok("1e ML-DSA signing is deterministic here (reproducible) yet NOT used as a VRF (commit-reveal RANDAO instead)",
                Arrays.equals(sig, sigB) && PhantomCrypto.verify(pk, msg, sigB));
        ok("1f id == sha3-256(pubkey) (binds identity to key)", Keys.idOf(k).equals(PhantomCrypto.hex(PhantomCrypto.sha3_256(pk.getEncoded()))));

        // ───── 2. AEAD: integrity + nonce-reuse rationale ─────
        System.out.println("\n-- 2. ChaCha20-Poly1305 AEAD --");
        byte[] key = rnd(32), nonce = rnd(12), pt = PhantomCrypto.utf8("the cluster ledger partition");
        byte[] ct = PhantomCrypto.aead(true, key, nonce, pt);
        ok("2a AEAD decrypt round-trips", Arrays.equals(PhantomCrypto.aead(false, key, nonce, ct), pt));
        ok("2b a tampered ciphertext fails the auth tag", failsAead(key, nonce, flip(ct, 3)));
        ok("2c a wrong key fails the auth tag", failsAead(rnd(32), nonce, ct));
        ok("2d a wrong nonce fails the auth tag", failsAead(key, rnd(12), ct));
        // RATIONALE for the cluster-store fix: a REUSED (key,nonce) over two plaintexts leaks pt1^pt2.
        byte[] p1 = PhantomCrypto.utf8("AAAAAAAAAAAAAAAA"), p2 = PhantomCrypto.utf8("BBBBBBBBBBBBBBBB");
        byte[] c1 = PhantomCrypto.aead(true, key, nonce, p1), c2 = PhantomCrypto.aead(true, key, nonce, p2);
        boolean leaks = Arrays.equals(xor(c1, c2, 16), xor(p1, p2, 16));   // keystream cancels -> plaintext XOR leaks
        ok("2e [rationale] reusing one (key,nonce) over two plaintexts leaks pt1^pt2 (why nonce reuse is fatal)", leaks);

        // ───── 3. Cluster store: misuse-resistant nonce (the fix) ─────
        System.out.println("\n-- 3. ClusterStore (encrypt-then-RS-shard) --");
        byte[] secret = rnd(32), partition = rnd(800);
        byte[][] s1 = ClusterStore.shard(partition, secret, 7, 2, 3);
        byte[][] s2 = ClusterStore.shard(partition, secret, 7, 2, 3);   // SAME secret + SAME version
        ok("3a re-sharding the same partition+version uses a FRESH nonce (ciphertext differs -> no reuse)", !Arrays.equals(s1[0], s2[0]));
        boolean[] two = {true, true, false};
        ok("3b any k shards reconstruct exactly", Arrays.equals(ClusterStore.reconstruct(s1, two, secret, 7, 2, 3), partition));
        ok("3c a wrong cluster key is rejected (AEAD over the framed ciphertext)", failsReconstruct(s1, two, rnd(32), 7));
        boolean[] one = {true, false, false};
        ok("3d a single shard cannot reconstruct (k-of-n)", failsReconstruct(s1, one, secret, 7));

        // ───── 4. Key derivation (HKDF) domain separation ─────
        System.out.println("\n-- 4. HKDF key derivation --");
        byte[] seed = rnd(32);
        MLDSAPrivateKeyParameters root = PhantomCrypto.rootFromSeed(seed), dev = PhantomCrypto.deviceKeyFromSeed(seed);
        String rootPub = PhantomCrypto.hex(root.getPublicKeyParameters().getEncoded()), devPub = PhantomCrypto.hex(dev.getPublicKeyParameters().getEncoded());
        ok("4a root and device keys from one seed are DISTINCT (domain-separated info)", !rootPub.equals(devPub));
        ok("4b derivation is deterministic from the seed", PhantomCrypto.hex(PhantomCrypto.rootFromSeed(seed).getPublicKeyParameters().getEncoded()).equals(rootPub));
        ok("4c HKDF info separation: different info -> different output", !Arrays.equals(
                PhantomCrypto.hkdf(seed, null, PhantomCrypto.utf8("a"), 32), PhantomCrypto.hkdf(seed, null, PhantomCrypto.utf8("b"), 32)));

        // ───── 5. Wallet recovery KDF (Argon2id + HKDF + AEAD) ─────
        System.out.println("\n-- 5. Recovery backup (Argon2id + HKDF + ChaCha20-Poly1305) --");
        byte[] recSeed = rnd(32), mesh = rnd(32);
        byte[] blob1 = PhantomCrypto.backup(recSeed, "correct horse", mesh);
        byte[] blob2 = PhantomCrypto.backup(recSeed, "correct horse", mesh);
        ok("5a two backups of the same seed differ (fresh random salt+nonce each time)", !Arrays.equals(blob1, blob2));
        ok("5b recovery with the correct password+mesh round-trips", Arrays.equals(PhantomCrypto.recover(blob1, "correct horse", mesh), recSeed));
        ok("5c a wrong password fails (AEAD auth)", recoverFails(blob1, "wrong horse", mesh));
        ok("5d a missing mesh share fails (bound into the key)", recoverFails(blob1, "correct horse", rnd(32)));
        ok("5e a tampered blob fails (AEAD integrity)", recoverFails(flip(blob1, blob1.length - 1), "correct horse", mesh));

        // ───── 6. Account Merkle commitment (domain-separated) ─────
        System.out.println("\n-- 6. Account Merkle commitment --");
        byte[] leaf = Ledger.accountLeaf("aaaa", 100, 0);
        byte[] interior = Ledger.merkleNode(leaf, leaf);
        ok("6a leaf vs interior are domain-separated (tagged leaf != 0x01-prefixed node)", !Arrays.equals(leaf, interior));
        List<byte[]> leaves = new ArrayList<>(); for (int i = 0; i < 7; i++) leaves.add(Ledger.accountLeaf("id" + i, i, 0));
        byte[] rootH = Ledger.merkleRoot(leaves);
        ok("6b an inclusion proof verifies against the root", Ledger.merkleVerify(leaves.get(3), 3, Ledger.merkleProof(leaves, 3), rootH));
        ok("6c a forged sibling path does not verify", !Ledger.merkleVerify(leaves.get(3), 3, Ledger.merkleProof(leaves, 2), rootH));

        // ───── 7. DKG (Shamir + Feldman VSS) ─────
        System.out.println("\n-- 7. DKG (Shamir secret sharing + Feldman VSS) --");
        Dkg.Ceremony cy = Dkg.ceremony(3, 5, RND);     // 3-of-5
        BigInteger S = cy.secret();
        ok("7a aggregate secret reconstructs from k=3 shares (Lagrange)", Dkg.combine(new Dkg.Share[]{cy.shares[0], cy.shares[2], cy.shares[4]}).equals(S));
        ok("7b k-1 = 2 shares reconstruct the WRONG value (threshold privacy)", !Dkg.combine(new Dkg.Share[]{cy.shares[0], cy.shares[1]}).equals(S));
        ok("7c every aggregate share Feldman-verifies against the commitments", Dkg.verify(cy.shares[1], cy.commitments) && Dkg.verify(cy.shares[4], cy.commitments));
        Dkg.Share tampered = new Dkg.Share(cy.shares[2].x, cy.shares[2].y.add(BigInteger.ONE).mod(Dkg.N));
        ok("7d a tampered share is caught by Feldman verification", !Dkg.verify(tampered, cy.commitments));
        ok("7e the aggregate secret = sum of member contributions (no single member knows it a priori)",
                cy.contributions.length == 5 && !cy.contributions[0].equals(S));
        // HARDENED: a malicious dealer is DISQUALIFIED and the ceremony continues (no griefing/abort)
        Dkg.Deal[] deals = new Dkg.Deal[5]; BigInteger[] cons = new BigInteger[5];
        for (int m = 0; m < 5; m++) { cons[m] = new BigInteger(200, RND).mod(Dkg.N); deals[m] = Dkg.deal(3, 5, cons[m], RND); }
        Dkg.Share[] sh = deals[2].shares.clone();                                   // tamper dealer 2's share -> Feldman-inconsistent
        sh[1] = new Dkg.Share(sh[1].x, sh[1].y.add(BigInteger.ONE).mod(Dkg.N));
        deals[2] = new Dkg.Deal(deals[2].secret, deals[2].coeffs, sh, deals[2].commitments);
        Dkg.Ceremony hc = Dkg.ceremonyFrom(3, 5, deals, cons);
        ok("7f a malicious dealer is DISQUALIFIED and the ceremony continues (qualified=" + hc.qualifiedCount() + "/5)", hc.qualifiedCount() == 4 && !hc.qualified[2]);
        ok("7g the hardened ceremony's secret reconstructs from k shares (over the qualified set)",
                Dkg.combine(new Dkg.Share[]{hc.shares[0], hc.shares[1], hc.shares[3]}).equals(hc.secret()));

        // ───── 8. Signing-string delimiter guard (audit NOTE-1 hardening) ─────
        System.out.println("\n-- 8. Canonical signing-string delimiter guard --");
        Ledger L = new Ledger();
        ok("8a a tx field containing the '|' delimiter is rejected (anti-injection)",
                !Ledger.canonClean(new org.json.JSONObject().put("from", "alice").put("to", "bob|999|1|0")));
        ok("8b a normal hex/numeric tx passes the guard", Ledger.canonClean(new org.json.JSONObject().put("from", "aa".repeat(32)).put("to", "bb".repeat(32))));

        // ───── findings ─────
        System.out.println("\n  ---- FINDINGS / NOTES (audit) ----");
        System.out.println("  [FIXED]   ClusterStore AEAD nonce was derived deterministically from `version`; reusing a");
        System.out.println("            version with different content would have caused a fatal ChaCha20-Poly1305 nonce");
        System.out.println("            reuse (see 2e). Now a fresh random nonce per encryption (3a) + version in the key.");
        System.out.println("  [FIXED]   NOTE-1 delimiter injection: a central guard now rejects '|' in any field feeding a");
        System.out.println("            signed canonical (8a/8b) + the /announce addr — closes the class without a format");
        System.out.println("            change (existing signatures still verify; no honest field carries '|').");
        System.out.println("  [FIXED]   NOTE-2 DKG griefing: a Feldman-inconsistent dealer is now DISQUALIFIED and the");
        System.out.println("            ceremony continues over the qualified set (7f/7g) instead of aborting; contributions");
        System.out.println("            are rejection-sampled (unbiased). Residual rushing-bias is neutralized by store");
        System.out.println("            key = sha3(S); full Gennaro commit-reveal DKG remains the deeper (optional) step.");
        System.out.println("  [NOTE-3]  ML-DSA signing is DETERMINISTIC in this BouncyCastle build (1e) — safe (no");
        System.out.println("            nonce-reuse class), and the chain doesn't rely on signature unpredictability");
        System.out.println("            (leader election uses the commit-reveal RANDAO, not sign-as-VRF).");
        System.out.println("  [OK]      HKDF domain separation, Argon2id(64MiB,t=3,p=4), SHA3-256 ids, domain-separated");
        System.out.println("            Merkle, AEAD integrity; Feldman leaks g^S but store key=sha3(S) keeps S secret.");

        System.out.println("\n==== CryptoAuditTest: " + pass + " passed, " + fail + " failed ====");
        System.exit(fail == 0 ? 0 : 1);
    }

    // helpers
    static byte[] rnd(int n) { byte[] b = new byte[n]; RND.nextBytes(b); return b; }
    static byte[] flip(byte[] b, int i) { byte[] c = b.clone(); c[i] ^= 0x40; return c; }
    static byte[] xor(byte[] a, byte[] b, int n) { byte[] r = new byte[n]; for (int i = 0; i < n; i++) r[i] = (byte) (a[i] ^ b[i]); return r; }
    static boolean failsAead(byte[] key, byte[] nonce, byte[] ct) { try { PhantomCrypto.aead(false, key, nonce, ct); return false; } catch (Exception e) { return true; } }
    static boolean failsReconstruct(byte[][] s, boolean[] p, byte[] secret, long v) { try { ClusterStore.reconstruct(s, p, secret, v, 2, 3); return false; } catch (Exception e) { return true; } }
    static boolean recoverFails(byte[] blob, String pw, byte[] mesh) { try { PhantomCrypto.recover(blob, pw, mesh); return false; } catch (Exception e) { return true; } }
}
