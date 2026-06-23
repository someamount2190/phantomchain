package com.phantomchain.debug;

import static com.phantomchain.debug.TestKit.*;

import java.util.Arrays;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;

/**
 * KNOWN-ANSWER TESTS (KATs) — validates the cryptographic primitives PhantomChain uses against the
 * OFFICIAL published test vectors that standards bodies / researchers established:
 *   SHA3-256 & SHAKE-256 ........ NIST FIPS 202 (CAVP)
 *   HKDF-SHA256 ................. RFC 5869 Test Case 1
 *   Argon2id ................... RFC 9106 reference vector
 *   ChaCha20-Poly1305 .......... RFC 8439 §2.8.2 AEAD vector
 *   ML-DSA-65 .................. FIPS 204 parameter sizes + deterministic seed expansion
 * A PASS means the implementation produces the EXACT bytes the standard specifies.
 */
public class KnownAnswerTest {
    static void kat(String n, byte[] got, String expectHex) {
        boolean c = PhantomCrypto.hex(got).equals(expectHex.toLowerCase());
        System.out.println((c ? "  PASS " : "  ** FAIL ** ") + n + (c ? "" : "\n        got      " + PhantomCrypto.hex(got) + "\n        expected " + expectHex.toLowerCase()));
        if (c) pass++; else fail++;
    }
    static byte[] rep(int b, int n) { byte[] x = new byte[n]; Arrays.fill(x, (byte) b); return x; }

    public static void main(String[] a) throws Exception {
        System.out.println("==== KNOWN-ANSWER TESTS (official standard vectors) ====\n");

        // ───── FIPS 202: SHA3-256 ─────
        System.out.println("-- FIPS 202 SHA3-256 (NIST CAVP) --");
        kat("SHA3-256(\"\")  == FIPS 202 empty-string vector", PhantomCrypto.sha3_256(new byte[0]),
                "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        kat("SHA3-256(\"abc\") == FIPS 202 'abc' vector", PhantomCrypto.sha3_256(PhantomCrypto.utf8("abc")),
                "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");

        // ───── FIPS 202: SHAKE-256 (XOF) ─────
        System.out.println("\n-- FIPS 202 SHAKE-256 (XOF) --");
        kat("SHAKE-256(\"\", 32B) == FIPS 202 empty-string vector", PhantomCrypto.shake256(new byte[0], 32),
                "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");

        // ───── RFC 5869: HKDF-SHA256, Test Case 1 ─────
        System.out.println("\n-- RFC 5869 HKDF-SHA256 (Test Case 1) --");
        byte[] ikm = rep(0x0b, 22);
        byte[] salt = PhantomCrypto.unhex("000102030405060708090a0b0c");
        byte[] info = PhantomCrypto.unhex("f0f1f2f3f4f5f6f7f8f9");
        kat("HKDF-SHA256(IKM,salt,info,42) == RFC 5869 TC1 OKM", PhantomCrypto.hkdf(ikm, salt, info, 42),
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

        // ───── RFC 9106: Argon2id reference vector (BC primitive PhantomCrypto wraps) ─────
        System.out.println("\n-- RFC 9106 Argon2id (reference vector) --");
        Argon2Parameters ap = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(3).withMemoryAsKB(32).withParallelism(4)
                .withSalt(rep(0x02, 16)).withSecret(rep(0x03, 8)).withAdditional(rep(0x04, 12)).build();
        Argon2BytesGenerator ag = new Argon2BytesGenerator(); ag.init(ap);
        byte[] argonTag = new byte[32]; ag.generateBytes(rep(0x01, 32), argonTag);
        kat("Argon2id(P=01*32,S=02*16,K=03*8,X=04*12,m=32,t=3,p=4) == RFC 9106 tag", argonTag,
                "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");

        // ───── RFC 8439: ChaCha20-Poly1305 AEAD §2.8.2 (BC primitive PhantomCrypto wraps) ─────
        System.out.println("\n-- RFC 8439 ChaCha20-Poly1305 (§2.8.2 AEAD vector) --");
        byte[] key = PhantomCrypto.unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        byte[] nonce = PhantomCrypto.unhex("070000004041424344454647");
        byte[] aad = PhantomCrypto.unhex("50515253c0c1c2c3c4c5c6c7");
        byte[] pt = PhantomCrypto.utf8("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
        ChaCha20Poly1305 cc = new ChaCha20Poly1305();
        cc.init(true, new AEADParameters(new KeyParameter(key), 128, nonce, aad));
        byte[] out = new byte[cc.getOutputSize(pt.length)];
        int off = cc.processBytes(pt, 0, pt.length, out, 0); off += cc.doFinal(out, off);
        kat("ChaCha20-Poly1305 ciphertext||tag == RFC 8439 §2.8.2", out,
                "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
              + "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
              + "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
              + "3ff4def08e4b7a9de576d26586cec64b6116"
              + "1ae10b594f09e26a7e902ecbd0600691");

        // ───── FIPS 204: ML-DSA-65 parameter sizes + deterministic seed expansion ─────
        System.out.println("\n-- FIPS 204 ML-DSA-65 (sizes + deterministic keygen) --");
        byte[] seed = rep(0x00, 32);
        MLDSAPrivateKeyParameters sk1 = new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_65, seed);
        MLDSAPrivateKeyParameters sk2 = new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_65, seed);
        byte[] pk1 = sk1.getPublicKeyParameters().getEncoded();
        ok("ML-DSA-65 public key is 1952 bytes (FIPS 204 parameter set)", pk1.length == 1952);
        byte[] sig = PhantomCrypto.sign(sk1, PhantomCrypto.utf8("FIPS204-KAT"));
        ok("ML-DSA-65 signature is 3309 bytes (FIPS 204 parameter set)", sig.length == 3309);
        ok("ML-DSA-65 keygen from a fixed 32-byte seed is DETERMINISTIC (same pubkey)",
                Arrays.equals(pk1, sk2.getPublicKeyParameters().getEncoded()));
        // byte-level anchor: the FIPS 204 keyGen expansion of the all-zero seed must reproduce exactly.
        // Pins BouncyCastle 1.84's ML-DSA-65 ExpandA/ExpandS output so any change to the primitive is caught.
        kat("ML-DSA-65 SHA3-256(pubkey) of the all-zero-seed key == pinned FIPS 204 keyGen anchor",
                PhantomCrypto.sha3_256(pk1), "b0681bf95c4068feb39a3099dbcc299108cc779dbeed196debdea877074a37aa");
        ok("ML-DSA-65 sign/verify of the seeded key round-trips", PhantomCrypto.verify(sk1.getPublicKeyParameters(), PhantomCrypto.utf8("FIPS204-KAT"), sig));
        System.out.println("  [note] the full NIST ACVP ML-DSA sign byte-KAT (seed,msg->sig fixtures) needs the ACVP vector");
        System.out.println("         files (signing draws randomness); the keyGen above is a deterministic byte anchor.");

        System.out.println("\n==== KnownAnswerTest: " + pass + " passed, " + fail + " failed ====");
        System.exit(fail == 0 ? 0 : 1);
    }
}
