import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

/**
 * PhantomChain v0.3 crypto smoke test (Android-runtime / JVM half).
 * Validates the post-quantum + recovery cryptography the spec assumes.
 *
 * No hand-rolled crypto: every primitive AND construction is a standard
 * library call (BouncyCastle 1.84) —
 *   ML-DSA-65 (FIPS 204), ML-KEM-1024 (FIPS 203), Argon2id (RFC 9106),
 *   HKDF (RFC 5869), ChaCha20-Poly1305 (RFC 8439).
 * Deterministic identity-root keygen uses ML-DSA's native seed constructor
 * (FIPS 204 KeyGen(seed)), not a custom RNG.
 *
 * Hardware parts (StrongBox sealing, BiometricPrompt) are NOT exercised here —
 * they need a physical device and are delivered as an instrumented test.
 */
public class PhantomSmoke {

    static int pass = 0, fail = 0;
    static void check(String name, boolean ok) {
        System.out.printf("  [%s] %s%n", ok ? "PASS" : "FAIL", name);
        if (ok) pass++; else fail++;
    }
    static void section(String s) { System.out.println("\n== " + s + " =="); }
    static byte[] utf8(String s) { return s.getBytes(StandardCharsets.UTF_8); }

    // ---- HKDF (RFC 5869) — standard extract-and-expand KDF ----
    static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int len) {
        HKDFBytesGenerator h = new HKDFBytesGenerator(new SHA256Digest());
        h.init(new HKDFParameters(ikm, salt, info));
        byte[] out = new byte[len];
        h.generateBytes(out, 0, len);
        return out;
    }

    // ---- Argon2id (RFC 9106) — memory-hard password KDF ----
    static byte[] argon2id(byte[] password, byte[] salt) {
        Argon2Parameters p = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withSalt(salt).withMemoryAsKB(65536).withIterations(3).withParallelism(4).build();
        Argon2BytesGenerator g = new Argon2BytesGenerator();
        g.init(p);
        byte[] out = new byte[32];
        g.generateBytes(password, out);
        return out;
    }

    // ---- ML-DSA-65 (Dilithium-3) ----
    static AsymmetricCipherKeyPair mldsaRandomKeyPair(SecureRandom rnd) {
        MLDSAKeyPairGenerator g = new MLDSAKeyPairGenerator();
        g.init(new MLDSAKeyGenerationParameters(rnd, MLDSAParameters.ml_dsa_65));
        return g.generateKeyPair();
    }
    /** Native FIPS 204 deterministic KeyGen from a 32-byte seed. */
    static MLDSAPrivateKeyParameters mldsaFromSeed(byte[] seed32) {
        return new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_65, seed32);
    }
    static byte[] mldsaSign(MLDSAPrivateKeyParameters priv, byte[] msg) throws Exception {
        MLDSASigner s = new MLDSASigner();
        s.init(true, priv);
        s.update(msg, 0, msg.length);
        return s.generateSignature();
    }
    static boolean mldsaVerify(MLDSAPublicKeyParameters pub, byte[] msg, byte[] sig) {
        MLDSASigner s = new MLDSASigner();
        s.init(false, pub);
        s.update(msg, 0, msg.length);
        return s.verifySignature(sig);
    }

    // ---- ChaCha20-Poly1305 AEAD (spec's XChaCha20-Poly1305 is the same primitive, 24-byte nonce) ----
    static byte[] aeadSeal(byte[] key, byte[] nonce12, byte[] pt) throws Exception {
        ChaCha20Poly1305 c = new ChaCha20Poly1305();
        c.init(true, new ParametersWithIV(new KeyParameter(key), nonce12));
        byte[] out = new byte[c.getOutputSize(pt.length)];
        int n = c.processBytes(pt, 0, pt.length, out, 0);
        c.doFinal(out, n);
        return out;
    }
    static byte[] aeadOpen(byte[] key, byte[] nonce12, byte[] ct) throws Exception {
        ChaCha20Poly1305 c = new ChaCha20Poly1305();
        c.init(false, new ParametersWithIV(new KeyParameter(key), nonce12));
        byte[] out = new byte[c.getOutputSize(ct.length)];
        int n = c.processBytes(ct, 0, ct.length, out, 0);
        n += c.doFinal(out, n);
        return Arrays.copyOf(out, n);
    }

    public static void main(String[] args) throws Exception {
        SecureRandom sr = new SecureRandom();
        System.out.println("PhantomChain v0.3 crypto smoke test  (BouncyCastle "
                + org.bouncycastle.crypto.CryptoServicesRegistrar.class.getPackage().getImplementationVersion() + ")");

        // 1. ML-DSA-65 device-key sign/verify
        section("1. ML-DSA-65 (Dilithium-3) — device & identity-root signing");
        AsymmetricCipherKeyPair kp = mldsaRandomKeyPair(sr);
        MLDSAPublicKeyParameters pub = (MLDSAPublicKeyParameters) kp.getPublic();
        MLDSAPrivateKeyParameters priv = (MLDSAPrivateKeyParameters) kp.getPrivate();
        byte[] tx = utf8("rotation: bind device_key_2, revoke device_key_1");
        byte[] sig = mldsaSign(priv, tx);
        check("keygen", pub.getEncoded().length > 0);
        check("sign + verify (valid)", mldsaVerify(pub, tx, sig));
        byte[] tampered = tx.clone(); tampered[0] ^= 0x01;
        check("verify rejects tampered message", !mldsaVerify(pub, tampered, sig));
        System.out.printf("     pubkey=%d B  signature=%d B%n", pub.getEncoded().length, sig.length);

        // 2. ML-KEM-1024 recovery/mesh envelope
        section("2. ML-KEM-1024 (Kyber) — recovery envelope / mesh share transport");
        MLKEMKeyPairGenerator kg = new MLKEMKeyPairGenerator();
        kg.init(new MLKEMKeyGenerationParameters(sr, MLKEMParameters.ml_kem_1024));
        AsymmetricCipherKeyPair kkp = kg.generateKeyPair();
        MLKEMGenerator gen = new MLKEMGenerator(sr);
        SecretWithEncapsulation enc = gen.generateEncapsulated((MLKEMPublicKeyParameters) kkp.getPublic());
        byte[] secretB = new MLKEMExtractor((MLKEMPrivateKeyParameters) kkp.getPrivate())
                .extractSecret(enc.getEncapsulation());
        check("encapsulated secret == decapsulated secret", Arrays.equals(enc.getSecret(), secretB));
        System.out.printf("     encapsulation=%d B  shared_secret=%d B%n",
                enc.getEncapsulation().length, enc.getSecret().length);

        // 3. QR recovery envelope: Argon2id(password) + mesh share --HKDF--> K --AEAD--> seal the recovery seed
        section("3. QR recovery envelope — Argon2id + HKDF(mesh share) + AEAD (cold path)");
        byte[] recoverySeed = new byte[32]; sr.nextBytes(recoverySeed);   // secret backed up in the QR
        byte[] salt = new byte[16]; sr.nextBytes(salt);
        byte[] kMesh = new byte[32]; sr.nextBytes(kMesh);                 // simulated anchor-mesh share
        byte[] nonce = new byte[12]; sr.nextBytes(nonce);
        byte[] info = utf8("phantom-recovery-K");
        String password = "correct horse battery staple 9!";

        byte[] kPw = argon2id(utf8(password), salt);
        byte[] K = hkdf(kPw, kMesh, info, 32);                            // HKDF: IKM=kPw, salt=mesh share
        byte[] qrCipher = aeadSeal(K, nonce, recoverySeed);
        System.out.printf("     QR ciphertext payload = %d B  (fits a single static QR <= ~2900 B)%n", qrCipher.length);

        byte[] recovered = aeadOpen(hkdf(argon2id(utf8(password), salt), kMesh, info, 32), nonce, qrCipher);
        check("recovers seed with password + mesh share", Arrays.equals(recovered, recoverySeed));

        boolean wrongPwFails;
        try { aeadOpen(hkdf(argon2id(utf8("wrong password"), salt), kMesh, info, 32), nonce, qrCipher); wrongPwFails = false; }
        catch (Exception e) { wrongPwFails = true; }
        check("wrong password -> decryption fails (auth tag)", wrongPwFails);

        boolean noMeshFails;
        try { aeadOpen(hkdf(kPw, new byte[32], info, 32), nonce, qrCipher); noMeshFails = false; }
        catch (Exception e) { noMeshFails = true; }
        check("captured QR + password but NO mesh share -> useless", noMeshFails);

        // 4. Deterministic identity-root derivation from the recovered seed (§8.2) — native ML-DSA seed KeyGen
        section("4. Deterministic identity-root derivation (same seed -> same key)");
        byte[] rootSeedA = hkdf(recovered, null, utf8("phantom-identity-root"), 32);
        byte[] rootSeedB = hkdf(recovered, null, utf8("phantom-identity-root"), 32);
        MLDSAPrivateKeyParameters root1 = mldsaFromSeed(rootSeedA);
        MLDSAPrivateKeyParameters root2 = mldsaFromSeed(rootSeedB);
        byte[] rootPub1 = root1.getPublicKeyParameters().getEncoded();
        byte[] rootPub2 = root2.getPublicKeyParameters().getEncoded();
        check("two derivations from same seed -> identical identity-root pubkey", Arrays.equals(rootPub1, rootPub2));

        byte[] otherSeed = recovered.clone(); otherSeed[0] ^= 0x01;
        byte[] rootPub3 = mldsaFromSeed(hkdf(otherSeed, null, utf8("phantom-identity-root"), 32))
                .getPublicKeyParameters().getEncoded();
        check("different seed -> different identity-root pubkey", !Arrays.equals(rootPub1, rootPub3));

        byte[] rotSig = mldsaSign(root1, tx);
        check("identity-root signs rotation tx -> verifies", mldsaVerify(root1.getPublicKeyParameters(), tx, rotSig));

        System.out.printf("%n== RESULT: %d passed, %d failed ==%n", pass, fail);
        if (fail > 0) System.exit(1);
    }
}
