package com.phantomchain.debug;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
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

/**
 * PhantomChain v0.3 software crypto (debug build) — same library-only constructions
 * validated in the JVM test suite. No StrongBox / biometric here; biometric is
 * simulated in the UI. Primitives: ML-DSA-65, Argon2id, HKDF, ChaCha20-Poly1305, SHA3-256.
 */
public class PhantomCrypto {

    private static final SecureRandom RNG = new SecureRandom();

    // in-memory debug wallet state
    public byte[] recoverySeed;                 // master secret backed up into the QR
    public MLDSAPrivateKeyParameters deviceKey; // per-device hot key (biometric-bound on real hw)
    public byte[] identityId;                   // SHA3-256(identity-root pubkey)

    public static byte[] utf8(String s) { return s.getBytes(StandardCharsets.UTF_8); }

    public static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int len) {
        HKDFBytesGenerator h = new HKDFBytesGenerator(new SHA256Digest());
        h.init(new HKDFParameters(ikm, salt, info));
        byte[] out = new byte[len];
        h.generateBytes(out, 0, len);
        return out;
    }

    public static byte[] argon2id(byte[] pw, byte[] salt) {
        Argon2Parameters p = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withSalt(salt).withMemoryAsKB(65536).withIterations(3).withParallelism(4).build();
        Argon2BytesGenerator g = new Argon2BytesGenerator();
        g.init(p);
        byte[] out = new byte[32];
        g.generateBytes(pw, out);
        return out;
    }

    public static byte[] sha3_256(byte[] in) {
        SHA3Digest d = new SHA3Digest(256);
        d.update(in, 0, in.length);
        byte[] o = new byte[32];
        d.doFinal(o, 0);
        return o;
    }

    /** SHAKE-256 XOF (used for deterministic external-chain address derivation in the bridge). */
    public static byte[] shake256(byte[] in, int outLen) {
        org.bouncycastle.crypto.digests.SHAKEDigest d = new org.bouncycastle.crypto.digests.SHAKEDigest(256);
        d.update(in, 0, in.length);
        byte[] o = new byte[outLen];
        d.doFinal(o, 0, outLen);
        return o;
    }

    /** Native FIPS 204 deterministic KeyGen from a seed (HKDF-domain-separated from the master seed). */
    public static MLDSAPrivateKeyParameters rootFromSeed(byte[] seed32) {
        byte[] ml = hkdf(seed32, null, utf8("phantom-identity-root"), 32);
        return new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_65, ml);
    }

    public static MLDSAPrivateKeyParameters randomDeviceKey() {
        MLDSAKeyPairGenerator g = new MLDSAKeyPairGenerator();
        g.init(new MLDSAKeyGenerationParameters(RNG, MLDSAParameters.ml_dsa_65));
        return (MLDSAPrivateKeyParameters) g.generateKeyPair().getPrivate();
    }

    public static byte[] sign(MLDSAPrivateKeyParameters k, byte[] msg) {
        MLDSASigner s = new MLDSASigner();
        s.init(true, k);
        s.update(msg, 0, msg.length);
        try { return s.generateSignature(); }
        catch (Exception e) { throw new RuntimeException(e); }
    }

    public static boolean verify(MLDSAPublicKeyParameters k, byte[] msg, byte[] sig) {
        MLDSASigner s = new MLDSASigner();
        s.init(false, k);
        s.update(msg, 0, msg.length);
        return s.verifySignature(sig);
    }

    /** enroll: master seed -> deterministic identity-root + a random device key. */
    public String enroll() {
        recoverySeed = new byte[32];
        RNG.nextBytes(recoverySeed);
        MLDSAPrivateKeyParameters root = rootFromSeed(recoverySeed);
        identityId = sha3_256(root.getPublicKeyParameters().getEncoded());
        deviceKey = deviceKeyFromSeed(recoverySeed);
        return hex(identityId);
    }

    /** Deterministic device key (debug: derived from seed so the wallet is restorable;
     *  on real hardware this is the non-exportable StrongBox key instead). */
    public static MLDSAPrivateKeyParameters deviceKeyFromSeed(byte[] seed) {
        byte[] dk = hkdf(seed, null, utf8("phantom-device-key"), 32);
        return new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_65, dk);
    }

    /** Restore a wallet from a persisted recovery seed. */
    public void load(byte[] seed) {
        recoverySeed = seed.clone();
        identityId = sha3_256(rootFromSeed(seed).getPublicKeyParameters().getEncoded());
        deviceKey = deviceKeyFromSeed(seed);
    }

    /** QR blob = salt(16) | nonce(12) | AEAD(recoverySeed) under K = HKDF(Argon2id(pw), meshShare). */
    public static byte[] backup(byte[] recoverySeed, String password, byte[] kMesh) {
        byte[] salt = new byte[16]; RNG.nextBytes(salt);
        byte[] nonce = new byte[12]; RNG.nextBytes(nonce);
        byte[] K = hkdf(argon2id(utf8(password), salt), kMesh, utf8("phantom-recovery-K"), 32);
        byte[] ct = aead(true, K, nonce, recoverySeed);
        byte[] out = new byte[16 + 12 + ct.length];
        System.arraycopy(salt, 0, out, 0, 16);
        System.arraycopy(nonce, 0, out, 16, 12);
        System.arraycopy(ct, 0, out, 28, ct.length);
        return out;
    }

    /** recover: requires correct password AND the mesh share; throws on auth failure. */
    public static byte[] recover(byte[] blob, String password, byte[] kMesh) {
        byte[] salt = Arrays.copyOfRange(blob, 0, 16);
        byte[] nonce = Arrays.copyOfRange(blob, 16, 28);
        byte[] ct = Arrays.copyOfRange(blob, 28, blob.length);
        byte[] K = hkdf(argon2id(utf8(password), salt), kMesh, utf8("phantom-recovery-K"), 32);
        return aead(false, K, nonce, ct);
    }

    public static byte[] aead(boolean enc, byte[] key, byte[] nonce, byte[] in) {
        try {
            ChaCha20Poly1305 c = new ChaCha20Poly1305();
            c.init(enc, new ParametersWithIV(new KeyParameter(key), nonce));
            byte[] out = new byte[c.getOutputSize(in.length)];
            int n = c.processBytes(in, 0, in.length, out, 0);
            n += c.doFinal(out, n);
            return Arrays.copyOf(out, n);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }

    public static byte[] unhex(String s) {
        int n = s.length() / 2;
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return b;
    }

    /** ML-DSA-65 public-key (de)serialization — the single home for the key<->hex conversions that were
     *  inlined across the tx builders, the ledger, and the node. */
    public static String pubHex(MLDSAPrivateKeyParameters key) { return hex(key.getPublicKeyParameters().getEncoded()); }
    public static MLDSAPublicKeyParameters pubKey(String hex) { return new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, unhex(hex)); }

    /** Read a stream fully into a UTF-8 string (the HTTP-response reader shared by the peer client and wallet). */
    public static String readAll(java.io.InputStream is) throws Exception {
        java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream(); byte[] buf = new byte[4096]; int n;
        while ((n = is.read(buf)) > 0) bo.write(buf, 0, n); is.close();
        return new String(bo.toByteArray(), java.nio.charset.StandardCharsets.UTF_8);
    }
}
