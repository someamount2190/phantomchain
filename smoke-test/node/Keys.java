package com.phantomchain.debug;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;

/**
 * This node's ML-DSA-65 key, persisted as a 32-byte seed in hex. In ML-DSA the seed (xi) IS the
 * private key — the full keypair expands deterministically from it. The seed never leaves this host;
 * only the derived public key (and its sha3-256 id) are published into genesis.
 */
public class Keys {
    public static MLDSAPrivateKeyParameters loadOrCreate(File f) throws Exception {
        byte[] seed;
        if (f.exists()) {
            seed = PhantomCrypto.unhex(new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8).trim());
        } else {
            seed = new byte[32];
            new SecureRandom().nextBytes(seed);
            if (f.getParentFile() != null) f.getParentFile().mkdirs();
            Files.write(f.toPath(), PhantomCrypto.hex(seed).getBytes(StandardCharsets.UTF_8));
        }
        return new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_65, seed);
    }

    public static String pubHex(MLDSAPrivateKeyParameters key) {
        return PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded());
    }
    public static String idOf(MLDSAPrivateKeyParameters key) {
        return PhantomCrypto.hex(PhantomCrypto.sha3_256(key.getPublicKeyParameters().getEncoded()));
    }
}
