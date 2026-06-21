package com.phantomchain.debug;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Hardware-backed, biometric-gated key wrapper. An AES-256-GCM key lives in the AndroidKeyStore
 * (StrongBox/TEE where available) and requires a fresh biometric authentication for every use
 * (validity = -1 / AUTH_BIOMETRIC_STRONG). The wallet's 32-byte ML-DSA seed is sealed under this key,
 * so the seed only becomes usable after BiometricPrompt succeeds against a bound CryptoObject.
 * This is the design's "biometric-bound hardware key": the biometric and the key are one.
 */
public class BioKeystore {
    static final String ALIAS = "phantom_wallet_seal";
    static final String AKS = "AndroidKeyStore";
    static final String XFORM = "AES/GCM/NoPadding";

    static SecretKey getOrCreate() throws Exception { return getOrCreate(true); }

    /** auth=true: per-use biometric-gated key (real devices). auth=false: a non-gated key under a separate
     *  alias, used ONLY on a device with no biometric enrolled (e.g. a headless emulator) so the demo can
     *  run with simulated consent. The seal is opened with the same variant it was created with. */
    static SecretKey getOrCreate(boolean auth) throws Exception {
        String alias = auth ? ALIAS : ALIAS + "_sim";
        KeyStore ks = KeyStore.getInstance(AKS); ks.load(null);
        if (ks.containsAlias(alias)) return (SecretKey) ks.getKey(alias, null);
        KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, AKS);
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256);
        if (auth) {
            b.setUserAuthenticationRequired(true).setInvalidatedByBiometricEnrollment(true);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
                b.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG);  // per-use biometric
            else
                b.setUserAuthenticationValidityDurationSeconds(-1);
        }
        kg.init(b.build());
        return kg.generateKey();
    }

    static Cipher encryptCipher() throws Exception { return encryptCipher(true); }
    static Cipher decryptCipher(byte[] iv) throws Exception { return decryptCipher(iv, true); }

    /** Cipher for sealing the seed — bind to a BiometricPrompt CryptoObject, then doFinal(seed). */
    static Cipher encryptCipher(boolean auth) throws Exception {
        Cipher c = Cipher.getInstance(XFORM);
        c.init(Cipher.ENCRYPT_MODE, getOrCreate(auth));
        return c;
    }

    /** Cipher for opening the sealed seed — bind to a BiometricPrompt CryptoObject, then doFinal(ct). */
    static Cipher decryptCipher(byte[] iv, boolean auth) throws Exception {
        Cipher c = Cipher.getInstance(XFORM);
        c.init(Cipher.DECRYPT_MODE, getOrCreate(auth), new GCMParameterSpec(128, iv));
        return c;
    }
}
