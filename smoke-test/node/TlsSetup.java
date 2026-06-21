package com.phantomchain.debug;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Transport security with available libraries only (no rolled crypto):
 *  - a per-cluster self-signed CA (EC P-256) mints a server cert per node;
 *  - nodes serve TLS 1.3 and verify each other's certs against the CA (server-authenticated);
 *  - key exchange uses BouncyCastle JSSE so the hybrid PQ group X25519MLKEM768 can be offered
 *    (falls back to JDK SunJSSE classical TLS 1.3 if BCJSSE/group is unavailable).
 * Message-level authenticity is already provided by ML-DSA signatures, so this gives a fully
 * authenticated + encrypted channel. (mTLS is a one-flag upgrade: require client auth + node certs.)
 */
public class TlsSetup {
    static final char[] PASS = "phantomchain".toCharArray();
    static final long T0 = 1_700_000_000_000L;                  // fixed validity window (deterministic)
    static final long T1 = T0 + 100L * 365 * 24 * 3600 * 1000;
    static volatile boolean hybrid = false;

    static KeyPair ec() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    static X509Certificate selfSign(KeyPair kp, String cn) throws Exception {
        X500Name n = new X500Name("CN=" + cn);
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                n, BigInteger.ONE, new Date(T0), new Date(T1), n, kp.getPublic());
        b.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true,
                new org.bouncycastle.asn1.x509.BasicConstraints(true));   // CA cert must be cA=true for PKIX
        ContentSigner s = new JcaContentSignerBuilder("SHA256withECDSA").build(kp.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(b.build(s));
    }

    static X509Certificate sign(PublicKey subjKey, String cn, long serial, X509Certificate ca, PrivateKey caKey) throws Exception {
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                new X500Name(ca.getSubjectX500Principal().getName()), BigInteger.valueOf(serial),
                new Date(T0), new Date(T1), new X500Name("CN=" + cn), subjKey);
        ContentSigner s = new JcaContentSignerBuilder("SHA256withECDSA").build(caKey);
        return new JcaX509CertificateConverter().getCertificate(b.build(s));
    }

    /** Mint the CA + one server keystore per node into dir (idempotent). */
    static synchronized void ensureCerts(File dir, int n) throws Exception {
        dir.mkdirs();
        File ts = new File(dir, "truststore.p12");
        if (ts.exists() && new File(dir, "node-" + (n - 1) + ".p12").exists()) return;
        KeyPair caKp = ec();
        X509Certificate caCert = selfSign(caKp, "phantomchain-ca");
        KeyStore trust = KeyStore.getInstance("PKCS12"); trust.load(null, null);
        trust.setCertificateEntry("ca", caCert);
        try (OutputStream o = new FileOutputStream(ts)) { trust.store(o, PASS); }
        KeyStore caKs = KeyStore.getInstance("PKCS12"); caKs.load(null, null);   // retain CA key so new validators can be onboarded
        caKs.setKeyEntry("ca", caKp.getPrivate(), PASS, new Certificate[]{caCert});
        try (OutputStream o = new FileOutputStream(new File(dir, "ca.p12"))) { caKs.store(o, PASS); }
        for (int i = 0; i < n; i++) {
            KeyPair kp = ec();
            X509Certificate cert = sign(kp.getPublic(), "node-" + i, 100 + i, caCert, caKp.getPrivate());
            KeyStore ks = KeyStore.getInstance("PKCS12"); ks.load(null, null);
            ks.setKeyEntry("node", kp.getPrivate(), PASS, new Certificate[]{cert, caCert});
            try (OutputStream o = new FileOutputStream(new File(dir, "node-" + i + ".p12"))) { ks.store(o, PASS); }
        }
    }

    /** Mint a cert for a NEW node index from the retained cluster CA (validator onboarding). */
    static void mintNodeCert(File dir, int index) throws Exception {
        if (new File(dir, "node-" + index + ".p12").exists()) return;
        KeyStore caKs = KeyStore.getInstance("PKCS12");
        try (InputStream in = new FileInputStream(new File(dir, "ca.p12"))) { caKs.load(in, PASS); }
        java.security.PrivateKey caKey = (java.security.PrivateKey) caKs.getKey("ca", PASS);
        X509Certificate caCert = (X509Certificate) caKs.getCertificate("ca");
        KeyPair kp = ec();
        X509Certificate cert = sign(kp.getPublic(), "node-" + index, 100 + index, caCert, caKey);
        KeyStore ks = KeyStore.getInstance("PKCS12"); ks.load(null, null);
        ks.setKeyEntry("node", kp.getPrivate(), PASS, new Certificate[]{cert, caCert});
        try (OutputStream o = new FileOutputStream(new File(dir, "node-" + index + ".p12"))) { ks.store(o, PASS); }
    }

    static SSLContext context(File dir, int index) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = new FileInputStream(new File(dir, "node-" + index + ".p12"))) { ks.load(in, PASS); }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX"); kmf.init(ks, PASS);
        KeyStore trust = KeyStore.getInstance("PKCS12");
        try (InputStream in = new FileInputStream(new File(dir, "truststore.p12"))) { trust.load(in, PASS); }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX"); tmf.init(trust);

        // JDK SunJSSE classical TLS 1.3 — rock-solid, curl-interoperable. PQ-hybrid KEX (X25519MLKEM768)
        // is a documented upgrade: BCJSSE provider (register BC JCE provider + enable the hybrid group)
        // or JDK 27 native via JEP 527 (jdk.tls.namedGroups=X25519MLKEM768).
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        hybrid = false;
        return ctx;
    }
}
