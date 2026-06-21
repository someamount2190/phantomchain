package com.phantomchain.debug;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.SecureRandom;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;

/**
 * Self-custodial PhantomChain wallet (the shippable logic the Android app drives):
 *  - an ML-DSA-65 signing key derived deterministically from a 32-byte seed (so the QR restores it);
 *  - a self-sovereign account id = sha3-256(pubkey) — no pre-registration, the node learns the pubkey
 *    from the tx and binds it to the id;
 *  - a CA-pinned TLS 1.3 RPC client to a live node (trusts only the cluster CA);
 *  - a password-encrypted QR backup of the seed (Argon2id + HKDF + ChaCha20-Poly1305).
 * On Android the signing key sits behind a Keystore-gated, biometric-unlocked secret; here it is in memory.
 */
public class Wallet {
    final byte[] seed;
    final MLDSAPrivateKeyParameters key;
    public final String id;
    final String node;
    final SSLContext tls;

    public Wallet(byte[] seed, String node, SSLContext tls) {
        this.seed = seed.clone();
        this.key = PhantomCrypto.deviceKeyFromSeed(seed);
        this.id = PhantomCrypto.hex(PhantomCrypto.sha3_256(key.getPublicKeyParameters().getEncoded()));
        this.node = node; this.tls = tls;
    }

    public static byte[] newSeed() { byte[] s = new byte[32]; new SecureRandom().nextBytes(s); return s; }

    String cid;   // chain id, fetched once from /genesis and cached

    public JSONObject account() throws Exception { return new JSONObject(get("/account?id=" + id).trim()); }
    public long balance() throws Exception { return account().getLong("balance"); }
    public long nonce() throws Exception { return account().getLong("nonce"); }
    public String chainId() throws Exception {
        if (cid == null) cid = new JSONObject(get("/genesis").trim()).getString("chainId");
        return cid;
    }

    /** Build, sign, and submit a transfer; the tx carries our pubkey so the node can bind id==sha3(pub),
     *  and the chain id so the signature is not replayable on another chain. */
    public String send(String to, long amount, long fee) throws Exception {
        long nonce = nonce();
        String c = chainId();
        byte[] sig = PhantomCrypto.sign(key, PhantomCrypto.utf8(Ledger.txCanon(c, id, to, amount, fee, nonce)));
        JSONObject tx = new JSONObject().put("from", id).put("to", to).put("amount", amount).put("cid", c)
                .put("fee", fee).put("nonce", nonce)
                .put("pub", PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded()))
                .put("sig", PhantomCrypto.hex(sig));
        return post("/gossip/tx", tx.toString()).trim();
    }

    public byte[] backupBlob(String password) { return PhantomCrypto.backup(seed, password, new byte[0]); }
    public static byte[] recoverSeed(byte[] blob, String password) { return PhantomCrypto.recover(blob, password, new byte[0]); }

    // ---- CA-pinned TLS RPC ----
    public static SSLContext tlsTrusting(File truststore, char[] pass) throws Exception {
        KeyStore trust = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(truststore.toPath())) { trust.load(in, pass); }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX"); tmf.init(trust);
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(null, tmf.getTrustManagers(), new SecureRandom());
        return ctx;
    }

    HttpsURLConnection conn(String path) throws Exception {
        HttpsURLConnection c = (HttpsURLConnection) new java.net.URL("https://" + node + path).openConnection();
        c.setSSLSocketFactory(tls.getSocketFactory());
        c.setHostnameVerifier((h, s) -> true);   // trust is via the pinned cluster CA, not hostname
        c.setConnectTimeout(8000); c.setReadTimeout(8000);
        return c;
    }
    String get(String path) throws Exception {
        HttpsURLConnection c = conn(path);
        try { return readAll(c.getInputStream()); } finally { c.disconnect(); }
    }
    String post(String path, String body) throws Exception {
        HttpsURLConnection c = conn(path);
        c.setRequestMethod("POST"); c.setDoOutput(true);
        c.setRequestProperty("Content-Type", "application/json");
        c.getOutputStream().write(body.getBytes(StandardCharsets.UTF_8));
        try { return readAll(c.getInputStream()); } finally { c.disconnect(); }
    }
    public static String rpcGet(String node, SSLContext tls, String path) throws Exception {
        HttpsURLConnection c = (HttpsURLConnection) new java.net.URL("https://" + node + path).openConnection();
        c.setSSLSocketFactory(tls.getSocketFactory()); c.setHostnameVerifier((h, s) -> true);
        c.setConnectTimeout(8000); c.setReadTimeout(8000);
        try { return readAll(c.getInputStream()); } finally { c.disconnect(); }
    }
    public static String rpcPost(String node, SSLContext tls, String path, String body) throws Exception {
        HttpsURLConnection c = (HttpsURLConnection) new java.net.URL("https://" + node + path).openConnection();
        c.setSSLSocketFactory(tls.getSocketFactory()); c.setHostnameVerifier((h, s) -> true);
        c.setConnectTimeout(8000); c.setReadTimeout(8000);
        c.setRequestMethod("POST"); c.setDoOutput(true); c.setRequestProperty("Content-Type", "application/json");
        c.getOutputStream().write(body.getBytes(StandardCharsets.UTF_8));
        try { return readAll(c.getInputStream()); }
        catch (java.io.IOException e) { java.io.InputStream es = c.getErrorStream(); if (es != null) return "HTTP" + c.getResponseCode() + ":" + readAll(es); throw e; }
        finally { c.disconnect(); }
    }

    static String readAll(InputStream is) throws Exception {
        ByteArrayOutputStream bo = new ByteArrayOutputStream(); byte[] buf = new byte[4096]; int n;
        while ((n = is.read(buf)) > 0) bo.write(buf, 0, n); is.close();
        return new String(bo.toByteArray(), StandardCharsets.UTF_8);
    }
}
