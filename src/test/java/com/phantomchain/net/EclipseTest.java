package com.phantomchain.net;

import static com.phantomchain.debug.TestKit.*;

import com.phantomchain.debug.*;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;

/**
 * NETWORK-LAYER adversarial test against a LIVE NetNode: the anti-eclipse defense and the operator-token
 * write gate (gaps not covered by MtlsTest / ReadPeerSplitTest).
 *
 * Eclipse attack: a peer (even a legit cluster member, connected over mTLS) tries to poison another
 * validator's address in the peer table via /announce. The defense is that /announce is SIGNED — the
 * server verifies sig over "announce|cid|index|addr" against VAL_IDS[index]'s key — so no one can spoof
 * another validator's address. We prove a forged-signature announce is dropped while a correctly-signed
 * one is accepted.
 */
public class EclipseTest {


    public static void main(String[] a) throws Exception {
        File base = new File(System.getProperty("java.io.tmpdir"), "pc-eclipse-" + System.nanoTime());
        File data = new File(base, "data"); data.mkdirs();
        File certs = new File(data, "certs"); TlsSetup.ensureCerts(certs, 2);    // cluster CA + node-0/node-1

        // two validators; we hold BOTH keys so we can craft a correctly-signed announce for index 1
        MLDSAPrivateKeyParameters k0 = Keys.loadOrCreate(new File(base, "n0.key"));
        MLDSAPrivateKeyParameters k1 = Keys.loadOrCreate(new File(base, "n1.key"));
        String cid = "pc-eclipse";
        String spec = new JSONObject().put("chainId", cid).put("genesisTime", 1700000000000L)
            .put("validators", new org.json.JSONArray()
                .put(val(k0)).put(val(k1))).toString();
        Genesis gen = Genesis.fromJson(spec);

        int peerPort = freePort(), readPort = freePort();
        NodeConfig cfg = new NodeConfig();
        cfg.rpcPort = peerPort; cfg.readPort = readPort; cfg.selfAddr = "127.0.0.1:" + peerPort;
        cfg.seeds = new java.util.ArrayList<>(java.util.Arrays.asList("127.0.0.1:" + peerPort));
        cfg.dataDir = data.getAbsolutePath(); cfg.keyFile = new File(base, "n0.key").getAbsolutePath(); cfg.certIndex = 0;

        NetNode node = new NetNode(gen, cfg, k0);
        node.boot();
        Thread.sleep(800);   // let listeners bind

        SSLContext member = TlsSetup.context(certs, 1);   // a legit cluster member's client cert (node-1)
        System.out.println("[live NetNode: peer(mTLS) :" + peerPort + ", read :" + readPort + "]");

        // ---- eclipse: forged-signature /announce for index 1 must be dropped ----
        String evil = "10.0.0.66:6666", good = "10.0.0.7:9999";
        get(member, peerPort, "/announce?index=1&addr=" + enc(evil) + "&sig=deadbeefdeadbeef");
        String peersAfterForged = get(member, peerPort, "/peers")[1];
        boolean forgedDropped = !peersAfterForged.contains(evil);
        ok("eclipse: /announce with a FORGED signature does NOT poison the peer table", forgedDropped);

        // ---- control: a correctly-signed /announce for index 1 IS accepted ----
        String sig = PhantomCrypto.hex(PhantomCrypto.sign(k1, PhantomCrypto.utf8("announce|" + cid + "|1|" + good)));
        get(member, peerPort, "/announce?index=1&addr=" + enc(good) + "&sig=" + sig);
        String peersAfterValid = get(member, peerPort, "/peers")[1];
        ok("control: a correctly-signed /announce IS accepted (legit discovery works)", peersAfterValid.contains(good));

        // ---- announce can't be replayed onto the WRONG index (sig bound to index) ----
        // reuse index-1's valid signature but claim index 0 -> must be rejected (sig is over "...|1|...")
        get(member, peerPort, "/announce?index=0&addr=" + enc(good) + "&sig=" + sig);
        String peers0 = get(member, peerPort, "/peers")[1];
        try { JSONObject pj = new JSONObject(peers0); ok("eclipse: a valid sig can't be replayed onto a different index", !good.equals(pj.optString("0", ""))); }
        catch (Exception e) { ok("eclipse: a valid sig can't be replayed onto a different index", !peers0.contains("\"0\":\"" + good)); }

        // ---- operator-token write gate (only meaningful when PC_OP_TOKEN is set) ----
        if (!NetNode.OP_TOKEN.isEmpty()) {
            String noTok = get(member, peerPort, "/submit?to=" + enc(Keys.idOf(k1)) + "&amount=1")[0];
            String wrong = get(member, peerPort, "/submit?to=" + enc(Keys.idOf(k1)) + "&amount=1&token=wrong")[0];
            String[] withTok = get(member, peerPort, "/submit?to=" + enc(Keys.idOf(k1)) + "&amount=1&token=" + enc(NetNode.OP_TOKEN));
            ok("op-token: write endpoint WITHOUT a token is rejected (401)", "401".equals(noTok));
            ok("op-token: write endpoint with a WRONG token is rejected (401)", "401".equals(wrong));
            ok("op-token: write endpoint with the correct token is allowed (200)", "200".equals(withTok[0]));
        } else {
            System.out.println("  [skip] op-token gate not tested (run with PC_OP_TOKEN=<secret> to exercise it)");
        }

        // ---- a read endpoint is reachable on the open read port without any client cert (sanity) ----
        SSLContext noCert; {
            noCert = SSLContext.getInstance("TLSv1.3");
            javax.net.ssl.TrustManagerFactory tmf = javax.net.ssl.TrustManagerFactory.getInstance("PKIX");
            java.security.KeyStore ts = java.security.KeyStore.getInstance("PKCS12");
            try (InputStream in = new java.io.FileInputStream(new File(certs, "truststore.p12"))) { ts.load(in, TlsSetup.PASS); }
            tmf.init(ts);
            noCert.init(new javax.net.ssl.KeyManager[0], tmf.getTrustManagers(), new java.security.SecureRandom());
        }
        ok("read port serves /status without a client cert", "200".equals(get(noCert, readPort, "/status")[0]));
        ok("peer port rejects the same cert-less client (mTLS enforced)", "-1".equals(get(noCert, peerPort, "/status")[0]));

        node.stop();
        System.out.println("\nEclipseTest: " + pass + " passed, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }

}
