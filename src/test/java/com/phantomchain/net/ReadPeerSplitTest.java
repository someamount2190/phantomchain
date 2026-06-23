package com.phantomchain.net;

import static com.phantomchain.debug.TestKit.*;

import com.phantomchain.debug.*;

import java.io.File;
import java.net.ServerSocket;
import java.net.URL;
import java.security.KeyStore;
import java.security.SecureRandom;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * Verifies the read/peer port split that resolves the mTLS design tension: the OPEN read port
 * (server-auth TLS, no client cert) serves only the read-only allowlist; the PEER port (mTLS) requires a
 * client cert and serves everything. Built on the production NodeHttpServer (JDK HttpsServer wrapper) with
 * the real NetNode.READ_ENDPOINTS allowlist.
 */
public class ReadPeerSplitTest {

    /** HTTP status code, or -1 on TLS/transport failure (handshake rejected). */
    static int code(SSLContext c, int port, String path) {
        HttpsURLConnection con = null;
        try {
            con = (HttpsURLConnection) new URL("https://127.0.0.1:" + port + path).openConnection();
            con.setSSLSocketFactory(c.getSocketFactory());
            con.setHostnameVerifier((h, s) -> true);
            con.setConnectTimeout(4000);
            con.setReadTimeout(4000);
            return con.getResponseCode();
        } catch (Exception e) { return -1; }
        finally { if (con != null) con.disconnect(); }
    }


    public static void main(String[] a) throws Exception {
        File dir = new File(System.getProperty("java.io.tmpdir"), "pc-split-" + System.nanoTime());
        TlsSetup.ensureCerts(dir, 2);
        final SSLContext serverCtx = TlsSetup.context(dir, 0);

        // no-cert client (trusts the cluster CA so it can still reach the server-auth read port)
        KeyStore trust = KeyStore.getInstance("PKCS12");
        try (java.io.InputStream in = new java.io.FileInputStream(new File(dir, "truststore.p12"))) { trust.load(in, TlsSetup.PASS); }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX"); tmf.init(trust);
        SSLContext noCert = SSLContext.getInstance("TLSv1.3");
        noCert.init(new KeyManager[0], tmf.getTrustManagers(), new SecureRandom());
        SSLContext validCert = TlsSetup.context(dir, 1);

        int peer = freePort(), read = freePort();

        // PEER server: mTLS (client cert REQUIRED), full access
        NodeHttpServer peerSrv = new NodeHttpServer(peer, serverCtx, true, req -> new Resp(200, "ok"));
        peerSrv.start();

        // READ server: server-auth only (NO client cert), allowlisted to NetNode.READ_ENDPOINTS
        NodeHttpServer readSrv = new NodeHttpServer(read, serverCtx, false,
                req -> NetNode.READ_ENDPOINTS.contains(req.uri) ? new Resp(200, "ok") : new Resp(403, "forbidden\n"));
        readSrv.start();
        Thread.sleep(400);

        System.out.println("[read/peer split — peer=:" + peer + " (mTLS), read=:" + read + " (open)]");
        ok("open read port serves a read endpoint WITHOUT a client cert (200)", code(noCert, read, "/status") == 200);
        ok("open read port BLOCKS a write endpoint (403)", code(noCert, read, "/submit") == 403);
        ok("peer port REJECTS a no-cert client (mTLS enforced, -1)", code(noCert, peer, "/status") == -1);
        ok("peer port serves a read endpoint to a cert client (200)", code(validCert, peer, "/status") == 200);
        ok("peer port serves a WRITE endpoint to a cert client (200)", code(validCert, peer, "/submit") == 200);
        ok("read port also serves a cert client (200)", code(validCert, read, "/head") == 200);

        peerSrv.stop(); readSrv.stop();
        System.out.println("\nReadPeerSplitTest: " + pass + " passed, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }
}
