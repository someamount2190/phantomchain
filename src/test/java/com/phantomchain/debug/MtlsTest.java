package com.phantomchain.debug;

import java.io.File;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.URL;
import java.security.KeyStore;
import java.security.SecureRandom;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.TrustManagerFactory;

import fi.iki.elonen.NanoHTTPD;

/**
 * mTLS enforcement test (ARCHITECTURE §6 documented next hardening). Spins up the real NanoHTTPD server
 * (the production class NetNode extends) using the mTLS server-socket override, then proves against the
 * cluster CA that a valid node-cert peer is accepted (200) while a no-cert peer and a foreign-CA peer are
 * rejected. NanoHTTPD 2.3.1's makeSecure() path hard-resets needClientAuth=false in
 * SecureServerSocketFactory.create() (verified in the bytecode), so mTLS is wired by overriding
 * getServerSocketFactory() — the same override NetNode uses in production.
 */
public class MtlsTest {
    static int pass = 0, fail = 0;
    static void ok(String n, boolean c) { if (c) { pass++; System.out.println("  PASS " + n); } else { fail++; System.out.println("  ** FAIL ** " + n); } }

    /** GET https://127.0.0.1:port/x with the given client SSLContext; true iff it returns 200. */
    static boolean get(SSLContext c, int port) {
        HttpsURLConnection con = null;
        try {
            con = (HttpsURLConnection) new URL("https://127.0.0.1:" + port + "/x").openConnection();
            con.setSSLSocketFactory(c.getSocketFactory());
            con.setHostnameVerifier((h, s) -> true);     // trust is via the cluster CA, not hostname
            con.setConnectTimeout(4000);
            con.setReadTimeout(4000);
            int code = con.getResponseCode();
            try (InputStream in = con.getInputStream()) { while (in.read() >= 0) ; }
            return code == 200;
        } catch (Exception e) {
            return false;   // handshake failure / connection reset => rejected
        } finally {
            if (con != null) con.disconnect();
        }
    }

    static TrustManagerFactory clusterTmf(File dir) throws Exception {
        KeyStore trust = KeyStore.getInstance("PKCS12");
        try (java.io.InputStream in = new java.io.FileInputStream(new File(dir, "truststore.p12"))) { trust.load(in, TlsSetup.PASS); }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX"); tmf.init(trust);
        return tmf;
    }

    static int freePort() throws Exception { try (ServerSocket s = new ServerSocket(0)) { return s.getLocalPort(); } }

    public static void main(String[] a) throws Exception {
        File base = new File(System.getProperty("java.io.tmpdir"), "pc-mtls-" + System.nanoTime());
        File cluster = new File(base, "cluster");
        TlsSetup.ensureCerts(cluster, 3);                 // cluster CA + node-0/1/2 certs

        // client SSLContext with NO client cert (empty KeyManagers) but trusting the cluster CA
        SSLContext noCert = SSLContext.getInstance("TLSv1.3");
        noCert.init(new KeyManager[0], clusterTmf(cluster).getTrustManagers(), new SecureRandom());

        // foreign CA + a cert signed by it (different trust boundary)
        File foreign = new File(base, "foreign");
        TlsSetup.ensureCerts(foreign, 1);
        KeyStore fks = KeyStore.getInstance("PKCS12");
        try (java.io.InputStream in = new java.io.FileInputStream(new File(foreign, "node-0.p12"))) { fks.load(in, TlsSetup.PASS); }
        KeyManagerFactory fkmf = KeyManagerFactory.getInstance("PKIX"); fkmf.init(fks, TlsSetup.PASS);
        // foreign client PRESENTS its foreign cert but TRUSTS the cluster CA (isolates the server-side client-cert check)
        SSLContext foreignClient = SSLContext.getInstance("TLSv1.3");
        foreignClient.init(fkmf.getKeyManagers(), clusterTmf(cluster).getTrustManagers(), new SecureRandom());

        int port = freePort();
        final SSLContext serverCtx = TlsSetup.context(cluster, 0);          // server presents node-0 cert, trusts cluster CA
        NanoHTTPD srv = new NanoHTTPD(port) {
            @Override public Response serve(IHTTPSession session) { return newFixedLengthResponse("ok"); }
            @Override public fi.iki.elonen.NanoHTTPD.ServerSocketFactory getServerSocketFactory() {   // mTLS via override (makeSecure resets it)
                return () -> {
                    SSLServerSocket ss = (SSLServerSocket) serverCtx.getServerSocketFactory().createServerSocket();
                    ss.setNeedClientAuth(true);
                    ss.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
                    return ss;
                };
            }
        };
        srv.start(NanoHTTPD.SOCKET_READ_TIMEOUT, false);
        Thread.sleep(400);                                                 // let the listener bind

        System.out.println("[mTLS enforcement, NanoHTTPD server on :" + port + "]");
        ok("peer with a valid node cert (node-1) is accepted (200)", get(TlsSetup.context(cluster, 1), port));
        ok("peer with a valid node cert (node-2) is accepted (200)", get(TlsSetup.context(cluster, 2), port));
        ok("peer with NO client cert is rejected (client auth required)", !get(noCert, port));
        ok("peer with a FOREIGN-CA client cert is rejected (not in the cluster trust set)", !get(foreignClient, port));

        srv.stop();
        System.out.println("\nMtlsTest: " + pass + " passed, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }
}
