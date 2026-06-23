package com.phantomchain.debug;

import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/**
 * Cluster-member contribution service (spec §9: a device contributes to a cluster with explicit
 * biometric consent). After the user biometric-authenticates ("Contribute to cluster"), the wallet's
 * ML-DSA seed is materialized in memory for the session and this on-device server signs block hashes
 * on request. The desktop cluster COORDINATOR collects >=threshold of these member signatures and
 * assembles the cluster's single M-of-N vote — no operator earns; rewards land directly in each
 * member's wallet (this device's account id).
 *
 * Reachable only via `adb forward tcp:<hostport> tcp:8080` (a debug tunnel), never a public surface.
 *   GET /member          -> {"id":..., "pub":...}     (member identity for CLUSTERFORM + rewards)
 *   GET /sign?hash=HEX    -> {"m":id, "sig":hex}       (this device's signature over the block hash)
 *   GET /health          -> {"active":true, "id":...}
 *
 * Runs on a minimal raw-socket HTTP/1.1 loop (no third-party web server) so the same class works on both
 * the JVM and Android — the JDK's com.sun.net.httpserver is not available on Android.
 */
public class ClusterMember {
    static volatile ClusterMember running;
    final MLDSAPrivateKeyParameters key;
    final String id, pub;
    private final ServerSocket server;
    private volatile boolean alive = true;

    ClusterMember(int port, byte[] seed) throws Exception {
        this.key = PhantomCrypto.deviceKeyFromSeed(seed);
        this.pub = PhantomCrypto.pubHex(key);
        this.id = PhantomCrypto.hex(PhantomCrypto.sha3_256(key.getPublicKeyParameters().getEncoded()));
        this.server = new ServerSocket(port);
        Thread t = new Thread(this::acceptLoop, "cluster-member"); t.setDaemon(true); t.start();
    }

    /** Start (or restart) the member service with a freshly biometric-unsealed seed. Returns the member id. */
    static synchronized String start(int port, byte[] seed) throws Exception {
        if (running != null) running.stop();
        ClusterMember m = new ClusterMember(port, seed);
        running = m;
        return m.id;
    }

    void stop() { alive = false; try { server.close(); } catch (Exception e) { /* already closed */ } }

    private void acceptLoop() {
        while (alive) {
            try {
                Socket sock = server.accept();
                new Thread(() -> {
                    try { sock.setSoTimeout(5000); handle(sock); }
                    catch (Exception e) { /* drop a malformed/slow client */ }
                    finally { try { sock.close(); } catch (Exception e) { } }
                }).start();
            } catch (Exception e) { if (!alive) return; }   // accept() throws on stop() closing the socket
        }
    }

    private void handle(Socket sock) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream(), StandardCharsets.UTF_8));
        String reqLine = in.readLine();   // e.g. "GET /sign?hash=abc HTTP/1.1"
        if (reqLine == null) return;
        String[] parts = reqLine.split(" ");
        String target = parts.length > 1 ? parts[1] : "/";
        String path = target, query = "";
        int q = target.indexOf('?');
        if (q >= 0) { path = target.substring(0, q); query = target.substring(q + 1); }
        byte[] body = route(path, query).getBytes(StandardCharsets.UTF_8);
        OutputStream os = sock.getOutputStream();
        os.write(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + body.length
                + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.UTF_8));
        os.write(body);
        os.flush();
    }

    private String route(String path, String query) {
        try {
            if ("/member".equals(path)) return new JSONObject().put("id", id).put("pub", pub).toString();
            if ("/health".equals(path)) return new JSONObject().put("active", true).put("id", id).toString();
            if ("/sign".equals(path)) {
                String hash = param(query, "hash");
                if (hash == null || hash.isEmpty()) return new JSONObject().put("error", "no hash").toString();
                byte[] sig = PhantomCrypto.sign(key, PhantomCrypto.utf8(hash));   // sign exactly what verifyClusterVote checks
                return new JSONObject().put("m", id).put("sig", PhantomCrypto.hex(sig)).put("hash", hash).toString();
            }
            return new JSONObject().put("error", "unknown endpoint").toString();
        } catch (Exception e) {
            return new JSONObject().put("error", String.valueOf(e.getMessage())).toString();
        }
    }

    private static String param(String query, String key) {
        if (query.isEmpty()) return null;
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0 && pair.substring(0, eq).equals(key)) {
                try { return URLDecoder.decode(pair.substring(eq + 1), "UTF-8"); }
                catch (Exception e) { return pair.substring(eq + 1); }
            }
        }
        return null;
    }
}
