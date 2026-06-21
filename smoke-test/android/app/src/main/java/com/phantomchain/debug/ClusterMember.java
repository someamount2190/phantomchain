package com.phantomchain.debug;

import fi.iki.elonen.NanoHTTPD;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;

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
 */
public class ClusterMember extends NanoHTTPD {
    static volatile ClusterMember running;
    final MLDSAPrivateKeyParameters key;
    final String id, pub;

    ClusterMember(int port, byte[] seed) {
        super(port);
        this.key = PhantomCrypto.deviceKeyFromSeed(seed);
        this.pub = PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded());
        this.id = PhantomCrypto.hex(PhantomCrypto.sha3_256(key.getPublicKeyParameters().getEncoded()));
    }

    /** Start (or restart) the member service with a freshly biometric-unsealed seed. Returns the member id. */
    static synchronized String start(int port, byte[] seed) throws Exception {
        if (running != null) running.stop();
        ClusterMember m = new ClusterMember(port, seed);
        m.start(NanoHTTPD.SOCKET_READ_TIMEOUT, false);
        running = m;
        return m.id;
    }

    @Override
    public Response serve(IHTTPSession s) {
        try {
            String uri = s.getUri();
            if ("/member".equals(uri))
                return json(new JSONObject().put("id", id).put("pub", pub));
            if ("/health".equals(uri))
                return json(new JSONObject().put("active", true).put("id", id));
            if ("/sign".equals(uri)) {
                String hash = s.getParms().get("hash");
                if (hash == null || hash.isEmpty()) return json(new JSONObject().put("error", "no hash"));
                byte[] sig = PhantomCrypto.sign(key, PhantomCrypto.utf8(hash));   // sign exactly what verifyClusterVote checks
                return json(new JSONObject().put("m", id).put("sig", PhantomCrypto.hex(sig)).put("hash", hash));
            }
            return newFixedLengthResponse(Response.Status.OK, "application/json", "{\"error\":\"unknown endpoint\"}");
        } catch (Exception e) {
            String msg = String.valueOf(e.getMessage()).replace('"', '\'');
            return newFixedLengthResponse(Response.Status.OK, "application/json", "{\"error\":\"" + msg + "\"}");
        }
    }

    Response json(JSONObject o) { return newFixedLengthResponse(Response.Status.OK, "application/json", o.toString()); }
}
