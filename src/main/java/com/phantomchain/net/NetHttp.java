package com.phantomchain.net;

import com.phantomchain.debug.PhantomCrypto;

import java.nio.charset.StandardCharsets;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

/**
 * Peer HTTP client over the cluster TLS — extracted from {@link NetNode}.
 *
 * Short-timeout GET/POST to a peer, trusting the per-cluster CA (not the hostname, since peers are
 * addressed by ip:port). Returns null on any failure (callers treat a peer as unavailable). {@link NetNode}
 * keeps thin {@code httpGet}/{@code httpPost} delegators so the consensus/gossip/sync call sites are unchanged.
 */
final class NetHttp {
    private NetHttp() {}

    static HttpsURLConnection conn(SSLContext tls, String addr, String path) throws Exception {
        HttpsURLConnection c = (HttpsURLConnection) new java.net.URL("https://" + addr + path).openConnection();
        c.setSSLSocketFactory(tls.getSocketFactory());
        c.setHostnameVerifier((h, s) -> true);   // trust is via the cluster CA, not hostname
        c.setConnectTimeout(3000); c.setReadTimeout(3000);
        return c;
    }

    static String post(SSLContext tls, String addr, String path, String body) {
        HttpsURLConnection c = null;
        try {
            c = conn(tls, addr, path);
            c.setRequestMethod("POST"); c.setDoOutput(true);
            c.setRequestProperty("Content-Type", "application/json");
            c.getOutputStream().write(body.getBytes(StandardCharsets.UTF_8)); c.getOutputStream().flush();
            return PhantomCrypto.readAll(c.getInputStream());
        } catch (Exception e) { return null; } finally { if (c != null) c.disconnect(); }
    }

    static String get(SSLContext tls, String addr, String path) {
        HttpsURLConnection c = null;
        try {
            c = conn(tls, addr, path);
            return PhantomCrypto.readAll(c.getInputStream());
        } catch (Exception e) { return null; } finally { if (c != null) c.disconnect(); }
    }

}
