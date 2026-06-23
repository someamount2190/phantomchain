package com.phantomchain.debug;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.URL;
import java.net.URLEncoder;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;

/**
 * Shared test harness — the assertion counters and the socket/HTTP boilerplate that were copy-pasted
 * across the suites. Each {@code *Test}/{@code *Sim} runs as its own {@code main()} in its own JVM (the
 * Gradle runner spawns one per suite), so the static counters are fresh per run. Use via
 * {@code import static com.phantomchain.debug.TestKit.*;}.
 */
public final class TestKit {
    private TestKit() {}

    public static int pass = 0, fail = 0;

    /** Record a check; prints "PASS"/"** FAIL **" so the per-suite tally lines up with the CI runner. */
    public static void ok(String n, boolean c) {
        if (c) { pass++; System.out.println("  PASS " + n); }
        else { fail++; System.out.println("  ** FAIL ** " + n); }
    }

    /** A free ephemeral TCP port (for in-process node listeners). */
    public static int freePort() throws Exception { try (ServerSocket s = new ServerSocket(0)) { return s.getLocalPort(); } }

    public static String enc(String s) throws Exception { return URLEncoder.encode(s, "UTF-8"); }

    /** GET/POST over the given client SSLContext; returns {httpCode, body} (code "-1" on handshake/connect failure). */
    public static String[] req(SSLContext ctx, String method, int port, String path, String reqBody) {
        HttpsURLConnection c = null;
        try {
            c = (HttpsURLConnection) new URL("https://127.0.0.1:" + port + path).openConnection();
            c.setSSLSocketFactory(ctx.getSocketFactory());
            c.setHostnameVerifier((h, s) -> true);
            c.setConnectTimeout(5000); c.setReadTimeout(5000);
            c.setRequestMethod(method);
            if (reqBody != null) {
                c.setDoOutput(true);
                c.setRequestProperty("Content-Type", "application/json");
                c.getOutputStream().write(reqBody.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }
            int code = c.getResponseCode();
            InputStream in = code < 400 ? c.getInputStream() : c.getErrorStream();
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            if (in != null) { byte[] buf = new byte[4096]; int n; while ((n = in.read(buf)) > 0) bo.write(buf, 0, n); }
            return new String[]{String.valueOf(code), bo.toString("UTF-8")};
        } catch (Exception e) { return new String[]{"-1", ""}; }
        finally { if (c != null) c.disconnect(); }
    }
    public static String[] get(SSLContext ctx, int port, String path) { return req(ctx, "GET", port, path, null); }

    /** A genesis validator entry (1M stake/alloc, verified, with its bound first-reveal commitment). */
    public static JSONObject val(MLDSAPrivateKeyParameters k) throws Exception {
        return new JSONObject().put("pubkey", PhantomCrypto.pubHex(k)).put("stake", 1_000_000L).put("identity", 1L)
                .put("verified", true).put("alloc", 1_000_000L).put("beaconCommit0", Ledger.beaconCommit0For(k.getEncoded()));
    }
}
