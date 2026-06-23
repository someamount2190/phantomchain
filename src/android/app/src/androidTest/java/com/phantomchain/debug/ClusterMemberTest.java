package com.phantomchain.debug;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Runtime proof that the on-device {@link ClusterMember} server works on the Android runtime (ART). It
 * replaced NanoHTTPD with a minimal raw-{@code ServerSocket} HTTP/1.1 loop; this boots it on a test port
 * and exercises its three endpoints, asserting the JSON contract the desktop coordinator relies on.
 * Bypasses the app's biometric gate (which only unseals the seed) and drives the server directly.
 *
 *   ./gradlew -p src/android connectedDebugAndroidTest
 */
@RunWith(AndroidJUnit4.class)
public class ClusterMemberTest {

    /** Raw-socket HTTP/1.1 GET (not HttpURLConnection — Android blocks cleartext there; a raw socket, like
     *  the desktop coordinator's, is unaffected). Returns the response body; asserts a 200 status line. */
    private static String get(int port, String path) throws Exception {
        try (Socket sock = new Socket("127.0.0.1", port)) {
            sock.setSoTimeout(4000);
            OutputStream os = sock.getOutputStream();
            os.write(("GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.UTF_8));
            os.flush();
            BufferedReader r = new BufferedReader(new InputStreamReader(sock.getInputStream(), StandardCharsets.UTF_8));
            String statusLine = r.readLine();   // "HTTP/1.1 200 OK"
            assertTrue("200 status line from " + path + " (got: " + statusLine + ")",
                    statusLine != null && statusLine.contains("200"));
            String line;
            while ((line = r.readLine()) != null && !line.isEmpty()) { /* skip headers to the blank line */ }
            StringBuilder body = new StringBuilder();
            while ((line = r.readLine()) != null) body.append(line);
            return body.toString();
        }
    }

    @Test
    public void rawSocketServerServesOnAndroid() throws Exception {
        byte[] seed = new byte[32];
        for (int i = 0; i < seed.length; i++) seed[i] = (byte) (i + 1);
        int port = 18080;
        String id = ClusterMember.start(port, seed);
        try {
            Thread.sleep(300);   // let the accept loop bind

            JSONObject member = new JSONObject(get(port, "/member"));
            assertEquals("member id matches start()", id, member.getString("id"));
            assertTrue("member exposes its pubkey", member.getString("pub").length() > 0);

            JSONObject health = new JSONObject(get(port, "/health"));
            assertTrue("health reports active", health.getBoolean("active"));
            assertEquals(id, health.getString("id"));

            JSONObject signed = new JSONObject(get(port, "/sign?hash=deadbeef"));
            assertEquals("echoes the requested hash", "deadbeef", signed.getString("hash"));
            assertEquals("signs as this member", id, signed.getString("m"));
            assertTrue("returns a signature", signed.getString("sig").length() > 0);
        } finally {
            if (ClusterMember.running != null) ClusterMember.running.stop();
        }
    }
}
