package com.phantomchain.net;

import com.sun.net.httpserver.HttpExchange;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * A parsed HTTP request: method, path, URL-decoded query parameters, and the (capped) body. Built once per
 * request from an {@link HttpExchange} so the handlers stay decoupled from the HTTP server in use.
 */
final class Req {
    final String method;
    final String uri;                 // path only (e.g. "/submit")
    final Map<String, String> query;  // URL-decoded
    final String body;                // raw request body, or null if empty / over the 1 MiB cap

    private Req(String method, String uri, Map<String, String> query, String body) {
        this.method = method; this.uri = uri; this.query = query; this.body = body;
    }

    static Req from(HttpExchange ex) throws IOException {
        URI u = ex.getRequestURI();
        return new Req(ex.getRequestMethod(), u.getPath(), parseQuery(u.getRawQuery()), readBody(ex.getRequestBody()));
    }

    static Map<String, String> parseQuery(String raw) {
        Map<String, String> m = new HashMap<>();
        if (raw == null || raw.isEmpty()) return m;
        for (String pair : raw.split("&")) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            String k = eq < 0 ? pair : pair.substring(0, eq);
            String v = eq < 0 ? "" : pair.substring(eq + 1);
            try { m.put(URLDecoder.decode(k, "UTF-8"), URLDecoder.decode(v, "UTF-8")); }
            catch (Exception e) { /* skip a malformed pair rather than fail the whole request */ }
        }
        return m;
    }

    /** Read the body, capped at 1 MiB (over-cap -> null, matching the former NanoHTTPD postData limit). */
    static String readBody(InputStream in) throws IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[8192]; int n;
        while ((n = in.read(buf)) > 0) {
            if (bo.size() + n > 1_048_576) return null;
            bo.write(buf, 0, n);
        }
        return bo.size() == 0 ? null : bo.toString("UTF-8");
    }
}
