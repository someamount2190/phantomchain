package com.phantomchain.net;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

/**
 * One TLS 1.3 HTTPS endpoint, on the JDK's built-in {@link HttpsServer} (module {@code jdk.httpserver}).
 *
 * Replaces the former NanoHTTPD 2.3.1 dependency (last released 2017): same behaviour — a single server per
 * port, optional mutual TLS — but on a maintained, in-JDK stack with no third-party jar. mTLS is configured
 * the clean way via {@link HttpsConfigurator} ({@code needClientAuth}); the old code had to override
 * NanoHTTPD's server-socket factory to dodge a bug where {@code makeSecure()} silently reset
 * {@code needClientAuth=false}.
 *
 * The handler reads the request into a {@link Req} (path + URL-decoded query + body, body capped at 1 MiB),
 * runs the supplied dispatch to a {@link Resp}, and writes it back. Handler exceptions and oversized/bad
 * requests degrade to a 500 here; the dispatch itself already maps client errors to 400 (see NodeRpc.serve).
 */
final class NodeHttpServer {
    private final HttpsServer server;
    private final ThreadPoolExecutor pool;

    NodeHttpServer(int port, SSLContext ctx, boolean needClientAuth, Function<Req, Resp> dispatch) throws IOException {
        server = HttpsServer.create(new InetSocketAddress(port), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(ctx) {
            @Override public void configure(HttpsParameters params) {
                SSLParameters p = ctx.getDefaultSSLParameters();
                p.setProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
                p.setNeedClientAuth(needClientAuth);   // peer port: require a cluster-CA client cert (mTLS). read port: false.
                params.setSSLParameters(p);
            }
        });
        server.createContext("/", exchange -> {
            Resp r;
            try {
                r = dispatch.apply(Req.from(exchange));
                if (r == null) r = new Resp(500, "ERR null response\n");
            } catch (Exception e) {
                r = new Resp(500, "ERR " + e.getClass().getSimpleName() + ": " + e.getMessage() + "\n");
            }
            byte[] body = r.body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/plain");
            exchange.sendResponseHeaders(r.status, body.length);
            try (OutputStream os = exchange.getResponseBody()) { os.write(body); }
        });
        // Bounded thread-per-request: scales 0..MAX under load and reaps idle threads, but caps at MAX so a
        // connection flood on the open read port cannot exhaust memory with unbounded threads. Beyond MAX
        // concurrent handlers, new connections are rejected (backpressure) — a dropped consensus message is
        // recoverable via gossip/retry. 64 is generous for a node's peer set + read clients.
        pool = new ThreadPoolExecutor(0, 64, 60L, TimeUnit.SECONDS, new SynchronousQueue<>());
        pool.setThreadFactory(r -> { Thread t = new Thread(r, "http-" + port); t.setDaemon(true); return t; });
        server.setExecutor(pool);
    }

    void start() { server.start(); }
    void stop()  { server.stop(0); pool.shutdownNow(); }   // stop the HTTP server AND release its thread pool
}
