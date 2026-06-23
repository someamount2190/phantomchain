package com.phantomchain.net;

/** An HTTP response: status code + plain-text body. The handlers build these; NodeHttpServer writes them. */
final class Resp {
    final int status;
    final String body;
    Resp(int status, String body) { this.status = status; this.body = body; }
}
