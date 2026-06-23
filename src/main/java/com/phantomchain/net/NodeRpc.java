package com.phantomchain.net;

import com.phantomchain.debug.*;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static fi.iki.elonen.NanoHTTPD.MIME_PLAINTEXT;

/**
 * The HTTP API surface — request routing, parsing, the operator-token gate, and the ~33 endpoint handlers,
 * extracted from {@link NetNode}.
 *
 * Separates "the RPC server" from the node's identity / consensus / persistence (which stay in
 * {@link NetNode}); holds a back-reference for the shared state (ledger, peers, mempool dedup, vote book)
 * and the infrastructure it dispatches to (gossip, verifyQC, sync, persist). {@link NetNode}.serve /
 * serveRead delegate here. Covered end-to-end by {@code RpcEndpointTest} (every endpoint) plus the live
 * integration / partition / fuzz suites.
 */
final class NodeRpc {
    final NetNode n;
    NodeRpc(NetNode n) { this.n = n; }

    Response resp(String b) { return newFixedLengthResponse(b + "\n"); }
    String param(IHTTPSession s, String k) { List<String> v = s.getParameters().get(k); return (v == null || v.isEmpty()) ? null : v.get(0); }
    String body(IHTTPSession s) { Map<String, String> f = new HashMap<>(); try { s.parseBody(f); } catch (Exception e) { return null; } String b = f.get("postData"); return (b != null && b.length() > 1_048_576) ? null : b; }
    boolean opAuth(IHTTPSession s) { return NetNode.OP_TOKEN.isEmpty() || NetNode.OP_TOKEN.equals(param(s, "token")); }   // open if no token configured

    String status() throws Exception {
        StringBuilder bal = new StringBuilder();
        for (int i = 0; i < n.N; i++) bal.append(" bal").append(i).append("=").append(n.ledger.balanceOf(n.VAL_IDS[i]));
        StringBuilder sl = new StringBuilder();
        for (int i = 0; i < n.N; i++) if (n.isSlashed(i)) { if (sl.length() > 0) sl.append(","); sl.append(i); }
        return "node=" + n.index + " height=" + n.ledger.height()
                + " last=" + n.ledger.lastHash().substring(0, 12) + " mempool=" + n.ledger.mempoolSize()
                + " peers=" + n.peers.size() + " slashed=[" + sl + "]" + bal;
    }

    // Read-only report builders typed to LedgerView: the parameter type makes it a compile error for
    // these handlers to mutate engine state (they can only call the read surface). Output is byte-for-byte
    // what the inline /econ and /identity handlers produced (covered by RpcEndpointTest).
    static String econReport(LedgerView v, int count, String[] valIds) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) sb.append("node" + i
                + ": stake=" + v.stakeOf(valIds[i])
                + " identity=" + v.identityCountOf(valIds[i])
                + " weight=" + String.format("%.1f%%", 100 * v.weight(i))
                + " balance=" + v.balanceOf(valIds[i])
                + (v.excluded(valIds[i]) ? " [SLASHED]" : "") + "\n");
        sb.append("total_minted=" + v.totalMinted() + " burned=" + v.burned()
                + " circulating=" + v.circulatingSupply() + " height=" + v.height());
        return sb.toString();
    }
    static String identityReport(LedgerView v, int count, String[] valIds) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) sb.append("node" + i
                + ": verified=" + v.isVerified(valIds[i])
                + " vouches=" + v.vouchCountOf(valIds[i]) + "/" + Ledger.VOUCH_THRESHOLD
                + " weight=" + String.format("%.1f%%", 100 * v.weight(i)) + "\n");
        return sb.toString();
    }

    String peersJson() { JSONObject o = new JSONObject(); for (Map.Entry<Integer, String> e : n.peers.entrySet()) o.put(String.valueOf(e.getKey()), e.getValue()); return o.toString(); }

    /** Open-read-port handler: serve the read-only allowlist, reject everything else (writes / consensus
     *  / gossip stay on the mTLS peer port). */
    Response serveRead(IHTTPSession s) {
        if (!NetNode.READ_ENDPOINTS.contains(s.getUri()))
            return newFixedLengthResponse(Response.Status.FORBIDDEN, MIME_PLAINTEXT, "not exposed on the open read port (use the mTLS peer port)\n");
        return serve(s);
    }

    Response serve(IHTTPSession s) {
        String uri = s.getUri();
        try {
            if (NetNode.OP_ENDPOINTS.contains(uri) && !opAuth(s))
                return newFixedLengthResponse(Response.Status.UNAUTHORIZED, MIME_PLAINTEXT, "operator token required\n");
            switch (uri) {
                case "/status": synchronized (n.ledger) { return resp(status()); }
                case "/econ": synchronized (n.ledger) { return resp(econReport(n.ledger, n.N, n.VAL_IDS)); }
                case "/identity": synchronized (n.ledger) { return resp(identityReport(n.ledger, n.N, n.VAL_IDS)); }
                case "/vouch": {
                    String ci = param(s, "i");
                    if (ci == null) return resp("need i=<candidate index>");
                    String cand = n.VAL_IDS[Integer.parseInt(ci)];
                    JSONObject tx; String res;
                    synchronized (n.ledger) {
                        if (!n.ledger.isVerified(n.id)) return resp("reject: this node is not personhood-verified, cannot vouch");
                        tx = n.ledger.buildVouchTx(n.id, cand, n.key);
                        res = n.ledger.addToMempool(tx, NetNode.PUB_BY_ID);
                    }
                    if ("accepted".equals(res)) { n.seenTx.add(tx.getString("sig")); n.gossipTx(tx.toString()); }
                    return resp("vouch=" + res + " by node" + n.index + " for node" + ci);
                }
                case "/bond": case "/unbond": {
                    boolean unbond = uri.equals("/unbond");
                    long amt = Long.parseLong(param(s, "amount") == null ? "0" : param(s, "amount"));
                    JSONObject tx; String res;
                    synchronized (n.ledger) { tx = n.ledger.buildBondTx(n.id, amt, n.ledger.projectedNonce(n.id), unbond, n.key); res = n.ledger.addToMempool(tx, NetNode.PUB_BY_ID); }
                    if ("accepted".equals(res)) { n.seenTx.add(tx.getString("sig")); n.gossipTx(tx.toString()); }
                    return resp((unbond ? "unbond=" : "bond=") + res + " amount=" + amt);
                }
                case "/unjail": {
                    JSONObject tx; String res;
                    synchronized (n.ledger) { tx = n.ledger.buildUnjailTx(n.id, n.ledger.projectedNonce(n.id), n.key); res = n.ledger.addToMempool(tx, NetNode.PUB_BY_ID); }
                    if ("accepted".equals(res)) { n.seenTx.add(tx.getString("sig")); n.gossipTx(tx.toString()); }
                    return resp("unjail=" + res + " by node" + n.index);
                }
                case "/valjoin": {   // this node bonds-in and requests to join the validator set
                    JSONObject tx; String res;
                    synchronized (n.ledger) { tx = n.ledger.buildValJoinTx(n.key); res = n.ledger.addToMempool(tx, NetNode.PUB_BY_ID); }
                    if ("accepted".equals(res)) { n.seenTx.add(Ledger.txId(tx)); n.gossipTx(tx.toString()); }
                    return resp("valjoin=" + res + " id=" + n.id.substring(0, 12));
                }
                case "/gov/propose": {
                    String pp = param(s, "param"), pid = param(s, "pid");
                    long val = Long.parseLong(param(s, "value") == null ? "0" : param(s, "value"));
                    if (pp == null || pid == null) return resp("need pid=&param=&value=");
                    JSONObject tx; String res;
                    synchronized (n.ledger) { tx = n.ledger.buildProposeTx(n.id, pid, pp, val, n.ledger.projectedNonce(n.id), n.key); res = n.ledger.addToMempool(tx, NetNode.PUB_BY_ID); }
                    if ("accepted".equals(res)) { n.seenTx.add(tx.getString("sig")); n.gossipTx(tx.toString()); }
                    return resp("propose=" + res + " " + pid + " " + pp + "=" + val);
                }
                case "/gov/vote": {
                    String pid = param(s, "pid"); boolean yes = "true".equals(param(s, "yes"));
                    if (pid == null) return resp("need pid=&yes=true|false");
                    JSONObject tx; String res;
                    synchronized (n.ledger) { tx = n.ledger.buildVoteTx(n.id, pid, yes, n.ledger.projectedNonce(n.id), n.key); res = n.ledger.addToMempool(tx, NetNode.PUB_BY_ID); }
                    if ("accepted".equals(res)) { n.seenTx.add(tx.getString("sig")); n.gossipTx(tx.toString()); }
                    return resp("govvote=" + res + " " + pid + " yes=" + yes);
                }
                case "/gov": synchronized (n.ledger) {
                    StringBuilder sb = new StringBuilder();
                    for (String pid : n.ledger.proposalIds()) {
                        JSONObject p = n.ledger.proposal(pid);
                        sb.append(pid + ": " + p.getString("param") + "=" + p.getLong("value")
                                + " deadline=" + p.getLong("deadline") + " executed=" + p.getBoolean("executed")
                                + " votes=" + p.getJSONObject("votes").length() + "\n");
                    }
                    sb.append("params: blockReward=" + n.ledger.blockReward() + " halvingBlocks=" + n.ledger.halvingBlocks()
                            + " maxSupply=" + n.ledger.maxSupply() + " feeBurnBps=" + n.ledger.feeBurnBps() + " slashBps=" + n.ledger.slashBps()
                            + " jailBlocks=" + n.ledger.jailBlocks() + " unbondingBlocks=" + n.ledger.unbondingBlocks());
                    return resp(sb.toString());
                }
                case "/head": synchronized (n.ledger) { return resp(n.ledger.chainSize() + "|" + n.ledger.lastHash()); }
                case "/account": synchronized (n.ledger) {
                    String aid = param(s, "id"); if (aid == null) return resp("need id=");
                    return resp(new JSONObject().put("id", aid).put("balance", n.ledger.balanceOf(aid))
                            .put("nonce", n.ledger.projectedNonce(aid)).put("cid", n.ledger.chainId()).toString());
                }
                case "/stateproof": synchronized (n.ledger) {   // authenticated account inclusion proof (Merkle) — verifiable by a light client
                    String aid = param(s, "id"); if (aid == null) return resp("need id=");
                    JSONObject pr = n.ledger.accountProof(aid);
                    pr.put("accountsRoot", n.ledger.accountsMerkleRoot());   // == pr.root; light clients trust it via stateRoot when srVersion=m1
                    pr.put("verified", Ledger.verifyAccountProof(pr));     // self-check the served proof
                    return resp(pr.toString());
                }
                case "/shard": synchronized (n.ledger) {
                    String ss = param(s, "s"); if (ss == null) return resp("need s=<shard 0.." + (Ledger.SHARDS - 1) + ">");
                    int sh = Integer.parseInt(ss); if (sh < 0 || sh >= Ledger.SHARDS) return resp("bad shard");
                    JSONArray roots = new JSONArray();
                    for (int i = 0; i < Ledger.SHARDS; i++) roots.put(n.ledger.shardRoot(i));
                    return resp(new JSONObject().put("shard", sh).put("shards", Ledger.SHARDS)
                            .put("data", n.ledger.shardData(sh)).put("roots", roots)
                            .put("shardsRoot", n.ledger.shardsRoot()).toString());
                }
                case "/extaddr": {   // derive this node's deterministic external-chain address
                    String chain = param(s, "chain"); if (chain == null) return resp("need chain=");
                    return resp(Ledger.extAddr(chain, PhantomCrypto.hex(n.key.getPublicKeyParameters().getEncoded())));
                }
                case "/bridge/out": {   // lock PHNT to the reserve for external release
                    String chain = param(s, "chain"); long amount = Long.parseLong(param(s, "amount") == null ? "0" : param(s, "amount"));
                    long fee = Long.parseLong(param(s, "fee") == null ? "1" : param(s, "fee"));
                    String ext = Ledger.extAddr(chain == null ? "ETH" : chain, PhantomCrypto.hex(n.key.getPublicKeyParameters().getEncoded()));
                    JSONObject tx; String res;
                    synchronized (n.ledger) { tx = n.ledger.buildBridgeOutTx(n.id, chain == null ? "ETH" : chain, ext, amount, fee, n.ledger.projectedNonce(n.id), n.key); res = n.ledger.addToMempool(tx, NetNode.PUB_BY_ID); }
                    if ("accepted".equals(res)) { n.seenTx.add(Ledger.txId(tx)); n.gossipTx(tx.toString()); }
                    return resp("bridge_out=" + res + " amount=" + amount + " -> " + (chain == null ? "ETH" : chain) + ":" + ext);
                }
                case "/bridge/outs": synchronized (n.ledger) {   // outbound locks awaiting external release (for custodians)
                    JSONArray a = new JSONArray(); for (JSONObject o : n.ledger.bridgeOuts()) a.put(o); return resp(a.toString());
                }
                case "/oracle": synchronized (n.ledger) {
                    String pair = param(s, "pair"); if (pair == null) return resp("need pair=");
                    return resp(new JSONObject().put("pair", pair).put("median", n.ledger.oracleMedian(pair))
                            .put("sources", n.ledger.oracleSources(pair)).toString());
                }
                case "/identity-info": synchronized (n.ledger) {
                    String aid = param(s, "id"); if (aid == null) return resp("need id=");
                    JSONObject idn = n.ledger.identityDoc(aid);
                    return resp(idn == null ? new JSONObject().put("registered", false).toString() : idn.toString());
                }
                case "/body": {   // leaf: full body if we still hold it, else pruned
                    int h = Integer.parseInt(param(s, "h"));
                    synchronized (n.ledger) { return resp(n.ledger.hasBody(h) ? n.ledger.blockAt(h).toString() : "pruned"); }
                }
                case "/rsshard": synchronized (n.ledger) {   // this node's RS shard of block h (stored, or computed if we hold the body)
                    int h = Integer.parseInt(param(s, "h"));
                    if (h < 0 || h >= n.ledger.chainSize()) return resp("{}");
                    JSONObject b = n.ledger.blockAt(h);
                    if (b.has("rsShard")) return resp(new JSONObject().put("idx", b.getInt("rsIdx")).put("shard", b.getString("rsShard")).toString());
                    if (n.ledger.hasBody(h)) {
                        byte[] body = b.getJSONArray("txs").toString().getBytes(StandardCharsets.UTF_8);
                        byte[][] shards = NetNode.RS.encode(ReedSolomon.split(body, NetNode.RS_K));
                        return resp(new JSONObject().put("idx", n.myShardIdx()).put("shard", PhantomCrypto.hex(shards[n.myShardIdx()])).toString());
                    }
                    return resp("{}");
                }
                case "/block": {   // full block; if pruned, RS-reconstruct from k shards and verify vs the committed hash
                    int h = Integer.parseInt(param(s, "h"));
                    JSONObject header;
                    synchronized (n.ledger) {
                        if (h < 0 || h >= n.ledger.chainSize()) return resp(new JSONObject().put("error", "no height").toString());
                        if (n.ledger.hasBody(h)) return resp(n.ledger.blockAt(h).toString());
                        header = n.ledger.blockAt(h);
                    }
                    byte[][] shards = new byte[NetNode.RS_N][]; boolean[] present = new boolean[NetNode.RS_N]; int got = 0, slen = 0;
                    if (header.has("rsShard")) { int idx = header.getInt("rsIdx"); byte[] sh = PhantomCrypto.unhex(header.getString("rsShard")); shards[idx] = sh; present[idx] = true; got++; slen = sh.length; }
                    for (int p = 0; p < n.N && got < NetNode.RS_K; p++) {
                        if (p == n.index) continue; String addr = n.peers.get(p); if (addr == null) continue;
                        String r = n.httpGet(addr, "/rsshard?h=" + h); if (r == null) continue;
                        try { JSONObject o = new JSONObject(r.trim()); if (!o.has("shard")) continue;
                            int idx = o.getInt("idx"); if (idx < 0 || idx >= NetNode.RS_N || present[idx]) continue;
                            byte[] sh = PhantomCrypto.unhex(o.getString("shard")); shards[idx] = sh; present[idx] = true; got++; slen = sh.length;
                        } catch (Exception e) { }
                    }
                    if (got >= NetNode.RS_K) try {
                        byte[] body = ReedSolomon.join(NetNode.RS.decode(shards, present, slen));
                        JSONArray txs = new JSONArray(new String(body, StandardCharsets.UTF_8));
                        JSONObject full = new JSONObject(header.toString()).put("txs", txs);
                        full.remove("pruned"); full.remove("rsShard"); full.remove("rsIdx");
                        synchronized (n.ledger) { if (header.getString("hash").equals(n.ledger.blockHash(full))) return resp(full.toString()); }   // trustless
                    } catch (Exception e) { }
                    return resp(header.toString());   // fallback
                }
                case "/peers": return resp(peersJson());
                case "/genesis": return resp(NetNode.GEN.toJson().toString());
                case "/announce": {   // only the validator that owns this index (proven by signature) can set its address
                    int aidx = Integer.parseInt(param(s, "index")); String addr = param(s, "addr"); String sig = param(s, "sig");
                    if (aidx >= 0 && aidx < n.N && addr != null && sig != null && addr.indexOf('|') < 0) {   // no delimiter injection into the signed announce
                        MLDSAPublicKeyParameters pub = NetNode.PUB_BY_ID.get(n.VAL_IDS[aidx]);
                        if (pub != null && PhantomCrypto.verify(pub, PhantomCrypto.utf8("announce|" + NetNode.GEN.chainId + "|" + aidx + "|" + addr), PhantomCrypto.unhex(sig)))
                            n.peers.put(aidx, addr);
                    }
                    return resp(peersJson());
                }
                case "/sync": { int before; synchronized (n.ledger) { before = n.ledger.height(); } n.syncFromPeers(); synchronized (n.ledger) { return resp("synced from=" + before + " to=" + n.ledger.height()); } }

                case "/submit": {
                    String to = param(s, "to"); if (to == null) to = n.VAL_IDS[(n.index + 1) % n.N];
                    long amount = Long.parseLong(param(s, "amount") == null ? "10" : param(s, "amount"));
                    long fee = Long.parseLong(param(s, "fee") == null ? "1" : param(s, "fee"));
                    JSONObject tx; String res;
                    synchronized (n.ledger) { tx = n.ledger.buildTxProjected(n.id, to, amount, fee, n.key); res = n.ledger.addToMempool(tx, NetNode.PUB_BY_ID); }
                    if ("accepted".equals(res)) { n.seenTx.add(tx.getString("sig")); n.gossipTx(tx.toString()); }
                    return resp("submit=" + res + " amount=" + amount + " fee=" + fee);
                }
                case "/gossip/tx": {
                    String b = body(s); if (b == null) return resp("no body");
                    JSONObject tx = new JSONObject(b);
                    if (!n.seenTx.add(Ledger.txId(tx))) return resp("dup");
                    String res; synchronized (n.ledger) { res = n.ledger.addToMempool(tx, NetNode.PUB_BY_ID); }
                    if ("accepted".equals(res)) n.gossipTx(b);
                    return resp("tx=" + res);
                }

                case "/vote": {
                    String b = body(s); if (b == null) return resp("no body");
                    JSONObject blk = new JSONObject(b);
                    int h = blk.getInt("height"); int view = blk.getInt("view");
                    String hash = blk.getString("hash");
                    synchronized (n.ledger) {
                        int proposer = n.ledger.proposerFor(blk.getString("prevHash"), h, view);
                        if (blk.getInt("proposer") != proposer) { System.out.println("VOTE-REJECT wrong proposer h=" + h + " v=" + view + " got=" + blk.getInt("proposer") + " want=" + proposer); return resp("reject: wrong proposer for view"); }
                        if (n.isSlashed(proposer)) return resp("reject: proposer is slashed");
                        if (!n.ledger.proposalLinks(blk)) { System.out.println("VOTE-REJECT bad links h=" + h + " stateRootMatch=" + n.ledger.stateRoot().equals(blk.optString("prevStateRoot")) + " shardsMatch=" + n.ledger.shardsRoot().equals(blk.optString("prevShardsRoot")) + " beaconValid=" + n.ledger.beaconRevealValid(blk)); return resp("reject: bad links/hash"); }
                        if (!n.ledger.txsValid(blk, NetNode.PUB_BY_ID)) { System.out.println("VOTE-REJECT bad txs h=" + h); return resp("reject: bad txs"); }
                        JSONObject prev = n.votedAt.get(h);
                        if (prev != null && !prev.getString("hash").equals(hash)) return resp("reject: already voted at height " + h);
                        JSONObject myVote = new JSONObject().put("valId", n.id).put("height", h).put("hash", hash).put("sig", PhantomCrypto.hex(n.voteSig(hash)));
                        n.votedAt.put(h, myVote); n.saveVotes();   // PERSIST before returning the vote
                        n.recordVote(myVote); n.gossipVote(myVote);
                        return resp(new JSONObject().put("i", n.index).put("sig", myVote.getString("sig")).toString());
                    }
                }
                case "/commit": {
                    String b = body(s); if (b == null) return resp("no body");
                    JSONObject blk = new JSONObject(b);
                    if (!n.verifyQC(blk)) return resp("reject: insufficient quorum");
                    if (!n.seenBlock.add(blk.getString("hash"))) return resp("dup");
                    String res; synchronized (n.ledger) { res = n.ledger.commitBlock(blk, NetNode.PUB_BY_ID); if ("appended".equals(res)) n.save(); }
                    return resp("commit=" + res);
                }

                case "/gossip/vote": { String b = body(s); if (b == null) return resp("no body"); n.handleIncomingVote(new JSONObject(b)); return resp("ok"); }
                case "/gossip/slash": {
                    String b = body(s); if (b == null) return resp("no body");
                    n.queueSlash(new JSONObject(b));   // engine verifies the evidence + dedups before admitting
                    return resp("ok");
                }
                case "/byz/equivocate": {   // DEBUG-only adversary hook; disabled unless PC_DEBUG=1
                    if (!NetNode.DEBUG_ENDPOINTS) return newFixedLengthResponse(Response.Status.NOT_FOUND, MIME_PLAINTEXT, "no route\n");
                    int h; synchronized (n.ledger) { h = n.ledger.chainSize(); }
                    String ha = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8("equivA|" + h)));
                    String hb = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8("equivB|" + h)));
                    JSONObject vA = new JSONObject().put("valId", n.id).put("height", h).put("hash", ha).put("sig", PhantomCrypto.hex(n.voteSig(ha)));
                    JSONObject vB = new JSONObject().put("valId", n.id).put("height", h).put("hash", hb).put("sig", PhantomCrypto.hex(n.voteSig(hb)));
                    n.gossipVote(vA); n.gossipVote(vB);
                    return resp("equivocated at height " + h + " (two conflicting signed votes broadcast)");
                }
                default: return newFixedLengthResponse(Response.Status.NOT_FOUND, MIME_PLAINTEXT, "no route\n");
            }
        } catch (JSONException | IllegalArgumentException e) {
            // Malformed request: bad JSON body, missing/unparseable params (NumberFormatException is an
            // IllegalArgumentException). This is the caller's fault, not ours -> 400, and no stack trace
            // (an unauthenticated peer must not be able to flood our logs by spamming garbage bodies).
            return newFixedLengthResponse(Response.Status.BAD_REQUEST, MIME_PLAINTEXT, "bad request: " + e.getMessage() + "\n");
        } catch (Exception e) {
            // Genuine server-side fault: keep the stack trace, it's a real bug to investigate.
            e.printStackTrace();
            return newFixedLengthResponse(Response.Status.INTERNAL_ERROR, MIME_PLAINTEXT, "ERR " + e.getClass().getSimpleName() + ": " + e.getMessage() + "\n");
        }
    }
}
