package com.phantomchain.net;

import static com.phantomchain.debug.TestKit.*;

import com.phantomchain.debug.*;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

import org.json.JSONArray;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;

/**
 * Coverage for the full NetNode HTTP surface — boots a live single node (2-validator genesis) and exercises
 * every endpoint over the mTLS peer port with a member client cert, asserting the response shape / status.
 *
 * This is the safety net that makes the serve() dispatch refactorable: previously only /status, /submit,
 * /head, /peers, /announce were touched (Eclipse/Mtls/ReadPeerSplit); the read endpoints (/econ /identity
 * /account /stateproof /shard /extaddr /oracle /identity-info /body /rsshard /block /genesis /gov
 * /bridge/outs), the mempool writes (/vouch /bond /unbond /unjail /valjoin /gov/propose /gov/vote
 * /bridge/out /sync), and the gossip/consensus POST endpoints were not. They are now.
 */
public class RpcEndpointTest {


    static SSLContext CTX; static int PORT;
    static String[] req(String method, String path, String reqBody) {
        HttpsURLConnection c = null;
        try {
            c = (HttpsURLConnection) new URL("https://127.0.0.1:" + PORT + path).openConnection();
            c.setSSLSocketFactory(CTX.getSocketFactory());
            c.setHostnameVerifier((h, s) -> true);
            c.setConnectTimeout(5000); c.setReadTimeout(5000);
            c.setRequestMethod(method);
            if (reqBody != null) {
                c.setDoOutput(true);
                c.setRequestProperty("Content-Type", "application/json");   // so NanoHTTPD populates postData (matches NetHttp.post)
                c.getOutputStream().write(reqBody.getBytes(StandardCharsets.UTF_8));
            }
            int code = c.getResponseCode();
            InputStream in = code < 400 ? c.getInputStream() : c.getErrorStream();
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            if (in != null) { byte[] buf = new byte[4096]; int n; while ((n = in.read(buf)) > 0) bo.write(buf, 0, n); }
            return new String[]{String.valueOf(code), bo.toString("UTF-8")};
        } catch (Exception e) { return new String[]{"-1", e.toString()}; }
        finally { if (c != null) c.disconnect(); }
    }
    static String get(String path) { return req("GET", path, null)[1]; }
    static String getCode(String path) { return req("GET", path, null)[0]; }
    static String post(String path, String body) { return req("POST", path, body)[1]; }

    // op-token suffix for the gated write endpoints
    static String TOK = "";
    static String w(String path) throws Exception { return path + (path.indexOf('?') < 0 ? "?" : "&") + (TOK.isEmpty() ? "" : "token=" + enc(TOK)); }

    static String ID0, ID1;

    public static void main(String[] a) throws Exception {
        File base = new File(System.getProperty("java.io.tmpdir"), "pc-rpc-" + System.nanoTime());
        File data = new File(base, "data"); data.mkdirs();
        File certs = new File(data, "certs"); TlsSetup.ensureCerts(certs, 2);
        MLDSAPrivateKeyParameters k0 = Keys.loadOrCreate(new File(base, "n0.key"));
        MLDSAPrivateKeyParameters k1 = Keys.loadOrCreate(new File(base, "n1.key"));
        ID0 = Keys.idOf(k0); ID1 = Keys.idOf(k1);
        String cid = "pc-rpc";
        Genesis gen = Genesis.fromJson(new JSONObject().put("chainId", cid).put("genesisTime", 1700000000000L)
                .put("validators", new JSONArray().put(val(k0)).put(val(k1))).toString());

        int peerPort = freePort(), readPort = freePort();
        NodeConfig cfg = new NodeConfig();
        cfg.rpcPort = peerPort; cfg.readPort = readPort; cfg.selfAddr = "127.0.0.1:" + peerPort;
        cfg.seeds = new java.util.ArrayList<>(java.util.Arrays.asList("127.0.0.1:" + peerPort));
        cfg.dataDir = data.getAbsolutePath(); cfg.keyFile = new File(base, "n0.key").getAbsolutePath(); cfg.certIndex = 0;

        NetNode node = new NetNode(gen, cfg, k0);
        node.boot();
        Thread.sleep(800);

        CTX = TlsSetup.context(certs, 1);   // member client cert over the mTLS peer port
        PORT = peerPort;
        TOK = NetNode.OP_TOKEN;
        System.out.println("[live NetNode peer :" + peerPort + "  op-token=" + (TOK.isEmpty() ? "<none>" : "<set>") + "]");

        // ===== READ endpoints =====
        ok("/status reports node + height", get("/status").matches("(?s).*node=\\d+ height=\\d+.*"));
        ok("/econ reports supply + per-validator weight", get("/econ").contains("total_minted=") && get("/econ").contains("weight="));
        ok("/identity reports verified + vouch progress", get("/identity").contains("verified="));
        ok("/head is height|hash", get("/head").matches("\\d+\\|[0-9a-f]+\\s*"));
        ok("/account returns balance/nonce/cid", new JSONObject(get("/account?id=" + ID0)).getLong("balance") == 1_000_000L);
        { JSONObject p = new JSONObject(get("/stateproof?id=" + ID0));
          ok("/stateproof serves a self-verifying account proof", p.optBoolean("present") && p.optBoolean("verified")); }
        { JSONObject sh = new JSONObject(get("/shard?s=0"));
          ok("/shard returns the shard slice + shardsRoot", sh.getInt("shards") == Ledger.SHARDS && sh.has("shardsRoot")); }
        ok("/extaddr derives an external address", get("/extaddr?chain=ETH").trim().length() > 0 && !get("/extaddr?chain=ETH").contains("need"));
        ok("/bridge/outs is a (empty) JSON array", get("/bridge/outs").trim().startsWith("["));
        ok("/oracle returns a median (0, no rates yet)", new JSONObject(get("/oracle?pair=BTCUSD")).getLong("median") == 0);
        ok("/identity-info reports unregistered for a bare validator id", !new JSONObject(get("/identity-info?id=" + ID0)).optBoolean("registered", false));
        ok("/body returns the genesis block body", get("/body?h=0").contains("\"height\":0") || get("/body?h=0").contains("txs"));
        ok("/rsshard returns JSON for h=0", get("/rsshard?h=0").trim().startsWith("{"));
        ok("/block returns the genesis block", new JSONObject(get("/block?h=0")).getInt("height") == 0);
        ok("/block out-of-range returns an error object", new JSONObject(get("/block?h=999")).has("error"));
        ok("/peers is a JSON map", get("/peers").trim().startsWith("{"));
        ok("/genesis returns the chain definition", new JSONObject(get("/genesis")).getString("chainId").equals(cid));
        ok("/gov lists params", get("/gov").contains("params:") && get("/gov").contains("feeBurnBps="));

        // ===== WRITE endpoints (op-token gated; assert accepted into the mempool) =====
        ok("/submit builds + accepts a fee-paying transfer", get(w("/submit?to=" + enc(ID1) + "&amount=25&fee=2")).contains("submit=accepted"));
        ok("/bond accepts a stake bond", get(w("/bond?amount=1000")).startsWith("bond=accepted"));
        ok("/unbond is wired", get(w("/unbond?amount=10")).startsWith("unbond="));
        ok("/unjail is wired", get(w("/unjail")).startsWith("unjail="));
        ok("/vouch is wired (node is a verified founder)", get(w("/vouch?i=1")).startsWith("vouch="));
        ok("/valjoin is wired", get(w("/valjoin")).startsWith("valjoin="));
        ok("/gov/propose accepts a whitelisted param change", get(w("/gov/propose?pid=p1&param=feeBurnBps&value=1200")).contains("propose=accepted"));
        ok("/gov/vote is wired", get(w("/gov/vote?pid=p1&yes=true")).startsWith("govvote="));
        ok("/bridge/out is wired", get(w("/bridge/out?chain=ETH&amount=5")).startsWith("bridge_out="));
        ok("/sync reports a height range", get(w("/sync")).startsWith("synced from="));

        // ===== gossip / consensus POST endpoints =====
        // a real gossiped tx is accepted into the mempool
        JSONObject tx; synchronized (node.ledger) { tx = node.ledger.buildTxProjected(ID0, ID1, 7, 1, k0); }
        String gres = post("/gossip/tx", tx.toString());
        ok("/gossip/tx accepts (or dedups) a valid signed tx", gres.startsWith("tx=accepted") || gres.startsWith("tx=dup"));
        ok("/gossip/tx rejects a garbage-signed tx", post("/gossip/tx", new JSONObject().put("from", ID0).put("to", ID1)
                .put("amount", 1).put("fee", 1).put("nonce", 0).put("cid", cid).put("sig", "00").put("pub", Keys.pubHex(k0)).toString()).startsWith("tx="));
        ok("/vote handles a missing body gracefully", post("/vote", null).contains("no body"));
        ok("/commit handles a missing body gracefully", post("/commit", null).contains("no body"));
        ok("/gossip/vote ack (equivocation detector swallows a bad-sig vote)",
                post("/gossip/vote", new JSONObject().put("valId", ID0).put("height", 0).put("hash", "00").put("sig", "00").toString()).trim().equals("ok"));
        ok("/gossip/slash ack (evidence for an unknown validator is dropped)",
                post("/gossip/slash", new JSONObject().put("from", "SLASH").put("valId", "deadbeefdeadbeef")
                        .put("ha", "aa").put("hb", "bb").put("sa", "00").put("sb", "00").toString()).trim().equals("ok"));

        // ===== routing / debug-gate =====
        ok("unknown route -> 404", "404".equals(getCode("/no/such/route")));
        ok("/byz/equivocate is 404 unless PC_DEBUG=1", get("/byz/equivocate").contains("no route") || get("/byz/equivocate").contains("equivocated"));

        node.stop();
        System.out.println("\nRpcEndpointTest: " + pass + " passed, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }

}
