package com.phantomchain.debug;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Per-node LOCAL configuration. Not consensus-relevant — every operator sets their own.
 * Tells this process what port to serve on, how the network reaches it, who to dial for
 * bootstrap (seeds), where to keep chain data, and where this node's private key lives.
 */
public class NodeConfig {
    public int rpcPort = 9090;
    public int readPort = 0;   // 0 => rpcPort+1. Open READ port: server-auth TLS, NO client cert required.
    public String selfAddr = "127.0.0.1:9090";   // host:port other nodes use to reach THIS node (public IP in prod)
    public List<String> seeds = new ArrayList<>();// host:port of bootstrap peers (membership is then learned)
    public String dataDir = "pcdata";             // chain.json, votes.json, certs/ live here
    public String keyFile = "node.key";           // this node's ML-DSA private key (32-byte seed, hex)
    public int certIndex = -1;                     // TLS cert slot; -1 = use validator index (joiners set this explicitly)

    public static NodeConfig load(File f) throws Exception {
        JSONObject o = new JSONObject(new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8));
        NodeConfig c = new NodeConfig();
        c.rpcPort = o.optInt("rpcPort", 9090);
        c.readPort = o.optInt("readPort", 0);
        c.selfAddr = o.optString("selfAddr", "127.0.0.1:" + c.rpcPort);
        c.dataDir = o.optString("dataDir", "pcdata");
        c.keyFile = o.optString("keyFile", "node.key");
        c.certIndex = o.optInt("certIndex", -1);
        JSONArray s = o.optJSONArray("seeds");
        if (s != null) for (int i = 0; i < s.length(); i++) c.seeds.add(s.getString(i));
        return c;
    }
}
