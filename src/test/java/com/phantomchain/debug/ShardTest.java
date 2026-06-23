package com.phantomchain.debug;

import java.io.File;
import javax.net.ssl.SSLContext;
import org.json.JSONArray;
import org.json.JSONObject;

/** Light-client shard-proof test: fetch one shard, verify an account is in the committed sharded state
 *  without holding the rest, confirm tampering is rejected, and confirm two nodes agree on the shard root.
 *  Usage: ShardTest <nodeA> <nodeB> <truststore.p12> <accountId> */
public class ShardTest {
    public static void main(String[] a) throws Exception {
        SSLContext tls = Wallet.tlsTrusting(new File(a[2]), "phantomchain".toCharArray());
        String acct = a[3];
        int s = Ledger.shardOf(acct);
        System.out.println("account " + acct.substring(0, 12) + "... -> shard " + s + "/" + Ledger.SHARDS);

        JSONObject r = new JSONObject(Wallet.rpcGet(a[0], tls, "/shard?s=" + s).trim());
        String data = r.getString("data"), shardsRoot = r.getString("shardsRoot");
        JSONArray roots = r.getJSONArray("roots");

        boolean proofOk   = Ledger.verifyShardProof(shardsRoot, s, data, roots);
        boolean present   = data.contains(acct);
        boolean tamperBad = !Ledger.verifyShardProof(shardsRoot, s, data + "tamper", roots);

        // consensus agreement: a second node must report the same shard root for the same shard
        JSONObject r2 = new JSONObject(Wallet.rpcGet(a[1], tls, "/shard?s=" + s).trim());
        boolean agree = r2.getString("shardsRoot").equals(shardsRoot)
                && r2.getJSONArray("roots").getString(s).equals(roots.getString(s));

        System.out.println("proof verifies (slice + sibling roots -> committed shardsRoot): " + proofOk);
        System.out.println("account present in its shard:                                  " + present);
        System.out.println("tampered slice rejected:                                       " + tamperBad);
        System.out.println("two nodes agree on the shard root (consensus):                 " + agree);
        System.out.println((proofOk && present && tamperBad && agree) ? "PASS" : "FAIL");
    }
}
