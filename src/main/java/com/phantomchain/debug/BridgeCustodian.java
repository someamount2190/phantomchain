package com.phantomchain.debug;

import com.phantomchain.debug.*;

import java.io.File;
import java.nio.file.Files;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.SSLContext;

import org.json.JSONArray;
import org.json.JSONObject;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;

/**
 * Off-chain bridge custodian SERVICE (existing engineering, not research): the M-of-N committee's signer
 * daemon. It (a) watches an external-deposit feed and posts M-of-N BRIDGE_IN attestations to release the
 * reserve; (b) watches on-chain outbound locks (/bridge/outs) and "releases" them externally (logged; in
 * production this is an external-chain RPC submit); (c) posts signed exchange-rate attestations to the
 * median oracle. In production each custodian runs its own instance with its own HSM key; here one process
 * holds the committee keys to demonstrate the full flow.
 * Usage: BridgeCustodian <node> <truststore.p12> <depositFeed.json> <custKey0> <custKey1> [iterations]
 */
public class BridgeCustodian {
    public static void main(String[] a) throws Exception {
        String node = a[0];
        SSLContext tls = Wallet.tlsTrusting(new File(a[1]), "phantomchain".toCharArray());
        File feed = new File(a[2]);
        Ledger L = new Ledger();
        L.chainId = new JSONObject(Wallet.rpcGet(node, tls, "/genesis").trim()).getString("chainId");
        MLDSAPrivateKeyParameters[] keys = { Keys.loadOrCreate(new File(a[3])), Keys.loadOrCreate(new File(a[4])) };
        String[] ids = { Keys.idOf(keys[0]), Keys.idOf(keys[1]) };
        int iterations = a.length > 5 ? Integer.parseInt(a[5]) : 6;
        Set<String> seenDeposits = new HashSet<>(), seenOuts = new HashSet<>();
        long baseRate = 2500;
        System.out.println("custodian service up; chainId=" + L.chainId + " committee=" + ids.length + " feed=" + feed.getName());

        for (int it = 0; it < iterations; it++) {
            // (a) inbound: external deposits -> M-of-N BRIDGE_IN
            if (feed.exists()) {
                JSONArray deposits = new JSONArray(new String(Files.readAllBytes(feed.toPath())));
                for (int i = 0; i < deposits.length(); i++) {
                    JSONObject d = deposits.getJSONObject(i);
                    String extTxid = d.getString("extTxid");
                    if (!seenDeposits.add(extTxid)) continue;
                    String recipient = d.getString("recipient"); long amount = d.getLong("amount");
                    JSONArray approvals = new JSONArray();
                    for (int k = 0; k < keys.length; k++) approvals.put(L.bridgeInApproval(ids[k], keys[k], recipient, amount, extTxid));
                    String res = Wallet.rpcPost(node, tls, "/gossip/tx", L.buildBridgeInTx(recipient, amount, extTxid, approvals).toString()).trim();
                    System.out.println("  INBOUND attest deposit " + extTxid + " -> mint " + amount + " to " + recipient.substring(0, 10) + " : " + res);
                }
            }
            // (b) outbound: watch on-chain locks, "release" externally
            JSONArray outs = new JSONArray(Wallet.rpcGet(node, tls, "/bridge/outs").trim());
            for (int i = 0; i < outs.length(); i++) {
                JSONObject o = outs.getJSONObject(i);
                String key = o.getString("actor") + o.getLong("amount") + o.getString("extAddr");
                if (!seenOuts.add(key)) continue;
                System.out.println("  OUTBOUND release " + o.getLong("amount") + " -> " + o.getString("chain") + ":" + o.getString("extAddr").substring(0, 10) + " (external submit)");
            }
            // (c) oracle: each custodian attests a rate (slight spread -> median)
            for (int k = 0; k < keys.length; k++)
                Wallet.rpcPost(node, tls, "/gossip/tx", L.buildOracleTx(ids[k], keys[k], "PHNT/USD", baseRate + k * 7).toString());
            Thread.sleep(2500);
        }
        System.out.println("oracle PHNT/USD median: " + Wallet.rpcGet(node, tls, "/oracle?pair=PHNT/USD").trim());
        System.out.println("custodian service done.");
    }
}
