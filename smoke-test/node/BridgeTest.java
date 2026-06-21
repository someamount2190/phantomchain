package com.phantomchain.debug;

import java.io.File;
import javax.net.ssl.SSLContext;
import org.json.JSONArray;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;

/** Cross-chain bridge test: M-of-N custodian attestation releases reserve -> recipient (inbound),
 *  threshold + replay enforced. Usage: BridgeTest <node> <truststore.p12> <custKey0> <custKey1> */
public class BridgeTest {
    static String NODE; static SSLContext TLS; static String CID; static Ledger L = new Ledger();
    static String get(String p) throws Exception { return Wallet.rpcGet(NODE, TLS, p).trim(); }
    static String post(JSONObject tx) throws Exception { return Wallet.rpcPost(NODE, TLS, "/gossip/tx", tx.toString()).trim(); }
    static long bal(String id) throws Exception { return new JSONObject(get("/account?id=" + id)).getLong("balance"); }
    static void nap() throws Exception { Thread.sleep(7000); }

    public static void main(String[] a) throws Exception {
        NODE = a[0]; TLS = Wallet.tlsTrusting(new File(a[1]), "phantomchain".toCharArray());
        CID = new JSONObject(get("/genesis")).getString("chainId"); L.chainId = CID;
        MLDSAPrivateKeyParameters c0 = Keys.loadOrCreate(new File(a[2])), c1 = Keys.loadOrCreate(new File(a[3]));
        String id0 = Keys.idOf(c0), id1 = Keys.idOf(c1);
        String recipient = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.unhex(Keys.pubHex(PhantomCrypto.randomDeviceKey()))));
        System.out.println("chainId=" + CID + "  reserve=" + bal(Ledger.BRIDGE_RESERVE) + "  recipient=" + recipient.substring(0, 12));

        String extTxid = "eth-deposit-0xABC123";
        long amount = 500;
        // 1) single custodian (threshold is 2) -> must reject
        JSONArray one = new JSONArray().put(L.bridgeInApproval(id0, c0, recipient, amount, extTxid));
        System.out.println("[1] BRIDGE_IN with 1/2 custodians (must reject) -> " + post(L.buildBridgeInTx(recipient, amount, extTxid, one)));
        // 2) two custodians -> release 500 from reserve to recipient
        JSONArray two = new JSONArray()
                .put(L.bridgeInApproval(id0, c0, recipient, amount, extTxid))
                .put(L.bridgeInApproval(id1, c1, recipient, amount, extTxid));
        System.out.println("[2] BRIDGE_IN with 2/2 custodians -> " + post(L.buildBridgeInTx(recipient, amount, extTxid, two)));
        nap();
        System.out.println("    recipient balance=" + bal(recipient) + " (expect 500)   reserve=" + bal(Ledger.BRIDGE_RESERVE));
        // 3) replay the SAME extTxid -> must reject (no double mint)
        System.out.println("[3] BRIDGE_IN replay same extTxid (must reject) -> " + post(L.buildBridgeInTx(recipient, amount, extTxid, two)));
        nap();
        System.out.println("    recipient balance still=" + bal(recipient) + " (expect 500, no double mint)");
        System.out.println("ext address (ETH) of recipient-style key: " + Ledger.extAddr("ETH", Keys.pubHex(c0)).substring(0, 16) + "...");
        System.out.println("DONE.");
    }
}
