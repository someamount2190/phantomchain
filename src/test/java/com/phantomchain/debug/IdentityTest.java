package com.phantomchain.debug;

import static com.phantomchain.debug.TestKit.*;

import java.io.File;

import javax.net.ssl.SSLContext;

import org.json.JSONArray;
import org.json.JSONObject;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;

/**
 * End-to-end test of the identity != key layer against a live node:
 *   register -> fund -> device-signed transfer -> rotate device (old key revoked) -> guardian recovery.
 * Usage: IdentityTest <node host:port> <truststore.p12>
 */
public class IdentityTest {
    static String NODE; static SSLContext TLS; static String CID;
    static Ledger L = new Ledger();   // bare ledger, used only for its tx builders (chainId set below)

    static String get(String p) throws Exception { return Wallet.rpcGet(NODE, TLS, p).trim(); }
    static String post(JSONObject tx) throws Exception { return Wallet.rpcPost(NODE, TLS, "/gossip/tx", tx.toString()).trim(); }
    static long balance(String id) throws Exception { return new JSONObject(get("/account?id=" + id)).getLong("balance"); }
    static long nonceOf(String id) throws Exception { return new JSONObject(get("/account?id=" + id)).getLong("nonce"); }
    static void sleep() throws Exception { Thread.sleep(7000); }
    static MLDSAPrivateKeyParameters key() { return PhantomCrypto.randomDeviceKey(); }
    static String pub(MLDSAPrivateKeyParameters k) { return PhantomCrypto.hex(k.getPublicKeyParameters().getEncoded()); }

    /** Build an identity transfer: from = identity id, signed by one of its device keys. */
    static JSONObject transfer(String fromId, MLDSAPrivateKeyParameters deviceKey, String to, long amount, long fee, long nonce) throws Exception {
        byte[] sig = PhantomCrypto.sign(deviceKey, PhantomCrypto.utf8(Ledger.txCanon(CID, fromId, to, amount, fee, nonce)));
        return new JSONObject().put("from", fromId).put("to", to).put("amount", amount).put("fee", fee)
                .put("nonce", nonce).put("cid", CID).put("pub", pub(deviceKey)).put("sig", PhantomCrypto.hex(sig));
    }

    public static void main(String[] a) throws Exception {
        NODE = a[0];
        TLS = Wallet.tlsTrusting(new File(a[1]), "phantomchain".toCharArray());
        CID = new JSONObject(get("/genesis")).getString("chainId");
        L.chainId = CID;
        System.out.println("chainId=" + CID);

        // 1) register an identity (root key authorizes; device key spends)
        MLDSAPrivateKeyParameters root = key(), device = key();
        String id = Ledger.idOf(pub(root));
        System.out.println("\n[1] REGISTER id=" + id.substring(0, 12) + "...  -> " + post(L.buildRegisterTx(root, device)));
        sleep();
        System.out.println("    identity-info: " + get("/identity-info?id=" + id));

        // 2) fund the identity from a validator faucet (/submit is open on this test node)
        System.out.println("\n[2] FUND -> " + Wallet.rpcGet(NODE, TLS, "/submit?to=" + id + "&amount=5000&fee=1"));
        sleep();
        System.out.println("    balance=" + balance(id));

        // 3) device-signed transfer from the identity
        String dest = Ledger.idOf(pub(key()));
        System.out.println("\n[3] TRANSFER 1000 (device-signed) -> " + post(transfer(id, device, dest, 1000, 2, nonceOf(id))));
        sleep();
        System.out.println("    identity balance=" + balance(id) + "  dest balance=" + balance(dest));

        // 4) rotate to a new device key (root-signed); old device must stop working
        MLDSAPrivateKeyParameters device2 = key();
        System.out.println("\n[4] ROTATE device (root-signed) -> " + post(L.buildRotateTx(id, root, pub(device2), 0)));
        sleep();
        System.out.println("    devices now: " + new JSONObject(get("/identity-info?id=" + id)).getJSONArray("devices").toString().substring(0, 24) + "...");
        System.out.println("    OLD device transfer (must reject) -> " + post(transfer(id, device, dest, 10, 2, nonceOf(id))));
        System.out.println("    NEW device transfer (must accept) -> " + post(transfer(id, device2, dest, 10, 2, nonceOf(id))));
        sleep();
        System.out.println("    identity balance=" + balance(id));

        // 5) guardian recovery: two guardian identities, threshold 2, recover to a fresh device
        MLDSAPrivateKeyParameters g1r = key(), g1d = key(), g2r = key(), g2d = key();
        String g1 = Ledger.idOf(pub(g1r)), g2 = Ledger.idOf(pub(g2r));
        post(L.buildRegisterTx(g1r, g1d)); post(L.buildRegisterTx(g2r, g2d)); sleep();
        System.out.println("\n[5] SET GUARDIANS [g1,g2] threshold=2 -> "
                + post(L.buildSetGuardiansTx(id, root, new JSONArray().put(g1).put(g2), 2, 1)));
        sleep();
        MLDSAPrivateKeyParameters device3 = key();
        JSONArray approvals = new JSONArray()
                .put(L.recoverApproval(g1, g1d, id, pub(device3), 2))
                .put(L.recoverApproval(g2, g2d, id, pub(device3), 2));
        System.out.println("    RECOVER (2 guardian approvals) -> " + post(L.buildRecoverTx(id, pub(device3), 2, approvals)));
        sleep();
        System.out.println("    recovered device transfer -> " + post(transfer(id, device3, dest, 10, 2, nonceOf(id))));
        sleep();
        System.out.println("    final identity balance=" + balance(id));
        System.out.println("\nDONE.");
    }
}
