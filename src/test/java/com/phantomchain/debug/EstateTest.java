package com.phantomchain.debug;

import static com.phantomchain.debug.TestKit.*;

import java.io.File;
import javax.net.ssl.SSLContext;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;

/** End-to-end estate/inheritance test: A registers, funds, names B as beneficiary, goes inactive,
 *  then anyone CLAIMs and the estate moves to B. Usage: EstateTest <node> <truststore.p12> */
public class EstateTest {
    static String NODE; static SSLContext TLS; static String CID; static Ledger L = new Ledger();
    static String get(String p) throws Exception { return Wallet.rpcGet(NODE, TLS, p).trim(); }
    static String post(JSONObject tx) throws Exception { return Wallet.rpcPost(NODE, TLS, "/gossip/tx", tx.toString()).trim(); }
    static long bal(String id) throws Exception { return new JSONObject(get("/account?id=" + id)).getLong("balance"); }
    static long nonce(String id) throws Exception { return new JSONObject(get("/account?id=" + id)).getLong("nonce"); }
    static MLDSAPrivateKeyParameters k() { return PhantomCrypto.randomDeviceKey(); }
    static String pub(MLDSAPrivateKeyParameters x) { return PhantomCrypto.hex(x.getPublicKeyParameters().getEncoded()); }
    static void nap() throws Exception { Thread.sleep(7000); }

    public static void main(String[] a) throws Exception {
        NODE = a[0]; TLS = Wallet.tlsTrusting(new File(a[1]), "phantomchain".toCharArray());
        CID = new JSONObject(get("/genesis")).getString("chainId"); L.chainId = CID;

        MLDSAPrivateKeyParameters rootA = k(), devA = k();
        String idA = Ledger.idOf(pub(rootA));
        String B = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.unhex(pub(k()))));   // beneficiary account
        System.out.println("A=" + idA.substring(0, 12) + "  B=" + B.substring(0, 12));
        System.out.println("[1] register A   -> " + post(L.buildRegisterTx(rootA, devA))); nap();
        System.out.println("[2] fund A 5000  -> " + Wallet.rpcGet(NODE, TLS, "/submit?to=" + idA + "&amount=5000&fee=1")); nap();
        System.out.println("    A=" + bal(idA) + " B=" + bal(B));
        System.out.println("[3] A names B as beneficiary -> " + post(L.buildSetBeneficiaryTx(idA, B, nonce(idA), devA))); nap();
        System.out.println("[4] premature CLAIM (must reject) -> " + post(L.buildClaimTx(idA, 1)));
        System.out.println("    advancing >estateInactivity(10) blocks while A stays inactive...");
        for (int n = 0; n < 13; n++) { Wallet.rpcGet(NODE, TLS, "/submit?to=" + B + "&amount=1&fee=1"); Thread.sleep(1100); }
        System.out.println("[5] CLAIM A's estate -> " + post(L.buildClaimTx(idA, 2))); nap();
        System.out.println("    FINAL A=" + bal(idA) + " B=" + bal(B) + "  (A should be 0, B inherited)");
        System.out.println("DONE.");
    }
}
