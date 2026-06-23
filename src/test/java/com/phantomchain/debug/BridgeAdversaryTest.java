package com.phantomchain.debug;

import static com.phantomchain.debug.TestKit.*;

import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

/**
 * BRIDGE adversarial testing — the cross-chain custodian path is the project's explicit trusted surface,
 * so its ON-CHAIN guards must hold: M-of-N distinct registered custodian attestations, replay protection,
 * reserve conservation, and custodian-only oracle posting. Attacks the real verifyBridgeIn / verifyOracle.
 */
public class BridgeAdversaryTest {

    static Map<String, MLDSAPublicKeyParameters> pub = new HashMap<>();
    static String[] ids; static MLDSAPrivateKeyParameters[] keys;

    public static void main(String[] a) throws Exception {
        System.out.println("==== BRIDGE adversarial (custodian M-of-N + replay + oracle) ====\n");
        int n = 5;
        keys = new MLDSAPrivateKeyParameters[n]; ids = new String[n];
        LinkedHashMap<String, Long> alloc = new LinkedHashMap<>();
        List<String> vals = new ArrayList<>(); Map<String, Long> stk = new HashMap<>(), idn = new HashMap<>();
        Set<String> ver = new HashSet<>(); Map<String, String> vp = new HashMap<>(), bc = new HashMap<>();
        for (int i = 0; i < n; i++) {
            keys[i] = PhantomCrypto.randomDeviceKey();
            ids[i] = PhantomCrypto.hex(PhantomCrypto.sha3_256(keys[i].getPublicKeyParameters().getEncoded()));
            pub.put(ids[i], new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, keys[i].getPublicKeyParameters().getEncoded()));
            alloc.put(ids[i], 1_000_000L); vals.add(ids[i]); stk.put(ids[i], 1_000_000L); idn.put(ids[i], 1L);
            ver.add(ids[i]); vp.put(ids[i], PhantomCrypto.hex(keys[i].getPublicKeyParameters().getEncoded()));
            bc.put(ids[i], Ledger.beaconCommit0For(keys[i].getEncoded()));
        }
        alloc.put(Ledger.BRIDGE_RESERVE, 1_000_000L);                 // fund the reserve
        Ledger L = new Ledger();
        L.genesisEcon("pc-bridge", alloc, vals, stk, idn, ver, vp, bc, 1700000000000L);

        // register 3 custodians, threshold 2-of-3
        MLDSAPrivateKeyParameters[] cust = { PhantomCrypto.randomDeviceKey(), PhantomCrypto.randomDeviceKey(), PhantomCrypto.randomDeviceKey() };
        String[] cid = new String[3];
        for (int i = 0; i < 3; i++) { String cp = PhantomCrypto.hex(cust[i].getPublicKeyParameters().getEncoded()); cid[i] = Ledger.idOf(cp); L.custodians.put(cid[i], cp); }
        L.bridgeThreshold = 2;

        String recip = ids[0]; long amt = 1000;
        // ---- BRIDGE_IN (inbound mint from reserve) ----
        ok("control: 2-of-3 distinct custodian attestations release from the reserve", L.verifyBridgeIn(
                L.buildBridgeInTx(recip, amt, "ext-1", new JSONArray()
                        .put(L.bridgeInApproval(cid[0], cust[0], recip, amt, "ext-1"))
                        .put(L.bridgeInApproval(cid[1], cust[1], recip, amt, "ext-1")))) ? trueOk() : false);

        ok("B1 sub-threshold (1 of 3) attestation is rejected", !L.verifyBridgeIn(
                L.buildBridgeInTx(recip, amt, "ext-2", new JSONArray().put(L.bridgeInApproval(cid[0], cust[0], recip, amt, "ext-2")))));

        ok("B2 duplicate custodian (same custodian signs twice) doesn't count as 2-of-N", !L.verifyBridgeIn(
                L.buildBridgeInTx(recip, amt, "ext-3", new JSONArray()
                        .put(L.bridgeInApproval(cid[0], cust[0], recip, amt, "ext-3"))
                        .put(L.bridgeInApproval(cid[0], cust[0], recip, amt, "ext-3")))));

        // non-custodian: a random key claiming an unregistered custodian id
        MLDSAPrivateKeyParameters outsider = PhantomCrypto.randomDeviceKey();
        String outId = Ledger.idOf(PhantomCrypto.hex(outsider.getPublicKeyParameters().getEncoded()));
        ok("B3 attestation from a NON-custodian key is rejected", !L.verifyBridgeIn(
                L.buildBridgeInTx(recip, amt, "ext-4", new JSONArray()
                        .put(L.bridgeInApproval(cid[0], cust[0], recip, amt, "ext-4"))
                        .put(L.bridgeInApproval(outId, outsider, recip, amt, "ext-4")))));

        // forged signature: valid custodian id+pub but a garbage sig
        JSONObject badAppr = L.bridgeInApproval(cid[1], cust[1], recip, amt, "ext-5").put("sig", "00");
        ok("B4 forged custodian signature is rejected", !L.verifyBridgeIn(
                L.buildBridgeInTx(recip, amt, "ext-5", new JSONArray().put(L.bridgeInApproval(cid[0], cust[0], recip, amt, "ext-5")).put(badAppr))));

        // approvals over a DIFFERENT (amount/recipient) than the tx claims -> sig msg mismatch
        ok("B5 attestations bound to a different amount can't be reused for a larger mint", !L.verifyBridgeIn(
                L.buildBridgeInTx(recip, 5000, "ext-6", new JSONArray()
                        .put(L.bridgeInApproval(cid[0], cust[0], recip, amt, "ext-6"))     // signed for amt=1000
                        .put(L.bridgeInApproval(cid[1], cust[1], recip, amt, "ext-6")))));  // but tx asks 5000

        ok("B6 release exceeding the reserve balance is rejected (conservation)", !L.verifyBridgeIn(
                L.buildBridgeInTx(recip, 2_000_000L, "ext-7", new JSONArray()
                        .put(L.bridgeInApproval(cid[0], cust[0], recip, 2_000_000L, "ext-7"))
                        .put(L.bridgeInApproval(cid[1], cust[1], recip, 2_000_000L, "ext-7")))));

        ok("B7 non-positive amount is rejected", !L.verifyBridgeIn(
                L.buildBridgeInTx(recip, 0, "ext-8", new JSONArray()
                        .put(L.bridgeInApproval(cid[0], cust[0], recip, 0, "ext-8"))
                        .put(L.bridgeInApproval(cid[1], cust[1], recip, 0, "ext-8")))));

        // replay: mark the external txid processed, then a fresh valid attestation set must still be rejected
        L.bridgeProcessed.add("ext-9");
        ok("B8 replay of an already-processed external txid is rejected", !L.verifyBridgeIn(
                L.buildBridgeInTx(recip, amt, "ext-9", new JSONArray()
                        .put(L.bridgeInApproval(cid[0], cust[0], recip, amt, "ext-9"))
                        .put(L.bridgeInApproval(cid[1], cust[1], recip, amt, "ext-9")))));

        // ---- ORACLE (custodian-only rate feed) ----
        ok("O1 oracle post by a NON-custodian is rejected", !L.verifyOracle(
                buildOracle("ETH/PHNT", 1234, outsider)));
        ok("control: oracle post by a registered custodian is accepted", L.verifyOracle(
                L.buildOracleTx(cid[2], cust[2], "ETH/PHNT", 1234)) ? trueOk() : false);

        System.out.println("\n==== BridgeAdversaryTest: " + pass + " passed, " + fail + " failed ====");
        System.exit(fail == 0 ? 0 : 1);
    }

    static boolean trueOk() { return true; }   // readability: control cases assert the defense ALLOWS the valid op
    /** An oracle tx claiming a custodian id that isn't registered (signed by an outsider key). */
    static JSONObject buildOracle(String pair, long rate, MLDSAPrivateKeyParameters key) throws Exception {
        String p = PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded());
        String id = Ledger.idOf(p);
        byte[] sig = PhantomCrypto.sign(key, PhantomCrypto.utf8("oracle|pc-bridge|" + pair + "|" + rate));
        return new JSONObject().put("from", "ORACLE").put("custodian", id).put("pub", p).put("pair", pair).put("rate", rate).put("cid", "pc-bridge").put("sig", PhantomCrypto.hex(sig));
    }
}
