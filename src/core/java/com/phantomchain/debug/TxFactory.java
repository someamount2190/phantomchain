package com.phantomchain.debug;

import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;

/**
 * Client-side transaction construction — the signed-tx builders, extracted from {@link Ledger}.
 *
 * These are pure constructors: build the canonical preimage for a tx type, sign it with the caller's key,
 * and return the wire JSON. They read only {@code chainId} (for domain separation) — no consensus state —
 * so they belong with "how a wallet/node builds a tx", not with the state machine. {@link Ledger} keeps
 * thin delegators so call sites (NodeRpc, the wallet, tests) are unchanged.
 */
final class TxFactory {
    private TxFactory() {}

    static JSONObject buildVouchTx(Ledger l, String voucher, String candidate, MLDSAPrivateKeyParameters key) throws Exception {
        byte[] sig = PhantomCrypto.sign(key, PhantomCrypto.utf8("vouch|" + l.chainId + "|" + candidate));
        return new JSONObject().put("from", "VOUCH").put("voucher", voucher).put("candidate", candidate).put("cid", l.chainId).put("sig", PhantomCrypto.hex(sig));
    }

    static JSONObject buildRegisterTx(Ledger l, MLDSAPrivateKeyParameters rootKey, MLDSAPrivateKeyParameters deviceKey) throws Exception {
        String root = PhantomCrypto.hex(rootKey.getPublicKeyParameters().getEncoded());
        String device = PhantomCrypto.hex(deviceKey.getPublicKeyParameters().getEncoded());
        byte[] sig = PhantomCrypto.sign(rootKey, PhantomCrypto.utf8("register|" + l.chainId + "|" + root + "|" + device));
        return new JSONObject().put("from", "REGISTER").put("root", root).put("device", device).put("cid", l.chainId).put("sig", PhantomCrypto.hex(sig));
    }
    static JSONObject buildRotateTx(Ledger l, String id, MLDSAPrivateKeyParameters rootKey, String newDevice, long rotNonce) throws Exception {
        byte[] sig = PhantomCrypto.sign(rootKey, PhantomCrypto.utf8("rotate|" + l.chainId + "|" + id + "|" + newDevice + "|" + rotNonce));
        return new JSONObject().put("from", "ROTATE").put("id", id).put("newDevice", newDevice).put("rotNonce", rotNonce).put("cid", l.chainId).put("sig", PhantomCrypto.hex(sig));
    }
    static JSONObject buildSetGuardiansTx(Ledger l, String id, MLDSAPrivateKeyParameters rootKey, JSONArray guardians, int threshold, long rotNonce) throws Exception {
        byte[] sig = PhantomCrypto.sign(rootKey, PhantomCrypto.utf8("setguardians|" + l.chainId + "|" + id + "|" + guardians.toString() + "|" + threshold + "|" + rotNonce));
        return new JSONObject().put("from", "SETGUARDIANS").put("id", id).put("guardians", guardians).put("threshold", threshold).put("rotNonce", rotNonce).put("cid", l.chainId).put("sig", PhantomCrypto.hex(sig));
    }
    static JSONObject recoverApproval(Ledger l, String guardianId, MLDSAPrivateKeyParameters guardianDeviceKey, String id, String newDevice, long rotNonce) throws Exception {
        String pub = PhantomCrypto.hex(guardianDeviceKey.getPublicKeyParameters().getEncoded());
        byte[] sig = PhantomCrypto.sign(guardianDeviceKey, PhantomCrypto.utf8("recover|" + l.chainId + "|" + id + "|" + newDevice + "|" + rotNonce));
        return new JSONObject().put("guardian", guardianId).put("pub", pub).put("sig", PhantomCrypto.hex(sig));
    }
    static JSONObject buildRecoverTx(Ledger l, String id, String newDevice, long rotNonce, JSONArray approvals) throws Exception {
        return new JSONObject().put("from", "RECOVER").put("id", id).put("newDevice", newDevice).put("rotNonce", rotNonce).put("cid", l.chainId).put("approvals", approvals);
    }

    static JSONObject buildSetBeneficiaryTx(Ledger l, String actor, String beneficiaryId, long nonce, MLDSAPrivateKeyParameters key) throws Exception {
        JSONObject tx = new JSONObject().put("from", "SETBENEFICIARY").put("actor", actor).put("beneficiary", beneficiaryId).put("nonce", nonce).put("cid", l.chainId)
                .put("pub", PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded()));
        return tx.put("sig", PhantomCrypto.hex(PhantomCrypto.sign(key, PhantomCrypto.utf8(Ledger.actionCanon(tx)))));
    }
    static JSONObject buildClaimTx(Ledger l, String account, long salt) throws Exception {
        return new JSONObject().put("from", "CLAIM").put("account", account).put("salt", salt).put("cid", l.chainId);
    }

    static JSONObject buildValJoinTx(Ledger l, MLDSAPrivateKeyParameters key) throws Exception {
        String pub = PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded());
        String commit0 = Ledger.beaconCommit0For(key.getEncoded());
        byte[] sig = PhantomCrypto.sign(key, PhantomCrypto.utf8("valjoin|" + l.chainId + "|" + pub + "|" + commit0));
        return new JSONObject().put("from", "VALJOIN").put("pubkey", pub).put("cid", l.chainId).put("beaconCommit0", commit0).put("sig", PhantomCrypto.hex(sig));
    }

    static JSONObject buildClusterFormTx(Ledger l, String clusterId, List<String> members, Map<String, String> memberPubs,
                                         int threshold, MLDSAPrivateKeyParameters initKey, String beaconCommit0) throws Exception {
        JSONArray ms = new JSONArray(); for (String m : members) ms.put(m);
        JSONObject mp = new JSONObject(); for (Map.Entry<String, String> e : memberPubs.entrySet()) mp.put(e.getKey(), e.getValue());
        String initPub = PhantomCrypto.hex(initKey.getPublicKeyParameters().getEncoded());
        byte[] sig = PhantomCrypto.sign(initKey, PhantomCrypto.utf8(Ledger.clusterFormCanon(l.chainId, clusterId, ms, threshold) + "|" + beaconCommit0));
        return new JSONObject().put("from", "CLUSTERFORM").put("clusterId", clusterId).put("members", ms)
                .put("memberPubs", mp).put("threshold", threshold).put("cid", l.chainId)
                .put("initPub", initPub).put("beaconCommit0", beaconCommit0).put("sig", PhantomCrypto.hex(sig));
    }
    static JSONObject buildClusterDisbandTx(Ledger l, String clusterId, List<MLDSAPrivateKeyParameters> memberKeys) throws Exception {
        String canon = Ledger.clusterDisbandCanon(l.chainId, clusterId);
        JSONArray approvals = new JSONArray();
        for (MLDSAPrivateKeyParameters mk : memberKeys)
            approvals.put(new JSONObject().put("m", Ledger.idOf(PhantomCrypto.hex(mk.getPublicKeyParameters().getEncoded())))
                    .put("sig", PhantomCrypto.hex(PhantomCrypto.sign(mk, PhantomCrypto.utf8(canon)))));
        return new JSONObject().put("from", "CLUSTERDISBAND").put("clusterId", clusterId).put("cid", l.chainId).put("approvals", approvals);
    }

    static JSONObject buildBridgeOutTx(Ledger l, String actor, String chain, String ext, long amount, long fee, long nonce, MLDSAPrivateKeyParameters key) throws Exception {
        JSONObject tx = new JSONObject().put("from", "BRIDGE_OUT").put("actor", actor).put("chain", chain).put("extAddr", ext)
                .put("amount", amount).put("fee", fee).put("nonce", nonce).put("cid", l.chainId)
                .put("pub", PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded()));
        return tx.put("sig", PhantomCrypto.hex(PhantomCrypto.sign(key, PhantomCrypto.utf8(Ledger.bridgeOutCanon(tx)))));
    }
    static JSONObject bridgeInApproval(Ledger l, String custodianId, MLDSAPrivateKeyParameters custKey, String recipient, long amount, String extTxid) throws Exception {
        String pub = PhantomCrypto.hex(custKey.getPublicKeyParameters().getEncoded());
        byte[] sig = PhantomCrypto.sign(custKey, PhantomCrypto.utf8("bridgein|" + l.chainId + "|" + recipient + "|" + amount + "|" + extTxid));
        return new JSONObject().put("custodian", custodianId).put("pub", pub).put("sig", PhantomCrypto.hex(sig));
    }
    static JSONObject buildBridgeInTx(Ledger l, String recipient, long amount, String extTxid, JSONArray approvals) throws Exception {
        return new JSONObject().put("from", "BRIDGE_IN").put("recipient", recipient).put("amount", amount)
                .put("extTxid", extTxid).put("cid", l.chainId).put("approvals", approvals);
    }
    static JSONObject buildOracleTx(Ledger l, String custodianId, MLDSAPrivateKeyParameters custKey, String pair, long rate) throws Exception {
        String pub = PhantomCrypto.hex(custKey.getPublicKeyParameters().getEncoded());
        byte[] sig = PhantomCrypto.sign(custKey, PhantomCrypto.utf8("oracle|" + l.chainId + "|" + pair + "|" + rate));
        return new JSONObject().put("from", "ORACLE").put("custodian", custodianId).put("pub", pub).put("pair", pair).put("rate", rate).put("cid", l.chainId).put("sig", PhantomCrypto.hex(sig));
    }

    static JSONObject buildBondTx(Ledger l, String actor, long amount, long nonce, boolean unbond, MLDSAPrivateKeyParameters key) throws Exception {
        JSONObject tx = new JSONObject().put("from", unbond ? "UNBOND" : "BOND").put("actor", actor).put("amount", amount).put("nonce", nonce).put("cid", l.chainId)
                .put("pub", PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded()));
        return tx.put("sig", PhantomCrypto.hex(PhantomCrypto.sign(key, PhantomCrypto.utf8(Ledger.actionCanon(tx)))));
    }
    static JSONObject buildUnjailTx(Ledger l, String actor, long nonce, MLDSAPrivateKeyParameters key) throws Exception {
        JSONObject tx = new JSONObject().put("from", "UNJAIL").put("actor", actor).put("nonce", nonce).put("cid", l.chainId)
                .put("pub", PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded()));
        return tx.put("sig", PhantomCrypto.hex(PhantomCrypto.sign(key, PhantomCrypto.utf8(Ledger.actionCanon(tx)))));
    }
    static JSONObject buildProposeTx(Ledger l, String actor, String propId, String param, long value, long nonce, MLDSAPrivateKeyParameters key) throws Exception {
        JSONObject tx = new JSONObject().put("from", "PROPOSE").put("actor", actor).put("propId", propId).put("param", param).put("value", value).put("nonce", nonce).put("cid", l.chainId)
                .put("pub", PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded()));
        return tx.put("sig", PhantomCrypto.hex(PhantomCrypto.sign(key, PhantomCrypto.utf8(Ledger.actionCanon(tx)))));
    }
    static JSONObject buildVoteTx(Ledger l, String actor, String propId, boolean choice, long nonce, MLDSAPrivateKeyParameters key) throws Exception {
        JSONObject tx = new JSONObject().put("from", "VOTE").put("actor", actor).put("propId", propId).put("choice", choice).put("nonce", nonce).put("cid", l.chainId)
                .put("pub", PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded()));
        return tx.put("sig", PhantomCrypto.hex(PhantomCrypto.sign(key, PhantomCrypto.utf8(Ledger.actionCanon(tx)))));
    }
}
