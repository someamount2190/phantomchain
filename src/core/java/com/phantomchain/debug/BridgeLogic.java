package com.phantomchain.debug;

import java.util.HashSet;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Cross-chain bridge verification — the trusted custodian M-of-N surface, extracted from {@link Ledger}.
 *
 * Bridge state (custodians, bridgeThreshold, bridgeProcessed, oracleRates) stays in {@link Ledger}; this
 * class owns the consensus/security-relevant CHECKS (the part an auditor reads to convince themselves the
 * bridge can't mint without a real M-of-N quorum). {@link Ledger} keeps thin delegators so call sites are
 * unchanged. Guarded by {@code BridgeTest} + {@code BridgeAdversaryTest}.
 */
final class BridgeLogic {
    private BridgeLogic() {}

    static String bridgeOutCanon(JSONObject tx) throws Exception {
        return "bridgeout|" + tx.optString("cid", "") + "|" + tx.getString("actor") + "|" + tx.getString("chain")
                + "|" + tx.getString("extAddr") + "|" + tx.getLong("amount") + "|" + tx.optLong("fee", 0) + "|" + tx.getLong("nonce");
    }

    /** Inbound: >=M custodians attest an external deposit -> release PHNT from the reserve to the recipient. */
    static boolean verifyBridgeIn(Ledger l, JSONObject tx) throws Exception {
        if (!l.chainId.equals(tx.optString("cid", ""))) return false;
        if (l.bridgeProcessed.contains(tx.getString("extTxid"))) return false;       // replay guard
        String recipient = tx.getString("recipient"); long amount = tx.getLong("amount");
        if (amount <= 0 || l.balanceOf(Ledger.BRIDGE_RESERVE) < amount) return false; // conservation: release only what's reserved
        String msg = "bridgein|" + l.chainId + "|" + recipient + "|" + amount + "|" + tx.getString("extTxid");
        JSONArray ap = tx.getJSONArray("approvals"); Set<String> seen = new HashSet<>(); int ok = 0;
        for (int i = 0; i < ap.length(); i++) {
            JSONObject a = ap.getJSONObject(i);
            String cust = a.getString("custodian"), pub = a.getString("pub");
            if (!pub.equals(l.custodians.get(cust)) || !seen.add(cust)) continue;     // distinct, registered custodian
            if (PhantomCrypto.verify(Ledger.pk(pub), PhantomCrypto.utf8(msg), PhantomCrypto.unhex(a.getString("sig")))) ok++;
        }
        return ok >= l.bridgeThreshold;
    }

    static boolean verifyOracle(Ledger l, JSONObject tx) throws Exception {
        if (!l.chainId.equals(tx.optString("cid", ""))) return false;
        String cust = tx.getString("custodian"), pub = tx.getString("pub");
        if (!pub.equals(l.custodians.get(cust))) return false;   // only registered custodians may post rates
        return PhantomCrypto.verify(Ledger.pk(pub), PhantomCrypto.utf8("oracle|" + l.chainId + "|" + tx.getString("pair") + "|" + tx.getLong("rate")), PhantomCrypto.unhex(tx.getString("sig")));
    }

    /** Current price = median of custodian-attested rates for a pair (manipulation-resistant). */
    static long oracleMedian(Ledger l, String pair) {
        java.util.Map<String, Long> rs = l.oracleRates.get(pair);
        if (rs == null || rs.isEmpty()) return 0;
        java.util.List<Long> v = new java.util.ArrayList<>(rs.values()); java.util.Collections.sort(v);
        return v.get(v.size() / 2);
    }
}
