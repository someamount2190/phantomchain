package com.phantomchain.debug;

import org.json.JSONObject;

/**
 * Estate / inheritance policy — extracted from {@link Ledger}.
 *
 * Two pieces of consensus-relevant policy: which party an action attributes to (so an OUTGOING action
 * resets the inactivity clock while an INCOMING transfer does not), and whether a CLAIM is permitted
 * (beneficiary set, non-empty balance, sustained inactivity). Estate STATE (beneficiary / lastActive /
 * estateInactivity) stays in {@link Ledger}; this owns the rules. Guarded by {@code EstateAttackTest} +
 * {@code EstateTest}.
 */
final class EstateLogic {
    private EstateLogic() {}

    /** The party whose action this tx represents (resets the inactivity clock). Incoming transfers do NOT. */
    static String activeParty(JSONObject tx) {
        String t = tx.optString("from");
        if (!Ledger.SPECIAL.contains(t)) return t;   // transfer: the sender
        switch (t) {
            case "BOND": case "UNBOND": case "UNJAIL": case "PROPOSE": case "VOTE": case "SETBENEFICIARY": return tx.optString("actor", null);
            case "REGISTER": { String r = tx.optString("root", ""); return r.isEmpty() ? null : Ledger.idOf(r); }
            case "ROTATE": case "RECOVER": case "SETGUARDIANS": return tx.optString("id", null);
            case "VOUCH": return tx.optString("voucher", null);
            default: return null;   // GENESIS, SLASH, CLAIM
        }
    }

    static boolean verifyClaim(Ledger l, JSONObject tx) throws Exception {
        if (!l.chainId.equals(tx.optString("cid", ""))) return false;
        String acct = tx.getString("account");
        return l.beneficiary.containsKey(acct) && l.balanceOf(acct) > 0
                && l.height() - l.lastActive.getOrDefault(acct, 0L) >= l.estateInactivity;   // inactive long enough
    }
}
