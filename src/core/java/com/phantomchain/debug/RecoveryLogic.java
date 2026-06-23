package com.phantomchain.debug;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Identity key-management & guardian recovery verification — extracted from {@link Ledger}.
 *
 * Identity STATE (the {@code identities} map) stays in {@link Ledger}; this owns the authorization
 * checks: one-time REGISTER, root-authorized ROTATE / SETGUARDIANS (rotNonce replay guard), and the
 * M-of-N guardian RECOVER. Guarded by {@code RecoveryAttackTest} / {@code IdentityTest}.
 */
final class RecoveryLogic {
    private RecoveryLogic() {}

    static boolean verifyRegister(Ledger l, JSONObject tx) throws Exception {
        if (!l.chainId.equals(tx.optString("cid", ""))) return false;
        String root = tx.getString("root"), device = tx.getString("device");
        if (l.identities.containsKey(Ledger.idOf(root))) return false;   // one-time
        return PhantomCrypto.verify(Ledger.pk(root), PhantomCrypto.utf8("register|" + l.chainId + "|" + root + "|" + device), PhantomCrypto.unhex(tx.getString("sig")));
    }

    static boolean verifyRootOp(Ledger l, JSONObject tx, String msg) throws Exception {
        if (!l.chainId.equals(tx.optString("cid", ""))) return false;
        JSONObject idn = l.identities.get(tx.getString("id"));
        if (idn == null || tx.getLong("rotNonce") != idn.getLong("rotNonce")) return false;   // replay-protected by rotNonce
        return PhantomCrypto.verify(Ledger.pk(idn.getString("root")), PhantomCrypto.utf8(msg), PhantomCrypto.unhex(tx.getString("sig")));
    }

    static boolean verifyRotate(Ledger l, JSONObject tx) throws Exception {
        return verifyRootOp(l, tx, "rotate|" + l.chainId + "|" + tx.getString("id") + "|" + tx.getString("newDevice") + "|" + tx.getLong("rotNonce"));
    }

    static boolean verifySetGuardians(Ledger l, JSONObject tx) throws Exception {
        return verifyRootOp(l, tx, "setguardians|" + l.chainId + "|" + tx.getString("id") + "|" + tx.getJSONArray("guardians").toString() + "|" + tx.getInt("threshold") + "|" + tx.getLong("rotNonce"));
    }

    static boolean verifyRecover(Ledger l, JSONObject tx) throws Exception {
        if (!l.chainId.equals(tx.optString("cid", ""))) return false;
        JSONObject idn = l.identities.get(tx.getString("id"));
        if (idn == null || tx.getLong("rotNonce") != idn.getLong("rotNonce")) return false;
        JSONArray gs = idn.getJSONArray("guardians"); int threshold = idn.getInt("threshold");
        java.util.Set<String> guardianSet = new java.util.HashSet<>(); for (int i = 0; i < gs.length(); i++) guardianSet.add(gs.getString(i));
        String msg = "recover|" + l.chainId + "|" + tx.getString("id") + "|" + tx.getString("newDevice") + "|" + tx.getLong("rotNonce");
        JSONArray ap = tx.getJSONArray("approvals"); java.util.Set<String> seen = new java.util.HashSet<>(); int ok = 0;
        for (int i = 0; i < ap.length(); i++) {
            JSONObject a = ap.getJSONObject(i);
            String g = a.getString("guardian"), ph = a.getString("pub");
            if (!guardianSet.contains(g) || !seen.add(g)) continue;        // distinct guardian
            JSONObject gidn = l.identities.get(g); if (gidn == null) continue;
            boolean dev = false; JSONArray gd = gidn.getJSONArray("devices");
            for (int j = 0; j < gd.length(); j++) if (gd.getString(j).equals(ph)) dev = true;
            if (dev && PhantomCrypto.verify(Ledger.pk(ph), PhantomCrypto.utf8(msg), PhantomCrypto.unhex(a.getString("sig")))) ok++;
        }
        return threshold > 0 && ok >= threshold;
    }
}
