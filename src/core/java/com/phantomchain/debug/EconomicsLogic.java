package com.phantomchain.debug;

import java.util.HashMap;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Monetary policy — emission, epoch reward distribution, and supply accounting, extracted from
 * {@link Ledger}.
 *
 * The decaying, supply-capped block reward; the per-epoch split of newly-minted emission by on-chain
 * contribution (proposer bonus + one unit per QC signature), with cluster shares fanned out to member
 * identities; and live circulating-supply accounting. Economic STATE (supply counters and the governable
 * params) stays in {@link Ledger}; thin delegators keep the API. Guarded by the economics sims
 * (LongRunEconSim / EconStabilitySim) and ClusterTest's emission checks.
 */
final class EconomicsLogic {
    private EconomicsLogic() {}

    /** Decaying emission: blockReward halved once per halvingBlocks. Deterministic, capped by maxSupply. */
    static long blockRewardAt(Ledger l, int height) {
        if (height <= 0) return 0;
        int halvings = l.halvingBlocks > 0 ? (height - 1) / l.halvingBlocks : 0;
        if (halvings > 62) return 0;
        return l.blockReward >> halvings;
    }

    /** At each epoch boundary, mint emission (decaying curve, supply-capped) and split by on-chain
     *  contribution (QC sigs + proposer bonus). */
    static void maybeEpochReward(Ledger l) throws Exception {
        int h = l.chain.size() - 1;
        if (h < 1 || h % Ledger.EPOCH_LEN != 0) return;
        Map<String, Long> units = new HashMap<>();
        long pool = 0;
        for (int hi = h - Ledger.EPOCH_LEN + 1; hi <= h; hi++) {
            pool += blockRewardAt(l, hi);
            JSONObject blk = l.chain.get(hi);
            int prop = blk.optInt("proposer", -1);
            if (prop >= 0 && prop < l.validators.size()) units.merge(l.validators.get(prop), (long) Ledger.PROPOSER_BONUS, Long::sum);
            JSONArray qc = blk.optJSONArray("qc");
            if (qc != null) for (int k = 0; k < qc.length(); k++) {
                int si = qc.getJSONObject(k).getInt("i");
                if (si >= 0 && si < l.validators.size()) units.merge(l.validators.get(si), 1L, Long::sum);
            }
        }
        if (l.totalMinted + pool > l.maxSupply) pool = Math.max(0, l.maxSupply - l.totalMinted);   // emission cap
        long totalU = 0; for (long u : units.values()) totalU += u;
        if (totalU <= 0 || pool <= 0) return;
        long distributed = 0;
        for (Map.Entry<String, Long> e : units.entrySet()) {
            long share = pool * e.getValue() / totalU;
            creditEarner(l, e.getKey(), share);   // cluster shares fan out directly to member identities (§9.6)
            distributed += share;
        }
        l.totalMinted += distributed;
    }

    /** Credit a reward share: a cluster id fans out evenly to its members; otherwise straight to the account. */
    static void creditEarner(Ledger l, String valId, long share) throws Exception {
        if (share <= 0) return;
        JSONObject c = l.clusters.get(valId);
        if (c != null) {
            JSONArray ms = c.getJSONArray("members"); int n = ms.length();
            long per = share / n, rem = share - per * n;
            for (int i = 0; i < n; i++) {
                String mid = ms.getString(i); long amt = per + (i < rem ? 1 : 0);
                Ledger.Account a = l.accounts.get(mid); if (a == null) { a = new Ledger.Account(); l.accounts.put(mid, a); }
                a.balance += amt;
            }
        } else {
            Ledger.Account a = l.accounts.get(valId); if (a == null) { a = new Ledger.Account(); l.accounts.put(valId, a); }
            a.balance += share;
        }
    }

    /** Live token supply: liquid balances + bonded stake + tokens mid-unbond. */
    static long circulatingSupply(Ledger l) {
        long s = 0;
        for (Ledger.Account a : l.accounts.values()) s += a.balance;
        for (long v : l.stake.values()) s += v;
        for (JSONObject u : l.unbonding) s += u.optLong("amount", 0);
        return s;
    }
}
