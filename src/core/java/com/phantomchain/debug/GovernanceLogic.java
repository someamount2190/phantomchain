package com.phantomchain.debug;

import org.json.JSONObject;

/**
 * On-chain governance — the two-phase proposal lifecycle, extracted from {@link Ledger}.
 *
 * Governance STATE (the {@code proposals} map and the governable parameter fields) stays in
 * {@link Ledger}; this owns the policy: at a proposal's deadline, tally snapshot-weighted votes against a
 * turnout quorum (snapshot weights prevent last-minute stake grinding); if it passes, apply only after a
 * timelock (so the network can react to a malicious change); and clamp every applied value to safe bounds
 * (e.g. slashing can't be disabled, maxSupply can't drop below already-minted). Guarded by
 * {@code GovernanceAttackTest}.
 */
final class GovernanceLogic {
    private GovernanceLogic() {}

    /** At deadline, tally snapshot-weighted votes with a turnout quorum; if it passes, apply after the timelock. */
    static void finalizeProposals(Ledger l) throws Exception {
        int H = l.height();
        for (JSONObject p : l.proposals.values()) {
            if (p.getBoolean("executed")) continue;
            if (!p.getBoolean("tallied") && H >= p.getLong("deadline")) {
                JSONObject votes = p.getJSONObject("votes"), snap = p.getJSONObject("snapshot");
                long yes = 0, no = 0;
                for (String voter : Ledger.keysOf(votes)) {
                    long w = snap.optLong(voter, 0);                       // snapshot weight (no last-minute stake grinding)
                    if (votes.getBoolean(voter)) yes += w; else no += w;
                }
                long total = p.getLong("totalWeight");
                boolean turnout = total > 0 && (yes + no) * 10000L >= total * (long) Ledger.GOV_QUORUM_BPS;
                p.put("tallied", true).put("passed", turnout && yes > no);
            }
            if (p.getBoolean("tallied") && p.getBoolean("passed") && H >= p.getLong("applyAt")) {
                applyParam(l, p.getString("param"), p.getLong("value"));     // timelocked execution
                p.put("executed", true);
            }
        }
    }

    /** Apply a passed proposal's value, clamped to safe bounds — governance cannot set unsafe values. */
    static void applyParam(Ledger l, String param, long v) {
        switch (param) {
            case "blockReward":       l.blockReward = Ledger.clamp(v, 0, 1_000_000L);                       break;
            case "halvingBlocks":     l.halvingBlocks = (int) Ledger.clamp(v, 1, 100_000_000L);             break;
            case "maxSupply":         l.maxSupply = Ledger.clamp(v, l.totalMinted, 1_000_000_000_000L);     break;   // never below already-minted
            case "feeBurnBps":        l.feeBurnBps = (int) Ledger.clamp(v, 0, 10000);                       break;
            case "slashBps":          l.slashBps = (int) Ledger.clamp(v, 100, 10000);                       break;   // floor: slashing can't be disabled
            case "jailBlocks":        l.jailBlocks = (int) Ledger.clamp(v, 1, 100_000_000L);                break;
            case "unbondingBlocks":   l.unbondingBlocks = (int) Ledger.clamp(v, 1, 100_000_000L);           break;
            case "estateInactivity":  l.estateInactivity = Ledger.clamp(v, 1, 100_000_000L);                break;
            case "minValidatorStake": l.minValidatorStake = (int) Ledger.clamp(v, 1, 1_000_000_000L);       break;
            case "bridgeThreshold":   l.bridgeThreshold = (int) Ledger.clamp(v, 1, 1000);                   break;
            case "identityBond":      l.identityBond = Ledger.clamp(v, 0, 1_000_000_000L);                  break;
            case "committeeSize":     l.committeeSize = (int) Ledger.clamp(v, 0, 100_000L);                 break;
        }
    }
}
