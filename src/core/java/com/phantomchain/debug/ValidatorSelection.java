package com.phantomchain.debug;

import java.util.ArrayList;

/**
 * Validator weighting, proposer election, and committee sortition — extracted from {@link Ledger}.
 *
 * Pure functions of committed state (validator set, stake, verified-identity, regions, beacon): the
 * §9 weight model (0.6·√stake-share + 0.4·identity-share, a geo-coverage premium, renormalization, and
 * the §9.4 10% per-validator hard cap), the weighted RANDAO {@code proposerFor}, and the beacon-
 * sortitioned signing {@code committeeFor}/{@code committeeQuorum}. State stays in {@link Ledger}; thin
 * delegators there keep the (heavily-used) API. Bit-identical to the prior in-Ledger code — proposer/
 * committee selection and the reward weights it feeds are unchanged. Guarded by {@code CommitteeTest},
 * {@code ClusterTest}, and the economics sims.
 */
final class ValidatorSelection {
    private ValidatorSelection() {}

    static final double GEO_ALPHA = 0.2, GEO_BETA = 0.1, GEO_MAX = 2.5;   // Doc D coverage-premium params
    static final double WEIGHT_CAP = 0.10;            // §9.4: no single (cluster) validator may exceed 10% of network weight
    static final int CAP_MIN_VALIDATORS = 10;         // below this the cap is infeasible (1/N > cap), so it stays INERT

    static java.util.List<Integer> liveIdx(Ledger l) {
        java.util.List<Integer> r = new ArrayList<>();
        for (int i = 0; i < l.validators.size(); i++) if (!l.excluded(l.validators.get(i))) r.add(i);
        return r;
    }

    /** Geo coverage premium (opt-in): sparse regions earn a higher multiplier so coverage is incentivized. */
    static double coverageMultiplier(Ledger l, int idx) {
        String region = l.regions.get(l.validators.get(idx));
        if (region == null || region.isEmpty()) return 1.0;   // standard cluster, no premium
        long density = 0;
        for (int j : liveIdx(l)) if (region.equals(l.regions.get(l.validators.get(j))))
            density += Math.max(1L, l.identity.getOrDefault(l.validators.get(j), 1L));
        return Math.min(GEO_MAX, 1.0 + GEO_ALPHA / (density + GEO_BETA));
    }

    /** Final consensus/reward weight = baseWeight × geo coverage multiplier, renormalized, then the 10% cap. */
    static double weight(Ledger l, int idx) {
        if (idx < 0 || idx >= l.validators.size() || l.excluded(l.validators.get(idx))) return 0;
        Double w = weightMap(l).get(idx);
        return w == null ? 0 : w;
    }

    /** All live validators' final weights (base × geo, renormalized, then the 10% cap) in ONE pass.
     *  Hot loops (proposerFor/committeeFor) use this instead of per-idx weight() to avoid O(n²). Shared
     *  sqrt/identity/region denominators are computed once. Bit-identical to the old per-idx weight(). */
    static java.util.Map<Integer, Double> weightMap(Ledger l) {
        java.util.List<Integer> live = liveIdx(l);
        java.util.Map<Integer, Double> w = new java.util.HashMap<>();
        if (live.isEmpty()) return w;
        double sqSum = 0; long idSum = 0;                                  // denominators computed ONCE (not per validator)
        for (int j : live) {
            sqSum += Math.sqrt(l.stake.getOrDefault(l.validators.get(j), 0L));
            if (l.verified.contains(l.validators.get(j))) idSum += l.identity.getOrDefault(l.validators.get(j), 0L);
        }
        java.util.Map<String, Long> density = new java.util.HashMap<>();   // region densities computed ONCE
        for (int j : live) { String rg = l.regions.get(l.validators.get(j));
            if (rg != null && !rg.isEmpty()) density.merge(rg, Math.max(1L, l.identity.getOrDefault(l.validators.get(j), 1L)), Long::sum); }
        double total = 0;
        for (int j : live) {
            double stakeShare = sqSum > 0 ? Math.sqrt(l.stake.getOrDefault(l.validators.get(j), 0L)) / sqSum : 0;
            long myId = l.verified.contains(l.validators.get(j)) ? l.identity.getOrDefault(l.validators.get(j), 0L) : 0;
            double idShare = idSum > 0 ? (double) myId / idSum : 0;
            String rg = l.regions.get(l.validators.get(j));
            double cov = (rg == null || rg.isEmpty()) ? 1.0 : Math.min(GEO_MAX, 1.0 + GEO_ALPHA / (density.get(rg) + GEO_BETA));
            double v = (0.6 * stakeShare + 0.4 * idShare) * cov;
            w.put(j, v); total += v;
        }
        if (total <= 0) { for (int j : live) w.put(j, 0.0); return w; }
        for (int j : live) w.put(j, w.get(j) / total);
        if (live.size() < CAP_MIN_VALIDATORS) return w;                    // cap vacuous below CAP_MIN -> normalized base×geo (exact prior behavior)
        java.util.Set<Integer> capped = new java.util.HashSet<>();         // §9.4 iterative 10% cap on the normalized map
        for (int iter = 0; iter <= live.size(); iter++) {
            double excess = 0; boolean any = false;
            for (int j : live) if (!capped.contains(j) && w.get(j) > WEIGHT_CAP + 1e-12) { excess += w.get(j) - WEIGHT_CAP; w.put(j, WEIGHT_CAP); capped.add(j); any = true; }
            if (!any) break;
            double freeSum = 0; for (int j : live) if (!capped.contains(j)) freeSum += w.get(j);
            if (freeSum <= 0) break;
            for (int j : live) if (!capped.contains(j)) w.put(j, w.get(j) + excess * (w.get(j) / freeSum));
        }
        return w;
    }

    /** Weighted, deterministic proposer for (height,view), seeded by the commit-reveal beacon. */
    static int proposerFor(Ledger l, String prevHash, int height, int view) throws Exception {
        java.util.List<Integer> live = liveIdx(l);
        if (live.isEmpty()) return height % Math.max(1, l.validators.size());
        byte[] seed = PhantomCrypto.sha3_256(PhantomCrypto.utf8(l.beacon + "|" + height + "|" + view));
        long s = 0; for (int i = 0; i < 8; i++) s = (s << 8) | (seed[i] & 0xffL);
        s &= Long.MAX_VALUE;
        java.util.Map<Integer, Double> wm = weightMap(l);   // computed once (was O(n²) via per-idx weight())
        double total = 0; for (int idx : live) total += wm.getOrDefault(idx, 0.0);
        if (total <= 0) return live.get((int) (s % live.size()));
        double r = ((double) (s % 1_000_000L) / 1_000_000L) * total, c = 0;
        for (int idx : live) { c += wm.getOrDefault(idx, 0.0); if (r < c) return idx; }
        return live.get(live.size() - 1);
    }

    /** Beacon-sortitioned signing committee for `height`: a weight-proportional sample (without replacement)
     *  of `committeeSize` validators. committeeSize<=0 or live<=committeeSize returns the FULL live set. */
    static java.util.List<Integer> committeeFor(Ledger l, int height) {
        java.util.List<Integer> live = liveIdx(l);
        int k = l.committeeSize;
        if (k <= 0 || live.size() <= k) return live;
        java.util.List<Integer> pool = new ArrayList<>(live);
        java.util.List<Long> w = new ArrayList<>();
        java.util.Map<Integer, Double> wm = weightMap(l);   // computed once (was O(n²) via per-idx weight())
        for (int idx : pool) w.add(Math.max(1L, Math.round(wm.getOrDefault(idx, 0.0) * 1_000_000_000L)));   // integer weights = deterministic
        java.util.List<Integer> sel = new ArrayList<>();
        for (int seat = 0; seat < k && !pool.isEmpty(); seat++) {
            long total = 0; for (long x : w) total += x;
            byte[] hsh = PhantomCrypto.sha3_256(PhantomCrypto.utf8(l.beacon + "|cmte|" + height + "|" + seat));
            long s = 0; for (int i = 0; i < 8; i++) s = (s << 8) | (hsh[i] & 0xffL);
            long r = Math.floorMod(s, total), cum = 0; int pick = pool.size() - 1;
            for (int j = 0; j < pool.size(); j++) { cum += w.get(j); if (r < cum) { pick = j; break; } }
            sel.add(pool.get(pick)); pool.remove(pick); w.remove(pick);
        }
        java.util.Collections.sort(sel);
        return sel;
    }

    /** BFT quorum within the signing committee for `height`. */
    static int committeeQuorum(Ledger l, int height) {
        int c = committeeFor(l, height).size();
        return Math.max(1, c - (c - 1) / 3);
    }
}
