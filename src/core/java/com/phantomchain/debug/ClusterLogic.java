package com.phantomchain.debug;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Cluster membership — formation, disband, and the M-of-N member-signature bundle, extracted from
 * {@link Ledger}.
 *
 * A cluster of members pools its stake to join the validator set as ONE validator (§9.4); its consensus
 * signature on a block is a bundle of ≥threshold distinct member signatures (the stand-in for a true
 * threshold signature, §9.7); it disbands when ≥threshold of its OWN members sign the disband string.
 * Cluster STATE (clusters / collapsed / the validator set) stays in {@link Ledger}; thin delegators keep
 * the API. Guarded by {@code ClusterTest} / {@code ClusterGovTest}.
 */
final class ClusterLogic {
    private ClusterLogic() {}

    static String clusterFormCanon(String cid, String clusterId, JSONArray members, int threshold) {
        return "clusterform|" + cid + "|" + clusterId + "|" + members.toString() + "|" + threshold;
    }

    /** A cluster forms by bonding >= minValidatorStake of pooled member stake, then an initiating member
     *  signs the {members, threshold} set. The cluster then joins the validator set as one validator. */
    static boolean verifyClusterForm(Ledger l, JSONObject tx) throws Exception {
        if (!l.chainId.equals(tx.optString("cid", ""))) return false;
        String clusterId = tx.getString("clusterId");
        if (l.validators.contains(clusterId) || l.clusters.containsKey(clusterId)) return false;     // no re-form / id clash
        JSONArray members = tx.getJSONArray("members"); JSONObject mpubs = tx.getJSONObject("memberPubs");
        int threshold = tx.getInt("threshold");
        if (members.length() == 0 || threshold < 1 || threshold > members.length()) return false;
        java.util.Set<String> uniq = new java.util.HashSet<>();
        for (int i = 0; i < members.length(); i++) {                                              // members distinct + pubkey binds to id
            String mid = members.getString(i); if (!uniq.add(mid)) return false;
            String mp = mpubs.optString(mid, ""); if (mp.isEmpty() || !Ledger.idOf(mp).equals(mid)) return false;
        }
        long clusterStake = 0; for (int i = 0; i < members.length(); i++) clusterStake += l.stake.getOrDefault(members.getString(i), 0L);
        if (clusterStake < l.minValidatorStake) return false;                                      // pooled member stake meets the validator floor (§9.4)
        if (tx.optString("beaconCommit0", "").length() != 64) return false;                        // binds the cluster's first beacon reveal
        String initPub = tx.getString("initPub"); String initId = Ledger.idOf(initPub);
        if (!uniq.contains(initId)) return false;                                                  // initiator must be a member
        return PhantomCrypto.verify(Ledger.pk(initPub),
                PhantomCrypto.utf8(clusterFormCanon(l.chainId, clusterId, members, threshold) + "|" + tx.getString("beaconCommit0")),
                PhantomCrypto.unhex(tx.getString("sig")));
    }

    /** Apply a CLUSTERFORM to state (the cluster joins the validator set as one validator). Returns true iff registered. */
    static boolean applyClusterForm(Ledger l, JSONObject tx) throws Exception {
        if (!verifyClusterForm(l, tx)) return false;
        String clusterId = tx.getString("clusterId"); JSONArray cm = tx.getJSONArray("members");
        if (l.validators.contains(clusterId) || l.clusters.containsKey(clusterId)) return false;
        long clusterStake = 0; for (int mi = 0; mi < cm.length(); mi++) clusterStake += l.stake.getOrDefault(cm.getString(mi), 0L);
        l.clusters.put(clusterId, new JSONObject().put("members", cm)
                .put("memberPubs", tx.getJSONObject("memberPubs")).put("threshold", tx.getInt("threshold")));
        l.validators.add(clusterId); l.valPubs.put(clusterId, "CLUSTER");   // marker: consensus sig is an M-of-N member bundle, not one key
        l.stake.put(clusterId, clusterStake);                            // §9.4 cluster_total_stake = pooled member stake
        l.identity.put(clusterId, (long) cm.length());                   // §9.4 cluster identity weight = enrolled members
        l.commits.put(clusterId, tx.getString("beaconCommit0"));
        return true;
    }

    static String clusterDisbandCanon(String cid, String clusterId) { return "clusterdisband|" + cid + "|" + clusterId; }

    /** Collapse (§9.7) is authorized by the cluster's OWN members: >= threshold distinct member signatures. */
    static boolean verifyClusterDisband(Ledger l, JSONObject tx) throws Exception {
        if (!l.chainId.equals(tx.optString("cid", ""))) return false;
        String clusterId = tx.getString("clusterId");
        JSONObject c = l.clusters.get(clusterId); if (c == null || l.collapsed.contains(clusterId)) return false;
        return verifyClusterVote(l, clusterId, clusterDisbandCanon(l.chainId, clusterId), tx.optJSONArray("approvals"));
    }

    /** A cluster's consensus signature on a block is a bundle [{m:memberId, sig}]; valid iff >= threshold
     *  DISTINCT member keys signed the block hash. The M-of-N stand-in for a threshold signature. */
    static boolean verifyClusterVote(Ledger l, String clusterId, String hash, JSONArray bundle) throws Exception {
        JSONObject c = l.clusters.get(clusterId); if (c == null || bundle == null) return false;
        JSONObject mpubs = c.getJSONObject("memberPubs"); int threshold = c.getInt("threshold");
        java.util.Set<String> members = new java.util.HashSet<>();
        JSONArray ms = c.getJSONArray("members"); for (int i = 0; i < ms.length(); i++) members.add(ms.getString(i));
        java.util.Set<String> seen = new java.util.HashSet<>(); int ok = 0;
        for (int i = 0; i < bundle.length(); i++) {
            JSONObject e = bundle.getJSONObject(i); String mid = e.optString("m", "");
            if (!members.contains(mid) || !seen.add(mid)) continue;                               // unknown or double-counted member
            String mp = mpubs.optString(mid, ""); if (mp.isEmpty()) continue;
            if (PhantomCrypto.verify(Ledger.pk(mp), PhantomCrypto.utf8(hash), PhantomCrypto.unhex(e.getString("sig")))) ok++;
        }
        return ok >= threshold;
    }
}
