package com.phantomchain.debug;

import java.util.ArrayList;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * The consensus-critical serialization surface, extracted from {@link Ledger}.
 *
 * This owns the canonical byte layout of the state root and the authenticated account
 * Merkle commitment. It is intentionally the ONLY place state is hashed into the
 * consensus commitment, so the byte layout — where a chain-split hides — lives in one
 * small, auditable file instead of being woven through a 1.6 kLOC class. {@link Ledger}
 * keeps thin delegators ({@code stateRoot()}, {@code accountsMerkleRoot()}, …) that
 * forward here, so every existing call site is unchanged.
 *
 * The byte layout is frozen by {@code GoldenStateRootTest} (pinned roots for
 * v1/v2/full/m1 × states); any change here that moves a single byte turns it red.
 * All methods read {@link Ledger}'s package-private state via the passed instance and
 * MUST remain byte-identical to the pre-extraction {@code Ledger} code.
 */
final class StateRootCodec {
    private StateRootCodec() {}

    /** Flat canonical hash over the full committed state. Field order is consensus-critical. */
    static String stateRoot(Ledger l) throws Exception {
        StringBuilder sb = new StringBuilder("acc|");
        java.util.List<String> ids = new ArrayList<>(l.accounts.keySet()); java.util.Collections.sort(ids);
        for (String id : ids) { Ledger.Account a = l.accounts.get(id); sb.append(id).append(':').append(a.balance).append(':').append(a.nonce).append(';'); }
        sb.append("stk|"); java.util.List<String> sk = new ArrayList<>(l.stake.keySet()); java.util.Collections.sort(sk);
        for (String id : sk) sb.append(id).append(':').append(l.stake.get(id)).append(';');
        sb.append("ver|"); java.util.List<String> vr = new ArrayList<>(l.verified); java.util.Collections.sort(vr);
        for (String id : vr) sb.append(id).append(';');
        sb.append("jail|"); java.util.List<String> jl = new ArrayList<>(l.jailed.keySet()); java.util.Collections.sort(jl);
        for (String id : jl) sb.append(id).append(':').append(l.jailed.get(id)).append(';');
        sb.append("unb|"); for (JSONObject u : l.unbonding) sb.append(u.optString("actor")).append(':').append(u.optLong("amount")).append(':').append(u.optLong("mature")).append(';');
        sb.append("idn|"); java.util.List<String> idl = new ArrayList<>(l.identities.keySet()); java.util.Collections.sort(idl);
        for (String id : idl) { JSONObject o = l.identities.get(id);
            sb.append(id).append(':').append(o.getString("root")).append(':').append(o.getJSONArray("devices").toString())
              .append(':').append(o.getJSONArray("guardians").toString()).append(':').append(o.getInt("threshold")).append(':').append(o.getLong("rotNonce")).append(';'); }
        sb.append("vals|"); for (String v : l.validators) sb.append(v).append(',');
        sb.append("vp|"); java.util.List<String> vpl = new ArrayList<>(l.valPubs.keySet()); java.util.Collections.sort(vpl);
        for (String v : vpl) sb.append(v).append('=').append(l.valPubs.get(v)).append(';');
        sb.append("rg|"); java.util.List<String> rgl = new ArrayList<>(l.regions.keySet()); java.util.Collections.sort(rgl);
        for (String v : rgl) sb.append(v).append('=').append(l.regions.get(v)).append(';');
        sb.append("tr|"); java.util.List<String> trl = new ArrayList<>(l.tiers.keySet()); java.util.Collections.sort(trl);
        for (String v : trl) sb.append(v).append('=').append(l.tiers.get(v)).append(';');
        sb.append("cu|"); java.util.List<String> cul = new ArrayList<>(l.custodians.keySet()); java.util.Collections.sort(cul);
        for (String v : cul) sb.append(v).append('=').append(l.custodians.get(v)).append(';');
        if (!l.clusters.isEmpty()) {   // appended only when clusters exist -> empty-cluster chains keep their prior state root (backward compatible)
            sb.append("cls|"); java.util.List<String> cll = new ArrayList<>(l.clusters.keySet()); java.util.Collections.sort(cll);
            for (String k : cll) { JSONObject c = l.clusters.get(k);
                sb.append(k).append('=').append(c.getJSONArray("members").toString()).append(':').append(c.getInt("threshold")).append(';'); }
        }
        if (!l.collapsed.isEmpty()) {   // disbanded clusters (§9.7) — consensus-critical (excluded), backward-compatible when empty
            sb.append("clp|"); java.util.List<String> clpl = new ArrayList<>(l.collapsed); java.util.Collections.sort(clpl);
            for (String v : clpl) sb.append(v).append(';');
        }
        sb.append("bth|").append(l.bridgeThreshold).append("|bp|");
        java.util.List<String> bpl = new ArrayList<>(l.bridgeProcessed); java.util.Collections.sort(bpl);
        for (String v : bpl) sb.append(v).append(';');
        sb.append("orc|"); java.util.List<String> opl = new ArrayList<>(l.oracleRates.keySet()); java.util.Collections.sort(opl);
        for (String pair : opl) { sb.append(pair).append(':'); Map<String, Long> rs = l.oracleRates.get(pair);
            java.util.List<String> cl = new ArrayList<>(rs.keySet()); java.util.Collections.sort(cl);
            for (String c : cl) sb.append(c).append('=').append(rs.get(c)).append(','); sb.append(';'); }
        sb.append("bcn|").append(l.beacon).append("|cm|");
        java.util.List<String> cml = new ArrayList<>(l.commits.keySet()); java.util.Collections.sort(cml);
        for (String v : cml) sb.append(v).append('=').append(l.commits.get(v)).append(';');
        sb.append("la|"); java.util.List<String> lal = new ArrayList<>(l.lastActive.keySet()); java.util.Collections.sort(lal);
        for (String id : lal) sb.append(id).append('@').append(l.lastActive.get(id)).append(';');
        sb.append("ben|"); java.util.List<String> bl = new ArrayList<>(l.beneficiary.keySet()); java.util.Collections.sort(bl);
        for (String id : bl) sb.append(id).append('>').append(l.beneficiary.get(id)).append(';');
        sb.append("supply|").append(l.totalMinted).append('|').append(l.burned);
        sb.append("|params|").append(l.blockReward).append(',').append(l.halvingBlocks).append(',').append(l.maxSupply)
          .append(',').append(l.feeBurnBps).append(',').append(l.slashBps).append(',').append(l.jailBlocks).append(',').append(l.unbondingBlocks).append(',').append(l.estateInactivity).append(',').append(l.minValidatorStake);
        // state-root param tail compatibility: identityBond + committeeSize were appended in later builds.
        // The serialization version is committed state (srVersion, persisted with the chain) — NOT a JVM
        // launch flag — so every node computes the identical tail without operator coordination.
        if (l.srv().hasIdentityBond()) sb.append(',').append(l.identityBond);                 // present except V1
        if (l.srv().hasCommitteeSize()) sb.append(',').append(l.committeeSize);               // present in FULL/M1
        // permanent tombstone (excludes from quorum/weight via excluded()) — consensus-critical, must be covered
        sb.append("|sl|"); java.util.List<String> sll = new ArrayList<>(l.slashed); java.util.Collections.sort(sll);
        for (String v : sll) sb.append(v).append(';');
        // pending personhood vouches (accrue toward verified admission)
        sb.append("vch|"); java.util.List<String> vchl = new ArrayList<>(l.vouches.keySet()); java.util.Collections.sort(vchl);
        for (String c : vchl) { sb.append(c).append('='); java.util.List<String> vs = new ArrayList<>(l.vouches.get(c)); java.util.Collections.sort(vs);
            for (String v : vs) sb.append(v).append(','); sb.append(';'); }
        // open governance proposals (execute param changes at timelock)
        sb.append("prp|"); java.util.List<String> prl = new ArrayList<>(l.proposals.keySet()); java.util.Collections.sort(prl);
        for (String pid : prl) { JSONObject p = l.proposals.get(pid);
            sb.append(pid).append(':').append(p.optString("param")).append(':').append(p.optLong("value")).append(':').append(p.optLong("deadline"))
              .append(':').append(p.optLong("applyAt")).append(':').append(p.optBoolean("tallied")).append(':').append(p.optBoolean("passed"))
              .append(':').append(p.optBoolean("executed")).append(':').append(p.optLong("totalWeight")).append(':');
            JSONObject votes = p.optJSONObject("votes"); if (votes != null) { java.util.List<String> vk = new ArrayList<>(Ledger.keysOf(votes)); java.util.Collections.sort(vk);
                for (String act : vk) sb.append(act).append('=').append(votes.optBoolean(act)).append(','); }
            sb.append(';'); }
        // "m1": commit to the authenticated account Merkle root so a light client can be given a
        // trustless inclusion proof for any account against the consensus state root (additive — empty
        // for "full"/legacy chains, so their state root is byte-identical to before this build).
        if (l.srv().bindsMerkleRoot()) sb.append("|amr|").append(accountsMerkleRoot(l));
        return PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(sb.toString())));
    }

    // ===== authenticated account state: a real Merkle commitment with verifiable inclusion proofs =====
    // Leaves are the canonical (id,balance,nonce) tuples sorted by id; the tree is a binary SHA3-256
    // Merkle tree with domain-separated leaf/interior hashing.
    static byte[] accountLeaf(String id, long balance, long nonce) {
        return PhantomCrypto.sha3_256(PhantomCrypto.utf8("acctleaf|" + id + "|" + balance + "|" + nonce));
    }
    static java.util.List<String> sortedAccountIds(Ledger l) {
        java.util.List<String> ids = new ArrayList<>(l.accounts.keySet());
        java.util.Collections.sort(ids);
        return ids;
    }
    static java.util.List<byte[]> accountLeaves(Ledger l) {
        java.util.List<byte[]> ls = new ArrayList<>();
        for (String id : sortedAccountIds(l)) { Ledger.Account a = l.accounts.get(id); ls.add(accountLeaf(id, a.balance, a.nonce)); }
        return ls;
    }
    /** Root = SHA3("amr|count|innerRoot"). Binding the leaf COUNT defeats the CVE-2012-2459 duplicate-last
     *  forgery, where odd-node duplication lets a different leaf set ([A,B,C] vs [A,B,C,C]) share the raw
     *  inner root; the count makes those roots differ. */
    static byte[] boundMerkleRoot(int count, byte[] inner) {
        return PhantomCrypto.sha3_256(PhantomCrypto.utf8("amr|" + count + "|" + PhantomCrypto.hex(inner)));
    }
    static String accountsMerkleRoot(Ledger l) {
        java.util.List<byte[]> leaves = accountLeaves(l);
        return PhantomCrypto.hex(boundMerkleRoot(leaves.size(), merkleRoot(leaves)));
    }

    /** Interior node = SHA3(0x01 ‖ left ‖ right); the 0x01 prefix domain-separates interior nodes from
     *  leaves (which are SHA3 of a "acctleaf|"-tagged preimage), preventing second-preimage/leaf-as-node attacks. */
    static byte[] merkleNode(byte[] l, byte[] r) {
        byte[] c = new byte[1 + l.length + r.length];
        c[0] = 0x01;
        System.arraycopy(l, 0, c, 1, l.length);
        System.arraycopy(r, 0, c, 1 + l.length, r.length);
        return PhantomCrypto.sha3_256(c);
    }
    static byte[] merkleRoot(java.util.List<byte[]> leaves) {
        if (leaves.isEmpty()) return PhantomCrypto.sha3_256(PhantomCrypto.utf8("emptymerkle"));
        java.util.List<byte[]> level = new ArrayList<>(leaves);
        while (level.size() > 1) {
            java.util.List<byte[]> next = new ArrayList<>();
            for (int i = 0; i < level.size(); i += 2)
                next.add(merkleNode(level.get(i), i + 1 < level.size() ? level.get(i + 1) : level.get(i)));   // odd tail: duplicate last
            level = next;
        }
        return level.get(0);
    }
    /** Sibling hashes from leaf to root for the leaf at index `idx`. */
    static java.util.List<byte[]> merkleProof(java.util.List<byte[]> leaves, int idx) {
        java.util.List<byte[]> sibs = new ArrayList<>();
        java.util.List<byte[]> level = new ArrayList<>(leaves);
        int i = idx;
        while (level.size() > 1) {
            int sib = (i % 2 == 0) ? Math.min(i + 1, level.size() - 1) : i - 1;   // last-even sibling = self (matches duplicate)
            sibs.add(level.get(sib));
            java.util.List<byte[]> next = new ArrayList<>();
            for (int j = 0; j < level.size(); j += 2)
                next.add(merkleNode(level.get(j), j + 1 < level.size() ? level.get(j + 1) : level.get(j)));
            level = next; i /= 2;
        }
        return sibs;
    }
    static boolean merkleVerify(byte[] leaf, int idx, java.util.List<byte[]> sibs, byte[] root) {
        byte[] h = leaf; int i = idx;
        for (byte[] s : sibs) { h = (i % 2 == 0) ? merkleNode(h, s) : merkleNode(s, h); i /= 2; }
        return java.util.Arrays.equals(h, root);
    }

    /** Serializable inclusion proof for `id` against accountsMerkleRoot() (what /stateproof serves). */
    static JSONObject accountProof(Ledger l, String id) {
        java.util.List<String> ids = sortedAccountIds(l);
        int idx = ids.indexOf(id);
        if (idx < 0) return new JSONObject().put("present", false).put("id", id).put("root", accountsMerkleRoot(l));
        java.util.List<byte[]> leaves = accountLeaves(l);
        Ledger.Account a = l.accounts.get(id);
        JSONArray sibs = new JSONArray();
        for (byte[] sx : merkleProof(leaves, idx)) sibs.put(PhantomCrypto.hex(sx));
        return new JSONObject().put("present", true).put("id", id)
                .put("balance", a.balance).put("nonce", a.nonce)
                .put("index", idx).put("count", ids.size())
                .put("siblings", sibs).put("root", accountsMerkleRoot(l));   // count-bound root
    }
    /** Stateless verification of an account proof (a light client runs exactly this against a trusted root). */
    static boolean verifyAccountProof(JSONObject p) {
        if (p == null || !p.optBoolean("present", false)) return false;
        int idx = p.getInt("index"), count = p.getInt("count");
        if (idx < 0 || idx >= count) return false;                 // reject a duplicated/out-of-range position
        byte[] h = accountLeaf(p.getString("id"), p.getLong("balance"), p.getLong("nonce"));
        JSONArray sa = p.getJSONArray("siblings");
        int i = idx;
        for (int j = 0; j < sa.length(); j++) { byte[] s = PhantomCrypto.unhex(sa.getString(j)); h = (i % 2 == 0) ? merkleNode(h, s) : merkleNode(s, h); i /= 2; }
        return PhantomCrypto.hex(boundMerkleRoot(count, h)).equals(p.getString("root"));   // climb -> inner -> bind count
    }
}
