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

    // ===== full-state persistence (toJson / fromJson) =====
    static String toJson(Ledger l) throws Exception {
        JSONObject root = new JSONObject();
        root.put("owner", l.ownerId == null ? JSONObject.NULL : l.ownerId);
        root.put("chainId", l.chainId);
        root.put("srVersion", l.srVersion);   // state-root serialization version travels with the chain (no launch flag)
        JSONObject accs = new JSONObject();
        for (Map.Entry<String, Ledger.Account> e : l.accounts.entrySet())
            accs.put(e.getKey(), new JSONObject().put("balance", e.getValue().balance).put("nonce", e.getValue().nonce));
        root.put("accounts", accs);
        JSONArray ch = new JSONArray(); for (JSONObject b : l.chain) ch.put(b);
        root.put("chain", ch);
        JSONArray mp = new JSONArray(); for (JSONObject t : l.mempool) mp.put(t);
        root.put("mempool", mp);
        JSONArray sl = new JSONArray(); for (String v : l.slashed) sl.put(v);
        root.put("slashed", sl);
        JSONObject st = new JSONObject(); for (Map.Entry<String, Long> e : l.stake.entrySet()) st.put(e.getKey(), (long) e.getValue());
        root.put("stake", st);
        JSONObject idn = new JSONObject(); for (Map.Entry<String, Long> e : l.identity.entrySet()) idn.put(e.getKey(), (long) e.getValue());
        root.put("identity", idn);
        JSONArray vs = new JSONArray(); for (String v : l.validators) vs.put(v);
        root.put("validators", vs);
        root.put("minted", l.totalMinted);
        JSONArray ver = new JSONArray(); for (String v : l.verified) ver.put(v);
        root.put("verified", ver);
        JSONObject vo = new JSONObject();
        for (Map.Entry<String, java.util.Set<String>> e : l.vouches.entrySet()) { JSONArray a = new JSONArray(); for (String x : e.getValue()) a.put(x); vo.put(e.getKey(), a); }
        root.put("vouches", vo);
        root.put("burned", l.burned);
        root.put("params", new JSONObject()
            .put("blockReward", l.blockReward).put("halvingBlocks", l.halvingBlocks).put("maxSupply", l.maxSupply)
            .put("feeBurnBps", l.feeBurnBps).put("slashBps", l.slashBps).put("jailBlocks", l.jailBlocks).put("unbondingBlocks", l.unbondingBlocks)
            .put("estateInactivity", l.estateInactivity).put("minValidatorStake", l.minValidatorStake).put("bridgeThreshold", l.bridgeThreshold).put("identityBond", l.identityBond).put("committeeSize", l.committeeSize));
        JSONObject jl = new JSONObject(); for (Map.Entry<String, Long> e : l.jailed.entrySet()) jl.put(e.getKey(), (long) e.getValue());
        root.put("jailed", jl);
        JSONArray ub = new JSONArray(); for (JSONObject u : l.unbonding) ub.put(u);
        root.put("unbonding", ub);
        JSONObject pr = new JSONObject(); for (Map.Entry<String, JSONObject> e : l.proposals.entrySet()) pr.put(e.getKey(), e.getValue());
        root.put("proposals", pr);
        JSONObject idns = new JSONObject(); for (Map.Entry<String, JSONObject> e : l.identities.entrySet()) idns.put(e.getKey(), e.getValue());
        root.put("identities", idns);
        JSONObject la = new JSONObject(); for (Map.Entry<String, Long> e : l.lastActive.entrySet()) la.put(e.getKey(), (long) e.getValue());
        root.put("lastActive", la);
        JSONObject bf = new JSONObject(); for (Map.Entry<String, String> e : l.beneficiary.entrySet()) bf.put(e.getKey(), e.getValue());
        root.put("beneficiary", bf);
        JSONObject vp = new JSONObject(); for (Map.Entry<String, String> e : l.valPubs.entrySet()) vp.put(e.getKey(), e.getValue());
        root.put("valPubs", vp);
        JSONObject rg = new JSONObject(); for (Map.Entry<String, String> e : l.regions.entrySet()) rg.put(e.getKey(), e.getValue());
        root.put("regions", rg);
        JSONObject tr = new JSONObject(); for (Map.Entry<String, String> e : l.tiers.entrySet()) tr.put(e.getKey(), e.getValue());
        root.put("tiers", tr);
        JSONObject cu = new JSONObject(); for (Map.Entry<String, String> e : l.custodians.entrySet()) cu.put(e.getKey(), e.getValue());
        root.put("custodians", cu);
        JSONObject cls = new JSONObject(); for (Map.Entry<String, JSONObject> e : l.clusters.entrySet()) cls.put(e.getKey(), e.getValue());
        root.put("clusters", cls);
        JSONArray clp = new JSONArray(); for (String x : l.collapsed) clp.put(x);
        root.put("collapsed", clp);
        JSONArray bp = new JSONArray(); for (String x : l.bridgeProcessed) bp.put(x);
        root.put("bridgeProcessed", bp);
        JSONObject orc = new JSONObject();
        for (Map.Entry<String, Map<String, Long>> e : l.oracleRates.entrySet()) { JSONObject in = new JSONObject(); for (Map.Entry<String, Long> i : e.getValue().entrySet()) in.put(i.getKey(), (long) i.getValue()); orc.put(e.getKey(), in); }
        root.put("oracleRates", orc);
        root.put("beacon", l.beacon);
        JSONObject cm = new JSONObject(); for (Map.Entry<String, String> e : l.commits.entrySet()) cm.put(e.getKey(), e.getValue());
        root.put("commits", cm);
        return root.toString();
    }

    static void fromJson(Ledger l, String s) throws Exception {
        JSONObject root = new JSONObject(s);
        l.ownerId = root.isNull("owner") ? null : root.getString("owner");
        l.chainId = root.optString("chainId", "");
        l.srVersion = root.optString("srVersion", "full");   // legacy snapshots without the field == "full"
        l.accounts.clear(); l.chain.clear(); l.mempool.clear();
        JSONObject accs = root.getJSONObject("accounts");
        for (java.util.Iterator<String> it = accs.keys(); it.hasNext(); ) {
            String k = it.next();
            JSONObject a = accs.getJSONObject(k);
            Ledger.Account ac = new Ledger.Account(); ac.balance = a.getLong("balance"); ac.nonce = a.getLong("nonce");
            l.accounts.put(k, ac);
        }
        JSONArray ch = root.getJSONArray("chain");
        for (int i = 0; i < ch.length(); i++) l.chain.add(ch.getJSONObject(i));
        JSONArray mp = root.optJSONArray("mempool");
        if (mp != null) for (int i = 0; i < mp.length(); i++) l.mempool.add(mp.getJSONObject(i));
        l.slashed.clear();
        JSONArray sl = root.optJSONArray("slashed");
        if (sl != null) for (int i = 0; i < sl.length(); i++) l.slashed.add(sl.getString(i));
        l.stake.clear(); JSONObject st = root.optJSONObject("stake");
        if (st != null) for (String k : Ledger.keysOf(st)) l.stake.put(k, st.getLong(k));
        l.identity.clear(); JSONObject idn = root.optJSONObject("identity");
        if (idn != null) for (String k : Ledger.keysOf(idn)) l.identity.put(k, idn.getLong(k));
        l.validators.clear(); JSONArray vs = root.optJSONArray("validators");
        if (vs != null) for (int i = 0; i < vs.length(); i++) l.validators.add(vs.getString(i));
        l.totalMinted = root.optLong("minted", 0);
        l.verified.clear(); JSONArray ver = root.optJSONArray("verified");
        if (ver != null) for (int i = 0; i < ver.length(); i++) l.verified.add(ver.getString(i));
        l.vouches.clear(); JSONObject vo = root.optJSONObject("vouches");
        if (vo != null) for (String k : Ledger.keysOf(vo)) { java.util.Set<String> set = new java.util.HashSet<>(); JSONArray a = vo.getJSONArray(k); for (int i = 0; i < a.length(); i++) set.add(a.getString(i)); l.vouches.put(k, set); }
        l.burned = root.optLong("burned", 0);
        JSONObject params = root.optJSONObject("params");
        if (params != null) {
            l.blockReward = params.optLong("blockReward", l.blockReward);
            l.halvingBlocks = params.optInt("halvingBlocks", l.halvingBlocks);
            l.maxSupply = params.optLong("maxSupply", l.maxSupply);
            l.feeBurnBps = params.optInt("feeBurnBps", l.feeBurnBps);
            l.slashBps = params.optInt("slashBps", l.slashBps);
            l.jailBlocks = params.optInt("jailBlocks", l.jailBlocks);
            l.unbondingBlocks = params.optInt("unbondingBlocks", l.unbondingBlocks);
            l.estateInactivity = params.optLong("estateInactivity", l.estateInactivity);
            l.minValidatorStake = params.optInt("minValidatorStake", l.minValidatorStake);
            l.identityBond = params.optLong("identityBond", l.identityBond);
            l.committeeSize = params.optInt("committeeSize", l.committeeSize);
            l.bridgeThreshold = params.optInt("bridgeThreshold", l.bridgeThreshold);
        }
        l.jailed.clear(); JSONObject jl = root.optJSONObject("jailed");
        if (jl != null) for (String k : Ledger.keysOf(jl)) l.jailed.put(k, jl.getLong(k));
        l.unbonding.clear(); JSONArray ub = root.optJSONArray("unbonding");
        if (ub != null) for (int i = 0; i < ub.length(); i++) l.unbonding.add(ub.getJSONObject(i));
        l.proposals.clear(); JSONObject pr = root.optJSONObject("proposals");
        if (pr != null) for (String k : Ledger.keysOf(pr)) l.proposals.put(k, pr.getJSONObject(k));
        l.identities.clear(); JSONObject idns = root.optJSONObject("identities");
        if (idns != null) for (String k : Ledger.keysOf(idns)) l.identities.put(k, idns.getJSONObject(k));
        l.lastActive.clear(); JSONObject la = root.optJSONObject("lastActive");
        if (la != null) for (String k : Ledger.keysOf(la)) l.lastActive.put(k, la.getLong(k));
        l.beneficiary.clear(); JSONObject bf = root.optJSONObject("beneficiary");
        if (bf != null) for (String k : Ledger.keysOf(bf)) l.beneficiary.put(k, bf.getString(k));
        l.valPubs.clear(); JSONObject vp = root.optJSONObject("valPubs");
        if (vp != null) for (String k : Ledger.keysOf(vp)) l.valPubs.put(k, vp.getString(k));
        l.regions.clear(); JSONObject rg = root.optJSONObject("regions");
        if (rg != null) for (String k : Ledger.keysOf(rg)) l.regions.put(k, rg.getString(k));
        l.tiers.clear(); JSONObject tr = root.optJSONObject("tiers");
        if (tr != null) for (String k : Ledger.keysOf(tr)) l.tiers.put(k, tr.getString(k));
        l.clusters.clear(); JSONObject cls = root.optJSONObject("clusters");
        if (cls != null) for (String k : Ledger.keysOf(cls)) l.clusters.put(k, cls.getJSONObject(k));
        l.collapsed.clear(); JSONArray clp = root.optJSONArray("collapsed");
        if (clp != null) for (int i = 0; i < clp.length(); i++) l.collapsed.add(clp.getString(i));
        l.custodians.clear(); JSONObject cu = root.optJSONObject("custodians");
        if (cu != null) for (String k : Ledger.keysOf(cu)) l.custodians.put(k, cu.getString(k));
        l.bridgeProcessed.clear(); JSONArray bp = root.optJSONArray("bridgeProcessed");
        if (bp != null) for (int i = 0; i < bp.length(); i++) l.bridgeProcessed.add(bp.getString(i));
        l.oracleRates.clear(); JSONObject orc = root.optJSONObject("oracleRates");
        if (orc != null) for (String pair : Ledger.keysOf(orc)) { Map<String, Long> rs = new java.util.HashMap<>(); JSONObject in = orc.getJSONObject(pair); for (String c : Ledger.keysOf(in)) rs.put(c, in.getLong(c)); l.oracleRates.put(pair, rs); }
        l.beacon = root.optString("beacon", Ledger.ZERO32);
        l.commits.clear(); JSONObject cm = root.optJSONObject("commits");
        if (cm != null) for (String k : Ledger.keysOf(cm)) l.commits.put(k, cm.getString(k));
    }

    // ===== state sharding: per-id state partitioned into SHARDS, each independently rooted =====
    static int shardOf(String id) {   // hex account ids shard by prefix; special ids (e.g. BRIDGE_RESERVE) by hash
        try { return id.length() >= 4 ? Math.floorMod(Integer.parseInt(id.substring(0, 4), 16), Ledger.SHARDS) : 0; }
        catch (NumberFormatException e) { return Math.floorMod(PhantomCrypto.sha3_256(PhantomCrypto.utf8(id))[0] & 0xff, Ledger.SHARDS); }
    }
    /** Canonical serialization of all per-id state assigned to shard s (sorted by id). */
    static String shardData(Ledger l, int s) throws Exception {
        java.util.TreeSet<String> ids = new java.util.TreeSet<>();
        ids.addAll(l.accounts.keySet()); ids.addAll(l.stake.keySet()); ids.addAll(l.identity.keySet());
        ids.addAll(l.verified); ids.addAll(l.jailed.keySet()); ids.addAll(l.identities.keySet());
        ids.addAll(l.lastActive.keySet()); ids.addAll(l.beneficiary.keySet());
        StringBuilder sb = new StringBuilder();
        for (String id : ids) {
            if (shardOf(id) != s) continue;
            Ledger.Account a = l.accounts.get(id);
            sb.append(id).append('|').append(a == null ? 0 : a.balance).append(',').append(a == null ? 0 : a.nonce)
              .append(',').append(l.stake.getOrDefault(id, 0L)).append(',').append(l.identity.getOrDefault(id, 0L))
              .append(',').append(l.verified.contains(id) ? 1 : 0).append(',').append(l.jailed.getOrDefault(id, 0L))
              .append(',').append(l.lastActive.getOrDefault(id, 0L)).append(',').append(l.beneficiary.getOrDefault(id, ""))
              .append(',').append(l.identities.containsKey(id) ? l.identities.get(id).toString() : "").append(';');
        }
        return sb.toString();
    }
    static String shardRoot(Ledger l, int s) throws Exception { return PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(shardData(l, s)))); }
    /** Merkle commitment (flat) over all shard roots — bound into each block header as prevShardsRoot. */
    static String shardsRoot(Ledger l) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (int s = 0; s < Ledger.SHARDS; s++) sb.append(shardRoot(l, s));
        return PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(sb.toString())));
    }
}
