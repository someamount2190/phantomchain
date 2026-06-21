package com.phantomchain.debug;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

/**
 * Single-node toy ledger for the debug app: accounts with balances+nonces, signature/balance/nonce
 * validated transactions, and a hash-linked, device-signed block chain. This is NOT consensus —
 * one node seals every block. It is the smallest honest step from "sign a string" to a real chain.
 */
public class Ledger {

    static final String ZERO32 = "0000000000000000000000000000000000000000000000000000000000000000";

    static class Account { long balance; long nonce; }

    String ownerId;
    String chainId = "";   // domain-separation tag; every signed payload (tx, action, block, vote) commits to it
    final Map<String, Account> accounts = new HashMap<>();
    final List<JSONObject> chain = new ArrayList<>();
    final List<JSONObject> mempool = new ArrayList<>();
    final java.util.Set<String> slashed = new java.util.HashSet<>();   // validator IDs proven to have double-signed
    // ---- mining economics (simulation) ----
    final Map<String, Long> stake = new HashMap<>();              // id -> bonded stake (PROVABLE: on-chain)
    final Map<String, Long> identity = new HashMap<>();           // id -> enrolled-human count (REAL: needs personhood proof)
    final java.util.List<String> validators = new ArrayList<>();  // index-ordered ids; APPEND-ONLY so indices/QC stay valid
    // ---- commit-reveal randomness beacon (RANDAO): proposer reveals a value it committed in its prior block ----
    String beacon = ZERO32;                                       // accumulated unbiasable-ish randomness
    final Map<String, String> commits = new HashMap<>();          // validator id -> its outstanding reveal commitment
    final Map<String, String> valPubs = new HashMap<>();          // validator id -> consensus pubkey hex (genesis + joined)
    final Map<String, String> regions = new HashMap<>();          // validator id -> region_id (opt-in geo coverage premium)
    final Map<String, String> tiers = new HashMap<>();            // validator id -> "light" (absent/"heavy" = full archived-body storage)
    // ---- cross-chain bridge (on-chain side; the M-of-N custodian HSM service is the explicit OFF-chain trust boundary) ----
    final Map<String, String> custodians = new HashMap<>();        // custodian id -> pubkey hex
    int bridgeThreshold = 1;                                       // M-of-N custodian attestations required (governable)
    final java.util.Set<String> bridgeProcessed = new java.util.HashSet<>();   // external tx ids already minted (replay guard)
    static final String BRIDGE_RESERVE = "BRIDGE_RESERVE";        // reserve account funds inbound releases
    final java.util.List<JSONObject> bridgeOuts = new ArrayList<>();           // recent outbound locks (custodian observability)
    final Map<String, Map<String, Long>> oracleRates = new HashMap<>();        // pair -> {custodian id -> rate} (median = price)
    int minValidatorStake = 500_000;                              // min bonded stake to join the validator set (governable)
    long identityBond = 0;                                        // stake an identity must lock to be admitted to `verified` (governable; 0 = vouch-only). Sybil-cost: N identities cost N×bond.
    int committeeSize = 0;                                        // 0 = full validator set signs (deterministic BFT); >0 = beacon-sortitioned signing committee of this size (probabilistic safety, only meaningful at large N)
    long totalMinted = 0;
    long burned = 0;                          // total tokens burned (fee burn + slashing) — deflationary sink
    static final int EPOCH_LEN = 3;
    static final int PROPOSER_BONUS = 2;      // extra contribution units for proposing
    static final int  RETAIN_RECENT = 8;      // recent block bodies kept fully; older unassigned bodies pruned
    static final int  MAX_MEMPOOL = 10000;    // DoS bound: reject new txs past this
    static final int  MAX_BLOCK_TXS = 1000;   // DoS bound: cap txs packed per block
    static final long MIN_FEE = 1;            // anti-spam: transfers must pay at least this
    // ---- production economics: governable parameters (changeable via on-chain governance) ----
    long blockReward = 100;                   // initial per-block emission; halves every halvingBlocks
    int  halvingBlocks = 12;                  // emission halving period (blocks)
    long maxSupply = 10_000_000L;             // hard emission cap
    int  feeBurnBps = 5000;                   // basis points of tx fees burned (remainder -> block proposer)
    int  slashBps = 10000;                    // basis points of stake burned on equivocation (10000 = 100%)
    int  jailBlocks = 10;                     // jail duration (blocks) after a slash, before unjail is allowed
    int  unbondingBlocks = 10;               // lock period (blocks) before unbonded stake becomes liquid
    // ---- staking / slashing / governance state ----
    final Map<String, Long> jailed = new HashMap<>();          // id -> height at which unjail becomes allowed
    final List<JSONObject> unbonding = new ArrayList<>();      // [{actor, amount, mature}] pending unbonds
    final Map<String, JSONObject> proposals = new HashMap<>(); // propId -> {proposer,param,value,deadline,executed,votes:{voter:choice}}
    // ---- identity != key: durable on-chain identity with rotatable device keys + guardian recovery ----
    final Map<String, JSONObject> identities = new HashMap<>(); // identity_id -> {root, devices:[hex], guardians:[id], threshold, rotNonce}
    // ---- estate / inheritance: only an OUTGOING (fingerprint) action resets the clock ----
    final Map<String, Long> lastActive = new HashMap<>();      // id -> height of last outgoing action
    final Map<String, String> beneficiary = new HashMap<>();   // id -> estate beneficiary id
    long estateInactivity = 10;                                // blocks of inactivity before estate is claimable (governable; small for testnet)
    // ---- personhood (social web-of-trust; PLUGGABLE: admission to 'verified' is by VOUCH tx today,
    //      swap for a biometric-uniqueness proof tx in future without touching consensus) ----
    final java.util.Set<String> verified = new java.util.HashSet<>();      // personhood-verified human IDs
    final Map<String, java.util.Set<String>> vouches = new HashMap<>();    // candidate -> set of vouchers
    static final int VOUCH_THRESHOLD = 2;                                  // vouches from verified humans to admit

    boolean initialized() { return ownerId != null && !chain.isEmpty(); }
    int height() { return chain.isEmpty() ? -1 : chain.size() - 1; }
    String lastHash() throws Exception { return chain.isEmpty() ? ZERO32 : chain.get(chain.size() - 1).getString("hash"); }
    // ---- ledger-history sharding: a block keeps a full body or is pruned to header-only ----
    boolean hasBody(int h) { return h >= 0 && h < chain.size() && chain.get(h).has("txs"); }
    void pruneBlock(int h) { chain.get(h).remove("txs"); chain.get(h).put("pruned", true); }   // keep header (hash/qc/proposer/roots)
    void pruneBlockRS(int h, int idx, byte[] shard) {   // drop the full body, retain only THIS node's RS shard
        chain.get(h).remove("txs");
        chain.get(h).put("pruned", true).put("rsIdx", idx).put("rsShard", PhantomCrypto.hex(shard));
    }
    /** Recompute a block's committed hash from its body — used to verify a reconstructed body. */
    String blockHash(JSONObject b) throws Exception {
        String preimage = chainId + "|" + b.getInt("height") + "|" + b.getString("prevHash") + "|"
                + b.getJSONArray("txs").toString() + "|" + b.getLong("ts");
        return PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(preimage)));
    }
    long balanceOf(String id) { Account a = accounts.get(id); return a == null ? 0 : a.balance; }
    long nonceOf(String id) { Account a = accounts.get(id); return a == null ? 0 : a.nonce; }

    /** Genesis: credit the owner and seal block 0 (coinbase). */
    void genesis(String ownerId, long amount, MLDSAPrivateKeyParameters deviceKey, long ts) throws Exception {
        this.ownerId = ownerId;
        accounts.clear(); chain.clear(); mempool.clear();
        Account a = new Account(); a.balance = amount; a.nonce = 0;
        accounts.put(ownerId, a);
        JSONObject coinbase = new JSONObject().put("from", "GENESIS").put("to", ownerId)
                .put("amount", amount).put("nonce", 0).put("sig", "");
        JSONArray txs = new JSONArray(); txs.put(coinbase);
        chain.add(sealBlock(0, ZERO32, txs, ts, deviceKey));
    }

    static final java.util.Set<String> SPECIAL = new java.util.HashSet<>(java.util.Arrays.asList(
            "GENESIS", "SLASH", "VOUCH", "BOND", "UNBOND", "UNJAIL", "PROPOSE", "VOTE",
            "REGISTER", "ROTATE", "SETGUARDIANS", "RECOVER", "SETBENEFICIARY", "CLAIM", "VALJOIN",
            "BRIDGE_OUT", "BRIDGE_IN", "ORACLE"));
    static boolean isTransfer(JSONObject tx) { return !SPECIAL.contains(tx.optString("from")); }

    /** Stable tx id for dedup/mempool removal: the signature if present, else a hash of the tx body
     *  (RECOVER carries only per-guardian approval sigs, no single top-level sig). */
    static String txId(JSONObject tx) {
        String sig = tx.optString("sig", "");
        return sig.isEmpty() ? PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(tx.toString()))) : sig;
    }

    /** Canonical signing string for a transfer (fee is part of the signed payload). */
    static String txCanon(String cid, String from, String to, long amount, long fee, long nonce) {
        return cid + "|" + from + "|" + to + "|" + amount + "|" + fee + "|" + nonce;
    }

    /** Canonical signing string for an actor-signed action tx (bond/unbond/unjail/propose/vote). */
    static String actionCanon(JSONObject tx) throws Exception {
        String t = tx.getString("from"), actor = tx.getString("actor"), cid = tx.optString("cid", "");
        long nonce = tx.getLong("nonce");
        switch (t) {
            case "BOND":    return "bond|" + cid + "|" + actor + "|" + tx.getLong("amount") + "|" + nonce;
            case "UNBOND":  return "unbond|" + cid + "|" + actor + "|" + tx.getLong("amount") + "|" + nonce;
            case "UNJAIL":  return "unjail|" + cid + "|" + actor + "|" + nonce;
            case "PROPOSE": return "propose|" + cid + "|" + actor + "|" + tx.getString("propId") + "|" + tx.getString("param") + "|" + tx.getLong("value") + "|" + nonce;
            case "VOTE":    return "vote|" + cid + "|" + actor + "|" + tx.getString("propId") + "|" + tx.getBoolean("choice") + "|" + nonce;
            case "SETBENEFICIARY": return "setbeneficiary|" + cid + "|" + actor + "|" + tx.getString("beneficiary") + "|" + nonce;
            default:        return "";
        }
    }

    /** Build a signed transfer from the owner's key (single-node path; fee=0). */
    JSONObject buildTx(String from, String to, long amount, MLDSAPrivateKeyParameters fromKey) throws Exception {
        long nonce = nonceOf(from);
        byte[] sig = PhantomCrypto.sign(fromKey, PhantomCrypto.utf8(txCanon(chainId, from, to, amount, 0, nonce)));
        return new JSONObject().put("from", from).put("to", to).put("amount", amount).put("cid", chainId)
                .put("fee", 0).put("nonce", nonce).put("pub", PhantomCrypto.hex(fromKey.getPublicKeyParameters().getEncoded()))
                .put("sig", PhantomCrypto.hex(sig));
    }

    /** Validate (signature, balance, nonce) and apply to state; queue in mempool. */
    String submitTx(JSONObject tx, MLDSAPublicKeyParameters fromPub) throws Exception {
        String from = tx.getString("from");
        String to = tx.getString("to");
        long amount = tx.getLong("amount");
        long nonce = tx.getLong("nonce");
        long fee = tx.optLong("fee", 0);
        String canon = txCanon(chainId, from, to, amount, fee, nonce);
        if (!PhantomCrypto.verify(fromPub, PhantomCrypto.utf8(canon), PhantomCrypto.unhex(tx.getString("sig"))))
            return "rejected: bad signature";
        if (amount <= 0 || fee < 0) return "rejected: non-positive amount or negative fee";
        long cost; try { cost = Math.addExact(amount, fee); } catch (ArithmeticException e) { return "rejected: amount overflow"; }
        Account fa = accounts.get(from);
        if (fa == null || fa.balance < cost) return "rejected: insufficient balance";
        if (nonce != fa.nonce) return "rejected: bad nonce (expected " + fa.nonce + ")";
        fa.balance -= amount + fee; fa.nonce += 1;
        burned += fee;   // single-node path: fee is removed from supply
        Account ta = accounts.get(to);
        if (ta == null) { ta = new Account(); accounts.put(to, ta); }
        ta.balance += amount;
        mempool.add(tx);
        return "accepted";
    }

    /** Seal all mempool txs into the next block. */
    JSONObject mineBlock(MLDSAPrivateKeyParameters deviceKey, long ts) throws Exception {
        JSONArray txs = new JSONArray();
        for (int ti = 0; ti < mempool.size() && ti < MAX_BLOCK_TXS; ti++) txs.put(mempool.get(ti));
        JSONObject b = sealBlock(chain.size(), lastHash(), txs, ts, deviceKey);
        chain.add(b);
        mempool.clear();
        return b;
    }

    JSONObject sealBlock(int height, String prevHash, JSONArray txs, long ts, MLDSAPrivateKeyParameters key) throws Exception {
        String preimage = chainId + "|" + height + "|" + prevHash + "|" + txs.toString() + "|" + ts;
        String hash = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(preimage)));
        byte[] sig = PhantomCrypto.sign(key, PhantomCrypto.utf8(hash));
        return new JSONObject().put("height", height).put("prevHash", prevHash).put("txs", txs)
                .put("ts", ts).put("hash", hash).put("sig", PhantomCrypto.hex(sig));
    }

    /** Re-derive every block hash and check prevHash links. */
    boolean verifyChain() throws Exception {
        String prev = ZERO32;
        for (JSONObject b : chain) {
            if (!b.getString("prevHash").equals(prev)) return false;
            if (!b.optBoolean("pruned", false)) {   // pruned blocks: header trusted (hash was QC-committed)
                String preimage = chainId + "|" + b.getInt("height") + "|" + b.getString("prevHash") + "|"
                        + b.getJSONArray("txs").toString() + "|" + b.getLong("ts");
                String h = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(preimage)));
                if (!h.equals(b.getString("hash"))) return false;
            }
            prev = b.getString("hash");
        }
        return true;
    }

    /** JSONObject keys as a list — works on both the standalone org.json jar and Android's built-in
     *  org.json (which lacks keySet()). */
    static java.util.List<String> keysOf(JSONObject o) {
        java.util.List<String> ks = new ArrayList<>();
        for (Iterator<String> it = o.keys(); it.hasNext(); ) ks.add(it.next());
        return ks;
    }

    String toJson() throws Exception {
        JSONObject root = new JSONObject();
        root.put("owner", ownerId == null ? JSONObject.NULL : ownerId);
        root.put("chainId", chainId);
        JSONObject accs = new JSONObject();
        for (Map.Entry<String, Account> e : accounts.entrySet())
            accs.put(e.getKey(), new JSONObject().put("balance", e.getValue().balance).put("nonce", e.getValue().nonce));
        root.put("accounts", accs);
        JSONArray ch = new JSONArray(); for (JSONObject b : chain) ch.put(b);
        root.put("chain", ch);
        JSONArray mp = new JSONArray(); for (JSONObject t : mempool) mp.put(t);
        root.put("mempool", mp);
        JSONArray sl = new JSONArray(); for (String v : slashed) sl.put(v);
        root.put("slashed", sl);
        JSONObject st = new JSONObject(); for (Map.Entry<String, Long> e : stake.entrySet()) st.put(e.getKey(), (long) e.getValue());
        root.put("stake", st);
        JSONObject idn = new JSONObject(); for (Map.Entry<String, Long> e : identity.entrySet()) idn.put(e.getKey(), (long) e.getValue());
        root.put("identity", idn);
        JSONArray vs = new JSONArray(); for (String v : validators) vs.put(v);
        root.put("validators", vs);
        root.put("minted", totalMinted);
        JSONArray ver = new JSONArray(); for (String v : verified) ver.put(v);
        root.put("verified", ver);
        JSONObject vo = new JSONObject();
        for (Map.Entry<String, java.util.Set<String>> e : vouches.entrySet()) { JSONArray a = new JSONArray(); for (String x : e.getValue()) a.put(x); vo.put(e.getKey(), a); }
        root.put("vouches", vo);
        root.put("burned", burned);
        root.put("params", new JSONObject()
            .put("blockReward", blockReward).put("halvingBlocks", halvingBlocks).put("maxSupply", maxSupply)
            .put("feeBurnBps", feeBurnBps).put("slashBps", slashBps).put("jailBlocks", jailBlocks).put("unbondingBlocks", unbondingBlocks)
            .put("estateInactivity", estateInactivity).put("minValidatorStake", minValidatorStake).put("bridgeThreshold", bridgeThreshold).put("identityBond", identityBond).put("committeeSize", committeeSize));
        JSONObject jl = new JSONObject(); for (Map.Entry<String, Long> e : jailed.entrySet()) jl.put(e.getKey(), (long) e.getValue());
        root.put("jailed", jl);
        JSONArray ub = new JSONArray(); for (JSONObject u : unbonding) ub.put(u);
        root.put("unbonding", ub);
        JSONObject pr = new JSONObject(); for (Map.Entry<String, JSONObject> e : proposals.entrySet()) pr.put(e.getKey(), e.getValue());
        root.put("proposals", pr);
        JSONObject idns = new JSONObject(); for (Map.Entry<String, JSONObject> e : identities.entrySet()) idns.put(e.getKey(), e.getValue());
        root.put("identities", idns);
        JSONObject la = new JSONObject(); for (Map.Entry<String, Long> e : lastActive.entrySet()) la.put(e.getKey(), (long) e.getValue());
        root.put("lastActive", la);
        JSONObject bf = new JSONObject(); for (Map.Entry<String, String> e : beneficiary.entrySet()) bf.put(e.getKey(), e.getValue());
        root.put("beneficiary", bf);
        JSONObject vp = new JSONObject(); for (Map.Entry<String, String> e : valPubs.entrySet()) vp.put(e.getKey(), e.getValue());
        root.put("valPubs", vp);
        JSONObject rg = new JSONObject(); for (Map.Entry<String, String> e : regions.entrySet()) rg.put(e.getKey(), e.getValue());
        root.put("regions", rg);
        JSONObject tr = new JSONObject(); for (Map.Entry<String, String> e : tiers.entrySet()) tr.put(e.getKey(), e.getValue());
        root.put("tiers", tr);
        JSONObject cu = new JSONObject(); for (Map.Entry<String, String> e : custodians.entrySet()) cu.put(e.getKey(), e.getValue());
        root.put("custodians", cu);
        JSONArray bp = new JSONArray(); for (String x : bridgeProcessed) bp.put(x);
        root.put("bridgeProcessed", bp);
        JSONObject orc = new JSONObject();
        for (Map.Entry<String, Map<String, Long>> e : oracleRates.entrySet()) { JSONObject in = new JSONObject(); for (Map.Entry<String, Long> i : e.getValue().entrySet()) in.put(i.getKey(), (long) i.getValue()); orc.put(e.getKey(), in); }
        root.put("oracleRates", orc);
        root.put("beacon", beacon);
        JSONObject cm = new JSONObject(); for (Map.Entry<String, String> e : commits.entrySet()) cm.put(e.getKey(), e.getValue());
        root.put("commits", cm);
        return root.toString();
    }

    void fromJson(String s) throws Exception {
        JSONObject root = new JSONObject(s);
        ownerId = root.isNull("owner") ? null : root.getString("owner");
        chainId = root.optString("chainId", "");
        accounts.clear(); chain.clear(); mempool.clear();
        JSONObject accs = root.getJSONObject("accounts");
        for (Iterator<String> it = accs.keys(); it.hasNext(); ) {
            String k = it.next();
            JSONObject a = accs.getJSONObject(k);
            Account ac = new Account(); ac.balance = a.getLong("balance"); ac.nonce = a.getLong("nonce");
            accounts.put(k, ac);
        }
        JSONArray ch = root.getJSONArray("chain");
        for (int i = 0; i < ch.length(); i++) chain.add(ch.getJSONObject(i));
        JSONArray mp = root.optJSONArray("mempool");
        if (mp != null) for (int i = 0; i < mp.length(); i++) mempool.add(mp.getJSONObject(i));
        slashed.clear();
        JSONArray sl = root.optJSONArray("slashed");
        if (sl != null) for (int i = 0; i < sl.length(); i++) slashed.add(sl.getString(i));
        stake.clear(); JSONObject st = root.optJSONObject("stake");
        if (st != null) for (String k : keysOf(st)) stake.put(k, st.getLong(k));
        identity.clear(); JSONObject idn = root.optJSONObject("identity");
        if (idn != null) for (String k : keysOf(idn)) identity.put(k, idn.getLong(k));
        validators.clear(); JSONArray vs = root.optJSONArray("validators");
        if (vs != null) for (int i = 0; i < vs.length(); i++) validators.add(vs.getString(i));
        totalMinted = root.optLong("minted", 0);
        verified.clear(); JSONArray ver = root.optJSONArray("verified");
        if (ver != null) for (int i = 0; i < ver.length(); i++) verified.add(ver.getString(i));
        vouches.clear(); JSONObject vo = root.optJSONObject("vouches");
        if (vo != null) for (String k : keysOf(vo)) { java.util.Set<String> set = new java.util.HashSet<>(); JSONArray a = vo.getJSONArray(k); for (int i = 0; i < a.length(); i++) set.add(a.getString(i)); vouches.put(k, set); }
        burned = root.optLong("burned", 0);
        JSONObject params = root.optJSONObject("params");
        if (params != null) {
            blockReward = params.optLong("blockReward", blockReward);
            halvingBlocks = params.optInt("halvingBlocks", halvingBlocks);
            maxSupply = params.optLong("maxSupply", maxSupply);
            feeBurnBps = params.optInt("feeBurnBps", feeBurnBps);
            slashBps = params.optInt("slashBps", slashBps);
            jailBlocks = params.optInt("jailBlocks", jailBlocks);
            unbondingBlocks = params.optInt("unbondingBlocks", unbondingBlocks);
            estateInactivity = params.optLong("estateInactivity", estateInactivity);
            minValidatorStake = params.optInt("minValidatorStake", minValidatorStake);
            identityBond = params.optLong("identityBond", identityBond);
            committeeSize = params.optInt("committeeSize", committeeSize);
            bridgeThreshold = params.optInt("bridgeThreshold", bridgeThreshold);
        }
        jailed.clear(); JSONObject jl = root.optJSONObject("jailed");
        if (jl != null) for (String k : keysOf(jl)) jailed.put(k, jl.getLong(k));
        unbonding.clear(); JSONArray ub = root.optJSONArray("unbonding");
        if (ub != null) for (int i = 0; i < ub.length(); i++) unbonding.add(ub.getJSONObject(i));
        proposals.clear(); JSONObject pr = root.optJSONObject("proposals");
        if (pr != null) for (String k : keysOf(pr)) proposals.put(k, pr.getJSONObject(k));
        identities.clear(); JSONObject idns = root.optJSONObject("identities");
        if (idns != null) for (String k : keysOf(idns)) identities.put(k, idns.getJSONObject(k));
        lastActive.clear(); JSONObject la = root.optJSONObject("lastActive");
        if (la != null) for (String k : keysOf(la)) lastActive.put(k, la.getLong(k));
        beneficiary.clear(); JSONObject bf = root.optJSONObject("beneficiary");
        if (bf != null) for (String k : keysOf(bf)) beneficiary.put(k, bf.getString(k));
        valPubs.clear(); JSONObject vp = root.optJSONObject("valPubs");
        if (vp != null) for (String k : keysOf(vp)) valPubs.put(k, vp.getString(k));
        regions.clear(); JSONObject rg = root.optJSONObject("regions");
        if (rg != null) for (String k : keysOf(rg)) regions.put(k, rg.getString(k));
        tiers.clear(); JSONObject tr = root.optJSONObject("tiers");
        if (tr != null) for (String k : keysOf(tr)) tiers.put(k, tr.getString(k));
        custodians.clear(); JSONObject cu = root.optJSONObject("custodians");
        if (cu != null) for (String k : keysOf(cu)) custodians.put(k, cu.getString(k));
        bridgeProcessed.clear(); JSONArray bp = root.optJSONArray("bridgeProcessed");
        if (bp != null) for (int i = 0; i < bp.length(); i++) bridgeProcessed.add(bp.getString(i));
        oracleRates.clear(); JSONObject orc = root.optJSONObject("oracleRates");
        if (orc != null) for (String pair : keysOf(orc)) { Map<String, Long> rs = new HashMap<>(); JSONObject in = orc.getJSONObject(pair); for (String c : keysOf(in)) rs.put(c, in.getLong(c)); oracleRates.put(pair, rs); }
        beacon = root.optString("beacon", ZERO32);
        commits.clear(); JSONObject cm = root.optJSONObject("commits");
        if (cm != null) for (String k : keysOf(cm)) commits.put(k, cm.getString(k));
    }

    // ===== multi-node (round-robin proposer) =====
    // State changes ONLY on block commit; mempool holds validated-pending txs (projected over committed state).

    void genesisMulti(java.util.LinkedHashMap<String, Long> alloc, long ts) throws Exception {
        accounts.clear(); chain.clear(); mempool.clear(); ownerId = null;
        JSONArray txs = new JSONArray();
        for (Map.Entry<String, Long> e : alloc.entrySet()) {
            Account a = new Account(); a.balance = e.getValue(); a.nonce = 0; accounts.put(e.getKey(), a);
            txs.put(new JSONObject().put("from", "GENESIS").put("to", e.getKey())
                    .put("amount", (long) e.getValue()).put("nonce", 0).put("sig", ""));
        }
        String preimage = chainId + "|" + 0 + "|" + ZERO32 + "|" + txs.toString() + "|" + ts;
        String hash = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(preimage)));
        chain.add(new JSONObject().put("height", 0).put("prevHash", ZERO32).put("txs", txs)
                .put("ts", ts).put("hash", hash).put("sig", "").put("proposer", -1));
    }

    private long[] proj(String id, Map<String, long[]> m) {
        long[] v = m.get(id);
        if (v == null) { v = new long[]{ balanceOf(id), nonceOf(id) }; m.put(id, v); }
        return v;
    }

    private Map<String, long[]> mempoolProjection() throws Exception {
        Map<String, long[]> m = new HashMap<>();
        for (JSONObject tx : mempool) applyProj(tx, m);
        return m;
    }

    JSONObject buildTxProjected(String from, String to, long amount, long fee, MLDSAPrivateKeyParameters key) throws Exception {
        long nonce = proj(from, mempoolProjection())[1];
        byte[] sig = PhantomCrypto.sign(key, PhantomCrypto.utf8(txCanon(chainId, from, to, amount, fee, nonce)));
        return new JSONObject().put("from", from).put("to", to).put("amount", amount).put("cid", chainId)
                .put("fee", fee).put("nonce", nonce).put("pub", PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded()))
                .put("sig", PhantomCrypto.hex(sig));
    }

    String addToMempool(JSONObject tx, Map<String, MLDSAPublicKeyParameters> pubById) throws Exception {
        if (mempool.size() >= MAX_MEMPOOL) return "rejected: mempool full";
        if (isTransfer(tx) && tx.optLong("fee", 0) < MIN_FEE) return "rejected: fee below minimum";   // anti-spam
        Map<String, long[]> m = mempoolProjection();
        String err = txCheck(tx, pubById, m);
        if (err != null) return "rejected: " + err;
        mempool.add(tx);
        return "accepted";
    }

    JSONObject buildBlock(int proposerIndex, MLDSAPrivateKeyParameters key, long ts) throws Exception {
        JSONArray txs = new JSONArray();
        for (int ti = 0; ti < mempool.size() && ti < MAX_BLOCK_TXS; ti++) txs.put(mempool.get(ti));
        int height = chain.size();
        String prevHash = lastHash();
        String preimage = chainId + "|" + height + "|" + prevHash + "|" + txs.toString() + "|" + ts;
        String hash = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(preimage)));
        byte[] sig = PhantomCrypto.sign(key, PhantomCrypto.utf8(hash));
        return new JSONObject().put("height", height).put("prevHash", prevHash).put("txs", txs)
                .put("ts", ts).put("hash", hash).put("sig", PhantomCrypto.hex(sig)).put("proposer", proposerIndex);
    }

    String commitBlock(JSONObject b, Map<String, MLDSAPublicKeyParameters> pubById) throws Exception {
        if (b.getInt("height") != chain.size()) return "rejected: bad height (have " + chain.size() + ")";
        if (!b.getString("prevHash").equals(lastHash())) return "rejected: bad prevHash";
        String preimage = chainId + "|" + b.getInt("height") + "|" + b.getString("prevHash") + "|"
                + b.getJSONArray("txs").toString() + "|" + b.getLong("ts");
        String hash = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(preimage)));
        if (!hash.equals(b.getString("hash"))) return "rejected: bad hash";
        String psr = b.optString("prevStateRoot", null);
        if (psr != null && !stateRoot().equals(psr)) return "rejected: state root mismatch";   // app-hash divergence guard
        String pshr = b.optString("prevShardsRoot", null);
        if (pshr != null && !shardsRoot().equals(pshr)) return "rejected: shards root mismatch";
        if (!beaconRevealValid(b)) return "rejected: bad beacon reveal";   // RANDAO: reveal must match prior commit
        int H = b.getInt("height");
        JSONArray txs = b.getJSONArray("txs");
        // 1) validate every tx against a projection of committed state (balances + nonces)
        Map<String, long[]> m = new HashMap<>();
        for (int i = 0; i < txs.length(); i++) {
            String err = txCheck(txs.getJSONObject(i), pubById, m);
            if (err != null) return "rejected: " + err;
        }
        // 2) flush projected balances/nonces
        for (Map.Entry<String, long[]> e : m.entrySet()) {
            Account a = accounts.get(e.getKey());
            if (a == null) { a = new Account(); accounts.put(e.getKey(), a); }
            a.balance = e.getValue()[0]; a.nonce = e.getValue()[1];
        }
        // 3) apply non-balance state effects + collect fees
        long blockFees = 0;
        int proposerIdx = b.optInt("proposer", -1);
        for (int i = 0; i < txs.length(); i++) {
            JSONObject tx = txs.getJSONObject(i);
            String t = tx.optString("from");
            String active = activeParty(tx);
            if (active != null) lastActive.put(active, (long) H);   // outgoing action resets the estate clock
            if (isTransfer(tx)) { blockFees += tx.optLong("fee", 0); continue; }
            switch (t) {
                case "VOUCH": {
                    String cand = tx.getString("candidate");
                    vouches.computeIfAbsent(cand, k -> new java.util.HashSet<>()).add(tx.getString("voucher"));
                    tryAdmit(cand);
                    break;
                }
                case "SLASH": {
                    String vid = tx.getString("valId");
                    long burnAmt = stake.getOrDefault(vid, 0L) * slashBps / 10000;     // % penalty on bonded stake
                    stake.put(vid, stake.getOrDefault(vid, 0L) - burnAmt);
                    burned += burnAmt;
                    for (JSONObject u : unbonding) if (vid.equals(u.optString("actor"))) {   // can't dodge slashing by unbonding first
                        long ub = u.getLong("amount") * slashBps / 10000; u.put("amount", u.getLong("amount") - ub); burned += ub;
                    }
                    jailed.put(vid, (long) (H + jailBlocks));
                    slashed.add(vid);   // PERMANENT tombstone: proven equivocators stay excluded even after jail/unjail
                    break;
                }
                case "BOND":   stake.merge(tx.getString("actor"), tx.getLong("amount"), Long::sum); tryAdmit(tx.getString("actor")); break;
                case "UNBOND": {
                    String actor = tx.getString("actor"); long amt = tx.getLong("amount");
                    stake.put(actor, Math.max(0, stake.getOrDefault(actor, 0L) - amt));   // weight drops now; tokens locked
                    unbonding.add(new JSONObject().put("actor", actor).put("amount", amt).put("mature", (long) (H + unbondingBlocks)));
                    if (identityBond > 0 && stake.getOrDefault(actor, 0L) < identityBond) verified.remove(actor);   // withdrawing the bond forfeits identity admission (keeps Sybil-cost honest)
                    break;
                }
                case "UNJAIL": {
                    String actor = tx.getString("actor"); Long u = jailed.get(actor);
                    if (u != null && H >= u) jailed.remove(actor);
                    break;
                }
                case "PROPOSE": {
                    String pid = tx.getString("propId");
                    if (!proposals.containsKey(pid) && GOV_PARAMS.contains(tx.getString("param"))) {
                        JSONObject snap = new JSONObject(); long tot = 0;   // snapshot voting weight at proposal time
                        for (int vi = 0; vi < validators.size(); vi++) { long w = Math.round(weight(vi) * 1_000_000_000L); snap.put(validators.get(vi), w); tot += w; }
                        proposals.put(pid, new JSONObject().put("proposer", tx.getString("actor"))
                                .put("param", tx.getString("param")).put("value", tx.getLong("value"))
                                .put("deadline", (long) (H + GOV_VOTING_BLOCKS)).put("applyAt", (long) (H + GOV_VOTING_BLOCKS + GOV_TIMELOCK))
                                .put("snapshot", snap).put("totalWeight", tot)
                                .put("tallied", false).put("passed", false).put("executed", false).put("votes", new JSONObject()));
                    }
                    break;
                }
                case "VOTE": {
                    JSONObject p = proposals.get(tx.getString("propId"));
                    if (p != null && !p.getBoolean("tallied") && H < p.getLong("deadline") && p.getJSONObject("snapshot").has(tx.getString("actor")))
                        p.getJSONObject("votes").put(tx.getString("actor"), tx.getBoolean("choice"));   // only snapshot validators vote
                    break;
                }
                case "REGISTER": {
                    identities.put(idOf(tx.getString("root")), new JSONObject().put("root", tx.getString("root"))
                            .put("devices", new JSONArray().put(tx.getString("device")))
                            .put("guardians", new JSONArray()).put("threshold", 1).put("rotNonce", 0L));
                    break;
                }
                case "ROTATE": case "RECOVER": {   // root- or guardian-authorized device-key replacement
                    JSONObject idn = identities.get(tx.getString("id"));
                    if (idn != null) idn.put("devices", new JSONArray().put(tx.getString("newDevice"))).put("rotNonce", idn.getLong("rotNonce") + 1);
                    break;
                }
                case "SETGUARDIANS": {
                    JSONObject idn = identities.get(tx.getString("id"));
                    if (idn != null) idn.put("guardians", tx.getJSONArray("guardians")).put("threshold", tx.getInt("threshold")).put("rotNonce", idn.getLong("rotNonce") + 1);
                    break;
                }
                case "VALJOIN": {   // append-only: a sufficiently-bonded key joins the validator set
                    String vpub = tx.getString("pubkey"), vid = idOf(vpub);
                    if (!validators.contains(vid) && stake.getOrDefault(vid, 0L) >= minValidatorStake) {
                        validators.add(vid); valPubs.put(vid, vpub); identity.putIfAbsent(vid, 1L);
                        commits.put(vid, tx.getString("beaconCommit0"));   // bind the joiner's first reveal (no free grind)
                    }
                    break;
                }
                case "BRIDGE_OUT":   // locked amount already moved to reserve via projection
                    blockFees += tx.optLong("fee", 0);
                    bridgeOuts.add(new JSONObject().put("actor", tx.getString("actor")).put("chain", tx.getString("chain"))
                            .put("extAddr", tx.getString("extAddr")).put("amount", tx.getLong("amount")));
                    break;
                case "ORACLE":   // custodian rate attestation -> median price
                    oracleRates.computeIfAbsent(tx.getString("pair"), k -> new HashMap<>()).put(tx.getString("custodian"), tx.getLong("rate"));
                    break;
                case "BRIDGE_IN": {   // release reserve -> recipient on M-of-N custodian attestation (replay-guarded)
                    String extTxid = tx.getString("extTxid"), recipient = tx.getString("recipient"); long amount = tx.getLong("amount");
                    if (!bridgeProcessed.contains(extTxid) && balanceOf(BRIDGE_RESERVE) >= amount) {
                        accounts.get(BRIDGE_RESERVE).balance -= amount;
                        Account ra = accounts.get(recipient); if (ra == null) { ra = new Account(); accounts.put(recipient, ra); }
                        ra.balance += amount;
                        bridgeProcessed.add(extTxid);
                    }
                    break;
                }
                case "SETBENEFICIARY": beneficiary.put(tx.getString("actor"), tx.getString("beneficiary")); break;
                case "CLAIM": {   // permissionless: enforces the inactivity policy, moving the estate to the beneficiary
                    String acct = tx.getString("account"); long bal = balanceOf(acct);
                    if (beneficiary.containsKey(acct) && bal > 0 && (long) H - lastActive.getOrDefault(acct, 0L) >= estateInactivity) {
                        accounts.get(acct).balance = 0;
                        String benef = beneficiary.get(acct);
                        Account ta = accounts.get(benef); if (ta == null) { ta = new Account(); accounts.put(benef, ta); }
                        ta.balance += bal;
                    }
                    break;
                }
            }
        }
        chain.add(b);
        beaconApply(b);   // fold the proposer's reveal into the beacon, record its next commitment
        // 4) tx fees: burn feeBurnBps%, remainder to the block proposer (validator income beyond emission)
        if (blockFees > 0) {
            long burnF = blockFees * feeBurnBps / 10000;
            burned += burnF;
            long toProp = blockFees - burnF;
            if (proposerIdx >= 0 && proposerIdx < validators.size() && toProp > 0) {
                String pid = validators.get(proposerIdx);
                Account a = accounts.get(pid); if (a == null) { a = new Account(); accounts.put(pid, a); }
                a.balance += toProp;
            } else burned += toProp;
        }
        // 5) mature unbondings -> liquid balance
        for (Iterator<JSONObject> it = unbonding.iterator(); it.hasNext(); ) {
            JSONObject u = it.next();
            if (u.getLong("mature") <= height()) {
                Account a = accounts.get(u.getString("actor"));
                if (a == null) { a = new Account(); accounts.put(u.getString("actor"), a); }
                a.balance += u.getLong("amount"); it.remove();
            }
        }
        // 6) finalize due governance proposals
        finalizeProposals();
        // 7) drop included txs from mempool
        final java.util.Set<String> included = new java.util.HashSet<>();
        for (int i = 0; i < txs.length(); i++) included.add(txId(txs.getJSONObject(i)));
        mempool.removeIf(t -> included.contains(txId(t)));
        // 8) epoch emission (decaying, supply-capped)
        if (!validators.isEmpty()) maybeEpochReward();
        return "appended";
    }

    // ===== quorum-certificate support =====

    /** Build an unsigned block proposal (hash over header+txs; quorum signs the hash). */
    JSONObject buildProposal(int proposerIndex, long ts) throws Exception {
        JSONArray txs = new JSONArray();
        for (int ti = 0; ti < mempool.size() && ti < MAX_BLOCK_TXS; ti++) txs.put(mempool.get(ti));
        int height = chain.size();
        String prevHash = lastHash();
        String preimage = chainId + "|" + height + "|" + prevHash + "|" + txs.toString() + "|" + ts;
        String hash = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(preimage)));
        return new JSONObject().put("height", height).put("prevHash", prevHash).put("txs", txs)
                .put("ts", ts).put("hash", hash).put("proposer", proposerIndex)
                .put("prevStateRoot", stateRoot()).put("prevShardsRoot", shardsRoot());
    }

    /** Read-only: does this proposal link to our head, hash recompute, and build on our exact state? */
    boolean proposalLinks(JSONObject b) throws Exception {
        if (b.getInt("height") != chain.size()) return false;
        if (!b.getString("prevHash").equals(lastHash())) return false;
        String preimage = chainId + "|" + b.getInt("height") + "|" + b.getString("prevHash") + "|"
                + b.getJSONArray("txs").toString() + "|" + b.getLong("ts");
        String hash = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(preimage)));
        if (!hash.equals(b.getString("hash"))) return false;
        String psr = b.optString("prevStateRoot", null);
        if (psr != null && !stateRoot().equals(psr)) return false;   // built on the same committed state
        String pshr = b.optString("prevShardsRoot", null);
        if (pshr != null && !shardsRoot().equals(pshr)) return false; // and the same shard commitment
        return beaconRevealValid(b);                                  // and a valid RANDAO reveal
    }

    /** Read-only: are all txs in this block valid against committed state? (used when voting) */
    boolean txsValid(JSONObject b, Map<String, MLDSAPublicKeyParameters> pubById) throws Exception {
        JSONArray txs = b.getJSONArray("txs");
        Map<String, long[]> m = new HashMap<>();
        for (int i = 0; i < txs.length(); i++)
            if (txCheck(txs.getJSONObject(i), pubById, m) != null) return false;
        return true;
    }

    /** Equivocation evidence: two valid signatures by the same validator over two different hashes. */
    static boolean verifySlash(JSONObject tx, Map<String, MLDSAPublicKeyParameters> pubById) throws Exception {
        String valId = tx.getString("valId");
        String ha = tx.getString("ha"), hb = tx.getString("hb");
        if (ha.equals(hb)) return false;
        MLDSAPublicKeyParameters pub = pubById.get(valId);
        if (pub == null) return false;
        return PhantomCrypto.verify(pub, PhantomCrypto.utf8(ha), PhantomCrypto.unhex(tx.getString("sa")))
            && PhantomCrypto.verify(pub, PhantomCrypto.utf8(hb), PhantomCrypto.unhex(tx.getString("sb")));
    }

    // ===== personhood (social web-of-trust; pluggable -> future biometric admission) =====
    boolean isVerified(String id) { return verified.contains(id); }

    /** Admit a candidate to `verified` once it has enough vouches AND has locked the identity bond (Sybil-cost). */
    void tryAdmit(String cand) {
        if (vouches.getOrDefault(cand, java.util.Collections.emptySet()).size() >= VOUCH_THRESHOLD
                && stake.getOrDefault(cand, 0L) >= identityBond)
            verified.add(cand);
    }

    JSONObject buildVouchTx(String voucher, String candidate, MLDSAPrivateKeyParameters key) throws Exception {
        byte[] sig = PhantomCrypto.sign(key, PhantomCrypto.utf8("vouch|" + chainId + "|" + candidate));
        return new JSONObject().put("from", "VOUCH").put("voucher", voucher).put("candidate", candidate).put("cid", chainId).put("sig", PhantomCrypto.hex(sig));
    }

    boolean verifyVouch(JSONObject tx, Map<String, MLDSAPublicKeyParameters> pubById) throws Exception {
        String voucher = tx.getString("voucher"), candidate = tx.getString("candidate");
        if (!verified.contains(voucher) || voucher.equals(candidate)) return false;   // only verified humans may vouch
        if (!chainId.equals(tx.optString("cid", ""))) return false;
        MLDSAPublicKeyParameters pub = pubById.get(voucher);
        if (pub == null) return false;
        return PhantomCrypto.verify(pub, PhantomCrypto.utf8("vouch|" + chainId + "|" + candidate), PhantomCrypto.unhex(tx.getString("sig")));
    }

    // ===== production economics: fees / staking / slashing / governance =====
    static final int GOV_VOTING_BLOCKS = 6;        // proposal voting window (blocks)
    static final int GOV_TIMELOCK = 4;             // delay between a proposal passing and taking effect
    static final int GOV_QUORUM_BPS = 3334;        // minimum turnout (>1/3 of snapshot voting weight)
    static final java.util.Set<String> GOV_PARAMS = new java.util.HashSet<>(java.util.Arrays.asList(
            "blockReward", "halvingBlocks", "maxSupply", "feeBurnBps", "slashBps", "jailBlocks", "unbondingBlocks", "estateInactivity", "minValidatorStake", "bridgeThreshold", "identityBond", "committeeSize"));

    boolean jailedActive(String id) { Long u = jailed.get(id); return u != null && height() < u; }
    long projectedNonce(String id) throws Exception { return proj(id, mempoolProjection())[1]; }

    /** Resolve the public key for an account: a known validator's key, or a self-sovereign account's
     *  pubkey carried in the tx (bound by id == sha3-256(pubkey)). Enables any wallet to transact. */
    MLDSAPublicKeyParameters pubFor(String id, JSONObject tx, Map<String, MLDSAPublicKeyParameters> pubById) {
        MLDSAPublicKeyParameters p = pubById.get(id);
        if (p != null) return p;
        String ph = tx.optString("pub", "");
        if (ph.isEmpty()) return null;
        byte[] raw = PhantomCrypto.unhex(ph);
        if (!id.equals(PhantomCrypto.hex(PhantomCrypto.sha3_256(raw)))) return null;   // pubkey must hash to the account id
        return new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, raw);
    }

    // ===== identity != key (registry): id = sha3(root); root authorizes rotations, device keys spend =====
    static String idOf(String rootPubHex) { return PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.unhex(rootPubHex))); }
    static MLDSAPublicKeyParameters pk(String hex) { return new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, PhantomCrypto.unhex(hex)); }

    /** Authorize a signer: a registered identity must sign with one of its CURRENT device keys; an
     *  unregistered account stays self-sovereign (validator key or sha3(pub)==id). */
    MLDSAPublicKeyParameters authPub(String id, JSONObject tx, Map<String, MLDSAPublicKeyParameters> pubById) {
        JSONObject idn = identities.get(id);
        if (idn == null) return pubFor(id, tx, pubById);
        String ph = tx.optString("pub", "");
        JSONArray devs = idn.getJSONArray("devices");
        for (int i = 0; i < devs.length(); i++) if (devs.getString(i).equals(ph)) return pk(ph);
        return null;   // pub is not (or no longer) an authorized device of this identity
    }

    boolean verifyRegister(JSONObject tx) throws Exception {
        if (!chainId.equals(tx.optString("cid", ""))) return false;
        String root = tx.getString("root"), device = tx.getString("device");
        if (identities.containsKey(idOf(root))) return false;   // one-time
        return PhantomCrypto.verify(pk(root), PhantomCrypto.utf8("register|" + chainId + "|" + root + "|" + device), PhantomCrypto.unhex(tx.getString("sig")));
    }
    boolean verifyRootOp(JSONObject tx, String msg) throws Exception {
        if (!chainId.equals(tx.optString("cid", ""))) return false;
        JSONObject idn = identities.get(tx.getString("id"));
        if (idn == null || tx.getLong("rotNonce") != idn.getLong("rotNonce")) return false;   // replay-protected by rotNonce
        return PhantomCrypto.verify(pk(idn.getString("root")), PhantomCrypto.utf8(msg), PhantomCrypto.unhex(tx.getString("sig")));
    }
    boolean verifyRotate(JSONObject tx) throws Exception {
        return verifyRootOp(tx, "rotate|" + chainId + "|" + tx.getString("id") + "|" + tx.getString("newDevice") + "|" + tx.getLong("rotNonce"));
    }
    boolean verifySetGuardians(JSONObject tx) throws Exception {
        return verifyRootOp(tx, "setguardians|" + chainId + "|" + tx.getString("id") + "|" + tx.getJSONArray("guardians").toString() + "|" + tx.getInt("threshold") + "|" + tx.getLong("rotNonce"));
    }
    boolean verifyRecover(JSONObject tx) throws Exception {
        if (!chainId.equals(tx.optString("cid", ""))) return false;
        JSONObject idn = identities.get(tx.getString("id"));
        if (idn == null || tx.getLong("rotNonce") != idn.getLong("rotNonce")) return false;
        JSONArray gs = idn.getJSONArray("guardians"); int threshold = idn.getInt("threshold");
        java.util.Set<String> guardianSet = new java.util.HashSet<>(); for (int i = 0; i < gs.length(); i++) guardianSet.add(gs.getString(i));
        String msg = "recover|" + chainId + "|" + tx.getString("id") + "|" + tx.getString("newDevice") + "|" + tx.getLong("rotNonce");
        JSONArray ap = tx.getJSONArray("approvals"); java.util.Set<String> seen = new java.util.HashSet<>(); int ok = 0;
        for (int i = 0; i < ap.length(); i++) {
            JSONObject a = ap.getJSONObject(i);
            String g = a.getString("guardian"), ph = a.getString("pub");
            if (!guardianSet.contains(g) || !seen.add(g)) continue;        // distinct guardian
            JSONObject gidn = identities.get(g); if (gidn == null) continue;
            boolean dev = false; JSONArray gd = gidn.getJSONArray("devices");
            for (int j = 0; j < gd.length(); j++) if (gd.getString(j).equals(ph)) dev = true;
            if (dev && PhantomCrypto.verify(pk(ph), PhantomCrypto.utf8(msg), PhantomCrypto.unhex(a.getString("sig")))) ok++;
        }
        return threshold > 0 && ok >= threshold;
    }

    JSONObject buildRegisterTx(MLDSAPrivateKeyParameters rootKey, MLDSAPrivateKeyParameters deviceKey) throws Exception {
        String root = PhantomCrypto.hex(rootKey.getPublicKeyParameters().getEncoded());
        String device = PhantomCrypto.hex(deviceKey.getPublicKeyParameters().getEncoded());
        byte[] sig = PhantomCrypto.sign(rootKey, PhantomCrypto.utf8("register|" + chainId + "|" + root + "|" + device));
        return new JSONObject().put("from", "REGISTER").put("root", root).put("device", device).put("cid", chainId).put("sig", PhantomCrypto.hex(sig));
    }
    JSONObject buildRotateTx(String id, MLDSAPrivateKeyParameters rootKey, String newDevice, long rotNonce) throws Exception {
        byte[] sig = PhantomCrypto.sign(rootKey, PhantomCrypto.utf8("rotate|" + chainId + "|" + id + "|" + newDevice + "|" + rotNonce));
        return new JSONObject().put("from", "ROTATE").put("id", id).put("newDevice", newDevice).put("rotNonce", rotNonce).put("cid", chainId).put("sig", PhantomCrypto.hex(sig));
    }
    JSONObject buildSetGuardiansTx(String id, MLDSAPrivateKeyParameters rootKey, JSONArray guardians, int threshold, long rotNonce) throws Exception {
        byte[] sig = PhantomCrypto.sign(rootKey, PhantomCrypto.utf8("setguardians|" + chainId + "|" + id + "|" + guardians.toString() + "|" + threshold + "|" + rotNonce));
        return new JSONObject().put("from", "SETGUARDIANS").put("id", id).put("guardians", guardians).put("threshold", threshold).put("rotNonce", rotNonce).put("cid", chainId).put("sig", PhantomCrypto.hex(sig));
    }
    JSONObject recoverApproval(String guardianId, MLDSAPrivateKeyParameters guardianDeviceKey, String id, String newDevice, long rotNonce) throws Exception {
        String pub = PhantomCrypto.hex(guardianDeviceKey.getPublicKeyParameters().getEncoded());
        byte[] sig = PhantomCrypto.sign(guardianDeviceKey, PhantomCrypto.utf8("recover|" + chainId + "|" + id + "|" + newDevice + "|" + rotNonce));
        return new JSONObject().put("guardian", guardianId).put("pub", pub).put("sig", PhantomCrypto.hex(sig));
    }
    JSONObject buildRecoverTx(String id, String newDevice, long rotNonce, JSONArray approvals) {
        return new JSONObject().put("from", "RECOVER").put("id", id).put("newDevice", newDevice).put("rotNonce", rotNonce).put("cid", chainId).put("approvals", approvals);
    }

    // ===== estate / inheritance =====
    /** The party whose action this tx represents (resets the inactivity clock). Incoming transfers do NOT. */
    static String activeParty(JSONObject tx) {
        String t = tx.optString("from");
        if (!SPECIAL.contains(t)) return t;   // transfer: the sender
        switch (t) {
            case "BOND": case "UNBOND": case "UNJAIL": case "PROPOSE": case "VOTE": case "SETBENEFICIARY": return tx.optString("actor", null);
            case "REGISTER": { String r = tx.optString("root", ""); return r.isEmpty() ? null : idOf(r); }
            case "ROTATE": case "RECOVER": case "SETGUARDIANS": return tx.optString("id", null);
            case "VOUCH": return tx.optString("voucher", null);
            default: return null;   // GENESIS, SLASH, CLAIM
        }
    }
    boolean verifyClaim(JSONObject tx) throws Exception {
        if (!chainId.equals(tx.optString("cid", ""))) return false;
        String acct = tx.getString("account");
        return beneficiary.containsKey(acct) && balanceOf(acct) > 0
                && height() - lastActive.getOrDefault(acct, 0L) >= estateInactivity;   // inactive long enough
    }
    JSONObject buildSetBeneficiaryTx(String actor, String beneficiaryId, long nonce, MLDSAPrivateKeyParameters key) throws Exception {
        JSONObject tx = new JSONObject().put("from", "SETBENEFICIARY").put("actor", actor).put("beneficiary", beneficiaryId).put("nonce", nonce).put("cid", chainId)
                .put("pub", PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded()));
        return tx.put("sig", PhantomCrypto.hex(PhantomCrypto.sign(key, PhantomCrypto.utf8(actionCanon(tx)))));
    }
    JSONObject buildClaimTx(String account, long salt) { return new JSONObject().put("from", "CLAIM").put("account", account).put("salt", salt).put("cid", chainId); }

    // ===== dynamic validator set: a bonded key joins the validator set (append-only) =====
    boolean verifyValJoin(JSONObject tx) throws Exception {
        if (!chainId.equals(tx.optString("cid", ""))) return false;
        String pub = tx.getString("pubkey"), id = idOf(pub);
        if (validators.contains(id)) return false;                          // already a validator
        if (stake.getOrDefault(id, 0L) < minValidatorStake) return false;   // must be sufficiently bonded
        if (tx.optString("beaconCommit0", "").length() != 64) return false; // must publish a beacon commitment (binds first reveal)
        // the commitment is signed over too, so a joiner can't be assigned someone else's commit0
        return PhantomCrypto.verify(pk(pub), PhantomCrypto.utf8("valjoin|" + chainId + "|" + pub + "|" + tx.getString("beaconCommit0")), PhantomCrypto.unhex(tx.getString("sig")));
    }
    JSONObject buildValJoinTx(MLDSAPrivateKeyParameters key) throws Exception {
        String pub = PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded());
        String commit0 = beaconCommit0For(key.getEncoded());
        byte[] sig = PhantomCrypto.sign(key, PhantomCrypto.utf8("valjoin|" + chainId + "|" + pub + "|" + commit0));
        return new JSONObject().put("from", "VALJOIN").put("pubkey", pub).put("cid", chainId).put("beaconCommit0", commit0).put("sig", PhantomCrypto.hex(sig));
    }

    // ===== cross-chain bridge (on-chain side) =====
    static String extAddr(String chain, String pubHex) {
        byte[] dom = PhantomCrypto.utf8("ext_addr_" + chain + "|"), pk = PhantomCrypto.unhex(pubHex);
        byte[] in = new byte[dom.length + pk.length];
        System.arraycopy(dom, 0, in, 0, dom.length); System.arraycopy(pk, 0, in, dom.length, pk.length);
        return PhantomCrypto.hex(PhantomCrypto.shake256(in, 20));   // deterministic 20-byte external address
    }
    static String bridgeOutCanon(JSONObject tx) {
        return "bridgeout|" + tx.optString("cid", "") + "|" + tx.getString("actor") + "|" + tx.getString("chain")
                + "|" + tx.getString("extAddr") + "|" + tx.getLong("amount") + "|" + tx.optLong("fee", 0) + "|" + tx.getLong("nonce");
    }
    /** Inbound: >=M custodians attest an external deposit -> release PHNT from the reserve to the recipient. */
    boolean verifyBridgeIn(JSONObject tx) throws Exception {
        if (!chainId.equals(tx.optString("cid", ""))) return false;
        if (bridgeProcessed.contains(tx.getString("extTxid"))) return false;       // replay guard
        String recipient = tx.getString("recipient"); long amount = tx.getLong("amount");
        if (amount <= 0 || balanceOf(BRIDGE_RESERVE) < amount) return false;        // conservation: release only what's reserved
        String msg = "bridgein|" + chainId + "|" + recipient + "|" + amount + "|" + tx.getString("extTxid");
        JSONArray ap = tx.getJSONArray("approvals"); java.util.Set<String> seen = new java.util.HashSet<>(); int ok = 0;
        for (int i = 0; i < ap.length(); i++) {
            JSONObject a = ap.getJSONObject(i);
            String cust = a.getString("custodian"), pub = a.getString("pub");
            if (!pub.equals(custodians.get(cust)) || !seen.add(cust)) continue;     // distinct, registered custodian
            if (PhantomCrypto.verify(pk(pub), PhantomCrypto.utf8(msg), PhantomCrypto.unhex(a.getString("sig")))) ok++;
        }
        return ok >= bridgeThreshold;
    }
    JSONObject buildBridgeOutTx(String actor, String chain, String ext, long amount, long fee, long nonce, MLDSAPrivateKeyParameters key) throws Exception {
        JSONObject tx = new JSONObject().put("from", "BRIDGE_OUT").put("actor", actor).put("chain", chain).put("extAddr", ext)
                .put("amount", amount).put("fee", fee).put("nonce", nonce).put("cid", chainId)
                .put("pub", PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded()));
        return tx.put("sig", PhantomCrypto.hex(PhantomCrypto.sign(key, PhantomCrypto.utf8(bridgeOutCanon(tx)))));
    }
    JSONObject bridgeInApproval(String custodianId, MLDSAPrivateKeyParameters custKey, String recipient, long amount, String extTxid) throws Exception {
        String pub = PhantomCrypto.hex(custKey.getPublicKeyParameters().getEncoded());
        byte[] sig = PhantomCrypto.sign(custKey, PhantomCrypto.utf8("bridgein|" + chainId + "|" + recipient + "|" + amount + "|" + extTxid));
        return new JSONObject().put("custodian", custodianId).put("pub", pub).put("sig", PhantomCrypto.hex(sig));
    }
    JSONObject buildBridgeInTx(String recipient, long amount, String extTxid, JSONArray approvals) {
        return new JSONObject().put("from", "BRIDGE_IN").put("recipient", recipient).put("amount", amount)
                .put("extTxid", extTxid).put("cid", chainId).put("approvals", approvals);
    }
    boolean verifyOracle(JSONObject tx) throws Exception {
        if (!chainId.equals(tx.optString("cid", ""))) return false;
        String cust = tx.getString("custodian"), pub = tx.getString("pub");
        if (!pub.equals(custodians.get(cust))) return false;   // only registered custodians may post rates
        return PhantomCrypto.verify(pk(pub), PhantomCrypto.utf8("oracle|" + chainId + "|" + tx.getString("pair") + "|" + tx.getLong("rate")), PhantomCrypto.unhex(tx.getString("sig")));
    }
    JSONObject buildOracleTx(String custodianId, MLDSAPrivateKeyParameters custKey, String pair, long rate) throws Exception {
        String pub = PhantomCrypto.hex(custKey.getPublicKeyParameters().getEncoded());
        byte[] sig = PhantomCrypto.sign(custKey, PhantomCrypto.utf8("oracle|" + chainId + "|" + pair + "|" + rate));
        return new JSONObject().put("from", "ORACLE").put("custodian", custodianId).put("pub", pub).put("pair", pair).put("rate", rate).put("cid", chainId).put("sig", PhantomCrypto.hex(sig));
    }
    /** Current price = median of custodian-attested rates for a pair (manipulation-resistant). */
    long oracleMedian(String pair) {
        Map<String, Long> rs = oracleRates.get(pair);
        if (rs == null || rs.isEmpty()) return 0;
        java.util.List<Long> v = new ArrayList<>(rs.values()); java.util.Collections.sort(v);
        return v.get(v.size() / 2);
    }

    /** Live token supply: liquid balances + bonded stake + tokens mid-unbond. */
    long circulatingSupply() {
        long s = 0;
        for (Account a : accounts.values()) s += a.balance;
        for (long v : stake.values()) s += v;
        for (JSONObject u : unbonding) s += u.optLong("amount", 0);
        return s;
    }

    /** Deterministic hash of all consensus-relevant state (canonical: sorted maps). Committed in each
     *  block header as the post-state of the PREVIOUS block (Tendermint-style app hash), so any
     *  divergence in balances/stake/personhood/jail/supply/params is detected at the next block. */
    String stateRoot() {
        StringBuilder sb = new StringBuilder("acc|");
        java.util.List<String> ids = new ArrayList<>(accounts.keySet()); java.util.Collections.sort(ids);
        for (String id : ids) { Account a = accounts.get(id); sb.append(id).append(':').append(a.balance).append(':').append(a.nonce).append(';'); }
        sb.append("stk|"); java.util.List<String> sk = new ArrayList<>(stake.keySet()); java.util.Collections.sort(sk);
        for (String id : sk) sb.append(id).append(':').append(stake.get(id)).append(';');
        sb.append("ver|"); java.util.List<String> vr = new ArrayList<>(verified); java.util.Collections.sort(vr);
        for (String id : vr) sb.append(id).append(';');
        sb.append("jail|"); java.util.List<String> jl = new ArrayList<>(jailed.keySet()); java.util.Collections.sort(jl);
        for (String id : jl) sb.append(id).append(':').append(jailed.get(id)).append(';');
        sb.append("unb|"); for (JSONObject u : unbonding) sb.append(u.optString("actor")).append(':').append(u.optLong("amount")).append(':').append(u.optLong("mature")).append(';');
        sb.append("idn|"); java.util.List<String> idl = new ArrayList<>(identities.keySet()); java.util.Collections.sort(idl);
        for (String id : idl) { JSONObject o = identities.get(id);
            sb.append(id).append(':').append(o.getString("root")).append(':').append(o.getJSONArray("devices").toString())
              .append(':').append(o.getJSONArray("guardians").toString()).append(':').append(o.getInt("threshold")).append(':').append(o.getLong("rotNonce")).append(';'); }
        sb.append("vals|"); for (String v : validators) sb.append(v).append(',');
        sb.append("vp|"); java.util.List<String> vpl = new ArrayList<>(valPubs.keySet()); java.util.Collections.sort(vpl);
        for (String v : vpl) sb.append(v).append('=').append(valPubs.get(v)).append(';');
        sb.append("rg|"); java.util.List<String> rgl = new ArrayList<>(regions.keySet()); java.util.Collections.sort(rgl);
        for (String v : rgl) sb.append(v).append('=').append(regions.get(v)).append(';');
        sb.append("tr|"); java.util.List<String> trl = new ArrayList<>(tiers.keySet()); java.util.Collections.sort(trl);
        for (String v : trl) sb.append(v).append('=').append(tiers.get(v)).append(';');
        sb.append("cu|"); java.util.List<String> cul = new ArrayList<>(custodians.keySet()); java.util.Collections.sort(cul);
        for (String v : cul) sb.append(v).append('=').append(custodians.get(v)).append(';');
        sb.append("bth|").append(bridgeThreshold).append("|bp|");
        java.util.List<String> bpl = new ArrayList<>(bridgeProcessed); java.util.Collections.sort(bpl);
        for (String v : bpl) sb.append(v).append(';');
        sb.append("orc|"); java.util.List<String> opl = new ArrayList<>(oracleRates.keySet()); java.util.Collections.sort(opl);
        for (String pair : opl) { sb.append(pair).append(':'); Map<String, Long> rs = oracleRates.get(pair);
            java.util.List<String> cl = new ArrayList<>(rs.keySet()); java.util.Collections.sort(cl);
            for (String c : cl) sb.append(c).append('=').append(rs.get(c)).append(','); sb.append(';'); }
        sb.append("bcn|").append(beacon).append("|cm|");
        java.util.List<String> cml = new ArrayList<>(commits.keySet()); java.util.Collections.sort(cml);
        for (String v : cml) sb.append(v).append('=').append(commits.get(v)).append(';');
        sb.append("la|"); java.util.List<String> lal = new ArrayList<>(lastActive.keySet()); java.util.Collections.sort(lal);
        for (String id : lal) sb.append(id).append('@').append(lastActive.get(id)).append(';');
        sb.append("ben|"); java.util.List<String> bl = new ArrayList<>(beneficiary.keySet()); java.util.Collections.sort(bl);
        for (String id : bl) sb.append(id).append('>').append(beneficiary.get(id)).append(';');
        sb.append("supply|").append(totalMinted).append('|').append(burned);
        sb.append("|params|").append(blockReward).append(',').append(halvingBlocks).append(',').append(maxSupply)
          .append(',').append(feeBurnBps).append(',').append(slashBps).append(',').append(jailBlocks).append(',').append(unbondingBlocks).append(',').append(estateInactivity).append(',').append(minValidatorStake).append(',').append(identityBond).append(',').append(committeeSize);
        // permanent tombstone (excludes from quorum/weight via excluded()) — consensus-critical, must be covered
        sb.append("|sl|"); java.util.List<String> sll = new ArrayList<>(slashed); java.util.Collections.sort(sll);
        for (String v : sll) sb.append(v).append(';');
        // pending personhood vouches (accrue toward verified admission)
        sb.append("vch|"); java.util.List<String> vchl = new ArrayList<>(vouches.keySet()); java.util.Collections.sort(vchl);
        for (String c : vchl) { sb.append(c).append('='); java.util.List<String> vs = new ArrayList<>(vouches.get(c)); java.util.Collections.sort(vs);
            for (String v : vs) sb.append(v).append(','); sb.append(';'); }
        // open governance proposals (execute param changes at timelock)
        sb.append("prp|"); java.util.List<String> prl = new ArrayList<>(proposals.keySet()); java.util.Collections.sort(prl);
        for (String pid : prl) { JSONObject p = proposals.get(pid);
            sb.append(pid).append(':').append(p.optString("param")).append(':').append(p.optLong("value")).append(':').append(p.optLong("deadline"))
              .append(':').append(p.optLong("applyAt")).append(':').append(p.optBoolean("tallied")).append(':').append(p.optBoolean("passed"))
              .append(':').append(p.optBoolean("executed")).append(':').append(p.optLong("totalWeight")).append(':');
            JSONObject votes = p.optJSONObject("votes"); if (votes != null) { java.util.List<String> vk = new ArrayList<>(keysOf(votes)); java.util.Collections.sort(vk);
                for (String act : vk) sb.append(act).append('=').append(votes.optBoolean(act)).append(','); }
            sb.append(';'); }
        return PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(sb.toString())));
    }

    // ===== state sharding: per-id state partitioned into SHARDS, each independently rooted =====
    static final int SHARDS = 16;
    static int shardOf(String id) {   // hex account ids shard by prefix; special ids (e.g. BRIDGE_RESERVE) by hash
        try { return id.length() >= 4 ? Math.floorMod(Integer.parseInt(id.substring(0, 4), 16), SHARDS) : 0; }
        catch (NumberFormatException e) { return Math.floorMod(PhantomCrypto.sha3_256(PhantomCrypto.utf8(id))[0] & 0xff, SHARDS); }
    }

    /** Canonical serialization of all per-id state assigned to shard s (sorted by id). */
    String shardData(int s) {
        java.util.TreeSet<String> ids = new java.util.TreeSet<>();
        ids.addAll(accounts.keySet()); ids.addAll(stake.keySet()); ids.addAll(identity.keySet());
        ids.addAll(verified); ids.addAll(jailed.keySet()); ids.addAll(identities.keySet());
        ids.addAll(lastActive.keySet()); ids.addAll(beneficiary.keySet());
        StringBuilder sb = new StringBuilder();
        for (String id : ids) {
            if (shardOf(id) != s) continue;
            Account a = accounts.get(id);
            sb.append(id).append('|').append(a == null ? 0 : a.balance).append(',').append(a == null ? 0 : a.nonce)
              .append(',').append(stake.getOrDefault(id, 0L)).append(',').append(identity.getOrDefault(id, 0L))
              .append(',').append(verified.contains(id) ? 1 : 0).append(',').append(jailed.getOrDefault(id, 0L))
              .append(',').append(lastActive.getOrDefault(id, 0L)).append(',').append(beneficiary.getOrDefault(id, ""))
              .append(',').append(identities.containsKey(id) ? identities.get(id).toString() : "").append(';');
        }
        return sb.toString();
    }
    String shardRoot(int s) { return PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(shardData(s)))); }
    /** Merkle commitment (flat) over all shard roots — bound into each block header as prevShardsRoot. */
    String shardsRoot() {
        StringBuilder sb = new StringBuilder();
        for (int s = 0; s < SHARDS; s++) sb.append(shardRoot(s));
        return PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(sb.toString())));
    }
    /** Light-client proof: a shard slice + the sibling roots verify against a committed shardsRoot,
     *  WITHOUT holding the rest of the state. */
    static boolean verifyShardProof(String committedShardsRoot, int s, String shardDataStr, JSONArray roots) {
        if (roots == null || roots.length() != SHARDS || s < 0 || s >= SHARDS) return false;
        if (!roots.getString(s).equals(PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(shardDataStr))))) return false;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < SHARDS; i++) sb.append(roots.getString(i));
        return committedShardsRoot.equals(PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(sb.toString()))));
    }

    static long clamp(long v, long lo, long hi) { return Math.max(lo, Math.min(hi, v)); }
    void applyParam(String param, long v) {   // governance cannot set values outside safe bounds
        switch (param) {
            case "blockReward":     blockReward = clamp(v, 0, 1_000_000L);                 break;
            case "halvingBlocks":   halvingBlocks = (int) clamp(v, 1, 100_000_000L);       break;
            case "maxSupply":       maxSupply = clamp(v, totalMinted, 1_000_000_000_000L); break;   // never below already-minted
            case "feeBurnBps":      feeBurnBps = (int) clamp(v, 0, 10000);                 break;
            case "slashBps":        slashBps = (int) clamp(v, 100, 10000);                 break;   // floor: slashing can't be disabled
            case "jailBlocks":      jailBlocks = (int) clamp(v, 1, 100_000_000L);          break;
            case "unbondingBlocks": unbondingBlocks = (int) clamp(v, 1, 100_000_000L);     break;
            case "estateInactivity": estateInactivity = clamp(v, 1, 100_000_000L);        break;
            case "minValidatorStake": minValidatorStake = (int) clamp(v, 1, 1_000_000_000L); break;
            case "bridgeThreshold": bridgeThreshold = (int) clamp(v, 1, 1000); break;
            case "identityBond":    identityBond = clamp(v, 0, 1_000_000_000L); break;
            case "committeeSize":   committeeSize = (int) clamp(v, 0, 100_000L); break;
        }
    }

    /** Apply a validated tx's balance/nonce deltas to a projection map (no validation here). */
    void applyProj(JSONObject tx, Map<String, long[]> m) throws Exception {
        String t = tx.optString("from");
        if ("GENESIS".equals(t) || "SLASH".equals(t) || "VOUCH".equals(t) || "CLAIM".equals(t) || "VALJOIN".equals(t) || "BRIDGE_IN".equals(t) || "ORACLE".equals(t)
                || "REGISTER".equals(t) || "ROTATE".equals(t) || "SETGUARDIANS".equals(t) || "RECOVER".equals(t)) return;   // no projection effect (BRIDGE_IN applied at commit)
        if ("BRIDGE_OUT".equals(t)) { long[] fa = proj(tx.getString("actor"), m); fa[0] -= tx.getLong("amount") + tx.optLong("fee", 0); fa[1] += 1; proj(BRIDGE_RESERVE, m)[0] += tx.getLong("amount"); return; }
        if ("BOND".equals(t)) { long[] fa = proj(tx.getString("actor"), m); fa[0] -= tx.getLong("amount"); fa[1] += 1; return; }
        if ("UNBOND".equals(t) || "UNJAIL".equals(t) || "PROPOSE".equals(t) || "VOTE".equals(t) || "SETBENEFICIARY".equals(t)) { proj(tx.getString("actor"), m)[1] += 1; return; }
        long[] fa = proj(tx.getString("from"), m);
        fa[0] -= tx.getLong("amount") + tx.optLong("fee", 0); fa[1] += 1;
        proj(tx.getString("to"), m)[0] += tx.getLong("amount");
    }

    /** Validate a tx against a projection map; on success apply its balance/nonce deltas. null=ok else reason. */
    String txCheck(JSONObject tx, Map<String, MLDSAPublicKeyParameters> pubById, Map<String, long[]> m) throws Exception {
        String t = tx.optString("from");
        if ("GENESIS".equals(t)) return null;
        if ("SLASH".equals(t)) return verifySlash(tx, pubById) ? null : "bad slash evidence";
        if ("VOUCH".equals(t)) return verifyVouch(tx, pubById) ? null : "bad vouch";
        if ("REGISTER".equals(t)) return verifyRegister(tx) ? null : "bad register";
        if ("ROTATE".equals(t)) return verifyRotate(tx) ? null : "bad rotate";
        if ("SETGUARDIANS".equals(t)) return verifySetGuardians(tx) ? null : "bad setguardians";
        if ("RECOVER".equals(t)) return verifyRecover(tx) ? null : "bad recover";
        if ("CLAIM".equals(t)) return verifyClaim(tx) ? null : "estate not claimable";
        if ("VALJOIN".equals(t)) return verifyValJoin(tx) ? null : "bad valjoin";
        if ("BRIDGE_IN".equals(t)) return verifyBridgeIn(tx) ? null : "bad bridge_in";
        if ("ORACLE".equals(t)) return verifyOracle(tx) ? null : "bad oracle";
        if ("BRIDGE_OUT".equals(t)) {   // user locks PHNT to the reserve for external release
            String actor = tx.getString("actor"); long nonce = tx.getLong("nonce");
            long amount = tx.getLong("amount"), fee = tx.optLong("fee", 0);
            if (!chainId.equals(tx.optString("cid", ""))) return "wrong chainId";
            MLDSAPublicKeyParameters pub = authPub(actor, tx, pubById);
            if (pub == null) return "unknown actor";
            if (!PhantomCrypto.verify(pub, PhantomCrypto.utf8(bridgeOutCanon(tx)), PhantomCrypto.unhex(tx.getString("sig")))) return "bad signature";
            if (amount <= 0 || fee < 0) return "non-positive amount or negative fee";
            long cost; try { cost = Math.addExact(amount, fee); } catch (ArithmeticException e) { return "amount overflow"; }
            long[] fa = proj(actor, m);
            if (nonce != fa[1]) return "bad nonce (expected " + fa[1] + ")";
            if (fa[0] < cost) return "insufficient balance";
            applyProj(tx, m);
            return null;
        }
        if (SPECIAL.contains(t)) {   // actor-signed, nonce-protected action (BOND/UNBOND/UNJAIL/PROPOSE/VOTE/SETBENEFICIARY)
            String actor = tx.getString("actor"); long nonce = tx.getLong("nonce");
            MLDSAPublicKeyParameters pub = authPub(actor, tx, pubById);
            if (pub == null) return "unknown actor";
            if (!chainId.equals(tx.optString("cid", ""))) return "wrong chainId";
            if (!PhantomCrypto.verify(pub, PhantomCrypto.utf8(actionCanon(tx)), PhantomCrypto.unhex(tx.getString("sig")))) return "bad signature";
            long[] fa = proj(actor, m);
            if (nonce != fa[1]) return "bad nonce (expected " + fa[1] + ")";
            if (("BOND".equals(t) || "UNBOND".equals(t)) && tx.getLong("amount") <= 0) return "non-positive stake amount";
            if ("BOND".equals(t) && fa[0] < tx.getLong("amount")) return "insufficient balance to bond";
            if ("UNBOND".equals(t) && stake.getOrDefault(actor, 0L) < tx.getLong("amount")) return "insufficient stake to unbond";
            applyProj(tx, m);
            return null;
        }
        // plain transfer
        String from = t, to = tx.getString("to");
        long amount = tx.getLong("amount"), fee = tx.optLong("fee", 0), nonce = tx.getLong("nonce");
        MLDSAPublicKeyParameters pub = authPub(from, tx, pubById);
        if (pub == null) return "unknown sender";
        if (!chainId.equals(tx.optString("cid", ""))) return "wrong chainId";
        if (!PhantomCrypto.verify(pub, PhantomCrypto.utf8(txCanon(chainId, from, to, amount, fee, nonce)), PhantomCrypto.unhex(tx.getString("sig")))) return "bad signature";
        if (amount <= 0 || fee < 0) return "non-positive amount or negative fee";
        long cost;
        try { cost = Math.addExact(amount, fee); } catch (ArithmeticException e) { return "amount overflow"; }   // no wraparound spend
        long[] fa = proj(from, m);
        if (nonce != fa[1]) return "bad nonce (expected " + fa[1] + ")";
        if (fa[0] < cost) return "insufficient balance";
        applyProj(tx, m);
        return null;
    }

    JSONObject buildBondTx(String actor, long amount, long nonce, boolean unbond, MLDSAPrivateKeyParameters key) throws Exception {
        JSONObject tx = new JSONObject().put("from", unbond ? "UNBOND" : "BOND").put("actor", actor).put("amount", amount).put("nonce", nonce).put("cid", chainId)
                .put("pub", PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded()));
        return tx.put("sig", PhantomCrypto.hex(PhantomCrypto.sign(key, PhantomCrypto.utf8(actionCanon(tx)))));
    }
    JSONObject buildUnjailTx(String actor, long nonce, MLDSAPrivateKeyParameters key) throws Exception {
        JSONObject tx = new JSONObject().put("from", "UNJAIL").put("actor", actor).put("nonce", nonce).put("cid", chainId)
                .put("pub", PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded()));
        return tx.put("sig", PhantomCrypto.hex(PhantomCrypto.sign(key, PhantomCrypto.utf8(actionCanon(tx)))));
    }
    JSONObject buildProposeTx(String actor, String propId, String param, long value, long nonce, MLDSAPrivateKeyParameters key) throws Exception {
        JSONObject tx = new JSONObject().put("from", "PROPOSE").put("actor", actor).put("propId", propId).put("param", param).put("value", value).put("nonce", nonce).put("cid", chainId)
                .put("pub", PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded()));
        return tx.put("sig", PhantomCrypto.hex(PhantomCrypto.sign(key, PhantomCrypto.utf8(actionCanon(tx)))));
    }
    JSONObject buildVoteTx(String actor, String propId, boolean choice, long nonce, MLDSAPrivateKeyParameters key) throws Exception {
        JSONObject tx = new JSONObject().put("from", "VOTE").put("actor", actor).put("propId", propId).put("choice", choice).put("nonce", nonce).put("cid", chainId)
                .put("pub", PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded()));
        return tx.put("sig", PhantomCrypto.hex(PhantomCrypto.sign(key, PhantomCrypto.utf8(actionCanon(tx)))));
    }

    /** Two-phase governance: at deadline, tally snapshot-weighted votes with a turnout quorum; if it
     *  passes, apply only after a timelock (gives the network time to react to a malicious proposal). */
    void finalizeProposals() throws Exception {
        int H = height();
        for (JSONObject p : proposals.values()) {
            if (p.getBoolean("executed")) continue;
            if (!p.getBoolean("tallied") && H >= p.getLong("deadline")) {
                JSONObject votes = p.getJSONObject("votes"), snap = p.getJSONObject("snapshot");
                long yes = 0, no = 0;
                for (String voter : keysOf(votes)) {
                    long w = snap.optLong(voter, 0);                       // snapshot weight (no last-minute stake grinding)
                    if (votes.getBoolean(voter)) yes += w; else no += w;
                }
                long total = p.getLong("totalWeight");
                boolean turnout = total > 0 && (yes + no) * 10000L >= total * (long) GOV_QUORUM_BPS;
                p.put("tallied", true).put("passed", turnout && yes > no);
            }
            if (p.getBoolean("tallied") && p.getBoolean("passed") && H >= p.getLong("applyAt")) {
                applyParam(p.getString("param"), p.getLong("value"));     // timelocked execution
                p.put("executed", true);
            }
        }
    }

    // ===== mining economics (simulation) =====
    // weight = 0.6*sqrt(stake)-share + 0.4*identity-share, over non-slashed validators.
    // PROVABLE for real: stake (bonded on-chain), QC signatures, block.proposer.
    // SIM-TRUSTED (real needs more): identity count -> Sybil-resistant personhood; the proposer
    // randomness here is seeded by prevHash (GRINDABLE) where real consensus needs a VRF.

    void genesisEcon(String chainId, java.util.LinkedHashMap<String, Long> alloc, java.util.List<String> vals,
                     Map<String, Long> stk, Map<String, Long> idn, java.util.Set<String> seedVerified,
                     Map<String, String> valPubsSeed, long ts) throws Exception {
        genesisEcon(chainId, alloc, vals, stk, idn, seedVerified, valPubsSeed, null, ts);
    }

    void genesisEcon(String chainId, java.util.LinkedHashMap<String, Long> alloc, java.util.List<String> vals,
                     Map<String, Long> stk, Map<String, Long> idn, java.util.Set<String> seedVerified,
                     Map<String, String> valPubsSeed, Map<String, String> beaconCommitsSeed, long ts) throws Exception {
        this.chainId = chainId;   // set before genesisMulti so the genesis block hash commits to it
        genesisMulti(alloc, ts);
        validators.clear(); validators.addAll(vals);
        valPubs.clear(); if (valPubsSeed != null) valPubs.putAll(valPubsSeed);
        regions.clear(); tiers.clear(); custodians.clear(); bridgeProcessed.clear();
        beacon = ZERO32; commits.clear(); oracleRates.clear();
        // bind each validator's FIRST reveal to a commitment published at keygen (closes the unconstrained-
        // first-reveal grind); mix all genesis commitments into the initial beacon so it isn't a known ZERO32.
        if (beaconCommitsSeed != null && !beaconCommitsSeed.isEmpty()) {
            commits.putAll(beaconCommitsSeed);
            java.util.List<String> bcl = new ArrayList<>(beaconCommitsSeed.values()); java.util.Collections.sort(bcl);
            StringBuilder mb = new StringBuilder("beacon0"); for (String c : bcl) mb.append('|').append(c);
            beacon = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(mb.toString())));
        }
        stake.clear(); stake.putAll(stk);
        identity.clear(); identity.putAll(idn);
        verified.clear(); if (seedVerified != null) verified.addAll(seedVerified);   // bootstrap founding humans
        vouches.clear();
        totalMinted = 0; burned = 0;
        jailed.clear(); unbonding.clear(); proposals.clear();
    }

    boolean excluded(String id) { return slashed.contains(id) || jailedActive(id); }   // permanent tombstone OR active jail
    java.util.List<Integer> liveIdx() {
        java.util.List<Integer> r = new ArrayList<>();
        for (int i = 0; i < validators.size(); i++) if (!excluded(validators.get(i))) r.add(i);
        return r;
    }

    static final double GEO_ALPHA = 0.2, GEO_BETA = 0.1, GEO_MAX = 2.5;   // Doc D coverage-premium params

    /** Base weight = 0.6·√stake-share + 0.4·identity-share, over non-excluded validators. */
    double baseWeight(int idx) {
        if (idx < 0 || idx >= validators.size() || excluded(validators.get(idx))) return 0;
        double sqSum = 0; long idSum = 0;
        for (int j : liveIdx()) {
            sqSum += Math.sqrt(stake.getOrDefault(validators.get(j), 0L));
            if (verified.contains(validators.get(j))) idSum += identity.getOrDefault(validators.get(j), 0L);   // identity weight only for personhood-verified humans
        }
        double stakeShare = sqSum > 0 ? Math.sqrt(stake.getOrDefault(validators.get(idx), 0L)) / sqSum : 0;
        long myId = verified.contains(validators.get(idx)) ? identity.getOrDefault(validators.get(idx), 0L) : 0;
        double idShare = idSum > 0 ? (double) myId / idSum : 0;
        return 0.6 * stakeShare + 0.4 * idShare;
    }

    /** Geo coverage premium (opt-in): sparse regions earn a higher multiplier so coverage is incentivized.
     *  density = identity weight of a region's live validators; multiplier = min(MAX, 1 + α/(density+β)). */
    double coverageMultiplier(int idx) {
        String region = regions.get(validators.get(idx));
        if (region == null || region.isEmpty()) return 1.0;   // standard cluster, no premium
        long density = 0;
        for (int j : liveIdx()) if (region.equals(regions.get(validators.get(j))))
            density += Math.max(1L, identity.getOrDefault(validators.get(j), 1L));
        return Math.min(GEO_MAX, 1.0 + GEO_ALPHA / (density + GEO_BETA));
    }

    /** Final consensus/reward weight = baseWeight × geo coverage multiplier, renormalized over live set. */
    double weight(int idx) {
        if (idx < 0 || idx >= validators.size() || excluded(validators.get(idx))) return 0;
        double mine = baseWeight(idx) * coverageMultiplier(idx), total = 0;
        for (int j : liveIdx()) total += baseWeight(j) * coverageMultiplier(j);
        return total > 0 ? mine / total : 0;
    }

    /** RANDAO-style randomness beacon: derived from the previous block's quorum signatures, so no
     *  single proposer can bias it (the sigs come from the whole quorum, committed on-chain).
     *  Deterministic across nodes. Library-only (SHA3), PQ-safe. Not a VRF — VRF is on the pipeline. */
    String randBeacon(int height) {
        int p = height - 1;
        if (p < 0 || p >= chain.size()) return ZERO32;
        JSONObject prev = chain.get(p);
        JSONArray qc = prev.optJSONArray("qc");
        StringBuilder sb = new StringBuilder("beacon|");
        if (qc != null && qc.length() > 0) {
            for (int k = 0; k < qc.length(); k++) { JSONObject e = qc.optJSONObject(k); if (e != null) sb.append(e.optString("sig")); }
        } else {
            sb.append(prev.optString("hash"));
        }
        return PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(sb.toString())));
    }

    /** Verify the proposer's reveal matches the commitment it made in its prior block (RANDAO binding). */
    boolean beaconRevealValid(JSONObject b) {
        int prop = b.optInt("proposer", -1);
        if (prop < 0 || prop >= validators.size()) return true;
        String prev = commits.get(validators.get(prop));
        if (prev == null) return true;   // only reachable for legacy genesis without seeded commit0 (first reveal then unconstrained)
        // commit is sha3 over the RAW 32 secret bytes (matching beaconCommit()), so hash the unhexed reveal
        return PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.unhex(b.optString("reveal", "")))).equals(prev);
    }
    /** Fold the proposer's revealed value into the beacon and record its next commitment. */
    void beaconApply(JSONObject b) {
        int prop = b.optInt("proposer", -1);
        if (prop < 0 || prop >= validators.size()) return;
        beacon = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(beacon + "|" + b.optString("reveal", ""))));
        if (b.has("commit")) commits.put(validators.get(prop), b.getString("commit"));
    }

    // ---- canonical beacon-secret derivation (single source of truth; node-side only knows its own key) ----
    // The seed is derived from the validator's ML-DSA private key so commit0 can be published at keygen and
    // BOUND at genesis/VALJOIN — closing the unconstrained-first-reveal grind.
    static byte[] beaconSeedFor(byte[] keyEncoded) { return PhantomCrypto.hkdf(keyEncoded, null, PhantomCrypto.utf8("pcbeaconseed"), 32); }
    static byte[] beaconSecretFor(byte[] keyEncoded, long c) { return PhantomCrypto.hkdf(beaconSeedFor(keyEncoded), null, PhantomCrypto.utf8("pcbeacon" + c), 32); }
    static String beaconCommit0For(byte[] keyEncoded) { return PhantomCrypto.hex(PhantomCrypto.sha3_256(beaconSecretFor(keyEncoded, 0))); }

    /** Weighted, deterministic proposer for (height,view), seeded by the commit-reveal beacon. */
    int proposerFor(String prevHash, int height, int view) throws Exception {
        java.util.List<Integer> live = liveIdx();
        if (live.isEmpty()) return height % Math.max(1, validators.size());
        byte[] seed = PhantomCrypto.sha3_256(PhantomCrypto.utf8(beacon + "|" + height + "|" + view));
        long s = 0; for (int i = 0; i < 8; i++) s = (s << 8) | (seed[i] & 0xffL);
        s &= Long.MAX_VALUE;
        double total = 0; for (int idx : live) total += weight(idx);
        if (total <= 0) return live.get((int) (s % live.size()));
        double r = ((double) (s % 1_000_000L) / 1_000_000L) * total, c = 0;
        for (int idx : live) { c += weight(idx); if (r < c) return idx; }
        return live.get(live.size() - 1);
    }

    /** Beacon-sortitioned signing committee for `height`: a weight-proportional sample (without replacement)
     *  of `committeeSize` validators, deterministic from the beacon. committeeSize<=0 or live<=committeeSize
     *  returns the FULL live set (deterministic BFT — the safe small-N fallback). Integer weights keep it
     *  cross-node deterministic. Fixed per height (not view) so two conflicting blocks share one committee. */
    java.util.List<Integer> committeeFor(int height) {
        java.util.List<Integer> live = liveIdx();
        int k = committeeSize;
        if (k <= 0 || live.size() <= k) return live;
        java.util.List<Integer> pool = new ArrayList<>(live);
        java.util.List<Long> w = new ArrayList<>();
        for (int idx : pool) w.add(Math.max(1L, Math.round(weight(idx) * 1_000_000_000L)));   // integer weights = deterministic
        java.util.List<Integer> sel = new ArrayList<>();
        for (int seat = 0; seat < k && !pool.isEmpty(); seat++) {
            long total = 0; for (long x : w) total += x;
            byte[] hsh = PhantomCrypto.sha3_256(PhantomCrypto.utf8(beacon + "|cmte|" + height + "|" + seat));
            long s = 0; for (int i = 0; i < 8; i++) s = (s << 8) | (hsh[i] & 0xffL);
            long r = Math.floorMod(s, total), cum = 0; int pick = pool.size() - 1;
            for (int j = 0; j < pool.size(); j++) { cum += w.get(j); if (r < cum) { pick = j; break; } }
            sel.add(pool.get(pick)); pool.remove(pick); w.remove(pick);
        }
        java.util.Collections.sort(sel);
        return sel;
    }
    /** BFT quorum within the signing committee for `height`. */
    int committeeQuorum(int height) {
        int c = committeeFor(height).size();
        return Math.max(1, c - (c - 1) / 3);
    }

    /** Decaying emission: blockReward halved once per halvingBlocks. Deterministic, capped by maxSupply. */
    long blockRewardAt(int height) {
        if (height <= 0) return 0;
        int halvings = halvingBlocks > 0 ? (height - 1) / halvingBlocks : 0;
        if (halvings > 62) return 0;
        return blockReward >> halvings;
    }

    /** At each epoch boundary, mint emission (decaying curve, supply-capped) and split by on-chain
     *  contribution (QC sigs + proposer bonus). */
    void maybeEpochReward() throws Exception {
        int h = chain.size() - 1;
        if (h < 1 || h % EPOCH_LEN != 0) return;
        Map<String, Long> units = new HashMap<>();
        long pool = 0;
        for (int hi = h - EPOCH_LEN + 1; hi <= h; hi++) {
            pool += blockRewardAt(hi);
            JSONObject blk = chain.get(hi);
            int prop = blk.optInt("proposer", -1);
            if (prop >= 0 && prop < validators.size()) units.merge(validators.get(prop), (long) PROPOSER_BONUS, Long::sum);
            JSONArray qc = blk.optJSONArray("qc");
            if (qc != null) for (int k = 0; k < qc.length(); k++) {
                int si = qc.getJSONObject(k).getInt("i");
                if (si >= 0 && si < validators.size()) units.merge(validators.get(si), 1L, Long::sum);
            }
        }
        if (totalMinted + pool > maxSupply) pool = Math.max(0, maxSupply - totalMinted);   // emission cap
        long totalU = 0; for (long u : units.values()) totalU += u;
        if (totalU <= 0 || pool <= 0) return;
        long distributed = 0;
        for (Map.Entry<String, Long> e : units.entrySet()) {
            Account a = accounts.get(e.getKey());
            if (a == null) { a = new Account(); accounts.put(e.getKey(), a); }
            long share = pool * e.getValue() / totalU;
            a.balance += share; distributed += share;
        }
        totalMinted += distributed;
    }
}
