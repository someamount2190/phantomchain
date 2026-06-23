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

    public static class Account { long balance; long nonce; }

    String ownerId;
    public String chainId = "";   // domain-separation tag; every signed payload (tx, action, block, vote) commits to it
    public final Map<String, Account> accounts = new HashMap<>();
    public final List<JSONObject> chain = new ArrayList<>();
    public final List<JSONObject> mempool = new ArrayList<>();
    public final java.util.Set<String> slashed = new java.util.HashSet<>();   // validator IDs proven to have double-signed
    // ---- mining economics (simulation) ----
    public final Map<String, Long> stake = new HashMap<>();              // id -> bonded stake (PROVABLE: on-chain)
    public final Map<String, Long> identity = new HashMap<>();           // id -> enrolled-human count (REAL: needs personhood proof)
    public final java.util.List<String> validators = new ArrayList<>();  // index-ordered ids; APPEND-ONLY so indices/QC stay valid
    // ---- commit-reveal randomness beacon (RANDAO): proposer reveals a value it committed in its prior block ----
    public String beacon = ZERO32;                                       // accumulated unbiasable-ish randomness
    public final Map<String, String> commits = new HashMap<>();          // validator id -> its outstanding reveal commitment
    public final Map<String, String> valPubs = new HashMap<>();          // validator id -> consensus pubkey hex (genesis + joined)
    public final Map<String, String> regions = new HashMap<>();          // validator id -> region_id (opt-in geo coverage premium)
    public final Map<String, String> tiers = new HashMap<>();            // validator id -> "light" (absent/"heavy" = full archived-body storage)
    // ---- cluster mining (spec §9): a cluster of M-of-N enrolled member devices acts as ONE validator;
    // its block "signature" is a bundle of >=threshold member ML-DSA sigs, and epoch rewards are split
    // DIRECTLY to each member identity (no operator intermediary, §9.6). Threshold-Dilithium aggregation
    // is the research primitive that would compress the bundle to one sig; this is the honest M-of-N interim.
    final Map<String, JSONObject> clusters = new HashMap<>();      // clusterId -> {members:[id...], memberPubs:{id->pubHex}, threshold:M}
    final java.util.Set<String> collapsed = new java.util.HashSet<>();   // clusters disbanded (§9.7): excluded from consensus, members freed to reform
    // ---- cross-chain bridge (on-chain side; the M-of-N custodian HSM service is the explicit OFF-chain trust boundary) ----
    public final Map<String, String> custodians = new HashMap<>();        // custodian id -> pubkey hex
    public int bridgeThreshold = 1;                                       // M-of-N custodian attestations required (governable)
    final java.util.Set<String> bridgeProcessed = new java.util.HashSet<>();   // external tx ids already minted (replay guard)
    public static final String BRIDGE_RESERVE = "BRIDGE_RESERVE";        // reserve account funds inbound releases
    public final java.util.List<JSONObject> bridgeOuts = new ArrayList<>();           // recent outbound locks (custodian observability)
    public final Map<String, Map<String, Long>> oracleRates = new HashMap<>();        // pair -> {custodian id -> rate} (median = price)
    int minValidatorStake = 500_000;                              // min bonded stake to join the validator set (governable)
    long identityBond = 0;                                        // stake an identity must lock to be admitted to `verified` (governable; 0 = vouch-only). Sybil-cost: N identities cost N×bond.
    public int committeeSize = 0;                                        // 0 = full validator set signs (deterministic BFT); >0 = beacon-sortitioned signing committee of this size (probabilistic safety, only meaningful at large N)
    // State-root serialization version. Travels WITH the chain (set at genesis, persisted in the snapshot)
    // instead of a JVM launch flag, so a node can never silently fork by being started without the right
    // flag. "v1"/"v2" describe historical (shorter) tails; "full" (default) is the current complete
    // serialization; "m1" additionally binds the authenticated account Merkle root into the state root
    // (opt-in: makes light-client account proofs trustless without changing existing chains).
    public String srVersion = "full";
    /** Hardened chains make the app-hash (prevStateRoot/prevShardsRoot) MANDATORY in every block, closing
     *  the bypass-by-omission where optString(...,null) silently skips the check when the field is absent.
     *  Gated on srVersion so legacy "full"/"v1"/"v2" chains (incl. the live testnet, which may hold pre-
     *  state-root / pre-sharding historical blocks) still sync; "m1" already binds the Merkle state root, so
     *  for it the roots must be present. (Found by node/FuzzTest.java.) */
    boolean requireAppHash() { return srv().requiresAppHash(); }
    /** Typed view of {@link #srVersion}, derived from the verbatim-serialized string. All consensus
     *  version gating goes through this (never raw String.equals on srVersion) so the state-root tail
     *  can't silently diverge on a typo'd or missed compare. See {@link SrVersion}. */
    SrVersion srv() { return SrVersion.parse(srVersion); }
    public long totalMinted = 0;
    public long burned = 0;                          // total tokens burned (fee burn + slashing) — deflationary sink
    public static final int EPOCH_LEN = 3;
    static final int PROPOSER_BONUS = 2;      // extra contribution units for proposing
    public static final int  RETAIN_RECENT = 8;      // recent block bodies kept fully; older unassigned bodies pruned
    static final int  MAX_MEMPOOL = 10000;    // DoS bound: reject new txs past this
    static final int  MAX_BLOCK_TXS = 1000;   // DoS bound: cap txs packed per block
    static final long MIN_FEE = 1;            // anti-spam: transfers must pay at least this
    // ---- production economics: governable parameters (changeable via on-chain governance) ----
    public long blockReward = 100;                   // initial per-block emission; halves every halvingBlocks
    public int  halvingBlocks = 12;                  // emission halving period (blocks)
    public long maxSupply = 10_000_000L;             // hard emission cap
    public int  feeBurnBps = 5000;                   // basis points of tx fees burned (remainder -> block proposer)
    public int  slashBps = 10000;                    // basis points of stake burned on equivocation (10000 = 100%)
    public int  jailBlocks = 10;                     // jail duration (blocks) after a slash, before unjail is allowed
    public int  unbondingBlocks = 10;               // lock period (blocks) before unbonded stake becomes liquid
    // ---- staking / slashing / governance state ----
    final Map<String, Long> jailed = new HashMap<>();          // id -> height at which unjail becomes allowed
    final List<JSONObject> unbonding = new ArrayList<>();      // [{actor, amount, mature}] pending unbonds
    public final Map<String, JSONObject> proposals = new HashMap<>(); // propId -> {proposer,param,value,deadline,executed,votes:{voter:choice}}
    // ---- identity != key: durable on-chain identity with rotatable device keys + guardian recovery ----
    public final Map<String, JSONObject> identities = new HashMap<>(); // identity_id -> {root, devices:[hex], guardians:[id], threshold, rotNonce}
    // ---- estate / inheritance: only an OUTGOING (fingerprint) action resets the clock ----
    final Map<String, Long> lastActive = new HashMap<>();      // id -> height of last outgoing action
    final Map<String, String> beneficiary = new HashMap<>();   // id -> estate beneficiary id
    long estateInactivity = 10;                                // blocks of inactivity before estate is claimable (governable; small for testnet)
    // ---- personhood (social web-of-trust; PLUGGABLE: admission to 'verified' is by VOUCH tx today,
    //      swap for a biometric-uniqueness proof tx in future without touching consensus) ----
    public final java.util.Set<String> verified = new java.util.HashSet<>();      // personhood-verified human IDs
    public final Map<String, java.util.Set<String>> vouches = new HashMap<>();    // candidate -> set of vouchers
    public static final int VOUCH_THRESHOLD = 2;                                  // vouches from verified humans to admit

    boolean initialized() { return ownerId != null && !chain.isEmpty(); }
    public int height() { return chain.isEmpty() ? -1 : chain.size() - 1; }
    public String lastHash() throws Exception { return chain.isEmpty() ? ZERO32 : chain.get(chain.size() - 1).getString("hash"); }
    // ---- ledger-history sharding: a block keeps a full body or is pruned to header-only ----
    public boolean hasBody(int h) { return h >= 0 && h < chain.size() && chain.get(h).has("txs"); }
    public void pruneBlock(int h) throws Exception { chain.get(h).remove("txs"); chain.get(h).put("pruned", true); }   // keep header (hash/qc/proposer/roots)
    public void pruneBlockRS(int h, int idx, byte[] shard) throws Exception {   // drop the full body, retain only THIS node's RS shard
        chain.get(h).remove("txs");
        chain.get(h).put("pruned", true).put("rsIdx", idx).put("rsShard", PhantomCrypto.hex(shard));
    }
    /** Recompute a block's committed hash from its body — used to verify a reconstructed body. */
    public String blockHash(JSONObject b) throws Exception {
        String preimage = chainId + "|" + b.getInt("height") + "|" + b.getString("prevHash") + "|"
                + b.getJSONArray("txs").toString() + "|" + b.getLong("ts");
        return PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(preimage)));
    }
    public long balanceOf(String id) { Account a = accounts.get(id); return a == null ? 0 : a.balance; }
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
            "CLUSTERFORM", "CLUSTERDISBAND", "BRIDGE_OUT", "BRIDGE_IN", "ORACLE"));
    static boolean isTransfer(JSONObject tx) { return !SPECIAL.contains(tx.optString("from")); }

    /** Stable tx id for dedup/mempool removal: the signature if present, else a hash of the tx body
     *  (RECOVER carries only per-guardian approval sigs, no single top-level sig). */
    public static String txId(JSONObject tx) {
        String sig = tx.optString("sig", "");
        return sig.isEmpty() ? PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(tx.toString()))) : sig;
    }

    /** Canonical signing string for a transfer (fee is part of the signed payload). */
    public static String txCanon(String cid, String from, String to, long amount, long fee, long nonce) {
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

    public String toJson() throws Exception { return StateRootCodec.toJson(this); }

    public void fromJson(String s) throws Exception { StateRootCodec.fromJson(this, s); }

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

    public JSONObject buildTxProjected(String from, String to, long amount, long fee, MLDSAPrivateKeyParameters key) throws Exception {
        long nonce = proj(from, mempoolProjection())[1];
        byte[] sig = PhantomCrypto.sign(key, PhantomCrypto.utf8(txCanon(chainId, from, to, amount, fee, nonce)));
        return new JSONObject().put("from", from).put("to", to).put("amount", amount).put("cid", chainId)
                .put("fee", fee).put("nonce", nonce).put("pub", PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded()))
                .put("sig", PhantomCrypto.hex(sig));
    }

    public String addToMempool(JSONObject tx, Map<String, MLDSAPublicKeyParameters> pubById) throws Exception {
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

    public String commitBlock(JSONObject b, Map<String, MLDSAPublicKeyParameters> pubById) throws Exception {
        if (b.getInt("height") != chain.size()) return "rejected: bad height (have " + chain.size() + ")";
        if (!b.getString("prevHash").equals(lastHash())) return "rejected: bad prevHash";
        String preimage = chainId + "|" + b.getInt("height") + "|" + b.getString("prevHash") + "|"
                + b.getJSONArray("txs").toString() + "|" + b.getLong("ts");
        String hash = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(preimage)));
        if (!hash.equals(b.getString("hash"))) return "rejected: bad hash";
        if (requireAppHash()) {   // hardened-chain bounds (deterministic; found by MempoolDosTest/TimestampTest)
            if (b.getJSONArray("txs").length() > MAX_BLOCK_TXS) return "rejected: block exceeds MAX_BLOCK_TXS";   // engine-enforced DoS cap (not just transport)
            if (b.getLong("ts") < chain.get(chain.size() - 1).optLong("ts", 0)) return "rejected: non-monotonic ts";   // ts >= prev (no wall-clock -> deterministic)
        }
        String psr = b.optString("prevStateRoot", null);
        if (requireAppHash() && psr == null) return "rejected: prevStateRoot required (srVersion=" + srVersion + ")";   // no bypass-by-omission
        if (psr != null && !stateRoot().equals(psr)) return "rejected: state root mismatch";   // app-hash divergence guard
        String pshr = b.optString("prevShardsRoot", null);
        if (requireAppHash() && pshr == null) return "rejected: prevShardsRoot required (srVersion=" + srVersion + ")";
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
            String active = EstateLogic.activeParty(tx);
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
                case "CLUSTERFORM": applyClusterForm(tx); break;   // a bonded cluster of M-of-N members joins the validator set as ONE validator
                case "CLUSTERDISBAND":   // the cluster's own members (>=threshold) collapse it (§9.7): excluded from consensus, members freed
                    if (verifyClusterDisband(tx)) collapsed.add(tx.getString("clusterId"));
                    break;
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
        GovernanceLogic.finalizeProposals(this);
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
    public JSONObject buildProposal(int proposerIndex, long ts) throws Exception {
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
    public boolean proposalLinks(JSONObject b) throws Exception {
        if (b.getInt("height") != chain.size()) return false;
        if (!b.getString("prevHash").equals(lastHash())) return false;
        String preimage = chainId + "|" + b.getInt("height") + "|" + b.getString("prevHash") + "|"
                + b.getJSONArray("txs").toString() + "|" + b.getLong("ts");
        String hash = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(preimage)));
        if (!hash.equals(b.getString("hash"))) return false;
        if (requireAppHash()) {   // hardened-chain bounds (mirror commitBlock so voters reject these too)
            if (b.getJSONArray("txs").length() > MAX_BLOCK_TXS) return false;
            if (b.getLong("ts") < chain.get(chain.size() - 1).optLong("ts", 0)) return false;
        }
        String psr = b.optString("prevStateRoot", null);
        if (requireAppHash() && psr == null) return false;           // hardened chains: app-hash is mandatory (no omission bypass)
        if (psr != null && !stateRoot().equals(psr)) return false;   // built on the same committed state
        String pshr = b.optString("prevShardsRoot", null);
        if (requireAppHash() && pshr == null) return false;
        if (pshr != null && !shardsRoot().equals(pshr)) return false; // and the same shard commitment
        return beaconRevealValid(b);                                  // and a valid RANDAO reveal
    }

    /** Read-only: are all txs in this block valid against committed state? (used when voting) */
    public boolean txsValid(JSONObject b, Map<String, MLDSAPublicKeyParameters> pubById) throws Exception {
        JSONArray txs = b.getJSONArray("txs");
        Map<String, long[]> m = new HashMap<>();
        for (int i = 0; i < txs.length(); i++)
            if (txCheck(txs.getJSONObject(i), pubById, m) != null) return false;
        return true;
    }

    /** Equivocation evidence: two valid signatures by the same validator over two different hashes. */
    public static boolean verifySlash(JSONObject tx, Map<String, MLDSAPublicKeyParameters> pubById) throws Exception {
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

    public JSONObject buildVouchTx(String voucher, String candidate, MLDSAPrivateKeyParameters key) throws Exception {
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
    public long projectedNonce(String id) throws Exception { return proj(id, mempoolProjection())[1]; }

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
    public static String idOf(String rootPubHex) { return PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.unhex(rootPubHex))); }
    static MLDSAPublicKeyParameters pk(String hex) { return new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, PhantomCrypto.unhex(hex)); }

    /** Authorize a signer: a registered identity must sign with one of its CURRENT device keys; an
     *  unregistered account stays self-sovereign (validator key or sha3(pub)==id). */
    MLDSAPublicKeyParameters authPub(String id, JSONObject tx, Map<String, MLDSAPublicKeyParameters> pubById) throws Exception {
        JSONObject idn = identities.get(id);
        if (idn == null) return pubFor(id, tx, pubById);
        String ph = tx.optString("pub", "");
        JSONArray devs = idn.getJSONArray("devices");
        for (int i = 0; i < devs.length(); i++) if (devs.getString(i).equals(ph)) return pk(ph);
        return null;   // pub is not (or no longer) an authorized device of this identity
    }

    public JSONObject buildRegisterTx(MLDSAPrivateKeyParameters rootKey, MLDSAPrivateKeyParameters deviceKey) throws Exception {
        String root = PhantomCrypto.hex(rootKey.getPublicKeyParameters().getEncoded());
        String device = PhantomCrypto.hex(deviceKey.getPublicKeyParameters().getEncoded());
        byte[] sig = PhantomCrypto.sign(rootKey, PhantomCrypto.utf8("register|" + chainId + "|" + root + "|" + device));
        return new JSONObject().put("from", "REGISTER").put("root", root).put("device", device).put("cid", chainId).put("sig", PhantomCrypto.hex(sig));
    }
    public JSONObject buildRotateTx(String id, MLDSAPrivateKeyParameters rootKey, String newDevice, long rotNonce) throws Exception {
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
    public JSONObject buildRecoverTx(String id, String newDevice, long rotNonce, JSONArray approvals) throws Exception {
        return new JSONObject().put("from", "RECOVER").put("id", id).put("newDevice", newDevice).put("rotNonce", rotNonce).put("cid", chainId).put("approvals", approvals);
    }

    // ===== estate / inheritance =====
    JSONObject buildSetBeneficiaryTx(String actor, String beneficiaryId, long nonce, MLDSAPrivateKeyParameters key) throws Exception {
        JSONObject tx = new JSONObject().put("from", "SETBENEFICIARY").put("actor", actor).put("beneficiary", beneficiaryId).put("nonce", nonce).put("cid", chainId)
                .put("pub", PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded()));
        return tx.put("sig", PhantomCrypto.hex(PhantomCrypto.sign(key, PhantomCrypto.utf8(actionCanon(tx)))));
    }
    JSONObject buildClaimTx(String account, long salt) throws Exception { return new JSONObject().put("from", "CLAIM").put("account", account).put("salt", salt).put("cid", chainId); }

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
    public JSONObject buildValJoinTx(MLDSAPrivateKeyParameters key) throws Exception {
        String pub = PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded());
        String commit0 = beaconCommit0For(key.getEncoded());
        byte[] sig = PhantomCrypto.sign(key, PhantomCrypto.utf8("valjoin|" + chainId + "|" + pub + "|" + commit0));
        return new JSONObject().put("from", "VALJOIN").put("pubkey", pub).put("cid", chainId).put("beaconCommit0", commit0).put("sig", PhantomCrypto.hex(sig));
    }

    // ===== cluster mining (spec §9): M-of-N member devices act as one validator =====
    public boolean isCluster(String id) { return clusters.containsKey(id); }

    static String clusterFormCanon(String cid, String clusterId, JSONArray members, int threshold) { return ClusterLogic.clusterFormCanon(cid, clusterId, members, threshold); }
    boolean verifyClusterForm(JSONObject tx) throws Exception { return ClusterLogic.verifyClusterForm(this, tx); }

    public JSONObject buildClusterFormTx(String clusterId, java.util.List<String> members, Map<String, String> memberPubs,
                                  int threshold, MLDSAPrivateKeyParameters initKey, String beaconCommit0) throws Exception {
        JSONArray ms = new JSONArray(); for (String m : members) ms.put(m);
        JSONObject mp = new JSONObject(); for (Map.Entry<String, String> e : memberPubs.entrySet()) mp.put(e.getKey(), e.getValue());
        String initPub = PhantomCrypto.hex(initKey.getPublicKeyParameters().getEncoded());
        byte[] sig = PhantomCrypto.sign(initKey, PhantomCrypto.utf8(clusterFormCanon(chainId, clusterId, ms, threshold) + "|" + beaconCommit0));
        return new JSONObject().put("from", "CLUSTERFORM").put("clusterId", clusterId).put("members", ms)
                .put("memberPubs", mp).put("threshold", threshold).put("cid", chainId)
                .put("initPub", initPub).put("beaconCommit0", beaconCommit0).put("sig", PhantomCrypto.hex(sig));
    }

    /** Apply a CLUSTERFORM to state (idempotent; the cluster joins the validator set as one validator). */
    public boolean applyClusterForm(JSONObject tx) throws Exception { return ClusterLogic.applyClusterForm(this, tx); }

    static String clusterDisbandCanon(String cid, String clusterId) { return ClusterLogic.clusterDisbandCanon(cid, clusterId); }
    boolean verifyClusterDisband(JSONObject tx) throws Exception { return ClusterLogic.verifyClusterDisband(this, tx); }

    JSONObject buildClusterDisbandTx(String clusterId, java.util.List<MLDSAPrivateKeyParameters> memberKeys) throws Exception {
        String canon = clusterDisbandCanon(chainId, clusterId);
        JSONArray approvals = new JSONArray();
        for (MLDSAPrivateKeyParameters mk : memberKeys)
            approvals.put(new JSONObject().put("m", idOf(PhantomCrypto.hex(mk.getPublicKeyParameters().getEncoded())))
                    .put("sig", PhantomCrypto.hex(PhantomCrypto.sign(mk, PhantomCrypto.utf8(canon)))));
        return new JSONObject().put("from", "CLUSTERDISBAND").put("clusterId", clusterId).put("cid", chainId).put("approvals", approvals);
    }

    /** A cluster's consensus signature on a block is a bundle of >= threshold distinct member sigs (M-of-N). */
    public boolean verifyClusterVote(String clusterId, String hash, JSONArray bundle) throws Exception { return ClusterLogic.verifyClusterVote(this, clusterId, hash, bundle); }

    /** Credit an epoch-reward share to a validator. For a cluster the share is split DIRECTLY and equally
     *  among its member identities (spec §9.6 — no operator intermediary); remainder to the first members. */
    void creditEarner(String valId, long share) throws Exception { EconomicsLogic.creditEarner(this, valId, share); }

    // ===== cross-chain bridge (on-chain side) =====
    public static String extAddr(String chain, String pubHex) {
        byte[] dom = PhantomCrypto.utf8("ext_addr_" + chain + "|"), pk = PhantomCrypto.unhex(pubHex);
        byte[] in = new byte[dom.length + pk.length];
        System.arraycopy(dom, 0, in, 0, dom.length); System.arraycopy(pk, 0, in, dom.length, pk.length);
        return PhantomCrypto.hex(PhantomCrypto.shake256(in, 20));   // deterministic 20-byte external address
    }
    static String bridgeOutCanon(JSONObject tx) throws Exception { return BridgeLogic.bridgeOutCanon(tx); }
    /** Inbound: >=M custodians attest an external deposit -> release PHNT from the reserve to the recipient. */
    boolean verifyBridgeIn(JSONObject tx) throws Exception { return BridgeLogic.verifyBridgeIn(this, tx); }
    public JSONObject buildBridgeOutTx(String actor, String chain, String ext, long amount, long fee, long nonce, MLDSAPrivateKeyParameters key) throws Exception {
        JSONObject tx = new JSONObject().put("from", "BRIDGE_OUT").put("actor", actor).put("chain", chain).put("extAddr", ext)
                .put("amount", amount).put("fee", fee).put("nonce", nonce).put("cid", chainId)
                .put("pub", PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded()));
        return tx.put("sig", PhantomCrypto.hex(PhantomCrypto.sign(key, PhantomCrypto.utf8(bridgeOutCanon(tx)))));
    }
    public JSONObject bridgeInApproval(String custodianId, MLDSAPrivateKeyParameters custKey, String recipient, long amount, String extTxid) throws Exception {
        String pub = PhantomCrypto.hex(custKey.getPublicKeyParameters().getEncoded());
        byte[] sig = PhantomCrypto.sign(custKey, PhantomCrypto.utf8("bridgein|" + chainId + "|" + recipient + "|" + amount + "|" + extTxid));
        return new JSONObject().put("custodian", custodianId).put("pub", pub).put("sig", PhantomCrypto.hex(sig));
    }
    public JSONObject buildBridgeInTx(String recipient, long amount, String extTxid, JSONArray approvals) throws Exception {
        return new JSONObject().put("from", "BRIDGE_IN").put("recipient", recipient).put("amount", amount)
                .put("extTxid", extTxid).put("cid", chainId).put("approvals", approvals);
    }
    boolean verifyOracle(JSONObject tx) throws Exception { return BridgeLogic.verifyOracle(this, tx); }
    public JSONObject buildOracleTx(String custodianId, MLDSAPrivateKeyParameters custKey, String pair, long rate) throws Exception {
        String pub = PhantomCrypto.hex(custKey.getPublicKeyParameters().getEncoded());
        byte[] sig = PhantomCrypto.sign(custKey, PhantomCrypto.utf8("oracle|" + chainId + "|" + pair + "|" + rate));
        return new JSONObject().put("from", "ORACLE").put("custodian", custodianId).put("pub", pub).put("pair", pair).put("rate", rate).put("cid", chainId).put("sig", PhantomCrypto.hex(sig));
    }
    /** Current price = median of custodian-attested rates for a pair (manipulation-resistant). */
    public long oracleMedian(String pair) { return BridgeLogic.oracleMedian(this, pair); }
    public long circulatingSupply() { return EconomicsLogic.circulatingSupply(this); }

    /** Deterministic hash of all consensus-relevant state (canonical: sorted maps). Committed in each
     *  block header as the post-state of the PREVIOUS block (Tendermint-style app hash), so any
     *  divergence in balances/stake/personhood/jail/supply/params is detected at the next block. */
    // ===== consensus serialization: state root + authenticated account Merkle commitment =====
    // Implementation lives in StateRootCodec (the single auditable byte-layout surface). These thin
    // delegators preserve the Ledger API so every call site (NetNode, tests) is unchanged. Byte layout
    // is frozen by node/GoldenStateRootTest.
    public String stateRoot() throws Exception { return StateRootCodec.stateRoot(this); }
    static byte[] accountLeaf(String id, long balance, long nonce) { return StateRootCodec.accountLeaf(id, balance, nonce); }
    static byte[] boundMerkleRoot(int count, byte[] inner) { return StateRootCodec.boundMerkleRoot(count, inner); }
    static byte[] merkleNode(byte[] l, byte[] r) { return StateRootCodec.merkleNode(l, r); }
    static byte[] merkleRoot(java.util.List<byte[]> leaves) { return StateRootCodec.merkleRoot(leaves); }
    static java.util.List<byte[]> merkleProof(java.util.List<byte[]> leaves, int idx) { return StateRootCodec.merkleProof(leaves, idx); }
    static boolean merkleVerify(byte[] leaf, int idx, java.util.List<byte[]> sibs, byte[] root) { return StateRootCodec.merkleVerify(leaf, idx, sibs, root); }
    java.util.List<String> sortedAccountIds() { return StateRootCodec.sortedAccountIds(this); }
    java.util.List<byte[]> accountLeaves() { return StateRootCodec.accountLeaves(this); }
    public String accountsMerkleRoot() { return StateRootCodec.accountsMerkleRoot(this); }
    public JSONObject accountProof(String id) { return StateRootCodec.accountProof(this, id); }
    public static boolean verifyAccountProof(JSONObject p) { return StateRootCodec.verifyAccountProof(p); }

    // ===== state sharding: per-id state partitioned into SHARDS, each independently rooted =====
    public static final int SHARDS = 16;
    static int shardOf(String id) { return StateRootCodec.shardOf(id); }
    public String shardData(int s) throws Exception { return StateRootCodec.shardData(this, s); }
    public String shardRoot(int s) throws Exception { return StateRootCodec.shardRoot(this, s); }
    public String shardsRoot() throws Exception { return StateRootCodec.shardsRoot(this); }
    /** Light-client proof: a shard slice + the sibling roots verify against a committed shardsRoot,
     *  WITHOUT holding the rest of the state. */
    static boolean verifyShardProof(String committedShardsRoot, int s, String shardDataStr, JSONArray roots) throws Exception {
        if (roots == null || roots.length() != SHARDS || s < 0 || s >= SHARDS) return false;
        if (!roots.getString(s).equals(PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(shardDataStr))))) return false;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < SHARDS; i++) sb.append(roots.getString(i));
        return committedShardsRoot.equals(PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(sb.toString()))));
    }

    static long clamp(long v, long lo, long hi) { return Math.max(lo, Math.min(hi, v)); }
    public void applyParam(String param, long v) { GovernanceLogic.applyParam(this, param, v); }   // impl in GovernanceLogic

    /** Apply a validated tx's balance/nonce deltas to a projection map (no validation here). */
    void applyProj(JSONObject tx, Map<String, long[]> m) throws Exception {
        String t = tx.optString("from");
        if ("GENESIS".equals(t) || "SLASH".equals(t) || "VOUCH".equals(t) || "CLAIM".equals(t) || "VALJOIN".equals(t) || "CLUSTERFORM".equals(t) || "CLUSTERDISBAND".equals(t) || "BRIDGE_IN".equals(t) || "ORACLE".equals(t)
                || "REGISTER".equals(t) || "ROTATE".equals(t) || "SETGUARDIANS".equals(t) || "RECOVER".equals(t)) return;   // no projection effect (BRIDGE_IN applied at commit)
        if ("BRIDGE_OUT".equals(t)) { long[] fa = proj(tx.getString("actor"), m); fa[0] -= tx.getLong("amount") + tx.optLong("fee", 0); fa[1] += 1; proj(BRIDGE_RESERVE, m)[0] += tx.getLong("amount"); return; }
        if ("BOND".equals(t)) { long[] fa = proj(tx.getString("actor"), m); fa[0] -= tx.getLong("amount"); fa[1] += 1; return; }
        if ("UNBOND".equals(t) || "UNJAIL".equals(t) || "PROPOSE".equals(t) || "VOTE".equals(t) || "SETBENEFICIARY".equals(t)) { proj(tx.getString("actor"), m)[1] += 1; return; }
        long[] fa = proj(tx.getString("from"), m);
        fa[0] -= tx.getLong("amount") + tx.optLong("fee", 0); fa[1] += 1;
        proj(tx.getString("to"), m)[0] += tx.getLong("amount");
    }

    /** Reject the '|' delimiter in any field that feeds a signed canonical string. Closes the (currently
     *  unexploitable) delimiter-injection class centrally without changing the canonical format, so existing
     *  signatures still verify and only malformed/malicious txs (no honest field carries '|') are rejected. */
    static final String[] CANON_FIELDS = {"cid","from","to","actor","id","recipient","beneficiary","propId",
            "param","pair","newDevice","extTxid","extAddr","custodian","voucher","candidate","chain","clusterId"};
    static boolean canonClean(JSONObject tx) {
        for (String key : CANON_FIELDS) { String v = tx.optString(key, null); if (v != null && v.indexOf('|') >= 0) return false; }
        return true;
    }

    /** Validate a tx against a projection map; on success apply its balance/nonce deltas. null=ok else reason. */
    String txCheck(JSONObject tx, Map<String, MLDSAPublicKeyParameters> pubById, Map<String, long[]> m) throws Exception {
        String t = tx.optString("from");
        if ("GENESIS".equals(t)) return null;
        if (!canonClean(tx)) return "delimiter in signed field";   // anti-injection (audit NOTE-1)
        if ("SLASH".equals(t)) return verifySlash(tx, pubById) ? null : "bad slash evidence";
        if ("VOUCH".equals(t)) return verifyVouch(tx, pubById) ? null : "bad vouch";
        if ("REGISTER".equals(t)) return RecoveryLogic.verifyRegister(this, tx) ? null : "bad register";
        if ("ROTATE".equals(t)) return RecoveryLogic.verifyRotate(this, tx) ? null : "bad rotate";
        if ("SETGUARDIANS".equals(t)) return RecoveryLogic.verifySetGuardians(this, tx) ? null : "bad setguardians";
        if ("RECOVER".equals(t)) return RecoveryLogic.verifyRecover(this, tx) ? null : "bad recover";
        if ("CLAIM".equals(t)) return EstateLogic.verifyClaim(this, tx) ? null : "estate not claimable";
        if ("VALJOIN".equals(t)) return verifyValJoin(tx) ? null : "bad valjoin";
        if ("CLUSTERFORM".equals(t)) return verifyClusterForm(tx) ? null : "bad clusterform";
        if ("CLUSTERDISBAND".equals(t)) return verifyClusterDisband(tx) ? null : "bad clusterdisband";
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

    public JSONObject buildBondTx(String actor, long amount, long nonce, boolean unbond, MLDSAPrivateKeyParameters key) throws Exception {
        JSONObject tx = new JSONObject().put("from", unbond ? "UNBOND" : "BOND").put("actor", actor).put("amount", amount).put("nonce", nonce).put("cid", chainId)
                .put("pub", PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded()));
        return tx.put("sig", PhantomCrypto.hex(PhantomCrypto.sign(key, PhantomCrypto.utf8(actionCanon(tx)))));
    }
    public JSONObject buildUnjailTx(String actor, long nonce, MLDSAPrivateKeyParameters key) throws Exception {
        JSONObject tx = new JSONObject().put("from", "UNJAIL").put("actor", actor).put("nonce", nonce).put("cid", chainId)
                .put("pub", PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded()));
        return tx.put("sig", PhantomCrypto.hex(PhantomCrypto.sign(key, PhantomCrypto.utf8(actionCanon(tx)))));
    }
    public JSONObject buildProposeTx(String actor, String propId, String param, long value, long nonce, MLDSAPrivateKeyParameters key) throws Exception {
        JSONObject tx = new JSONObject().put("from", "PROPOSE").put("actor", actor).put("propId", propId).put("param", param).put("value", value).put("nonce", nonce).put("cid", chainId)
                .put("pub", PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded()));
        return tx.put("sig", PhantomCrypto.hex(PhantomCrypto.sign(key, PhantomCrypto.utf8(actionCanon(tx)))));
    }
    public JSONObject buildVoteTx(String actor, String propId, boolean choice, long nonce, MLDSAPrivateKeyParameters key) throws Exception {
        JSONObject tx = new JSONObject().put("from", "VOTE").put("actor", actor).put("propId", propId).put("choice", choice).put("nonce", nonce).put("cid", chainId)
                .put("pub", PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded()));
        return tx.put("sig", PhantomCrypto.hex(PhantomCrypto.sign(key, PhantomCrypto.utf8(actionCanon(tx)))));
    }


    // ===== mining economics (simulation) =====
    // weight = 0.6*sqrt(stake)-share + 0.4*identity-share, over non-slashed validators.
    // PROVABLE for real: stake (bonded on-chain), QC signatures, block.proposer.
    // SIM-TRUSTED (real needs more): identity count -> Sybil-resistant personhood; the proposer
    // randomness here is seeded by prevHash (GRINDABLE) where real consensus needs a VRF.

    public void genesisEcon(String chainId, java.util.LinkedHashMap<String, Long> alloc, java.util.List<String> vals,
                     Map<String, Long> stk, Map<String, Long> idn, java.util.Set<String> seedVerified,
                     Map<String, String> valPubsSeed, long ts) throws Exception {
        genesisEcon(chainId, alloc, vals, stk, idn, seedVerified, valPubsSeed, null, ts);
    }

    public void genesisEcon(String chainId, java.util.LinkedHashMap<String, Long> alloc, java.util.List<String> vals,
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

    public boolean excluded(String id) { return slashed.contains(id) || jailedActive(id) || collapsed.contains(id); }   // tombstone, active jail, OR disbanded cluster
    // §9 validator weighting (stake/identity + geo premium + 10% cap) — impl in ValidatorSelection.
    public java.util.List<Integer> liveIdx() { return ValidatorSelection.liveIdx(this); }
    public double coverageMultiplier(int idx) { return ValidatorSelection.coverageMultiplier(this, idx); }
    public static final double WEIGHT_CAP = ValidatorSelection.WEIGHT_CAP;   // facade: §9.4 per-validator cap
    public double weight(int idx) { return ValidatorSelection.weight(this, idx); }
    public java.util.Map<Integer, Double> weightMap() { return ValidatorSelection.weightMap(this); }


    /** Verify the proposer's reveal matches the commitment it made in its prior block (RANDAO binding). */
    // commit-reveal RANDAO beacon — impl in BeaconLogic; thin delegators keep the Ledger API.
    public boolean beaconRevealValid(JSONObject b) { return BeaconLogic.beaconRevealValid(this, b); }
    void beaconApply(JSONObject b) throws Exception { BeaconLogic.beaconApply(this, b); }
    public static byte[] beaconSeedFor(byte[] keyEncoded) { return BeaconLogic.beaconSeedFor(keyEncoded); }
    public static byte[] beaconSecretFor(byte[] keyEncoded, long c) { return BeaconLogic.beaconSecretFor(keyEncoded, c); }
    public static String beaconCommit0For(byte[] keyEncoded) { return BeaconLogic.beaconCommit0For(keyEncoded); }

    // weighted RANDAO proposer election + beacon-sortitioned committee — impl in ValidatorSelection.
    public int proposerFor(String prevHash, int height, int view) throws Exception { return ValidatorSelection.proposerFor(this, prevHash, height, view); }
    public java.util.List<Integer> committeeFor(int height) { return ValidatorSelection.committeeFor(this, height); }
    public int committeeQuorum(int height) { return ValidatorSelection.committeeQuorum(this, height); }

    /** Decaying emission: blockReward halved once per halvingBlocks. Deterministic, capped by maxSupply. */
    // monetary policy (emission / epoch rewards / supply) — impl in EconomicsLogic.
    long blockRewardAt(int height) { return EconomicsLogic.blockRewardAt(this, height); }
    void maybeEpochReward() throws Exception { EconomicsLogic.maybeEpochReward(this); }
}
