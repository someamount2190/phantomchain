package com.phantomchain.debug;

import org.json.JSONObject;

/**
 * Read-only projection of {@link Ledger} — the engine state the net layer is allowed to observe,
 * with no method that mutates committed state. {@code Ledger implements LedgerView}, so a read-only
 * consumer (status / econ / identity / account handlers) can take a {@code LedgerView} and be unable
 * to advance the chain, touch the mempool, or rewrite balances even by mistake. The mutating surface
 * (commitBlock / addToMempool / pruneBlock / genesis* / enqueueSlash / build*) stays on the concrete
 * {@code Ledger} and is reachable only where a node genuinely drives consensus.
 *
 * The collection accessors return unmodifiable views, so this is read-only in depth, not just at the
 * top level. Pair this with the package boundary: net depends on the engine's public facade only, and
 * the engine's mutable fields are package-private — so this interface documents intent AND the
 * compiler enforces it.
 */
public interface LedgerView {
    // ---- chain / identity ----
    String chainId();
    int height();
    int chainSize();
    String lastHash() throws Exception;
    JSONObject blockAt(int h);
    boolean hasBody(int h);

    // ---- accounts / personhood ----
    long balanceOf(String id);
    long stakeOf(String id);
    long identityCountOf(String id);
    boolean isVerified(String id);
    int vouchCountOf(String id);
    JSONObject identityDoc(String id);

    // ---- economics ----
    long totalMinted();
    long burned();
    long circulatingSupply();
    long blockReward();
    long maxSupply();
    int feeBurnBps();
    int slashBps();
    int jailBlocks();
    int halvingBlocks();
    int unbondingBlocks();
    int bridgeThreshold();

    // ---- validator set / consensus view ----
    int validatorCount();
    String[] validatorIds();
    int validatorIndex(String id);
    String commitOf(String id);
    String tierOf(String id);
    double weight(int idx);
    boolean excluded(String id);
    int mempoolSize();
    int slashedCount();
    java.util.List<Integer> committeeFor(int height);
    int committeeQuorum(int height);

    // ---- governance / bridge / oracle ----
    java.util.Set<String> proposalIds();
    JSONObject proposal(String id);
    int oracleSources(String pair);
    java.util.Map<String, String> valPubs();
    java.util.List<JSONObject> bridgeOuts();
}
