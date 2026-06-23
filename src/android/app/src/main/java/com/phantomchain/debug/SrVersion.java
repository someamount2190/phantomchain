package com.phantomchain.debug;

/**
 * Typed state-root / serialization version.
 *
 * The on-chain, on-disk representation stays the canonical string
 * ("v1" / "v2" / "full" / "m1") that travels with the chain — this enum exists so
 * consensus-relevant behavior is never keyed on scattered {@code String.equals}
 * comparisons, where a typo or a missed call site silently changes the state-root
 * tail on one node and forks the chain. To add a version you declare its features
 * here, in one place, instead of sprinkling new string compares across the ledger.
 *
 * Each step is an additive serialization-tail extension (newer is a superset):
 * <pre>
 *   V1   oldest tail            — no identityBond, no committeeSize in the param tail
 *   V2   + identityBond
 *   FULL + committeeSize        — current default; byte-identical to pre-typing builds
 *   M1   FULL + binds the authenticated account Merkle root into the state root, and
 *        makes the prev app-hash roots mandatory (no bypass-by-omission), with the
 *        engine-enforced block-size cap and non-decreasing timestamps.
 * </pre>
 *
 * {@link #parse} maps an unknown/empty tag to {@link #FULL} — exactly the behavior of
 * the previous string gating (an unrecognized value was neither "v1"/"v2" nor "m1",
 * so it took the "full" branch everywhere) — so this refactor is byte-compatible and
 * forward-compatible: an unknown future tag is still stored verbatim and degrades to
 * FULL semantics rather than throwing.
 */
public enum SrVersion {
    V1("v1"),
    V2("v2"),
    FULL("full"),
    M1("m1");

    public final String wire;

    SrVersion(String wire) { this.wire = wire; }

    /** Parse the persisted tag; unknown/empty -> FULL (matches the legacy default branch). */
    public static SrVersion parse(String s) {
        if (s == null || s.isEmpty()) return FULL;
        for (SrVersion v : values()) if (v.wire.equals(s)) return v;
        return FULL;
    }

    /** identityBond is in the param tail for every version except the oldest (V1). */
    public boolean hasIdentityBond() { return this != V1; }

    /** committeeSize is in the param tail only once it exists alongside identityBond (FULL, M1). */
    public boolean hasCommitteeSize() { return this == FULL || this == M1; }

    /** M1 binds the account Merkle root into the state root. */
    public boolean bindsMerkleRoot() { return this == M1; }

    /** M1 makes the prev app-hash roots mandatory and enforces the hardened block bounds. */
    public boolean requiresAppHash() { return this == M1; }
}
