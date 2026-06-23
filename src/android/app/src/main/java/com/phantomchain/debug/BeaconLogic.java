package com.phantomchain.debug;

import org.json.JSONObject;

/**
 * Commit-reveal RANDAO beacon — extracted from {@link Ledger}.
 *
 * Each proposer reveals a value it committed in its prior block; the reveal is folded into the running
 * {@code beacon} and the proposer's next commitment is recorded. Beacon STATE ({@code beacon},
 * {@code commits}) stays in {@link Ledger}; this owns the reveal validation, the fold, and the
 * key-derived secret/commit derivation that lets {@code commit0} be published at keygen and bound at
 * genesis/VALJOIN (closing the unconstrained-first-reveal grind). Guarded by {@code AdversaryTest} /
 * {@code GenuineAdversaryTest}.
 */
final class BeaconLogic {
    private BeaconLogic() {}

    static boolean beaconRevealValid(Ledger l, JSONObject b) {
        int prop = b.optInt("proposer", -1);
        if (prop < 0 || prop >= l.validators.size()) return true;
        String prev = l.commits.get(l.validators.get(prop));
        if (prev == null) return true;   // only reachable for legacy genesis without seeded commit0 (unconstrained first reveal)
        // commit is sha3 over the RAW 32 secret bytes (matching beaconCommit()), so hash the unhexed reveal
        return PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.unhex(b.optString("reveal", "")))).equals(prev);
    }

    /** Fold the proposer's revealed value into the beacon and record its next commitment. */
    static void beaconApply(Ledger l, JSONObject b) throws Exception {
        int prop = b.optInt("proposer", -1);
        if (prop < 0 || prop >= l.validators.size()) return;
        l.beacon = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8(l.beacon + "|" + b.optString("reveal", ""))));
        if (b.has("commit")) l.commits.put(l.validators.get(prop), b.getString("commit"));
    }

    // Canonical beacon-secret derivation (single source of truth; a node only knows its own key).
    static byte[] beaconSeedFor(byte[] keyEncoded) { return PhantomCrypto.hkdf(keyEncoded, null, PhantomCrypto.utf8("pcbeaconseed"), 32); }
    static byte[] beaconSecretFor(byte[] keyEncoded, long c) { return PhantomCrypto.hkdf(beaconSeedFor(keyEncoded), null, PhantomCrypto.utf8("pcbeacon" + c), 32); }
    static String beaconCommit0For(byte[] keyEncoded) { return PhantomCrypto.hex(PhantomCrypto.sha3_256(beaconSecretFor(keyEncoded, 0))); }
}
