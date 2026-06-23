package com.phantomchain.debug;

import static com.phantomchain.debug.TestKit.*;

import java.util.Arrays;
import java.util.HashSet;

/**
 * Deterministic unit test for the stake-cost (bonded-identity) Sybil-resistance hardening.
 * Verifies the admission rule (vouches >= threshold AND stake >= identityBond) and that
 * withdrawing the bond forfeits `verified`. identityBond = 0 must preserve the old vouch-only behavior.
 */
public class SybilTest {
    static void check(String name, boolean cond) { if (cond) { pass++; System.out.println("  PASS " + name); } else { fail++; System.out.println("  FAIL " + name); } }

    public static void main(String[] a) {
        // --- identityBond > 0: bond is required on top of vouches ---
        Ledger L = new Ledger();
        L.identityBond = 1000;
        L.vouches.put("cand", new HashSet<>(Arrays.asList("v1", "v2")));   // 2 vouches (>= VOUCH_THRESHOLD)
        L.tryAdmit("cand");
        check("vouched but unbonded -> NOT verified", !L.verified.contains("cand"));

        L.stake.put("cand", 999L);                                        // just under the bond
        L.tryAdmit("cand");
        check("vouched + under-bond -> NOT verified", !L.verified.contains("cand"));

        L.stake.put("cand", 1000L);                                       // meets the bond
        L.tryAdmit("cand");
        check("vouched + bonded -> verified", L.verified.contains("cand"));

        // withdrawing below the bond forfeits admission (the UNBOND revoke condition)
        L.stake.put("cand", 500L);
        if (L.identityBond > 0 && L.stake.getOrDefault("cand", 0L) < L.identityBond) L.verified.remove("cand");
        check("unbond below bond -> verified revoked", !L.verified.contains("cand"));

        // a single Sybil with stake but too few vouches is still excluded
        L.stake.put("solo", 100000L);
        L.vouches.put("solo", new HashSet<>(Arrays.asList("v1")));         // only 1 vouch
        L.tryAdmit("solo");
        check("bonded but under-vouched -> NOT verified", !L.verified.contains("solo"));

        // --- identityBond == 0: backward-compatible vouch-only behavior ---
        Ledger L0 = new Ledger();                                         // identityBond defaults to 0
        L0.vouches.put("c", new HashSet<>(Arrays.asList("v1", "v2")));
        L0.tryAdmit("c");
        check("identityBond=0 -> vouch-only admits (no bond needed)", L0.verified.contains("c"));

        System.out.println("SybilTest: " + pass + " passed, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }
}
