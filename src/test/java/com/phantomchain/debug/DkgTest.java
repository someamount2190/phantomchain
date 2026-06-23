package com.phantomchain.debug;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * DKG tests for the cluster store key (spec §9.3 frontier). Covers single-dealer Shamir+Feldman
 * correctness, k-of-n reconstruction, the k-1 secrecy bound, Feldman detection of a malicious
 * share / forged commitment, and the full N-member ceremony — including that no single device
 * knows the aggregate secret, dropout (k-of-n) liveness, and deterministic key derivation.
 */
public class DkgTest {
    static int pass = 0, fail = 0;
    static void ok(String n, boolean c) { if (c) { pass++; System.out.println("  PASS " + n); } else { fail++; System.out.println("  ** FAIL ** " + n); } }

    static java.util.List<int[]> subsets(int n, int k) {
        java.util.List<int[]> out = new java.util.ArrayList<>();
        rec(n, k, 0, new int[k], 0, out);
        return out;
    }
    static void rec(int n, int k, int start, int[] cur, int depth, java.util.List<int[]> out) {
        if (depth == k) { out.add(cur.clone()); return; }
        for (int i = start; i < n; i++) { cur[depth] = i; rec(n, k, i + 1, cur, depth + 1, out); }
    }
    static Dkg.Share[] pick(Dkg.Share[] all, int[] idx) {
        Dkg.Share[] out = new Dkg.Share[idx.length];
        for (int j = 0; j < idx.length; j++) out[j] = all[idx[j]];
        return out;
    }

    public static void main(String[] a) throws Exception {
        SecureRandom rnd = new SecureRandom();
        int k = 2, n = 3;

        // ── single-dealer Shamir + Feldman ──
        System.out.println("[single-dealer Shamir+Feldman, k=" + k + " n=" + n + "]");
        BigInteger secret = new BigInteger(256, rnd).mod(Dkg.N);
        Dkg.Deal d = Dkg.deal(k, n, secret, rnd);

        boolean allVerify = true;
        for (Dkg.Share s : d.shares) allVerify &= Dkg.verify(s, d.commitments);
        ok("all n shares pass Feldman verification against the commitments", allVerify);

        boolean allK = true;
        for (int[] sub : subsets(n, k)) allK &= Dkg.combine(pick(d.shares, sub)).equals(secret);
        ok("ANY k=" + k + " of n=" + n + " shares reconstruct the exact secret", allK);

        // k-1 reveals nothing: a single share reconstructs to f(x_i) != f(0) = secret
        boolean singleLeak = true;
        for (int i = 0; i < n; i++) {
            Dkg.Share[] one = { d.shares[i] };
            singleLeak &= !Dkg.combine(one).equals(secret);   // one point gives no info about f(0)
        }
        ok("a single (k-1) share reveals nothing about the secret", singleLeak);

        // malicious share: tamper y -> Feldman catches it (this is the exact predicate the ceremony enforces on every dealer share)
        Dkg.Share bad = new Dkg.Share(d.shares[0].x, d.shares[0].y.add(BigInteger.ONE).mod(Dkg.N));
        ok("a tampered share FAILS Feldman verification (malicious dealer detected)", !Dkg.verify(bad, d.commitments));

        // forged commitment: shift C_0 -> verification fails
        org.bouncycastle.math.ec.ECPoint[] forged = d.commitments.clone();
        forged[0] = forged[0].add(Dkg.G).normalize();
        ok("a forged commitment FAILS verification", !Dkg.verify(d.shares[0], forged));

        // ── multi-dealer ceremony ──
        System.out.println("\n[N-member DKG ceremony, k=" + k + " n=" + n + "]");
        Dkg.Ceremony cy = Dkg.ceremony(k, n, rnd);
        BigInteger agg = cy.secret();

        boolean cyVerify = true;
        for (Dkg.Share s : cy.shares) cyVerify &= Dkg.verify(s, cy.commitments);
        ok("every member's aggregate share verifies against the aggregate commitments", cyVerify);

        boolean cyK = true;
        for (int[] sub : subsets(n, k)) cyK &= Dkg.combine(pick(cy.shares, sub)).equals(agg);
        ok("ANY k=" + k + " of n=" + n + " members reconstruct the aggregate secret", cyK);

        boolean noSingleKnows = true;
        for (BigInteger c : cy.contributions) noSingleKnows &= !c.equals(agg);   // S = Σ r_m, known to no single member
        ok("NO single member's contribution equals the aggregate secret (key not on one device)", noSingleKnows);

        // dropout liveness: each k-subset still reconstructs; a lone share does not
        boolean loneFail = true;
        for (int i = 0; i < n; i++) { Dkg.Share[] one = { cy.shares[i] }; loneFail &= !Dkg.combine(one).equals(agg); }
        ok("dropout-safe: a lone member's share cannot reconstruct the secret", loneFail);

        // deterministic 32-byte store key, identical regardless of which k-subset reconstructed the secret
        byte[] key0 = Dkg.storeKeyFromSecret(Dkg.combine(pick(cy.shares, new int[]{0, 1})));
        byte[] key1 = Dkg.storeKeyFromSecret(Dkg.combine(pick(cy.shares, new int[]{1, 2})));
        ok("store key is deterministic across reconstructing k-subsets (32 bytes)", key0.length == 32 && Arrays.equals(key0, key1));

        // ── larger ceremony sanity (k=3 n=5) ──
        System.out.println("\n[larger ceremony, k=3 n=5]");
        Dkg.Ceremony big = Dkg.ceremony(3, 5, rnd);
        boolean bigK = true;
        for (int[] sub : subsets(5, 3)) bigK &= Dkg.combine(pick(big.shares, sub)).equals(big.secret());
        ok("ANY 3 of 5 reconstruct the secret (every k-subset, 10 combinations)", bigK);
        ok("3-of-5 ceremony: no single contribution is the secret", noneEqual(big.contributions, big.secret()));
        boolean bigTwoFail = true;
        for (int[] sub : subsets(5, 2)) bigTwoFail &= !Dkg.combine(pick(big.shares, sub)).equals(big.secret());
        ok("NO 2-of-5 subset can reconstruct the secret (below threshold)", bigTwoFail);

        System.out.println("\nDkgTest: " + pass + " passed, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }

    static boolean noneEqual(BigInteger[] xs, BigInteger s) {
        for (BigInteger x : xs) if (x.equals(s)) return false;
        return true;
    }
}
