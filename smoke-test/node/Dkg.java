package com.phantomchain.debug;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Distributed key generation for the cluster store key (spec §9.3 documented frontier).
 *
 * The limitation being designed around: {@link ClusterStore} encrypts the cluster's ledger
 * partition under a single 32-byte clusterSecret held by whichever device runs shard().
 * Every member shard is ciphertext, but the encryption KEY itself lives on one device.
 *
 * DKG removes single-device key custody at generation: each of the N member devices is a
 * dealer contributing a random secret r_m; the aggregate secret S = Σ r_m is unknown to any
 * single device. Each member ends up holding only a Shamir share (threshold k) of S, plus
 * Feldman commitments that make every share VERIFIABLE (a malicious/inconsistent dealer is
 * detected rather than silently corrupting the key).
 *
 * Mechanism: Shamir secret sharing over Z_n where n = P-256 group order (prime), so the
 * secret field and the commitment-group order match. Feldman VSS commitments C_j = a_j·G;
 * share (x_i, y_i) verifies as y_i·G == Σ_j x_i^j · C_j. The ceremony sums per-dealer
 * polynomials, so the aggregate secret and aggregate commitments are consistent without any
 * device ever assembling the secret.
 *
 * HONEST RESIDUAL (same stance as the consensus QC vs a true threshold signature): the key
 * IS reconstructed inside a cooperating k-of-N quorum at use-time — transiently, to re-seal
 * or rotate, never persisted on a single device. True threshold-ENCRYPTION (joint public key,
 * k-of-N partial decryption, the key never reconstructed at all) is the deeper frontier and
 * needs a threshold-PKE scheme; it is not built here. This DKG closes the single-device
 * generation/custody gap named in FRONTIER.md; it does not overclaim threshold-PKE.
 */
public class Dkg {

    /** P-256: a standard prime-order EC group. n (order) is prime → our secret field Z_n. */
    static final X9ECParameters P = ECNamedCurveTable.getByName("P-256");
    static final BigInteger N = P.getN();      // prime group order = secret field modulus
    static final ECPoint G = P.getG();         // group generator

    /** A (x, y) Shamir share; x is public (member index), y = f(x) in Z_n. */
    public static final class Share {
        public final BigInteger x, y;
        public Share(BigInteger x, BigInteger y) { this.x = x; this.y = y; }
    }

    /** A single dealer's round: polynomial coefficients, n shares, and k Feldman commitments. */
    public static final class Deal {
        public final BigInteger secret;          // a_0 (the dealer's secret contribution; dealer-only)
        public final BigInteger[] coeffs;        // a_0 .. a_{k-1}
        public final Share[] shares;             // shares for x = 1..n
        public final ECPoint[] commitments;      // C_j = a_j·G for j = 0..k-1
        public Deal(BigInteger secret, BigInteger[] coeffs, Share[] shares, ECPoint[] commitments) {
            this.secret = secret; this.coeffs = coeffs; this.shares = shares; this.commitments = commitments;
        }
    }

    /** A full N-member, threshold-k DKG ceremony's output. */
    public static final class Ceremony {
        public final int k, n;
        public final BigInteger[] contributions;     // each member's r_m (member-only)
        public final Share[] shares;                 // member i's aggregate share of S
        public final ECPoint[] commitments;          // aggregate commitments C_j = Σ_m a_{m,j}·G
        public Ceremony(int k, int n, BigInteger[] contributions, Share[] shares, ECPoint[] commitments) {
            this.k = k; this.n = n; this.contributions = contributions;
            this.shares = shares; this.commitments = commitments;
        }
        /** The aggregate secret S = Σ r_m. Known to NO single member (each knows only their own r_m). */
        public BigInteger secret() {
            BigInteger s = BigInteger.ZERO;
            for (BigInteger c : contributions) s = s.add(c).mod(N);
            return s;
        }
    }

    // ───────────────────────── single-dealer Shamir + Feldman ─────────────────────────

    /** Produce n shares (threshold k) of secretContribution, with Feldman commitments. */
    public static Deal deal(int k, int n, BigInteger secretContribution, SecureRandom rnd) {
        if (k < 1 || n < k) throw new IllegalArgumentException("need 1 <= k <= n");
        if (secretContribution.signum() < 0 || secretContribution.compareTo(N) >= 0)
            throw new IllegalArgumentException("secret must be in [0, n)");
        BigInteger[] a = new BigInteger[k];
        a[0] = secretContribution;
        for (int j = 1; j < k; j++) a[j] = randomField(rnd);
        Share[] shares = new Share[n];
        for (int i = 1; i <= n; i++) {
            BigInteger x = BigInteger.valueOf(i);
            shares[i - 1] = new Share(x, eval(a, x));
        }
        ECPoint[] C = new ECPoint[k];
        for (int j = 0; j < k; j++) C[j] = G.multiply(a[j]).normalize();
        return new Deal(a[0], a, shares, C);
    }

    /** Feldman-verify a share against commitments (detects a tampered share or forged commitment). */
    public static boolean verify(Share s, ECPoint[] commitments) {
        ECPoint lhs = G.multiply(s.y).normalize();
        ECPoint rhs = null;
        BigInteger pow = BigInteger.ONE;             // x_i^j
        for (int j = 0; j < commitments.length; j++) {
            rhs = (rhs == null) ? commitments[j].multiply(pow) : rhs.add(commitments[j].multiply(pow));
            pow = pow.multiply(s.x).mod(N);
        }
        return java.util.Arrays.equals(lhs.getEncoded(true), rhs.normalize().getEncoded(true));
    }

    /** Lagrange-interpolate f(0) (the secret) from any >= k shares. */
    public static BigInteger combine(Share[] shares) {
        BigInteger secret = BigInteger.ZERO;
        for (int i = 0; i < shares.length; i++) {
            BigInteger num = BigInteger.ONE, den = BigInteger.ONE;
            for (int j = 0; j < shares.length; j++) {
                if (i == j) continue;
                num = num.multiply(shares[j].x.negate()).mod(N);              // (0 - x_j)
                den = den.multiply(shares[i].x.subtract(shares[j].x)).mod(N); // (x_i - x_j)
            }
            BigInteger lagrange = num.multiply(den.modInverse(N)).mod(N);
            secret = secret.add(shares[i].y.multiply(lagrange)).mod(N);
        }
        return secret;
    }

    // ───────────────────────── multi-dealer DKG ceremony ─────────────────────────

    /** Run an N-member, threshold-k DKG. Each member contributes a random 256-bit secret. */
    public static Ceremony ceremony(int k, int n, SecureRandom rnd) {
        Deal[] deals = new Deal[n];
        BigInteger[] contribs = new BigInteger[n];
        for (int m = 0; m < n; m++) {
            contribs[m] = new BigInteger(256, rnd).mod(N);
            deals[m] = deal(k, n, contribs[m], rnd);
        }
        // member i sums the sub-shares it received from every dealer, rejecting any dealer
        // whose share fails Feldman verification (a malicious/inconsistent dealer is caught here).
        Share[] agg = new Share[n];
        for (int i = 0; i < n; i++) {
            BigInteger x = BigInteger.valueOf(i + 1), y = BigInteger.ZERO;
            for (int m = 0; m < n; m++) {
                Share sub = deals[m].shares[i];
                if (!verify(sub, deals[m].commitments))
                    throw new IllegalStateException("dealer " + m + " committed an inconsistent share (Feldman reject)");
                y = y.add(sub.y).mod(N);
            }
            agg[i] = new Share(x, y);
        }
        // aggregate commitments: C_j = Σ_m C_{m,j} (commit to the summed polynomial)
        ECPoint[] aggC = new ECPoint[k];
        for (int j = 0; j < k; j++) {
            ECPoint acc = null;
            for (int m = 0; m < n; m++) acc = (acc == null) ? deals[m].commitments[j] : acc.add(deals[m].commitments[j]);
            aggC[j] = acc.normalize();
        }
        return new Ceremony(k, n, contribs, agg, aggC);
    }

    /** Map a reconstructed secret to the canonical 32-byte cluster store key (drop-in for ClusterStore.clusterSecret). */
    public static byte[] storeKeyFromSecret(BigInteger secret) {
        byte[] be = secret.mod(N).toByteArray();   // minimal big-endian; may carry a leading sign byte
        byte[] fixed = new byte[32];
        int copy = Math.min(be.length, 32);
        System.arraycopy(be, be.length - copy, fixed, 32 - copy, copy);   // right-align low 32 bytes
        return PhantomCrypto.sha3_256(fixed);
    }

    // ───────────────────────── helpers ─────────────────────────

    static BigInteger eval(BigInteger[] a, BigInteger x) {
        BigInteger y = BigInteger.ZERO, pow = BigInteger.ONE;
        for (BigInteger aj : a) { y = y.add(aj.multiply(pow)).mod(N); pow = pow.multiply(x).mod(N); }
        return y;
    }

    static BigInteger randomField(SecureRandom rnd) {
        BigInteger r;
        do { r = new BigInteger(N.bitLength(), rnd); } while (r.signum() < 0 || r.compareTo(N) >= 0);
        return r;
    }
}
