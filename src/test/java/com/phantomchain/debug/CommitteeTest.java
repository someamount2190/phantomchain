package com.phantomchain.debug;

import static com.phantomchain.debug.TestKit.*;

import java.util.*;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;

/**
 * Committee-sortition validation. Two parts:
 *   PART 1 — correctness: deterministic, weight-proportional, right size, full-set fallback, sig reduction.
 *   PART 2 — SAFETY SIMULATION: committee sortition trades deterministic BFT for probabilistic safety. This
 *            quantifies the real boundary — for an adversary controlling fraction f of weight and committee
 *            size k, how often does a committee end up with enough Byzantine seats to break the
 *            quorum-intersection guarantee (>= 2*cq - k)? That number is the safety-failure probability and
 *            tells you the (f, k) regime where it is honest to turn this on.
 */
public class CommitteeTest {

    static Ledger mk(int n, long[] stake) throws Exception {
        LinkedHashMap<String, Long> alloc = new LinkedHashMap<>(); List<String> vals = new ArrayList<>();
        Map<String, Long> stk = new HashMap<>(), idn = new HashMap<>(); Set<String> ver = new HashSet<>(); Map<String, String> vp = new HashMap<>();
        String[] ids = new String[n];
        for (int i = 0; i < n; i++) {
            MLDSAPrivateKeyParameters k = PhantomCrypto.randomDeviceKey(); ids[i] = Keys.idOf(k);
            alloc.put(ids[i], 1_000_000L); vals.add(ids[i]); stk.put(ids[i], stake[i]); idn.put(ids[i], 1L); ver.add(ids[i]); vp.put(ids[i], Keys.pubHex(k));
        }
        Ledger L = new Ledger(); L.genesisEcon("pc-cmte", alloc, vals, stk, idn, ver, vp, 0);
        L.beacon = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8("seed")));   // non-zero beacon
        return L;
    }

    public static void main(String[] a) throws Exception {
        System.out.println("==== PART 1: correctness ====");
        int N = 100; long[] eq = new long[N]; Arrays.fill(eq, 1_000_000L);
        Ledger L = mk(N, eq);

        L.committeeSize = 0;
        ok("committeeSize=0 -> full set", L.committeeFor(5).size() == N);
        L.committeeSize = N + 10;
        ok("committeeSize>=N -> full set", L.committeeFor(5).size() == N);

        L.committeeSize = 16;
        ok("committee has exactly k members", L.committeeFor(5).size() == 16);
        ok("committee deterministic (same height)", L.committeeFor(7).equals(L.committeeFor(7)));
        ok("committee varies by height", !L.committeeFor(7).equals(L.committeeFor(8)));
        ok("committee members are distinct", new HashSet<>(L.committeeFor(9)).size() == 16);
        ok("committeeQuorum = k-(k-1)/3", L.committeeQuorum(9) == 16 - 15 / 3);
        System.out.println("  sig reduction at N=100,k=16: QC needs " + L.committeeQuorum(9) + " sigs vs full-set "
                + (N - (N - 1) / 3) + " (" + Math.round(100.0 * (1 - (double) L.committeeQuorum(9) / (N - (N - 1) / 3))) + "% fewer)");

        // weight-proportional: a 10x-stake validator should appear in committees far more than an equal one
        long[] skew = new long[N]; Arrays.fill(skew, 1_000_000L); skew[0] = 100_000_000L;   // idx0 has ~100x stake
        Ledger LW = mk(N, skew); LW.committeeSize = 16;
        int idx0 = 0, in0 = 0, inLast = 0;
        for (int h = 0; h < 2000; h++) { List<Integer> c = LW.committeeFor(h); if (c.contains(idx0)) in0++; if (c.contains(N - 1)) inLast++; }
        System.out.println("  high-stake idx0 in " + in0 + "/2000 committees; equal-stake idxLast in " + inLast + "/2000");
        ok("weight-proportional (high stake selected far more often)", in0 > inLast * 3);

        // ==== PART 2: safety simulation ====
        System.out.println("\n==== PART 2: safety simulation (P[committee Byzantine seats break quorum intersection]) ====");
        System.out.println("    unsafe when byzantine seats >= 2*cq - k  (no guaranteed honest node in a quorum intersection)");
        double[] fs = {0.10, 0.20, 0.25, 0.30};
        int[] ks = {16, 64, 256, 512};
        int TRIALS = 4000;
        System.out.printf("    %-8s", "f \\ k");
        for (int k : ks) System.out.printf("%-12s", k);
        System.out.println();
        for (double f : fs) {
            System.out.printf("    %-8s", String.format("%.2f", f));
            for (int k : ks) {
                int n = 1000; if (k >= n) { System.out.printf("%-12s", "-"); continue; }
                long[] st = new long[n]; Arrays.fill(st, 1_000_000L);
                Ledger LS = mk(n, st); LS.committeeSize = k;
                int byzCount = (int) Math.round(f * n);                      // first byzCount validators are Byzantine
                int cq = LS.committeeQuorum(0); int safeBound = 2 * cq - k;  // need byz-in-committee < safeBound
                int unsafe = 0;
                for (int t = 0; t < TRIALS; t++) {
                    LS.beacon = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8("s" + t)));
                    int b = 0; for (int idx : LS.committeeFor(0)) if (idx < byzCount) b++;
                    if (b >= safeBound) unsafe++;
                }
                System.out.printf("%-12s", String.format("%.2g%%", 100.0 * unsafe / TRIALS));
            }
            System.out.println();
        }
        System.out.println("    (0% = safe to enable at that f,k; non-zero = committee can be captured -> do NOT enable.)");

        System.out.println("\nCommitteeTest: " + pass + " passed, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }
}
