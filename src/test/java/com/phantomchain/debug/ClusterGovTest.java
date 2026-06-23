package com.phantomchain.debug;

import static com.phantomchain.debug.TestKit.*;

import java.util.*;
import org.json.JSONArray;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;

/**
 * Cluster governance (spec §9.4 cap + §9.7 collapse):
 *   - the 10% per-validator weight cap engages at scale and stays INERT on small sets (so existing chains
 *     — incl. the live testnet — are unchanged);
 *   - a cluster's own members (>= threshold) can disband it; a disbanded cluster is excluded from consensus
 *     and its members are freed.
 */
public class ClusterGovTest {
    static MLDSAPrivateKeyParameters key() { return PhantomCrypto.randomDeviceKey(); }

    static Ledger mk(long[] stake) throws Exception {
        int n = stake.length;
        LinkedHashMap<String, Long> alloc = new LinkedHashMap<>(); List<String> vals = new ArrayList<>();
        Map<String, Long> stk = new HashMap<>(), idn = new HashMap<>(); Set<String> ver = new HashSet<>(); Map<String, String> vp = new HashMap<>();
        for (int i = 0; i < n; i++) { MLDSAPrivateKeyParameters k = key(); String id = Keys.idOf(k);
            alloc.put(id, 1_000_000L); vals.add(id); stk.put(id, stake[i]); idn.put(id, 1L); ver.add(id); vp.put(id, Keys.pubHex(k)); }
        Ledger L = new Ledger(); L.genesisEcon("pc-gov", alloc, vals, stk, idn, ver, vp, 0);
        L.beacon = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8("seed")));
        return L;
    }

    public static void main(String[] a) throws Exception {
        System.out.println("==== §9.4  10% weight cap ====");
        // small set (N=4): one dominant validator KEEPS its >10% share (cap inert -> existing chains unchanged)
        Ledger S = mk(new long[]{1_000_000_000L, 1000, 1000, 1000});
        ok("N=4: cap inert — dominant validator keeps >10% (live chains unaffected)", S.weight(0) > 0.10);

        // at scale (N=11): a dominant validator is capped at 10%, excess redistributed, weights still sum to ~1
        long[] big = new long[11]; Arrays.fill(big, 1000L); big[0] = 1_000_000_000L;
        Ledger B = mk(big);
        double w0 = B.weight(0), sum = 0; for (int i = 0; i < 11; i++) sum += B.weight(i);
        ok("N=11: dominant validator capped at 10%", w0 <= 0.10 + 1e-9 && w0 > 0.099);
        ok("N=11: capped weights still sum to ~1.0", Math.abs(sum - 1.0) < 1e-6);
        ok("N=11: the 10 small validators share the redistributed ~90%", (sum - w0) > 0.89);

        System.out.println("\n==== §9.7  cluster collapse / disband ====");
        Ledger L = mk(new long[]{1_000_000L, 1_000_000L});   // 2 base validators
        int M = 3, threshold = 2;
        MLDSAPrivateKeyParameters[] mk = new MLDSAPrivateKeyParameters[M]; String[] mid = new String[M];
        List<String> members = new ArrayList<>(); Map<String, String> mpub = new HashMap<>();
        for (int i = 0; i < M; i++) { mk[i] = key(); mid[i] = Keys.idOf(mk[i]); members.add(mid[i]); mpub.put(mid[i], Keys.pubHex(mk[i])); L.stake.put(mid[i], 250_000L); }
        String clusterId = "cluster-zeta";
        L.applyClusterForm(L.buildClusterFormTx(clusterId, members, mpub, threshold, mk[0], Ledger.beaconCommit0For(mk[0].getEncoded())));
        int cidx = L.validators.indexOf(clusterId);
        ok("cluster active before disband (in live set, weight>0)", L.liveIdx().contains(cidx) && L.weight(cidx) > 0);

        // under-threshold disband (1 of 3) rejected
        ok("disband with 1-of-3 member sigs rejected", !L.verifyClusterDisband(L.buildClusterDisbandTx(clusterId, Arrays.asList(mk[0]))));
        // a non-member cannot disband
        ok("disband signed by a non-member rejected", !L.verifyClusterDisband(L.buildClusterDisbandTx(clusterId, Arrays.asList(key(), key()))));

        // threshold disband (2 of 3) accepted -> collapse
        ok("disband with 2-of-3 member sigs accepted", L.verifyClusterDisband(L.buildClusterDisbandTx(clusterId, Arrays.asList(mk[0], mk[1]))));
        L.collapsed.add(clusterId);   // apply (commitBlock does this on a valid CLUSTERDISBAND)
        ok("disbanded cluster is excluded from consensus", L.excluded(clusterId));
        ok("disbanded cluster has weight 0 and is out of the live set", L.weight(cidx) == 0 && !L.liveIdx().contains(cidx));
        ok("members keep their own stake (freed, not slashed)", L.stake.get(mid[0]) == 250_000L);

        System.out.println("\nClusterGovTest: " + pass + " passed, " + fail + " failed");
        System.exit(fail == 0 ? 0 : 1);
    }
}
