package com.phantomchain.debug;

import static com.phantomchain.debug.TestKit.*;

import java.util.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

/**
 * Long-horizon transaction + economics simulation: drives the REAL state machine (commitBlock) over a
 * configurable number of simulated days so the genuine economic policy plays out — decaying emission with
 * halvings (blockRewardAt), the hard supply cap (maxSupply), fee burn (feeBurnBps), and reward-by-on-chain-
 * contribution (proposer bonus + QC-signer units, maybeEpochReward). Transactions are real, signed, fee-
 * paying transfers validated by commitBlock->txCheck. The per-block QC carries the real committee SIGNER
 * SET (what reward distribution reads) without ML-DSA signing each block, so a 100-day horizon is tractable
 * while the economics remain exactly the production formulas.
 *
 * Usage: LongRunEconSim [N] [days] [blocksPerDay] [txPerBlock] [blockReward] [halvingDays] [maxSupply]
 */
public class LongRunEconSim {

    public static void main(String[] a) throws Exception {
        int N            = arg(a, 0, 60);
        int days         = arg(a, 1, 100);
        int blocksPerDay = arg(a, 2, 144);          // 144 -> ~10-minute blocks
        int txPerBlock   = arg(a, 3, 6);
        long blockReward = arg(a, 4, 50);
        int halvingDays  = arg(a, 5, 50);           // emission halves at this day
        long maxSupply   = a.length > 6 ? Long.parseLong(a[6]) : 450_000L;   // set to bite ~day 80 to show the cap

        int H = days * blocksPerDay;
        int halvingBlocks = halvingDays * blocksPerDay;
        System.out.printf(Locale.US,
            "================ %d-DAY ECONOMICS SIM  N=%d  %d blocks (%d/day ~= %d-min blocks)  %d tx/block ================%n",
            days, N, H, blocksPerDay, 24 * 60 / blocksPerDay, txPerBlock);
        System.out.printf(Locale.US, "  policy: blockReward=%d, halving@day%d (every %d blocks), maxSupply=%d, feeBurn=50%%, EPOCH_LEN=%d%n",
            blockReward, halvingDays, halvingBlocks, maxSupply, Ledger.EPOCH_LEN);

        Random rnd = new Random(7L);
        long t0 = System.currentTimeMillis();

        // ---- validators + genesis ----
        MLDSAPrivateKeyParameters[] keys = new MLDSAPrivateKeyParameters[N];
        String[] ids = new String[N]; long[] ctr = new long[N];
        Map<String, MLDSAPublicKeyParameters> pubById = new HashMap<>();
        LinkedHashMap<String, Long> alloc = new LinkedHashMap<>();
        List<String> vals = new ArrayList<>();
        Map<String, Long> stk = new HashMap<>(), idn = new HashMap<>();
        Set<String> verified = new HashSet<>();
        Map<String, String> valPubs = new HashMap<>(), beaconCommits = new HashMap<>();
        long GENESIS_ALLOC = 100_000_000L;
        for (int i = 0; i < N; i++) {
            keys[i] = PhantomCrypto.randomDeviceKey();
            ids[i] = PhantomCrypto.hex(PhantomCrypto.sha3_256(keys[i].getPublicKeyParameters().getEncoded()));
            String pub = PhantomCrypto.hex(keys[i].getPublicKeyParameters().getEncoded());
            pubById.put(ids[i], new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, keys[i].getPublicKeyParameters().getEncoded()));
            alloc.put(ids[i], GENESIS_ALLOC); vals.add(ids[i]);
            stk.put(ids[i], (long) (500_000 + Math.pow(rnd.nextDouble(), 2) * 4_000_000));   // varied stake -> weighted proposing
            idn.put(ids[i], 1L); verified.add(ids[i]); valPubs.put(ids[i], pub);
            beaconCommits.put(ids[i], Ledger.beaconCommit0For(keys[i].getEncoded()));
        }
        Ledger L = new Ledger();
        L.genesisEcon("pc-econ-100d", alloc, vals, stk, idn, verified, valPubs, beaconCommits, 1700000000000L);
        L.blockReward = blockReward; L.halvingBlocks = halvingBlocks; L.maxSupply = maxSupply;
        L.feeBurnBps = 5000; L.committeeSize = 0;   // full-set QC: every validator signs -> emission spreads by participation
        long startSupply = L.circulatingSupply();

        // ---- run ----
        int[] proposerCount = new int[N];
        long totalTx = 0, totalFees = 0;
        long halvingNotedSupply = -1; int capDay = -1;
        System.out.println("  day | height | reward/blk |   emission |     burned | circulating |   tx/day");
        System.out.println("  ----+--------+------------+------------+------------+-------------+---------");
        long dayTx = 0;
        for (int h = 1; h <= H; h++) {
            int reward = (int) L.blockRewardAt(h);
            for (int t = 0; t < txPerBlock; t++) {
                int from = rnd.nextInt(N), to = rnd.nextInt(N);
                long fee = 1 + rnd.nextInt(5);
                JSONObject tx = L.buildTxProjected(ids[from], ids[to], 1 + rnd.nextInt(1000), fee, keys[from]);
                if ("accepted".equals(L.addToMempool(tx, pubById))) { totalFees += fee; }
            }
            int proposer = L.proposerFor(L.lastHash(), h, 0);
            proposerCount[proposer]++;
            JSONObject blk = L.buildProposal(proposer, 1700000000000L + (long) h * (86400L / blocksPerDay) * 1000);
            blk.put("view", 0);
            blk.put("reveal", PhantomCrypto.hex(Ledger.beaconSecretFor(keys[proposer].getEncoded(), ctr[proposer])));
            blk.put("commit", PhantomCrypto.hex(PhantomCrypto.sha3_256(Ledger.beaconSecretFor(keys[proposer].getEncoded(), ctr[proposer] + 1))));
            // QC = the real committee signer SET (indices are what maybeEpochReward credits); no per-block ML-DSA
            JSONArray qc = new JSONArray();
            for (int j : L.committeeFor(h)) qc.put(new JSONObject().put("i", j));
            blk.put("qc", qc);

            long txInBlock = blk.getJSONArray("txs").length();
            String res = L.commitBlock(blk, pubById);
            if (!"appended".equals(res)) { System.out.println("  ** commit FAILED h=" + h + ": " + res); return; }
            ctr[proposer]++; totalTx += txInBlock; dayTx += txInBlock;
            L.mempool.clear();

            if (halvingNotedSupply < 0 && h == halvingBlocks + 1) halvingNotedSupply = L.totalMinted;
            if (capDay < 0 && L.totalMinted >= maxSupply) capDay = (h + blocksPerDay - 1) / blocksPerDay;

            if (h % blocksPerDay == 0) {                  // end of a simulated day
                int day = h / blocksPerDay;
                if (day % 10 == 0 || day == 1 || day == halvingDays || day == days) {
                    System.out.printf(Locale.US, "  %3d | %6d | %10d | %10d | %10d | %11d | %8d%n",
                        day, h, reward, L.totalMinted, L.burned, L.circulatingSupply(), dayTx);
                }
                dayTx = 0;
            }
        }
        long tEnd = System.currentTimeMillis();

        // ---- economic summary ----
        long emission = L.totalMinted;
        long feeBurn = L.burned;
        long proposerFeeIncome = totalFees - feeBurn;     // fee remainder paid to proposers
        long netIssuance = emission - feeBurn;            // new supply net of the deflationary burn
        int rewardBefore = (int) L.blockRewardAt(halvingBlocks);
        int rewardAfter  = (int) L.blockRewardAt(halvingBlocks + 1);

        // decentralization of proposing (weight-proportional) + supply conservation
        int distinct = 0, maxProp = 0; for (int c : proposerCount) { if (c > 0) distinct++; if (c > maxProp) maxProp = c; }
        long endSupply = L.circulatingSupply();

        System.out.println("\n  ---- 100-day economic outcome ----");
        System.out.printf(Locale.US, "  transactions: %,d committed (%.0f/day), total fees paid %,d%n", totalTx, (double) totalTx / days, totalFees);
        System.out.printf(Locale.US, "  emission (minted): %,d of %,d cap  (%.1f%% of cap issued)%n", emission, maxSupply, 100.0 * emission / maxSupply);
        System.out.printf(Locale.US, "  halving worked: reward/block %d -> %d at day %d%n", rewardBefore, rewardAfter, halvingDays);
        if (capDay > 0) System.out.printf(Locale.US, "  HARD CAP reached ~day %d: emission stops, validator income transitions to fees only (Bitcoin-style)%n", capDay);
        else System.out.printf(Locale.US, "  cap not reached; headroom %,d%n", maxSupply - emission);
        System.out.printf(Locale.US, "  fee burn (deflationary sink): %,d burned = %.0f%% of fees; proposers earned %,d in fee remainder%n",
            feeBurn, 100.0 * feeBurn / Math.max(1, totalFees), proposerFeeIncome);
        System.out.printf(Locale.US, "  net issuance (emission - burn): %,d%n", netIssuance);
        System.out.printf(Locale.US, "  supply conservation: start %,d + emission %,d - burn %,d = %,d  (actual %,d, match=%b)%n",
            startSupply, emission, feeBurn, startSupply + emission - feeBurn, endSupply, startSupply + emission - feeBurn == endSupply);
        System.out.printf(Locale.US, "  proposer decentralization: %d/%d validators proposed; busiest proposed %d blocks (%.1f%% of %d)%n",
            distinct, N, maxProp, 100.0 * maxProp / H, H);
        System.out.printf(Locale.US, "  height %d, %d accounts, stateRoot=%s...%n", L.height(), L.accounts.size(), L.stateRoot().substring(0, 16));
        System.out.printf(Locale.US, "  wall-clock %.1fs%n", (tEnd - t0) / 1000.0);
    }

    static int arg(String[] a, int i, int d) { return a.length > i ? Integer.parseInt(a[i]) : d; }
    static long arg(String[] a, int i, long d) { return a.length > i ? Long.parseLong(a[i]) : d; }
}
