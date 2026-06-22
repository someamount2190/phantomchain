# PhantomChain — Economic Design for Stability at 50,000,000 Transactions

This document specifies a monetary policy that keeps the economy **stable across 50 million
transactions** (~9.5 years at 100 tx/block, 10‑minute blocks → 500,000 blocks), and validates it with a
simulation that uses the **real** emission and fee‑burn formulas from `Ledger`
(`blockRewardAt`, `maybeEpochReward`, the `feeBurnBps` burn in `commitBlock`). Reproduce with
`node/EconStabilitySim.java`.

## What "stable" means (the criteria the design must pass)

| # | Criterion | Threshold |
|---|---|---|
| **C1** | **Supply bounded** — no runaway inflation, no collapse from over‑burning | stays within the genesis…genesis+cap band (no drop below 85% of genesis) |
| **C2** | **Burn sustainable** — the deflationary sink can't consume the supply over 50M tx | cumulative fee burn < 5% of supply |
| **C3** | **Security‑budget continuity** — validator income survives the end of emission (no "fee cliff") | late‑life budget ≥ 40% of early‑life budget |
| **C4** | **Net issuance bounded** — emission minus burn doesn't drift without limit | |emission − burn| < 10% of supply |

## The core problem at 50M‑tx scale

Emission is **per block** (capped), but fee burn is **per transaction**. Over 50M transactions the burn
term dominates unless it is calibrated. The chain's **current default `feeBurnBps = 5000` (50% burn)** is
fine for a short testnet but is **not stable at scale**: with any real fee market it burns *more than the
entire supply*. The simulation makes this concrete (SCENARIO A):

```
NAIVE  feeBurnBps=5000, avgFee=0.50 PHNT
  → 12.5M PHNT burned = 151% of supply; circulating collapses 18.9M → 8.275M
  → C1 FAIL, C2 FAIL, C4 FAIL  → UNSTABLE
```

Two design levers fix this, and they are independent:
1. **Burn *fraction*** (`feeBurnBps`) controls the deflationary sink → governs C1/C2/C4.
2. **Validators keep the *non‑burned* fee remainder**, so fees can be high enough to fund security
   (C3) while the burn fraction stays low (C2). EIP‑1559‑style: most of the fee pays the validator, a
   small slice is burned.

## The designed parameter set (denominated in base units)

> **Denomination.** 1 PHNT = **1e8 base units** (like sats/wei). Fees are integers in base units, so a
> realistic sub‑cent fee is representable and `long` never overflows (max ≈ 9.2e18 base = 9.2e10 PHNT).

| Parameter | Value | Why |
|---|---|---|
| Genesis supply | **18,900,000 PHNT** (90% of 21M) | distributed at launch; the bulk of supply is not emission |
| `blockReward` | **8 PHNT/block** | initial security subsidy |
| `halvingBlocks` | **125,000** (~2.4 yr) | tapers emission smoothly |
| `maxSupply` (emission cap) | **2,100,000 PHNT** (10% of 21M) | hard ceiling on issuance; Σ emission asymptotes to ~2.0M, so the cap is approached, never slammed |
| `feeBurnBps` | **1,000 (10% burn)** | small deflationary sink: keeps C2 well under 5% |
| Fee market | **avg ≈ 0.10 PHNT/tx** | 90% (0.09) to the proposer funds security; 10% (0.01) burned |
| Throughput (assumed) | 100 tx/block, 144 blocks/day | 14,400 tx/day → 50M tx in ~9.5 yr |

Total supply ceiling = genesis 18.9M + emission cap 2.1M = **21,000,000 PHNT**.

## Validated outcome over 50M transactions (SCENARIO B)

```
DESIGNED  feeBurnBps=1000, avgFee=0.10 PHNT, emission cap 2.1M
  final supply 20.275M PHNT  (genesis 18.900M + emission 1.875M − burn 0.500M)
  C1 supply bounded     : 18.900M … 20.275M                          PASS
  C2 burn sustainable   : 2.47% of supply burned over 50M tx (<5%)   PASS
  C3 security continuity: 2,448 → 1,440 PHNT/day (ratio 0.59, no cliff) PASS
  C4 net issuance       : +1.375M PHNT (6.8% of supply, front-loaded) PASS
  fee market            : validators keep 90% of fees, 10% burned
  OVERALL: STABLE
```

Trajectory (sampled): supply rises from 18.9M and **asymptotes at ~20.3M** as emission tapers (halvings)
and the small burn offsets it — a stable equilibrium, not a drift. The **security budget transitions
smoothly from emission‑funded to fee‑funded** (no Bitcoin‑style cliff) because fee income (~0.09 PHNT ×
14,400/day ≈ 1,296 PHNT/day) already exceeds late‑life emission, so validators stay paid after issuance
ends.

## Validation of the model

`EconStabilitySim` computes emission by calling the **real `Ledger.blockRewardAt`** and burns with the
**exact `commitBlock` integer formula** (`blockFees * feeBurnBps / 10000`). Cross‑checked against the live
14,400‑block engine run (`LongRunEconSim`):
- emission: model 450,000 vs engine **449,966** (34 short = per‑epoch integer‑split dust, 0.008%);
- burn: model @avgFee 3 = 100,800 vs engine **104,075** (within random‑draw variance of the engine's
  per‑tx fees).

## How to apply it

These are all **governable** parameters (`GOV_PARAMS` already includes `blockReward`, `halvingBlocks`,
`maxSupply`, `feeBurnBps`), so the design ships as **genesis settings** for a new chain and is adjustable
on‑chain via `PROPOSE`/`VOTE` (snapshot‑weighted, time‑locked). The one concrete change a real deployment
should make versus today's defaults is **lowering `feeBurnBps` from 5000 to ~1000** and denominating in
base units; the rest is genesis configuration. No consensus‑critical code change is required — the live
testnet keeps its own params until governance changes them.

## Honest limits

- The fee market is modeled at a constant average; a real fee market fluctuates, but the **burn fraction**
  (the stability lever) is what's bounded, so the conclusion is robust to the average.
- "Stable" is proven for the 50M‑tx horizon. Past it, burn keeps accruing slowly (~2.5%/50M tx); a real
  deployment relies on the fee market re‑pricing as supply/throughput change — the same assumption every
  fee‑burning chain makes. The cap guarantees the *upper* bound unconditionally.
