# Decomposition plan — breaking up `Ledger`

`Ledger` (~1.6 kLOC) is a single class doing accounts, staking, governance, bridge,
beacon, estate, clusters/shards, and serialization. That is an audit-surface and
maintainability problem, and the version gating that drove it was string equality —
precisely where chain-splits hide. This document is the plan to decompose it safely.

## The one invariant that makes this hard

`stateRoot()` hashes a **canonical byte string** built field-by-field in a fixed
order. Any reordering, added/removed field, or format change in that string changes
the state root → nodes that disagree on the bytes **fork**. So decomposition cannot
be "move methods around until it's tidy." Every step must be **state-root-neutral**,
proven, not asserted.

## Enabler (done)

- **CI + a real build.** `build.gradle` compiles `src/node` + the three pure core
  classes and `./gradlew runTests` runs the deterministic JVM suite (25 suites);
  `.github/workflows/ci.yml` gates every push/PR. Decomposition steps are now
  regression-gated instead of hand-run javac.
- **Typed version gating (`SrVersion`).** The first extraction: the `"v1"/"v2"/
  "full"/"m1"` string compares scattered through `Ledger` are replaced by an enum
  with explicit feature predicates (`hasIdentityBond` / `hasCommitteeSize` /
  `bindsMerkleRoot` / `requiresAppHash`). The wire string is still serialized
  verbatim, so the state root is byte-identical (guarded by `ClusterTest`’s
  "hashes exactly as before"); a new version is now declared in one typed place.

## Step 0 — pin the state root before moving anything ✅ DONE

`node/GoldenStateRootTest` builds deterministic ledgers (fixed seeds → fixed ids) and
asserts `stateRoot()` + `accountsMerkleRoot()` against pinned hex constants for
**v1/v2/full/m1 × {genesis, mutated}** (16 vectors). It's in the CI gate, so any byte
change in the layout becomes a precise red, not a silent fork — the safety net every
later step runs against.

## Step 1 — extract the serialization codec ✅ DONE

`StateRootCodec` owns the ENTIRE consensus byte surface: `stateRoot()`, the
authenticated account Merkle commitment (root/proof/verify), the per-shard state roots
(`shardsRoot`/`shardData`), and full-state persistence (`toJson`/`fromJson`). `Ledger`
keeps thin delegators so all call sites are unchanged. Golden net is 40 checks (sr +
amr + shardsRoot + a toJson↔fromJson round-trip × v1/v2/full/m1 × {genesis, mutated}),
in CI. Verified byte-identical.

## Step 2 — extract leaf subsystems behind interfaces (in progress)

Leaves done:
- **`BridgeLogic`** — cross-chain custodian M-of-N verification (`verifyBridgeIn` /
  `verifyOracle` / `bridgeOutCanon`); bridge state stays in `Ledger`; delegators keep
  call sites unchanged. Guarded by `BridgeAdversaryTest`.
- **`EstateLogic`** — inheritance policy (`activeParty` clock-reset rule + `verifyClaim`
  inactivity check); estate state stays in `Ledger`; call sites updated directly (no
  delegators — both were Ledger-internal). Guarded by `EstateAttackTest`.

Next, same pattern: Governance (proposal lifecycle), Recovery (guardian M-of-N),
Beacon (commit-reveal). `Ledger`: 1640 → 1275 lines so far.

## Step 2 — extract leaf subsystems behind interfaces, one at a time

Order by coupling to the state root, least first. Each move: codec already owns the
bytes → the subsystem owns only logic + in-memory state → golden vectors stay green.

| Module            | Owns                                            | State-root coupling |
|-------------------|-------------------------------------------------|---------------------|
| `Accounts`        | balances, nonces, transfers                     | high (core tail)    |
| `Staking`         | stake, unbonding, slashing/tombstone, rewards   | high                |
| `Governance`      | proposals, votes, timelock, param clamps        | medium              |
| `Beacon`          | commit-reveal RANDAO                             | medium              |
| `Estate`          | inactivity claim / inheritance                  | low                 |
| `Bridge`          | custodian M-of-N, oracle, reserve               | low                 |
| `ClusterShards`   | 16-shard commitment, RS erasure roots, geo tier | low                 |

`Ledger` becomes a thin coordinator wiring these together; `commitBlock` stays the
single state-transition entry point (the existing invariant). Each extraction is its
own PR, green CI required.

## Step 3 — enforce it

Once split, a simple architecture test (no subsystem imports another’s internals;
only `StateRootCodec` serializes) keeps it from re-monolithizing.

## Sequencing

Steps are independent PRs in this order: **0 (golden vectors) → 1 (codec) → 2
(subsystems, low-coupling first) → 3 (guard)**. Do not start step 2 before step 0 is
green — moving state-bearing code without pinned byte vectors is how you ship a fork.

---

## Scope vs. depth (the breadth critique)

The breadth — PQ crypto, DKG, bridges, inheritance, geo tiers, erasure coding — is
real and each is its own research area. Two honest points:

1. **The network is no longer just a state-machine smoke test.** A live 4-node
   validator cluster (`phantomchain-testnet-2`) was driven end-to-end: real ML-DSA
   quorum certificates, weighted-RANDAO proposer election, view-change on a downed
   proposer (commit at 3-of-4), a 2-of-4 partition that correctly **halted instead
   of forking**, and crash-recovery resync. That is consensus behavior, not a unit
   test. (It also surfaced two real liveness/robustness bugs — see issues #1/#2.)

2. **Depth is honestly tiered, not uniform.** `FRONTIER.md` already marks the
   research-gated items (threshold ML-DSA, proof-of-personhood, PUF attestation) as
   interim. The recommendation is to keep that discipline: treat **consensus +
   accounts + staking** as the production core (deepen + decompose per above), and
   keep **bridge / DKG / estate / geo-premium** as clearly-labeled experimental
   modules behind the same `commitBlock` boundary — not as equal-confidence claims.
   Decomposition (above) is what lets the core be deepened without the experimental
   breadth dragging on its audit surface.
