# PhantomChain — Build Frontier & Tier Status

This document is the honest, current map of what is **built and verified**, what is **interim**, and
what remains a **research or large-engineering frontier**. It mirrors the design spec's own practice of
naming OPEN problems explicitly. Live testnet: `phantomchain-testnet-2`, 4 BFT validators on
`188.166.224.212:9090-9093` (write endpoints operator-token gated; read endpoints open).

---

## TIER 0 — Critical correctness & safety  ✅ DONE + LIVE
| Fix | Status |
|---|---|
| Reject non-positive amount / negative fee + `Math.addExact` overflow guard | ✅ verified (spend-from-nothing closed) |
| chainId domain separation in every signed payload (tx, action, vouch, block hash, votes-via-hash) | ✅ verified (no cross-chain/fork replay) |
| BFT-correct quorum `N−(N−1)/3` (was unsafe N/2+1) | ✅ verified (conflicting commits impossible) |
| `verifyQC` checks block came from the scheduled proposer for (height,view) | ✅ verified |

## TIER 1 — Production hardening  ✅ DONE + LIVE
| Item | Status |
|---|---|
| State root in header (Tendermint-style app-hash) — chain commits to *state*, not just txs | ✅ verified (divergence rejected next block) |
| Atomic persistence (temp + atomic rename) | ✅ |
| DoS bounds: bounded mempool, min-fee, block-size cap | ✅ |
| Governance: snapshot-weighted voting + turnout quorum + timelock + clamped param bounds | ✅ verified |
| Slashing: permanent tombstone + slashes unbonding queue + param floors | ✅ verified |
| Operator-token RPC gate, `/byz/equivocate` disabled in prod, 1 MiB body cap | ✅ verified |
| Signed `/announce` (anti-eclipse) | ✅ |
| Dynamic quorum over active validator set (carried from T1; liveness on committed set-shrink) | ✅ verified |

## TIER 2 — Spec features
| Feature | Status |
|---|---|
| **identity ≠ key** (durable identity, rotatable device keys, root authorizes) | ✅ DONE + LIVE + verified |
| **On-chain key rotation** (old key instantly revoked) | ✅ verified |
| **Guardian recovery** (M-of-N guardian approvals rotate a lost device) | ✅ verified |
| **Estate / inheritance** (inactivity-triggered; only outgoing actions reset the clock) | ✅ DONE + LIVE + verified |
| Split-key QR recovery (K_pw + mesh) | 🟡 INTERIM — wallet QR is currently password-only; **superseded** by on-chain guardian recovery (above), which realizes the spec's "mesh authorizes recovery" better than the interim QR. Mesh-share QR is a nice-to-have, not a blocker. |
| Wire rotation/guardians/estate into the Android wallet UI | ⬜ TODO (app work; on-chain layer + builders are done and tested via CLI) |
| Dynamic validator **JOIN** (a bonded key joins the validator set live) | ✅ DONE + verified — `VALJOIN` tx grows an append-only validator set (indices never shift, so existing QCs stay valid); nodes run as **observers** until promoted; TLS onboarding via the **retained cluster CA** (`mintcert`). A brand-new 5th node bonded 600k, joined at index 4, and **proposed + signed** blocks in 5-validator consensus. |
| Full governance lifecycle (review window, emergency protocol, reproducible-build attestation) | 🟡 PARTIAL — param-change governance with quorum+timelock done; the spec's full social/process lifecycle is product/ops work. |

## TIER 2 — Large engineering frontiers (designed, not built)
These are each multi-subsystem efforts the design spec defines but defers; building them to production
needs significant infra and, in places, the Tier-3 research primitives.

- **Cluster mining model** (Doc A §cluster, Doc D geo-premium): **dynamic validator membership DONE; state
  sharding COMMITMENT LAYER DONE+LIVE** (16 shards, shard-root Merkle in every header, verifiable
  light-client `/shard` proofs) **and storage/history-sharding DONE+LIVE** (nodes prune unassigned archived
  block bodies, R=2 redundancy, trustless on-demand `/block` reconstruction verified vs committed hash — "no
  single device holds the full ledger"), **geo-coverage premium DONE+LIVE** (opt-in region_id; sparse-region
  validators earn `min(2.5,1+0.2/(density+0.1))`× weight — verified a lone-region validator gets boosted
  share), and **heavy/light tiers DONE+LIVE** (light validators store no archived bodies; verified a light
  node holds 0/6 archived yet still validates/votes), and **RS(k,n) erasure coding DONE+LIVE** (`ReedSolomon`
  GF(256) Cauchy MDS codec, self-tested 500×; each node stores only its RS shard of archived history, any
  k=2 of n=4 reconstruct, verified vs committed hash). **The cluster model is now complete.** Original frontier note: Reed-Solomon erasure-coded ledger shards,
  heavy/light device tiers, 10% per-cluster cap, geographic coverage premium with RTT verification,
  cluster collapse handling. *Status:* **dynamic validator membership is now built** (VALJOIN, above) — the
  "bring yourself to the mesh" core. What remains is the SHARDING/geo layer: the current chain is
  full-replication (every validator holds the whole ledger), which is correct but not sharded. Erasure
  coding + RTT-attested geo-verification is a large distributed-systems build; the weighting math
  (`0.6·√stake + 0.4·identity`) is already in `weight()`. The shard/geo layers are the remaining frontier.
- **Cross-chain bridge / external tx layer** (Doc C): **DONE end-to-end via existing engineering.** On-chain:
  custodian M-of-N set, BRIDGE_RESERVE, SHAKE-256 ext-addresses (`/extaddr`), `BRIDGE_OUT` (lock) + `BRIDGE_IN`
  (M-of-N attested release, replay guard) + `ORACLE` (median-of-custodian rate feed). **Off-chain custodian
  SERVICE built** (`BridgeCustodian` daemon): watches an external-deposit feed → posts M-of-N BRIDGE_IN,
  watches on-chain locks (`/bridge/outs`) → external release, posts signed rate attestations to the median
  oracle. Verified end-to-end: deposit→mint, lock→release-observed, oracle median, conservation. *Remaining
  is engineering-with-existing-tools (not research):* distributed custodians (each its own HSM key + P2P to
  assemble approvals; the demo holds the committee in one process), DKG for the custodian key, real
  external-chain JSON-RPC integration (replace the deposit-feed file), and zk-STARK privacy proofs (optional;
  STARK libraries exist). The custodian set is still the explicit trusted / non-PQ surface by design.

## TIER 3 — Research-gated (interim mechanisms + honest gaps)
| Item | Current state | Honest gap |
|---|---|---|
| **Proof-of-personhood / Sybil resistance** [OPEN-ID-01] | Pluggable social web-of-trust **VOUCH** + **stake-cost hardening** (existing engineering): admission to `verified` now also requires a locked `identityBond` (governable; 0 = vouch-only), so N Sybil identities cost N×bond and withdrawing the bond forfeits admission (`tryAdmit`, UNBOND revoke). Unit-verified (`node/SybilTest.java`, 6/6). Admission gates the 40% identity weight. | Strong one-person-one-identity without a biometric DB is *unsolved in the spec itself*. Stake-cost raises the Sybil *price* but is not *uniqueness* (a wealthy attacker can still bond many) — it is hardening, not a solution. VOUCH stays collusion-vulnerable. The admission mechanism is pluggable: a future biometric-uniqueness or ZK-personhood proof drops in as a new admission tx without touching consensus. |
| **Threshold ML-DSA** | Multisig quorum-certificate (N separate ML-DSA sigs) — works, BFT-correct. | No production threshold-Dilithium library exists (2026). The QC is functionally equivalent for safety; it just doesn't compress to one aggregate signature. Interface is ready to swap. |
| **PQ-VRF leader election** | ✅ **ENGINEERED-AROUND via commit-reveal RANDAO** (eth2-proven, existing engineering). Each proposer reveals the secret it committed in its *prior* block and commits the next; the beacon folds `beacon = sha3(beacon \| reveal)` and seeds the weighted proposer. Reveals are bound by an on-chain commitment (`commits[validator]`), verified in both `commitBlock` and `proposalLinks`, and beacon + commitments are covered by `stateRoot`. The per-node secret is **derived from the validator's ML-DSA key** so its `commit0` (commitment to the first reveal) is published at keygen and **bound at genesis + `VALJOIN`** — the first reveal is no longer free. The genesis beacon is the **mix of all founders' `commit0`s**, not a known `ZERO32`. `beaconCtr` is persisted and resynced from the chain on restart. Verified locally + LIVE on testnet-2, and adversarially: `AdversaryTest` (garbage/replayed/wrong-index/foreign/empty reveals rejected) + `GenuineAdversaryTest` (20k freely-chosen first reveals all rejected → **grind CLOSED**). | Residual is now small and characterized: (a) the inherent RANDAO **1-bit reveal/withhold** choice each proposal (forfeits a turn to bias one bit); (b) a **founder** could key-grind its own `commit0` during the genesis ceremony before the initial beacon is fixed (trusted-setup assumption) — an untrusted `VALJOIN`er cannot, since it commits before knowing the beacon at its future first-proposal height. A true PQ-VRF removes even (a)/(b) but is research-grade (no prod PQ-VRF library, 2026; "sign-as-VRF" fails because ML-DSA sigs aren't unique → grindable). |
| **Biometric fuzzy-extractor** | Wallet uses a biometric-**gated** Android Keystore seal (real BiometricPrompt + StrongBox-class key sealing the seed). | The spec's "finger regenerates a stable ≥128-bit key across devices" extractor does not exist at acceptable FRR; this is the documented deprecation trigger for the interim QR recovery. |
| **PUF / manufacturer-independent attestation** [OPEN-05/10] | Trust root is the device secure element. | PUF-native silicon not deployable; research direction only. |

---

## Summary
The **monetary + consensus + identity core is built, hardened, and live**: a post-quantum PoS-BFT chain
with chainId-bound signing, BFT quorum, state-root commitment, decaying emission, fees, staking,
slashing-with-tombstone, governance (quorum+timelock), social-vouch personhood, **self-sovereign accounts,
identity≠key with on-chain rotation + guardian recovery, and estate/inheritance** — all verified on a
4-validator public testnet, with a CA-pinned wallet (Android APK) that signs over TLS.

The **cluster model** (sharding/geo/RS) and the **cross-chain bridge** are now built via existing
engineering, and three of the four research-gated primitives have production-grade engineer-arounds:
threshold ML-DSA → multisig quorum certificate, biometric extractor → biometric-gated Keystore seal, and
**PQ-VRF → commit-reveal RANDAO beacon** (eth2-proven, verified across 67 blocks + a node restart). What
genuinely remains research-grade is **strong proof-of-personhood** (one-person-one-identity without a
biometric DB is unsolved in the spec itself; VOUCH is the honest-but-soft interim) and **PUF-native
attestation**. These are documented honestly rather than stubbed, because the integrity of the project
rests on not overclaiming — the same principle the design spec applies to its OPEN problems.
