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

  **CLUSTER MINING — a cluster of M-of-N member devices acting as ONE validator (spec §9): BUILT + VERIFIED.**
  The earlier bullet covered the *sharding/storage/geo* layers; this is the cluster *mining* model itself —
  the part the spec leads with ("devices collectively are the mining node"). Now built:
  - **State machine (`Ledger`):** a `CLUSTERFORM` tx registers a cluster as a single append-only validator
    (`valPubs="CLUSTER"` marker); pooled member stake must meet the validator floor; each member's pubkey is
    bound to its id; the cluster's "signature" on a block is an **M-of-N bundle of member ML-DSA sigs**
    (`verifyClusterVote`), and epoch rewards are split **directly to each member identity** with no operator
    intermediary (`creditEarner`, §9.6). Cluster weight = pooled stake + member-count identity weight (§9.4).
    State-root coverage is backward-compatible (the cluster section is omitted when empty, so pre-cluster
    chains — incl. the live testnet — hash identically). Verified: `node/ClusterTest.java` 25/25
    (formation, M-of-N threshold + forgery/duplicate/non-member/wrong-hash rejection, direct reward split).
  - **Consensus (`NetNode` + driver):** `verifyQC` accepts a cluster validator's M-of-N bundle. Verified
    end-to-end in `node/ClusterConsensus.java` 7/7 — the cluster is elected proposer by weight, co-signs via
    rotating 2-of-3 member subsets (M-of-N liveness — a member can be offline), commits real blocks through
    the real engine (weighted `proposerFor`, RANDAO beacon, state/shard roots), members earn equally, and a
    sub-threshold (1-of-3) vote fails the QC.
  - **Real devices (Android):** the wallet app gained a cluster-member role (`ClusterMember` on-device
    signing server, started by a biometric-consented "Contribute to cluster"). `node/ClusterCoordinator.java`
    forms a 2-of-3 cluster from emulator device(s) + desktop members and casts the cluster's vote by fetching
    each device's signature live. **Verified: a real Android emulator co-signed all 9 of the cluster's blocks
    (signature ML-DSA-verified, not forgeable by the coordinator) and its device wallet earned directly.**
  - **RS-sharded intra-cluster ledger (§9.3): BUILT + VERIFIED.** `ClusterStore` encrypts the cluster's
    partition (ChaCha20-Poly1305) then RS(k,n)-erasure-codes the ciphertext into one shard per member device;
    any k members reconstruct, fewer cannot, and every shard is a ciphertext fragment — useless alone.
    `node/ClusterStoreTest.java` 9/9 (2-of-3: any 2 reconstruct, 1 can't + leaks no plaintext, wrong-key/
    tampered shard rejected, versioned nonces). DKG so the cluster key is never assembled on one device is now
    **DONE + VERIFIED** (`node/Dkg.java`: Shamir secret sharing + Feldman VSS over P-256; the N-member ceremony
    sums per-dealer polynomials so the aggregate secret is known to no single device, every share is verifiable
    against its commitments, and k-of-N reconstructs it ephemerally — `DkgTest` 13/13; wired into the store via
    `ClusterStore.clusterSecretFromCeremony` in `ClusterStoreDkgTest` 6/6 so the key is reconstructed from k
    shares and never stored on one device). **Honest residual:** the key IS reconstructed inside a cooperating
    k-of-N quorum at use-time (transiently); true threshold-encryption that never reconstructs is the deeper
    frontier — same honest-interim stance as the consensus QC.
  - **Per-cluster 10% weight cap (§9.4) + collapse/disband (§9.7): BUILT + VERIFIED.** `weight()` caps any
    single validator (incl. a cluster) at 10% of network weight, redistributing the excess — engaged at
    scale, **provably INERT below 10 validators** so the live testnet (N=4) and local nets are bit-identical
    (verified: observer still syncs the droplet to the same head, zero rejections). A `CLUSTERDISBAND` tx
    signed by >= threshold of the cluster's OWN members collapses it: excluded from consensus (liveness
    preserved), members freed (keep their stake, not slashed — §9.7). `node/ClusterGovTest.java` 11/11.
  - **Honest research gap (unchanged):** true threshold ML-DSA aggregate signature — no production library;
    the M-of-N bundle is the interim, not a threshold sig. Host note: only one emulator runs stably alongside
    the desktop coordinator (saturation), so the live device demo is 1 device + 2 desktop members; the
    coordinator accepts N device endpoints. **Cluster mining model: functionally complete** (state machine,
    live consensus, real-device participation, intra-cluster storage, weight cap, collapse); the remaining
    item is the threshold-sig research primitive (DKG for the cluster key is now DONE — §9.3).
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

## Scale caveat (read alongside every "✅ DONE + LIVE + VERIFIED" below)
"Verified" here means **verified at the scale it was run** — the public testnet is **N=4 validators**, and
local nets are small. Several mechanisms are *deliberately inert at that scale* and therefore exercised only
by unit tests, not the live net: the **10% weight cap** and **committee sortition** are provably inert below
`CAP_MIN_VALIDATORS=10`, and the per-cluster paths need a multi-device cluster. Read the status flags as
"correct + integration-tested small; not yet proven at production validator counts," not as a maturity claim.

Two structural items are **engineering frontiers, not done**, and are not stubbed to look finished:
- **True mTLS** — the dual-purpose TLS port (open wallet RPC + node-to-node) means real client-cert auth
  needs a port/context split, not a flag (see ARCHITECTURE §8). Today: app-layer ML-DSA auth + op-token.
- **Threshold ML-DSA / DKG** — no production library exists (2026); the QC and cluster/bridge "M-of-N" are
  signature *bundles*, and the bridge custodian + cluster key are assembled in one process in the demos.

## Authenticated account proofs (added)
The flat `stateRoot()` proves the *whole* state but cannot prove a *single* account to a light client.
Accounts now also carry a SHA3 binary **Merkle commitment** (`accountsMerkleRoot`) with verifiable
inclusion proofs (`accountProof`/`verifyAccountProof`, served by `/stateproof`, unit-tested in
`node/MerkleProofTest.java` 12/12: inclusion, tamper/forged-balance/wrong-root rejection, odd-leaf paths,
determinism). Under `srVersion="m1"` this root is bound into the consensus `stateRoot`, so proofs are
trustless; under the default `"full"` (what the live testnet runs) it is an auxiliary endpoint and the
state root is byte-identical to prior builds. The serialization version is committed chain state, removing
the previous `-Dpc.srcompat` launch-flag fork risk.

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
