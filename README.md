# PhantomChain

[![CI](https://github.com/someamount2190/phantomchain/actions/workflows/ci.yml/badge.svg)](https://github.com/someamount2190/phantomchain/actions/workflows/ci.yml)

A post-quantum **PoS-BFT blockchain** with a self-custodial Android wallet. All cryptography uses
standardized post-quantum primitives via BouncyCastle — no classical ECDSA/RSA in the consensus or
identity path, and no hand-rolled crypto.

## Architecture

```
CLIENT / EDGE     Android wallet: biometric-gated Keystore seal, CA-pinned TLS RPC, QR backup
SERVER / MESH     Validators (NetNode): BFT-lite consensus, P2P discovery, RPC, economics
STATE MACHINE     Ledger: pure deterministic state transition, committed via a state root per block
PRIMITIVES        PhantomCrypto: ML-DSA-65, ML-KEM-1024, SHA3/SHAKE, Argon2id, ChaCha20-Poly1305
```

The `Ledger` is a pure deterministic function of committed blocks (no network dependency — it is the
same class the Android app embeds). `NetNode` drives consensus but never mutates state outside
`commitBlock`. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full reference.

## What's built

- **Consensus** — BFT-lite with quorum certificates (`N−(N−1)/3`), proposer legitimacy checks, state-root
  agreement, view-change on dead proposers, single-slot deterministic finality.
- **Authenticated state** — every block commits to a full-state `stateRoot`; accounts additionally carry a
  SHA3 Merkle commitment with verifiable light-client inclusion proofs (`/stateproof`,
  `verifyAccountProof`), consensus-bound when a chain runs `srVersion="m1"`. The serialization version is
  committed chain state, not a launch flag, so nodes can't fork by being misconfigured.
- **Leader election** — commit-reveal RANDAO beacon (un-grindable; adversarially tested).
- **Identity ≠ key** — durable identities with rotatable device keys, root-authorized rotation, and
  M-of-N guardian recovery; plus estate/inheritance.
- **Economics & governance** — decaying capped emission, fee burn, staking with unbonding, slashing with
  permanent tombstone, snapshot-weighted timelocked governance.
- **Cluster model** — 16-shard commitment layer, Reed-Solomon (GF(256)) erasure-coded history sharding,
  heavy/light tiers, geo-coverage premium, dynamic `VALJOIN` membership.
- **Cross-chain bridge** — on-chain custodian M-of-N core + off-chain custodian daemon.

For the honest status of each layer — including the explicitly **interim** and **research-gated**
items (proof-of-personhood, threshold ML-DSA, PUF attestation) — see
[`docs/FRONTIER.md`](docs/FRONTIER.md).

## Design specs

- [`docs/phantomchain-design-spec.md`](docs/phantomchain-design-spec.md) — core protocol
- [`docs/phantomchain-identity-keys-recovery-v0.3.md`](docs/phantomchain-identity-keys-recovery-v0.3.md) — identity, keys, recovery
- [`docs/phantomchain-external-tx-layer.md`](docs/phantomchain-external-tx-layer.md) — cross-chain bridge
- [`docs/phantomchain-geo-coverage-premium.md`](docs/phantomchain-geo-coverage-premium.md) — geo coverage premium

## Build & run

JDK 17. Build and run the deterministic JVM test suite with the Gradle wrapper (deps resolved from
Maven Central — no vendored jars needed):

```
./gradlew runTests              # 25 deterministic suites (the CI gate)
./gradlew runIntegrationTests   # socket-binding NetNode tests (mTLS / read-peer split / eclipse)
```

CI (`.github/workflows/ci.yml`) runs the same on every push/PR. The networked cluster (real TCP, TLS
1.3, peer discovery, view-change, crash recovery, slashing) and the Android debug app are both
reproducible — full steps, endpoint reference, and gotchas are in [`docs/BUILD.md`](docs/BUILD.md).
Decomposition plan for the `Ledger` monolith: [`docs/REFACTOR.md`](docs/REFACTOR.md).
