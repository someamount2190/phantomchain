# PhantomChain

[![CI](https://github.com/someamount2190/phantomchain/actions/workflows/ci.yml/badge.svg)](https://github.com/someamount2190/phantomchain/actions/workflows/ci.yml)

A **research implementation** of a post-quantum PoS-BFT blockchain — a from-scratch, working reference
for quantum-safe consensus and recoverable on-chain identity, running as a live 4-validator testnet.
It is **not** a product and has no token; it exists to explore the design and to be read.

All cryptography uses standardized post-quantum primitives via BouncyCastle (ML-DSA-65, ML-KEM-1024) —
no classical ECDSA/RSA in the consensus or identity path, and no hand-rolled crypto.

## Two ideas worth taking

The chain as a whole is a learning exercise, but two pieces stand on their own and are the most
portable part of this work:

- **Recoverable post-quantum identity** — identities are decoupled from keys (*identity ≠ key*): a
  durable on-chain identity with rotatable device keys, instant on-chain revocation, **M-of-N guardian
  recovery** of a lost device, and inactivity-triggered **estate / inheritance**. It attacks the single
  worst UX failure in crypto — *lost key means lost funds* — at the protocol layer, and it's
  post-quantum. Spec: [`docs/phantomchain-identity-keys-recovery-v0.3.md`](docs/phantomchain-identity-keys-recovery-v0.3.md).
- **PQ-native consensus signatures** — the post-quantum signatures sit in the **quorum certificates
  themselves**, not only in user transactions. That is the one property an incumbent chain cannot
  cheaply retrofit — it would have to hard-fork and re-stake its entire validator set. The interesting
  engineering is making ML-DSA's ~3.3 KB signatures workable inside a QC.

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

## Status & limits

This is research, reported honestly. The full, current map — what is **built and verified**, what is
**interim**, and what is a **research frontier** — lives in [`docs/FRONTIER.md`](docs/FRONTIER.md). The
short version:

- **Live:** `phantomchain-testnet-2`, 4 BFT validators on `188.166.224.212:9090-9093` (read endpoints
  open; writes operator-token gated). Core safety (BFT-correct quorum `N−(N−1)/3`, per-block state root,
  chainId domain separation in every signed payload), the identity/rotation/guardian-recovery/inheritance
  layer, staking/slashing/timelocked governance, and dynamic validator `VALJOIN` are all built and verified.
- **The honest caveat:** the BFT consensus is **bespoke** — which is exactly where chains lose funds. A
  real liveness-wedge bug (votes persisted before commit could deadlock a height across restart) was found
  and fixed; the durable lesson is that safety-critical consensus wants a vetted engine, not a hand-roll
  ([`docs/CONSENSUS-VIEWCHANGE.md`](docs/CONSENSUS-VIEWCHANGE.md)).
- **Research-gated / not claimed:** proof-of-personhood, threshold ML-DSA, PUF attestation — named as
  frontiers, not shipped.
- **Security is by design and review, not economics.** A testnet has no real stake securing it; nothing
  here should be read as production-ready or as an invitation to put value on it.

## What I learned / would do differently

- **Hand-rolling BFT was the highest-risk decision.** It worked and it taught the internals, but the
  liveness wedge is the receipt: next time the safety-critical core gets a vetted/formally-verified engine,
  and the novelty goes everywhere else.
- **Post-quantum reshapes the data plane, not just the threat model.** ML-DSA-65 signatures (~3.3 KB vs
  64 bytes for Ed25519) and ML-KEM ciphertexts change quorum-certificate design, block size, and storage
  economics. PQ is a permanent byte tax you design around, not a flag you flip.
- **Identity ≠ key was the idea that paid off.** Guardian recovery and inheritance solve a problem people
  have *today*, independent of the quantum thesis — and they're the part of this work most worth reusing.

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

## License

Licensed under the **Apache License, Version 2.0** — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
The patent grant is deliberate: Apache 2.0 gives every user an explicit, irrevocable patent license to
the post-quantum cryptography and consensus implemented here (and terminates it for anyone who brings a
patent suit over the Work) — protection a permissive license without a patent clause (e.g. MIT) does not
provide.
