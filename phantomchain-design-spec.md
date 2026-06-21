# PhantomChain
## Design Specification — Draft v0.2
### Post-Quantum Native Blockchain / Two-Layer Architecture / Biometric Hardware Identity

---

**Classification:** Working Design Document  
**Version:** 0.2  
**Date:** June 2026  
**Status:** Active Design — Open Problems Enumerated  
**Supersedes:** v0.1

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Core Principles](#2-core-principles)
3. [Threat Model](#3-threat-model)
4. [Two-Layer Architecture](#4-two-layer-architecture)
5. [Physical Layer](#5-physical-layer)
6. [Server Layer](#6-server-layer)
7. [Biometric Identity](#7-biometric-identity)
8. [Device Recovery](#8-device-recovery)
9. [Cluster Mining Model](#9-cluster-mining-model)
10. [Device Contribution Market](#10-device-contribution-market)
11. [Developer Confirmation Protocol](#11-developer-confirmation-protocol)
12. [Secure Infrastructure](#12-secure-infrastructure)
13. [Consensus & Finality](#13-consensus--finality)
14. [Tokenomics](#14-tokenomics)
15. [Supply Chain Model](#15-supply-chain-model)
16. [Estate & Inheritance](#16-estate--inheritance)
17. [Open Problems](#17-open-problems)
18. [Appendix A — Closed Problems](#appendix-a--closed-problems)
19. [Appendix B — Cryptographic Standards](#appendix-b--cryptographic-standards)

---

## 1. Abstract

PhantomChain is a post-quantum native Layer 1 blockchain with a two-layer architecture that separates cryptographic identity from operational software. The physical layer — hardware-attested, biometrically bound, and version-locked — holds signing authority permanently. The server layer handles consensus, ledger continuity, and software evolution without ever touching the signing root.

Identity is derived from fingerprint biometrics using a fuzzy extractor inside a Trusted Execution Environment, producing a Dilithium-3 keypair that never leaves the device. Balance is maintained by the server mesh and attributed to the hardware-attested identity across all physical layer versions.

Mining is performed by clusters of human-enrolled devices. There are no separate validators, miners, or stakers — every contributing device is a mining node. The network is a mesh of real people contributing real hardware with explicit biometric consent.

No central authority. No updatable firmware on the trust root. No ECDSA anywhere. No seed phrases. No capital monopoly. No anonymous Sybil attacks.

**The two statements that define the system:**

> Your finger is your wallet.

> Every other blockchain says: bring your capital. PhantomChain says: bring yourself.

> This document is a living design specification. It describes the architecture as designed, not as deployed. Sections marked [OPEN] denote unsolved problems addressed in subsequent design iterations.

---

## 2. Design Philosophy & Core Principles

### 2.1 Philosophy

PhantomChain is built on a fundamental reorientation of what a blockchain is for.

Every blockchain before this one asked the same question: how do we secure capital? The answer was always the same — make attacks expensive through proof of work or proof of stake. The atomic unit was always a token. People were an afterthought.

PhantomChain asks a different question: how do we secure people? The atomic unit is a human being. Capital follows from that, not the other way around.

**On identity:**
Identity is not a username. It is not a seed phrase. It is not a wallet address that can be copied or stolen or forgotten. Identity is the person — irreducible, non-transferable, physically present. Your finger is your wallet because you cannot lose yourself.

**On capital:**
Capital matters, but it does not define participation. A person with one token and a person with a million tokens are both one person. They have one identity, one vote, one presence in the network. Capital buys stake weight, not humanity weight. Those are different things and they will always be different things in this system.

**On quantum resistance:**
The cryptographic decisions made today will be attacked by hardware that does not yet exist. We build for that adversary now, not later. Every primitive is post-quantum by default. There is no migration path from ECDSA because we never used it. The threat model includes nation-state actors with decade-long time horizons.

**On governments and regulation:**
PhantomChain is not built to evade governments. It is built to make the government's legitimate needs achievable without compromising everyone else's privacy.

Traditional compliance is surveillance by default — collect everything, store it, hope it doesn't get breached. It always gets breached. PhantomChain's compliance model is different: nothing is anonymous, everything is traceable under legal process, and no mass surveillance database exists to be stolen.

Every actor on the network is a real human with a permanent non-repudiable identity. No anonymous wallets. No throwaway addresses. If law enforcement has a warrant and a genuine reason, the trail exists and it is permanent. What doesn't exist is a database of every citizen's financial life sitting on a server waiting to be harvested.

We are cooperative with legitimate legal process. We are not cooperative with mass surveillance. That distinction is a design principle, not a legal strategy.

**On decentralization:**
Decentralization is not the goal. It is the consequence of building a human network. When the atomic unit is a person and identity cannot be manufactured or purchased, decentralization emerges from participation. It cannot be gamed by capital because capital does not equal identity. It cannot be gamed by Sybil attack because Sybil attacks require fake identities and fake identities require fake fingers.

**On trust:**
The system is designed so that trust is never required — only verification. Your keys never leave your body. Your identity is derived from what you physically are. The code that runs on your device is attested by hardware. The release that updates the network is signed by a specific finger. At every layer, the question is not "do you trust this?" but "can you verify this?" The answer is always yes.

**On manipulation resistance:**
PhantomChain cannot be easily manipulated because its resistance is structural, not policy-based. Capital cannot buy dominant governance weight. Voters cannot be manufactured. Validators cannot be captured by accumulating stake. There is no central custody pool to weaponize, no anonymous coordination possible, no back-room governance. Every actor is a real person with a permanent on-chain identity and a biometric signature on everything they do. Manipulation requires corrupting real humans, not buying enough tokens.

**On whales:**
Capital is welcome. It is not sovereign. A whale enrolls, holds large stake, contributes to clusters, and earns proportionally — but three structural mechanisms prevent dominance. √stake weight compresses capital advantage at every scale: 100x the stake yields 10x the weight, not 100x. The 10% hard cap is absolute regardless of stake size. And 40% of consensus weight is identity weight, which cannot be purchased at any price. A whale's capital buys a seat at the table. It does not buy the table.

**On dilution as a feature:**
A cartel that forms at launch might control 30% of enrolled identities and 40% of stake. But their identity share is fixed to the number of real people they control. As the network grows from thousands to millions, their percentage of total identity weight approaches zero. Their stake percentage also dilutes unless they continuously inject capital to keep pace with new deposits — but new deposits come from new users earning and holding, not just whales.

In proof-of-work and proof-of-stake, a cartel that controls 40% of hash rate or stake at launch can maintain or grow that share by reinvesting rewards. Hash rate and stake scale with capital, and capital compounds. In PhantomChain, a cartel cannot scale its identity weight beyond the humans it controls. Those humans are a finite set. As the network grows organically, the cartel's relative power shrinks automatically — no action required from honest participants.

This is why bootstrapping with founder-operated infrastructure is acceptable. Even if the founder initially controls a large share of weight, that share dilutes as real users enroll. The system does not require perfect decentralization at genesis — it requires a growth path to decentralization. Dilution provides that path automatically.

**On growth:**
Every person who enrolls becomes infrastructure. They are simultaneously a node, a voter, a miner, and a holder. Their participation increases security, decentralization, governance resilience, and network value at the same time. As the network grows, the identity weight component of consensus grows with it — making capital weight proportionally less dominant over time. The network becomes harder to manipulate as it scales, not easier. Growth and security compound together. This is the inverse of every existing blockchain, where growth tends to attract capital concentration and governance capture.

The value proposition and the security model are the same thing. People enroll because they want secure self-custody. Their enrollment makes the network more secure. That attracts more people who want the same property. There is no artificial incentive needed — the system is its own growth mechanism.

---

### 2.2 Core Principles

| Principle | Statement |
|---|---|
| One person, one wallet | One human = one fingerprint = one wallet = one device = one identity |
| Biometric sovereignty | Identity cannot be transferred, purchased, delegated, or manufactured |
| Physical layer immutability | Cryptographic primitives and signing authority never change |
| Server layer adaptability | All operational parameters are updatable via governance |
| Human network | The atomic unit of the network is a person, not a token |
| Consent-first contribution | No device participates without explicit biometric confirmation |
| Transparent estate | Death is a graceful transition, not a catastrophic loss |
| Democratic governance | One person, one vote — capital cannot buy more voice |
| Post-quantum by default | Every primitive chosen for the adversary that does not yet exist |
| Cooperative with legal process | Traceable under warrant — not surveillance by default |
| Trust through verification | No layer of the system requires trust — every layer is verifiable |
| Decentralization as emergence | Decentralization is the consequence of human participation, not an enforced parameter |
| Manipulation resistance by design | Every structural attack vector fails at the architecture level — not at the policy level |
| Security compounds with growth | The network becomes harder to manipulate as participation increases, not easier |
| Sovereign self-custody | Users are their own custody solution — no exchange or third party required |
| Growth through value alignment | The security model and the growth model are the same thing |
| Dilution as a feature | Every new honest participant reduces the relative power of any cartel — automatically, without intervention |
| Capital welcome, not sovereign | Whales participate and earn proportionally — but cannot dominate governance, consensus, or identity weight |

---

## 3. Threat Model

### 3.1 Primary Adversaries

- Quantum-capable state actors executing harvest-now-decrypt-later attacks on stored transaction data
- Nation-state supply chain attackers (Lazarus Group class) targeting developer infrastructure and signing pipelines
- Financial adversaries seeking to compromise signing authority through software update vectors
- Physical coercion actors targeting known holders of high-value balances
- TEE firmware attackers exploiting chip manufacturer trust relationships
- Sybil attackers attempting to manufacture identity weight through mass enrollment
- Malicious cluster operators exploiting contributor reward distribution

### 3.2 Attack Vectors Explicitly Neutralized

| Attack Vector | Mitigation |
|---|---|
| ECDSA key extraction via Shor's algorithm | No ECDSA anywhere. Dilithium-3 throughout. |
| Supply chain compromise of update pipeline | Physical layer immutable. Server updates cannot reach signing keys. |
| Dark Skippy firmware extraction | Keypair derived inside TEE from biometric. Never stored, never exportable. |
| Malicious app impersonating wallet | Hardware attestation proves binary integrity at runtime. |
| Address poisoning | Addresses bound to hardware-attested public key hashes. |
| Developer social engineering | Open governance — no single developer has unilateral authority. Physical layer operations require community vote. |
| Seed phrase theft | No seed phrase exists. |
| Exchange hack | No exchange holds signing keys. Physical layer is sovereign. |
| Remote key exfiltration | Key derived on demand inside TEE, never stored in exportable form. |
| Sybil via multiple devices | One-person-one-device enforced by biometric uniqueness at server mesh. |
| Capital concentration in governance | One person, one vote. Capital weight capped. Identity weight non-purchasable. |
| Anonymous contribution fraud | Every contribution signed by biometric identity. Non-repudiable. |

### 3.3 Residual Risks

- **Chip manufacturer TEE backdoor** — PUF research direction, not yet deployable [OPEN-05]
- **Physical coercion** — user-layer operational security, outside protocol responsibility [CLOSED by design boundary]
- **Biometric degradation** — multi-finger enrollment resolves most cases [CLOSED]
- **Developer identity compromise** — threshold multisig governance, air-gapped signing hardware
- **Death without beneficiary** — community treasury recovery after extended inactivity [CLOSED]

---

## 4. Two-Layer Architecture

### 4.1 The Principle

Separation of cryptographic authority from operational software. These two concerns have different security requirements, different update cadences, and different threat models. Conflating them is the root cause of every major supply chain attack in crypto history.

```
┌─────────────────────────────────────────────────────┐
│              PHYSICAL LAYER  (immutable)            │
│  Biometric fuzzy extractor → Dilithium-3 keypair    │
│  TEE-sealed key derivation  → Hardware attestation  │
│  Transaction signing        → Balance commitment     │
│  Fixed cryptographic primitives  (NIST 2024 final)  │
│  One-person-one-device enforcement                  │
└──────────────────────┬──────────────────────────────┘
                       │  Attestation handshake
                       ▼
┌─────────────────────────────────────────────────────┐
│              SERVER LAYER  (updatable)              │
│  aBFT consensus             Validator coordination  │
│  Ledger & balance state     Fraud detection         │
│  Tokenomics parameters      Cluster management      │
│  Estate & inheritance       Market matching         │
│  Developer membership       Release escrow          │
└─────────────────────────────────────────────────────┘
```

### 4.2 Fixed vs. Updatable

| Concern | Physical Layer (immutable) | Server Layer (updatable) |
|---|---|---|
| Signing algorithm | Dilithium-3 — forever | N/A |
| Address derivation | SHA3-256 of public key — forever | N/A |
| Fee burn mechanism | Exists — forever | Burn rate parameters |
| Dual-weight validator model | Exists — forever | 60/40 ratio, caps |
| One-person-one-device | Enforced — forever | N/A |
| Emission schedule structure | Single token — forever | Exact curve, amounts |
| Consensus mechanism | N/A | aBFT parameters |
| Fraud detection | N/A | Heuristics, thresholds |
| Slashing parameters | N/A | Amounts, conditions |
| Inactivity periods | N/A | Durations, thresholds |
| Market parameters | N/A | Fees, minimums, rules |

### 4.3 Separation Invariants

- A server layer update cannot modify, read, or influence physical layer key material
- A physical layer version upgrade does not affect balance
- The attestation handshake protocol is fixed — server layer cannot redefine valid attestation
- Physical layer version changes require explicit threshold ceremony — hard forks by design
- Server layer parameter changes require 3-of-5 multisig governance — not validator stake vote
- One-person-one-device cannot be overridden by any server layer update

---

## 5. Physical Layer

### 5.1 Cryptographic Primitives

| Primitive | Algorithm | Purpose |
|---|---|---|
| Key Encapsulation | ML-KEM (Kyber-1024) | Encrypted session establishment |
| Digital Signature | ML-DSA (Dilithium-3) | Transaction signing — permanent identity |
| Signature Fallback | SLH-DSA (SPHINCS+) | High-value signing, conservative fallback |
| Symmetric Encryption | XChaCha20-Poly1305 | TEE-sealed storage, transaction payload |
| Hash | SHA3-256 / SHAKE-256 | Address derivation, commitment scheme |
| Biometric KDF | Multimodal fuzzy extractor + SHAKE-256 | Fingerprint + face → fused key material |
| Threshold Signature | Dilithium-3 threshold scheme | Cluster block submission |

All primitives are NIST 2024 finalized standards. No ECDSA. No RSA. No secp256k1.

### 5.2 Identity Derivation

Identity is derived from two independent biometric modalities — fingerprint and face — both processed inside the TEE simultaneously. Neither modality alone is sufficient. The fused output is what produces the keypair.

```
Fingerprint scan          Face scan (front camera)
      │                         │
      ▼  (inside TEE)           ▼  (inside TEE)
Fuzzy extractor           Fuzzy extractor
  minutiae + ridge map      facial geometry + landmarks
  Reed-Solomon ECC          Reed-Solomon ECC
  helper data stored        helper data stored
      │                         │
      ▼                         ▼
Stable key material A     Stable key material B
  (256-bit)                  (256-bit)
      │                         │
      └──────────┬──────────────┘
                 ▼
        SHAKE-256 domain-separated fusion
          H("fingerprint" ∥ A ∥ "face" ∥ B)
                 │
                 ▼
        Fused biometric seed (256-bit)
                 │
                 ▼
        Dilithium-3 keypair derivation
                 │
          ├──► Private key  (TEE-sealed, never exported)
          │
          └──► Public key → SHA3-256 → Address
```

**Why two modalities:**
Each modality independently protects against the other's failure mode. Fingerprint spoofing requires a physical artifact. Face spoofing requires a 3D model or live deepfake against liveness detection. Compromising both simultaneously against a live person with an attested device is a qualitatively harder attack. The fused key cannot be derived from either modality alone — both must be present at every signing event.

**Hardware requirement:**
Fingerprint sensor + front-facing camera with liveness detection. Standard on all modern smartphones. No external hardware required.

### 5.3 One-Person-One-Device Enforcement

The constraint is cryptographic, not policy-based.

```
Enrollment attempt
      │
      ▼
Fuzzy extractor produces key commitment from fingerprint
      │
      ▼
Server mesh checks commitment against global registry
      │
      ├──► Commitment exists → same person
      │    └──► Device migration flow (old device deregistered)
      │
      └──► Commitment new → new registration accepted
```

Two enrollments of the same finger produce the same key commitment. Duplicates are rejected by the server mesh. Identity cannot be manufactured, purchased, or split.

### 5.4 Hardware Attestation

On each session initialization the TEE produces an attestation report containing:

- Hash of the running binary
- Proof of genuine hardware enclave
- Session public key
- Timestamp-bound nonce

A modified binary produces a different hash — attestation fails, transaction rejected.

### 5.5 What the Physical Layer Owns Permanently

- Hardware-bound Dilithium-3 keypair — non-exportable, TEE-sealed
- Fuzzy extractor helper data — non-reversible to biometric
- Attestation signing key — hardware root, chip-embedded
- Transaction signing format — fixed, backward compatible forever
- Address derivation scheme — SHA3-256 of Dilithium-3 public key
- One-person-one-device rule — cryptographically enforced, not bypassable

---

## 6. Server Layer

### 6.1 Overview

The server layer handles everything that evolves: consensus, ledger state, tokenomics parameters, cluster management, estate processing, developer membership, release escrow, and the device contribution market. It holds the ledger. It cannot touch the signing root.

### 6.2 Ledger Model

Balance is keyed by hardware-attested public key hash — not software version, device model, or application version.

```
Hardware Attested Public Key Hash  →  Balance + Transaction History

Physical Layer v1  ──────────────────────────┐
Physical Layer v2  ──────────────────────────┤──► Same identity. Same balance.
Physical Layer v3  ──────────────────────────┘
```

### 6.3 Update Governance

**Server layer updates:**
- Any enrolled identity may propose a change via the open governance protocol (Section 11)
- 80% of enrolled identities must vote yes before any change is implemented
- Reproducible build generated from the approved diff — deterministic hash
- Build hash published on-chain before deployment
- Viral update propagation to all server nodes (Section 6.4)
- Automated rollback if consensus drops below threshold post-update

**Physical layer updates (hard fork):**
- Outside open governance scope — physical layer is immutable by design
- Requires community-wide migration announcement (90-day window)
- 75% supermajority validator ratification
- Compatibility bridge through server layer for previous versions
- Separate ceremony defined in Section 4

### 6.4 Viral Update Propagation

Server layer updates propagate automatically across the entire mesh without manual intervention on any node.

```
You sign release from any attested device, anywhere in the world
      │  (Tier 1 ceremony — fingerprint bound to build hash)
      ▼
Signed release hash published to server mesh
      │
      ▼
Running nodes detect: valid signature + version > current
      │
      ▼
Node pulls release, verifies build hash matches signed hash
      │
      ├──► Hash matches → update applies, node continues
      └──► Hash mismatch → update rejected, alert raised
```

Authority is the signature, not the version number. A node updates because it has verified your Dilithium-3 signature — not because it trusts another node's announcement. An unsigned release with a higher version number is ignored by every node on the network.

**Consequence:** a single fingerprint scan from anywhere in the world propagates a verified update across the entire server mesh. No SSH access to individual servers. No manual deployment coordination. No update window requiring your physical presence at infrastructure.

---

## 7. Biometric Identity

### 7.1 The Core Statement

Your body is your wallet. Identity is derived from two things you physically are — your fingerprint and your face. Neither can be lost, forgotten, or phished. Both must be present simultaneously to sign anything.

```
Enrollment:    finger + face  →  wallet created
Transaction:   finger + face  →  wallet signs
Recovery:      finger + face  →  wallet restored
Migration:     finger + face  →  wallet moves to new device
Contribution:  finger + face  →  explicit mining consent
```

Standard transactions may use fingerprint alone for UX convenience. High-value transactions, physical layer operations, and estate designations require both modalities. The threshold is a server layer parameter.

### 7.2 Fuzzy Extractor Design — Fingerprint

| Component | Function |
|---|---|
| Feature extraction | Minutiae points + ridge orientation map |
| Error correction | Reed-Solomon codes over feature vector |
| Helper data | Stored in TEE — enables reconstruction, not reversal |
| Key generation | SHAKE-256 over corrected feature vector → 256-bit seed A |
| Domain separation | "fingerprint" prefix — cannot collide with face output |

### 7.3 Fuzzy Extractor Design — Face

| Component | Function |
|---|---|
| Feature extraction | Facial geometry landmarks + depth map (liveness required) |
| Liveness detection | Anti-spoofing — rejects photos, screens, static masks |
| Error correction | Reed-Solomon codes over geometry vector |
| Helper data | Stored in TEE — enables reconstruction, not reversal |
| Key generation | SHAKE-256 over corrected geometry vector → 256-bit seed B |
| Domain separation | "face" prefix — cannot collide with fingerprint output |

### 7.4 Multimodal Fusion

```
Seed A (fingerprint)  +  Seed B (face)
              │
              ▼
  SHAKE-256("fingerprint" ∥ A ∥ "face" ∥ B)
              │
              ▼
       Fused 256-bit seed
              │
              ▼
  Dilithium-3 keypair — TEE-sealed, never exported
```

The fused key cannot be derived from either modality in isolation. An attacker with a spoofed fingerprint and no face, or a face photo and no fingerprint, derives nothing usable. Both must be presented live, simultaneously, on an attested device.

### 7.5 Multi-Finger Enrollment

All ten fingers enrolled at setup. Each finger independently derives seed A through its own fuzzy extractor. Face enrollment produces a single stable seed B. Any enrolled finger combined with a live face scan reconstructs the master keypair.

```
At enrollment:
  Each finger i derives Ai inside TEE
  Face derives B inside TEE
  Fused seed: SHAKE-256("fingerprint" ∥ Ai ∥ "face" ∥ B)
  Server mesh stores commitment hash of each fused seed separately
  Any single valid (Ai, B) pair reconstructs the master keypair

At signing:
  Present any enrolled finger + live face scan
  Derive (Ai, B) inside TEE
  Fused seed reconstructed
  Server mesh confirms commitment matches
  Transaction signed
```

Ten fingers × one face = ten independent signing and recovery paths.

**Degradation handling:**
- Temporary finger injury → use different finger
- Permanent finger loss → remaining fingers cover
- Face injury → re-enrollment of face authenticated by healthy finger
- Surgical amputation → doctor-assisted out-of-band recovery ceremony

### 7.6 Transaction Tiers by Modality Requirement

| Transaction Type | Required Modality |
|---|---|
| Standard transaction | Fingerprint only (UX convenience) |
| High-value transaction (above server layer threshold) | Fingerprint + face |
| Mining contribution consent | Fingerprint + face |
| Estate beneficiary designation | Fingerprint + face |
| Physical layer signing ceremony | Fingerprint + face + multi-finger sequence |
| Developer membership grant | Fingerprint + face |

All thresholds are server layer parameters — adjustable via governance.

### 7.7 Privacy Guarantees

- Raw biometric data never leaves the TEE
- Helper data for both modalities is computationally infeasible to reverse
- Server mesh holds only fused public key hash — no biometric data of any kind
- No central biometric database. No biometric escrow. No face recognition server.
- Face processing is entirely on-device inside TEE — no cloud inference

### 7.8 Enrollment Protocol

1. Three scans per finger, all ten fingers — fuzzy extractor computes helper data per finger
2. Five face scans across angles — fuzzy extractor computes helper data for face geometry
3. Liveness challenge confirmed — randomized blink/turn sequence, anti-spoofing verified
4. Fused keypair derived for each (finger, face) combination, sealed into TEE
5. Public key registered with server mesh via genesis transaction
6. Per-modality commitment hashes published to server mesh
7. Self-certifying — no authority required

**Hardware requirement:** Fingerprint sensor + front-facing camera with depth/liveness detection. Standard on all modern smartphones (iPhone Face ID class, Android face unlock with liveness). No external hardware required.

### 7.9 Periodic Biometric Refresh

Biometric data drifts over time. Fingerprints wear, faces age, injury alters features. Helper data computed at enrollment degrades in accuracy as the gap between stored template and current biometric widens. Periodic re-enrollment keeps helper data fresh and maintains low FRR.

Re-enrollment does not change the keypair. The same Dilithium-3 keypair is re-derived from the refreshed helper data — identity and balance are continuous.

```
Refresh due (server layer parameter — default: 12 months)
      │
      ▼
Wallet UI prompts: "Your biometric data is due for refresh.
 Scan your fingers and face to update."
      │
      ▼
User completes full enrollment scan (fingers + face)
      │  (same protocol as initial enrollment)
      ▼
New helper data computed inside TEE
      │
      ▼
Keypair re-derived — must match existing public key
      │
      ├──► Match → new helper data replaces old, refresh timestamp updated
      └──► No match → enrollment failure, recovery flow initiated
```

**Security properties of periodic refresh:**

- Stolen helper data has a bounded useful lifetime — expires at next refresh window
- Accumulated biometric drift is corrected before it causes signing failures
- Refresh itself is a liveness proof — confirms the enrolled person is still alive and in possession of the device
- Refresh window is a server layer parameter — adjustable by governance

**Interaction with estate inactivity timer:**

A completed biometric refresh resets both the refresh clock and the estate inactivity timer simultaneously. One scan. Two clocks reset.

---

## 8. Device Recovery

### 8.1 NFC Trusted Contact Recovery

Device loss is resolved through the NFC trusted contact system. The finger is the identity — any attested device can serve as a TEE to run the derivation.

```
Old device lost
      │
      ▼
User approaches trusted contact (NFC-capable attested device)
      │
      ▼
NFC tap initiates authenticated recovery session
      │
      ▼
User scans finger on trusted contact's device TEE
      │  (trusted contact is relay and witness, not authority)
      ▼
Fuzzy extractor derives same Dilithium-3 public key
      │
      ▼
Server mesh validates:
  ├──► Derived public key matches registered identity
  ├──► Recovery request signed by that key
  ├──► Trusted contact's device is attested
  └──► No concurrent recovery in progress (anti-replay)
      │
      ▼
New device provisioning token issued
      │
      ▼
User enrolls on new device — same keypair derived
      │
      ▼
Balance and identity fully restored
```

### 8.2 Anti-Abuse Properties

- Recovery requires physical presence at trusted contact with attested device
- Server mesh rate-limits recovery attempts per identity
- Recovery-in-progress flag prevents concurrent recovery attacks
- Anti-replay via session nonce
- Coercion requires: live finger + physical presence + attested device — three independent physical requirements

### 8.3 Recovery Governance

- Threshold: 1-of-N — any single enrolled trusted contact is sufficient
- Trusted contacts registered at enrollment — permanent, no revocation
- NFC physical presence + live biometric + attested device is sufficient security for 1-of-N threshold
- No on-chain registry complexity beyond the enrollment record

---

## 9. Cluster Mining Model

### 9.1 The Core Model

There are no separate servers, validators, or miners. Devices collectively are the mining node. The mesh of enrolled, identity-confirmed devices is the validator. Contributing to a cluster requires explicit biometric consent.

```
No central anchor server.

Device A (enrolled, consented) ──┐
Device B (enrolled, consented) ──┤
Device C (enrolled, consented) ──┼──► Collective mining node
Device D (enrolled, consented) ──┤
Device E (enrolled, consented) ──┘

The mesh IS the server.
The combined devices ARE the validator.
```

Devices participate at different responsibility levels based on capability:

```
Heavy (always-on laptops, servers):
  ├──► Full shard storage
  ├──► Transaction processing
  └──► Threshold signature participation — all epochs

Light (phones, intermittent devices):
  ├──► Identity weight contribution
  ├──► Transaction relay
  ├──► Lightweight shard fragment
  └──► Threshold signature when online
```

Heavier contribution earns proportionally more. The contribution market (Section 10) handles matching and pricing naturally.

### 9.2 Contribution Consent Flow

```
Device already enrolled in PhantomChain identity
      │
      ▼
User sees invitation to contribute to cluster
      │
      ▼
Explicit fingerprint confirmation — biometric consent
      │
      ▼
Device joins cluster as contributing peer
      │
      ▼
Contribution recorded on-chain under their identity
      │
      ▼
They earn proportional mining rewards directly
```

Consent is always revocable with a single fingerprint scan.

### 9.3 Cluster Internal Architecture

Each contributing device holds a shard of the cluster's ledger partition using Reed-Solomon erasure coding. No single device holds the complete ledger. The ledger exists only as the combined mesh — a single device in isolation holds an encrypted fragment that is cryptographically useless alone.

```
Device A holds:
  ├──► Ledger shard partition A (encrypted)
  ├──► Merkle proof of its shard's integrity
  └──► Its own identity and signing capability

Device B holds:
  ├──► Ledger shard partition B (encrypted)
  ├──► Merkle proof of its shard's integrity
  └──► Its own identity and signing capability

Combined mesh holds:
  ├──► Complete ledger — reconstructable from shards
  ├──► Full transaction history — distributed
  └──► Collective signing capability — threshold
```

Block submission uses a threshold Dilithium-3 signature scheme:

```
Cluster of N devices, threshold M-of-N

Transaction batch ready
      │
      ▼
M contributing devices sign with their keys
      │
      ▼
Threshold signature assembled
      │
      ▼
Cluster submits to global network as single validator
      │
      ▼
Global network verifies threshold signature
```

**Cluster collapse model:**

If devices drop below threshold — the cluster collapses. No rebalancing, no coordinator, no complex recovery protocol. Devices are freed to rejoin other clusters or reform. Resilience at the network level comes from cluster plurality — many independent clusters — not from redundancy within a single cluster. Collapse is a user coordination problem, not an architectural one. Fast, low-friction cluster formation (see 9.7) is the mitigation.

No misbehavior. No slashing. Clean termination.

**Single-device security properties:**

A stolen device yields one encrypted shard fragment (useless without the mesh) and one identity's signing capability (protected by TEE and biometric). The mesh is not compromised. The ledger is not exposed.

### 9.4 Mining Weight Formula

```
Cluster weight = (stake_component × 0.6) + (identity_component × 0.4)

stake_component     = √(cluster_total_stake) / Σ√(all_cluster_stakes)
identity_component  = cluster_enrolled_identities / total_network_identities

Hard cap: no single cluster > 10% total network weight
          excess redistributed proportionally

Geographic bonus: first cluster in a region earns uniqueness weight premium
Data center rule: clusters sharing physical infrastructure count reduced weight
```

**Why √stake and not linear stake:**

Linear stake weighting — even with a hard cap — concentrates influence. Empirical analysis across ten major blockchains shows linear PoS produces Nakamoto coefficients as low as 4, meaning four large validators can censor the network. Square Root Stake Weight (SRSW) compresses capital advantage: a cluster with 4× the stake gets 2× the weight, not 4×. Formally proven to improve Gini and Nakamoto coefficients by an average of 51% over linear models. [Motepalli & Jacobsen, arXiv:2504.14351; arXiv:2312.13938]

Identity weight stays linear because biometric identity is already one-person-one-unit — there is no compounding dynamic to correct. The asymmetry is intentional: √stake for capital, linear for humans.

**Why identity farming is not a viable attack:**

In systems without hardware-bound identity, Sybil attacks exploit sub-linear cost curves by manufacturing fake identities. PhantomChain's biometric enrollment is itself the Sybil resistance layer. Identity weight is bounded by the number of real enrolled humans. It cannot be manufactured, purchased, or split. [arXiv:2407.01844]

**Why the 10% hard cap is validated:**

IOTA enforces an identical 10% validator voting power cap with excess redistributed proportionally — live in production. The mechanism is independently justified. [IOTA Tokenomics Whitepaper, 2025]

### 9.5 One-Person-One-Cluster

A person's identity weight contributes to exactly one cluster at a time. Identity weight cannot be split across clusters simultaneously. Participation is a commitment.

### 9.6 Reward Distribution

Protocol distributes directly to each contributing identity. No cluster operator intermediary required.

```
Cluster earns X tokens this epoch
      │
      ▼
Per-device contribution score calculated:
  ├──► Uptime percentage
  ├──► Ledger shard availability
  ├──► Transaction relay volume
  └──► Consensus participation rate
      │
      ▼
Reward distributed proportionally to each identity's wallet
      │
      ▼
On-chain — transparent, auditable, non-disputable
```

Clusters may optionally vote to pool rewards internally — but this is a cluster governance decision, not a protocol requirement.

### 9.7 Cluster Formation

```
Initiator signs genesis cluster transaction with fingerprint
      │
      ▼
Cluster ID published on-chain
      │
      ▼
Others join — each with explicit fingerprint confirmation
      │
      ▼
Threshold agreed by founding members — signed on-chain
      │
      ▼
Cluster active when minimum threshold devices enrolled
      │
      ▼
Mining begins
```

### 9.8 Graceful Exit

```
User withdraws contribution — fingerprint confirmation
      │
      ▼
Final epoch rewards credited
Device returns to light client mode
On-chain withdrawal recorded
      │
      ▼
If remaining devices still meet threshold → cluster continues
If remaining devices fall below threshold → cluster collapses
  └──► Members rejoin other clusters or reform
```

---

## 10. Device Contribution Market

### 10.1 What the Market Is

A labor market, not a capital market. What participants sell is not computing power or capital — it is their participation as a human being, their device's contribution of time and resources, and their identity weight — which is uniquely theirs and cannot be replicated.

```
Supply:  People with devices willing to contribute
         Bounded by number of real human participants
         Cannot be manufactured or purchased

Demand:  Clusters needing more weight, redundancy, throughput
         Communities wanting to mine without sufficient devices

Price:   Discovered by the network based on cluster needs
         and contributor reputation history
```

### 10.2 Mesh Discovery Protocol

Discovery runs on the same adaptive relay and fetch transport as ShadowMesh. No central marketplace. No matchmaking server. The mesh itself is the discovery layer.

**Two flows, both native to the mesh:**

```
PUSH — Contributor announces availability:

  Contributor signs listing with fingerprint
    ├──► Available hours per day
    ├──► Contribution type (storage, bandwidth, compute)
    ├──► Minimum reward threshold
    └──► Geographic location (optional)
          │
          ▼
  Listing propagates outward through mesh relay
  Neighboring nodes forward to their neighbors
  Listing reaches clusters in proximity naturally
  Listing expires after defined TTL — re-signed to renew


PULL — Cluster broadcasts need:

  Cluster operator signs opening with fingerprint
    ├──► Devices needed
    ├──► Contribution requirements
    ├──► Reward share offered
    └──► Threshold configuration
          │
          ▼
  Opening propagates outward through mesh fetch
  Mesh routes toward nodes matching contribution criteria
  Contributors matching the opening receive it directly


MATCH — When listing meets opening:

  Contributor reviews cluster terms
          │
          ▼
  Fingerprint confirmation — explicit biometric consent
          │
          ▼
  Match transaction signed by both parties
          │
          ▼
  Written on-chain — immutable record of agreement
  Cluster threshold updated
  Contribution begins next epoch
```

**Properties of mesh-native discovery:**

- No central registry — no single point of failure or censorship
- Geographic proximity in relay naturally surfaces local contributors to local clusters
- Listings and openings are signed — cannot be forged or spoofed
- TTL expiry prevents stale listings polluting the mesh
- Same infrastructure as ShadowMesh — one physical deployment, shared transport layer

### 10.3 Reputation System

Every contribution attributed to a biometric identity. Reputation is real, portable, and non-transferable.

```
Contributor identity → on-chain contribution history:
  ├──► Clusters contributed to
  ├──► Uptime across all clusters
  ├──► Contribution score per epoch
  ├──► Withdrawal history (graceful vs abrupt)
  └──► Any disputes
```

High reputation → higher reward share negotiated. Low reputation → lower share or probationary acceptance. Reputation cannot be faked or transferred — it is attached to a biometric identity.

### 10.4 Device Categories

| Category | Primary Value | Market Premium |
|---|---|---|
| Always-on server | Compute + storage + uptime | High |
| Desktop/Laptop | Moderate compute, stable | Medium-High |
| Smartphone | Identity weight, intermittent | Medium |
| Raspberry Pi class | High uptime, low cost | Medium (niche) |
| High-bandwidth node | Network relay | Premium in sparse regions |
| Geographic premium node | First in region | Geographic bonus |

### 10.5 Cluster Operator Role

Some people will specialize in forming and managing clusters — onboarding participants, maintaining threshold health, optimizing reward distribution. They earn negotiated coordination fees paid by cluster members. This is a real economic role, separate from protocol rewards, transparent on-chain.

In deployment contexts like Zamboanga, cluster operators become local technical infrastructure leaders — a natural extension of the barangay council governance model.

### 10.6 Market Properties Unique to PhantomChain

- **Non-repudiation** — contributions biometrically signed, disputes resolved by on-chain record
- **Accountability** — bad actors identifiable and excludable, anonymous sabotage impossible
- **Trust premium** — long history of reliable contribution commands higher reward rates
- **Natural scarcity** — supply bounded by number of real humans, not capital

---

## 11. Open Governance Protocol

### 11.1 Philosophy

PhantomChain has no central authority. Governance is open, biometrically confirmed, and community-sovereign. The server layer evolves through a public proposal and vote mechanism where every enrolled identity participates. No single person, including the founder, can unilaterally change the system.

The physical layer remains immutable. Open governance applies to the server layer only.

### 11.2 Voting Weight

| Identity Class | Voting Weight |
|---|---|
| Founder | 10% |
| Trusted Developer (each) | 1–2% (set at admission) |
| Enrolled identity | Equal share of remaining weight |

The founder's 10% and developer weights are not permanent. Both are subject to reduction or removal by community vote through the same 80% threshold mechanism. Power migrates to the community by design.

As more developers are voted in, the weight per developer adjusts to maintain the total developer pool within a governance-defined cap. The community controls the cap.

### 11.3 Proposal Lifecycle

```
Any enrolled identity authors a proposal
  ├──► Description (plain language — what changes and why)
  ├──► Code diff (exact server layer lines affected)
  ├──► Impact statement (what breaks, what improves)
  └──► Author fingerprint signature
        │
        ▼
Mandatory review window opens (default: 14 days)
  ├──► Proposal visible to all enrolled identities
  ├──► Trusted developers publish public endorsement or rejection
  ├──► Community discussion on-chain, attributed to biometric identities
  └──► No voting during review window
        │
        ▼
Voting window opens (default: 30 days)
  ├──► Each enrolled identity votes yes/no with fingerprint confirmation
  ├──► Vote is public and attributed — no anonymous voting
  ├──► Running tally visible to all
  └──► Voting window cannot be extended or shortened
        │
        ▼
Threshold check
  ├──► 80% of total enrolled identities voted yes → proposal passes
  └──► Below 80% → proposal fails, no further action
        │
        ▼
If passed:
  Reproducible build generated from approved diff
  Build hash published on-chain
  Viral update propagation to all server nodes (Section 6.4)
```

### 11.4 The 80% Threshold

80% of all enrolled identities — not 80% of voters, not 80% of active users. The entire enrolled userbase is the denominator.

This threshold is deliberately high. The network attracts people who enrolled specifically for its security model. A proposal that meaningfully affects that model will mobilize them. A proposal that doesn’t matter to most users will not reach 80% and will not pass. The threshold is a natural filter, not a bureaucratic barrier.

Low participation kills a proposal by default. A small motivated group cannot move the network while the majority is indifferent. This is the correct behavior for a security-first system.

### 11.4a Governance Layer Integrity

The voting application and proposal submission layer are protected by the same hardware attestation model as the wallet itself (Section 5.4).

**Attack surface and mitigations:**

| Attack | Mitigation |
|---|---|
| Proposal diff tampered in transit | Proposal hash published on-chain before review window opens — any tampering produces hash mismatch |
| Voting app shows false description | App binary attested by TEE at session init — modified binary fails attestation before display |
| Vote tally manipulated | Each vote is an independent on-chain transaction signed by a biometric identity — tally is reconstructable by any node from raw votes |
| Build injected into propagation path | Nodes verify build hash against on-chain vote record before applying — unverified builds are rejected |
| User votes on description without reading diff | Vote transaction binds fingerprint to build hash, not description — user is signing the code, not the words about the code |

**Independent verification:**

Every user can verify what their vote was actually bound to without trusting the application:

```
On-chain proposal record contains:
  ├──► Exact build hash (published before review window)
  ├──► Full code diff (immutable, permanent)
  └──► All vote transactions with bound hashes

User verifies:
  Their signed hash == proposal record hash == deployed build hash
  All three must match — any discrepancy is detectable by anyone
```

A tampered display requires a tampered binary. A tampered binary fails TEE attestation. The governance layer inherits the same trust properties as the identity layer — no additional trust assumptions required.

### 11.4b Deployment and Live Confirmation

Governance approval is phase one. Live confirmation is phase two. A change is not permanent until the network confirms it works in production.

```
PHASE 1 — Vote passes (80% threshold met)
      │
      ▼
Reproducible build generated from approved diff
Build hash published on-chain
Viral propagation — all server nodes update to new code
Network runs on new code immediately
      │
      ▼
PHASE 2 — Live confirmation window opens (default: 72 hours)
  ├──► Network operates normally on new code
  ├──► All enrolled identities can observe behavior
  ├──► Any enrolled identity can raise a revert proposal
  └──► Confirmation prompt sent to all enrolled identities
      │
      ▼
Confirmation threshold met (default: same 80%)
  ├──► Yes → change is permanent, previous version archived
  └──► No / window expires without confirmation → automatic revert
            │
            ▼
      Previous code restored via viral propagation
      Reverted build hash published on-chain
      Proposal marked failed — cannot be resubmitted for 90 days
```

**Properties of two-phase deployment:**

- Theoretical approval and practical acceptance are separate gates
- A change that breaks something in production is caught before it becomes permanent
- The network never gets permanently stuck on bad code
- Revert is automatic — no governance vote required to roll back, only to go forward
- 90-day resubmission cooldown prevents rapid re-proposal of rejected changes

The confirmation window duration and resubmission cooldown are server layer parameters — adjustable via governance.

### 11.4c Emergency Security Protocol

For critical security vulnerabilities where the 45-day normal governance timeline creates unacceptable exposure, trusted developers may deploy an emergency patch immediately — without a prior vote. The patch stays live unless the community actively rejects it within 7 days.

The normal flow is inverted: deploy first, community decides after.

```
EMERGENCY DEPLOYMENT

Trusted developer identifies critical vulnerability
      │
      ▼
Developer publishes emergency patch:
  ├──► Code diff
  ├──► Vulnerability description (may be redacted until patch live)
  ├──► Severity justification
  └──► Developer fingerprint signature
        │
        ▼
Patch deploys immediately via viral propagation
Network runs on patched code
        │
        ▼
Developers vote AGAINST their own patch (all of them, publicly)
  ├──► On-chain, fingerprint-confirmed opposition votes
  ├──► Signal to community: "this was necessary, not permanent"
  └──► Developer opposition is mandatory — not optional
        │
        ▼
7-day community rejection window
  ├──► Patch remains live by default
  ├──► Community votes to REJECT if they oppose the patch
  ├──► 60% of active voters reject → patch reverts immediately
  └──► No 60% rejection within 7 days → patch becomes permanent
```

**Why the trigger is rejection, not confirmation:**

Under a critical security patch, requiring an affirmative keep vote creates a coordination problem — a genuine security fix could auto-revert simply because people couldn't mobilize fast enough under time pressure. Inverting the trigger removes that pressure while preserving community authority to remove something bad. 60% to reject is lower than the standard 80% because time pressure is real, but still a meaningful majority.

**Why developers vote against their own patch:**

Developers are not advocates for their emergency changes. They are first responders who acted because speed was necessary. Their opposition vote is a standing deferral to the community — a public record that they do not claim permanent authority over what they deployed. It also prevents abuse: a developer who manufactures a fake emergency to push through a change they couldn't pass through normal governance has their own opposition vote on-chain as evidence against them.

**Abuse prevention:**

- Emergency path requires a trusted developer identity with governance weight — not available to arbitrary enrolled identities
- Developer who abuses the emergency path loses community trust and is subject to developer removal vote
- All emergency deployments are permanently on-chain with full attribution — no anonymous emergency patches
- Frequent use of the emergency path by a single developer is a visible on-chain pattern subject to community scrutiny

The emergency path is a pressure valve, not a backdoor.

### 11.4d Active Voter Pool

The 80% threshold is calculated against the active voter pool — not total enrolled identities.

**Onboarding:**
All enrolled identities join the active voter pool by default at enrollment. Participation is opt-in from the first vote.

**Inactivity warning:**
```
Vote closes — identity did not participate
      │
      ▼
Warning sent to device:
  "You did not participate in the recent governance vote.
   If you do not wish to participate in future votes,
   you can opt out in Settings. Opting out removes you
   from the active voter pool."
```

**Opt-out:**
- Available in Settings at any time
- Removes identity from active voter pool
- Identity no longer counted in the 80% denominator
- Identity no longer receives vote notifications
- Reversible — re-enable participation in Settings at any time

**Properties:**
- Ghost accounts and permanently inactive identities cannot paralyze governance
- The denominator reflects genuinely engaged participants
- Opt-out is a deliberate choice, not a passive default — warning ensures awareness
- Re-enabling is always possible — no permanent exclusion

### 11.5 Threshold Mutability

The 80% threshold is a server layer parameter. The community can vote to change it using the current threshold.

```
Proposal to change voting threshold:
  ├──► Specifies new threshold (e.g. 67%, 90%)
  └──► Standard proposal lifecycle applies
        │
        ▼
Current threshold applies to the vote
  ├──► 80% votes yes → threshold changes to proposed value
  └──► Below 80% → no change
```

This means the threshold is self-consistent: lowering it requires meeting it first. A proposal to reduce the threshold from 80% to 51% must itself achieve 80% approval. The community must broadly agree that a lower bar is acceptable before the bar drops.

All governance parameters — threshold, review window duration, voting window duration, developer weight caps — are server layer values subject to the same mechanism.

### 11.5 Developer Admission

Any enrolled identity may publicly apply to become a trusted developer. There is no permission required to apply.

```
Applicant publishes developer application (signed with fingerprint):
  ├──► Identity (public key hash — pseudonymous or named, applicant's choice)
  ├──► Contribution history (code, proposals, on-chain activity)
  ├──► Proposed voting weight (1–2%)
  └──► Public statement of intent
        │
        ▼
Community votes using standard proposal mechanism
  ├──► 80% threshold applies
  └──► Approved → developer weight assigned, recorded on-chain
```

Developer status is removable by the same 80% vote. Developer weight is visible on-chain at all times. There is no private developer registry.

### 11.6 Founder Weight Reduction

The founder's 10% weight is not a permanent right. It is a starting position that reflects the trust placed in the founding identity at launch. The community may vote to reduce it at any time.

```
Any enrolled identity proposes founder weight reduction
  ├──► Specifies new weight (e.g. 5%, 2%, 0%)
  └──► Standard proposal lifecycle applies
        │
        ▼
80% threshold vote — active voter pool only
  ├──► Founder is recused — cannot vote on any proposal that touches
  │    founder weight, founder authority, or founder privileges
  ├──► Founder's 10% is excluded from both numerator and denominator
  ├──► Passes → founder weight updated on-chain immediately
  └──► Fails → no change
```

The community decides alone on any matter affecting founder power. The founder has no vote on their own authority. This applies to all proposals that directly or indirectly modify founder governance weight or privileges.

### 11.7 Physical Layer Exception

Open governance does not apply to the physical layer. Cryptographic primitives, signing authority, and the biometric identity model are immutable by design. No vote, regardless of threshold, can modify the physical layer.

Physical layer changes remain hard fork territory — requiring a separate ceremony outside the governance protocol, with the migration path defined in Section 4.

### 11.8 Trusted Contact Revocation

Trusted contacts are permanent by default but revocable by the owner through a fresh enrollment ceremony.

```
Owner initiates trusted contact revocation:
  ├──► Full biometric re-enrollment (fingerprint + face, all ten fingers)
  ├──► Re-enrollment produces fresh helper data and re-confirms keypair
  ├──► Revocation transaction signed with freshly confirmed key
  └──► Specified trusted contact removed from on-chain registry
        │
        ▼
30-day announcement period
  ├──► Revoked contact notified on-chain
  └──► No recovery initiated using that contact during window
        │
        ▼
Revocation confirmed — contact permanently removed
```

The ceremony cost (full re-enrollment) is intentional friction — expensive enough to prevent casual revocation, possible when a relationship genuinely changes or a contact is compromised.

---

## 12. Secure Infrastructure

### 12.1 Model

No cloud providers. Physical hardware owned and operated. Global server mesh composed of your anchor nodes and community-donated mining cluster nodes. No single jurisdiction. No single point of coercion.

```
YOUR PHYSICAL LAYER
  Air-gapped build machines (minimum 2 — independent verification)
  Signing device (TEE, biometric)
  Anchor validator nodes (minimum 3, different jurisdictions)
  Network monitoring station

COMMUNITY MINING MESH
  Cluster nodes globally distributed
  Incentivized by mining rewards
  No two clusters in same data center count full weight
  Geographic diversity enforced by weight formula
  Permissionless joining within attestation requirements
```

### 12.2 Anchor Nodes

Your anchor nodes serve as genesis validators establishing the initial network. They participate in the same 60/40 weight formula as all other clusters — no privileged consensus authority. The network does not depend on your servers being online. They function as:

- Initial release escrow publication points
- Governance proposal publication anchors
- Network health monitoring

Suggested geographic distribution:
- Philippines (primary — Zamboanga deployment context)
- Singapore (Southeast Asia relay)
- One Western jurisdiction (legal and connectivity diversity)

### 12.3 Air-Gapped Build Environment

```
Code review complete on internet-connected machine
      │
      ▼
Commit hash transferred to air-gapped build machine
      │  (QR code, USB with verified hash, or one-way data diode)
      ▼
Reproducible build executed on air-gapped machine
      │
      ▼
Build hash output
      │
      ▼
Independent verification on second air-gapped machine
      │
      ├──► Hashes match → proceed to signing ceremony
      └──► Hashes differ → build rejected, investigation triggered
```

A compromised internet-connected developer machine cannot touch the build that reaches your signing ceremony.

### 12.4 Full Update Pipeline

```
1. DEVELOPMENT
   Team implements under your direction
   Code review — all activity signed with attested developer keys
   Build triggered from reviewed commit only
   Reproducible build → deterministic hash
   Independent verification (minimum 2 machines)

2. YOUR AUTHORIZATION
   Build hash presented to you for review
   Signing ceremony (Tier 0 or Tier 1 depending on layer)
   TEE binds signature to specific hash

3. ESCROW
   Signed release published to server mesh on-chain
   Hash + signature publicly visible
   Revocation window begins
   Independent security researchers can audit pending release

4. DEPLOYMENT
   Revocation window closes with no owner activity
   Server mesh broadcasts update authorization
   Validators update in rolling fashion
   Old and new versions run simultaneously during transition
   Per-validator attestation verified post-update
   Automatic rollback if >20% validator attestation fails

5. CONFIRMATION
   Full validator set on new version
   On-chain deployment record finalized
   Your key signs deployment confirmation
```

### 12.5 Data Center Concentration Rule

If more than 10% of total validator weight is in a single data center or autonomous system, excess weight is redistributed. Server layer parameter — adjustable via governance, enforced from genesis.

---

## 13. Consensus & Finality

### 13.1 Mechanism

Asynchronous Byzantine Fault Tolerant (aBFT) consensus using a Lachesis-derived DAG model. No proof of work. No energy waste. No capital-only weight. Each cluster creates event blocks containing transactions. Events reference previous events from other clusters, creating a cryptographically linked DAG. Total ordering determined without a leader node.

| Property | Value |
|---|---|
| Finality | ~1-2 seconds under normal conditions |
| Fault tolerance | Up to 1/3 Byzantine clusters |
| Participation requirement | Attested device with enrolled identity + stake |
| Light client requirement | Any enrolled device |
| Mesh relay | Optional transport toward global consensus |

### 13.2 Transaction Lifecycle

```
User initiates transaction
      │
      ▼
Physical layer signs with Dilithium-3 (inside TEE, triggered by finger)
      │
      ▼
Signed transaction broadcast to network
      │  (direct internet or mesh relay)
      ▼
Cluster validates: attestation + signature + balance
      │
      ▼
Transaction enters DAG as event block
      │
      ▼
Lachesis consensus → finality (~1-2s)
      │
      ▼
Balance updated in server mesh ledger
      │
      ▼
Confirmation returned to light client
```

### 13.3 Cluster Participation Requirements

- Minimum enrolled contributing devices (threshold for submission)
- Minimum stake deposit — slashable on active misbehavior
- Running attested server layer software (hash in on-chain registry)
- At least one hardware-attested enrolled identity per cluster
- Geographic registration on-chain

---

## 14. Tokenomics

### 14.1 Design Principles

**Dilution is a core economic property, not a side effect.**

A cartel or whale position established at launch dilutes automatically as the network grows. Identity weight is bounded by real enrolled humans — it cannot be purchased or manufactured. As total enrolled identities grow, any fixed set of controlled identities becomes a smaller fraction of total network weight. Honest organic growth is the antidote to early concentration. No governance action required.

This makes the launch phase — where founder and early participants hold disproportionate weight — a temporary and self-correcting condition, not a permanent structural risk.

The structure is immutable in the physical layer. The parameters are server layer configuration — observable, adjustable, and governed by the community as the network matures.

No tokenomics model survives first contact with a live network unchanged. PhantomChain accepts this reality architecturally rather than fighting it.

### 14.2 Token Model

Single token. Fixed maximum supply. No two-token complexity. No perpetual inflation.

Bootstrap emission over 4 years on a decaying curve funds early miners before transaction fee volume matures. Post-bootstrap: fee-only validator revenue. Bitcoin end-state economics with a defined crossover mechanism.

### 14.3 Fee Structure

```
Every transaction:

Base fee     →  burned automatically
               (deflationary — ties network health to usage)
               (removes cluster incentive to manipulate fees)

Priority tip →  clusters
               (optional, demand-driven, real revenue)

Storage fee  →  refundable deposit
               (100% rebatable on data deletion)
               (incentivizes responsible storage usage)

Net user cost = base_fee + storage_deposit − storage_rebate
```

### 14.4 Mining Weight Formula

```
Cluster weight = (stake_component × 0.6) + (identity_component × 0.4)

Where:
  stake_component     = √(cluster_stake) / Σ√(all_cluster_stakes)
  identity_component  = cluster_identities / total_network_identities

Hard cap: no single cluster > 10% total network weight
Geographic bonus: first cluster in region earns uniqueness premium
Data center penalty: clusters sharing infrastructure count reduced weight
```

√stake (Square Root Stake Weight) — not linear. Formally proven to improve decentralization by 51% over linear models. See Section 9.4 for full justification. All ratio and cap values are server layer parameters — adjustable via governance.

### 14.5 Emission Schedule

```
Phase 1 — Bootstrap (Years 1–4):
  Decaying emission curve
  Pays miners before fee revenue matures
  Rate tied to network participation

Phase 2 — Mature (Year 5+):
  Zero new emissions
  Miners sustained by transaction fees only
  Crossover trigger: fee revenue reaches sustainability threshold
  Threshold is a server layer parameter — adjustable
```

### 14.6 What Is Immutable vs. Updatable

| Element | Status |
|---|---|
| Single token | Immutable |
| Fixed maximum supply | Immutable |
| Burn mechanism exists | Immutable |
| Dual-weight model exists | Immutable |
| One-person-one-slot | Immutable |
| 60/40 ratio | Server layer — updatable |
| 10% hard cap | Server layer — updatable |
| Emission curve | Server layer — updatable |
| Slashing amounts | Server layer — updatable |
| Geographic bonus formula | Server layer — updatable |
| Sustainability threshold | Server layer — updatable |

---

## 15. Supply Chain Model

### 15.1 The Core Principle

A fully compromised build pipeline cannot forge a transaction. Signing authority lives in the physical layer, unreachable by software delivery.

### 15.2 Comparison

| Concern | Physical Layer | Server Layer |
|---|---|---|
| Update frequency | Rare — protocol changes only | Regular — operational improvements |
| Release authorization | 5-of-7 multisig, 90-day window | 3-of-5 multisig, standard release |
| Compromise consequence | Hard fork required | Observable, recoverable |
| Signing authority exposure | None — immutable | None — isolated by design |
| Signing key location | Air-gapped hardware | Dedicated HSM |
| Reproducible build | Mandatory | Mandatory |

### 15.3 Developer Identity Protection

- Release signing keys held completely out-of-band from CI/CD
- All signing ceremonies require physical presence of keyholders
- Build pipeline outputs are public and auditable before signing
- Any mismatch between public source and signed binary is detectable
- Developer compromise can corrupt an artifact but cannot produce a validly-signed release without the threshold ceremony

---

## 16. Estate & Inheritance

### 16.1 The Model

Death is a graceful transition, not a catastrophic loss. Wealth flows forward — to designated people or to the community. The process is transparent, disputable by a living owner, and always cancellable.

### 16.2 Inactivity Trigger

```
Activity that resets the clock (fingerprint required):
  ├──► Any signed transaction
  ├──► Any cluster contribution confirmation
  ├──► Any governance vote
  └──► Explicit liveness proof (null transaction — one-tap reset)

Does NOT reset the clock:
  ├──► Incoming transactions
  ├──► Passive mining rewards credited
  └──► Any action not requiring fingerprint
```

### 16.3 Inactivity Timeline (Server Layer Parameters)

```
Year 0:    Last fingerprint activity
Year 3:    Warning flagged on-chain (silent — visible to watchers)
Year 3.5:  Public announcement — 6-month window opens
           Owner can cancel with single fingerprint tap — instant
Year 4:    Estate recovery opens
           ├──► Beneficiary designated → 30-day dispute window → transfer
           └──► No beneficiary → community recovery → 30-day dispute → treasury
Year 7:    Unclaimed wallets → community treasury
           (if recovery process never initiated)
```

All durations are server layer parameters — adjustable via governance.

### 16.4 Beneficiary Designation

Optional. Recorded on-chain. Signed by owner's fingerprint at time of designation. Updatable any time with fresh fingerprint confirmation.

```
Designation transaction:
  {
    owner_identity:  <public key hash>,
    beneficiaries: [
      { identity: <key hash>, share: 50% },
      { identity: <key hash>, share: 30% },
      { identity: <key hash>, share: 20% }
    ],
    condition: inactivity_trigger,
    signature: <owner Dilithium-3 fingerprint sign>
  }
```

### 16.5 Recovery Flow — Designated Beneficiary

```
Inactivity period expires
      │
      ▼
Beneficiary initiates recovery claim (signed with their fingerprint)
      │
      ▼
Server mesh verifies:
  ├──► Inactivity period genuinely elapsed
  ├──► Claimant matches designated beneficiary identity
  ├──► No concurrent competing claims
  └──► Announcement period has passed
      │
      ▼
30-day dispute window
      │  Owner cancels everything instantly with one fingerprint transaction
      ▼
No dispute → recovery executes
Tokens transferred to beneficiary wallets
Original wallet permanently deactivated
Identity slot freed — original person can re-enroll fresh if alive
```

### 16.6 Recovery Flow — No Beneficiary

```
Inactivity period expires
      │
      ▼
Anyone initiates community recovery claim (identified by their fingerprint)
      │
      ▼
30-day public announcement period
      │
      ▼
No owner activity during announcement
      │
      ▼
Tokens flow to community treasury
      │  (NOT to the filing person — prevents predatory filing)
      ▼
Filing person receives small finder's fee from treasury
      │  (incentivizes the process without incentivizing exploitation)
```

### 16.7 Safety Properties

- Living owner always cancels recovery with one fingerprint transaction — instant
- Dispute window is the primary protection against false death claims
- Re-enrollment after false recovery creates a fresh wallet — tokens already distributed are not reclaimed
- Community treasury governed by validator set — transparent on-chain allocation

### 16.8 Liveness Proof as Product Feature

```
Wallet UI reminder:
"You haven't confirmed your liveness in 2 years.
 Tap your finger to reset your inactivity timer."

One second. One tap. Estate clock reset.
```

---

## 17. Open Problems

### Critical — Must Solve Before Mainnet

**[CLOSED-04b] Tokenomics weight formula** — resolved in v0.2
Linear stake replaced with √stake (SRSW) — formally proven to improve decentralization by 51% over linear models. Identity farming attack does not apply — biometric enrollment is the Sybil resistance layer. 10% hard cap validated by IOTA production deployment. Remaining work: simulation of emission curve parameters and genesis allocation amounts — these are server layer values, not structural decisions.

**[CLOSED-06] Trusted contact recovery governance** — resolved in v0.2
Threshold is 1-of-N — any single trusted contact is sufficient to authorize recovery. Trusted contacts are permanent — registered at enrollment, no revocation mechanism required. NFC session security is sufficient — the recovery requires physical presence, live biometric, and an attested device. No on-chain registry complexity needed beyond the enrollment record.

**[CLOSED-14] Bootstrap validator incentive** — resolved in v0.2
No minimum cluster requirement at launch. Network bootstraps on founder-operated cloud infrastructure. As enrollment grows, the weight formula and cluster economics naturally incentivize decentralization — clusters become mathematically advantageous once sufficient identities exist to make them competitive. Decentralization is an emergent property of growth, not a launch prerequisite. No genesis allocation complexity required.

### Important — Must Solve Before Public Launch

**[CLOSED-05] TEE chip manufacturer trust** — resolved by design boundary
Manufacturer backdoor is outside protocol responsibility by the same logic as physical coercion. A manufacturer who compromises TEE integrity loses market eligibility and faces legal liability across every jurisdiction they operate in. Responsibility is distributed across manufacturers — multi-vendor device support means no single manufacturer compromise affects the whole network. Accepted residual risk.

**[CLOSED-07] Cross-platform physical layer consistency** — resolved by phased rollout
Android first. iOS, Windows, and Linux follow as subsequent physical layer targets. The server layer handles platform abstraction — the protocol defines the attestation interface, platform-specific implementations conform to it. Not a launch blocker.

**[CLOSED-08] Regulatory compliance architecture** — resolved by post-quantum ZKP commitment
Full compliance hooks will be implemented using post-quantum zero-knowledge proofs (see OPEN-11). The architecture is: compliance is provable without identity disclosure. Sanctions screening, threshold reporting, and AML hooks all expressible as ZK statements. Closes fully when OPEN-11 closes.

**[CLOSED-09] Validator geographic distribution incentives** — dropped
Not a launch requirement. Geographic diversity emerges naturally from human participation. Mesh-native discovery (Section 10.2) surfaces local contributors to local clusters by proximity without a formula. Revisit if concentration becomes an observed problem post-launch.

**[CLOSED-15] Minor participation** — resolved by disclaimer
Legal responsibility is the user's. Enrollment displays a jurisdiction disclaimer signed off by fingerprint confirmation. PhantomChain does not enforce age — local law governs local participants. No architectural change required.

**[CLOSED-16] Market discovery mechanism** — resolved in v0.2
Mesh-native push/pull discovery protocol designed in Section 10.2. Contributors push availability announcements through mesh relay. Clusters pull openings through mesh fetch. Match is on-chain, fingerprint-confirmed. Runs on the same adaptive relay and fetch transport as ShadowMesh — no central marketplace, no separate infrastructure.

### Research — Long-Term Roadmap

**[OPEN-10] PUF-based TEE attestation**
Independent of chip manufacturer. Requires PUF-capable silicon to be standard in consumer mobile chips — not yet the case. PhantomChain's design philosophy is consumer device onboarding without external hardware. This remains long-term research until PUF is native to standard mobile chipsets. Multi-vendor TEE support remains the interim mitigation.

**[CLOSED-11] Post-quantum zero-knowledge proofs** — resolved in v0.2
Two deployable solutions identified. zk-STARKs achieve post-quantum security via collision-resistant hash functions with no trusted setup — deployable today. ZK-ACE (arXiv:2603.07974, 2026) provides identity-bound zero-knowledge authorization built specifically for ML-DSA/Dilithium systems, replacing transaction-carried signature objects with succinct ZK statements and achieving order-of-magnitude reduction in consensus-visible authorization data. LaZer library (ACM CCS 2024) provides lattice-based ZK proofs for quantum-safe privacy. OPEN-08 compliance architecture closes with this. Implementation target: server layer v1.1.

**[CLOSED-12] ShadowMesh integration** — dropped
PhantomChain is an independent system. No shared infrastructure, no protocol coupling with ShadowMesh. Separate deployments, separate design.

**[CLOSED-13] Multimodal biometric binding** — resolved in v0.2
Designed as fingerprint + face dual-modal fusion using consumer hardware only. Vein scanning dropped — requires external hardware incompatible with design philosophy. Face geometry + liveness detection is standard on modern smartphones. Full design in Section 7. Research basis: Yirga et al. (Frontiers in AI, 2025) demonstrates multimodal fuzzy extractor key generation with FAR < 1% and FRR < 3.4% using face + vein modalities; fingerprint + face achieves equivalent or better accuracy on consumer hardware.

**[CLOSED-17] Cross-cluster contribution** — resolved in v0.2
Restaking research (arXiv:2505.03843) confirms fragmented stake models inherit lowest-cost attack vulnerabilities versus unified stake models. Splitting identity weight weakens each cluster's threshold security without compensating benefit. One-person-one-cluster commitment model is correct and retained.

---

## Appendix A — Closed Problems

| Problem | Resolution |
|---|---|
| Single device loss | NFC trusted contact — finger re-derives same keypair on any attested device |
| Consumer devices as servers | Reed-Solomon shard model — no device holds complete ledger, mesh reconstructs collectively |
| Cluster device dropout | Collapse model — cluster collapses cleanly below threshold, no rebalancing protocol needed, devices rejoin or reform |
| Biometric degradation | Ten-finger enrollment — any surviving finger sufficient |
| Coercion resistance | User-layer operational security — outside protocol responsibility by design |
| Software update breaking attestation | Two-layer separation — server updates cannot reach physical layer authority |
| Balance loss on version upgrade | Server mesh maps hardware identity to balance, not software version |
| Capital concentration | √stake (SRSW) + 40% identity weight + 10% hard cap — formally proven 51% decentralization improvement over linear models |
| Supply chain attack on signing keys | Physical layer immutability — no software path reaches TEE-sealed key material |
| Founder centralization | Open governance — founder holds 10% weight, reducible by community vote. No unilateral authority over server layer |
| Trusted contact going adversarial | Revocation via full re-enrollment ceremony — expensive but always possible |
| Tokenomics parameters locked at genesis | Parameters are server layer — updatable while structure remains immutable |
| Death without inheritance | Inactivity trigger → designated beneficiary or community treasury |
| Anonymous Sybil attacks | One-person-one-device enforced cryptographically by biometric uniqueness |
| Single-modality biometric spoofing | Dual-modal fingerprint + face fusion — both must be present live simultaneously, neither alone derives the key |
| Face photo or fingerprint artifact attack | Liveness detection on face + physical fingerprint sensor — static spoofs rejected at TEE level |
| Single-modality biometric spoofing | Dual-modal fingerprint + face fusion — both must be present live simultaneously, neither alone derives the key |
| Face photo or fingerprint artifact attack | Liveness detection on face + physical fingerprint sensor — static spoofs rejected at TEE level |
| Developer key exposure in CI/CD | Air-gapped build environment + out-of-band signing ceremony |
| Coerced developer release | Duress finger signal + revocation window |
| Bootstrap incentive problem | Cloud-first launch — founder-operated infrastructure at genesis, cluster architecture emerges as enrollment grows |
| Single cluster operator taking reward cut | Protocol distributes directly to contributing identities — no intermediary |

---

## Appendix B — Cryptographic Standards Reference

| Standard | Algorithm | NIST Publication |
|---|---|---|
| ML-KEM | Kyber-1024 | FIPS 203 |
| ML-DSA | Dilithium-3 | FIPS 204 |
| SLH-DSA | SPHINCS+ | FIPS 205 |
| SHA3-256 | — | FIPS 202 |
| SHAKE-256 | — | FIPS 202 |
| XChaCha20-Poly1305 | — | RFC 8439 extended |

No ECDSA. No RSA. No secp256k1. Clean break from classical cryptography throughout.

---

## Appendix C — Research References

| Reference | Title | Relevance |
|---|---|---|
| arXiv:2504.14351 | Decentralization in PoS Blockchain Consensus: Quantification and Advancement (Motepalli & Jacobsen, 2025) | SRSW and LSW formal proofs — justifies √stake weight formula |
| arXiv:2312.13938 | How Does Stake Distribution Influence Consensus? | SRSW empirical analysis across 10 blockchains — Nakamoto coefficient baseline |
| arXiv:2504.12859 | Enhancing Decentralization in Blockchain Decision-Making Through Quadratic Voting and Its Generalization | Formal proofs of QV types improving Gini and Nakamoto coefficients |
| arXiv:2407.01844 | An Efficient and Sybil Attack Resistant Voting Mechanism | Proof that coin voting is SA-proof but inefficient; identity layer is the solution |
| arXiv:2403.15429 | Single-Token vs Two-Token Blockchain Tokenomics (Kiayias, Lazos, Schlegel) | Quantitative rewarding mechanism — monetary policy equilibrium proofs |
| arXiv:1903.04213 | Weighted Voting on the Blockchain: Improving Consensus in PoS Protocols | Validator profile scoring and weighted majority rule |
| IOTA Tokenomics Whitepaper 2025 | IOTA Technical and Tokenomics Whitepaper | Production validation of 10% voting power cap with redistribution |
| arXiv:2603.07974 | ZK-ACE: Identity-Centric Zero-Knowledge Authorization for Post-Quantum Blockchain Systems (2026) | Post-quantum ZKP for ML-DSA identity systems — compliance architecture |
| ACM CCS 2024 | The LaZer Library: Lattice-Based Zero Knowledge and Succinct Proofs for Quantum-Safe Privacy | Lattice-based ZKP library — quantum-safe privacy primitives |
| Frontiers in AI 2025 | Cryptographic Key Generation Using Deep Learning with Biometric Face and Finger Vein Data (Yirga et al.) | Multimodal fuzzy extractor design — FAR/FRR benchmarks for dual-modal biometric key generation |
| arXiv:2505.03843 | Economic Security of Multiple Shared Security Protocols | Fragmented vs unified stake models — justifies one-cluster commitment |
| arXiv:2410.03183 | Research Directions for Verifiable Crypto-Physically Secure TEEs | PUF + TEE attestation research direction — physical layer v2 reference |

---

*PhantomChain Design Specification v0.2 — June 2026*  
*Document status: Active design. Subject to revision as open problems are resolved.*  
*Previous version: v0.1 — superseded by this document.*
