# PhantomChain
## External Transaction Layer — Design Specification
### Cross-Chain Interoperability / Post-Quantum Bridge Protocol / Identity-Preserving Outbound Transfers

---

**Classification:** Working Design Document  
**Version:** 0.2  
**Date:** June 2026  
**Status:** Active Design — Open Problems Enumerated  
**Depends On:** PhantomChain Design Specification v0.2, Geographic Coverage Premium v0.1  
**Section Numbers:** 19–31 (continuation of v0.2 numbering; Section 18 reserved for Geographic Coverage Premium)

---

## Table of Contents

19. [External Transaction Layer — Abstract](#19-external-transaction-layer--abstract)
20. [Threat Model Extension](#20-threat-model-extension)
21. [Architecture Overview](#21-architecture-overview)
22. [PhantomChain Address Adapter](#22-phantomchain-address-adapter)
23. [Outbound Transaction Protocol (OTP)](#23-outbound-transaction-protocol-otp)
24. [Inbound Transaction Protocol (ITP)](#24-inbound-transaction-protocol-itp)
25. [Bridge Custodian Model](#25-bridge-custodian-model)
26. [ZK Identity Proof Layer](#26-zk-identity-proof-layer)
27. [Finality Reconciliation](#27-finality-reconciliation)
28. [External Chain Registry](#28-external-chain-registry)
29. [Privacy Model for External Transactions](#29-privacy-model-for-external-transactions)
30. [Regulatory Compliance Interface](#30-regulatory-compliance-interface)
31. [Open Problems — External Layer](#31-open-problems--external-layer)
32. [Appendix D — Cross-Chain Security Properties](#appendix-d--cross-chain-security-properties)

---

## 19. External Transaction Layer — Abstract

PhantomChain's internal transaction model is complete and self-consistent: every actor is a real person with a hardware-attested Dilithium-3 identity, every transaction is biometrically signed, and the ledger is a closed mesh of enrolled humans.

External transactions — value flows between PhantomChain and other blockchain ecosystems — require a principled boundary layer. This boundary must solve five distinct problems simultaneously:

1. **Address translation** — External chains expect addresses derived from classical cryptography (ECDSA/secp256k1). PhantomChain produces Dilithium-3 public keys. These are incompatible formats with no native bridge.

2. **Signature translation** — A PhantomChain transaction is Dilithium-3 signed. An Ethereum transaction expects an ECDSA signature. Neither chain can natively verify the other's proofs.

3. **Identity preservation** — The external transaction must not sever PhantomChain's non-repudiability guarantee. A PhantomChain user sending to Ethereum must remain traceable under legal process, even though Ethereum itself is pseudonymous.

4. **Finality mismatch** — PhantomChain achieves aBFT finality in ~1-2 seconds. External chains have probabilistic finality windows ranging from 6 seconds (ETH post-merge) to 60+ minutes (Bitcoin). The bridge must handle asymmetric finality without exposing either side to reorg risk.

5. **No classical key introduction** — The design philosophy forbids ECDSA anywhere. A bridge that requires PhantomChain users to hold an ECDSA key defeats the post-quantum guarantee and reintroduces seed phrase risk. The bridge must be post-quantum on the PhantomChain side, regardless of what the external chain uses.

The External Transaction Layer solves all five problems through a combination of:
- A deterministic address adapter that derives a stable external-chain address from a Dilithium-3 public key without introducing ECDSA keys into the user's custody
- A set of Bridge Custodian Nodes that hold classical keys in a threshold HSM pool, not in any individual user's hands
- A ZK identity proof layer that proves transaction validity to the external chain without exposing biometric identity
- A finality reconciliation protocol that waits for sufficient external chain confirmation before releasing PhantomChain funds
- An on-chain registry that maintains the canonical mapping between PhantomChain identities and their external chain addresses

The External Transaction Layer is a **server layer component**. It is updatable via governance. The physical layer is not touched, not extended, and not aware of the external layer's existence. Signing authority remains biometric-and-TEE-bound on PhantomChain for all outbound initiation.

---

## 20. Threat Model Extension

The external layer introduces new attack surfaces not present in the internal model. These are in addition to, not instead of, the threat model in Section 3.

### 20.1 New Adversaries

| Adversary | Goal | Capability |
|---|---|---|
| Bridge node operator cartel | Steal or redirect bridged funds | Controls ≥ threshold of bridge custodian nodes |
| External chain reorg attacker | Double-spend via reorg after bridge release | Controls sufficient hash rate or stake on destination chain |
| Address mapping poisoner | Redirect outbound funds to attacker's address | Read/write access to mapping registry before finalization |
| ZK proof forger | Submit fraudulent proofs claiming valid PhantomChain transactions | Breaks ZK soundness assumption |
| Replay attacker | Re-submit valid historical proofs to drain bridge pool | Captures previously valid ZK proofs |
| Cross-chain MEV extractor | Front-run bridge transactions for profit | Mempool visibility on destination chain |

### 20.2 Attack Vectors Neutralized by Design

| Attack | Mitigation |
|---|---|
| Single bridge node theft | Threshold HSM model — no single node holds a spendable key |
| User ECDSA key compromise | Users never hold ECDSA keys — only bridge custodians do, in HSMs |
| Address mapping spoofing | Mapping signed by user's Dilithium-3 key and published on-chain before use |
| Proof replay | Each proof bound to a unique nullifier derived from the transaction's on-chain identifier |
| Bridge reorg on PhantomChain side | aBFT finality is absolute — no reorg possible post-finalization |
| Bridge drain via governance attack | Bridge pool limits and withdrawal rate limits enforced at protocol level |

### 20.3 Residual Risks

- **External chain reorg** — mitigated by confirmation depth requirements per chain, not fully eliminable [OPEN-ETX-01]
- **Bridge custodian majority compromise** — mitigated by threshold model and geographic distribution, residual risk acknowledged
- **ZK soundness failure** — theoretical; mitigated by use of hash-based STARKs with no trusted setup [OPEN-ETX-02]
- **Classical cryptography deprecation on external chains** — if destination chain migrates away from ECDSA, bridge custodian model must update [OPEN-ETX-03]
- **MEV extraction on destination chain** — outside PhantomChain's control; users informed of timing risk

---

## 21. Architecture Overview

The External Transaction Layer sits entirely within the server layer. It does not extend the physical layer. It is invisible to users who only transact internally on PhantomChain.

```
┌──────────────────────────────────────────────────────────────────┐
│                    PHYSICAL LAYER (unchanged)                    │
│  Dilithium-3 keypair    TEE attestation    Biometric signing     │
│  All outbound TX initiation still signed here — no change       │
└────────────────────────────┬─────────────────────────────────────┘
                             │  Attestation handshake (unchanged)
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│              SERVER LAYER — INTERNAL (existing)                  │
│  aBFT consensus    Ledger    Cluster management    Governance    │
│                              │                                   │
│              ┌───────────────▼──────────────────┐               │
│              │   EXTERNAL TRANSACTION LAYER      │               │
│              │                                   │               │
│              │  ┌─────────────────────────────┐  │               │
│              │  │  Address Adapter Registry   │  │               │
│              │  │  (Dilithium pk → ext addr)  │  │               │
│              │  └──────────────┬──────────────┘  │               │
│              │                 │                  │               │
│              │  ┌──────────────▼──────────────┐  │               │
│              │  │  ZK Identity Proof Layer    │  │               │
│              │  │  (STARK proofs — no biom.)  │  │               │
│              │  └──────────────┬──────────────┘  │               │
│              │                 │                  │               │
│              │  ┌──────────────▼──────────────┐  │               │
│              │  │  Bridge Custodian Pool      │  │               │
│              │  │  (Threshold HSM — M-of-N)   │  │               │
│              │  └──────────────┬──────────────┘  │               │
│              │                 │                  │               │
│              │  ┌──────────────▼──────────────┐  │               │
│              │  │  Finality Reconciliation    │  │               │
│              │  │  (Per-chain confirmation    │  │               │
│              │  │   depth requirements)       │  │               │
│              │  └─────────────────────────────┘  │               │
│              └───────────────────────────────────┘               │
└──────────────────────────────────────────────────────────────────┘
                             │
                             ▼ External chain interfaces
          ┌──────────────────┼──────────────────┐
          ▼                  ▼                  ▼
    Ethereum/EVM         Bitcoin           Solana / other
    (ECDSA/secp256k1)   (ECDSA/secp256k1)  (Ed25519)
```

### 21.1 Key Properties

**PhantomChain users never hold external-chain keys.** Their PhantomChain identity controls the initiation and authorization of all external transactions. Classical keys exist only inside bridge custodian HSMs.

**The external layer does not weaken internal guarantees.** A user who never interacts with the external layer is unaffected by its existence. The bridge pool is isolated from internal ledger operations.

**The bridge is not a trust boundary — it is a verification boundary.** The bridge custodians do not need to be trusted to behave honestly; they are subject to threshold cryptography constraints that make individual misbehavior detectable and non-exploitable below the threshold.

---

## 22. PhantomChain Address Adapter

### 22.1 The Problem

External chains identify accounts by addresses derived from their native key format:

| Chain | Key Type | Address Derivation |
|---|---|---|
| Ethereum / EVM | secp256k1 ECDSA | keccak256(pubkey)[12:] |
| Bitcoin | secp256k1 ECDSA | HASH160(pubkey) + checksum |
| Solana | Ed25519 | pubkey directly |

PhantomChain users have Dilithium-3 public keys. None of the above chains can natively verify Dilithium-3 signatures. There is no path to making a user's Dilithium-3 key sign a valid Ethereum transaction.

The adapter solves this without introducing classical keys into user custody.

### 22.2 Adapter Architecture

Each PhantomChain user who opts into external transaction capability is assigned a set of **bridge-controlled external addresses** — one per registered external chain. These addresses are derived deterministically from the user's Dilithium-3 public key, but the corresponding private keys are held by the Bridge Custodian Pool in threshold HSMs.

```
User's Dilithium-3 public key (pk_dilithium)
      │
      ▼
SHAKE-256("ext_addr_eth" ∥ pk_dilithium) → 256-bit seed
      │
      ▼
Bridge Custodian Pool derives secp256k1 keypair from seed
  Private key:  held in threshold HSM pool, never in user custody
  Public key:   standard secp256k1
      │
      ▼
Ethereum address: keccak256(secp256k1_pubkey)[12:]
      │
      ▼
Mapping published on PhantomChain ledger:
  {
    phantomchain_identity:  SHA3-256(pk_dilithium),
    ethereum_address:       0x...,
    chain_id:               1 (Ethereum mainnet),
    registration_time:      block_height,
    signature:              Dilithium-3 sign by user (consent proof),
    custodian_attestation:  threshold HSM attestation of derivation
  }
```

**Domain separation by chain:** Each chain uses a distinct SHAKE-256 prefix (`ext_addr_eth`, `ext_addr_btc`, `ext_addr_sol`, etc.). The same PhantomChain identity yields different addresses on each chain. Addresses are non-reversible — an observer with only the Ethereum address cannot determine the PhantomChain identity without access to the on-chain mapping.

**User consent:** Registering an external address requires a Dilithium-3 signed transaction from the user. No external address is created without explicit user action.

### 22.3 Address Stability

Once registered, an external address is permanent for that user on that chain. The derivation is deterministic — given the same pk_dilithium and chain prefix, the same address is always produced. This allows recovery: if the bridge pool is rebuilt, all addresses can be re-derived from the on-chain Dilithium-3 public keys.

### 22.4 What the User Sees

From the user's perspective: they have a PhantomChain wallet (their finger). On request, the wallet UI displays a receiving address for each registered external chain. They do not hold the corresponding private key. They control inbound funds by initiating a claim transaction on PhantomChain (biometrically signed).

---

## 23. Outbound Transaction Protocol (OTP)

An outbound transaction moves value from PhantomChain to an external chain.

### 23.1 Full Flow

```
STEP 1 — USER INITIATES
  User opens wallet, selects "Send to external chain"
  Specifies:
    ├──► Destination chain (e.g. Ethereum)
    ├──► Destination address (external chain address — e.g. 0x...)
    ├──► Amount
    └──► Optionally: memo / transaction purpose (for compliance)
  Fingerprint confirmation required
  Initiates outbound request transaction on PhantomChain (Dilithium-3 signed)

STEP 2 — PHANTOMCHAIN LOCKS FUNDS
  Server mesh validates:
    ├──► Sufficient balance
    ├──► Destination chain is registered in External Chain Registry
    ├──► Destination address format valid for chain
    └──► Rate limits not exceeded (per-user, per-chain, network-wide)
  Funds locked in bridge escrow account on PhantomChain ledger
  Lock is aBFT finalized (~1-2 seconds)
  Outbound request record published on-chain:
    {
      request_id:           unique nullifier (SHA3-256 of tx hash + nonce),
      source_identity:      SHA3-256(pk_dilithium),
      destination_chain:    chain_id,
      destination_address:  0x...,
      amount:               X,
      lock_block:           PhantomChain block height,
      expiry:               lock_block + timeout_window,
      zk_proof:             (see Section 25)
    }

STEP 3 — ZK PROOF GENERATION
  ZK proof generated (see Section 25):
    Proves:  valid PhantomChain balance lock exists
    Proves:  source identity authorized the lock (without revealing biometric)
    Proves:  destination address is the correct registered adapter address
             OR user-specified recipient (for free-form sends)
    Reveals: amount, destination, nullifier
    Hides:   source PhantomChain identity (default) OR reveals it (compliance mode)

STEP 4 — BRIDGE CUSTODIAN POOL SIGNS
  Bridge Custodian Pool receives:
    ├──► On-chain lock record (verifiable on PhantomChain)
    ├──► ZK proof
    └──► Destination chain transaction template
  Custodians verify:
    ├──► Lock record exists and is aBFT finalized
    ├──► ZK proof valid
    ├──► Nullifier not previously used (replay prevention)
    └──► Amount within per-transaction limits
  M-of-N custodians sign destination chain transaction
    (M and N are server layer parameters)
  Threshold signature assembled
  Transaction submitted to destination chain

STEP 5 — EXTERNAL CHAIN CONFIRMATION
  Finality Reconciliation module monitors destination chain
  Waits for confirmation depth per chain (see Section 26)
  Once confirmed:
    Bridge escrow on PhantomChain is released (funds burned from escrow)
    Nullifier marked used — permanent, irreversible
    Outbound record finalized on-chain
    User receives confirmation notification

STEP 6 — FAILURE / TIMEOUT HANDLING
  If destination chain transaction fails or times out:
    Escrow lock expires at block_height + timeout_window
    Funds returned to user's PhantomChain wallet automatically
    No user action required
    Timeout and return recorded on-chain
```

### 23.2 Rate Limits and Protections

Rate limits are server layer parameters, adjustable via governance. Defaults:

| Limit | Default Value | Rationale |
|---|---|---|
| Per-user per-day outbound | 50,000 PHNT | Protects user from large coerced transfers |
| Per-user per-transaction | 10,000 PHNT | Limits single-event exposure |
| Network-wide per-hour | 1,000,000 PHNT | Limits bridge pool drain rate |
| Daily velocity escalation | 3× requires biometric re-confirmation | High-value sends require explicit intent |

Limits are not configurable by the user for their own account — they are protocol minimums. Governance can raise them; they cannot be individually disabled.

### 23.3 Free-Form vs. Adapter Sends

**Adapter send:** Destination is the user's own registered external address. Full ZK proof available. Identity mapping verifiable.

**Free-form send:** Destination is any external chain address specified by the user (e.g., sending to a friend's Ethereum wallet). ZK proof still proves valid PhantomChain lock; it does not prove destination ownership. Destination address is logged on-chain under the sender's identity. Free-form sends are always compliance-visible (source identity on-chain) because no adapter mapping exists to provide a privacy guarantee.

---

## 24. Inbound Transaction Protocol (ITP)

An inbound transaction moves value from an external chain into PhantomChain.

### 24.1 The Receiving Address

A PhantomChain user's external chain receiving address is their adapter address (Section 21). Funds sent to that address on the external chain are controlled by the Bridge Custodian Pool.

### 24.2 Full Flow

```
STEP 1 — EXTERNAL CHAIN DEPOSIT
  Third party (or user themselves) sends funds to user's external
  chain adapter address (e.g., Ethereum 0x...)
  Funds arrive at address controlled by Bridge Custodian Pool's HSMs

STEP 2 — BRIDGE MONITORS AND DETECTS
  Bridge Custodian Pool runs monitoring nodes on all registered chains
  Detects incoming transaction to any registered adapter address
  Waits for chain-specific confirmation depth (see Section 26)
  Once confirmed at required depth:
    Generates deposit record:
      {
        chain_id:             1 (Ethereum mainnet),
        tx_hash:              0x... (external chain),
        adapter_address:      0x...,
        phantomchain_dest:    SHA3-256(pk_dilithium),
        amount:               Y (converted at current rate),
        confirmation_block:   external block height,
        nullifier:            SHA3-256(chain_id ∥ tx_hash ∥ adapter_address)
      }

STEP 3 — BRIDGE CUSTODIAN ATTESTATION
  M-of-N Bridge Custodians independently verify the deposit on-chain
  Each publishes attestation signed by their HSM key
  Once M attestations collected:
    Threshold signature over deposit record assembled

STEP 4 — PHANTOMCHAIN CREDIT
  Threshold-signed deposit record submitted to PhantomChain server mesh
  Server mesh validates:
    ├──► Threshold signature valid (M-of-N custodians)
    ├──► Nullifier not previously used
    ├──► Destination identity registered on PhantomChain
    └──► Amount within inbound rate limits
  Funds minted from bridge reserve into destination identity's wallet
    (or: released from pre-funded reserve — see Section 24)
  Inbound record finalized on-chain
  Nullifier permanently marked used

STEP 5 — USER NOTIFICATION
  Wallet UI notifies user of inbound credit
  No user action required for standard inbound
  High-value inbound (above threshold) may prompt optional biometric acknowledgment
```

### 24.3 Inbound Rate Limits

| Limit | Default | Rationale |
|---|---|---|
| Per-user per-day inbound | 500,000 PHNT equivalent | AML threshold |
| Network-wide per-hour inbound | 5,000,000 PHNT equivalent | Bridge reserve protection |
| Single transaction above 100,000 PHNT | Triggers compliance flag | Regulatory reporting threshold |

### 24.4 Exchange Rate

PhantomChain is a closed-economy chain. Inbound assets from external chains must be denominated in PHNT on arrival. Exchange rate is determined by:

1. **Primary:** On-chain oracle network maintained by a set of community-elected oracle nodes (server layer parameter — oracle set governed by community vote)
2. **Fallback:** Time-weighted average of the last N oracle readings (N is server layer parameter)
3. **Circuit breaker:** If oracle readings diverge by > X% within Y minutes, inbound processing pauses pending governance review

Oracle selection and replacement is a server layer governance function. Oracle operators must be enrolled PhantomChain identities.

---

## 25. Bridge Custodian Model

The Bridge Custodian Pool is the only part of the system that holds classical (non-post-quantum) private keys. These keys are necessary because external chains require classical signatures. The design minimizes classical key exposure and makes individual custodian compromise non-exploitable.

### 25.1 Custodian Structure

```
Bridge Custodian Pool: N nodes (N = server layer parameter, minimum 7)
Signing threshold: M-of-N (M = server layer parameter, minimum 5)

Each custodian node:
  ├──► Physical server in a distinct jurisdiction
  ├──► Air-gapped HSM holding classical key shares
  ├──► Runs attested PhantomChain server layer software
  ├──► Operated by a governance-elected enrolled PhantomChain identity
  └──► Subject to slashing on provable misbehavior
```

No single custodian holds a complete private key. The key material is split using Shamir Secret Sharing across all N nodes. M nodes must cooperate to produce a valid signature. A custodian who holds fewer than M shares can produce no usable key material.

### 25.2 Custodian Governance

Custodians are elected by community vote (standard 80% governance threshold). Candidacy requires:

- Enrolled PhantomChain identity (biometric)
- Demonstrated infrastructure capability (verifiable on-chain uptime history)
- Jurisdictional disclosure (on-chain)
- Bonded stake (slashable on misbehavior)

Custodians serve fixed terms (default: 1 year), renewable by vote. Removal before term end requires an emergency governance vote (60% threshold — lower than standard due to security urgency).

### 25.3 Key Derivation and Rotation

At custodian set initialization or rotation:

```
Distributed Key Generation (DKG) ceremony:
  All N custodians participate in a threshold DKG protocol
    (e.g., FROST for secp256k1, adapted for each chain's key type)
  Each custodian receives a key share
  No custodian ever sees the full private key
  The public key (and derived adapter addresses) are deterministic outputs of DKG
  DKG ceremony record published on-chain (shares NOT published)

Key rotation:
  Triggered by: custodian set change, suspected compromise, scheduled rotation
  New DKG ceremony run with new/unchanged custodian set
  New public key published
  Adapter address registry updated (new addresses derived from new public key)
  Old addresses remain valid for inbound during a grace period
  Old key material certified destroyed by each custodian (on-chain attestation)
```

### 25.4 Custodian Slashing Conditions

| Condition | Evidence | Penalty |
|---|---|---|
| Double-signing (signing conflicting transactions) | Two valid signatures over conflicting records | Full bond slash + permanent removal |
| Downtime (consecutive missed signatures) | N consecutive missed signing events | Partial slash |
| Unauthorized transaction (signing without valid ZK proof) | On-chain record mismatch | Full bond slash + removal |
| Key material exposure | Cryptographic proof of individual key reconstruction | Full bond slash + removal |

Slashing is executed automatically by the server layer upon detection. It does not require a governance vote. Detection is performed by the server mesh, which has visibility into all signing events.

### 25.5 Bridge Reserve

The Bridge Custodian Pool maintains a reserve of PHNT on PhantomChain and a reserve of each supported external asset. The reserve absorbs timing mismatches between external chain confirmation and PhantomChain credit.

Reserve requirements are server layer parameters. The reserve is auditable by any enrolled identity at any time via the public ledger.

Governance controls:
- Reserve minimum thresholds
- Maximum single outbound transaction (as % of reserve)
- Daily outbound cap (as % of reserve)
- Reserve top-up triggers

---

## 26. ZK Identity Proof Layer

### 26.1 Purpose

Every outbound transaction must carry a proof that:

1. A valid, aBFT-finalized lock exists on PhantomChain for the stated amount
2. The lock was authorized by the PhantomChain identity that owns the funds
3. The requesting identity is the registered owner of the destination adapter address (for adapter sends)
4. The proof has not been used before (nullifier uniqueness)

This proof must be verifiable by the Bridge Custodian Pool without the custodians needing to query PhantomChain in real time, and without exposing biometric identity to the custodians or to the external chain.

### 26.2 Proof System Selection

Two post-quantum-compatible ZK proof systems are available:

| System | Post-Quantum | Trusted Setup | Size | Verify Time | Deployment Status |
|---|---|---|---|---|---|
| zk-STARKs | Yes (hash-based) | None required | ~100KB | Fast | Deployable today |
| ZK-ACE (ML-DSA) | Yes (Dilithium-native) | None | ~50KB | Very fast | 2026, deployable |
| LaZer (lattice-based) | Yes | None | ~200KB | Moderate | ACM CCS 2024 |

**Primary:** zk-STARKs for launch (deployable immediately, no trusted setup, widely audited).

**Roadmap:** ZK-ACE once production-validated. ZK-ACE is specifically designed for ML-DSA/Dilithium-3 identity systems and produces succinct proofs that replace transaction-carried signatures. For PhantomChain, ZK-ACE proofs would replace the need to carry Dilithium-3 signature data in the outbound request record, reducing proof size and verification time.

### 26.3 What Each Proof Proves

```
Statement:
  "I know a PhantomChain identity (pk_dilithium) such that:
    (1) SHA3-256(pk_dilithium) = claimed_identity_commitment
    (2) A Dilithium-3 signature exists over lock_record_hash,
        verifiable under pk_dilithium
    (3) lock_record_hash corresponds to a PhantomChain ledger entry
        at block_height B with amount A locked to escrow
    (4) The Merkle path from lock_record_hash to the block root
        at block_height B is valid
    (5) nullifier = SHA3-256(lock_record_hash ∥ nonce) is fresh
        (not in the nullifier set)"

Reveals:  amount, destination_address, nullifier, block_height
Hides:    pk_dilithium, Dilithium-3 signature, biometric derivation
```

The proof is generated inside the user's TEE. The TEE has access to the Dilithium-3 private key and the lock record. The proof is computed entirely in-device; the private key never appears in the proof output.

### 26.4 Nullifier Design

Each nullifier is unique to a specific lock record. It cannot be reused. The nullifier set is maintained on PhantomChain's ledger and is checked by the Bridge Custodian Pool before signing any outbound transaction.

```
nullifier = SHA3-256("outbound" ∥ lock_record_hash ∥ user_nonce)

user_nonce: a monotonically incrementing counter per user, stored
            in TEE — prevents nullifier reuse even if the same
            lock record is somehow presented twice
```

The nullifier reveals nothing about the user's identity — it is a hash of a hash, domain-separated, with a device-local nonce.

### 26.5 Compliance Mode Proofs

Compliance mode proofs are available when regulatory disclosure is required (warrant, threshold reporting, etc.). In compliance mode:

```
Additional reveals:  pk_dilithium (or identity_commitment)
                     Transaction metadata (memo field if present)

Mechanism:          ZK proof modified to include pk_dilithium in
                    the public output
                    User must explicitly authorize compliance reveal
                    (biometric confirmation)
                    Compliance reveal is logged on PhantomChain
                    with identity of requesting party (if known)
```

Compliance reveal is the user's choice at transaction time for voluntary disclosure, or compelled by legal process (which operates at the server layer, not the ZK layer — see Section 29).

---

## 27. Finality Reconciliation

### 27.1 The Mismatch Problem

PhantomChain has aBFT finality: once a transaction is finalized, it cannot be reverted. There is no concept of a reorg on PhantomChain. This is a hard property of Lachesis consensus.

External chains have probabilistic finality:

| Chain | Typical Confirmation Depth | Time to Practical Finality |
|---|---|---|
| Ethereum (post-merge) | 32 slots (justified) / 64 slots (finalized) | ~6.4 min / ~12.8 min |
| Bitcoin | 6 blocks (convention) | ~60 minutes |
| Solana | ~32 slots (confirmed) | ~13 seconds |
| Polygon | ~128 blocks | ~4 minutes |
| Avalanche C-Chain | 1 block (aBFT) | ~1-2 seconds |

The bridge must not release PhantomChain escrow until the external transaction has reached sufficient confirmation depth. Releasing early exposes the bridge to double-spend via reorg.

### 27.2 Confirmation Depth Registry

Each supported external chain has a registered confirmation depth requirement. These are server layer parameters, adjustable by governance.

```
External Chain Registry entry:
  {
    chain_id:                  1,
    chain_name:                "Ethereum",
    finality_mechanism:        "probabilistic",
    confirmation_depth:        64,      // Ethereum finalized epoch
    confirmation_time_est:     800,     // seconds
    emergency_depth:           32,      // reduced in emergency
    bridge_contract_address:   0x...,   // if applicable
    monitor_node_set:          [...],   // enrolled identity operators
    max_single_tx:             500000,  // PHNT equivalent
    status:                    "active"
  }
```

### 27.3 The Wait Model

For outbound transactions:

```
PhantomChain escrow finalized (aBFT — instant, irreversible)
      │
      ▼
Bridge submits to external chain
      │
      ▼
Finality Reconciliation module monitors:
  ├──► External chain block confirmations counted
  ├──► Reorg detection: if a reorg removes the transaction,
  │    the bridge re-submits
  └──► On confirmation_depth reached:
       Escrow released (funds burned)
       Outbound record finalized
       Nullifier permanently marked
```

For inbound transactions:

```
Funds arrive at external chain adapter address
      │
      ▼
Finality Reconciliation module monitors:
  ├──► Waits for confirmation_depth on source chain
  └──► On confirmation_depth reached:
       Bridge Custodians attest deposit
       PhantomChain credit issued
```

The user's PhantomChain funds are locked for the duration of the outbound confirmation wait. They are not lost — they are in escrow. The user sees "pending external confirmation" in their wallet UI with an estimated time.

### 27.4 Stuck Transaction Handling

If an external chain transaction is submitted but not confirmed within 2× the estimated confirmation time:

```
Bridge detects stuck transaction
      │
      ▼
Attempts resubmission with higher gas / fee
      │
      ▼
If still not confirmed within absolute timeout:
  Outbound request marked failed
  PhantomChain escrow returned to user
  Failure logged on-chain with details
  User notified
```

Users can also cancel a pending outbound transaction during the confirmation window, subject to:
- Not yet submitted to external chain: instant cancel, funds returned
- Submitted but not confirmed: cancel queued; funds returned after submission definitively fails or times out
- Confirmed on external chain: cannot be cancelled (irreversible)

---

## 28. External Chain Registry

### 28.1 Purpose

The External Chain Registry is the on-chain record of all chains PhantomChain can bridge to. It contains the technical parameters, governance records, and operational status of each chain integration.

New chains are added by governance vote. Chains are suspended by emergency governance (Section 11.4c). Chain parameters are updated by standard governance.

### 28.2 Chain Registration Requirements

A new chain must meet these criteria before governance vote:

| Requirement | Verification |
|---|---|
| Open-source node software | Code reviewable by trusted developers |
| Documented finality mechanism | Published, peer-reviewed |
| Stable address format | Not subject to ongoing change |
| Bridge contract (for smart contract chains) | Audited by community-appointed security researchers |
| Monitor node operator set | Minimum 3 enrolled PhantomChain identities willing to operate monitor nodes |
| Bridge reserve adequacy | Sufficient reserve to cover initial limits |
| Legal risk assessment | Trusted developer endorsement |

### 28.3 Chain Suspension

A chain can be suspended (bridge paused) without a full governance vote under two conditions:

1. **Emergency:** A trusted developer can suspend a chain for 72 hours pending community review (same mechanism as emergency security protocol in Section 11.4c).

2. **Automatic:** If the Finality Reconciliation module detects a reorg exceeding the registered confirmation depth (indicating a chain-level security event), the chain is automatically suspended and alerts are raised. Resumption requires a governance vote.

---

## 29. Privacy Model for External Transactions

### 29.1 Default Privacy Properties

| Transaction Type | PhantomChain Visibility | External Chain Visibility |
|---|---|---|
| Internal PhantomChain TX | Sender identity (public key hash) visible | Not applicable |
| Outbound adapter send | Sender identity visible on PhantomChain | External chain sees only the adapter address (no link to PhantomChain identity for external observers without registry access) |
| Outbound free-form send | Sender identity visible on PhantomChain | Same as above |
| Inbound (from own external address) | Recipient identity visible | External chain sees only the adapter address |
| Inbound (from third party) | Recipient visible; sender is whoever deposited externally | External sender identity from external chain records only |

By default, PhantomChain identity is not exposed on external chains. The adapter address is a hash-derived pseudonym. An observer on Ethereum who sees a transaction from an adapter address cannot determine the PhantomChain identity without access to PhantomChain's public ledger.

However, the mapping between external address and PhantomChain identity is itself public on-chain (it must be, for recovery and compliance purposes). This means PhantomChain identity is **pseudonymous on external chains, not anonymous** — the link is public record, just not immediately visible to external chain observers.

### 29.2 What PhantomChain Guarantees

- No external chain observer can determine PhantomChain identity from an external transaction without consulting PhantomChain's public ledger
- The ZK proof does not reveal the Dilithium-3 public key to the Bridge Custodian Pool or to the external chain
- Bridge Custodians see the adapter address they are signing for, and the amount, but not the user's PhantomChain identity commitment (unless compliance mode is active)

### 29.3 What PhantomChain Does Not Guarantee

- Anonymity of external chain transactions: external chain transactions are public records on that chain
- Privacy of the mapping: the adapter address → PhantomChain identity mapping is public on PhantomChain's ledger
- Privacy from PhantomChain cluster nodes: nodes can see the outbound transaction record including the source identity commitment (same visibility as any other transaction)

This privacy model is consistent with PhantomChain's core design principle: nothing is anonymous, everything is traceable under legal process, and there is no surveillance database, only a transparent ledger.

---

## 30. Regulatory Compliance Interface

### 30.1 Principle

External transactions are the highest-risk surface for regulatory compliance. They move value across sovereignty boundaries, across pseudonymous protocols, and into ecosystems with different traceability models. PhantomChain's approach is the same as its internal compliance model: everything is traceable under legal process, nothing is surveilled by default.

### 30.2 On-Chain Traceability

Every outbound and inbound transaction creates a permanent, immutable on-chain record linking:
- The PhantomChain identity commitment (public key hash)
- The external chain address
- The amount
- The timestamp (block height)
- The nullifier

This record is sufficient for legal traceability. A warrant targeting a known external chain address can be linked to a PhantomChain identity via the public registry. A warrant targeting a PhantomChain identity can be linked to their external chain addresses via the same registry.

No additional surveillance infrastructure is required. The public ledger is the audit trail.

### 30.3 Threshold Reporting

Transactions exceeding configurable thresholds (server layer parameters) are automatically flagged in the on-chain compliance record. These flags are visible to:
- The user (always)
- Law enforcement with valid legal process (cryptographic access mechanism below)
- Not visible to third parties or other users

### 30.4 ZK-Based Compliance Disclosure

For compliance verification that does not require full identity disclosure:

Using ZK-ACE or zk-STARKs, a user (or the system under legal compulsion) can prove:
- "This external transaction was authorized by an identity that is not on sanctions list X" — without revealing who it is
- "This transaction amount is below reporting threshold T" — without revealing the exact amount
- "This identity has no prior compliance flags in the last N years" — without revealing the identity

This allows counterparty compliance checks (e.g., exchanges that require AML screening before accepting deposits) to be satisfied without the exchange receiving the user's full PhantomChain identity.

### 30.5 Legal Process Interface

Law enforcement access to identity disclosure follows the same model as PhantomChain's internal compliance model. The External Layer adds no new access mechanisms and removes none.

For external transactions specifically:

| Request Type | Response |
|---|---|
| "Who owns external address 0x...?" | Registry lookup returns PhantomChain identity commitment |
| "What external transactions did identity X make?" | Ledger query returns full outbound/inbound history |
| "Freeze funds in transit" | Bridge Custodian Pool can pause a specific pending transaction on governance instruction — not unilaterally |
| "Seize funds in bridge escrow" | Requires governance vote (no single party can unilaterally seize) |

Fund seizure by legal order requires governance action, not unilateral Bridge Custodian compliance. This is by design: no single jurisdiction can compel a unilateral freeze. The community governs bridge operations, and legal process must engage the community governance mechanism. This is the PhantomChain principle applied to external transactions: cooperative with legitimate legal process, not cooperative with unilateral coercive demands.

---

## 31. Open Problems — External Layer

### Critical — Must Solve Before Bridge Mainnet

**[OPEN-ETX-01] External chain reorg handling depth calibration**
The confirmation depths in Section 26 are based on current chain security. For Bitcoin, 6-block conventional finality is generally accepted but not formally guaranteed. For Ethereum, the finalized epoch (64 slots) provides stronger guarantees than justified (32 slots) but is slower. The correct depth per chain is a risk-weighted judgment that must be validated empirically and reviewed periodically. Governance process for depth updates needed.

**[OPEN-ETX-04] Exchange rate oracle design and manipulation resistance**
The oracle model in Section 23.3 is deliberately underspecified. Oracle manipulation (price oracle attacks) is a well-documented attack on bridges and DeFi protocols. The oracle set governance, TWAP window length, circuit breaker parameters, and oracle operator bond requirements need formal modeling. Manipulation-resistant oracle design is a non-trivial independent subproblem.

**[OPEN-ETX-05] Bridge reserve sizing and liquidity model**
The bridge reserve must be large enough to handle peak inbound volume without stalling, but not so large that it represents a concentrated target. The equilibrium reserve size, replenishment mechanism, and the accounting model (are reserves locked PHNT, or a separate liability pool?) require formal economic modeling. The interaction between reserve size and inbound rate limits needs simulation.

**[OPEN-ETX-06] DKG ceremony security for Bridge Custodian Pool**
The Distributed Key Generation ceremony that initializes the threshold HSM pool is a high-value target. A compromised DKG produces a compromised key set without detection. The ceremony must be performed in a way that guarantees no single participant knows the full private key, and that the ceremony itself is verifiable by the community. FROST DKG is the primary candidate but its implementation in an HSM environment with enforcement of non-exportability needs explicit design.

### Important — Must Solve Before Public Bridge Launch

**[OPEN-ETX-02] zk-STARK proof size optimization for mobile**
zk-STARK proofs at ~100KB are not prohibitive, but proof generation inside a mobile TEE is compute-intensive. Generation time on low-end devices must be benchmarked. If generation is too slow for acceptable UX, batching or pre-computation strategies are needed. ZK-ACE, when production-validated, reduces this substantially.

**[OPEN-ETX-07] Bridge Custodian geographic and jurisdictional diversity requirements**
Minimum requirements for custodian node distribution across jurisdictions need formal definition. A bridge where 5-of-7 custodians are in one jurisdiction is vulnerable to a single nation-state compelled disclosure or seizure event. Diversity requirements must be enforced at governance admission level, not after the fact.

**[OPEN-ETX-08] Multi-hop external transaction privacy**
A sophisticated analyst with visibility into both PhantomChain's ledger and multiple external chains' records could correlate adapter address activity with PhantomChain identity transitions over time. The current design makes this possible in principle. Whether this is an acceptable privacy tradeoff or whether additional mixing/delay mechanisms are warranted requires explicit privacy modeling.

### Research — Long-Term Roadmap

**[OPEN-ETX-03] Post-quantum external chains**
If an external chain migrates to post-quantum cryptography (e.g., Ethereum's long-term roadmap includes PQ migration), the Bridge Custodian classical key model may become unnecessary — a direct Dilithium-3 signature could eventually be validated on-chain. This would eliminate the custodian pool entirely for PQ-native chains. The design should be evaluated for compatibility with a direct-signing model when the external chain supports it.

**[OPEN-ETX-09] Atomic swap protocol (trustless bridge alternative)**
The Bridge Custodian model requires trust in the threshold, however distributed. A hash-timelock-based atomic swap protocol between PhantomChain and external chains would eliminate custodian trust entirely for chains that support it. Requires the external chain to support hash timelocks (Ethereum and Bitcoin both do). Feasibility and UX tradeoffs require design work. Cannot be implemented with post-quantum proofs natively on HTLC-supporting chains today, but the model is worth preserving as a roadmap item.

---

## Appendix D — Cross-Chain Security Properties

### Formal Security Statement

The External Transaction Layer achieves the following security properties:

| Property | Guarantee | Condition |
|---|---|---|
| **Fund safety (outbound)** | Funds not lost unless both (a) ≥ M of N bridge custodians collude AND (b) external chain reorg occurs within confirmation window | M-of-N threshold holds; confirmation depth sufficient |
| **Fund safety (inbound)** | Funds not credited without genuine external chain deposit confirmed at required depth | Finality Reconciliation module operating correctly |
| **Non-repudiation** | Every outbound transaction permanently linked to a PhantomChain identity on-chain | Ledger immutability |
| **Replay prevention** | No outbound proof usable more than once | Nullifier uniqueness maintained by ledger |
| **Privacy (default)** | External chain observers cannot determine PhantomChain identity from external transactions without consulting PhantomChain public ledger | Address mapping is pseudonymous |
| **No classical key user custody** | PhantomChain users never hold ECDSA or other classical keys | Bridge Custodian model holds |
| **Post-quantum internal signing** | All PhantomChain-side transaction authorization uses Dilithium-3 | Physical layer unchanged |
| **Bridge governance resistance** | No single actor (including founder) can unilaterally freeze or redirect bridge funds | Governance threshold enforced |

### Limitations Statement

The External Transaction Layer does NOT provide:

- Full anonymity on external chains (adapter addresses are pseudonyms with a public mapping)
- Trustless bridging (Bridge Custodian model requires threshold trust)
- Immunity from external chain security failures (reorgs, 51% attacks affect bridge safety)
- Post-quantum security on the external chain side (external chains use classical cryptography)
- Protection from legal compelled disclosure of the adapter address → identity mapping (the mapping is public ledger)

These limitations are design decisions, not oversights. Full trustless bridging would require post-quantum light client proofs on external chains — a research frontier, not a deployable primitive. Full anonymity would conflict with PhantomChain's compliance-cooperative design principle. The current model maximizes safety and recoverability within the constraints of the external ecosystem.

---

## Design Consistency Check

The External Transaction Layer is consistent with PhantomChain's core principles as stated in Section 2.2:

| Principle | Maintained? | How |
|---|---|---|
| One person, one wallet | ✓ | External addresses are derived from and controlled by the single PhantomChain identity |
| Biometric sovereignty | ✓ | All outbound initiation requires biometric confirmation; classical keys never in user custody |
| Physical layer immutability | ✓ | External layer is server layer only; physical layer not touched |
| Server layer adaptability | ✓ | All parameters (depths, limits, oracle, custodian set) are server layer governance |
| Human network | ✓ | Bridge Custodians are enrolled PhantomChain identities |
| Post-quantum by default | ✓ | PhantomChain-side signing remains Dilithium-3; external chain side is explicitly identified as classical |
| Cooperative with legal process | ✓ | Full traceability under legal process preserved; no mass surveillance database |
| Trust through verification | ✓ | ZK proofs replace trust at every internal boundary; custodian threshold replaces single-party trust |
| Manipulation resistance by design | ✓ | No single actor controls bridge; threshold model enforced cryptographically |

One acknowledged tension: the Bridge Custodian Pool is the closest thing to a trusted third party that exists anywhere in PhantomChain's design. It is deliberately designed to be threshold-distributed and governance-controlled rather than a single custodian, but it represents a structural departure from the otherwise fully decentralized internal model. This is unavoidable given external chain architecture constraints, and is documented explicitly rather than obscured.

---

*PhantomChain External Transaction Layer — Design Specification v0.2 — June 2026*  
*Document status: Active design. Appendix to PhantomChain v0.2. Subject to revision as open problems are resolved.*  
*Depends on: PhantomChain Design Specification v0.2; Geographic Coverage Premium v0.1 (Section 18)*
