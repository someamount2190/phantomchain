# PhantomChain — Architecture

This is the authoritative architecture reference. It describes **what is built** (grounded in the actual
code) and the **target design for each upcoming build**, so every subsequent build proceeds against a
deliberate plan. Companion docs: `FRONTIER.md` (tier status), `BUILD.md` (run/repro), the four design
specs in the project root (`phantomchain-*.md`).

Principle that governs everything here: **don't overclaim; design the seams before building; document
OPEN problems honestly** (the same stance the design spec takes with its OPEN-IDs).

---

## 1. Layering

The spec's two-layer split is realized as:

```
┌─────────────────────────────────────────────────────────────────┐
│ CLIENT / EDGE          Android wallet (release): biometric-gated  │
│                        Keystore seal, CA-pinned TLS RPC, QR        │
├─────────────────────────────────────────────────────────────────┤
│ SERVER / MESH          Validators (NetNode): BFT-lite consensus,   │
│ (updatable)            P2P, RPC. Economics, identity, governance.  │
├─────────────────────────────────────────────────────────────────┤
│ STATE MACHINE          Ledger: deterministic state transition,    │
│ (consensus-critical)   committed to by a state root each block.    │
├─────────────────────────────────────────────────────────────────┤
│ PRIMITIVES (immutable) PhantomCrypto: ML-DSA-65, ML-KEM-1024,      │
│                        SHA3, Argon2id, HKDF, ChaCha20-Poly1305.    │
└─────────────────────────────────────────────────────────────────┘
```

**Invariant:** the state machine (`Ledger`) is a pure deterministic function of committed blocks; the
network layer (`NetNode`) drives it but never mutates state outside `commitBlock`. This is what makes the
**state root** meaningful and what every future build (sharding, bridge) must preserve.

---

## 2. Component map (modules → responsibility → key types)

| Module | Responsibility | Key methods/state |
|---|---|---|
| `PhantomCrypto` | PQ primitives only; no consensus logic | `sign/verify` (ML-DSA-65), `sha3_256`, `argon2id`, `hkdf`, `aead`, `backup/recover`, `deviceKeyFromSeed` |
| `Genesis` | Chain definition (public) | `chainId`, `genesisTime`, `validators[{pubkey,stake,identity,verified,alloc}]` |
| `NodeConfig` | Per-node local config (not consensus) | `rpcPort`, `selfAddr`, `seeds[]`, `dataDir`, `keyFile`, `certIndex` |
| `Keys` | Node key persistence (32-byte ML-DSA seed) | `loadOrCreate`, `pubHex`, `idOf` |
| `TlsSetup` | Per-cluster EC CA + node certs; CA retained for onboarding | `ensureCerts`, `mintNodeCert`, `context` |
| `Ledger` | **The state machine**: accounts, validators, identities, economics, governance, estate; tx validation + apply; state root | see §4–§8 |
| `NetNode` | Networked validator: consensus, P2P, RPC | `consensusLoop`, `doRound`, `verifyQC`, `syncValidatorSet`, `serve` |
| `NodeMain` | CLI: `keygen` · `genesis` · `mintcert` · `run` | — |
| `Wallet` / `WalletMain` | Self-custodial wallet logic + CLI | `send`, `account`, `backup/recover`, CA-pinned RPC |
| Android: `MainActivity`, `BioKeystore`, `WalletStore`, `Wallet` | Shippable wallet app | BiometricPrompt → Keystore-sealed seed → live RPC |

Dependency direction is strictly downward: `NetNode → Ledger → PhantomCrypto`. `Ledger` has **no network
dependency** (it's the same class the Android app embeds). Preserve this; sharding/bridge logic that needs
I/O lives in `NetNode`/new modules, not `Ledger`.

---

## 3. Identity & account model (`Ledger`)

Three identity concepts, deliberately separated:

1. **Self-sovereign account** — `id = sha3-256(pubkey)`; any keypair transacts by carrying its `pub` in
   the tx (`pubFor` binds `id == sha3(pub)`). No registration needed.
2. **Registered identity (identity ≠ key)** — `identities[id] = {root, devices[], guardians[], threshold,
   rotNonce}`; `id = sha3(root_pubkey)`. The **root key authorizes rotations/recovery**; **device keys
   spend** (`authPub` requires a current device key). Rotation instantly revokes old keys; guardians enable
   M-of-N recovery.
3. **Validator** — an entry in the append-only `validators[]` list with a consensus pubkey in `valPubs`.
   Joined via `VALJOIN` (bond ≥ `minValidatorStake`).

Account state: `accounts[id] = {balance, nonce}`. Stake/identity-weight/personhood are separate maps
(`stake`, `identity`, `verified`/`vouches`).

---

## 4. Transaction taxonomy

All txs carry `cid` (chainId) and are domain-separated in their signed preimage (no cross-chain replay).
Canonical signing strings: `txCanon(cid,from,to,amount,fee,nonce)` for transfers; `actionCanon(tx)` for
actor-signed actions; bespoke strings for identity/validator ops. Dedup/mempool id = `txId(tx)` (signature,
or content-hash when absent, e.g. RECOVER).

| Type | Auth | Effect |
|---|---|---|
| transfer | device/self-sovereign key | balance move; fee split (burn + proposer) |
| `BOND`/`UNBOND` | actor key (nonce) | balance↔stake; unbond locks `unbondingBlocks` |
| `VALJOIN` | candidate key | append to validator set if bonded ≥ min |
| `SLASH` | equivocation evidence | %-burn stake + unbonding, permanent tombstone + jail |
| `UNJAIL` | actor key | clear temporary jail (not tombstone) |
| `PROPOSE`/`VOTE` | actor key | governance param change (snapshot-weighted, timelocked) |
| `VOUCH` | verified human key | personhood admission (threshold) |
| `REGISTER`/`ROTATE`/`SETGUARDIANS`/`RECOVER` | root key / guardians | identity lifecycle |
| `SETBENEFICIARY`/`CLAIM` | actor key / permissionless | estate/inheritance |

Validation flows through one shared path: `txCheck` (validate vs a projection) → `applyProj` (balance/nonce
deltas) → `commitBlock` (state effects). This single dispatch is the extension point for new tx types.

---

## 5. Consensus architecture (`NetNode` + `Ledger`)

**Type:** BFT-lite. Commit = a **quorum certificate** (QC) = a multiset of ML-DSA signatures over the block
hash from a BFT quorum. (Not a true threshold signature — see Tier-3.)

**Pipeline (per height h):**
```
proposerFor(prevHash,h,view)  →  build proposal (incl. prevStateRoot)  →  /vote (each validator signs ≤1
block/height)  →  collect QC  →  verifyQC (proposer legitimacy + quorum)  →  commitBlock  →  gossip /commit
```

**Key mechanisms (all built):**
- **Proposer selection** — weighted by `weight() = 0.6·√stake-share + 0.4·identity-share` (identity only
  for `verified`), seeded by the **commit-reveal RANDAO `beacon`** (§9.3; each proposer reveals a
  prior-committed secret, `beacon = sha3(beacon | reveal)` — de-grinds leader election).
- **View-change** — `proposerFor(prevHash,h,view)`; a dead proposer's slot times out and the next view's
  proposer takes over. A node never self-equivocates across views (the doRound guard).
- **Quorum** — `quorumNow()` = `active − (active−1)/3` over the **non-excluded** validator set (dynamic;
  tombstoned/jailed don't count → liveness on committed set-shrink; safety preserved).
- **State root** — each block header carries `prevStateRoot` (Tendermint-style app-hash); voting and commit
  reject any block built on a divergent state. This is the integrity backbone.
- **Dynamic membership** — `validators[]` is **append-only** (indices never shift → existing QCs stay
  valid); `VALJOIN` adds, exclusion removes from the active set.
- **Accountability** — equivocation evidence → `SLASH` → %-burn + permanent tombstone.

**Finality:** single-slot, deterministic on QC (no fork-choice needed because conflicting commits are
impossible under a correct quorum). Safety rests on: BFT quorum + chainId/height-bound signatures +
proposer-legitimacy check + state-root agreement.

---

## 6. Networking & transport (`NetNode`)

- **Transport:** TLS 1.3 over a per-cluster EC CA (`TlsSetup`); CA retained (`ca.p12`) for validator
  onboarding. (mTLS client-auth is the documented next hardening; today server-auth + message-layer
  ML-DSA + op-token.)
- **Discovery:** seed → `/announce` (**signed** by the validator's key, anti-eclipse) → `/peers` gossip.
- **Replication:** `/gossip/tx`, `/vote`, `/commit`, `/gossip/vote`, `/gossip/slash`; `/sync` pulls blocks
  block-by-block (verifyQC each).
- **RPC split:** read endpoints open (`/status /econ /identity /account /genesis /head /block /gov
  /identity-info`); write/operator endpoints op-token-gated; `/byz/equivocate` debug-only.
- **Persistence:** atomic write (temp+rename) of `chain.json` + `votes.json`.

---

## 7. Economics & governance (`Ledger`)

- **Emission:** `blockRewardAt(h)` decaying (halvings), supply-capped `maxSupply`, split per epoch by
  on-chain contribution (QC sigs + proposer bonus).
- **Fees:** `feeBurnBps` burned, remainder to block proposer.
- **Staking:** bond/unbond with `unbondingBlocks` lock + maturation queue.
- **Slashing:** `slashBps` of stake + unbonding burned; permanent tombstone; floors prevent governance
  disabling it.
- **Governance:** `PROPOSE`/`VOTE` → snapshot-weighted, turnout-quorum, **timelocked** param changes over a
  whitelist (`GOV_PARAMS`); all params `clamp`ed to safe bounds.
- All economic params are governable instance fields, persisted under `params`, in the state root.

---

## 8. Security model (boundaries)

| Property | Status |
|---|---|
| Post-quantum signing (ML-DSA-65), no ECDSA/RSA | ✅ |
| Cross-chain/replay resistance (chainId domain separation) | ✅ |
| BFT safety (no conflicting commits) | ✅ under honest quorum |
| State integrity (app-hash) | ✅ |
| Self-custody + key rotation + guardian recovery | ✅ |
| Sybil resistance / one-person-one-identity | 🟡 soft (social vouch; OPEN-ID-01) |
| Threshold signature / aggregate QC | 🟡 multisig (no PQ threshold lib) |
| Unbiasable leader election | ✅ commit-reveal RANDAO beacon (residual: 1-bit last-revealer bias) |
| Transport peer-auth | 🟡 server-TLS + signed-announce + op-token (mTLS pending) |

---

## 9. TARGET DESIGNS for upcoming builds

Each build below must (a) keep `Ledger` a pure deterministic state machine, (b) preserve the append-only
validator invariant, (c) extend via the `txCheck`→`applyProj`→`commitBlock` dispatch, and (d) be covered by
the state root. Build only after the relevant section here is settled.

### 9.1 Cluster sharding + geo-premium
**Status: CLUSTER MODEL COMPLETE + LIVE — commitment sharding + RS-erasure-coded storage + geo-premium +
heavy/light tiers + dynamic membership all done.** State is partitioned into `SHARDS=16` by `shardOf(id)`; each
shard is independently rooted (`shardRoot`), a flat shard-root Merkle (`shardsRoot`) is bound into every
block header as `prevShardsRoot` (consensus-verified in `proposalLinks`/`commitBlock`), and light-client
shard proofs (`verifyShardProof`, `/shard?s=`) verify any shard slice against the committed root WITHOUT
holding the rest of the state (verified: proof checks, account-presence, tamper-rejection, cross-node
agreement). This is the foundation that makes the storage layer possible.

**STORAGE LAYER — BUILT + VERIFIED + LIVE, now RS(k,n) erasure-coded** (`ReedSolomon`: GF(256) systematic
Cauchy matrix, MDS, self-tested 500× — any k of n reconstruct). Each node stores only its RS shard
(idx = validatorIndex % RS_N) of each archived block via `pruneBlockRS`; `/rsshard` serves a shard;
`/block` RS-reconstructs from any RS_K shards and verifies vs the committed hash. Verified live: an archived
block's body is `pruned` on every node (each holds a distinct shard) yet every node reconstructs it.
RS_K=2/RS_N=4. (The earlier replication design is superseded; light tier still keeps nothing.) Design follows.
*Decision:* shard the ledger
HISTORY (cold block bodies), NOT the current state. Validation needs current state (bounded by #accounts),
so keeping it replicated preserves the pure state-machine + safety model; history is what grows unbounded
and is worth distributing — exactly the spec's "no single device holds the full ledger." Mechanism: keep
the last `RETAIN_RECENT` bodies fully; for older blocks each validator stores only **assigned** bodies
(`holdsBody(h,i)=∃ r∈[0,R): (h+r) mod N == i`, replication factor `R`, genesis always kept); unassigned
bodies are **pruned** (drop `txs`, keep header). Reconstruction is verified + transparent: `/body?h=` is a
leaf; `/block?h=` reconstructs from the `R` holders and **verifies fetched txs against the committed (QC'd)
block hash** before returning, so sync keeps working and reconstruction is trustless. Pruning never touches
consensus inputs (randBeacon/proposer/epoch read header only) or state/shard roots. This is
**replication-assigned ledger sharding**; the **RS(k,n) upgrade** (store an RS shard not whole-body
replicas; `n/k` overhead vs `R×`) is a drop-in replacement for the store/reconstruct step (needs a GF(256)
codec) — documented frontier. Stateless-witness STATE sharding (validators not holding full current state)
is the deeper frontier, only needed at very large state. **REMAINING after this:** heavy/light tiers;
geo-premium. Original (broader) design below.
**Goal:** stop requiring every validator to hold the whole ledger; add the geo coverage premium.
**Design:**
- **Shard map:** partition the *account/state* space into `S` shards by `shardOf(id) = int(sha3(id)) mod S`.
  Validators are assigned to shards by `assignment(valId, epoch) = shuffle(validators, beacon(epoch))`,
  each validator covering `R` shards (replication factor) for availability.
- **Erasure coding for cold data:** committed block bodies older than a window are Reed-Solomon encoded
  (`k`-of-`n`) and distributed; the header chain (hashes + state roots + QCs) stays fully replicated (small).
  This keeps consensus full-replication on *headers* (cheap, safe) while *bodies/state* sharded.
- **Retrieval protocol:** `/shard/get?key=` returns the shard slice + a Merkle proof against the committed
  state root; any node reconstructs missing shards from `k` peers.
- **Tiers:** `heavy` (serves full shards + processes) vs `light` (header + identity weight + relay) — a
  field in the validator record; light nodes don't get shard-storage assignments.
- **Geo-premium (Doc D):** `region_id = sha3(AS ∥ country)`; opt-in `Verified Regional` validators accept
  anchor RTT checks; `coverage_multiplier = min(MAX, 1+α/(density+β))` applied to `weight()` *before* the
  10% cap. Density from identity weight only.
- **Invariant to preserve:** state root must commit to the **shard roots** (a Merkle root over shard roots),
  so a node can verify any shard slice without holding it. Consensus still commits the global state root.
- **Entry criteria before coding:** finalize `S`, `R`, RS `(k,n)`, the shard-root Merkle layout, and the
  reassignment-on-membership-change protocol (since membership is dynamic).

### 9.2 Cross-chain bridge — ON-CHAIN CORE DONE + verified
On-chain side built: genesis custodian set + threshold, BRIDGE_RESERVE, SHAKE-256 ext-address derivation,
BRIDGE_OUT (lock) + BRIDGE_IN (M-of-N custodian-attested release, replay-guarded). The off-chain custodian
HSM service + zk-STARK proofs + oracle + reorg reconciliation remain the documented frontier (the explicit
trusted/non-PQ surface). Original design:
**Goal:** move value to/from external chains without classical keys in user custody.
**Design (boundary-first):**
- **Trust boundary made explicit:** a bridge **custodian set** (threshold-HSM, M-of-N) is the one
  non-PQ, trusted surface. Keep it OUT of `Ledger`; it's a separate service that posts attestations as txs.
- **Address derivation:** `ext_addr = SHAKE-256("ext_addr_<chain>" ∥ pubkey)` (deterministic, recoverable).
- **Lock/mint:** outbound = on-chain escrow lock → custodian M-of-N sign external release; inbound =
  external deposit → custodian attestation tx → mint from reserve. Both rate-limited.
- **Proofs:** zk-STARK identity proof (PQ, no trusted setup) as the launch proof system.
- **OPEN before mainnet (per spec):** DKG ceremony, oracle manipulation, reserve sizing, reorg depth.
  These gate the bridge; document, don't fake.

### 9.3 Tier-3 primitives (interfaces + interim)
- **Personhood:** keep the pluggable admission tx (VOUCH today); define a `PersonhoodProof` interface so a
  future biometric-uniqueness/ZK proof drops in as a new admission tx without touching consensus.
- **Threshold ML-DSA:** keep the QC interface; swap multisig→aggregate when a prod lib exists.
- **PQ-VRF:** ✅ **DONE — commit-reveal RANDAO beacon** (eth2-proven, existing engineering). Each proposer
  reveals the 32-byte secret it committed in its prior block and commits the next (`commits[validator]`
  binds it); `commitBlock` and `proposalLinks` both verify the reveal so voters reject a bad one, and the
  beacon + commitment map are covered by `stateRoot`. The secret is `HKDF(beaconSeed, "pcbeacon"+ctr)` where
  `beaconSeed` is **derived from the validator's ML-DSA key**, so its `commit0` is publishable at keygen and
  **bound at genesis + `VALJOIN`** (closes the unconstrained-first-reveal grind); the genesis beacon is the
  mix of all founders' `commit0`s, not `ZERO32`. `beaconCtr` is persisted and resynced from the chain on
  restart. Seeds the weighted proposer via `beacon = sha3(beacon | reveal)`. Verified: 67 blocks + restart
  resync + adversarial (`AdversaryTest`, `GenuineAdversaryTest`: 20k grinded first reveals rejected → grind
  closed), LIVE on testnet-2. Residual: 1-bit reveal/withhold + founder ceremony key-grind (trusted setup);
  true PQ-VRF removes both (research-grade). **Bug found in build:** `beaconCommit()` hashes the raw 32
  secret bytes but the first cut of `beaconRevealValid` hashed `utf8(revealHexString)` — off-by-encoding
  stalled consensus at h≈3 until switched to `sha3(unhex(reveal))`. Only surfaced by running a real net.
- **Biometric extractor:** the deprecation trigger for interim QR recovery (stable ≥128-bit key across
  devices at acceptable FRR) — not available; document.

---

## 10. Build sequencing
1. **(done)** Tiers 0–2 core + dynamic validator join.
2. **Cluster sharding** — §9.1; settle shard-root Merkle + reassignment first.
3. **(done)** **PQ-VRF commit-reveal RANDAO** — §9.3; de-risks leader election; verified 67 blocks + restart.
4. **Bridge** — §9.2; only after a custodian-service design review; largest lift.
5. Research items (personhood, threshold ML-DSA, biometric) — partnership/research track, not a sprint.

Each build: design section settled here → implement in `Ledger`/`NetNode` via the standard dispatch →
state-root coverage → local multi-node test → deploy → update `FRONTIER.md` + memory.
