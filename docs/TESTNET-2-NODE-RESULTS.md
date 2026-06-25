# testnet-2 — node results snapshot

Recorded **2026-06-25** (droplet UTC ~06:35), capturing the live 4-validator cluster **before**
repurposing the droplet into a single dev/primary validator with the PC test nodes providing the mesh.
This is the baseline the next build starts from.

## Deployment

- **Host:** DigitalOcean droplet `188.166.224.212` — 7.9 GB RAM (~1.9 GB used), load ~0.04, up 4 days.
- **chainId:** `phantomchain-testnet-2` · `genesisTime=0` · `bridgeThreshold=1`.
- **Topology:** 4 validators, **all on the one droplet** (single-server cluster), launched via
  `com.phantomchain.debug.NodeMain run <config.json> <genesis.json>` from `/root/pc/tn/n0..n3/`.
- **Process uptime:** ~2 d 4 h; RSS 300–480 MB per node (4 JVMs, `-Xmx256m`).
- **Ports 9090–9093:** TLS (HTTPS) RPC, bound `0.0.0.0`, ufw-open. Reachable from droplet localhost
  **and** from a remote PC over the public internet (both verified, below).

## Mesh wiring (per-node config)

| Node | RPC port | selfAddr | seeds | role |
|---|---|---|---|---|
| n0 | 9090 | `188.166.224.212:9090` | `[]` | seed / bootstrap |
| n1 | 9091 | `188.166.224.212:9091` | `[188.166.224.212:9090]` | follower-validator |
| n2 | 9092 | `188.166.224.212:9092` | `[188.166.224.212:9090]` | follower-validator |
| n3 | 9093 | `188.166.224.212:9093` | `[188.166.224.212:9090]` | follower-validator |

`/peers` (n0) reports the full mesh: `{0: …:9090, 1: …:9091, 2: …:9092, 3: …:9093}`.

## Consensus health — all 4 nodes identical → converged

| Metric | Value |
|---|---|
| Committed height | 19 |
| Head | `20 \| d208bf5b28bd64ce2ba15ae0cc7b2544cdcaa5c707849c3991453246578399e4` |
| Mempool | 0 |
| Peers (each node) | 4 |
| Slashed | `[]` |
| Balances | bal0=1000205 · bal1=1000603 · bal2=1000408 · bal3=1000274 |

**Verdict:** BFT-correct convergence — every node reports the identical head hash and balances, empty
mempool, nothing slashed. The cluster is healthy.

## Validator set & economics (`/econ`)

| Node | Stake | Identity | Weight | Balance |
|---|---:|---:|---:|---:|
| 0 | 3,000,000 | 1 | 35.3% | 1,000,205 |
| 1 | 1,000,000 | 1 | 26.0% | 1,000,603 |
| 2 | 1,000,000 | 1 | 26.0% | 1,000,408 |
| 3 | 1,000,000 | 2 | 12.7% | 1,000,274 |

`total_minted=1495 · burned=5 · circulating=10,001,490`. Genesis validator[0] stake 3,000,000,
`verified=true`, alloc 1,000,000.

## Governance params (`/gov`)

`blockReward=100 · halvingBlocks=12 · maxSupply=10,000,000 · feeBurnBps=5000 (50%) · slashBps=10000 (100%) · jailBlocks=10 · unbondingBlocks=10`

## TLS / identity

- Shared CA bundle at `/root/pc/tn/shared/tls/`: `truststore.p12` + `node-0.p12 … node-3.p12`;
  `genesis.json` in `/root/pc/tn/shared/`.
- Each node presents its `node-<i>.p12` on the mTLS RPC/peer port and is validated against the shared
  `truststore.p12`. This is the bundle a new (PC) node needs to join: the truststore + its own cert.

## Reachability (gates the next build)

| From | Result |
|---|---|
| Droplet localhost → `https://127.0.0.1:9090-9093/{status,head}` | ✓ all respond |
| **PC → `https://188.166.224.212:9090-9093/head` (public internet)** | ✓ all return head `20` |

The PC can reach the droplet's TLS RPC, so PC test nodes can connect to the droplet primary.

## Baseline conclusion

The cluster is **healthy and fully converged at head 20**. Recorded as the baseline before the planned
change: (1) reduce the droplet to a **single primary/dev validator**, and (2) stand up the **mesh from
PC test nodes** ("devices") that connect to and follow that primary — since only one server is
available, the mesh comes from the PC nodes, not additional servers.
