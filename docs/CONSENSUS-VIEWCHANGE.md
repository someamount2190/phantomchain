# Design: View-Change Certificates (closes [OPEN-BFT-01], the residual #1 wedge)

**Status:** target semantics — **specified, intentionally NOT hand-rolled.** The *common* wedge (proposer
crash with a converged mempool) is already fixed by deterministic proposals (`Ledger.nextBlockTs`, see
`VoteLockWedgeTest`) — a small, fully-verifiable change. The **residual** (divergent mempool / Byzantine
proposer can still produce a different-hash later-view block that per-height-locked validators reject) needs
a full view-change protocol.

**Implementation stance (project philosophy: no hand-rolled safety-critical code).** PhantomChain takes its
safety-critical primitives from vetted libraries (BouncyCastle for all crypto; threshold-ML-DSA and PQ-VRF
are documented as honest gaps awaiting production libraries, *not* rolled in-house). A correct BFT
view-change is exactly that class of primitive — subtle, fork-on-mistake, and impossible to verify
exhaustively by ad-hoc tests. So this is **not** a hand-rolling guide. The complete fix should be either:
- a **vetted/audited BFT engine** (e.g. BFT-SMaRt — academically reviewed, Java) adopted under the
  validator API, or a CometBFT-style engine via a stable interface; or
- a **formally-verified** view-change implementation.

This document is the **required behaviour** — the safety and liveness properties any such implementation
must satisfy, and the adversarial scenarios that gate it — so the chosen library/implementation can be held
to a precise contract. It is the same posture FRONTIER takes for threshold-ML-DSA: *interface ready, swap in
a proven implementation; do not roll it.*

## The problem, precisely

A validator's vote at height `h` locks per-height and is never released (`votedAt[h]`). A block commits with
a quorum `Q = c − (c−1)/3` of signatures over its hash. The single-phase QC gives **single-slot finality**:
the vote IS the commit signal. Safety today rests on "one signature per height per validator," so two
conflicting blocks can never both reach `Q` (their quorums would overlap in a validator that signed both).

The cost is liveness: if a view-0 block gathers a sub-quorum partial vote and then stalls, the locked voters
reject every different-hash later-view block forever (`VoteLockWedgeTest`, residual half).

## Why there is no shortcut

To let a locked validator safely vote a *different* block `B1` at a higher view, it must know that the block
it locked on, `B0`, **did not and cannot commit**. A validator's local view of gossiped votes is **not**
sufficient: under partition it may have seen only `B0`'s votes while `B0'` committed on the other side. The
only way to be certain is evidence from a **quorum** of validators — which, intersecting any commit-quorum
in `> f` nodes, is guaranteed to surface a committed block. That evidence is the view-change certificate.

## Protocol

### Messages
- `VIEW-CHANGE`: `{ h, newView, highVote: {hash, view, sig} | null, valId, sig }`
  - `highVote` = the highest-view block this validator has voted at height `h` (its `votedAt[h]` plus the
    view it voted in), or `null` if it has voted nothing at `h`.
  - signed by the validator over `(chainId, h, newView, highVote)`.
- `VCC` (view-change certificate): a set of `≥ Q` distinct valid `VIEW-CHANGE` messages for the same
  `(h, newView)`.

> Implementation note: today a vote is `{valId, height, hash, sig}` with no `view`. Add the `view` the vote
> was cast in to `votedAt[h]` so `highVote` can carry it. This is a persisted-state format change
> (`votes-<i>.json`) — migrate by treating a missing `view` as 0.

### Flow
1. **Timeout.** When a validator's view timer for `(h, view)` expires without a commit, it broadcasts
   `VIEW-CHANGE(h, view+1, highVote)` to the peer set and stops voting in `view`.
2. **Collect.** The scheduled proposer for `(h, view+1)` gathers `VIEW-CHANGE` messages until it has `Q`
   distinct valid ones → a `VCC`.
3. **Select the value (the safety-critical rule).**
   - If any `highVote` in the `VCC` is non-null, the proposer **MUST re-propose the block with the highest
     `view`** among them (ties broken by the lowest hash — deterministic). It must supply that exact block
     body (it has it from proposal gossip, or fetches it by hash). It may **not** propose fresh.
   - If every `highVote` is null, the proposer is free to build a fresh deterministic proposal.
4. **Propose with justification.** The `(h, view+1)` block carries the `VCC`. The block hash preimage is
   unchanged (content-addressed); the `VCC` rides alongside, like the `qc`.
5. **Vote with lock-release.** A validator receiving the `(h, view+1)` proposal:
   - verifies the `VCC` (≥ `Q` distinct valid `VIEW-CHANGE` for `(h, view+1)`),
   - verifies the proposed block matches the VCC selection rule (highest-view `highVote`, or fresh iff all
     null),
   - and **only then** replaces `votedAt[h]` with the new block and signs it. The per-height reject is kept
     for any proposal **without** a valid justifying `VCC` (so the fast path is unchanged and equivocation
     is still impossible without a certificate).

### Safety argument (sketch — to be hardened before implementation)
Suppose `B0` committed at `(h, v0)`: a quorum `Q0` signed `B0`. Any `VCC` for `(h, v>v0)` contains `Q`
messages; `|Q0| + |Q| > c + f`, so they intersect in `> f` validators, ≥1 honest. That honest validator's
`highVote` reports `B0` at view `≥ v0`, and no honest validator reports a *conflicting* block at a higher
view (it would have had to sign two blocks at `h`, which the per-height lock forbids without a VCC, and a VCC
for a conflicting block would itself require this same argument). So the highest-view `highVote` in any VCC
is `B0`, the proposer must re-propose `B0`, and no conflicting block can be proposed-with-justification →
no fork. Liveness: once mempools converge and a correct proposer collects a VCC, it either re-proposes the
stuck block (which now reaches `Q`) or, if nothing was voted, proposes fresh.

### Persistence & timers
- Persist `votedAt[h]` **with its view** (format migration above).
- Persist the highest `newView` a validator has sent a `VIEW-CHANGE` for, to avoid contributing to two
  different VCCs at the same height after a restart.
- View timer already exists (`VIEW_TIMEOUT`); add the `VIEW-CHANGE` broadcast on expiry.

## Test plan (build alongside, not after)
1. **Liveness:** N=4, proposer for view 0 crashes after a sub-quorum partial vote on a *divergent* mempool;
   assert the view-1 proposer collects a VCC, re-proposes, and the height finalizes. (`VoteLockWedgeTest`
   residual flips to "finalizes".)
2. **Safety — forged VCC:** a VCC with `< Q` or duplicate/foreign signatures is rejected.
3. **Safety — partition + merge:** split the validators, let one side gather votes for `B0`; assert the
   other side can never finalize a conflicting `B1` (the VCC forces re-proposing `B0`).
4. **Safety — Byzantine proposer:** a proposer that proposes fresh despite a non-null `highVote` in its VCC
   is rejected by honest validators.
5. **Equivocation unchanged:** a validator that signs two blocks at `h` without a VCC is still slashable.
6. **Restart:** a validator that sent `VIEW-CHANGE(h, v)` does not contribute to a different VCC at `h`
   after a crash-restart.

## Adoption path (not a hand-roll)
The contract above is what a chosen implementation must satisfy; it is **not** a license to roll the protocol
in-house. Realistic options, in order of preference:
1. **Adopt a vetted BFT engine** (BFT-SMaRt or equivalent) behind a thin adapter: PhantomChain's blocks/QC
   become that engine's value/decision, and `votedAt`/QC give way to the engine's lock/commit. The adapter
   maps the safety/liveness contract above onto the engine's guarantees.
2. **Formally-verified view-change** (e.g. a TLA+/Ivy-checked spec compiled or carefully transcribed) if a
   library swap is too invasive for the current single-phase QC.
3. **Stay on the current simple consensus** with the deterministic-proposal mitigation, and keep this as a
   documented honest gap (the present state) — appropriate while clusters are small and mempools converge.

Any of these is a deliberate, reviewed change; the surfaces it would touch (`Consensus`, `NodeRpc`,
`NetNode`, the `votes-<i>.json` format) are listed only so an integrator knows the blast radius. The
adversarial test plan above is the acceptance gate regardless of which option is chosen.
