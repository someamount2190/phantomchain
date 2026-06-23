# PhantomChain
## Geographic Coverage Premium — Design Specification
### Section 18 Amendment to PhantomChain Design Specification v0.2

---

**Classification:** Working Design Document  
**Version:** 0.1  
**Date:** June 2026  
**Status:** Active Design — Open Problems Enumerated  
**Amends:** PhantomChain Design Specification v0.2, Section 9.4 (Mining Weight Formula)  
**Section Number:** 18 (continuation of v0.2 numbering)

---

## Table of Contents

18. [Geographic Coverage Premium](#18-geographic-coverage-premium)
    - [18.1 Design Principle](#181-design-principle)
    - [18.2 Participation Tiers](#182-participation-tiers)
    - [18.3 Region Identity](#183-region-identity)
    - [18.4 Verification by Anchor Observers](#184-verification-by-anchor-observers)
    - [18.5 Coverage Density](#185-coverage-density)
    - [18.6 The Multiplier](#186-the-multiplier)
    - [18.7 Minimum Cluster Size](#187-minimum-cluster-size)
    - [18.8 Sparse Region Override](#188-sparse-region-override)
    - [18.9 Cluster Collapse and Region Vacancy](#189-cluster-collapse-and-region-vacancy)
    - [18.10 Anchor Node Ineligibility](#1810-anchor-node-ineligibility)
    - [18.11 Amended Mining Weight Formula](#1811-amended-mining-weight-formula)
    - [18.12 Parameter Summary](#1812-parameter-summary)
    - [18.13 Open Problems](#1813-open-problems)

---

## 18. Geographic Coverage Premium

### 18.1 Design Principle

The geographic premium is a security mechanism, not a growth incentive. Its purpose is to ensure that no single geography dominates consensus weight by making coverage of sparse regions economically attractive. Expansion into underserved regions is a secondary consequence, not the primary goal.

The premium attaches to the region's coverage state, not to any individual cluster. No cluster owns the premium. It is earned collectively by all clusters in a sparse region and disappears as the region fills. There is no first-mover advantage to capture.

**The single statement that defines the premium:**

> A cluster earns more weight not because it arrived first, but because the region it serves is underserved. The moment the region is adequately served, the premium contracts automatically — for everyone in it, equally.

This design neutralizes the two failure modes of the original one-line formulation in Section 9.4:

- **Land-grab entrenchment** — prevented because the premium attaches to the region's state, not to any cluster's registration timestamp
- **Capital substitution for geography** — prevented because coverage density is computed from identity weight, not stake weight

### 18.2 Participation Tiers

Geographic premium is opt-in. Participation requires accepting verification overhead and making region declaration public on-chain. Clusters that do not opt in participate fully in consensus, mining, and governance with no penalty — they simply earn no geographic premium.

```
STANDARD CLUSTER (default):
  No region declaration
  No verification overhead
  No geographic premium
  Full consensus, mining, and governance participation
  Infrastructure location privacy preserved

VERIFIED REGIONAL CLUSTER (opt-in):
  Declares region on-chain (AS number + ISO 3166 country code)
  Accepts RTT verification by anchor observers at enrollment and each epoch
  Region declaration permanently public on-chain
  Earns regional coverage multiplier while region is sparse
  Subject to periodic re-verification — verification status public at all times
```

The opt-in structure makes the verification cost a voluntary signal of genuine regional presence. A cluster that accepts the verification overhead has a stronger legitimate claim to the premium than one that would receive it by default.

Privacy preservation is a first-class concern: operators who have legitimate reasons not to disclose infrastructure location — security, jurisdiction, personal safety — are never coerced into disclosure by the premium mechanism. The premium is an incentive, not a gate on participation.

### 18.3 Region Identity

A region is identified by a composite of network-layer and legal-layer signals:

```
region_id = SHA3-256(AS_number ∥ ISO_3166_country_code)
```

**AS number** captures actual network infrastructure topology — the autonomous system that routes the cluster's traffic. This reflects real physical network presence more accurately than IP geolocation alone.

**ISO 3166 country code** anchors the region to legal jurisdiction. A single AS spanning multiple countries is appropriately split into distinct regions. A single country served by multiple AS numbers produces multiple distinct regions within that country, which is correct — they represent genuinely different network zones.

Region identity is not self-declared. The cluster proposes a claim; the anchor observer network confirms or rejects it.

**Known limitation — mobile networks:** Mobile carriers frequently route traffic through AS numbers registered to their national headquarters rather than the device's physical location. A device in a rural area may appear under the same AS as the carrier's urban core. Section 18.4 addresses this as a known edge case, and [OPEN-GEO-02] tracks the formal resolution.

### 18.4 Verification by Anchor Observers

Region claims are verified using RTT triangulation from the founder anchor nodes (Section 12.2). Anchor nodes are already geographically distributed across distinct jurisdictions and serve as the natural reference set. No separate verification infrastructure is required.

```
VERIFICATION FLOW:

Cluster submits region claim:
  {
    declared_AS:       ASN,
    declared_country:  ISO_3166,
    cluster_id:        on-chain identifier,
    signature:         Dilithium-3 (cluster operator fingerprint)
  }
        │
        ▼
Each anchor node independently measures RTT to cluster
        │
        ▼
RTT readings compared against expected latency envelope
for declared region (derived from public internet latency maps —
see [OPEN-GEO-01] for calibration governance)
        │
        ├──► All anchors consistent with declared region
        │    └──► Verified — premium eligible
        │
        ├──► Majority consistent, minority outlier
        │    └──► Verified with on-chain flag
        │         (flag visible — governance may investigate)
        │
        └──► Majority inconsistent with declared region
             └──► Claim rejected — no premium
                  Cluster may resubmit after cooling period
                  (default: 7 days — server layer parameter)
```

**Re-verification cadence:** Verification is re-run every epoch (server layer parameter). A cluster that migrates its infrastructure loses verified status until re-confirmed by the next verification cycle.

**Residual risk — VPN spoofing:** A cluster operating behind a VPN could sustain RTT signatures consistent with a false region claim across multiple anchor measurements and epochs. This is accepted as a non-critical residual risk. The attack requires sustained multi-anchor RTT deception for the full duration of premium capture, at infrastructure cost that is likely to exceed the marginal premium value for any realistically-sized cluster. The geographic premium is an incentive layer — a successfully maintained deception captures modestly inflated weight on a single cluster, bounded by the hard cap and minimum cluster size requirement. The cost-benefit does not favor the attack at any interesting scale.

### 18.5 Coverage Density

Coverage density for a region is computed from identity weight, not stake weight. A region is genuinely covered when real enrolled humans are operating there — capital deployment alone does not constitute coverage.

```
coverage_density(region) =
  Σ(identity_weight of verified active clusters in region)
  ─────────────────────────────────────────────────────────
           total_network_identity_weight
```

Only verified regional clusters contribute to a region's coverage density. Standard clusters are invisible to the density calculation — they neither earn the regional premium nor suppress it for verified clusters in that region.

This has a deliberate consequence: a well-capitalized standard cluster cannot suppress a region's sparseness reading by parking stake in that region without accepting verification. The premium responds only to real, verified human presence.

### 18.6 The Multiplier

```
regional_coverage_multiplier(region) =
  min(
    MAX_MULTIPLIER,
    1 + (α / (coverage_density(region) + β))
  )

Parameters (server layer — adjustable via governance):
  α               = 0.2    (curve magnitude)
  β               = 0.1    (softening constant — stability near zero density)
  MAX_MULTIPLIER  = 2.5    (hard ceiling)
```

**Behavior across coverage density levels:**

| Coverage Density | Raw Curve Value | Effective Multiplier | Interpretation |
|---|---|---|---|
| 0% | 1 + 2.0 = 3.0 | 2.5 (capped) | Fully unserved region |
| 5% | 1 + 1.33 = 2.33 | 2.33 | Very sparse |
| 10% | 1 + 1.0 = 2.0 | 2.0 | Sparse |
| 20% | 1 + 0.67 = 1.67 | 1.67 | Developing coverage |
| 50% | 1 + 0.33 = 1.33 | 1.33 | Moderate coverage |
| 100% | 1 + 0.18 = 1.18 | 1.18 | Approaching baseline |

**The multiplier is identical for all verified clusters in the same region simultaneously.** As more clusters join a region, all of them earn less — including earlier ones. As clusters leave or collapse, all remaining clusters earn more. No cluster can hold a premium it earned before others arrived.

**Interaction with the 10% hard cap:** The regional multiplier inflates a cluster's effective weight before the cap check. The 10% hard cap from Section 9.4 applies after multiplication. A cluster in a sparse region cannot use the geographic premium to exceed 10% of total network weight.

**Parameter governance:** All three curve parameters are server layer values, observable and adjustable by community vote. The initial values are deliberately conservative starting points. As the network matures and empirical density data accumulates, governance can refine these to match observed participation patterns. The relationship between parameters should be preserved in governance proposals: raising MAX_MULTIPLIER without raising β risks instability at near-zero density; changing α alone shifts the density level at which the premium becomes meaningful.

### 18.7 Minimum Cluster Size

A cluster must meet a minimum active device threshold before qualifying for the regional premium. This prevents the Sybil geography attack — registering minimal clusters across many sparse regions to harvest multiplied weight at low cost from multiple small positions.

```
K(t) = max(FLOOR_K, round(GROWTH_FACTOR × total_enrolled_identities(t)))

Parameters (server layer):
  FLOOR_K        = 5      (absolute minimum at any network scale)
  GROWTH_FACTOR  = 0.001  (0.1% of total enrolled identities)

Behavior at network scale:
  1,000 enrolled:      K = max(5, 1)    = 5
  10,000 enrolled:     K = max(5, 10)   = 10
  100,000 enrolled:    K = max(5, 100)  = 100
  1,000,000 enrolled:  K = max(5, 1000) = 1,000
```

**Active devices only:** K counts active contributing devices in the current epoch — not enrolled members, not dormant devices. A cluster with 20 enrolled members where 4 are actively contributing this epoch has an effective size of 4 for K evaluation. Enrollment without contribution does not satisfy K.

**Security property of dynamic K:** As the network grows, the cost of the distributed Sybil geography attack grows proportionally. At small network scale, K=5 is cheap but total network weight is small — the attack gains little. At large network scale, K=1000 per sparse-region cluster becomes expensive to execute across many regions simultaneously, while the premium is also smaller because density has normalized globally. Attack cost tracks attack value at every scale.

### 18.8 Sparse Region Override

The dynamic K grows with network size. Without a correction, genuinely sparse regions would be priced out of the premium as the global network scales — a remote community of 50 people cannot field K=1000 active devices regardless of their genuine need for coverage incentives.

The sparse region override resolves this without requiring population oracles, external demographic data, or any centralized judgment about what constitutes a "sparse" population.

```
K EVALUATION LOGIC per region:

if total_enrolled_identities_in_region(t) < SPARSE_THRESHOLD:
    effective_K(region) = FLOOR_K
else:
    effective_K(region) = max(FLOOR_K, round(GROWTH_FACTOR × total_network_enrolled(t)))

Parameters (server layer):
  SPARSE_THRESHOLD = 500  (total enrolled identities across all clusters in region)
```

**How the override works:** A region where fewer than SPARSE_THRESHOLD total people have enrolled across all its verified clusters is treated as structurally sparse. The global dynamic K does not apply. These clusters need only meet FLOOR_K = 5 active devices to qualify for the premium — regardless of global network size.

Once a region's total enrolled identity count crosses SPARSE_THRESHOLD, it transitions to the global dynamic K on the next epoch boundary. There is no retroactive penalty — clusters that qualified under the override continue to qualify provided they meet the new effective K.

**SPARSE_THRESHOLD governance:** SPARSE_THRESHOLD is a server layer parameter, adjustable by governance. The initial value of 500 is a conservative placeholder. The correct value is deployment-context dependent:

- A dense urban barangay may reach 500 enrolled identities quickly — the threshold would be appropriate
- A remote island community may never reach 500 total adults — the threshold should be lower for that context
- A national rural network may have many clusters each with 30-100 people — the threshold should accommodate that structure

Governance should revisit SPARSE_THRESHOLD as real enrollment data becomes available from deployment contexts. The threshold is not a one-size-fits-all number — it is a parameter that should track observed participation patterns in the communities the network actually serves.

**Transition smoothing:** A hard threshold transition creates a discontinuity — a region at 499 enrolled identities qualifies under FLOOR_K; at 500 it suddenly needs dynamic K, which at large network scale might be 500 or more. [OPEN-GEO-03] tracks the design of a graduated transition window that interpolates effective_K over some number of epochs to prevent abrupt premium loss for communities that cross the threshold.

### 18.9 Cluster Collapse and Region Vacancy

When a verified regional cluster collapses (falls below the consensus threshold per Section 9.3), its contribution to coverage density is removed from the next epoch's calculation. The region's density drops. The multiplier rises for any remaining clusters in that region, and rises to maximum if the last cluster in a region collapses.

No explicit vacancy management is required. The density formula handles it automatically. There is no premium to transfer because no cluster ever owned it — the premium was a property of the region's state expressed through the formula.

```
Region with 3 verified clusters (density D, multiplier M):

Cluster A collapses
  → Region density drops to D'
  → Multiplier rises to M' for Clusters B and C
  → No action required by B, C, or governance

Clusters B and C also collapse
  → Region density returns to 0
  → Multiplier rises to MAX_MULTIPLIER (2.5)
  → Region is fully vacant again — maximum incentive for new cluster formation
  → Any new cluster forming in this region earns MAX_MULTIPLIER
     (subject to meeting K and passing verification)
```

The collapse model interacts correctly with the premium: a poorly-performing region empties, the premium maximizes, and new clusters are incentivized to form. There is no governance action required and no prior cluster has any claim on the premium when the region reforms.

### 18.10 Anchor Node Ineligibility

Founder anchor nodes designated at genesis are permanently ineligible for the regional coverage multiplier.

```
Ineligibility properties:
  Set:      genesis configuration
  Scope:    all anchor nodes designated at genesis
  Duration: permanent — no expiry, no review
  Override: none — cannot be removed by any server layer governance vote
  Visibility: public and auditable on-chain from block zero
```

The immutability of this designation is intentional and important. A server layer governance vote that granted anchor nodes premium eligibility would undermine the purpose of the premium — bootstrap infrastructure should not capture the incentive structure designed for organic community growth. Making the ineligibility immutable removes it from the political surface of governance entirely.

Anchor nodes participate in all normal consensus weight mechanisms — stake weight, identity weight, the 60/40 formula. Their participation is rewarded appropriately. The geographic premium is specifically reserved for the community clusters that provide the organic coverage the network depends on at scale.

### 18.11 Amended Mining Weight Formula

This section amends Section 9.4 of the base specification. The full amended formula:

```
Cluster weight = base_weight × regional_coverage_multiplier(region)

Where:

base_weight =
  (stake_component × 0.6) + (identity_component × 0.4)

  stake_component     = √(cluster_total_stake) / Σ√(all_cluster_stakes)
  identity_component  = cluster_enrolled_identities / total_network_identities

regional_coverage_multiplier(region) =
  1.0                                          if cluster is Standard (no verification)
  min(MAX_MULTIPLIER, 1 + α/(density + β))     if cluster is Verified Regional
                                               AND active_devices ≥ effective_K(region)
  1.0                                          if cluster is Verified Regional
                                               but active_devices < effective_K(region)

effective_K(region) =
  FLOOR_K                                      if total_regional_enrolled < SPARSE_THRESHOLD
  max(FLOOR_K, round(GROWTH_FACTOR × N))       otherwise
  where N = total_enrolled_identities on network

Hard constraints (unchanged from Section 9.4):
  No single cluster > 10% total network weight (applied after multiplier)
  Geographic bonus applies after the 60/40 base formula
  Data center concentration rule (Section 12.5) applied independently
```

**Interaction between multiplier and hard cap:** The multiplier is applied to base_weight before the 10% cap check. A cluster with 5% base_weight in a MAX_MULTIPLIER region has 12.5% effective weight — which is capped to 10%. The excess is redistributed. This is the correct behavior: the cap enforces network-wide concentration limits unconditionally; the premium operates within that constraint.

### 18.12 Parameter Summary

All parameters are server layer values, adjustable via governance. Initial values are conservative starting points, not permanent commitments.

| Parameter | Initial Value | Description | Governance Notes |
|---|---|---|---|
| α | 0.2 | Multiplier curve magnitude | Raise to strengthen incentive; lower to reduce premium value |
| β | 0.1 | Curve softening constant | Raise to flatten curve near zero density; lower to steepen it |
| MAX_MULTIPLIER | 2.5 | Hard ceiling on multiplier | Should not be raised above ~3.0 without simulation of weight distribution effects |
| FLOOR_K | 5 | Minimum active devices regardless of network size | Must remain low enough for genuine sparse communities to qualify |
| GROWTH_FACTOR | 0.001 | Dynamic K as fraction of total enrolled identities | Governs attack cost at scale — do not lower without security analysis |
| SPARSE_THRESHOLD | 500 | Regional enrolled count below which FLOOR_K applies | Should be calibrated to real deployment contexts |
| Verification epoch | Every epoch | RTT re-verification cadence | Raising reduces overhead; lowering improves detection of infrastructure migration |
| Claim cooling period | 7 days | Wait after rejected claim before resubmission | Prevents rapid resubmission farming |
| RTT reference update cadence | Quarterly | How often the latency reference map is refreshed | Subject to [OPEN-GEO-01] governance design |

### 18.13 Open Problems

**[OPEN-GEO-01] RTT envelope calibration and governance**

The latency envelope used to validate RTT readings against declared regions must be sourced from a reliable, manipulation-resistant dataset. Public internet latency datasets (CAIDA Ark, RIPE Atlas) are the natural sources but require periodic updating as global routing changes. Two sub-problems need design:

- *Source governance:* Who controls the reference dataset, how is it updated, and how are updates validated before deployment? An anchor node operator who also controls the reference dataset has a conflict of interest.
- *Staleness detection:* A stale reference map silently degrades verification quality — claims that should be rejected pass, and legitimate claims in regions with changed routing may fail. An active staleness detector is needed.

This is a prerequisite for RTT verification operating correctly in production. Not a launch blocker for the premium feature itself (the premium can launch with a best-effort static reference), but required for long-term verification integrity.

**[OPEN-GEO-02] AS number assignment for mobile-heavy networks**

Mobile network carriers frequently route traffic through AS numbers registered to their national headquarters rather than the device's physical location. A device in rural Zamboanga may appear under the same AS number as a carrier's Manila datacenter. This would mis-assign genuine sparse-region clusters to a different region, disqualifying them from the premium they should earn.

Two candidate resolutions:

- *Country-code preference:* When AS number and country code conflict (AS registered in country X, device latency profile consistent with country Y), prefer country code for region assignment. Requires the verification protocol to detect this conflict.
- *Carrier AS whitelist:* Maintain a list of known national carrier AS numbers that are consistently mis-assigned, with explicit country override rules. Requires ongoing maintenance and introduces a governance surface.

Neither is clean. This is a real deployment risk for mobile-heavy communities — which are exactly the communities the premium is designed to serve.

**[OPEN-GEO-03] SPARSE_THRESHOLD transition management**

When a region crosses SPARSE_THRESHOLD, its effective K transitions from FLOOR_K to the global dynamic K. At large network scale (1M enrolled), the dynamic K could be 1000 — a jump from 5 to 1000 in a single epoch for a community that has just crossed 500 enrolled. Clusters that were qualifying under FLOOR_K may suddenly fail the K check and lose the premium.

A graduated transition window would smooth this:

```
During transition window (default: 30 epochs after crossing SPARSE_THRESHOLD):
  effective_K = FLOOR_K + (dynamic_K - FLOOR_K) × (epochs_since_crossing / window_length)
```

This interpolates K linearly over the window, giving existing clusters time to grow their active device count before facing the full dynamic K. The window length is a server layer parameter. The interaction between transition window length and the epoch cadence of K recalculation needs formal design.

---

*PhantomChain Geographic Coverage Premium — Design Specification v0.1 — June 2026*  
*Document status: Active design. Amends Section 9.4 of PhantomChain Design Specification v0.2.*  
*Section 18 of the PhantomChain specification family.*
