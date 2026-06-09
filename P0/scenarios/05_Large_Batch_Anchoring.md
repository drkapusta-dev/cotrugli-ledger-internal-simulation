# 05_Large_Batch_Anchoring.md

**Scenario ID:** P0-05-LargeBatchAnchoring
**Description:** Scale + cost test. Anchor **100, 500, and 1000** evidence items and show the core
economic property: **N items → ONE Merkle root → ONE signed checkpoint → ONE anchor** (the RT0-C
anchoring-cost win), with O(log N) per-item proofs and a deterministic root at every size.

### Objective
Demonstrate that the proof spine scales: the **on-ledger cost is O(1) signatures regardless of N**,
per-item inclusion proofs stay small (O(log N)), every item still verifies offline, and roots are
deterministic at each batch size. State the cost honestly: batching amortizes anchoring, it does not
make it free, and a larger batch trades timeliness/granularity for cost.

### Pre-registered Pass/Fail Criteria
1. 100 / 500 / 1000 items each anchored under **exactly ONE** signed checkpoint (1 signature): **PASS**
2. **All** items verify offline at each size (full-chain): **PASS**
3. Per-item inclusion proof length ≤ `ceil(log2 N) + 1` (O(log N)): **PASS**
4. Root is **deterministic** per N across two runs: **PASS**
5. A proof from one batch does **not** verify against another batch's root (cross-batch replay): **PASS**
6. No over-claim: "1 signature for N items" is the *on-ledger* win; off-ledger blob storage is still
   O(N) (compressed), and anchoring is amortized, not free: **PASS**
7. Vučja otpornost (batch-level): ≥ 8.0 · Ovčja os: ≥ 6.5

### What we measure
- `num_signatures` per batch (must be 1), `tree_size`, max/avg inclusion-proof length vs `log2 N`.
- Informational (non-deterministic) timing: encode+anchor ms and verify ms per size. Timing is
  reported for context only and is **excluded** from the determinism check (which compares roots).

### Execution Steps
1. For N ∈ {100, 500, 1000}: generate N deterministic synthetic items → `anchor_evidence_batch`
   (ONE root, ONE checkpoint) → verify all items offline → record root, proof sizes, 1-signature.
2. Save a full proof package for N=100 + a per-size summary.
3. Red-team (batch-level: cross-batch replay, index/structure abuse, truncation) + Sheep Report + determinism.

### Expected Artifacts
- `proof_package_05.json` (N=100, full) · `large_batch_summary.json` (per-size roots + perf)
- `red_team_report_05.json` · this report's results block

### Anticipated Accepted Limits
- Batching **amortizes** anchoring cost (1 signature / N items) but does not eliminate it; the single
  checkpoint still has a real on-ledger cost.
- Larger batches **delay** an item's provable-anchoring until the batch seals (cost ↔ timeliness tradeoff).
- Off-ledger blob storage scales O(N) (lossless-compressed); the on-ledger commitment stays tiny.

**Status:** Ready to execute
**Next:** Grok red-teams + scores; then RUN 06 — Offline Verification + Erasure Request.
