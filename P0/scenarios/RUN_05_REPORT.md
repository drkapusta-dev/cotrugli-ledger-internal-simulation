# RUN 05 — Large Batch Anchoring · Report

**Run ID:** P0-AIAct-Track1-2026-06-09 · **Scenario:** P0-05-LargeBatchAnchoring
**Executor:** Cl1 · **Status:** ✅ all pre-registered criteria PASS · all red-team attacks defended

## What was done
Anchored **100, 500, and 1000** synthetic evidence items, each batch under **exactly ONE** signed
checkpoint, then verified **every** item offline (`P0/scripts/run_large_batch.py`).

## Key outputs
| N | Signatures | Items verified | Max proof len | log₂N+1 bound | anchor (ms)* | verify (ms)* |
|---|---|---|---|---|---|---|
| 100 | **1** | 100 / 100 | 7 | 8 | 16.5 | 17.9 |
| 500 | **1** | 500 / 500 | 9 | 10 | 243.0 | 93.3 |
| 1000 | **1** | 1000 / 1000 | 10 | 11 | 935.3 | 181.6 |

\* timing is hardware-dependent and **informational only** — excluded from the determinism guarantee.

Roots (deterministic): N100 `sha256:49b543ef…4c8018` · N500 `sha256:d21b4c6b…34116f` · N1000 `sha256:1e19ed6b…01f31d`.

**The economic property holds:** N items → ONE Merkle root → ONE signature → ONE anchor. On-ledger
cost is **O(1) signatures regardless of N**; per-item inclusion proofs stay **O(log N)** (7/9/10 ≤
8/10/11). This is the RT0-C anchoring-cost win, made real at scale.

### Pre-registered PASS/FAIL
✅ one signature per batch (all sizes) · ✅ all items verified (all sizes) ·
✅ proofs within log₂N+1 bound (all sizes) · ✅ anchored exactly N items

## Red-Team results (executed) — `P0/scripts/red_team_run_05.py`
| # | Attack | Verdict |
|---|---|---|
| 1 | Cross-batch proof replay | ✅ **PASS** — an item's proof from the 100-batch fails against the 200-batch root; a proof is bound to its own batch. |
| 2 | Index manipulation (wrong leaf index) | ✅ **PASS** — the audit path reconstructs a different root. |
| 3 | Truncate / extend the batch | ✅ **PASS** — dropping or adding one item changes the root; detectable vs the pinned root. |
| 4 | Leaf/node confusion (node hash as a leaf) | ✅ **PASS** — RFC 6962 prefixes leaves (`0x00`) and nodes (`0x01`) differently; a node can't masquerade as a leaf (second-preimage resistance). |
| 5 | Over-claim audit (anchoring cost) | ✅ **PASS** — no over-claim; the cost win is honestly bounded (amortize-not-free, O(N) off-ledger storage disclosed). |

**All 5 attacks defended.**

### ⚠ Honest accepted limits (cost discipline)
1. **One signature for N items is the *on-ledger* win** — batching **amortizes** anchoring; it does
   not make it free. The single checkpoint still has a real on-ledger cost.
2. **Bigger batches delay** an item's provable-anchoring until the batch seals (cost ↔ timeliness tradeoff).
3. **Off-ledger blob storage scales O(N)** (lossless-compressed); only the on-ledger commitment stays tiny.
4. Timing is hardware-dependent; the **determinism guarantee is the ROOT**, not the speed.

## Determinism (confirmed)
Two fresh runs → **all three roots byte-identical** (N=100, 500, 1000).

## 🐑 Sheep Report (for a non-technical reader)
Imagine you must mail **1000 letters** and prove later that none were swapped:

- Instead of paying for **1000 wax seals**, you drop all 1000 into **one tamper-evident sack** and
  apply **a single seal**. That one seal stands behind all 1000 — far cheaper, just as tamper-evident.
- For **any single letter**, there's a short "**path receipt**" (about 7–10 little steps for 100–1000
  letters) that proves *that exact letter* is inside the sealed sack — **without opening the sack or
  reading the others**.
- We tried to cheat the sack: use one letter's receipt for a **different** sack, claim a letter sits
  in the **wrong slot**, **add or remove** a letter, or **disguise a signpost as a letter**. **Every
  trick was caught.**
- **Honest note:** one seal for a thousand letters is cheaper, but it isn't *free* — you still pay for
  the one seal, and you only get the proof once the sack is **closed** (so very large sacks mean a
  little waiting). The sack also still **takes shelf space** for all 1000 letters; only the *seal* is tiny.
- **What this is NOT:** not "infinitely scalable at zero cost" — it's "**the proof cost grows tiny
  (one seal, short receipts) while the honest accounting stays exact.**"

## Next
**RUN 05 READY.** Awaiting Grok red-team review + score; then RUN 06 — Offline Verification + Erasure Request (the final P0 scenario).
