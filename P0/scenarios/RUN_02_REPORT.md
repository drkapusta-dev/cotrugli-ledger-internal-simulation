# RUN 02 — Error & Recovery · Report

**Run ID:** P0-AIAct-Track1-2026-06-09 · **Scenario:** P0-02-ErrorRecovery
**Executor:** Cl1 (Core Attestor) · **Status:** ✅ all pre-registered criteria PASS · all red-team attacks defended

## What was done
Ran the real Evidence Codec v0.2 + anchor spine on **24 synthetic agent tool-calls** with a
realistic failure mix and explicit retry chains (`P0/scripts/run_error_recovery.py`):

- statuses: **14 success · 5 error · 2 partial · 3 timeout** · **7 retry records**
- retry chains, e.g. `op-04-a1` (timeout) → `op-04-a2` (error) → `op-04-a3` (success) — three
  separate anchored leaves; the failures stay on the record.

```
24 mixed items -> lossless blobs (failures committed exactly like successes)
  -> ONE Merkle root -> ONE Ed25519 signed checkpoint
  -> offline verify ALL 24 -> recovery append-only checks -> corrupt-blob fail-closed -> idempotent re-run
```

## Key outputs
| Fact | Value |
|---|---|
| Items encoded & batched | **24 / 24** (failures included) |
| Merkle root (deterministic) | `sha256:2295e9501d4c58bae231bbf8dec6a92ef0fdd1b1a92ab9bbecd55f99c5a51b04` |
| Offline verification (public package only) | **24 / 24 full-chain OK** |
| Failure faithfulness | 10 non-success records attested **verbatim** (status never rewritten) |
| Recovery append-only | **7 / 7** retries are separate leaves; each prior attempt present, unchanged, verifies |
| Corrupt-blob probe (an error record) | **detected**, localized; neighbour + checkpoint untouched |

### Pre-registered PASS/FAIL
- ✅ all items encoded & batched
- ✅ failures attested faithfully (not dropped, not rewritten to success)
- ✅ recovery append-only (retry = new leaf; prior attempt intact & verifies)
- ✅ attempt→retry linkage resolvable **without mutating** the original
- ✅ corrupted blob detected & localized (fail-closed)
- ✅ full offline verification

## Red-Team results (executed) — `P0/scripts/red_team_run_02.py`
**PASS = the cheat is rejected.** Results in `P0/evidence/red_team_report_02.json`.

| # | Attack | Verdict | What happened |
|---|---|---|---|
| 1 | Rewrite a failure as a success | ✅ **PASS** | keep commitment → `blob_intact=False`; forge commitment → `merkle_inclusion=False`. A failure can't become a success under the signed root. |
| 2 | Drop a failed attempt from an anchored batch | ✅ **PASS** *(+ accepted limit)* | dropping the item yields a **different** root → rejected against the pinned root. |
| 3 | Launder a failure via a forged "successful retry" | ✅ **PASS** | forged retry is not a leaf under the root → rejected; the original failure leaf still verifies. Recovery is append-only, never erasure. |
| 4 | Over-claim audit (recovery discipline) | ✅ **PASS** | no forbidden/over-claim phrases; failures still counted as failures (10); honest_limits present. |

**All 4 attacks defended.**

### ⚠ Honest ACCEPTED LIMITS (confirmed this run)
1. **Recovery is permanent-append, not erasure.** A retry adds a new record; the failure stays on
   the chain forever (immutability). The system never makes a failure disappear — by design.
2. **The spine detects but does not recover content.** A corrupted off-ledger blob is *detected* and
   *localized* (it says which item), but the content cannot be recovered from the proof spine —
   content lives off-ledger; re-fetch from the source/custody layer is required. (Proof spine ≠
   storage durability.)
3. **Pre-ingestion omission is not provable-absent by the spine alone.** Dropping an item from an
   *already-anchored* batch changes the (pinned) root and is caught (attack 2). But an event that
   **never enters** the batch can't be proven missing without a heartbeat/sequence layer (P1+).
4. **Retry linkage is attested-as-claimed.** The spine attests that a `retry_of` link was *recorded*;
   it does not attest that the retry semantically belongs to the same logical operation (an operator
   could mislabel the link). Semantic correctness of the link is overlay/review, not core.

## Determinism (confirmed)
Two fresh runs → **byte-identical**:
- root `sha256:2295e9501d4c…a51b04`
- digest over (root + all 24 commitments + all inclusion proofs) `cf34d676…54d7f0` — identical.

## 🐑 Sheep Report (for a non-technical reader)
- This time the AI agent's work **didn't all go smoothly**: some actions failed, some half-finished,
  some timed out, and some were **tried again**. We recorded **all 24** of them — the good and the bad.
- **Failures are kept as failures.** We never quietly turn a failed action into a "success." If you
  later look, a failure still reads as a failure — sealed, unchangeable.
- **Trying again doesn't erase the first try.** A retry is a *new* sealed record that points back to
  the failed one. The original failure stays on the record permanently. Nothing is swept under the rug.
- An **independent checker** confirmed all 24 records (failures included) are intact and belong to the
  signed bundle. **24 out of 24 passed.**
- We then **tried to cheat**: turn a failure into a success, secretly delete a failed record, sneak in
  a fake "successful retry," and over-promise in the wording. **Every cheat was caught.**
- **Honest caveats:** (a) once recorded, a failure can never be deleted — recovery means *adding* a new
  record, not fixing the past; (b) if a record is damaged in storage, we can *tell you which one* is
  damaged but we can't magically restore its contents; (c) if someone never records an action at all,
  this layer alone can't prove it was hidden (that needs an extra "nothing-missing" mechanism, later).
- **What this is NOT:** not a certificate, not "the AI worked correctly", not "no errors happened" —
  only that **what was recorded is intact, honestly labelled, and checkable**, errors and all.

## Next
**RUN 02 READY.** Awaiting Grok red-team review + score; then RUN 03 — Malicious Bypass.
