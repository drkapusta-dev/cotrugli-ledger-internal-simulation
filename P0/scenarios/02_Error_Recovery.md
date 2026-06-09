# 02_Error_Recovery.md

**Scenario ID:** P0-02-ErrorRecovery
**Description:** Realistic operation where a portion of agent tool-calls fail, partially
succeed, time out, and are retried — and the proof spine must attest all of it faithfully.

### Objective
Prove the proof spine treats failure as **first-class evidence** and that recovery is
**append-only**, never a silent edit:

- Errored / partial / timed-out tool-calls are anchored and verifiable **exactly like** successes
  (the core attests *what happened*, it does not decide success or clean up failures).
- A **retry is a NEW attested record** linked to the prior attempt by reference; the failed
  attempt stays on the record, intact and verifiable, forever (no mutation, no deletion).
- The pipeline **fails closed** on a corrupted stored blob (detects + localizes it) and a re-run
  is **idempotent** (deterministic recovery after interruption).

### Evidence model (per item)
`id · timestamp · agent_id · event_class · tool · input_hash (hash-only) · attempt ·
status ∈ {success, error, partial, timeout} · error{code, message_hash} | null ·
result | partial | null · retry_of (prior attempt id) | null · mandate · policy_snapshot`

No source content is stored — only hashes and non-content references (GDPR data-minimisation).
A retry chain example: `tool-call-004@1` (timeout) → `tool-call-004@2` (error) →
`tool-call-004@3` (success). All three are separate anchored leaves.

### Pre-registered Pass/Fail Criteria
1. All ~25 items (incl. errors/partials/timeouts/retries) encoded & batched: **PASS**
2. Errored/partial/timeout evidence attested faithfully (not dropped, not rewritten to success): **PASS**
3. Recovery is append-only: each retry is a **separate** leaf; the prior attempt is present, **unchanged**, still verifies: **PASS**
4. Attempt→retry linkage is resolvable by reference **without mutating** the original: **PASS**
5. Corrupted stored blob is **detected** (fail-closed) and localized to the right item: **PASS**
6. Idempotent re-run reproduces the **identical** Merkle root: **PASS**
7. Full offline verification of the whole batch (errors included): **PASS**
8. No over-claim: an errored event reads as *recorded*, not *succeeded*; recovery ≠ erasure of failure: **PASS**
9. Vučja otpornost (red-team, error/recovery-specific): ≥ 8.0
10. Ovčja os (clarity of output): ≥ 6.0

### Execution Steps
1. Enterprise Agent generates ~25 synthetic tool-calls with a realistic failure mix + retry chains.
2. Evidence Codec v0.2 encodes **every** item (success and failure alike) — lossless.
3. Create batch + Merkle tree + ONE signed checkpoint.
4. Offline-verify all items from the public proof package.
5. Recovery-discipline checks: append-only, linkage-without-mutation, failure persists.
6. Pipeline checks: corrupt-blob detection (fail-closed) + idempotent re-run.
7. Red-team probes (error/recovery-specific) + Sheep Report + determinism confirmation.

### Expected Artifacts
- ~25 evidence items (mixed statuses) · 1 EvidenceBatch + signed checkpoint · inclusion proofs
- `verification_report.json` · `red_team_report.json` · this report's results block

### Anticipated Accepted Limits (to confirm honestly)
- The proof spine **detects** a corrupted off-ledger blob and says *which* item is corrupt, but it
  cannot **recover the content** — content lives off-ledger; recovery requires re-fetch from the
  source/custody layer. (Proof spine ≠ storage durability.)
- "Recovery" at the ledger level = append a new record; the failure is **permanent** on the chain
  (immutability). The system never makes a failure disappear.
- Omission **before** ingestion (an event that never reaches the batch) cannot be proven absent by
  the spine alone — that needs a heartbeat/sequence (P1+); within an anchored batch, dropping an
  item changes the root and is detectable against a pinned root.

**Status:** Ready to execute
**Next:** Grok red-teams + scores; then RUN 03 Malicious Bypass.
