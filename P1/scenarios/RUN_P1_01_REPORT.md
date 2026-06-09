# RUN P1-01 — Witness Ring · Report

**Run ID:** P1-Witness-2026-06-09 · **Scenario:** P1-01-WitnessRing
**Executor:** Cl1 · **Status:** ✅ all pre-registered criteria PASS · no silent break · accepted limits disclosed

> P1 begins where P0's hardest run ended. RUN 04 (Operator Tamper) *assumed* an externally-witnessed
> root; this run makes the witness real and attacks it — the loop *build the witness → prove it under
> attack* closes.

## What was done
Stress-tested the **real witness layer** (`app/witness.py`) with **n = 5** independent witnesses and
quorum **k = 3**: an operator publishes checkpoint C1 over root R1, witnesses co-sign, and a verifier
accepts it as *witnessed* only when ≥ k pinned, distinct witnesses signed the root.

## Key outputs
| Check | Result |
|---|---|
| Honest k-of-n | **witnessed** with `witness-0/1/2` |
| Operator rewrite over R1′ (transplant old cosigs) | **not witnessed** → detected (cosigs signed R1, not R1′) |
| Impersonated witness (operator's key as `witness-0`) | **not counted** (pinned-key mismatch) |
| Collusion below k (operator + 2 witnesses on R1′) | **not witnessed** (quorum holds) |
| Equivocation (R1 to {0,1}, R1′ to {2,3}) | **1 conflict flagged** |
| Determinism | witnessed root + verdict **byte-identical** across runs |

### Pre-registered PASS/FAIL
✅ honest k-of-n witnessed · ✅ operator rewrite detected · ✅ impersonated witness rejected ·
✅ collusion-below-k blocked · ✅ equivocation detected

## Red-Team results (executed) — `P1/scripts/red_team_p1_01.py`
| # | Attack | Verdict |
|---|---|---|
| 1 | Forge the quorum with the operator's own keys | **DEFENDED** — pinned-key match rejects operator-minted witnesses (valid=[], witnessed=False). |
| 2 | Replay a witness cosignature onto a rewritten root | **DEFENDED** — a cosignature binds the exact root; it won't verify on R′. |
| 3 | ≥ k colluding witnesses witness a forged root | **ACCEPTED LIMIT** — at ≥ k collusion a lie can be witnessed (gate G3). |
| 4 | Self-equivocating witness (one witness, two roots) | **DEFENDED** — equivocation is caught even with a single witness. |
| 5 | Over-claim audit | **DEFENDED** — discloses the ≥k-collusion and liveness limits. |

**No silent break:** every attack is defended or a disclosed accepted limit.

### ⚠ THE accepted limits (the honest core)
1. **≥ k colluding witnesses can witness a lie.** Quorum defends against an operator + up to (k−1)
   dishonest witnesses; at k it falls. So **k/n, witness independence, and who-runs/pays the witnesses
   without re-centralizing** are load-bearing — the economic question (**gate G3**), not solved here.
2. **Liveness.** Witnesses that withhold cosignatures prevent a quorum → the checkpoint is
   **un-witnessed** (fails safe). The layer never produces a *falsely* witnessed checkpoint, but it
   cannot force availability.
3. **Garbage-in.** Witnesses attest the **root they were shown**, not upstream event truth (RUN 03's
   bypass limit still applies above the boundary).

## Determinism (confirmed)
Two fresh runs → witnessed root `sha256:3ac45fe2…7f1c54` and the full verdict are **byte-identical**.

## 🐑 Sheep Report (for a non-technical reader)
Recall the shopkeeper who posts the ledger's *fingerprint* on the town notice board. Now we add a
rule: **the fingerprint only "counts" once k independent town-clerks have also stamped it.**

- The shopkeeper **can't fake the clerks' stamps** — each clerk has their own seal, and the town
  keeps a copy of every clerk's seal to check against.
- If the shopkeeper **rewrites an old page** and posts a new fingerprint, the clerks' earlier stamps
  **don't fit** it — so the rewrite isn't "counted." We tried transplanting old stamps onto a new
  page: caught.
- If the shopkeeper tells **clerk A one story and clerk B another**, comparing their stamps shows two
  different fingerprints for the same day — **the lie shows.** (Even a *single* two-faced clerk who
  stamps two versions is caught the same way.)
- **The honest catches:** (a) if **k clerks conspire with the shopkeeper**, they can all stamp the same
  lie — so you want **many, truly independent** clerks who **don't depend on the shopkeeper for their
  pay**; (b) if clerks simply **refuse to stamp**, the page just isn't "witnessed" — that's safe, never
  *falsely* witnessed; (c) the clerks only vouch for the **fingerprint they were shown**, not for
  whether the underlying business was honest.
- **What this is NOT:** not "the operator can never cheat" — it's "**the operator can't cheat unseen as
  long as enough independent witnesses are watching, and we're honest about what 'enough' costs.**"

## Next
**RUN P1-01 READY.** Awaiting Grok red-team review + score; then the rest of P1 (gateway/reconciliation
hardening, erasure-witness, witness economics tie-in to gate G3).
