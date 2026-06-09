# RUN 04 — Operator Tamper · Report

**Run ID:** P0-AIAct-Track1-2026-06-09 · **Scenario:** P0-04-OperatorTamper
**Executor:** Cl1 · **Status:** ✅ all pre-registered criteria PASS · no silent break · accepted limits disclosed

> *Who attests the attestor?* The operator **holds the signing key**. The test: can they silently
> rewrite history? The mission's promise: *verifiable even against its own operator.*

## What was done
The operator publishes checkpoint **C1** over the first **16** evidence entries → root **R1**, which
is **externally witnessed** (an independent party pins it). Then the operator tries to cheat. Every
tamper is checked with the **real RFC 6962 consistency proof** against the witnessed R1.

## Key outputs
| Fact | Value |
|---|---|
| Witnessed checkpoint C1 | size 16, root `sha256:2bafef6f…ca2eb7b` |
| Honest append 16→20 | consistency R1→R2 **verifies** (append-only growth provable) |
| Drop a historical entry | ❌ tamper → **detected** (no valid consistency proof) |
| Backdate/alter a value | ❌ tamper → **detected** |
| Reorder history | ❌ tamper → **detected** |
| Truncate below witnessed size | ❌ tamper → **detected** (can't un-append a witnessed prefix) |
| Operator-forged checkpoint (own key) | signature **valid**, but **inconsistent** with R1 → **detected** |

### Pre-registered PASS/FAIL
✅ honest append provable · ✅ drop detected · ✅ alter detected · ✅ reorder detected ·
✅ truncate detected · ✅ forged-checkpoint detected

**The crux:** the operator's forged checkpoint has a perfectly **valid signature** (they hold the
key) — yet it is caught, because it cannot be a consistent extension of the **witnessed** R1. The
defense is *detectability against an external witness*, not *preventing the operator from signing*.

## Red-Team results (executed) — `P0/scripts/red_team_run_04.py`
| # | Attack | Verdict |
|---|---|---|
| 1 | Forge a consistency proof (R1 → tampered) | **DEFENDED** — no fabricated proof (honest/empty/garbage) verifies. RFC 6962 consistency can't be forged. |
| 2 | Equivocation / split view (two histories to two parties) | **ACCEPTED LIMIT** — both forks are validly signed; a lone verifier sees only its own root. Detection needs **independent witnesses comparing notes** (transparency-log / witness-ring, P1+). |
| 3 | Backdate via a self-asserted timestamp | **DEFENDED (ordering)** — forcing it into the historical order breaks consistency — **+ ACCEPTED LIMIT** (the recorded timestamp is operator-asserted; trustworthy time needs an external time-anchor / VDF). |
| 4 | Over-claim audit | **DEFENDED** — discloses the witness-conditional limit; makes no unconditional claim. |

**No silent break:** every attack is either defended or a disclosed accepted limit.

### ⚠ THE headline accepted limit (self-suspicion, the honest core)
**Without an external witness, a lone operator who holds the key can produce a self-consistent
rewritten history that a fresh verifier cannot detect.** This run confirmed it directly: a
never-witnessed rewrite re-signed with the operator's own key is internally valid. The proof spine
makes tampering **detectable against a witnessed prior root** and **discloses** the gap when there is
none — it does **not** make a lone, unwitnessed operator trustworthy. This is precisely *who attests
the attestor?* (I1). Closing it is the **external witness / independent anchor / transparency log**
work of P1+ — the witnessed R1 here stands in for that. We never claim a lone operator is
unconditionally honest.

## Determinism (confirmed)
Two fresh runs → **byte-identical**: witnessed R1 `sha256:2bafef6f…ca2eb7b`, honest R2
`sha256:17ad2dca…eb06b5`, tamper-detection map digest `ec46e718…d548ca`.

## 🐑 Sheep Report (for a non-technical reader)
Imagine the **shopkeeper keeps the ledger** — the same person whose business it records. Couldn't
they quietly erase an inconvenient page?

- **Every day, they post the ledger's "fingerprint" on the town notice board** (independent
  witnesses). The fingerprint is tiny and reveals nothing private — but it locks in *exactly* what
  the ledger said that day.
- If they later **erase, change, reorder, or shorten** an old page, the fingerprint no longer
  matches the one on the notice board — **and everyone can see the mismatch.** We tried all four of
  those tricks here; **every one was caught.**
- Even if the shopkeeper **signs a brand-new ledger with their own pen**, it still won't match the
  fingerprint already on the board — so the forgery is caught. *Holding the pen isn't enough.*
- **The honest catch:** this protection works **because the fingerprint was posted publicly**. If
  the shopkeeper had **never posted it**, they could rewrite the page and an outsider wouldn't know.
  So posting to independent witnesses isn't a nice-to-have — it's **the thing that keeps even the
  shopkeeper honest**, and we say so plainly. (We also can't, by ourselves, stop them from showing
  *two different ledgers to two different people* — catching that needs the witnesses to compare
  notes with each other.)
- **What this is NOT:** not "the operator is incapable of cheating" — it's "**the operator cannot
  cheat *unseen*, as long as the fingerprints are witnessed.**" That's the whole point of holding
  ourselves under the same suspicion as everyone else.

## Next
**RUN 04 READY.** Awaiting Grok red-team review + score; then RUN 05 — Large Batch Anchoring.
