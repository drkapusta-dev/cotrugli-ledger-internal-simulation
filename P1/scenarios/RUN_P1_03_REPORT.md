# RUN P1-03 — Erasure Witness · Report

**Run ID:** P1-Witness-2026-06-09 · **Scenario:** P1-03-ErasureWitness
**Executor:** Cl1 · **Status:** ✅ all pre-registered criteria PASS · no silent break · accepted limits disclosed

> Cross-over of the witness layer (P1-01/02) and erasure (RUN 06). It closes the half of RUN 06's
> self-attestation limit that *can* be closed: the erasure is now **independently witnessed**, not
> just the operator's signed word — and it honestly discloses the half that can't (physical destruction).

## What was done
10 salted-committed items; operator checkpoint **C1** (root R1) **witnessed** by k=3 of n=5 independent
witnesses. Then an erasure for one subject: delete content + shred salt + sign & **append** a
Certificate of Destruction → checkpoint **C2** (root R2), also **witnessed** by k.

## Key outputs
| Check | Result |
|---|---|
| C1 witnessed (k-of-n) | ✅ witnessed |
| Erasure appended (C1 → C2 consistency) + certificate verifies | ✅ |
| **C2 (the erasure) witnessed** by k independents | ✅ — erasure is **independently attested**, not just the operator's word |
| Post-erasure: commitment still anchored · content gone · non-linkable | ✅ |
| Un-erase (drop the cert, present the pre-erasure log) | ✅ **detected** vs witnessed C2 |
| Determinism | ✅ roots + verdicts byte-identical |

### Pre-registered PASS/FAIL
✅ C1 witnessed · ✅ erasure appended + consistent · ✅ C2 erasure witnessed · ✅ post-erasure
immutable + non-linkable · ✅ un-erase detected

## Red-Team results (executed) — `P1/scripts/red_team_p1_03.py`
| # | Attack | Verdict |
|---|---|---|
| 1 | Claim erasure but secretly retain the content | **ACCEPTED LIMIT** — witnesses attest the *record*, not physical destruction (enclave gate). |
| 2 | Repudiate: deny the erasure ever happened | **DEFENDED** — a witnessed C2 is non-repudiable (k independents recorded it). |
| 3 | Forge a witnessed erasure with operator-controlled keys | **DEFENDED** — the pinned registry rejects operator-minted witnesses. |
| 4 | Un-erase: roll back to before the certificate | **DEFENDED** — can't shrink below a witnessed C2. |
| 5 | Backdate the erasure | **DEFENDED (ordering)** + **ACCEPTED LIMIT** (exact wall-clock needs a time-anchor). |
| 6 | Over-claim audit | **DEFENDED** — discloses the physical-destruction and ≥k-collusion limits. |

**No silent break.**

### ⚠ THE accepted limits (the honest core)
1. **Witnesses attest the erasure RECORD, not physical destruction.** They confirm a signed
   Certificate of Destruction was appended, ordered after C1, and independently co-signed — they
   cannot see inside custody. **Proving the bytes are physically gone still needs HSM/enclave
   attestation** (a separate gate). So P1-03 turns "operator's word" into "independently witnessed
   record" — a real upgrade — but not into physical-destruction proof.
2. **≥ k witness collusion** can still witness a false erasure record (gate **G3**).
3. A salted hash **may still be personal data** (legal, **G1**); non-linkability is by salt-shred, not
   deletion of the commitment.

## Determinism (confirmed)
Two fresh runs → R1, R2, the consistency result, and the full verdict map are **byte-identical**.

## 🐑 Sheep Report (for a non-technical reader)
You asked us to **destroy your file**. Here's what now happens — and what we promise honestly:

- We **delete the file and shred the key** that could ever unlock it again. After that, even *we*
  can't read it back.
- We write a dated **"destroyed" note** into the public book — and **k = 3 independent clerks stamp
  that note too.** So two things become impossible for us: **pretending we never destroyed it**, and
  **faking a destruction we didn't do** (we'd need the real clerks, and we can't forge their stamps).
- We also can't **quietly un-destroy** it later — the clerks' stamped note is already in the book, and
  removing it would show.
- **The one honest gap:** the clerks watch us *file the "destroyed" paperwork* — they don't stand over
  the shredder. To *prove* the file truly went through the shredder (not hidden in a drawer), you'd
  need a special **tamper-proof shredder that issues its own certificate** — a separate upgrade we're
  honest about.
- **What this is NOT:** not "we cryptographically prove your data is gone from the universe" — it's
  "**we destroyed our copy, we can't read it back, and independent witnesses make the destruction
  record honest and undeniable.**"

## Next
**P1-03 READY.** Awaiting Grok red-team review + score; then the gates (G1 legal, **G3 witness
economics** — now sharply defined: break cost = k independent corruptions), or P1-04.
