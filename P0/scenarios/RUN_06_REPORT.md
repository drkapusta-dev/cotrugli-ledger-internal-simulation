# RUN 06 — Offline Verification + Erasure · Report

**Run ID:** P0-AIAct-Track1-2026-06-09 · **Scenario:** P0-06-OfflineErasure (final P0)
**Executor:** Cl1 · **Status:** ✅ all pre-registered criteria PASS · no silent break · accepted limits disclosed

> The final scenario, and the hardest tension: **GDPR right-to-erasure vs an immutable proof chain**
> (I4 / RT3). We honour deletion **without breaking the chain or pretending the commitment vanished.**

## What was done — two halves

**(1) Full offline verification** from only the public proof package, at two honest levels:
- **PUBLIC verifier** (no salt): checkpoint signature + inclusion + commitment-bound → ✅. *Cannot*
  authenticate hidden content — that's the salted-commitment privacy property (matches the CORE
  contract's `privacy_mode` / public-verifier limits).
- **AUTHORIZED verifier** (member-disclosure, holds the salt): additionally recomputes the salted
  commitment from content+salt → content authenticated → ✅.

**(2) Erasure** for a subject (`ev-004`): delete off-ledger content + **shred the salt** + issue a
signed **Certificate of Destruction**, **appended** to the log (C1→C2 consistency verifies).

## Key outputs
| Check | Result |
|---|---|
| Public offline verify (no salt) | ✅ all 12 |
| Authorized offline verify (with salt) | ✅ all 12 |
| Certificate of Destruction signed + appended (C1→C2 consistency) | ✅ |
| Post-erasure: commitment **still anchored** (immutability) | ✅ inclusion verifies |
| Post-erasure: off-ledger content **not retrievable** | ✅ (`verify_blob` fails closed) |
| Post-erasure: commitment **non-linkable** without the shredded salt | ✅ cannot recompute |
| Post-erasure: certificate **verifies**; other items **unaffected** | ✅ |

**The honest mechanism:** the commitment stays on the immutable log (chain intact), but the content
is gone and the salt is shredded → it becomes a **non-linkable tombstone**. Erasure is an
**append** (a Certificate of Destruction), never a silent deletion of history.

### Pre-registered PASS/FAIL
✅ full offline verification (public + authorized) · ✅ erasure appends a signed, consistent certificate ·
✅ post-erasure inclusion immutable · ✅ content not retrievable · ✅ non-linkable · ✅ others unaffected

## Red-Team results (executed) — `P0/scripts/red_team_run_06.py`
| # | Attack | Verdict |
|---|---|---|
| 1 | Re-link the erased commitment without the salt | **DEFENDED** (high-entropy 2²⁵⁶ salt) **+ ACCEPTED LIMIT** (low-entropy content + known salt could re-link). |
| 2 | Forge a Certificate of Destruction | **DEFENDED** (forged cert rejected vs custodian key) **+ ACCEPTED LIMIT** (the cert attests the *workflow ran*, custodian self-attests — not third-party-verified physical destruction). |
| 3 | Use erasure to silently vanish evidence | **DEFENDED** — erasure leaves a permanent, auditable **tombstone** (which ref, when); you can see *that* something was erased, just not its content. |
| 4 | Un-erase (drop the certificate) | **DEFENDED** — can't un-append a witnessed certificate (consistency catches the shrink). |
| 5 | Over-claim audit | **DEFENDED** — discloses the legal, no-copy, and self-attestation limits. |

**No silent break:** every attack is defended or a disclosed accepted limit.

### ⚠ THE accepted limits (I4 / RT3 — the honest core)
1. **A salted hash may still be personal data** under strict GDPR — a **legal** question (gate G1),
   not resolvable by code. We do not claim it is anonymous.
2. **The commitment stays on the immutable log.** Non-linkability is by **salt-shred, not deletion**
   — deleting the commitment would break the chain. Deleting the commitment *itself* conflicts with
   immutability (RT3-A) → prunable anchoring / legal opinion (P1+).
3. The Certificate of Destruction is an **attested workflow** (custodian self-attests). Third-party
   assurance that the content is truly gone needs an **independent witness** (HSM/enclave attestation, P1+).
4. We **cannot prove no copy exists** anywhere (backups, caches) — only that the **controlled store**
   ran the prescribed erasure and the commitment is **no longer subject-linkable**.

## Determinism (confirmed)
Two fresh runs → pre-erasure root **byte-identical**: `sha256:39c86303…a3f229`.

## 🐑 Sheep Report (for a non-technical reader)
You asked us to **delete your record** — but we'd also promised everyone that our logbook can't be
secretly altered. How do we do both?

- For each record we keep a **scrambled fingerprint** in the sealed logbook, and the actual details
  **off to the side** (not in the public book), locked with a **one-of-a-kind scramble code**.
- When you ask us to erase: we **destroy the details** and **shred the scramble code**. After that,
  the fingerprint is still in the book (so the book stays trustworthy and unbroken) — but **nobody,
  including us, can turn it back into your details.** It becomes an unreadable stub.
- We also write a dated **"destruction note"** into the book — so there's honest proof that a record
  *was* there and *was* erased on request. **Erasure leaves a receipt, not a hole** — which means
  no one can abuse "erasure" to make awkward records secretly disappear.
- **We tried to cheat this too:** un-scramble a stub without the code, fake a destruction note, use
  erasure to vanish something quietly, or tear the destruction note out later. **All caught.**
- **The honest part:** (a) whether a scrambled fingerprint still counts as "your data" in law is a
  **lawyer's call**, not ours; (b) we destroyed *our* copy and can prove the steps — but we **can't
  promise** some old **backup** somewhere doesn't still hold a copy; (c) "we destroyed it" is **our
  signed word** — full proof needs an independent witness watching the shredder.
- **What this is NOT:** not "your data is gone from the entire universe", not "legally anonymous" —
  it's "**our controlled copy is destroyed, the stub can't be read, and the whole thing is honestly
  on the record.**"

## Next
**RUN 06 READY.** This completes all six P0 scenarios. Ready for the **final P0 evaluation**.
