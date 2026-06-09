# RUN P1-02 — Witness Long Game · Report

**Run ID:** P1-Witness-2026-06-09 · **Scenario:** P1-02-WitnessLongGame
**Executor:** Cl1 · **Status:** ✅ all pre-registered criteria PASS · no silent break · accepted limits disclosed

> Directly answers Grok's P1-01 feedback: don't test the witness layer at a single snapshot — play
> the adversary out **over time** (witnesses offline, gradual corruption, sybil on selection).

## What was done
Registry of **n = 7** independent witnesses, quorum **k = 4**. Three long games:

## Key outputs
| Game | Result |
|---|---|
| **Liveness / safety sweep** (witnesses offline 7 → 0) | witnessed iff `online ≥ k`; **liveness threshold = 4**; **no false witnessing at any point** |
| **Gradual corruption** (corrupt c = 0…k, lie cosigned by corrupted set) | lie witnessed **only at c ≥ k**; **crossover = 4** → the security margin is **k = 4 corruptions** |
| **Honest detection** (k corrupted on a lie + 1 honest on the truth) | **equivocation flagged** (1 conflict) — the fork shows |
| **Sybil** (k unregistered fake witnesses) | **rejected** — the pinned registry counts none of them |
| Determinism | margin + verdicts **byte-identical** across runs |

### Pre-registered PASS/FAIL
✅ liveness/safety, no false witnessing · ✅ safe while corrupted < k · ✅ crossover margin = k ·
✅ honest witness detects the fork · ✅ sybil (unregistered) rejected

## Red-Team results (executed) — `P1/scripts/red_team_p1_02.py`
| # | Attack | Verdict |
|---|---|---|
| 1 | Corrupt k−1 witnesses and witness a lie | **DEFENDED** — below k, a forged root is not witnessed. |
| 2 | Corrupt k + control selection (no honest asked) | **ACCEPTED LIMIT** — break cost is k independent corruptions + selection control (G3). |
| 3 | k corrupted but an honest witness is still asked | **DEFENDED** — one honest witness exposes the fork (equivocation). |
| 4 | Sybil: inject unregistered fake witnesses | **DEFENDED** — the pinned registry rejects them. |
| 5 | Liveness DoS: witnesses offline below k | **DEFENDED (safety)** + **ACCEPTED LIMIT** (liveness not guaranteed). |
| 6 | Over-claim audit | **DEFENDED** — discloses the margin, selection, and liveness limits. |

**No silent break.**

### ⚠ THE accepted limits (the honest core)
1. **The break cost is k independent corruptions** — finite, and only as high as the witnesses are
   genuinely independent and not paid by the operator. Raising it (staking/slashing, who-pays) is the
   economic question, **gate G3**.
2. **A *silent* takeover also needs selection control** — with ≥ 1 honest witness in the asked set the
   lie is caught, so the operator must also choose *who is asked*. **Independent/random witness
   selection** is therefore load-bearing.
3. **Liveness is not guaranteed** — enough witnesses offline → no new witnessed checkpoint. The layer
   trades *liveness* for *safety*: it would rather produce **nothing** than a falsely-witnessed root.

## Determinism (confirmed)
Two fresh runs → security margin **4**, liveness threshold **4**, and the full pre-registered verdict
map are **byte-identical**.

## 🐑 Sheep Report (for a non-technical reader)
The one thing to take away: **this system is built to disappoint you honestly rather than reassure
you falsely.**

Picture the town notice board again, where **k = 4** independent clerks must each stamp the day's
fingerprint before it "counts."

- **How hard is it to fake?** A crook would have to **bribe four** of the clerks *at once* — not one,
  not three. We can even tell you the exact number: it's the quorum. Make the clerks more numerous and
  more independent, and that number (and the bribe bill) goes up. *Who pays the clerks so they stay
  independent is the open question we're honest about.*
- **What if a clerk gets bribed slowly, one at a time?** Until the **fourth** bribe, the fake page
  simply doesn't count — the honest clerks' refusal is enough.
- **What if even one honest clerk is still asked?** The honest clerk stamps the *real* fingerprint, the
  bribed ones stamp the *fake* one — and now there are **two different stamps for the same day**, which
  anyone can see. So to cheat quietly, the crook also has to **control which clerks get asked**.
- **What if a crook just prints their own fake "clerks"?** Doesn't work — only the **town's registered
  clerks** count; printed strangers are ignored.
- **What if the clerks go home and nobody's around?** Then the page is simply **"not witnessed yet"** —
  never falsely stamped. We'd rather tell you *"we can't confirm this right now"* than pretend.
- **What this is NOT:** not "impossible to ever cheat" — it's "**you know exactly how many independent
  people a cheat would have to corrupt, and short of that, the system tells the truth or stays silent —
  it never quietly lies.**"

## Next
**RUN P1-02 READY.** Awaiting Grok red-team review + score; then P1-03 (Erasure Witness) or the gates
(G3 witness economics is now sharply defined by the k-corruption margin surfaced here).
