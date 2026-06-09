# Gate G3 — Witness Economics v0.1 (draft input)

**Status:** draft for Drazen / consortium decision — *not* a final answer. A first concrete model now
that P1-02 quantified the security parameter. This is a strategy/economics input, not code.

> The make-or-break flagged by **every** round-3 red-team (RT0): *who pays the witnesses, forever,
> without re-centralizing?* If COTRUGLI pays all witnesses, they depend on the operator they are
> supposed to check — independence collapses and the real security drops below the nominal quorum.

## 1. What G3 must defend (now quantified)
From **P1-02 (Witness Long Game)** the security parameter is explicit:

- A witnessed lie costs the attacker **k independent corruptions** (the quorum), *and only as high as
  the witnesses are genuinely independent and not paid by the operator*.
- A *silent* takeover additionally needs **control of witness selection**.

So G3 must deliver three properties, jointly:

1. **Independence** — no single funder (especially the operator / COTRUGLI treasury) can pay or fire a
   quorum-breaking fraction of witnesses. Otherwise k effective < k nominal.
2. **Cost-to-corrupt > value-of-the-lie** — corrupting k witnesses must be economically irrational.
3. **Sustainability** — the layer is funded indefinitely without depending on the operator's goodwill.

Design brief (Gemini's framing, adopted): *make honesty the dominant strategy even among the
selfish — math replaces virtue.*

## 2. Design principles (the non-negotiables)
- **Structural separation from the treasury.** Witnesses are NOT paid or removed by the operator. A
  witness's livelihood must not hinge on the party it audits. (Directly raises effective k.)
- **Blind / pooled payment.** A witness is paid from a **common pool** and does **not** know whose
  checkpoints it co-signs → it cannot favour a paying client (kills the pay-to-play / RT0-B attack
  where a client bribes its own witness).
- **Stake + slash.** Each witness posts a stake; a provable equivocation or a cosignature over a root
  it never saw is **slashable**. P1-01/02 already make equivocation and forged cosignatures
  *detectable* — slashing turns detection into a **cost**. Target: `slash_loss > max gain from one lie`.
- **Many, diverse witnesses.** Different jurisdictions / org types (EU university, open-source
  foundation, auditor, civil-society, Infobip-class operator) so no correlated capture and no single
  jurisdiction can compel a quorum.
- **Independent selection.** Which witnesses are asked is set by a **public beacon / round-robin**, not
  the operator — closing the selection-control half of the P1-02 silent-takeover limit.

## 3. Funding sources (multi-source so no single party funds a quorum)
A **mix**, deliberately, so removing any one source (or capturing any one funder) cannot starve or
control the layer:

1. **Per-proof service fee** on the Proof-of-Coverage / assurance product → auto-split into the
   **blind pool** (the RT0 = I5 loop: the coverage market that buyers pay for funds the witnesses that
   make coverage trustworthy).
2. **Consortium membership** dues (members consume the witnessed proofs).
3. **Reviewer / regulated-audit package** fees.
4. **EU public-interest infrastructure** funding (a neutral attestation layer is public-good-shaped).
5. **Witness stake yield** (stake earns from the pool; slashing redistributes).
6. **CLU-style internal, non-transferable accounting** for inter-member settlement — *not* a token, not
   public money, fenced exactly as the Cotrugli Ledger constraints require.

**Guard rail:** no single funder may cover more than `(n − k + 1)`-witnesses-worth of the pool, so no
funder can buy a quorum. (This is the economic mirror of the k-corruption security parameter.)

## 4. The cost-to-corrupt inequality (the gate's quantitative heart)
Let:
- `k` = quorum, `n` = registered witnesses, `S` = stake per witness, `G` = max gain from a witnessed lie.
- Corrupting a quorum requires bribing **k** independent witnesses, each of whom forfeits stake `S` (and
  future pool income) if caught — and P1-01/02 make catching likely whenever ≥1 honest witness or
  observer participates.

**G3 passes if a parameterization exists where** `k · (S + future_income) > G` **for the target
use-case's `G`, AND no single funder controls ≥ `(n − k + 1)` witnesses.** P1-02 gives `k`; this gate
chooses `S`, `n`, and the funding split so the inequality holds with margin.

## 5. What stays open (honest)
- Exact `G` per use-case (AI Act evidence vs higher-stakes settlement) — sizing `S`/`n` follows from it.
- Legal form of stake/fees in the EU (governance + counsel; overlaps **G1**).
- Pool governance: who runs the blind pool without becoming a new central point (a witness-of-the-pool
  problem — likely the same k-of-n discipline applied to the pool operator).
- Liveness incentives: witnesses must be paid to **stay available** (P1-02's liveness limit), not only
  to sign honestly.

## 6. Go / no-go criterion for G3
**GO** if the consortium can commit to: (a) structural treasury separation, (b) a blind/pooled,
multi-source funding mix with the single-funder guard rail, and (c) a stake/slash parameterization
where cost-to-corrupt exceeds the use-case's attack value. **NO-GO / reformulate** if witnesses can
only be funded by the operator, or if no parameterization makes corruption irrational for the target
use-case.

*Recommended next step: pick the first use-case (AI Act evidence, low `G`), size `n/k/S` for it, and
validate the blind-pool + selection-beacon mechanics in a P1 simulation before any real funding.*
