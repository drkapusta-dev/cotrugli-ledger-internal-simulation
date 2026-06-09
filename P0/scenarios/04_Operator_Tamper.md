# 04_Operator_Tamper.md

**Scenario ID:** P0-04-OperatorTamper
**Description:** The **operator** — the party that runs the evidence service and **holds the signing
key** — actively tries to cheat: drop, backdate, reorder, selectively omit, truncate, and forge a
fresh checkpoint over a rewritten history. This is the "**who attests the attestor?**" test, and
the mission's binding promise: *the system must be verifiable even against its own operator.*

### Objective
Show that a key-holding operator **cannot silently rewrite history that was already externally
witnessed** — RFC 6962 **append-only consistency proofs** make any drop/alter/reorder/truncate
detectable to anyone who holds an earlier witnessed root. And, with equal honesty, show the limit:
**without an external witness, a lone operator who holds the key CAN produce a fully self-consistent
alternate history** — which is exactly why the witness/external-anchor is load-bearing (P1+).

The crux (self-suspicion): the defense is **not** "the operator can't sign" — they hold the key and
can sign anything. The defense is that an **independent witness pinned an earlier root R1**, and the
operator cannot produce a valid consistency proof from R1 to a tampered history.

### Setup
- Operator keeps an append-only log of evidence commitments; publishes checkpoint **C1** over the
  first **N0 = 16** entries → root **R1**. **R1 is externally witnessed** (an independent party
  pins it — simulated).
- Honest growth: append more entries → **N1 = 20**, root **R2**; a consistency proof R1→R2 verifies.

### Pre-registered Pass/Fail Criteria
1. Honest append N0→N1 yields a **valid** consistency proof (append-only growth is provable): **PASS**
2. **Drop** a witnessed historical entry → no valid consistency proof from R1 → **detected**: **PASS**
3. **Backdate/alter** a witnessed historical entry → **detected** via consistency: **PASS**
4. **Reorder** witnessed historical entries → **detected**: **PASS**
5. **Truncate** below the witnessed size (hide recent activity) → **detected** (m > n): **PASS**
6. **Operator-forged checkpoint** over a rewritten root, signed with the operator's **own** key →
   signature is valid **but** inconsistent with the witnessed R1 → **detected**: **PASS**
7. Full offline verification of the honest log: **PASS**
8. No over-claim: detection is **conditional on R1 being externally witnessed**; a never-witnessed
   root can be rewritten by a key-holding operator: **PASS (disclosed)**
9. Vučja otpornost (operator-level): ≥ 8.0 · Ovčja os: ≥ 6.5

### THE headline accepted limit (self-suspicion, stated up front)
**A lone operator who holds the signing key and whose roots were never externally witnessed can
produce a self-consistent rewritten history** — re-anchor a clean alternate log, sign it with their
own key, and a verifier with no earlier reference cannot tell. The proof spine makes tampering
**detectable against a witnessed prior state**; it does **not** make a key-holding operator
honest on its own. This is the "who attests the attestor?" problem (I1). Closing it needs an
**external witness / independent anchor / transparency log** (the witnessed R1 in this run stands
in for it) — that is the P1+ work. We make the operator's silent rewrite **detectable when witnessed
and disclosed when not** — never pretend a lone operator is unconditionally trustworthy.

### Execution Steps
1. Build the log; publish + witness C1 (R1) over the first 16 entries.
2. Honest append to 20; prove R1→R2 consistency.
3. Operator tamper attempts (drop / alter / reorder / truncate / forged checkpoint) — each checked
   against the witnessed R1.
4. Demonstrate the accepted limit: a never-witnessed rewrite is internally valid.
5. Red-team (operator self-suspicion: equivocation, forged consistency, time-anchor) + Sheep Report + determinism.

### Expected Artifacts
- log + witnessed R1 + honest R2 + consistency proofs · tamper attempt results
- `verification_report_04.json` · `red_team_report_04.json` · this report's results block

**Status:** Ready to execute
**Next:** Grok red-teams + scores; then RUN 05 Large Batch Anchoring.
