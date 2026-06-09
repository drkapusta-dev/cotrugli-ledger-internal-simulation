# 02_Witness_Long_Game.md

**Scenario ID:** P1-02-WitnessLongGame
**Description:** The "long game" against the witness layer — the deeper adversarial test Grok flagged
after P1-01. Instead of a single snapshot, this plays the adversary out **over time**: witnesses
going **offline** (liveness vs safety), the operator **gradually corrupting** witnesses round by
round (the security margin to a witnessed lie), and **sybil** on witness selection.

### Objective
Quantify the witness layer's real margin and its honest failure modes:
- **Safety never breaks silently:** below quorum the layer produces an **un-witnessed** checkpoint —
  never a *falsely* witnessed one — no matter how many witnesses are offline.
- **Security margin = k corruptions:** a witnessed lie requires the operator to corrupt **≥ k**
  independent witnesses; the crossover round is explicit.
- **Honest participation exposes the lie:** as long as **≥ 1 honest witness** is asked and signs the
  real root, the operator's forged root is caught by **equivocation** — so a *silent* takeover needs
  both k corruptions AND control of witness **selection**.
- **Sybil is bounded by the pinned registry:** the operator cannot add unregistered witnesses to reach
  quorum; biasing **selection** among registered witnesses toward corrupted ones is the disclosed limit
  that **independent selection** (random beacon / consortium-chosen) defends.

### Setup
- Registry of **n = 7** independent witnesses; quorum **k = 4**.

### Pre-registered Pass/Fail Criteria
1. **Liveness/safety:** with `online ≥ k` a checkpoint can be witnessed; with `online < k` it is
   **un-witnessed** (fails safe). **No** falsely-witnessed checkpoint is ever produced: **PASS**
2. **Gradual corruption — safe side:** while `corrupted < k`, a forged root is **not** witnessed: **PASS**
3. **Crossover (accepted limit):** at `corrupted ≥ k` the forged root **is** witnessed — the explicit
   security margin is **k corruptions**: **PASS (disclosed)**
4. **Honest detection:** at `corrupted ≥ k`, if ≥ 1 honest witness also signs the real root, the fork
   is **flagged** by equivocation: **PASS**
5. **Sybil bound:** unregistered fake witnesses are **not counted** (pinned registry); selection bias
   among registered witnesses is the disclosed limit needing independent selection: **PASS (disclosed)**
6. Determinism: the margin/verdicts reproduce across runs: **PASS**
7. Vučja otpornost (long game): ≥ 8.0 · Ovčja os: ≥ 7.0

### THE accepted limits (stated up front)
1. **The break cost is k independent corruptions** — finite, and only as high as the witnesses are
   independent and not dependent on the operator. Raising it (staking/slashing, who-pays) is the
   economic question, **gate G3**.
2. **Silent takeover also needs selection control.** With honest witnesses in the asked set, the lie
   is caught by equivocation; hiding it requires the operator to choose *who is asked* — so
   **independent/random witness selection** is load-bearing.
3. **Liveness is not guaranteed.** Enough witnesses offline → no new witnessed checkpoint. The layer
   trades *liveness* for *safety*: it would rather produce nothing than a falsely-witnessed root.

### Execution Steps
1. Liveness/safety sweep: drop witnesses offline from n down past k; record witnessed-vs-un-witnessed
   and confirm no false witnessing.
2. Gradual corruption: corrupt c = 0..k; for each, the operator forges a root cosigned by the
   corrupted set; record the crossover at c = k.
3. Honest detection: at c = k, add one honest witness on the real root; confirm equivocation flags it.
4. Sybil: operator injects unregistered fake witnesses; confirm they are not counted.
5. Red-team (long-game) + Sheep Report + determinism.

### Expected Artifacts
- liveness/safety sweep · corruption crossover · equivocation flag · sybil rejection
- `verification_report_p1_02.json` · `red_team_report_p1_02.json` · this report's results block

**Status:** Ready to execute
**Next:** Grok red-teams + scores; then P1-03 (Erasure Witness) or the gates.
