# 01_Witness_Ring.md

**Scenario ID:** P1-01-WitnessRing
**Description:** Adversarial stress-test of the **witness layer v0.1** (`app/witness.py`) — the P1
build that closes the largest cluster of P0 accepted limits (RUN 04 Operator Tamper / I1, RUN 03
issuer-pin & equivocation). We now test the witness layer the way P0 tested the codec.

### Objective
Prove that a checkpoint root is **witnessed** only when **k independent witnesses co-sign it against
their pinned keys**, that a key-holding operator cannot forge that quorum or transplant cosignatures
onto a rewritten root, and that **equivocation** (different roots to different parties) is detectable
— while disclosing the real boundary: **≥ k colluding witnesses can still witness a lie** (the
governance/economic question, gate G3), and witnesses that withhold cosignatures cause a **fail-safe
un-witnessed** state (not a falsely-witnessed one).

### Setup
- Operator holds the log key. **n = 5** independent witnesses; quorum **k = 3**.
- Operator publishes checkpoint C1 over root R1 (size 16); ≥ k witnesses co-sign → **witnessed**.

### Pre-registered Pass/Fail Criteria
1. Honest k-of-n: a checkpoint with ≥ k valid pinned-witness cosignatures verifies as **witnessed**: **PASS**
2. **Operator rewrite**: a checkpoint over a rewritten root R1′ (operator's own key) has **no** valid
   witness quorum — transplanting the old cosignatures fails (they signed R1) → **not witnessed**: **PASS**
3. **Impersonated witness**: an anchor claiming a registry witness_id but signed with a key the
   operator controls is **not counted** (pinned-key mismatch): **PASS**
4. **Collusion below k**: operator + (k−1) malicious witnesses cannot reach quorum → **not witnessed**: **PASS**
5. **Equivocation**: the same (log_id, tree_size) co-signed at two different roots is **flagged**: **PASS**
6. Determinism: the witnessed root + verdict reproduce across runs: **PASS**
7. Vučja otpornost (witness-level): ≥ 8.0 · Ovčja os: ≥ 6.5

### THE accepted limits (stated up front)
1. **≥ k colluding witnesses can witness a lie.** Quorum defends against an operator + up to (k−1)
   dishonest witnesses; at k it falls. So **k/n, witness independence, and who-runs/pays the
   witnesses without re-centralizing** are load-bearing — the economic question (gate **G3**), not
   solved here.
2. **Liveness**: witnesses that withhold cosignatures prevent a quorum → the checkpoint is **un-
   witnessed** (fails safe). The layer never produces a *falsely* witnessed checkpoint, but it cannot
   force availability.
3. **Garbage-in**: witnesses attest the **root they were shown**, not upstream event truth (RUN 03
   bypass limit still applies above the boundary).

### Execution Steps
1. Build the operator log + checkpoint C1 (R1); have k witnesses co-sign → witnessed.
2. Run the pre-registered checks (rewrite, impersonation, collusion<k, equivocation).
3. Red-team (forge quorum, replay cosig, ≥k collusion, self-equivocating witness, over-claim) +
   Sheep Report + determinism.

### Expected Artifacts
- witnessed checkpoint + witness registry · verdict map · equivocation report
- `verification_report_p1_01.json` · `red_team_report_p1_01.json` · this report's results block

**Status:** Ready to execute
**Next:** Grok red-teams + scores; then the rest of P1 (gateway/reconciliation, erasure-witness, …).
