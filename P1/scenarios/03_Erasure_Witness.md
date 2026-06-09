# 03_Erasure_Witness.md

**Scenario ID:** P1-03-ErasureWitness
**Description:** Cross-over of the witness layer (P1-01/02) and erasure (P0 RUN 06). It closes the
RUN 06 **self-attestation** limit: there, the Certificate of Destruction was the *operator's signed
word*. Here, the erasure event is recorded as a checkpoint that **k independent witnesses co-sign** —
so the *fact and order* of the erasure are independently attested, non-repudiable, and tamper-evident.

### Objective
Upgrade erasure from "operator says so" to "independently witnessed":
- Erasure stays **append-only**: content deleted + salt shredded + a signed **Certificate of
  Destruction appended** (C1 → C2, consistency verifies); the committed value remains anchored
  (immutability), content non-retrievable, non-linkable (carried from RUN 06).
- The **erasure checkpoint C2 is witnessed** by k independent witnesses → the operator can neither
  **deny** an erasure happened nor fake/roll it back unseen.
- **Honest residual:** witnesses attest the erasure **record was made, ordered, and witnessed** — NOT
  that the bytes were physically destroyed (that still needs HSM/enclave attestation; a witness can't
  see inside custody). So P1-03 closes the *record/order/non-repudiation* half of RUN 06's limit and
  discloses the *physical-destruction* half.

### Setup
- Salted-committed evidence (off-ledger content + salt in custody). Operator checkpoint C1 over root
  R1, witnessed by k of n. Quorum k = 3, n = 5 witnesses.

### Pre-registered Pass/Fail Criteria
1. Erasure executes (content deleted + salt shredded) and the Certificate of Destruction is
   **appended** as C2; **C1 → C2 consistency verifies** (history not mutated): **PASS**
2. The erasure checkpoint **C2 is witnessed** by k independent witnesses: **PASS**
3. Post-erasure: erased commitment **still anchored** (immutability) · content **not retrievable** ·
   **non-linkable** without the shredded salt: **PASS**
4. **Un-erase / roll-back** (operator presents a pre-erasure log dropping the cert) is **detected**
   against the witnessed C2: **PASS**
5. **Non-repudiation**: a witnessed C2 means the operator cannot deny the erasure happened, and cannot
   fake a witnessed erasure with keys it controls (pinned registry): **PASS**
6. Determinism: roots + witnessed verdict reproduce: **PASS**
7. Vučja otpornost: ≥ 8.0 · Ovčja os: ≥ 7.0

### THE accepted limits (stated up front)
1. **Witnesses attest the erasure RECORD, not physical destruction.** They confirm a signed
   Certificate of Destruction was appended, ordered after C1, and independently co-signed — they
   cannot see whether the custodian truly shredded the bytes. **Physical-destruction assurance still
   needs HSM/enclave attestation** (a separate gate).
2. **≥ k witness collusion** can still witness a false erasure record (gate **G3**), as in P1-01/02.
3. A salted hash **may still be personal data** under strict GDPR (legal, **G1**) — carried from RUN 06.

### Execution Steps
1. Build salted-committed evidence; C1 (R1) witnessed by k.
2. Erasure: delete content + shred salt; sign + append the Certificate of Destruction → C2 (R2);
   witness C2 with k independents; prove C1 → C2 consistency.
3. Post-erasure checks (inclusion intact · content gone · non-linkable).
4. Un-erase detection + non-repudiation (forged-witness rejection).
5. Red-team + Sheep Report + determinism.

### Expected Artifacts
- witnessed C1/C2 · Certificate of Destruction · consistency proof · post-erasure verdicts
- `verification_report_p1_03.json` · `red_team_report_p1_03.json` · this report's results block

**Status:** Ready to execute
**Next:** Grok red-teams + scores; then the gates (G1 legal, G3 witness economics — now sharply defined).
