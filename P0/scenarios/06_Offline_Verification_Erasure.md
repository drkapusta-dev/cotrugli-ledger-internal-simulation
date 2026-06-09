# 06_Offline_Verification_Erasure.md

**Scenario ID:** P0-06-OfflineErasure
**Description:** The final P0 scenario. Two halves: (1) **full offline verification** of evidence
using **only the public proof package** (zero trust in the issuer), and (2) the **erasure** problem
(I4 / RT3): GDPR right-to-erasure vs an immutable proof chain — how to honour a deletion request
**without breaking the chain or pretending the commitment vanished from history.**

### Objective
Show the honest erasure design: **salted commitment + off-ledger content + salt-shred +
Certificate of Destruction (an append-only attested erasure record) + non-linkable tombstone.**
After erasure: the content is gone, the salt is shredded, the commitment **remains anchored**
(immutability — the chain stays intact and verifiable), but it is **no longer linkable** to the
subject. We prove the controlled store ran the prescribed workflow — not that "no copy exists
anywhere on earth" (impossible), and not that a salted hash is definitely not personal data (legal).

### Design
- Each evidence item is committed with a **salted commitment** `H(salt‖content)`; content + salt are
  held **off-ledger** in custody; only the commitment is anchored (checkpoint C1, root R1).
- An **erasure request** for a subject: delete the off-ledger content, **shred the salt**, and issue
  a **Certificate of Destruction** — a signed record `{erased_ref, request_id, time, salt_ref,
  method}` that is itself **appended** to the log (C1→C2, consistency proof) — erasure is a NEW
  attested record, never a silent deletion of history.

### Pre-registered Pass/Fail Criteria
1. **Full offline verification** of the pre-erasure package using ONLY public data: **PASS**
2. Salted commitment: content off-ledger, commitment anchored, verifiable while content present: **PASS**
3. Erasure executes: content deleted + salt shredded; **Certificate of Destruction** issued, signed, and **appended** (C1→C2 consistency verifies — history not mutated): **PASS**
4. Post-erasure: the erased item's commitment is **still anchored / inclusion still verifies** (immutability preserved): **PASS**
5. Post-erasure: the off-ledger content is **no longer retrievable** → `verify_blob` fails closed: **PASS**
6. Post-erasure: the commitment is **non-linkable** without the shredded salt (cannot recompute/confirm): **PASS**
7. The Certificate of Destruction **verifies** (signature + references the erased ref, request, time): **PASS**
8. Determinism: the pre-erasure root reproduces across runs: **PASS**
9. No over-claim: erasure = **attested-workflow + non-linkable tombstone**, NOT proof no copy exists; a salted hash **may still be personal data** (legal): **PASS (disclosed)**
10. Vučja otpornost (erasure mechanisms): ≥ 8.0 · Ovčja os: ≥ 6.5

### THE accepted limits (I4 / RT3, stated up front)
1. **A salted hash may still be personal data** under strict GDPR — a **legal** question (gate G1),
   not resolvable by code. We do not claim it is anonymous.
2. **The commitment stays on the immutable log.** We achieve **non-linkability by salt-shred**, not
   by deleting the commitment (deleting it would break the chain). If a regulator orders deletion of
   the **commitment itself**, that is in tension with immutability (RT3-A) → prunable anchoring /
   legal opinion (P1+).
3. The Certificate of Destruction is an **attested workflow** — the custodian self-attests the
   destruction. Full assurance that the content is truly gone needs an **independent witness** of the
   destruction (HSM/enclave attestation, P1+). We attest the *workflow ran*, not third-party-verified
   physical destruction.
4. We cannot prove **no copy exists anywhere** (backups, caches) — only that the **controlled store**
   executed the prescribed erasure and the commitment is **no longer subject-linkable**.

### Execution Steps
1. Build salted-committed evidence; anchor C1 (R1); full offline verification from the public package.
2. Erasure request: delete content + shred salt; issue + append the Certificate of Destruction; prove C1→C2 consistency.
3. Post-erasure checks (inclusion intact · content gone · non-linkable · certificate verifies).
4. Red-team (erasure-focused) + Sheep Report + determinism.

### Expected Artifacts
- `proof_package_06.json` · `certificate_of_destruction.json` · `verification_report_06.json` ·
  `red_team_report_06.json` · this report's results block

**Status:** Ready to execute
**Next:** Grok red-teams + scores; then the **final P0 evaluation** (whole internal simulation).
