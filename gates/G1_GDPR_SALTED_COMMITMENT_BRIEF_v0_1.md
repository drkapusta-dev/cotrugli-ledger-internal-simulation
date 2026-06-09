# Gate G1 — GDPR brief: is a salted/HMAC commitment "personal data"? (v0.1)

**Status:** structured question **for external EU data-protection counsel** — *not* legal advice and
*not* a legal opinion. This frames the precise question, gives counsel the exact technical facts, and
defines what a GO/NO-GO answer looks like. Cheap, parallelizable, high-impact (it gates the whole
erasure / GDPR posture).

> The round-3 red-team named this the cheapest, run-it-first gate: **is a salted hash still personal
> data under strict GDPR?** Everything in the erasure design (RUN 06 + P1-03) hinges on the answer.

## 1. The technical facts (for counsel — these are how the system actually works)
- **Content is never on the ledger.** Only a **commitment** is recorded: either a **salted SHA-256**
  `H(salt ‖ content)` or an **HMAC-SHA256** `HMAC(key, content)`. Raw content (which may relate to an
  identifiable person) is held **off-ledger** in the controller's custody.
- **Salt / HMAC key are controller-held, high-entropy (256-bit), off-ledger.** They are never published
  with the proof and never placed on the ledger.
- The commitment is on an **append-only, witnessed, immutable** log: it cannot be deleted without
  breaking the proof chain (and any deletion would itself be detectable / witnessed).
- **Erasure workflow:** on a subject request, the controller **deletes the off-ledger content** and
  **shreds the salt/key**. After that, the commitment is **non-linkable**: with a 256-bit salt
  destroyed, recomputing or confirming what content the commitment covered is computationally
  infeasible. A **witnessed Certificate of Destruction** (independent k-of-n witnesses) records that
  the erasure happened, when, and for which reference (see P1-03).
- The commitment value itself **remains** on the immutable log (a "non-linkable tombstone").

## 2. The questions for counsel (the actual legal asks)
1. **Is the on-ledger commitment "personal data" under GDPR Art 4(1)** when the off-ledger content
   relates to an identifiable natural person — applying the **Recital 26 identifiability test**
   ("means reasonably likely to be used")? Consider the salt/key being **controller-held** vs the
   ledger being **public/consortium-visible**.
2. **Before erasure:** is the salted/HMAC commitment **anonymous** (outside GDPR) or **pseudonymous**
   (inside GDPR, because the controller still holds the salt/key + content)?
3. **After salt-shred + content deletion:** does the remaining commitment become **effectively
   anonymous / irreversibly non-linkable**, or does it remain personal data?
4. **Art 17 (right to erasure):** does *content deletion + salt-shred + a witnessed Certificate of
   Destruction + a non-linkable tombstone* **satisfy the erasure obligation**, or does Art 17 require
   deletion of the **commitment value itself** from the log (which conflicts with immutability)?
5. Does the **HMAC variant** (controller-held secret key, rotatable, `key_epoch`) change the analysis
   versus a per-record salt — e.g., does destroying one key epoch erase a whole cohort acceptably?
6. Any **cross-border (Art 44)** considerations for a **self-hosted** deployment (content never leaves
   the controller's boundary) versus the **witness layer** (only the commitment/root is co-signed
   externally)?

## 3. What a GO / NO-GO answer looks like
- **GO** if counsel confirms **either**: (a) the salted/HMAC commitment is **not personal data**
  (anonymous) once content + salt are off-ledger / shredded; **or** (b) it is pseudonymous but the
  **salt-shred + witnessed Certificate of Destruction + non-linkable tombstone satisfies Art 17**.
- **CONDITIONAL GO** if counsel specifies a **bounded change** that makes it compliant (e.g., prunable
  anchoring of the commitment, a specific salt-entropy / custody standard, retention limits on the
  off-ledger content).
- **NO-GO / reformulate** if the commitment is personal data **and** Art 17 requires deleting the
  commitment value itself from an immutable log — which would force a redesign (prunable anchoring) or
  a different erasure model.

## 4. Supporting material to hand counsel
- RUN 06 report (offline verification + erasure) and P1-03 (witnessed erasure) — the exact workflow.
- The commitment profiles (`ncte.commitment.hash_only / sha256_salted / hmac_sha256`) and the CORE
  boundary contract (privacy_mode / retention_class semantics).
- Honest framing already in use: **"assurance, not a formal legal-approval"**; we make **no**
  compliance claim — this brief exists precisely to get the **regulated answer** from counsel.

*Out of scope: this document does not assert any GDPR conclusion. It is the input for a paid legal
opinion, which is the G1 gate.*
