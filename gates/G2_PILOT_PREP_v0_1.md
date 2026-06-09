# Gate G2 — Enterprise pilot prep v0.1 (draft input)

**Status:** draft input for Drazen's GTM decision — *not* a commitment. Defines the first use-case, a
**minimal self-hosted pilot**, and exactly what G2 must validate.

> The round-3 red-team's G2: **will any enterprise actually route traffic through a (self-hosted)
> gateway and value the proof?** Adoption — not the proof spine — is the open question here.

## 1. First use-case (chosen)
**AI Act evidence for agent/tool-call activity.** Reasons:
- It is **compelled demand** (AI Act record-keeping) rather than nice-to-have.
- It is the **low-G** use-case the G3 sim showed is economically defensible (a witness layer is
  affordable here; high-stakes settlement is not, yet).
- It exercises the **moat**: agent/tool-call granularity is *excluded* from vendor compliance APIs —
  exactly the plane only a neutral, cross-vendor layer captures.
- The full path already exists end-to-end: `python -m app.ai_act_demo --verify-core-boundary` →
  dossier + coverage + ESSL badge + Proof-of-Coverage + CORE-validated boundary reference + manifest.

## 2. Deployment shape: self-hosted async sidecar
From the red-team findings (RT1-B fix): the enterprise runs **its own node**; **data never leaves its
boundary** (solves Art-44 / DPA / latency / SPOF). The neutral layer attests the node's **output**
(commitments + checkpoints), not the traffic. Witnessing (P1) co-signs only the **root**, never content.

```
enterprise's own agents/tools
  → self-hosted sidecar (captures agent/tool-call events, client-side, content stays local)
  → salted/HMAC commitment + receipt + signed checkpoint   (the built spine)
  → [optional] k-of-n witness co-signature of the checkpoint root   (P1 witness layer)
  → AI Act Track-1 demo pack (dossier / coverage / badge / Proof-of-Coverage / CORE-validated ref)
```

Nothing in the pilot needs live DLT, production key custody, or a real witness mesh — those are gated.
The pilot can run with the **simulated witness** path (already built) and a single self-hosted node.

## 3. What G2 must validate (the actual gate)
1. **Routing willingness:** does at least one enterprise agree to route agent/tool-call activity
   through a **self-hosted** sidecar? (The whole G2 question.)
2. **Data-boundary acceptance:** is "content stays local, only commitments/roots leave" acceptable to
   their security/DPA review? (Ties to G1.)
3. **Value perception:** do they see the **AI Act evidence + agent-granularity** output as worth
   running the sidecar — i.e., does the Proof-of-Coverage / dossier answer a real compliance need?
4. **Operational fit:** can a non-specialist run the demo pack and read the manifest (reviewer
   walkthrough already exists)?

## 4. First candidate: DOME
Per the integration history, **DOME first**: the adapter already has the DOME seam (VC bridge / IED
subscriber), and consortium members consent to shared governance — the lowest-friction first router.
A DOME member running the self-hosted sidecar on synthetic-then-real agent events is the minimal pilot.

## 5. Minimal pilot plan (4 honest steps)
1. **Dry run on synthetic data** (already possible): the demo pack + reviewer walkthrough, shown to the
   pilot partner — "this is what you'd get."
2. **Self-hosted node** at the partner: ingest *their* (initially synthetic, then low-sensitivity real)
   agent/tool-call events; content stays local; produce the demo pack locally.
3. **Witnessed checkpoint** (simulated witnesses to start): show the partner the root can be
   independently co-signed without exposing content.
4. **Review:** partner's compliance/security reviews the output against a real AI Act record-keeping
   need; capture the **routing-willingness + value** answer = the G2 verdict.

## 6. GO / NO-GO criterion for G2
- **GO** if ≥ 1 enterprise (ideally a DOME member) agrees to route real agent/tool-call activity through
  a self-hosted sidecar **and** values the AI Act evidence output.
- **NO-GO / reformulate** if enterprises won't self-host or don't value the proof (then the wedge,
  packaging, or use-case needs to change — not the proof spine).

## 7. Honest framing for the pilot (claim discipline)
Allowed: *"independent, tamper-evident, replayable evidence for in-scope agent/tool-call activity,
verifiable offline; assurance that supports AI Act record-keeping needs."* Not allowed: any
full-compliance / formal legal-approval / complete-coverage wording (see the reviewer walkthrough's
allowed/not-allowed checklist). The pilot proves **adoption + value**, not legal compliance.
