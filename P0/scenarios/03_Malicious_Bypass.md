# 03_Malicious_Bypass.md

**Scenario ID:** P0-03-MaliciousBypass
**Description:** Agents (and a malicious operator) actively try to defeat the evidence layer:
bypass the gateway, call vendors directly, fake tool outputs, exceed their mandate, forge
authorization, and replay receipts. This scenario maps the **true edge** of what the proof spine
can and cannot do — and states it honestly.

### Objective
Show the **controlled execution boundary** (a simulated Vanguard Gateway) as a control point —
"**no receipt under the signed root → no authorized execution**" — and, with equal honesty, show
the **accepted limit**: an action that never touches the boundary is invisible to the proof layer
alone; detecting it needs reconciliation with an independent signal.

What the gateway does in this sim (this is simulation logic; the codec/anchor is the real spine):
- assigns a monotonic `gateway_seq` to every processed request (allow **and** deny);
- checks the principal's **mandate** against the tool's required capability → `decision: allow|deny`
  (a denied action is recorded as **deny evidence**, never silently dropped);
- captures the tool-call **client-side** (input committed before the vendor sees it);
- the batch checkpoint (gateway-signed Merkle root) is the authorization anchor.

### Evidence model (per gateway event)
`id · gateway_seq · timestamp · agent_id · principal · mandate · tool · capability_required ·
input_hash (hash-only) · decision ∈ {allow, deny} · deny_reason | null · result | null ·
event_class = "GATEWAY_DECISION"`

Bypass actions are **vendor-side ground truth** that the gateway never saw — they are NOT in the
proof package; they exist only to drive the reconciliation check.

### Pre-registered Pass/Fail Criteria
1. All gateway events (allow + deny) encoded, batched, anchored, offline-verified: **PASS**
2. Out-of-mandate actions recorded as **deny evidence** (control point, not silent drop): **PASS**
3. Gateway sequence is **contiguous** in the anchored batch; a missing/removed seq is detectable: **PASS**
4. A faked/altered tool output is **detected** (commitment mismatch — can't rewrite what passed): **PASS**
5. A forged authorization (look-alike key signing a fake root) is **rejected** vs the pinned key: **PASS**
6. A replayed receipt (double-execute) is **detectable** as a duplicate seq within the batch: **PASS**
7. **Reconciliation** surfaces a true bypass as a `gateway_count` vs `vendor_observed_count` discrepancy: **PASS (detect, not prevent)**
8. Full offline verification: **PASS**
9. No over-claim: the spine **controls/detects within the boundary**; it does **not** prevent all bypass: **PASS**
10. Vučja otpornost (incl. semantic attacks): ≥ 8.0 · Ovčja os: ≥ 6.5

### THE headline accepted limit (stated up front)
**"No receipt → no execution" is a CONTROL convention enforced by the boundary, not a cryptographic
proof that nothing happened outside it.** A determined agent that calls a vendor directly, never
touching the gateway, produces **no receipt** — the proof spine alone cannot see it or attest its
content. The system reduces this risk three ways, none of which "closes" it:
- the boundary makes the *honest* path the easy one (allowed actions get an authorization anchor);
- **reconciliation** against an independent vendor count surfaces the *number* of unaccounted actions;
- in-boundary completeness (contiguous sequence) makes *partial* tampering visible.
This is the from-ingestion-forward / garbage-in limit named across the whole red-team. We disclose
it; we do not pretend to solve it here.

### Execution Steps
1. Gateway processes ~28 requests (mostly read-only allows; several out-of-mandate writes → deny).
2. Codec v0.2 encodes every gateway event → batch → ONE signed checkpoint.
3. Offline-verify all; check sequence contiguity; record deny evidence.
4. Drive bypass actions (vendor-side, unseen) → reconciliation discrepancy.
5. Red-team (bypass-focused + semantic) + Sheep Report + determinism.

### Expected Artifacts
- ~28 gateway events (allow + deny) · 1 batch + signed checkpoint · inclusion proofs
- `verification_report_03.json` · `red_team_report_03.json` · this report's results block

**Status:** Ready to execute
**Next:** Grok red-teams + scores; then RUN 04 Operator Tamper.
