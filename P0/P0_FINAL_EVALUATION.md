# P0 — Final Evaluation (Proof Spine Stress Test)

**Run ID:** P0-AIAct-Track1-2026-06-09 · **Status:** all 6 scenarios executed · **gate:** ≥ 8.5 to advance to P1
**Self-assessment by:** Cl1 (Core Attestor). The overall P0 score is the **Red Team's (Grok) + Orchestrator's (Drazen)** call.

## 1. Scenario results
| # | Scenario | Pre-registered | Red-team | Determinism | Grok score |
|---|---|---|---|---|---|
| 01 | Happy Path Batch (30) | ✅ all PASS | all 4 defended | 100% | **9.1** PASSED |
| 02 | Error & Recovery (24) | ✅ all PASS | all 4 defended | 100% | **9.0** PASSED |
| 03 | Malicious Bypass (28) | ✅ all PASS | crypto held; limits disclosed | 100% | **9.3** PASSED |
| 04 | Operator Tamper (I1) | ✅ all PASS | no silent break | 100% | **9.4** PASSED |
| 05 | Large Batch (100/500/1000) | ✅ all PASS | all 5 defended | 100% | **9.3** PASSED |
| 06 | Offline Verify + Erasure (I4) | ✅ all PASS | no silent break | 100% | *pending* |

Average of scored runs (01–05): **9.22**. Every run used the **real** Evidence Codec v0.2 + anchor
proof spine from `ncte-adapter` (the built artifact, not a copy), with deterministic, reproducible roots.

## 2. What P0 PROVED (the built slice)
- **Tamper-evidence & offline verifiability** of evidence at rest and at scale — anyone can verify
  from the public proof package, trusting no one (RUN 01, 05, 06).
- **Failure is first-class evidence**; recovery is **append-only**, never a silent edit (RUN 02).
- A **controlled boundary** records allow/deny decisions and a contiguous sequence; bypass is
  surfaced by **reconciliation** (RUN 03).
- **Verifiable even against its own operator**: a key-holding operator cannot silently rewrite a
  **witnessed** history (RFC 6962 consistency) — even a validly-signed forged checkpoint is caught
  (RUN 04).
- **O(1) anchoring cost**: N items → one signature; O(log N) proofs (RUN 05) — the RT0-C economics.
- **Erasure without breaking the chain**: salted commitment + salt-shred + appended Certificate of
  Destruction → non-linkable tombstone; content gone, chain intact (RUN 06).

## 3. The honest accepted-limits map → P1+ work
P0 disclosed, rather than hid, the real edges. Consolidated:
| Limit (where surfaced) | Closes with (P1+) |
|---|---|
| Bypass with **no receipt** is invisible to the spine alone (RUN 03) | controlled-execution boundary adoption + reconciliation against independent vendor signal |
| The spine attests a decision **was recorded**, not that it was **correct** (RUN 03) | policy/review overlay (not core) |
| **Issuer/gateway key must be pinned out-of-band** (RUN 03/04) | key distribution / transparency log |
| A lone, **unwitnessed** operator can rewrite history (RUN 04, I1) | **external witness / independent anchor / transparency log** |
| **Equivocation / split-view** undetectable by a lone verifier (RUN 04) | witness-network gossip |
| Self-asserted **timestamps** (RUN 04) | external time-anchor / VDF |
| Salted hash **may still be personal data** (RUN 06, I4/G1) | **legal opinion** (cheap, parallel) |
| Deleting the **commitment itself** vs immutability (RUN 06, RT3) | prunable anchoring + legal |
| Certificate of Destruction is **self-attested** (RUN 06) | independent witness / HSM-enclave attestation |
| Can't prove **no copy exists** anywhere (RUN 06) | accepted limit (disclose, don't claim) |

These are exactly the items the round-3 red-team named: the **technical proof spine is not the weak
point** — the open work is **economics, adoption, and the witness/legal layer** (Drazen's court + P1+).

## 4. Honest readiness (self-scored, refusing to inflate)
- **Built slice (proof spine / codec / AI-Act mapping):** strong — ~9.2 across runs, all real, all
  reproducible, all red-teamed.
- **System "wolf + sheep" readiness:** **lower** — the witness layer, controlled-execution-boundary
  adoption, independent erasure-destruction proof, and the **economic/incentive model** are largely
  **P1+ / not built**. The Sheep (clarity) axis rose run-over-run (analogies landed) but a fully
  non-technical reader still needs the accepted-limits explained.
- **Claim discipline:** held throughout — "assurance, not certification"; every run carries its
  honest limits and the naming guard stayed green.

## 5. Recommendation
P0's purpose was to **stress-test what is built** and **map the edges honestly**. On the scored runs
it cleared the **≥ 8.5 gate** comfortably (9.22 avg) with no silent breaks. Recommend: **P0 PASSED**
(pending Grok's RUN 06 score + overall), then proceed to the **3 go/no-go gates** before P1 build —
G1 legal opinion (salted-hash personal-data), G2 enterprise pilot intent (self-hosted gateway), G3
economic model (blind-pooled witness funding) — and the **witness layer** as the first P1 build, since
it closes the largest cluster of accepted limits above.

*All P0 artifacts, scripts, and per-run reports are in `P0/`. Every result is reproducible:
`NCTE_ADAPTER_PATH=../ncte-adapter ../ncte-adapter/.venv/bin/python P0/scripts/run_*.py`.*
