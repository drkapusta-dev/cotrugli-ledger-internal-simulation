# Cotrugli Ledger — Internal Simulation (CISE)

A **phased, adversarial internal testing program** for the Cotrugli evidence/proof spine. The goal
is to stress-test *what is actually built* — honestly — and to map the real edges, holding the
system under the same suspicion as everyone else: *verifiable even against its own operator.*

> **Claim discipline (binding):** this is **assurance, not certification**. Every result is a
> SIMULATION on SYNTHETIC data. `Assurance ≠ certification · Anchored ≠ settled · Verified ≠
> content-authenticated · detect-within-boundary ≠ prevent-all-bypass.`

Each scenario exercises the **real** Evidence Codec v0.2 + anchor proof spine from the
[`ncte-adapter`](https://github.com/drkapusta-dev/NCTE-adapter-apeirora) repo (the built artifact,
not a copy), so the simulation tests what genuinely exists.

## P0 — Proof Spine Stress Test ✅ complete

Six scenarios, each: deterministic run → real red-team attacks → honest accepted-limits → Sheep
Report (plain-language) → determinism check. Gate to advance: **≥ 8.5**.

| # | Scenario | What it tests | Score |
|---|---|---|---|
| 01 | [Happy Path Batch](P0/scenarios/RUN_01_REPORT.md) | tamper-evidence + offline verifiability at rest | **9.1** |
| 02 | [Error & Recovery](P0/scenarios/RUN_02_REPORT.md) | failures as first-class evidence; append-only recovery | **9.0** |
| 03 | [Malicious Bypass](P0/scenarios/RUN_03_REPORT.md) | controlled boundary; bypass = detect-not-prevent | **9.3** |
| 04 | [Operator Tamper](P0/scenarios/RUN_04_REPORT.md) | *who attests the attestor?* (RFC 6962 consistency) | **9.4** |
| 05 | [Large Batch Anchoring](P0/scenarios/RUN_05_REPORT.md) | O(1) anchoring cost at 100/500/1000 items | **9.3** |
| 06 | [Offline Verify + Erasure](P0/scenarios/RUN_06_REPORT.md) | GDPR erasure vs immutability (salt-shred + tombstone) | *pending* |

**Final evaluation:** [`P0/P0_FINAL_EVALUATION.md`](P0/P0_FINAL_EVALUATION.md) — aggregate, the
consolidated **accepted-limits → P1+ map**, and an honest readiness self-assessment.

The honest headline across P0: **the technical proof spine is not the weak point.** The open work is
the **witness layer, adoption, and the economic / legal layer** (P1+).

## Running a scenario

Requires a checkout of `ncte-adapter` (point `NCTE_ADAPTER_PATH` at it) and a Python env with its
deps (`pydantic`, `rfc8785`, `cryptography` — the `ncte-adapter` venv works):

```bash
NCTE_ADAPTER_PATH=../ncte-adapter \
  ../ncte-adapter/.venv/bin/python P0/scripts/run_happy_path.py        # scenario 01
# run_error_recovery.py · run_malicious_bypass.py · run_operator_tamper.py
# run_large_batch.py · run_offline_erasure.py  · red_team_run_0N.py
```

Every run is **deterministic** (fixed seeds + timestamps): the Merkle root reproduces exactly, so any
reviewer can re-run and compare. Exit code `0` = all pre-registered criteria pass.

## Layout
```
P0/
  P0_Run_Protocol_v0.1.md      run protocol + roles + pass/fail gate
  P0_FINAL_EVALUATION.md       capstone evaluation across all 6 scenarios
  README.md                    P0 run notes
  scenarios/                   per-scenario specs + RUN_0N_REPORT.md results
  scripts/                     run_*.py (simulations) + red_team_run_*.py (attacks)
  evidence/                    generated proof packages + verification/red-team reports
```

## Roles
Orchestrator & Final Approver: **Drazen** · Core Attestor: **Cl1** · Red Team (Vuk): **Gr1** ·
Enterprise Agent: **Gem1 / Kim1** · Verifier: **De1**. *Attack ≠ judge; pass/fail is pre-registered.*
