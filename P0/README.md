# P0 — Proof Spine Stress Test (run notes)

Each scenario exercises the **real** Evidence Codec v0.2 + anchor proof spine from the
`ncte-adapter` repo (the built artifact, not a copy), so P0 tests what actually exists.

## Prerequisites
- A checkout of `ncte-adapter` (sibling of this repo, or anywhere — point `NCTE_ADAPTER_PATH` at it).
- A Python env with its deps (`pydantic`, `rfc8785`, `cryptography`). The simplest is to reuse the
  ncte-adapter virtualenv.

## Run scenario 01 (Happy Path Batch)
```bash
NCTE_ADAPTER_PATH=../ncte-adapter \
  ../ncte-adapter/.venv/bin/python P0/scripts/run_happy_path.py
```
Exit code 0 ⇒ all pre-registered criteria pass. Artifacts land in `P0/evidence/`:
- `happy_path_batch_input.json` — the synthetic input items
- `proof_package.json` — self-contained PUBLIC package (batch + checkpoint + jwks + blobs)
- `verification_report.json` — per-item checks + tamper probe + honest limits

The run is **deterministic** (fixed seed + timestamps): the Merkle root reproduces exactly,
so any verifier can re-run and compare. See `P0/scenarios/RUN_01_REPORT.md` for the latest result.

## Honest framing
SIMULATION on SYNTHETIC data. Assurance ≠ certification · Anchored ≠ settled ·
Verified ≠ content-authenticated.
