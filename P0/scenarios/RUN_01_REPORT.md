# RUN 01 — Happy Path Batch · Report to Red Team (Grok)

**Run ID:** P0-AIAct-Track1-2026-06-09 · **Scenario:** P0-01-HappyPath
**Executor:** Cl1 (Core Attestor) · **Status:** ✅ all pre-registered criteria PASS

## What was done
Integrated the **real Evidence Codec v0.2 + anchor proof spine** from the `ncte-adapter`
repo (not a copy — the actual built artifact) into `P0/scripts/run_happy_path.py`, and ran
the full chain on **30 synthetic agent tool-calls**:

```
30 synthetic AGENT_ACTION tool-calls (deterministic, hash-only inputs)
  -> Evidence Codec v0.2 lossless blobs   (commitment over canonical ORIGINAL, RFC 8785 JCS)
  -> ONE RFC 6962 Merkle batch root
  -> ONE Ed25519 signed checkpoint        (1 signature anchors all 30 — RT0-C cost win)
  -> per-item inclusion proofs
  -> full OFFLINE verification from the PUBLIC proof package only
  -> basic tamper-resistance probe
```

The commitment is **bound to the CORE contract** `NCTE_AI_ACT_EVIDENCE_BOUNDARY_v0_1`
via `evidence_commitment.hash_only_commit` (= `ncte.commitment.hash_only.v0_1`).

## Key outputs
| Fact | Value |
|---|---|
| Items encoded & batched | **30 / 30** |
| Merkle root (deterministic) | `sha256:1b572772c0e2a996d70e3975307531cde351d7e93feab3f724de8b7a700dd220` |
| Checkpoint | Ed25519, kid `cise-p0-happy-k1`, signs the one root |
| Off-ledger compressed store | 7 580 bytes across 30 blobs (lossless) |
| Offline verification (public package only) | **30 / 30 items full-chain OK** |
| Tamper probe (blob #7 flipped) | **detected** — only `blob_intact` fails; neighbour + checkpoint untouched |
| Determinism | re-run reproduces the identical root |

Each item's 4 granular checks all pass: `checkpoint_signature`, `root_binds_batch`,
`merkle_inclusion`, `blob_intact`.

### Pre-registered PASS/FAIL (from 01_Happy_Path_Batch.md)
- ✅ all 30 encoded and batched
- ✅ Merkle root calculated + checkpoint signed
- ✅ all inclusion proofs valid
- ✅ full offline verification
- ✅ basic tamper-resistance (≥ 8.0 axis: tamper is detected, localized, non-spreading)

## Artifacts (in `P0/evidence/`)
- `happy_path_batch_input.json` — the 30 raw synthetic items
- `proof_package.json` — self-contained PUBLIC package (batch + checkpoint + jwks + blobs)
- `verification_report.json` — per-item checks + tamper probe + honest limits

## Honest limits (claim discipline)
- **SIMULATION on SYNTHETIC data** — not a compliance/conformity claim.
- Assurance ≠ certification · Anchored ≠ settled · Verified ≠ content-authenticated.
- Happy path proves the spine works cleanly; it does **not** prove resistance to a determined
  adversary — that is scenarios 03 (Malicious Bypass) and 04 (Operator Tamper).

## Over to Red Team (Gr1)
The public proof package is self-contained and offline-verifiable. Suggested next probes:
1. Can you make a tampered/forged item verify? (attack `blob_intact` / `merkle_inclusion`)
2. Can you swap an item's inclusion proof to point at another leaf and still pass?
3. Can you re-sign a different root with a look-alike key and pass `checkpoint_signature`?
4. Is anything in the package over-claimed vs what it actually proves?

**Next scenario when Drazen says go:** 02 Error & Recovery.
