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

## Red-Team results (executed) — Grok scored RUN 01 **8.7/10**

The 4 probes were **executed** against the real proof package via
`P0/scripts/red_team_run_01.py` (results in `P0/evidence/red_team_report.json`).
**PASS = the defense holds (forgery rejected).**

| # | Attack | Verdict | What happened |
|---|---|---|---|
| 1 | Forge/tamper an item so it verifies | ✅ **PASS** | (a) swap blob, keep commitment → `blob_intact=False`; (b) forge a matching commitment → `merkle_inclusion=False`. You can't keep the anchored commitment with forged bytes, and a forged commitment is not a leaf under the signed root. |
| 2 | Swap inclusion proof / index to another leaf | ✅ **PASS** | item i's commitment + item j's proof → `False`; i's proof claiming index j → `False`. The audit path reconstructs a *different* root. |
| 3 | Re-sign a forged root with a look-alike key | ✅ **PASS** *(+ accepted limit)* | Forged root signed by an attacker key, verified against the **pinned issuer key** → `False` (rejected). |
| 4 | Over-claim audit (claim discipline) | ✅ **PASS** | No forbidden-claim phrases in the machine artifacts; `honest_limits` present. Artifacts carry structural facts + disclosed limits only. |

**All 4 attacks defended.**

### ⚠ Honest ACCEPTED LIMIT (surfaced by attack 3)
Offline verification proves *internal consistency* + that **some** key signed the root — it does
**not** prove the signer is the legitimate issuer unless the verifier **pins the issuer key
out-of-band**. If an attacker controls the whole package and also swaps the shipped `jwks` to their
own public key, the package is self-consistently "valid" against *that* key. So: **the issuer key
must be distributed/pinned separately, never trusted from inside the package.** This is a trust-root
property, not a codec bug — disclosed, not hidden. (Strengthening it = witness layer / independent
anchor, a P1+ topic.)

## Determinism (confirmed)
Two fresh runs produce a **byte-identical** result:
- Merkle root: `sha256:1b572772c0e2a996d70e3975307531cde351d7e93feab3f724de8b7a700dd220`
- Digest over (root + all 30 commitments + all inclusion proofs): `1b0e1833…d4d1abe` — **identical** across runs.
Any verifier can re-run and compare. (Compression bytes may differ across zlib builds, but the
commitment is over the canonical ORIGINAL, so the root and all proofs are stable.)

## 🐑 Sheep Report (for a non-technical reader)
*What a non-technical person sees and can trust, in plain words:*

- We recorded **30 things an AI agent did** (synthetic, for this test) and put each one in a sealed
  digital envelope. Sealing means: if anyone changes even one character later, the seal visibly breaks.
- We bundled all 30 seals into **one master fingerprint** and signed that fingerprint **once**. One
  signature stands behind all 30 records — cheap and tamper-evident.
- An **independent checker** — using *only* the public bundle, trusting nobody — confirmed all 30
  records are intact and genuinely belong to the signed bundle. **30 out of 30 passed.**
- We then **tried to cheat**: forge a record, fake a membership proof, sign with a copycat key,
  and over-promise in the wording. **Every cheat was caught.**
- **One honest caveat:** the check proves the records weren't tampered with *and* that they were
  signed — but you must get the signer's "official stamp" from a trusted place, not from inside the
  bundle itself. (Like verifying an *officially sealed* document: you confirm the seal against a
  known registry, not against a stamp the sender printed themselves.)
- **What this is NOT:** it is *not* a government certificate, *not* "the AI is compliant", *not*
  proof the records are true in the real world — only that they are intact, anchored, and checkable.

## Next
**RUN 01 RED-TEAM COMPLETE.** Next scenario when Drazen says go: **02 Error & Recovery**.
