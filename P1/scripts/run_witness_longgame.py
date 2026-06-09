#!/usr/bin/env python3
"""P1-02 Witness Long Game — liveness/safety, gradual corruption, sybil (deeper witness test).

COTRUGLI CISE · P1 · Scenario 02. Answers Grok's P1-01 feedback: test the witness layer over TIME,
not a single snapshot.

  - liveness vs safety: witnesses offline -> un-witnessed (fails safe), never falsely witnessed.
  - gradual corruption: a witnessed lie needs >= k corrupted witnesses (explicit security margin).
  - honest detection: >= 1 honest witness asked -> the forged root is caught by equivocation.
  - sybil: unregistered fake witnesses are not counted (pinned registry); selection bias is the
    disclosed limit needing independent selection.

Uses the real witness layer from ncte-adapter.

Run:
    NCTE_ADAPTER_PATH=../ncte-adapter \
      ../ncte-adapter/.venv/bin/python P1/scripts/run_witness_longgame.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ADAPTER_PATH = Path(os.environ.get("NCTE_ADAPTER_PATH", str(_REPO_ROOT.parent / "ncte-adapter"))).resolve()
if not (_ADAPTER_PATH / "app" / "witness.py").exists():
    sys.exit(f"❌ witness layer not found at {_ADAPTER_PATH}/app/witness.py. Set NCTE_ADAPTER_PATH.")
sys.path.insert(0, str(_ADAPTER_PATH))

from app.anchor import build_checkpoint  # noqa: E402
from app.anchor_backends import SimulatedWitnessAnchor  # noqa: E402
from app.merkle import merkle_root, to_hex  # noqa: E402
from app.signing import Signer, b64u_encode  # noqa: E402
from app.witness import detect_equivocation, verify_witnessed_checkpoint, witness_statements  # noqa: E402

RUN_ID = "P1-Witness-2026-06-09"
SCENARIO_ID = "P1-02-WitnessLongGame"
LOG_ID = "witness-longgame-log-1"
N, K, SIZE, TS = 7, 4, 16, "2026-06-09T17:00:00Z"
_EVIDENCE = _REPO_ROOT / "P1" / "evidence"


def _signer(seed: bytes, kid: str) -> Signer:
    return Signer.from_seed_b64(b64u_encode((seed + b"\x00" * 32)[:32]), kid)


def _root(tag: str) -> str:
    return to_hex(merkle_root([f"{tag}-{i:03d}".encode() for i in range(SIZE)]))


def _witnessed(operator, cosigners, root):
    cp = build_checkpoint(operator, SIZE, root, TS, log_id=LOG_ID)
    cp.external_anchors = [SimulatedWitnessAnchor(w).publish(cp) for w in cosigners]
    return cp


def _write_json(name, payload):
    p = _EVIDENCE / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return p


def run() -> dict:
    print(f"🚀 {SCENARIO_ID} — Witness Long Game (n={N}, k={K})\n")
    operator = _signer(b"p1lg-operator", "operator-k1")
    witnesses = [_signer(f"p1lg-witness-{i}".encode(), f"witness-{i}") for i in range(N)]
    registry = {w.key_id: w.public_jwk() for w in witnesses}
    R_true = _root("Rtrue")
    R_lie = _root("Rlie")

    # 1) LIVENESS / SAFETY sweep: only `online` witnesses can co-sign the TRUE root.
    liveness = []
    false_witnessing = False
    for online in range(N, -1, -1):
        cp = _witnessed(operator, witnesses[:online], R_true)
        v = verify_witnessed_checkpoint(cp, operator_jwks=operator.jwks(), witness_registry=registry, k=K)
        liveness.append({"online": online, "witnessed": v.witnessed})
        # safety invariant: witnessed is True only when online >= k
        if v.witnessed and online < K:
            false_witnessing = True
    safety_ok = (not false_witnessing) and all(
        r["witnessed"] == (r["online"] >= K) for r in liveness)
    liveness_threshold = min((r["online"] for r in liveness if r["witnessed"]), default=None)
    print(f"✅ liveness/safety: witnessed iff online>=k; liveness threshold (lowest online still "
          f"witnessed)={liveness_threshold}; no false witnessing={not false_witnessing}")

    # 2) GRADUAL CORRUPTION: operator forges R_lie cosigned by the first c corrupted witnesses.
    corruption = []
    crossover = None
    for c in range(0, K + 1):
        cp = _witnessed(operator, witnesses[:c], R_lie)            # corrupted witnesses sign the lie
        v = verify_witnessed_checkpoint(cp, operator_jwks=operator.jwks(), witness_registry=registry, k=K)
        corruption.append({"corrupted": c, "lie_witnessed": v.witnessed})
        if v.witnessed and crossover is None:
            crossover = c
    safe_below_k = all(not r["lie_witnessed"] for r in corruption if r["corrupted"] < K)
    crossover_at_k = (crossover == K)
    print(f"✅ gradual corruption: lie witnessed only at corrupted>=k; crossover={crossover} "
          f"(security margin = {K} corruptions); safe-below-k={safe_below_k}")

    # 3) HONEST DETECTION: at c=k, an honest witness signs R_true while corrupted sign R_lie.
    cp_lie = _witnessed(operator, witnesses[:K], R_lie)            # k corrupted on the lie
    cp_true = _witnessed(operator, [witnesses[K]], R_true)         # 1 honest on the truth
    conflicts = detect_equivocation(witness_statements(cp_lie) + witness_statements(cp_true))
    honest_detection = len(conflicts) == 1
    print(f"✅ honest detection: 1 honest witness on R_true vs {K} corrupted on R_lie -> "
          f"equivocation conflicts={len(conflicts)} -> caught={honest_detection}")

    # 4) SYBIL: operator injects unregistered fake witnesses to reach quorum.
    fakes = [_signer(f"sybil-{i}".encode(), f"sybil-{i}") for i in range(K)]
    cp_sybil = _witnessed(operator, fakes, R_lie)                  # k fake (unregistered) cosigners
    v_sybil = verify_witnessed_checkpoint(cp_sybil, operator_jwks=operator.jwks(),
                                          witness_registry=registry, k=K)
    sybil_rejected = v_sybil.witnessed is False and v_sybil.valid_witnesses == []
    print(f"✅ sybil: {K} unregistered fake witnesses -> witnessed={v_sybil.witnessed} "
          f"-> rejected={sybil_rejected}")

    pre_reg = {
        "liveness_safety_no_false_witnessing": safety_ok,
        "safe_while_corrupted_below_k": safe_below_k,
        "crossover_security_margin_is_k": crossover_at_k,
        "honest_witness_detects_fork": honest_detection,
        "sybil_unregistered_rejected": sybil_rejected,
    }

    report = {
        "run_id": RUN_ID, "scenario_id": SCENARIO_ID, "n": N, "k": K,
        "security_margin_corruptions": K, "liveness_threshold_online": liveness_threshold,
        "liveness_sweep": liveness, "corruption_sweep": corruption,
        "equivocation_conflicts_on_honest_detection": conflicts,
        "pre_registered": pre_reg,
        "honest_limits": [
            "SIMULATION on SYNTHETIC data — not a compliance/conformity claim.",
            "The break cost is k INDEPENDENT corruptions — finite, and only as high as the witnesses "
            "are independent and not dependent on the operator (staking/slashing/who-pays = gate G3).",
            "Silent takeover also needs SELECTION control: with >=1 honest witness asked, the lie is "
            "caught by equivocation; hiding it requires choosing who is asked -> independent/random "
            "witness selection is load-bearing.",
            "Liveness is NOT guaranteed: enough witnesses offline -> no new witnessed checkpoint. The "
            "layer trades liveness for safety (rather produce nothing than a falsely-witnessed root).",
            "Sybil is bounded by the PINNED registry (unregistered witnesses never count); selection "
            "bias among registered witnesses is the disclosed limit.",
        ],
    }
    _write_json("verification_report_p1_02.json", report)

    print("\n📋 pre-registered PASS/FAIL:")
    for k_, v_ in pre_reg.items():
        print(f"   {'PASS' if v_ else 'FAIL'}  {k_}")
    return {"report": report, "pre_registered": pre_reg}


if __name__ == "__main__":
    result = run()
    ok = all(result["pre_registered"].values())
    print(f"\n{'🟢 ALL PRE-REGISTERED CRITERIA PASS' if ok else '🔴 SOME CRITERIA FAILED'}")
    sys.exit(0 if ok else 1)
