#!/usr/bin/env python3
"""P1-01 Witness Ring — adversarial stress-test of the REAL witness layer (app/witness.py).

COTRUGLI CISE · P1 · Scenario 01.

A checkpoint root is WITNESSED only when k independent witnesses co-sign it against their PINNED
keys. This run proves: honest k-of-n witnessing; a key-holding operator cannot forge the quorum or
transplant cosignatures onto a rewritten root; an impersonated witness is not counted; collusion
below k fails; and equivocation (different roots to different parties) is detectable. It discloses
the boundary honestly: >= k colluding witnesses can witness a lie (gate G3 economics), and withheld
cosignatures cause a fail-safe un-witnessed state.

Uses the real witness layer + anchor + signing from the ncte-adapter repo.

Run (with the ncte-adapter venv):
    NCTE_ADAPTER_PATH=../ncte-adapter \
      ../ncte-adapter/.venv/bin/python P1/scripts/run_witness_ring.py
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
from app.witness import (  # noqa: E402
    detect_equivocation,
    verify_witnessed_checkpoint,
    witness_statements,
)

RUN_ID = "P1-Witness-2026-06-09"
SCENARIO_ID = "P1-01-WitnessRing"
LOG_ID = "witness-ring-log-1"
N_WITNESSES = 5
K = 3
SIZE = 16
TS = "2026-06-09T16:00:00Z"
_EVIDENCE = _REPO_ROOT / "P1" / "evidence"


def _signer(seed: bytes, key_id: str) -> Signer:
    return Signer.from_seed_b64(b64u_encode((seed + b"\x00" * 32)[:32]), key_id)


def _root(tag: bytes, size: int = SIZE) -> str:
    return to_hex(merkle_root([f"{tag.decode()}-{i:03d}".encode() for i in range(size)]))


def _witnessed_checkpoint(operator, witnesses, root, ts=TS):
    cp = build_checkpoint(operator, SIZE, root, ts, log_id=LOG_ID)
    cp.external_anchors = [SimulatedWitnessAnchor(w).publish(cp) for w in witnesses]
    return cp


def _write_json(name, payload):
    p = _EVIDENCE / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return p


def run() -> dict:
    print(f"🚀 {SCENARIO_ID} — Witness Ring (n={N_WITNESSES}, k={K})\n")
    operator = _signer(b"p1-operator", "operator-k1")
    witnesses = [_signer(f"p1-witness-{i}".encode(), f"witness-{i}") for i in range(N_WITNESSES)]
    registry = {w.key_id: w.public_jwk() for w in witnesses}
    R1 = _root(b"R1")

    # 1) honest k-of-n witnessed checkpoint.
    cp = _witnessed_checkpoint(operator, witnesses[:K], R1)
    v = verify_witnessed_checkpoint(cp, operator_jwks=operator.jwks(), witness_registry=registry, k=K)
    print(f"✅ honest k-of-n: witnessed={v.witnessed} valid={v.valid_witnesses}")

    # 2) operator rewrite: forge a checkpoint over R1' (own key) and transplant the old cosignatures.
    R1_prime = _root(b"R1prime")
    forged = build_checkpoint(operator, SIZE, R1_prime, TS, log_id=LOG_ID)
    forged.external_anchors = list(cp.external_anchors)            # cosigs that signed R1, not R1'
    v_rewrite = verify_witnessed_checkpoint(forged, operator_jwks=operator.jwks(),
                                            witness_registry=registry, k=K)
    rewrite_detected = v_rewrite.witnessed is False
    print(f"✅ operator rewrite over R1′ w/ transplanted cosigs: witnessed={v_rewrite.witnessed} "
          f"-> detected={rewrite_detected}")

    # 3) impersonated witness: operator embeds a cosig claiming witness-0 but signs with its own key.
    imp = _witnessed_checkpoint(operator, [witnesses[1], witnesses[2]], R1)
    fake = SimulatedWitnessAnchor(operator).publish(imp)
    fake["witness_id"] = "witness-0"                               # impersonate a registry witness
    imp.external_anchors = imp.external_anchors + [fake]
    v_imp = verify_witnessed_checkpoint(imp, operator_jwks=operator.jwks(),
                                        witness_registry=registry, k=K)
    impersonation_rejected = "witness-0" not in v_imp.valid_witnesses and v_imp.witnessed is False
    print(f"✅ impersonated witness-0 (operator key): counted={'witness-0' in v_imp.valid_witnesses} "
          f"witnessed={v_imp.witnessed} -> rejected={impersonation_rejected}")

    # 4) collusion below k: operator + (k-1) malicious witnesses cosign a forged root.
    collusion = _witnessed_checkpoint(operator, witnesses[:K - 1], R1_prime)
    v_coll = verify_witnessed_checkpoint(collusion, operator_jwks=operator.jwks(),
                                         witness_registry=registry, k=K)
    collusion_below_k_blocked = v_coll.witnessed is False
    print(f"✅ collusion below k ({K-1} witnesses on R1′): witnessed={v_coll.witnessed} "
          f"-> blocked={collusion_below_k_blocked}")

    # 5) equivocation: operator shows R1 to witnesses {0,1}, R1' to witnesses {2,3}.
    cp_a = _witnessed_checkpoint(operator, [witnesses[0], witnesses[1]], R1)
    cp_b = _witnessed_checkpoint(operator, [witnesses[2], witnesses[3]], R1_prime)
    conflicts = detect_equivocation(witness_statements(cp_a) + witness_statements(cp_b))
    equivocation_detected = len(conflicts) == 1
    print(f"✅ equivocation (R1 to {{0,1}}, R1′ to {{2,3}}): conflicts={len(conflicts)} "
          f"-> detected={equivocation_detected}")

    pre_reg = {
        "honest_k_of_n_witnessed": v.witnessed and v.valid_witnesses == sorted(w.key_id for w in witnesses[:K]),
        "operator_rewrite_detected": rewrite_detected,
        "impersonated_witness_rejected": impersonation_rejected,
        "collusion_below_k_blocked": collusion_below_k_blocked,
        "equivocation_detected": equivocation_detected,
    }

    report = {
        "run_id": RUN_ID, "scenario_id": SCENARIO_ID, "n": N_WITNESSES, "k": K,
        "witnessed_root_R1": R1, "honest_verdict": json.loads(v.model_dump_json()),
        "equivocation_conflicts": conflicts,
        "pre_registered": pre_reg,
        "honest_limits": [
            "SIMULATION on SYNTHETIC data — not a compliance/conformity claim.",
            "Quorum defends against an operator + up to (k-1) dishonest witnesses; at >= k COLLUDING "
            "witnesses a forged root can be witnessed. So k/n + witness independence + who-runs/pays "
            "the witnesses without re-centralizing is the economic question (gate G3), not solved here.",
            "Liveness: witnesses that withhold cosignatures prevent a quorum -> the checkpoint is "
            "un-witnessed (fails safe); the layer never produces a FALSELY witnessed checkpoint, but "
            "cannot force availability.",
            "Garbage-in: witnesses attest the root they were shown, not upstream event truth (RUN 03 "
            "bypass limit still applies above the boundary).",
            "Assurance != certification · witnessed-when-quorum != witness-honest-by-construction.",
        ],
    }
    _write_json("verification_report_p1_01.json", report)

    print("\n📋 pre-registered PASS/FAIL:")
    for kk, vv in pre_reg.items():
        print(f"   {'PASS' if vv else 'FAIL'}  {kk}")
    return {"report": report, "pre_registered": pre_reg}


if __name__ == "__main__":
    result = run()
    ok = all(result["pre_registered"].values())
    print(f"\n{'🟢 ALL PRE-REGISTERED CRITERIA PASS' if ok else '🔴 SOME CRITERIA FAILED'}")
    sys.exit(0 if ok else 1)
