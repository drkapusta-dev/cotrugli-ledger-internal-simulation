#!/usr/bin/env python3
"""P1-01 Red Team — witness-layer attacks.

Each attack reports whether the cryptographic guarantee held (`defended`) and whether it reveals a
disclosed `accepted_limit`. A run is sound iff every attack is DEFENDED or a DISCLOSED accepted
limit — no silent break.

Run (with the ncte-adapter venv):
    NCTE_ADAPTER_PATH=../ncte-adapter \
      ../ncte-adapter/.venv/bin/python P1/scripts/red_team_p1_01.py
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

LOG_ID = "witness-ring-log-1"
N, K, SIZE, TS = 5, 3, 16, "2026-06-09T16:00:00Z"
_EVIDENCE = _REPO_ROOT / "P1" / "evidence"


def _signer(seed: bytes, kid: str) -> Signer:
    return Signer.from_seed_b64(b64u_encode((seed + b"\x00" * 32)[:32]), kid)


def _root(tag: bytes) -> str:
    return to_hex(merkle_root([f"{tag.decode()}-{i:03d}".encode() for i in range(SIZE)]))


def _cp(operator, witnesses, root):
    cp = build_checkpoint(operator, SIZE, root, TS, log_id=LOG_ID)
    cp.external_anchors = [SimulatedWitnessAnchor(w).publish(cp) for w in witnesses]
    return cp


def _ctx():
    operator = _signer(b"p1-operator", "operator-k1")
    witnesses = [_signer(f"p1-witness-{i}".encode(), f"witness-{i}") for i in range(N)]
    registry = {w.key_id: w.public_jwk() for w in witnesses}
    return operator, witnesses, registry


# A1 — forge the quorum using the operator's OWN keys for k fake witnesses.
def attack_1_forge_quorum(operator, witnesses, registry):
    R = _root(b"R1")
    cp = build_checkpoint(operator, SIZE, R, TS, log_id=LOG_ID)
    fakes = []
    for i in range(K):
        a = SimulatedWitnessAnchor(operator).publish(cp)
        a["witness_id"] = f"witness-{i}"               # claim registry ids, but operator-signed
        fakes.append(a)
    cp.external_anchors = fakes
    v = verify_witnessed_checkpoint(cp, operator_jwks=operator.jwks(), witness_registry=registry, k=K)
    return {"attack": "1. Forge the quorum with the operator's own keys", "defended": v.witnessed is False,
            "accepted_limit": False, "verdict": "DEFENDED — pinned-key match rejects operator-minted witnesses",
            "detail": f"k operator-signed anchors claiming registry ids -> valid={v.valid_witnesses}, "
                      f"witnessed={v.witnessed}. The operator cannot mint witnesses with keys it controls."}


# A2 — replay a genuine witness cosignature onto a different (rewritten) root.
def attack_2_replay_cosig(operator, witnesses, registry):
    R, Rp = _root(b"R1"), _root(b"R1prime")
    good = _cp(operator, [witnesses[0]], R)            # witness-0 genuinely cosigns R
    forged = build_checkpoint(operator, SIZE, Rp, TS, log_id=LOG_ID)
    forged.external_anchors = list(good.external_anchors)   # transplant onto R'
    v = verify_witnessed_checkpoint(forged, operator_jwks=operator.jwks(), witness_registry=registry, k=1)
    return {"attack": "2. Replay a witness cosignature onto a rewritten root", "defended": v.witnessed is False,
            "accepted_limit": False, "verdict": "DEFENDED — a cosignature binds the exact root",
            "detail": f"witness-0's cosig over R transplanted onto R' -> valid={v.valid_witnesses}, "
                      f"witnessed={v.witnessed}. The cosignature covers the root, so it won't verify on R'."}


# A3 — >= k GENUINE witnesses collude with the operator to witness a forged root.
def attack_3_k_collusion(operator, witnesses, registry):
    Rp = _root(b"R1prime")
    cp = _cp(operator, witnesses[:K], Rp)              # k real witnesses sign the forged root
    v = verify_witnessed_checkpoint(cp, operator_jwks=operator.jwks(), witness_registry=registry, k=K)
    return {"attack": "3. >= k colluding witnesses witness a forged root", "defended": False,
            "accepted_limit": v.witnessed is True,
            "verdict": "ACCEPTED LIMIT — at >= k collusion a lie can be witnessed (gate G3)",
            "detail": f"{K} genuine witnesses co-sign a forged root -> witnessed={v.witnessed}. Quorum "
                      f"defends up to (k-1) dishonest witnesses; at k it falls. k/n + independence + "
                      f"who-pays-without-recentralizing is the economic question (G3), not solved here."}


# A4 — a single self-equivocating witness cosigns two different roots at the same state.
def attack_4_self_equivocation(operator, witnesses, registry):
    R, Rp = _root(b"R1"), _root(b"R1prime")
    a = _cp(operator, [witnesses[0]], R)
    b = _cp(operator, [witnesses[0]], Rp)             # same witness, conflicting root, same (log,size)
    conflicts = detect_equivocation(witness_statements(a) + witness_statements(b))
    return {"attack": "4. Self-equivocating witness (one witness, two roots)", "defended": len(conflicts) == 1,
            "accepted_limit": False, "verdict": "DEFENDED — equivocation is caught even with a single witness",
            "detail": f"witness-0 cosigns both R and R' at the same (log_id, tree_size) -> conflicts="
                      f"{len(conflicts)}. Comparing statements reveals the fork regardless of who signed."}


# A5 — over-claim audit.
def attack_5_overclaim():
    report = json.loads((_EVIDENCE / "verification_report_p1_01.json").read_text(encoding="utf-8"))
    scanned = {k: v for k, v in report.items() if k != "honest_limits"}
    text = json.dumps(scanned).lower()
    over = ["tamper-proof", "cannot be forged", "witnesses are trusted", "prevents rewrite",
            "guarantees", "compliant"]
    hits = [p for p in over if p in text]
    limits = report.get("honest_limits", [])
    discloses_collusion = any("colluding" in l.lower() and "g3" in l.lower() for l in limits)
    discloses_liveness = any("liveness" in l.lower() for l in limits)
    defended = (not hits) and discloses_collusion and discloses_liveness
    return {"attack": "5. Over-claim audit", "defended": defended, "accepted_limit": False,
            "verdict": "DEFENDED — discloses the >=k-collusion and liveness limits",
            "detail": f"over-claim hits: {hits or 'none'}; discloses collusion/G3: {discloses_collusion}; "
                      f"discloses liveness: {discloses_liveness}."}


def main() -> int:
    operator, witnesses, registry = _ctx()
    results = [attack_1_forge_quorum(operator, witnesses, registry),
               attack_2_replay_cosig(operator, witnesses, registry),
               attack_3_k_collusion(operator, witnesses, registry),
               attack_4_self_equivocation(operator, witnesses, registry),
               attack_5_overclaim()]
    for r in results:
        print(f"[{r['verdict']}]\n    {r['attack']}\n    {r['detail']}")
        if r.get("accepted_limit"):
            print("    ⚠ accepted limit disclosed (see verdict/detail).")
        print()
    (_EVIDENCE / "red_team_report_p1_01.json").write_text(
        json.dumps({"attacks": results}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    no_silent_break = all(r["defended"] or r["accepted_limit"] for r in results)
    print("🟢 NO SILENT BREAK — every attack is DEFENDED or a DISCLOSED accepted limit"
          if no_silent_break else "🔴 A SILENT BREAK")
    return 0 if no_silent_break else 1


if __name__ == "__main__":
    sys.exit(main())
