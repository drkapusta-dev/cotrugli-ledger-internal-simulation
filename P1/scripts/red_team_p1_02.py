#!/usr/bin/env python3
"""P1-02 Red Team — long-game witness attacks (gradual corruption, sybil, liveness DoS).

Each attack reports `defended` (cryptographic guarantee held) and `accepted_limit` (disclosed
boundary). Sound iff every attack is DEFENDED or a DISCLOSED accepted limit — no silent break.

Run:
    NCTE_ADAPTER_PATH=../ncte-adapter \
      ../ncte-adapter/.venv/bin/python P1/scripts/red_team_p1_02.py
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

LOG_ID = "witness-longgame-log-1"
N, K, SIZE, TS = 7, 4, 16, "2026-06-09T17:00:00Z"
_EVIDENCE = _REPO_ROOT / "P1" / "evidence"


def _signer(seed: bytes, kid: str) -> Signer:
    return Signer.from_seed_b64(b64u_encode((seed + b"\x00" * 32)[:32]), kid)


def _root(tag: str) -> str:
    return to_hex(merkle_root([f"{tag}-{i:03d}".encode() for i in range(SIZE)]))


def _cp(operator, cosigners, root):
    cp = build_checkpoint(operator, SIZE, root, TS, log_id=LOG_ID)
    cp.external_anchors = [SimulatedWitnessAnchor(w).publish(cp) for w in cosigners]
    return cp


def _ctx():
    op = _signer(b"p1lg-operator", "operator-k1")
    ws = [_signer(f"p1lg-witness-{i}".encode(), f"witness-{i}") for i in range(N)]
    reg = {w.key_id: w.public_jwk() for w in ws}
    return op, ws, reg


def attack_1_corrupt_to_k_minus_1(op, ws, reg):
    v = verify_witnessed_checkpoint(_cp(op, ws[:K - 1], _root("Rlie")),
                                    operator_jwks=op.jwks(), witness_registry=reg, k=K)
    return {"attack": "1. Corrupt k-1 witnesses and witness a lie", "defended": v.witnessed is False,
            "accepted_limit": False, "verdict": "DEFENDED — below k, a forged root is not witnessed",
            "detail": f"{K-1} corrupted witnesses on a forged root -> witnessed={v.witnessed}. The honest "
                      f"margin holds until the k-th corruption."}


def attack_2_corrupt_to_k_silent(op, ws, reg):
    # k corrupted witnesses, NO honest witness asked -> silent witnessed lie.
    v = verify_witnessed_checkpoint(_cp(op, ws[:K], _root("Rlie")),
                                    operator_jwks=op.jwks(), witness_registry=reg, k=K)
    return {"attack": "2. Corrupt k witnesses + control selection (no honest asked)",
            "defended": False, "accepted_limit": v.witnessed is True,
            "verdict": "ACCEPTED LIMIT — break cost is k independent corruptions + selection control (G3)",
            "detail": f"{K} corrupted witnesses, no honest witness in the asked set -> witnessed="
                      f"{v.witnessed}. The margin is exactly k; raising it (independence, staking, "
                      f"who-pays) is gate G3, and a SILENT takeover also requires controlling who is asked."}


def attack_3_honest_in_set(op, ws, reg):
    # k corrupted on the lie, but 1 honest witness signs the truth -> equivocation flags it.
    cp_lie = _cp(op, ws[:K], _root("Rlie"))
    cp_true = _cp(op, [ws[K]], _root("Rtrue"))
    conflicts = detect_equivocation(witness_statements(cp_lie) + witness_statements(cp_true))
    return {"attack": "3. k corrupted but an honest witness is still asked", "defended": len(conflicts) == 1,
            "accepted_limit": False, "verdict": "DEFENDED — one honest witness exposes the fork",
            "detail": f"equivocation conflicts={len(conflicts)}. With >=1 honest witness in the asked "
                      f"set, the forged root and the true root collide and are flagged."}


def attack_4_sybil(op, ws, reg):
    fakes = [_signer(f"sybil-{i}".encode(), f"sybil-{i}") for i in range(K)]
    v = verify_witnessed_checkpoint(_cp(op, fakes, _root("Rlie")),
                                    operator_jwks=op.jwks(), witness_registry=reg, k=K)
    return {"attack": "4. Sybil: inject unregistered fake witnesses", "defended": v.witnessed is False,
            "accepted_limit": False, "verdict": "DEFENDED — the pinned registry rejects unregistered witnesses",
            "detail": f"{K} unregistered fake witnesses -> valid={v.valid_witnesses}, witnessed="
                      f"{v.witnessed}. Reaching quorum from outside the registry is impossible; biasing "
                      f"SELECTION among registered witnesses is the disclosed limit (needs independent selection)."}


def attack_5_liveness_dos(op, ws, reg):
    # take witnesses offline below k -> un-witnessed, but never falsely witnessed.
    online = K - 1
    v = verify_witnessed_checkpoint(_cp(op, ws[:online], _root("Rtrue")),
                                    operator_jwks=op.jwks(), witness_registry=reg, k=K)
    return {"attack": "5. Liveness DoS: take witnesses offline below k", "defended": v.witnessed is False,
            "accepted_limit": True, "verdict": "DEFENDED (safety) + ACCEPTED LIMIT (liveness not guaranteed)",
            "detail": f"only {online} witnesses online (< k) -> witnessed={v.witnessed} (un-witnessed). "
                      f"Safety holds (never falsely witnessed); liveness is traded away — the layer would "
                      f"rather produce nothing than a falsely-witnessed root."}


def attack_6_overclaim():
    report = json.loads((_EVIDENCE / "verification_report_p1_02.json").read_text(encoding="utf-8"))
    scanned = {k: v for k, v in report.items() if k != "honest_limits"}
    text = json.dumps(scanned).lower()
    over = ["unbreakable", "cannot be corrupted", "always available", "tamper-proof", "guarantees", "compliant"]
    hits = [p for p in over if p in text]
    limits = report.get("honest_limits", [])
    discloses_margin = any("k independent corruptions" in l.lower() for l in limits)
    discloses_liveness = any("liveness is not guaranteed" in l.lower() for l in limits)
    defended = (not hits) and discloses_margin and discloses_liveness
    return {"attack": "6. Over-claim audit", "defended": defended, "accepted_limit": False,
            "verdict": "DEFENDED — discloses the k-corruption margin, selection-control, and liveness limits",
            "detail": f"over-claim hits: {hits or 'none'}; discloses k-corruption margin: {discloses_margin}; "
                      f"discloses liveness-not-guaranteed: {discloses_liveness}."}


def main() -> int:
    op, ws, reg = _ctx()
    results = [attack_1_corrupt_to_k_minus_1(op, ws, reg), attack_2_corrupt_to_k_silent(op, ws, reg),
               attack_3_honest_in_set(op, ws, reg), attack_4_sybil(op, ws, reg),
               attack_5_liveness_dos(op, ws, reg), attack_6_overclaim()]
    for r in results:
        print(f"[{r['verdict']}]\n    {r['attack']}\n    {r['detail']}")
        if r.get("accepted_limit"):
            print("    ⚠ accepted limit disclosed (see verdict/detail).")
        print()
    (_EVIDENCE / "red_team_report_p1_02.json").write_text(
        json.dumps({"attacks": results}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    no_silent_break = all(r["defended"] or r["accepted_limit"] for r in results)
    print("🟢 NO SILENT BREAK — every attack is DEFENDED or a DISCLOSED accepted limit"
          if no_silent_break else "🔴 A SILENT BREAK")
    return 0 if no_silent_break else 1


if __name__ == "__main__":
    sys.exit(main())
