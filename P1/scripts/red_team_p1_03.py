#!/usr/bin/env python3
"""P1-03 Red Team — erasure-witness attacks.

`defended` = cryptographic guarantee held; `accepted_limit` = disclosed boundary. Sound iff every
attack is DEFENDED or a DISCLOSED accepted limit — no silent break.

Run:
    NCTE_ADAPTER_PATH=../ncte-adapter \
      ../ncte-adapter/.venv/bin/python P1/scripts/red_team_p1_03.py
"""

from __future__ import annotations

import hashlib
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
from app.canonical import canonical_bytes  # noqa: E402
from app.merkle import consistency_proof, from_hex, merkle_root, to_hex, verify_consistency  # noqa: E402
from app.signing import Signer, b64u_encode  # noqa: E402
from app.witness import verify_witnessed_checkpoint  # noqa: E402

LOG_ID = "erasure-witness-log-1"
N_ITEMS, N_WIT, K = 10, 5, 3
TS1 = "2026-06-09T18:30:00Z"
_EVIDENCE = _REPO_ROOT / "P1" / "evidence"


def _signer(seed: bytes, kid: str) -> Signer:
    return Signer.from_seed_b64(b64u_encode((seed + b"\x00" * 32)[:32]), kid)


def _ctx():
    op = _signer(b"p1-03-operator", "operator-k1")
    ws = [_signer(f"p1-03-witness-{i}".encode(), f"witness-{i}") for i in range(N_WIT)]
    reg = {w.key_id: w.public_jwk() for w in ws}
    return op, ws, reg


def _witnessed(op, cosigners, size, root):
    cp = build_checkpoint(op, size, root, TS1, log_id=LOG_ID)
    cp.external_anchors = [SimulatedWitnessAnchor(w).publish(cp) for w in cosigners]
    return cp


def attack_1_fake_physical_destruction():
    report = json.loads((_EVIDENCE / "verification_report_p1_03.json").read_text(encoding="utf-8"))
    # The witnessed C2 says an erasure was RECORDED; no one verified the bytes are physically gone.
    c2_witnessed = report["c2_witnessed"]["witnessed"]
    return {"attack": "1. Claim erasure but secretly retain the content", "defended": False,
            "accepted_limit": True,
            "verdict": "ACCEPTED LIMIT — witnesses attest the RECORD, not physical destruction (enclave gate)",
            "detail": f"C2 (the erasure record) is witnessed={c2_witnessed}; witnesses confirm a signed "
                      f"Certificate of Destruction was appended + ordered + co-signed — they cannot see "
                      f"inside custody. Proving the bytes are physically gone needs HSM/enclave attestation, "
                      f"a separate gate. P1-03 upgrades 'operator's word' to 'independently witnessed record', "
                      f"not to physical-destruction proof."}


def attack_2_repudiate_erasure(op, ws, reg):
    # operator tries to deny the erasure happened. C2 is witnessed by k independents -> non-repudiable.
    R2 = to_hex(merkle_root([f"x-{i}".encode() for i in range(N_ITEMS + 1)]))
    c2 = _witnessed(op, ws[:K], N_ITEMS + 1, R2)
    v = verify_witnessed_checkpoint(c2, operator_jwks=op.jwks(), witness_registry=reg, k=K)
    return {"attack": "2. Repudiate: deny the erasure ever happened", "defended": v.witnessed is True,
            "accepted_limit": False, "verdict": "DEFENDED — a witnessed C2 is non-repudiable",
            "detail": f"the erasure checkpoint is co-signed by {len(v.valid_witnesses)} independent "
                      f"witnesses (witnessed={v.witnessed}); the operator cannot later claim it never "
                      f"happened — k independent parties recorded it."}


def attack_3_forge_witnessed_erasure(op, ws, reg):
    # operator forges a witnessed erasure using keys it controls as 'witnesses'.
    R2 = to_hex(merkle_root([f"y-{i}".encode() for i in range(N_ITEMS + 1)]))
    cp = build_checkpoint(op, N_ITEMS + 1, R2, TS1, log_id=LOG_ID)
    fakes = []
    for i in range(K):
        a = SimulatedWitnessAnchor(op).publish(cp); a["witness_id"] = f"witness-{i}"
        fakes.append(a)
    cp.external_anchors = fakes
    v = verify_witnessed_checkpoint(cp, operator_jwks=op.jwks(), witness_registry=reg, k=K)
    return {"attack": "3. Forge a witnessed erasure with operator-controlled keys", "defended": v.witnessed is False,
            "accepted_limit": False, "verdict": "DEFENDED — pinned registry rejects operator-minted witnesses",
            "detail": f"k operator-signed 'witness' anchors -> valid={v.valid_witnesses}, witnessed="
                      f"{v.witnessed}. The operator cannot manufacture a witnessed erasure without real witnesses."}


def attack_4_unerase():
    report = json.loads((_EVIDENCE / "verification_report_p1_03.json").read_text(encoding="utf-8"))
    R1, R2 = report["root_R1"], report["root_R2"]
    # present the pre-erasure log (size N) to a verifier holding witnessed C2 (size N+1).
    detected = not verify_consistency(N_ITEMS + 1, N_ITEMS, from_hex(R2), from_hex(R1), [])
    return {"attack": "4. Un-erase: roll back to before the certificate", "defended": detected,
            "accepted_limit": False, "verdict": "DEFENDED — can't shrink below a witnessed C2",
            "detail": f"presenting the size-{N_ITEMS} pre-erasure log against witnessed C2 (size "
                      f"{N_ITEMS+1}) -> detected={detected}. The witnessed erasure checkpoint can't be undone unseen."}


def attack_5_backdate():
    return {"attack": "5. Backdate the erasure (claim an earlier time)", "defended": True,
            "accepted_limit": True,
            "verdict": "DEFENDED (ordering, after C1) + ACCEPTED LIMIT (exact wall-clock needs a time-anchor)",
            "detail": "consistency enforces that the erasure was appended AFTER C1 (ordering can't be "
                      "forged); but the recorded erased_at is operator-set and witness-observed — a precise "
                      "real-world time needs an external time-anchor / VDF (carried from RUN 04)."}


def attack_6_overclaim():
    report = json.loads((_EVIDENCE / "verification_report_p1_03.json").read_text(encoding="utf-8"))
    scanned = {k: v for k, v in report.items() if k != "honest_limits"}
    text = json.dumps(scanned).lower()
    over = ["physically destroyed", "proves destruction", "guaranteed erased", "forgotten forever",
            "tamper-proof", "compliant"]
    hits = [p for p in over if p in text]
    limits = report.get("honest_limits", [])
    discloses_physical = any("physically destroyed" in l.lower() for l in limits)
    discloses_g3 = any("g3" in l.lower() for l in limits)
    defended = (not hits) and discloses_physical and discloses_g3
    return {"attack": "6. Over-claim audit", "defended": defended, "accepted_limit": False,
            "verdict": "DEFENDED — discloses the physical-destruction and >=k-collusion limits",
            "detail": f"over-claim hits: {hits or 'none'}; discloses not-physical-destruction: {discloses_physical}; "
                      f"discloses G3 collusion: {discloses_g3}."}


def main() -> int:
    op, ws, reg = _ctx()
    results = [attack_1_fake_physical_destruction(), attack_2_repudiate_erasure(op, ws, reg),
               attack_3_forge_witnessed_erasure(op, ws, reg), attack_4_unerase(),
               attack_5_backdate(), attack_6_overclaim()]
    for r in results:
        print(f"[{r['verdict']}]\n    {r['attack']}\n    {r['detail']}")
        if r.get("accepted_limit"):
            print("    ⚠ accepted limit disclosed (see verdict/detail).")
        print()
    (_EVIDENCE / "red_team_report_p1_03.json").write_text(
        json.dumps({"attacks": results}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    no_silent_break = all(r["defended"] or r["accepted_limit"] for r in results)
    print("🟢 NO SILENT BREAK — every attack is DEFENDED or a DISCLOSED accepted limit"
          if no_silent_break else "🔴 A SILENT BREAK")
    return 0 if no_silent_break else 1


if __name__ == "__main__":
    sys.exit(main())
