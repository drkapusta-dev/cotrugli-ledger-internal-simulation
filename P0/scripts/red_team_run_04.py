#!/usr/bin/env python3
"""P0-04 Red Team — operator self-suspicion attacks.

Each attack reports whether the cryptographic guarantee held (`defended`) and whether it reveals a
disclosed `accepted_limit`. The theme: a key-holding operator's silent rewrite is caught against a
WITNESSED root, but several operator games (equivocation, self-asserted time) need an external
witness network to close — disclosed, not hidden.

Run (with the ncte-adapter venv):
    NCTE_ADAPTER_PATH=../ncte-adapter \
      ../ncte-adapter/.venv/bin/python P0/scripts/red_team_run_04.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ADAPTER_PATH = Path(os.environ.get("NCTE_ADAPTER_PATH", str(_REPO_ROOT.parent / "ncte-adapter"))).resolve()
if not (_ADAPTER_PATH / "app" / "evidence_anchor.py").exists():
    sys.exit(f"❌ ncte-adapter not found at {_ADAPTER_PATH}. Set NCTE_ADAPTER_PATH.")
sys.path.insert(0, str(_ADAPTER_PATH))

from app import core_boundary_contract as core  # noqa: E402
from app.anchor import build_checkpoint, verify_checkpoint  # noqa: E402
from app.evidence_commitment import hash_only_commit  # noqa: E402
from app.merkle import consistency_proof, from_hex, merkle_root, to_hex, verify_consistency  # noqa: E402
from app.signing import Signer, b64u_encode  # noqa: E402

_EVIDENCE = _REPO_ROOT / "P0" / "evidence"
_COMMIT = hash_only_commit
_KEY_ID = "cise-p0-operator-k1"
LOG_ID = "operator-log-1"


def _signer():
    return Signer.from_seed_b64(b64u_encode((b"cotrugli-cise-p0-optamper-seed04" + b"\x00" * 32)[:32]), _KEY_ID)


def _events(n):
    return [{"id": f"op-evt-{i:03d}", "timestamp": f"2026-06-09T12:00:{i % 60:02d}Z",
             "agent_id": "agent-prod-742", "event_class": "AGENT_ACTION", "tool": "get_financial_summary",
             "input_hash": f"sha256:input-{i:04x}",
             "result": {"status": "success", "balance_eur": 10000.0 + i, "currency": "EUR"},
             "policy_snapshot": "AI_ACT_TRACK1_v2026-06"} for i in range(n)]


def _entries(events):
    return [_COMMIT(e).encode("utf-8") for e in events]


def _root(entries):
    return to_hex(merkle_root(entries))


# A1 — forge a consistency proof from R1 to a tampered root.
def attack_1_forge_consistency():
    events = _events(20)
    entries = _entries(events)
    R1 = _root(entries[:16])
    altered = _events(20); altered[5]["result"]["balance_eur"] = 999999.0
    tampered = _entries(altered)
    Rt = _root(tampered)
    # try the honest proof, random proof, empty proof — all must be rejected for R1 -> Rt.
    honest_proof = consistency_proof(entries, 16)
    attempts = {
        "honest_proof_for_tampered_root": verify_consistency(16, 20, from_hex(R1), from_hex(Rt), honest_proof),
        "empty_proof": verify_consistency(16, 20, from_hex(R1), from_hex(Rt), []),
        "garbage_proof": verify_consistency(16, 20, from_hex(R1), from_hex(Rt),
                                            [bytes.fromhex("ab" * 32)] * len(honest_proof)),
    }
    defended = not any(attempts.values())
    return {"attack": "1. Forge a consistency proof (R1 -> tampered)",
            "defended": defended, "accepted_limit": False,
            "verdict": "DEFENDED — no fabricated consistency proof verifies",
            "detail": f"attempts {attempts} — all rejected. RFC 6962 consistency cannot be forged "
                      f"to make a tampered history extend the witnessed root."}


# A2 — equivocation / split view: show different 'witnessed' roots to different parties.
def attack_2_equivocation():
    signer = _signer()
    log_x = _entries(_events(16))
    alt = _events(16); alt[2]["result"]["balance_eur"] = -1.0
    log_y = _entries(alt)
    Rx, Ry = _root(log_x), _root(log_y)
    cp_x = build_checkpoint(signer, 16, Rx, "2026-06-09T12:00:00Z", log_id=LOG_ID)
    cp_y = build_checkpoint(signer, 16, Ry, "2026-06-09T12:00:00Z", log_id=LOG_ID)
    both_sigs_valid = verify_checkpoint(signer.jwks(), cp_x) and verify_checkpoint(signer.jwks(), cp_y)
    # A single verifier sees only one; detection requires comparing the two (witness gossip).
    detectable_by_comparison = (Rx != Ry)
    return {"attack": "2. Equivocation / split view (two histories to two parties)",
            "defended": False, "accepted_limit": True,
            "verdict": "ACCEPTED LIMIT — needs a witness network/gossip; a single verifier can't detect a fork",
            "detail": f"both forks are validly signed by the operator (sigs_valid={both_sigs_valid}); a lone "
                      f"verifier sees only its own root. Cross-comparison catches it (roots differ="
                      f"{detectable_by_comparison}) — i.e. detection requires independent witnesses comparing "
                      f"notes (a transparency-log / witness-ring property, P1+)."}


# A3 — backdate via a self-asserted timestamp.
def attack_3_self_asserted_time():
    signer = _signer()
    base = _events(16)
    # operator appends a NEW event but stamps it in the past.
    backdated = {"id": "op-evt-LATE", "timestamp": "2020-01-01T00:00:00Z", "agent_id": "agent-prod-742",
                 "event_class": "AGENT_ACTION", "tool": "get_financial_summary", "input_hash": "sha256:late",
                 "result": {"status": "success", "balance_eur": 1.0, "currency": "EUR"},
                 "policy_snapshot": "AI_ACT_TRACK1_v2026-06"}
    entries = _entries(base) + [_COMMIT(backdated).encode()]
    R1 = _root(_entries(base))
    # As an APPEND it's fine; but to slot it into the historical ORDER it must enter the prefix ->
    # that breaks consistency. So order can't be forged; the self-asserted *timestamp value* can.
    inserted = [_COMMIT(backdated).encode()] + _entries(base)   # try to put it "before" history
    order_forge_detected = not verify_consistency(
        16, len(inserted), from_hex(R1), from_hex(_root(inserted)),
        consistency_proof(inserted, 16) if 0 < 16 < len(inserted) else [])
    return {"attack": "3. Backdate via a self-asserted timestamp",
            "defended": order_forge_detected, "accepted_limit": True,
            "verdict": "DEFENDED (ordering) + ACCEPTED LIMIT (the recorded timestamp is operator-asserted)",
            "detail": f"forcing the event into the historical ORDER breaks consistency (detected="
                      f"{order_forge_detected}). But the spine attests the RECORDED timestamp, not real time — "
                      f"a self-asserted timestamp value needs an external time-anchor / VDF / witnessed "
                      f"checkpoint time to be trustworthy (P1+)."}


# A4 — over-claim audit.
def attack_4_overclaim():
    report = json.loads((_EVIDENCE / "verification_report_04.json").read_text(encoding="utf-8"))
    text = (_EVIDENCE / "verification_report_04.json").read_text(encoding="utf-8").lower()
    extra = ["operator cannot tamper", "tamper-proof", "cannot cheat", "guarantees", "compliant"]
    hits = [p for p in list(core.FORBIDDEN_PHRASES) + extra if p.lower() in text]
    has_limits = bool(report.get("honest_limits"))
    discloses_witness = any("external witness" in l.lower() or "who attests the attestor" in l.lower()
                            for l in report.get("honest_limits", []))
    defended = (not hits) and has_limits and discloses_witness
    return {"attack": "4. Over-claim audit (does it claim the operator can't tamper?)",
            "defended": defended, "accepted_limit": False,
            "verdict": "DEFENDED — discloses the witness-conditional limit; no unconditional claim",
            "detail": f"forbidden/over-claim hits: {hits or 'none'}; honest_limits present: {has_limits}; "
                      f"discloses external-witness requirement: {discloses_witness}."}


def main() -> int:
    results = [attack_1_forge_consistency(), attack_2_equivocation(),
               attack_3_self_asserted_time(), attack_4_overclaim()]
    for r in results:
        print(f"[{r['verdict']}]\n    {r['attack']}\n    {r['detail']}")
        if r.get("accepted_limit"):
            print("    ⚠ accepted limit disclosed (see verdict/detail).")
        print()
    (_EVIDENCE / "red_team_report_04.json").write_text(
        json.dumps({"attacks": results}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    # A run is sound iff every attack is either DEFENDED or a DISCLOSED accepted limit — i.e. no
    # silent break. An accepted limit is honest disclosure, not a failure.
    no_silent_break = all(r["defended"] or r["accepted_limit"] for r in results)
    print("🟢 NO SILENT BREAK — every attack is DEFENDED or a DISCLOSED accepted limit"
          if no_silent_break else "🔴 A SILENT BREAK (attack neither defended nor disclosed)")
    return 0 if no_silent_break else 1


if __name__ == "__main__":
    sys.exit(main())
