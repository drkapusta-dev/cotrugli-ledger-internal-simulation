#!/usr/bin/env python3
"""P0-04 Operator Tamper — "who attests the attestor?" via RFC 6962 consistency proofs.

COTRUGLI CISE · P0 Proof Spine Stress Test · Scenario 04.

The operator HOLDS THE SIGNING KEY and tries to silently rewrite history. The defense is not "the
operator can't sign" (they can sign anything) — it is that an independent witness pinned an earlier
root R1, and the operator cannot produce a valid append-only consistency proof from R1 to a tampered
history. Honest limit: without a witnessed R1, a key-holding operator can produce a self-consistent
rewrite that a fresh verifier cannot detect ("who attests the attestor?", I1).

Uses the REAL RFC 6962 merkle + checkpoint signing from the ncte-adapter spine.

Run (with the ncte-adapter venv):
    NCTE_ADAPTER_PATH=../ncte-adapter \
      ../ncte-adapter/.venv/bin/python P0/scripts/run_operator_tamper.py
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

from app.anchor import build_checkpoint, verify_checkpoint  # noqa: E402
from app.evidence_commitment import hash_only_commit  # noqa: E402
from app.merkle import (  # noqa: E402
    consistency_proof,
    from_hex,
    merkle_root,
    to_hex,
    verify_consistency,
)
from app.signing import Signer, b64u_encode  # noqa: E402

RUN_ID = "P0-AIAct-Track1-2026-06-09"
SCENARIO_ID = "P0-04-OperatorTamper"
N_TOTAL = 20
N_WITNESSED = 16                     # C1 is published + externally witnessed over the first 16
LOG_ID = "operator-log-1"
TS_C1 = "2026-06-09T12:00:00Z"
TS_C2 = "2026-06-09T12:05:00Z"
_DEMO_SEED = b"cotrugli-cise-p0-optamper-seed04"
_KEY_ID = "cise-p0-operator-k1"
_COMMIT = hash_only_commit
_EVIDENCE_DIR = _REPO_ROOT / "P0" / "evidence"


def _events(n: int = N_TOTAL) -> list[dict]:
    out = []
    for i in range(n):
        out.append({
            "id": f"op-evt-{i:03d}", "timestamp": f"2026-06-09T12:00:{i % 60:02d}Z",
            "agent_id": "agent-prod-742", "event_class": "AGENT_ACTION",
            "tool": "get_financial_summary", "input_hash": f"sha256:input-{i:04x}",
            "result": {"status": "success", "balance_eur": 10000.0 + i, "currency": "EUR"},
            "policy_snapshot": "AI_ACT_TRACK1_v2026-06",
        })
    return out


def _entries(events: list[dict]) -> list[bytes]:
    """Leaf entry per event = its commitment bytes (same convention as the anchor log / codec)."""
    return [_COMMIT(e).encode("utf-8") for e in events]


def _root(entries: list[bytes]) -> str:
    return to_hex(merkle_root(entries))


def _consistency_holds(entries_now: list[bytes], witnessed_size: int, witnessed_root: str) -> bool:
    """A verifier holding (witnessed_size, witnessed_root) asks the operator's CURRENT log to prove
    it is an append-only extension. True only if the current log really extends the witnessed prefix."""
    n = len(entries_now)
    if witnessed_size > n:
        return False                  # truncated below the witnessed size -> cannot extend
    if witnessed_size == n:
        return _root(entries_now) == witnessed_root
    try:
        proof = consistency_proof(entries_now, witnessed_size)
    except ValueError:
        return False
    return verify_consistency(
        witnessed_size, n, from_hex(witnessed_root), from_hex(_root(entries_now)),
        [b for b in proof],
    )


def _signer() -> Signer:
    return Signer.from_seed_b64(b64u_encode((_DEMO_SEED + b"\x00" * 32)[:32]), _KEY_ID)


def _write_json(name: str, payload) -> Path:
    path = _EVIDENCE_DIR / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def run() -> dict:
    print(f"🚀 {SCENARIO_ID} — Operator Tamper (who attests the attestor?)\n")
    signer = _signer()
    events = _events()
    entries = _entries(events)

    # Phase 1 — publish + WITNESS C1 over the first 16 entries.
    witnessed_entries = entries[:N_WITNESSED]
    R1 = _root(witnessed_entries)
    C1 = build_checkpoint(signer, N_WITNESSED, R1, TS_C1, log_id=LOG_ID)
    print(f"✅ C1 published & externally witnessed: size={N_WITNESSED} root={R1[:28]}…")

    # Phase 2 — honest append to 20; prove R1 -> R2 consistency.
    R2 = _root(entries)
    honest_consistency = _consistency_holds(entries, N_WITNESSED, R1)
    print(f"✅ honest append {N_WITNESSED}->{N_TOTAL}: consistency R1->R2 verifies = {honest_consistency}")

    # Phase 3 — operator tamper attempts, each checked against the WITNESSED R1.
    tampers = {}

    # drop a witnessed historical entry (then re-pad to keep size, to look unchanged).
    drop = entries[:5] + entries[6:] + [_COMMIT({"id": "filler"}).encode()]
    tampers["drop_historical_entry"] = not _consistency_holds(drop, N_WITNESSED, R1)

    # alter a witnessed historical value.
    altered_events = _events(); altered_events[5]["result"]["balance_eur"] = 999999.0
    alter = _entries(altered_events)
    tampers["backdate_alter_value"] = not _consistency_holds(alter, N_WITNESSED, R1)

    # reorder two witnessed historical entries.
    reorder = entries[:]; reorder[3], reorder[5] = reorder[5], reorder[3]
    tampers["reorder_history"] = not _consistency_holds(reorder, N_WITNESSED, R1)

    # truncate below the witnessed size (hide recent activity).
    truncate = entries[:12]
    tampers["truncate_below_witnessed"] = not _consistency_holds(truncate, N_WITNESSED, R1)

    # operator forges a FRESH checkpoint over a rewritten root, signed with their OWN key.
    forged_root = _root(alter)
    forged_cp = build_checkpoint(signer, len(alter), forged_root, TS_C2, log_id=LOG_ID)
    forged_sig_valid = verify_checkpoint(signer.jwks(), forged_cp)         # operator holds the key!
    forged_consistent = _consistency_holds(alter, N_WITNESSED, R1)         # but inconsistent w/ R1
    tampers["forged_checkpoint_detected"] = forged_sig_valid and (not forged_consistent)
    print(f"✅ operator-forged checkpoint: signature_valid={forged_sig_valid} (own key) but "
          f"consistent_with_witnessed_R1={forged_consistent} -> detected={tampers['forged_checkpoint_detected']}")

    for name, detected in tampers.items():
        print(f"   {'PASS' if detected else 'FAIL'}  tamper detected: {name}")

    # Phase 4 — the ACCEPTED LIMIT: a NEVER-witnessed rewrite is internally valid.
    never_witnessed_root = _root(alter)
    nw_cp = build_checkpoint(signer, len(alter), never_witnessed_root, TS_C1, log_id=LOG_ID)
    nw_internally_valid = verify_checkpoint(signer.jwks(), nw_cp)  # fresh verifier, no R1 -> looks fine
    print(f"\n⚠ accepted limit: with NO externally-witnessed R1, the operator's rewritten history is "
          f"internally valid (checkpoint signature ok = {nw_internally_valid}); a fresh verifier "
          f"cannot detect it. -> external witness is load-bearing (I1, P1+).")

    report = {
        "run_id": RUN_ID, "scenario_id": SCENARIO_ID,
        "witnessed_size": N_WITNESSED, "witnessed_root": R1, "honest_root": R2,
        "honest_append_consistency": honest_consistency,
        "tamper_detection": tampers,
        "accepted_limit_unwitnessed_rewrite_internally_valid": nw_internally_valid,
        "honest_limits": [
            "SIMULATION on SYNTHETIC data — not a compliance/conformity claim.",
            "The operator HOLDS THE KEY: the defense is detectability against an externally-witnessed "
            "prior root (RFC 6962 consistency), NOT preventing the operator from signing.",
            "Without an external witness, a lone key-holding operator can produce a self-consistent "
            "rewritten history a fresh verifier cannot detect ('who attests the attestor?', I1).",
            "Closing this needs an external witness / independent anchor / transparency log (P1+).",
            "Assurance != certification · Anchored != settled · detectable-when-witnessed != operator-honest-on-its-own.",
        ],
    }
    _write_json("verification_report_04.json", report)

    pre_reg = {
        "honest_append_provable": honest_consistency,
        "drop_detected": tampers["drop_historical_entry"],
        "alter_detected": tampers["backdate_alter_value"],
        "reorder_detected": tampers["reorder_history"],
        "truncate_detected": tampers["truncate_below_witnessed"],
        "forged_checkpoint_detected": tampers["forged_checkpoint_detected"],
    }
    print("\n📋 pre-registered PASS/FAIL:")
    for k, v in pre_reg.items():
        print(f"   {'PASS' if v else 'FAIL'}  {k}")
    return {"report": report, "pre_registered": pre_reg}


if __name__ == "__main__":
    result = run()
    ok = all(result["pre_registered"].values())
    print(f"\n{'🟢 ALL PRE-REGISTERED CRITERIA PASS' if ok else '🔴 SOME CRITERIA FAILED'}")
    sys.exit(0 if ok else 1)
