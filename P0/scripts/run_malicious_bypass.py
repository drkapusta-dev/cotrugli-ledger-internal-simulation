#!/usr/bin/env python3
"""P0-03 Malicious Bypass — REAL Evidence Codec v0.2 + a simulated controlled boundary.

COTRUGLI CISE · P0 Proof Spine Stress Test · Scenario 03.

A simulated Vanguard Gateway (the controlled execution boundary) processes ~28 agent requests:
most are in-mandate reads (ALLOW); several are out-of-mandate writes (DENY, recorded as evidence).
Every processed request — allow and deny — gets a monotonic gateway_seq and is anchored under ONE
signed checkpoint. Separately, a few BYPASS actions never touch the gateway (vendor-side ground
truth) — they drive the reconciliation check.

Honest headline: "no receipt -> no authorized execution" is a CONTROL convention the boundary
enforces, NOT a cryptographic proof that nothing happened outside it. A true bypass is invisible to
the proof spine alone; reconciliation against an independent vendor count surfaces only the NUMBER
of unaccounted actions. We disclose this; we do not pretend to solve it.

Run (with the ncte-adapter venv):
    NCTE_ADAPTER_PATH=../ncte-adapter \
      ../ncte-adapter/.venv/bin/python P0/scripts/run_malicious_bypass.py
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ADAPTER_PATH = Path(os.environ.get("NCTE_ADAPTER_PATH", str(_REPO_ROOT.parent / "ncte-adapter"))).resolve()
if not (_ADAPTER_PATH / "app" / "evidence_anchor.py").exists():
    sys.exit(f"❌ ncte-adapter not found at {_ADAPTER_PATH}. Set NCTE_ADAPTER_PATH.")
sys.path.insert(0, str(_ADAPTER_PATH))

from app.evidence_anchor import (  # noqa: E402
    AnchoredEvidenceBatch,
    anchor_evidence_batch,
    chain_ok,
    verify_anchored_item,
)
from app.evidence_codec import decode  # noqa: E402
from app.evidence_commitment import hash_only_commit  # noqa: E402
from app.signing import Signer, b64u_encode  # noqa: E402

RUN_ID = "P0-AIAct-Track1-2026-06-09"
SCENARIO_ID = "P0-03-MaliciousBypass"
CHECKPOINT_TS = "2026-06-09T11:05:00Z"
POLICY_SNAPSHOT = "AI_ACT_TRACK1_v2026-06"
_DEMO_SEED = b"cotrugli-cise-p0-bypass-seed-003"
_KEY_ID = "cise-p0-bypass-gw-k1"            # the GATEWAY key (the authorization anchor)
_COMMIT = hash_only_commit
_EVIDENCE_DIR = _REPO_ROOT / "P0" / "evidence"

PRINCIPAL = "tenant:alpha"
MANDATE = "read-only-financial"             # only read capabilities authorized
_READ_TOOLS = ["get_financial_summary", "check_account_balance", "summarize_document", "classify_transaction"]
_WRITE_TOOLS = ["post_ledger_entry", "transfer_funds", "delete_record"]
_CAP = {**{t: "read" for t in _READ_TOOLS}, **{t: "write" for t in _WRITE_TOOLS}}
_MANDATE_CAPS = {"read-only-financial": {"read"}}


def _ts(seq: int) -> str:
    mm, ss = divmod(seq, 60)
    return f"2026-06-09T11:{mm:02d}:{ss:02d}Z"


def gateway_process(seq: int, tool: str) -> dict:
    """The simulated controlled boundary: assign seq, check mandate, decide allow/deny, emit event."""
    cap = _CAP[tool]
    allowed = cap in _MANDATE_CAPS[MANDATE]
    decision = "allow" if allowed else "deny"
    return {
        "id": f"gw-{seq:03d}",
        "gateway_seq": seq,
        "timestamp": _ts(seq),
        "agent_id": "agent-prod-742",
        "principal": PRINCIPAL,
        "mandate": MANDATE,
        "tool": tool,
        "capability_required": cap,
        "input_hash": f"sha256:input-{seq:04x}",          # hash-only; no source content
        "decision": decision,
        "deny_reason": None if allowed else f"capability '{cap}' not in mandate '{MANDATE}'",
        "result": ({"status": "success", "balance_eur": 12000.0 + seq, "currency": "EUR"}
                   if allowed else None),
        "event_class": "GATEWAY_DECISION",
        "policy_snapshot": POLICY_SNAPSHOT,
    }


def request_plan(n: int = 28) -> list[str]:
    """Deterministic request stream: mostly reads, every 6th is an out-of-mandate write (-> deny)."""
    plan = []
    for i in range(n):
        if i % 6 == 5:
            plan.append(_WRITE_TOOLS[(i // 6) % len(_WRITE_TOOLS)])   # malicious / over-mandate
        else:
            plan.append(_READ_TOOLS[i % len(_READ_TOOLS)])
    return plan


# BYPASS ground truth: actions the agent ran straight against the vendor, never via the gateway.
# These are NOT in the proof package — they only exist to drive reconciliation.
_BYPASS_ACTIONS = [
    {"tool": "transfer_funds", "note": "direct vendor call, no gateway receipt"},
    {"tool": "delete_record", "note": "direct vendor call, no gateway receipt"},
    {"tool": "post_ledger_entry", "note": "direct vendor call, no gateway receipt"},
]


def _signer() -> Signer:
    seed = (_DEMO_SEED + b"\x00" * 32)[:32]
    return Signer.from_seed_b64(b64u_encode(seed), _KEY_ID)


def _write_json(name: str, payload) -> Path:
    path = _EVIDENCE_DIR / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def run() -> dict:
    print(f"🚀 {SCENARIO_ID} — Malicious Bypass\n")

    # 1) Gateway processes the request stream (allow + deny), assigning a monotonic seq.
    events = [gateway_process(seq, tool) for seq, tool in enumerate(request_plan(28))]
    hist = Counter(e["decision"] for e in events)
    print(f"✅ gateway processed {len(events)} requests — decisions {dict(hist)} "
          f"({hist['deny']} out-of-mandate writes recorded as DENY evidence)")

    # 2) Anchor every gateway event (allow + deny) under ONE signed checkpoint.
    signer = _signer()
    anchored, blobs = anchor_evidence_batch(events, signer, timestamp=CHECKPOINT_TS, commit=_COMMIT)
    batch = anchored.batch
    print(f"✅ anchored {batch.tree_size} gateway events under ONE root: {batch.root}")

    _write_json("malicious_bypass_batch_input.json", events)
    proof_package = {
        "run_id": RUN_ID, "scenario_id": SCENARIO_ID,
        "batch": json.loads(batch.model_dump_json()),
        "checkpoint": json.loads(anchored.checkpoint.model_dump_json()),
        "jwks": anchored.jwks, "blobs": blobs,
    }
    pkg_path = _write_json("proof_package_03.json", proof_package)
    print(f"💾 saved public proof package -> {pkg_path.relative_to(_REPO_ROOT)}")

    # Reload ONLY the public package; verify every event offline.
    reloaded = json.loads(pkg_path.read_text(encoding="utf-8"))
    re_anchored = AnchoredEvidenceBatch(batch=reloaded["batch"], checkpoint=reloaded["checkpoint"],
                                        jwks=reloaded["jwks"])
    re_blobs = reloaded["blobs"]
    decoded = [decode(b) for b in re_blobs]

    per_item_ok = [chain_ok(verify_anchored_item(re_anchored, i, re_blobs[i], commit=_COMMIT))
                   for i in range(re_anchored.batch.tree_size)]
    all_verify = all(per_item_ok)
    print(f"\n✅ offline verification: {sum(per_item_ok)}/{len(per_item_ok)} events full-chain OK")

    # 2) deny evidence present & first-class.
    denies = [d for d in decoded if d["decision"] == "deny"]
    deny_evidence_ok = len(denies) > 0 and all(d["deny_reason"] for d in denies)
    print(f"✅ control point: {len(denies)} out-of-mandate actions recorded as DENY evidence "
          f"(not silently dropped): {deny_evidence_ok}")

    # 3) sequence contiguity (within-boundary non-omission): seqs are 0..N-1 with no gap.
    seqs = sorted(d["gateway_seq"] for d in decoded)
    contiguous = seqs == list(range(len(decoded)))
    print(f"✅ gateway sequence contiguous 0..{len(decoded)-1} (a removed seq is detectable): {contiguous}")

    # 7) reconciliation: a true bypass surfaces as gateway_count vs vendor_observed_count gap.
    gateway_count = len(decoded)
    vendor_observed_count = gateway_count + len(_BYPASS_ACTIONS)   # independent signal (sim)
    discrepancy = vendor_observed_count - gateway_count
    bypass_surfaced = discrepancy == len(_BYPASS_ACTIONS) and discrepancy > 0
    print(f"⚠ reconciliation: gateway saw {gateway_count}, vendor observed {vendor_observed_count} "
          f"-> {discrepancy} unaccounted (possible bypass) SURFACED={bypass_surfaced} "
          f"[spine alone cannot see bypassed actions — accepted limit]")

    report = {
        "run_id": RUN_ID, "scenario_id": SCENARIO_ID,
        "num_events": len(events), "decision_histogram": dict(hist),
        "merkle_root": batch.root, "tree_size": batch.tree_size, "checkpoint_kid": signer.key_id,
        "all_events_full_chain_ok": all_verify,
        "deny_evidence_first_class": deny_evidence_ok, "deny_count": len(denies),
        "sequence_contiguous": contiguous,
        "reconciliation": {"gateway_count": gateway_count,
                           "vendor_observed_count": vendor_observed_count,
                           "unaccounted": discrepancy, "bypass_surfaced": bypass_surfaced},
        "honest_limits": [
            "SIMULATION on SYNTHETIC data — not a compliance/conformity claim.",
            "'No receipt -> no execution' is a CONTROL convention the boundary enforces, NOT a "
            "cryptographic proof that nothing happened outside it.",
            "A true bypass (vendor call with no gateway receipt) is INVISIBLE to the proof spine "
            "alone; reconciliation against an independent vendor count surfaces only the NUMBER of "
            "unaccounted actions, not their content (from-ingestion-forward / garbage-in limit).",
            "The spine attests a gateway DECISION was recorded; it does NOT attest the decision was "
            "CORRECT — decision correctness is policy/review, an overlay concern, not core.",
            "Issuer/gateway key must be pinned out-of-band; a package whose own jwks is trusted can "
            "be self-consistently forged.",
            "Assurance != certification · Anchored != settled · detect-within-boundary != prevent-all-bypass.",
        ],
    }
    _write_json("verification_report_03.json", report)

    pre_reg = {
        "all_events_anchored_and_verified": all_verify and batch.tree_size == len(events),
        "deny_recorded_as_evidence": deny_evidence_ok,
        "sequence_contiguous": contiguous,
        "bypass_surfaced_by_reconciliation": bypass_surfaced,
        "full_offline_verification": all_verify,
    }
    print("\n📋 pre-registered PASS/FAIL:")
    for k, v in pre_reg.items():
        print(f"   {'PASS' if v else 'FAIL'}  {k}")
    return {"report": report, "pre_registered": pre_reg, "proof_package_path": str(pkg_path)}


if __name__ == "__main__":
    result = run()
    ok = all(result["pre_registered"].values())
    print(f"\n{'🟢 ALL PRE-REGISTERED CRITERIA PASS' if ok else '🔴 SOME CRITERIA FAILED'}")
    sys.exit(0 if ok else 1)
