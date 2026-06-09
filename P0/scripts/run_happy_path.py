#!/usr/bin/env python3
"""P0-01 Happy Path Batch — REAL Evidence Codec v0.2 integration.

COTRUGLI CISE · P0 Proof Spine Stress Test · Scenario 01.

Exercises the ACTUAL built artifact (not a copy): the Evidence Codec v0.2 +
anchor proof spine from the ncte-adapter repo, end to end:

  30 synthetic agent tool-calls (deterministic, synthetic)
    -> Evidence Codec v0.2 lossless blobs (commitment over canonical ORIGINAL)
    -> ONE Merkle batch root  (RFC 6962)
    -> ONE signed checkpoint  (Ed25519 — one signature anchors all 30)
    -> per-item inclusion proofs
    -> full OFFLINE verification using ONLY the public proof package
    -> basic tamper-resistance probe (flip one stored blob)

The commitment binds to the CORE contract NCTE_AI_ACT_EVIDENCE_BOUNDARY_v0_1 via
`evidence_commitment.hash_only_commit` (= ncte.commitment.hash_only.v0_1).

Honest framing: this is a SIMULATION on SYNTHETIC data. It demonstrates that
evidence is anchored, intact, and offline-verifiable. Assurance != certification;
anchored != settled; verified != content-authenticated.

Run (with the ncte-adapter venv, which has the deps):
    NCTE_ADAPTER_PATH=../ncte-adapter \
      ../ncte-adapter/.venv/bin/python P0/scripts/run_happy_path.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# --------------------------------------------------------------------------- #
# Locate the ncte-adapter checkout (the real codec lives there) and import it.
# Tests the BUILT artifact, not a vendored copy. Override with NCTE_ADAPTER_PATH.
# --------------------------------------------------------------------------- #
_REPO_ROOT = Path(__file__).resolve().parents[2]          # cotrugli-ledger-internal-simulation/
_DEFAULT_ADAPTER = _REPO_ROOT.parent / "ncte-adapter"     # sibling checkout
_ADAPTER_PATH = Path(os.environ.get("NCTE_ADAPTER_PATH", str(_DEFAULT_ADAPTER))).resolve()

if not (_ADAPTER_PATH / "app" / "evidence_anchor.py").exists():
    sys.exit(
        f"❌ ncte-adapter not found at {_ADAPTER_PATH}.\n"
        f"   Set NCTE_ADAPTER_PATH to your ncte-adapter checkout."
    )
sys.path.insert(0, str(_ADAPTER_PATH))

from app.evidence_anchor import (  # noqa: E402
    AnchoredEvidenceBatch,
    anchor_evidence_batch,
    chain_ok,
    verify_anchored_item,
)
from app.evidence_commitment import hash_only_commit  # noqa: E402  (CORE-bound commit fn)
from app.signing import Signer, b64u_encode  # noqa: E402

# --------------------------------------------------------------------------- #
# Deterministic run parameters (reproducible evidence: NO wall-clock).
# --------------------------------------------------------------------------- #
RUN_ID = "P0-AIAct-Track1-2026-06-09"
SCENARIO_ID = "P0-01-HappyPath"
NUM_ITEMS = 30
CHECKPOINT_TS = "2026-06-09T09:05:00Z"
POLICY_SNAPSHOT = "AI_ACT_TRACK1_v2026-06"
# Fixed 32-byte DEMO seed -> byte-stable Ed25519 checkpoint signature (synthetic, non-production).
_DEMO_SEED = b"cotrugli-cise-p0-happy-seed-0001"
_KEY_ID = "cise-p0-happy-k1"

_EVIDENCE_DIR = _REPO_ROOT / "P0" / "evidence"

# A small deterministic rotation of read-only financial agent tool-calls.
_TOOLS = [
    ("get_financial_summary", "read-only-financial"),
    ("summarize_document", "read-only-document"),
    ("check_account_balance", "read-only-financial"),
    ("classify_transaction", "read-only-analytics"),
]


def _ts_for(i: int) -> str:
    """Deterministic per-item timestamp: 09:00:00 + i seconds (no wall-clock)."""
    mm, ss = divmod(i, 60)
    return f"2026-06-09T09:{mm:02d}:{ss:02d}Z"


def generate_evidence_items(num_items: int = NUM_ITEMS) -> list[dict]:
    """Deterministic synthetic agent tool-call evidence (the Enterprise Agent plane)."""
    items: list[dict] = []
    for i in range(num_items):
        tool, mandate = _TOOLS[i % len(_TOOLS)]
        items.append({
            "id": f"tool-call-{i:03d}",
            "timestamp": _ts_for(i),
            "agent_id": "agent-prod-742",
            "event_class": "AGENT_ACTION",
            "tool": tool,
            "input_hash": f"sha256:input-{i:04x}",   # hash-only; no source content
            "result": {
                "status": "success",
                "balance_eur": 12450.75 + i,
                "currency": "EUR",
                "risk_level": "low",
            },
            "mandate": mandate,
            "policy_snapshot": POLICY_SNAPSHOT,
        })
    return items


def _signer() -> Signer:
    seed = (_DEMO_SEED + b"\x00" * 32)[:32]
    return Signer.from_seed_b64(b64u_encode(seed), _KEY_ID)


def _write_json(name: str, payload) -> Path:
    path = _EVIDENCE_DIR / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def run() -> dict:
    print(f"🚀 {SCENARIO_ID} — Happy Path Batch ({NUM_ITEMS} items)\n")

    # 1) Enterprise Agent generates synthetic tool-calls.
    items = generate_evidence_items(NUM_ITEMS)
    print(f"✅ generated {len(items)} synthetic agent tool-calls (deterministic)")

    # 2-5) Codec v0.2: lossless blobs -> Merkle batch -> ONE signed checkpoint.
    signer = _signer()
    anchored, blobs = anchor_evidence_batch(
        items, signer, timestamp=CHECKPOINT_TS, commit=hash_only_commit
    )
    batch = anchored.batch
    print(f"✅ encoded {batch.tree_size} lossless blobs (CORE hash_only.v0_1 commitment)")
    print(f"✅ ONE Merkle root: {batch.root}")
    print(f"✅ ONE signed checkpoint (Ed25519, kid={signer.key_id}) anchors all {batch.tree_size} items")

    total_compressed = sum(it.compressed_size for it in batch.items)
    print(f"   off-ledger compressed store: {total_compressed} bytes across {batch.tree_size} blobs")

    # Persist the artifacts.
    _write_json("happy_path_batch_input.json", items)
    proof_package = {
        "run_id": RUN_ID,
        "scenario_id": SCENARIO_ID,
        "batch": json.loads(batch.model_dump_json()),
        "checkpoint": json.loads(anchored.checkpoint.model_dump_json()),
        "jwks": anchored.jwks,
        "blobs": blobs,                 # off-ledger compressed evidence, hex, aligned by index
    }
    pkg_path = _write_json("proof_package.json", proof_package)
    print(f"💾 saved public proof package -> {pkg_path.relative_to(_REPO_ROOT)}")

    # 6) INDEPENDENT offline verification — reload ONLY the public proof package
    #    (no access to generator internals), verify every item's full chain.
    reloaded = json.loads(pkg_path.read_text(encoding="utf-8"))
    re_anchored = AnchoredEvidenceBatch(
        batch=reloaded["batch"], checkpoint=reloaded["checkpoint"], jwks=reloaded["jwks"]
    )
    re_blobs = reloaded["blobs"]

    per_item = []
    all_pass = True
    for i in range(re_anchored.batch.tree_size):
        checks = verify_anchored_item(re_anchored, i, re_blobs[i], commit=hash_only_commit)
        ok = chain_ok(checks)
        all_pass = all_pass and ok
        per_item.append({"index": i, "commitment": re_anchored.batch.items[i].commitment,
                         "checks": checks, "chain_ok": ok})
    print(f"\n✅ offline verification (public package only): "
          f"{sum(p['chain_ok'] for p in per_item)}/{len(per_item)} items full-chain OK")

    # 7) Basic tamper-resistance probe (pre-registered axis for scenario 01): flip one stored
    #    blob and confirm ONLY that item's blob_intact fails — others + checkpoint untouched.
    tamper_idx = 7
    tampered_blob = ("00" if re_blobs[tamper_idx][:2] != "00" else "ff") + re_blobs[tamper_idx][2:]
    t_checks = verify_anchored_item(re_anchored, tamper_idx, tampered_blob, commit=hash_only_commit)
    neighbour_ok = chain_ok(verify_anchored_item(
        re_anchored, tamper_idx + 1, re_blobs[tamper_idx + 1], commit=hash_only_commit))
    tamper_detected = (t_checks["blob_intact"] is False and t_checks["merkle_inclusion"] is True
                       and neighbour_ok is True)
    print(f"✅ tamper probe (blob #{tamper_idx} flipped): detected={tamper_detected} "
          f"(blob_intact={t_checks['blob_intact']}, neighbour still OK={neighbour_ok})")

    # Verification report + run summary.
    report = {
        "run_id": RUN_ID,
        "scenario_id": SCENARIO_ID,
        "num_items": NUM_ITEMS,
        "merkle_root": batch.root,
        "tree_size": batch.tree_size,
        "checkpoint_kid": signer.key_id,
        "all_items_full_chain_ok": all_pass,
        "tamper_probe": {"index": tamper_idx, "detected": tamper_detected, "checks": t_checks},
        "per_item": per_item,
        "honest_limits": [
            "SIMULATION on SYNTHETIC data — not a compliance/conformity claim.",
            "Assurance != certification · Anchored != settled · Verified != content-authenticated.",
            "Commitment binds to CORE NCTE_AI_ACT_EVIDENCE_BOUNDARY_v0_1 (hash_only.v0_1).",
        ],
    }
    _write_json("verification_report.json", report)

    pre_reg = {
        "all_30_encoded_and_batched": batch.tree_size == NUM_ITEMS,
        "merkle_root_and_checkpoint_signed": verify_anchored_item(
            re_anchored, 0, re_blobs[0], commit=hash_only_commit)["checkpoint_signature"],
        "all_inclusion_proofs_valid": all(p["checks"]["merkle_inclusion"] for p in per_item),
        "full_offline_verification": all_pass,
        "basic_tamper_resistance": tamper_detected,
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
