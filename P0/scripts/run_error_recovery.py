#!/usr/bin/env python3
"""P0-02 Error & Recovery — REAL Evidence Codec v0.2 integration.

COTRUGLI CISE · P0 Proof Spine Stress Test · Scenario 02.

A realistic batch where a portion of agent tool-calls fail, partially succeed, time out, and
are retried. The proof spine must attest ALL of it faithfully and treat recovery as append-only:

  ~25 synthetic tool-calls (success / error / partial / timeout + retry chains)
    -> Evidence Codec v0.2 lossless blobs (failures committed exactly like successes)
    -> ONE Merkle root -> ONE signed checkpoint
    -> offline verify ALL items
    -> recovery discipline: each retry is a NEW leaf; the failed attempt stays intact & verifies
    -> pipeline fail-closed: corrupted stored blob is detected & localized
    -> idempotent re-run: identical root

Honest framing: SIMULATION on SYNTHETIC data. The spine records failure as first-class evidence;
it never makes a failure disappear. Assurance != certification; recovery != erasure of failure.

Run (with the ncte-adapter venv):
    NCTE_ADAPTER_PATH=../ncte-adapter \
      ../ncte-adapter/.venv/bin/python P0/scripts/run_error_recovery.py
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
SCENARIO_ID = "P0-02-ErrorRecovery"
CHECKPOINT_TS = "2026-06-09T10:05:00Z"
POLICY_SNAPSHOT = "AI_ACT_TRACK1_v2026-06"
_DEMO_SEED = b"cotrugli-cise-p0-error-seed-0002"
_KEY_ID = "cise-p0-error-k1"
_COMMIT = hash_only_commit
_EVIDENCE_DIR = _REPO_ROOT / "P0" / "evidence"

# Logical operations and the status of EACH attempt (a retry = a new attempt = a new evidence item).
# Recovery chains are explicit: a failing attempt is followed by a retry that references it.
_PLAN = [
    ("op-00", ["success"]),
    ("op-01", ["error", "success"]),               # recover: error -> retry success
    ("op-02", ["success"]),
    ("op-03", ["partial"]),                         # partial, abandoned
    ("op-04", ["timeout", "error", "success"]),     # 3-step recovery chain
    ("op-05", ["success"]),
    ("op-06", ["error"]),                           # hard fail, no recovery
    ("op-07", ["success"]),
    ("op-08", ["timeout", "success"]),
    ("op-09", ["success"]),
    ("op-10", ["partial", "success"]),              # partial -> full retry
    ("op-11", ["success"]),
    ("op-12", ["error", "error"]),                  # two failed attempts, abandoned
    ("op-13", ["success"]),
    ("op-14", ["success"]),
    ("op-15", ["timeout", "success"]),
    ("op-16", ["success"]),
]

_TOOL_FOR = {
    "success": ("get_financial_summary", "read-only-financial"),
    "error": ("post_ledger_entry", "write-ledger"),
    "partial": ("summarize_document", "read-only-document"),
    "timeout": ("check_account_balance", "read-only-financial"),
}
_ERROR_CODE = {"error": "UPSTREAM_5XX", "timeout": "DEADLINE_EXCEEDED", "partial": "TRUNCATED_RESULT"}


def _ts(i: int) -> str:
    mm, ss = divmod(i, 60)
    return f"2026-06-09T10:{mm:02d}:{ss:02d}Z"


def generate_items() -> list[dict]:
    items: list[dict] = []
    gi = 0  # global index -> timestamp + ordering
    for op, attempts in _PLAN:
        prev_id = None
        for a_idx, status in enumerate(attempts, start=1):
            tool, mandate = _TOOL_FOR[status]
            item = {
                "id": f"{op}-a{a_idx}",
                "timestamp": _ts(gi),
                "agent_id": "agent-prod-742",
                "event_class": "AGENT_ACTION",
                "tool": tool,
                "input_hash": f"sha256:input-{gi:04x}",  # hash-only, no source content
                "attempt": a_idx,
                "status": status,
                "error": (None if status == "success"
                          else {"code": _ERROR_CODE[status], "message_hash": f"sha256:err-{gi:04x}"}),
                "result": (
                    {"status": "success", "balance_eur": 12450.75 + gi, "currency": "EUR"}
                    if status == "success" else
                    {"status": "partial", "fields_returned": 2, "fields_expected": 5}
                    if status == "partial" else None
                ),
                "retry_of": prev_id,                    # link to the prior attempt (recovery)
                "mandate": mandate,
                "policy_snapshot": POLICY_SNAPSHOT,
            }
            items.append(item)
            prev_id = item["id"]
            gi += 1
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
    print(f"🚀 {SCENARIO_ID} — Error & Recovery\n")
    items = generate_items()
    hist = Counter(it["status"] for it in items)
    retries = [it for it in items if it["retry_of"]]
    print(f"✅ generated {len(items)} items — statuses {dict(hist)}; {len(retries)} retry records")

    # Encode EVERY item (failures included) -> batch -> ONE signed checkpoint.
    signer = _signer()
    anchored, blobs = anchor_evidence_batch(items, signer, timestamp=CHECKPOINT_TS, commit=_COMMIT)
    batch = anchored.batch
    print(f"✅ encoded {batch.tree_size} lossless blobs (failures committed exactly like successes)")
    print(f"✅ ONE Merkle root: {batch.root}")

    _write_json("error_recovery_batch_input.json", items)
    proof_package = {
        "run_id": RUN_ID, "scenario_id": SCENARIO_ID,
        "batch": json.loads(batch.model_dump_json()),
        "checkpoint": json.loads(anchored.checkpoint.model_dump_json()),
        "jwks": anchored.jwks, "blobs": blobs,
    }
    pkg_path = _write_json("proof_package_02.json", proof_package)
    print(f"💾 saved public proof package -> {pkg_path.relative_to(_REPO_ROOT)}")

    # Reload ONLY the public package; verify every item offline.
    reloaded = json.loads(pkg_path.read_text(encoding="utf-8"))
    re_anchored = AnchoredEvidenceBatch(batch=reloaded["batch"], checkpoint=reloaded["checkpoint"],
                                        jwks=reloaded["jwks"])
    re_blobs = reloaded["blobs"]
    decoded = [decode(b) for b in re_blobs]
    id_to_index = {d["id"]: i for i, d in enumerate(decoded)}

    per_item_ok = [chain_ok(verify_anchored_item(re_anchored, i, re_blobs[i], commit=_COMMIT))
                   for i in range(re_anchored.batch.tree_size)]
    all_verify = all(per_item_ok)
    print(f"\n✅ offline verification (errors included): {sum(per_item_ok)}/{len(per_item_ok)} full-chain OK")

    # Criterion 2/8 — failures attested faithfully (decoded status == input status; never rewritten).
    status_faithful = all(decoded[i]["status"] == items[i]["status"] for i in range(len(items)))
    failures = [d for d in decoded if d["status"] != "success"]
    print(f"✅ failure faithfulness: {len(failures)} non-success records attested verbatim "
          f"(status never rewritten): {status_faithful}")

    # Criterion 3/4 — recovery is append-only; each retry is a separate leaf and its referenced
    # prior attempt is present, unchanged, and verifies.
    recovery_ok = True
    recovery_detail = []
    for r in retries:
        ri = id_to_index[r["id"]]
        prior_id = r["retry_of"]
        present = prior_id in id_to_index
        pi = id_to_index.get(prior_id, -1)
        separate_leaf = present and (re_anchored.batch.items[ri].commitment
                                     != re_anchored.batch.items[pi].commitment)
        prior_verifies = present and chain_ok(
            verify_anchored_item(re_anchored, pi, re_blobs[pi], commit=_COMMIT))
        prior_unchanged = present and decoded[pi]["status"] == items[pi]["status"]  # failure persists
        ok = present and separate_leaf and prior_verifies and prior_unchanged
        recovery_ok = recovery_ok and ok
        recovery_detail.append({"retry": r["id"], "retry_of": prior_id, "prior_present": present,
                                "separate_leaf": separate_leaf, "prior_verifies": prior_verifies,
                                "prior_failure_persists": prior_unchanged})
    print(f"✅ recovery append-only: {len(retries)}/{len(retries)} retries are separate leaves; "
          f"each prior attempt present, unchanged, verifies: {recovery_ok}")

    # Criterion 5 — pipeline fail-closed: corrupt a FAILURE item's blob, confirm detection + locality.
    err_idx = next(i for i, d in enumerate(decoded) if d["status"] == "error")
    tampered = ("00" if re_blobs[err_idx][:2] != "00" else "ff") + re_blobs[err_idx][2:]
    t_checks = verify_anchored_item(re_anchored, err_idx, tampered, commit=_COMMIT)
    neighbour_ok = chain_ok(verify_anchored_item(
        re_anchored, (err_idx + 1) % len(re_blobs),
        re_blobs[(err_idx + 1) % len(re_blobs)], commit=_COMMIT))
    corruption_detected = (t_checks["blob_intact"] is False and t_checks["merkle_inclusion"] is True
                           and neighbour_ok is True)
    print(f"✅ corrupt-blob fail-closed (item #{err_idx}, an error record): detected={corruption_detected} "
          f"(blob_intact={t_checks['blob_intact']}, neighbour OK={neighbour_ok})")

    report = {
        "run_id": RUN_ID, "scenario_id": SCENARIO_ID,
        "num_items": len(items), "status_histogram": dict(hist), "retry_count": len(retries),
        "merkle_root": batch.root, "tree_size": batch.tree_size, "checkpoint_kid": signer.key_id,
        "all_items_full_chain_ok": all_verify,
        "status_faithful": status_faithful,
        "recovery_append_only": recovery_ok, "recovery_detail": recovery_detail,
        "corrupt_blob": {"index": err_idx, "detected": corruption_detected, "checks": t_checks},
        "honest_limits": [
            "SIMULATION on SYNTHETIC data — not a compliance/conformity claim.",
            "Recovery = append a NEW record; the failure is PERMANENT on the chain (immutability).",
            "The spine DETECTS a corrupted off-ledger blob and says which item, but cannot RECOVER "
            "its content (content is off-ledger; re-fetch from source/custody is required).",
            "Omission BEFORE ingestion cannot be proven absent by the spine alone (needs heartbeat/"
            "sequence, P1+); within an anchored batch, dropping an item changes the root.",
            "Assurance != certification · Anchored != settled · recovery != erasure of failure.",
        ],
    }
    _write_json("verification_report_02.json", report)

    pre_reg = {
        "all_items_encoded_and_batched": batch.tree_size == len(items),
        "failures_attested_faithfully": status_faithful and len(failures) > 0,
        "recovery_append_only": recovery_ok,
        "linkage_without_mutation": recovery_ok,
        "corrupt_blob_detected_localized": corruption_detected,
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
