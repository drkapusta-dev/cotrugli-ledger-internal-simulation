#!/usr/bin/env python3
"""P0-02 Red Team — error/recovery-specific attacks against the proof package.

PASS = the defense holds (the cheat is rejected). Attacks target the failure-handling surface:
hide a failure, drop a failed attempt, launder a failure via a forged retry, over-claim recovery.

Run (with the ncte-adapter venv):
    NCTE_ADAPTER_PATH=../ncte-adapter \
      ../ncte-adapter/.venv/bin/python P0/scripts/red_team_run_02.py
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
from app.evidence_anchor import AnchoredEvidenceBatch, verify_anchored_item  # noqa: E402
from app.evidence_codec import (  # noqa: E402
    EvidenceBatchItem,
    decode,
    encode,
    encode_batch,
    verify_item_in_batch,
)
from app.evidence_commitment import hash_only_commit  # noqa: E402

_EVIDENCE = _REPO_ROOT / "P0" / "evidence"
_COMMIT = hash_only_commit


def _load():
    pkg = json.loads((_EVIDENCE / "proof_package_02.json").read_text(encoding="utf-8"))
    anchored = AnchoredEvidenceBatch(batch=pkg["batch"], checkpoint=pkg["checkpoint"], jwks=pkg["jwks"])
    items = json.loads((_EVIDENCE / "error_recovery_batch_input.json").read_text(encoding="utf-8"))
    return pkg, anchored, pkg["blobs"], items


# 1 — Hide a failure: rewrite an error record to success.
def attack_1_hide_failure(anchored, blobs):
    idx = next(i for i, b in enumerate(blobs) if decode(b)["status"] == "error")
    forged = decode(blobs[idx])
    forged["status"] = "success"
    forged["error"] = None
    forged["result"] = {"status": "success", "balance_eur": 0.0, "currency": "EUR"}
    _, forged_blob = encode(forged, commit=_COMMIT)
    keep = verify_anchored_item(anchored, idx, forged_blob, commit=_COMMIT)        # keep anchored commitment
    spliced = anchored.model_copy(deep=True)
    spliced.batch.items[idx] = EvidenceBatchItem(
        commitment=_COMMIT(forged), leaf_index=idx,
        inclusion_proof=anchored.batch.items[idx].inclusion_proof, compressed_size=1)
    forge = verify_anchored_item(spliced, idx, forged_blob, commit=_COMMIT)        # forge new commitment
    defended = keep["blob_intact"] is False and forge["merkle_inclusion"] is False
    return {"attack": "1. Rewrite a failure as a success", "defended": defended,
            "detail": f"keep-commitment -> blob_intact={keep['blob_intact']}; "
                      f"forge-commitment -> merkle_inclusion={forge['merkle_inclusion']}. "
                      f"A failure cannot be silently turned into a success under the signed root."}


# 2 — Drop a failed attempt from the (already-anchored) batch.
def attack_2_drop_failure(anchored, items):
    pinned_root = anchored.batch.root
    drop_i = next(i for i, it in enumerate(items) if it["status"] == "error")
    reduced = [it for j, it in enumerate(items) if j != drop_i]
    new_batch, _ = encode_batch(reduced, commit=_COMMIT)
    defended = new_batch.root != pinned_root
    return {"attack": "2. Drop a failed attempt from an anchored batch", "defended": defended,
            "accepted_limit": True,
            "detail": f"dropping item #{drop_i} yields root {new_batch.root[:18]}… != pinned "
                      f"{pinned_root[:18]}… -> rejected against the pinned root. "
                      f"ACCEPTED LIMIT: omission BEFORE ingestion (an event that never enters the batch) "
                      f"cannot be proven absent by the spine alone — needs heartbeat/sequence (P1+)."}


# 3 — Launder a failure via a forged 'successful retry'.
def attack_3_forge_retry(anchored, blobs, items):
    err_idx = next(i for i, it in enumerate(items) if it["status"] == "error")
    fake = {**items[err_idx], "id": items[err_idx]["id"] + "-FAKEretry", "attempt": 99,
            "status": "success", "error": None,
            "result": {"status": "success", "balance_eur": 1.0, "currency": "EUR"},
            "retry_of": items[err_idx]["id"]}
    _, fake_blob = encode(fake, commit=_COMMIT)
    spliced = EvidenceBatchItem(commitment=_COMMIT(fake), leaf_index=err_idx,
                                inclusion_proof=anchored.batch.items[err_idx].inclusion_proof,
                                compressed_size=1)
    forged_included = verify_item_in_batch(spliced, anchored.batch)               # not under root
    failure_still_verifies = verify_anchored_item(
        anchored, err_idx, blobs[err_idx], commit=_COMMIT)                         # failure persists
    defended = (forged_included is False) and chain_ok_dict(failure_still_verifies)
    return {"attack": "3. Launder a failure via a forged 'successful retry'", "defended": defended,
            "detail": f"forged retry under signed root -> included={forged_included} (rejected); "
                      f"the original failure leaf still verifies (blob_intact="
                      f"{failure_still_verifies['blob_intact']}). A retry NEVER deletes the prior "
                      f"failure — recovery is append-only, not erasure."}


# 4 — Over-claim audit (does any artifact imply the failure was erased / success guaranteed?).
def attack_4_overclaim_audit():
    hits = []
    extra_terms = ["failure erased", "guaranteed success", "no errors", "fully recovered", "compliant"]
    for name in ["proof_package_02.json", "verification_report_02.json"]:
        low = (_EVIDENCE / name).read_text(encoding="utf-8").lower()
        for phrase in list(core.FORBIDDEN_PHRASES) + extra_terms:
            if phrase.lower() in low:
                hits.append(f"{name}: '{phrase}'")
    report = json.loads((_EVIDENCE / "verification_report_02.json").read_text(encoding="utf-8"))
    has_limits = bool(report.get("honest_limits"))
    # the failure records must still be present as failures in the report's histogram
    nonsuccess = sum(v for k, v in report.get("status_histogram", {}).items() if k != "success")
    defended = (not hits) and has_limits and nonsuccess > 0
    return {"attack": "4. Over-claim audit (recovery discipline)", "defended": defended,
            "detail": f"forbidden/over-claim hits: {hits or 'none'}; honest_limits present: {has_limits}; "
                      f"non-success records still counted in histogram: {nonsuccess}. "
                      f"Artifacts record failures as failures and disclose limits — recovery is not sold as erasure."}


def chain_ok_dict(checks: dict) -> bool:
    return all(checks.values())


def main() -> int:
    pkg, anchored, blobs, items = _load()
    results = [
        attack_1_hide_failure(anchored, blobs),
        attack_2_drop_failure(anchored, items),
        attack_3_forge_retry(anchored, blobs, items),
        attack_4_overclaim_audit(),
    ]
    for r in results:
        print(f"[{'PASS (defended)' if r['defended'] else 'FAIL (broken!)'}] {r['attack']}")
        print(f"    {r['detail']}")
        if r.get("accepted_limit"):
            print("    ⚠ accepted limit disclosed (see detail).")
        print()
    out = {"attacks": results}
    (_EVIDENCE / "red_team_report_02.json").write_text(
        json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    all_defended = all(r["defended"] for r in results)
    print("🟢 ALL ATTACKS DEFENDED" if all_defended else "🔴 A DEFENSE FAILED")
    return 0 if all_defended else 1


if __name__ == "__main__":
    sys.exit(main())
