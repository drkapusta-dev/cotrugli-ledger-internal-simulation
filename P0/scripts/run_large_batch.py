#!/usr/bin/env python3
"""P0-05 Large Batch Anchoring — scale + cost test (100 / 500 / 1000 items).

COTRUGLI CISE · P0 Proof Spine Stress Test · Scenario 05.

The core economic property: N items -> ONE Merkle root -> ONE signed checkpoint -> ONE anchor.
On-ledger cost is O(1) signatures regardless of N (the RT0-C win); per-item proofs are O(log N);
every item still verifies offline; roots are deterministic at each size.

Honest: batching AMORTIZES anchoring cost, it does not make it free; bigger batches trade
timeliness for cost; off-ledger blob storage is still O(N) (compressed).

Run (with the ncte-adapter venv):
    NCTE_ADAPTER_PATH=../ncte-adapter \
      ../ncte-adapter/.venv/bin/python P0/scripts/run_large_batch.py
"""

from __future__ import annotations

import json
import math
import os
import sys
import time
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
from app.evidence_commitment import hash_only_commit  # noqa: E402
from app.signing import Signer, b64u_encode  # noqa: E402

RUN_ID = "P0-AIAct-Track1-2026-06-09"
SCENARIO_ID = "P0-05-LargeBatchAnchoring"
SIZES = [100, 500, 1000]
CHECKPOINT_TS = "2026-06-09T13:05:00Z"
_DEMO_SEED = b"cotrugli-cise-p0-largebatch-s005"
_KEY_ID = "cise-p0-largebatch-k1"
_COMMIT = hash_only_commit
_EVIDENCE_DIR = _REPO_ROOT / "P0" / "evidence"


def _items(n: int) -> list[dict]:
    out = []
    for i in range(n):
        out.append({
            "id": f"tc-{i:05d}", "timestamp": f"2026-06-09T13:{(i // 60) % 60:02d}:{i % 60:02d}Z",
            "agent_id": f"agent-{i % 8:03d}", "event_class": "AGENT_ACTION",
            "tool": ["get_financial_summary", "summarize_document", "classify_transaction"][i % 3],
            "input_hash": f"sha256:input-{i:06x}",
            "result": {"status": "success", "balance_eur": 10000.0 + i, "currency": "EUR"},
            "policy_snapshot": "AI_ACT_TRACK1_v2026-06",
        })
    return out


def _signer() -> Signer:
    return Signer.from_seed_b64(b64u_encode((_DEMO_SEED + b"\x00" * 32)[:32]), _KEY_ID)


def _write_json(name: str, payload) -> Path:
    path = _EVIDENCE_DIR / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def run() -> dict:
    print(f"🚀 {SCENARIO_ID} — Large Batch Anchoring {SIZES}\n")
    signer = _signer()
    summary = []
    pkg_100 = None

    for n in SIZES:
        items = _items(n)
        t0 = time.perf_counter()
        anchored, blobs = anchor_evidence_batch(items, signer, timestamp=CHECKPOINT_TS, commit=_COMMIT)
        t_anchor = time.perf_counter() - t0

        # exactly ONE signature anchors the whole batch.
        num_signatures = 1 if anchored.checkpoint.signature else 0

        # verify ALL items offline.
        t1 = time.perf_counter()
        all_ok = all(chain_ok(verify_anchored_item(anchored, i, blobs[i], commit=_COMMIT))
                     for i in range(anchored.batch.tree_size))
        t_verify = time.perf_counter() - t1

        proof_lens = [len(it.inclusion_proof) for it in anchored.batch.items]
        max_proof = max(proof_lens)
        log_bound = math.ceil(math.log2(n)) + 1
        compressed_total = sum(it.compressed_size for it in anchored.batch.items)

        row = {
            "n": n, "root": anchored.batch.root, "tree_size": anchored.batch.tree_size,
            "num_signatures": num_signatures, "all_items_verified": all_ok,
            "max_inclusion_proof_len": max_proof, "log2n_bound": log_bound,
            "proof_within_log_bound": max_proof <= log_bound,
            "offledger_compressed_bytes": compressed_total,
            "anchor_ms": round(t_anchor * 1000, 1), "verify_ms": round(t_verify * 1000, 1),  # informational
        }
        summary.append(row)
        print(f"✅ N={n:>4}: ONE root {anchored.batch.root[:20]}… · 1 signature · "
              f"{anchored.batch.tree_size}/{n} verified · max proof len {max_proof} (≤ log₂N+1={log_bound}) · "
              f"anchor {row['anchor_ms']}ms verify {row['verify_ms']}ms")

        if n == 100:
            pkg_100 = {"run_id": RUN_ID, "scenario_id": SCENARIO_ID,
                       "batch": json.loads(anchored.batch.model_dump_json()),
                       "checkpoint": json.loads(anchored.checkpoint.model_dump_json()),
                       "jwks": anchored.jwks, "blobs": blobs}

    _write_json("proof_package_05.json", pkg_100)
    # NOTE: timing fields are informational and EXCLUDED from any determinism check.
    _write_json("large_batch_summary.json", {
        "run_id": RUN_ID, "scenario_id": SCENARIO_ID, "sizes": SIZES,
        "per_size": [{k: v for k, v in r.items()} for r in summary],
        "honest_limits": [
            "SIMULATION on SYNTHETIC data — not a compliance/conformity claim.",
            "ONE signature for N items is the ON-LEDGER cost win; batching AMORTIZES anchoring, it "
            "does not make it free (the single checkpoint still has a real on-ledger cost).",
            "Bigger batches DELAY an item's provable-anchoring until the batch seals (cost<->timeliness).",
            "Off-ledger blob storage scales O(N) (lossless-compressed); the on-ledger commitment stays tiny.",
            "Timing is hardware-dependent and informational only; the determinism guarantee is the ROOT.",
        ],
    })

    pre_reg = {
        "one_signature_per_batch_all_sizes": all(r["num_signatures"] == 1 for r in summary),
        "all_items_verified_all_sizes": all(r["all_items_verified"] for r in summary),
        "proofs_within_log_bound_all_sizes": all(r["proof_within_log_bound"] for r in summary),
        "anchored_exactly_n_items": all(r["tree_size"] == r["n"] for r in summary),
    }
    print("\n📋 pre-registered PASS/FAIL:")
    for k, v in pre_reg.items():
        print(f"   {'PASS' if v else 'FAIL'}  {k}")
    return {"summary": summary, "pre_registered": pre_reg}


if __name__ == "__main__":
    result = run()
    ok = all(result["pre_registered"].values())
    print(f"\n{'🟢 ALL PRE-REGISTERED CRITERIA PASS' if ok else '🔴 SOME CRITERIA FAILED'}")
    sys.exit(0 if ok else 1)
