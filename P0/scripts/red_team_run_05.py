#!/usr/bin/env python3
"""P0-05 Red Team — batch-level attacks against large anchored batches.

PASS = the cheat is rejected. Targets the batch/Merkle surface: cross-batch proof replay, index
manipulation, truncation/extension, and leaf/node confusion (RFC 6962 domain separation).

Run (with the ncte-adapter venv):
    NCTE_ADAPTER_PATH=../ncte-adapter \
      ../ncte-adapter/.venv/bin/python P0/scripts/red_team_run_05.py
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
from app.evidence_anchor import anchor_evidence_batch  # noqa: E402
from app.evidence_codec import EvidenceBatchItem, encode_batch, verify_item_in_batch  # noqa: E402
from app.evidence_commitment import hash_only_commit  # noqa: E402
from app.signing import Signer, b64u_encode  # noqa: E402

_EVIDENCE = _REPO_ROOT / "P0" / "evidence"
_COMMIT = hash_only_commit


def _items(n, salt=""):
    return [{"id": f"tc{salt}-{i:05d}", "tool": "get_financial_summary",
             "input_hash": f"sha256:input-{i:06x}",
             "result": {"status": "success", "balance_eur": 10000.0 + i}} for i in range(n)]


# A1 — cross-batch proof replay: an item's proof from batch A used against batch B's root.
def attack_1_cross_batch():
    batch_a, _ = encode_batch(_items(100), commit=_COMMIT)
    batch_b, _ = encode_batch(_items(200), commit=_COMMIT)
    item = batch_a.items[10]
    verifies_against_b = verify_item_in_batch(item, batch_b)   # item from A, root of B
    return {"attack": "1. Cross-batch proof replay", "defended": verifies_against_b is False,
            "detail": f"item from the 100-batch verified against the 200-batch root = {verifies_against_b}. "
                      f"Different root -> rejected; a proof is bound to its own batch."}


# A2 — index manipulation: claim the item sits at a different leaf index.
def attack_2_index():
    batch, _ = encode_batch(_items(128), commit=_COMMIT)
    it = batch.items[20]
    spoofed = EvidenceBatchItem(commitment=it.commitment, leaf_index=21,
                                inclusion_proof=it.inclusion_proof, compressed_size=it.compressed_size)
    verifies = verify_item_in_batch(spoofed, batch)
    return {"attack": "2. Index manipulation (claim a different leaf index)", "defended": verifies is False,
            "detail": f"item 20's commitment+proof claimed at index 21 -> verifies={verifies} "
                      f"(the audit path reconstructs a different root)."}


# A3 — truncation / extension of the batch to hide or pad items.
def attack_3_truncate_extend():
    base = _items(256)
    full, _ = encode_batch(base, commit=_COMMIT)
    truncated, _ = encode_batch(base[:255], commit=_COMMIT)
    extended, _ = encode_batch(base + _items(1, salt="X"), commit=_COMMIT)
    changed = (truncated.root != full.root) and (extended.root != full.root)
    return {"attack": "3. Truncate / extend the batch", "defended": changed,
            "detail": f"dropping one item -> root {truncated.root[:16]}…; adding one -> {extended.root[:16]}…; "
                      f"both differ from the pinned full root {full.root[:16]}… -> detectable."}


# A4 — leaf/node confusion (RFC 6962 domain separation): pass an internal node hash as a leaf.
def attack_4_leaf_node():
    batch, _ = encode_batch(_items(64), commit=_COMMIT)
    it = batch.items[0]
    node_hash = it.inclusion_proof[0]            # an INTERNAL node hash from the audit path
    forged = EvidenceBatchItem(commitment=node_hash, leaf_index=0,
                               inclusion_proof=it.inclusion_proof[1:], compressed_size=1)
    verifies = verify_item_in_batch(forged, batch)
    return {"attack": "4. Leaf/node confusion (node hash as a leaf)", "defended": verifies is False,
            "detail": f"presenting an internal node hash as a leaf commitment -> verifies={verifies}. "
                      f"RFC 6962 prefixes leaves (0x00) and nodes (0x01) differently, so a node can't "
                      f"masquerade as a leaf (second-preimage resistance)."}


# A5 — over-claim audit (is the anchoring-cost win honestly bounded?).
def attack_5_overclaim():
    summary = json.loads((_EVIDENCE / "large_batch_summary.json").read_text(encoding="utf-8"))
    limits = summary.get("honest_limits", [])
    # Scan everything EXCEPT honest_limits (where the disclosure legitimately says "not free").
    scanned = {k: v for k, v in summary.items() if k != "honest_limits"}
    text = json.dumps(scanned).lower()
    # Unambiguous positive over-claims (a bare "free" in a "not free" disclosure is honest, not a claim).
    over_terms = ["anchoring is free", "zero cost", "no cost", "cost-free", "infinitely scalable", "compliant"]
    hits = [p for p in list(core.FORBIDDEN_PHRASES) + over_terms if p.lower() in text]
    discloses_amortize = any("amortize" in l.lower() and "free" in l.lower() for l in limits)
    discloses_on = any("o(n)" in l.lower() for l in limits)
    defended = (not hits) and discloses_amortize and discloses_on
    return {"attack": "5. Over-claim audit (anchoring cost)", "defended": defended,
            "detail": f"over-claim hits (excl. disclosures): {hits or 'none'}; discloses amortize-not-free: "
                      f"{discloses_amortize}; discloses O(N) off-ledger storage: {discloses_on}."}


def main() -> int:
    results = [attack_1_cross_batch(), attack_2_index(), attack_3_truncate_extend(),
               attack_4_leaf_node(), attack_5_overclaim()]
    for r in results:
        print(f"[{'PASS (defended)' if r['defended'] else 'FAIL (broken!)'}] {r['attack']}")
        print(f"    {r['detail']}\n")
    (_EVIDENCE / "red_team_report_05.json").write_text(
        json.dumps({"attacks": results}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    ok = all(r["defended"] for r in results)
    print("🟢 ALL ATTACKS DEFENDED" if ok else "🔴 A DEFENSE FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
