#!/usr/bin/env python3
"""P0-01 Red Team — execute the 4 attacks against the Happy Path proof package.

Loads the PUBLIC proof package produced by run_happy_path.py and actually attempts each
attack against the REAL codec/anchor verifier. "PASS" = the defense holds (forgery rejected).
Attack 3 surfaces an honest ACCEPTED LIMIT about the trust root.

Run (with the ncte-adapter venv):
    NCTE_ADAPTER_PATH=../ncte-adapter \
      ../ncte-adapter/.venv/bin/python P0/scripts/red_team_run_01.py
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
from app.evidence_anchor import AnchoredEvidenceBatch, verify_anchored_item  # noqa: E402
from app.evidence_codec import (  # noqa: E402
    EvidenceBatchItem,
    decode,
    encode,
    verify_item_in_batch,
)
from app.evidence_commitment import hash_only_commit  # noqa: E402
from app.signing import Signer, b64u_encode  # noqa: E402

_EVIDENCE = _REPO_ROOT / "P0" / "evidence"
_COMMIT = hash_only_commit


def _load():
    pkg = json.loads((_EVIDENCE / "proof_package.json").read_text(encoding="utf-8"))
    anchored = AnchoredEvidenceBatch(batch=pkg["batch"], checkpoint=pkg["checkpoint"], jwks=pkg["jwks"])
    return pkg, anchored, pkg["blobs"]


# --------------------------------------------------------------------------- #
# Attack 1 — forge/tamper an item and try to make it verify under the signed root.
# --------------------------------------------------------------------------- #
def attack_1_forge_item(anchored, blobs):
    idx = 5
    # (a) keep the anchored commitment, swap the blob to forged content.
    forged = decode(blobs[idx])
    forged["result"]["balance_eur"] = 999999.99          # change the money
    _, forged_blob = encode(forged, commit=_COMMIT)
    checks_a = verify_anchored_item(anchored, idx, forged_blob, commit=_COMMIT)
    a_rejected = checks_a["blob_intact"] is False          # decoded != anchored commitment

    # (b) forge a NEW commitment matching the forged content, splice it into the item.
    forged_commitment = _COMMIT(forged)
    spliced = anchored.model_copy(deep=True)
    spliced.batch.items[idx] = EvidenceBatchItem(
        commitment=forged_commitment, leaf_index=idx,
        inclusion_proof=anchored.batch.items[idx].inclusion_proof,
        compressed_size=len(forged_blob) // 2,
    )
    checks_b = verify_anchored_item(spliced, idx, forged_blob, commit=_COMMIT)
    b_rejected = checks_b["merkle_inclusion"] is False     # forged commitment not under signed root

    defended = a_rejected and b_rejected
    return {
        "attack": "1. Forge/tamper an item so it verifies",
        "defended": defended,
        "detail": (f"(a) swap blob, keep commitment -> blob_intact={checks_a['blob_intact']} (rejected={a_rejected}); "
                   f"(b) forge matching commitment -> merkle_inclusion={checks_b['merkle_inclusion']} (rejected={b_rejected}). "
                   f"Either path is rejected: you cannot keep the anchored commitment with forged bytes, "
                   f"and a forged commitment is not a leaf under the signed root."),
    }


# --------------------------------------------------------------------------- #
# Attack 2 — swap an item's inclusion proof / index to point at another leaf.
# --------------------------------------------------------------------------- #
def attack_2_swap_proof(anchored, blobs):
    i, j = 3, 11
    item_i = anchored.batch.items[i]
    # (a) item i's commitment but item j's inclusion proof.
    spliced_proof = EvidenceBatchItem(
        commitment=item_i.commitment, leaf_index=i,
        inclusion_proof=anchored.batch.items[j].inclusion_proof,
        compressed_size=item_i.compressed_size,
    )
    a_ok = verify_item_in_batch(spliced_proof, anchored.batch)
    # (b) item i's commitment + proof but claim item j's index.
    spliced_index = EvidenceBatchItem(
        commitment=item_i.commitment, leaf_index=j,
        inclusion_proof=item_i.inclusion_proof, compressed_size=item_i.compressed_size,
    )
    b_ok = verify_item_in_batch(spliced_index, anchored.batch)

    defended = (a_ok is False) and (b_ok is False)
    return {
        "attack": "2. Swap inclusion proof / index to another leaf",
        "defended": defended,
        "detail": (f"(a) i's commitment + j's proof -> verifies={a_ok}; "
                   f"(b) i's proof claiming index j -> verifies={b_ok}. "
                   f"The audit path reconstructs a DIFFERENT root, so both are rejected."),
    }


# --------------------------------------------------------------------------- #
# Attack 3 — re-sign a forged root with a look-alike key; pass checkpoint_signature.
# --------------------------------------------------------------------------- #
def attack_3_resign_root(anchored, blobs):
    forged_root = "sha256:" + "de" * 32
    attacker = Signer.from_seed_b64(b64u_encode(b"attacker-look-alike-key-32bytes!"), anchored.checkpoint.signature.key_id)

    # (a) forged root signed by attacker, but verified against the LEGIT issuer jwks (pinned).
    forged_cp = build_checkpoint(attacker, anchored.batch.tree_size, forged_root,
                                 anchored.checkpoint.timestamp, log_id=anchored.checkpoint.log_id)
    a_ok = verify_checkpoint(anchored.jwks, forged_cp)     # against the real issuer key

    # (b) attacker ALSO swaps the jwks to their own pubkey (controls the whole package).
    b_ok = verify_checkpoint(attacker.jwks(), forged_cp)

    # Defense holds for the pinned-issuer case (a). (b) is the disclosed accepted limit.
    defended = (a_ok is False)
    return {
        "attack": "3. Re-sign a forged root with a look-alike key",
        "defended": defended,
        "accepted_limit": (b_ok is True),
        "detail": (f"(a) forged root signed by attacker, verified against the PINNED issuer key -> "
                   f"verifies={a_ok} (rejected). "
                   f"(b) attacker also swaps the shipped jwks to their own key -> verifies={b_ok}. "
                   f"ACCEPTED LIMIT: offline verification proves internal consistency + that SOME key signed it; "
                   f"the verifier MUST pin the issuer key out-of-band. A package whose own jwks is blindly trusted "
                   f"can be self-consistently forged — so the issuer key is distributed/pinned separately, not from the package."),
    }


# --------------------------------------------------------------------------- #
# Attack 4 — over-claim audit: does any machine artifact claim beyond what it proves?
# --------------------------------------------------------------------------- #
def attack_4_overclaim_audit():
    artifacts = ["proof_package.json", "verification_report.json"]
    hits = []
    for name in artifacts:
        text = (_EVIDENCE / name).read_text(encoding="utf-8")
        low = text.lower()
        for phrase in core.FORBIDDEN_PHRASES:
            if phrase.lower() in low:
                hits.append(f"{name}: '{phrase}'")
    # The machine artifacts should carry only structural facts + honest_limits, no claim language.
    report = json.loads((_EVIDENCE / "verification_report.json").read_text(encoding="utf-8"))
    has_limits = bool(report.get("honest_limits"))
    defended = (not hits) and has_limits
    return {
        "attack": "4. Over-claim audit (claim discipline)",
        "defended": defended,
        "detail": (f"forbidden-phrase hits in machine artifacts: {hits or 'none'}; "
                   f"honest_limits present in report: {has_limits}. "
                   f"Artifacts carry structural facts + disclosed limits only — no compliance/certification language."),
    }


def main() -> int:
    pkg, anchored, blobs = _load()
    # sanity: the package itself still verifies before we attack it.
    baseline = all(verify_anchored_item(anchored, i, blobs[i], commit=_COMMIT)["blob_intact"]
                   for i in range(anchored.batch.tree_size))
    results = [
        attack_1_forge_item(anchored, blobs),
        attack_2_swap_proof(anchored, blobs),
        attack_3_resign_root(anchored, blobs),
        attack_4_overclaim_audit(),
    ]
    print(f"baseline package intact before attacks: {baseline}\n")
    for r in results:
        verdict = "PASS (defended)" if r["defended"] else "FAIL (broken!)"
        print(f"[{verdict}] {r['attack']}")
        print(f"    {r['detail']}")
        if r.get("accepted_limit"):
            print(f"    ⚠ accepted limit disclosed (see detail).")
        print()
    out = {"baseline_intact": baseline, "attacks": results}
    (_EVIDENCE / "red_team_report.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    all_defended = all(r["defended"] for r in results)
    print("🟢 ALL ATTACKS DEFENDED" if all_defended else "🔴 A DEFENSE FAILED")
    return 0 if all_defended else 1


if __name__ == "__main__":
    sys.exit(main())
