#!/usr/bin/env python3
"""P0-03 Red Team — bypass-focused + SEMANTIC attacks against the proof package.

Honest by construction: this scenario is where the architecture's true limit lives, so each
attack reports BOTH whether the cryptographic guarantee held (`defended`) AND whether it reveals
a disclosed `accepted_limit`. A semantic attack that *should* win (and is disclosed) is not a
failure of the spine — it is the boundary of what the spine claims.

Run (with the ncte-adapter venv):
    NCTE_ADAPTER_PATH=../ncte-adapter \
      ../ncte-adapter/.venv/bin/python P0/scripts/red_team_run_03.py
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
from app.evidence_anchor import (  # noqa: E402
    AnchoredEvidenceBatch,
    anchor_evidence_batch,
    chain_ok,
    verify_anchored_item,
)
from app.evidence_codec import EvidenceBatchItem, decode, encode, verify_item_in_batch  # noqa: E402
from app.evidence_commitment import hash_only_commit  # noqa: E402
from app.signing import Signer, b64u_encode  # noqa: E402

_EVIDENCE = _REPO_ROOT / "P0" / "evidence"
_COMMIT = hash_only_commit


def _load():
    pkg = json.loads((_EVIDENCE / "proof_package_03.json").read_text(encoding="utf-8"))
    anchored = AnchoredEvidenceBatch(batch=pkg["batch"], checkpoint=pkg["checkpoint"], jwks=pkg["jwks"])
    events = json.loads((_EVIDENCE / "malicious_bypass_batch_input.json").read_text(encoding="utf-8"))
    report = json.loads((_EVIDENCE / "verification_report_03.json").read_text(encoding="utf-8"))
    return pkg, anchored, pkg["blobs"], events, report


# A1 — bypass the gateway entirely (vendor call, no receipt). THE headline limit.
def attack_1_full_bypass(anchored, blobs, report):
    # The attacker performs an action that never produces a gateway event. Can they make it appear
    # as a legitimate anchored record? (No — they lack the gateway key / a leaf under the root.)
    fake = {"id": "gw-BYPASS", "gateway_seq": 999, "decision": "allow", "tool": "transfer_funds",
            "result": {"status": "success", "stolen_eur": 1_000_000}}
    _, fake_blob = encode(fake, commit=_COMMIT)
    spliced = EvidenceBatchItem(commitment=_COMMIT(fake), leaf_index=0,
                                inclusion_proof=anchored.batch.items[0].inclusion_proof, compressed_size=1)
    cannot_forge_record = verify_item_in_batch(spliced, anchored.batch) is False
    # The ONLY signal is reconciliation count (needs an independent vendor signal).
    recon = report["reconciliation"]
    surfaced_by_count = recon["bypass_surfaced"]
    return {"attack": "1. Bypass the gateway entirely (no receipt)",
            "defended": cannot_forge_record,
            "accepted_limit": True,
            "verdict": "ACCEPTED LIMIT — spine cannot see a true bypass; only reconciliation surfaces the COUNT",
            "detail": (f"attacker cannot inject a fake anchored record (under-root check fails: "
                       f"forged-record-rejected={cannot_forge_record}); BUT the bypassed action itself "
                       f"is invisible to the spine — content unattestable. Reconciliation surfaced "
                       f"{recon['unaccounted']} unaccounted actions (gateway {recon['gateway_count']} vs "
                       f"vendor {recon['vendor_observed_count']}), surfaced={surfaced_by_count}. "
                       f"This is the from-ingestion-forward / 'no receipt -> no execution is a CONTROL "
                       f"convention' limit — disclosed, not solved.")}


# A2 — semantic attacks (Grok's ask): (a) convincing fake event; (b) valid record, wrong decision.
def attack_2_semantic(anchored, blobs, events):
    # (a) a structurally perfect, plausible fake event spliced in -> not under the signed root.
    plausible = {**events[0], "id": "gw-FAKE", "gateway_seq": 28,
                 "result": {"status": "success", "balance_eur": 99999.0, "currency": "EUR"}}
    _, _b = encode(plausible, commit=_COMMIT)
    spliced = EvidenceBatchItem(commitment=_COMMIT(plausible), leaf_index=5,
                                inclusion_proof=anchored.batch.items[5].inclusion_proof, compressed_size=1)
    fake_rejected = verify_item_in_batch(spliced, anchored.batch) is False

    # (b) a VALIDLY-signed event whose decision is a LIE: allow a write under a read-only mandate.
    gw_signer = Signer.from_seed_b64(b64u_encode((b"cotrugli-cise-p0-bypass-seed-003" + b"\x00")[:32]),
                                     "cise-p0-bypass-gw-k1")
    lie = {"id": "gw-LIE", "gateway_seq": 0, "principal": "tenant:alpha", "mandate": "read-only-financial",
           "tool": "transfer_funds", "capability_required": "write", "decision": "allow",  # WRONG
           "deny_reason": None, "input_hash": "sha256:lie", "event_class": "GATEWAY_DECISION"}
    lie_anchored, lie_blobs = anchor_evidence_batch([lie], gw_signer, timestamp="2026-06-09T11:09:00Z", commit=_COMMIT)
    lie_verifies = chain_ok(verify_anchored_item(lie_anchored, 0, lie_blobs[0], commit=_COMMIT))
    return {"attack": "2. Semantic forgery (fake event + lie-in-valid-record)",
            "defended": fake_rejected,            # the injection attack is cryptographically defended
            "accepted_limit": lie_verifies,       # the lie-in-a-valid-record is the disclosed limit
            "verdict": "DEFENDED (fake injection) + ACCEPTED LIMIT (record attested, decision-correctness is not)",
            "detail": (f"(a) plausible fake event spliced under the signed root -> verifies={not fake_rejected} "
                       f"(rejected={fake_rejected}). "
                       f"(b) an event with decision='allow' for a WRITE under a read-only mandate, validly "
                       f"signed by the gateway key, verifies cryptographically={lie_verifies}. The spine "
                       f"attests the DECISION WAS RECORDED — it does NOT attest the decision was CORRECT. "
                       f"Catching a wrong-but-signed decision is a policy/review (overlay) job, not core. "
                       f"This is the sharpest honest limit a real 'wolf' finds.")}


# A3 — forge gateway authorization with a look-alike key.
def attack_3_forge_auth(anchored):
    forged_root = "sha256:" + "ab" * 32
    attacker = Signer.from_seed_b64(b64u_encode(b"attacker-fake-gateway-key-32byte"), anchored.checkpoint.signature.key_id)
    forged_cp = build_checkpoint(attacker, anchored.batch.tree_size, forged_root,
                                 anchored.checkpoint.timestamp, log_id=anchored.checkpoint.log_id)
    against_pinned = verify_checkpoint(anchored.jwks, forged_cp)         # vs real gateway key
    against_swapped = verify_checkpoint(attacker.jwks(), forged_cp)      # attacker swaps jwks too
    return {"attack": "3. Forge gateway authorization (look-alike key)",
            "defended": against_pinned is False, "accepted_limit": against_swapped is True,
            "verdict": "DEFENDED vs pinned gateway key (+ issuer-pin accepted limit)",
            "detail": (f"forged root signed by attacker, checked against the PINNED gateway key -> "
                       f"verifies={against_pinned} (rejected). If the attacker also swaps the shipped jwks "
                       f"-> verifies={against_swapped}: the gateway key MUST be pinned out-of-band.")}


# A4 — replay an authorized receipt to double-execute.
def attack_4_replay(anchored, blobs, events):
    seqs = [d["gateway_seq"] for d in (decode(b) for b in blobs)]
    seqs_unique = len(seqs) == len(set(seqs))
    # A replayed receipt reuses an existing (seq, commitment): a single-use consumer rejects the
    # second use; the gateway controls seq issuance, so a replay cannot mint a NEW authorization.
    replay_is_same_leaf = _COMMIT(events[3]) == anchored.batch.items[3].commitment
    return {"attack": "4. Replay an authorized receipt (double-execute)",
            "defended": seqs_unique and replay_is_same_leaf, "accepted_limit": False,
            "verdict": "DEFENDED within the boundary (unique seq; single-use enforced by consumer)",
            "detail": (f"all {len(seqs)} gateway_seq are unique (no duplicate authorization): {seqs_unique}. "
                       f"A replay reuses the identical (seq, commitment) leaf -> a single-use consumer "
                       f"rejects the second use; the gateway controls seq issuance, so a replay cannot mint "
                       f"a new authorization. (Replay PREVENTION requires the executor to honor single-use.)")}


# A5 — over-claim audit.
def attack_5_overclaim(report):
    extra = ["prevents bypass", "cannot be bypassed", "impossible to bypass", "guarantees", "compliant", "fully secure"]
    text = (_EVIDENCE / "verification_report_03.json").read_text(encoding="utf-8").lower()
    text += (_EVIDENCE / "proof_package_03.json").read_text(encoding="utf-8").lower()
    hits = [p for p in list(core.FORBIDDEN_PHRASES) + extra if p.lower() in text]
    has_limits = bool(report.get("honest_limits"))
    discloses_bypass_limit = any("invisible to the proof spine" in lim.lower() or "control convention" in lim.lower()
                                 for lim in report.get("honest_limits", []))
    defended = (not hits) and has_limits and discloses_bypass_limit
    return {"attack": "5. Over-claim audit (does it claim to prevent bypass?)",
            "defended": defended, "accepted_limit": False,
            "verdict": "DEFENDED — the report discloses the bypass limit, claims detect-not-prevent",
            "detail": f"forbidden/over-claim hits: {hits or 'none'}; honest_limits present: {has_limits}; "
                      f"explicitly discloses the bypass control-convention limit: {discloses_bypass_limit}."}


def main() -> int:
    pkg, anchored, blobs, events, report = _load()
    results = [
        attack_1_full_bypass(anchored, blobs, report),
        attack_2_semantic(anchored, blobs, events),
        attack_3_forge_auth(anchored),
        attack_4_replay(anchored, blobs, events),
        attack_5_overclaim(report),
    ]
    for r in results:
        print(f"[{r['verdict']}]\n    {r['attack']}\n    {r['detail']}")
        if r.get("accepted_limit"):
            print("    ⚠ accepted limit disclosed (see verdict/detail).")
        print()
    out = {"attacks": results}
    (_EVIDENCE / "red_team_report_03.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    # "Defended" = every cryptographic guarantee held. Accepted limits are disclosed, not failures.
    crypto_ok = all(r["defended"] for r in results)
    print("🟢 ALL CRYPTOGRAPHIC GUARANTEES HELD (accepted limits disclosed honestly)"
          if crypto_ok else "🔴 A CRYPTOGRAPHIC GUARANTEE FAILED")
    return 0 if crypto_ok else 1


if __name__ == "__main__":
    sys.exit(main())
