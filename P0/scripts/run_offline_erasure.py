#!/usr/bin/env python3
"""P0-06 Offline Verification + Erasure — the honest I4/RT3 story.

COTRUGLI CISE · P0 Proof Spine Stress Test · Scenario 06 (final).

Two halves:
  (1) FULL OFFLINE VERIFICATION from only the public proof package, at two honest levels:
      - PUBLIC verifier (no salt): checkpoint signature + inclusion + commitment-bound. Cannot
        authenticate hidden content (the salted-commitment privacy property).
      - AUTHORIZED verifier (member_disclosure, holds the salt): additionally recomputes the salted
        commitment from content+salt -> content authenticated.
  (2) ERASURE: salted commitment + off-ledger content + salt-shred + a signed, APPENDED
      Certificate of Destruction (C1->C2 consistency). After erasure the content is gone, the salt
      is shredded, the commitment REMAINS anchored (immutability), but it is no longer linkable.

Honest limits (I4/RT3): a salted hash may still be personal data (legal, G1); the commitment stays
on the immutable log (non-linkability by shred, not deletion); the certificate attests the WORKFLOW
ran (custodian self-attests), not third-party-verified physical destruction; we cannot prove no
copy exists anywhere.

Run (with the ncte-adapter venv):
    NCTE_ADAPTER_PATH=../ncte-adapter \
      ../ncte-adapter/.venv/bin/python P0/scripts/run_offline_erasure.py
"""

from __future__ import annotations

import hashlib
import hmac
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
from app.canonical import canonical_bytes  # noqa: E402
from app.evidence_codec import decode, encode  # noqa: E402
from app.evidence_commitment import commit_salted  # noqa: E402
from app.merkle import (  # noqa: E402
    consistency_proof,
    from_hex,
    hash_leaf,
    inclusion_proof,
    merkle_root,
    to_hex,
    verify_consistency,
    verify_inclusion_hashed,
)
from app.signing import Signer, b64u_encode, verify_with_jwk  # noqa: E402

RUN_ID = "P0-AIAct-Track1-2026-06-09"
SCENARIO_ID = "P0-06-OfflineErasure"
N = 12
SUBJECT_IDX = 4
T0 = "2026-06-09T14:00:00Z"     # evidence anchored
T1 = "2026-06-09T14:30:00Z"     # erasure executed (T1 > T0)
# Custodian secret seed. In production salts are RANDOM and shredding is irreversible; here the
# salt is HMAC(seed, id) so the pre-erasure ROOT is reproducible for the determinism check. "Shred"
# models the salt becoming unavailable to ALL parties (verifiers never had it; custody deletes it).
_CUSTODIAN_SEED = b"cotrugli-cise-p0-custodian-secret-06"
_DEMO_SEED = b"cotrugli-cise-p0-erasure-seed-006"
_KEY_ID = "cise-p0-erasure-custodian-k1"
_EVIDENCE_DIR = _REPO_ROOT / "P0" / "evidence"


def _items(n: int = N) -> list[dict]:
    return [{"id": f"ev-{i:03d}", "subject": f"person-{i:03d}", "timestamp": f"2026-06-09T14:00:{i:02d}Z",
             "tool": "summarize_document", "input_hash": f"sha256:input-{i:04x}",
             "result": {"status": "success", "note_hash": f"sha256:note-{i:04x}"},
             "policy_snapshot": "AI_ACT_TRACK1_v2026-06", "privacy_mode": "hash_only"} for i in range(n)]


def _salt_for(item_id: str) -> bytes:
    return hmac.new(_CUSTODIAN_SEED, item_id.encode(), hashlib.sha256).digest()


def _signer() -> Signer:
    return Signer.from_seed_b64(b64u_encode((_DEMO_SEED + b"\x00" * 32)[:32]), _KEY_ID)


def _write_json(name: str, payload) -> Path:
    path = _EVIDENCE_DIR / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def run() -> dict:
    print(f"🚀 {SCENARIO_ID} — Offline Verification + Erasure\n")
    signer = _signer()
    items = _items()

    # Build salted commitments; content + salt held OFF-LEDGER in custody; only commitments anchored.
    custody_salt: dict[str, bytes] = {}
    custody_blob: dict[str, str | None] = {}
    commitments: list[str] = []
    for it in items:
        salt = _salt_for(it["id"]); custody_salt[it["id"]] = salt
        commitment, _ = commit_salted(it, salt=salt, salt_ref=f"custody://salt/{it['id']}")
        commitments.append(commitment)
        _, blob = encode(it, commit=lambda o, c=commitment: c)   # store compressed content off-ledger
        custody_blob[it["id"]] = blob

    entries = [c.encode("utf-8") for c in commitments]
    R1 = to_hex(merkle_root(entries))
    C1 = build_checkpoint(signer, N, R1, T0, log_id="erasure-log-1")
    proofs = [[to_hex(p) for p in inclusion_proof(entries, i)] for i in range(N)]
    print(f"✅ anchored {N} salted-committed items: C1 size={N} root={R1[:24]}…")

    public_package = {
        "run_id": RUN_ID, "scenario_id": SCENARIO_ID,
        "checkpoint": json.loads(C1.model_dump_json()), "jwks": signer.jwks(),
        "commitments": commitments, "inclusion_proofs": proofs, "tree_size": N,
    }
    _write_json("proof_package_06.json", public_package)

    # ---- Phase 1: FULL OFFLINE VERIFICATION from the public package ----
    def public_verify(i: int) -> bool:
        return (verify_checkpoint(public_package["jwks"], C1) and
                verify_inclusion_hashed(hash_leaf(entries[i]), i, N,
                                        [from_hex(p) for p in proofs[i]], from_hex(R1)))

    def authorized_verify(i: int) -> bool:
        """Member-disclosure: holds the salt + content -> recompute the salted commitment."""
        item_id = items[i]["id"]
        blob = custody_blob.get(item_id)
        salt = custody_salt.get(item_id)
        if blob is None or salt is None:
            return False                      # content gone or salt shredded -> cannot authenticate
        content = decode(blob)
        recomputed, _ = commit_salted(content, salt=salt, salt_ref=f"custody://salt/{item_id}")
        return recomputed == commitments[i]

    public_all = all(public_verify(i) for i in range(N))
    authorized_all = all(authorized_verify(i) for i in range(N))
    print(f"✅ PUBLIC offline verify (no salt): {public_all} (checkpoint+inclusion+commitment-bound)")
    print(f"✅ AUTHORIZED offline verify (with salt): {authorized_all} (content authenticated)")

    # ---- Phase 2: ERASURE for the subject (delete content + shred salt) ----
    subj = items[SUBJECT_IDX]["id"]
    erased_commitment = commitments[SUBJECT_IDX]
    custody_blob[subj] = None              # delete off-ledger content
    del custody_salt[subj]                 # SHRED the salt (irreversible in production)
    print(f"\n🗑  erasure request executed for {subj}: content deleted + salt shredded")

    # Certificate of Destruction — signed, then APPENDED to the log (erasure is a NEW record).
    cert_body = {
        "schema": "ncte.certificate_of_destruction.v0.1",
        "erased_evidence_ref": subj, "erased_commitment": erased_commitment,
        "request_id": "dsr-2026-06-09-001", "erased_at": T1,
        "salt_ref": f"custody://salt/{subj}",
        "method": "salt-shred + off-ledger-content-delete",
        "content_destroyed": True, "commitment_retained_for_chain_integrity": True,
    }
    cert_sig = signer.sign(canonical_bytes(cert_body))
    certificate = {**cert_body, "signature": {"key_id": signer.key_id, "value": cert_sig}}
    _write_json("certificate_of_destruction.json", certificate)

    cert_commitment = "sha256:" + hashlib.sha256(canonical_bytes(certificate)).hexdigest()
    entries_after = entries + [cert_commitment.encode("utf-8")]
    R2 = to_hex(merkle_root(entries_after))
    C2 = build_checkpoint(signer, N + 1, R2, T1, log_id="erasure-log-1")
    cons = verify_consistency(N, N + 1, from_hex(R1), from_hex(R2),
                              [b for b in consistency_proof(entries_after, N)])
    print(f"✅ Certificate of Destruction signed + appended: C1->C2 consistency verifies = {cons}")

    # ---- Phase 3: post-erasure checks ----
    inclusion_intact = public_verify(SUBJECT_IDX)                 # commitment still anchored
    content_retrievable = custody_blob[subj] is not None         # content gone
    still_linkable = authorized_verify(SUBJECT_IDX)              # salt shredded -> cannot recompute
    cert_verifies = verify_with_jwk(signer.jwks()["keys"][0], canonical_bytes(cert_body), cert_sig)
    others_unaffected = all(authorized_verify(i) for i in range(N) if i != SUBJECT_IDX)

    print(f"✅ post-erasure: inclusion still verifies (immutability)={inclusion_intact}; "
          f"content retrievable={content_retrievable}; still linkable={still_linkable}; "
          f"certificate verifies={cert_verifies}; other items unaffected={others_unaffected}")

    report = {
        "run_id": RUN_ID, "scenario_id": SCENARIO_ID, "n_items": N, "subject_ref": subj,
        "root_R1": R1, "root_R2": R2, "consistency_c1_c2": cons,
        "public_offline_verify_all": public_all, "authorized_offline_verify_all": authorized_all,
        "post_erasure": {
            "inclusion_still_verifies": inclusion_intact,
            "content_retrievable": content_retrievable,
            "still_linkable_without_salt": still_linkable,
            "certificate_verifies": cert_verifies,
            "other_items_unaffected": others_unaffected,
        },
        "honest_limits": [
            "SIMULATION on SYNTHETIC data — not a compliance/conformity claim.",
            "A salted hash MAY still be personal data under strict GDPR — a LEGAL question (gate G1), "
            "not resolvable by code; we do not claim it is anonymous.",
            "The commitment STAYS on the immutable log: non-linkability is by salt-shred, NOT deletion "
            "(deleting the commitment would break the chain). Deleting the commitment itself conflicts "
            "with immutability -> prunable anchoring / legal opinion (P1+).",
            "The Certificate of Destruction is an ATTESTED WORKFLOW (custodian self-attests); "
            "third-party-verified physical destruction needs an independent witness / HSM-enclave "
            "attestation (P1+).",
            "We cannot prove NO COPY exists anywhere (backups, caches) — only that the controlled "
            "store ran the prescribed erasure and the commitment is no longer subject-linkable.",
            "In production the salt is RANDOM and shredding is irreversible; here it is seed-derived "
            "for reproducibility, and 'shred' models the salt becoming unavailable to all parties.",
        ],
    }
    _write_json("verification_report_06.json", report)

    pre_reg = {
        "full_offline_verification_public_and_authorized": public_all and authorized_all,
        "erasure_appends_signed_certificate_consistent": cons and cert_verifies,
        "post_erasure_inclusion_immutable": inclusion_intact,
        "post_erasure_content_not_retrievable": not content_retrievable,
        "post_erasure_non_linkable": not still_linkable,
        "other_items_unaffected": others_unaffected,
    }
    print("\n📋 pre-registered PASS/FAIL:")
    for k, v in pre_reg.items():
        print(f"   {'PASS' if v else 'FAIL'}  {k}")
    return {"report": report, "pre_registered": pre_reg, "root_R1": R1}


if __name__ == "__main__":
    result = run()
    ok = all(result["pre_registered"].values())
    print(f"\n{'🟢 ALL PRE-REGISTERED CRITERIA PASS' if ok else '🔴 SOME CRITERIA FAILED'}")
    sys.exit(0 if ok else 1)
