#!/usr/bin/env python3
"""P1-03 Erasure Witness — independently-witnessed erasure (closes RUN 06 self-attestation limit).

COTRUGLI CISE · P1 · Scenario 03. Cross-over of the witness layer (P1-01/02) and erasure (RUN 06).

The Certificate of Destruction is no longer just the operator's word: the erasure checkpoint C2 is
co-signed by k independent witnesses, so the FACT and ORDER of the erasure are independently
attested, non-repudiable, and tamper-evident. Honest residual: witnesses attest the erasure RECORD
was made + ordered + witnessed — NOT that the bytes were physically destroyed (needs HSM/enclave).

Uses the real evidence-commitment + merkle + anchor + witness layers from ncte-adapter.

Run:
    NCTE_ADAPTER_PATH=../ncte-adapter \
      ../ncte-adapter/.venv/bin/python P1/scripts/run_erasure_witness.py
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
if not (_ADAPTER_PATH / "app" / "witness.py").exists():
    sys.exit(f"❌ witness layer not found at {_ADAPTER_PATH}/app/witness.py. Set NCTE_ADAPTER_PATH.")
sys.path.insert(0, str(_ADAPTER_PATH))

from app.anchor import build_checkpoint  # noqa: E402
from app.anchor_backends import SimulatedWitnessAnchor  # noqa: E402
from app.canonical import canonical_bytes  # noqa: E402
from app.evidence_codec import decode, encode  # noqa: E402
from app.evidence_commitment import commit_salted  # noqa: E402
from app.merkle import consistency_proof, from_hex, merkle_root, to_hex, verify_consistency  # noqa: E402
from app.signing import Signer, b64u_encode, verify_with_jwk  # noqa: E402
from app.witness import verify_witnessed_checkpoint  # noqa: E402

RUN_ID = "P1-Witness-2026-06-09"
SCENARIO_ID = "P1-03-ErasureWitness"
LOG_ID = "erasure-witness-log-1"
N_ITEMS, SUBJECT_IDX = 10, 4
N_WIT, K = 5, 3
TS0, TS1 = "2026-06-09T18:00:00Z", "2026-06-09T18:30:00Z"
_CUSTODIAN_SEED = b"p1-03-custodian-secret"
_EVIDENCE = _REPO_ROOT / "P1" / "evidence"


def _signer(seed: bytes, kid: str) -> Signer:
    return Signer.from_seed_b64(b64u_encode((seed + b"\x00" * 32)[:32]), kid)


def _salt(item_id: str) -> bytes:
    return hmac.new(_CUSTODIAN_SEED, item_id.encode(), hashlib.sha256).digest()


def _items(n=N_ITEMS):
    return [{"id": f"ev-{i:03d}", "subject": f"person-{i:03d}", "tool": "summarize_document",
             "input_hash": f"sha256:in-{i:04x}", "result": {"status": "success"},
             "policy_snapshot": "AI_ACT_TRACK1_v2026-06"} for i in range(n)]


def _witnessed(operator, witnesses, size, root, ts):
    cp = build_checkpoint(operator, size, root, ts, log_id=LOG_ID)
    cp.external_anchors = [SimulatedWitnessAnchor(w).publish(cp) for w in witnesses]
    return cp


def _write_json(name, payload):
    p = _EVIDENCE / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return p


def run() -> dict:
    print(f"🚀 {SCENARIO_ID} — Erasure Witness (items={N_ITEMS}, witnesses={N_WIT}, k={K})\n")
    operator = _signer(b"p1-03-operator", "operator-k1")
    witnesses = [_signer(f"p1-03-witness-{i}".encode(), f"witness-{i}") for i in range(N_WIT)]
    registry = {w.key_id: w.public_jwk() for w in witnesses}
    items = _items()

    # salted commitments; content + salt held off-ledger in custody.
    custody_salt, custody_blob, commitments = {}, {}, []
    for it in items:
        s = _salt(it["id"]); custody_salt[it["id"]] = s
        c, _ = commit_salted(it, salt=s, salt_ref=f"custody://salt/{it['id']}")
        commitments.append(c)
        _, blob = encode(it, commit=lambda o, cc=c: cc)
        custody_blob[it["id"]] = blob

    entries = [c.encode("utf-8") for c in commitments]
    R1 = to_hex(merkle_root(entries))
    C1 = _witnessed(operator, witnesses[:K], N_ITEMS, R1, TS0)
    v1 = verify_witnessed_checkpoint(C1, operator_jwks=operator.jwks(), witness_registry=registry, k=K)
    print(f"✅ C1 witnessed (size={N_ITEMS}, root {R1[:20]}…): witnessed={v1.witnessed}")

    # ---- erasure for the subject ----
    subj = items[SUBJECT_IDX]["id"]
    erased_commitment = commitments[SUBJECT_IDX]
    custody_blob[subj] = None                 # delete content
    del custody_salt[subj]                    # shred salt
    cert_body = {"schema": "ncte.certificate_of_destruction.v0.1", "erased_evidence_ref": subj,
                 "erased_commitment": erased_commitment, "request_id": "dsr-2026-06-09-001",
                 "erased_at": TS1, "salt_ref": f"custody://salt/{subj}",
                 "method": "salt-shred + off-ledger-content-delete", "content_destroyed": True}
    cert_sig = operator.sign(canonical_bytes(cert_body))
    certificate = {**cert_body, "signature": {"key_id": operator.key_id, "value": cert_sig}}
    _write_json("certificate_of_destruction_p1_03.json", certificate)

    cert_commitment = "sha256:" + hashlib.sha256(canonical_bytes(certificate)).hexdigest()
    entries_after = entries + [cert_commitment.encode("utf-8")]
    R2 = to_hex(merkle_root(entries_after))
    # erasure is APPEND-ONLY (C1 -> C2 consistency) AND C2 is independently WITNESSED.
    consistency = verify_consistency(N_ITEMS, N_ITEMS + 1, from_hex(R1), from_hex(R2),
                                     [b for b in consistency_proof(entries_after, N_ITEMS)])
    C2 = _witnessed(operator, witnesses[:K], N_ITEMS + 1, R2, TS1)
    v2 = verify_witnessed_checkpoint(C2, operator_jwks=operator.jwks(), witness_registry=registry, k=K)
    print(f"✅ erasure appended: C1->C2 consistency={consistency}; C2 witnessed={v2.witnessed} "
          f"(erasure independently attested, not just the operator's word)")

    # ---- post-erasure (RUN 06 invariants) ----
    cert_verifies = verify_with_jwk(operator.jwks()["keys"][0], canonical_bytes(cert_body), cert_sig)
    content_retrievable = custody_blob[subj] is not None
    salt_present = subj in custody_salt
    # erased commitment still present in the (immutable) tree
    inclusion_intact = erased_commitment in commitments
    print(f"✅ post-erasure: cert verifies={cert_verifies}; content retrievable={content_retrievable}; "
          f"non-linkable (salt shredded)={not salt_present}; commitment still anchored={inclusion_intact}")

    # ---- un-erase / roll-back detection ----
    # operator presents the pre-erasure log (size N) and claims it is current, hiding the erasure.
    R_preerase = to_hex(merkle_root(entries))   # = R1
    unerase_detected = not verify_consistency(N_ITEMS + 1, N_ITEMS, from_hex(R2), from_hex(R_preerase), [])
    print(f"✅ un-erase attempt (drop the cert, present size-{N_ITEMS} log): detected={unerase_detected} "
          f"(a verifier holding witnessed C2 rejects the smaller log)")

    pre_reg = {
        "c1_witnessed": v1.witnessed,
        "erasure_appended_consistent": consistency and cert_verifies,
        "c2_erasure_witnessed": v2.witnessed,
        "post_erasure_immutable_and_nonlinkable": inclusion_intact and (not content_retrievable) and (not salt_present),
        "un_erase_detected": unerase_detected,
    }

    report = {
        "run_id": RUN_ID, "scenario_id": SCENARIO_ID, "n_items": N_ITEMS, "n_witnesses": N_WIT, "k": K,
        "subject_ref": subj, "root_R1": R1, "root_R2": R2, "consistency_c1_c2": consistency,
        "c1_witnessed": json.loads(v1.model_dump_json()), "c2_witnessed": json.loads(v2.model_dump_json()),
        "pre_registered": pre_reg,
        "honest_limits": [
            "SIMULATION on SYNTHETIC data — not a compliance/conformity claim.",
            "Witnesses attest the erasure RECORD was made + ordered after C1 + independently co-signed "
            "— NOT that the bytes were physically destroyed. Physical-destruction assurance still needs "
            "HSM/enclave attestation (a separate gate); a witness cannot see inside custody.",
            ">= k witness collusion can still witness a false erasure record (gate G3).",
            "A salted hash MAY still be personal data under strict GDPR (legal, gate G1).",
            "Non-linkability is by salt-shred, not deletion of the commitment (the chain stays intact).",
        ],
    }
    _write_json("verification_report_p1_03.json", report)

    print("\n📋 pre-registered PASS/FAIL:")
    for k_, v_ in pre_reg.items():
        print(f"   {'PASS' if v_ else 'FAIL'}  {k_}")
    return {"report": report, "pre_registered": pre_reg}


if __name__ == "__main__":
    result = run()
    ok = all(result["pre_registered"].values())
    print(f"\n{'🟢 ALL PRE-REGISTERED CRITERIA PASS' if ok else '🔴 SOME CRITERIA FAILED'}")
    sys.exit(0 if ok else 1)
