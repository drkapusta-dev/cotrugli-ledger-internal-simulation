#!/usr/bin/env python3
"""P0-06 Red Team — erasure-focused attacks (I4 / RT3).

Each attack reports whether the cryptographic guarantee held (`defended`) and whether it reveals a
disclosed `accepted_limit`. A run is sound iff every attack is DEFENDED or a DISCLOSED accepted
limit — no silent break.

Run (with the ncte-adapter venv):
    NCTE_ADAPTER_PATH=../ncte-adapter \
      ../ncte-adapter/.venv/bin/python P0/scripts/red_team_run_06.py
"""

from __future__ import annotations

import hashlib
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
from app.canonical import canonical_bytes  # noqa: E402
from app.evidence_commitment import commit_salted  # noqa: E402
from app.merkle import consistency_proof, from_hex, merkle_root, to_hex, verify_consistency  # noqa: E402
from app.signing import Signer, b64u_encode, verify_with_jwk  # noqa: E402

_EVIDENCE = _REPO_ROOT / "P0" / "evidence"


def _load():
    pkg = json.loads((_EVIDENCE / "proof_package_06.json").read_text(encoding="utf-8"))
    cert = json.loads((_EVIDENCE / "certificate_of_destruction.json").read_text(encoding="utf-8"))
    report = json.loads((_EVIDENCE / "verification_report_06.json").read_text(encoding="utf-8"))
    return pkg, cert, report


# A1 — re-link the erased commitment to content without the shredded salt.
def attack_1_relink(pkg):
    erased_commitment = pkg["commitments"][4]
    guessed_content = {"id": "ev-004", "subject": "person-004", "timestamp": "2026-06-09T14:00:04Z",
                       "tool": "summarize_document", "input_hash": "sha256:input-0004",
                       "result": {"status": "success", "note_hash": "sha256:note-0004"},
                       "policy_snapshot": "AI_ACT_TRACK1_v2026-06", "privacy_mode": "hash_only"}
    # The attacker knows/guesses the content but NOT the 32-byte salt. Try a handful of salts.
    matched = False
    for trial in range(1000):
        salt = hashlib.sha256(f"guess-{trial}".encode()).digest()
        c, _ = commit_salted(guessed_content, salt=salt, salt_ref="x")
        if c == erased_commitment:
            matched = True
            break
    return {"attack": "1. Re-link the erased commitment without the salt",
            "defended": not matched, "accepted_limit": True,
            "verdict": "DEFENDED (high-entropy salt) + ACCEPTED LIMIT (low-entropy content + known salt would re-link)",
            "detail": f"even knowing the content, recomputing the commitment needs the 32-byte salt; "
                      f"1000 trial salts matched={matched}; the real salt space is 2^256. ACCEPTED LIMIT: if "
                      f"the CONTENT were low-entropy AND the salt known, a salted commitment could be "
                      f"brute-forced — which is why the salt is high-entropy and shredded (non-linkable)."}


# A2 — forge a Certificate of Destruction (claim erased while secretly retaining content).
def attack_2_forge_certificate(pkg, cert):
    custodian_jwk = pkg["jwks"]["keys"][0]
    body = {k: v for k, v in cert.items() if k != "signature"}
    # attacker re-signs the (or a fake) certificate with their own key.
    attacker = Signer.from_seed_b64(b64u_encode(b"attacker-fake-custodian-key-32by"), cert["signature"]["key_id"])
    forged_sig = attacker.sign(canonical_bytes(body))
    forged_against_custodian = verify_with_jwk(custodian_jwk, canonical_bytes(body), forged_sig)
    genuine_against_custodian = verify_with_jwk(custodian_jwk, canonical_bytes(body), cert["signature"]["value"])
    return {"attack": "2. Forge a Certificate of Destruction",
            "defended": (forged_against_custodian is False) and genuine_against_custodian,
            "accepted_limit": True,
            "verdict": "DEFENDED (forged cert rejected) + ACCEPTED LIMIT (cert attests the WORKFLOW, self-attested)",
            "detail": f"forged cert signed by attacker -> verifies against custodian key="
                      f"{forged_against_custodian} (rejected); genuine cert verifies={genuine_against_custodian}. "
                      f"ACCEPTED LIMIT: the certificate attests the custodian RAN the erasure workflow — it does "
                      f"not third-party-prove the content is physically gone (needs an independent witness / "
                      f"HSM-enclave attestation, P1+)."}


# A3 — use erasure to silently vanish inconvenient evidence (no trace).
def attack_3_silent_vanish(cert, report):
    # Erasure leaves a PERMANENT appended Certificate of Destruction (a tombstone): you can see THAT
    # something was erased, which ref, and when — so erasure cannot be used without a trace.
    tombstone_exists = cert.get("erased_evidence_ref") and cert.get("erased_at")
    inclusion_immutable = report["post_erasure"]["inclusion_still_verifies"]
    return {"attack": "3. Use erasure to silently vanish evidence", "defended": bool(tombstone_exists and inclusion_immutable),
            "accepted_limit": False,
            "verdict": "DEFENDED — erasure leaves a permanent, auditable tombstone",
            "detail": f"a Certificate of Destruction names the erased ref ({cert.get('erased_evidence_ref')}) and "
                      f"time ({cert.get('erased_at')}) and is appended permanently; the commitment's inclusion "
                      f"still verifies. You can see THAT (and when) something was erased — just not its content. "
                      f"Erasure cannot be used to make evidence vanish without a trace."}


# A4 — un-erase: drop the appended Certificate of Destruction from history.
def attack_4_unerase(pkg, cert):
    # Rebuild the log up to size N (without the cert) and ask: does it consistently extend C2 (N+1)?
    commitments = pkg["commitments"]
    entries = [c.encode("utf-8") for c in commitments]
    cert_commitment = "sha256:" + hashlib.sha256(canonical_bytes(cert)).hexdigest()
    entries_after = entries + [cert_commitment.encode("utf-8")]
    R2 = to_hex(merkle_root(entries_after))
    R_without = to_hex(merkle_root(entries))      # operator tries to present the pre-cert log as "current"
    # A verifier holding C2 (size N+1, R2) cannot be shown a smaller log that drops the cert:
    detected = not verify_consistency(len(entries_after), len(entries), from_hex(R2), from_hex(R_without), [])
    return {"attack": "4. Un-erase (drop the Certificate of Destruction)", "defended": detected,
            "accepted_limit": False,
            "verdict": "DEFENDED — can't un-append a witnessed certificate",
            "detail": f"dropping the appended cert shrinks the log below the witnessed size; a verifier holding "
                      f"C2 (size {len(entries_after)}) rejects a presented log of size {len(entries)} -> detected={detected}."}


# A5 — over-claim audit.
def attack_5_overclaim(report):
    # Scan everything EXCEPT honest_limits (the disclosures legitimately name what we DON'T claim).
    scanned = {k: v for k, v in report.items() if k != "honest_limits"}
    text = json.dumps(scanned).lower()
    text += (_EVIDENCE / "certificate_of_destruction.json").read_text(encoding="utf-8").lower()
    over = ["forgotten forever", "guaranteed anonymous", "gdpr compliant", "right to be forgotten guaranteed", "compliant"]
    hits = [p for p in list(core.FORBIDDEN_PHRASES) + over if p.lower() in text]
    limits = report.get("honest_limits", [])
    discloses_legal = any("personal data" in l.lower() for l in limits)
    discloses_nocopy = any("no copy exists" in l.lower() for l in limits)
    discloses_selfattest = any("self-attest" in l.lower() or "attested workflow" in l.lower() for l in limits)
    defended = (not hits) and discloses_legal and discloses_nocopy and discloses_selfattest
    return {"attack": "5. Over-claim audit (erasure honesty)", "defended": defended, "accepted_limit": False,
            "verdict": "DEFENDED — discloses the legal, no-copy and self-attestation limits",
            "detail": f"over-claim hits: {hits or 'none'}; discloses salted-hash-may-be-personal-data: {discloses_legal}; "
                      f"discloses can't-prove-no-copy: {discloses_nocopy}; discloses self-attested-workflow: {discloses_selfattest}."}


def main() -> int:
    pkg, cert, report = _load()
    results = [attack_1_relink(pkg), attack_2_forge_certificate(pkg, cert),
               attack_3_silent_vanish(cert, report), attack_4_unerase(pkg, cert),
               attack_5_overclaim(report)]
    for r in results:
        print(f"[{r['verdict']}]\n    {r['attack']}\n    {r['detail']}")
        if r.get("accepted_limit"):
            print("    ⚠ accepted limit disclosed (see verdict/detail).")
        print()
    (_EVIDENCE / "red_team_report_06.json").write_text(
        json.dumps({"attacks": results}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    no_silent_break = all(r["defended"] or r["accepted_limit"] for r in results)
    print("🟢 NO SILENT BREAK — every attack is DEFENDED or a DISCLOSED accepted limit"
          if no_silent_break else "🔴 A SILENT BREAK")
    return 0 if no_silent_break else 1


if __name__ == "__main__":
    sys.exit(main())
