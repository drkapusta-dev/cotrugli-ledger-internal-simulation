# 01_Happy_Path_Batch.md

**Scenario ID:** P0-01-HappyPath  
**Description:** Normal operation - 30 agent tool calls in one batch (AI Act Track 1 evidence)

### Objective
Verify that the full chain works cleanly:  
Raw evidence → Codec (lossless) → Merkle batch → Anchor checkpoint → Offline verification

### Pre-registered Pass/Fail Criteria
- All 30 items successfully encoded and batched: **PASS**
- Merkle root correctly calculated and checkpoint signed: **PASS**
- All inclusion proofs valid: **PASS**
- Full offline verification successful: **PASS**
- Neutrality & claim discipline maintained (no overclaiming): **PASS**
- Vučja otpornost (basic tampering resistance): ≥ 8.0
- Ovčja os (clarity of output): ≥ 6.0

### Execution Steps
1. Enterprise Agent generates 30 synthetic tool calls (balance checks, document summaries, etc.)
2. Vanguard Gateway (simulated) captures them
3. Evidence Codec v0.2 encodes each item (lossless + preview)
4. Create batch + Merkle tree
5. Build signed checkpoint via evidence_anchor.py
6. Independent Verifier does full offline verification using only public proof package

### Expected Artifacts
- 30 EvidenceBlob entries
- 1 EvidenceBatch + checkpoint
- Inclusion proofs for all items
- Verification report

**Status:** Ready to execute  
**Next:** Grok will prepare the actual test data and simulation when Drazen says "RUN 01"
