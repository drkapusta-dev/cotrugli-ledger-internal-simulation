#!/usr/bin/env python3
"""
P0-01 Happy Path Batch Simulation
"""

import json
from datetime import datetime
from pathlib import Path

# Za sada simuliramo - kasnije ćemo importati pravi codec
def simulate_happy_path_batch(num_items=30):
    print(f"🚀 Starting Happy Path Batch Simulation - {num_items} items\n")
    
    evidence_items = []
    
    for i in range(num_items):
        item = {
            "id": f"tool-call-{i:03d}",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "agent_id": "agent-prod-742",
            "tool": "get_financial_summary",
            "input_hash": f"input-hash-{i:04x}",
            "result": {
                "status": "success",
                "balance_eur": 12450.75 + i,
                "currency": "EUR",
                "risk_level": "low"
            },
            "mandate": "read-only-financial",
            "policy_snapshot": "AI_ACT_TRACK1_v2026-06"
        }
        evidence_items.append(item)
    
    print(f"✅ Generated {num_items} synthetic evidence items")
    print(f"📦 Ready for Evidence Codec v0.2 processing")
    
    # Sačuvaj za daljnje korištenje
    output_path = Path("P0/evidence/happy_path_batch_input.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(evidence_items, indent=2))
    
    print(f"💾 Saved input to {output_path}")
    print("\nSljedeći korak: Evidence Codec + Batch Anchoring")
    
    return evidence_items

if __name__ == "__main__":
    simulate_happy_path_batch(30)
