#!/usr/bin/env python3
"""G3 Witness Economics — a small, sharp economic simulation (gate validation).

COTRUGLI CISE · Gate G3. The witness layer's CRYPTO is already proven (P1-01/02/03). This validates
the INCENTIVE layer: does a parameterization exist where corrupting the witnesses is economically
irrational and no single funder controls a quorum?

It models four things, deterministically (no wall-clock, no RNG):
  1. cost-to-corrupt:        k * (stake + NPV(future income)) vs the value of a lie G
  2. blind pool + rotation:  per-client targeting is impossible -> must corrupt a pool-wide quorum
  3. gradual corruption:     over R rounds, attacker bribes while slashing+replacement removes the
                             caught (detection comes from P1-01/02); does the SIMULTANEOUS corrupted
                             count ever reach k?
  4. single-funder guard:    no funder may cover >= (n-k+1) witnesses (else it can buy/disable a quorum)

Run (no dependencies):
    python3 P1/scripts/run_g3_witness_economics.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_GATES = _REPO_ROOT / "gates"


def npv(per_round: float, horizon: int, discount: float) -> float:
    """Net present value of a fixed per-round income over a horizon."""
    return sum(per_round * (discount ** t) for t in range(horizon))


def bribe_cost(stake: float, income_per_round: float, horizon: int, discount: float) -> float:
    """What it costs to flip one witness: its forfeited stake + the future income it loses if caught."""
    return stake + npv(income_per_round, horizon, discount)


def cost_to_corrupt(k: int, stake: float, income_per_round: float, horizon: int, discount: float) -> float:
    return k * bribe_cost(stake, income_per_round, horizon, discount)


# 2) blind pool: per-client targeting is impossible.
def blind_pool_targeting(n: int, k: int, blind: bool) -> dict:
    """With a blind pool + rotation, the attacker can't bribe 'the witness for client X' (it doesn't
    know who signs X). It must corrupt a quorum of the WHOLE pool -> the cost is layer-wide, not
    per-client. Without blindness, the attacker targets the specific signer(s) -> far cheaper."""
    targets_needed = k if blind else 1
    return {"blind": blind, "witnesses_attacker_must_corrupt": targets_needed,
            "note": ("blind pool -> must corrupt a pool-wide quorum (k)" if blind
                     else "non-blind -> target the specific signer(s) (pay-to-play)")}


# 3) gradual corruption over rounds, with slashing + replacement.
def gradual_corruption(rounds: int, attacker_budget_per_round: float, bribe: float,
                       detection_lag: int, k: int, n: int) -> dict:
    """Each round the attacker corrupts `floor(budget/bribe)` fresh witnesses. A corrupted witness is
    caught after `detection_lag` rounds (any honest witness/observer triggers equivocation, P1-01/02),
    then slashed and replaced by an honest one. Track the SIMULTANEOUSLY-corrupted count."""
    new_per_round = int(attacker_budget_per_round // bribe)
    corrupted_active: list = []          # rounds at which currently-active corruptions were created
    timeline = []
    break_round = None
    for r in range(rounds):
        # add this round's freshly corrupted (capped by available honest witnesses)
        available_honest = n - len(corrupted_active)
        added = min(new_per_round, max(0, available_honest))
        corrupted_active.extend([r] * added)
        # slash+replace those whose detection_lag has elapsed
        corrupted_active = [cr for cr in corrupted_active if r - cr < detection_lag]
        simultaneous = len(corrupted_active)
        timeline.append({"round": r, "added": added, "simultaneous_corrupted": simultaneous})
        if simultaneous >= k and break_round is None:
            break_round = r
    return {"new_per_round": new_per_round, "detection_lag": detection_lag,
            "max_simultaneous_corrupted": max((t["simultaneous_corrupted"] for t in timeline), default=0),
            "break_round": break_round, "broke": break_round is not None,
            "budget_per_round_to_break": (k / detection_lag) * bribe}


# 4) single-funder guard rail.
def single_funder_guard(funder_coverage: dict, n: int, k: int) -> dict:
    """No funder may cover >= (n-k+1) witnesses, else it can withdraw to drop availability below k OR
    capture a quorum. `funder_coverage` maps funder -> #witnesses it funds."""
    cap = n - k + 1
    worst = max(funder_coverage.values()) if funder_coverage else 0
    worst_funder = max(funder_coverage, key=funder_coverage.get) if funder_coverage else None
    return {"guard_cap_exclusive": cap, "max_single_funder_coverage": worst,
            "worst_funder": worst_funder, "ok": worst < cap}


def evaluate(scenario: dict) -> dict:
    s = scenario
    bribe = bribe_cost(s["stake"], s["income_per_round"], s["horizon"], s["discount"])
    c2c = cost_to_corrupt(s["k"], s["stake"], s["income_per_round"], s["horizon"], s["discount"])
    cost_gt_gain = c2c > s["value_of_lie_G"]
    grad = gradual_corruption(s["rounds"], s["attacker_budget_per_round"], bribe,
                              s["detection_lag"], s["k"], s["n"])
    guard = single_funder_guard(s["funder_coverage"], s["n"], s["k"])
    blind = blind_pool_targeting(s["n"], s["k"], s["blind_pool"])

    go = cost_gt_gain and (not grad["broke"]) and guard["ok"] and blind["witnesses_attacker_must_corrupt"] == s["k"]
    reasons = []
    if not cost_gt_gain:
        reasons.append(f"cost-to-corrupt {c2c:,.0f} <= value-of-lie {s['value_of_lie_G']:,.0f}")
    if grad["broke"]:
        reasons.append(f"gradual corruption reaches k at round {grad['break_round']} "
                       f"(attacker budget {s['attacker_budget_per_round']:,.0f}/round >= "
                       f"{grad['budget_per_round_to_break']:,.0f} break threshold)")
    if not guard["ok"]:
        reasons.append(f"single funder covers {guard['max_single_funder_coverage']} >= cap "
                       f"{guard['guard_cap_exclusive']} (can buy/disable a quorum)")
    if not blind["witnesses_attacker_must_corrupt"] == s["k"]:
        reasons.append("non-blind pool -> per-client targeting (pay-to-play)")

    return {"scenario": s["name"], "bribe_cost_per_witness": round(bribe, 2),
            "cost_to_corrupt_k": round(c2c, 2), "value_of_lie_G": s["value_of_lie_G"],
            "cost_gt_gain": cost_gt_gain, "gradual": grad, "single_funder_guard": guard,
            "blind_pool": blind, "verdict": "GO" if go else "NO-GO", "reasons": reasons}


# --------------------------------------------------------------------------- #
# Scenarios: a GO (AI Act evidence, low G, disciplined funding) and two NO-GO probes.
# --------------------------------------------------------------------------- #
SCENARIOS = [
    {"name": "ai_act_evidence_disciplined (target GO)", "n": 7, "k": 4,
     "stake": 100_000, "income_per_round": 5_000, "horizon": 20, "discount": 0.95,
     "value_of_lie_G": 200_000, "rounds": 30, "attacker_budget_per_round": 200_000,
     "detection_lag": 2, "blind_pool": True,
     "funder_coverage": {"coverage_fee_pool": 2, "consortium": 2, "eu_public": 2, "stake_yield": 1}},
    {"name": "high_stakes_settlement (NO-GO: G too high for these params)", "n": 7, "k": 4,
     "stake": 100_000, "income_per_round": 5_000, "horizon": 20, "discount": 0.95,
     "value_of_lie_G": 2_000_000, "rounds": 30, "attacker_budget_per_round": 200_000,
     "detection_lag": 2, "blind_pool": True,
     "funder_coverage": {"coverage_fee_pool": 2, "consortium": 2, "eu_public": 2, "stake_yield": 1}},
    {"name": "operator_funds_everyone (NO-GO: funder capture)", "n": 7, "k": 4,
     "stake": 100_000, "income_per_round": 5_000, "horizon": 20, "discount": 0.95,
     "value_of_lie_G": 200_000, "rounds": 30, "attacker_budget_per_round": 200_000,
     "detection_lag": 2, "blind_pool": True,
     "funder_coverage": {"operator_treasury": 7}},
]


def run() -> dict:
    print("🚀 G3 Witness Economics — economic validation of the witness layer\n")
    results = [evaluate(s) for s in SCENARIOS]
    for r in results:
        print(f"[{r['verdict']}] {r['scenario']}")
        print(f"    bribe/witness={r['bribe_cost_per_witness']:,.0f} · cost-to-corrupt-k="
              f"{r['cost_to_corrupt_k']:,.0f} vs G={r['value_of_lie_G']:,.0f} (cost>gain={r['cost_gt_gain']})")
        print(f"    gradual: new/round={r['gradual']['new_per_round']}, max-simultaneous="
              f"{r['gradual']['max_simultaneous_corrupted']}/{SCENARIOS[0]['k']}, broke={r['gradual']['broke']} "
              f"(break threshold {r['gradual']['budget_per_round_to_break']:,.0f}/round)")
        print(f"    single-funder guard: max-coverage={r['single_funder_guard']['max_single_funder_coverage']} "
              f"< cap {r['single_funder_guard']['guard_cap_exclusive']} -> ok={r['single_funder_guard']['ok']}")
        print(f"    blind pool: attacker must corrupt {r['blind_pool']['witnesses_attacker_must_corrupt']} witnesses")
        if r["reasons"]:
            for reason in r["reasons"]:
                print(f"    ⚠ {reason}")
        print()

    go_no_go = {
        "GO_criteria": [
            "cost-to-corrupt (k*(stake+NPV income)) > value-of-lie G, with margin",
            "no single funder covers >= (n-k+1) witnesses (single-funder guard rail)",
            "under gradual corruption (slashing+replacement), simultaneous corrupted stays < k "
            "for the horizon given the attacker's per-round budget",
            "blind pool + rotation: the attacker must corrupt a pool-wide quorum (no per-client targeting)",
        ],
        "NO_GO": "if any GO criterion fails -> reformulate (raise stake/n, lower G via use-case choice, "
                 "diversify funders, or strengthen detection/slashing).",
        "results": results,
    }
    _GATES.mkdir(parents=True, exist_ok=True)
    (_GATES / "G3_economics_sim_results.json").write_text(
        json.dumps(go_no_go, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    primary = results[0]
    print(f"📋 PRIMARY scenario verdict (AI Act evidence, disciplined): {primary['verdict']}")
    print("   (the two NO-GO probes confirm the gate DISCRIMINATES: it fails on funder-capture and on too-high G)")
    return {"results": results, "primary": primary}


if __name__ == "__main__":
    out = run()
    # Exit 0 if the gate discriminates correctly: primary=GO and the two probes=NO-GO.
    ok = (out["results"][0]["verdict"] == "GO"
          and out["results"][1]["verdict"] == "NO-GO"
          and out["results"][2]["verdict"] == "NO-GO")
    print(f"\n{'🟢 GATE DISCRIMINATES (GO on disciplined AI Act; NO-GO on capture/high-G)' if ok else '🔴 CHECK SCENARIOS'}")
    sys.exit(0 if ok else 1)
