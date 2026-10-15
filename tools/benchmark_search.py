"""Deterministic synthetic search comparison; never connects to a panel or network.

All strategies receive the same candidate, HTTP-request, traffic, apply and time
budgets and the same screening/confirmation policy. Only their candidate ordering
differs. Virtual seconds are an explicit cost model, not measured VPN timings.
No-result runs remain in every aggregate and in the exported per-run records.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import statistics
import sys
from collections import deque
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.parameters.generator import CombinationGenerator
from app.parameters.models import ParameterSpec
from app.testing import search
from app.testing.search import AdaptiveScheduler, SearchBudget

SCENARIOS = ("broken_baseline_joint", "triple_interaction", "rare_profile", "transient",
             "endpoint_failure", "expensive_apply", "no_working_configuration")
STRATEGIES = ("mutation", "pairwise", "exhaustive", "adaptive")


def parameters(scenario: str) -> list[ParameterSpec]:
    if scenario == "rare_profile":
        return [ParameterSpec.from_dict("network", {"type": "enum", "values": ["tcp", "ws", "grpc", "xhttp"],
                                                      "baseline": "tcp", "path": ["streamSettings", "network"]}),
                ParameterSpec.from_dict("security", {"type": "enum", "values": ["none", "tls"],
                                                       "baseline": "none", "path": ["streamSettings", "security"]}),
                ParameterSpec.from_dict("flag", {"type": "integer", "values": [0, 1], "baseline": 0})]
    return [ParameterSpec.from_dict(name, {"type": "integer", "values": [0, 1], "baseline": 0}) for name in "abcd"]


def working(scenario: str, values: dict[str, Any]) -> bool:
    if scenario == "no_working_configuration":
        return False
    if scenario == "rare_profile":
        return values["network"] == "xhttp" and values["security"] == "tls" and values["flag"] == 1
    if scenario == "triple_interaction":
        return values["a"] == values["b"] == values["c"] == 1
    return values["a"] == values["b"] == 1


def response(scenario: str, values: dict[str, Any], digest: str, trial: int, seed: int) -> tuple[bool, bool]:
    """Shared deterministic oracle: ordering in another strategy cannot change it."""
    if not working(scenario, values):
        return False, False
    if scenario == "transient":
        noise = int.from_bytes(hashlib.sha256(f"{seed}:{digest}:{trial}".encode()).digest()[:8], "big") / 2**64
        if noise < .2:
            return False, True
    return True, False


def simulate(strategy: str, scenario: str, seed: int = 0, *, candidate_limit: int = 12,
             request_budget: int = 32, time_budget_seconds: float = 90) -> dict[str, Any]:
    if strategy not in STRATEGIES or scenario not in SCENARIOS:
        raise ValueError("Unknown synthetic strategy or scenario")
    generator = CombinationGenerator(parameters(scenario), protocol="vless")
    scheduler = (AdaptiveScheduler(generator.iter_adaptive(candidate_limit, seed=seed))
                 if strategy == "adaptive" else None)
    if strategy == "mutation":
        queue = deque(generator.mutation_seeds())
    elif strategy == "pairwise":
        queue = deque((item, frozenset()) for item in generator.iter_pairwise(candidate_limit))
    elif strategy == "exhaustive":
        queue = deque((item, frozenset()) for item in itertools.islice(generator.iter_valid(), candidate_limit))
    else:
        queue = deque()

    clock = [0.0]
    real_monotonic = search.time.monotonic
    search.time.monotonic = lambda: clock[0]
    try:
        options = {"request_budget": request_budget, "traffic_budget_bytes": 64 * 1024,
                   "apply_budget": candidate_limit, "time_budget_seconds": time_budget_seconds}
        budget = SearchBudget(options, candidate_limit)
        applied_cost = 20.0 if scenario == "expensive_apply" else 2.0
        seen = set()
        next_runs: dict[str, int] = {}
        first_viable = None
        confirmed_at = None
        confirmed_hash = None
        reference_failures = 0
        termination = "frontier_exhausted"

        def permits(*, new: bool, confirmation: bool = False) -> bool:
            needed = (applied_cost if new else 0) + .35 + (.25 if confirmation else 0)
            return (budget.remaining_time() >= needed and budget.permits(
                requests=1, response_bytes=2048 if confirmation else 512,
                api_applies=1 if new else 0, new_candidate=new))

        def exhausted_reason(*, new: bool, confirmation: bool = False) -> str:
            if budget.used["candidates"] >= candidate_limit and new:
                return "candidate_budget"
            if budget.used["requests"] >= request_budget:
                return "request_budget"
            if budget.used["traffic_bytes"] + (2048 if confirmation else 512) > options["traffic_budget_bytes"]:
                return "traffic_budget"
            if new and budget.used["api_applies"] >= candidate_limit:
                return "apply_budget"
            return "time_budget"

        def trial(candidate, *, new: bool = False, confirmation: bool = False):
            clock[0] += (applied_cost if new else 0) + .35 + (.25 if confirmation else 0)
            number = next_runs.get(candidate.hash, 0) + 1
            next_runs[candidate.hash] = number
            ok, transient = response(scenario, candidate.values, candidate.hash, number, seed)
            budget.observe({"api_applies": int(new), "client_starts": 1,
                            "result": {"http_requests": 1, "traffic_bytes": 2048 if confirmation else 512}})
            return ok, transient

        # Endpoint health is a common control policy, not an adaptive advantage.
        # A failed first reference resource is bypassed for every strategy.
        if scenario == "endpoint_failure":
            for endpoint_ok in (False, True):
                if budget.remaining_time() < .25 or not budget.permits(1):
                    termination = "time_budget" if budget.remaining_time() < .25 else "request_budget"
                    break
                clock[0] += .25
                budget.observe({"result": {"http_requests": 1, "traffic_bytes": 0}})
                reference_failures += not endpoint_ok

        while True:
            if scheduler:
                selected = scheduler.next()
                if selected is None:
                    break
                candidate = selected[0]
                changed = frozenset()
            else:
                if not queue:
                    break
                candidate, changed = queue.popleft()
            if candidate.hash in seen:
                if scheduler:
                    scheduler.finish()
                continue
            if not permits(new=True):
                termination = exhausted_reason(new=True)
                break
            seen.add(candidate.hash)
            budget.used["candidates"] += 1
            ok, transient = trial(candidate, new=True)
            # One classified transient retry, identical for all strategies.
            if not ok and transient and permits(new=False):
                ok, _ = trial(candidate)
            if ok:
                if first_viable is None:
                    first_viable = round(clock[0], 3)
                all_confirmed = True
                for _ in range(3):
                    if not permits(new=False, confirmation=True):
                        termination = exhausted_reason(new=False, confirmation=True)
                        all_confirmed = False
                        break
                    ok, _ = trial(candidate, confirmation=True)
                    if not ok:
                        all_confirmed = False
                        break
                if all_confirmed:
                    confirmed_at = round(clock[0], 3)
                    confirmed_hash = candidate.hash
                    termination = "first_confirmed"
                    break
                if termination != "frontier_exhausted":
                    break
                if scheduler:
                    scheduler.add_neighbours(item for item, _ in generator.mutation_neighbors(candidate.values, changed))
                elif strategy == "mutation":
                    queue.extend(generator.mutation_neighbors(candidate.values, changed))
            if scheduler:
                scheduler.finish()

        return {"strategy": strategy, "scenario": scenario, "seed": seed,
                "confirmed": confirmed_hash is not None, "no_result": confirmed_hash is None,
                "time_to_first_viable_seconds": first_viable,
                "time_to_first_confirmed_seconds": confirmed_at,
                "elapsed_virtual_seconds": round(clock[0], 3), "termination_reason": termination,
                "reference_failures": reference_failures, "used": budget.snapshot(),
                "planning_coverage": generator.coverage_metadata}
    finally:
        search.time.monotonic = real_monotonic


def compare(seeds: int = 12, *, candidate_limit: int = 12, request_budget: int = 32,
            time_budget_seconds: float = 90) -> dict[str, Any]:
    records = [simulate(strategy, scenario, seed, candidate_limit=candidate_limit,
                        request_budget=request_budget, time_budget_seconds=time_budget_seconds)
               for scenario in SCENARIOS for strategy in STRATEGIES for seed in range(seeds)]
    summaries = []
    for scenario in SCENARIOS:
        for strategy in STRATEGIES:
            group = [record for record in records if record["scenario"] == scenario and record["strategy"] == strategy]
            summaries.append({"scenario": scenario, "strategy": strategy, "runs": len(group),
                              "confirmed": sum(record["confirmed"] for record in group),
                              "no_result": sum(record["no_result"] for record in group),
                              "success_fraction": statistics.mean(record["confirmed"] for record in group),
                              # Every failed run receives the common horizon;
                              # no-result runs are not removed from this measure.
                              "restricted_mean_confirmation_seconds": statistics.mean(
                                  record["time_to_first_confirmed_seconds"]
                                  if record["confirmed"] else time_budget_seconds for record in group),
                              "mean_requests": statistics.mean(record["used"]["requests"] for record in group),
                              "mean_candidates": statistics.mean(record["used"]["candidates"] for record in group),
                              "mean_api_applies": statistics.mean(record["used"]["api_applies"] for record in group)})
    return {"kind": "synthetic_only", "schema_version": 1,
            "assumptions": {"same_observation_policy_for_all_strategies": True,
                            "screening_requests": 1, "confirmation_new_sessions": 3,
                            "transient_screening_retries": 1, "speed_test": False,
                            "reference_control_policy": "skip_failed_endpoint_for_every_strategy",
                            "mutation_policy": "legacy_successful_parent_neighbours",
                            "tls_infrastructure": "synthetically_available_in_all_profiles",
                            "candidate_construction_cost_in_virtual_time": 0,
                            "costs_seconds": {"apply": 2, "expensive_apply": 20,
                                              "client_start": .1, "http_request": .25,
                                              "confirmation_window_wait": .25},
                            "candidate_limit": candidate_limit, "request_budget": request_budget,
                            "time_budget_seconds": time_budget_seconds, "seeds": seeds},
            "summary": summaries, "records": records}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", type=int, default=12)
    parser.add_argument("--candidates", type=int, default=12)
    parser.add_argument("--requests", type=int, default=32)
    parser.add_argument("--seconds", type=float, default=90)
    parser.add_argument("--output", type=Path, default=ROOT / "docs" / "review-2026-10-04" / "benchmark-results.json")
    args = parser.parse_args()
    if min(args.seeds, args.candidates, args.requests, args.seconds) <= 0:
        parser.error("budgets and seeds must be positive")
    output = args.output.resolve()
    if not output.is_relative_to(ROOT):
        parser.error("output must stay inside this project")
    result = compare(args.seeds, candidate_limit=args.candidates, request_budget=args.requests,
                     time_budget_seconds=args.seconds)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("Synthetic only; virtual seconds are a cost model. No panel or network calls.")
    for summary in result["summary"]:
        print(f"{summary['scenario']:<26} {summary['strategy']:<10} "
              f"confirmed={summary['confirmed']:>2}/{summary['runs']} "
              f"no_result={summary['no_result']:>2} requests={summary['mean_requests']:.2f} "
              f"restricted_mean_s={summary['restricted_mean_confirmation_seconds']:.2f}")
    print(f"Saved {len(result['records'])} complete run summaries to {output}")


if __name__ == "__main__":
    main()
