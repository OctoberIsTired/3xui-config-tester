from __future__ import annotations

import json
import math

import pytest

from app.parameters.generator import Combination, CombinationGenerator
from app.parameters.models import ParameterSpec
from app.testing.search import AdaptiveScheduler, SearchBudget


def budget_options(**changes):
    return {"request_budget": 12, "traffic_budget_bytes": 1024,
            "apply_budget": 4, "time_budget_seconds": 60, **changes}


def collect(scheduler, count):
    result = []
    for _ in range(count):
        item = scheduler.next()
        if item is None:
            break
        result.append((item[0].hash, item[1]))
        scheduler.finish()
    return result


def test_scheduler_restores_active_pending_trial_and_exact_remaining_order():
    scheduler = AdaptiveScheduler([Combination({"value": value}) for value in range(8)], .3)
    scheduler.add_neighbours([Combination({"value": value}) for value in range(100, 108)])
    collect(scheduler, 3)
    active = scheduler.next()
    scheduler.pending_trial = {"run": 2, "phase": "confirmation", "configuration_hash": active[0].hash}
    scheduler.viable = [active[0].hash]
    snapshot = json.loads(json.dumps(scheduler.snapshot()))
    restored = AdaptiveScheduler([], .3, saved=snapshot)
    assert restored.next() == active
    assert restored.pending_trial == scheduler.pending_trial
    assert restored.viable == [active[0].hash]
    assert restored.selections == scheduler.selections
    scheduler.finish()
    restored.finish()
    assert collect(restored, 20) == collect(scheduler, 20)


@pytest.mark.parametrize("fraction", [.1, .25, .4, .6, 1.0])
def test_exploration_quota_is_preserved_at_every_prefix_and_after_resume(fraction):
    scheduler = AdaptiveScheduler([Combination({"explore": value}) for value in range(100)], fraction)
    scheduler.add_neighbours([Combination({"exploit": value}) for value in range(100)], limit=100)
    explored = 0
    for index in range(1, 31):
        candidate, reason = scheduler.next()
        explored += reason == "coverage_exploration"
        assert explored >= math.ceil(index * fraction - 1e-12)
        scheduler.finish()
        if index == 11:
            scheduler = AdaptiveScheduler([], fraction, saved=scheduler.snapshot())
    assert len(scheduler.seen) == 30


def test_scheduler_explores_joint_rescue_with_no_successful_parent():
    specs = [ParameterSpec.from_dict(name, {"type": "integer", "values": [0, 1], "baseline": 0})
             for name in "ab"]
    generator = CombinationGenerator(specs)
    scheduler = AdaptiveScheduler(generator.iter_adaptive(4, seed=11))
    observed = []
    while item := scheduler.next():
        observed.append(item[0].values)
        scheduler.finish()
    assert {"a": 1, "b": 1} in observed
    assert len(observed) == 4
    assert scheduler.next() is None


def test_scheduler_deduplicates_frontier_neighbours_and_resumed_active():
    first = Combination({"value": 0})
    second = Combination({"value": 1})
    scheduler = AdaptiveScheduler([first, first, second])
    scheduler.add_neighbours([first, second, second], limit=8)
    scheduler.add_neighbours([Combination({"value": 999})], limit=0)
    rows = collect(scheduler, 20)
    assert {digest for digest, _ in rows} == {first.hash, second.hash}
    assert len(rows) == 2


def test_budget_restore_keeps_elapsed_time_usage_and_cached_apply_allowance(monkeypatch):
    from app.testing import search
    clock = [100.0]
    monkeypatch.setattr(search.time, "monotonic", lambda: clock[0])
    budget = SearchBudget(budget_options(apply_budget=1), candidate_limit=2)
    budget.used["candidates"] = 1
    budget.observe({"api_applies": 1, "client_starts": 1,
                    "result": {"screening": {"successful_requests": 1, "failed_requests": 1,
                                              "traffic_bytes": 256}}})
    clock[0] += 9
    state = json.loads(json.dumps(budget.snapshot()))
    restored = SearchBudget(budget_options(apply_budget=1), 2, saved=state)
    assert restored.snapshot()["elapsed_seconds"] == 9
    assert restored.used == budget.used
    assert restored.permits(requests=1, api_applies=0)
    assert not restored.permits(requests=1, api_applies=1)
    clock[0] += 51
    assert not restored.permits()


def test_budget_accounts_explicit_trial_costs_and_each_limit(monkeypatch):
    from app.testing import search
    monkeypatch.setattr(search.time, "monotonic", lambda: 0.0)
    budget = SearchBudget(budget_options(request_budget=2, traffic_budget_bytes=100, apply_budget=1), 1)
    assert budget.permits(2, response_bytes=100, api_applies=1, new_candidate=True)
    assert not budget.permits(3)
    assert not budget.permits(response_bytes=101)
    assert not budget.permits(api_applies=2)
    budget.observe({"api_applies": 1, "client_starts": 1,
                    "result": {"http_requests": 2, "traffic_bytes": 100,
                               "screening": {"successful_requests": 99, "failed_requests": 99}}})
    budget.used["candidates"] += 1
    assert budget.used == {"candidates": 1, "requests": 2, "traffic_bytes": 100,
                           "api_applies": 1, "client_starts": 1}
    assert not budget.permits(requests=0, new_candidate=True)
    assert not budget.permits()
    assert budget.permits(requests=0, response_bytes=0, api_applies=0)


def test_synthetic_benchmark_is_deterministic_bounded_and_retains_no_result_runs():
    from tools.benchmark_search import SCENARIOS, STRATEGIES, compare, simulate
    from app.testing import search
    real_clock = search.time.monotonic
    for scenario in SCENARIOS:
        for strategy in STRATEGIES:
            first = simulate(strategy, scenario, seed=7, candidate_limit=5, request_budget=8,
                             time_budget_seconds=20)
            assert first == simulate(strategy, scenario, seed=7, candidate_limit=5, request_budget=8,
                                     time_budget_seconds=20)
            assert first["used"]["candidates"] <= 5
            assert first["used"]["requests"] <= 8
            assert first["used"]["api_applies"] <= 5
            assert first["elapsed_virtual_seconds"] <= 20
            assert first["confirmed"] != first["no_result"]
    assert search.time.monotonic is real_clock
    comparison = compare(seeds=2)
    assert comparison["kind"] == "synthetic_only"
    assert len(comparison["records"]) == len(SCENARIOS) * len(STRATEGIES) * 2
    failed = [item for item in comparison["summary"] if item["scenario"] == "no_working_configuration"]
    assert all(item["no_result"] == item["runs"] == 2 for item in failed)
    assert all(item["restricted_mean_confirmation_seconds"] == 90 for item in failed)
    tiny = simulate("adaptive", "endpoint_failure", time_budget_seconds=.1)
    assert tiny["elapsed_virtual_seconds"] <= .1
    assert tiny["termination_reason"] == "time_budget"
