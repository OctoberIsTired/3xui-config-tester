from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.config import ExperimentConfig
from app.parameters.generator import configuration_hash
from app.parameters.models import ParameterSpec
from app.state.checkpoint import Checkpoint
from app.testing.measurements import MeasurementSuite
from app.testing.runner import ExperimentRunner


class Manager:
    mode = "clone"
    source_id = 1
    test_inbound_id = 9
    cleanup_pending = False
    cleaned = False

    async def prepare(self):
        return 9

    async def cleanup(self):
        self.cleaned = True


class Panel:
    async def get_inbound(self, _):
        return {"id": 9, "port": 9443, "protocol": "vless", "streamSettings": {}}


def config(tmp_path, **adaptive):
    return ExperimentConfig(panel={"url": "https://panel.example.test"},
        inbound={"mode": "clone", "source_id": 1, "test_port": 9443},
        parameters=tuple(ParameterSpec.from_dict(name, {"type": "enum", "values": [0, 1],
            "baseline": 0, "target": "client", "path": ["knobs", name]}) for name in ("a", "b")),
        testing={"combination_strategy": "adaptive", "ports": [9443], "max_combinations": 4,
            "urls": ["https://example.test", "https://reference.test"], "validate_config": False,
            "adaptive": {"time_budget_seconds": 10, "request_budget": 100,
                "comparison_requests": 2, "confirmation_windows": 2, "confirmation_requests": 2,
                "window_delay_seconds": 0, "screening_retries": 0, "negative_resample_fraction": 0, **adaptive}},
        output={"directory": str(tmp_path), "formats": ["json"]})


class Runner(ExperimentRunner):
    def __init__(self, cfg, oracle=None):
        super().__init__(cfg, Panel())
        self.manager = Manager()
        self.oracle = oracle or (lambda values, fidelity: values == {"a": 1, "b": 1})
        self.calls = []

    async def preflight(self):
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        return {"openapi_version": "3.x", "xray_version": "fixture", "manager": self.manager,
                "source": {"streamSettings": {}}}

    def _candidate_error(self, *args):
        return None

    async def _one_run(self, test_id, run_number, values, digest, manager, base_payload,
                       server_address, **kwargs):
        fidelity, count = kwargs["fidelity"], kwargs["requests"]
        self.calls.append((digest, run_number, fidelity))
        ok = self.oracle(values, fidelity)
        payload, _ = self._candidate_payload(values, base_payload)
        self._last_inbound_payload_hash = configuration_hash(payload)
        return {"test_id": test_id, "run": run_number, "timestamp": "fixture",
                "configuration_hash": digest, "configuration": values, "api_applies": 1 if run_number == 1 else 0,
                "client_starts": 1, "duration_ms": 1,
                "result": {"status": "OK" if ok else "FAILED", "score": float(ok),
                           "stage": fidelity, "http_requests": count, "traffic_bytes": 10,
                           "successful_requests": count if ok else 0, "failed_requests": 0 if ok else count}}


@pytest.fixture(autouse=True)
def reference(monkeypatch):
    async def healthy(*args, **kwargs):
        return {"reference_ok": True, "reference_request_count": 2, "reference_bytes_received": 0}
    monkeypatch.setattr(MeasurementSuite, "reference_check", healthy)


def records(tmp_path):
    return [json.loads(line) for line in (tmp_path / "results.jsonl").read_text().splitlines()]


def test_joint_rescue_and_immediate_confirmation(tmp_path):
    runner = Runner(config(tmp_path))
    summary = asyncio.run(runner.run())
    assert summary["confirmed_candidates"] == 1
    assert summary["termination_reason"] == "first_confirmed"
    observed = records(tmp_path)
    confirmed = [item for item in observed if item["qualification"] == "confirmed_in_observed_windows"]
    assert confirmed and confirmed[-1]["configuration"] == {"a": 1, "b": 1}
    digest = confirmed[-1]["configuration_hash"]
    assert [item["run"] for item in observed if item["configuration_hash"] == digest] == [1, 2, 3, 4]
    assert [item["fidelity"] for item in observed if item["configuration_hash"] == digest] == [
        "screening", "comparison", "confirmation", "confirmation"]
    assert runner.manager.cleaned


def test_screening_success_does_not_confirm_failed_windows(tmp_path):
    runner = Runner(config(tmp_path), lambda values, fidelity: fidelity != "confirmation")
    summary = asyncio.run(runner.run())
    assert summary["viable_candidates"] > 0 and summary["confirmed_candidates"] == 0
    assert all(item["qualification"] != "confirmed_in_observed_windows" for item in records(tmp_path))
    assert all(item["fidelity"] != "quality" for item in records(tmp_path))


def test_request_budget_stops_promotion_and_cleans(tmp_path):
    runner = Runner(config(tmp_path, request_budget=3), lambda *_: True)
    summary = asyncio.run(runner.run())
    assert summary["termination_reason"] == "budget_exhausted"
    assert summary["budget"]["requests"] <= 3
    assert summary["confirmed_candidates"] == 0 and runner.manager.cleaned


def test_speed_sample_is_capped_by_the_remaining_traffic_budget(tmp_path):
    cfg = config(tmp_path, request_budget=10, traffic_budget_bytes=50)
    cfg.testing["http"] = {"max_response_bytes": 10}
    cfg.testing["speed_test"] = {"enabled": True, "url": "https://fixture.test/download", "max_bytes": 100}
    runner = Runner(cfg, lambda *_: True)
    samples: list[tuple[str, int]] = []
    original = runner._one_run

    async def recorded(*args, **kwargs):
        samples.append((kwargs["fidelity"], kwargs["speed_bytes"]))
        return await original(*args, **kwargs)

    runner._one_run = recorded
    summary = asyncio.run(runner.run())
    assert summary["confirmed_candidates"] == 1
    assert summary["termination_reason"] == "first_confirmed"
    # Every measured rung asks for a sample, capped by the traffic left after the
    # response allowance; the cheap screening probe never asks, and a window with
    # no room is still measured, just without a throughput sample.
    assert samples == [("screening", 0), ("comparison", 20), ("confirmation", 10),
                       ("confirmation", 0), ("quality", 0)]
    assert [fidelity for _, _, fidelity in runner.calls] == [
        "screening", "comparison", "confirmation", "confirmation", "quality"]
    assert summary["budget"]["requests"] == 10
    assert summary["budget"]["traffic_bytes"] == 50
    assert runner.manager.cleaned


def test_quality_samples_can_satisfy_configured_successful_request_minimum(tmp_path):
    cfg = config(tmp_path)
    cfg.testing["quality_gates"] = {"min_successful_requests": 2}
    cfg.testing["speed_test"] = {"enabled": True, "url": "https://fixture.test/download", "max_bytes": 100}
    runner = Runner(cfg, lambda *_: True)
    summary = asyncio.run(runner.run())
    assert summary["confirmed_candidates"] == 1
    quality = next(item["result"] for item in records(tmp_path) if item["fidelity"] == "quality")
    assert quality["successful_requests"] >= 2
    assert quality["requested_http_requests"] >= 2
    assert runner.manager.cleaned


@pytest.mark.parametrize("local_override", [True, False])
def test_confirmation_reserves_target_specific_response_cap(tmp_path, local_override):
    cfg = config(tmp_path, traffic_budget_bytes=250)
    cfg.testing["http"] = {"max_response_bytes": 10}
    target = "https://fixture.test/confirmation"
    if local_override:
        cfg.testing["confirmation_urls"] = [{"url": target, "max_response_bytes": 300}]
    else:
        cfg.testing["confirmation_urls"] = [target]
        cfg.testing["http_expectations"] = {target: {"max_response_bytes": 300}}
    runner = Runner(cfg, lambda *_: True)
    summary = asyncio.run(runner.run())
    assert summary["termination_reason"] == "budget_exhausted"
    assert summary["confirmed_candidates"] == 0
    assert [fidelity for _, _, fidelity in runner.calls] == ["screening", "comparison"]
    assert summary["budget"]["traffic_bytes"] == 20
    assert runner.manager.cleaned


def test_reference_preserves_configured_status_content_and_caps(tmp_path, monkeypatch):
    cfg = config(tmp_path)
    target = "https://fixture.test/expected-not-found"
    cfg.testing["urls"] = [{"url": target, "expected_status": 404, "expected_content": "healthy"}]
    cfg.testing["http_expectations"] = {target: {"max_response_bytes": 20}}
    observed = []
    async def healthy(urls, **kwargs):
        observed.extend(urls)
        return {"reference_ok": True, "reference_request_count": len(urls), "reference_bytes_received": 0}
    monkeypatch.setattr(MeasurementSuite, "reference_check", healthy)
    summary = asyncio.run(Runner(cfg, lambda *_: True).run())
    assert summary["confirmed_candidates"] == 1
    assert observed == [{"url": target, "expected_status": 404,
                         "expected_content": "healthy", "max_response_bytes": 20}]


def test_trial_timeout_conservatively_consumes_reserved_payload_allowance(tmp_path):
    cfg = config(tmp_path, traffic_budget_bytes=30)
    cfg.testing["http"] = {"max_response_bytes": 10}
    runner = Runner(cfg, lambda *_: True)
    original = runner._one_run
    async def timeout(*args, **kwargs):
        if kwargs["fidelity"] == "comparison":
            raise TimeoutError("fixture partial measurement lost on cancellation")
        return await original(*args, **kwargs)
    runner._one_run = timeout
    summary = asyncio.run(runner.run())
    assert summary["termination_reason"] == "budget_exhausted"
    assert summary["confirmed_candidates"] == 0
    assert summary["budget"]["traffic_bytes"] == 30
    timed_out = records(tmp_path)[-1]["result"]
    assert timed_out["status"] == "TIMEOUT"
    assert timed_out["http_requests"] == 2
    assert timed_out["traffic_bytes"] == 20
    assert timed_out["budget_accounting"] == "reserved_on_timeout"
    assert runner.manager.cleaned


def test_screening_timeout_retains_target_specific_budget_allowance(tmp_path, monkeypatch):
    cfg = config(tmp_path)
    cfg.testing["http"] = {"max_response_bytes": 10}
    cfg.testing["urls"] = [{"url": "https://fixture.test/", "max_response_bytes": 100}]
    runner = ExperimentRunner(cfg, Panel())
    payload = {"port": 9443, "streamSettings": {}}
    runner._candidate_payload = lambda *_: (payload, None)
    runner._readback_error = lambda *_: None
    runner._builder = lambda *_: SimpleNamespace(socks_port=10808, build=lambda *_: {})
    runner._config_reason = lambda *_: None
    runner._active_inbound = payload
    runner._last_inbound_payload_hash = configuration_hash(payload)
    monkeypatch.setattr("app.testing.runner.validate_pair", lambda *_: None)
    class Client:
        def __init__(self, *args, **kwargs):
            pass
        async def start(self, config):
            pass
        async def stop(self):
            pass
        def diagnostic_categories(self):
            return []
        def log_tail(self):
            return ""
    monkeypatch.setattr("app.testing.runner.XrayClient", Client)
    async def timeout(*args, **kwargs):
        raise TimeoutError("fixture partial body read")
    monkeypatch.setattr(MeasurementSuite, "screen", timeout)
    record = asyncio.run(runner._one_run(1, 1, {"a": 0, "b": 0}, "fixture", Manager(), payload,
        "fixture.test", screening_only=True, fidelity="screening", requests=1))
    result = record["result"]
    assert result["status"] == "FAILED"
    assert result["http_requests"] == 1 and result["traffic_bytes"] == 100
    assert result["budget_accounting"] == "reserved_on_timeout"


def test_complete_frontier_reports_exhaustion_even_at_candidate_limit(tmp_path):
    runner = Runner(config(tmp_path), lambda *_: False)
    summary = asyncio.run(runner.run())
    assert summary["configurations_tested"] == 4
    assert summary["termination_reason"] == "frontier_exhausted"
    assert runner.manager.cleaned


def test_append_before_checkpoint_crash_replays_without_duplicate_trial(tmp_path, monkeypatch):
    runner = Runner(config(tmp_path), lambda *_: True)
    original = Checkpoint.save
    def crash(checkpoint, path):
        if (tmp_path / "results.jsonl").exists():
            raise RuntimeError("simulated power loss after append")
        original(checkpoint, path)
    monkeypatch.setattr(Checkpoint, "save", crash)
    with pytest.raises(RuntimeError, match="power loss"):
        asyncio.run(runner.run())
    assert len(records(tmp_path)) == 1
    monkeypatch.setattr(Checkpoint, "save", original)
    resumed = Runner(config(tmp_path), lambda *_: True)
    summary = asyncio.run(resumed.run(resume=True))
    assert summary["confirmed_candidates"] == 1
    keys = [(item["configuration_hash"], item["run"]) for item in records(tmp_path)]
    assert len(keys) == len(set(keys)) == 4
    assert all(fidelity != "screening" for _, _, fidelity in resumed.calls)


def test_reference_outage_is_environment_result(tmp_path, monkeypatch):
    async def unavailable(*args, **kwargs):
        return {"reference_ok": False, "reference_request_count": 2, "reference_bytes_received": 0}
    monkeypatch.setattr(MeasurementSuite, "reference_check", unavailable)
    runner = Runner(config(tmp_path))
    summary = asyncio.run(runner.run())
    assert summary["termination_reason"] == "environment_unavailable"
    assert runner.calls == [] and runner.manager.cleaned


def test_stop_between_promotion_and_confirmation(tmp_path):
    runner = Runner(config(tmp_path), lambda *_: True)
    original = runner._one_run
    async def stopping(*args, **kwargs):
        result = await original(*args, **kwargs)
        if kwargs["fidelity"] == "comparison":
            runner.request_stop()
        return result
    runner._one_run = stopping
    summary = asyncio.run(runner.run())
    assert summary["termination_reason"] == "stopped" and summary["interrupted"]
    assert summary["confirmed_candidates"] == 0 and runner.manager.cleaned


@pytest.mark.parametrize("stopped", [True, False])
def test_partial_last_confirmation_window_never_confirms(tmp_path, stopped):
    runner = Runner(config(tmp_path), lambda *_: True)
    original = runner._one_run
    async def partial(*args, **kwargs):
        record = await original(*args, **kwargs)
        if kwargs["fidelity"] == "confirmation" and record["run"] == 4:
            record["result"].update({"stage": "measurement", "http_requests": 1,
                "http_request_count": 1, "successful_requests": 1, "measurement_stopped": stopped,
                "success_rate": 1.0, "tcp_connect_ok": True, "gate_failures": []})
            # The ordinary quality gate allows one successful request. The
            # confirmation policy must additionally require a complete window.
            assert runner._quality_gate(record["result"])[0]
            if stopped:
                runner.request_stop()
        return record
    runner._one_run = partial
    summary = asyncio.run(runner.run())
    assert summary["termination_reason"] == ("stopped" if stopped else "frontier_exhausted")
    assert summary["confirmed_candidates"] == 0
    observed = records(tmp_path)
    final_window = next(item for item in observed if item["run"] == 4)
    assert final_window["result"]["status"] == "FAILED"
    assert "http_requests<2" in final_window["result"]["gate_failures"]
    assert final_window["result"]["requested_http_requests"] == 2
    assert final_window["qualification"] == "unconfirmed"
    if stopped:
        assert "measurement_stopped" in final_window["result"]["gate_failures"]
    assert all(item["qualification"] != "confirmed_in_observed_windows" for item in observed)
    assert runner.manager.cleaned


@pytest.mark.parametrize("port", [9443.5, True, "9443"])
def test_non_integer_test_port_rejected(port):
    with pytest.raises(ValueError):
        ExperimentConfig(panel={}, inbound={"test_port": port}, parameters=())


def test_readback_ignored_ws_and_sockopt_are_rejected():
    expected = {"port": 9443, "streamSettings": {"network": "ws", "security": "none",
        "wsSettings": {"path": "/new"}, "sockopt": {"acceptProxyProtocol": False}}}
    actual = {"port": 9443, "streamSettings": json.dumps({"network": "ws", "security": "none",
        "wsSettings": {"path": "/old"}, "sockopt": {"acceptProxyProtocol": True}})}
    assert ExperimentRunner._readback_error(expected, actual)


def continue_budget(cfg, **limits):
    """Raise the recorded budget the way a continuation of an exhausted run does."""
    cfg.testing["adaptive"] = {**cfg.testing["adaptive"], **{key: value for key, value in limits.items()
                                                             if key != "max_combinations"}}
    if "max_combinations" in limits:
        cfg.testing["max_combinations"] = limits["max_combinations"]


def checkpoint_experiment_id(path):
    """Идентификатор эксперимента из чекпойнта; его сохранение доказывает продолжение."""
    checkpoint = Checkpoint.load(path)
    assert checkpoint is not None
    return checkpoint.experiment_id


def test_continuation_reuses_the_checkpoint_and_never_remeasures_a_candidate(tmp_path):
    """Продолжение исчерпанного прогона: тот же каталог, тот же чекпойнт,
    увеличенный бюджет и ни одного повторного измерения."""
    oracle = lambda values, fidelity: values == {"a": 1, "b": 1}
    cfg = config(tmp_path, request_budget=3)
    first = Runner(cfg, oracle)
    stopped = asyncio.run(first.run())
    assert stopped["termination_reason"] == "budget_exhausted"
    assert first.calls
    experiment_id = checkpoint_experiment_id(tmp_path / "state.json")

    continue_budget(cfg, max_combinations=8, request_budget=40)
    resumed = Runner(cfg, oracle)
    summary = asyncio.run(resumed.run(resume=True, max_tests=cfg.testing["max_combinations"]))

    # Same experiment, same checkpoint, new limits in force.
    assert checkpoint_experiment_id(tmp_path / "state.json") == experiment_id
    assert summary["termination_reason"] == "first_confirmed" and summary["confirmed_candidates"] == 1
    assert summary["budget"]["limits"]["requests"] == 40
    assert summary["budget"]["requests"] > stopped["budget"]["requests"]
    # Resume keys stay unique and no finished candidate run is measured twice.
    keys = [(item["configuration_hash"], item["run"]) for item in records(tmp_path)]
    assert len(keys) == len(set(keys))
    assert not set(resumed.calls) & set(first.calls)
    assert runner_calls_cover(records(tmp_path), resumed.calls)


def runner_calls_cover(observed, calls):
    """Каждый повтор продолжения, кроме инкрементальных, есть в журнале прогона."""
    journal = {(item["configuration_hash"], item["run"]) for item in observed}
    return all((digest, run) in journal for digest, run, _ in calls)


def test_continuation_with_a_larger_candidate_limit_queues_new_candidates(tmp_path):
    """Размер плана следует за бюджетом кандидатов: продолжение с большим
    лимитом добавляет кандидатов, которых прежний план не содержал."""
    oracle = lambda *_: False
    cfg = config(tmp_path, request_budget=2, max_combinations=2)
    first = Runner(cfg, oracle)
    stopped = asyncio.run(first.run())
    assert stopped["termination_reason"] == "budget_exhausted"
    planned = {item.hash for item in first.generator.adaptive_frontier(2, seed=0)}
    assert {digest for digest, _, _ in first.calls} <= planned

    continue_budget(cfg, max_combinations=8, request_budget=60)
    resumed = Runner(cfg, oracle)
    summary = asyncio.run(resumed.run(resume=True, max_tests=cfg.testing["max_combinations"]))

    attempted = {digest for digest, _, _ in resumed.calls}
    assert attempted - planned
    assert summary["termination_reason"] == "frontier_exhausted"
    keys = [(item["configuration_hash"], item["run"]) for item in records(tmp_path)]
    assert len(keys) == len(set(keys))
    assert not set(resumed.calls) & set(first.calls)


def test_resume_still_refuses_a_change_outside_the_budget(tmp_path):
    """Бюджет — единственное, что разрешено менять при продолжении."""
    cfg = config(tmp_path, request_budget=3)
    asyncio.run(Runner(cfg, lambda *_: False).run())
    cfg.testing["runs_per_combination"] = 2
    with pytest.raises(ValueError, match="inconsistent resume"):
        asyncio.run(Runner(cfg, lambda *_: False).run(resume=True))
