"""Throughput must be sampled on every measured rung of a candidate.

The Web UI pipeline screens a candidate first (a cheap probe, `screening_only`),
then re-runs it at comparison, confirmation and quality fidelity. Speed used to be
attached to the finalist rung alone, so a confirmed combination carried a single
`download_mbps` for all of its runs. These tests drive the real `_one_run` with a
local mock transport: no panel, no Xray binary and no network are involved.
"""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import httpx
import pytest

from app.config import ExperimentConfig
from app.parameters.generator import configuration_hash
from app.parameters.models import ParameterSpec
from app.testing.measurements import MeasurementSuite
from app.testing.runner import ExperimentRunner

SPEED_URL = "https://fixture.test/download"
MEASURED = {"comparison", "confirmation", "quality"}


class Manager:
    mode = "clone"
    source_id = 1
    test_inbound_id = 9
    cleanup_pending = False
    cleaned = False

    async def prepare(self):
        return 9

    async def apply(self, payload):
        return None

    async def cleanup(self):
        self.cleaned = True


class Panel:
    async def get_inbound(self, _):
        return {"id": 9, "port": 9443, "protocol": "vless", "streamSettings": {}}

    async def xray_logs(self, count=20):
        return []


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


def config(tmp_path):
    return ExperimentConfig(
        panel={"url": "https://panel.example.test"},
        inbound={"mode": "clone", "source_id": 1, "test_port": 9443},
        parameters=tuple(ParameterSpec.from_dict(name, {"type": "enum", "values": [0, 1],
            "baseline": 0, "target": "client", "path": ["knobs", name]}) for name in ("a", "b")),
        testing={"combination_strategy": "adaptive", "ports": [9443], "max_combinations": 4,
            "urls": ["https://example.test", "https://reference.test"], "validate_config": False,
            # The clone port is closed in a hermetic test; connectivity is not
            # what these tests are about, the speed policy is.
            "screening": {"enabled": True, "requests": 1, "min_success_rate": 1.0,
                          "require_tcp_connect": False},
            "quality_gates": {"min_success_rate": 1.0, "min_successful_requests": 1,
                              "require_tcp_connect": False},
            "speed_test": {"enabled": True, "url": SPEED_URL, "max_bytes": 1_000_000,
                           "max_duration_seconds": 2},
            "adaptive": {"time_budget_seconds": 10, "request_budget": 100,
                "traffic_budget_bytes": 30_000_000, "apply_budget": 50,
                "comparison_requests": 2, "confirmation_windows": 2, "confirmation_requests": 2,
                "window_delay_seconds": 0, "screening_retries": 0, "negative_resample_fraction": 0}},
        output={"directory": str(tmp_path), "formats": ["json"]})


class Runner(ExperimentRunner):
    def __init__(self, cfg):
        super().__init__(cfg, Panel())
        self.manager = Manager()

    async def preflight(self):
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        return {"openapi_version": "3.x", "xray_version": "fixture", "manager": self.manager,
                "source": {"streamSettings": {}}}

    def _candidate_error(self, *args):
        return None

    def _config_reason(self, *args):
        return None


@pytest.fixture(autouse=True)
def reference(monkeypatch):
    async def healthy(*args, **kwargs):
        return {"reference_ok": True, "reference_request_count": 1, "reference_bytes_received": 0}
    monkeypatch.setattr(MeasurementSuite, "reference_check", healthy)


def records(tmp_path):
    return [json.loads(line) for line in (tmp_path / "results.jsonl").read_text().splitlines()]


def mock_http(monkeypatch, requested: list[str]) -> None:
    """Route measurement traffic to a local mock transport instead of the network."""
    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(200, content=b"x" * 32)

    # Read the real class before monkeypatch replaces it on the shared httpx module.
    real_client = httpx.AsyncClient

    def factory(**kwargs):
        kwargs.pop("proxy", None)
        return real_client(transport=httpx.MockTransport(handler), timeout=kwargs.get("timeout", 1))

    monkeypatch.setattr("app.testing.measurements.httpx.AsyncClient", factory)


def test_every_measured_rung_of_a_confirmed_candidate_samples_speed(tmp_path, monkeypatch):
    requested: list[str] = []
    mock_http(monkeypatch, requested)
    monkeypatch.setattr("app.testing.runner.validate_pair", lambda *_: None)
    monkeypatch.setattr("app.testing.runner.XrayClient", Client)
    runner = Runner(config(tmp_path))
    runner._builder = lambda *_: SimpleNamespace(socks_port=10808, build=lambda *_: {})
    runner._readback_error = lambda *_: None

    summary = asyncio.run(runner.run())

    assert summary["confirmed_candidates"] == 1
    observed = records(tmp_path)
    measured = [item for item in observed if item["fidelity"] in MEASURED]
    assert [item["fidelity"] for item in measured] == [
        "comparison", "confirmation", "confirmation", "quality"]
    assert all(item["result"].get("status") == "OK" for item in measured)
    # The bug: comparison and confirmation windows were measured without throughput.
    assert all("download_mbps" in item["result"] for item in measured)
    # ... and the cheap screening probe stays a probe.
    screenings = [item for item in observed if item["fidelity"] == "screening"]
    assert screenings and all("download_mbps" not in item["result"] for item in screenings)
    # One speed download per measured run, not one per combination.
    assert requested.count(SPEED_URL) == len(measured)


def stub_runner(monkeypatch, cfg):
    """A runner whose panel, Xray and config checks are replaced by fixtures."""
    seen: list[dict] = []

    class Recorder(MeasurementSuite):
        def __init__(self, testing, *args, **kwargs):
            super().__init__(testing, *args, **kwargs)
            seen.append(dict(testing.get("speed_test", {})))

        async def screen(self, *args, **kwargs):
            return {"successful_requests": 1, "failed_requests": 0, "success_rate": 1.0,
                    "http_request_count": 1, "tcp_connect_supported": False}

        async def run(self, **kwargs):
            # Mirror MeasurementSuite.run: throughput only when the suite was
            # built with an enabled speed test.
            metrics = {"successful_requests": 1, "failed_requests": 0, "success_rate": 1.0,
                       "http_request_count": 2, "tcp_connect_supported": False}
            if self.speed_test.get("enabled") and self.speed_test.get("url"):
                metrics["download_mbps"] = 12.5
            return metrics

    monkeypatch.setattr("app.testing.runner.MeasurementSuite", Recorder)
    monkeypatch.setattr("app.testing.runner.validate_pair", lambda *_: None)
    monkeypatch.setattr("app.testing.runner.XrayClient", Client)
    payload = {"port": 9443, "streamSettings": {}}
    runner = ExperimentRunner(cfg, Panel())
    runner._candidate_payload = lambda *_: (payload, None)
    runner._readback_error = lambda *_: None
    runner._builder = lambda *_: SimpleNamespace(socks_port=10808, build=lambda *_: {})
    runner._config_reason = lambda *_: None
    runner._active_inbound = payload
    runner._last_inbound_payload_hash = configuration_hash(payload)
    return runner, seen, payload


def test_screening_probe_never_samples_speed(tmp_path, monkeypatch):
    runner, seen, payload = stub_runner(monkeypatch, config(tmp_path))
    record = asyncio.run(runner._one_run(1, 1, {"a": 0, "b": 0}, "fixture", Manager(), payload,
        "fixture.test", screening_only=True, fidelity="screening", requests=1, speed_bytes=0))

    assert record["result"]["status"] == "OK" and record["result"]["stage"] == "screening"
    assert [item["enabled"] for item in seen] == [False]
    assert "download_mbps" not in record["result"]


def test_confirmation_run_without_traffic_room_skips_the_sample_but_not_the_run(tmp_path, monkeypatch):
    runner, seen, payload = stub_runner(monkeypatch, config(tmp_path))
    # speed_bytes == 0 is what the budget hands over when it cannot pay for a
    # sample: the window is still measured, it just carries no throughput metric.
    record = asyncio.run(runner._one_run(1, 1, {"a": 0, "b": 0}, "fixture", Manager(), payload,
        "fixture.test", fidelity="confirmation", requests=2, speed_bytes=0))

    assert record["result"]["status"] == "OK" and record["result"]["stage"] == "measurement"
    assert [item["enabled"] for item in seen] == [False]
    assert "download_mbps" not in record["result"]


def test_measured_rung_with_a_traffic_allowance_carries_the_capped_sample(tmp_path, monkeypatch):
    runner, seen, payload = stub_runner(monkeypatch, config(tmp_path))
    record = asyncio.run(runner._one_run(1, 1, {"a": 0, "b": 0}, "fixture", Manager(), payload,
        "fixture.test", fidelity="comparison", requests=2, speed_bytes=4096))

    assert [{"enabled": item["enabled"], "max_bytes": item.get("max_bytes")} for item in seen] == [
        {"enabled": True, "max_bytes": 4096}]
    assert record["result"]["download_mbps"] == 12.5
