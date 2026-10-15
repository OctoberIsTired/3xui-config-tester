from __future__ import annotations

import asyncio
import copy
import json
import socket
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app.config import ExperimentConfig
from app.parameters.models import ParameterSpec
from app.testing.measurements import MeasurementSuite
from app.testing.runner import ExperimentRunner, prepare_inbound_payload
from app.xray.validation import CHECK_TIMEOUT
from app.xray.transports import effective_transport


class FakePanel:
    async def get_inbound(self, _inbound_id: int) -> dict[str, Any]:
        return {"id": 9, "port": 9443, "protocol": "vless", "streamSettings": {}}


class FakeManager:
    mode = "clone"
    source_id = 1
    test_inbound_id = 9
    cleaned = False

    async def prepare(self) -> int:
        return self.test_inbound_id

    async def cleanup(self) -> None:
        self.cleaned = True


class BootstrapRunner(ExperimentRunner):
    def __init__(self, config: ExperimentConfig, manager: FakeManager):
        super().__init__(config, FakePanel())  # type: ignore[arg-type]
        self.manager = manager

    async def preflight(self) -> dict[str, Any]:
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        return {"openapi_version": "3.8.0", "xray_version": "26.9.9", "manager": self.manager,
                "source": {"streamSettings": {}}}

    def _candidate_error(self, values: dict[str, Any], base_payload: dict[str, Any], server_address: str) -> str | None:
        return None

    async def _run_controls(self, manager: FakeManager, base_payload: dict[str, Any], server_address: str) -> None:
        return None

    async def _one_run(self, test_id: int, run_number: int, values: dict[str, Any], digest: str,
                       manager: FakeManager, base_payload: dict[str, Any], server_address: str,
                       *, include_ping: bool = False) -> dict[str, Any]:
        del manager, base_payload, server_address, include_ping
        status = "FAILED" if test_id == 1 else "OK"
        return {"test_id": test_id, "run": run_number, "timestamp": "now",
                "configuration_hash": digest, "configuration": values,
                "result": {"status": status, "score": 0.0 if status == "FAILED" else 1.0}}


class ValidationTransitionRunner(BootstrapRunner):
    def _candidate_error(self, values: dict[str, Any], base_payload: dict[str, Any],
                         server_address: str) -> str | None:
        del values, base_payload, server_address
        self._config_validator.check({})
        return None


def mutation_config(output: Path) -> ExperimentConfig:
    parameter = ParameterSpec.from_dict("transport", {
        "type": "enum", "values": ["broken", "working-a", "working-b"],
        "baseline": "broken", "mutate": True, "path": ["streamSettings", "network"],
    })
    return ExperimentConfig(
        panel={"url": "https://localhost"},
        inbound={"mode": "clone", "source_id": 1, "test_port": 9443},
        parameters=(parameter,),
        testing={"combination_strategy": "mutation", "mutation_generations": 2,
                 "max_combinations": 3, "runs_per_combination": 1,
                 "validate_config": False,
                 "server_address": "example.test", "urls": ["https://example.com"]},
        output={"directory": str(output), "formats": ["json"]},
    )


def test_failed_baseline_still_bootstraps_first_mutation_generation(tmp_path: Path) -> None:
    manager = FakeManager()
    summary = asyncio.run(BootstrapRunner(mutation_config(tmp_path), manager).run())
    records = [json.loads(line) for line in (tmp_path / "results.jsonl").read_text(encoding="utf-8").splitlines()]
    assert summary["configurations_tested"] == 3
    assert summary["completed"] == 3
    assert summary["termination_reason"] == "limit_reached"
    assert [item["result"]["status"] for item in records] == ["FAILED", "OK", "OK"]
    assert manager.cleaned is True


def test_progress_reports_the_created_test_inbound(tmp_path: Path) -> None:
    """Копия создаётся в панели; UI должен видеть её id и порт, а не только номер конфигурации."""
    updates: list[dict[str, Any]] = []
    runner = BootstrapRunner(mutation_config(tmp_path), FakeManager())
    runner.progress_callback = updates.append
    asyncio.run(runner.run())
    reported = [item for item in updates if "test_inbound_id" in item]
    assert reported and reported[0]["test_inbound_id"] == 9
    assert reported[0]["test_inbound_port"] == 9443


def test_runner_stops_when_core_check_times_out(tmp_path: Path, monkeypatch) -> None:
    calls = 0

    def fake_run(command: list[str], **kwargs: Any) -> SimpleNamespace:
        nonlocal calls
        calls += 1
        if command[1:3] == ["help", "run"]:
            return SimpleNamespace(stdout="Usage: xray run -test", stderr="", returncode=0)
        raise subprocess.TimeoutExpired(command, kwargs.get("timeout"))

    monkeypatch.setattr("app.xray.validation.subprocess.run", fake_run)
    updates: list[dict[str, Any]] = []
    runner = ValidationTransitionRunner(mutation_config(tmp_path), FakeManager())
    runner._config_validator.enabled = True
    runner._config_validator.strict = True
    runner.progress_callback = updates.append

    with pytest.raises(Exception, match="xray_core_validation_unavailable:xray_config_test_timeout"):
        asyncio.run(runner.run())

    assert calls >= 2


def test_warning_reads_last_core_failure_without_retrying(tmp_path: Path) -> None:
    runner = BootstrapRunner(mutation_config(tmp_path), FakeManager())
    validator = runner._config_validator
    validator._probed_identity = validator._core_identity()
    validator._availability = CHECK_TIMEOUT
    validator._probed = True
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr("app.xray.validation.subprocess.run", lambda *_args, **_kwargs: pytest.fail("unexpected retry"))
        warnings = runner._warnings()
    assert any(CHECK_TIMEOUT in warning for warning in warnings)


def test_failed_candidate_keeps_the_masked_client_log(tmp_path: Path) -> None:
    """Категории не объясняют провал рукопожатия — рядом кладётся маскированный лог клиента."""
    runner = ExperimentRunner(mutation_config(tmp_path), FakePanel())  # type: ignore[arg-type]
    runner._record_client_log(
        "[Warning] PROXY protocol header invalid for 8c1b0e2a-1f4d-4f0e-9b7a-6d5c4b3a2f10\n", 2, 1, "FAILED")
    text = (tmp_path / "client-xray.log").read_text(encoding="utf-8")
    assert "# test_id=2 run=1 status=FAILED" in text
    assert "PROXY protocol header" in text
    assert "8c1b0e2a" not in text


def test_failed_configuration_stops_after_configured_failure_threshold(tmp_path: Path) -> None:
    config = mutation_config(tmp_path)
    config.testing["runs_per_combination"] = 3
    config.testing["max_failed_runs"] = 1
    summary = asyncio.run(BootstrapRunner(config, FakeManager()).run())
    records = [json.loads(line) for line in (tmp_path / "results.jsonl").read_text(encoding="utf-8").splitlines()]

    # The broken baseline is recorded once, while each working candidate receives all repeats.
    assert summary["completed"] == 7
    assert [item["test_id"] for item in records].count(1) == 1
    assert [item["test_id"] for item in records].count(2) == 3
    assert [item["test_id"] for item in records].count(3) == 3


def test_quality_and_screening_gates_are_strict_by_default(tmp_path: Path) -> None:
    runner = ExperimentRunner(mutation_config(tmp_path), FakePanel())  # type: ignore[arg-type]
    screen_ok, failures = runner._screening_gate({"tcp_connect_ok": True, "success_rate": 0.5})
    assert screen_ok is False and "success_rate<1" in failures
    ok, failures, score = runner._quality_gate({
        "tcp_connect_ok": True, "success_rate": 1.0, "successful_requests": 3,
        "latency_p95_ms": 100.0,
    })
    assert ok is True and failures == [] and 0 < score <= 1


def test_kcp_skips_tcp_connect_gate_and_probe(tmp_path: Path) -> None:
    suite = MeasurementSuite({"urls": ["https://example.com"]}, timeout=1,
                             target_host="example.com", target_port=443, transport="kcp")
    connectivity = asyncio.run(suite._connectivity_metrics())
    assert connectivity == {"tcp_connect_supported": False}

    runner = ExperimentRunner(mutation_config(tmp_path), FakePanel())  # type: ignore[arg-type]
    assert runner._screening_gate({"tcp_connect_supported": False, "success_rate": 1.0}) == (True, [])
    quality_ok, failures, _ = runner._quality_gate({
        "tcp_connect_supported": False, "success_rate": 1.0, "successful_requests": 1,
    })
    assert quality_ok and failures == []


@pytest.mark.parametrize("stream", [
    {"network": "mkcp"},
    {"network": "tcp", "method": "kcp"},
])
def test_effective_kcp_alias_skips_tcp_connect_gate(stream: dict[str, str]) -> None:
    transport = effective_transport(stream)
    suite = MeasurementSuite({"urls": ["https://example.com"]}, timeout=1,
                             target_host="example.com", target_port=443, transport=transport)

    assert transport == "kcp"
    assert asyncio.run(suite._connectivity_metrics()) == {"tcp_connect_supported": False}


def test_transport_switch_drops_incompatible_vless_flow_from_json_settings() -> None:
    payload = {
        "protocol": "vless",
        "streamSettings": '{"network":"tcp","security":"tls"}',
        "settings": '{"clients":[{"id":"redacted","flow":"xtls-rprx-vision"}]}',
    }
    result = prepare_inbound_payload(payload, {"network": "ws", "security": "tls"})
    assert isinstance(result["streamSettings"], str)
    assert isinstance(result["settings"], str)
    assert "flow" not in json.loads(result["settings"])["clients"][0]


def test_tcp_tls_keeps_vless_flow_on_inbound() -> None:
    payload = {
        "protocol": "vless",
        "streamSettings": {"network": "tcp", "security": "tls"},
        "settings": {"clients": [{"id": "redacted", "flow": "xtls-rprx-vision"}]},
    }
    result = prepare_inbound_payload(payload, {"network": "tcp", "security": "tls"})
    assert result["settings"]["clients"][0]["flow"] == "xtls-rprx-vision"


def test_kcp_timeout_explains_udp_requirement() -> None:
    diagnostic = ExperimentRunner._transport_diagnostic(
        "kcp", {"last_http_error": "ConnectTimeout: "},
    )
    assert diagnostic and "UDP" in diagnostic and "kcpSettings" in diagnostic


def test_canary_detects_that_tcp_answers_for_every_port(tmp_path: Path, monkeypatch) -> None:
    """VPN/proxy подтверждает TCP на любом порту — тогда проверка tcp_connect недостоверна."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    monkeypatch.setattr(ExperimentRunner, "CANARY_PORT", listener.getsockname()[1])
    runner = ExperimentRunner(mutation_config(tmp_path), FakePanel())  # type: ignore[arg-type]
    assert asyncio.run(runner._tcp_probe_is_trustworthy("127.0.0.1")) is False
    listener.close()
    assert asyncio.run(runner._tcp_probe_is_trustworthy("127.0.0.1")) is True


def test_warning_names_an_untrustworthy_tcp_probe(tmp_path: Path) -> None:
    runner = ExperimentRunner(mutation_config(tmp_path), FakePanel())  # type: ignore[arg-type]
    runner._tcp_probe_trustworthy = False
    assert any("tcp_connect_ok" in item for item in runner._warnings())


def test_dead_tunnel_with_open_tcp_names_the_environment() -> None:
    """TCP подтверждает кто угодно (VPN, firewall) — молчаливый отказ туннеля нужно объяснять."""
    diagnostic = ExperimentRunner._transport_diagnostic(
        "xhttp", {"last_http_error": "ConnectTimeout: ", "tcp_connect_ok": True},
    )
    assert diagnostic and "VPN" in diagnostic and "tcp_connect" in diagnostic

    assert ExperimentRunner._transport_diagnostic(
        "xhttp", {"last_http_error": "ConnectTimeout: "}) is None


def test_invalid_success_rate_is_rejected(tmp_path: Path) -> None:
    config = mutation_config(tmp_path)
    config.testing["quality_gates"] = {"min_success_rate": 1.2}
    runner = ExperimentRunner(config, FakePanel())  # type: ignore[arg-type]
    try:
        runner._quality_gate({"tcp_connect_ok": True, "success_rate": 1.0, "successful_requests": 1})
    except ValueError as error:
        assert "between 0 and 1" in str(error)
    else:
        raise AssertionError("invalid min_success_rate was accepted")


def clone_port_config(**testing: Any) -> ExperimentConfig:
    return ExperimentConfig(panel={}, inbound={"mode": "clone", "source_id": 1}, parameters=(), testing=testing)


def test_clone_ports_accept_a_list_or_a_legacy_interval() -> None:
    """Один ключ задаёт и список портов (FW открывает отдельные порты, не подряд), и прежний интервал."""
    assert clone_port_config(ports=[24443]).candidate_ports == (24443,)
    assert clone_port_config(ports=[24443, 24500, 25500]).candidate_ports == (24443, 24500, 25500)
    assert clone_port_config(port_range=[20000, 20002]).candidate_ports == (20000, 20001, 20002)
    assert clone_port_config(port_range=24443).candidate_ports == (24443,)
    # testing.ports — предпочтительная форма; прежний интервал остаётся резервом.
    assert clone_port_config(ports=[24443], port_range=[20000, 21000]).candidate_ports == (24443,)
    assert clone_port_config().candidate_ports == tuple(range(20000, 30001))


def test_invalid_clone_ports_fail_when_the_config_is_built() -> None:
    with pytest.raises(ValueError, match="1..65535"):
        clone_port_config(ports=[70000])
    with pytest.raises(ValueError, match="at least one port"):
        clone_port_config(ports=[])
    with pytest.raises(ValueError, match=r"must be \[low, high\]"):
        clone_port_config(port_range=[20000, 21000, 22000])
    with pytest.raises(ValueError, match="first <= second"):
        clone_port_config(port_range=[21000, 20000])
    with pytest.raises(ValueError, match="one port or a list of ports"):
        clone_port_config(ports="24443")


def test_readback_compares_effective_transport_aliases_and_method_precedence() -> None:
    expected = {"streamSettings": {"network": "raw", "tcpSettings": {"header": {"type": "none"}}}}
    equivalent = {"streamSettings": {"network": "tcp", "tcpSettings": {"header": {"type": "none"}}}}
    different = {"streamSettings": {"network": "ws", "wsSettings": {"path": "/"}}}
    assert ExperimentRunner._readback_error(expected, equivalent) is None
    assert ExperimentRunner._readback_error(expected, different) == "panel_readback_transport_mismatch"

    method_expected = {"streamSettings": {"network": "ws", "method": "splithttp",
                                           "xhttpSettings": {"path": "/x"}}}
    method_actual = {"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/x"}}}
    assert ExperimentRunner._readback_error(method_expected, method_actual) is None


def test_readback_tolerates_empty_values_the_panel_drops_on_save() -> None:
    expected = {"settings": {"decryption": "none", "clients": [{"id": "u", "flow": ""}]},
                "streamSettings": {"network": "tcp", "security": "tls",
                                   "tlsSettings": {"serverName": "example.com", "alpn": []}}}
    actual = {"settings": {"decryption": "none", "clients": [{"id": "u"}]},
              "streamSettings": {"network": "tcp", "security": "tls",
                                 "tlsSettings": {"serverName": "example.com"}}}
    assert ExperimentRunner._readback_error(expected, actual) is None

    dropped_flow = copy.deepcopy(expected)
    dropped_flow["settings"]["clients"][0]["flow"] = "xtls-rprx-vision"
    assert ExperimentRunner._readback_error(dropped_flow, actual) == "panel_readback_settings_mismatch"

    changed = copy.deepcopy(actual)
    changed["settings"]["decryption"] = "auto"
    assert ExperimentRunner._readback_error(expected, changed) == "panel_readback_settings_mismatch"


def test_run_record_carries_a_masked_copy_of_the_applied_inbound(tmp_path: Path, monkeypatch) -> None:
    """Экспорт должен уметь собрать inbound в панели, не читая журнал, поэтому
    запись прогона несёт применённую полезную нагрузку без учётных данных."""
    base = {"id": 9, "port": 9443, "protocol": "vless", "enable": True, "listen": "",
            "settings": json.dumps({"clients": [{"id": "8c1b0e2a-1f4d-4f0e-9b7a-6d5c4b3a2f10", "flow": "",
                                                 "email": "user@example.invalid", "enable": True}],
                                    "decryption": "none"}, separators=(",", ":")),
            "streamSettings": json.dumps({"network": "tcp", "security": "tls",
                                          "tlsSettings": {"serverName": "example.test"}}, separators=(",", ":")),
            "sniffing": json.dumps({"enabled": True, "destOverride": ["http"]}, separators=(",", ":"))}
    applied: list[dict[str, Any]] = []

    class Panel:
        async def get_inbound(self, _inbound_id: int) -> dict[str, Any]:
            return copy.deepcopy(applied[-1]) if applied else copy.deepcopy(base)

        async def xray_logs(self, count: int = 20) -> str:
            return ""

    class Manager:
        mode = "clone"
        source_id = 1
        test_inbound_id = 9
        cleanup_pending = False

        async def apply(self, payload: dict[str, Any]) -> None:
            applied.append(copy.deepcopy(payload))

    class FakeClient:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        async def start(self, _config: dict[str, Any]) -> None:
            return None

        async def stop(self) -> None:
            return None

        def log_tail(self) -> str:
            return ""

        def diagnostic_categories(self) -> list[str]:
            return []

    class FakeSuite:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def response_allowance(self, count: int) -> int:
            return 128 * count

        async def screen(self, count: int) -> dict[str, Any]:
            return {"tcp_connect_ok": True, "successful_requests": count, "failed_requests": 0,
                    "success_rate": 1.0, "http_request_count": count, "http_bytes_received": 128 * count}

        async def run(self, **_kwargs: Any) -> dict[str, Any]:
            raise AssertionError("a screening trial must not run the full suite")

    class StubbedRunner(ExperimentRunner):
        def _config_reason(self, client_config: dict[str, Any]) -> str | None:
            del client_config
            return None

    config = ExperimentConfig(
        panel={"url": "https://localhost"},
        inbound={"mode": "clone", "source_id": 1, "test_port": 9443},
        parameters=(ParameterSpec.from_dict("network", {"type": "enum", "values": ["tcp", "ws"],
                                                        "baseline": "tcp",
                                                        "path": ["streamSettings", "network"]}),),
        testing={"combination_strategy": "mutation", "max_combinations": 1, "runs_per_combination": 1,
                 "validate_config": False, "server_address": "example.test", "socks_port": 10809,
                 "urls": ["https://example.com"], "screening": {"enabled": True, "requests": 1}},
        output={"directory": str(tmp_path), "formats": ["json"]},
    )
    manager = Manager()
    runner = StubbedRunner(config, Panel())  # type: ignore[arg-type]
    runner._manager = manager  # type: ignore[assignment]
    monkeypatch.setattr("app.testing.runner.XrayClient", FakeClient)
    monkeypatch.setattr("app.testing.runner.MeasurementSuite", FakeSuite)
    monkeypatch.setattr("app.testing.runner.validate_pair", lambda *_args, **_kwargs: None)

    record = asyncio.run(runner._one_run(1, 1, {}, "digest", manager, copy.deepcopy(base), "example.test",
                                         screening_only=True, fidelity="screening", requests=1,
                                         urls=["https://example.com"]))
    assert record["result"]["status"] == "OK"
    template = record["inbound_payload"]
    assert template["port"] == 9443 and template["protocol"] == "vless" and template["enable"] is True
    assert "id" not in template and "up" not in template and "expiryTime" not in template
    client = json.loads(template["settings"])["clients"][0]
    assert client["id"] == "***" and client["email"] == "***"
    assert json.loads(template["streamSettings"])["tlsSettings"]["serverName"] == "example.test"
    assert "8c1b0e2a" not in json.dumps(template, ensure_ascii=False)
