from __future__ import annotations


import asyncio
import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from app.config import ExperimentConfig
from app.parameters.models import ParameterSpec
from app.testing.runner import ExperimentRunner
from app.xray.config_builder import ClientConfigBuilder
from app.xray.validation import (CHECK_BINARY_MISSING, CHECK_DISABLED, CHECK_TIMEOUT, CLIENT_CONFIG_INVALID,
                                 CORE_REJECTED, CoreValidationUnavailable, ClientConfigValidator,
                                 check_client_config, reason_code_for_output)


def base_config() -> dict[str, Any]:
    """A client config shaped exactly like the one ClientConfigBuilder emits."""
    return ClientConfigBuilder("example.test").build({}, (), {
        "protocol": "vless",
        "port": 9443,
        "settings": {"clients": [{"id": "redacted", "flow": "xtls-rprx-vision"}]},
        "streamSettings": {"network": "tcp", "security": "tls"},
    })


def altered(**changes: Any) -> dict[str, Any]:
    config = base_config()
    stream = config["outbounds"][0]["streamSettings"]
    stream.update(changes)
    return config


def test_builder_output_passes_the_structural_check() -> None:
    assert check_client_config(base_config()) is None
    reality = ClientConfigBuilder("example.test").build({}, (), {
        "protocol": "vless",
        "port": 443,
        "settings": {"clients": [{"id": "redacted", "flow": "xtls-rprx-vision"}]},
        "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"settings": {
            "password": "B" * 43, "serverName": "www.example.com", "shortId": "0123456789abcdef",
            "fingerprint": "chrome"}}},
    })
    assert check_client_config(reality) is None


@pytest.mark.parametrize(("name", "config", "expected"), [
    ("not an object", [], CLIENT_CONFIG_INVALID),
    ("no socks inbound", {**base_config(), "inbounds": []}, "client_socks_inbound_missing"),
    ("no outbound", {"inbounds": base_config()["inbounds"], "outbounds": []}, "client_outbound_missing"),
    ("unsupported protocol", {**base_config(), "outbounds": [{"protocol": "freedom"}]},
     "client_outbound_protocol_unsupported"),
    ("unsupported transport", altered(network="zzz"), "client_transport_unsupported"),
    ("unsupported security", altered(security="xtls"), "client_security_unsupported"),
    ("vision on ws", altered(network="ws", security="tls"), "client_flow_incompatible"),
    ("vision without tls", altered(security="none"), "client_flow_incompatible"),
    ("reality without key", altered(network="tcp", security="reality"), "client_reality_settings_incomplete"),
])
def test_structural_check_rejects_configs_xray_cannot_build(name: str, config: Any, expected: str) -> None:
    assert check_client_config(config) == expected, name


def test_structural_check_rejects_missing_user_and_mux() -> None:
    no_user = base_config()
    no_user["outbounds"][0]["settings"]["vnext"][0]["users"] = []
    assert check_client_config(no_user) == "client_credentials_missing"
    assert check_client_config(altered()) is None
    empty_flow = base_config()
    empty_flow["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"] = ""
    assert check_client_config(empty_flow) is None, "an empty flow is not a Vision flow"
    muxed = base_config()
    muxed["outbounds"][0]["mux"] = {"enabled": True, "concurrency": -1}
    assert check_client_config(muxed) is None
    muxed["outbounds"][0]["mux"] = {"enabled": "yes"}
    assert check_client_config(muxed) == "client_mux_invalid"


@pytest.mark.parametrize("network", ["raw", "mkcp", "websocket", "splithttp", "tcp", "kcp", "ws", "xhttp"])
def test_structural_check_accepts_pinned_core_transport_aliases(network):
    config = altered(network=network, security="none")
    config["outbounds"][0]["settings"]["vnext"][0]["users"][0].pop("flow", None)
    assert check_client_config(config) is None


def test_structural_check_rejects_removed_quic_transport():
    assert check_client_config(altered(network="quic", security="none")) == "client_transport_unsupported"


def test_structural_check_uses_method_precedence_and_mux_sentinels():
    config = altered(network="quic", method="raw", security="none")
    config["outbounds"][0]["settings"]["vnext"][0]["users"][0].pop("flow", None)
    assert check_client_config(config) is None
    config["outbounds"][0]["mux"] = {"enabled": True, "xudpConcurrency": -1}
    assert check_client_config(config) is None


def test_reason_code_mapping_never_returns_raw_output() -> None:
    secret = "password=SECRET_PRIVATE_KEY"
    assert reason_code_for_output(f"failed to load config: unknown transport protocol: zzz {secret}") == \
        "client_config_unsupported_transport"
    assert reason_code_for_output("infra/conf/serial: failed to decode config: invalid character ']'") == \
        "client_config_json_syntax_error"
    assert reason_code_for_output("prohibited unless the server address is a private IP or domain") == \
        "client_config_plaintext_public_destination"
    assert reason_code_for_output(f"failed to build REALITY config {secret}") == "client_config_reality_parameters_invalid"
    assert reason_code_for_output("unknown cipher method: bogus") == "client_config_unsupported_cipher"
    assert reason_code_for_output("something new") == CORE_REJECTED


def test_missing_binary_degrades_without_failing_the_run(tmp_path: Path) -> None:
    validator = ClientConfigValidator(str(tmp_path / "no-such-xray"), strict=False, config_directory=tmp_path)
    assert validator.availability() == CHECK_BINARY_MISSING
    assert validator.check(base_config()) == (False, None)


def test_disabled_check_never_spawns_a_process(tmp_path: Path) -> None:
    validator = ClientConfigValidator("xray", enabled=False, strict=False, config_directory=tmp_path)
    with patch("app.xray.validation.subprocess.run") as runner:
        assert validator.availability() == CHECK_DISABLED
        assert validator.check(base_config()) == (False, None)
    assert not runner.called


def completed(returncode: int, output: str) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=output, stderr="")


def test_core_rejection_becomes_a_stable_code_and_its_output_is_dropped(tmp_path: Path) -> None:
    responses = [completed(0, "usage: xray run [-c config.json]  The -test flag tells Xray to test config files only"),
                 completed(23, "Failed to start: unknown transport protocol: zzz password=SECRET_KEY")]
    calls: list[list[str]] = []
    real_run = subprocess.run

    def fake_run(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess:
        if command[0] != "xray":
            return real_run(command, **_kwargs)
        calls.append(command)
        return responses[min(len(calls), len(responses)) - 1]

    validator = ClientConfigValidator("xray", config_directory=tmp_path, timeout=5)
    with patch("app.xray.validation.subprocess.run", fake_run):
        assert validator.check(base_config()) == (True, "client_config_unsupported_transport")
        assert validator.check(base_config()) == (True, "client_config_unsupported_transport")

    assert calls[0][1:] == ["help", "run"]
    assert calls[1][1:4] == ["run", "-test", "-c"]
    assert len(calls) == 2, "an identical config must be answered from the cache"
    assert list(tmp_path.iterdir()) == [], "the temporary config must not be left behind"
    assert "SECRET_KEY" not in str(validator.check(base_config()))


def test_core_acceptance_is_reported_as_valid(tmp_path: Path) -> None:
    responses = [completed(0, "The -test flag tells Xray to test config files only"),
                 completed(0, "Configuration OK.")]

    real_run = subprocess.run
    def fake_run(_command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess:
        if _command[0] != "xray":
            return real_run(_command, **_kwargs)
        return responses.pop(0)

    validator = ClientConfigValidator("xray", config_directory=tmp_path)
    with patch("app.xray.validation.subprocess.run", fake_run):
        assert validator.check(base_config()) == (True, None)


def test_unusable_binary_degrades_instead_of_blocking_candidates(tmp_path: Path) -> None:
    real_run = subprocess.run
    def fake_run(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess:
        if command[0] != "xray":
            return real_run(command, **_kwargs)
        if command[1] == "help":
            return completed(0, "The -test flag tells Xray to test config files only")
        raise subprocess.TimeoutExpired(command, 5)

    validator = ClientConfigValidator("xray", strict=False, config_directory=tmp_path, timeout=5)
    with patch("app.xray.validation.subprocess.run", fake_run):
        assert validator.check(base_config()) == (False, None)
        assert validator._availability == CHECK_TIMEOUT
        assert validator.check(altered(network="ws")) == (False, None)


def test_strict_mode_raises_a_stable_error_for_missing_core(tmp_path: Path) -> None:
    validator = ClientConfigValidator(str(tmp_path / "no-such-xray"), config_directory=tmp_path)
    with pytest.raises(CoreValidationUnavailable) as error:
        validator.check(base_config())
    assert error.value.reason_code == CHECK_BINARY_MISSING
    assert str(tmp_path) not in str(error.value)


def test_failed_help_probe_is_not_accepted_just_because_it_mentions_test_flag(tmp_path: Path, monkeypatch) -> None:
    def fake_run(_command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess:
        return completed(2, "error: unsupported invocation; flags include -test")

    validator = ClientConfigValidator("xray", config_directory=tmp_path)
    monkeypatch.setattr("app.xray.validation.subprocess.run", fake_run)
    with pytest.raises(CoreValidationUnavailable) as error:
        validator.check(base_config())
    assert error.value.reason_code == "xray_binary_unusable"


def test_core_verdict_cache_is_invalidated_when_binary_identity_changes(tmp_path: Path, monkeypatch) -> None:
    calls: list[list[str]] = []
    identity = ("xray-a", 1, 1, 1)

    def fake_run(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess:
        calls.append(command)
        return completed(0, "Usage: xray run -test")

    validator = ClientConfigValidator("xray", config_directory=tmp_path)
    monkeypatch.setattr("app.xray.validation.subprocess.run", fake_run)
    monkeypatch.setattr(validator, "_core_identity", lambda: identity)
    assert validator.check(base_config()) == (True, None)
    assert validator.check(base_config()) == (True, None)
    identity = ("xray-a", 2, 2, 2)
    assert validator.check(base_config()) == (True, None)
    assert [item[1:3] for item in calls].count(["run", "-test"]) == 2
    assert [item[1:3] for item in calls].count(["help", "run"]) == 2


def test_timeout_is_retried_and_never_cached(tmp_path: Path, monkeypatch) -> None:
    config_calls = 0
    help_calls = 0

    def fake_run(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess:
        nonlocal config_calls, help_calls
        if command[1:3] == ["help", "run"]:
            help_calls += 1
            return completed(0, "Usage: xray run -test")
        config_calls += 1
        if config_calls == 1:
            raise subprocess.TimeoutExpired(command, 1)
        return completed(0, "Configuration OK")

    validator = ClientConfigValidator("xray", config_directory=tmp_path)
    monkeypatch.setattr("app.xray.validation.subprocess.run", fake_run)
    with pytest.raises(CoreValidationUnavailable) as error:
        validator.check(base_config())
    assert error.value.reason_code == CHECK_TIMEOUT
    assert validator.availability() == CHECK_TIMEOUT
    assert help_calls == 1, "status reads must not retry or hide the last failure"
    assert validator.check(base_config()) == (True, None)
    assert config_calls == 2
    assert help_calls == 2


def test_config_with_external_file_dependency_is_not_cached(tmp_path: Path, monkeypatch) -> None:
    config = base_config()
    config["outbounds"][0]["streamSettings"]["tlsSettings"] = {
        "certificates": [{"certificateFile": "certificate.pem", "keyFile": "private-key.pem"}],
    }
    config_calls = 0

    def fake_run(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess:
        nonlocal config_calls
        if command[1:3] == ["help", "run"]:
            return completed(0, "Usage: xray run -test")
        config_calls += 1
        return completed(0, "Configuration OK")

    validator = ClientConfigValidator("xray", config_directory=tmp_path)
    monkeypatch.setattr("app.xray.validation.subprocess.run", fake_run)
    assert validator.check(config) == (True, None)
    assert validator.check(config) == (True, None)
    assert config_calls == 2
    assert validator._has_external_file_dependency({"routing": {"rules": [{"ip": ["geoip:private"]}]}})
    assert validator._has_external_file_dependency({"routing": {"rules": [{"domain": ["geosite:category-ads"]}]}})


def test_unknown_core_failure_is_not_reused(tmp_path: Path, monkeypatch) -> None:
    core_calls = 0

    def fake_run(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess:
        nonlocal core_calls
        if command[1:3] == ["help", "run"]:
            return completed(0, "Usage: xray run -test")
        core_calls += 1
        return completed(17, "unexpected internal failure")

    validator = ClientConfigValidator("xray", config_directory=tmp_path)
    validator._cache_limit = 1
    monkeypatch.setattr("app.xray.validation.subprocess.run", fake_run)
    assert validator.check(base_config()) == (True, CORE_REJECTED)
    assert validator.check(base_config()) == (True, CORE_REJECTED)
    assert core_calls == 2, "generic core failures are not deterministic config verdicts"


def test_verdict_cache_is_bounded_lru(tmp_path: Path, monkeypatch) -> None:
    core_calls = 0

    def fake_run(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess:
        nonlocal core_calls
        if command[1:3] == ["help", "run"]:
            return completed(0, "Usage: xray run -test")
        core_calls += 1
        return completed(0, "Configuration OK")

    validator = ClientConfigValidator("xray", config_directory=tmp_path)
    validator._cache_limit = 2
    monkeypatch.setattr("app.xray.validation.subprocess.run", fake_run)
    first, second, third = base_config(), altered(network="ws"), altered(network="grpc")
    assert validator.check(first) == (True, None)
    assert validator.check(second) == (True, None)
    assert validator.check(third) == (True, None)
    assert len(validator._cache) == 2
    assert validator.check(first) == (True, None)
    assert core_calls == 4


class RecordingManager:
    mode = "clone"
    source_id = 1
    test_inbound_id = 9

    def __init__(self) -> None:
        self.applied: list[dict[str, Any]] = []
        self.cleaned = False

    async def prepare(self) -> int:
        return self.test_inbound_id

    async def apply(self, payload: dict[str, Any]) -> None:
        self.applied.append(payload)

    async def cleanup(self) -> None:
        self.cleaned = True


class StubPanel:
    async def get_inbound(self, _inbound_id: int) -> dict[str, Any]:
        return json.loads(json.dumps({
            "id": 9, "port": 9443, "protocol": "vless",
            "settings": {"clients": [{"id": "redacted"}]},
            "streamSettings": {"network": "tcp", "security": "tls"},
        }))


class PreflightPanel(StubPanel):
    def __init__(self) -> None:
        self.writes = 0

    async def authenticate(self) -> None:
        return None

    async def discover(self) -> dict[str, Any]:
        return {"info": {"version": "3.8.0"}, "paths": {}}

    async def list_inbounds(self) -> list[dict[str, Any]]:
        return []

    async def server_status(self) -> dict[str, Any]:
        return {"xray": {"state": "running", "version": "26.9.9"}}

    async def add_inbound(self, *_args: Any, **_kwargs: Any) -> None:
        self.writes += 1

    async def update_inbound(self, *_args: Any, **_kwargs: Any) -> None:
        self.writes += 1


class OfflineRunner(ExperimentRunner):
    """Runs the real candidate validation while refusing to touch the network."""

    def __init__(self, config: ExperimentConfig, manager: RecordingManager):
        super().__init__(config, StubPanel())  # type: ignore[arg-type]
        self.manager = manager
        self.connection_attempts = 0

    async def preflight(self) -> dict[str, Any]:
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        return {"openapi_version": "3.8.0", "xray_version": "26.9.9", "manager": self.manager,
                "source": {"protocol": "vless", "streamSettings": {"network": "tcp", "security": "tls"}}}

    async def _run_controls(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    async def _one_run(self, test_id: int, run_number: int, values: dict[str, Any], digest: str,
                       *_args: Any, **_kwargs: Any) -> dict[str, Any]:
        self.connection_attempts += 1
        return {"test_id": test_id, "run": run_number, "timestamp": "now", "configuration_hash": digest,
                "configuration": values, "result": {"status": "OK", "score": 1.0}}


def single_candidate_config(output: Path) -> ExperimentConfig:
    parameter = ParameterSpec.from_dict("transport", {
        "type": "enum", "values": ["tcp"], "path": ["streamSettings", "network"],
    })
    return ExperimentConfig(
        panel={"url": "https://localhost"},
        inbound={"mode": "clone", "source_id": 1, "test_port": 9443},
        parameters=(parameter,),
        testing={"combination_strategy": "pairwise", "max_combinations": 5, "runs_per_combination": 1,
                 "server_address": "example.test", "urls": ["https://example.com"]},
        output={"directory": str(output), "formats": ["json"]},
    )


def test_runner_records_the_rejected_config_without_updating_the_inbound(tmp_path: Path) -> None:
    manager = RecordingManager()
    runner = OfflineRunner(single_candidate_config(tmp_path), manager)
    with patch.object(runner._config_validator, "check",
                      return_value=(True, "client_config_plaintext_public_destination")):
        summary = asyncio.run(runner.run())

    records = [json.loads(line) for line in (tmp_path / "results.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [item["result"] for item in records] == [
        {"status": "SKIPPED", "stage": "validation", "reason_code": "client_config_plaintext_public_destination"}]
    assert summary["skipped"] == 1 and summary["failed"] == 0 and summary["completed"] == 1
    assert manager.applied == [] and manager.cleaned is True
    assert runner.connection_attempts == 0, "a rejected config must never reach a connection attempt"


def test_dry_run_reports_core_rejected_candidates_as_skipped(tmp_path: Path) -> None:
    runner = OfflineRunner(single_candidate_config(tmp_path), RecordingManager())
    with patch.object(runner._config_validator, "check",
                      return_value=(True, "client_config_plaintext_public_destination")):
        response = asyncio.run(runner.run(dry_run=True))
    assert response["planned_combinations"] == 1
    assert response["skipped_combinations"] == 1
    assert runner.connection_attempts == 0


def test_runner_reports_the_unavailable_check_as_a_warning(tmp_path: Path) -> None:
    manager = RecordingManager()
    config = single_candidate_config(tmp_path)
    config.testing["validate_config"] = False
    runner = OfflineRunner(config, manager)
    with patch.object(runner._config_validator, "availability", return_value=CHECK_BINARY_MISSING):
        summary = asyncio.run(runner.run())
    assert any(CHECK_BINARY_MISSING in warning for warning in summary["warnings"])
    assert runner.connection_attempts == 1


def test_strict_preflight_stops_before_any_panel_write(tmp_path: Path) -> None:
    panel = PreflightPanel()
    runner = ExperimentRunner(single_candidate_config(tmp_path), panel)  # type: ignore[arg-type]
    with patch.object(runner._config_validator, "availability", return_value=CHECK_BINARY_MISSING):
        with pytest.raises(CoreValidationUnavailable) as error:
            asyncio.run(runner.preflight())
    assert error.value.reason_code == CHECK_BINARY_MISSING
    assert panel.writes == 0


def test_strict_candidate_failure_stops_before_candidate_apply(tmp_path: Path) -> None:
    manager = RecordingManager()
    runner = OfflineRunner(single_candidate_config(tmp_path), manager)
    with patch.object(runner._config_validator, "check",
                      side_effect=CoreValidationUnavailable(CHECK_TIMEOUT)):
        with pytest.raises(CoreValidationUnavailable) as error:
            asyncio.run(runner.run())
    assert error.value.reason_code == CHECK_TIMEOUT
    assert manager.applied == [] and manager.cleaned is True


def test_runner_structure_check_runs_before_the_local_core(tmp_path: Path) -> None:
    runner = ExperimentRunner(single_candidate_config(tmp_path), StubPanel())  # type: ignore[arg-type]
    candidate = {
        "protocol": "vless", "port": 9443, "settings": {"clients": [{"id": "redacted"}]},
        "streamSettings": {"network": "zzz", "security": "tls"},
    }
    with patch.object(runner._config_validator, "check") as core:
        assert runner._candidate_error({}, candidate, "example.test") == "client_transport_unsupported"
    assert not core.called


@pytest.mark.parametrize(("network", "path", "override", "expected"), [
    ("ws", ["outbounds", 0, "streamSettings", "wsSettings", "path"], "/client", "ws_path_mismatch"),
    ("grpc", ["outbounds", 0, "streamSettings", "grpcSettings", "serviceName"], "other", "grpc_service_name_mismatch"),
    ("tcp", ["outbounds", 0, "settings", "vnext", 0, "users", 0, "id"], "other-id", "client_credentials_mismatch"),
    ("tcp", ["outbounds", 0, "streamSettings", "method"], "websocket", "transport_or_security_mismatch"),
])
def test_candidate_error_rejects_client_server_override_mismatches(tmp_path, network, path, override, expected):
    spec = ParameterSpec.from_dict("client_override", {"type": "string", "values": [override],
                                                        "target": "client", "path": path})
    config = ExperimentConfig(
        panel={"url": "https://localhost"}, inbound={"mode": "clone", "source_id": 1, "test_port": 9443},
        parameters=(spec,), testing={"combination_strategy": "pairwise", "max_combinations": 5,
                                     "runs_per_combination": 1, "server_address": "example.test",
                                     "urls": ["https://example.com"], "validate_config": False},
        output={"directory": str(tmp_path), "formats": ["json"]},
    )
    runner = ExperimentRunner(config, StubPanel())  # type: ignore[arg-type]
    stream: dict[str, Any] = {"network": network, "security": "none"}
    if network == "ws":
        stream["wsSettings"] = {"path": "/server"}
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": "server"}
    inbound = {"id": 9, "port": 9443, "protocol": "vless",
               "settings": {"clients": [{"id": "server-id"}]}, "streamSettings": stream}
    assert runner._candidate_error({"client_override": override}, inbound, "example.test") == expected


def test_candidate_error_does_not_reject_ignored_kcp_seed_override(tmp_path):
    spec = ParameterSpec.from_dict("client_seed", {
        "type": "string", "values": ["client-seed"], "target": "client",
        "path": ["outbounds", 0, "streamSettings", "kcpSettings", "seed"],
    })
    config = ExperimentConfig(
        panel={"url": "https://localhost"}, inbound={"mode": "clone", "source_id": 1, "test_port": 9443},
        parameters=(spec,), testing={"combination_strategy": "pairwise", "max_combinations": 5,
                                     "runs_per_combination": 1, "server_address": "example.test",
                                     "urls": ["https://example.com"],
                                     "validate_config": False,
                                     "xray_binary": str(Path(__file__).resolve().parents[1] / ".tools" / "xray" / "xray.exe")},
        output={"directory": str(tmp_path), "formats": ["json"]},
    )
    runner = ExperimentRunner(config, StubPanel())  # type: ignore[arg-type]
    runner._server_xray_version = "26.9.9"
    inbound = {"id": 9, "port": 9443, "protocol": "vless",
               "settings": {"clients": [{"id": "server-id"}]},
               "streamSettings": {"network": "kcp", "security": "none",
                                  "kcpSettings": {"seed": "server-seed"}}}
    assert runner._candidate_error({"client_seed": "client-seed"}, inbound, "example.test") is None
    assert any("KCP seed is ignored" in item for item in runner._warnings())


def test_kcp_diagnostic_reaches_the_candidate_result(tmp_path: Path, monkeypatch) -> None:
    class EchoPanel(StubPanel):
        current: dict[str, Any] | None = None

        async def get_inbound(self, inbound_id: int) -> dict[str, Any]:
            del inbound_id
            assert self.current is not None
            return json.loads(json.dumps(self.current))

    panel = EchoPanel()

    class EchoManager(RecordingManager):
        async def apply(self, payload: dict[str, Any]) -> None:
            await super().apply(payload)
            panel.current = json.loads(json.dumps(payload))

    class FakeXray:
        def __init__(self, *_args: Any, **_kwargs: Any):
            pass

        async def start(self, _config: dict[str, Any]) -> None:
            return None

        async def stop(self) -> None:
            return None

    class FakeMeasurements:
        def __init__(self, *_args: Any, **_kwargs: Any):
            pass

        async def screen(self, _count: int) -> dict[str, Any]:
            return {"tcp_connect_supported": False, "successful_requests": 1, "failed_requests": 0,
                    "success_rate": 1.0, "http_request_count": 1, "http_bytes_received": 0}

        async def run(self, **_kwargs: Any) -> dict[str, Any]:
            return {"tcp_connect_supported": False, "successful_requests": 1, "failed_requests": 0,
                    "success_rate": 1.0, "http_request_count": 1, "http_bytes_received": 0,
                    "latency_p95_ms": 10.0}

    monkeypatch.setattr("app.testing.runner.XrayClient", FakeXray)
    monkeypatch.setattr("app.testing.runner.MeasurementSuite", FakeMeasurements)
    config = single_candidate_config(tmp_path)
    config.testing["validate_config"] = False
    runner = ExperimentRunner(config, panel)  # type: ignore[arg-type]
    runner._server_xray_version = "26.9.9"
    manager = EchoManager()
    runner._manager = manager  # mirrors the assignment performed by run()
    source = {"id": 9, "port": 9443, "protocol": "vless",
              "settings": {"clients": [{"id": "server-id"}]},
              "streamSettings": {"network": "kcp", "security": "none",
                                 "kcpSettings": {"seed": "private-seed", "header": {"type": "utp"}}}}
    record = asyncio.run(runner._one_run(1, 1, {"transport": "kcp"}, "digest", manager, source,
                                         "example.test"))
    diagnostics = record["result"]["diagnostics"]
    assert [item["code"] for item in diagnostics] == ["kcp_seed_ignored_by_core", "kcp_header_ignored_by_core"]
    assert "private-seed" not in json.dumps(record)


def test_candidate_pair_matches_any_enabled_vless_account(tmp_path):
    spec = ParameterSpec.from_dict("client_override", {
        "type": "string", "values": ["second-id"], "target": "client",
        "path": ["outbounds", 0, "settings", "vnext", 0, "users", 0, "id"],
    })
    config = ExperimentConfig(
        panel={"url": "https://localhost"}, inbound={"mode": "clone", "source_id": 1, "test_port": 9443},
        parameters=(spec,), testing={"combination_strategy": "pairwise", "max_combinations": 5,
                                     "runs_per_combination": 1, "server_address": "example.test",
                                     "urls": ["https://example.com"], "validate_config": False},
        output={"directory": str(tmp_path), "formats": ["json"]},
    )
    runner = ExperimentRunner(config, StubPanel())  # type: ignore[arg-type]
    inbound = {"id": 9, "port": 9443, "protocol": "vless",
               "settings": {"clients": [{"id": "first-id", "enable": False}, {"id": "second-id"}]},
               "streamSettings": {"network": "tcp", "security": "none"}}
    assert runner._candidate_error({"client_override": "second-id"}, inbound, "example.test") is None


def test_candidate_check_precedes_apply_and_readback_check_precedes_client_start(tmp_path: Path, monkeypatch) -> None:
    """The candidate is checked before apply; the readback is checked after it.

    The readback config only exists once the candidate has been applied, so its
    ``run -test`` must sit between `manager.apply` and the client start.
    """
    class EchoPanel(StubPanel):
        current: dict[str, Any] | None = None

        async def get_inbound(self, inbound_id: int) -> dict[str, Any]:
            del inbound_id
            assert self.current is not None
            return json.loads(json.dumps(self.current))

    panel = EchoPanel()
    starts: list[dict[str, Any]] = []

    class EchoManager(RecordingManager):
        async def apply(self, payload: dict[str, Any]) -> None:
            await super().apply(payload)
            panel.current = json.loads(json.dumps(payload))

    class FakeXray:
        def __init__(self, *_args: Any, **_kwargs: Any):
            pass

        async def start(self, config: dict[str, Any]) -> None:
            starts.append(config)

        async def stop(self) -> None:
            return None

    monkeypatch.setattr("app.testing.runner.XrayClient", FakeXray)
    config = single_candidate_config(tmp_path)
    runner = ExperimentRunner(config, panel)  # type: ignore[arg-type]
    manager = EchoManager()
    runner._manager = manager  # type: ignore[assignment]  # mirrors the assignment performed by run()
    source = {"id": 9, "port": 9443, "protocol": "vless",
              "settings": {"clients": [{"id": "server-id"}]},
              "streamSettings": {"network": "tcp", "security": "tls"}}
    applies_at_check: list[int] = []

    def fake_check(_client_config: dict[str, Any]) -> tuple[bool, str | None]:
        applies_at_check.append(len(manager.applied))
        return (True, None) if len(applies_at_check) == 1 else (True, "client_config_unsupported_transport")

    monkeypatch.setattr(runner._config_validator, "check", fake_check)
    assert runner._candidate_error({"transport": "tcp"}, source, "example.test") is None
    record = asyncio.run(runner._one_run(1, 1, {"transport": "tcp"}, "digest", manager, source,  # type: ignore[arg-type]
                                         "example.test"))
    assert applies_at_check == [0, 1], "the candidate check precedes apply and the readback check follows it"
    assert record["result"]["status"] == "INVALID_CONFIG"
    assert record["result"]["stage"] == "validation"
    assert record["result"]["reason_code"] == "client_config_unsupported_transport"
    assert starts == [], "a rejected readback config must never reach the client start"
    assert record["client_starts"] == 0
    assert record["api_applies"] == 1, "the candidate payload was applied before the readback check"
