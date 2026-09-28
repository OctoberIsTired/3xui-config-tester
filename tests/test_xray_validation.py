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
                                 CORE_REJECTED, ClientConfigValidator, check_client_config, reason_code_for_output)


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
    assert check_client_config(muxed) == "client_mux_invalid"
    muxed["outbounds"][0]["mux"] = {"enabled": "yes"}
    assert check_client_config(muxed) == "client_mux_invalid"


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
    assert CORE_REJECTED in reason_code_for_output("something new")


def test_missing_binary_degrades_without_failing_the_run(tmp_path: Path) -> None:
    validator = ClientConfigValidator(str(tmp_path / "no-such-xray"), config_directory=tmp_path)
    assert validator.availability() == CHECK_BINARY_MISSING
    assert validator.check(base_config()) == (False, None)


def test_disabled_check_never_spawns_a_process(tmp_path: Path) -> None:
    validator = ClientConfigValidator("xray", enabled=False, config_directory=tmp_path)
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

    def fake_run(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess:
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

    def fake_run(_command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess:
        return responses.pop(0)

    validator = ClientConfigValidator("xray", config_directory=tmp_path)
    with patch("app.xray.validation.subprocess.run", fake_run):
        assert validator.check(base_config()) == (True, None)


def test_unusable_binary_degrades_instead_of_blocking_candidates(tmp_path: Path) -> None:
    def fake_run(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess:
        if command[1] == "help":
            return completed(0, "The -test flag tells Xray to test config files only")
        raise subprocess.TimeoutExpired(command, 5)

    validator = ClientConfigValidator("xray", config_directory=tmp_path, timeout=5)
    with patch("app.xray.validation.subprocess.run", fake_run):
        assert validator.check(base_config()) == (False, None)
    assert validator.availability() == CHECK_TIMEOUT
    with patch("app.xray.validation.subprocess.run") as runner:
        assert validator.check(altered(network="ws")) == (False, None)
    assert not runner.called


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
    runner = OfflineRunner(single_candidate_config(tmp_path), manager)
    with patch.object(runner._config_validator, "availability", return_value=CHECK_BINARY_MISSING):
        summary = asyncio.run(runner.run())
    assert any(CHECK_BINARY_MISSING in warning for warning in summary["warnings"])
    assert runner.connection_attempts == 1


def test_runner_structure_check_runs_before_the_local_core(tmp_path: Path) -> None:
    runner = ExperimentRunner(single_candidate_config(tmp_path), StubPanel())  # type: ignore[arg-type]
    candidate = {
        "protocol": "vless", "port": 9443, "settings": {"clients": [{"id": "redacted"}]},
        "streamSettings": {"network": "zzz", "security": "tls"},
    }
    with patch.object(runner._config_validator, "check") as core:
        assert runner._candidate_error({}, candidate, "example.test") == "client_transport_unsupported"
    assert not core.called
