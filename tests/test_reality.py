from __future__ import annotations

import copy
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from app.config import ExperimentConfig
from app.parameters.models import ParameterSpec
from app.state.checkpoint import Checkpoint
from app.testing.runner import ExperimentRunner
from app.xray.config_builder import ClientConfigBuilder
from app.xray.reality import (RealityCredentials, prepare_reality_inbound,
                              resolve_profile, validate_pair, parse_candidates, configured_candidates)


def source_inbound() -> dict:
    return {"id": 1, "port": 443, "protocol": "vless",
            "settings": {"clients": [{"id": "client-id", "flow": "xtls-rprx-vision"}]},
            "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {}}}


def test_generated_credentials_roundtrip_and_resume_requires_file(tmp_path: Path) -> None:
    fake = type("Completed", (), {"stdout": "PrivateKey: " + "A" * 43 + "\nPassword (PublicKey): " + "B" * 43 + "\n"})()
    with patch("app.xray.reality.subprocess.run", return_value=fake) as process:
        credentials = RealityCredentials.generate("xray")
    assert process.call_args.args[0] == ["xray", "x25519"]
    assert len(credentials.short_id) == 16
    path = tmp_path / ".reality-credentials.json"
    credentials.save(path, "experiment")
    assert credentials.private_key in path.read_text(encoding="utf-8")
    assert RealityCredentials.load(path, "experiment") == credentials
    with pytest.raises(ValueError, match="checkpoint"):
        RealityCredentials.load(path, "other")
    path.unlink()
    with pytest.raises(FileNotFoundError, match="--resume"):
        RealityCredentials.load(path, "experiment")


def test_reality_profile_requires_explicit_target_for_tls_source() -> None:
    assert resolve_profile({}, source_inbound())[1] == "reality_target_or_sni_missing"
    assert resolve_profile({"reality": {"target": "example.com:443", "server_names": ["example.com"]}},
                           source_inbound())[1] is None
    assert resolve_profile({"reality": {"target": "https://example.com", "server_names": ["example.com"]}},
                           source_inbound())[1] == "reality_target_invalid"


def test_candidate_file_is_relative_deduplicated_and_rejects_conflicting_modes(tmp_path: Path) -> None:
    content = "targets:\n  - {target: www.microsoft.com:443, server_name: www.microsoft.com}\n"
    (tmp_path / "targets.yaml").write_text(content, encoding="utf-8")
    path = tmp_path / "experiment.yaml"
    testing = {"reality": {"candidates_file": "targets.yaml"}}
    assert configured_candidates(testing, path) == parse_candidates(content)
    assert len(parse_candidates(content + "  - {target: www.microsoft.com:443, server_name: www.microsoft.com}\n")) == 1
    with pytest.raises(ValueError, match="either one REALITY target"):
        configured_candidates({"reality": {"candidates_file": "targets.yaml", "target": "x:443"}}, path)
    # The parsed list is cached per file state; an edited file must be re-read.
    (tmp_path / "targets.yaml").write_text(
        "targets:\n  - {target: dl.google.com:443, server_name: dl.google.com}\n", encoding="utf-8")
    assert configured_candidates(testing, path)[0]["target"] == "dl.google.com:443"


def test_reality_scan_filters_targets_before_any_panel_mutation() -> None:
    import asyncio

    class ScanPanel:
        def __init__(self):
            self.calls = []

        async def scan_reality_target(self, target, sni, xver=0):
            self.calls.append((target, sni, xver))
            return {"feasible": target.startswith("www.microsoft"), "privateTarget": False,
                    "reason": "no TLS 1.3"}

    panel = ScanPanel()
    config = ExperimentConfig({}, {}, (), testing={})
    runner = ExperimentRunner(config, panel)  # type: ignore[arg-type]
    candidates = [{"target": "www.microsoft.com:443", "server_name": "www.microsoft.com"},
                  {"target": "invalid.example:443", "server_name": "invalid.example"}]
    accepted, rejected = asyncio.run(runner._scan_candidates(candidates, source_inbound()))
    assert accepted == candidates[:1]
    assert panel.calls == [(item["target"], item["server_name"], 0) for item in candidates]
    assert "invalid.example" in rejected[0]
    assert runner._reality_scan_rejected == []
    with pytest.raises(Exception, match="scanRealityTarget"):
        asyncio.run(ExperimentRunner(config, object())._scan_candidates(candidates, source_inbound()))  # type: ignore[arg-type]


def test_server_client_validation_catches_sni_short_id_and_xhttp_mismatches() -> None:
    profile, _ = resolve_profile({"reality": {"target": "example.com:443", "server_names": ["example.com"]}},
                                 source_inbound())
    assert profile is not None
    credentials = RealityCredentials("A" * 43, "B" * 43, "0123456789abcdef")
    inbound = source_inbound()
    inbound["streamSettings"] = {"network": "xhttp", "security": "reality",
                                 "xhttpSettings": {"path": "/", "mode": "auto"}}
    inbound = prepare_reality_inbound(inbound, profile, credentials)
    client = ClientConfigBuilder("proxy.example.com").build({}, [], inbound)
    assert validate_pair(inbound, client) is None
    changed = copy.deepcopy(client)
    changed["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"] = "wrong.example.com"
    assert validate_pair(inbound, changed) == "reality_sni_mismatch"
    changed = copy.deepcopy(client)
    changed["outbounds"][0]["streamSettings"]["realitySettings"]["shortId"] = "aabb"
    assert validate_pair(inbound, changed) == "reality_short_id_mismatch"
    changed = copy.deepcopy(client)
    changed["outbounds"][0]["streamSettings"]["xhttpSettings"]["path"] = "/other"
    assert validate_pair(inbound, changed) == "xhttp_path_mismatch"


def test_panel_readback_detects_effective_security_change() -> None:
    before = source_inbound()
    after = copy.deepcopy(before)
    after["streamSettings"]["security"] = "none"
    assert ExperimentRunner._readback_error(before, after) == "panel_readback_transport_mismatch"
    assert ExperimentRunner._readback_error(before, copy.deepcopy(before)) is None


class SkipPanel:
    async def get_inbound(self, _inbound_id: int) -> dict:
        return source_inbound()


class SkipManager:
    mode = "clone"
    source_id = 1
    test_inbound_id = 2

    def __init__(self) -> None:
        self.applied = 0
        self.cleaned = False
        self.prepared = False

    async def prepare(self) -> int:
        self.prepared = True
        return self.test_inbound_id

    async def apply(self, payload: dict) -> None:
        self.applied += 1

    async def cleanup(self) -> None:
        self.cleaned = True


class SkipRunner(ExperimentRunner):
    def __init__(self, config: ExperimentConfig, manager: SkipManager):
        super().__init__(config, SkipPanel())  # type: ignore[arg-type]
        self.manager = manager

    async def preflight(self) -> dict:
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        return {"openapi_version": "3.8", "xray_version": "26.9", "source": source_inbound(), "manager": self.manager}

    async def _run_controls(self, manager: SkipManager, base_payload: dict, server_address: str) -> None:
        return None


def skip_config(directory: Path) -> ExperimentConfig:
    security = ParameterSpec.from_dict("security", {"type": "enum", "values": ["reality"],
                                                     "path": ["streamSettings", "security"]})
    return ExperimentConfig({"url": "https://panel.example.com"},
                            {"mode": "clone", "source_id": 1, "test_port": 9443}, (security,),
                            testing={"server_address": "proxy.example.com", "urls": ["https://example.com"],
                                     "runs_per_combination": 5, "max_failed_runs": 3},
                            output={"directory": str(directory), "formats": ["json"]})


def test_reality_list_dry_run_scans_and_keeps_targets_distinct(tmp_path: Path) -> None:
    import asyncio

    class ProbePanel(SkipPanel):
        def __init__(self):
            self.scanned = []

        async def scan_reality_target(self, target, sni, xver=0):
            self.scanned.append((target, sni))
            return {"feasible": True, "privateTarget": False, "certChainBytes": 4000}

    pairs = [{"target": f"site{index}.example:443", "server_name": f"site{index}.example"}
             for index in (1, 2)]
    original = skip_config(tmp_path)
    config = ExperimentConfig(original.panel, original.inbound, original.parameters,
                              testing={**original.testing, "reality": {"candidates": pairs}},
                              output=original.output)
    manager = SkipManager()
    runner = SkipRunner(config, manager)
    panel = ProbePanel()
    runner.panel = panel  # type: ignore[assignment]
    result = asyncio.run(runner.run(dry_run=True))
    assert panel.scanned == [(pair["target"], pair["server_name"]) for pair in pairs]
    assert manager.applied == 0
    assert result["planned_combinations"] == 2
    combinations = list(runner.generator.iter_valid())
    assert len({item.hash for item in combinations}) == 2
    runner._reality_credentials = RealityCredentials("A" * 43, "B" * 43, "0123456789abcdef")
    payloads = [runner._candidate_payload(item.values, source_inbound())[0] for item in combinations]
    assert [item["streamSettings"]["realitySettings"]["target"] for item in payloads] == [
        pair["target"] for pair in pairs]
    assert runner._payload_hash(source_inbound(), combinations[0].values) != runner._payload_hash(
        source_inbound(), combinations[1].values)
    changed = ExperimentConfig(config.panel, config.inbound, config.parameters,
                               testing={**config.testing, "reality": {"candidates": pairs[:1]}}, output=config.output)
    assert runner._search_signature() != ExperimentRunner(changed, panel)._search_signature()  # type: ignore[arg-type]


def test_resume_stops_before_clone_if_previously_accepted_target_fails_probe(tmp_path: Path) -> None:
    import asyncio

    pair = {"target": "www.microsoft.com:443", "server_name": "www.microsoft.com"}
    original = skip_config(tmp_path)
    config = ExperimentConfig(original.panel, original.inbound, original.parameters,
                              testing={**original.testing, "reality": {"candidates": [pair]}}, output=original.output)
    checkpoint = Checkpoint("experiment", {"reality_candidates": [pair]})
    checkpoint.save(tmp_path / "state.json")

    class FailedProbe(SkipPanel):
        async def scan_reality_target(self, target, sni, xver=0):
            return {"feasible": False, "reason": "no TLS 1.3"}

    manager = SkipManager()
    runner = SkipRunner(config, manager)
    runner.panel = FailedProbe()  # type: ignore[assignment]
    with pytest.raises(ValueError, match="retry --resume"):
        asyncio.run(runner.run(resume=True))
    assert not manager.prepared


def test_invalid_reality_candidate_skips_once_without_panel_update_and_resume(tmp_path: Path) -> None:
    import asyncio
    manager = SkipManager()
    config = skip_config(tmp_path)
    first = asyncio.run(SkipRunner(config, manager).run())
    assert first["skipped"] == 1 and first["failed"] == 0 and manager.applied == 0
    records = [json.loads(line) for line in (tmp_path / "results.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(records) == 1 and records[0]["result"]["status"] == "SKIPPED"
    second = asyncio.run(SkipRunner(config, manager).run(resume=True))
    assert second["skipped"] == 1 and manager.applied == 0
    assert len((tmp_path / "results.jsonl").read_text(encoding="utf-8").splitlines()) == 1


def test_controls_continue_after_failure_and_keep_raw_secrets_out(tmp_path: Path) -> None:
    import asyncio

    class ControlRunner(SkipRunner):
        async def _one_run(self, test_id, run_number, values, digest, manager, base_payload,
                           server_address, *, include_ping=False, screening_only=False):
            self.calls.append(base_payload["streamSettings"]["security"])
            return {"timestamp": "now", "result": {"status": "FAILED" if len(self.calls) == 1 else "OK",
                    "stage": "screening", "screening": {"success_rate": 0.0 if len(self.calls) == 1 else 1.0},
                    "client_xray_diagnostics": ["reality_handshake"]}}

    runner = ControlRunner(skip_config(tmp_path), SkipManager())
    runner.calls = []
    runner._reality_profile, _ = resolve_profile(
        {"reality": {"target": "example.com:443", "server_names": ["example.com"]}}, source_inbound())
    runner._reality_credentials = RealityCredentials("A" * 43, "B" * 43, "0123456789abcdef")
    asyncio.run(ExperimentRunner._run_controls(runner, runner.manager, source_inbound(), "proxy.example.com"))
    rows = [json.loads(line) for line in (tmp_path / "diagnostics.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [row["profile"] for row in rows] == ["tcp_tls", "tcp_reality", "xhttp_reality"]
    assert [row["status"] for row in rows] == ["FAILED", "OK", "OK"]
    assert runner._reality_credentials.private_key not in (tmp_path / "diagnostics.jsonl").read_text(encoding="utf-8")
