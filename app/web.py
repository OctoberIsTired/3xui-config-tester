"""Local-only configuration UI for 3xui-tester.

This intentionally has no authentication.  It binds only to 127.0.0.1 and
never serializes panel credentials back to the browser.
"""
from __future__ import annotations

import argparse
import asyncio
import itertools
import json
import re
import socket
import threading
import uuid
from copy import deepcopy
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import yaml

from app.api.three_xui import ThreeXUIClient
from app.config import ExperimentConfig, _expand_env, load_config, offline_warnings, REALITY_CANDIDATES_UNCHECKED_WARNING
from app.xray.reality import configured_candidates, parse_candidates
from app.parameters.generator import CombinationGenerator
from app.parameters.models import ParameterSpec
from app.parameters.registry import parameter_registry
from app.results.writer import ResultStore, _configuration_label
from app.security.masking import mask_parameter_values, mask_secrets
from app.testing.runner import ExperimentRunner


def _config_from_raw(raw: dict[str, Any], source: Path | None = None) -> ExperimentConfig:
    raw = _expand_env(raw)
    for key in ("panel", "inbound", "parameters"):
        if key not in raw:
            raise ValueError(f"Missing required section: {key}")
    parameters = tuple(ParameterSpec.from_dict(name, definition) for name, definition in raw["parameters"].items())
    config = ExperimentConfig(raw["panel"], raw["inbound"], parameters, raw.get("testing", {}), raw.get("timeouts", {}), raw.get("output", {}), source)
    config.search_parameters()
    return config


def _compact_configuration_label(serialized: Any, number: int) -> str:
    try:
        configuration = json.loads(serialized) if isinstance(serialized, str) else dict(serialized or {})
    except (TypeError, ValueError):
        configuration = {}
    profile = " / ".join(str(configuration[key]).upper() for key in ("network", "security")
                         if isinstance(configuration.get(key), str) and configuration[key])
    return f"#{number} · {profile}" if profile else f"#{number}"


class WebService:
    REPORT_FILES = ("results.xlsx", "results.csv", "summary.csv", "results.json", "results.jsonl", "errors.jsonl", "diagnostics.jsonl")
    RUN_ID = re.compile(r"\d{8}-\d{6}-[0-9a-f]{8}\Z")

    def __init__(self, config_path: Path):
        self.config_path = config_path.resolve()
        self._run_lock = threading.Lock()
        self._run_state: dict[str, Any] = {"status": "idle"}
        self._runner: ExperimentRunner | None = None
        self._stop_requested = False

    def raw_config(self) -> dict[str, Any]:
        if self.config_path.exists():
            return yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        return {
            "panel": {"url": "", "api_token": "${PANEL_API_TOKEN}", "verify_tls": True},
            "inbound": {"mode": "clone", "source_id": None},
            "testing": {"server_address": "", "xray_binary": "xray",
                        "port_range": [20000, 21000], "urls": ["https://example.com"],
                        "combination_strategy": "pairwise", "max_combinations": 50},
            "parameters": {},
            "output": {"directory": "./results", "formats": ["csv", "json", "xlsx"]},
        }

    def public_config(self) -> dict[str, Any]:
        data = deepcopy(self.raw_config())
        panel = data.setdefault("panel", {})
        for key in ("api_token", "password", "username"):
            panel.pop(key, None)
        reality = data.get("testing", {}).get("reality")
        if isinstance(reality, dict) and reality.get("candidates_file"):
            reality["candidates"] = configured_candidates(data["testing"], self.config_path)
            reality.pop("candidates_file", None)
        return data

    def save(self, incoming: dict[str, Any]) -> dict[str, Any]:
        current = self.raw_config()
        panel = incoming.setdefault("panel", {})
        # Preserve backend-only credentials and panel options not exposed by the UI.
        for key, value in current.get("panel", {}).items():
            if key in {"api_token", "username", "password"} or key not in panel:
                panel[key] = deepcopy(value)
        if "timeouts" not in incoming and "timeouts" in current:
            incoming["timeouts"] = deepcopy(current["timeouts"])
        if current.get("output", {}).get("formats"):
            incoming.setdefault("output", {})["formats"] = deepcopy(current["output"]["formats"])
        _config_from_raw(incoming, self.config_path)
        if not self.config_path.exists():
            if not str(panel.get("url", "")).strip():
                raise ValueError("Enter the panel URL before saving")
            if not incoming.get("inbound", {}).get("source_id"):
                raise ValueError("Select or enter a source inbound ID before saving")
            if not str(incoming.get("testing", {}).get("server_address", "")).strip():
                raise ValueError("Enter the server address before saving")
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.config_path.with_suffix(".tmp.yaml")
        temporary.write_text(yaml.safe_dump(incoming, allow_unicode=True, sort_keys=False), encoding="utf-8")
        temporary.replace(self.config_path)
        return self.public_config()

    def preview(self, raw: dict[str, Any]) -> dict[str, Any]:
        config = _config_from_raw(raw, self.config_path)
        generator = CombinationGenerator(config.search_parameters())
        warnings = self._preview_warnings(config)
        if config.combination_strategy == "mutation":
            plan = generator.mutations()
            return {"strategy": "mutation", "adaptive": True,
                    "raw_combinations": generator.raw_count,
                    "planned_combinations": config.max_combinations,
                    "planned_runs": config.max_combinations * config.runs_per_combination,
                    "initial_candidates": len(plan),
                    "mutable_parameters": sum(parameter.mutate for parameter in generator.parameters),
                    "fixed_parameters": sum(not parameter.mutate for parameter in generator.parameters),
                    "mutation_generations": config.mutation_generations,
                    "beam_width": config.beam_width,
                    "children_per_parent": config.children_per_parent,
                    "limit": config.max_combinations, "truncated": False,
                    "preview": [mask_parameter_values(item.values, generator.parameters) for item in plan[:20]], "warnings": warnings}
        if config.combination_strategy == "pairwise":
            plan = generator.pairwise()
            limited = plan[:config.max_combinations]
            return {"strategy": config.combination_strategy, "raw_combinations": generator.raw_count,
                    "planned_combinations": len(limited), "designed_combinations": len(plan),
                    "planned_runs": len(limited) * config.runs_per_combination,
                    "limit": config.max_combinations, "truncated": len(plan) > len(limited),
                    "preview": [mask_parameter_values(item.values, generator.parameters) for item in limited[:20]], "warnings": warnings}
        plan = list(itertools.islice(generator.iter_valid(), config.max_combinations))
        return {"strategy": "exhaustive", "raw_combinations": generator.raw_count,
                "planned_combinations": len(plan),
                "planned_runs": len(plan) * config.runs_per_combination,
                "limit": config.max_combinations, "truncated": generator.raw_count > config.max_combinations,
                "preview": [mask_parameter_values(item.values, generator.parameters) for item in plan[:20]],
                "warnings": warnings}

    @staticmethod
    def _preview_warnings(config: ExperimentConfig) -> list[str]:
        warnings = offline_warnings(config)
        if config.has_reality_candidates:
            warnings.append(REALITY_CANDIDATES_UNCHECKED_WARNING)
        return warnings

    @staticmethod
    def import_reality_candidates(content: str) -> list[dict[str, str]]:
        if len(content.encode("utf-8")) > 128 * 1024:
            raise ValueError("REALITY candidate file is too large")
        return parse_candidates(content)

    @staticmethod
    def default_reality_candidates() -> list[dict[str, str]]:
        path = Path(__file__).resolve().parents[1] / "configs" / "reality-targets.yaml"
        return parse_candidates(path.read_text(encoding="utf-8"))

    def list_inbounds(self, panel_options: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        raw = self.raw_config()
        if panel_options:
            panel = raw.setdefault("panel", {})
            for key in ("url", "verify_tls", "trust_env"):
                if key in panel_options:
                    panel[key] = panel_options[key]
        config = _config_from_raw(raw, self.config_path)
        if not str(config.panel.get("url", "")).strip():
            raise ValueError("Enter the panel URL before loading inbounds")

        async def request() -> list[dict[str, Any]]:
            client = ThreeXUIClient(config.panel, config.api_timeout)
            try:
                await client.authenticate()
                await client.discover()
                return await client.list_inbounds()
            finally:
                await client.aclose()

        inbounds = asyncio.run(request())
        return [{key: item.get(key) for key in ("id", "remark", "protocol", "port", "enable", "tag")} for item in inbounds]

    def registry(self) -> dict[str, Any]:
        """Merge the documented catalogue with values from the live source inbound."""
        if not self.config_path.exists():
            return parameter_registry(live_error="Save the connection settings to load live inbound values")
        config = load_config(self.config_path)

        async def request() -> tuple[dict[str, Any], str | None, str | None]:
            client = ThreeXUIClient(config.panel, config.api_timeout)
            try:
                await client.authenticate()
                openapi = await client.discover()
                source = await client.get_inbound(int(config.inbound["source_id"]))
                status = await client.server_status()
                xray = status.get("xray", {})
                xray_version = xray.get("version") if isinstance(xray, dict) else None
                return source, openapi.get("info", {}).get("version"), xray_version
            finally:
                await client.aclose()

        try:
            source, panel_version, xray_version = asyncio.run(request())
            catalog = parameter_registry(source, panel_version=panel_version, xray_version=xray_version)
            # These are outbound/client identities. An inbound commonly stores an
            # empty serverName, which must not replace the explicit client SNI.
            client_defaults = {
                "tls_server_name": config.testing.get("tls_server_name"),
                "tls_verify_peer_name": config.testing.get("verify_peer_cert_by_name"),
            }
            for name, value in client_defaults.items():
                if value is not None and name in catalog["parameters"]:
                    catalog["parameters"][name]["current"] = value
            return catalog
        except Exception as error:
            # The documented catalogue remains usable while the panel is offline.
            return parameter_registry(live_error=f"{type(error).__name__}: {error}")

    def start_run(self, incoming: dict[str, Any]) -> dict[str, Any]:
        with self._run_lock:
            if self._run_state.get("status") in {"running", "stopping"}:
                raise RuntimeError("A test run is already active")
        raw = deepcopy(incoming)
        current = self.raw_config()
        panel = raw.setdefault("panel", {})
        for key, value in current.get("panel", {}).items():
            if key in {"api_token", "username", "password"} or key not in panel:
                panel[key] = deepcopy(value)
        job_id = uuid.uuid4().hex
        output = raw.setdefault("output", {})
        base_directory = Path(str(output.get("directory", "./results")))
        run_directory = base_directory / "runs" / f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{job_id[:8]}"
        output["directory"] = str(run_directory)
        config = _config_from_raw(raw, self.config_path)
        generator = CombinationGenerator(config.search_parameters())
        initial_candidates = len(generator.mutations()) if config.combination_strategy == "mutation" else None
        designed_count = len(generator.pairwise()) if config.combination_strategy == "pairwise" else None
        planned = (config.max_combinations if config.combination_strategy == "mutation" else
                   min(designed_count if designed_count is not None else generator.raw_count, config.max_combinations))
        with self._run_lock:
            self._stop_requested = False
            self._run_state = {"id": job_id, "status": "running", "strategy": config.combination_strategy,
                               "raw_combinations": generator.raw_count, "planned_combinations": planned,
                               "planned_runs": planned * config.runs_per_combination,
                               "result_directory": str(run_directory), "completed": 0, "failed": 0,
                               "skipped": 0, "warnings": self._preview_warnings(config)}
            if initial_candidates is not None:
                self._run_state.update({"initial_candidates": initial_candidates,
                                        "mutable_parameters": sum(parameter.mutate for parameter in generator.parameters),
                                        "fixed_parameters": sum(not parameter.mutate for parameter in generator.parameters),
                                        "mutation_generations": config.mutation_generations,
                                        "beam_width": config.beam_width,
                                        "children_per_parent": config.children_per_parent})

        def progress(update: dict[str, Any]) -> None:
            with self._run_lock:
                self._run_state.update({key: update[key] for key in ("completed", "failed", "test_id", "run",
                                                               "planned_combinations", "planned_runs")
                                        if key in update})
                for key in ("skipped", "warnings"):
                    if key in update:
                        self._run_state[key] = update[key]
                if "generation" in update:
                    self._run_state["generation"] = update["generation"]
                if "configuration" in update:
                    self._run_state["last_configuration"] = update["configuration"]
                if "result" in update:
                    self._run_state["last_result"] = update["result"]

        def worker() -> None:
            async def action() -> dict[str, Any]:
                client = ThreeXUIClient(config.panel, config.api_timeout)
                runner = ExperimentRunner(config, client, progress)
                with self._run_lock:
                    self._runner = runner
                    if self._stop_requested:
                        runner.request_stop()
                try:
                    return await runner.run(max_tests=config.max_combinations)
                finally:
                    await client.aclose()

            try:
                result = asyncio.run(action())
                with self._run_lock:
                    if result.get("interrupted"):
                        status = "stopped"
                    elif result.get("cleanup_error"):
                        status = "failed"
                    elif result.get("export_error"):
                        status = "completed_with_warnings"
                    else:
                        status = "completed"
                    self._run_state["status"] = status
                    self._run_state["summary"] = result
                    for key in ("skipped", "warnings"):
                        if key in result:
                            self._run_state[key] = result[key]
            except Exception as error:
                with self._run_lock:
                    self._run_state.update({"status": "failed", "error": f"{type(error).__name__}: {error}"})
            finally:
                with self._run_lock:
                    self._runner = None

        threading.Thread(target=worker, name=f"3xui-test-{job_id[:8]}", daemon=True).start()
        return self.run_status()

    def stop_run(self) -> dict[str, Any]:
        with self._run_lock:
            self._stop_requested = True
            if self._runner:
                self._runner.request_stop()
            if self._run_state.get("status") == "running":
                self._run_state["status"] = "stopping"
        return self.run_status()

    def run_status(self) -> dict[str, Any]:
        with self._run_lock:
            return deepcopy(self._run_state)

    def runs_directory(self) -> Path:
        raw = self.raw_config()
        return Path(str(raw.get("output", {}).get("directory", "./results"))).resolve() / "runs"

    def list_runs(self) -> list[dict[str, Any]]:
        root = self.runs_directory()
        if not root.is_dir():
            return []
        with self._run_lock:
            active = deepcopy(self._run_state)
        runs = []
        for directory in sorted(root.iterdir(), key=lambda item: item.name, reverse=True):
            if not directory.is_dir() or directory.is_symlink() or not self.RUN_ID.fullmatch(directory.name):
                continue
            journal = directory / "results.jsonl"
            files = [name for name in self.REPORT_FILES if (directory / name).is_file()]
            if journal.is_file():
                with journal.open("rb") as stream:
                    records = sum(bool(line.strip()) for line in stream)
            else:
                records = 0
            status = active.get("status") if Path(str(active.get("result_directory", ""))).resolve() == directory.resolve() else "saved"
            runs.append({"id": directory.name, "status": status, "records": records, "files": files})
        return runs

    def report_path(self, run_id: str, filename: str) -> Path:
        if not self.RUN_ID.fullmatch(run_id) or filename not in self.REPORT_FILES:
            raise ValueError("Unknown report")
        root = self.runs_directory()
        directory = root / run_id
        path = directory / filename
        if directory.is_symlink() or path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(directory.resolve()):
            raise FileNotFoundError("Report is not available")
        return path

    def run_dashboard(self) -> dict[str, Any]:
        """Summarize the durable journal so the UI survives a page refresh."""
        with self._run_lock:
            state = deepcopy(self._run_state)
        directory = state.get("result_directory")
        if not directory:
            return {"records": 0, "planned_runs": state.get("planned_runs", 0), "candidates": []}
        path = Path(str(directory))
        journal = path / "results.jsonl"
        if not journal.exists():
            return {"records": 0, "planned_runs": state.get("planned_runs", 0), "candidates": []}
        store = ResultStore(path)
        records = store.records()
        attempted = [item for item in records if item.get("result", {}).get("status") != "SKIPPED"]
        skipped = len(records) - len(attempted)
        summaries = store._summaries(attempted)
        candidates = [
            {
                "number": number,
                "label": f"#{number} · {_configuration_label(item.get("configuration"), item.get("configuration_hash"))}",
                "short_label": _compact_configuration_label(item.get("configuration"), number),
                "tests": item.get("tests", 0), "successful": item.get("successful_tests", 0),
                "failed": item.get("failed_tests", 0), "success_rate": item.get("success_rate", 0),
                "score": item.get("score_avg"), "p95_ms": item.get("latency_p95_avg"),
                "p95_stddev_ms": item.get("latency_p95_stddev"),
                "download_mbps": item.get("download_avg"), "download_stddev_mbps": item.get("download_stddev"),
            }
            for number, item in enumerate(summaries, start=1)
        ]
        successful = [item for item in candidates if item["successful"]]
        def maximum(name: str) -> dict[str, Any] | None:
            values = [item for item in successful if item.get(name) is not None]
            return max(values, key=lambda item: float(item[name])) if values else None

        def minimum(name: str) -> dict[str, Any] | None:
            values = [item for item in successful if item.get(name) is not None]
            return min(values, key=lambda item: float(item[name])) if values else None

        success_count = sum(1 for item in attempted if item.get("result", {}).get("status") == "OK")
        return {
            "records": len(records), "attempted": len(attempted), "skipped": skipped,
            "planned_runs": state.get("planned_runs", 0),
            "success_rate": success_count / len(attempted) if attempted else None,
            "best_score": maximum("score"), "best_p95": minimum("p95_ms"),
            "fastest": maximum("download_mbps"), "candidates": candidates,
        }


class Handler(BaseHTTPRequestHandler):
    service: WebService

    def log_message(self, *_: object) -> None:
        return

    def _json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(mask_secrets(payload), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length))

    def do_GET(self) -> None:  # noqa: N802
        try:
            if self.path == "/":
                body = PAGE.encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif self.path == "/api/config":
                self._json(self.service.public_config())
            elif self.path == "/api/inbounds":
                self._json(self.service.list_inbounds())
            elif self.path == "/api/registry":
                self._json(self.service.registry())
            elif self.path == "/api/reality/default-candidates":
                self._json(self.service.default_reality_candidates())
            elif self.path == "/api/run/status":
                self._json(self.service.run_status())
            elif self.path == "/api/run/dashboard":
                self._json(self.service.run_dashboard())
            elif self.path == "/api/runs":
                self._json(self.service.list_runs())
            elif self.path.startswith("/api/runs/"):
                parts = self.path.split("/")
                if len(parts) != 6 or parts[4] != "download":
                    raise ValueError("Unknown report")
                report = self.service.report_path(parts[3], parts[5])
                body = report.read_bytes()
                content_type = {
                    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    ".csv": "text/csv; charset=utf-8",
                    ".json": "application/json; charset=utf-8",
                    ".jsonl": "application/x-ndjson; charset=utf-8",
                }[report.suffix]
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Disposition", f'attachment; filename="{report.name}"')
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self._json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
        except Exception as error:
            self._json({"error": type(error).__name__, "message": str(error)}, HTTPStatus.BAD_REQUEST)

    def do_POST(self) -> None:  # noqa: N802
        try:
            body = self._body()
            if self.path == "/api/preview":
                self._json(self.service.preview(body))
            elif self.path == "/api/inbounds":
                self._json(self.service.list_inbounds(body))
            elif self.path == "/api/config":
                self._json(self.service.save(body))
            elif self.path == "/api/reality/import":
                self._json(self.service.import_reality_candidates(str(body.get("content", ""))))
            elif self.path == "/api/run/start":
                self._json(self.service.start_run(body), HTTPStatus.ACCEPTED)
            elif self.path == "/api/run/stop":
                self._json(self.service.stop_run(), HTTPStatus.ACCEPTED)
            else:
                self._json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
        except Exception as error:
            self._json({"error": type(error).__name__, "message": str(error)}, HTTPStatus.BAD_REQUEST)


# Kept separate from the backend so the UI can evolve without mixing browser code and API code.
PAGE = Path(__file__).with_name("web_ui.html").read_text(encoding="utf-8")


class ExclusiveThreadingHTTPServer(ThreadingHTTPServer):
    """Reject a second backend on the same Windows port instead of sharing it."""

    daemon_threads = True
    allow_reuse_address = False

    def server_bind(self) -> None:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def main() -> None:
    parser = argparse.ArgumentParser(description="Local configuration UI for 3xui-tester")
    parser.add_argument("--config", type=Path, default=Path("configs/local.yaml"))
    parser.add_argument("--port", type=int, default=8765)
    options = parser.parse_args()
    Handler.service = WebService(options.config)
    server = ExclusiveThreadingHTTPServer(("127.0.0.1", options.port), Handler)
    print(f"3xui-tester UI: http://127.0.0.1:{options.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
