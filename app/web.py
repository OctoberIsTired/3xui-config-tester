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


PAGE = r"""<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>3xui-tester — конфигурация</title><style>
*{box-sizing:border-box}body{margin:0;background:#0d1117;color:#e6edf3;font:15px system-ui,sans-serif}main{max-width:1150px;margin:auto;padding:28px}h1{margin-top:0}section{background:#161b22;border:1px solid #30363d;border-radius:10px;margin:16px 0;padding:18px}label{display:block;font-size:13px;color:#9da7b3;margin:9px 0 3px}input,select,textarea,button{font:inherit;border-radius:6px;border:1px solid #30363d;padding:8px;background:#0d1117;color:#e6edf3;width:100%}textarea{min-height:72px;resize:vertical}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px}.row{display:grid;grid-template-columns:1fr 110px 1fr 1.4fr 105px 42px;gap:8px;align-items:end;border-top:1px solid #30363d;padding:10px 0}.row label{margin:0}.actions{display:flex;gap:10px;flex-wrap:wrap}.actions button{width:auto;background:#238636;border:0;cursor:pointer}.actions button.alt{background:#30363d}.delete{background:#b62324!important}.muted{color:#9da7b3}pre{white-space:pre-wrap;background:#0d1117;padding:12px;border-radius:6px;overflow:auto}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:8px;border-bottom:1px solid #30363d}@media(max-width:850px){.row{grid-template-columns:1fr 1fr}.row .delete{width:42px}}</style></head><body><main>
<h1>3xui-tester <span class="muted">локальная конфигурация</span></h1><p class="muted">Интерфейс привязан к 127.0.0.1. Токен панели остаётся только на backend.</p>
<section><h2>Панель и тестовый inbound</h2><div class="grid"><div><label>Panel URL<input id="panelUrl"></label></div><div><label>Source inbound ID<input id="sourceId" type="number"></label></div><div><label>Clone port<input id="testPort" type="number"></label></div><div><label>Server address<input id="serverAddress"></label></div><div><label>TLS SNI<input id="tlsSni"></label></div><div><label>Output directory<input id="outputDir"></label></div></div><label>Test URLs (по одному на строку)<textarea id="urls"></textarea></label></section>
<section><div class="actions"><button onclick="loadInbounds()" class="alt">Обновить inbound</button></div><div id="inbounds" class="muted">Нажмите «Обновить inbound».</div></section>
<section><h2>Параметры</h2><p class="muted">Values — JSON-массив; Path — JSON-массив компонентов. Conditions — JSON rule, например <code>{"network":{"equals":"ws"}}</code>.</p><div id="params"></div><div class="actions"><button onclick="addParam()" class="alt">Добавить параметр</button></div></section>
<section><div class="actions"><button onclick="preview()">Preview combinations</button><button onclick="save()" class="alt">Сохранить config</button></div><pre id="result">Готово к настройке.</pre></section>
</main><script>
let cfg={}; const types=['enum','integer','float','boolean','string'];
const el=id=>document.getElementById(id); const text=(v)=>JSON.stringify(v??[],null,0);
function input(label,value,cls){return `<label>${label}<input class="${cls}" value="${String(value??'').replaceAll('&','&amp;').replaceAll('"','&quot;')}"></label>`}
function render(){el('panelUrl').value=cfg.panel?.url||'';el('sourceId').value=cfg.inbound?.source_id||'';el('testPort').value=cfg.inbound?.test_port||9443;el('serverAddress').value=cfg.testing?.server_address||'';el('tlsSni').value=cfg.testing?.tls_server_name||'';el('outputDir').value=cfg.output?.directory||'./results';el('urls').value=(cfg.testing?.urls||[]).join('\n');let root=el('params');root.innerHTML='';for(const [name,p] of Object.entries(cfg.parameters||{})){let node=document.createElement('div');node.className='row';node.innerHTML=input('Name',name,'p-name')+`<label>Type<select class="p-type">${types.map(t=>`<option ${t===p.type?'selected':''}>${t}</option>`).join('')}</select></label>`+input('Values / range',p.values?text(p.values):`${p.min}..${p.max} / ${p.step}`,'p-values')+input('Path',text(p.path||[]),'p-path')+`<label>Target<select class="p-target"><option ${p.target!=='client'?'selected':''}>inbound</option><option ${p.target==='client'?'selected':''}>client</option></select></label><button class="delete" title="Удалить">×</button>`;let cond=document.createElement('div');cond.innerHTML=`<label>Conditions JSON<textarea class="p-cond">${p.conditions?text(p.conditions):''}</textarea></label>`;node.append(cond);node.querySelector('.delete').onclick=()=>node.remove();root.append(node)}}
function addParam(){cfg.parameters=cfg.parameters||{};cfg.parameters['new_parameter']={type:'enum',values:['value'],path:[]};render()}
function read(){let parameters={};document.querySelectorAll('.row').forEach(row=>{let name=row.querySelector('.p-name').value.trim(),type=row.querySelector('.p-type').value,v=row.querySelector('.p-values').value.trim(),p=row.querySelector('.p-path').value.trim(),cond=row.querySelector('.p-cond').value.trim();if(!name)return;let item={type,target:row.querySelector('.p-target').value,path:JSON.parse(p||'[]')};if(v.startsWith('['))item.values=JSON.parse(v);else {let m=v.match(/^(.+)\.\.(.+)\s*\/\s*(.+)$/);if(!m)throw Error(`Parameter ${name}: values must be JSON list or min..max / step`);item.min=Number(m[1]);item.max=Number(m[2]);item.step=Number(m[3])}if(cond)item.conditions=JSON.parse(cond);parameters[name]=item});return {panel:{url:el('panelUrl').value,verify_tls:false},inbound:{mode:'clone',source_id:Number(el('sourceId').value),test_port:Number(el('testPort').value)},testing:{server_address:el('serverAddress').value,tls_server_name:el('tlsSni').value,verify_peer_cert_by_name:el('tlsSni').value,socks_port:18080,xray_binary:'.tools/xray/xray.exe',urls:el('urls').value.split('\n').map(x=>x.trim()).filter(Boolean)},parameters,output:{directory:el('outputDir').value,formats:['csv','json','xlsx']}}}
async function call(path,method='GET',body){let r=await fetch(path,{method,headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});let d=await r.json();if(!r.ok)throw Error(d.message||d.error);return d}async function preview(){try{let d=await call('/api/preview','POST',read());el('result').textContent=`Raw combinations: ${d.raw_combinations}\n\n${JSON.stringify(d.preview,null,2)}`}catch(e){el('result').textContent='Ошибка: '+e.message}}async function save(){try{cfg=await call('/api/config','POST',read());el('result').textContent='Сохранено.';render()}catch(e){el('result').textContent='Ошибка: '+e.message}}async function loadInbounds(){try{let d=await call('/api/inbounds');el('inbounds').innerHTML=`<table><tr><th>ID</th><th>Remark</th><th>Protocol</th><th>Port</th><th>Enabled</th></tr>${d.map(x=>`<tr><td>${x.id}</td><td>${x.remark||''}</td><td>${x.protocol}</td><td>${x.port}</td><td>${x.enable}</td></tr>`).join('')}</table>`}catch(e){el('inbounds').textContent='Ошибка API: '+e.message}}fetch('/api/config').then(r=>r.json()).then(d=>{cfg=d;render()}).catch(e=>el('result').textContent='Ошибка загрузки: '+e.message);
</script></body></html>"""

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
