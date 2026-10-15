"""WebService: configuration draft, runs and dashboard state."""
from __future__ import annotations
import json
import math
import re

import asyncio
import inspect
import itertools
import threading
import uuid
from threading import Event
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from app.api.three_xui import PanelAPIRejected, ThreeXUIClient
from app.inbound.manager import InboundManager
from app.config import ExperimentConfig, _expand_env, load_config, offline_warnings, REALITY_CANDIDATES_UNCHECKED_WARNING
from app.xray.reality import configured_candidates, parse_candidates
from app.parameters.generator import CombinationGenerator, configuration_hash
from app.parameters.models import ParameterSpec
from app.parameters.registry import parameter_registry
from app.results.writer import ResultStore, _configuration_label
from app.security.masking import SecretRedactor, mask_parameter_values, mask_secrets
from app.testing.runner import ExperimentRunner
from app.state.checkpoint import atomic_json


class SourceInboundMissing(Exception):
    """The saved source_id does not exist on a reachable panel."""

    def __init__(self, source_id: int, available: list[int]):
        ids = ", ".join(str(item) for item in available) or "нет"
        super().__init__(
            f"source_id {source_id} отсутствует на панели (доступные идентификаторы: {ids}). "
            "Нажмите «Загрузить inbound'ы» и выберите существующий, затем сохраните конфигурацию снова"
        )


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


def _raised_budget(recorded: Any, requested: dict[str, float]) -> dict[str, float]:
    """Validate the budget a continuation adds to an exhausted run.

    A continuation may only raise limits, and every dimension the previous run
    had already used up has to end above the recorded usage: otherwise the
    resumed search would stop again without measuring anything new. The
    comparison is a pre-flight sanity check against the durable checkpoint, not
    a substitute for the runner's own accounting.
    """
    limits = recorded.get("limits") if isinstance(recorded, dict) else None
    if not isinstance(limits, dict):
        raise ValueError("The saved run has no recorded budget to continue")
    for key, value in requested.items():
        previous = limits.get(key)
        if isinstance(previous, bool) or not isinstance(previous, (int, float)):
            raise ValueError(f"The saved run has no recorded {key} budget to continue")
        if value < previous:
            raise ValueError(f"A continuation must not lower the {key} budget ({previous:g} was exhausted)")
        consumed = recorded.get(key, 0)
        if consumed >= previous and value <= consumed:
            raise ValueError(f"The {key} budget was already used up at {consumed:g}; set a higher one to continue")
    if not any(requested[key] > limits[key] for key in requested):
        raise ValueError("Set a budget higher than the exhausted run; nothing new would be measured")
    return dict(requested)


class WebService:
    REPORT_FILES = ("results.xlsx", "results.csv", "summary.csv", "results.json", "results.jsonl", "errors.jsonl", "diagnostics.jsonl", "client-xray.log", "run-error.txt", "discovery.json", "preflight.json", "recovery-status.json")
    RUN_ID = re.compile(r"\d{8}-\d{6}-[0-9a-f]{8}\Z")
    ACTIVE_STATES = {"starting", "running", "stopping", "cleanup"}
    # A run may be continued in place with a larger budget only when the
    # adaptive search stopped because its own budget ran out.
    CONTINUABLE_REASONS = {"budget_exhausted"}
    RUN_METADATA_FIELDS = ("termination_reason", "confirmed_candidates", "viable_candidates", "budget")
    BUDGET_FIELDS = ("candidates", "requests", "traffic_bytes", "api_applies", "client_starts", "elapsed_seconds")

    def __init__(self, config_path: Path):
        self.config_path = config_path.resolve()
        self._run_lock = threading.Lock()
        self._run_state: dict[str, Any] = {"status": "idle"}
        self._runner: ExperimentRunner | None = None
        self._worker_thread: threading.Thread | None = None
        self._idle_event = Event()
        self._idle_event.set()
        self._closing = False
        self._stop_requested = False
        self._cache_lock = threading.Lock()
        self._dashboard_cache: dict[str, dict[str, Any]] = {}
        self._runs_cache: dict[str, dict[str, Any]] = {}
        self._redactor = SecretRedactor.from_config(_expand_env(self.raw_config()))

    def public_payload(self, value: Any) -> Any:
        """Last redaction boundary for HTTP responses and public diagnostics."""
        return self._redactor.redact(value)

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
        self._redactor.add(_expand_env(data))
        panel = data.setdefault("panel", {})
        for key in ("api_token", "password", "username"):
            panel.pop(key, None)
        reality = data.get("testing", {}).get("reality")
        if isinstance(reality, dict) and reality.get("candidates_file"):
            reality["candidates"] = configured_candidates(data["testing"], self.config_path)
            reality.pop("candidates_file", None)
        return self._redactor.redact(data)

    @staticmethod
    def _restore_private_parameters(raw: dict[str, Any], current: dict[str, Any]) -> None:
        """A browser placeholder is never an instruction to overwrite a secret."""
        incoming = raw.get("parameters", {})
        if not isinstance(incoming, dict):
            return
        for name, saved in current.get("parameters", {}).items():
            if not isinstance(saved, dict) or not SecretRedactor._sensitive_path(name, saved.get("path", ())):
                continue
            candidate = incoming.get(name)
            if candidate == "***":
                incoming[name] = deepcopy(saved)
            elif isinstance(candidate, dict):
                for key in ("values", "baseline", "min", "max", "step"):
                    value = candidate.get(key)
                    masked = value == "***" or (key == "values" and isinstance(value, list) and value and all(item == "***" for item in value))
                    if masked:
                        if key in saved:
                            candidate[key] = deepcopy(saved[key])
                        else:
                            candidate.pop(key, None)

    def save(self, incoming: dict[str, Any]) -> dict[str, Any]:
        current = self.raw_config()
        self._redactor.add(_expand_env(current))
        self._redactor.add(_expand_env(incoming))
        self._restore_private_parameters(incoming, current)
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
        raw = deepcopy(raw)
        self._restore_private_parameters(raw, self.raw_config())
        self._redactor.add(_expand_env(raw))
        config = _config_from_raw(raw, self.config_path)
        generator = CombinationGenerator(config.search_parameters())
        warnings = self._preview_warnings(config)
        common = {"offline": True, "topology": config.topology,
                  "validation_level": "offline",
                  "ports": [int(config.inbound["test_port"])] if config.inbound.get("test_port") else list(config.candidate_ports[:100]),
                  "serial_execution": True,
                  "mutable_parameters": sum(parameter.mutate for parameter in generator.parameters),
                  "fixed_parameters": sum(not parameter.mutate for parameter in generator.parameters)}
        if config.combination_strategy == "adaptive":
            options = config.adaptive
            plan = generator.adaptive_frontier(config.max_combinations, seed=options["seed"])
            logical_limit = len(plan) * (3 + options["screening_retries"] + options["confirmation_windows"])
            return {**common, "strategy": "adaptive", "adaptive": True, "goal": options["goal"],
                    "raw_combinations": generator.raw_count, "planned_combinations": len(plan),
                    "planned_runs": logical_limit, "planned_runs_is_upper_bound": True,
                    "initial_candidates": len(plan), "limit": config.max_combinations,
                    "truncated": generator.coverage_metadata.get("truncated", False),
                    "coverage": generator.coverage_metadata, "budgets": options,
                    "preview": [mask_parameter_values(item.values, generator.parameters) for item in plan[:20]],
                    "warnings": warnings}
        if config.combination_strategy == "mutation":
            plan = generator.mutations(limit=config.max_combinations)
            return {**common, "strategy": "mutation", "adaptive": True,
                    "raw_combinations": generator.raw_count,
                    "planned_combinations": config.max_combinations,
                    "planned_runs": config.max_combinations * config.runs_per_combination,
                    "initial_candidates": len(plan),
                    "mutable_parameters": sum(parameter.mutate for parameter in generator.parameters),
                    "fixed_parameters": sum(not parameter.mutate for parameter in generator.parameters),
                    "mutation_generations": config.mutation_generations,
                    "beam_width": config.beam_width,
                    "children_per_parent": config.children_per_parent,
                    "limit": config.max_combinations,
                    "truncated": generator.coverage_metadata.get("truncated", False),
                    "coverage": generator.coverage_metadata,
                    "preview": [mask_parameter_values(item.values, generator.parameters) for item in plan[:20]], "warnings": warnings}
        if config.combination_strategy == "pairwise":
            plan = generator.pairwise(limit=config.max_combinations)
            return {**common, "strategy": config.combination_strategy, "raw_combinations": generator.raw_count,
                    "planned_combinations": len(plan), "designed_combinations": len(plan),
                    "planned_runs": len(plan) * config.runs_per_combination,
                    "limit": config.max_combinations, "truncated": generator.coverage_metadata.get("truncated", False),
                    "coverage": generator.coverage_metadata,
                    "preview": [mask_parameter_values(item.values, generator.parameters) for item in plan[:20]], "warnings": warnings}
        plan = list(itertools.islice(generator.iter_valid(), config.max_combinations))
        return {**common, "strategy": "exhaustive", "raw_combinations": generator.raw_count,
                "planned_combinations": len(plan),
                "planned_runs": len(plan) * config.runs_per_combination,
                "limit": config.max_combinations, "truncated": generator.raw_count > config.max_combinations,
                "preview": [mask_parameter_values(item.values, generator.parameters) for item in plan[:20]],
                "warnings": warnings}

    @staticmethod
    def _preview_warnings(config: ExperimentConfig) -> list[str]:
        warnings = offline_warnings(config)
        profile = {parameter.path: parameter for parameter in config.parameters}
        locked = [name for name, path in (("transport", ("streamSettings", "network")),
                                          ("security", ("streamSettings", "security")))
                  if path in profile and (not profile[path].mutate or profile[path].count_values() == 1)]
        if locked:
            warnings.append("Профиль фиксирован: " + ", ".join(locked) +
                            ". Поиск не проверит другие семейства этих параметров")
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
        path = Path(__file__).resolve().parents[2] / "configs" / "reality-targets.yaml"
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
        self._redactor.add(config.panel)

        async def request() -> tuple[dict[str, Any], str | None, str | None]:
            client = ThreeXUIClient(config.panel, config.api_timeout)
            try:
                await client.authenticate()
                openapi = await client.discover()
                source_id = int(config.inbound["source_id"])
                try:
                    source = await client.get_inbound(source_id)
                except PanelAPIRejected as error:
                    # The panel is reachable but has no such record: an outdated
                    # source_id (the inbound was recreated or deleted). The raw
                    # panel message does not say what to do, so translate it
                    # while the id list is one cheap call away.
                    available = sorted({int(item.get("id", 0)) for item in await client.list_inbounds()})
                    raise SourceInboundMissing(source_id, available) from error
                status = await client.server_status()
                xray = status.get("xray", {})
                xray_version = xray.get("version") if isinstance(xray, dict) else None
                return source, openapi.get("info", {}).get("version"), xray_version
            finally:
                await client.aclose()

        try:
            source, panel_version, xray_version = asyncio.run(request())
            self._redactor.add(source)
            catalog = parameter_registry(source, panel_version=panel_version, xray_version=xray_version)
            catalog["environment"] = {"panel_access": "available", "route_required": False,
                                      "message": "Панель доступна через текущий маршрут компьютера"}
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
        except SourceInboundMissing as error:
            # The panel answers, so this is a wrong source_id, not an outage:
            # keep the documented catalogue usable and say what to fix.
            catalog = parameter_registry(live_error=str(error))
            catalog["environment"] = {"panel_access": "available", "route_required": False,
                                      "message": "Панель доступна через текущий маршрут компьютера"}
            return catalog
        except Exception as error:
            # The documented catalogue remains usable while the panel is offline.
            catalog = parameter_registry(live_error=self._redactor.redact_text(f"{type(error).__name__}: {error}"))
            catalog["environment"] = {"panel_access": "unavailable", "route_required": None,
                                      "message": "Панель недоступна: проверьте текущий VPN/маршрут и авторизацию. Причина ещё не установлена"}
            return catalog

    def _private_draft(self, incoming: dict[str, Any]) -> dict[str, Any]:
        """Browser draft plus backend-only panel credentials and unmasked parameters."""
        raw = deepcopy(incoming)
        current = self.raw_config()
        self._restore_private_parameters(raw, current)
        panel = raw.setdefault("panel", {})
        # Preserve backend-only credentials and panel options not exposed by the UI.
        for key, value in current.get("panel", {}).items():
            if key in {"api_token", "username", "password"} or key not in panel:
                panel[key] = deepcopy(value)
        self._redactor.add(_expand_env(raw))
        return raw

    def _progress_recorder(self) -> Any:
        def progress(update: dict[str, Any]) -> None:
            update = self._redactor.redact(update)
            with self._run_lock:
                self._run_state.update({key: update[key] for key in ("completed", "failed", "test_id", "run",
                                                               "planned_combinations", "planned_runs",
                                                               "test_inbound_id", "test_inbound_port", "phase",
                                                               "fidelity", "rung", "termination_reason", "budget",
                                                               "coverage", "profile_id", "environment", "diagnosis",
                                                               "lifecycle_state", "qualification", "stage",
                                                               "confirmed_candidates", "viable_candidates",
                                                               "duration_ms", "cleanup_pending")
                                        if key in update})
                for key in ("skipped", "warnings"):
                    if key in update:
                        self._run_state[key] = update[key]
                if update.get("lifecycle_state") == "cleanup":
                    self._run_state["status"] = "cleanup"
                if "generation" in update:
                    self._run_state["generation"] = update["generation"]
                if "configuration" in update:
                    self._run_state["last_configuration"] = update["configuration"]
                if "result" in update:
                    self._run_state["last_result"] = update["result"]

        return progress

    def _start_worker(self, job_id: str, config: ExperimentConfig, run_directory: Path, *, resume: bool = False) -> None:
        """Run the accepted job on its own thread.

        `resume` continues the checkpoint already stored in `run_directory`
        instead of starting a new experiment; the journal, checkpoint and
        directory are the ones the previous run left behind.
        """
        progress = self._progress_recorder()

        def worker() -> None:
            async def action() -> dict[str, Any]:
                client = ThreeXUIClient(config.panel, config.api_timeout)
                try:
                    runner = ExperimentRunner(config, client, progress)
                    if hasattr(runner, "redactor"):
                        # Include identities generated during the runner in the
                        # HTTP/outer-worker error boundary as well.
                        runner.redactor = self._redactor
                    with self._run_lock:
                        self._runner = runner
                        if self._stop_requested:
                            runner.request_stop()
                    return await runner.run(resume=resume, max_tests=config.max_combinations)
                finally:
                    await client.aclose()

            try:
                result = asyncio.run(action())
                result = self._redactor.redact(result)
                with self._run_lock:
                    if result.get("cleanup_error") or result.get("cleanup_pending"):
                        status = "cleanup_pending"
                    elif result.get("interrupted"):
                        status = "stopped"
                    elif result.get("export_error"):
                        status = "completed_with_warnings"
                    else:
                        status = "completed"
                    self._run_state["status"] = status
                    self._run_state["lifecycle_state"] = "cleanup_pending" if status == "cleanup_pending" else "finished"
                    self._run_state["summary"] = result
                    for key in ("skipped", "warnings", "confirmed_candidates", "viable_candidates",
                                "budget", "coverage", "termination_reason", "cleanup_pending", "environment"):
                        if key in result:
                            self._run_state[key] = result[key]
            except Exception as error:
                message = self._redactor.redact_text(f"{type(error).__name__}: {error}")
                with self._run_lock:
                    pending = self._recovery_pending(run_directory)
                    self._run_state.update({"status": "cleanup_pending" if pending else "failed",
                                            "lifecycle_state": "cleanup_pending" if pending else "finished",
                                            "cleanup_pending": pending, "error": message})
                self._write_run_error(run_directory, message)
            finally:
                with self._run_lock:
                    self._runner = None
                    self._idle_event.set()

        thread = threading.Thread(target=worker, name=f"3xui-config-test-{job_id[:8]}", daemon=False)
        with self._run_lock:
            self._worker_thread = thread
        try:
            thread.start()
        except Exception as error:
            with self._run_lock:
                self._run_state.update({"status": "failed", "error": self._redactor.redact_text(str(error))})
                self._idle_event.set()
            raise

    def start_run(self, incoming: dict[str, Any]) -> dict[str, Any]:
        job_id = uuid.uuid4().hex
        recovery_pending = False
        with self._run_lock:
            if self._closing:
                raise RuntimeError("The backend is shutting down")
            if self._run_state.get("status") in self.ACTIVE_STATES | {"cleanup_pending"}:
                raise RuntimeError("A test run is already active")
            self._stop_requested = False
            self._run_state = {"id": job_id, "status": "starting"}
            self._idle_event.clear()
        try:
            raw = self._private_draft(incoming)
            pending = self._pending_recovery_runs()
            if pending:
                recovery_pending = True
                with self._run_lock:
                    self._run_state["recovery_runs"] = pending
                raise RuntimeError("Unfinished inbound cleanup must be recovered before another run")
            output = raw.setdefault("output", {})
            base_directory = Path(str(output.get("directory", "./results")))
            run_directory = base_directory / "runs" / f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-{job_id[:8]}"
            output["directory"] = str(run_directory)
            config = _config_from_raw(raw, self.config_path)
            generator = CombinationGenerator(config.search_parameters())
            initial_candidates = (len(generator.mutations(limit=config.max_combinations))
                                  if config.combination_strategy == "mutation" else None)
            designed_count = len(generator.pairwise(limit=config.max_combinations)) if config.combination_strategy == "pairwise" else None
            planned = (config.max_combinations if config.combination_strategy in {"mutation", "adaptive"} else
                       min(designed_count if designed_count is not None else generator.raw_count, config.max_combinations))
        except Exception as error:
            with self._run_lock:
                self._run_state.update({"status": "cleanup_pending" if recovery_pending else "failed", "error": self._redactor.redact_text(f"{type(error).__name__}: {error}")})
                self._idle_event.set()
            raise
        with self._run_lock:
            self._run_state = {"id": job_id, "status": "stopping" if self._stop_requested else "running", "strategy": config.combination_strategy,
                               "run_id": run_directory.name,
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

        self._start_worker(job_id, config, run_directory)
        return self.run_status()

    def continue_run(self, run_id: str, incoming: dict[str, Any]) -> dict[str, Any]:
        """Continue an exhausted run in place with a larger budget.

        Only a run whose adaptive search stopped on budget exhaustion is
        accepted. The checkpoint (`state.json`), the journal, the result
        directory and therefore the resume keys `<configuration-hash>:<run>`
        stay the same; the new limits come from the same draft
        `/api/run/start` takes, so the browser needs no second configuration
        shape. The clone is re-created by the ordinary preflight/prepare path:
        a finished run has already cleaned its clone and its recovery manifest
        says so.
        """
        if not self.RUN_ID.fullmatch(run_id):
            raise ValueError("Unknown run")
        root = self.runs_directory()
        directory = root / run_id
        if not directory.is_dir() or directory.is_symlink() or directory.resolve().parent != root.resolve():
            raise FileNotFoundError("Run is not available")
        checkpoint_path = directory / "state.json"
        if checkpoint_path.is_symlink() or not checkpoint_path.is_file():
            raise FileNotFoundError("Saved run has no checkpoint to continue")
        try:
            checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise ValueError("Saved run checkpoint is not readable") from None
        scheduler = checkpoint.get("scheduler") if isinstance(checkpoint, dict) else None
        metadata = checkpoint.get("metadata") if isinstance(checkpoint, dict) else None
        reason = metadata.get("termination_reason") if isinstance(metadata, dict) else None
        if not isinstance(scheduler, dict) or not scheduler or reason not in self.CONTINUABLE_REASONS:
            raise RuntimeError("This run did not stop on budget exhaustion and cannot be continued")
        job_id = uuid.uuid4().hex
        recovery_pending = False
        with self._run_lock:
            if self._closing:
                raise RuntimeError("The backend is shutting down")
            if self._run_state.get("status") in self.ACTIVE_STATES | {"cleanup_pending"}:
                raise RuntimeError("A test run is already active")
            self._stop_requested = False
            self._run_state = {"id": job_id, "run_id": run_id, "status": "starting",
                               "result_directory": str(directory), "phase": "continuation"}
            self._idle_event.clear()
        try:
            raw = self._private_draft(incoming)
            pending = self._pending_recovery_runs()
            if pending:
                recovery_pending = True
                with self._run_lock:
                    self._run_state["recovery_runs"] = pending
                raise RuntimeError("Unfinished inbound cleanup must be recovered before another run")
            output = raw.setdefault("output", {})
            # Same experiment: the journal, checkpoint and reports of this run
            # keep growing in their own directory.
            output["directory"] = str(directory)
            config = _config_from_raw(raw, self.config_path)
            # A continuation must never reach a different panel than the run it
            # continues, even when the local configuration moved on.
            identity = metadata.get("panel_identity") if isinstance(metadata, dict) else None
            if identity != configuration_hash({"url": config.panel.get("url")}):
                raise ValueError("Saved run panel identity is missing or differs; manual matching is required")
            if config.combination_strategy != "adaptive":
                raise ValueError("Only an adaptive search can be continued with a larger budget")
            limits = _raised_budget(scheduler.get("budget"), {
                "candidates": config.max_combinations,
                "requests": int(config.adaptive["request_budget"]),
                "traffic_bytes": int(config.adaptive["traffic_budget_bytes"]),
                "api_applies": int(config.adaptive["apply_budget"]),
                "elapsed_seconds": float(config.adaptive["time_budget_seconds"]),
            })
            generator = CombinationGenerator(config.search_parameters())
        except Exception as error:
            with self._run_lock:
                self._run_state.update({"status": "cleanup_pending" if recovery_pending else "failed",
                                        "error": self._redactor.redact_text(f"{type(error).__name__}: {error}")})
                self._idle_event.set()
            raise
        with self._run_lock:
            self._run_state = {"id": job_id, "status": "stopping" if self._stop_requested else "running",
                               "run_id": run_id, "resumed": True, "strategy": config.combination_strategy,
                               "continuation": {"reason": reason, "budget": limits},
                               "raw_combinations": generator.raw_count,
                               "planned_combinations": config.max_combinations,
                               "planned_runs": config.max_combinations * config.runs_per_combination,
                               "result_directory": str(directory),
                               "completed": int(checkpoint.get("completed", 0) or 0),
                               "failed": int(checkpoint.get("failed", 0) or 0),
                               "skipped": 0, "warnings": self._preview_warnings(config)}
        self._start_worker(job_id, config, directory, resume=True)
        return self.run_status()

    def stop_run(self) -> dict[str, Any]:
        with self._run_lock:
            self._stop_requested = True
            if self._runner:
                self._runner.request_stop()
            if self._run_state.get("status") in {"starting", "running"}:
                self._run_state["status"] = "stopping"
        return self.run_status()

    def shutdown(self, timeout: float = 60.0) -> bool:
        """Stop the accepted job and wait for its runner/cleanup to return."""
        with self._run_lock:
            self._closing = True
        self.stop_run()
        finished = self._idle_event.wait(max(0.0, timeout))
        with self._run_lock:
            thread = self._worker_thread
        if finished and thread is not None and thread is not threading.current_thread():
            # The completion event is set by the worker's final block. Joining
            # closes the tiny remaining interval before its actual exit.
            thread.join(timeout=1.0)
        if not finished:
            with self._run_lock:
                self._run_state.update({"status": "cleanup_pending", "error": "Shutdown timed out; recovery must be checked before another run"})
        return finished

    def run_status(self) -> dict[str, Any]:
        with self._run_lock:
            return self._redactor.redact(deepcopy(self._run_state))

    def _write_run_error(self, directory: Path, message: str) -> None:
        """Keep the failure reason next to the results.

        `_run_state` lives in memory only, so without this file a page refresh
        loses the reason the run stopped.
        """
        try:
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "run-error.txt").write_text(self._redactor.redact_text(message), encoding="utf-8")
        except OSError:
            # The failure is already reported through _run_state.
            pass

    def runs_directory(self) -> Path:
        raw = self.raw_config()
        return Path(str(raw.get("output", {}).get("directory", "./results"))).resolve() / "runs"

    @staticmethod
    def _recovery_pending(directory: Path) -> bool:
        manifest = directory / ".recovery" / "inbound-recovery.json"
        if not manifest.exists():
            return False
        if manifest.is_symlink() or manifest.parent.is_symlink():
            return True
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
            return not isinstance(data, dict) or data.get("state") != "cleaned"
        except (OSError, ValueError):
            return True

    def _pending_recovery_runs(self) -> list[str]:
        root = self.runs_directory()
        if not root.is_dir():
            return []
        return [path.name for path in root.iterdir() if path.is_dir() and not path.is_symlink() and
                self.RUN_ID.fullmatch(path.name) and self._recovery_pending(path)]

    def recover_run(self, run_id: str) -> dict[str, Any]:
        """Explicitly reconcile and clean only a saved run from this panel."""
        if not self.RUN_ID.fullmatch(run_id):
            raise ValueError("Unknown run")
        root = self.runs_directory()
        directory = root / run_id
        if not directory.is_dir() or directory.is_symlink() or directory.resolve().parent != root.resolve():
            raise FileNotFoundError("Run is not available")
        recovery_dir = directory / ".recovery"
        if recovery_dir.is_symlink():
            raise ValueError("Recovery directory is not available")
        if not self._recovery_pending(directory):
            raise ValueError("There is no pending cleanup for this run")
        if any((recovery_dir / name).is_symlink() for name in ("inbound-recovery.json", "source-snapshot.json")):
            raise ValueError("Recovery files are not available")
        job_id = uuid.uuid4().hex
        with self._run_lock:
            if self._closing or self._run_state.get("status") in self.ACTIVE_STATES:
                raise RuntimeError("A test run is already active or the backend is shutting down")
            self._stop_requested = False
            self._idle_event.clear()
            self._run_state = {"id": job_id, "run_id": run_id, "status": "starting",
                               "result_directory": str(directory), "phase": "recovery", "cleanup_pending": True}

        def worker() -> None:
            async def action() -> dict[str, Any]:
                config = load_config(self.config_path)
                self._redactor.add(config.panel)
                checkpoint_path = directory / "state.json"
                if checkpoint_path.is_symlink():
                    raise ValueError("Recovery checkpoint is not available")
                try:
                    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    raise ValueError("Saved run has no verified panel identity; manual matching is required") from None
                identity = checkpoint.get("metadata", {}).get("panel_identity")
                if identity != configuration_hash({"url": config.panel.get("url")}):
                    raise ValueError("Saved run panel identity is missing or differs; manual matching is required")
                client = ThreeXUIClient(config.panel, config.api_timeout)
                try:
                    manager = InboundManager(client, config.inbound.get("mode", "clone"),
                                             int(config.inbound["source_id"]), recovery_dir=recovery_dir,
                                             topology=config.topology)
                    await client.authenticate()
                    discovery = await client.discover()
                    atomic_json(directory / "discovery.json", self._redactor(discovery))
                    source = await manager.preflight()
                    self._redactor.add(source)
                    atomic_json(directory / "preflight.json", self._redactor({
                        "operation": "recovery", "panel_identity": identity, "topology": config.topology,
                        "recovery": manager.recovery_summary()}))
                    with self._run_lock:
                        self._run_state["status"] = "cleanup"
                    # Stop closes new experimentation; an accepted cleanup must
                    # finish instead of being cancelled halfway through restore.
                    await asyncio.wait_for(manager.recover_pending(), timeout=30.0)
                    summary = manager.recovery_summary()
                    atomic_json(directory / "recovery-status.json", self._redactor(summary))
                    checkpoint.setdefault("metadata", {})["cleanup_pending"] = bool(summary.get("cleanup_pending"))
                    atomic_json(checkpoint_path, checkpoint, private=True)
                    return summary
                finally:
                    await client.aclose()
            try:
                summary = asyncio.run(asyncio.wait_for(action(), timeout=60.0))
                with self._run_lock:
                    self._run_state.update({"status": "cleanup_pending" if summary.get("cleanup_pending") else "completed",
                                            "cleanup_pending": bool(summary.get("cleanup_pending")), "summary": self._redactor(summary)})
            except Exception as error:
                message = self._redactor.redact_text(f"{type(error).__name__}: {error}")
                with self._run_lock:
                    self._run_state.update({"status": "cleanup_pending", "error": message})
                self._write_run_error(directory, message)
            finally:
                self._idle_event.set()

        thread = threading.Thread(target=worker, name=f"3xui-recovery-{job_id[:8]}", daemon=False)
        with self._run_lock:
            self._worker_thread = thread
        try:
            thread.start()
        except Exception:
            self._idle_event.set()
            with self._run_lock:
                self._run_state["status"] = "cleanup_pending"
            raise
        return self.run_status()

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
            pending = self._recovery_pending(directory)
            runs.append({"id": directory.name, **self._run_summary(directory),
                         "status": "cleanup_pending" if pending else "saved", "cleanup_pending": pending})
        for run in runs:
            if Path(str(active.get("result_directory", ""))).resolve() == (root / run["id"]).resolve():
                run["status"] = active.get("status")
        return runs

    def _run_summary(self, directory: Path) -> dict[str, Any]:
        """Public history fields, invalidated by journal, checkpoint or directory changes."""
        with self._cache_lock:
            return self._locked_run_summary(directory)

    def _public_run_fields(self, metadata: Any, budget: Any = None) -> dict[str, Any]:
        """Project a private checkpoint onto typed, explicitly public run fields."""
        if not isinstance(metadata, dict):
            metadata = {}
        result: dict[str, Any] = {}
        reason = metadata.get("termination_reason")
        if isinstance(reason, str) and reason:
            result["termination_reason"] = self._redactor.redact_text(reason)[:1024]
        for key in ("confirmed_candidates", "viable_candidates"):
            value = metadata.get(key)
            if type(value) is int and value >= 0:
                result[key] = value

        def public_counts(values: Any) -> dict[str, Any]:
            if not isinstance(values, dict):
                return {}
            return {key: value for key in self.BUDGET_FIELDS
                    if type(value := values.get(key)) in (int, float) and value >= 0
                    and (type(value) is int or math.isfinite(value))}

        if isinstance(budget, dict):
            public_budget = public_counts(budget)
            limits = public_counts(budget.get("limits"))
            if limits:
                public_budget["limits"] = limits
            if public_budget:
                result["budget"] = public_budget
        return self._redactor.redact(result)

    def _checkpoint_run_fields(self, path: Path) -> dict[str, Any]:
        if path.is_symlink():
            return {}
        try:
            checkpoint = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        if not isinstance(checkpoint, dict):
            return {}
        # Register backend-only literals before redacting the public projection.
        # The complete checkpoint is never cached or returned to the browser.
        self._redactor.add(checkpoint)
        scheduler = checkpoint.get("scheduler")
        budget = scheduler.get("budget") if isinstance(scheduler, dict) else None
        return self._public_run_fields(checkpoint.get("metadata"), budget)

    def _locked_run_summary(self, directory: Path) -> dict[str, Any]:
        journal = directory / "results.jsonl"
        checkpoint = directory / "state.json"
        try:
            journal_stat = journal.stat() if journal.is_file() else None
            checkpoint_stat = checkpoint.stat() if checkpoint.is_file() and not checkpoint.is_symlink() else None
            directory_stat = directory.stat()
        except OSError:
            return {"records": 0, "files": []}
        stamp = (journal_stat.st_mtime_ns if journal_stat else 0, journal_stat.st_size if journal_stat else 0,
                 checkpoint_stat.st_mtime_ns if checkpoint_stat else 0, checkpoint_stat.st_size if checkpoint_stat else 0,
                 directory_stat.st_mtime_ns)
        cached = self._runs_cache.get(directory.name)
        if cached and cached["stamp"] == stamp:
            return deepcopy(cached["summary"])
        if journal_stat:
            with journal.open("rb") as stream:
                records = sum(bool(line.strip()) and line.endswith(b"\n") for line in stream)
        else:
            records = 0
        files = [name for name in self.REPORT_FILES if (directory / name).is_file()]
        summary = {"records": records, "files": files, **self._checkpoint_run_fields(checkpoint)}
        self._runs_cache[directory.name] = {"stamp": stamp, "summary": summary}
        return deepcopy(summary)

    def report_path(self, run_id: str, filename: str) -> Path:
        if not self.RUN_ID.fullmatch(run_id) or filename not in self.REPORT_FILES:
            raise ValueError("Unknown report")
        root = self.runs_directory()
        directory = root / run_id
        path = directory / filename
        if directory.is_symlink() or path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(directory.resolve()):
            raise FileNotFoundError("Report is not available")
        return path

    def run_dashboard(self, query: dict[str, int] | None = None) -> dict[str, Any]:
        """Summarize the durable journal so the UI survives a page refresh.

        The journal is read incrementally: only bytes appended since the
        previous poll are parsed, so a growing run does not re-read the file
        every 1.5 s.
        """
        with self._run_lock:
            state = deepcopy(self._run_state)
        directory = state.get("result_directory")
        if not directory:
            return {"records": 0, "planned_runs": state.get("planned_runs", 0), "candidates": []}
        path = Path(str(directory))
        return self._directory_dashboard(path, state, query)

    def saved_run_dashboard(self, run_id: str, query: dict[str, int] | None = None) -> dict[str, Any]:
        if not self.RUN_ID.fullmatch(run_id):
            raise ValueError("Unknown run")
        root = self.runs_directory()
        path = root / run_id
        if not path.is_dir() or path.is_symlink() or path.resolve().parent != root.resolve():
            raise FileNotFoundError("Run is not available")
        with self._run_lock:
            state = deepcopy(self._run_state)
        if not state.get("result_directory") or Path(state["result_directory"]).resolve() != path.resolve():
            state = {"status": "cleanup_pending" if self._recovery_pending(path) else "saved",
                     "run_id": run_id, "result_directory": str(path)}
        return self._directory_dashboard(path, state, query)

    def _directory_dashboard(self, path: Path, state: dict[str, Any], query: dict[str, int] | None) -> dict[str, Any]:
        query = query or {}
        cursor, limit = query.get("cursor", 0), query.get("limit", 100)
        if cursor < 0 or not 1 <= limit <= 200:
            raise ValueError("Dashboard cursor must be nonnegative and limit in 1..200")
        summary = self._run_summary(path)
        public_metadata = {key: summary[key] for key in self.RUN_METADATA_FIELDS if key in summary}
        public_metadata.update(self._public_run_fields(state, state.get("budget")))
        records = self._new_journal_records(path)
        if records is None:
            return {"records": 0, "planned_runs": state.get("planned_runs", 0), "candidates": [],
                    "candidate_count": 0, "cursor": cursor, "limit": limit, "next_cursor": None,
                    "run_id": state.get("run_id", path.name), "status": state.get("status", "saved"),
                    "cleanup_pending": self._recovery_pending(path), **public_metadata}
        payload = self._dashboard_payload(records, state)
        payload.update(public_metadata)
        candidates = payload["candidates"]
        payload.update({"candidate_count": len(candidates), "cursor": cursor, "limit": limit,
                        "next_cursor": cursor + limit if cursor + limit < len(candidates) else None,
                        "candidates": candidates[cursor:cursor + limit],
                        "run_id": state.get("run_id", path.name), "status": state.get("status", "saved")})
        with self._cache_lock:
            cache = self._dashboard_cache.get(str(path), {})
            payload["journal"] = {"corrupt_records": cache.get("corrupt_records", 0),
                                  "incomplete_bytes": len(cache.get("tail", b""))}
        return self._redactor.redact(payload)

    def _new_journal_records(self, path: Path) -> list[dict[str, Any]] | None:
        with self._cache_lock:
            return self._locked_new_journal_records(path)

    def _locked_new_journal_records(self, path: Path) -> list[dict[str, Any]] | None:
        journal = path / "results.jsonl"
        try:
            stat = journal.stat()
        except FileNotFoundError:
            return None
        identity = (stat.st_dev, stat.st_ino)
        cache = self._dashboard_cache.setdefault(str(path), {"offset": 0, "tail": b"", "records": [],
                                                           "identity": identity, "corrupt_records": 0})
        if stat.st_size < cache["offset"] or identity != cache["identity"]:
            cache.update({"offset": 0, "tail": b"", "records": [], "identity": identity, "corrupt_records": 0})
        with journal.open("rb") as stream:
            stream.seek(cache["offset"])
            # Offset always points after *all* bytes read; tail retains only
            # bytes of the not-yet-complete record. Advancing by complete lines
            # would cause the tail to be read again on the next poll.
            pending = cache["tail"] + stream.read()
            cache["offset"] = stream.tell()
        lines = pending.split(b"\n")
        cache["tail"] = lines.pop()
        for line in lines:
            if line.strip():
                try:
                    record = json.loads(line.decode("utf-8"))
                    if not isinstance(record, dict):
                        raise ValueError("Journal records must be objects")
                    if not isinstance(record.get("configuration_hash"), str) or not isinstance(record.get("result"), dict):
                        raise ValueError("Journal record is missing its identity or result")
                    record.setdefault("configuration", {})
                    cache["records"].append(record)
                except (UnicodeDecodeError, ValueError):
                    # A damaged completed row is reported separately. Keeping
                    # its raw bytes in an error message could leak credentials.
                    cache["corrupt_records"] += 1
        return deepcopy(cache["records"])

    @staticmethod
    def _dashboard_payload(records: list[dict[str, Any]], state: dict[str, Any]) -> dict[str, Any]:
        path = Path(str(state["result_directory"]))
        store = ResultStore(path)

        def request_sample_count(group: list[dict[str, Any]]) -> int | None:
            total = 0
            for row in group:
                result = row.get("result", {})
                metrics = result.get("screening") or result
                if not isinstance(metrics, dict):
                    return None
                count = metrics.get("http_request_count")
                if count is None:
                    counts = (metrics.get("successful_requests"), metrics.get("failed_requests"))
                    if any(type(value) is not int or value < 0 for value in counts):
                        return None
                    count = sum(counts)
                if type(count) is not int or count < 0:
                    return None
                total += count
            return total if group else None

        attempted = [item for item in records if item.get("result", {}).get("status") != "SKIPPED"]
        skipped = len(records) - len(attempted)
        summaries = store._summaries(attempted)
        grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
        for item in attempted:
            key = (item.get("phase", "search"), item.get("fidelity", "full"),
                   item.get("environment_epoch", 0), item.get("configuration_hash"))
            grouped.setdefault(key, []).append(item)
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
                "configuration_hash": item.get("configuration_hash"),
                "phase": item.get("phase", "search"), "fidelity": item.get("fidelity", "full"),
                "environment_epoch": item.get("environment_epoch", 0), "profile_id": item.get("profile_id"),
                "qualification": str(item.get("qualification") or "legacy_measured"),
            }
            for number, item in enumerate(summaries, start=1)
        ]
        for candidate in candidates:
            group = grouped.get((candidate["phase"], candidate["fidelity"], candidate["environment_epoch"],
                                 candidate["configuration_hash"]), [])
            latest = group[-1] if group else {}
            metrics = latest.get("result", {})
            diagnosis = metrics.get("diagnosis") or latest.get("diagnosis")
            diagnosis_code = diagnosis.get("code") if isinstance(diagnosis, dict) else diagnosis
            candidate.update({"reason_code": metrics.get("reason_code") or metrics.get("reason") or diagnosis_code,
                              "diagnosis": diagnosis if isinstance(diagnosis, dict) else None,
                              "sample_count": request_sample_count(group),
                              "selection_reason": latest.get("selection_reason"),
                              "duration_ms": latest.get("duration_ms"),
                              "last_timestamp": latest.get("timestamp")})
        successful = [item for item in candidates if item["successful"] and
                      (item["qualification"].startswith("confirmed") or item["qualification"] == "legacy_measured")]
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
            "confirmed_candidates": len({item["configuration_hash"] for item in candidates
                                         if item["qualification"].startswith("confirmed")}),
            "preliminary_candidates": len({item["configuration_hash"] for item in candidates
                                           if item["successful"] and item["qualification"] in {"preliminary", "viable", "screened"}}),
            "best_score": maximum("score"), "best_p95": minimum("p95_ms"),
            "fastest": maximum("download_mbps"), "candidates": candidates,
        }

