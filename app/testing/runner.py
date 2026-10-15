from __future__ import annotations

import asyncio
import copy
import itertools
import json
import statistics
import time
import httpx
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable
from urllib.parse import urlparse

from app.api.base import PanelClient
from app.api.three_xui import PanelAPIError, ThreeXUIClient
from app.config import ExperimentConfig, offline_warnings
from app.inbound.manager import InboundManager
from app.parameters.generator import Combination, CombinationGenerator, configuration_hash, _pair_features
from app.parameters.mapping import apply_mapping
from app.results.writer import ResultStore
from app.security.masking import SecretRedactor, mask_inbound_payload, mask_log_text, mask_parameter_values, mask_secrets
from app.state.checkpoint import Checkpoint, atomic_json
from app.xray.client import XrayClient, XrayClientError, categorize_xray_logs
from app.xray.config_builder import ClientConfigBuilder
from app.xray.reality import (RealityCredentials, RealityProfile, configured_candidates, parse_candidates,
                              prepare_reality_inbound, profile_of, resolve_profile, stream_settings, validate_pair)
from app.xray.diagnostics import kcp_noop_diagnostics
from app.xray.validation import ClientConfigValidator, CoreValidationUnavailable, check_client_config
from app.testing.measurements import MeasurementSuite
from app.testing.network import direct_route_status
from app.testing.search import AdaptiveScheduler, SearchBudget, POLICY_VERSION
from app.xray.transports import effective_transport

# ML-DSA-65 pins need a long certificate chain; shorter ones cannot carry the key.
MIN_MLDSA_CERT_CHAIN_BYTES = 3500

# Budget dimensions a continuation may raise on top of an exhausted checkpoint.
# They are deliberately absent from `_search_signature`: raising a limit is the
# one change a resume is allowed to carry, while every other difference
# (parameters, strategy, gates, topology) still refuses an inconsistent resume.
CONTINUATION_BUDGET_KEYS = ("request_budget", "traffic_budget_bytes", "apply_budget", "time_budget_seconds")


def prepare_inbound_payload(payload: dict[str, Any], values: dict[str, Any]) -> dict[str, Any]:
    """Remove protocol options inherited from the source that the new transport cannot use."""
    if payload.get("protocol") != "vless":
        return payload

    stream_raw = payload.get("streamSettings", {})
    stream_was_text = isinstance(stream_raw, str)
    try:
        stream = json.loads(stream_raw) if stream_was_text else stream_raw
    except json.JSONDecodeError as error:
        raise ValueError("inbound.streamSettings must be valid JSON") from error
    if not isinstance(stream, dict):
        return payload

    # xtls-rprx-vision is valid on raw TCP only. The source `test` inbound
    # uses Vision, so carrying its client setting into WS/gRPC/KCP/etc makes
    # Xray reject each outbound before it even reaches the server.
    network = str(values.get("network", stream.get("network", "tcp")))
    security = str(values.get("security", stream.get("security", "none")))
    if network != "tcp" or security not in {"tls", "reality"}:
        settings_raw = payload.get("settings", {})
        settings_was_text = isinstance(settings_raw, str)
        try:
            settings = json.loads(settings_raw) if settings_was_text else settings_raw
        except json.JSONDecodeError as error:
            raise ValueError("inbound.settings must be valid JSON") from error
        if isinstance(settings, dict):
            for client in settings.get("clients", []):
                if isinstance(client, dict):
                    client.pop("flow", None)
            payload["settings"] = (json.dumps(settings, ensure_ascii=False, separators=(",", ":"))
                                   if settings_was_text else settings)

    payload["streamSettings"] = (json.dumps(stream, ensure_ascii=False, separators=(",", ":"))
                                 if stream_was_text else stream)
    return payload


@dataclass(frozen=True)
class SearchCandidate:
    combination: Combination
    changed: frozenset[str]
    new_changes: frozenset[str]
    parent_score: float


class CandidateValidationError(ValueError):
    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code


class ExperimentRunner:
    CANARY_PORT = 1
    CANARY_TIMEOUT = 1.0

    def __init__(self, config: ExperimentConfig, panel: PanelClient,
                 progress_callback: Callable[[dict[str, Any]], None] | None = None):
        self.config, self.panel = config, panel
        self.generator = CombinationGenerator(config.search_parameters())
        self._usable_candidates: list[dict[str, str]] = []
        self._reality_scan_rejected: list[str] = []
        self.stop_requested = False
        self.progress_callback = progress_callback
        self._tcp_probe_trustworthy: bool | None = None
        self._last_inbound_payload_hash: str | None = None
        self._active_inbound: dict[str, Any] | None = None
        self._reality_profile: RealityProfile | None = None
        self._reality_profile_error: str | None = None
        self._reality_credentials: RealityCredentials | None = None
        self.redactor = SecretRedactor.from_config(config)
        self._route_status: dict[str, Any] = {}
        self._server_xray_version: str | None = None
        self._known_client_diagnostics: dict[str, str] = {}
        self._context_signature = ""
        self._api_applies = 0
        self._client_starts = 0
        self._manager: InboundManager | None = None
        # Xray itself decides whether a client config can be built; the local
        # binary answers per unique config, structurally identical to the
        # process the runner would start next.
        self._config_validator = ClientConfigValidator(
            str(self.config.testing.get("xray_binary", "xray")),
            enabled=bool(self.config.testing.get("validate_config", True)),
            strict=bool(self.config.testing.get("validate_config", True)),
            timeout=float(self.config.timeouts.get("xray_config_test", 15)),
            config_directory=self.config.output_dir / ".xray-runtime",
        )

    async def _scan_candidates(self, candidates: list[dict[str, str]],
                               source: dict[str, Any]) -> tuple[list[dict[str, str]], list[str]]:
        """Probe every target on the panel; return the usable ones and why the rest were dropped."""
        if not callable(getattr(self.panel, "scan_reality_target", None)):
            raise PanelAPIError("Panel does not provide scanRealityTarget")
        openapi = getattr(self.panel, "openapi", None)
        if openapi is not None and "post" not in openapi.get("paths", {}).get(
                ThreeXUIClient.REALITY_SCAN_PATH, {}):
            raise PanelAPIError("Panel OpenAPI lacks scanRealityTarget")
        settings = stream_settings(source).get("realitySettings") or {}
        if isinstance(settings, str):
            settings = json.loads(settings)
        xver = int(settings.get("xver", 0)) if isinstance(settings, dict) else 0
        has_mldsa = isinstance(settings, dict) and bool(settings.get("mldsa65Seed"))
        semaphore = asyncio.Semaphore(4)

        async def scan(item: dict[str, str]) -> tuple[dict[str, str], dict[str, Any]]:
            async with semaphore:
                try:
                    result = await self.panel.scan_reality_target(item["target"], item["server_name"], xver)
                except (httpx.HTTPError, PanelAPIError) as error:
                    result = {"feasible": False, "reason": f"panel probe failed: {type(error).__name__}: {error}"}
                return item, result

        responses = await asyncio.gather(*(scan(item) for item in candidates))
        usable: list[dict[str, str]] = []
        rejected: list[str] = []
        for item, result in responses:
            chain_bytes = int(result.get("certChainBytes", 0) or 0)
            if (result.get("feasible") is True and result.get("privateTarget") is not True
                    and (not has_mldsa or chain_bytes >= MIN_MLDSA_CERT_CHAIN_BYTES)):
                usable.append(item)
                continue
            if result.get("reason"):
                reason = str(result["reason"])
            elif result.get("privateTarget"):
                reason = "private target"
            elif has_mldsa and chain_bytes < MIN_MLDSA_CERT_CHAIN_BYTES:
                reason = "certificate chain too short for ML-DSA-65"
            else:
                reason = "not feasible"
            rejected.append(f"{item['target']} / {item['server_name']}: {reason}")
        return usable, rejected

    def request_stop(self) -> None:
        self.stop_requested = True

    async def preflight(self) -> dict[str, Any]:
        try:
            __import__("socksio")
        except ImportError as error:
            raise RuntimeError("SOCKS measurements require project dependencies: run through 'uv run' or the project .venv") from error
        if "xlsx" in self.config.output.get("formats", []):
            try:
                __import__("openpyxl")
            except ImportError as error:
                raise RuntimeError("XLSX export requires openpyxl: run through 'uv run' or the project .venv") from error
        await self.panel.authenticate()
        openapi = await self.panel.discover()
        manager = InboundManager(self.panel, self.config.inbound.get("mode", "clone"), int(self.config.inbound["source_id"]),
                                 self.config.candidate_ports,
                                 test_port=int(self.config.inbound["test_port"]) if self.config.inbound.get("test_port") is not None else None,
                                 backup_path=self.config.output_dir / "source-inbound-backup.json",
                                 recovery_dir=self.config.output_dir / ".recovery", topology=self.config.topology)
        source = await manager.preflight()
        self.redactor.add(source)
        status = await self.panel.server_status()
        version = status.get("xray", {}).get("version")
        self._server_xray_version = str(version) if version is not None else None
        if status.get("xray", {}).get("state") != "running":
            raise RuntimeError("Panel reports that Xray is not running")
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        if not self.config.testing.get("urls"):
            raise ValueError("testing.urls is required for a non-dry run")
        server_address = str(self.config.testing.get("server_address") or urlparse(self.config.panel["url"]).hostname or "")
        if self.config.testing.get("require_direct_route", False):
            self._route_status = await direct_route_status(server_address)
            if self._route_status.get("direct") is not True:
                raise RuntimeError("direct_route_required: add a physical host route using tools/Set-TesterDirectRoute.ps1 or route.exe")
        self._tcp_probe_trustworthy = await self._tcp_probe_is_trustworthy(server_address)
        # Probe the local binary once, before any inbound is touched: a config
        # the core would reject must never reach the panel.
        core_state = self._config_validator.availability()
        if core_state is not None and self._config_validator.strict:
            raise CoreValidationUnavailable(core_state)
        self._context_signature = configuration_hash({"source": {key: source.get(key) for key in (
            "protocol", "port", "listen", "settings", "streamSettings")}, "topology": self.config.topology,
            "xray_version": status.get("xray", {}).get("version"), "urls": self.config.testing.get("urls"),
            "route": self._route_status})
        atomic_json(self.config.output_dir / "discovery.json", self.redactor(openapi))
        atomic_json(self.config.output_dir / "preflight.json", self.redactor({
            "openapi_version": openapi.get("info", {}).get("version"),
            "xray_version": status.get("xray", {}).get("version"), "source_id": manager.source_id,
            "source_protocol": source.get("protocol"), "source_enabled": source.get("enable"),
            "topology": self.config.topology, "source_requires_proxy_protocol":
            bool(stream_settings(source).get("sockopt", {}).get("acceptProxyProtocol")),
            "test_ports": list(self.config.candidate_ports), "fixed_test_port": manager.test_port,
            "route": self._route_status, "context_signature": self._context_signature,
            "panel_identity": configuration_hash({"url": self.config.panel.get("url")}),
            "recovery": manager.recovery_summary()}))
        return {"openapi_version": openapi.get("info", {}).get("version"), "xray_version": status.get("xray", {}).get("version"),
                "source": source, "manager": manager}

    async def run(self, *, dry_run: bool = False, resume: bool = False, max_tests: int | None = None) -> dict[str, Any]:
        prepared = await self.preflight()
        manager: InboundManager = prepared["manager"]
        self._manager = manager
        checkpoint_path = self.config.output_dir / "state.json"
        resume_checkpoint = Checkpoint.load(checkpoint_path) if resume else None
        if resume and resume_checkpoint is None:
            raise FileNotFoundError(f"--resume requested but {checkpoint_path} does not exist")
        self._reality_profile, self._reality_profile_error = resolve_profile(self.config.testing, prepared["source"])
        candidates = configured_candidates(self.config.testing, self.config.source_path)
        if candidates:
            available, rejected = await self._scan_candidates(candidates, prepared["source"])
            self._reality_scan_rejected = rejected
            saved = resume_checkpoint.metadata.get("reality_candidates") if resume_checkpoint else None
            if saved is not None:
                previous = parse_candidates({"targets": saved})
                if any(item not in available for item in previous):
                    raise ValueError("Previously accepted REALITY target is unavailable; retry --resume later")
                self._usable_candidates = previous
            else:
                self._usable_candidates = available
            if not self._usable_candidates:
                reasons = "; ".join(self._reality_scan_rejected[:3])
                raise ValueError(f"No REALITY targets passed the server-side feasibility check: {reasons}")
            self._reality_profile = profile_of(self._usable_candidates[0])
            self._reality_profile_error = None
            self.generator = CombinationGenerator(
                self.config.search_parameters(self._usable_candidates),
                protocol=str(prepared["source"].get("protocol", "")),
                source_stream=stream_settings(prepared["source"]),
            )
        else:
            self.generator = CombinationGenerator(self.config.parameters,
                protocol=str(prepared["source"].get("protocol", "")),
                source_stream=stream_settings(prepared["source"]))
        server_address = str(self.config.testing.get("server_address") or urlparse(self.config.panel["url"]).hostname or "")
        warnings = self._warnings()
        configured_limit = self.config.max_combinations
        effective_limit = min(max_tests, configured_limit) if max_tests is not None else configured_limit
        if self.config.combination_strategy == "adaptive":
            plan = self.generator.adaptive_frontier(effective_limit, seed=self.config.adaptive["seed"])
            combinations = iter(plan)
            preview, planned_count, dry_run_candidates = plan[:10], effective_limit, plan
        elif self.config.combination_strategy == "mutation":
            plan = self.generator.mutations(limit=effective_limit)
            combinations = iter(())
            preview = plan[:min(10, effective_limit)]
            planned_count = effective_limit
            dry_run_candidates = plan[:effective_limit]
        elif self.config.combination_strategy == "pairwise":
            plan = self.generator.pairwise(effective_limit)
            combinations = iter(plan[:effective_limit])
            preview = plan[:min(10, effective_limit)]
            planned_count = min(len(plan), effective_limit)
            dry_run_candidates = plan[:effective_limit]
        else:
            # One pass over the generator: the plan is needed as candidates, for the
            # preview and for the count, and each pass re-normalizes every candidate.
            plan = list(itertools.islice(self.generator.iter_valid(), effective_limit))
            combinations = iter(plan)
            preview = plan[:min(10, effective_limit)]
            planned_count = len(plan)
            dry_run_candidates = plan
        if self.progress_callback:
            self.progress_callback({"planned_combinations": planned_count,
                                    "planned_runs": planned_count * self.config.runs_per_combination,
                                    "warnings": warnings})
        if dry_run:
            candidates = dry_run_candidates
            # Only mutation seeds are knowable before the adaptive search runs.
            placeholders = RealityCredentials("A" * 43, "B" * 43, "0123456789abcdef")
            self._reality_credentials = placeholders
            skipped = sum(self._candidate_error(item.values, prepared["source"], server_address) is not None
                          for item in candidates)
            self._reality_credentials = None
            warnings = self._warnings()
            if self.progress_callback:
                self.progress_callback({"warnings": warnings})
            response = {"strategy": self.config.combination_strategy, "raw_combinations": self.generator.raw_count,
                    "planned_combinations": len(candidates) if self.config.combination_strategy == "exhaustive" else planned_count,
                    "limit": effective_limit,
                    "preview": [self._public_values(item.values) for item in preview],
                    "metadata": {"openapi_version": prepared["openapi_version"], "xray_version": prepared["xray_version"],
                                 "source_inbound_id": manager.source_id}, "warnings": warnings}
            response["skipped_initial_candidates" if self.config.combination_strategy == "mutation" else
                     "skipped_combinations"] = skipped
            return response
        if manager.mode == "existing" and not self.config.inbound.get("allow_existing", False):
            raise PermissionError("existing mode requires inbound.allow_existing: true")
        store = ResultStore(self.config.output_dir, self.redactor)
        checkpoint = resume_checkpoint
        experiment_id = checkpoint.experiment_id if checkpoint else datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        search_signature = self._search_signature()
        checkpoint = checkpoint or Checkpoint(experiment_id, {"started_at": datetime.now(UTC).isoformat(),
            "three_xui_version": prepared["openapi_version"], "xray_version": prepared["xray_version"],
            "source_inbound_id": manager.source_id, "search_signature": search_signature,
            "context_signature": self._context_signature,
            "panel_identity": configuration_hash({"url": self.config.panel.get("url")})})
        if self._usable_candidates:
            checkpoint.metadata["reality_candidates"] = self._usable_candidates
        if resume and checkpoint.metadata.get("search_signature") not in {None, search_signature}:
            raise ValueError("The configuration changed since this checkpoint; refusing an inconsistent resume")
        if resume and checkpoint.metadata.get("context_signature", self._context_signature) != self._context_signature:
            raise ValueError("The network/source context changed; start a new experiment instead of inconsistent resume")
        credentials_path = self.config.output_dir / ".reality-credentials.json"
        if self._reality_profile or self._usable_candidates:
            if resume:
                if checkpoint.metadata.get("reality_credentials"):
                    self._reality_credentials = RealityCredentials.load(credentials_path, experiment_id)
                elif any(item.get("result", {}).get("status") != "SKIPPED" for item in store.records()):
                    raise ValueError("Cannot resume an older REALITY experiment without saved credentials")
                else:
                    self._reality_credentials = RealityCredentials.generate(str(self.config.testing.get("xray_binary", "xray")))
                    self._reality_credentials.save(credentials_path, experiment_id)
            else:
                self._reality_credentials = RealityCredentials.generate(str(self.config.testing.get("xray_binary", "xray")))
                self._reality_credentials.save(credentials_path, experiment_id)
            checkpoint.metadata["reality_credentials"] = True
            self.redactor.add(self._reality_credentials.private_key).add(self._reality_credentials.password).add(self._reality_credentials.short_id)
        previous_records = store.records() if resume else []
        records_by_key = {f"{item['configuration_hash']}:{item['run']}": item for item in previous_records}
        if resume:
            checkpoint.completed_keys = set(records_by_key)
            checkpoint.failed = sum(item.get("result", {}).get("status") not in {"OK", "SKIPPED"} for item in previous_records)
        completed = len(records_by_key)
        skipped = sum(item.get("result", {}).get("status") == "SKIPPED" for item in previous_records)
        configurations_tested = 0
        interrupted = False
        termination_reason: str | None = None
        cleanup_error: str | None = None
        export_error: str | None = None
        adaptive_summary: dict[str, Any] = {}
        attempted_candidates: dict[str, Combination] = {}
        # Recovery after a crash immediately following create needs the panel
        # identity even when no trial has yet produced a journal record.
        checkpoint.save(checkpoint_path)
        try:
            if callable(getattr(manager, "recover_pending", None)):
                await manager.recover_pending()
            if self.stop_requested:
                return {"completed": completed, "interrupted": True, "termination_reason": "stopped"}
            test_id = await manager.prepare()
            base_payload = await self.panel.get_inbound(test_id)
            self.redactor.add(base_payload)
            if self.progress_callback:
                # The test inbound now exists in the panel; surfacing its id and
                # port lets the UI show that it was created (and on which port).
                self.progress_callback({"test_inbound_id": test_id,
                                        "test_inbound_port": int(base_payload.get("port", 0) or 0)})
            self._last_inbound_payload_hash = configuration_hash(base_payload)
            self._active_inbound = base_payload
            if self.config.combination_strategy != "adaptive":
                await self._run_controls(manager, base_payload, server_address)
            # Controls deliberately change the test inbound; the first search
            # candidate must always be applied again, even if hashes coincide.
            self._last_inbound_payload_hash = None
            self._active_inbound = None

            async def execute(number: int, combination: Combination,
                              generation: int | None = None) -> tuple[bool, float]:
                nonlocal completed, skipped, warnings
                attempted_candidates[combination.hash] = combination
                all_ok = True
                scores: list[float] = []
                failed_runs = 0
                first_key = f"{combination.hash}:1"
                if records_by_key.get(first_key, {}).get("result", {}).get("status") == "SKIPPED":
                    return False, 0.0
                reason = self._candidate_error(combination.values, base_payload, server_address)
                warnings = self._warnings()
                if reason:
                    if first_key not in records_by_key:
                        record = self._skipped_record(number, combination, reason)
                        store.append(record)
                        records_by_key[first_key] = record
                        checkpoint.completed_keys.add(first_key)
                        checkpoint.save(checkpoint_path)
                        completed += 1
                        skipped += 1
                        if self.progress_callback:
                            self.progress_callback({"completed": completed, "failed": checkpoint.failed,
                                                    "skipped": skipped, "test_id": number, "run": 1,
                                                    "configuration": self._public_values(combination.values),
                                                    "warnings": warnings, "result": record["result"]})
                    return False, 0.0
                for run_number in range(1, self.config.runs_per_combination + 1):
                    key = f"{combination.hash}:{run_number}"
                    record = records_by_key.get(key)
                    if record is None:
                        if self.stop_requested:
                            return False, 0.0
                        record = await self._one_run(
                            number, run_number, combination.values, combination.hash,
                            manager, base_payload, server_address,
                            include_ping=number == 1 and run_number == 1,
                        )
                        warnings = self._warnings()
                        store.append(record)
                        records_by_key[key] = record
                        if record["result"]["status"] not in {"OK", "SKIPPED"}:
                            checkpoint.failed += 1
                            store.error(record)
                        checkpoint.completed_keys.add(key)
                        checkpoint.save(checkpoint_path)
                        completed += 1
                        if self.progress_callback:
                            update = {"completed": completed, "failed": checkpoint.failed, "skipped": skipped,
                                      "test_id": number, "run": run_number,
                                      "configuration": self._public_values(combination.values),
                                      "warnings": warnings, "result": record["result"]}
                            if generation is not None:
                                update["generation"] = generation
                            self.progress_callback(update)
                        await asyncio.sleep(float(self.config.testing.get("test_delay", 0)))
                    result = record.get("result", {})
                    if result.get("status") != "OK":
                        all_ok = False
                        failed_runs += 1
                    scores.append(float(result.get("score", 0.0)))
                    if failed_runs >= self.config.max_failed_runs:
                        break
                return all_ok, statistics.mean(scores) if scores else 0.0

            if self.config.combination_strategy == "adaptive":
                adaptive_summary = await self._adaptive_search(plan, manager, base_payload, server_address,
                    store, checkpoint, checkpoint_path, records_by_key, effective_limit)
                completed = len(records_by_key)
                skipped = sum(item.get("result", {}).get("status") == "SKIPPED" for item in records_by_key.values())
                configurations_tested = adaptive_summary["configurations_tested"]
                termination_reason = adaptive_summary["termination_reason"]
                interrupted = self.stop_requested
            elif self.config.combination_strategy == "mutation":
                max_depth = self.config.mutation_generations
                beam_width = self.config.beam_width
                children_per_parent = self.config.children_per_parent
                root, root_changes = self.generator.mutation_root()
                tested = {root.hash}
                coverage: Counter[str] = Counter()
                number = 1
                root_ok, root_score = await execute(number, root, 0)
                configurations_tested = 1
                parents: list[tuple[Combination, frozenset[str], float]] = [(root, root_changes, root_score)]
                for generation in range(1, max_depth + 1):
                    if self.stop_requested:
                        interrupted = True
                        termination_reason = "stopped"
                        break
                    # Generation 1 is a bootstrap around the baseline even when
                    # the baseline failed. Later generations expand only OK parents.
                    if generation > 1 and not parents:
                        termination_reason = "no_working_parents"
                        break
                    remaining = effective_limit - configurations_tested
                    if remaining <= 0:
                        termination_reason = "limit_reached"
                        break
                    pool = self._mutation_pool(
                        parents, tested, coverage,
                        None if generation == 1 else children_per_parent,
                        candidate_budget=remaining,
                    )
                    if not pool:
                        termination_reason = ("no_mutation_candidates" if generation == 1
                                              else "no_further_mutations")
                        break
                    selected = self._select_candidates(pool, remaining, coverage)
                    selected.sort(key=lambda item: self._payload_hash(base_payload, item.combination.values))
                    working_nodes: list[tuple[Combination, frozenset[str], float]] = []
                    for candidate in selected:
                        if self.stop_requested:
                            interrupted = True
                            termination_reason = "stopped"
                            break
                        number += 1
                        working, score = await execute(number, candidate.combination, generation)
                        configurations_tested += 1
                        tested.add(candidate.combination.hash)
                        coverage.update(candidate.new_changes)
                        if working:
                            working_nodes.append((candidate.combination, candidate.changed, score))
                    if interrupted:
                        break
                    parents = self._select_beam(working_nodes, beam_width)
                if termination_reason is None:
                    termination_reason = ("limit_reached" if configurations_tested >= effective_limit
                                          else "generation_limit_reached")
            else:
                for number, combination in enumerate(combinations, start=1):
                    if self.stop_requested:
                        interrupted = True
                        termination_reason = "stopped"
                        break
                    await execute(number, combination)
                    configurations_tested += 1
                if termination_reason is None:
                    termination_reason = ("limit_reached" if configurations_tested >= effective_limit
                                          else "plan_exhausted")
            if self.config.two_stage_enabled and self.config.combination_strategy != "adaptive" and not self.stop_requested:
                ranked = sorted((item for item in store._summaries(list(records_by_key.values()))
                                 if item["phase"] == "search" and item.get("successful_tests", 0) > 0),
                                key=lambda item: float(item.get("score_avg", 0)), reverse=True)[:self.config.validation_top_k]
                for rank, item in enumerate(ranked, 1):
                    candidate = attempted_candidates.get(item["configuration_hash"])
                    if candidate is None:
                        continue
                    already = [record for record in records_by_key.values() if record.get("phase") == "validation"
                               and record["configuration_hash"] == candidate.hash]
                    for _ in range(max(0, self.config.validation_runs - len(already))):
                        if self.stop_requested:
                            interrupted, termination_reason = True, "stopped"
                            break
                        run_number = max(record["run"] for record in records_by_key.values()
                                         if record["configuration_hash"] == candidate.hash) + 1
                        record = await self._one_run(item["test_id"], run_number, candidate.values,
                            candidate.hash, manager, base_payload, server_address)
                        warnings = self._warnings()
                        record.update({"phase": "validation", "candidate_rank": rank})
                        key = f"{candidate.hash}:{run_number}"
                        store.append(record)
                        records_by_key[key] = record
                        checkpoint.completed_keys.add(key)
                        completed += 1
                        if record["result"].get("status") != "OK":
                            checkpoint.failed += 1
                            store.error(record)
                        checkpoint.save(checkpoint_path)
                        if self.progress_callback:
                            self.progress_callback({"completed": completed, "phase": "validation",
                                "test_id": item["test_id"], "run": run_number,
                                "warnings": warnings, "result": record["result"]})
        finally:
            if self.progress_callback:
                self.progress_callback({"lifecycle_state": "cleanup"})
            try:
                await asyncio.wait_for(manager.cleanup(), timeout=float(self.config.timeouts.get("cleanup", 30)))
            except Exception as error:
                cleanup_error = self.redactor.redact_text(f"{type(error).__name__}: {error}")
            checkpoint.metadata["cleanup_pending"] = bool(cleanup_error) or bool(getattr(manager, "cleanup_pending", False))
            checkpoint.metadata["termination_reason"] = ("stopped" if self.stop_requested else
                adaptive_summary.get("termination_reason", termination_reason))
            for key in ("confirmed_candidates", "viable_candidates"):
                if key in adaptive_summary:
                    checkpoint.metadata[key] = adaptive_summary[key]
            checkpoint.save(checkpoint_path)
            try:
                store.export(self.config.output.get("formats", ["csv", "json"]))
            except Exception as error:
                export_error = self.redactor.redact_text(f"{type(error).__name__}: {error}")
        warnings = self._warnings()
        result = {"experiment_id": experiment_id, "completed": completed,
                  "configurations_tested": configurations_tested, "failed": checkpoint.failed,
                  "skipped": skipped, "warnings": warnings, "termination_reason": termination_reason, **adaptive_summary,
                  "cleanup_pending": checkpoint.metadata.get("cleanup_pending", False)}
        if interrupted:
            result["interrupted"] = True
        if cleanup_error:
            result["cleanup_error"] = cleanup_error
        if export_error:
            result["export_error"] = export_error
        return self.redactor(result)

    async def _adaptive_search(self, plan: list[Combination], manager: InboundManager,
                               base_payload: dict[str, Any], server_address: str, store: ResultStore,
                               checkpoint: Checkpoint, checkpoint_path: Any,
                               records: dict[str, dict[str, Any]], limit: int) -> dict[str, Any]:
        options = self.config.adaptive
        saved = checkpoint.scheduler or None
        if saved and saved.get("policy_version") != POLICY_VERSION:
            raise ValueError("Adaptive policy changed; start a new experiment")
        scheduler = AdaptiveScheduler(plan, float(options["exploration_fraction"]), saved)
        budget = SearchBudget(options, limit, (saved or {}).get("budget"))
        # Replay durable records after an append/checkpoint crash. Never count
        # the same hash:run twice or reuse validation run=1.
        replay_budget = SearchBudget(options, limit)
        for record in records.values():
            replay_budget.observe(record)
        for key in replay_budget.used:
            budget.used[key] = max(budget.used[key], replay_budget.used[key])
        budget.used["candidates"] = len(scheduler.seen)
        termination = "frontier_exhausted"
        environment: dict[str, Any] = {"route": self._route_status, "reference_path": "system_route"}
        validated_pairs = {tuple(item) for item in (saved or {}).get("validated_pairs", [])}
        screened_pairs = {tuple(item) for item in (saved or {}).get("screened_pairs", [])}
        urls = list(self.config.testing.get("urls", []))
        confirmation_urls = list(self.config.testing.get("confirmation_urls") or urls)
        measurement_policy = MeasurementSuite(self.config.testing, float(self.config.timeouts.get("request", 5)))

        def coverage() -> dict[str, Any]:
            return {**self.generator.coverage_metadata, "basis": "structural_frontier",
                    "core_validated_pairs": len(validated_pairs), "screened_pairs": len(screened_pairs)}

        def persist() -> None:
            checkpoint.scheduler = {**scheduler.snapshot(), "budget": budget.snapshot(),
                                    "coverage": coverage(), "seed": options["seed"],
                                    "validated_pairs": sorted(validated_pairs), "screened_pairs": sorted(screened_pairs)}
            checkpoint.save(checkpoint_path)

        def progress(**fields: Any) -> None:
            if self.progress_callback:
                self.progress_callback(self.redactor({"completed": len(records), "failed": checkpoint.failed,
                    "budget": budget.snapshot(), "coverage": coverage(),
                    "warnings": self._warnings(),
                    "viable_candidates": len(scheduler.viable), "confirmed_candidates": len(scheduler.confirmed),
                    "environment": environment, **fields}))

        async def reference() -> bool:
            # Reference requests establish endpoint availability in the OS
            # route, which may still use the user's VPN. They are not a direct
            # ISP control and never establish censorship causation.
            unique_by_url: dict[str, dict[str, Any]] = {}
            for item in urls:
                url, target_options = measurement_policy._target(item)
                unique_by_url.setdefault(url, {"url": url, **target_options})
            unique = list(unique_by_url.values())[:2]
            response_allowance = measurement_policy.response_allowance(len(unique), urls=unique)
            if not budget.permits(len(unique), response_bytes=response_allowance):
                return True
            observation = await asyncio.wait_for(MeasurementSuite.reference_check(unique,
                timeout=float(self.config.timeouts.get("request", 5)),
                stop_callback=lambda: self.stop_requested), timeout=max(.01, budget.remaining_time()))
            count = int(observation.get("reference_request_count", 0))
            budget.used["requests"] += count
            budget.used["traffic_bytes"] += int(observation.get("reference_bytes_received", 0))
            environment["references"] = self.redactor(observation)
            diagnostic = {"timestamp": datetime.now(UTC).isoformat(), "type": "endpoint_reference",
                          "reference_path": "system_route", "observation": self.redactor(observation)}
            with (self.config.output_dir / "diagnostics.jsonl").open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(diagnostic, ensure_ascii=False) + "\n")
            persist()
            return observation.get("reference_ok") is True

        async def trial(candidate: Combination, fidelity: str, count: int, reason: str) -> dict[str, Any] | None:
            run_number = max((item["run"] for item in records.values()
                              if item.get("configuration_hash") == candidate.hash), default=0) + 1
            probe_urls = confirmation_urls if fidelity == "confirmation" else urls
            if fidelity == "screening" and probe_urls:
                offset = (run_number - 1) % len(probe_urls)
                probe_urls = probe_urls[offset:] + probe_urls[:offset]
            response_allowance = measurement_policy.response_allowance(count, urls=probe_urls)
            requested, validation_error = self._candidate_payload(candidate.values, base_payload)
            if requested is not None and callable(getattr(manager, "normalize_payload", None)):
                requested = manager.normalize_payload(requested)
            apply_needed = int(requested is not None and configuration_hash(requested) != self._last_inbound_payload_hash)
            # Speed is sampled on every run that executes the full measurement
            # suite (the cheap screening probe excepted), so the download bytes
            # are reserved for each of those trials instead of only for the
            # finalist rung. The sample is capped by what the traffic budget can
            # still pay for; when nothing is left the run proceeds without it
            # rather than being dropped.
            extra_speed = 0
            if fidelity != "screening" and self.config.testing.get("speed_test", {}).get("enabled"):
                extra_speed = min(int(self.config.testing["speed_test"].get("max_bytes", 5_000_000)),
                                  max(0, budget.limits["traffic_bytes"] - budget.used["traffic_bytes"] - response_allowance))
            if not budget.permits(count + int(extra_speed > 0), response_bytes=response_allowance + extra_speed,
                                  api_applies=apply_needed):
                return None
            key = f"{candidate.hash}:{run_number}"
            scheduler.pending_trial = {"key": key, "fidelity": fidelity, "requests": count}
            persist()
            number = scheduler.active["test_id"] if scheduler.active else scheduler.selections
            progress(stage=fidelity, test_id=number, run=run_number,
                     profile_id=self.generator.profile_id(candidate.values), phase="search" if fidelity == "screening" else "validation")
            started = time.monotonic()
            applies_before, starts_before = self._api_applies, self._client_starts
            try:
                reason_code = self._candidate_error(candidate.values, base_payload, server_address)
                if reason_code:
                    record = self._skipped_record(number, candidate, reason_code)
                    record["run"] = run_number
                    record.update({"duration_ms": (time.monotonic() - started) * 1000, "api_applies": 0, "client_starts": 0})
                else:
                    validated_pairs.update(_pair_features(candidate.values))
                    record = await asyncio.wait_for(self._one_run(number, run_number, candidate.values,
                        candidate.hash, manager, base_payload, server_address,
                        screening_only=fidelity == "screening", fidelity=fidelity, requests=count,
                        urls=probe_urls, speed_bytes=extra_speed),
                        timeout=max(.01, budget.remaining_time()))
            except TimeoutError:
                record = {"test_id": number, "run": run_number, "timestamp": datetime.now(UTC).isoformat(),
                          "configuration_hash": candidate.hash, "configuration": self._public_values(candidate.values),
                          "result": {"status": "TIMEOUT", "stage": fidelity, "reason_code": "budget_deadline",
                                     "http_requests": count + int(extra_speed > 0),
                                     "traffic_bytes": response_allowance + extra_speed,
                                     "budget_accounting": "reserved_on_timeout"},
                          "duration_ms": (time.monotonic() - started) * 1000,
                          "api_applies": self._api_applies - applies_before,
                          "client_starts": self._client_starts - starts_before}
            record["result"]["requested_http_requests"] = count
            observed_metrics = record["result"].get("screening") or record["result"]
            if observed_metrics.get("measurement_stopped"):
                record["result"].update({"status": "FAILED", "reason_code": "measurement_stopped"})
                record["result"]["gate_failures"] = [*record["result"].get("gate_failures", []), "measurement_stopped"]
            qualification = ("preliminary" if record["result"].get("status") == "OK" else "unconfirmed")
            record.update({"schema_version": 2, "policy_version": POLICY_VERSION,
                           "phase": "search" if fidelity == "screening" else "validation", "fidelity": fidelity,
                           "rung": {"screening": 1, "comparison": 2, "confirmation": 3, "quality": 4}[fidelity],
                           "profile_id": self.generator.profile_id(candidate.values), "context_signature": self._context_signature,
                           "environment_epoch": 0, "selection_reason": reason, "qualification": qualification,
                           "effective_configuration_hash": configuration_hash({"payload": requested,
                               "values": candidate.values, "context": self._context_signature}),
                           "server_payload_hash": configuration_hash(requested or {})})
            record["result"]["qualification"] = qualification
            if fidelity in {"comparison", "confirmation"}:
                # A speed gate can only judge a run that carried a speed sample:
                # when the traffic budget left no room for one, the failure is
                # dropped as unmeasured instead of hiding a real measurement.
                failures = record["result"].get("gate_failures", [])
                if "download_mbps" not in record["result"]:
                    failures = [item for item in failures if not item.startswith("download_mbps<")]
                actual_requests = int(record["result"].get("http_requests", observed_metrics.get("http_request_count", 0)))
                if actual_requests < count and record["result"].get("status") in {"OK", "FAILED"}:
                    failures.append(f"http_requests<{count}")
                    record["result"]["status"] = "FAILED"
                if record["result"].get("stage") == "measurement" and not failures:
                    record["result"]["status"] = "OK"
                record["result"]["gate_failures"] = failures
                if record["result"].get("status") == "OK":
                    record["qualification"] = record["result"]["qualification"] = "preliminary"
                else:
                    record["qualification"] = record["result"]["qualification"] = "unconfirmed"
            previous_confirmation = [item for item in records.values() if item.get("configuration_hash") == candidate.hash
                                     and item.get("fidelity") == "confirmation" and item["result"].get("status") == "OK"]
            if fidelity == "confirmation" and record["result"].get("status") == "OK" and len(previous_confirmation) + 1 >= options["confirmation_windows"]:
                record["qualification"] = record["result"]["qualification"] = "confirmed_in_observed_windows"
            if fidelity == "quality" and candidate.hash in scheduler.confirmed:
                record["qualification"] = record["result"]["qualification"] = "confirmed_in_observed_windows"
            record = self.redactor(record)
            store.append(record)
            records[key] = record
            checkpoint.completed_keys.add(key)
            if record["result"].get("status") not in {"OK", "SKIPPED"}:
                checkpoint.failed += 1
                store.error(record)
            budget.observe(record)
            if fidelity == "screening" and record["result"].get("status") not in {"SKIPPED", "INVALID_CONFIG", "API_ERROR", "XRAY_ERROR"}:
                screened_pairs.update(_pair_features(candidate.values))
            scheduler.pending_trial = None
            persist()
            progress(configuration=record["configuration"], result=record["result"], qualification=record["qualification"])
            return record

        try:
            if not await reference():
                termination = "environment_unavailable"
            else:
                while not self.stop_requested:
                    if not scheduler.active and not any(item.hash not in scheduler.seen
                            for queue in (scheduler.frontier, scheduler.exploitation) for item in queue):
                        break
                    if not scheduler.active and not budget.permits(1, new_candidate=True,
                            response_bytes=measurement_policy.response_allowance(1)):
                        termination = "budget_exhausted"
                        break
                    next_candidate = scheduler.next()
                    if next_candidate is None:
                        break
                    candidate, selection = next_candidate
                    budget.used["candidates"] = len(scheduler.seen)
                    persist()
                    prior = [item for item in records.values() if item.get("configuration_hash") == candidate.hash]
                    screens = [item for item in prior if item.get("fidelity") == "screening"]
                    screen_ok = any(item["result"].get("status") == "OK" for item in screens)
                    while not screen_ok and len(screens) <= options["screening_retries"] and not self.stop_requested:
                        record = await trial(candidate, "screening", 1, selection if not screens else "uncertain_retry")
                        if record is None:
                            termination = "budget_exhausted"
                            break
                        screens.append(record)
                        screen_ok = record["result"].get("status") == "OK"
                        if record["result"].get("status") in {"INVALID_CONFIG", "SKIPPED", "API_ERROR", "XRAY_ERROR"}:
                            break
                    if termination == "budget_exhausted":
                        break
                    if (not screen_ok and screens and screens[-1]["result"].get("status") not in {
                            "INVALID_CONFIG", "SKIPPED", "API_ERROR", "XRAY_ERROR"} and
                            int(candidate.hash[:8], 16) % 1000 < float(options["negative_resample_fraction"]) * 1000):
                        record = await trial(candidate, "screening", 1, "screening_negative_resample")
                        screen_ok = record is not None and record["result"].get("status") == "OK"
                    if not screen_ok:
                        scheduler.finish()
                        persist()
                        if scheduler.selections % options["control_interval"] == 0 and not await reference():
                            termination = "environment_unavailable"
                            break
                        continue
                    if candidate.hash not in scheduler.viable:
                        scheduler.viable.append(candidate.hash)
                    comparisons = [item for item in prior if item.get("fidelity") == "comparison"]
                    compared = comparisons[-1] if comparisons else await trial(candidate, "comparison", options["comparison_requests"], "screening_passed")
                    if compared is None:
                        termination = "budget_exhausted"
                        break
                    if compared["result"].get("status") != "OK":
                        scheduler.finish()
                        persist()
                        continue
                    confirmations = [item for item in prior if item.get("fidelity") == "confirmation"]
                    if any(item["result"].get("status") != "OK" for item in confirmations):
                        scheduler.finish()
                        persist()
                        continue
                    for window in range(len(confirmations), options["confirmation_windows"]):
                        if self.stop_requested:
                            break
                        delay = float(options["window_delay_seconds"]) if window else 0
                        if delay:
                            end = time.monotonic() + min(delay, budget.remaining_time())
                            while time.monotonic() < end and not self.stop_requested:
                                await asyncio.sleep(min(.1, max(0, end - time.monotonic())))
                        confirmed = await trial(candidate, "confirmation", options["confirmation_requests"], f"confirmation_window_{window + 1}")
                        if confirmed is None:
                            termination = "budget_exhausted"
                            break
                        confirmations.append(confirmed)
                        if confirmed["result"].get("status") != "OK":
                            break
                    confirmed_ok = len(confirmations) >= options["confirmation_windows"] and all(item["result"].get("status") == "OK" for item in confirmations)
                    if confirmed_ok:
                        if candidate.hash not in scheduler.confirmed:
                            scheduler.confirmed.append(candidate.hash)
                        if len(scheduler.confirmed) <= options["speed_finalists"] and self.config.testing.get("speed_test", {}).get("enabled"):
                            prior_quality = [item for item in prior if item.get("fidelity") == "quality"]
                            if not prior_quality:
                                quality_requests = max(1, int(self.config.testing.get("quality_gates", {}).get("min_successful_requests", 1)))
                                await trial(candidate, "quality", quality_requests, "confirmed_finalist")
                        remaining_candidates = max(0, int(budget.limits["candidates"] - budget.used["candidates"]))
                        if remaining_candidates:
                            scheduler.add_neighbours((item for item, _ in self.generator.mutation_neighbors(candidate.values,
                                frozenset(name for name, value in candidate.values.items()
                                          if value != dict(self.generator.mutation_root()[0].values).get(name)),
                                limit=min(self.config.children_per_parent, remaining_candidates))),
                                min(self.config.children_per_parent, remaining_candidates))
                        if options["goal"] == "first_confirmed":
                            termination = "first_confirmed"
                            scheduler.finish()
                            persist()
                            break
                    scheduler.finish()
                    persist()
                    if termination == "budget_exhausted":
                        break
                    if scheduler.selections % options["control_interval"] == 0 and not await reference():
                        termination = "environment_unavailable"
                        break
        except TimeoutError:
            termination = "budget_exhausted"
        finally:
            if self.stop_requested:
                termination = "stopped"
            persist()
        return {"configurations_tested": len(scheduler.seen), "termination_reason": termination,
                "viable_candidates": len(scheduler.viable), "confirmed_candidates": len(scheduler.confirmed),
                "confirmed_configuration_hashes": scheduler.confirmed, "budget": budget.snapshot(),
                "coverage": coverage(), "environment": environment}

    async def _tcp_probe_is_trustworthy(self, host: str) -> bool:
        """False when a canary connect to a port nobody serves is accepted.

        A VPN/proxy client wrapping all local traffic — or a firewall that
        accepts and drops — answers TCP for every port, so `tcp_connect_ok`
        stops proving that the test port is reachable. A refused or filtered
        canary keeps the check meaningful.
        """
        if not host:
            return True
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, self.CANARY_PORT),
                                               timeout=self.CANARY_TIMEOUT)
        except (OSError, TimeoutError):
            return True
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return False

    def _warnings(self) -> list[str]:
        warnings = offline_warnings(self.config)
        if (state := self._config_validator.availability()) is not None:
            if self._config_validator.strict:
                warnings.append(f"Required local Xray validation is unavailable ({state}); the run cannot continue.")
            else:
                warnings.append(
                    f"The local Xray config check is unavailable ({state}); client configs are checked "
                    "structurally only and some candidates may still be rejected at Xray startup."
                )
        warnings.extend(self._reality_scan_rejected)
        warnings.extend(self._known_client_diagnostics.values())
        if self._tcp_probe_trustworthy is False:
            warnings.append(
                "TCP canary is inconclusive: another port accepted a connection. A VPN/proxy, firewall or real "
                "listener could explain this; tcp_connect_ok alone does not prove a working tunnel."
            )
        security_parameter = next((item for item in self.generator.parameters if item.name == "security"), None)
        reality_selected = (security_parameter is not None and (
            "reality" in (security_parameter.values or ()) or security_parameter.baseline == "reality"))
        reality_selected = reality_selected or stream_settings(getattr(self._manager, "source_snapshot", None) or {}).get("security") == "reality"
        if self._reality_profile_error and reality_selected:
            warnings = [item for item in warnings if not item.startswith("REALITY is selected")]
            warnings.append(f"REALITY candidates will be skipped: {self._reality_profile_error}.")
        return warnings

    def _builder(self, server_address: str) -> ClientConfigBuilder:
        return ClientConfigBuilder(server_address, int(self.config.testing.get("socks_port", 10808)),
                                   tls_server_name=self.config.testing.get("tls_server_name"),
                                   verify_peer_cert_by_name=self.config.testing.get("verify_peer_cert_by_name"),
                                   pinned_peer_cert_sha256=self.config.testing.get("pinned_peer_cert_sha256"))

    def _candidate_payload(self, values: dict[str, Any], base_payload: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
        try:
            payload = prepare_inbound_payload(
                apply_mapping(base_payload, values, self.generator.parameters), values,
            )
            if self.config.inbound.get("mode", "clone") == "clone" and payload.get("port") != base_payload.get("port"):
                return None, "clone_port_fixed"
            if callable(getattr(self._manager, "normalize_payload", None)):
                payload = self._manager.normalize_payload(payload)
            if stream_settings(payload).get("security", "none") == "reality":
                candidate = values.get("reality_profile")
                profile = profile_of(candidate) if isinstance(candidate, dict) else self._reality_profile
                if profile is None:
                    return None, self._reality_profile_error or "reality_target_or_sni_missing"
                if self._reality_credentials is None:
                    return None, "reality_credentials_missing"
                payload = prepare_reality_inbound(payload, profile, self._reality_credentials)
            return payload, None
        except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None, "inbound_mapping_invalid"

    def _config_reason(self, client_config: dict[str, Any]) -> str | None:
        """Reject a client config before Xray is asked to connect with it."""
        reason = check_client_config(client_config)
        if reason:
            return reason
        checked, core_reason = self._config_validator.check(client_config)
        if not checked and self._config_validator.strict:
            state = self._config_validator.availability()
            raise CoreValidationUnavailable(state or "xray_config_test_unchecked")
        return core_reason if checked else None

    def _candidate_error(self, values: dict[str, Any], base_payload: dict[str, Any], server_address: str) -> str | None:
        payload, reason = self._candidate_payload(values, base_payload)
        if reason:
            return reason
        assert payload is not None
        try:
            client_config = self._builder(server_address).build(values, self.generator.parameters, payload)
            if self._server_xray_version == "26.9.9":
                for item in kcp_noop_diagnostics(client_config):
                    self._known_client_diagnostics[item["code"]] = item["message"]
            if self.config.combination_strategy == "adaptive":
                tls = client_config.get("outbounds", [{}])[0].get("streamSettings", {}).get("tlsSettings", {})
                if tls.get("allowInsecure"):
                    return "diagnostic_insecure_tls_excluded"
                if tls.get("minVersion") in {"1.0", "1.1"}:
                    return "diagnostic_legacy_tls_excluded"
            reason = validate_pair(payload, client_config)
            if reason:
                return reason
            reason = self._config_reason(client_config)
            if reason:
                return reason
            if stream_settings(payload).get("security") == "reality" and self._reality_credentials:
                reality = stream_settings(payload).get("realitySettings", {})
                if isinstance(reality, str):
                    reality = json.loads(reality)
                client = client_config["outbounds"][0]["streamSettings"].get("realitySettings", {})
                if (reality.get("privateKey") != self._reality_credentials.private_key or
                        client.get("password") != self._reality_credentials.password):
                    return "reality_key_mismatch"
        except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            return "client_config_invalid"
        return None

    @staticmethod
    def _readback_error(expected: dict[str, Any], actual: dict[str, Any]) -> str | None:
        before, after = stream_settings(expected), stream_settings(actual)
        if effective_transport(before) != effective_transport(after):
            return "panel_readback_transport_mismatch"
        if before.get("security") != after.get("security"):
            return "panel_readback_transport_mismatch"
        if before.get("security") == "reality":
            left, right = before.get("realitySettings", {}), after.get("realitySettings", {})
            if isinstance(left, str):
                left = json.loads(left)
            if isinstance(right, str):
                right = json.loads(right)
            if (left.get("target") or left.get("dest")) != (right.get("target") or right.get("dest")):
                return "panel_readback_reality_mismatch"
            for key in ("serverNames", "privateKey", "shortIds"):
                if left.get(key) != right.get(key):
                    return "panel_readback_reality_mismatch"
        if effective_transport(before) == "xhttp":
            left, right = before.get("xhttpSettings", {}), after.get("xhttpSettings", {})
            if isinstance(left, str):
                left = json.loads(left)
            if isinstance(right, str):
                right = json.loads(right)
            for key, default in (("path", "/"), ("host", ""), ("mode", "auto")):
                if left.get(key, default) != right.get(key, default):
                    return "panel_readback_xhttp_mismatch"
        def decoded(value: Any) -> Any:
            if isinstance(value, str) and value.lstrip().startswith(("{", "[")):
                try:
                    return json.loads(value)
                except ValueError:
                    return value
            return value

        dynamic = {"up", "down", "total", "lastTime", "lastOnline", "created_at", "updated_at"}
        def matches(left: Any, right: Any) -> bool:
            left, right = decoded(left), decoded(right)
            if isinstance(left, dict):
                return isinstance(right, dict) and all(key in dynamic or (
                    key in right and matches(value, right[key]))
                    or (key not in right and dropped_empty(value)) for key, value in left.items())
            if isinstance(left, list):
                return isinstance(right, list) and len(left) == len(right) and all(
                    matches(a, b) for a, b in zip(left, right, strict=True))
            return left == right

        # Extra panel fields and runtime counters are allowed. All active
        # requested settings must survive; list order remains significant.
        # Go structs on the panel side (3x-ui model.Client and friends) marshal
        # with omitempty, so an explicitly sent empty value ("flow": "") comes
        # back as an absent key; that is the same configuration, not drift.
        def dropped_empty(value: Any) -> bool:
            return isinstance(value, (str, list, dict)) and not value

        active_network = str(effective_transport(before))
        network_key = {"tcp": "tcpSettings", "ws": "wsSettings", "grpc": "grpcSettings",
                       "kcp": "kcpSettings", "xhttp": "xhttpSettings", "httpupgrade": "httpupgradeSettings"}.get(active_network)
        transport_keys = {"tcpSettings", "wsSettings", "grpcSettings", "kcpSettings", "xhttpSettings", "httpupgradeSettings"}
        for key, value in before.items():
            if key in {"network", "method"}:
                # The panel may return a canonical spelling or the equivalent
                # network/method selector. Compare their effective meaning above.
                continue
            if key in transport_keys and key != network_key:
                continue
            if key in {"tlsSettings", "realitySettings"} and key != f"{before.get('security')}Settings":
                continue
            if key not in after or not matches(value, after[key]):
                return "panel_readback_settings_mismatch"
        for key in ("protocol", "port", "listen", "settings", "sniffing", "allocate"):
            if key in expected and (key not in actual or not matches(expected[key], actual[key])):
                return "panel_readback_settings_mismatch"
        return None

    def _public_values(self, values: dict[str, Any]) -> dict[str, Any]:
        return mask_parameter_values(values, self.generator.parameters)

    def _redact_result(self, value: Any) -> Any:
        if self._reality_credentials:
            self.redactor.add(self._reality_credentials.private_key).add(self._reality_credentials.password).add(self._reality_credentials.short_id)
        return self.redactor(value)

    def _skipped_record(self, number: int, combination: Combination, reason: str) -> dict[str, Any]:
        return {"test_id": number, "run": 1, "timestamp": datetime.now(UTC).isoformat(),
                "configuration_hash": combination.hash, "configuration": self._public_values(combination.values),
                "result": {"status": "SKIPPED", "stage": "validation", "reason_code": reason}}

    def _control_payload(self, base_payload: dict[str, Any], network: str, security: str) -> dict[str, Any]:
        payload = copy.deepcopy(base_payload)
        stream = stream_settings(payload)
        stream["network"], stream["security"] = network, security
        if network == "xhttp":
            stream["xhttpSettings"] = {"path": "/", "mode": "auto", "host": ""}
        payload["streamSettings"] = (json.dumps(stream, ensure_ascii=False, separators=(",", ":"))
                                     if isinstance(payload.get("streamSettings"), str) else stream)
        return payload

    async def _run_controls(self, manager: InboundManager, base_payload: dict[str, Any], server_address: str) -> None:
        source_stream = stream_settings(base_payload)
        profiles: list[tuple[str, dict[str, Any] | None]] = [
            ("tcp_tls", base_payload if source_stream.get("network", "tcp") == "tcp" and
             source_stream.get("security") == "tls" else None),
            ("tcp_reality", self._control_payload(base_payload, "tcp", "reality")),
            ("xhttp_reality", self._control_payload(base_payload, "xhttp", "reality")),
        ]
        path = self.config.output_dir / "diagnostics.jsonl"
        for name, payload in profiles:
            if self.stop_requested:
                break
            reason = "control_profile_unavailable" if payload is None else self._candidate_error({}, payload, server_address)
            if reason:
                diagnostic = {"timestamp": datetime.now(UTC).isoformat(), "profile": name,
                              "status": "SKIPPED", "reason_code": reason}
            else:
                assert payload is not None
                record = await self._one_run(0, 1, {}, configuration_hash({"control": name}), manager,
                                             payload, server_address, screening_only=True)
                result = record["result"]
                screen = result.get("screening", {})
                diagnostic = {"timestamp": record["timestamp"], "profile": name,
                              "status": result.get("status"), "stage": result.get("stage"),
                              "reason_code": result.get("reason_code"),
                              "tcp_connect_ok": screen.get("tcp_connect_ok"),
                              "success_rate": screen.get("success_rate"),
                              "client_xray_diagnostics": result.get("client_xray_diagnostics", []),
                              "server_xray_diagnostics": result.get("server_xray_diagnostics", []),
                              "server_xray_log_status": result.get("server_xray_log_status")}
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(mask_secrets(diagnostic), ensure_ascii=False, sort_keys=True) + "\n")

    async def _one_run(self, test_id: int, run_number: int, values: dict[str, Any], digest: str, manager: InboundManager,
                       base_payload: dict[str, Any], server_address: str, *, include_ping: bool = False,
                       screening_only: bool = False, fidelity: str | None = None,
                       requests: int | None = None, urls: list[Any] | None = None,
                       speed_bytes: int | None = None) -> dict[str, Any]:
        started = datetime.now(UTC).isoformat()
        started_clock = time.monotonic()
        applies_before, starts_before = self._api_applies, self._client_starts
        client_diagnostics: list[dict[str, str]] = []
        result: dict[str, Any]
        payload: dict[str, Any] | None = None
        client: XrayClient | None = None
        try:
            payload, reason = self._candidate_payload(values, base_payload)
            if reason or payload is None:
                raise CandidateValidationError(reason or "inbound_mapping_invalid")
            if callable(getattr(manager, "normalize_payload", None)):
                payload = manager.normalize_payload(payload)
            payload_hash = configuration_hash(payload)
            if payload_hash != self._last_inbound_payload_hash or self._active_inbound is None:
                self._api_applies += 1
                await manager.apply(payload)
                await asyncio.sleep(float(self.config.testing.get("config_apply_delay", 0)))
                self._active_inbound = await self.panel.get_inbound(manager.test_inbound_id or manager.source_id)
                self._last_inbound_payload_hash = payload_hash
            current = self._active_inbound
            readback_error = self._readback_error(payload, current)
            if readback_error:
                raise CandidateValidationError(readback_error)
            transport = str(effective_transport(stream_settings(current)))
            builder = self._builder(server_address)
            client_config = builder.build(values, self.generator.parameters, current)
            if self._server_xray_version == "26.9.9":
                client_diagnostics = kcp_noop_diagnostics(client_config)
            pair_error = validate_pair(current, client_config)
            if pair_error:
                raise CandidateValidationError(pair_error)
            # The readback config is the one that would be started: check it
            # here as well, so a rejected config is a validation result rather
            # than a failed connection attempt.
            config_error = self._config_reason(client_config)
            if config_error:
                raise CandidateValidationError(config_error)
            client = XrayClient(str(self.config.testing.get("xray_binary", "xray")), float(self.config.timeouts.get("xray_start", 15)),
                                config_directory=self.config.output_dir / ".xray-runtime")
            try:
                self._client_starts += 1
                await client.start(client_config)
                request_timeout = float(self.config.timeouts.get("request", 5))
                tcp_connect_timeout = float(self.config.timeouts.get("tcp_connect", min(request_timeout, 3)))
                probe_testing = copy.deepcopy(self.config.testing)
                if urls is not None:
                    probe_testing["urls"] = urls
                if requests is not None:
                    probe_testing["latency"] = {"requests": requests}
                    probe_testing["stability"] = {"requests": requests}
                if fidelity is not None:
                    # Speed belongs to every measured rung, not only to the
                    # finalist rung: the screening probe stays cheap, every other
                    # fidelity samples throughput when speed_test is enabled and
                    # the traffic budget paid for the sample (speed_bytes == 0
                    # means there was no room left).
                    probe_testing.setdefault("speed_test", {})["enabled"] = fidelity != "screening" and bool(
                        self.config.testing.get("speed_test", {}).get("enabled")) and speed_bytes != 0
                    if speed_bytes is not None and speed_bytes > 0:
                        probe_testing["speed_test"]["max_bytes"] = speed_bytes
                suite = MeasurementSuite(probe_testing, request_timeout, builder.socks_port,
                                         server_address, int(current["port"]), tcp_connect_timeout,
                                         transport=transport, stop_callback=lambda: self.stop_requested)
                screening = dict(self.config.testing.get("screening", {}))
                screening_metrics: dict[str, Any] | None = None
                if screening_only or (fidelity is None and screening.get("enabled", True)):
                    screening_timeout = float(self.config.timeouts.get("screening", 8))
                    screen_request_count = requests or (1 if screening_only else max(1, int(screening.get("requests", 1))))
                    try:
                        screening_metrics = await asyncio.wait_for(
                            suite.screen(screen_request_count),
                            timeout=screening_timeout,
                        )
                    except TimeoutError:
                        screening_metrics = {"successful_requests": 0, "failed_requests": 1,
                                             "success_rate": 0.0, "screening_timed_out": True,
                                             "http_request_count": screen_request_count,
                                             "http_bytes_received": suite.response_allowance(screen_request_count),
                                             "budget_accounting": "reserved_on_timeout"}
                    screen_ok, screen_failures = self._screening_gate(screening_metrics)
                    if not screen_ok:
                        result = {"status": "FAILED", "stage": "screening", "score": 0.0,
                                  "gate_failures": screen_failures, "screening": screening_metrics}
                        diagnostic = self._transport_diagnostic(transport, screening_metrics)
                        if diagnostic:
                            result["transport_diagnostic"] = diagnostic
                    elif screening_only:
                        result = {"status": "OK", "stage": "screening", "score": 1.0,
                                  "screening": screening_metrics}
                    else:
                        metrics = await suite.run(include_ping=include_ping)
                        ok, failures, score = self._quality_gate(metrics)
                        result = {"status": "OK" if ok else "FAILED", "stage": "measurement",
                                  "score": score, "gate_failures": failures,
                                  "screening": screening_metrics, **metrics}
                else:
                    metrics = await suite.run(include_ping=include_ping)
                    ok, failures, score = self._quality_gate(metrics)
                    result = {"status": "OK" if ok else "FAILED", "stage": "measurement",
                              "score": score, "gate_failures": failures, **metrics}
            finally:
                await client.stop()
        except CoreValidationUnavailable:
            raise
        except CandidateValidationError as error:
            result = {"status": "INVALID_CONFIG", "stage": "validation", "reason_code": error.reason_code}
        except PanelAPIError as error:
            result = {"status": "API_ERROR", "stage": "panel_api", "error_type": type(error).__name__, "error_message": str(error)}
        except (XrayClientError, FileNotFoundError, OSError) as error:
            result = {"status": "XRAY_ERROR", "stage": "xray_client", "error_type": type(error).__name__, "error_message": str(error)}
        except asyncio.TimeoutError as error:
            result = {"status": "TIMEOUT", "stage": "run", "error_type": type(error).__name__, "error_message": str(error)}
        except ValueError as error:
            result = {"status": "INVALID_CONFIG", "stage": "run", "error_type": type(error).__name__, "error_message": str(error)}
        except Exception as error:
            result = {"status": "FAILED", "stage": "run", "error_type": type(error).__name__, "error_message": str(error)}
        if result.get("status") != "OK":
            if client is not None:
                result["client_xray_diagnostics"] = client.diagnostic_categories()
                self._record_client_log(client.log_tail(), test_id, run_number, str(result.get("status")))
            try:
                server_log = await self.panel.xray_logs(count=20) if hasattr(self.panel, "xray_logs") else None
            except Exception:
                server_log = None
            result["server_xray_log_status"] = "available" if server_log else "unavailable"
            result["server_xray_diagnostics"] = categorize_xray_logs(server_log)
        result = self._redact_result(result)
        if client_diagnostics:
            result["diagnostics"] = self._redact_result(client_diagnostics)
        metrics = result.get("screening") or result
        result["http_requests"] = int(metrics.get("http_request_count",
            int(metrics.get("successful_requests", 0)) + int(metrics.get("failed_requests", 0)))) + int("download_bytes" in result)
        if metrics.get("budget_accounting"):
            result["budget_accounting"] = metrics["budget_accounting"]
        result["traffic_bytes"] = int(metrics.get("http_bytes_received", metrics.get("traffic_bytes", 0))) + int(
            result.get("download_received_bytes", result.get("download_bytes", 0)))
        if fidelity and "diagnosis" not in result:
            observations = metrics.get("observations", [])
            last_failure = next((item.get("reason_code") for item in reversed(observations)
                                 if not item.get("successful")), None)
            code = ("e2e_success" if result.get("status") == "OK" else result.get("reason_code") or
                    ("tcp_unreachable" if metrics.get("tcp_connect_supported", True) and metrics.get("tcp_connect_ok") is False
                     else "request_timeout" if metrics.get("screening_timed_out") else last_failure or "e2e_unconfirmed"))
            result["diagnosis"] = {"code": code, "certainty": "observed", "evidence": {
                "tcp_connect_ok": metrics.get("tcp_connect_ok"), "successful_requests": metrics.get("successful_requests", 0)},
                "alternative_causes": [] if result.get("status") == "OK" else ["topology", "endpoint", "tls_or_auth", "network_path"]}
        record = {"test_id": test_id, "run": run_number, "timestamp": started, "configuration_hash": digest,
                  "configuration": self._public_values(values), "result": result,
                  "duration_ms": round((time.monotonic() - started_clock) * 1000, 3),
                  "api_applies": self._api_applies - applies_before, "client_starts": self._client_starts - starts_before}
        if payload is not None:
            # The listener that was really applied, credential-free: the export
            # hands it back to the panel editor instead of keeping a second copy
            # of the panel state on disk.
            record["inbound_payload"] = mask_inbound_payload(payload)
        return record

    def _screening_gate(self, metrics: dict[str, Any]) -> tuple[bool, list[str]]:
        settings = dict(self.config.testing.get("screening", {}))
        failures: list[str] = []
        if (settings.get("require_tcp_connect", True)
                and metrics.get("tcp_connect_supported", True)
                and not metrics.get("tcp_connect_ok", False)):
            failures.append("tcp_connect")
        minimum = self._rate(settings.get("min_success_rate", 1.0), "screening.min_success_rate")
        if float(metrics.get("success_rate", 0.0)) < minimum:
            failures.append(f"success_rate<{minimum:g}")
        return not failures, failures

    @staticmethod
    def _transport_diagnostic(transport: str, metrics: dict[str, Any]) -> str | None:
        error_type = str(metrics.get("last_http_error", "")).partition(":")[0]
        if metrics.get("tcp_connect_supported", True) and metrics.get("tcp_connect_ok") is False:
            return ("TCP-соединение с портом тестовой копии не установлено. Проверьте listener Xray, "
                    "доступность порта в firewall и фактический маршрут до сервера. Это наблюдение "
                    "не позволяет отличить ошибку инфраструктуры от фильтрации сети.")
        if transport == "kcp" and error_type in {"ConnectTimeout", "ReadTimeout"}:
            return ("KCP/mKCP использует UDP; Xray не получил ответ. Проверьте доступность UDP-порта inbound "
                    "и совпадение kcpSettings на сервере и клиенте.")
        # TCP ok + a dead tunnel means the SYN was answered by something that is
        # not the panel's Xray: a VPN/proxy client wrapping all local traffic, a
        # firewall that accepts and drops, or a clone port nobody forwards.
        if metrics.get("tcp_connect_ok") and error_type in {"ConnectError", "ConnectTimeout", "ReadTimeout"}:
            return ("TCP-подключение к порту копии проходит, но туннель не поднимается. Проверьте, что порт "
                    "реально доступен, direct/proxy topology и локальный VPN. Успешный tcp_connect не определяет "
                    "причину HTTP-отказа: возможны TLS/auth, PROXY protocol, endpoint или фильтрация. "
                    "Дополнительные наблюдения доступны в client-xray.log.")
        return None

    def _record_client_log(self, tail: str, test_id: int, run_number: int, status: str) -> None:
        """Keep the masked Xray client log next to the results.

        `client_xray_diagnostics` is only a handful of stable codes; a failed
        handshake (TLS, PROXY protocol, XHTTP) is named only in the raw log.
        """
        if not tail.strip():
            return
        try:
            with (self.config.output_dir / "client-xray.log").open("a", encoding="utf-8") as handle:
                handle.write(f"# test_id={test_id} run={run_number} status={status}\n")
                handle.write(self.redactor.redact_text(mask_log_text(tail)))
                if not tail.endswith("\n"):
                    handle.write("\n")
        except OSError:
            # Diagnostics must never break the run that produced them.
            pass

    def _quality_gate(self, metrics: dict[str, Any]) -> tuple[bool, list[str], float]:
        settings = dict(self.config.testing.get("quality_gates", {}))
        failures: list[str] = []
        if (settings.get("require_tcp_connect", True)
                and metrics.get("tcp_connect_supported", True)
                and not metrics.get("tcp_connect_ok", False)):
            failures.append("tcp_connect")
        minimum_rate = self._rate(settings.get("min_success_rate", 1.0), "quality_gates.min_success_rate")
        success_rate = float(metrics.get("success_rate", 0.0))
        if success_rate < minimum_rate:
            failures.append(f"success_rate<{minimum_rate:g}")
        minimum_requests = max(1, int(settings.get("min_successful_requests", 1)))
        if int(metrics.get("successful_requests", 0)) < minimum_requests:
            failures.append(f"successful_requests<{minimum_requests}")
        maximum_p95 = float(settings.get("max_latency_p95_ms", 0) or 0)
        p95 = metrics.get("latency_p95_ms")
        if maximum_p95 > 0 and (p95 is None or float(p95) > maximum_p95):
            failures.append(f"latency_p95_ms>{maximum_p95:g}")
        minimum_speed = float(settings.get("min_download_mbps", 0) or 0)
        speed = metrics.get("download_mbps")
        if minimum_speed > 0 and (speed is None or float(speed) < minimum_speed):
            failures.append(f"download_mbps<{minimum_speed:g}")
        latency_score = 1.0 / (1.0 + float(p95 or 10_000) / 250.0)
        score = .75 * success_rate + .25 * latency_score
        if speed is not None:
            score = min(1.0, score * .9 + min(float(speed) / 100.0, 1.0) * .1)
        return not failures, failures, round(score, 6)

    @staticmethod
    def _rate(value: Any, name: str) -> float:
        rate = float(value)
        if not 0 <= rate <= 1:
            raise ValueError(f"testing.{name} must be between 0 and 1")
        return rate

    def _mutation_pool(self, parents: list[tuple[Combination, frozenset[str], float]],
                       tested: set[str], coverage: Counter[str],
                       children_per_parent: int | None, *, candidate_budget: int) -> list[SearchCandidate]:
        unique: dict[str, SearchCandidate] = {}
        remaining = max(0, candidate_budget)
        for parent, parent_changes, parent_score in parents:
            if remaining <= 0:
                break
            limit = remaining if children_per_parent is None else min(remaining, children_per_parent)
            neighbors = self.generator.mutation_neighbors(parent.values, parent_changes, limit=limit)
            remaining -= len(neighbors)
            candidates = [SearchCandidate(child, changes, changes - parent_changes, parent_score)
                          for child, changes in neighbors
                          if child.hash not in tested]
            if children_per_parent is not None:
                candidates = self._select_candidates(candidates, children_per_parent, coverage)
            for candidate in candidates:
                existing = unique.get(candidate.combination.hash)
                if existing is None or candidate.parent_score > existing.parent_score:
                    unique[candidate.combination.hash] = candidate
        return list(unique.values())

    @staticmethod
    def _select_candidates(candidates: list[SearchCandidate], limit: int,
                           coverage: Counter[str]) -> list[SearchCandidate]:
        pending = list(candidates)
        selected: list[SearchCandidate] = []
        planned = Counter(coverage)
        while pending and len(selected) < limit:
            candidate = min(
                pending,
                key=lambda item: (
                    sum(planned[name] for name in item.new_changes),
                    -item.parent_score,
                    item.combination.hash,
                ),
            )
            pending.remove(candidate)
            selected.append(candidate)
            planned.update(candidate.new_changes)
        return selected

    @staticmethod
    def _select_beam(nodes: list[tuple[Combination, frozenset[str], float]],
                     width: int) -> list[tuple[Combination, frozenset[str], float]]:
        pending = list(nodes)
        selected: list[tuple[Combination, frozenset[str], float]] = []
        while pending and len(selected) < width:
            def utility(node: tuple[Combination, frozenset[str], float]) -> tuple[float, str]:
                if not selected:
                    diversity = 1.0
                else:
                    distances = []
                    for _, existing, _ in selected:
                        union = node[1] | existing
                        distances.append(1.0 - len(node[1] & existing) / len(union) if union else 0.0)
                    diversity = min(distances)
                return node[2] + .1 * diversity, node[0].hash
            best = max(pending, key=utility)
            pending.remove(best)
            selected.append(best)
        return selected

    def _payload_hash(self, base_payload: dict[str, Any], values: dict[str, Any]) -> str:
        return configuration_hash({"inbound": apply_mapping(base_payload, values, self.generator.parameters),
                                   "reality_profile": values.get("reality_profile")})

    def _search_signature(self) -> str:
        parameters = [{"name": item.name, "target": item.target, "path": list(item.path),
                       "values": list(item.iter_values()), "conditions": item.conditions,
                       "value_conditions": list(item.value_conditions), "baseline": item.baseline,
                       "baseline_defined": item.baseline_defined, "mutate": item.mutate}
                      for item in self.generator.parameters]
        # `max_combinations` (the candidate budget) and CONTINUATION_BUDGET_KEYS
        # stay out: an exhausted run is continued with a larger budget in the
        # same checkpoint, and only the budget may differ on such a resume.
        testing = {key: self.config.testing.get(key) for key in (
            "combination_strategy", "mutation_generations", "beam_width", "children_per_parent",
            "runs_per_combination", "max_failed_runs", "screening", "quality_gates", "confirmation_urls",
        )}
        testing["adaptive"] = {key: value for key, value in self.config.adaptive.items()
                               if key not in CONTINUATION_BUDGET_KEYS}
        testing["topology"] = self.config.topology
        if "reality" in self.config.testing:
            testing["reality"] = self.config.testing["reality"]
            testing["resolved_candidates"] = configured_candidates(self.config.testing, self.config.source_path)
            testing["usable_candidates"] = self._usable_candidates
        if self._reality_profile:
            testing["resolved_reality"] = {"target": self._reality_profile.target,
                                           "server_names": self._reality_profile.server_names}
        return configuration_hash({"parameters": parameters, "testing": testing})
