from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.parameters.models import ParameterSpec
from app.xray.reality import configured_candidates

_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV.sub(lambda match: os.environ.get(match.group(1), match.group(0)), value)
    if isinstance(value, list):
        return [_expand_env(item) for item in value]
    if isinstance(value, dict):
        return {key: _expand_env(item) for key, item in value.items()}
    return value


@dataclass(frozen=True)
class ExperimentConfig:
    panel: dict[str, Any]
    inbound: dict[str, Any]
    parameters: tuple[ParameterSpec, ...]
    testing: dict[str, Any] = field(default_factory=dict)
    timeouts: dict[str, Any] = field(default_factory=dict)
    output: dict[str, Any] = field(default_factory=dict)
    source_path: Path | None = None

    def search_parameters(self, candidates: list[dict[str, str]] | None = None) -> tuple[ParameterSpec, ...]:
        profiles = configured_candidates(self.testing, self.source_path) if candidates is None else candidates
        if not profiles:
            return self.parameters
        security = next((item for item in self.parameters if item.target == "inbound" and
                         item.path == ("streamSettings", "security")), None)
        if security is None or "reality" not in tuple(security.iter_values()):
            raise ValueError("REALITY candidates require a security parameter containing reality")
        if any(item.name == "reality_profile" for item in self.parameters):
            raise ValueError("reality_profile is reserved for the REALITY target list")
        identity = {"serverName", "shortId", "password", "publicKey"}
        conflicting = [item.name for item in self.parameters if item.target == "client" and item.path[:4] ==
                       ("outbounds", 0, "streamSettings", "realitySettings") and
                       item.path[-1:] and item.path[-1] in identity]
        if conflicting:
            raise ValueError("REALITY target lists control client identity; remove separate SNI/key parameters: "
                             + ", ".join(sorted(conflicting)))
        profile = ParameterSpec.from_dict("reality_profile", {
            "type": "enum", "values": profiles, "target": "context", "path": [],
            "conditions": {security.name: {"equals": "reality"}},
        })
        return (*self.parameters, profile)

    @property
    def has_reality_candidates(self) -> bool:
        """True when REALITY targets come from a list instead of one target/server_names pair."""
        reality = self.testing.get("reality")
        if not isinstance(reality, dict):
            return False
        return bool(reality.get("candidates") or reality.get("candidates_file"))

    @property
    def output_dir(self) -> Path:
        return Path(self.output.get("directory", "./results"))

    @property
    def runs_per_combination(self) -> int:
        value = int(self.testing.get("runs_per_combination", 1))
        if value < 1:
            raise ValueError("testing.runs_per_combination must be at least 1")
        return value

    @property
    def max_failed_runs(self) -> int:
        """Maximum failed attempts for one configuration before it is abandoned."""
        value = int(self.testing.get("max_failed_runs", 1))
        if value < 1:
            raise ValueError("testing.max_failed_runs must be at least 1")
        return value

    @property
    def beam_width(self) -> int:
        value = int(self.testing.get("beam_width", 8))
        if value < 1:
            raise ValueError("testing.beam_width must be at least 1")
        return value

    @property
    def children_per_parent(self) -> int:
        value = int(self.testing.get("children_per_parent", 8))
        if value < 1:
            raise ValueError("testing.children_per_parent must be at least 1")
        return value

    @property
    def two_stage(self) -> dict[str, Any]:
        value = self.testing.get("two_stage", {})
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ValueError("testing.two_stage must be an object")
        return value

    @property
    def two_stage_enabled(self) -> bool:
        return bool(self.two_stage.get("enabled", False))

    @property
    def validation_top_k(self) -> int:
        value = int(self.two_stage.get("top_k", 20))
        if value < 1:
            raise ValueError("testing.two_stage.top_k must be at least 1")
        return value

    @property
    def validation_runs(self) -> int:
        value = int(self.two_stage.get("validation_runs", 5))
        if value < 1:
            raise ValueError("testing.two_stage.validation_runs must be at least 1")
        return value

    def maximum_run_count(self, search_configurations: int) -> int:
        validation = self.validation_top_k * self.validation_runs if self.two_stage_enabled else 0
        return search_configurations * self.runs_per_combination + validation

    @property
    def api_timeout(self) -> float:
        return float(self.timeouts.get("api", 10))

    @property
    def combination_strategy(self) -> str:
        strategy = str(self.testing.get("combination_strategy", "pairwise"))
        if strategy not in {"mutation", "pairwise", "exhaustive"}:
            raise ValueError("testing.combination_strategy must be mutation, pairwise or exhaustive")
        return strategy

    @property
    def max_combinations(self) -> int:
        value = int(self.testing.get("max_combinations", 500))
        if value < 1:
            raise ValueError("testing.max_combinations must be at least 1")
        return value

    @property
    def mutation_generations(self) -> int:
        value = int(self.testing.get("mutation_generations", 2))
        if value < 1:
            raise ValueError("testing.mutation_generations must be at least 1")
        return value


def load_config(path: Path) -> ExperimentConfig:
    raw = _expand_env(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
    for section in ("panel", "inbound", "parameters"):
        if section not in raw:
            raise ValueError(f"Missing required configuration section: {section}")
    params = tuple(ParameterSpec.from_dict(name, definition) for name, definition in raw["parameters"].items())
    names = [parameter.name for parameter in params]
    if len(names) != len(set(names)):
        raise ValueError("Parameter names must be unique")
    config = ExperimentConfig(
        panel=raw["panel"], inbound=raw["inbound"], parameters=params,
        testing=raw.get("testing", {}), timeouts=raw.get("timeouts", {}),
        output=raw.get("output", {}), source_path=path.resolve(),
    )
    config.search_parameters()
    return config


REALITY_CANDIDATES_UNCHECKED_WARNING = (
    "REALITY targets are structurally valid but have not been checked from the panel server"
)


def offline_warnings(config: ExperimentConfig) -> list[str]:
    """Warn about YAML-only issues without assuming access to the source inbound."""
    warnings: list[str] = []
    reality_selected = any(
        parameter.target == "inbound"
        and parameter.path == ("streamSettings", "security")
        and ("reality" in tuple(parameter.iter_values())
             or parameter.baseline_defined and parameter.baseline == "reality")
        for parameter in config.parameters
    )
    if reality_selected:
        reality = config.testing.get("reality", {})
        if not isinstance(reality, dict) or not (reality.get("target") and reality.get("server_names")
                                                  or reality.get("candidates") or reality.get("candidates_file")):
            warnings.append(
                "REALITY is selected, but testing.reality.target/server_names are incomplete; "
                "candidates may be skipped if the source inbound has no REALITY settings."
            )
    request_timeout = float(config.timeouts.get("request", 5))
    connect_timeout = float(config.timeouts.get("tcp_connect", min(request_timeout, 3)))
    screening_timeout = float(config.timeouts.get("screening", 8))
    requests = max(1, int((config.testing.get("screening") or {}).get("requests", 1)))
    if screening_timeout <= connect_timeout + requests * request_timeout:
        warnings.append("Screening timeout may be too short for TCP connect plus HTTP requests.")
    if config.max_failed_runs < config.runs_per_combination:
        warnings.append("max_failed_runs may stop a candidate before all planned repeats finish.")
    return warnings
