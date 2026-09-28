from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Iterator, Literal

import json

ParameterType = Literal["enum", "integer", "float", "boolean", "string"]


@dataclass(frozen=True)
class ParameterSpec:
    name: str
    type: ParameterType
    values: tuple[Any, ...] | None = None
    minimum: Decimal | None = None
    maximum: Decimal | None = None
    step: Decimal | None = None
    path: tuple[str | int, ...] = ()
    target: str = "inbound"
    conditions: dict[str, Any] | None = None
    value_conditions: tuple[tuple[str, dict[str, Any]], ...] = ()
    baseline: Any = None
    baseline_defined: bool = False
    mutate: bool = True

    @classmethod
    def from_dict(cls, name: str, data: dict[str, Any]) -> "ParameterSpec":
        kind = data.get("type")
        if kind not in {"enum", "integer", "float", "boolean", "string"}:
            raise ValueError(f"Parameter {name}: unsupported type {kind!r}")
        values = data.get("values")
        target = data.get("target", "inbound")
        if target not in {"inbound", "client", "context"}:
            raise ValueError(f"Parameter {name}: target must be inbound, client or context")
        numeric_range = any(key in data for key in ("min", "max", "step"))
        if values is None and not numeric_range:
            raise ValueError(f"Parameter {name}: values or min/max/step is required")
        if numeric_range:
            if kind not in {"integer", "float"} or not all(key in data for key in ("min", "max", "step")):
                raise ValueError(f"Parameter {name}: a complete numeric range is required")
            low, high, step = map(lambda key: Decimal(str(data[key])), ("min", "max", "step"))
            if step <= 0 or low > high:
                raise ValueError(f"Parameter {name}: invalid numeric range")
            baseline, baseline_defined = _parse_baseline(name, kind, data)
            return cls(name, kind, None, low, high, step, _parse_path(data.get("path")), target,
                       data.get("conditions"), _parse_value_conditions(name, data.get("value_conditions")),
                       baseline, baseline_defined, bool(data.get("mutate", True)))
        if not isinstance(values, list) or not values:
            raise ValueError(f"Parameter {name}: values must be a non-empty list")
        cls._validate_values(name, kind, values)
        baseline, baseline_defined = _parse_baseline(name, kind, data)
        return cls(name, kind, tuple(values), path=_parse_path(data.get("path")), target=target,
                   conditions=data.get("conditions"),
                   value_conditions=_parse_value_conditions(name, data.get("value_conditions")),
                   baseline=baseline, baseline_defined=baseline_defined, mutate=bool(data.get("mutate", True)))

    @staticmethod
    def _validate_values(name: str, kind: str, values: list[Any]) -> None:
        checker = {"integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
                   "float": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
                   "boolean": lambda v: isinstance(v, bool),
                   # Enum choices may be structured JSON values. Xray uses these for
                   # fields such as TLS ALPN and sniffing.destOverride.
                   "enum": lambda v: v is None or isinstance(v, (str, int, float, bool, list, dict)),
                   "string": lambda v: isinstance(v, str)}[kind]
        if not all(checker(value) for value in values):
            raise ValueError(f"Parameter {name}: invalid value for type {kind}")

    def iter_values(self) -> Iterator[Any]:
        if self.values is not None:
            yield from self.values
            return
        assert self.minimum is not None and self.maximum is not None and self.step is not None
        current = self.minimum
        while current <= self.maximum:
            yield int(current) if self.type == "integer" else float(current)
            current += self.step

    def count_values(self) -> int:
        return len(self.values) if self.values is not None else int((self.maximum - self.minimum) / self.step) + 1  # type: ignore[operator]

    def conditions_for_value(self, value: Any) -> dict[str, Any] | None:
        key = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return dict(self.value_conditions).get(key)


def _parse_path(value: Any) -> tuple[str | int, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, (str, int)) for item in value):
        raise ValueError("path must be a list of string/int components")
    return tuple(value)


def _parse_value_conditions(name: str, value: Any) -> tuple[tuple[str, dict[str, Any]], ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError(f"Parameter {name}: value_conditions must be a list")
    parsed: list[tuple[str, dict[str, Any]]] = []
    for item in value:
        if not isinstance(item, dict) or "value" not in item or not isinstance(item.get("conditions"), dict):
            raise ValueError(f"Parameter {name}: invalid value_conditions item")
        key = json.dumps(item["value"], ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        parsed.append((key, item["conditions"]))
    return tuple(parsed)


def _parse_baseline(name: str, kind: str, data: dict[str, Any]) -> tuple[Any, bool]:
    if "baseline" not in data:
        return None, False
    value = data["baseline"]
    ParameterSpec._validate_values(name, kind, [value])
    return value, True
