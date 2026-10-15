from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
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

    def __hash__(self) -> int:
        # values/conditions hold unhashable lists and dicts, so the field-wide
        # dataclass hash is unavailable. Equal instances always share name and
        # path, and hash collisions between distinct specs are legal.
        return hash((self.name, self.path))

    @classmethod
    def from_dict(cls, name: str, data: dict[str, Any]) -> "ParameterSpec":
        kind = data.get("type")
        if kind not in {"enum", "integer", "float", "boolean", "string"}:
            raise ValueError(f"Parameter {name}: unsupported type {kind!r}")
        values = data.get("values")
        target = data.get("target", "inbound")
        if target not in {"inbound", "client", "context"}:
            raise ValueError(f"Parameter {name}: target must be inbound, client or context")
        path = _parse_path(data.get("path"))
        numeric_range = any(key in data for key in ("min", "max", "step"))
        if values is None and not numeric_range:
            raise ValueError(f"Parameter {name}: values or min/max/step is required")
        if numeric_range:
            if kind not in {"integer", "float"} or not all(key in data for key in ("min", "max", "step")):
                raise ValueError(f"Parameter {name}: a complete numeric range is required")
            try:
                low, high, step = map(lambda key: Decimal(str(data[key])), ("min", "max", "step"))
            except (InvalidOperation, TypeError, ValueError) as error:
                raise ValueError(f"Parameter {name}: invalid numeric range") from error
            if not all(value.is_finite() for value in (low, high, step)):
                raise ValueError(f"Parameter {name}: numeric range values must be finite")
            if step <= 0 or low > high:
                raise ValueError(f"Parameter {name}: invalid numeric range")
            if kind == "integer" and any(value != value.to_integral_value() for value in (low, high, step)):
                raise ValueError(f"Parameter {name}: integer range min, max and step must be integers")
            if kind == "float":
                float_low, float_high, float_step = (float(value) for value in (low, high, step))
                if not all(math.isfinite(value) for value in (float_low, float_high, float_step)):
                    raise ValueError(f"Parameter {name}: float range values must be representable as finite floats")
                if low < high and (float(low + step) <= float_low or float(high - step) >= float_high):
                    raise ValueError(f"Parameter {name}: float range step does not advance representable values")
            baseline, baseline_defined = _parse_baseline(name, kind, data)
            return cls(name, kind, None, low, high, step, path, target,
                       data.get("conditions"), _parse_value_conditions(name, data.get("value_conditions")),
                       baseline, baseline_defined, bool(data.get("mutate", True)))
        if not isinstance(values, list) or not values:
            raise ValueError(f"Parameter {name}: values must be a non-empty list")
        cls._validate_values(name, kind, values)
        baseline, baseline_defined = _parse_baseline(name, kind, data)
        return cls(name, kind, tuple(values), path=path, target=target,
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
        if kind == "float":
            for value in values:
                try:
                    finite = math.isfinite(float(value))
                except (OverflowError, TypeError, ValueError):
                    finite = False
                if not finite:
                    raise ValueError(f"Parameter {name}: float values must be finite")
        elif kind == "enum" and any(_contains_nonfinite_float(value) for value in values):
            raise ValueError(f"Parameter {name}: enum values must not contain non-finite numbers")

    def iter_values(self) -> Iterator[Any]:
        if self.values is not None:
            yield from self.values
            return
        assert self.minimum is not None and self.maximum is not None and self.step is not None
        if self.type == "integer":
            # Decimal addition is subject to the active precision context. For
            # large integer bounds it can round away a step and loop forever.
            current, maximum, step = int(self.minimum), int(self.maximum), int(self.step)
            while current <= maximum:
                yield current
                current += step
            return
        current = self.minimum
        while current <= self.maximum:
            yield float(current)
            current += self.step

    def count_values(self) -> int:
        if self.values is not None:
            return len(self.values)
        assert self.minimum is not None and self.maximum is not None and self.step is not None
        if self.type == "integer":
            return (int(self.maximum) - int(self.minimum)) // int(self.step) + 1
        return int((self.maximum - self.minimum) / self.step) + 1

    def conditions_for_value(self, value: Any) -> dict[str, Any] | None:
        key = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return dict(self.value_conditions).get(key)


def _parse_path(value: Any) -> tuple[str | int, ...]:
    if value is None:
        return ()
    if (not isinstance(value, list) or
            not all(isinstance(item, str) or
                    (isinstance(item, int) and not isinstance(item, bool) and item >= 0)
                    for item in value)):
        raise ValueError("path must be a list of string/int components")
    return tuple(value)


def _contains_nonfinite_float(value: Any) -> bool:
    if isinstance(value, float):
        return not math.isfinite(value)
    if isinstance(value, list):
        return any(_contains_nonfinite_float(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_nonfinite_float(key) or _contains_nonfinite_float(item)
                   for key, item in value.items())
    return False


def validate_active_parameter_paths(values: Mapping[str, Any], specs: Sequence[ParameterSpec]) -> None:
    """Reject active JSON-path writes that overlap within one payload target.

    A spec participates only when its name is present in `values`; callers that
    pass an unnormalized assignment must prefilter `specs` by their conditions.
    Client/server/context roots are independent.
    Exact duplicates are rejected too, even when they currently carry equal
    values, so mapping behavior cannot depend on insertion order.
    """
    roots: dict[str, dict[Any, Any]] = {}
    terminal = object()
    descendant = object()
    active_transport_fields: dict[str, dict[str, str]] = {}
    for parameter in specs:
        if parameter.name in values and parameter.path and parameter.target != "context":
            # Xray gives `method` precedence over `network`; allowing two
            # active custom writers would make the user-selected network
            # silently ineffective even though the JSON paths do not overlap.
            path = parameter.path
            if (len(path) >= 2 and path[-2] == "streamSettings"
                    and path[-1] in {"network", "method"}
                    and (parameter.target == "inbound" or
                         (parameter.target == "client" and path[:2] == ("outbounds", 0)))):
                fields = active_transport_fields.setdefault(parameter.target, {})
                other = "method" if path[-1] == "network" else "network"
                if other in fields:
                    raise ValueError(
                        f"Active parameters {fields[other]!r} and {parameter.name!r} conflict: "
                        f"active_transport_method_conflict for target {parameter.target!r}"
                    )
                fields[path[-1]] = parameter.name
            node = roots.setdefault(parameter.target, {})
            ancestors: list[dict[Any, Any]] = []
            for part in parameter.path:
                ancestor = node.get(terminal)
                if ancestor is not None:
                    raise ValueError(
                        f"Active parameters {ancestor!r} and {parameter.name!r} have overlapping "
                        f"paths for target {parameter.target!r}"
                    )
                ancestors.append(node)
                node = node.setdefault(part, {})
            existing = node.get(terminal)
            if existing is not None:
                raise ValueError(
                    f"Active parameters {existing!r} and {parameter.name!r} have overlapping "
                    f"paths for target {parameter.target!r}"
                )
            existing_descendant = node.get(descendant)
            if existing_descendant is not None:
                raise ValueError(
                    f"Active parameters {parameter.name!r} and {existing_descendant!r} have overlapping "
                    f"paths for target {parameter.target!r}"
                )
            node[terminal] = parameter.name
            node[descendant] = parameter.name
            for ancestor_node in ancestors:
                ancestor_node.setdefault(descendant, parameter.name)


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
