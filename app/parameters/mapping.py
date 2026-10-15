from __future__ import annotations

import copy
import json
from typing import Any, Sequence

from app.parameters.dependencies import conditions_match
from app.parameters.models import ParameterSpec, validate_active_parameter_paths


def apply_mapping(source: dict[str, Any], values: dict[str, Any], parameters: Sequence[ParameterSpec], target_name: str = "inbound") -> dict[str, Any]:
    """Copy an inbound payload and apply only declared paths of active parameters."""
    by_name = {parameter.name: parameter for parameter in parameters}
    active_specs = [
        parameter for parameter in parameters
        if parameter.target == target_name and parameter.path and parameter.name in values
        and conditions_match(parameter.conditions, values, parameters)
    ]
    validate_active_parameter_paths(values, active_specs)
    payload = copy.deepcopy(source)
    serialized_containers: list[tuple[dict[str, Any], str]] = []
    for name, value in values.items():
        spec = by_name[name]
        if not spec.path or spec.target != target_name:
            continue
        if not conditions_match(spec.conditions, values, parameters):
            continue
        target: Any = payload
        for part in spec.path[:-1]:
            if isinstance(part, int):
                if not isinstance(target, list):
                    raise ValueError(f"Parameter {name}: path expects a list at index {part}")
                while len(target) <= part:
                    target.append({})
                target = target[part]
            else:
                if not isinstance(target, dict):
                    raise ValueError(f"Parameter {name}: path expects an object at {part!r}")
                current = target.get(part)
                if isinstance(current, str):
                    try:
                        decoded = json.loads(current)
                    except json.JSONDecodeError as error:
                        raise ValueError(f"Parameter {name}: path component {part!r} is not JSON") from error
                    if not isinstance(decoded, (dict, list)):
                        raise ValueError(f"Parameter {name}: path component {part!r} must contain JSON object or list")
                    target[part] = decoded
                    serialized_containers.append((target, part))
                target = target.setdefault(part, {})
        if not spec.path:
            continue
        last = spec.path[-1]
        if isinstance(last, int):
            while len(target) <= last:
                target.append(None)
            target[last] = value
        else:
            target[last] = value
    # 3x-ui represents several nested inbound sections as JSON strings. Preserve
    # the representation returned by the panel after applying nested mutations.
    for container, key in reversed(serialized_containers):
        container[key] = json.dumps(container[key], ensure_ascii=False, separators=(",", ":"))
    return payload
