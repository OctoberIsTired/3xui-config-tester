from __future__ import annotations

from functools import lru_cache
from typing import Any, Sequence

from app.xray.transports import normalize_transport

_SEMANTIC_TRANSPORT_PATHS = {
    ("streamSettings", "network"), ("streamSettings", "method"),
    ("outbounds", 0, "streamSettings", "network"),
    ("outbounds", 0, "streamSettings", "method"),
}


def _scan_semantic_transport_names(specs: Sequence[Any]) -> frozenset[str]:
    names: set[str] = set()
    for spec in specs:
        path = tuple(getattr(spec, "path", ()))
        name = getattr(spec, "name", None)
        if name and len(path) >= 2 and path[-1] in {"network", "method"} and path[-2] == "streamSettings" \
                and path in _SEMANTIC_TRANSPORT_PATHS:
            names.add(name)
    return frozenset(names)


@lru_cache(maxsize=None)
def _cached_semantic_transport_names(specs: tuple[Any, ...]) -> frozenset[str]:
    # Parameters rarely change their paths: hashing the tuple lets every later
    # predicate evaluation answer with a set lookup instead of a linear scan
    # over all specs (the former hot loop of plan construction).
    return _scan_semantic_transport_names(specs)


def semantic_transport_names(specs: Sequence[Any] | None) -> frozenset[str]:
    """Names whose values compare through transport normalization."""
    if not specs:
        return frozenset()
    if isinstance(specs, tuple):
        return _cached_semantic_transport_names(specs)
    try:
        return _cached_semantic_transport_names(tuple(specs))
    except TypeError:  # unhashable specs container: fall back to a direct scan
        return _scan_semantic_transport_names(specs)


def condition_state(rule: dict[str, Any] | None, values: dict[str, Any],
                    pending: set[str] | frozenset[str], specs: Sequence[Any] | None = None,
                    transport_names: frozenset[str] | None = None) -> bool | None:
    """Evaluate partial assignments: None means a dependency is still undecided.

    A missing name outside ``pending`` is genuinely absent, which matters for
    ``exists: false``. An unassigned configured name must never be treated as an
    absent one during pruning.
    """
    if not rule:
        return True
    if "all" in rule or "any" in rule:
        operator = "all" if "all" in rule else "any"
        _require_list(rule[operator], operator)
        states = [condition_state(item, values, pending, specs, transport_names) for item in rule[operator]]
        if operator == "all":
            return False if False in states else (None if None in states else True)
        return True if True in states else (None if None in states else False)
    if "parameter" in rule:
        name = rule["parameter"]
        predicates = {key: value for key, value in rule.items() if key != "parameter"}
        return None if name in pending else _predicates(name, predicates, values, specs, transport_names)
    states = [None if name in pending else _predicates(
        name, predicates if isinstance(predicates, dict) else {"equals": predicates}, values, specs, transport_names)
        for name, predicates in rule.items()]
    return False if False in states else (None if None in states else True)


def dependency_names(rule: dict[str, Any] | None) -> set[str]:
    """Names read by a rule, including every branch of all/any."""
    if not rule:
        return set()
    if "all" in rule or "any" in rule:
        operator = "all" if "all" in rule else "any"
        _require_list(rule[operator], operator)
        return set().union(*(dependency_names(item) for item in rule[operator]))
    return {rule["parameter"]} if "parameter" in rule else set(rule)


def conditions_match(rule: dict[str, Any] | None, values: dict[str, Any],
                     specs: Sequence[Any] | None = None,
                     transport_names: frozenset[str] | None = None) -> bool:
    """Evaluate the declarative subset: equals, not_equals, in, not_in, exists, all, any."""
    if not rule:
        return True
    if "all" in rule:
        _require_list(rule["all"], "all")
        return all(conditions_match(item, values, specs, transport_names) for item in rule["all"])
    if "any" in rule:
        _require_list(rule["any"], "any")
        return any(conditions_match(item, values, specs, transport_names) for item in rule["any"])
    if "parameter" in rule:
        parameter = rule["parameter"]
        predicates = {key: value for key, value in rule.items() if key != "parameter"}
        return _predicates(parameter, predicates, values, specs, transport_names)
    # Shorthand: {network: {equals: ws}, security: {in: [tls, reality]}}
    return all(_predicates(name, predicates if isinstance(predicates, dict) else {"equals": predicates}, values, specs, transport_names)
               for name, predicates in rule.items())


def _require_list(value: Any, name: str) -> None:
    if not isinstance(value, list):
        raise ValueError(f"Dependency {name} must be a list")


def _predicates(name: str, predicates: dict[str, Any], values: dict[str, Any],
                specs: Sequence[Any] | None = None,
                transport_names: frozenset[str] | None = None) -> bool:
    actual = values.get(name)
    exists = name in values and actual is not None
    names = transport_names if transport_names is not None else semantic_transport_names(specs)
    semantic_transport = name in names
    if semantic_transport:
        actual = normalize_transport(actual)

    def expected_value(value: Any) -> Any:
        return normalize_transport(value) if semantic_transport else value

    for operator, expected in predicates.items():
        if operator == "equals" and actual != expected_value(expected):
            return False
        if operator == "not_equals" and actual == expected_value(expected):
            return False
        if operator == "in" and (not isinstance(expected, list) or actual not in [expected_value(item) for item in expected]):
            return False
        if operator == "not_in" and (not isinstance(expected, list) or actual in [expected_value(item) for item in expected]):
            return False
        if operator == "exists" and exists != bool(expected):
            return False
        if operator not in {"equals", "not_equals", "in", "not_in", "exists"}:
            raise ValueError(f"Unsupported dependency operator: {operator}")
    return True
