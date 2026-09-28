from __future__ import annotations

import hashlib
import itertools
import json
from dataclasses import dataclass
from typing import Any, Iterator, Sequence

from app.parameters.dependencies import conditions_match
from app.parameters.compatibility import compatible
from app.parameters.models import ParameterSpec


def configuration_hash(configuration: dict[str, Any]) -> str:
    canonical = json.dumps(configuration, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Combination:
    values: dict[str, Any]

    @property
    def hash(self) -> str:
        return configuration_hash(self.values)


class CombinationGenerator:
    def __init__(self, parameters: Sequence[ParameterSpec], *, protocol: str | None = None,
                 source_stream: dict[str, Any] | None = None):
        self.parameters = tuple(parameters)
        self.protocol = protocol
        self.source_stream = source_stream

    @property
    def raw_count(self) -> int:
        result = 1
        for parameter in self.parameters:
            result *= parameter.count_values()
        return result

    def iter_valid(self) -> Iterator[Combination]:
        """Lazy Cartesian product; inactive conditional parameters are removed and deduplicated."""
        seen: set[str] = set()
        domains = (parameter.iter_values() for parameter in self.parameters)
        for candidate_values in itertools.product(*domains):
            full = dict(zip((parameter.name for parameter in self.parameters), candidate_values, strict=True))
            combination = self._normalize(full)
            if combination and combination.hash not in seen:
                seen.add(combination.hash)
                yield combination

    def pairwise(self) -> list[Combination]:
        """Return a deterministic all-pairs covering set without expanding the full product.

        IPOG-style horizontal/vertical growth covers every pair in the raw domains.
        A repair pass then restores feasible pairs lost to conditional parameters or
        per-value compatibility rules.
        """
        if not self.parameters:
            return [Combination({})]
        domains = [list(parameter.iter_values()) for parameter in self.parameters]
        rows = self._pairwise_rows(domains)
        result: list[Combination] = []
        seen: set[str] = set()

        def add_combination(combination: Combination | None) -> None:
            if not combination or combination.hash in seen:
                return
            seen.add(combination.hash)
            result.append(combination)

        names = [parameter.name for parameter in self.parameters]
        for row in rows:
            full = self._coerce_compatible(dict(zip(names, row, strict=True)), domains)
            add_combination(self._normalize(full) if full is not None else None)

        # Preserve each feasible individual value even when conditional
        # normalization removed it from all repaired IPOG rows.
        for index, values in enumerate(domains):
            for value in values:
                full = self._repair({index: value}, domains)
                if full is not None:
                    add_combination(self._normalize(full))
        return result

    def iter_pairwise(self, limit: int | None = None) -> Iterator[Combination]:
        yield from itertools.islice(self.pairwise(), limit)

    def mutations(self) -> list[Combination]:
        """Baseline plus one dependency-aware mutation for every selected value."""
        return [item[0] for item in self.mutation_seeds()]

    def mutation_seeds(self) -> list[tuple[Combination, frozenset[str]]]:
        """Return the baseline and first-generation mutations with change metadata."""
        if not self.parameters:
            return [(Combination({}), frozenset())]
        domains = [list(parameter.iter_values()) for parameter in self.parameters]
        fixed = {parameter.name for parameter in self.parameters if not parameter.mutate}
        baseline = self._coerce_compatible(self._base_values(domains), domains, fixed)
        result: list[tuple[Combination, frozenset[str]]] = []
        seen: set[str] = set()

        def add(full: dict[str, Any] | None) -> None:
            combination = self._normalize(full) if full is not None else None
            if combination and combination.hash not in seen:
                seen.add(combination.hash)
                result.append((combination, self._changed_names(full, domains)))

        add(baseline)
        for index, (parameter, values) in enumerate(zip(self.parameters, domains, strict=True)):
            if not parameter.mutate:
                continue
            for value in values:
                add(self._repair_from(self._base_values(domains), {index: value}, domains))
        return result

    def mutation_root(self) -> tuple[Combination, frozenset[str]]:
        return self.mutation_seeds()[0]

    def mutation_neighbors(self, parent: dict[str, Any], changed: frozenset[str]) -> list[tuple[Combination, frozenset[str]]]:
        """Mutate one not-yet-mutated field of a successful parent configuration."""
        domains = [list(parameter.iter_values()) for parameter in self.parameters]
        parent_full = self._base_values(domains)
        parent_full.update(parent)
        result: list[tuple[Combination, frozenset[str]]] = []
        seen: set[str] = set()
        for index, (parameter, values) in enumerate(zip(self.parameters, domains, strict=True)):
            if not parameter.mutate or parameter.name in changed:
                continue
            for value in values:
                full = self._repair_from(parent_full, {index: value}, domains)
                combination = self._normalize(full) if full is not None else None
                if not combination or combination.hash in seen or combination.values == parent:
                    continue
                new_changed = self._changed_names(full, domains)
                if not new_changed.issuperset(changed):
                    continue
                seen.add(combination.hash)
                result.append((combination, new_changed))
        return result

    def iter_mutations(self, limit: int | None = None) -> Iterator[Combination]:
        yield from itertools.islice(self.mutations(), limit)

    def _normalize(self, full: dict[str, Any]) -> Combination | None:
        # Active parameters are those whose own conditions hold; each of them must
        # also satisfy the value_conditions of the value it received.
        normalized = self._active(full)
        if any(not conditions_match(parameter.conditions_for_value(normalized[parameter.name]), full)
               for parameter in self.parameters if parameter.name in normalized):
            return None
        if not compatible(normalized, self.parameters, protocol=self.protocol, source_stream=self.source_stream):
            return None
        return Combination(normalized)

    def _active(self, full: dict[str, Any]) -> dict[str, Any]:
        return {parameter.name: full[parameter.name] for parameter in self.parameters
                if conditions_match(parameter.conditions, full)}

    def _pairwise_rows(self, domains: list[list[Any]]) -> list[list[Any]]:
        if len(domains) == 1:
            return [[value] for value in domains[0]]
        rows = [list(values) for values in itertools.product(domains[0], domains[1])]
        for current in range(2, len(domains)):
            current_keys = {_value_key(value): value for value in domains[current]}
            previous_keys = [{_value_key(value): value for value in domain} for domain in domains[:current]]
            uncovered = {(prior, prior_key, current_key)
                         for prior, keyed in enumerate(previous_keys)
                         for prior_key in keyed for current_key in current_keys}
            for row in rows:
                chosen = max(domains[current], key=lambda value: sum(
                    (prior, _value_key(row[prior]), _value_key(value)) in uncovered for prior in range(current)))
                row.append(chosen)
                for prior in range(current):
                    uncovered.discard((prior, _value_key(row[prior]), _value_key(chosen)))
            while uncovered:
                prior, prior_key, current_key = min(uncovered)
                row = [domain[0] for domain in domains[:current]] + [current_keys[current_key]]
                row[prior] = previous_keys[prior][prior_key]
                for other in range(current):
                    if other == prior:
                        continue
                    row[other] = max(domains[other], key=lambda value: int(
                        (other, _value_key(value), current_key) in uncovered))
                for other in range(current):
                    uncovered.discard((other, _value_key(row[other]), current_key))
                rows.append(row)
        return rows

    def _repair(self, assigned: dict[int, Any], domains: list[list[Any]]) -> dict[str, Any] | None:
        return self._repair_from(self._base_values(domains), assigned, domains)

    def _repair_from(self, source: dict[str, Any], assigned: dict[int, Any],
                     domains: list[list[Any]]) -> dict[str, Any] | None:
        full = dict(source)
        locked = {parameter.name for parameter in self.parameters if not parameter.mutate}
        locked.update(self.parameters[index].name for index in assigned)
        for index, value in assigned.items():
            full[self.parameters[index].name] = value
        by_name = {parameter.name: (parameter, domains[index]) for index, parameter in enumerate(self.parameters)}
        for index in assigned:
            parameter = self.parameters[index]
            if not _satisfy(parameter.conditions, full, locked, by_name):
                return None
            if not _satisfy(parameter.conditions_for_value(full[parameter.name]), full, locked, by_name):
                return None
        if any(not conditions_match(self.parameters[index].conditions, full) for index in assigned):
            return None
        return self._coerce_compatible(full, domains, locked)

    def _base_values(self, domains: list[list[Any]]) -> dict[str, Any]:
        return {parameter.name: parameter.baseline if parameter.baseline_defined else domains[index][0]
                for index, parameter in enumerate(self.parameters)}

    def _changed_names(self, full: dict[str, Any], domains: list[list[Any]]) -> frozenset[str]:
        baseline = self._base_values(domains)
        return frozenset(parameter.name for parameter in self.parameters if parameter.mutate
                         and _value_key(full[parameter.name]) != _value_key(baseline[parameter.name]))

    def _coerce_compatible(self, full: dict[str, Any], domains: list[list[Any]],
                           locked: set[str] | None = None) -> dict[str, Any] | None:
        """Replace only values that violate compatibility, preserving IPOG variation."""
        locked = locked or set()
        for _ in range(len(self.parameters) + 1):
            changed = False
            for index, parameter in enumerate(self.parameters):
                if not conditions_match(parameter.conditions, full):
                    continue
                if conditions_match(parameter.conditions_for_value(full[parameter.name]), full):
                    continue
                if parameter.name in locked:
                    return None
                replacement = next((value for value in domains[index]
                                    if conditions_match(parameter.conditions_for_value(value),
                                                        {**full, parameter.name: value})), None)
                if replacement is None:
                    return None
                full[parameter.name] = replacement
                changed = True
            if not changed:
                if compatible(self._active(full), self.parameters, protocol=self.protocol, source_stream=self.source_stream):
                    return full
                for index, parameter in enumerate(self.parameters):
                    if parameter.name in locked:
                        continue
                    old = full[parameter.name]
                    for value in domains[index]:
                        if _value_key(value) == _value_key(old):
                            continue
                        candidate = {**full, parameter.name: value}
                        if (conditions_match(parameter.conditions_for_value(value), candidate)
                                and compatible(self._active(candidate), self.parameters, protocol=self.protocol,
                                               source_stream=self.source_stream)):
                            return candidate
                return None
        return None

    def preview(self, limit: int = 10) -> list[Combination]:
        return list(itertools.islice(self.iter_valid(), limit))


def _value_key(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _pair_feature(left_name: str, left_value: Any, right_name: str, right_value: Any) -> tuple[str, str, str, str]:
    if left_name > right_name:
        left_name, right_name, left_value, right_value = right_name, left_name, right_value, left_value
    return left_name, _value_key(left_value), right_name, _value_key(right_value)


def _pair_features(values: dict[str, Any]) -> set[tuple[str, str, str, str]]:
    return {_pair_feature(left, values[left], right, values[right]) for left, right in itertools.combinations(values, 2)}


def _satisfy(rule: dict[str, Any] | None, full: dict[str, Any], locked: set[str],
             by_name: dict[str, tuple[ParameterSpec, list[Any]]]) -> bool:
    if not rule:
        return True
    if "all" in rule:
        return all(_satisfy(item, full, locked, by_name) for item in rule["all"])
    if "any" in rule:
        for item in rule["any"]:
            candidate = dict(full)
            if _satisfy(item, candidate, locked, by_name):
                full.update(candidate)
                return True
        return False
    if "parameter" in rule:
        name = rule["parameter"]
        return _set_predicates(name, {key: value for key, value in rule.items() if key != "parameter"}, full, locked, by_name)
    return all(_set_predicates(name, predicates if isinstance(predicates, dict) else {"equals": predicates},
                               full, locked, by_name) for name, predicates in rule.items())


def _set_predicates(name: str, predicates: dict[str, Any], full: dict[str, Any], locked: set[str],
                    by_name: dict[str, tuple[ParameterSpec, list[Any]]]) -> bool:
    if name not in by_name:
        return predicates.get("exists") is False
    domain = by_name[name][1]
    candidates = domain
    if "equals" in predicates:
        candidates = [predicates["equals"]]
    elif "in" in predicates:
        candidates = [value for value in domain if value in predicates["in"]]
    elif "not_equals" in predicates:
        candidates = [value for value in domain if value != predicates["not_equals"]]
    elif "not_in" in predicates:
        candidates = [value for value in domain if value not in predicates["not_in"]]
    elif predicates.get("exists") is False:
        return False
    if name in locked:
        return full[name] in candidates
    if not candidates:
        return False
    full[name] = candidates[0]
    return True
