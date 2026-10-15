from __future__ import annotations

import hashlib
import itertools
import json
import random
from dataclasses import dataclass
from decimal import Decimal
from functools import lru_cache
from typing import Any, Iterator, Sequence

from app.parameters.dependencies import (condition_state, conditions_match, dependency_names,
                                         semantic_transport_names)
from app.parameters.compatibility import compatible
from app.parameters.coverage import ConstructionBudget, Witness
from app.parameters.models import ParameterSpec, validate_active_parameter_paths

_ABSENT = object()
_PROFILE_PATHS = {("streamSettings", "network"), ("streamSettings", "security"),
                  ("settings", "clients", 0, "flow")}
_COMPATIBILITY_PATHS = _PROFILE_PATHS | {
    ("streamSettings", "tlsSettings", "minVersion"), ("streamSettings", "tlsSettings", "maxVersion"),
    ("streamSettings", "tlsSettings", "alpn"), ("streamSettings", "xhttpSettings", "uplinkHTTPMethod"),
    ("streamSettings", "xhttpSettings", "mode"), ("streamSettings", "xhttpSettings", "xmux"),
    ("outbounds", 0, "streamSettings", "xhttpSettings", "xmux"),
}


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
        # The condition evaluator resolves transport-semantic names through the
        # specs; computing the set once keeps the recursive witness search from
        # re-deriving it on every node of plan construction.
        self._transport_names = semantic_transport_names(self.parameters)
        self.protocol = protocol
        self.source_stream = source_stream
        self.coverage_metadata: dict[str, Any] = {}
        graph = {parameter.name: dependency_names(parameter.conditions) |
                 set().union(*(dependency_names(rule) for _, rule in parameter.value_conditions))
                 for parameter in self.parameters}
        self._cyclic_names = set()
        for name in graph:
            pending = list(graph[name])
            seen = set()
            while pending:
                dependency = pending.pop()
                if dependency == name:
                    self._cyclic_names.add(name)
                    break
                if dependency not in seen:
                    seen.add(dependency)
                    pending.extend(graph.get(dependency, ()))

    @property
    def raw_count(self) -> int:
        result = 1
        for parameter in self.parameters:
            result *= parameter.count_values()
        return result

    def iter_valid(self) -> Iterator[Combination]:
        """Visit active domains lazily, deciding controls before their dependants.

        Inactive parameters receive a single baseline value for dependency
        evaluation; their raw domains are never expanded. Cyclic rules remain
        supported through deferred evaluation and final normalization.
        """
        seen: set[str] = set()
        deduplicate = bool(self._cyclic_names) or any(
            parameter.values is not None and len({_value_key(value) for value in parameter.values}) != len(parameter.values)
            for parameter in self.parameters)
        for _, combination in self._walk({}, {}):
            if deduplicate:
                if combination.hash in seen:
                    continue
                seen.add(combination.hash)
            yield combination

    def pairwise(self, limit: int | None = None, *, max_witness_nodes: int = 2000,
                 construction_budget: int = 200000, domain_limit: int = 256,
                 target_limit: int = 20000) -> list[Combination]:
        """Return a deterministic all-pairs covering set without expanding the full product.

        IPOG-style horizontal/vertical growth covers every pair in the raw domains.
        A pinned witness repair restores pairs lost to normalization. Finite
        construction budgets report unknown feasibility rather than pretending
        that a failed or truncated construction proves a pair impossible.
        """
        if not self.parameters:
            self.coverage_metadata = {"total_pairs": 0, "covered_pairs": 0, "feasible_pairs": 0,
                                      "infeasible_pairs": 0, "unknown_pairs": 0,
                                      "coverage_complete": True, "truncated": False}
            if limit is not None and limit <= 0:
                return []
            return [Combination({})]
        if domain_limit < 1:
            raise ValueError("domain_limit must be at least 1")
        domains = self._domains(domain_limit)
        counts = [parameter.count_values() if parameter.mutate else 1 for parameter in self.parameters]
        total_pairs = sum(left * right for left, right in itertools.combinations(counts, 2))
        sampled_pairs = sum(len(left) * len(right) for left, right in itertools.combinations(domains, 2))
        budget = ConstructionBudget(max(0, construction_budget))
        result: list[Combination] = []
        seen: set[str] = set()
        covered: set[tuple[str, str, str, str]] = set()
        infeasible: set[tuple[str, str, str, str]] = set()
        unknown: set[tuple[str, str, str, str]] = set()
        infeasible_values: set[tuple[str, str]] = set()

        def add_combination(combination: Combination | None) -> None:
            if not combination or combination.hash in seen or (limit is not None and len(result) >= max(0, limit)):
                return
            seen.add(combination.hash)
            result.append(combination)
            covered.update(_pair_features(combination.values))

        names = [parameter.name for parameter in self.parameters]
        # IPOG provides inexpensive broad seeds. Its vertical growth is bounded;
        # pinned witnesses below repair any actual gaps after normalization.
        rows = (self._pairwise_rows(domains, row_limit=min(2000, max(1, limit or 2000)))
                if sampled_pairs <= target_limit else [])
        if not rows and (limit is None or limit > 0):
            witness = self.feasible_witness({}, domains=domains, max_nodes=max_witness_nodes, budget=budget)
            add_combination(self._normalize(witness.values) if witness.values is not None else None)
        for row in rows:
            if limit is not None and len(result) >= max(0, limit):
                break
            if not budget.spend():
                break
            full = self._coerce_compatible(dict(zip(names, row, strict=True)), domains)
            add_combination(self._normalize(full) if full is not None else None)

        targets = itertools.islice(self._pair_targets(domains), max(0, target_limit))
        for assigned, feature in targets:
            if feature in covered:
                continue
            if (limit is not None and len(result) >= max(0, limit)) or budget.remaining <= 0:
                break
            witness = self.feasible_witness(assigned, domains=domains, max_nodes=max_witness_nodes, budget=budget)
            if witness.status == "feasible":
                add_combination(self._normalize(witness.values))
            elif witness.status == "infeasible":
                infeasible.add(feature)
            else:
                unknown.add(feature)

        # Single-value witnesses also cover parameters that never coexist with
        # another one, as well as the one-parameter case.
        for index, values in enumerate(domains):
            for value in values:
                if any(item.values.get(names[index], _ABSENT) == value for item in result):
                    continue
                if (limit is not None and len(result) >= max(0, limit)) or budget.remaining <= 0:
                    break
                witness = self.feasible_witness({index: value}, domains=domains,
                                                max_nodes=max_witness_nodes, budget=budget)
                if witness.status == "feasible":
                    add_combination(self._normalize(witness.values))
                elif witness.status == "infeasible":
                    infeasible_values.add((names[index], _value_key(value)))
        unknown_count = max(0, total_pairs - len(covered) - len(infeasible))
        covered_values = {(name, _value_key(value)) for item in result for name, value in item.values.items()}
        unknown_values = max(0, sum(counts) - len(covered_values) - len(infeasible_values))
        self.coverage_metadata = {
            "total_pairs": total_pairs, "sampled_pairs": sampled_pairs,
            "covered_pairs": len(covered), "feasible_pairs": len(covered),
            "infeasible_pairs": len(infeasible), "unknown_pairs": unknown_count,
            "uncovered_feasible_pairs": 0, "witness_unknown_pairs": len(unknown),
            "total_values": sum(counts), "covered_values": len(covered_values),
            "infeasible_values": len(infeasible_values), "unknown_values": unknown_values,
            "coverage_complete": unknown_count == 0 and unknown_values == 0,
            "truncated": unknown_count > 0 or unknown_values > 0,
            "domain_sampling": counts != [len(domain) for domain in domains],
            "construction_nodes": budget.used,
            "construction_budget_exhausted": budget.remaining <= 0,
            "candidate_limit_reached": limit is not None and len(result) >= max(0, limit),
            "candidate_count": len(result),
        }
        return result

    def iter_pairwise(self, limit: int | None = None) -> Iterator[Combination]:
        yield from self.pairwise(limit=limit)

    def adaptive_frontier(self, limit: int = 120, *, seed: int = 0) -> list[Combination]:
        """Independent profile/pair exploration, even when no parent works.

        Successful-parent exploitation belongs to the runner. This bounded
        frontier deliberately includes joint changes instead of stopping at
        one-field mutations of a failed baseline.
        """
        if limit <= 0:
            return []
        domains = self._domains(256)
        baseline_values = self._base_values(domains)
        budget = ConstructionBudget(max(10000, limit * 1000))
        candidates: list[Combination] = []
        seen: set[str] = set()

        def add(values: dict[str, Any] | None) -> None:
            combination = self._normalize(values) if values is not None else None
            if combination and combination.hash not in seen and len(candidates) < limit:
                seen.add(combination.hash)
                candidates.append(combination)

        baseline = self.feasible_witness({}, domains=domains, max_nodes=2000, budget=budget)
        add(baseline.values)
        profile_indices = [index for index, parameter in enumerate(self.parameters)
                           if parameter.path in _PROFILE_PATHS or parameter.name in {"network", "security", "flow"}]
        profile_domains = [domains[index] for index in profile_indices]
        for values in itertools.islice(itertools.product(*profile_domains), min(128, limit)):
            if len(candidates) >= limit:
                break
            witness = self.feasible_witness(dict(zip(profile_indices, values, strict=True)),
                                            domains=domains, max_nodes=2000, budget=budget)
            add(witness.values)

        # Reserve a small mixed-strength rescue frontier. Pair coverage alone
        # cannot detect a fault that requires three simultaneous changes. This
        # bounded subset is deliberately labelled exploration, not full 3-way
        # coverage. Unmapped custom domains use their first six mutable fields.
        mutable = [index for index, parameter in enumerate(self.parameters)
                   if parameter.mutate and len({_value_key(value) for value in domains[index]}) > 1]
        critical = [index for index in mutable if index in profile_indices]
        critical.extend(index for index in mutable if index not in critical)
        critical = critical[:6]
        triple_limit = min(8, max(1, limit // 4))
        triples_added = 0
        for indices in itertools.combinations(critical, 3):
            if len(candidates) >= limit or triples_added >= triple_limit or budget.remaining <= 0:
                break
            assignments = {index: next(value for value in reversed(domains[index])
                                        if _value_key(value) != _value_key(baseline_values[self.parameters[index].name]))
                           for index in indices}
            witness = self.feasible_witness(assignments, domains=domains, max_nodes=1000, budget=budget)
            before = len(candidates)
            add(witness.values)
            triples_added += len(candidates) > before

        # Pairwise already has a strict candidate and construction budget. Rotate
        # its choices by seed to avoid an identical rescue prefix every session.
        pool = self.pairwise(limit=limit, construction_budget=max(10000, limit * 1000))
        pool_features = set().union(*(_pair_features(item.values) for item in pool)) if pool else set()
        grouped: dict[str, list[Combination]] = {}
        for combination in pool:
            grouped.setdefault(self.profile_id(combination.values), []).append(combination)
        rng = random.Random(seed)
        groups = list(grouped.values())
        rng.shuffle(groups)
        for group in groups:
            rng.shuffle(group)
        while groups and len(candidates) < limit:
            next_groups = []
            for group in groups:
                add(group.pop(0).values)
                if group:
                    next_groups.append(group)
            groups = next_groups
        # A complete small pairwise set may leave most of the candidate budget
        # unused. Independent joint samples continue exploring higher-order
        # interactions even when every previous candidate failed.
        for _ in range(limit * 4):
            if len(candidates) >= limit or not mutable or budget.remaining <= 0:
                break
            indices = rng.sample(mutable, min(3, len(mutable)))
            assignments = {index: rng.choice(domains[index]) for index in indices}
            witness = self.feasible_witness(assignments, domains=domains, max_nodes=1000, budget=budget)
            add(witness.values)
        self.coverage_metadata["adaptive_frontier_count"] = len(candidates)
        self.coverage_metadata["profile_count"] = len({self.profile_id(item.values) for item in candidates})
        self.coverage_metadata["policy_version"] = "adaptive-frontier-v1"
        self.coverage_metadata["seed"] = seed
        self.coverage_metadata["mixed_strength_rescue_candidates"] = triples_added
        # Recompute coverage for the actual frontier: baseline/profile witnesses
        # can replace members of a truncated pool.
        covered = set().union(*(_pair_features(item.values) for item in candidates)) if candidates else set()
        total = self.coverage_metadata.get("total_pairs", 0)
        self.coverage_metadata["covered_pairs"] = len(covered)
        known_feasible = pool_features | covered
        self.coverage_metadata["feasible_pairs"] = len(known_feasible)
        self.coverage_metadata["uncovered_feasible_pairs"] = len(known_feasible - covered)
        self.coverage_metadata["unknown_pairs"] = max(0, total - len(known_feasible)
                                                      - self.coverage_metadata.get("infeasible_pairs", 0))
        covered_values = {(name, _value_key(value)) for item in candidates for name, value in item.values.items()}
        pool_values = {(name, _value_key(value)) for item in pool for name, value in item.values.items()}
        known_values = pool_values | covered_values
        self.coverage_metadata["covered_values"] = len(covered_values)
        self.coverage_metadata["uncovered_feasible_values"] = len(known_values - covered_values)
        self.coverage_metadata["unknown_values"] = max(0, self.coverage_metadata.get("total_values", 0)
                                                       - len(known_values)
                                                       - self.coverage_metadata.get("infeasible_values", 0))
        self.coverage_metadata["construction_nodes"] = self.coverage_metadata.get("construction_nodes", 0) + budget.used
        self.coverage_metadata["coverage_complete"] = (self.coverage_metadata["unknown_pairs"] == 0
            and self.coverage_metadata["uncovered_feasible_pairs"] == 0
            and self.coverage_metadata["unknown_values"] == 0
            and self.coverage_metadata["uncovered_feasible_values"] == 0)
        self.coverage_metadata["truncated"] = not self.coverage_metadata["coverage_complete"]
        return candidates

    def iter_adaptive(self, limit: int = 120, *, seed: int = 0) -> Iterator[Combination]:
        yield from self.adaptive_frontier(limit, seed=seed)

    def profile_id(self, values: dict[str, Any]) -> str:
        """Stable semantic profile label; never part of the legacy hash."""
        by_path = {parameter.path: values[parameter.name] for parameter in self.parameters
                   if parameter.name in values and parameter.path}
        stream = self.source_stream or {}
        network = by_path.get(("streamSettings", "network"), values.get("network", stream.get("network", "unknown")))
        security = by_path.get(("streamSettings", "security"), values.get("security", stream.get("security", "none")))
        flow = by_path.get(("settings", "clients", 0, "flow"), values.get("flow", ""))
        return ":".join(str(item) for item in (self.protocol or "unknown", network, security, flow or "none"))

    def mutations(self, limit: int | None = None) -> list[Combination]:
        """Baseline plus one dependency-aware mutation for every selected value."""
        return [item[0] for item in self.mutation_seeds(limit=limit)]

    def mutation_seeds(self, limit: int | None = None, *, domain_limit: int = 256,
                       construction_budget: int = 20000, max_witness_nodes: int = 256
                       ) -> list[tuple[Combination, frozenset[str]]]:
        """Return a bounded baseline-first mutation pool with change metadata.

        ``limit`` bounds emitted candidates; ``domain_limit`` and
        ``construction_budget`` independently bound sampled values and repair
        work. Large domains are sampled from their prefix while always retaining
        the declared baseline. This is exploration, not exhaustive coverage.
        """
        candidate_limit = 1000 if limit is None else max(0, limit)
        if domain_limit < 1 or construction_budget < 0 or max_witness_nodes < 0:
            raise ValueError("mutation budgets must be non-negative and domain_limit must be positive")
        if not self.parameters:
            result = [(Combination({}), frozenset())] if candidate_limit else []
            self.coverage_metadata = {"domain_sampling": False, "unknown_values": None,
                                      "truncated": not bool(result), "coverage_complete": bool(result),
                                      "coverage_scope": "baseline_only",
                                      "candidate_limit": candidate_limit, "candidate_count": len(result),
                                      "candidate_limit_reached": candidate_limit == 0,
                                      "construction_nodes": 0, "construction_budget_exhausted": False}
            return result
        if candidate_limit == 0:
            self.coverage_metadata = {"domain_sampling": False, "unknown_values": None,
                                      "truncated": True, "coverage_complete": False,
                                      "coverage_scope": "baseline_plus_single_parameter_mutations",
                                      "candidate_limit": 0, "candidate_count": 0,
                                      "candidate_limit_reached": True, "construction_nodes": 0,
                                      "construction_budget_exhausted": False, "domain_limit": domain_limit}
            return []
        domains = self._mutation_domains(domain_limit)
        fixed = {parameter.name for parameter in self.parameters if not parameter.mutate}
        budget = ConstructionBudget(construction_budget)
        baseline = self._coerce_compatible(self._base_values(domains), domains, fixed, budget=budget)
        result: list[tuple[Combination, frozenset[str]]] = []
        seen: set[str] = set()
        sampled = any(parameter.mutate and parameter.count_values() > len(domain)
                      for parameter, domain in zip(self.parameters, domains, strict=True))
        exhausted = budget.remaining <= 0

        def add(full: dict[str, Any] | None) -> None:
            combination = self._normalize(full) if full is not None else None
            if combination and combination.hash not in seen and len(result) < candidate_limit:
                seen.add(combination.hash)
                result.append((combination, self._changed_names(full, domains)))

        if candidate_limit:
            add(baseline)
        for index, (parameter, values) in enumerate(zip(self.parameters, domains, strict=True)):
            if len(result) >= candidate_limit or budget.remaining <= 0:
                break
            if not parameter.mutate:
                continue
            for value in values:
                if len(result) >= candidate_limit:
                    break
                if not budget.spend():
                    exhausted = True
                    break
                add(self._repair_from(self._base_values(domains), {index: value}, domains,
                                      budget=budget, max_nodes=max_witness_nodes))
            if budget.remaining <= 0:
                exhausted = True
                break
        reached = candidate_limit == 0 or len(result) >= candidate_limit
        truncated = sampled or exhausted or reached
        self.coverage_metadata = {
            "domain_sampling": sampled, "unknown_values": None,
            "truncated": truncated, "coverage_complete": False,
            "coverage_scope": "baseline_plus_single_parameter_mutations",
            "candidate_limit": candidate_limit, "candidate_count": len(result),
            "candidate_limit_reached": reached,
            "construction_nodes": budget.used,
            "construction_budget_exhausted": exhausted or budget.remaining <= 0,
            "domain_limit": domain_limit,
        }
        return result

    def mutation_root(self) -> tuple[Combination, frozenset[str]]:
        roots = self.mutation_seeds(limit=1, domain_limit=256)
        if roots:
            return roots[0]
        raise ValueError("Could not construct a feasible mutation root within the configured budget")

    def mutation_neighbors(self, parent: dict[str, Any], changed: frozenset[str], limit: int | None = None,
                           *, domain_limit: int = 256, construction_budget: int = 20000,
                           max_witness_nodes: int = 256) -> list[tuple[Combination, frozenset[str]]]:
        """Mutate bounded values of fields not yet changed on a parent."""
        candidate_limit = 1000 if limit is None else max(0, limit)
        if domain_limit < 1 or construction_budget < 0 or max_witness_nodes < 0:
            raise ValueError("mutation budgets must be non-negative and domain_limit must be positive")
        if candidate_limit == 0:
            self.coverage_metadata = {"domain_sampling": False, "unknown_values": None,
                                      "truncated": True, "coverage_complete": False,
                                      "coverage_scope": "single_field_neighbors", "candidate_limit": 0,
                                      "candidate_count": 0, "candidate_limit_reached": True,
                                      "construction_nodes": 0, "construction_budget_exhausted": False,
                                      "domain_limit": domain_limit}
            return []
        domains = self._mutation_domains(domain_limit)
        parent_full = self._base_values(domains)
        parent_full.update(parent)
        result: list[tuple[Combination, frozenset[str]]] = []
        seen: set[str] = set()
        budget = ConstructionBudget(construction_budget)
        sampled = any(parameter.mutate and parameter.count_values() > len(domain)
                      for parameter, domain in zip(self.parameters, domains, strict=True))
        exhausted = False
        for index, (parameter, values) in enumerate(zip(self.parameters, domains, strict=True)):
            if len(result) >= candidate_limit or budget.remaining <= 0:
                break
            if not parameter.mutate or parameter.name in changed:
                continue
            for value in values:
                if len(result) >= candidate_limit:
                    break
                if not budget.spend():
                    exhausted = True
                    break
                full = self._repair_from(parent_full, {index: value}, domains,
                                         budget=budget, max_nodes=max_witness_nodes)
                combination = self._normalize(full) if full is not None else None
                if not combination or combination.hash in seen or combination.values == parent:
                    continue
                new_changed = self._changed_names(full, domains)
                if not new_changed.issuperset(changed):
                    continue
                seen.add(combination.hash)
                result.append((combination, new_changed))
            if budget.remaining <= 0:
                exhausted = True
                break
        reached = candidate_limit == 0 or len(result) >= candidate_limit
        truncated = sampled or exhausted or reached
        self.coverage_metadata = {
            "domain_sampling": sampled, "unknown_values": None,
            "truncated": truncated, "coverage_complete": False,
            "coverage_scope": "single_field_neighbors",
            "candidate_limit": candidate_limit, "candidate_count": len(result),
            "candidate_limit_reached": reached,
            "construction_nodes": budget.used,
            "construction_budget_exhausted": exhausted or budget.remaining <= 0,
            "domain_limit": domain_limit,
        }
        return result

    def iter_mutations(self, limit: int | None = None) -> Iterator[Combination]:
        yield from self.mutations(limit=limit)

    def _mutation_domains(self, limit: int) -> list[list[Any]]:
        """Sample each mutable domain lazily, retaining its baseline if defined."""
        domains: list[list[Any]] = []
        for parameter in self.parameters:
            baseline = (parameter.baseline if parameter.baseline_defined
                        else next(parameter.iter_values()))
            if not parameter.mutate:
                domains.append([baseline])
                continue
            values = list(itertools.islice(parameter.iter_values(), limit))
            if parameter.baseline_defined and _value_key(baseline) not in {_value_key(value) for value in values}:
                if len(values) >= limit:
                    values[-1] = baseline
                else:
                    values.append(baseline)
            domains.append(values or [baseline])
        return domains

    def _domains(self, limit: int | None = None) -> list[list[Any]]:
        domains = []
        for parameter in self.parameters:
            if not parameter.mutate:
                domains.append([parameter.baseline if parameter.baseline_defined
                                else next(parameter.iter_values())])
                continue
            values = list(itertools.islice(parameter.iter_values(), limit))
            if parameter.baseline_defined and limit is not None and parameter.count_values() > limit:
                # Keep the current value in a sampled numeric range, provided it
                # belongs to that range; a baseline is not a new search choice.
                baseline = parameter.baseline
                if (parameter.values is not None and baseline in parameter.values
                        or parameter.values is None and parameter.minimum <= Decimal(str(baseline)) <= parameter.maximum
                        and (Decimal(str(baseline)) - parameter.minimum) % parameter.step == 0):
                    if _value_key(baseline) not in {_value_key(value) for value in values}:
                        values[-1] = baseline
            domains.append(values)
        return domains

    def _pair_targets(self, domains: list[list[Any]]) -> Iterator[tuple[dict[int, Any], tuple[str, str, str, str]]]:
        # Round-robin over parameter pairs: a construction cutoff should not
        # spend its entire budget on the first pair of large numeric domains.
        pairs = [(left, right) for left in range(len(domains)) for right in range(left + 1, len(domains))]
        iterators = [(left, right, iter(itertools.product(domains[left], domains[right])))
                     for left, right in pairs]
        while iterators:
            remaining = []
            for left, right, values in iterators:
                item = next(values, None)
                if item is None:
                    continue
                a, b = item
                yield {left: a, right: b}, _pair_feature(self.parameters[left].name, a,
                                                       self.parameters[right].name, b)
                remaining.append((left, right, values))
            iterators = remaining

    def feasible_witness(self, assigned: dict[int, Any], *, domains: list[list[Any]] | None = None,
                         preferred: dict[str, Any] | None = None, max_nodes: int = 2000,
                         budget: ConstructionBudget | None = None) -> Witness:
        """Find a compatible active witness without modifying pinned choices.

        ``unknown`` means a finite node budget was consumed. Only exhausted
        search without a budget cutoff proves ``infeasible``.
        """
        domains = domains if domains is not None else self._domains(256)
        pinned = {self.parameters[index].name: value for index, value in assigned.items()}
        for index, value in assigned.items():
            if _value_key(value) not in {_value_key(choice) for choice in domains[index]}:
                return Witness("infeasible")
        local_budget = ConstructionBudget(max(0, max_nodes))
        exhausted = [False]
        generator = self._walk(pinned, preferred or self._base_values(domains), domains=domains,
                               local_budget=local_budget, shared_budget=budget, exhausted=exhausted)
        first = next(generator, None)
        generator.close()
        if first is not None:
            return Witness("feasible", first[0], local_budget.used)
        return Witness("unknown" if exhausted[0] else "infeasible", nodes=local_budget.used)

    def _walk(self, pinned: dict[str, Any], preferred: dict[str, Any], *,
              domains: list[list[Any]] | None = None, local_budget: ConstructionBudget | None = None,
              shared_budget: ConstructionBudget | None = None,
              exhausted: list[bool] | None = None) -> Iterator[tuple[dict[str, Any], Combination]]:
        by_name = {parameter.name: (index, parameter) for index, parameter in enumerate(self.parameters)}
        names = set(by_name)
        exhausted = exhausted if exhausted is not None else [False]
        defaults = {parameter.name: parameter.baseline if parameter.baseline_defined
                    else next(parameter.iter_values()) for parameter in self.parameters}
        value_rules = {parameter.name: dict(parameter.value_conditions) for parameter in self.parameters
                       if parameter.value_conditions}
        compatibility_names = set()
        for parameter in self.parameters:
            if parameter.path and any(parameter.path[:len(path)] == path or path[:len(parameter.path)] == parameter.path
                                      for path in _COMPATIBILITY_PATHS):
                compatibility_names.add(parameter.name)
                compatibility_names.update(dependency_names(parameter.conditions))

        def recurse(full: dict[str, Any], pending: set[str], last_name: str | None = None) -> Iterator[tuple[dict[str, Any], Combination]]:
            if local_budget is not None and not local_budget.spend():
                exhausted[0] = True
                return
            if shared_budget is not None and not shared_budget.spend():
                exhausted[0] = True
                return
            # A known incompatible active value can be rejected before touching
            # any of the domains belonging to later conditional parameters.
            states = {name: condition_state(by_name[name][1].conditions, full, pending,
                                            specs=self.parameters, transport_names=self._transport_names) for name in full}
            for name, value in full.items():
                parameter = by_name[name][1]
                active = states[name]
                if name in pinned and active is False:
                    return
                if (active is True and name in value_rules
                        and condition_state(value_rules[name].get(_value_key(value)), full, pending,
                                            specs=self.parameters, transport_names=self._transport_names) is False):
                    return
            if last_name is None or last_name in compatibility_names:
                active_values = {name: value for name, value in full.items() if states[name] is True}
                unresolved = pending | {name for name in full if states[name] is None}
                if not compatible(active_values, self.parameters, protocol=self.protocol,
                                  source_stream=self.source_stream, pending=unresolved):
                    return
            if not pending:
                combination = self._normalize(full)
                if combination and all(name in combination.values and _value_key(combination.values[name]) == _value_key(value)
                                       for name, value in pinned.items()):
                    yield full, combination
                return
            ordered = [parameter for parameter in self.parameters if parameter.name in pending]
            # Controls may occur later in YAML. Evaluate resolved own conditions
            # first, then defer cycles until their values can be checked.
            parameter = next((item for item in ordered
                              if condition_state(item.conditions, full, pending,
                                                 specs=self.parameters, transport_names=self._transport_names) is not None), ordered[0])
            index = by_name[parameter.name][0]
            active = condition_state(parameter.conditions, full, pending, specs=self.parameters, transport_names=self._transport_names)
            if active is False and parameter.name not in self._cyclic_names:
                if parameter.name in pinned:
                    return
                choices = iter([defaults[parameter.name]])
            elif parameter.name in pinned:
                choices = iter([pinned[parameter.name]])
            elif not parameter.mutate:
                choices = iter([defaults[parameter.name]])
            else:
                choices = iter(domains[index]) if domains is not None else parameter.iter_values()
                if domains is not None and parameter.name in preferred:
                    choice = preferred[parameter.name]
                    if _value_key(choice) in {_value_key(value) for value in domains[index]}:
                        choices = itertools.chain([choice], (value for value in choices
                                                             if _value_key(value) != _value_key(choice)))
            remaining = pending - {parameter.name}
            for value in choices:
                yield from recurse({**full, parameter.name: value}, remaining, parameter.name)
                if exhausted[0]:
                    return

        yield from recurse({}, names)

    def _normalize(self, full: dict[str, Any]) -> Combination | None:
        # Active parameters are those whose own conditions hold; each of them must
        # also satisfy the value_conditions of the value it received.
        normalized = self._active(full)
        if any(not conditions_match(parameter.conditions_for_value(normalized[parameter.name]), full,
                                    specs=self.parameters, transport_names=self._transport_names)
               for parameter in self.parameters if parameter.name in normalized):
            return None
        validate_active_parameter_paths(normalized, self.parameters)
        if not compatible(normalized, self.parameters, protocol=self.protocol, source_stream=self.source_stream):
            return None
        return Combination(normalized)

    def _active(self, full: dict[str, Any]) -> dict[str, Any]:
        return {parameter.name: full[parameter.name] for parameter in self.parameters
                if conditions_match(parameter.conditions, full, specs=self.parameters, transport_names=self._transport_names)}

    def _pairwise_rows(self, domains: list[list[Any]], row_limit: int | None = None) -> list[list[Any]]:
        if len(domains) == 1:
            return [[value] for value in itertools.islice(domains[0], row_limit)]
        rows = [list(values) for values in itertools.islice(itertools.product(domains[0], domains[1]), row_limit)]
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
                if row_limit is not None and len(rows) >= row_limit:
                    break
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
                     domains: list[list[Any]], *, budget: ConstructionBudget | None = None,
                     max_nodes: int = 2000) -> dict[str, Any] | None:
        # A witness solver explores alternative all/any branches and joint
        # repairs; selecting the first predicate value greedily can lose pairs.
        effective_domains = [values if parameter.mutate else
                             [parameter.baseline if parameter.baseline_defined else values[0]]
                             for parameter, values in zip(self.parameters, domains, strict=True)]
        witness = self.feasible_witness(assigned, domains=effective_domains, preferred=source,
                                        max_nodes=max_nodes, budget=budget)
        return witness.values

    def _base_values(self, domains: list[list[Any]]) -> dict[str, Any]:
        return {parameter.name: parameter.baseline if parameter.baseline_defined else domains[index][0]
                for index, parameter in enumerate(self.parameters)}

    def _changed_names(self, full: dict[str, Any], domains: list[list[Any]]) -> frozenset[str]:
        baseline = self._base_values(domains)
        return frozenset(parameter.name for parameter in self.parameters if parameter.mutate
                         and _value_key(full[parameter.name]) != _value_key(baseline[parameter.name]))

    def _coerce_compatible(self, full: dict[str, Any], domains: list[list[Any]],
                           locked: set[str] | None = None,
                           budget: ConstructionBudget | None = None) -> dict[str, Any] | None:
        """Replace only values that violate compatibility, preserving IPOG variation."""
        locked = locked or set()
        for _ in range(len(self.parameters) + 1):
            changed = False
            for index, parameter in enumerate(self.parameters):
                if budget is not None and not budget.spend():
                    return None
                if not conditions_match(parameter.conditions, full, specs=self.parameters, transport_names=self._transport_names):
                    continue
                if conditions_match(parameter.conditions_for_value(full[parameter.name]), full,
                                    specs=self.parameters, transport_names=self._transport_names):
                    continue
                if parameter.name in locked:
                    return None
                replacement = None
                for value in domains[index]:
                    if budget is not None and not budget.spend():
                        return None
                    if conditions_match(parameter.conditions_for_value(value),
                                        {**full, parameter.name: value}, specs=self.parameters, transport_names=self._transport_names):
                        replacement = value
                        break
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
                        if budget is not None and not budget.spend():
                            return None
                        if _value_key(value) == _value_key(old):
                            continue
                        candidate = {**full, parameter.name: value}
                        if (conditions_match(parameter.conditions_for_value(value), candidate,
                                            specs=self.parameters, transport_names=self._transport_names)
                                and compatible(self._active(candidate), self.parameters, protocol=self.protocol,
                                               source_stream=self.source_stream)):
                            return candidate
                return None
        return None

    def preview(self, limit: int = 10) -> list[Combination]:
        return list(itertools.islice(self.iter_valid(), limit))


def _value_key(value: Any) -> str:
    try:
        return _value_key_memo(value)
    except TypeError:  # lists/dicts are legitimate parameter values
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@lru_cache(maxsize=4096)
def _value_key_memo(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _pair_feature(left_name: str, left_value: Any, right_name: str, right_value: Any) -> tuple[str, str, str, str]:
    if left_name > right_name:
        left_name, right_name, left_value, right_value = right_name, left_name, right_value, left_value
    return left_name, _value_key(left_value), right_name, _value_key(right_value)


def _pair_features(values: dict[str, Any]) -> set[tuple[str, str, str, str]]:
    return {_pair_feature(left, values[left], right, values[right]) for left, right in itertools.combinations(values, 2)}
