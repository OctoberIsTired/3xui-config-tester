from app.parameters.generator import CombinationGenerator
from app.parameters.models import ParameterSpec
import pytest


def spec(name: str, data: dict) -> ParameterSpec:
    return ParameterSpec.from_dict(name, data)


def test_mutation_limit_bounds_seed_creation_and_keeps_baseline_outside_sampled_prefix() -> None:
    parameter = spec("large", {"type": "integer", "min": 0, "max": 10_000_000,
                               "step": 1, "baseline": 9_999_999})
    generator = CombinationGenerator([parameter])

    seeds = generator.mutation_seeds(limit=10, domain_limit=8)

    assert len(seeds) <= 10
    assert seeds[0][0].values == {"large": 9_999_999}
    assert all(item.values["large"] < 8 or item.values["large"] == 9_999_999
               for item, _ in seeds)
    assert generator.coverage_metadata["domain_sampling"] is True
    assert generator.coverage_metadata["unknown_values"] is None
    assert generator.coverage_metadata["truncated"] is True


def test_fixed_large_parameter_does_not_expand_its_domain() -> None:
    parameter = spec("fixed", {"type": "integer", "min": 0, "max": 10_000_000,
                               "step": 1, "baseline": 42, "mutate": False})
    generator = CombinationGenerator([parameter])

    seeds = generator.mutation_seeds(limit=10)

    assert [item.values for item, _ in seeds] == [{"fixed": 42}]
    assert generator.coverage_metadata["domain_sampling"] is False
    assert generator.coverage_metadata["coverage_complete"] is False
    assert generator.coverage_metadata["coverage_scope"] == "baseline_plus_single_parameter_mutations"


def test_inactive_large_parameter_is_bounded_and_reports_unknown_coverage() -> None:
    control = spec("enabled", {"type": "boolean", "values": [False, True], "baseline": False})
    dependent = spec("large", {"type": "integer", "min": 0, "max": 10_000_000,
                                "step": 1, "baseline": 9_999_999,
                                "conditions": {"enabled": {"equals": True}}})
    generator = CombinationGenerator([control, dependent])

    seeds = generator.mutation_seeds(limit=10, domain_limit=8, construction_budget=200)

    assert len(seeds) <= 10
    assert seeds[0][0].values == {"enabled": False}
    assert generator.coverage_metadata["domain_sampling"] is True
    assert generator.coverage_metadata["unknown_values"] is None
    assert generator.coverage_metadata["truncated"] is True


def test_small_finite_seed_and_neighbor_semantics_remain_complete() -> None:
    toggle = spec("toggle", {"type": "boolean", "values": [False, True], "baseline": False})
    amount = spec("amount", {"type": "integer", "min": 1, "max": 3, "step": 1,
                              "baseline": 2})
    generator = CombinationGenerator([toggle, amount])

    seeds = generator.mutation_seeds()
    root, changed = generator.mutation_root()
    neighbors = generator.mutation_neighbors(root.values, changed)

    assert seeds[0][0].values == {"toggle": False, "amount": 2}
    assert {item.values["amount"] for item, _ in seeds} == {1, 2, 3}
    assert generator.coverage_metadata["domain_sampling"] is False
    assert all(item.values != root.values for item, _ in neighbors)


def test_mutation_neighbors_limit_applies_before_returning_candidates() -> None:
    parameter = spec("large", {"type": "integer", "min": 0, "max": 100_000,
                               "step": 1, "baseline": 0})
    generator = CombinationGenerator([parameter])
    root, changed = generator.mutation_root()

    neighbors = generator.mutation_neighbors(root.values, changed, limit=3, domain_limit=20)

    assert len(neighbors) <= 3
    assert generator.coverage_metadata["candidate_limit"] == 3
    assert generator.coverage_metadata["candidate_limit_reached"] is True


def test_mutation_root_repairs_incompatible_baseline_within_sampled_domain() -> None:
    network = spec("network", {"type": "enum", "values": ["ws", "tcp"],
                                "baseline": "ws", "path": ["streamSettings", "network"]})
    security = spec("security", {"type": "enum", "values": ["reality"],
                                  "baseline": "reality", "path": ["streamSettings", "security"]})

    root, _ = CombinationGenerator([network, security]).mutation_root()

    assert root.values == {"network": "tcp", "security": "reality"}


def test_mutation_root_fails_explicitly_when_only_fixed_baseline_is_incompatible() -> None:
    network = spec("network", {"type": "enum", "values": ["ws"],
                                "baseline": "ws", "mutate": False,
                                "path": ["streamSettings", "network"]})
    security = spec("security", {"type": "enum", "values": ["reality"],
                                  "baseline": "reality", "mutate": False,
                                  "path": ["streamSettings", "security"]})

    with pytest.raises(ValueError, match="feasible mutation root"):
        CombinationGenerator([network, security]).mutation_root()


def test_zero_candidate_limit_is_not_reported_as_complete_coverage() -> None:
    parameter = spec("value", {"type": "integer", "min": 0, "max": 10, "step": 1})
    generator = CombinationGenerator([parameter])

    assert generator.mutation_seeds(limit=0) == []
    assert generator.coverage_metadata["candidate_limit_reached"] is True
    assert generator.coverage_metadata["coverage_complete"] is False
    assert generator.coverage_metadata["truncated"] is True
