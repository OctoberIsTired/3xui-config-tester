from app.parameters.dependencies import conditions_match
from app.parameters.generator import CombinationGenerator, configuration_hash
from app.parameters.mapping import apply_mapping
from app.parameters.models import ParameterSpec
from app.parameters.registry import parameter_registry
import json
from pathlib import Path

from app.config import ExperimentConfig, load_config
import pytest


def parameter(name: str, data: dict) -> ParameterSpec:
    return ParameterSpec.from_dict(name, data)


def test_conditions_match_accepts_precomputed_transport_names() -> None:
    """Горячий цикл построения плана передаёт frozenset транспортно-семантических
    имён вместо повторного разбора спецификаций: результат обязан совпадать."""
    from app.parameters.dependencies import conditions_match, semantic_transport_names
    from app.parameters.models import ParameterSpec

    specs = (
        ParameterSpec.from_dict("network", {"type": "enum", "values": ["tcp", "ws"],
                                            "path": ["streamSettings", "network"]}),
        ParameterSpec.from_dict("security", {"type": "enum", "values": ["tls"],
                                             "path": ["streamSettings", "security"]}),
    )
    rule = {"network": {"equals": "tcp"}}
    values = {"network": "raw", "security": "tls"}
    names = semantic_transport_names(specs)
    assert "network" in names and "security" not in names
    assert conditions_match(rule, values, specs) is conditions_match(rule, values, specs, names) is True


def test_reality_candidate_list_owns_client_identity() -> None:
    security = parameter("security", {"type": "enum", "values": ["none", "reality"],
                                      "path": ["streamSettings", "security"]})
    candidates = [{"target": "www.example.com:443", "server_name": "www.example.com"}]

    def config(*extra: ParameterSpec) -> ExperimentConfig:
        return ExperimentConfig(panel={}, inbound={}, parameters=(security, *extra),
                                testing={"reality": {"candidates": candidates}})

    assert config().search_parameters()[-1].name == "reality_profile"
    with pytest.raises(ValueError, match="reality_server_name"):
        config(parameter("reality_server_name", {"type": "string", "values": ["example.com"], "target": "client",
                                                 "path": ["outbounds", 0, "streamSettings", "realitySettings",
                                                          "serverName"]})).search_parameters()


def test_numeric_boolean_and_lazy_dependency_generation() -> None:
    network = parameter("network", {"type": "enum", "values": ["tcp", "ws"]})
    path = parameter("ws_path", {"type": "string", "values": ["/", "/ws", "/api"], "conditions": {"network": {"equals": "ws"}}})
    mux = parameter("mux", {"type": "boolean", "values": [True, False]})
    concurrency = parameter("concurrency", {"type": "integer", "min": 1, "max": 3, "step": 1, "conditions": {"mux": {"equals": True}}})
    combinations = CombinationGenerator([network, path, mux, concurrency])
    assert combinations.raw_count == 36
    valid = list(combinations.iter_valid())
    assert len(valid) == 16  # tcp: 1 + ws: 3, each with false: 1 + true: 3
    assert {"network": "tcp", "mux": False} in [item.values for item in valid]


def test_nested_conditions_and_hash_are_stable() -> None:
    rule = {"all": [{"parameter": "network", "equals": "grpc"}, {"any": [{"parameter": "security", "in": ["tls", "reality"]}, {"parameter": "debug", "exists": False}]}]}
    assert conditions_match(rule, {"network": "grpc", "security": "tls"})
    assert not conditions_match(rule, {"network": "ws", "security": "tls"})
    assert configuration_hash({"a": 1, "b": 2}) == configuration_hash({"b": 2, "a": 1})


def test_parameter_mapping_keeps_targets_separate() -> None:
    inbound = parameter("network", {"type": "enum", "values": ["ws"], "path": ["streamSettings", "network"]})
    client = parameter("mux", {"type": "boolean", "values": [True], "target": "client", "path": ["outbounds", 0, "mux", "enabled"]})
    source = {"streamSettings": {"network": "tcp"}, "outbounds": [{"mux": {"enabled": False}}]}
    assert apply_mapping(source, {"network": "ws", "mux": True}, [inbound, client])["streamSettings"]["network"] == "ws"
    assert apply_mapping(source, {"network": "ws", "mux": True}, [inbound, client], "client")["outbounds"][0]["mux"]["enabled"] is True


def test_parameter_mapping_preserves_serialized_3xui_sections() -> None:
    network = parameter("network", {"type": "enum", "values": ["ws"], "path": ["streamSettings", "network"]})
    mapped = apply_mapping({"streamSettings": '{"network":"tcp"}'}, {"network": "ws"}, [network])
    assert isinstance(mapped["streamSettings"], str)
    assert json.loads(mapped["streamSettings"])["network"] == "ws"


def test_structured_enum_values_and_per_value_compatibility() -> None:
    network = parameter("network", {"type": "enum", "values": ["tcp", "ws"]})
    security = parameter("security", {
        "type": "enum",
        "values": ["none", "reality"],
        "value_conditions": [{
            "value": "reality",
            "conditions": {"any": [
                {"parameter": "network", "exists": False},
                {"parameter": "network", "in": ["tcp"]},
            ]},
        }],
    })
    alpn = parameter("alpn", {"type": "enum", "values": [["h2"], ["http/1.1"]]})
    values = [item.values for item in CombinationGenerator([network, security, alpn]).iter_valid()]
    assert len(values) == 6
    assert not any(item["network"] == "ws" and item["security"] == "reality" for item in values)


def test_registry_merges_live_inbound_values() -> None:
    registry = parameter_registry({
        "id": 1, "protocol": "vless", "port": 8443,
        "streamSettings": '{"network":"tcp","security":"tls","tlsSettings":{"settings":{"fingerprint":"random"}}}',
    }, panel_version="3.8.0", xray_version="26.9.9")
    assert len(registry["parameters"]) >= 50
    assert registry["parameters"]["network"]["current"] == "tcp"
    assert registry["parameters"]["tls_fingerprint"]["current"] == "random"
    assert registry["compatibility"]["xray"] == "26.9.9"


def test_example_config_covers_all_supported_transports() -> None:
    expected = {
        "tcp": {"none", "tls", "reality"},
        "kcp": {"none", "tls"},
        "ws": {"none", "tls"},
        "grpc": {"none", "tls", "reality"},
        "httpupgrade": {"none", "tls"},
        "xhttp": {"none", "tls", "reality"},
    }
    root = Path(__file__).resolve().parents[1]
    config = load_config(root / "configs" / "example.yaml")
    specs = [item for item in config.parameters if item.name in {"network", "security"}]
    generated = [item.values for item in CombinationGenerator(specs).iter_valid()]
    assert {item["network"] for item in generated} == set(expected)
    for network, security in expected.items():
        assert {item["security"] for item in generated if item["network"] == network} == security


def test_grpc_tls_alpn_candidates_always_offer_http2() -> None:
    from app.parameters.registry import parameter_registry

    params = parameter_registry()["parameters"]
    assert ["h3"] not in params["tls_alpn"]["values"]
    specs = [
        parameter("network", {"type": "enum", "values": ["grpc"]}),
        parameter("security", {"type": "enum", "values": ["tls"]}),
        parameter("tls_alpn", params["tls_alpn"]),
    ]
    generated = [item.values for item in CombinationGenerator(specs).iter_valid()]
    assert {tuple(item["tls_alpn"]) for item in generated} == {
        ("h2", "http/1.1"), ("h2",),
    }


def test_documented_compatibility_applies_to_custom_yaml_paths() -> None:
    specs = [parameter("transport_choice", {"type": "enum", "values": ["kcp", "tcp", "grpc", "ws", "xhttp"],
                                            "path": ["streamSettings", "network"]}),
             parameter("protection_choice", {"type": "enum", "values": ["none", "tls", "reality"],
                                             "path": ["streamSettings", "security"]}),
             parameter("alpn_choice", {"type": "enum", "values": [["h2"], ["http/1.1"]],
                                       "path": ["streamSettings", "tlsSettings", "alpn"],
                                       "conditions": {"protection_choice": {"equals": "tls"}}})]
    generator = CombinationGenerator(specs)
    for strategy in (generator.iter_valid, generator.pairwise, generator.mutations):
        rows = [item.values for item in strategy()]
        assert rows
        assert not any(row["transport_choice"] == "kcp" and row["protection_choice"] == "reality" for row in rows)
        assert not any(row["transport_choice"] == "ws" and row["protection_choice"] == "reality" for row in rows)
        assert not any(row["transport_choice"] == "grpc" and row.get("alpn_choice") == ["http/1.1"] for row in rows)
        assert not any(row["transport_choice"] == "ws" and row.get("alpn_choice") == ["h2"] for row in rows)


def test_tls_version_xhttp_get_and_xmux_constraints() -> None:
    from app.parameters.compatibility import compatible
    specs = [parameter(name, {"type": "enum", "values": [value], "path": path}) for name, value, path in [
        ("net", "xhttp", ["streamSettings", "network"]),
        ("min", "1.3", ["streamSettings", "tlsSettings", "minVersion"]),
        ("max", "1.2", ["streamSettings", "tlsSettings", "maxVersion"]),
        ("sec", "tls", ["streamSettings", "security"]),
        ("mode", "stream-up", ["streamSettings", "xhttpSettings", "mode"]),
        ("method", "GET", ["streamSettings", "xhttpSettings", "uplinkHTTPMethod"]),
    ]]
    values = {item.name: item.values[0] for item in specs}
    assert not compatible(values, specs)
    values.update({"max": "1.3", "mode": "packet-up"})
    assert compatible(values, specs)


def test_source_protocol_and_stream_rule_out_vision_on_vmess() -> None:
    flow = parameter("my_flow", {"type": "enum", "values": ["", "xtls-rprx-vision"],
                                 "path": ["settings", "clients", 0, "flow"]})
    generator = CombinationGenerator([flow], protocol="vmess",
                                     source_stream={"network": "tcp", "security": "tls"})
    assert [item.values["my_flow"] for item in generator.iter_valid()] == [""]


def test_pairwise_covers_all_pairs_without_full_cartesian_product() -> None:
    parameters = [parameter(name, {"type": "enum", "values": values}) for name, values in {
        "network": ["tcp", "ws", "grpc"],
        "security": ["none", "tls", "reality"],
        "fingerprint": ["chrome", "firefox", "safari"],
        "mux": [False, True],
    }.items()]
    generated = CombinationGenerator(parameters).pairwise()
    assert len(generated) < 3 * 3 * 3 * 2
    for left_index, left in enumerate(parameters):
        for right in parameters[left_index + 1:]:
            for left_value in left.values or ():
                for right_value in right.values or ():
                    assert any(item.values[left.name] == left_value and item.values[right.name] == right_value
                               for item in generated)


def test_pairwise_respects_per_value_compatibility() -> None:
    network = parameter("network", {"type": "enum", "values": ["tcp", "ws"]})
    security = parameter("security", {
        "type": "enum", "values": ["none", "reality"],
        "value_conditions": [{"value": "reality", "conditions": {"network": {"equals": "tcp"}}}],
    })
    generated = CombinationGenerator([network, security]).pairwise()
    assert not any(item.values == {"network": "ws", "security": "reality"} for item in generated)
    assert any(item.values == {"network": "tcp", "security": "reality"} for item in generated)


def test_mutations_start_from_live_baseline_and_activate_dependencies() -> None:
    network = parameter("network", {"type": "enum", "values": ["tcp", "ws"], "baseline": "tcp"})
    security = parameter("security", {"type": "enum", "values": ["none", "tls"], "baseline": "tls"})
    ws_path = parameter("ws_path", {"type": "string", "values": ["/", "/ws"], "baseline": "/",
                                          "conditions": {"network": {"equals": "ws"}}})
    generated = [item.values for item in CombinationGenerator([network, security, ws_path]).mutations()]
    assert generated[0] == {"network": "tcp", "security": "tls"}
    assert {"network": "ws", "security": "tls", "ws_path": "/ws"} in generated
    assert len(generated) < 2 * 2 * 2


def test_adaptive_mutations_keep_fixed_values_and_expand_successful_parent() -> None:
    network = parameter("network", {
        "type": "enum", "values": ["tcp", "ws"], "baseline": "tcp", "mutate": True,
    })
    security = parameter("security", {
        "type": "enum", "values": ["none", "tls"], "baseline": "tls", "mutate": False,
    })
    mux = parameter("mux", {
        "type": "boolean", "values": [False, True], "baseline": False, "mutate": True,
    })
    generator = CombinationGenerator([network, security, mux])

    root, changed = generator.mutation_root()
    assert root.values == {"network": "tcp", "security": "tls", "mux": False}
    first_generation = generator.mutation_neighbors(root.values, changed)
    assert first_generation
    assert all(item.values["security"] == "tls" for item, _ in first_generation)

    network_child, network_changes = next(
        item for item in first_generation if item[0].values["network"] == "ws"
    )
    second_generation = generator.mutation_neighbors(network_child.values, network_changes)
    assert any(item.values == {"network": "ws", "security": "tls", "mux": True}
               for item, _ in second_generation)
    assert all(item.values["security"] == "tls" for item, _ in second_generation)


def test_conditional_pairwise_repairs_pairs_with_both_choices_pinned() -> None:
    from app.parameters.generator import _pair_features
    specs = [parameter(name, {"type": "integer", "values": [0, 1],
                             **({"conditions": {"a": {"equals": 1}}} if name == "c" else {})})
             for name in "abc"]
    generator = CombinationGenerator(specs)
    feasible = set().union(*(_pair_features(item.values) for item in generator.iter_valid()))
    plan = generator.pairwise()
    covered = set().union(*(_pair_features(item.values) for item in plan))
    assert feasible <= covered
    assert any(item.values == {"a": 1, "b": 1, "c": 1} for item in plan)
    assert generator.coverage_metadata["coverage_complete"]
    assert generator.coverage_metadata["unknown_pairs"] == 0


def test_witness_backtracks_any_and_joint_value_conditions() -> None:
    specs = [parameter("a", {"type": "integer", "values": [0, 1]}),
             parameter("b", {"type": "integer", "values": [0, 1]}),
             parameter("c", {"type": "integer", "values": [0, 1], "conditions": {"any": [
                 {"a": {"equals": 1}}, {"b": {"equals": 1}},
             ]}})]
    witness = CombinationGenerator(specs).feasible_witness({0: 0, 2: 1})
    assert witness.status == "feasible"
    assert witness.values == {"a": 0, "b": 1, "c": 1}
    coupled = [parameter(name, {"type": "integer", "values": [0, 1],
                               "value_conditions": [{"value": 1, "conditions": {other: {"equals": 1}}}]})
               for name, other in [("a", "b"), ("b", "a")]]
    generator = CombinationGenerator(coupled)
    assert generator.feasible_witness({0: 1, 1: 1}).status == "feasible"
    assert generator.feasible_witness({0: 1, 1: 0}).status == "infeasible"
    assert generator.feasible_witness({0: 1, 1: 1}, max_nodes=0).status == "unknown"
    assert {tuple(item.values.values()) for item in generator.iter_valid()} == {(0, 0), (1, 1)}


def test_dependency_controls_later_in_yaml_prune_enormous_inactive_domains() -> None:
    dormant = parameter("dormant", {"type": "integer", "min": 0, "max": 10**12, "step": 1,
                                    "conditions": {"enabled": {"equals": True}}})
    enabled = parameter("enabled", {"type": "boolean", "values": [False, True]})

    class Counted(CombinationGenerator):
        visits = 0

        def _normalize(self, full):
            self.visits += 1
            return super()._normalize(full)

    generator = Counted([dormant, enabled])
    iterator = generator.iter_valid()
    assert next(iterator).values == {"enabled": False}
    assert next(iterator).values == {"dormant": 0, "enabled": True}
    assert generator.visits == 2


def test_fixed_values_apply_to_every_strategy_and_hash_stays_legacy() -> None:
    from hashlib import sha256
    specs = [parameter("a", {"type": "integer", "values": [0, 1]}),
             parameter("locked", {"type": "integer", "values": [0, 1], "baseline": 1, "mutate": False})]
    generator = CombinationGenerator(specs)
    for rows in (list(generator.iter_valid()), generator.pairwise(), generator.mutations(), generator.adaptive_frontier(20)):
        assert rows
        assert all(item.values["locked"] == 1 for item in rows)
    assert configuration_hash({"a": 0, "locked": 1}) == sha256(b'{"a":0,"locked":1}').hexdigest()
    assert generator.feasible_witness({1: 0}).status == "infeasible"


def test_truncated_pairwise_reports_unknown_instead_of_complete_coverage() -> None:
    generator = CombinationGenerator([parameter(name, {"type": "integer", "values": [0, 1]}) for name in "abc"])
    rows = generator.pairwise(limit=1)
    assert len(rows) == 1
    metadata = generator.coverage_metadata
    assert metadata["total_pairs"] == 12
    assert metadata["covered_pairs"] == 3
    assert metadata["unknown_pairs"] == 9
    assert not metadata["coverage_complete"]
    assert metadata["truncated"]


def test_adaptive_rescue_finds_joint_change_without_successful_parent() -> None:
    specs = [parameter(name, {"type": "integer", "values": [0, 1], "baseline": 0}) for name in "ab"]
    generator = CombinationGenerator(specs)
    rows = generator.adaptive_frontier(limit=4, seed=17)
    assert rows[0].values == {"a": 0, "b": 0}
    assert {"a": 1, "b": 1} in [item.values for item in rows]
    assert len({item.hash for item in rows}) == 4
    assert [item.hash for item in rows] == [item.hash for item in generator.adaptive_frontier(4, seed=17)]


def test_profile_id_uses_semantic_paths_for_renamed_parameters() -> None:
    specs = [parameter("transport_choice", {"type": "enum", "values": ["xhttp"],
                                           "path": ["streamSettings", "network"]}),
             parameter("protection_choice", {"type": "enum", "values": ["tls"],
                                              "path": ["streamSettings", "security"]})]
    generator = CombinationGenerator(specs, protocol="vless")
    assert generator.profile_id({"transport_choice": "xhttp", "protection_choice": "tls"}) == "vless:xhttp:tls:none"


def test_planning_numeric_ranges_obeys_construction_and_sampling_budgets() -> None:
    specs = [parameter("a", {"type": "integer", "min": 0, "max": 10**9, "step": 1}),
             parameter("b", {"type": "boolean", "values": [False, True]})]
    generator = CombinationGenerator(specs)
    rows = generator.pairwise(limit=2, domain_limit=3, construction_budget=7, max_witness_nodes=3)
    assert len(rows) <= 2
    metadata = generator.coverage_metadata
    assert metadata["domain_sampling"]
    assert metadata["total_pairs"] == 2 * (10**9 + 1)
    assert metadata["construction_nodes"] <= 7
    assert metadata["unknown_pairs"] > 0


def test_cyclic_activation_retains_feasible_witnesses() -> None:
    specs = [parameter(name, {"type": "integer", "values": [0, 1],
                              "conditions": {other: {"equals": 1}}})
             for name, other in [("a", "b"), ("b", "a")]]
    generator = CombinationGenerator(specs)
    assert [item.values for item in generator.iter_valid()] == [{}, {"a": 0}, {"b": 0}, {"a": 1, "b": 1}]
    assert generator.feasible_witness({0: 0}).status == "feasible"


def test_adaptive_uses_unused_pairwise_budget_for_joint_triple_rescue() -> None:
    generator = CombinationGenerator([parameter(name, {"type": "integer", "values": [0, 1], "baseline": 0})
                                      for name in "abcd"])
    assert len(generator.pairwise()) < 12
    rows = generator.adaptive_frontier(12, seed=9)
    assert any(item.values["a"] == item.values["b"] == item.values["c"] == 1 for item in rows)
    assert len(rows) > len(generator.pairwise())
    assert len({item.hash for item in rows}) == len(rows) <= 12


def test_empty_and_single_domain_plans_have_truthful_coverage() -> None:
    empty = CombinationGenerator([])
    assert [item.values for item in empty.iter_adaptive()] == [{}]
    assert empty.coverage_metadata["coverage_complete"]
    single = CombinationGenerator([parameter("a", {"type": "integer", "values": [0, 1, 2]})])
    assert len(single.pairwise(limit=1)) == 1
    assert single.coverage_metadata["total_pairs"] == 0
    assert single.coverage_metadata["unknown_values"] == 2
    assert not single.coverage_metadata["coverage_complete"]
