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
        "kcp": {"none"},
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
        assert not any(row["transport_choice"] == "kcp" and row["protection_choice"] != "none" for row in rows)
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
