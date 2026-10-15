from __future__ import annotations

import http.client
import json
import threading
from pathlib import Path
from typing import Any

import pytest
import yaml

from app.parameters.dependencies import conditions_match
from app.parameters.compatibility import compatible
from app.parameters.mapping import apply_mapping
from app.parameters.models import ParameterSpec, validate_active_parameter_paths
from app.web import ExclusiveThreadingHTTPServer, Handler, WebService


def make_spec(name: str, definition: dict[str, Any]) -> ParameterSpec:
    return ParameterSpec.from_dict(name, definition)


@pytest.mark.parametrize(
    "definition",
    [
        {"type": "float", "min": "NaN", "max": 1, "step": 0.1},
        {"type": "float", "min": 0, "max": "Infinity", "step": 0.1},
        {"type": "float", "min": "-Infinity", "max": 1, "step": 0.1},
        {"type": "float", "min": 0, "max": 1, "step": "Infinity"},
        {"type": "integer", "min": 0.5, "max": 2, "step": 1},
        {"type": "integer", "min": 0, "max": 2.5, "step": 1},
        {"type": "integer", "min": 0, "max": 2, "step": 0.5},
    ],
)
def test_numeric_ranges_reject_nonfinite_and_fractional_integer_bounds(definition):
    with pytest.raises(ValueError):
        make_spec("number", definition)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), 10**400],
                         ids=["nan", "positive-infinity", "negative-infinity", "integer-overflow-to-float"])
def test_float_values_must_be_finite_when_represented_as_float(value):
    with pytest.raises(ValueError, match="float values must be finite"):
        make_spec("number", {"type": "float", "values": [value]})


def test_integer_range_accepts_integral_decimal_notation():
    item = make_spec("number", {"type": "integer", "min": "1.0", "max": "3.00", "step": "1.0"})
    assert list(item.iter_values()) == [1, 2, 3]


def test_large_integer_range_uses_exact_bounded_iteration_and_count():
    low = 10**40
    item = make_spec("large", {"type": "integer", "min": low, "max": low + 2, "step": 1})
    assert item.count_values() == 3
    assert list(item.iter_values()) == [low, low + 1, low + 2]


def test_transport_alias_conditions_only_normalize_semantic_network_specs():
    network = make_spec("transport_choice", {"type": "enum", "values": ["websocket"],
                                             "path": ["streamSettings", "network"]})
    assert conditions_match({"transport_choice": {"equals": "ws"}},
                            {"transport_choice": "websocket"}, [network])
    assert not conditions_match({"foo": {"equals": "ws"}}, {"foo": "websocket"})


def test_transport_alias_activates_dependent_mapping_and_policy_rules():
    specs = [
        make_spec("network", {"type": "enum", "values": ["websocket"],
                               "path": ["streamSettings", "network"]}),
        make_spec("path", {"type": "string", "values": ["/ws"], "path": ["streamSettings", "wsSettings", "path"],
                            "conditions": {"network": {"equals": "ws"}}}),
    ]
    result = apply_mapping({}, {"network": "websocket", "path": "/ws"}, specs)
    assert result == {"streamSettings": {"network": "websocket", "wsSettings": {"path": "/ws"}}}

    kcp_specs = [make_spec("network", {"type": "enum", "values": ["mkcp"],
                                        "path": ["streamSettings", "network"]}),
                 make_spec("security", {"type": "enum", "values": ["tls"],
                                          "path": ["streamSettings", "security"]})]
    assert compatible({"network": "mkcp", "security": "tls"}, kcp_specs)
    assert not compatible({"network": "mkcp", "security": "reality"}, kcp_specs)


def test_transport_alias_conditions_are_used_by_generator_without_rewriting_values():
    from app.parameters.generator import Combination, CombinationGenerator

    specs = [
        make_spec("network", {"type": "enum", "values": ["raw"],
                               "path": ["streamSettings", "network"]}),
        make_spec("security", {"type": "enum", "values": ["reality"],
                                "conditions": {"network": {"equals": "tcp"}}}),
        make_spec("policy", {"type": "enum", "values": ["enabled"],
                              "conditions": {"network": {"in": ["tcp", "ws"]}}}),
    ]

    combinations = list(CombinationGenerator(specs).iter_valid())

    expected = {"network": "raw", "security": "reality", "policy": "enabled"}
    assert [item.values for item in combinations] == [expected]
    assert combinations[0].hash == Combination(expected).hash


def test_client_network_path_is_semantic_but_unrelated_raw_enum_is_literal():
    client_network = make_spec("client_network", {"type": "enum", "values": ["websocket"],
                                                    "path": ["outbounds", 0, "streamSettings", "network"]})
    assert conditions_match({"client_network": {"equals": "ws"}},
                            {"client_network": "websocket"}, [client_network])

    unrelated = make_spec("foo", {"type": "enum", "values": ["raw"], "path": ["custom", "mode"]})
    assert not conditions_match({"foo": {"equals": "tcp"}}, {"foo": "raw"}, [unrelated])


def test_method_alias_conditions_are_field_scoped_and_active_writers_conflict():
    from app.parameters.generator import CombinationGenerator

    selector_specs = [
        make_spec("network", {"type": "enum", "values": ["raw"],
                               "path": ["streamSettings", "network"]}),
        make_spec("method", {"type": "enum", "values": ["splithttp"],
                              "path": ["streamSettings", "method"]}),
    ]
    assert conditions_match({"method": {"equals": "xhttp"}},
                            {"network": "ws", "method": "splithttp"}, selector_specs)
    assert not conditions_match({"network": {"equals": "xhttp"}},
                                {"network": "ws", "method": "splithttp"}, selector_specs)

    with pytest.raises(ValueError, match="active_transport_method_conflict"):
        list(CombinationGenerator(selector_specs).iter_valid())


def test_inactive_method_default_does_not_override_network_conditions():
    from app.parameters.generator import CombinationGenerator

    specs = [
        make_spec("network", {"type": "enum", "values": ["raw"],
                               "path": ["streamSettings", "network"]}),
        make_spec("method", {"type": "enum", "values": ["splithttp"],
                              "path": ["streamSettings", "method"],
                              "conditions": {"network": {"equals": "ws"}}}),
        make_spec("tcp_knob", {"type": "boolean", "values": [True],
                                "path": ["streamSettings", "tcpSettings", "header"],
                                "conditions": {"network": {"equals": "tcp"}}}),
    ]

    combinations = list(CombinationGenerator(specs).iter_valid())

    assert [item.values for item in combinations] == [{"network": "raw", "tcp_knob": True}]


def test_float_range_rejects_a_step_that_cannot_advance_values():
    with pytest.raises(ValueError, match="step does not advance"):
        make_spec("number", {"type": "float", "min": "1e20", "max": "1.00000000000000000005e20", "step": 1})


@pytest.mark.parametrize("component", [True, False, -1, -2])
def test_paths_reject_boolean_and_negative_list_indices(component):
    with pytest.raises(ValueError, match="path must be a list"):
        make_spec("bad_path", {"type": "string", "values": ["x"], "path": ["items", component]})


@pytest.mark.parametrize(
    "paths",
    [
        (["settings", "network"], ["settings", "network"]),
        (["settings"], ["settings", "network"]),
        (["settings", "network"], ["settings"]),
    ],
)
def test_mapping_rejects_duplicate_and_parent_child_writes(paths):
    specs = [
        make_spec("first", {"type": "string", "values": ["one"], "path": paths[0]}),
        make_spec("second", {"type": "string", "values": ["two"], "path": paths[1]}),
    ]
    with pytest.raises(ValueError, match="overlapping paths"):
        apply_mapping({}, {"first": "one", "second": "two"}, specs)


def test_conditional_overlaps_are_checked_only_for_the_active_values():
    specs = [
        make_spec("mode", {"type": "enum", "values": ["a", "b"], "path": ["mode"]}),
        make_spec("left", {"type": "string", "values": ["left"], "path": ["settings", "value"],
                            "conditions": {"mode": {"equals": "a"}}}),
        make_spec("right", {"type": "string", "values": ["right"], "path": ["settings", "value"],
                             "conditions": {"mode": {"equals": "b"}}}),
    ]
    values_a = {"mode": "a", "left": "left", "right": "right"}
    values_b = {"mode": "b", "left": "left", "right": "right"}
    validate_active_parameter_paths({"mode": "a", "left": "left"}, specs)
    validate_active_parameter_paths({"mode": "b", "right": "right"}, specs)
    assert apply_mapping({}, values_a, specs) == {"mode": "a", "settings": {"value": "left"}}
    assert apply_mapping({}, values_b, specs) == {"mode": "b", "settings": {"value": "right"}}


def test_path_overlap_checks_are_independent_per_target():
    specs = [
        make_spec("inbound", {"type": "string", "values": ["server"], "path": ["x"]}),
        make_spec("client", {"type": "string", "values": ["client"], "path": ["x", "y"], "target": "client"}),
    ]
    values = {"inbound": "server", "client": "client"}
    validate_active_parameter_paths(values, specs)
    assert apply_mapping({}, values, specs, target_name="inbound") == {"x": "server"}
    assert apply_mapping({}, values, specs, target_name="client") == {"x": {"y": "client"}}


def test_context_control_is_kept_when_detecting_active_path_overlaps():
    specs = [
        make_spec("flag", {"type": "boolean", "values": [True], "target": "context", "path": [],
                            "conditions": None}),
        make_spec("left", {"type": "string", "values": ["left"], "path": ["same"],
                            "conditions": {"flag": {"equals": True}}}),
        make_spec("right", {"type": "string", "values": ["right"], "path": ["same"],
                             "conditions": {"flag": {"equals": True}}}),
    ]
    values = {"flag": True, "left": "left", "right": "right"}
    with pytest.raises(ValueError, match="overlapping paths"):
        apply_mapping({}, values, specs)


@pytest.mark.parametrize(
    "value",
    [[float("nan")], {"alpn": ["h2", float("inf")]}, {float("-inf"): "bad"}],
    ids=["nan-list-leaf", "infinity-nested-leaf", "infinity-dict-key"],
)
def test_structured_enum_values_reject_nonfinite_numeric_leaves(value):
    with pytest.raises(ValueError, match="enum values must not contain non-finite numbers"):
        make_spec("structured", {"type": "enum", "values": [value]})


def test_structured_enum_string_named_infinity_is_still_valid():
    assert make_spec("name", {"type": "enum", "values": ["Infinity"]}).values == ("Infinity",)


@pytest.mark.parametrize(
    "minimum,maximum",
    [("NaN", 1), ("-Infinity", 1), (0, "Infinity")],
)
def test_preview_rejects_nonfinite_numeric_ranges_with_http_400(tmp_path: Path, minimum, maximum):
    config_path = tmp_path / "local-test.yaml"
    config_path.write_text(yaml.safe_dump({"panel": {"url": ""}, "inbound": {"mode": "clone", "source_id": 1},
                                              "parameters": {}, "testing": {},
                                              "output": {"directory": str(tmp_path / "results")}}),
                          encoding="utf-8")
    previous_service = getattr(Handler, "service", None)
    Handler.service = WebService(config_path)
    server = ExclusiveThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        raw = {
            "panel": {"url": ""},
            "inbound": {"mode": "clone", "source_id": 1},
            "parameters": {"number": {"type": "float", "min": minimum, "max": maximum, "step": 1}},
            "testing": {"server_address": "198.51.100.7", "combination_strategy": "exhaustive",
                        "max_combinations": 5},
            "output": {"directory": str(tmp_path / "results"), "formats": ["json"]},
        }
        connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
        try:
            body = json.dumps(raw).encode("utf-8")
            connection.request("POST", "/api/preview", body=body,
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            payload = json.loads(response.read())
            assert response.status == 400
            assert payload["error"] == "ValueError"
        finally:
            connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        if previous_service is None:
            delattr(Handler, "service")
        else:
            Handler.service = previous_service
