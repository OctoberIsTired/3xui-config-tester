from app.xray.diagnostics import kcp_noop_diagnostics


def config_for(stream_settings):
    return {"outbounds": [{"protocol": "vless", "streamSettings": stream_settings}]}


def test_kcp_seed_and_header_are_diagnosed_without_rejection_or_echoing_values():
    config = config_for({"network": "mkcp", "security": "none", "kcpSettings": {
        "seed": "CUSTOM_PATH_SHOULD_NOT_LEAK", "header": {"type": "srtp"},
    }})

    diagnostics = kcp_noop_diagnostics(config)

    assert [item["code"] for item in diagnostics] == [
        "kcp_seed_ignored_by_core", "kcp_header_ignored_by_core",
    ]
    rendered = repr(diagnostics)
    assert "CUSTOM_PATH_SHOULD_NOT_LEAK" not in rendered
    assert "srtp" not in rendered
    assert all(set(item) == {"code", "message"} for item in diagnostics)


def test_default_kcp_header_and_numeric_settings_have_no_noop_warning():
    config = config_for({"network": "kcp", "security": "none", "kcpSettings": {
        "header": {"type": "none"}, "mtu": 1350, "tti": 20,
    }})

    assert kcp_noop_diagnostics(config) == []


def test_non_kcp_transport_does_not_report_kcp_fields():
    config = config_for({"network": "ws", "wsSettings": {"path": "/custom"},
                         "kcpSettings": {"seed": "ignored"}})

    assert kcp_noop_diagnostics(config) == []


def test_malformed_or_missing_client_stream_is_ignored_safely():
    assert kcp_noop_diagnostics({}) == []
    assert kcp_noop_diagnostics({"outbounds": "invalid"}) == []
    assert kcp_noop_diagnostics({"outbounds": [{"streamSettings": None}]}) == []
