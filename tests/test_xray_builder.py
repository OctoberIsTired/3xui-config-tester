from app.xray.config_builder import ClientConfigBuilder


def test_client_builder_does_not_copy_server_key_material() -> None:
    inbound = {"protocol": "vless", "port": 443, "settings": {"clients": [{"id": "client-id"}]},
               "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {
                   "certificates": [{"keyFile": "/root/private.key"}], "settings": {"fingerprint": "chrome", "pinnedPeerCertSha256": []}}}}
    config = ClientConfigBuilder("example.com").build({}, [], inbound)
    tls = config["outbounds"][0]["streamSettings"]["tlsSettings"]
    assert "certificates" not in tls and tls["fingerprint"] == "chrome" and "pinnedPeerCertSha256" not in tls


def test_client_builder_accepts_explicit_client_tls_identity() -> None:
    inbound = {"protocol": "vless", "port": 443, "settings": {"clients": [{"id": "client-id"}]},
               "streamSettings": {"security": "tls", "tlsSettings": {}}}
    config = ClientConfigBuilder("203.0.113.1", tls_server_name="vpn.example.com",
                                 verify_peer_cert_by_name="vpn.example.com", pinned_peer_cert_sha256="ab" * 32).build({}, [], inbound)
    tls = config["outbounds"][0]["streamSettings"]["tlsSettings"]
    assert tls["serverName"] == "vpn.example.com" and tls["verifyPeerCertByName"] == "vpn.example.com"


def test_client_builder_converts_reality_server_settings_to_client_settings() -> None:
    inbound = {
        "protocol": "vless", "port": 443,
        "settings": {"clients": [{"id": "client-id", "flow": "xtls-rprx-vision"}]},
        "streamSettings": {
            "network": "tcp", "security": "reality",
            "tlsSettings": {"certificates": [{"keyFile": "server.key"}]},
            "realitySettings": {
                "dest": "vpn.example.com:443", "serverNames": ["vpn.example.com"],
                "privateKey": "server-private-key", "shortIds": ["0123456789abcdef"],
                "settings": {"publicKey": "client-public-key", "fingerprint": "chrome", "spiderX": "/"},
            },
        },
    }

    config = ClientConfigBuilder("example.com").build({}, [], inbound)
    stream = config["outbounds"][0]["streamSettings"]
    assert stream["realitySettings"] == {
        "password": "client-public-key", "fingerprint": "chrome", "spiderX": "/",
        "serverName": "vpn.example.com", "shortId": "0123456789abcdef",
    }
    assert "tlsSettings" not in stream
    assert "privateKey" not in str(config)


def test_client_builder_prefers_new_reality_password() -> None:
    inbound = {"protocol": "vless", "port": 443, "settings": {"clients": [{"id": "client-id"}]},
               "streamSettings": {"network": "xhttp", "security": "reality", "realitySettings": {
                   "target": "example.com:443", "serverNames": ["example.com"], "shortIds": ["aabb"],
                   "settings": {"password": "current", "publicKey": "old", "fingerprint": "chrome"}}}}
    reality = ClientConfigBuilder("proxy.example.com").build({}, [], inbound)["outbounds"][0]["streamSettings"]["realitySettings"]
    assert reality["password"] == "current"
    assert "publicKey" not in reality


def test_client_builder_drops_stale_server_security_settings_for_none() -> None:
    inbound = {
        "protocol": "vless", "port": 443,
        "settings": {"clients": [{"id": "client-id"}]},
        "streamSettings": {
            "network": "kcp", "security": "none",
            "tlsSettings": {"certificates": [{"keyFile": "server.key"}]},
            "realitySettings": {"privateKey": "server-private-key"},
        },
    }

    stream = ClientConfigBuilder("example.com").build({}, [], inbound)["outbounds"][0]["streamSettings"]
    assert "tlsSettings" not in stream and "realitySettings" not in stream


def test_client_builder_omits_vision_flow_for_non_tcp_transport() -> None:
    inbound = {
        "protocol": "vless",
        "port": 9443,
        "settings": {"clients": [{"id": "redacted", "flow": "xtls-rprx-vision"}]},
        "streamSettings": {"network": "ws", "security": "tls", "tlsSettings": {}},
    }
    account = ClientConfigBuilder("example.com").build({}, [], inbound)["outbounds"][0]["settings"]["vnext"][0]["users"][0]
    assert "flow" not in account
