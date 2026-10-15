from __future__ import annotations

import copy
import json
from typing import Any, Sequence
from urllib.parse import urlsplit

from app.parameters.mapping import apply_mapping
from app.parameters.models import ParameterSpec
from app.xray.transports import effective_transport


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        value = json.loads(value)
    return copy.deepcopy(value or {})


class ClientConfigBuilder:
    """Build a local Xray SOCKS client from a 3x-ui VLESS/VMess/Trojan inbound."""

    def __init__(self, server_address: str, socks_port: int = 10808, tls_server_name: str | None = None,
                 verify_peer_cert_by_name: str | None = None, pinned_peer_cert_sha256: str | None = None):
        self.server_address = server_address
        self.socks_port = socks_port
        self.tls_server_name = tls_server_name
        self.verify_peer_cert_by_name = verify_peer_cert_by_name
        self.pinned_peer_cert_sha256 = pinned_peer_cert_sha256

    def build(self, parameters: dict[str, Any], specs: Sequence[ParameterSpec], active_inbound: dict[str, Any]) -> dict[str, Any]:
        protocol = active_inbound.get("protocol")
        settings = _json_object(active_inbound.get("settings"))
        clients = settings.get("clients", [])
        if protocol not in {"vless", "vmess", "trojan", "shadowsocks"}:
            raise ValueError(f"Automatic client builder needs a supported inbound; got {protocol!r}")
        if not isinstance(clients, list):
            raise ValueError("Automatic client builder needs an enabled inbound client")
        enabled_clients = [item for item in clients
                           if isinstance(item, dict) and item.get("enable", True) is not False]
        if not enabled_clients:
            raise ValueError("client_credentials_missing: inbound has no enabled client")
        user, port = copy.deepcopy(enabled_clients[0]), int(active_inbound["port"])
        if protocol == "shadowsocks" and settings.get("method"):
            # 3x-ui stores the inbound cipher at settings.method; normalized
            # client records carry passwords but omit a per-client method.
            user["method"] = settings["method"]
        stream = _json_object(active_inbound.get("streamSettings"))
        self._make_client_safe(stream)
        security = stream.get("security", "none")
        if security == "tls":
            tls = stream.setdefault("tlsSettings", {})
            if self.tls_server_name:
                tls["serverName"] = self.tls_server_name
            if self.verify_peer_cert_by_name:
                tls["verifyPeerCertByName"] = self.verify_peer_cert_by_name
            if self.pinned_peer_cert_sha256:
                tls["pinnedPeerCertSha256"] = self.pinned_peer_cert_sha256
        config = {"log": {"loglevel": "warning"},
                  "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": self.socks_port,
                                "protocol": "socks", "settings": {"udp": True}}],
                  "outbounds": [self._outbound(protocol, user, port, stream), {"tag": "direct", "protocol": "freedom"}]}
        return apply_mapping(config, parameters, specs, target_name="client")

    @staticmethod
    def _make_client_safe(stream: dict[str, Any]) -> None:
        """Translate 3x-ui's server-side settings into safe Xray outbound settings."""
        security = stream.get("security", "none")
        if security == "tls":
            tls = _json_object(stream.get("tlsSettings"))
            # 3x-ui stores client-facing TLS options in `settings`, alongside
            # server-only certificates and keys. Outbounds accept the options
            # directly and must never receive server key material.
            nested = _json_object(tls.get("settings"))
            allowed = {
                "serverName", "minVersion", "maxVersion", "cipherSuites", "alpn",
                "enableSessionResumption", "allowInsecure", "disableSystemRoot",
                "fingerprint", "echConfigList", "pinnedPeerCertSha256",
                "verifyPeerCertByName",
            }
            client_tls = {key: tls[key] for key in allowed if key in tls}
            for key in ("fingerprint", "echConfigList", "pinnedPeerCertSha256", "verifyPeerCertByName"):
                value = nested.get(key)
                # Inbound certificate pins are a list; outbound pins use one string.
                if value is not None and not (key == "pinnedPeerCertSha256" and not isinstance(value, str)):
                    client_tls[key] = value
            stream["tlsSettings"] = client_tls
            stream.pop("realitySettings", None)
        elif security == "reality":
            reality = _json_object(stream.get("realitySettings"))
            nested = _json_object(reality.get("settings"))
            client_reality = {key: nested[key] for key in (
                "fingerprint", "serverName", "shortId", "spiderX", "mldsa65Verify",
            ) if key in nested and nested[key] not in (None, "")}
            # Xray calls the client-side public key `password`; 3x-ui and old
            # inbound exports may still store it as `publicKey`.
            password = (nested.get("password") or nested.get("publicKey") or
                        reality.get("password") or reality.get("publicKey"))
            if password:
                client_reality["password"] = password
            if "serverName" not in client_reality:
                names = reality.get("serverNames") or []
                if names:
                    client_reality["serverName"] = names[0]
                elif reality.get("dest"):
                    host = urlsplit("//" + str(reality["dest"])).hostname
                    if host:
                        client_reality["serverName"] = host
            if "shortId" not in client_reality:
                short_ids = reality.get("shortIds") or []
                if short_ids:
                    client_reality["shortId"] = short_ids[0]
            stream["realitySettings"] = client_reality
            stream.pop("tlsSettings", None)
        else:
            # Stale settings from a previously selected security mode are not
            # part of the client profile and can contain server-only material.
            stream.pop("tlsSettings", None)
            stream.pop("realitySettings", None)
        if effective_transport(stream) == "ws":
            ws = _json_object(stream.get("wsSettings"))
            host = ws.pop("host", None)
            if host:
                ws["host"] = host
            stream["wsSettings"] = ws

    def _outbound(self, protocol: str, user: dict[str, Any], port: int, stream: dict[str, Any]) -> dict[str, Any]:
        if protocol == "vless":
            account = {"id": user["id"], "encryption": user.get("encryption", "none")}
            # A cloned inbound can retain a source user's Vision flow even
            # after its transport was switched. Do not emit incompatible flow
            # settings into the local Xray outbound.
            if (user.get("flow") and effective_transport(stream) == "tcp"
                    and stream.get("security", "none") in {"tls", "reality"}):
                account["flow"] = user["flow"]
            payload = {"vnext": [{"address": self.server_address, "port": port, "users": [account]}]}
        elif protocol == "vmess":
            payload = {"vnext": [{"address": self.server_address, "port": port,
                                   "users": [{"id": user["id"], "alterId": int(user.get("alterId", 0)), "security": user.get("security", "auto")}]}]}
        elif protocol == "trojan":
            payload = {"servers": [{"address": self.server_address, "port": port, "password": user["password"]}]}
        else:
            payload = {"servers": [{"address": self.server_address, "port": port, "method": user["method"], "password": user["password"]}]}
        return {"tag": "proxy", "protocol": protocol, "settings": payload, "streamSettings": stream}
