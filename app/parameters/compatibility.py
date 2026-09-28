"""Compatibility rules for the 3x-ui inbound formats supported by this runner."""
from __future__ import annotations

from typing import Any, Sequence

from app.parameters.models import ParameterSpec
from app.xray.reality import REALITY_TRANSPORTS


def compatible(values: dict[str, Any], specs: Sequence[ParameterSpec], *,
               protocol: str | None = None, source_stream: dict[str, Any] | None = None) -> bool:
    """Check effective values by Xray path, so renamed YAML parameters cannot bypass rules."""
    paths = {spec.path: values[spec.name] for spec in specs if spec.name in values and spec.path}
    stream = source_stream or {}

    def get(*path: str | int) -> Any:
        key = tuple(path)
        if key in paths:
            return paths[key]
        current: Any = stream
        if key[:1] == ("streamSettings",):
            key = key[1:]
        for part in key:
            if not isinstance(current, (dict, list)):
                return None
            try:
                current = current[part]
            except (KeyError, IndexError, TypeError):
                return None
        return current

    network = get("streamSettings", "network")
    security = get("streamSettings", "security")
    if network == "kcp" and security in {"tls", "reality"}:
        return False
    if security == "reality" and network is not None and network not in REALITY_TRANSPORTS:
        return False
    if security == "tls":
        minimum = get("streamSettings", "tlsSettings", "minVersion")
        maximum = get("streamSettings", "tlsSettings", "maxVersion")
        if minimum and maximum:
            try:
                if tuple(map(int, str(minimum).split("."))) > tuple(map(int, str(maximum).split("."))):
                    return False
            except ValueError:
                return False
        alpn = get("streamSettings", "tlsSettings", "alpn")
        if isinstance(alpn, list) and alpn:
            if network == "grpc" and "h2" not in alpn:
                return False
            if network in {"ws", "httpupgrade"} and "http/1.1" not in alpn:
                return False
    flow = get("settings", "clients", 0, "flow")
    if flow == "xtls-rprx-vision" and (protocol not in {None, "vless"} or network not in {None, "tcp"}
                                       or security not in {None, "tls", "reality"}):
        return False
    method = get("streamSettings", "xhttpSettings", "uplinkHTTPMethod")
    mode = get("streamSettings", "xhttpSettings", "mode")
    if network == "xhttp" and method == "GET" and mode not in {None, "packet-up"}:
        return False
    xmux = (get("outbounds", 0, "streamSettings", "xhttpSettings", "xmux")
            or get("streamSettings", "xhttpSettings", "xmux"))
    if network == "xhttp" and isinstance(xmux, dict):
        def positive(value: Any) -> bool:
            try:
                return int(str(value).split("-")[-1]) > 0
            except (ValueError, TypeError):
                return False
        if positive(xmux.get("maxConcurrency")) and positive(xmux.get("maxConnections")):
            return False
    return True
