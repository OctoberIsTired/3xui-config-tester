"""Safe, stable diagnostics for Xray settings with known no-op behavior."""
from __future__ import annotations

from typing import Any

from app.xray.transports import effective_transport


def kcp_noop_diagnostics(config: dict[str, Any]) -> list[dict[str, str]]:
    """Report KCP fields ignored by the pinned Xray 26.9.9 core.

    The diagnostics deliberately contain no values from the client config. They
    describe a no-op; they do not reject the profile or claim incompatibility.
    """
    stream = _client_stream(config)
    if not stream or effective_transport(stream) != "kcp":
        return []
    settings = stream.get("kcpSettings")
    if not isinstance(settings, dict):
        return []

    diagnostics: list[dict[str, str]] = []
    seed = settings.get("seed")
    if seed not in (None, ""):
        diagnostics.append({
            "code": "kcp_seed_ignored_by_core",
            "message": "KCP seed is ignored by the pinned Xray 26.9.9 core; changing it does not change the tunnel.",
        })
    header = settings.get("header")
    header_type = header.get("type") if isinstance(header, dict) else None
    if header_type not in (None, "", "none"):
        diagnostics.append({
            "code": "kcp_header_ignored_by_core",
            "message": "The KCP header setting is ignored by the pinned Xray 26.9.9 core; changing it does not change the tunnel.",
        })
    return diagnostics


def _client_stream(config: Any) -> dict[str, Any] | None:
    if not isinstance(config, dict):
        return None
    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list) or not outbounds or not isinstance(outbounds[0], dict):
        return None
    stream = outbounds[0].get("streamSettings")
    return stream if isinstance(stream, dict) else None
