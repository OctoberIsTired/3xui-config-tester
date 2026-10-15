"""Transport spellings accepted by the pinned Xray v26.9.9 config loader."""
from __future__ import annotations

from functools import lru_cache
from typing import Any


_TRANSPORT_ALIASES = {
    "raw": "tcp", "tcp": "tcp",
    "mkcp": "kcp", "kcp": "kcp",
    "ws": "ws", "websocket": "ws",
    "xhttp": "xhttp", "splithttp": "xhttp",
    "grpc": "grpc", "httpupgrade": "httpupgrade",
}


# The plan builder compares transport-semantic values millions of times per
# construction; the input set is tiny, so memoize the mapping. Unhashable
# arguments bypass the cache instead of failing the caller.
def _normalize_transport_cached(value: str) -> str:
    lowered = value.lower()
    return _TRANSPORT_ALIASES.get(lowered, lowered)


_normalize_transport_memo = lru_cache(maxsize=512)(_normalize_transport_cached)


def normalize_transport(value: Any) -> Any:
    """Return a semantic transport name; leave unknown and removed names visible."""
    if not isinstance(value, str):
        return value
    try:
        return _normalize_transport_memo(value)
    except TypeError:
        return _normalize_transport_cached(value)


def effective_transport(stream_settings: dict[str, Any]) -> Any:
    """Resolve Xray StreamConfig's `method` override before its `network` field."""
    value = stream_settings.get("method")
    if value is None:
        value = stream_settings.get("network", "tcp")
    return normalize_transport(value)
