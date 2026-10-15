from __future__ import annotations

import re
import json
import threading
from typing import Any, Iterable
from urllib.parse import quote, quote_plus

_SECRET_KEY = re.compile(r"(password|token|secret|private.?key|public.?key|short.?id|credential|cookie|authorization)", re.I)
_IDENTITY_KEY = re.compile(r"(^|[._])(username|uuid|client.?id|email|psk)($|[._])", re.I)
_BEARER = re.compile(r"(?i)(bearer\s+)[^\s\"',;}\]]+")


def mask_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: "***" if _SECRET_KEY.search(str(key)) else mask_secrets(item) for key, item in value.items()}
    if isinstance(value, list):
        return [mask_secrets(item) for item in value]
    if isinstance(value, tuple):
        return tuple(mask_secrets(item) for item in value)
    if isinstance(value, str):
        return _BEARER.sub(r"\1***", value)
    return value


class SecretRedactor:
    """Redact known credentials even when they occur in an unstructured error.

    Add configuration and panel snapshots before passing text to a public sink.
    The context only keeps literal string credentials in memory; it is never
    serialized into checkpoints or reports. ``add(str)`` registers an explicit
    secret, while ``add(mapping)`` discovers sensitive fields recursively.
    """

    def __init__(self, values: Iterable[str] = ()):
        self._lock = threading.RLock()
        self._values: set[str] = set()
        for value in values:
            self.add(value)

    @classmethod
    def from_config(cls, config: Any) -> "SecretRedactor":
        redactor = cls()
        if isinstance(config, dict):
            redactor.add(config)
            parameters = config.get("parameters", {})
            for name, definition in parameters.items():
                if isinstance(definition, dict) and redactor._sensitive_path(name, definition.get("path", ())):
                    redactor._add_literals(definition.get("values", ()))
                    redactor._add_literals(definition.get("baseline"))
        else:
            for section in ("panel", "inbound", "testing"):
                redactor.add(getattr(config, section, {}))
            for parameter in getattr(config, "parameters", ()):
                if redactor._sensitive_path(parameter.name, parameter.path):
                    redactor._add_literals(parameter.values or ())
                    redactor._add_literals(parameter.baseline)
        return redactor

    @staticmethod
    def _sensitive_path(name: str, path: Iterable[Any]) -> bool:
        parts = tuple(map(str, path))
        joined = ".".join((name, *parts))
        return bool(_SECRET_KEY.search(joined) or _IDENTITY_KEY.search(joined) or
                    (parts and parts[-1] == "id" and any(part in {"clients", "users"} for part in parts)))

    def _add_literals(self, value: Any) -> None:
        if isinstance(value, str):
            if not value or value == "***" or value.startswith("${"):
                return
            with self._lock:
                self._values.update((value, quote(value, safe=""), quote_plus(value),
                                     json.dumps(value, ensure_ascii=False)[1:-1]))
        elif isinstance(value, dict):
            for item in value.values():
                self._add_literals(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                self._add_literals(item)

    def add(self, value: Any) -> "SecretRedactor":
        if isinstance(value, str):
            self._add_literals(value)
        else:
            self._collect(value)
        return self

    def _collect(self, value: Any, path: tuple[str, ...] = ()) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                current = (*path, str(key))
                if key == "parameters" and isinstance(item, dict):
                    for name, definition in item.items():
                        if isinstance(definition, dict) and self._sensitive_path(name, definition.get("path", ())):
                            self._add_literals(definition.get("values", ()))
                            self._add_literals(definition.get("baseline"))
                elif self._sensitive_path(str(key), current):
                    self._add_literals(item)
                elif isinstance(item, str) and item.lstrip().startswith(("{", "[")):
                    # 3x-ui stores settings/streamSettings as JSON strings.
                    try:
                        self._collect(json.loads(item), current)
                    except (TypeError, ValueError):
                        pass
                else:
                    self._collect(item, current)
        elif isinstance(value, (list, tuple)):
            for item in value:
                self._collect(item, path)

    def redact_text(self, text: str) -> str:
        with self._lock:
            values = sorted(self._values, key=len, reverse=True)
        for secret in values:
            text = text.replace(secret, "***")
        return str(mask_secrets(text))

    def redact(self, value: Any) -> Any:
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                if key == "parameters" and isinstance(item, dict):
                    result[key] = {name: self._redact_definition(name, definition)
                                   if isinstance(definition, dict) else self.redact(definition)
                                   for name, definition in item.items()}
                elif _SECRET_KEY.search(str(key)):
                    result[key] = self._redact_definition(str(key), item) if isinstance(item, dict) and "type" in item and "path" in item else "***"
                else:
                    result[key] = self.redact(item)
            return result
        if isinstance(value, list):
            return [self.redact(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.redact(item) for item in value)
        if isinstance(value, str):
            return self.redact_text(value)
        return value

    def _redact_definition(self, name: str, definition: dict[str, Any]) -> dict[str, Any]:
        result = {key: self.redact(item) for key, item in definition.items()}
        if self._sensitive_path(name, definition.get("path", ())):
            for key in ("baseline", "current", "min", "max", "step"):
                if key in result:
                    result[key] = "***"
            if "values" in result:
                result["values"] = ["***" for _ in definition.get("values", ())]
        return result

    __call__ = redact


_UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_LONG_HEX = re.compile(r"\b[0-9a-fA-F]{24,}\b")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_KEYED_SECRET = re.compile(
    r"(?i)\b(password|passwd|secret|token|privatekey|private_key|publickey|public_key|shortid|short_id|id|uuid|email|psk)\"?\s*[:=]\s*\"?[^\s\",;}\]]+")


def mask_log_text(value: str) -> str:
    """Mask identity material inside raw Xray log text.

    Client logs name the outbound identity (client UUID, REALITY keys, login),
    so only a masked tail may be written into the run directory.
    """
    text = _UUID.sub("***", value)
    text = _LONG_HEX.sub("***", text)
    text = _EMAIL.sub("***", text)
    text = _KEYED_SECRET.sub(lambda match: f"{match.group(1)}=***", text)
    return _BEARER.sub(r"\1***", text)


# A 3x-ui inbound payload mixes the experimental listener with panel bookkeeping
# and client identity. The template keeps the first and drops/masks the rest.
_INBOUND_VOLATILE_KEYS = ("id", "userId", "clientStats", "clientsStats", "up", "down", "total", "expiryTime")
_INBOUND_CREDENTIAL_KEY = re.compile(
    r"(?i)^(id|uuid|user_?id|email|password|passwd|psk|secret|secret_?key|private_?key|public_?key|"
    r"pre_?shared_?key|short_?ids?|shortid|spider_?x|sub_?id|auth|credential|credentials|token|"
    r"cookie|authorization|server_?key|seed)$"
)
# 3x-ui keeps these as JSON text inside the inbound object.
INBOUND_SERIALIZED_FIELDS = frozenset({"settings", "streamSettings", "sniffing", "allocate"})


def mask_inbound_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Turn an applied inbound payload into a copy-pasteable, credential-free template.

    The export ships the tested inbound so the user can rebuild it in the panel
    editor, but it must not publish panel material: client credentials, REALITY
    keys and short IDs become ``***`` (the panel editor knows the real source
    identity). Port, protocol, transport, sockopt and sniffing survive, so the
    pasted configuration stays structurally complete. Panel bookkeeping that a
    create-inbound request must not carry is dropped.
    """
    template = {key: value for key, value in payload.items() if key not in _INBOUND_VOLATILE_KEYS}
    return _mask_inbound_value(template)


def _mask_inbound_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: (_mask_inbound_credentials(item) if _INBOUND_CREDENTIAL_KEY.search(str(key))
                      else _mask_inbound_value(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [_mask_inbound_value(item) for item in value]
    if isinstance(value, str):
        # settings/streamSettings/sniffing arrive as JSON text; keep that shape.
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return value
        if isinstance(parsed, (dict, list)):
            return json.dumps(_mask_inbound_value(parsed), ensure_ascii=False, separators=(",", ":"))
    return value


def _mask_inbound_credentials(value: Any) -> Any:
    """Mask credential leaves while keeping the container shape the panel expects."""
    if isinstance(value, list):
        return [_mask_inbound_credentials(item) for item in value]
    if isinstance(value, dict):
        return {key: _mask_inbound_credentials(item) for key, item in value.items()}
    if value is None or value == "":
        return value
    if isinstance(value, (str, int, float, bool)):
        return "***"
    return value


def mask_parameter_values(values: dict[str, Any], parameters: Iterable[Any]) -> dict[str, Any]:
    """Also hide values mapped to a secret path under an innocuous parameter name."""
    by_name = {parameter.name: parameter for parameter in parameters}
    public: dict[str, Any] = {}
    for name, value in values.items():
        parameter = by_name.get(name)
        path = parameter.path if parameter is not None else ()
        public[name] = "***" if SecretRedactor._sensitive_path(name, path) else mask_secrets(value)
    return public
