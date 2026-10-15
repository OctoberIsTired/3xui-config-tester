from __future__ import annotations

import json
import shutil
import subprocess
from collections import OrderedDict
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from app.parameters.generator import configuration_hash
from app.security.private_files import secure_directory, secure_file
from app.xray.transports import effective_transport

# Reason codes end up in results.jsonl, so keep the strings stable.
CLIENT_CONFIG_INVALID = "client_config_invalid"
CORE_REJECTED = "client_config_rejected_by_xray"

PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks"}
NETWORKS = {"tcp", "kcp", "ws", "httpupgrade", "xhttp", "grpc"}
SECURITIES = {"none", "tls", "reality"}
VISION_FLOWS = {"xtls-rprx-vision", "xtls-rprx-vision-udp443"}

# Availability states are warnings only in explicit non-strict mode. Required
# validation stops during preflight or before applying the candidate.
CHECK_DISABLED = "config_check_disabled"
CHECK_BINARY_MISSING = "xray_binary_missing"
CHECK_BINARY_UNUSABLE = "xray_binary_unusable"
CHECK_UNSUPPORTED = "xray_config_test_unsupported"
CHECK_FAILED = "xray_config_test_failed"
CHECK_TIMEOUT = "xray_config_test_timeout"


class CoreValidationUnavailable(RuntimeError):
    """The required local Xray check could not produce a verdict."""

    def __init__(self, reason_code: str):
        super().__init__(f"xray_core_validation_unavailable:{reason_code}")
        self.reason_code = reason_code

# Xray's own rejection messages, mapped to short codes. The raw text is never
# kept: it can carry client identifiers, addresses and REALITY key material.
_CORE_ERROR_CODES = (
    ("json_syntax_error", ("failed to decode config", "invalid character")),
    ("unsupported_transport", ("unknown transport protocol",)),
    ("unsupported_cipher", ("unknown cipher method",)),
    ("plaintext_public_destination", ("prohibited unless the server address",)),
    ("reality_parameters_invalid", ("failed to build reality config",)),
    ("unknown_field", ("unknown field",)),
)


def _valid_port(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535


def _usable_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def check_client_config(config: Any) -> str | None:
    """Reject a client config Xray cannot build, without spawning a process.

    This mirrors the structural rules of the core config loader for the parts
    the builder controls. It is a fast pre-filter only: the local Xray binary
    stays the authority on everything else (see `ClientConfigValidator`).
    """
    if not isinstance(config, dict):
        return CLIENT_CONFIG_INVALID
    inbounds = config.get("inbounds")
    socks = ([item for item in inbounds if isinstance(item, dict) and item.get("protocol") == "socks"]
             if isinstance(inbounds, list) else [])
    if not socks:
        return "client_socks_inbound_missing"
    if any(not _valid_port(item.get("port")) for item in socks):
        return "client_socks_port_invalid"
    outbounds = config.get("outbounds")
    outbound = (outbounds[0] if isinstance(outbounds, list) and outbounds
                and isinstance(outbounds[0], dict) else None)
    if outbound is None:
        return "client_outbound_missing"
    protocol = outbound.get("protocol")
    if protocol not in PROTOCOLS:
        return "client_outbound_protocol_unsupported"
    options = outbound.get("settings")
    if not isinstance(options, dict):
        return CLIENT_CONFIG_INVALID
    if protocol in {"vless", "vmess"}:
        candidates = options.get("vnext")
        servers = [item for item in candidates if isinstance(item, dict)] if isinstance(candidates, list) else []
        if not servers:
            return "client_outbound_missing"
        server, account = servers[0], None
        users = server.get("users")
        if isinstance(users, list) and users and isinstance(users[0], dict):
            account = users[0]
        if account is None or not _usable_string(account.get("id")):
            return "client_credentials_missing"
        if protocol == "vless" and account.get("encryption", "none") not in {"", "none"}:
            return "client_encryption_unsupported"
    else:
        candidates = options.get("servers")
        servers = [item for item in candidates if isinstance(item, dict)] if isinstance(candidates, list) else []
        if not servers:
            return "client_outbound_missing"
        server, account = servers[0], None
        if not _usable_string(server.get("password")) or (protocol == "shadowsocks" and not _usable_string(server.get("method"))):
            return "client_credentials_missing"
    if not _usable_string(server.get("address")) or not _valid_port(server.get("port")):
        return "client_server_address_invalid"
    stream = outbound.get("streamSettings")
    if not isinstance(stream, dict):
        return "client_stream_settings_invalid"
    network, security = effective_transport(stream), stream.get("security", "none")
    if network not in NETWORKS:
        return "client_transport_unsupported"
    if security not in SECURITIES:
        return "client_security_unsupported"
    flow = account.get("flow") if isinstance(account, dict) and protocol == "vless" else None
    # xtls-rprx-vision is raw-TCP-only and needs TLS or REALITY around it.
    if flow and (flow not in VISION_FLOWS or network != "tcp" or security not in {"tls", "reality"}):
        return "client_flow_incompatible"
    if security == "reality":
        reality = stream.get("realitySettings")
        if not isinstance(reality, dict) or any(
                not _usable_string(reality.get(key)) for key in ("password", "serverName", "fingerprint")):
            return "client_reality_settings_incomplete"
    mux = outbound.get("mux")
    if mux is not None:
        if not isinstance(mux, dict) or ("enabled" in mux and not isinstance(mux["enabled"], bool)):
            return "client_mux_invalid"
        for key in ("concurrency", "xudpConcurrency"):
            concurrency = mux.get(key)
            if (concurrency is not None and (not isinstance(concurrency, int)
                                             or isinstance(concurrency, bool) or concurrency < -1)):
                return "client_mux_invalid"
    return None


def reason_code_for_output(raw: str | None) -> str:
    """Map the core's rejection message to a stable code; never keep the text."""
    lowered = (raw or "").lower()
    for code, phrases in _CORE_ERROR_CODES:
        if any(phrase in lowered for phrase in phrases):
            return f"client_config_{code}"
    return CORE_REJECTED


class ClientConfigValidator:
    """Validate a client config with the local Xray core before it is started.

    Xray's own `run -test` mode parses and builds the config without opening a
    listener or dialing anything, so it reports rejected transports, ciphers,
    REALITY parameters and address rules that no local check can predict. The
    command family is identical to the one used for a real run, which keeps the
    verdict faithful to the process that would be started next.
    """

    def __init__(self, binary: str = "xray", *, enabled: bool = True, strict: bool = True, timeout: float = 15,
                 config_directory: Path | None = None):
        self.binary, self.enabled, self.strict, self.timeout = binary, enabled, strict, timeout
        self.config_directory = config_directory
        self._availability: str | None = None
        self._probed = False
        self._probed_identity: tuple[Any, ...] | None = None
        self._cache: OrderedDict[tuple[str, tuple[Any, ...]], str | None] = OrderedDict()
        self._cache_limit = 256

    def availability(self, *, retry: bool = False) -> str | None:
        """Return the last availability outcome; optionally retry a transient failure."""
        identity = self._core_identity()
        if identity != self._probed_identity:
            self._probed = False
            self._availability = None
            self._probed_identity = identity
        if retry and self._availability in {CHECK_TIMEOUT, CHECK_FAILED, CHECK_BINARY_UNUSABLE}:
            self._probed = False
        if not self._probed:
            self._availability = self._probe()
            self._probed = True
        return self._availability

    def _probe(self) -> str | None:
        if not self.enabled:
            return CHECK_DISABLED
        try:
            completed = subprocess.run([self.binary, "help", "run"], capture_output=True, text=True,
                                       timeout=self.timeout)
        except OSError:
            return CHECK_BINARY_MISSING
        except subprocess.SubprocessError:
            return CHECK_BINARY_UNUSABLE
        if completed.returncode != 0:
            return CHECK_BINARY_UNUSABLE
        return None if "-test" in f"{completed.stdout}{completed.stderr}" else CHECK_UNSUPPORTED

    def _core_identity(self) -> tuple[Any, ...]:
        """Identify the executable currently selected by the configured path/PATH.

        Include file metadata in the cache key so replacing an Xray binary in place
        cannot reuse a verdict produced by the previous core. The configured command
        remains part of the identity when it cannot be resolved or statted.
        """
        resolved = shutil.which(self.binary) or self.binary
        path = Path(resolved).expanduser()
        try:
            path = path.resolve()
            stat = path.stat()
            return (str(path), stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
        except OSError:
            return (str(path), None, None, None)

    def check(self, config: dict[str, Any]) -> tuple[bool, str | None]:
        """Return (checked, reason); `checked` False means the core was not asked.

        Identical configs are answered from the cache, because the runner asks
        about the same client config for every repeat of a combination.
        """
        unavailable = self.availability(retry=True)
        if unavailable is not None:
            if self.strict:
                raise CoreValidationUnavailable(unavailable)
            return False, None
        cacheable = not self._has_external_file_dependency(config)
        key = (configuration_hash(config), self._core_identity())
        if cacheable and key in self._cache:
            self._cache.move_to_end(key)
            return True, self._cache[key]
        path: Path | None = None
        try:
            if self.config_directory:
                secure_directory(self.config_directory)
            with NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False,
                                    dir=str(self.config_directory) if self.config_directory else None) as file:
                path = Path(file.name)
                secure_file(path)
                json.dump(config, file)
            completed = subprocess.run([self.binary, "run", "-test", "-c", str(path)], capture_output=True,
                                       text=True, timeout=self.timeout, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            self._fail(CHECK_TIMEOUT)
            if self.strict:
                raise CoreValidationUnavailable(CHECK_TIMEOUT)
            return False, None
        except (OSError, subprocess.SubprocessError):
            self._fail(CHECK_FAILED)
            if self.strict:
                raise CoreValidationUnavailable(CHECK_FAILED)
            return False, None
        finally:
            if path is not None:
                path.unlink(missing_ok=True)
        reason = reason_code_for_output(f"{completed.stdout}{completed.stderr}") if completed.returncode else None
        deterministic_verdict = completed.returncode == 0 or reason != CORE_REJECTED
        if cacheable and deterministic_verdict:
            self._cache[key] = reason
            self._cache.move_to_end(key)
            while len(self._cache) > self._cache_limit:
                self._cache.popitem(last=False)
        return True, reason

    @classmethod
    def _has_external_file_dependency(cls, value: Any) -> bool:
        """Avoid reusing a verdict when a referenced file may have changed."""
        external_keys = {"geoip", "geosite", "certificate", "privatekey", "key"}
        if isinstance(value, dict):
            for key, child in value.items():
                normalized = str(key).replace("_", "").lower()
                if "file" in normalized or normalized in external_keys:
                    return True
                if cls._has_external_file_dependency(child):
                    return True
        elif isinstance(value, list):
            return any(cls._has_external_file_dependency(item) for item in value)
        elif isinstance(value, str):
            lowered = value.strip().lower()
            return lowered.startswith(("geoip:", "geosite:", "ext:", "file:", "file://"))
        return False

    def _fail(self, state: str) -> None:
        """Keep the last failure visible; the next `check` explicitly retries it."""
        self._availability, self._probed = state, True
