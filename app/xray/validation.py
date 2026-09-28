from __future__ import annotations

import json
import subprocess
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from app.parameters.generator import configuration_hash

# Reason codes end up in results.jsonl, so keep the strings stable.
CLIENT_CONFIG_INVALID = "client_config_invalid"
CORE_REJECTED = "client_config_rejected_by_xray"

PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks"}
NETWORKS = {"tcp", "kcp", "ws", "httpupgrade", "xhttp", "splithttp", "grpc", "quic"}
SECURITIES = {"none", "tls", "reality"}
VISION_FLOWS = {"xtls-rprx-vision", "xtls-rprx-vision-udp443"}

# Availability states are reported as warnings; a missing check never blocks a run.
CHECK_DISABLED = "config_check_disabled"
CHECK_BINARY_MISSING = "xray_binary_missing"
CHECK_BINARY_UNUSABLE = "xray_binary_unusable"
CHECK_UNSUPPORTED = "xray_config_test_unsupported"
CHECK_FAILED = "xray_config_test_failed"
CHECK_TIMEOUT = "xray_config_test_timeout"

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
    network, security = stream.get("network", "tcp"), stream.get("security", "none")
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
        concurrency = mux.get("concurrency") if isinstance(mux, dict) else None
        if (not isinstance(mux, dict)
                or ("enabled" in mux and not isinstance(mux["enabled"], bool))
                or (concurrency is not None and (not isinstance(concurrency, int)
                                                or isinstance(concurrency, bool) or concurrency < 0))):
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

    def __init__(self, binary: str = "xray", *, enabled: bool = True, timeout: float = 15,
                 config_directory: Path | None = None):
        self.binary, self.enabled, self.timeout = binary, enabled, timeout
        self.config_directory = config_directory
        self._availability: str | None = None
        self._probed = False
        self._cache: dict[str, str | None] = {}

    def availability(self) -> str | None:
        """None when the core check can run; otherwise a stable reason for a warning."""
        if not self._probed:
            self._probed = True
            self._availability = self._probe()
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
        return None if "-test" in f"{completed.stdout}{completed.stderr}" else CHECK_UNSUPPORTED

    def check(self, config: dict[str, Any]) -> tuple[bool, str | None]:
        """Return (checked, reason); `checked` False means the core was not asked.

        Identical configs are answered from the cache, because the runner asks
        about the same client config for every repeat of a combination.
        """
        if self.availability() is not None:
            return False, None
        key = configuration_hash(config)
        if key in self._cache:
            return True, self._cache[key]
        path: Path | None = None
        try:
            if self.config_directory:
                self.config_directory.mkdir(parents=True, exist_ok=True)
            with NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False,
                                    dir=str(self.config_directory) if self.config_directory else None) as file:
                json.dump(config, file)
                path = Path(file.name)
            completed = subprocess.run([self.binary, "run", "-test", "-c", str(path)], capture_output=True,
                                       text=True, timeout=self.timeout, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            self._fail(CHECK_TIMEOUT)
            return False, None
        except (OSError, subprocess.SubprocessError):
            self._fail(CHECK_FAILED)
            return False, None
        finally:
            if path is not None:
                path.unlink(missing_ok=True)
        reason = reason_code_for_output(f"{completed.stdout}{completed.stderr}") if completed.returncode else None
        self._cache[key] = reason
        return True, reason

    def _fail(self, state: str) -> None:
        """Stop asking a binary that cannot answer; the run continues unchecked."""
        self._availability, self._probed = state, True
