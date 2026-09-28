from __future__ import annotations

import base64
import copy
import json
import re
import secrets
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml



REALITY_TRANSPORTS = {"tcp", "grpc", "xhttp"}
_SHORT_ID = re.compile(r"(?:[0-9a-fA-F]{2}){0,8}\Z")
_KEY = re.compile(r"[A-Za-z0-9_-]{43}\Z")


def _object(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, dict):
        return {}
    return copy.deepcopy(value)


def stream_settings(inbound: dict[str, Any]) -> dict[str, Any]:
    return _object(inbound.get("streamSettings"))


def _store_stream(inbound: dict[str, Any], stream: dict[str, Any]) -> None:
    inbound["streamSettings"] = (json.dumps(stream, ensure_ascii=False, separators=(",", ":"))
                                 if isinstance(inbound.get("streamSettings"), str) else stream)


@dataclass(frozen=True)
class RealityProfile:
    target: str
    server_names: tuple[str, ...]


def profile_of(candidate: dict[str, str]) -> RealityProfile:
    """Convert one target list entry into the profile used for a single run."""
    return RealityProfile(candidate["target"], (candidate["server_name"],))


def parse_candidates(data: Any) -> list[dict[str, str]]:
    """Parse a public, key-free list of target/SNI pairs."""
    if isinstance(data, str):
        data = yaml.safe_load(data)
    if not isinstance(data, dict) or not isinstance(data.get("targets"), list):
        raise ValueError("REALITY file must contain a targets list")
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in data["targets"]:
        if not isinstance(item, dict) or set(item) != {"target", "server_name"}:
            raise ValueError("Each REALITY target needs target and server_name")
        target, name = item["target"], item["server_name"]
        profile, error = resolve_profile({"reality": {"target": target, "server_names": [name]}}, {})
        if error or profile is None:
            raise ValueError(f"Invalid REALITY target/SNI pair: {error}")
        pair = (profile.target, profile.server_names[0])
        if pair not in seen:
            result.append({"target": pair[0], "server_name": pair[1]})
            seen.add(pair)
    if not result or len(result) > 512:
        raise ValueError("REALITY targets must contain 1..512 unique pairs")
    return result


_CANDIDATE_CACHE: dict[tuple[str, int, int], list[dict[str, str]]] = {}


def _candidates_from_file(path: Path) -> list[dict[str, str]]:
    """Reuse the parsed list while the file is unchanged; one preview reads it several times."""
    stat = path.stat()
    key = (str(path), stat.st_mtime_ns, stat.st_size)
    cached = _CANDIDATE_CACHE.get(key)
    if cached is None:
        _CANDIDATE_CACHE.clear()
        cached = _CANDIDATE_CACHE[key] = parse_candidates(path.read_text(encoding="utf-8"))
    return [dict(item) for item in cached]


def configured_candidates(testing: dict[str, Any], source_path: Path | None = None) -> list[dict[str, str]]:
    reality = testing.get("reality") or {}
    if not isinstance(reality, dict):
        raise ValueError("testing.reality must be an object")
    file_name, inline = reality.get("candidates_file"), reality.get("candidates")
    if file_name and inline:
        raise ValueError("Use either reality.candidates_file or reality.candidates")
    if (file_name or inline) and (reality.get("target") or reality.get("server_names")):
        raise ValueError("Use either one REALITY target or a candidates list")
    if file_name:
        if not isinstance(file_name, str) or not source_path:
            raise ValueError("reality.candidates_file requires a YAML config path")
        path = Path(file_name)
        if not path.is_absolute():
            path = source_path.parent / path
        return _candidates_from_file(path)
    if inline is not None:
        return parse_candidates({"targets": inline})
    return []


@dataclass(frozen=True)
class RealityCredentials:
    private_key: str
    password: str
    short_id: str

    @classmethod
    def generate(cls, binary: str) -> RealityCredentials:
        completed = subprocess.run([binary, "x25519"], capture_output=True, text=True, check=True, timeout=15)
        fields = dict(line.split(":", 1) for line in completed.stdout.splitlines() if ":" in line)
        private_key = fields.get("PrivateKey", "").strip()
        password = fields.get("Password (PublicKey)", fields.get("PublicKey", "")).strip()
        credentials = cls(private_key, password, secrets.token_hex(8))
        credentials.validate()
        return credentials

    def validate(self) -> None:
        if not _KEY.fullmatch(self.private_key) or not _KEY.fullmatch(self.password) or not _SHORT_ID.fullmatch(self.short_id) or not self.short_id:
            raise ValueError("Invalid generated REALITY credentials")
        for value in (self.private_key, self.password):
            try:
                if len(base64.urlsafe_b64decode(value + "=")) != 32:
                    raise ValueError("Invalid REALITY X25519 key length")
            except (ValueError, base64.binascii.Error) as error:
                raise ValueError("Invalid REALITY X25519 key encoding") from error

    @classmethod
    def load(cls, path: Path, experiment_id: str) -> RealityCredentials:
        if not path.is_file():
            raise FileNotFoundError("REALITY credentials for --resume are missing; restore the credentials file")
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("experiment_id") != experiment_id:
            raise ValueError("REALITY credentials do not match this checkpoint")
        credentials = cls(str(data["private_key"]), str(data["password"]), str(data["short_id"]))
        credentials.validate()
        return credentials

    def save(self, path: Path, experiment_id: str) -> None:
        payload = json.dumps({"experiment_id": experiment_id, "private_key": self.private_key,
                              "password": self.password, "short_id": self.short_id})
        handle = path.open("x", encoding="utf-8")
        try:
            with handle:
                handle.write(payload)
        except Exception:
            path.unlink(missing_ok=True)
            raise


def resolve_profile(testing: dict[str, Any], source: dict[str, Any]) -> tuple[RealityProfile | None, str | None]:
    explicit = testing.get("reality") or {}
    if not isinstance(explicit, dict):
        return None, "reality_settings_invalid"
    source_stream = stream_settings(source)
    existing = _object(source_stream.get("realitySettings")) if source_stream.get("security") == "reality" else {}
    if explicit:
        target = explicit.get("target")
        names = explicit.get("server_names")
    else:
        target = existing.get("target") or existing.get("dest")
        names = existing.get("serverNames")
    if not target or not names:
        return None, "reality_target_or_sni_missing"
    if (not isinstance(target, str) or target.strip() != target or
            any(char.isspace() for char in target) or "://" in target or "/" in target or "@" in target):
        return None, "reality_target_invalid"
    parsed = urlsplit("//" + target)
    try:
        port = parsed.port
    except ValueError:
        return None, "reality_target_invalid"
    if not parsed.hostname or port is None or not 1 <= port <= 65535 or parsed.query or parsed.fragment:
        return None, "reality_target_invalid"
    if (not isinstance(names, list) or not names or
            any(not isinstance(name, str) or not name or name.strip() != name or
                any(char in name for char in " /*:@") for name in names)):
        return None, "reality_server_names_invalid"
    return RealityProfile(target, tuple(names)), None


def prepare_reality_inbound(inbound: dict[str, Any], profile: RealityProfile,
                            credentials: RealityCredentials) -> dict[str, Any]:
    payload = copy.deepcopy(inbound)
    stream = stream_settings(payload)
    if stream.get("security") != "reality":
        return payload
    settings = _object(stream.get("realitySettings"))
    settings.update({"target": profile.target, "serverNames": list(profile.server_names),
                     "privateKey": credentials.private_key, "shortIds": [credentials.short_id]})
    settings.pop("dest", None)
    nested = _object(settings.get("settings"))
    nested.update({"password": credentials.password, "publicKey": credentials.password,
                   "serverName": profile.server_names[0], "shortId": credentials.short_id,
                   "fingerprint": nested.get("fingerprint") or "chrome"})
    settings["settings"] = nested
    stream["realitySettings"] = settings
    stream.pop("tlsSettings", None)
    _store_stream(payload, stream)
    return payload


def validate_pair(inbound: dict[str, Any], client_config: dict[str, Any]) -> str | None:
    server = stream_settings(inbound)
    outbounds = client_config.get("outbounds") or []
    if not outbounds or not isinstance(outbounds[0], dict):
        return "client_outbound_missing"
    outbound = outbounds[0].get("streamSettings", {})
    if not isinstance(outbound, dict):
        return "client_stream_settings_invalid"
    network = server.get("network", "tcp")
    security = server.get("security", "none")
    if network != outbound.get("network", "tcp") or security != outbound.get("security", "none"):
        return "transport_or_security_mismatch"
    if security == "reality":
        if network not in REALITY_TRANSPORTS:
            return "reality_transport_unsupported"
        reality = _object(server.get("realitySettings"))
        client = _object(outbound.get("realitySettings"))
        if not reality.get("target") or not reality.get("privateKey") or not reality.get("serverNames") or not reality.get("shortIds"):
            return "reality_server_settings_missing"
        if (not isinstance(client.get("password"), str) or not client["password"] or
                not isinstance(client.get("fingerprint"), str) or not client["fingerprint"] or
                client["fingerprint"] == "unsafe"):
            return "reality_client_settings_missing"
        if any(not isinstance(value, str) or not _SHORT_ID.fullmatch(value)
               for value in reality["shortIds"]):
            return "reality_short_id_invalid"
        if client.get("serverName") not in reality["serverNames"]:
            return "reality_sni_mismatch"
        if client.get("shortId") not in reality["shortIds"]:
            return "reality_short_id_mismatch"
    if network == "xhttp":
        server_xhttp = _object(server.get("xhttpSettings"))
        client_xhttp = _object(outbound.get("xhttpSettings"))
        for key in ("path", "host"):
            if server_xhttp.get(key, "") != client_xhttp.get(key, ""):
                return f"xhttp_{key}_mismatch"
        server_mode = server_xhttp.get("mode", "auto")
        client_mode = client_xhttp.get("mode", "auto")
        if server_mode != "auto" and client_mode != server_mode:
            return "xhttp_mode_mismatch"
    return None
