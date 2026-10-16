from __future__ import annotations

import copy
import json
import os
import re
import socket
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from app.api.three_xui import PanelAPIRejected
from app.api.base import PanelClient
from app.security.private_files import secure_directory, secure_file


def _private_json(path: Path, value: Any) -> None:
    """Replace a recovery file atomically; never leave a partial snapshot."""
    secure_directory(path.parent)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            secure_file(temporary)
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


@dataclass
class InboundManager:
    client: PanelClient
    mode: str
    source_id: int
    candidate_ports: tuple[int, ...] = tuple(range(20000, 21001))
    test_port: int | None = None
    backup_path: Path | None = None
    source_snapshot: dict[str, Any] | None = None
    test_inbound_id: int | None = None
    panel_ports: frozenset[int] = frozenset()
    recovery_dir: Path | None = None
    topology: str = "direct"
    _manifest: dict[str, Any] | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.mode not in {"clone", "existing"}:
            raise ValueError("inbound.mode must be clone or existing")
        if self.topology not in {"direct", "reverse_proxy"}:
            raise ValueError("inbound.topology must be direct or reverse_proxy")
        if self.recovery_dir is not None:
            self.recovery_dir = Path(self.recovery_dir)
            if self.recovery_manifest_path and self.recovery_manifest_path.exists():
                manifest = json.loads(self.recovery_manifest_path.read_text(encoding="utf-8"))
                if (manifest.get("version") != 1 or manifest.get("mode") != self.mode
                        or manifest.get("source_id") != self.source_id):
                    raise RuntimeError("Recovery manifest belongs to a different inbound experiment")
                self._manifest = manifest

    @property
    def recovery_manifest_path(self) -> Path | None:
        return self.recovery_dir / "inbound-recovery.json" if self.recovery_dir else None

    @property
    def cleanup_pending(self) -> bool:
        return bool(self._manifest and self._manifest.get("state") != "cleaned")

    def recovery_summary(self) -> dict[str, Any]:
        """Public status contains no source payload, remark, URL or exception text."""
        return {"cleanup_pending": self.cleanup_pending,
                "state": self._manifest.get("state", "not_prepared") if self._manifest else "not_prepared",
                "mode": self.mode, "source_id": self.source_id,
                "test_inbound_id": self._manifest.get("test_inbound_id") if self._manifest else None,
                "test_port": self._manifest.get("port") if self._manifest else self.test_port}

    def _save_manifest(self, **changes: Any) -> None:
        if self._manifest is None:
            self._manifest = {"version": 1, "mode": self.mode, "source_id": self.source_id,
                              "topology": self.topology}
        self._manifest.update(changes)
        if self.recovery_manifest_path:
            _private_json(self.recovery_manifest_path, self._manifest)

    @property
    def _snapshot_path(self) -> Path | None:
        if self.recovery_dir:
            return self.recovery_dir / "source-snapshot.json"
        return self.backup_path

    async def preflight(self) -> dict[str, Any]:
        self.source_snapshot = copy.deepcopy(await self.client.get_inbound(self.source_id))
        if self.mode == "clone":
            self.panel_ports = frozenset(int(item.get("port", 0))
                                         for item in await self.client.list_inbounds())
        # Do not overwrite a pending existing-mode snapshot after an interrupted run.
        if not self.cleanup_pending:
            if self._snapshot_path:
                _private_json(self._snapshot_path, self.source_snapshot)
            if self.mode == "existing" and self.backup_path and self.backup_path != self._snapshot_path:
                _private_json(self.backup_path, self.source_snapshot)
        return self.source_snapshot

    def choose_port(self) -> int:
        if self.test_port is not None and self.test_port not in self.panel_ports:
            return self.test_port
        # Configured ports describe the server firewall; this local socket check
        # is only a hint. No unconfigured port is selected.
        for port in self.candidate_ports:
            if port in self.panel_ports:
                continue
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.1)
                if probe.connect_ex(("127.0.0.1", port)) != 0:
                    return port
        if self.test_port is not None:
            raise RuntimeError(f"Configured test_port {self.test_port} is already used by the panel, "
                               "and no other configured clone port is free")
        raise RuntimeError("No locally free port among the configured clone ports")

    @staticmethod
    def _clone_client_email(marker: str, index: int) -> str:
        token = marker.removeprefix("[3xui-config-tester:").removesuffix("]")
        if not re.fullmatch(r"[0-9a-f]{32}", token):
            raise ValueError("Clone identity marker is invalid")
        return f"3xui-tester-{token}-{index}@example.invalid"

    def _assign_clone_client_emails(self, payload: dict[str, Any], marker: str | None) -> None:
        if marker is None:
            return
        settings = payload.get("settings")
        serialized = isinstance(settings, str)
        if serialized:
            try:
                settings = json.loads(settings)
            except (TypeError, ValueError):
                return
        if not isinstance(settings, dict) or not isinstance(settings.get("clients"), list):
            return
        for index, client in enumerate(settings["clients"]):
            if isinstance(client, dict):
                client["email"] = self._clone_client_email(marker, index)
        payload["settings"] = (json.dumps(settings, ensure_ascii=False, separators=(",", ":"))
                               if serialized else settings)

    def normalize_payload(self, payload: dict[str, Any], *, clone_marker: str | None = None) -> dict[str, Any]:
        """Normalize the experimental listener; never alter the source route."""
        normalized = copy.deepcopy(payload)
        if self.mode != "clone":
            return normalized
        marker = clone_marker or (self._manifest.get("marker") if self._manifest else None)
        self._assign_clone_client_emails(normalized, marker)
        # A disabled template may still carry useful settings. The disposable
        # clone must actually be loaded by Xray for a reachability experiment.
        normalized["enable"] = True
        if self.topology != "direct":
            return normalized
        # Empty listen uses the panel/Xray default network listener instead of
        # inheriting a proxy-only loopback, specific interface or Unix socket.
        normalized["listen"] = ""
        stream = normalized.get("streamSettings")
        serialized = isinstance(stream, str)
        if serialized:
            stream = json.loads(stream)
        if not isinstance(stream, dict):
            return normalized
        for name in ("sockopt", "tcpSettings", "wsSettings", "httpupgradeSettings"):
            settings = stream.get(name)
            if isinstance(settings, dict) and "acceptProxyProtocol" in settings:
                settings["acceptProxyProtocol"] = False
        normalized["streamSettings"] = (json.dumps(stream, ensure_ascii=False, separators=(",", ":"))
                                         if serialized else stream)
        return normalized

    async def prepare(self) -> int:
        if self.cleanup_pending:
            raise RuntimeError("Inbound recovery is pending; recover it before creating another test resource")
        if self.source_snapshot is None:
            await self.preflight()
        assert self.source_snapshot is not None
        if self.mode == "existing":
            if self._snapshot_path:
                _private_json(self._snapshot_path, self.source_snapshot)
            self._save_manifest(state="restore_pending", test_inbound_id=self.source_id)
            self.test_inbound_id = self.source_id
            return self.source_id
        marker = f"[3xui-config-tester:{uuid.uuid4().hex}]"
        clone = self.normalize_payload(self.source_snapshot, clone_marker=marker)
        for key in ("id", "clientStats", "up", "down", "total", "expiryTime"):
            clone.pop(key, None)
        clone["port"] = self.choose_port()
        # A generated-only remark avoids persisting a sensitive source remark.
        clone["remark"] = marker
        self._save_manifest(state="create_pending", marker=marker, port=clone["port"],
                            protocol=clone.get("protocol"), test_inbound_id=None, creation_outcome="unknown")
        try:
            await self.client.create_inbound(clone)
            self._save_manifest(creation_outcome="acknowledged")
        except PanelAPIRejected:
            # A structured rejection is an explicit negative acknowledgement;
            # unlike transport errors, it does not leave an unknown create outcome.
            self._save_manifest(state="cleaned", test_inbound_id=None, creation_outcome="rejected")
            raise
        except BaseException:
            # The server may have committed before a timeout/cancellation.
            self._save_manifest(state="cleanup_pending")
            raise
        try:
            inbound_id = await self._resolve_clone()
            if inbound_id is None:
                raise RuntimeError("Panel created inbound but test clone ID could not be determined")
            self.test_inbound_id = inbound_id
            self._save_manifest(state="active", test_inbound_id=inbound_id, creation_outcome="identified")
        except BaseException:
            self._save_manifest(state="cleanup_pending")
            raise
        return self.test_inbound_id

    def _is_owned_clone(self, item: dict[str, Any]) -> bool:
        if not self._manifest:
            return False
        marker = self._manifest.get("marker")
        if not isinstance(marker, str) or not re.fullmatch(r"\[3xui-config-tester:[0-9a-f]{32}\]", marker):
            return False
        try:
            return (int(item["id"]) != self.source_id and item.get("remark") == marker
                    and int(item["port"]) == self._manifest.get("port")
                    and item.get("protocol") == self._manifest.get("protocol"))
        except (KeyError, TypeError, ValueError):
            return False

    async def _resolve_clone(self) -> int | None:
        candidates = await self.client.list_inbounds()
        matches = {int(item["id"]) for item in candidates if self._is_owned_clone(item)}
        if len(matches) > 1:
            raise RuntimeError("Test clone ID could not be determined: ambiguous resource ownership")
        if matches:
            inbound_id = next(iter(matches))
            expected_id = self._manifest.get("test_inbound_id") if self._manifest else None
            if expected_id is not None and int(expected_id) != inbound_id:
                raise RuntimeError("Test clone ownership changed; recovery requires inspection")
            return inbound_id
        # A changed remark/port/protocol on the known ID is not permission to delete it.
        expected_id = self._manifest.get("test_inbound_id") if self._manifest else None
        if expected_id is not None and any(int(item.get("id", 0)) == int(expected_id) for item in candidates):
            raise RuntimeError("Test clone ownership changed; recovery requires inspection")
        return None

    async def apply(self, payload: dict[str, Any]) -> None:
        if self.test_inbound_id is None:
            raise RuntimeError("Test inbound not prepared")
        if self.mode == "clone" and self._manifest and payload.get("port") != self._manifest.get("port"):
            raise ValueError("The prepared clone port is fixed for this experiment")
        await self.client.update_inbound(self.test_inbound_id, self.normalize_payload(payload))

    async def recover_pending(self) -> None:
        """Explicit recovery after discovery/preflight have been durably recorded."""
        await self.cleanup()
        if self.source_snapshot is not None:
            self.source_snapshot = copy.deepcopy(await self.client.get_inbound(self.source_id))
        if self.mode == "clone":
            self.panel_ports = frozenset(int(item.get("port", 0))
                                         for item in await self.client.list_inbounds())

    @staticmethod
    def _restoration_matches(snapshot: dict[str, Any], actual: dict[str, Any]) -> bool:
        volatile = {"up", "down", "clientStats", "clientsStats", "lastTrafficResetTime"}
        for key, expected in snapshot.items():
            if key in volatile:
                continue
            observed = actual.get(key)
            if key in {"settings", "streamSettings", "sniffing", "allocate"}:
                try:
                    expected = json.loads(expected) if isinstance(expected, str) else expected
                    observed = json.loads(observed) if isinstance(observed, str) else observed
                except (ValueError, TypeError):
                    pass
            if observed != expected:
                return False
        return True

    def _clone_client_pattern(self) -> re.Pattern[str] | None:
        if not self._manifest:
            return None
        marker = self._manifest.get("marker")
        if not isinstance(marker, str):
            return None
        token = marker.removeprefix("[3xui-config-tester:").removesuffix("]")
        if not re.fullmatch(r"[0-9a-f]{32}", token):
            return None
        return re.compile(rf"3xui-tester-{re.escape(token)}-\d+@example\.invalid")

    async def _delete_clone_client_records(self) -> None:
        """Best-effort removal of the clone's orphaned client records.

        3x-ui keeps clients in a global store and leaves the records unattached
        when their inbound is deleted (observed on v3.8). The panel exposes a
        global client list plus a bulk delete; older panel versions and client
        adapters without these endpoints simply skip the step. A failure here
        must not fail the cleanup: the disposable inbound itself is already gone.
        """
        pattern = self._clone_client_pattern()
        list_clients = getattr(self.client, "list_clients", None)
        delete_clients = getattr(self.client, "delete_clients", None)
        if pattern is None or not callable(list_clients) or not callable(delete_clients):
            return
        list_call = cast("Callable[[], Awaitable[list[dict[str, Any]]]]", list_clients)
        delete_call = cast("Callable[[list[str]], Awaitable[dict[str, Any]]]", delete_clients)
        try:
            clients = await list_call()
            emails = [str(item["email"]) for item in clients
                      if isinstance(item, dict) and pattern.fullmatch(str(item.get("email", "")))]
            await delete_call(emails)
        except Exception:
            return

    async def cleanup(self) -> None:
        if not self.cleanup_pending:
            return
        self._save_manifest(state="cleanup_pending")
        try:
            if self.mode == "existing":
                snapshot = self.source_snapshot
                if self._snapshot_path and self._snapshot_path.exists():
                    snapshot = json.loads(self._snapshot_path.read_text(encoding="utf-8"))
                if snapshot is None or int(snapshot.get("id", self.source_id)) != self.source_id:
                    raise RuntimeError("Source restoration snapshot is unavailable or belongs to another inbound")
                try:
                    await self.client.update_inbound(self.source_id, snapshot)
                except Exception:
                    # An update response can be lost after the source is restored.
                    actual = await self.client.get_inbound(self.source_id)
                    if not self._restoration_matches(snapshot, actual):
                        raise
                else:
                    actual = await self.client.get_inbound(self.source_id)
                    if not self._restoration_matches(snapshot, actual):
                        raise RuntimeError("Panel acknowledged restoration but source configuration still differs")
                self.source_snapshot = copy.deepcopy(snapshot)
            else:
                for attempt in range(2):
                    inbound_id = await self._resolve_clone()
                    if inbound_id is None:
                        if self._manifest and self._manifest.get("test_inbound_id") is None:
                            raise RuntimeError("Creation outcome remains uncertain; no owned clone could be reconciled")
                        break
                    self.test_inbound_id = inbound_id
                    self._save_manifest(test_inbound_id=inbound_id, creation_outcome="identified")
                    try:
                        await self.client.delete_inbound(inbound_id)
                    except Exception:
                        if await self._resolve_clone() is None:
                            break
                        if attempt == 1:
                            raise
                    else:
                        if await self._resolve_clone() is None:
                            break
                        if attempt == 1:
                            raise RuntimeError("Panel acknowledged clone deletion but the owned resource still exists")
                # The inbound is gone either way; sweep the client records the
                # panel left unattached (also covers an earlier partial cleanup).
                await self._delete_clone_client_records()
            self.test_inbound_id = None
            self._save_manifest(state="cleaned", test_inbound_id=None)
        except BaseException:
            self._save_manifest(state="cleanup_pending")
            raise
