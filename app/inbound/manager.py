from __future__ import annotations

import copy
import json
import socket
import uuid
from dataclasses import dataclass
from typing import Any
from pathlib import Path

from app.api.base import PanelClient


@dataclass
class InboundManager:
    client: PanelClient
    mode: str
    source_id: int
    port_range: tuple[int, int] = (20000, 30000)
    test_port: int | None = None
    backup_path: Path | None = None
    source_snapshot: dict[str, Any] | None = None
    test_inbound_id: int | None = None

    async def preflight(self) -> dict[str, Any]:
        self.source_snapshot = await self.client.get_inbound(self.source_id)
        if self.mode == "clone" and self.test_port is not None:
            in_use = [item for item in await self.client.list_inbounds() if int(item.get("port", 0)) == self.test_port]
            if in_use:
                raise RuntimeError(f"Configured test_port {self.test_port} is already used by inbound(s): {[item.get('id') for item in in_use]}")
        if self.mode == "existing" and self.backup_path:
            self.backup_path.parent.mkdir(parents=True, exist_ok=True)
            self.backup_path.write_text(json.dumps(self.source_snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
            # On Ubuntu this makes a recovery backup readable only by its owner.
            self.backup_path.chmod(0o600)
        return self.source_snapshot

    def choose_port(self) -> int:
        if self.test_port is not None:
            return self.test_port
        # This is a local availability hint. Panel creation remains the remote authority.
        for port in range(self.port_range[0], self.port_range[1] + 1):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.1)
                if probe.connect_ex(("127.0.0.1", port)) != 0:
                    return port
        raise RuntimeError("No locally free port in configured port_range")

    async def prepare(self) -> int:
        if self.source_snapshot is None:
            await self.preflight()
        assert self.source_snapshot is not None
        if self.mode == "existing":
            self.test_inbound_id = self.source_id
            return self.source_id
        if self.mode != "clone":
            raise ValueError("inbound.mode must be clone or existing")
        clone = copy.deepcopy(self.source_snapshot)
        for key in ("id", "clientStats", "up", "down", "total", "expiryTime"):
            clone.pop(key, None)
        clone["port"] = self.choose_port()
        marker = f"[3xui-config-tester:{uuid.uuid4().hex}]"
        clone["remark"] = f"{marker} {self.source_snapshot.get('remark', self.source_id)}"
        created = await self.client.create_inbound(clone)
        self.test_inbound_id = int(created.get("id", created.get("obj", 0))) if isinstance(created, dict) else 0
        if not self.test_inbound_id:
            # Some panel versions acknowledge add without embedding the object.
            try:
                candidates = await self.client.list_inbounds()
                matching = [item for item in candidates if item.get("remark") == clone["remark"]]
                if len(matching) != 1:
                    raise RuntimeError("Panel created inbound but test clone ID could not be determined")
                self.test_inbound_id = int(matching[0]["id"])
            except Exception:
                # Do not leave a clone behind solely because its create response
                # omitted the ID. The per-run marker makes this deletion precise.
                await self._delete_marked_clones(marker)
                raise
        return self.test_inbound_id

    async def _delete_marked_clones(self, marker: str) -> None:
        try:
            candidates = await self.client.list_inbounds()
            for item in candidates:
                if str(item.get("remark", "")).startswith(marker):
                    await self.client.delete_inbound(int(item["id"]))
        except Exception:
            # The original create/list failure is the useful error to surface.
            # A unique marker still makes a later manual cleanup unambiguous.
            pass

    async def apply(self, payload: dict[str, Any]) -> None:
        if self.test_inbound_id is None:
            raise RuntimeError("Test inbound not prepared")
        await self.client.update_inbound(self.test_inbound_id, payload)

    async def cleanup(self) -> None:
        if self.test_inbound_id is None or self.source_snapshot is None:
            return
        if self.mode == "existing":
            await self.client.update_inbound(self.source_id, self.source_snapshot)
        else:
            inbound_id = self.test_inbound_id
            first_error: Exception | None = None
            for attempt in range(2):
                try:
                    await self.client.delete_inbound(inbound_id)
                except Exception as error:
                    first_error = first_error or error
                    try:
                        still_exists = any(int(item.get("id", 0)) == inbound_id
                                           for item in await self.client.list_inbounds())
                    except Exception:
                        still_exists = True
                    if not still_exists:
                        self.test_inbound_id = None
                        return
                    if attempt == 1:
                        raise error
                else:
                    self.test_inbound_id = None
                    return
            if first_error:
                raise first_error
        self.test_inbound_id = None
