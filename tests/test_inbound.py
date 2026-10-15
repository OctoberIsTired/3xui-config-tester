import asyncio
import copy
import json
from types import SimpleNamespace

import pytest

from app.api.three_xui import PanelAPIError, PanelAPIRejected
from app.inbound.manager import InboundManager


class FakePanel:
    def __init__(self) -> None:
        self.source = {"id": 4, "port": 443, "remark": "production", "protocol": "vless", "clientStats": []}
        self.items = {4: self.source.copy()}
        self.deleted: list[int] = []

    async def get_inbound(self, inbound_id: int) -> dict:
        return self.items[inbound_id].copy()

    async def create_inbound(self, payload: dict) -> dict:
        self.items[9] = {**payload, "id": 9}
        return {"id": 9}

    async def list_inbounds(self) -> list[dict]:
        return list(self.items.values())

    async def update_inbound(self, inbound_id: int, payload: dict) -> dict:
        self.items[inbound_id] = payload.copy()
        return {}

    async def delete_inbound(self, inbound_id: int) -> None:
        self.deleted.append(inbound_id)
        self.items.pop(inbound_id, None)


def test_clone_never_modifies_source_and_is_deleted() -> None:
    panel = FakePanel()
    manager = InboundManager(panel, "clone", 4)
    manager.choose_port = lambda: 23456  # type: ignore[method-assign]
    assert asyncio.run(manager.prepare()) == 9
    assert panel.items[4]["port"] == 443
    assert panel.items[9]["port"] == 23456
    asyncio.run(manager.cleanup())
    assert panel.deleted == [9]


@pytest.mark.parametrize("serialized", [False, True])
def test_clone_assigns_stable_unique_client_emails_and_apply_preserves_them(serialized) -> None:
    panel = FakePanel()
    settings = {"clients": [{"id": "fake-uuid-a", "email": "shared@example.test"},
                            {"id": "fake-uuid-b", "email": "shared@example.test"}]}
    panel.items[4]["settings"] = json.dumps(settings) if serialized else settings
    original = copy.deepcopy(panel.items[4])
    manager = InboundManager(panel, "clone", 4, test_port=9443)

    asyncio.run(manager.prepare())
    created = panel.items[9]["settings"]
    created = json.loads(created) if isinstance(created, str) else created
    emails = [item["email"] for item in created["clients"]]
    assert emails[0] != emails[1]
    assert all(email.endswith("@example.invalid") for email in emails)
    assert panel.items[4] == original

    # Apply receives a payload based on the source template in normal generation;
    # the experiment marker restores exactly the same per-client clone identity.
    requested = copy.deepcopy(original)
    requested["port"] = 9443
    asyncio.run(manager.apply(requested))
    applied = panel.items[9]["settings"]
    applied = json.loads(applied) if isinstance(applied, str) else applied
    assert [item["email"] for item in applied["clients"]] == emails
    assert panel.items[4] == original
    asyncio.run(manager.cleanup())


def test_definite_create_rejection_does_not_mark_cleanup_pending(tmp_path) -> None:
    class RejectedPanel(FakePanel):
        async def create_inbound(self, payload: dict) -> dict:
            raise PanelAPIRejected("Duplicate email: ***")

    panel = RejectedPanel()
    manager = InboundManager(panel, "clone", 4, test_port=9443, recovery_dir=tmp_path)
    with pytest.raises(PanelAPIRejected, match="Duplicate email"):
        asyncio.run(manager.prepare())
    assert not manager.cleanup_pending
    assert json.loads((tmp_path / "inbound-recovery.json").read_text())["creation_outcome"] == "rejected"
    assert set(panel.items) == {4}


def test_malformed_create_ack_remains_uncertain(tmp_path) -> None:
    class MalformedAckPanel(FakePanel):
        async def create_inbound(self, payload: dict) -> dict:
            raise PanelAPIError("panel API response lacks a boolean success field")

    manager = InboundManager(MalformedAckPanel(), "clone", 4, test_port=9443, recovery_dir=tmp_path)
    with pytest.raises(PanelAPIError, match="lacks a boolean"):
        asyncio.run(manager.prepare())
    assert manager.cleanup_pending
    assert json.loads((tmp_path / "inbound-recovery.json").read_text())["state"] == "cleanup_pending"


def test_fixed_test_port_is_used() -> None:
    panel = FakePanel()
    manager = InboundManager(panel, "clone", 4, test_port=9443)
    assert manager.choose_port() == 9443


def test_choose_port_follows_the_configured_candidate_order(monkeypatch) -> None:
    """Порты клона — список, а не интервал: открытые в firewall порты редко идут подряд."""
    probes: list[int] = []

    class Probe:
        def __enter__(self) -> "Probe":
            return self

        def __exit__(self, *_args: object) -> bool:
            return False

        def settimeout(self, _value: float) -> None:
            pass

        def connect_ex(self, address: tuple[str, int]) -> int:
            probes.append(address[1])
            # 0 означает «кто-то слушает»: локальная проверка занятости порта.
            return 0 if address[1] == 24443 else 111

    monkeypatch.setattr("app.inbound.manager.socket.socket", lambda *args, **kwargs: Probe())
    manager = InboundManager(FakePanel(), "clone", 4, candidate_ports=(24443, 24500, 25500))
    assert manager.choose_port() == 24500
    assert probes == [24443, 24500]


def test_clone_cleanup_retries_after_transient_delete_timeout() -> None:
    class FlakyDeletePanel(FakePanel):
        def __init__(self) -> None:
            super().__init__()
            self.delete_attempts = 0

        async def delete_inbound(self, inbound_id: int) -> None:
            self.delete_attempts += 1
            if self.delete_attempts == 1:
                raise TimeoutError("temporary panel timeout")
            self.deleted.append(inbound_id)
            self.items.pop(inbound_id, None)

    panel = FlakyDeletePanel()
    manager = InboundManager(panel, "clone", 4)
    manager.choose_port = lambda: 23456  # type: ignore[method-assign]
    asyncio.run(manager.prepare())
    asyncio.run(manager.cleanup())
    assert panel.delete_attempts == 2
    assert panel.deleted == [9]
    assert manager.test_inbound_id is None


def test_clone_cleanup_accepts_delete_that_succeeded_before_timeout() -> None:
    class DelayedDeletePanel(FakePanel):
        async def delete_inbound(self, inbound_id: int) -> None:
            self.deleted.append(inbound_id)
            self.items.pop(inbound_id, None)
            raise TimeoutError("response timed out after server deleted clone")

    panel = DelayedDeletePanel()
    manager = InboundManager(panel, "clone", 4)
    manager.choose_port = lambda: 23456  # type: ignore[method-assign]
    asyncio.run(manager.prepare())
    asyncio.run(manager.cleanup())
    assert panel.deleted == [9]
    assert manager.test_inbound_id is None


def test_ambiguous_clone_ownership_is_preserved_for_recovery() -> None:
    class NoIdPanel(FakePanel):
        async def create_inbound(self, payload: dict) -> dict:
            self.items[9] = {**payload, "id": 9}
            return {}

        async def list_inbounds(self) -> list[dict]:
            # preflight тоже спрашивает список портов, когда копии ещё нет.
            clone = self.items.get(9)
            return [*self.items.values(), {**clone, "id": 10}] if clone else list(self.items.values())

    panel = NoIdPanel()
    manager = InboundManager(panel, "clone", 4)
    manager.choose_port = lambda: 23456  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="could not be determined"):
        asyncio.run(manager.prepare())
    with pytest.raises(RuntimeError, match="ambiguous resource ownership"):
        asyncio.run(manager.cleanup())
    assert panel.deleted == []
    assert manager.cleanup_pending


class FreePortProbe:
    """Локальная проверка порта: ничего не слушает, порт свободен."""

    def __enter__(self) -> "FreePortProbe":
        return self

    def __exit__(self, *_args: object) -> bool:
        return False

    def settimeout(self, _value: float) -> None:
        pass

    def connect_ex(self, _address: tuple[str, int]) -> int:
        return 111


def patch_free_ports(monkeypatch) -> None:
    """Подменяет модуль `socket` только внутри manager: глобальная правка
    ломает собственные сокеты asyncio (нет bind/close)."""
    import socket as real_socket

    monkeypatch.setattr("app.inbound.manager.socket",
                        SimpleNamespace(AF_INET=real_socket.AF_INET, SOCK_STREAM=real_socket.SOCK_STREAM,
                                        socket=lambda *args, **kwargs: FreePortProbe()))


def test_ports_the_panel_already_uses_are_skipped(monkeypatch) -> None:
    """Порт, занятый другим inbound'ом (включая исходный), копии не подходит:
    панель примет конфиг, но Xray не забиндит порт — копия не поднимется."""
    patch_free_ports(monkeypatch)
    panel = FakePanel()
    panel.items[7] = {"id": 7, "port": 24443, "remark": "other"}
    manager = InboundManager(panel, "clone", 4, candidate_ports=(443, 24443, 25500))
    assert asyncio.run(manager.prepare()) == 9
    assert panel.items[9]["port"] == 25500
    assert panel.items[4]["port"] == 443


def test_fixed_test_port_falls_through_when_the_panel_already_uses_it(monkeypatch) -> None:
    patch_free_ports(monkeypatch)
    manager = InboundManager(FakePanel(), "clone", 4, candidate_ports=(25500,), test_port=443)
    assert asyncio.run(manager.prepare()) == 9
    assert manager.test_inbound_id == 9


def test_busy_fixed_port_without_a_free_candidate_reports_it(monkeypatch) -> None:
    patch_free_ports(monkeypatch)
    manager = InboundManager(FakePanel(), "clone", 4, candidate_ports=(443,), test_port=443)
    with pytest.raises(RuntimeError, match="Configured test_port 443 is already used"):
        asyncio.run(manager.prepare())


def test_lost_create_response_recovers_only_exact_owned_clone(tmp_path) -> None:
    class LostResponsePanel(FakePanel):
        async def create_inbound(self, payload: dict) -> dict:
            ledger = json.loads((tmp_path / "inbound-recovery.json").read_text(encoding="utf-8"))
            assert ledger["state"] == "create_pending"
            assert ledger["marker"] == payload["remark"]
            self.items[9] = {**payload, "id": 9}
            self.items[10] = {**payload, "id": 10, "remark": payload["remark"] + " unrelated"}
            self.items[11] = {**payload, "id": 11, "port": 9444}
            raise TimeoutError("fake response lost after commit")

    panel = LostResponsePanel()
    original = copy.deepcopy(panel.items[4])
    manager = InboundManager(panel, "clone", 4, test_port=9443, recovery_dir=tmp_path)
    with pytest.raises(TimeoutError):
        asyncio.run(manager.prepare())
    assert manager.test_inbound_id is None
    asyncio.run(manager.cleanup())
    assert panel.deleted == [9]
    assert panel.items[4] == original
    assert 10 in panel.items and 11 in panel.items
    assert not manager.cleanup_pending
    assert json.loads((tmp_path / "inbound-recovery.json").read_text())["state"] == "cleaned"


def test_cleanup_pending_survives_restart_and_recovers_without_source_snapshot(tmp_path) -> None:
    class UnavailablePanel(FakePanel):
        available = True

        async def list_inbounds(self) -> list[dict]:
            if not self.available:
                raise TimeoutError("fake panel unavailable")
            return await super().list_inbounds()

    panel = UnavailablePanel()
    manager = InboundManager(panel, "clone", 4, test_port=9443, recovery_dir=tmp_path)
    asyncio.run(manager.prepare())
    panel.available = False
    with pytest.raises(TimeoutError):
        asyncio.run(manager.cleanup())
    assert manager.cleanup_pending
    restarted = InboundManager(panel, "clone", 4, test_port=9443, recovery_dir=tmp_path)
    with pytest.raises(RuntimeError, match="recovery is pending"):
        asyncio.run(restarted.prepare())
    panel.available = True
    asyncio.run(restarted.recover_pending())
    assert set(panel.items) == {4}
    assert restarted.source_snapshot is None
    assert not restarted.cleanup_pending
    assert restarted.panel_ports == frozenset({443})


def test_existing_restart_restores_original_private_snapshot(tmp_path) -> None:
    panel = FakePanel()
    original = copy.deepcopy(panel.items[4])
    first = InboundManager(panel, "existing", 4, recovery_dir=tmp_path)
    asyncio.run(first.prepare())
    asyncio.run(first.apply({**original, "port": 9443}))
    restarted = InboundManager(panel, "existing", 4, recovery_dir=tmp_path)
    assert asyncio.run(restarted.preflight())["port"] == 9443
    assert json.loads((tmp_path / "source-snapshot.json").read_text())["port"] == 443
    asyncio.run(restarted.recover_pending())
    assert panel.items[4] == original
    assert restarted.source_snapshot == original
    assert not restarted.cleanup_pending


@pytest.mark.parametrize("serialized", [False, True])
def test_direct_clone_normalizes_proxy_header_without_mutating_source(tmp_path, serialized) -> None:
    panel = FakePanel()
    stream = {"network": "xhttp", "sockopt": {"acceptProxyProtocol": True, "tcpFastOpen": True},
              "wsSettings": {"path": "/fixture", "acceptProxyProtocol": True}}
    panel.items[4]["streamSettings"] = json.dumps(stream) if serialized else stream
    original = copy.deepcopy(panel.items[4])
    manager = InboundManager(panel, "clone", 4, test_port=9443, recovery_dir=tmp_path, topology="direct")
    asyncio.run(manager.prepare())
    clone_stream = panel.items[9]["streamSettings"]
    if serialized:
        assert isinstance(clone_stream, str)
        clone_stream = json.loads(clone_stream)
    assert clone_stream["sockopt"] == {"acceptProxyProtocol": False, "tcpFastOpen": True}
    assert clone_stream["wsSettings"]["acceptProxyProtocol"] is False
    assert panel.items[4] == original
    requested = copy.deepcopy(panel.items[9])
    requested["streamSettings"] = original["streamSettings"]
    asyncio.run(manager.apply(requested))
    applied = panel.items[9]["streamSettings"]
    applied = json.loads(applied) if isinstance(applied, str) else applied
    assert applied["sockopt"]["acceptProxyProtocol"] is False
    assert requested["streamSettings"] == original["streamSettings"]
    asyncio.run(manager.cleanup())


@pytest.mark.parametrize("mode,topology", [("clone", "reverse_proxy"), ("existing", "direct")])
def test_proxy_topology_and_existing_source_keep_proxy_requirement(tmp_path, mode, topology) -> None:
    panel = FakePanel()
    panel.items[4]["streamSettings"] = {"sockopt": {"acceptProxyProtocol": True}}
    manager = InboundManager(panel, mode, 4, test_port=9443, recovery_dir=tmp_path, topology=topology)
    target = asyncio.run(manager.prepare())
    assert panel.items[target]["streamSettings"]["sockopt"]["acceptProxyProtocol"] is True
    asyncio.run(manager.cleanup())


def test_changed_clone_ownership_never_deletes_foreign_resource(tmp_path) -> None:
    panel = FakePanel()
    manager = InboundManager(panel, "clone", 4, test_port=9443, recovery_dir=tmp_path)
    asyncio.run(manager.prepare())
    panel.items[9]["remark"] = "foreign-owner"
    with pytest.raises(RuntimeError, match="ownership changed"):
        asyncio.run(manager.cleanup())
    assert panel.deleted == []
    assert manager.cleanup_pending
    assert 9 in panel.items


def test_uncertain_create_without_visible_clone_remains_pending(tmp_path) -> None:
    class LostCreatePanel(FakePanel):
        async def create_inbound(self, payload: dict) -> dict:
            raise TimeoutError("unknown server outcome")

    panel = LostCreatePanel()
    manager = InboundManager(panel, "clone", 4, test_port=9443, recovery_dir=tmp_path)
    with pytest.raises(TimeoutError):
        asyncio.run(manager.prepare())
    with pytest.raises(RuntimeError, match="Creation outcome remains uncertain"):
        asyncio.run(manager.cleanup())
    assert manager.cleanup_pending
    assert panel.deleted == []
    assert json.loads((tmp_path / "inbound-recovery.json").read_text())["state"] == "cleanup_pending"


def test_successful_delete_acknowledgement_without_deletion_stays_pending(tmp_path) -> None:
    class IgnoredDeletePanel(FakePanel):
        async def delete_inbound(self, inbound_id: int) -> None:
            self.deleted.append(inbound_id)

    panel = IgnoredDeletePanel()
    manager = InboundManager(panel, "clone", 4, test_port=9443, recovery_dir=tmp_path)
    asyncio.run(manager.prepare())
    with pytest.raises(RuntimeError, match="owned resource still exists"):
        asyncio.run(manager.cleanup())
    assert panel.deleted == [9, 9]
    assert manager.cleanup_pending


def test_manifest_and_public_status_do_not_contain_source_secret_or_remark(tmp_path) -> None:
    panel = FakePanel()
    panel.items[4]["remark"] = "FAKE_SECRET_REMARK"
    panel.items[4]["settings"] = {"password": "FAKE_RECOVERY_PASSWORD"}
    manager = InboundManager(panel, "clone", 4, test_port=9443, recovery_dir=tmp_path)
    asyncio.run(manager.prepare())
    public = json.dumps(manager.recovery_summary()) + (tmp_path / "inbound-recovery.json").read_text()
    assert "FAKE_SECRET_REMARK" not in public
    assert "FAKE_RECOVERY_PASSWORD" not in public
    assert "FAKE_RECOVERY_PASSWORD" in (tmp_path / "source-snapshot.json").read_text()
    assert list(tmp_path.glob("*.tmp")) == []
    asyncio.run(manager.cleanup())


def test_recovery_manifest_cannot_be_reused_for_other_source(tmp_path) -> None:
    manager = InboundManager(FakePanel(), "clone", 4, test_port=9443, recovery_dir=tmp_path)
    asyncio.run(manager.prepare())
    with pytest.raises(RuntimeError, match="different inbound experiment"):
        InboundManager(FakePanel(), "clone", 7, recovery_dir=tmp_path)


def test_ignored_existing_restoration_remains_pending(tmp_path) -> None:
    class IgnoredRestorePanel(FakePanel):
        ignore_updates = False

        async def update_inbound(self, inbound_id: int, payload: dict) -> dict:
            if self.ignore_updates:
                return {}
            return await super().update_inbound(inbound_id, payload)

    panel = IgnoredRestorePanel()
    manager = InboundManager(panel, "existing", 4, recovery_dir=tmp_path)
    asyncio.run(manager.prepare())
    asyncio.run(manager.apply({**panel.items[4], "port": 9443}))
    panel.ignore_updates = True
    with pytest.raises(RuntimeError, match="source configuration still differs"):
        asyncio.run(manager.cleanup())
    assert manager.cleanup_pending
    assert panel.items[4]["port"] == 9443


def test_existing_restoration_lost_response_is_verified(tmp_path) -> None:
    class DelayedRestorePanel(FakePanel):
        async def update_inbound(self, inbound_id: int, payload: dict) -> dict:
            await super().update_inbound(inbound_id, payload)
            raise TimeoutError("fake response lost after successful restoration")

    panel = DelayedRestorePanel()
    original = copy.deepcopy(panel.items[4])
    manager = InboundManager(panel, "existing", 4, recovery_dir=tmp_path)
    asyncio.run(manager.prepare())
    panel.items[4]["port"] = 9443
    asyncio.run(manager.cleanup())
    assert panel.items[4] == original
    assert not manager.cleanup_pending


@pytest.mark.parametrize("listen", ["127.0.0.1", "::1", "192.0.2.25", "/run/fixture.sock", "", "0.0.0.0", "::"])
def test_direct_clone_uses_default_listener_and_enabled_state_without_changing_source(tmp_path, listen) -> None:
    panel = FakePanel()
    panel.items[4].update({"listen": listen, "enable": False})
    original = copy.deepcopy(panel.items[4])
    manager = InboundManager(panel, "clone", 4, test_port=9443, recovery_dir=tmp_path, topology="direct")
    asyncio.run(manager.prepare())
    assert panel.items[9]["listen"] == ""
    assert panel.items[9]["enable"] is True
    assert panel.items[4] == original
    requested = {**panel.items[9], "listen": listen, "enable": False}
    expected = manager.normalize_payload(requested)
    asyncio.run(manager.apply(requested))
    assert panel.items[9] == expected
    assert panel.items[9]["listen"] == ""
    assert panel.items[9]["enable"] is True
    assert requested["listen"] == listen and requested["enable"] is False
    assert panel.items[4] == original
    asyncio.run(manager.cleanup())


def test_proxy_clone_preserves_listener_but_enables_only_clone(tmp_path) -> None:
    panel = FakePanel()
    panel.items[4].update({"listen": "127.0.0.1", "enable": False})
    original = copy.deepcopy(panel.items[4])
    manager = InboundManager(panel, "clone", 4, test_port=9443, recovery_dir=tmp_path, topology="reverse_proxy")
    asyncio.run(manager.prepare())
    assert panel.items[9]["listen"] == "127.0.0.1"
    assert panel.items[9]["enable"] is True
    assert panel.items[4] == original
    asyncio.run(manager.cleanup())


def test_existing_normalization_preserves_listener_and_enabled_state(tmp_path) -> None:
    panel = FakePanel()
    panel.items[4].update({"listen": "127.0.0.1", "enable": False})
    original = copy.deepcopy(panel.items[4])
    manager = InboundManager(panel, "existing", 4, recovery_dir=tmp_path, topology="direct")
    asyncio.run(manager.prepare())
    assert manager.normalize_payload(original) == original
    assert panel.items[4] == original
    asyncio.run(manager.cleanup())
