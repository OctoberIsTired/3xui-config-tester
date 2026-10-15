from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from app.xray.client import XrayClient, XrayClientError, categorize_xray_logs


class RunningProcess:
    returncode = None


def test_readiness_waits_for_socks_listener() -> None:
    async def scenario() -> None:
        async def accept(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(accept, "127.0.0.1", 0)
        port = int(server.sockets[0].getsockname()[1])
        client = XrayClient()
        client.process = RunningProcess()  # type: ignore[assignment]
        try:
            await asyncio.wait_for(client._confirm_running("127.0.0.1", port), 1)
        finally:
            client.process = None
            server.close()
            await server.wait_closed()

    asyncio.run(scenario())


def test_windows_start_captures_categories_without_exposing_raw_logs() -> None:
    """Windows-специфика тестируется без патча os.name: подмена os.name мутирует
    глобальный модуль os, от которого зависит и pathlib.Path.__new__ (на Linux
    Path() в патч-окне становится WindowsPath), и private_files._is_windows.
    Предмет теста — захват лога и маскирование категорий, а не ACL, поэтому
    приватное хранилище подменяется на no-op."""
    class ExitedProcess:
        returncode = 1

    async def scenario() -> None:
        secret = "PRIVATE_KEY_SHOULD_NOT_ESCAPE"

        async def launch(*_args: object, **kwargs: Any) -> ExitedProcess:
            kwargs["stdout"].write(f"invalid config {secret}".encode())
            kwargs["stdout"].flush()
            return ExitedProcess()

        create_process = AsyncMock(side_effect=launch)
        client = XrayClient(config_directory=Path.cwd())
        config: dict[str, Any] = {"inbounds": [{"protocol": "socks", "port": 18080}]}
        with patch("app.xray.client.secure_directory", lambda _path: None), patch(
            "app.xray.client.secure_file", lambda _path: None
        ), patch(
            "app.xray.client.asyncio.create_subprocess_exec", create_process
        ), pytest.raises(XrayClientError, match="Xray exited during startup") as error:
            await client.start(config)

        assert secret not in str(error.value)
        assert client.diagnostic_categories() == ["configuration_error"]
        assert create_process.await_args.kwargs["stdout"] is not asyncio.subprocess.DEVNULL
        assert create_process.await_args.kwargs["stderr"] is asyncio.subprocess.STDOUT

    asyncio.run(scenario())


def test_diagnostic_categories_never_return_raw_log_lines() -> None:
    client = XrayClient()
    client._log_tail = "reality rejected shortId SECRET_SHORT_ID and privateKey=SECRET_PRIVATE_KEY"
    assert client.diagnostic_categories() == ["reality_handshake"]
    assert "SECRET" not in str(client.diagnostic_categories())
    assert categorize_xray_logs(None) == ["log_unavailable"]


def test_proxy_protocol_failure_is_named_not_unclassified() -> None:
    """Копия клона принимает соединения напрямую: PROXY protocol ломает рукопожатие."""
    client = XrayClient()
    client._log_tail = "[Warning] failed to read PROXY protocol header"
    assert client.diagnostic_categories() == ["proxy_protocol"]


def test_client_log_tail_is_available_for_masked_persistence() -> None:
    client = XrayClient()
    client._log_tail = "raw line"
    assert client.log_tail() == "raw line"
