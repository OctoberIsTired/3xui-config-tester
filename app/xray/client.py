from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryFile
from typing import Any, BinaryIO
from app.security.private_files import secure_directory, secure_file


class XrayClientError(RuntimeError):
    pass


def categorize_xray_logs(raw: str | None) -> list[str]:
    """Map sensitive log text to stable, non-sensitive diagnostic codes."""
    lower = (raw or "").lower()
    if not lower.strip():
        return ["log_unavailable"]
    patterns = (
        ("configuration_error", ("failed to parse", "invalid config", "failed to load", "failed to build")),
        ("reality_handshake", ("reality", "shortid", "short id")),
        ("tls_handshake", ("tls handshake", "certificate", "x509")),
        ("xhttp_error", ("xhttp", "splithttp")),
        ("connection_timeout", ("timeout", "deadline exceeded")),
        ("connection_refused", ("connection refused", "actively refused")),
        ("network_unreachable", ("network is unreachable", "no route to host")),
        ("authentication_error", ("authentication failed", "invalid user")),
        ("proxy_protocol", ("proxy protocol", "proxyprotocol", "proxy_protocol")),
    )
    found = [category for category, phrases in patterns if any(phrase in lower for phrase in phrases)]
    return found or ["log_unclassified"]


class XrayClient:
    MAX_LOG_BYTES = 64 * 1024

    def __init__(self, binary: str = "xray", start_timeout: float = 15, config_directory: Path | None = None):
        self.binary, self.start_timeout = binary, start_timeout
        self.config_directory = config_directory
        self.process: asyncio.subprocess.Process | None = None
        self.config_path: Path | None = None
        self._log_file: BinaryIO | None = None
        self._log_tail = ""

    async def start(self, config: dict[str, Any]) -> None:
        await self.stop()
        self._log_tail = ""
        if self.config_directory:
            secure_directory(self.config_directory)
        with NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False,
                                dir=str(self.config_directory) if self.config_directory else None) as file:
            self.config_path = Path(file.name)
            try:
                secure_file(self.config_path)
                json.dump(config, file)
            except BaseException:
                file.close()
                self.config_path.unlink(missing_ok=True)
                self.config_path = None
                raise
        # A regular file works with Windows subprocess handles and cannot block
        # Xray when its output is more verbose than a pipe reader can consume.
        self._log_file = TemporaryFile(mode="w+b", dir=str(self.config_directory) if self.config_directory else None)
        try:
            self.process = await asyncio.create_subprocess_exec(
                self.binary, "run", "-c", str(self.config_path),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=self._log_file, stderr=asyncio.subprocess.STDOUT,
            )
        except BaseException:
            await self.stop()
            raise
        socks = next((item for item in config.get("inbounds", []) if item.get("protocol") == "socks"), None)
        if not socks:
            await self.stop()
            raise XrayClientError("Client config has no SOCKS inbound for readiness check")
        try:
            await asyncio.wait_for(
                self._confirm_running(str(socks.get("listen", "127.0.0.1")), int(socks["port"])),
                timeout=self.start_timeout,
            )
        except Exception:
            await self.stop()
            raise

    async def _confirm_running(self, host: str, port: int) -> None:
        assert self.process is not None
        while True:
            if self.process.returncode is not None:
                raise XrayClientError("Xray exited during startup; see diagnostic categories")
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=.25)
                writer.close()
                await writer.wait_closed()
                return
            except (OSError, TimeoutError):
                await asyncio.sleep(.1)

    async def stop(self) -> None:
        if self.process and self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=5)
            except TimeoutError:
                self.process.kill()
                await self.process.wait()
        self.process = None
        if self._log_file:
            self._log_file.flush()
            size = os.fstat(self._log_file.fileno()).st_size
            self._log_file.seek(max(0, size - self.MAX_LOG_BYTES))
            self._log_tail = self._log_file.read(self.MAX_LOG_BYTES).decode("utf-8", errors="replace")
            self._log_file.close()
            self._log_file = None
        if self.config_path:
            self.config_path.unlink(missing_ok=True)
            self.config_path = None

    def diagnostic_categories(self) -> list[str]:
        """Return stable categories only; never expose potentially secret Xray lines."""
        return categorize_xray_logs(self._log_tail)

    def log_tail(self) -> str:
        """Raw client log tail; callers must mask it before persisting."""
        return self._log_tail
