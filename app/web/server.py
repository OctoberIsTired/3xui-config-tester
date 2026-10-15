"""Server bootstrap: config bootstrap, banner and main()."""
from __future__ import annotations
import socket

import argparse
import shutil
import sys
from http.server import ThreadingHTTPServer
from pathlib import Path

from app.web.handler import Handler
from app.web.service import WebService


class ExclusiveThreadingHTTPServer(ThreadingHTTPServer):
    """Reject a second backend on the same Windows port instead of sharing it."""

    daemon_threads = True
    allow_reuse_address = False

    def server_bind(self) -> None:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def _bootstrap_config(config_path: Path) -> None:
    """Create the local config from the shipped example when it is missing."""
    if config_path.exists():
        return
    example = Path(__file__).resolve().parents[2] / "configs" / "example.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    if example.exists():
        shutil.copyfile(example, config_path)
    else:
        config_path.write_text("", encoding="utf-8")


def _startup_banner(port: int) -> str:
    return (
        f"3xui-config-tester UI: http://127.0.0.1:{port}\n"
        "Конфиг: configs/local.yaml (создаётся автоматически из configs/example.yaml)\n"
        "Остановка: Ctrl+C"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Local configuration UI for 3xui-config-tester")
    parser.add_argument("--config", type=Path, default=Path("configs/local.yaml"))
    parser.add_argument("--port", type=int, default=8765)
    options = parser.parse_args()
    _bootstrap_config(options.config)
    Handler.service = WebService(options.config)
    server = ExclusiveThreadingHTTPServer(("127.0.0.1", options.port), Handler)
    print(_startup_banner(options.port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            shutdown = getattr(Handler.service, "shutdown", None)
            if shutdown is not None:
                if not shutdown(timeout=60.0):
                    print("Остановка не завершена: проверьте recovery manifest перед следующим запуском", file=sys.stderr)
            else:
                Handler.service.stop_run()
        finally:
            server.server_close()


if __name__ == "__main__":
    main()
