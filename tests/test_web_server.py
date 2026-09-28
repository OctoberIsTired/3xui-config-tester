from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import yaml

from app.web import ExclusiveThreadingHTTPServer, Handler, WebService

RAW_CONFIG = {
    "panel": {"url": "", "verify_tls": True},
    "inbound": {"mode": "clone", "source_id": 1},
    "testing": {"server_address": "vpn.example.test", "urls": ["https://example.com"],
                "combination_strategy": "pairwise", "max_combinations": 5},
    "parameters": {"network": {"type": "enum", "values": ["tcp"], "path": ["streamSettings", "network"]}},
}


@pytest.fixture()
def backend(tmp_path: Path):
    """Serve the real Handler on an ephemeral port, with the output directory inside tmp."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(
        {**RAW_CONFIG, "output": {"directory": str(tmp_path / "results"), "formats": ["json"]}},
        sort_keys=False), encoding="utf-8")
    Handler.service = WebService(config_path)
    server = ExclusiveThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def call(url: str, body: dict | None = None) -> tuple[int, str, bytes]:
    request = urllib.request.Request(
        url, method="POST" if body is not None else "GET",
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.headers.get("Content-Type", ""), response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.headers.get("Content-Type", ""), error.read()


def test_backend_binds_loopback_and_serves_the_page_and_the_public_config(backend) -> None:
    base_url, server = backend
    assert server.server_address[0] == "127.0.0.1"

    status, content_type, body = call(base_url + "/")
    assert status == 200 and content_type.startswith("text/html")
    assert b'id="parameterCards"' in body

    status, content_type, body = call(base_url + "/api/config")
    draft = json.loads(body)
    assert status == 200 and content_type.startswith("application/json")
    assert draft["panel"]["url"] == "" and "api_token" not in draft["panel"]


def test_preview_endpoint_answers_without_a_panel(backend) -> None:
    base_url, _ = backend
    status, _, body = call(base_url + "/api/preview", {**RAW_CONFIG, "output": {"directory": "./results"}})
    preview = json.loads(body)
    assert status == 200
    assert preview["strategy"] == "pairwise"
    assert preview["raw_combinations"] == 1
    assert preview["planned_combinations"] == 1
    assert preview["preview"] == [{"network": "tcp"}]


def test_reality_import_endpoint_returns_parsed_pairs(backend) -> None:
    base_url, _ = backend
    content = "targets:\n  - {target: www.microsoft.com:443, server_name: www.microsoft.com}\n"
    status, _, body = call(base_url + "/api/reality/import", {"content": content})
    assert status == 200
    assert json.loads(body) == [{"target": "www.microsoft.com:443", "server_name": "www.microsoft.com"}]


def test_empty_dashboard_and_run_list_come_back_as_json(backend) -> None:
    base_url, _ = backend
    status, _, body = call(base_url + "/api/run/dashboard")
    assert status == 200 and json.loads(body)["records"] == 0
    status, _, body = call(base_url + "/api/runs")
    assert status == 200 and json.loads(body) == []


def test_unknown_routes_and_missing_reports_are_rejected(backend) -> None:
    base_url, _ = backend
    assert call(base_url + "/api/nope")[0] == 404
    assert call(base_url + "/api/nope", {})[0] == 404
    assert call(base_url + "/api/runs/20260923-120000-abc123ef/results.csv")[0] == 400, "the download route needs /download/"
    status, _, body = call(base_url + "/api/runs/20260923-120000-abc123ef/download/results.csv")
    assert status == 400 and json.loads(body)["error"] == "FileNotFoundError"
