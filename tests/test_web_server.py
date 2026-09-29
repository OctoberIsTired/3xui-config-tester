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
    assert call(base_url + "/api/runs/20260923-120000-abc123ef/results.csv")[0] == 404, "the download route needs /download/"
    status, _, body = call(base_url + "/api/runs/20260923-120000-abc123ef/download/results.csv")
    assert status == 404 and json.loads(body)["error"] == "FileNotFoundError"
    assert call(base_url + "/api/runs/20260923-120000-abc123ef/download/../../config.yaml")[0] == 404


def test_internal_and_conflict_errors_are_distinguished(backend, monkeypatch) -> None:
    base_url, _ = backend
    service = Handler.service

    def conflict(self) -> None:
        raise RuntimeError("A test run is already active")

    def broken(self) -> None:
        raise PermissionError("denied")

    monkeypatch.setattr(WebService, "run_status", conflict)
    status, _, body = call(base_url + "/api/run/status")
    assert status == 409 and "already active" in json.loads(body)["message"]

    monkeypatch.setattr(WebService, "run_status", broken)
    status, _, body = call(base_url + "/api/run/status")
    assert status == 500 and json.loads(body)["message"] == "Internal server error"


def test_stop_endpoint_answers_for_a_run_without_a_body_argument(backend) -> None:
    """POST /api/run/stop не принимает тело: передача его позиционно давала TypeError,
    который HTTP-слой маскировал в «Internal server error»."""
    base_url, _ = backend
    service = Handler.service
    service._run_state = {"id": "job", "status": "running", "planned_runs": 4}

    status, content_type, body = call(base_url + "/api/run/stop", {})
    assert status == 202 and content_type.startswith("application/json")
    assert json.loads(body)["status"] == "stopping"
    assert service._stop_requested is True


def test_dashboard_reads_the_journal_incrementally(backend) -> None:
    base_url, _ = backend
    service = Handler.service
    run_dir = service.runs_directory() / "20260923-120000-abc123ef"
    run_dir.mkdir(parents=True)
    service._run_state = {"status": "running", "planned_runs": 4, "result_directory": str(run_dir)}

    def record(status: str, digest: str) -> dict:
        return {"phase": "search", "configuration_hash": digest, "configuration": {"network": "tcp"},
                "test_id": "t", "run": 1, "result": {"status": status, "score": 0.5}}

    journal = run_dir / "results.jsonl"
    journal.write_text(json.dumps(record("OK", "h1")) + "\n", encoding="utf-8")
    first = json.loads(call(base_url + "/api/run/dashboard")[2])
    assert first["records"] == 1 and first["attempted"] == 1

    with journal.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record("OK", "h2")) + "\n")
        stream.write(json.dumps(record("SKIPPED", "h3")) + "\n")
    second = json.loads(call(base_url + "/api/run/dashboard")[2])
    assert second["records"] == 3 and second["skipped"] == 1
    assert len(second["candidates"]) == 2

    # No changes since the last poll: the cached result must stay identical.
    third = json.loads(call(base_url + "/api/run/dashboard")[2])
    assert third == second


def test_list_runs_caches_the_record_count_between_changes(backend) -> None:
    base_url, _ = backend
    service = Handler.service
    run_dir = service.runs_directory() / "20260923-120000-abc123ef"
    run_dir.mkdir(parents=True)
    journal = run_dir / "results.jsonl"
    journal.write_text('{"a": 1}\n{"a": 2}\n', encoding="utf-8")

    assert json.loads(call(base_url + "/api/runs")[2])[0]["records"] == 2

    # Same size and mtime, different content: the cached count must survive.
    stamp = journal.stat().st_mtime_ns
    journal.write_text('{"b": 1}\n{"b": 2}\n', encoding="utf-8")
    import os
    os.utime(journal, ns=(stamp, stamp))
    assert json.loads(call(base_url + "/api/runs")[2])[0]["records"] == 2

    journal.write_text('{"a": 1}\n{"a": 2}\n{"a": 3}\n', encoding="utf-8")
    assert json.loads(call(base_url + "/api/runs")[2])[0]["records"] == 3


def test_unknown_static_paths_are_not_served(backend) -> None:
    base_url, _ = backend
    assert call(base_url + "/static/nope.js")[0] == 404
    assert call(base_url + "/static/nope.css")[0] == 404
    assert call(base_url + "/../config.yaml")[0] == 404


def test_page_references_and_backend_serves_static_assets(backend) -> None:
    """The split page must link the split assets, and both must be served."""
    base_url, _ = backend
    status, _, body = call(base_url + "/")
    assert status == 200
    page = body.decode("utf-8")
    assert page.count('/static/app.js') == 1
    assert page.count('/static/app.css') == 1
    assert "<script>" not in page.replace('<script src="/static/app.js" defer></script>', "")

    status, content_type, body = call(base_url + "/static/app.js")
    assert status == 200 and content_type.startswith("text/javascript")
    assert b"function buildDraft" in body

    status, content_type, body = call(base_url + "/static/app.css")
    assert status == 200 and content_type.startswith("text/css")
    assert b".candidate-table" in body
