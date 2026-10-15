from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from app.parameters.generator import configuration_hash
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


def call(url: str, body: dict | None = None, headers: dict | None = None) -> tuple[int, str, bytes]:
    request = urllib.request.Request(
        url, method="POST" if body is not None else "GET",
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        headers={"Content-Type": "application/json", **(headers or {})})
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
    assert page.count('/static/api.js') == 1
    assert page.count('/static/draft.js') == 1
    assert page.count('/static/render.js') == 1
    assert page.count('/static/app.css') == 1
    assert "<script>" not in page.replace(
        '<script src="/static/api.js" defer></script>', ""
    ).replace('<script src="/static/draft.js" defer></script>', "").replace(
        '<script src="/static/render.js" defer></script>', ""
    )

    for name, marker in (("api.js", b"async function call"), ("draft.js", b"function buildDraft"),
                         ("render.js", b"function renderDashboard")):
        status, content_type, body = call(base_url + "/static/" + name)
        assert status == 200 and content_type.startswith("text/javascript")
        assert marker in body

    status, content_type, body = call(base_url + "/static/app.css")
    assert status == 200 and content_type.startswith("text/css")
    assert b".candidate-table" in body


@pytest.mark.parametrize("filename", ["client-xray.log", "run-error.txt"])
def test_diagnostic_downloads_are_text_and_private_snapshots_are_blocked(backend, filename):
    base_url, _ = backend
    directory = Handler.service.runs_directory() / "20261004-120000-abc123ef"
    directory.mkdir(parents=True)
    (directory / filename).write_text("safe diagnostic", encoding="utf-8")
    (directory / "source-inbound-backup.json").write_text("private", encoding="utf-8")
    status, content_type, body = call(base_url + f"/api/runs/{directory.name}/download/{filename}")
    assert status == 200 and content_type == "text/plain; charset=utf-8" and body == b"safe diagnostic"
    assert call(base_url + f"/api/runs/{directory.name}/download/source-inbound-backup.json")[0] == 400


@pytest.mark.parametrize("headers", [{"Host": "attacker.example.test"}, {"Origin": "https://attacker.example.test"},
                                      {"Origin": "null"}, {"Sec-Fetch-Site": "cross-site"}])
def test_browser_requests_require_the_loopback_origin(backend, headers):
    base_url, _ = backend
    assert call(base_url + "/api/config", headers=headers)[0] == 403
    assert call(base_url + "/api/run/stop", {}, headers=headers)[0] == 403


def test_same_origin_preview_and_request_size_limits(backend):
    base_url, _ = backend
    assert call(base_url + "/api/preview", RAW_CONFIG, headers={"Origin": base_url})[0] == 200
    assert call(base_url + "/api/run/stop", {}, headers={"Content-Length": str(Handler.MAX_REQUEST_BYTES + 1)})[0] == 413
    assert call(base_url + "/api/run/stop", {}, headers={"Content-Type": "text/plain"})[0] == 415
    request = urllib.request.Request(base_url + "/api/preview", data=b"[]", headers={"Content-Type": "application/json"})
    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(request, timeout=5)
    assert error.value.code == 400


def test_server_main_waits_for_service_shutdown_before_closing_http(tmp_path, monkeypatch):
    import app.web.server as bootstrap
    import sys
    from types import SimpleNamespace
    events = []
    class Server:
        def __init__(self, *_args): pass
        def serve_forever(self): raise KeyboardInterrupt
        def server_close(self): events.append("http_closed")
    def shutdown(*, timeout):
        assert timeout == 60.0
        events.append("cleanup_joined")
        return True
    monkeypatch.setattr(sys, "argv", ["test", "--config", str(tmp_path / "config.yaml")])
    monkeypatch.setattr(bootstrap, "_bootstrap_config", lambda _path: None)
    monkeypatch.setattr(bootstrap, "WebService", lambda _path: SimpleNamespace(shutdown=shutdown))
    monkeypatch.setattr(bootstrap, "ExclusiveThreadingHTTPServer", Server)
    bootstrap.main()
    assert events == ["cleanup_joined", "http_closed"]


def test_saved_run_dashboard_survives_a_new_service_and_paginates(backend):
    from app.results.writer import ResultStore
    base_url, _ = backend
    original = Handler.service
    directory = original.runs_directory() / "20261004-120000-abc123ef"
    store = ResultStore(directory)
    for index in range(5):
        store.append({"test_id": index, "run": 1, "configuration_hash": str(index),
                      "configuration": {"network": "tcp"}, "result": {"status": "OK"}})
    Handler.service = WebService(original.config_path)
    try:
        path = base_url + f"/api/runs/{directory.name}/dashboard"
        status, _, body = call(path + "?cursor=0&limit=2")
        page = json.loads(body)
        assert status == 200 and page["status"] == "saved"
        assert page["records"] == 5 and len(page["candidates"]) == 2 and page["next_cursor"] == 2
        next_page = json.loads(call(path + "?cursor=2&limit=2")[2])
        assert [row["configuration_hash"] for row in next_page["candidates"]] == ["2", "3"]
        assert call(path + "?limit=201")[0] == 400
        assert call(path + "?cursor=-1")[0] == 400
        assert call(base_url + "/api/run/dashboard?limit=201")[0] == 400
    finally:
        Handler.service = original


@pytest.mark.parametrize("filename", ["results.json", "results.jsonl"])
def test_public_json_download_redaction_preserves_valid_json(backend, filename):
    base_url, _ = backend
    directory = Handler.service.runs_directory() / "20261004-120000-abc123ef"
    directory.mkdir(parents=True)
    payload = {"message": "rejected Bearer FAKE_DOWNLOAD_TOKEN", "result": {"status": "FAILED"}}
    (directory / filename).write_text(json.dumps(payload) + "\n", encoding="utf-8")
    status, _, body = call(base_url + f"/api/runs/{directory.name}/download/{filename}")
    assert status == 200
    redacted = json.loads(body)
    assert redacted["result"]["status"] == "FAILED"
    assert redacted["message"] == "rejected Bearer ***"


# ---------- Продолжение исчерпанного прогона ----------

CONTINUATION_RUN_ID = "20261015-120000-abc123ef"
CONTINUATION_PANEL_URL = "https://panel.example.test"
CONTINUATION_BODY = {
    **RAW_CONFIG,
    "panel": {"url": CONTINUATION_PANEL_URL, "verify_tls": False},
    "testing": {**RAW_CONFIG["testing"], "combination_strategy": "adaptive", "max_combinations": 10,
                "adaptive": {"request_budget": 40, "traffic_budget_bytes": 6000000, "apply_budget": 10,
                             "time_budget_seconds": 240}},
    "output": {"directory": "./results", "formats": ["json"]},
}


class InlineThread(threading.Thread):
    """Прогон в тесте синхронный: start() сразу выполняет worker."""

    def start(self) -> None:
        self.run()


def write_exhausted_run(service: WebService, *, reason: str = "budget_exhausted",
                        run_id: str = CONTINUATION_RUN_ID, used: dict | None = None,
                        identity: str | None = None) -> Path:
    """Чекпойнт завершившегося прогона: бюджет исчерпан, копия уже удалена."""
    directory = service.runs_directory() / run_id
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "results.jsonl").write_text(json.dumps(
        {"test_id": 1, "run": 1, "configuration_hash": "h1", "configuration": {"network": "tcp"},
         "result": {"status": "OK"}}) + "\n", encoding="utf-8")
    budget = {"candidates": 5, "requests": 20, "traffic_bytes": 3000000, "api_applies": 5,
              "client_starts": 1, "elapsed_seconds": 120.0, **(used or {})}
    budget["limits"] = {"candidates": 5, "requests": 20, "traffic_bytes": 3000000,
                        "api_applies": 5, "elapsed_seconds": 120.0}
    if identity is None:
        identity = configuration_hash({"url": CONTINUATION_PANEL_URL})
    (directory / "state.json").write_text(json.dumps({
        "schema_version": 2, "experiment_id": "20261015T120000Z",
        "metadata": {"termination_reason": reason, "panel_identity": identity},
        "completed": 2, "failed": 0, "completed_keys": ["h1:1", "h2:1"],
        "scheduler": {"policy_version": "adaptive-1", "seen": ["h1", "h2"], "selections": 2,
                      "active": None, "frontier": [], "exploitation": [], "confirmed": [], "viable": [],
                      "budget": budget}}), encoding="utf-8")
    return directory


def test_continuation_endpoint_reports_a_missing_or_unfinished_run(backend) -> None:
    base_url, _ = backend
    unknown = base_url + "/api/runs/20261015-120000-ffffffff/continue"
    assert call(unknown, CONTINUATION_BODY)[0] == 404
    directory = write_exhausted_run(Handler.service, reason="frontier_exhausted")
    status, _, body = call(base_url + f"/api/runs/{directory.name}/continue", CONTINUATION_BODY)
    assert status == 409 and "budget exhaustion" in json.loads(body)["message"]


def test_continuation_endpoint_rejects_a_budget_that_is_not_raised(backend) -> None:
    base_url, _ = backend
    directory = write_exhausted_run(Handler.service)
    lowered = {**CONTINUATION_BODY, "testing": {**CONTINUATION_BODY["testing"],
               "adaptive": {**CONTINUATION_BODY["testing"]["adaptive"], "request_budget": 10}}}
    status, _, body = call(base_url + f"/api/runs/{directory.name}/continue", lowered)
    assert status == 400 and "must not lower the requests budget" in json.loads(body)["message"]
    unchanged = {**CONTINUATION_BODY, "testing": {**CONTINUATION_BODY["testing"],
                 "adaptive": {**CONTINUATION_BODY["testing"]["adaptive"], "request_budget": 20}}}
    status, _, body = call(base_url + f"/api/runs/{directory.name}/continue", unchanged)
    assert status == 400 and "already used up at 20" in json.loads(body)["message"]


def test_continuation_endpoint_starts_a_resumed_job(backend, monkeypatch) -> None:
    base_url, _ = backend
    directory = write_exhausted_run(Handler.service)
    captured = {}

    class ContinuingRunner:
        def __init__(self, config, _client, _progress) -> None:
            captured["directory"] = str(config.output_dir)
            captured["candidates"] = config.max_combinations

        async def run(self, *, resume=False, max_tests=None, dry_run=False):
            captured.update(resume=resume, max_tests=max_tests)
            return {"experiment_id": "20261015T120000Z", "completed": 2, "termination_reason": "frontier_exhausted"}

    monkeypatch.setattr("app.web.service.ExperimentRunner", ContinuingRunner)
    monkeypatch.setattr("app.web.service.threading",
                        SimpleNamespace(Thread=InlineThread, Lock=threading.Lock))
    status, content_type, body = call(base_url + f"/api/runs/{directory.name}/continue", CONTINUATION_BODY)
    assert status == 202 and content_type.startswith("application/json")
    payload = json.loads(body)
    assert payload["run_id"] == directory.name and payload["resumed"] is True
    assert Path(payload["result_directory"]) == directory
    assert captured == {"directory": str(directory), "candidates": 10, "resume": True, "max_tests": 10}
