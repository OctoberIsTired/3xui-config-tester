from pathlib import Path
import threading

import yaml

from app.results.writer import ResultStore
from app.web import PAGE, WebService, _compact_configuration_label
import app.web as web_module

STATIC_DIR = Path(web_module.__file__).with_name("static")
APP_JS = STATIC_DIR.joinpath("app.js").read_text(encoding="utf-8")
APP_CSS = STATIC_DIR.joinpath("app.css").read_text(encoding="utf-8")


def test_reality_file_import_is_available_in_web_ui() -> None:
    rows = WebService.import_reality_candidates(
        "targets:\n  - {target: www.microsoft.com:443, server_name: www.microsoft.com}\n")
    assert rows == [{"target": "www.microsoft.com:443", "server_name": "www.microsoft.com"}]
    assert len(WebService.default_reality_candidates()) == 10
    assert 'id="realityFile"' in PAGE
    assert "/api/reality/import" in APP_JS


def test_web_ui_drops_reality_identity_parameters_from_every_draft() -> None:
    """Preview, run and save all send drafts; all of them must respect the target list."""
    assert "function stripRealityIdentity(draft)" in APP_JS
    # Один общий buildDraft: обе его ветки (полный черновик и подключение)
    # проходят через stripRealityIdentity.
    assert APP_JS.count("return stripRealityIdentity(") == 2
    assert "delete draft.parameters.reality_server_name" not in APP_JS


def test_web_ui_marks_parameters_owned_by_the_reality_target_list() -> None:
    """A parameter the list strips from every draft has to look list-owned in the UI."""
    assert "function listManagedRealityPath(path)" in APP_JS
    assert "const REALITY_LIST_MANAGED_NOTE" in APP_JS
    # The stripper and every mark share one predicate, so a shown mark cannot
    # disagree with what actually leaves the draft.
    assert "if (realityListOwns(item?.path || [])) delete draft.parameters[name];" in APP_JS
    # definition, stripper, renderPresets, card, customCard
    assert APP_JS.count("realityListOwns(") == 5
    assert APP_JS.count("REALITY_LIST_MANAGED_NOTE") == 4  # definition, three marks
    leaves = APP_JS.split("const REALITY_IDENTITY_LEAVES = ", 1)[1].split("];", 1)[0]
    for leaf in ("serverName", "shortId", "password", "publicKey"):
        assert f'"{leaf}"' in leaves
    # Loading or clearing the list re-renders, or a stale mark would survive.
    assert "function showRealityCandidates" in APP_JS
    show_body = APP_JS.split("function showRealityCandidates", 1)[1].split("function selectRealityCandidates", 1)[0]
    assert "renderPresets();" in show_body and "renderCards();" in show_body


def test_web_ui_uses_one_shared_draft_builder() -> None:
    """The duplicated read()/connectionDraft() builders must stay merged."""
    assert APP_JS.count("function buildDraft(") == 1
    assert "function read() {" in APP_JS
    # Полный черновик: preview/run/save; подключение — своя ветка того же сборщика.
    assert "return buildDraft({ includePlan: true });" in APP_JS
    assert 'buildDraft({ includePlan: false })' in APP_JS
    assert "function connectionDraft" not in APP_JS


def test_web_ui_keeps_split_markup_and_assets() -> None:
    """The page is markup only; the logic and styles live in static assets."""
    assert '<link rel="stylesheet" href="/static/app.css">' in PAGE
    assert '<script src="/static/app.js" defer></script>' in PAGE
    assert "<style>" not in PAGE and "function buildDraft" not in PAGE
    assert "candidate-table" in APP_CSS and "badge-running" in APP_CSS


def test_web_ui_keeps_expanded_details_across_redraws() -> None:
    """Поллинг запуска перерисовывает карточку статуса и таблицу кандидатов целиком,
    поэтому раскрытые блоки должны восстанавливаться по ключу, а не сворачиваться."""
    assert "function openDetailsKeys(root)" in APP_JS
    assert "function restoreOpenDetails(root, keys)" in APP_JS
    # definition + renderRun + renderDashboard: у обоих сборщиков одна пара помощников.
    assert APP_JS.count("openDetailsKeys(") == 3
    assert APP_JS.count("restoreOpenDetails(") == 3
    # Ключ есть и у блоков карточки статуса, и у строк таблицы кандидатов.
    block = APP_JS.split("function detailsBlock(", 1)[1].split("</details>`;", 1)[0]
    assert 'data-key="' in block
    assert APP_JS.count('detailsBlock("') == 3  # lastConfiguration, lastMetrics, summary
    assert "details.dataset.key = candidate.label;" in APP_JS
    assert "details.dataset.label" not in APP_JS


def test_web_ui_backfills_security_for_reality_lists() -> None:
    """A REALITY list without a security parameter must be repaired at the
    draft boundary, not rejected by the server after 'Copy inbound' drops it."""
    guard = APP_JS.split("if (realityCandidates.length) {", 1)[1].split("parameters.security = security;", 1)[0]
    assert 'security.values = [...(security.values || []), "reality"]' in guard
    assert '"streamSettings", "security"' in guard
    # The guard lives inside the single shared builder, so every call site gets it.
    builder_start = APP_JS.index("function buildDraft(")
    assert APP_JS.index("if (realityCandidates.length) {", builder_start) > builder_start


def test_web_exposes_cli_candidate_file_as_yaml_snapshot(tmp_path: Path) -> None:
    (tmp_path / "targets.yaml").write_text(
        "targets:\n  - {target: www.microsoft.com:443, server_name: www.microsoft.com}\n", encoding="utf-8")
    config_path = tmp_path / "local.yaml"
    config_path.write_text(yaml.safe_dump({"panel": {}, "inbound": {}, "parameters": {},
                                          "testing": {"reality": {"candidates_file": "targets.yaml"}}}), encoding="utf-8")
    reality = WebService(config_path).public_config()["testing"]["reality"]
    assert reality["candidates"][0]["target"] == "www.microsoft.com:443"
    assert "candidates_file" not in reality


def test_compact_configuration_label_keeps_transport_and_security() -> None:
    serialized = '{"network":"tcp","security":"tls","tls_alpn":["http/1.1"],"tls_server_name":"example.com"}'
    assert _compact_configuration_label(serialized, 1) == "#1 · TCP / TLS"
    assert _compact_configuration_label("{}", 2) == "#2"


def test_web_ui_creates_config_without_preexisting_yaml(tmp_path: Path) -> None:
    config_path = tmp_path / "configs" / "local.yaml"
    service = WebService(config_path)

    draft = service.public_config()
    assert not config_path.exists()
    assert draft["panel"]["url"] == ""
    assert "api_token" not in draft["panel"]
    assert draft["inbound"]["source_id"] is None
    assert draft["testing"]["xray_binary"] == "xray"
    assert service.registry()["live_error"]

    draft["panel"]["url"] = "https://panel.example.test"
    draft["inbound"]["source_id"] = 7
    draft["testing"]["server_address"] = "vpn.example.test"
    draft["testing"]["xray_binary"] = "xray"
    saved = service.save(draft)

    assert config_path.exists()
    assert "api_token" not in saved["panel"]
    stored = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert stored["panel"]["api_token"] == "${PANEL_API_TOKEN}"
    assert stored["inbound"]["source_id"] == 7
    assert stored["testing"]["server_address"] == "vpn.example.test"


def test_web_ui_requires_connection_before_first_save(tmp_path: Path) -> None:
    config_path = tmp_path / "local.yaml"
    service = WebService(config_path)
    draft = service.public_config()
    try:
        service.save(draft)
    except ValueError as error:
        assert "panel URL" in str(error)
    else:
        raise AssertionError("An incomplete first-run config was saved")
    assert not config_path.exists()


def test_inbound_list_is_available_before_config_is_saved(tmp_path: Path, monkeypatch) -> None:
    captured = {}

    class FakePanel:
        def __init__(self, panel, _timeout):
            captured["panel"] = panel

        async def authenticate(self):
            pass

        async def discover(self):
            return {}

        async def list_inbounds(self):
            return [{"id": 7, "remark": "source", "protocol": "vless", "port": 443,
                     "enable": True, "tag": "inbound-7"}]

        async def aclose(self):
            pass

    monkeypatch.setattr("app.web.ThreeXUIClient", FakePanel)
    config_path = tmp_path / "local.yaml"
    rows = WebService(config_path).list_inbounds({"url": "https://panel.example.test", "verify_tls": False})
    assert rows[0]["id"] == 7
    assert captured["panel"]["url"] == "https://panel.example.test"
    assert captured["panel"]["verify_tls"] is False
    assert not config_path.exists()


def test_start_run_defines_job_and_isolated_result_directory(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.yaml"
    raw = {
        "panel": {"url": "https://localhost:2054", "api_token": "${PANEL_API_TOKEN}", "verify_tls": False},
        "inbound": {"mode": "clone", "source_id": 1, "test_port": 9443},
        "testing": {"combination_strategy": "mutation", "mutation_generations": 3, "max_combinations": 5,
                    "server_address": "203.0.113.10", "urls": ["https://example.com"]},
        "parameters": {"network": {"type": "enum", "values": ["tcp"],
                                    "baseline": "tcp", "path": ["streamSettings", "network"]}},
        "output": {"directory": str(tmp_path / "results"), "formats": ["json"]},
    }
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    monkeypatch.setattr(threading.Thread, "start", lambda _thread: None)
    status = WebService(config_path).start_run(raw)
    assert status["id"]
    assert status["status"] == "running"
    assert status["planned_combinations"] == 5
    assert status["planned_runs"] == 5
    assert status["initial_candidates"] == 1
    assert status["mutation_generations"] == 3
    assert Path(status["result_directory"]).parent.name == "runs"


def test_mutation_preview_describes_adaptive_limit(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    raw = {
        "panel": {"url": "https://localhost:2054", "api_token": "${PANEL_API_TOKEN}", "verify_tls": False},
        "inbound": {"mode": "clone", "source_id": 1, "test_port": 9443},
        "testing": {"combination_strategy": "mutation", "mutation_generations": 2,
                    "max_combinations": 7, "server_address": "203.0.113.10"},
        "parameters": {
            "network": {"type": "enum", "values": ["tcp", "ws"], "baseline": "tcp",
                        "mutate": True, "path": ["streamSettings", "network"]},
            "security": {"type": "enum", "values": ["tls"], "baseline": "tls",
                         "mutate": False, "path": ["streamSettings", "security"]},
        },
        "output": {"directory": str(tmp_path / "results"), "formats": ["json"]},
    }
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    preview = WebService(config_path).preview(raw)
    assert preview["adaptive"] is True
    assert preview["planned_combinations"] == 7
    assert preview["planned_runs"] == 7
    assert preview["initial_candidates"] == 2
    assert preview["mutation_generations"] == 2
    assert preview["beam_width"] == 8
    assert preview["children_per_parent"] == 8


def test_preview_warns_about_reality_without_contacting_panel(tmp_path: Path, monkeypatch) -> None:
    raw = {
        "panel": {"url": "https://panel.example.test"},
        "inbound": {"mode": "clone", "source_id": 1},
        "testing": {"server_address": "vpn.example.test", "max_failed_runs": 1,
                    "runs_per_combination": 5},
        "timeouts": {"request": 8, "screening": 8},
        "parameters": {"security": {"type": "enum", "values": ["tls", "reality"],
                                    "path": ["streamSettings", "security"]}},
    }
    monkeypatch.setattr("app.web.ThreeXUIClient", lambda *_: (_ for _ in ()).throw(AssertionError("network")))
    preview = WebService(tmp_path / "missing.yaml").preview(raw)
    assert any("testing.reality.target/server_names" in warning for warning in preview["warnings"])
    assert any("Screening timeout" in warning for warning in preview["warnings"])
    assert any("max_failed_runs" in warning for warning in preview["warnings"])
    raw["testing"]["reality"] = {"target": "www.example.test:443", "server_names": ["www.example.test"]}
    assert not any("testing.reality.target/server_names" in warning
                   for warning in WebService(tmp_path / "missing.yaml").preview(raw)["warnings"])


def test_save_preserves_unedited_timeouts_and_output_formats(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    original = {
        "panel": {"url": "https://localhost:2054", "api_token": "${PANEL_API_TOKEN}", "verify_tls": True,
                  "trust_env": True},
        "inbound": {"mode": "clone", "source_id": 1},
        "testing": {"server_address": "example.test"},
        "timeouts": {"api": 45},
        "parameters": {"network": {"type": "enum", "values": ["tcp"], "path": ["streamSettings", "network"]}},
        "output": {"directory": "./results", "formats": ["csv", "json", "xlsx"]},
    }
    config_path.write_text(yaml.safe_dump(original), encoding="utf-8")
    incoming = {
        "panel": {"url": "https://localhost:2054", "verify_tls": True},
        "inbound": {"mode": "clone", "source_id": 1},
        "testing": {"server_address": "changed.example.test"},
        "parameters": original["parameters"],
        "output": {"directory": "./other-results", "formats": ["xlsx"]},
    }
    WebService(config_path).save(incoming)
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["timeouts"] == {"api": 45}
    assert saved["output"]["formats"] == ["csv", "json", "xlsx"]
    assert saved["panel"]["trust_env"] is True


def test_run_dashboard_aggregates_repeated_measurements(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump({"panel": {}, "inbound": {}, "parameters": {}}), encoding="utf-8")
    result_directory = tmp_path / "results"
    store = ResultStore(result_directory)
    for run, latency, speed in ((1, 100.0, 100.0), (2, 110.0, 140.0)):
        store.append({"test_id": 1, "run": run, "configuration_hash": "abc",
                      "configuration": {"tls_alpn": ["h2"]},
                      "result": {"status": "OK", "score": 0.9, "latency_p95_ms": latency,
                                 "download_mbps": speed}})
    service = WebService(config_path)
    service._run_state = {"status": "completed", "result_directory": str(result_directory), "planned_runs": 5}
    dashboard = service.run_dashboard()
    assert dashboard["records"] == 2
    assert dashboard["success_rate"] == 1.0
    assert dashboard["best_score"]["label"] == '#1 · tls_alpn=["h2"]'
    assert dashboard["candidates"][0]["short_label"] == "#1"
    assert dashboard["candidates"][0]["p95_stddev_ms"] > 0


def test_run_dashboard_counts_skipped_separately(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump({"panel": {}, "inbound": {}, "parameters": {}}), encoding="utf-8")
    result_directory = tmp_path / "results"
    store = ResultStore(result_directory)
    for run, status in ((1, "OK"), (2, "FAILED"), (3, "SKIPPED")):
        store.append({"test_id": run, "run": 1, "configuration_hash": str(run),
                      "configuration": {}, "result": {"status": status}})
    service = WebService(config_path)
    service._run_state = {"status": "completed", "result_directory": str(result_directory), "planned_runs": 3}
    dashboard = service.run_dashboard()
    assert dashboard["records"] == 3
    assert dashboard["attempted"] == 2
    assert dashboard["skipped"] == 1
    assert dashboard["success_rate"] == 0.5
    assert len(dashboard["candidates"]) == 2


def test_run_dashboard_keeps_candidate_rows_in_first_seen_order(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump({"panel": {}, "inbound": {}, "parameters": {}}), encoding="utf-8")
    result_directory = tmp_path / "results"
    store = ResultStore(result_directory)
    service = WebService(config_path)
    service._run_state = {"status": "running", "result_directory": str(result_directory)}

    for test_id, score in ((1, 0.2), (2, 0.9)):
        store.append({"test_id": test_id, "run": 1, "configuration_hash": str(test_id),
                      "configuration": {"candidate": test_id},
                      "result": {"status": "OK", "score": score}})
    assert [item["label"].split(" · ")[0] for item in service.run_dashboard()["candidates"]] == ["#1", "#2"]

    store.append({"test_id": 1, "run": 2, "configuration_hash": "1",
                  "configuration": {"candidate": 1}, "result": {"status": "OK", "score": 1.0}})
    store.append({"test_id": 3, "run": 1, "configuration_hash": "3",
                  "configuration": {"candidate": 3}, "result": {"status": "OK", "score": 0.1}})
    candidates = service.run_dashboard()["candidates"]
    assert [item["label"].split(" · ")[0] for item in candidates] == ["#1", "#2", "#3"]
    assert [item["score"] for item in candidates] == [0.6, 0.9, 0.1]


def test_run_history_lists_reports_and_rejects_unknown_downloads(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    output = tmp_path / "results"
    config_path.write_text(yaml.safe_dump({"output": {"directory": str(output)}}), encoding="utf-8")
    run_id = "20260923-120000-abc123ef"
    run_dir = output / "runs" / run_id
    store = ResultStore(run_dir)
    store.append({"test_id": 1, "run": 1, "configuration": {}, "result": {"status": "OK"}})
    (run_dir / "results.csv").write_text("status\nOK\n", encoding="utf-8")
    (run_dir / "diagnostics.jsonl").write_text('{"status":"OK"}\n', encoding="utf-8")
    (run_dir / ".reality-credentials.json").write_text('{"private_key":"secret"}\n', encoding="utf-8")

    service = WebService(config_path)
    assert service.list_runs() == [{"id": run_id, "status": "saved", "records": 1,
                                    "files": ["results.csv", "results.jsonl", "diagnostics.jsonl"]}]
    assert service.report_path(run_id, "results.csv") == run_dir / "results.csv"
    assert service.report_path(run_id, "diagnostics.jsonl") == run_dir / "diagnostics.jsonl"
    for invalid_id, invalid_file in (("..", "results.csv"), (run_id, "config.yaml"),
                                    (run_id, ".reality-credentials.json")):
        try:
            service.report_path(invalid_id, invalid_file)
        except ValueError:
            pass
        else:
            raise AssertionError("Unexpected report access")
