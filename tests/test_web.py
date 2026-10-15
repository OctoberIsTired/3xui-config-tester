from pathlib import Path
import asyncio
import json
import threading
from types import SimpleNamespace

import yaml
import pytest

from app.api.three_xui import PanelAPIRejected
from app.parameters.generator import configuration_hash
from app.results.writer import ResultStore
from app.web import PAGE, WebService, _compact_configuration_label
import app.web as web_module

STATIC_DIR = Path(web_module.__file__).resolve().parent.parent / "static"
APP_JS = "\n".join(
    STATIC_DIR.joinpath(name).read_text(encoding="utf-8") for name in ("api.js", "draft.js", "render.js")
)
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
    # проходят через stripRealityIdentity, а поверх неё — через
    # ensureRealitySecurity (см. test_web_ui_backfills_security_for_reality_lists).
    assert APP_JS.count("return ensureRealitySecurity(stripRealityIdentity(") == 2
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
    assert '<script src="/static/render.js" defer></script>' in PAGE
    assert '<script src="/static/draft.js" defer></script>' in PAGE
    assert '<script src="/static/api.js" defer></script>' in PAGE
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
    assert "function ensureRealitySecurity(draft)" in APP_JS
    guard = APP_JS.split("function ensureRealitySecurity(draft)", 1)[1].split("function buildDraft(", 1)[0]
    assert 'security.values = [...(security.values || []), "reality"]' in guard
    assert '"streamSettings", "security"' in guard
    # Helper определён до сборщика, поэтому достроенный security не может быть
    # срезан stripRealityIdentity как identity-параметр.
    assert APP_JS.index("function ensureRealitySecurity(draft)") < APP_JS.index("function buildDraft(")
    # Гарантия стоит на обеих ветках buildDraft: полный черновик (preview/run/
    # save) и сохранение подключения, чей parameters берётся из YAML как есть.
    assert APP_JS.count("return ensureRealitySecurity(stripRealityIdentity(") == 2


def test_web_ui_requires_a_value_only_for_closed_parameter_domains() -> None:
    """«Выберите хотя бы одно значение» — требование для закрытого домена (enum).
    String-параметр с сохранённым значением вне подсказок (SNI, введённый
    вручную) не оставляет активных чипов и не должен валить весь черновик."""
    guard = APP_JS.split("item.values = draftValues[key];", 1)[1].split("parameters[key] = item;", 1)[0]
    assert 'if (s.type === "string") return;' in guard
    assert "throw Error(`${s.title}: ${L.errors.noValues}`)" in guard
    # Правка живёт внутри единственного сборщика, а не в местах вызова.
    builder = APP_JS.index("function buildDraft(")
    assert APP_JS.index('if (s.type === "string") return;', builder) > builder
    # Параметр без значений нельзя отправить вовсе: сервер требует values или
    # диапазон, поэтому пропуск карточки — не подмена ключа.
    assert "delete item.values" not in APP_JS


def test_web_ui_shows_saved_string_values_outside_the_suggestions() -> None:
    """Сохранённое string-значение вне подсказок реестра снова рисуется чипом,
    иначе syncDraft собирает пустой набор и молча теряет выбор пользователя."""
    body = APP_JS.split("let active = selectedValues(name, spec);", 1)[1].split("chips(name, options, active)", 1)[0]
    assert 'spec.type === "string"' in body
    assert "spec.values.concat(" in body
    assert "chips(name, spec.values, active)" not in APP_JS
    assert APP_JS.count("chips(name, options, active)") == 1


def test_web_ui_exposes_the_clone_port_list() -> None:
    """Порт клона — список: firewall открывает отдельные порты, а не сплошной диапазон."""
    assert 'id="clonePorts"' in PAGE
    assert 'id="testPort"' in PAGE
    parser = APP_JS.split("function parseClonePorts", 1)[1].split("function buildDraft", 1)[0]
    assert "return { ports: numbers };" in parser
    assert "return { port_range: [low, high] };" in parser
    builder = APP_JS.split("function buildDraft", 1)[1]
    assert 'clonePorts = parseClonePorts($("clonePorts").value)' in builder
    assert "...clonePorts," in builder
    # Диапазон и список — один ключ каждый: устаревший не должен пережить сохранение.
    assert "delete testing.port_range;" in builder and "delete testing.ports;" in builder
    # Загруженный конфиг переносится в поле в той же форме, в которой был записан.
    assert 't.ports.join(", ")' in APP_JS
    assert 't.port_range.join("-")' in APP_JS


def test_web_ui_shows_the_created_test_inbound() -> None:
    """Во время прогона должно быть видно, что копия создана и на каком порту."""
    assert "d.test_inbound_id !== undefined" in APP_JS
    assert "L.testInbound" in APP_JS and "L.portLabel" in APP_JS


class InlineThread(threading.Thread):
    """Прогон в тесте синхронный: start() сразу выполняет worker."""

    def start(self) -> None:
        self.run()


def test_failed_run_keeps_the_error_next_to_the_results(tmp_path: Path, monkeypatch) -> None:
    """Текст ошибки нужен после перезагрузки страницы: _run_state живёт только в памяти."""
    config_path = tmp_path / "config.yaml"
    raw = {
        "panel": {"url": "https://localhost:2054", "api_token": "${PANEL_API_TOKEN}", "verify_tls": False},
        "inbound": {"mode": "clone", "source_id": 1},
        "testing": {"combination_strategy": "mutation", "max_combinations": 1,
                    "server_address": "203.0.113.10", "urls": ["https://example.com"]},
        "parameters": {},
        "output": {"directory": str(tmp_path / "results"), "formats": ["json"]},
    }
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")

    class FailingRunner:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        async def run(self, **_kwargs):
            raise RuntimeError("panel rejected the test inbound")

    monkeypatch.setattr("app.web.service.ExperimentRunner", FailingRunner)
    monkeypatch.setattr("app.web.service.threading",
                        SimpleNamespace(Thread=InlineThread, Lock=threading.Lock))
    status = WebService(config_path).start_run(raw)
    assert status["status"] == "failed"
    assert "panel rejected the test inbound" in status["error"]
    saved = Path(status["result_directory"]) / "run-error.txt"
    assert "panel rejected the test inbound" in saved.read_text(encoding="utf-8")


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

    monkeypatch.setattr("app.web.service.ThreeXUIClient", FakePanel)
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
    assert preview["validation_level"] == "offline"
    assert preview["planned_combinations"] == 7
    assert preview["planned_runs"] == 7
    assert preview["initial_candidates"] == 2
    assert preview["mutation_generations"] == 2
    assert preview["beam_width"] == 8
    assert preview["children_per_parent"] == 8


# ---------- Продолжение исчерпанного прогона ----------

EXHAUSTED_RUN_ID = "20261015-120000-abc123ef"
EXHAUSTED_DRAFT = {
    "panel": {"url": "https://panel.example.test", "api_token": "${PANEL_API_TOKEN}", "verify_tls": False},
    "inbound": {"mode": "clone", "source_id": 1, "test_port": 9443},
    "testing": {"server_address": "203.0.113.10", "urls": ["https://example.com"],
                "combination_strategy": "adaptive", "max_combinations": 10,
                "adaptive": {"request_budget": 20, "traffic_budget_bytes": 3000000, "apply_budget": 5,
                             "time_budget_seconds": 120}},
    "parameters": {"network": {"type": "enum", "values": ["tcp"], "baseline": "tcp",
                               "path": ["streamSettings", "network"]}},
    "output": {"directory": "./results", "formats": ["json"]},
}


def continuing_service(tmp_path: Path) -> WebService:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump({**EXHAUSTED_DRAFT,
        "output": {"directory": str(tmp_path / "results"), "formats": ["json"]}}), encoding="utf-8")
    return WebService(config_path)


def write_exhausted_checkpoint(service: WebService, *, reason: str = "budget_exhausted",
                               run_id: str = EXHAUSTED_RUN_ID, used: dict | None = None,
                               limits: dict | None = None, identity: str | None = None) -> Path:
    """Сохранить прогон так, как его оставляет завершившийся адаптивный поиск."""
    directory = service.runs_directory() / run_id
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "results.jsonl").write_text(json.dumps(
        {"test_id": 1, "run": 1, "configuration_hash": "h1", "configuration": {"network": "tcp"},
         "result": {"status": "OK", "score": 1.0}}) + "\n", encoding="utf-8")
    recorded = {"candidates": 10, "requests": 20, "traffic_bytes": 3000000, "api_applies": 5,
                "client_starts": 1, "elapsed_seconds": 120.0, **(used or {})}
    recorded["limits"] = {"candidates": 10, "requests": 20, "traffic_bytes": 3000000, "api_applies": 5,
                          "elapsed_seconds": 120.0, **(limits or {})}
    if identity is None:
        identity = configuration_hash({"url": service.raw_config().get("panel", {}).get("url")})
    (directory / "state.json").write_text(json.dumps({
        "schema_version": 2, "experiment_id": "20261015T120000Z",
        "metadata": {"termination_reason": reason, "panel_identity": identity},
        "completed": 7, "failed": 1, "completed_keys": [f"h{index}:1" for index in range(7)],
        "scheduler": {"policy_version": "adaptive-1", "seen": ["h1", "h2"], "selections": 2,
                      "exploration_selections": 2, "active": None, "frontier": [], "exploitation": [],
                      "confirmed": [], "viable": [], "coverage": {}, "seed": 0, "budget": recorded}}),
        encoding="utf-8")
    return directory


def doubled(draft: dict) -> dict:
    """Черновик, который отправляет кнопка «Продолжить с бюджетом ×2»."""
    raw = json.loads(json.dumps(draft))
    raw["testing"]["max_combinations"] *= 2
    adaptive = raw["testing"]["adaptive"]
    for key in ("request_budget", "traffic_budget_bytes", "apply_budget", "time_budget_seconds"):
        adaptive[key] *= 2
    raw["output"] = {"directory": str(draft.get("output", {}).get("directory", "./results")), "formats": ["json"]}
    return raw


def test_continue_run_reuses_the_directory_checkpoint_and_new_limits(tmp_path: Path, monkeypatch) -> None:
    """Продолжение — тот же каталог и чекпойнт, но с новым бюджетом и resume=True."""
    service = continuing_service(tmp_path)
    directory = write_exhausted_checkpoint(service)
    captured = {}

    class ContinuingRunner:
        def __init__(self, config, _client, _progress) -> None:
            captured["directory"] = str(config.output_dir)
            captured["adaptive"] = dict(config.adaptive)
            captured["candidates"] = config.max_combinations

        async def run(self, *, resume=False, max_tests=None, dry_run=False):
            captured.update(resume=resume, max_tests=max_tests)
            return {"experiment_id": "20261015T120000Z", "completed": 9, "termination_reason": "first_confirmed"}

    monkeypatch.setattr("app.web.service.ExperimentRunner", ContinuingRunner)
    monkeypatch.setattr("app.web.service.threading",
                        SimpleNamespace(Thread=InlineThread, Lock=threading.Lock))
    status = service.continue_run(directory.name, doubled(EXHAUSTED_DRAFT))

    assert captured["directory"] == str(directory)
    assert captured["resume"] is True and captured["max_tests"] == 20
    assert captured["candidates"] == 20 and captured["adaptive"]["request_budget"] == 40
    assert captured["adaptive"]["traffic_budget_bytes"] == 6000000
    assert status["run_id"] == directory.name and Path(status["result_directory"]) == directory
    assert status["resumed"] is True
    assert status["continuation"]["budget"] == {"candidates": 20, "requests": 40, "traffic_bytes": 6000000,
                                                "api_applies": 10, "elapsed_seconds": 240.0}
    # Прогресс прошлого прогона переносится в статус, а не начинается с нуля.
    assert status["completed"] == 7 and status["failed"] == 1


def test_continue_run_needs_a_run_that_stopped_on_budget_exhaustion(tmp_path: Path) -> None:
    service = continuing_service(tmp_path)
    directory = write_exhausted_checkpoint(service, reason="frontier_exhausted")
    with pytest.raises(RuntimeError, match="budget exhaustion"):
        service.continue_run(directory.name, doubled(EXHAUSTED_DRAFT))
    assert service.run_status()["status"] == "idle"


def test_continue_run_rejects_an_unknown_or_unreadable_run(tmp_path: Path) -> None:
    service = continuing_service(tmp_path)
    with pytest.raises(ValueError, match="Unknown run"):
        service.continue_run("../../config", doubled(EXHAUSTED_DRAFT))
    with pytest.raises(FileNotFoundError, match="not available"):
        service.continue_run("20261015-120000-ffffffff", doubled(EXHAUSTED_DRAFT))
    directory = service.runs_directory() / EXHAUSTED_RUN_ID
    directory.mkdir(parents=True)
    with pytest.raises(FileNotFoundError, match="no checkpoint"):
        service.continue_run(EXHAUSTED_RUN_ID, doubled(EXHAUSTED_DRAFT))


def test_continue_run_rejects_a_lower_or_used_up_budget(tmp_path: Path) -> None:
    """Больший бюджет — единственное, что оправдывает продолжение."""
    service = continuing_service(tmp_path)
    directory = write_exhausted_checkpoint(service)
    lowered = doubled(EXHAUSTED_DRAFT)
    lowered["testing"]["adaptive"]["request_budget"] = 5
    with pytest.raises(ValueError, match="must not lower the requests budget"):
        service.continue_run(directory.name, lowered)
    unchanged = doubled(EXHAUSTED_DRAFT)
    unchanged["testing"]["adaptive"]["request_budget"] = 20
    with pytest.raises(ValueError, match="already used up at 20"):
        service.continue_run(directory.name, unchanged)


def test_continue_run_rejects_a_budget_that_changes_nothing(tmp_path: Path) -> None:
    service = continuing_service(tmp_path)
    directory = write_exhausted_checkpoint(service, used={"requests": 4, "candidates": 2, "traffic_bytes": 10,
                                                          "api_applies": 1, "elapsed_seconds": 3.0})
    with pytest.raises(ValueError, match="nothing new would be measured"):
        service.continue_run(directory.name, EXHAUSTED_DRAFT)


def test_continue_run_refuses_a_different_panel(tmp_path: Path) -> None:
    service = continuing_service(tmp_path)
    directory = write_exhausted_checkpoint(
        service, identity=configuration_hash({"url": "https://other.example.test"}))
    with pytest.raises(ValueError, match="panel identity"):
        service.continue_run(directory.name, doubled(EXHAUSTED_DRAFT))


def test_continue_run_refuses_a_non_adaptive_draft(tmp_path: Path) -> None:
    service = continuing_service(tmp_path)
    directory = write_exhausted_checkpoint(service)
    draft = doubled(EXHAUSTED_DRAFT)
    draft["testing"]["combination_strategy"] = "pairwise"
    with pytest.raises(ValueError, match="adaptive search"):
        service.continue_run(directory.name, draft)


def test_continue_run_waits_for_an_active_run_and_for_inbound_recovery(tmp_path: Path) -> None:
    service = continuing_service(tmp_path)
    directory = write_exhausted_checkpoint(service)
    service._run_state = {"id": "job", "status": "running"}
    with pytest.raises(RuntimeError, match="already active"):
        service.continue_run(directory.name, doubled(EXHAUSTED_DRAFT))

    service._run_state = {"status": "idle"}
    recovery = directory / ".recovery"
    recovery.mkdir()
    (recovery / "inbound-recovery.json").write_text(
        json.dumps({"version": 1, "state": "create_pending", "source_id": 1}), encoding="utf-8")
    with pytest.raises(RuntimeError, match="Unfinished inbound cleanup"):
        service.continue_run(directory.name, doubled(EXHAUSTED_DRAFT))
    assert service.run_status()["status"] == "cleanup_pending"


def test_web_ui_offers_the_continuation_only_for_a_budget_exhausted_run() -> None:
    """Кнопка продолжения привязана к причине остановки и одному эндпоинту."""
    assert "function continuationActions(runId, reason)" in APP_JS
    assert 'reason !== "budget_exhausted"' in APP_JS
    assert "function doubleBudgetInputs()" in APP_JS
    assert APP_JS.count("BUDGET_INPUT_IDS") == 2
    # Новые лимиты берутся из формы: отправляется тот же черновик, что и на старт.
    assert 'encodeURIComponent(runId)}/continue`, "POST", read()' in APP_JS
    # Карточка статуса (две кнопки) и история (одна) — из одной фабрики и одного словаря.
    assert APP_JS.count('data-action="continue-run" data-run-id') == 3
    assert "esc(L.continueRun)" in APP_JS and "esc(L.continueRunDoubled)" in APP_JS
    assert "L.historyContinue" in APP_JS
    assert "continuationActions(activeRunId, finishedReason)" in APP_JS
    assert 'document.querySelectorAll(\'[data-action="continue-run"]\')' in APP_JS


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
    monkeypatch.setattr("app.web.service.ThreeXUIClient", lambda *_: (_ for _ in ()).throw(AssertionError("network")))
    preview = WebService(tmp_path / "missing.yaml").preview(raw)
    assert any("testing.reality.target/server_names" in warning for warning in preview["warnings"])
    assert any("Screening timeout" in warning for warning in preview["warnings"])
    assert any("max_failed_runs" in warning for warning in preview["warnings"])
    raw["testing"]["reality"] = {"target": "www.example.test:443", "server_names": ["www.example.test"]}
    assert not any("testing.reality.target/server_names" in warning
                   for warning in WebService(tmp_path / "missing.yaml").preview(raw)["warnings"])


def test_save_rejects_reality_candidates_without_security_reality(tmp_path: Path) -> None:
    """Серверный guard причины «REALITY candidates require a security parameter
    containing reality»: черновик сохранения подключения, чей parameters взят из
    загруженного YAML как есть, не должен доходить до файла конфигурации."""
    raw = {
        "panel": {"url": "https://localhost:2054", "api_token": "${PANEL_API_TOKEN}"},
        "inbound": {"mode": "clone", "source_id": 1},
        "testing": {"server_address": "vpn.example.test",
                    "reality": {"candidates": [{"target": "www.microsoft.com:443",
                                                "server_name": "www.microsoft.com"}]}},
        "parameters": {"security": {"type": "enum", "values": ["none", "tls"],
                                    "path": ["streamSettings", "security"]}},
        "output": {"directory": str(tmp_path / "results"), "formats": ["json"]},
    }
    config_path = tmp_path / "config.yaml"
    with pytest.raises(ValueError, match="REALITY candidates require a security parameter"):
        WebService(config_path).save(raw)
    assert not config_path.exists()


def test_preview_accepts_the_repaired_reality_draft(tmp_path: Path) -> None:
    """Черновик после клиентской достройки ensureRealitySecurity — candidates +
    security, содержащий reality, — сервер принимает без панели."""
    raw = {
        "panel": {"url": "https://panel.example.test"},
        "inbound": {"mode": "clone", "source_id": 1},
        "testing": {"server_address": "vpn.example.test", "max_failed_runs": 1,
                    "runs_per_combination": 5,
                    "reality": {"candidates": [{"target": "www.microsoft.com:443",
                                                "server_name": "www.microsoft.com"}]}},
        "timeouts": {"request": 8, "screening": 8},
        "parameters": {"security": {"type": "enum", "values": ["none", "tls", "reality"],
                                    "path": ["streamSettings", "security"]}},
    }
    service = WebService(tmp_path / "missing.yaml")
    preview = service.preview(raw)
    assert preview["planned_combinations"] >= 1


def test_registry_reports_missing_source_inbound_with_available_ids(tmp_path: Path, monkeypatch) -> None:
    """Панель отвечает, но сохранённого source_id на ней нет (inbound пересоздали
    или удалили): диагностика должна назвать доступные идентификаторы, а не
    показывать сырой ответ панели как «API панели недоступен»."""
    config_path = tmp_path / "local.yaml"
    config_path.write_text(yaml.safe_dump({
        "panel": {"url": "https://panel.example.test", "api_token": "token"},
        "inbound": {"mode": "clone", "source_id": 10},
        "parameters": {},
    }), encoding="utf-8")

    class _Stub:
        def __init__(self, *_args): pass
        async def authenticate(self): pass
        async def discover(self): return {"info": {"version": "3.x"}}
        async def get_inbound(self, inbound_id):
            raise PanelAPIRejected("Obtain (record not found)")
        async def list_inbounds(self):
            return [{"id": 1}, {"id": 9}, {"id": 13}]
        async def aclose(self): pass

    monkeypatch.setattr("app.web.service.ThreeXUIClient", _Stub)
    catalog = WebService(config_path).registry()
    assert "source_id 10 отсутствует на панели" in catalog["live_error"]
    assert "1, 9, 13" in catalog["live_error"]
    assert catalog["environment"]["panel_access"] == "available"


def test_registry_keeps_unavailable_marking_for_transport_errors(tmp_path: Path, monkeypatch) -> None:
    """Сетевая ошибка — прежний путь: панель недоступна; подмена маркировки
    «доступна» для отказов транспорта недопустима."""
    config_path = tmp_path / "local.yaml"
    config_path.write_text(yaml.safe_dump({
        "panel": {"url": "https://panel.example.test", "api_token": "token"},
        "inbound": {"mode": "clone", "source_id": 1},
        "parameters": {},
    }), encoding="utf-8")

    class _Stub:
        def __init__(self, *_args): pass
        async def authenticate(self): raise ConnectionError("route down")
        async def aclose(self): pass

    monkeypatch.setattr("app.web.service.ThreeXUIClient", _Stub)
    catalog = WebService(config_path).registry()
    assert catalog["environment"]["panel_access"] == "unavailable"
    assert "ConnectionError" in catalog["live_error"]


def test_web_ui_distinguishes_missing_source_from_panel_outage() -> None:
    """Обе точки с live_error (saveConnection и renderMeta) различают «записи нет»
    (панель отвечает) и «панель недоступна», опираясь на один marker —
    environment.panel_access из WebService.registry()."""
    save_body = APP_JS.split("async function saveConnection", 1)[1].split("async function loadInbounds", 1)[0]
    meta_body = APP_JS.split("function renderMeta", 1)[1].split("$('routeStatus')", 1)[0]
    for body in (save_body, meta_body):
        assert 'registry.environment?.panel_access' in body
        assert '"available"' in body
    assert "но настройки источника не загружены: " in save_body
    assert "но настройки источника не получены: " in meta_body
    assert "но API панели недоступен: " in APP_JS
    assert APP_JS.count("async function saveConnection") == 1


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
    assert service.list_runs() == [{"id": run_id, "status": "saved", "cleanup_pending": False, "records": 1,
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


@pytest.mark.parametrize("with_journal", [False, True])
def test_saved_history_and_dashboard_read_only_public_checkpoint_fields_after_restart(tmp_path, with_journal):
    service, _ = _safety_service(tmp_path)
    run_id = "20261004-120000-abc123ef"
    directory = service.runs_directory() / run_id
    directory.mkdir(parents=True)
    private_secret = "FAKE_SAVED_CHECKPOINT_PRIVATE_KEY"
    budget = {"candidates": 3, "requests": 15, "traffic_bytes": 4096, "api_applies": 4,
              "client_starts": 4, "elapsed_seconds": 12.4,
              "limits": {"candidates": 8, "requests": 60, "traffic_bytes": 30000000,
                         "api_applies": 10, "elapsed_seconds": 120}}
    checkpoint = {"experiment_id": "private-experiment", "completed_keys": ["private-hash:1"],
                  "metadata": {"termination_reason": "first_confirmed", "confirmed_candidates": 1,
                               "viable_candidates": 2, "private_key": private_secret,
                               "panel": {"api_token": "FAKE_SAVED_CHECKPOINT_PANEL_TOKEN"}},
                  "scheduler": {"budget": {**budget, "private_key": private_secret,
                                           "unknown": {"payload": private_secret}},
                                "frontier": [{"identity": private_secret}], "pending_trial": {"password": private_secret}}}
    (directory / "state.json").write_text(json.dumps(checkpoint), encoding="utf-8")
    if with_journal:
        ResultStore(directory).append({"test_id": 1, "run": 1, "configuration_hash": "one",
                                       "configuration": {"network": "tcp"}, "qualification": "preliminary",
                                       "result": {"status": "OK", "score": .9}})

    restarted = WebService(service.config_path)
    history = restarted.list_runs()[0]
    dashboard = restarted.saved_run_dashboard(run_id)
    for payload in (history, dashboard):
        assert payload["termination_reason"] == "first_confirmed"
        assert payload["confirmed_candidates"] == 1 and payload["viable_candidates"] == 2
        assert payload["budget"] == budget
        serialized = json.dumps(payload)
        assert "FAKE_SAVED_CHECKPOINT" not in serialized
        assert "completed_keys" not in serialized and "private-experiment" not in serialized
        assert "frontier" not in serialized and "pending_trial" not in serialized
    assert set(history) == {"id", "status", "cleanup_pending", "records", "files",
                            "termination_reason", "confirmed_candidates", "viable_candidates", "budget"}
    # Even a private literal accidentally repeated in an allowed text field
    # must be hidden; registering the checkpoint must precede its projection.
    checkpoint["metadata"]["termination_reason"] = "failed: " + private_secret
    (directory / "state.json").write_text(json.dumps(checkpoint), encoding="utf-8")
    assert restarted.list_runs()[0]["termination_reason"] == "failed: ***"
    assert restarted.saved_run_dashboard(run_id)["termination_reason"] == "failed: ***"


def test_saved_run_cache_observes_checkpoint_mtime_and_size_without_a_journal_change(tmp_path):
    import os
    service, _ = _safety_service(tmp_path)
    run_id = "20261004-120000-abc123ef"
    directory = service.runs_directory() / run_id
    directory.mkdir(parents=True)
    checkpoint_path = directory / "state.json"
    checkpoint = {"metadata": {"termination_reason": "frontier_exhausted"},
                  "scheduler": {"budget": {"requests": 15}}}
    checkpoint_path.write_text(json.dumps(checkpoint), encoding="utf-8")
    assert service.list_runs()[0]["budget"]["requests"] == 15
    directory_stat, checkpoint_stat = directory.stat(), checkpoint_path.stat()

    checkpoint["scheduler"]["budget"]["requests"] = 18
    checkpoint_path.write_text(json.dumps(checkpoint), encoding="utf-8")
    assert checkpoint_path.stat().st_size == checkpoint_stat.st_size
    os.utime(checkpoint_path, ns=(checkpoint_stat.st_atime_ns, checkpoint_stat.st_mtime_ns + 1000000))
    os.utime(directory, ns=(directory_stat.st_atime_ns, directory_stat.st_mtime_ns))
    assert service.list_runs()[0]["budget"]["requests"] == 18
    assert service.saved_run_dashboard(run_id)["budget"]["requests"] == 18

    checkpoint_stat = checkpoint_path.stat()
    checkpoint["scheduler"]["budget"]["requests"] = 180
    checkpoint_path.write_text(json.dumps(checkpoint), encoding="utf-8")
    assert checkpoint_path.stat().st_size != checkpoint_stat.st_size
    os.utime(checkpoint_path, ns=(checkpoint_stat.st_atime_ns, checkpoint_stat.st_mtime_ns))
    os.utime(directory, ns=(directory_stat.st_atime_ns, directory_stat.st_mtime_ns))
    assert service.list_runs()[0]["budget"]["requests"] == 180
    assert service.saved_run_dashboard(run_id)["termination_reason"] == "frontier_exhausted"
    # Old or malformed checkpoints carry no invented reason or budget.
    checkpoint_path.write_text('{"metadata": {}}', encoding="utf-8")
    assert "termination_reason" not in service.list_runs()[0]
    assert "budget" not in service.saved_run_dashboard(run_id)


def test_bootstrap_config_creates_missing_config_from_example(tmp_path):
    from app.web import _bootstrap_config

    config_path = tmp_path / "configs" / "local.yaml"
    _bootstrap_config(config_path)
    assert config_path.exists()
    data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert "panel" in data and "testing" in data


def test_bootstrap_config_keeps_existing_file(tmp_path):
    from app.web import _bootstrap_config

    config_path = tmp_path / "local.yaml"
    config_path.write_text("panel:\n  url: keep\n", encoding="utf-8")
    _bootstrap_config(config_path)
    assert yaml.safe_load(config_path.read_text(encoding="utf-8")) == {"panel": {"url": "keep"}}


def test_startup_banner_mentions_url_and_config():
    from app.web import _startup_banner

    text = _startup_banner(8765)
    assert "http://127.0.0.1:8765" in text
    assert "configs/local.yaml" in text


def _safety_service(tmp_path: Path) -> tuple[WebService, dict]:
    raw = {"panel": {"url": "https://panel.example.test", "api_token": "FAKE_PANEL_REDACTION_TOKEN"},
           "inbound": {"mode": "clone", "source_id": 1, "test_port": 9443},
           "parameters": {}, "testing": {"server_address": "vpn.example.test", "max_combinations": 1},
           "output": {"directory": str(tmp_path / "results"), "formats": ["json"]}}
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return WebService(path), raw


def test_start_reservation_rejects_a_second_start_during_preparation(tmp_path, monkeypatch):
    service, raw = _safety_service(tmp_path)
    entered, release = threading.Event(), threading.Event()
    original = service.raw_config
    def blocked_config():
        entered.set()
        assert release.wait(3)
        return original()
    service.raw_config = blocked_config
    class DeferredThread:
        def __init__(self, **_kwargs): pass
        def start(self): pass
    monkeypatch.setattr("app.web.service.threading", SimpleNamespace(Thread=DeferredThread, Lock=threading.Lock))
    accepted = []
    first = threading.Thread(target=lambda: accepted.append(service.start_run(raw)))
    first.start()
    assert entered.wait(2)
    try:
        assert service.run_status()["status"] == "starting"
        with pytest.raises(RuntimeError, match="already active"):
            service.start_run(raw)
    finally:
        release.set()
        first.join(3)
    assert len(accepted) == 1


def test_stop_during_preparation_is_delivered_to_runner(tmp_path, monkeypatch):
    service, raw = _safety_service(tmp_path)
    entered, release = threading.Event(), threading.Event()
    original = service.raw_config
    def blocked_config():
        entered.set()
        assert release.wait(3)
        return original()
    service.raw_config = blocked_config
    observed = []
    class Client:
        def __init__(self, *_args): pass
        async def aclose(self): observed.append("closed")
    class Runner:
        def __init__(self, *_args): self.stopped = False
        def request_stop(self): self.stopped = True
        async def run(self, **_kwargs):
            assert self.stopped
            observed.append("stopped")
            return {"interrupted": True}
    monkeypatch.setattr("app.web.service.ThreeXUIClient", Client)
    monkeypatch.setattr("app.web.service.ExperimentRunner", Runner)
    first = threading.Thread(target=lambda: service.start_run(raw))
    first.start()
    assert entered.wait(2)
    assert service.stop_run()["status"] == "stopping"
    release.set()
    first.join(3)
    assert service.shutdown(3)
    assert service.run_status()["status"] == "stopped"
    assert observed == ["stopped", "closed"]


def test_shutdown_joins_worker_after_cleanup_and_client_close(tmp_path, monkeypatch):
    service, raw = _safety_service(tmp_path)
    started, stopped = threading.Event(), threading.Event()
    observed = []
    class Client:
        def __init__(self, *_args): pass
        async def aclose(self): observed.append("client_closed")
    class Runner:
        def __init__(self, *_args): pass
        def request_stop(self): stopped.set()
        async def run(self, **_kwargs):
            started.set()
            while not stopped.is_set():
                await asyncio.sleep(.005)
            observed.append("cleanup")
            return {"interrupted": True}
    monkeypatch.setattr("app.web.service.ThreeXUIClient", Client)
    monkeypatch.setattr("app.web.service.ExperimentRunner", Runner)
    service.start_run(raw)
    assert started.wait(2)
    assert service.shutdown(3)
    assert observed == ["cleanup", "client_closed"]
    assert not service._worker_thread.is_alive()
    with pytest.raises(RuntimeError, match="shutting down"):
        service.start_run(raw)


def test_failed_preparation_releases_the_start_reservation(tmp_path, monkeypatch):
    service, raw = _safety_service(tmp_path)
    with pytest.raises(ValueError):
        service.start_run({**raw, "testing": {**raw["testing"], "ports": []}})
    assert service.run_status()["status"] == "failed"
    monkeypatch.setattr(threading.Thread, "start", lambda _thread: None)
    assert service.start_run(raw)["status"] == "running"


def test_known_env_secret_is_hidden_in_registry_and_persistent_failure(tmp_path, monkeypatch):
    service, raw = _safety_service(tmp_path)
    raw["panel"]["api_token"] = "${FAKE_WEB_PANEL_TOKEN}"
    monkeypatch.setenv("FAKE_WEB_PANEL_TOKEN", "FAKE_EXPANDED_PANEL_TOKEN")
    service.config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    class Client:
        def __init__(self, *_args): pass
        async def authenticate(self): raise RuntimeError("rejected FAKE_EXPANDED_PANEL_TOKEN")
        async def aclose(self): pass
    class Runner:
        def __init__(self, *_args): pass
        async def run(self, **_kwargs): raise RuntimeError("rejected FAKE_EXPANDED_PANEL_TOKEN")
    monkeypatch.setattr("app.web.service.ThreeXUIClient", Client)
    assert "FAKE_EXPANDED_PANEL_TOKEN" not in json.dumps(service.registry())
    monkeypatch.setattr("app.web.service.ExperimentRunner", Runner)
    monkeypatch.setattr("app.web.service.threading", SimpleNamespace(Thread=InlineThread, Lock=threading.Lock))
    result = service.start_run(raw)
    assert "FAKE_EXPANDED_PANEL_TOKEN" not in json.dumps(result)
    assert "FAKE_EXPANDED_PANEL_TOKEN" not in (Path(result["result_directory"]) / "run-error.txt").read_text()


def test_redactor_discovers_secret_parameters_and_json_string_client_settings():
    from app.security.masking import SecretRedactor
    redactor = SecretRedactor.from_config({"panel": {"password": "FAKE_PASSWORD"}, "parameters": {
        "identity": {"type": "enum", "values": ["FAKE_CLIENT_ID"],
                     "path": ["settings", "clients", 0, "id"]}}})
    redactor.add({"settings": json.dumps({"clients": [{"id": "FAKE_SOURCE_UUID"}]})})
    assert redactor.redact_text("FAKE_PASSWORD FAKE_CLIENT_ID FAKE_SOURCE_UUID") == "*** *** ***"
    assert redactor.redact_text("enum settings clients") == "enum settings clients"


def test_partial_utf8_journal_record_is_completed_once_and_corruption_is_reported(tmp_path):
    service, _ = _safety_service(tmp_path)
    directory = tmp_path / "journal"
    directory.mkdir()
    record = {"configuration_hash": "a", "configuration": {"description": "проверка"},
              "run": 1, "result": {"status": "OK"}}
    line = json.dumps(record, ensure_ascii=False).encode("utf-8") + b"\n"
    split = line.index("п".encode("utf-8")) + 1
    journal = directory / "results.jsonl"
    journal.write_bytes(line[:split])
    assert service._new_journal_records(directory) == []
    assert service._new_journal_records(directory) == []
    with journal.open("ab") as stream:
        stream.write(line[split:] + b"{broken}\n" + line)
    assert service._new_journal_records(directory) == [record, record]
    assert service._new_journal_records(directory) == [record, record]
    service._run_state = {"status": "completed", "result_directory": str(directory)}
    assert service.run_dashboard()["journal"] == {"corrupt_records": 1, "incomplete_bytes": 0}


def test_concurrent_dashboard_polls_do_not_duplicate_rows(tmp_path):
    service, _ = _safety_service(tmp_path)
    directory = tmp_path / "journal"
    directory.mkdir()
    (directory / "results.jsonl").write_text('{"configuration_hash":"a","run":1,"result":{"status":"OK"}}\n')
    snapshots = []
    polls = [threading.Thread(target=lambda: snapshots.append(service._new_journal_records(directory))) for _ in range(8)]
    for thread in polls: thread.start()
    for thread in polls: thread.join(2)
    assert len(snapshots) == 8 and all(len(rows) == 1 for rows in snapshots)


def test_adaptive_preview_is_offline_bounded_and_keeps_the_single_port(tmp_path, monkeypatch):
    service, raw = _safety_service(tmp_path)
    raw["testing"].update({"combination_strategy": "adaptive", "max_combinations": 4,
                           "adaptive": {"seed": 9, "goal": "first_confirmed"}})
    raw["parameters"] = {name: {"type": "integer", "values": [0, 1], "baseline": 0} for name in ("a", "b")}
    monkeypatch.setattr("app.web.service.ThreeXUIClient", lambda *_args: (_ for _ in ()).throw(AssertionError("network")))
    preview = service.preview(raw)
    assert preview["offline"] is True and preview["strategy"] == "adaptive"
    assert preview["ports"] == [9443] and preview["serial_execution"] is True
    assert preview["initial_candidates"] <= 4
    assert {"a": 1, "b": 1} in preview["preview"]
    assert preview["coverage"]["seed"] == 9
    assert preview["planned_runs_is_upper_bound"] is True


def test_dashboard_separates_screening_confirmation_and_network_epochs(tmp_path):
    service, _ = _safety_service(tmp_path)
    directory = tmp_path / "results"
    store = ResultStore(directory)
    for run, phase, fidelity, epoch, qualification in (
        (1, "search", "screening", 0, "preliminary"),
        (2, "validation", "confirmation", 0, "confirmed_in_observed_windows"),
        (3, "validation", "confirmation", 1, "unstable"),
    ):
        store.append({"test_id": 1, "run": run, "phase": phase, "fidelity": fidelity,
                      "environment_epoch": epoch, "qualification": qualification,
                      "configuration_hash": "one", "configuration": {"network": "tcp"},
                      "result": {"status": "OK", "score": .9, "successful_requests": 5, "failed_requests": 0}})
    service._run_state = {"status": "completed", "result_directory": str(directory)}
    dashboard = service.run_dashboard()
    assert dashboard["candidate_count"] == 3
    assert dashboard["confirmed_candidates"] == 1
    assert dashboard["best_score"]["qualification"] == "confirmed_in_observed_windows"
    assert [row["environment_epoch"] for row in dashboard["candidates"]] == [0, 0, 1]
    assert all(row["download_mbps"] is None and row["sample_count"] == 5 for row in dashboard["candidates"])


def test_saved_dashboard_reads_nested_http_and_tcp_diagnoses(tmp_path):
    service, _ = _safety_service(tmp_path)
    run_id = "20261004-120000-abc123ef"
    directory = service.runs_directory() / run_id
    store = ResultStore(directory)
    for test_id, code, status in ((1, "e2e_success", "OK"), (2, "tcp_unreachable", "FAILED")):
        store.append({"test_id": test_id, "run": 1, "configuration_hash": str(test_id),
                      "configuration": {"network": "tcp"}, "phase": "search", "fidelity": "screening",
                      "result": {"status": status, "diagnosis": {"code": code, "certainty": "observed",
                          "evidence": {"tcp_connect_ok": status == "OK", "note": "FAKE_PANEL_REDACTION_TOKEN"},
                          "alternative_causes": [] if status == "OK" else ["network_path", "endpoint"]}}})
    restarted = WebService(service.config_path)
    candidates = restarted.saved_run_dashboard(run_id)["candidates"]
    assert [candidate["reason_code"] for candidate in candidates] == ["e2e_success", "tcp_unreachable"]
    assert candidates[1]["diagnosis"]["evidence"]["tcp_connect_ok"] is False
    assert candidates[1]["diagnosis"]["alternative_causes"] == ["network_path", "endpoint"]
    assert "FAKE_PANEL_REDACTION_TOKEN" not in json.dumps(candidates)


def test_saved_screening_request_counts_use_nested_metrics_and_preserve_unknown_samples(tmp_path):
    service, _ = _safety_service(tmp_path)
    run_id = "20261004-120000-abc123ef"
    store = ResultStore(service.runs_directory() / run_id)
    measurements = (
        ("explicit", {"http_request_count": 2, "successful_requests": 1, "failed_requests": 1}),
        ("fallback", {"successful_requests": 1, "failed_requests": 1}),
        ("missing", {"tcp_connect_ok": False}),
        ("partial", {"successful_requests": 1}),
        ("zero", {"http_request_count": 0}),
        ("mixed", {"http_request_count": 2}),
        ("mixed", {"successful_requests": 1}),
    )
    for run, (digest, screening) in enumerate(measurements, 1):
        store.append({"test_id": run, "run": run, "configuration_hash": digest,
                      "configuration": {"network": "tcp"}, "phase": "search", "fidelity": "screening",
                      "result": {"status": "FAILED", "successful_requests": 0, "failed_requests": 0,
                                 "screening": screening}})
    restarted = WebService(service.config_path)
    counts = {candidate["configuration_hash"]: candidate["sample_count"]
              for candidate in restarted.saved_run_dashboard(run_id)["candidates"]}
    assert counts == {"explicit": 2, "fallback": 2, "missing": None, "partial": None, "zero": 0, "mixed": None}
    assert 'HTTP ${metricValue(candidate.sample_count, "", 0)}' in APP_JS


def test_adaptive_form_preserves_the_shared_builder_and_confirmation_explanation():
    assert 'value="adaptive"' in PAGE and 'id="topology"' in PAGE
    assert "testing.adaptive = {" in APP_JS
    assert APP_JS.count("function buildDraft(") == 1
    assert "confirmation_windows:" in APP_JS and "traffic_budget_bytes:" in APP_JS
    assert "finally {\n    pollingRun = false;" in APP_JS
    assert "confirmed_in_observed_windows" in APP_JS
    assert "Системные настройки сети не меняются" in APP_JS


def _pending_saved_run(service, *, identity=True):
    from app.parameters.generator import configuration_hash
    directory = service.runs_directory() / "20261004-120000-abc123ef"
    recovery = directory / ".recovery"
    recovery.mkdir(parents=True)
    marker = "[3xui-config-tester:" + "a" * 32 + "]"
    (recovery / "inbound-recovery.json").write_text(json.dumps({"version": 1, "mode": "clone", "source_id": 1,
        "state": "cleanup_pending", "marker": marker, "port": 9443, "protocol": "vless", "test_inbound_id": 9}))
    metadata = {"panel_identity": configuration_hash({"url": "https://panel.example.test"})} if identity else {}
    (directory / "state.json").write_text(json.dumps({"experiment_id": "fake", "metadata": metadata, "completed_keys": []}))
    return directory, marker


def test_pending_recovery_survives_restart_and_blocks_a_new_experiment(tmp_path):
    service, raw = _safety_service(tmp_path)
    directory, _ = _pending_saved_run(service)
    restarted = WebService(service.config_path)
    assert restarted.list_runs()[0]["cleanup_pending"] is True
    with pytest.raises(RuntimeError, match="cleanup must be recovered"):
        restarted.start_run(raw)
    assert restarted.run_status()["status"] == "cleanup_pending"
    assert restarted.run_status()["recovery_runs"] == [directory.name]
    assert restarted.saved_run_dashboard(directory.name)["cleanup_pending"] is True


def test_worker_exception_keeps_cleanup_pending_visible(tmp_path, monkeypatch):
    service, raw = _safety_service(tmp_path)
    class Runner:
        def __init__(self, config, *_args): self.directory = config.output_dir
        async def run(self, **_kwargs):
            manifest = self.directory / ".recovery" / "inbound-recovery.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text('{"state":"cleanup_pending"}')
            raise RuntimeError("fake cleanup failed")
    monkeypatch.setattr("app.web.service.ExperimentRunner", Runner)
    monkeypatch.setattr("app.web.service.threading", SimpleNamespace(Thread=InlineThread, Lock=threading.Lock))
    result = service.start_run(raw)
    assert result["status"] == "cleanup_pending" and result["cleanup_pending"] is True
    assert service.list_runs()[0]["status"] == "cleanup_pending"


def test_explicit_recovery_checks_identity_and_preserves_the_source(tmp_path, monkeypatch):
    import copy
    service, _ = _safety_service(tmp_path)
    directory, marker = _pending_saved_run(service)
    source = {"id": 1, "port": 443, "protocol": "vless", "remark": "source",
              "settings": {"password": "FAKE_SOURCE_RECOVERY_SECRET"}}
    items = {1: copy.deepcopy(source), 9: {"id": 9, "port": 9443, "protocol": "vless", "remark": marker},
             10: {"id": 10, "port": 9443, "protocol": "vless", "remark": "foreign"}}
    deleted = []
    class Client:
        def __init__(self, *_args): pass
        async def authenticate(self): pass
        async def discover(self): return {"info": {"version": "fake"}}
        async def get_inbound(self, identifier): return copy.deepcopy(items[identifier])
        async def list_inbounds(self): return list(items.values())
        async def delete_inbound(self, identifier):
            assert (directory / "discovery.json").exists() and (directory / "preflight.json").exists()
            deleted.append(identifier)
            del items[identifier]
        async def aclose(self): pass
    monkeypatch.setattr("app.web.service.ThreeXUIClient", Client)
    monkeypatch.setattr("app.web.service.threading", SimpleNamespace(Thread=InlineThread, Lock=threading.Lock))
    result = service.recover_run(directory.name)
    assert result["status"] == "completed" and result["cleanup_pending"] is False
    assert deleted == [9] and items[1] == source and 10 in items
    assert service.list_runs()[0]["cleanup_pending"] is False
    assert "FAKE_SOURCE_RECOVERY_SECRET" not in json.dumps(result)
    assert json.loads((directory / "state.json").read_text())["metadata"]["cleanup_pending"] is False


def test_legacy_recovery_without_panel_identity_makes_no_panel_request(tmp_path, monkeypatch):
    service, _ = _safety_service(tmp_path)
    directory, _ = _pending_saved_run(service, identity=False)
    monkeypatch.setattr("app.web.service.ThreeXUIClient", lambda *_args: (_ for _ in ()).throw(AssertionError("network")))
    monkeypatch.setattr("app.web.service.threading", SimpleNamespace(Thread=InlineThread, Lock=threading.Lock))
    result = service.recover_run(directory.name)
    assert result["status"] == "cleanup_pending" and "manual matching" in result["error"]


def test_masked_secret_parameter_roundtrip_preserves_backend_credentials(tmp_path, monkeypatch):
    import copy
    service, raw = _safety_service(tmp_path)
    raw["parameters"] = {name: {"type": "string", "values": [secret], "baseline": secret,
                                  "mutate": False, "target": "client", "path": path}
                         for name, secret, path in (
                             ("private_key", "FAKE_PARAMETER_PRIVATE_KEY", ["outbounds", 0, "streamSettings", "realitySettings", "password"]),
                             ("identity", "FAKE_PARAMETER_UUID", ["outbounds", 0, "settings", "vnext", 0, "users", 0, "id"]))}
    service.config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    public = service.public_config()
    assert "FAKE_PARAMETER" not in json.dumps(public)
    assert public["parameters"]["private_key"]["type"] == "string"
    assert public["parameters"]["identity"]["values"] == ["***"]
    service.save(copy.deepcopy(public))
    saved = yaml.safe_load(service.config_path.read_text(encoding="utf-8"))
    assert saved["parameters"] == raw["parameters"]
    assert "FAKE_PARAMETER" not in json.dumps(service.preview(copy.deepcopy(public)))
    monkeypatch.setattr(threading.Thread, "start", lambda _thread: None)
    assert service.start_run(copy.deepcopy(public))["status"] == "running"


def test_final_scheduler_summary_replaces_the_last_progress_counters(tmp_path, monkeypatch):
    service, raw = _safety_service(tmp_path)
    class Runner:
        def __init__(self, _config, _client, progress): self.progress = progress
        async def run(self, **_kwargs):
            self.progress({"confirmed_candidates": 0, "budget": {"requests": 4}})
            self.progress({"lifecycle_state": "cleanup"})
            return {"confirmed_candidates": 1, "viable_candidates": 2, "budget": {"requests": 8},
                    "termination_reason": "first_confirmed", "cleanup_pending": False}
    monkeypatch.setattr("app.web.service.ExperimentRunner", Runner)
    monkeypatch.setattr("app.web.service.threading", SimpleNamespace(Thread=InlineThread, Lock=threading.Lock))
    result = service.start_run(raw)
    assert result["confirmed_candidates"] == 1 and result["viable_candidates"] == 2
    assert result["budget"] == {"requests": 8} and result["termination_reason"] == "first_confirmed"
    assert result["lifecycle_state"] == "finished" and result["cleanup_pending"] is False
