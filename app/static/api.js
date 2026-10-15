// 3xui-config-tester Web UI — transport layer: notices, busy state and the `call()` wrapper over /api/*. Load order: api.js -> draft.js -> render.js (shared global scope, no modules).
"use strict";

let presets = {},
  registry = {},
  config = {},
  selected = new Set(),
  customs = [],
  draftValues = {},
  mutationFlags = {};

const $ = (id) => document.getElementById(id);
const esc = (s) =>
  String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll('"', "&quot;");
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const shown = (v) => (typeof v === "string" ? v || "∅" : JSON.stringify(v));

// Единый словарь локализованных строк для динамически выводимого текста.
const L = {
  status: {
    idle: "ожидание",
    starting: "подготовка",
    running: "выполняется",
    stopping: "останавливается",
    stopped: "остановлено",
    completed: "завершено",
    failed: "ошибка",
    cleanup: "очистка",
    cleanup_pending: "требуется восстановление",
    completed_with_warnings: "завершено с предупреждениями",
  },
  statusLabel: "Статус",
  runsLabel: "Запуски",
  currentConfiguration: "Текущая конфигурация",
  testInbound: "Тестовый inbound",
  portLabel: "порт",
  configurationLimit: "Лимит конфигураций",
  mutationGeneration: "Поколение мутаций",
  mutableFixed: "Изменяемые / фиксированные",
  failedLabel: "Неудачи",
  skippedLabel: "Пропущено",
  resultsLabel: "Результаты",
  errorLabel: "Ошибка",
  warningsLabel: "Предупреждения",
  etaLabel: "Осталось (оценка)",
  etaNever: "—",
  lastConfiguration: "Последняя конфигурация",
  lastMetrics: "Последние метрики",
  summary: "Сводка",
  historyStatuses: {
    running: "выполняется",
    starting: "подготовка",
    stopping: "останавливается",
    completed: "завершено",
    failed: "ошибка",
    stopped: "остановлено",
    cleanup_pending: "требуется восстановление",
    completed_with_warnings: "с предупреждениями",
    saved: "сохранён",
  },
  openDashboard: "Открыть панель",
  bestMark: "лучшая",
  continueRun: "Продолжить с текущими лимитами",
  continueRunDoubled: "Продолжить с бюджетом ×2",
  historyContinue: "Продолжить",
  continuationHint:
    "Бюджет поиска исчерпан. Продолжение идёт тем же экспериментом: тот же каталог результатов и чекпойнт, завершённые кандидаты не измеряются повторно. Лимиты можно поправить в разделе «План поиска» до нажатия кнопки.",
  continuationPending: "Продолжение эксперимента с новым бюджетом…",
  continuationFailed: "Ошибка продолжения: ",
  resumedLabel: "Продолжение прежнего эксперимента",
  errors: {
    panelUrl: "Укажите полный URL панели с http:// или https://",
    sourceId: "Укажите ID исходного inbound",
    testPort: "Порт должен быть от 1 до 65535",
    portRange:
      "Порты копии: один или несколько через запятую (1–65535) либо интервал «с-по»",
    serverAddress: "Укажите адрес тестового inbound",
    xrayBinary: "Укажите путь к Xray",
    noValues: "выберите хотя бы одно значение",
  },
};

// ---------- Notices: единый компонент уведомлений с авто-скрытием ----------

const NOTICE_HIDE_MS = 6000;

function showNotice(node, message, kind = "error", { sticky = false } = {}) {
  if (!node) return;
  node.className = `notice notice-show ${
    kind === "error" ? "notice-error" : "notice-ok"
  }`;
  node.textContent = message;
  clearTimeout(node._noticeTimer);
  if (sticky) return; // важные состояния живут, пока их не заменит следующее уведомление
  node._noticeTimer = setTimeout(() => {
    node.className = "notice";
    node.textContent = "";
  }, NOTICE_HIDE_MS);
}

const noticeContainers = {
  result: () => $("planNotice"),
  runResult: () => $("runNotice"),
  connectionStatus: () => $("connectionStatus"),
  inboundResult: () => $("connectionStatus"),
  realityFileStatus: () => $("connectionStatus"),
};

function notify(target, message, kind = "error", options) {
  showNotice(noticeContainers[target]?.() || $(target), message, kind, options);
}

// Ошибки валидации с сервера привязываются к конкретным полям формы.
const FIELD_ERROR_PATTERNS = [
  [/URL панели|panel URL|panel\.url/i, "panelUrl"],
  [/ID исходного inbound|source_id/i, "sourceId"],
  [/Порты|портов|port_range|testing\.ports/i, "clonePorts"],
  [/Порт|test_port/i, "testPort"],
  [/тестового inbound|server_address/i, "serverAddress"],
  [/Xray|xray_binary/i, "xrayBinary"],
  [/Каталог|output/i, "outputDir"],
];

function bindFieldErrors(message) {
  for (const [pattern, id] of FIELD_ERROR_PATTERNS) {
    if (pattern.test(message) && $(id)) {
      $(id).classList.add("field-error");
      $(id).addEventListener(
        "input",
        () => $(id)?.classList.remove("field-error"),
        { once: true },
      );
      return $(id);
    }
  }
  return null;
}

// ---------- Состояние занятости кнопок ----------

let inflightRequests = 0;

function beginInflight() {
  inflightRequests += 1;
  document
    .querySelectorAll("[data-action]")
    .forEach((button) => (button.disabled = true));
}

function endInflight() {
  inflightRequests = Math.max(0, inflightRequests - 1);
  if (inflightRequests) return;
  document
    .querySelectorAll("[data-action]")
    .forEach((button) => (button.disabled = false));
  if (typeof syncActionAvailability === "function") syncActionAvailability();
}

async function withBusy(actions, fn) {
  const buttons = actions.flatMap((name) => [
    ...document.querySelectorAll(`[data-action="${name}"]`),
  ]);
  beginInflight();
  buttons.forEach((button) => button.classList.add("loading"));
  try {
    return await fn();
  } finally {
    endInflight();
    buttons.forEach((button) => button.classList.remove("loading"));
  }
}

// ---------- Параметры и карточки ----------

async function call(path, method = "GET", body) {
  let r = await fetch(path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  let d = await r.json();
  if (!r.ok) throw Error(d.message || d.error || "HTTP " + r.status);
  return d;
}

// ---------- Подключение, inbound, реестр ----------

