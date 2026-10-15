// 3xui-config-tester Web UI — draft layer: REALITY list ownership, the single buildDraft() and read(). Loads after api.js.
"use strict";

let realityCandidates = [];
const REALITY_IDENTITY_LEAVES = [
  "serverName",
  "shortId",
  "password",
  "publicKey",
];
const REALITY_LIST_MANAGED_NOTE =
  "Управляется списком целей REALITY — значение берётся из выбранной пары target/SNI и не попадает в конфиг.";

function listManagedRealityPath(path) {
  let prefix = ["outbounds", 0, "streamSettings", "realitySettings"];
  path = path || [];
  return (
    path.length > prefix.length &&
    prefix.every((part, index) => String(path[index]) === String(part)) &&
    REALITY_IDENTITY_LEAVES.includes(path[path.length - 1])
  );
}

function realityListOwns(path) {
  return Boolean(realityCandidates.length) && listManagedRealityPath(path);
}

function stripRealityIdentity(draft) {
  if (!draft.parameters) return draft;
  Object.entries(draft.parameters).forEach(([name, item]) => {
    if (realityListOwns(item?.path || [])) delete draft.parameters[name];
  });
  return draft;
}

// REALITY-список требует параметр security со значением reality (иначе сервер
// отклонит черновик с «REALITY candidates require a security parameter…»).
// Выбор мог его потерять — например, «Копия inbound» фиксирует только
// live-значения, а режим сохранения подключения несёт parameters из
// загруженного YAML как есть, — поэтому гарантия ставится на обеих ветвях
// buildDraft. Вызывается ПОСЛЕ stripRealityIdentity: достроенный параметр не
// должен попасть под удаление identity-параметров.
function ensureRealitySecurity(draft) {
  if (!realityCandidates.length) return draft;
  draft.parameters = draft.parameters || {};
  let security = draft.parameters.security;
  if (!security || security.type !== "enum") {
    let s = presets.security || {};
    security = {
      type: "enum",
      target: s.target || "inbound",
      path: s.path || ["streamSettings", "security"],
      mutate: mutationFlags.security !== false,
      values: [],
    };
    if (s.conditions) security.conditions = s.conditions;
    if (s.value_conditions) security.value_conditions = s.value_conditions;
  }
  if (!(security.values || []).includes("reality")) {
    security.values = [...(security.values || []), "reality"];
    notify(
      "realityFileStatus",
      "REALITY-список активен: в параметр security добавлено значение reality.",
      "ok",
      { sticky: true },
    );
  }
  draft.parameters.security = security;
  return draft;
}

function realityFields() {
  return realityCandidates.length
    ? { candidates: realityCandidates }
    : {
        target: $("realityTarget").value.trim(),
        server_names: $("realityServerNames")
          .value.split(",")
          .map((name) => name.trim())
          .filter(Boolean),
      };
}

function showRealityCandidates() {
  let n = realityCandidates.length;
  $("realityFileStatus").textContent = n
    ? `Загружено пар target/SNI: ${n}. При сохранении список попадёт в YAML.`
    : "Список целей не загружен.";
  renderPresets();
  renderCards();
}

function selectRealityCandidates(items) {
  realityCandidates = items;
  $("realityTarget").value = "";
  $("realityServerNames").value = "";
  showRealityCandidates();
}

async function loadRealityFile(input) {
  try {
    let file = input.files?.[0];
    if (!file) return;
    if (file.size > 128 * 1024) throw Error("Файл больше 128 КБ");
    selectRealityCandidates(
      await call("/api/reality/import", "POST", {
        content: await file.text(),
      }),
    );
  } catch (error) {
    notify("realityFileStatus", "Ошибка файла: " + error.message);
    input.value = "";
  }
}

async function useBuiltinReality() {
  try {
    selectRealityCandidates(await call("/api/reality/default-candidates"));
  } catch (error) {
    notify("realityFileStatus", "Ошибка: " + error.message);
  }
}

function clearRealityCandidates() {
  realityCandidates = [];
  $("realityFile").value = "";
  showRealityCandidates();
}

// ---------- Черновик конфигурации: ОДИН общий сборщик ----------

// «24443», «24443, 24500, 25500» — список портов копии (первый свободный
// побеждает); «20000-21000» — прежний интервал. Для YAML это разные ключи:
// список пишется в testing.ports, интервал — в testing.port_range.
function parseClonePorts(value) {
  let text = String(value).trim(),
    interval = text.match(/^(\d+)\s*-\s*(\d+)$/);
  if (interval) {
    let low = Number(interval[1]),
      high = Number(interval[2]);
    if (low < 1 || high > 65535 || low > high)
      throw Error(L.errors.portRange);
    return { port_range: [low, high] };
  }
  let parts = text
    .split(/[,\s]+/)
    .map((part) => part.trim())
    .filter(Boolean);
  let numbers = parts.map(Number);
  if (
    !numbers.length ||
    parts.some((part) => !/^\d+$/.test(part)) ||
    numbers.some((item) => !Number.isInteger(item) || item < 1 || item > 65535)
  )
    throw Error(L.errors.portRange);
  return { ports: numbers };
}

// buildDraft() — единственный сборщик черновика. Общая часть (panel, inbound,
// testing-подключение, output) собирается всегда; при includePlan=true
// добавляются план и параметры. Черновик всегда проходит через
// stripRealityIdentity, поэтому identity-параметры не попадают ни в один
// запрос: ни preview/run/save, ни сохранение подключения.
function buildDraft({ includePlan = true } = {}) {
  let panelUrl = $("panelUrl").value.trim(),
    sourceId = Number($("sourceId").value),
    port = $("testPort").value,
    clonePorts = parseClonePorts($("clonePorts").value),
    server = $("serverAddress").value.trim(),
    binary = $("xrayBinary").value.trim();
  if (!/^https?:\/\//i.test(panelUrl)) throw Error(L.errors.panelUrl);
  if (!Number.isInteger(sourceId) || sourceId < 1)
    throw Error(L.errors.sourceId);
  if (port && (!/^\d+$/.test(port) || !Number.isInteger(Number(port)) || Number(port) < 1 || Number(port) > 65535))
    throw Error(L.errors.testPort);
  if (!server) throw Error(L.errors.serverAddress);
  if (!binary) throw Error(L.errors.xrayBinary);

  let inbound = {
    ...(config.inbound || {}),
    mode: "clone",
    source_id: sourceId,
    topology: $("topology").value,
  };
  if (port) inbound.test_port = Number(port);
  else delete inbound.test_port;

  let previous = config.testing || {};
  let testing = {
    ...previous,
    server_address: server,
    xray_binary: binary,
    validate_config: $("validateConfig").value === "true",
    ...clonePorts,
    tls_server_name: $("tlsSni").value.trim(),
    verify_peer_cert_by_name: $("verifyPeerName").value.trim(),
    urls: $("urls")
      .value.split("\n")
      .map((value) => value.trim())
      .filter(Boolean),
  };
  // Цели REALITY добавляются к любому черновику; stripRealityIdentity ниже
  // уберёт управляемые списком identity-параметры.
  testing.reality = realityFields();
  // Список портов и интервал взаимоисключающие: поле формы задаёт ровно один
  // ключ, поэтому устаревший из loaded-конфига не должен пережить сохранение.
  if (clonePorts.ports) delete testing.port_range;
  else delete testing.ports;

  if (!includePlan) {
    // Режим сохранения подключения: план и параметры не трогаем.
    return ensureRealitySecurity(stripRealityIdentity({
      ...config,
      panel: {
        ...(config.panel || {}),
        url: panelUrl,
        verify_tls: $("verifyTls").value === "true",
        trust_env: $("trustEnv").value === "true",
      },
      inbound,
      testing,
      output: {
        ...(config.output || {}),
        directory: $("outputDir").value.trim() || "./results",
      },
    }));
  }

  // Режим полного черновика: план, параметры и измерения из формы.
  let parameters = {};
  document.querySelectorAll('.param[data-kind="preset"]').forEach((a) => {
    let key = a.dataset.key,
      s = presets[key],
      item = {
        type: s.type,
        target: s.target,
        path: s.path,
        mutate: mutationFlags[key] !== false,
      };
    if (s.conditions) item.conditions = s.conditions;
    if (s.value_conditions) item.value_conditions = s.value_conditions;
    if (Object.hasOwn(s, "current")) item.baseline = s.current;
    if (s.range) {
      item.min = Number(a.querySelector(".range-min").value);
      item.max = Number(a.querySelector(".range-max").value);
      item.step = Number(a.querySelector(".range-step").value);
    } else {
      syncDraft(a);
      item.values = draftValues[key];
      // Список значений — подсказки, а не закрытый домен: у string-поля пустой
      // выбор легален (SNI можно не задавать), а сохранённое значение вне
      // подсказок не оставляет активных чипов. Параметр без значений в черновик
      // не берём: сервер требует values или диапазон.
      if (!item.values.length) {
        if (s.type === "string") return;
        throw Error(`${s.title}: ${L.errors.noValues}`);
      }
    }
    parameters[key] = item;
  });
  document.querySelectorAll('.param[data-kind="custom"]').forEach((a) => {
    let name = a.querySelector(".c-name").value.trim();
    if (!name) return;
    parameters[name] = {
      type: a.querySelector(".c-type").value,
      target: a.querySelector(".c-target").value,
      mutate: a.querySelector(".c-mutate").value === "true",
      values: JSON.parse(a.querySelector(".c-values").value),
      path: JSON.parse(a.querySelector(".c-path").value),
      conditions: JSON.parse(a.querySelector(".c-conditions").value || "{}"),
    };
  });

  let requireTcp = $("requireTcpConnect").value === "true",
    minRate = Number($("minSuccessRate").value) / 100;
  testing.combination_strategy = $("combinationStrategy").value;
  testing.adaptive = {
    ...(previous.adaptive || {}),
    goal: $("searchGoal").value,
    time_budget_seconds: Number($("timeBudget").value) * 60,
    request_budget: Number($("requestBudget").value),
    traffic_budget_bytes: Number($("trafficBudget").value) * 1000000,
    apply_budget: Number($("applyBudget").value),
    exploration_fraction: Number($("explorationFraction").value) / 100,
    confirmation_windows: Number($("confirmationWindows").value),
    confirmation_requests: Number($("confirmationRequests").value),
    window_delay_seconds: Number($("confirmationDelay").value),
    seed: Number($("searchSeed").value),
  };
  testing.mutation_generations = Number($("mutationGenerations").value);
  testing.beam_width = Number($("beamWidth").value);
  testing.children_per_parent = Number($("childrenPerParent").value);
  testing.max_combinations = Number($("maxCombinations").value);
  testing.runs_per_combination = Number($("runsPerCombination").value);
  testing.max_failed_runs = Number($("maxFailedRuns").value);
  testing.socks_port = 18080;
  testing.screening = {
    ...(previous.screening || {}),
    enabled: true,
    requests: Number($("screeningRequests").value),
    min_success_rate: minRate,
    require_tcp_connect: requireTcp,
  };
  testing.quality_gates = {
    ...(previous.quality_gates || {}),
    min_success_rate: minRate,
    min_successful_requests: 1,
    max_latency_p95_ms: Number($("maxLatencyP95").value),
    require_tcp_connect: requireTcp,
  };
  testing.latency = {
    ...(previous.latency || {}),
    requests: Number($("latencyRequests").value),
  };
  testing.stability = {
    ...(previous.stability || {}),
    requests: Number($("stabilityRequests").value),
  };
  testing.ping = {
    ...(previous.ping || {}),
    enabled: $("pingEnabled").value === "true",
    requests: Number($("pingRequests").value),
  };
  testing.speed_test = {
    ...(previous.speed_test || {}),
    enabled: $("speedEnabled").value === "true",
    url: $("speedUrl").value.trim(),
    max_bytes: Number($("speedMegabytes").value) * 1000000,
  };

  return ensureRealitySecurity(stripRealityIdentity({
    panel: {
      url: panelUrl,
      verify_tls: $("verifyTls").value === "true",
      trust_env: $("trustEnv").value === "true",
    },
    inbound,
    testing,
    timeouts: {
      ...(config.timeouts || {}),
      request: Number($("requestTimeout").value),
      tcp_connect: Number($("tcpConnectTimeout").value),
      screening: Number($("screeningTimeout").value),
    },
    parameters,
    output: {
      directory: $("outputDir").value,
      formats: config.output?.formats || ["xlsx"],
    },
  }));
}

// Точки вызова: preview / run start / save используют полный черновик.
function read() {
  return buildDraft({ includePlan: true });
}

// ---------- Сеть ----------

