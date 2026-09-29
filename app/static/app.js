// 3xui-tester Web UI. All browser logic lives here; app/web_ui.html is markup only.
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
    running: "выполняется",
    stopping: "останавливается",
    stopped: "остановлено",
    completed: "завершено",
    failed: "ошибка",
  },
  statusLabel: "Статус",
  runsLabel: "Запуски",
  currentConfiguration: "Текущая конфигурация",
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
    stopping: "останавливается",
    completed: "завершено",
    failed: "ошибка",
  },
  openDashboard: "Открыть панель",
  bestMark: "лучшая",
  errors: {
    panelUrl: "Укажите полный URL панели с http:// или https://",
    sourceId: "Укажите ID исходного inbound",
    testPort: "Порт должен быть от 1 до 65535",
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

function selectedValues(name, spec) {
  if (Object.hasOwn(draftValues, name)) return draftValues[name];
  let existing = config.parameters?.[name]?.values;
  if (existing?.length) return existing;
  if (Object.hasOwn(spec, "current")) return [spec.current];
  return spec.values?.length ? [spec.values[0]] : [];
}

function renderMeta() {
  let compatibility = registry.compatibility || {},
    source = registry.source_inbound || {};
  $("registryMeta").innerHTML = registry.live_error
    ? "Документированный каталог загружен, но API панели недоступен: " +
      esc(registry.live_error)
    : "API панели: inbound #" +
      esc(source.id ?? "?") +
      " · " +
      esc(source.protocol ?? "?") +
      ":" +
      esc(source.port ?? "?") +
      " · 3x-ui " +
      esc(compatibility.three_xui || "?") +
      " · Xray " +
      esc(compatibility.xray || "?");
}

function conditionRefs(rule) {
  if (!rule || typeof rule !== "object") return [];
  if (Array.isArray(rule)) return rule.flatMap(conditionRefs);
  if (rule.parameter) return [rule.parameter];
  if (rule.all || rule.any) return conditionRefs(rule.all || rule.any);
  return Object.keys(rule).filter((k) => presets[k]);
}

function selectParameters(keys, on, allValues = false) {
  if (on) {
    keys.forEach((k) => {
      selected.add(k);
      if (!Object.hasOwn(mutationFlags, k)) mutationFlags[k] = true;
      if (allValues) draftValues[k] = [...(presets[k]?.values || [])];
      conditionRefs(presets[k]?.conditions).forEach((dep) => {
        selected.add(dep);
        if (!Object.hasOwn(mutationFlags, dep)) mutationFlags[dep] = false;
        if (!Object.hasOwn(draftValues, dep))
          draftValues[dep] = selectedValues(dep, presets[dep]);
      });
    });
  } else keys.forEach((k) => selected.delete(k));
  renderPresets();
  renderCards();
}

function selectInboundCopy() {
  if (registry.live_error || !registry.source_inbound) {
    $("registryMeta").textContent =
      "Сначала сохраните подключение и дождитесь загрузки данных панели. " +
      (registry.live_error || "");
    return;
  }
  selected = new Set();
  mutationFlags = {};
  draftValues = {};
  Object.entries(presets).forEach(([key, s]) => {
    if (Object.hasOwn(s, "current")) {
      selected.add(key);
      mutationFlags[key] = false;
      draftValues[key] = [s.current];
    }
  });
  renderPresets();
  renderCards();
  notify(
    "result",
    `Копия inbound: зафиксировано ${selected.size} live-параметров. Переключите нужные в «Мутировать».`,
    "ok",
  );
}

function setMutationMode(keys, mutate) {
  keys.forEach((k) => {
    selected.add(k);
    mutationFlags[k] = mutate;
    let s = presets[k];
    draftValues[k] = mutate
      ? [...(s.values || [])]
      : Object.hasOwn(s, "current")
        ? [s.current]
        : s.values?.length
          ? [s.values[0]]
          : [];
    conditionRefs(s?.conditions).forEach((dep) => {
      selected.add(dep);
      if (!Object.hasOwn(mutationFlags, dep)) mutationFlags[dep] = false;
      if (!Object.hasOwn(draftValues, dep))
        draftValues[dep] = selectedValues(dep, presets[dep]);
    });
  });
  renderPresets();
  renderCards();
}

function setSelectedValues(mode) {
  [...selected].forEach((k) => {
    let s = presets[k];
    draftValues[k] =
      mode === "all"
        ? [...(s.values || [])]
        : Object.hasOwn(s, "current")
          ? [s.current]
          : s.values?.length
            ? [s.values[0]]
            : [];
  });
  renderCards();
}

function renderPresets() {
  let node = $("presetList"),
    query = ($("parameterSearch")?.value || "").trim().toLowerCase(),
    entries = Object.entries(presets).filter(([k, s]) =>
      `${k} ${s.title} ${s.help} ${s.group}`.toLowerCase().includes(query),
    ),
    groups = {};
  entries.forEach((item) =>
    (groups[item[1].group || "Прочее"] ??= []).push(item),
  );
  node.innerHTML = "";
  Object.entries(groups).forEach(([group, items]) => {
    let section = document.createElement("section");
    section.className = "preset-group";
    let keys = items.map(([key]) => key),
      encoded = encodeURIComponent(JSON.stringify(keys));
    section.innerHTML = `<div class="group-head"><h3 class="group-title">${esc(
      group,
    )} · ${items.length}</h3><div class="group-actions"><button type="button" data-group-mutate="${encoded}">Мутировать</button><button type="button" data-group-fix="${encoded}">Фиксировать</button><button type="button" data-group-clear="${encoded}">Выключить</button></div></div><div class="group-grid"></div>`;
    section.querySelector("[data-group-mutate]").onclick = (e) =>
      setMutationMode(
        JSON.parse(decodeURIComponent(e.currentTarget.dataset.groupMutate)),
        true,
      );
    section.querySelector("[data-group-fix]").onclick = (e) =>
      setMutationMode(
        JSON.parse(decodeURIComponent(e.currentTarget.dataset.groupFix)),
        false,
      );
    section.querySelector("[data-group-clear]").onclick = (e) =>
      selectParameters(
        JSON.parse(decodeURIComponent(e.currentTarget.dataset.groupClear)),
        false,
      );
    let grid = section.querySelector(".group-grid");
    items.forEach(([key, s]) => {
      let item = document.createElement("label");
      item.className = "preset";
      let live = Object.hasOwn(s, "current")
        ? `<small class="live">Текущее: ${esc(shown(s.current))}</small>`
        : "";
      let mode = mutationFlags[key] === false ? " · фиксирован" : " · мутация";
      item.innerHTML = `<input type="checkbox" ${
        selected.has(key) ? "checked" : ""
      }><span><b>${esc(s.title)}</b><small>${esc(s.help)}${
        selected.has(key) ? mode : ""
      }</small>${
        realityListOwns(s.path)
          ? `<small class="warning">${esc(REALITY_LIST_MANAGED_NOTE)}</small>`
          : ""
      }${live}</span>`;
      item.querySelector("input").onchange = (e) =>
        selectParameters([key], e.target.checked);
      grid.append(item);
    });
    node.append(section);
  });
  $("parameterCount").textContent = `Выбрано ${
    selected.size
  } · показано ${entries.length} из ${Object.keys(presets).length}`;
}

function chips(name, values, active) {
  return `<div class="chips" data-name="${name}">${values
    .map(
      (v) =>
        `<button type="button" class="chip ${
          active.some((x) => same(x, v)) ? "active" : ""
        }" data-value="${encodeURIComponent(
          JSON.stringify(v),
        )}">${esc(shown(v))}</button>`,
    )
    .join("")}</div>`;
}

const TYPE_NAMES = {
  enum: "список",
  integer: "целое число",
  float: "дробное число",
  boolean: "да/нет",
  string: "строка",
};

function card(name, spec) {
  let original = config.parameters?.[name] || {},
    current = Object.hasOwn(spec, "current")
      ? " · текущее: " + esc(shown(spec.current))
      : "",
    mode =
      '<select class="mutation-role"><option value="true" ' +
      (mutationFlags[name] !== false ? "selected" : "") +
      '>Мутировать</option><option value="false" ' +
      (mutationFlags[name] === false ? "selected" : "") +
      ">Фиксировать</option></select>",
    target = spec.target === "client" ? "клиент" : "входящее подключение",
    header =
      '<div class="param-head"><h3>' +
      esc(spec.title || name) +
      '</h3><div class="row">' +
      mode +
      '<span class="tag">' +
      esc(spec.group || "") +
      " · " +
      target +
      " · " +
      (TYPE_NAMES[spec.type] || spec.type) +
      '</span></div></div><p class="hint">' +
      esc(spec.help || "") +
      "<br>Путь: " +
      esc(JSON.stringify(spec.path || [])) +
      (spec.conditions
        ? " · условие: " + esc(JSON.stringify(spec.conditions))
        : "") +
      current +
      "</p>" +
      (spec.warning ? '<p class="warning">' + esc(spec.warning) + "</p>" : "") +
      (realityListOwns(spec.path)
        ? '<p class="warning">' + esc(REALITY_LIST_MANAGED_NOTE) + "</p>"
        : "");
  if (spec.range) {
    let range = original;
    return (
      '<article class="param" data-key="' +
      name +
      '" data-kind="preset">' +
      header +
      '<div class="row"><label>Минимум<input class="range-min" type="number" value="' +
      (range.min ?? spec.range[0]) +
      '"></label><label>Максимум<input class="range-max" type="number" value="' +
      (range.max ?? spec.range[1]) +
      '"></label><label>Шаг<input class="range-step" type="number" value="' +
      (range.step ?? spec.range[2]) +
      '"></label></div></article>'
    );
  }
  let active = selectedValues(name, spec);
  return (
    '<article class="param" data-key="' +
    name +
    '" data-kind="preset">' +
    header +
    chips(name, spec.values, active) +
    '<label>Добавить своё значение и нажать Enter<input class="extra-value" placeholder="Строка, число, true/false или JSON"></label></article>'
  );
}

function customCard(item, index) {
  return (
    '<article class="param custom" data-kind="custom" data-index="' +
    index +
    '"><div class="param-head"><h3>Свой параметр</h3><button class="danger remove-custom" type="button">Удалить</button></div><div class="row"><label>Имя<input class="c-name" value="' +
    esc(item.name || "custom_parameter") +
    '"></label><label>Режим<select class="c-mutate"><option value="true" ' +
    (item.mutate !== false ? "selected" : "") +
    '>Мутировать</option><option value="false" ' +
    (item.mutate === false ? "selected" : "") +
    '>Фиксировать</option></select></label><label>Тип<select class="c-type">' +
    ["enum", "integer", "float", "boolean", "string"]
      .map(
        (type) =>
          '<option value="' +
          type +
          '" ' +
          (item.type === type ? "selected" : "") +
          ">" +
          TYPE_NAMES[type] +
          "</option>",
      )
      .join("") +
    '</select></label><label>Назначение<select class="c-target"><option value="inbound" ' +
    (item.target !== "client" ? "selected" : "") +
    '>Входящее подключение</option><option value="client" ' +
    (item.target === "client" ? "selected" : "") +
    '>Клиент</option></select></label><label>Значения (JSON)<textarea class="c-values">' +
    esc(JSON.stringify(item.values || [])) +
    '</textarea></label><label>Путь (JSON)<textarea class="c-path">' +
    esc(JSON.stringify(item.path || [])) +
    '</textarea></label><label>Условия (JSON)<textarea class="c-conditions">' +
    esc(JSON.stringify(item.conditions || {})) +
    "</textarea></label></div>" +
    (realityListOwns(item.path)
      ? '<p class="warning">' + esc(REALITY_LIST_MANAGED_NOTE) + "</p>"
      : "") +
    "</article>"
  );
}

function parseExtra(raw, type) {
  if (type === "boolean") {
    if (!["true", "false"].includes(raw.toLowerCase()))
      throw Error("Boolean должен быть true или false");
    return raw.toLowerCase() === "true";
  }
  if (type === "integer" || type === "float") {
    let n = Number(raw);
    if (!Number.isFinite(n)) throw Error("Ожидалось число");
    return type === "integer" ? Math.trunc(n) : n;
  }
  if (type === "enum" && /^(\[|\{|null$|true$|false$|-?\d)/i.test(raw)) {
    try {
      return JSON.parse(raw);
    } catch {}
  }
  return raw;
}

function syncDraft(article) {
  draftValues[article.dataset.key] = [
    ...article.querySelectorAll(".chip.active"),
  ].map((b) => JSON.parse(decodeURIComponent(b.dataset.value)));
}

function renderCards() {
  let node = $("parameterCards");
  node.innerHTML =
    [...selected].map((k) => card(k, presets[k])).join("") +
    customs.map(customCard).join("");
  if (!node.innerHTML)
    node.innerHTML = '<p class="hint">Выберите характеристики выше.</p>';
  node.querySelectorAll(".mutation-role").forEach(
    (s) =>
      (s.onchange = () => {
        let a = s.closest(".param"),
          key = a.dataset.key,
          spec = presets[key],
          mutate = s.value === "true";
        mutationFlags[key] = mutate;
        draftValues[key] = mutate
          ? [...(spec.values || [])]
          : Object.hasOwn(spec, "current")
            ? [spec.current]
            : spec.values?.length
              ? [spec.values[0]]
              : [];
        renderPresets();
        renderCards();
      }),
  );
  node.querySelectorAll(".chip").forEach(
    (b) =>
      (b.onclick = () => {
        b.classList.toggle("active");
        syncDraft(b.closest(".param"));
      }),
  );
  node.querySelectorAll(".extra-value").forEach(
    (i) =>
      (i.onkeydown = (e) => {
        if (e.key === "Enter" && i.value.trim()) {
          e.preventDefault();
          let article = i.closest(".param"),
            container = article.querySelector(".chips"),
            raw = i.value.trim(),
            value = parseExtra(raw, presets[article.dataset.key].type);
          let existing = [...container.querySelectorAll(".chip")].map((x) =>
            JSON.parse(decodeURIComponent(x.dataset.value)),
          );
          if (!existing.some((x) => same(x, value))) {
            let b = document.createElement("button");
            b.type = "button";
            b.className = "chip active";
            b.dataset.value = encodeURIComponent(JSON.stringify(value));
            b.textContent = shown(value);
            b.onclick = () => {
              b.classList.toggle("active");
              syncDraft(article);
            };
            container.append(b);
            syncDraft(article);
          }
          i.value = "";
        }
      }),
  );
  node.querySelectorAll(".remove-custom").forEach(
    (b) =>
      (b.onclick = () => {
        customs.splice(Number(b.closest(".param").dataset.index), 1);
        renderCards();
      }),
  );
}

function addCustom() {
  customs.push({
    name: "custom_parameter",
    type: "enum",
    target: "inbound",
    values: ["value"],
    path: [],
    conditions: {},
    mutate: true,
  });
  renderCards();
}

// ---------- REALITY: список целей управляет identity-параметрами ----------

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

// buildDraft() — единственный сборщик черновика. Общая часть (panel, inbound,
// testing-подключение, output) собирается всегда; при includePlan=true
// добавляются план и параметры. Черновик всегда проходит через
// stripRealityIdentity, поэтому identity-параметры не попадают ни в один
// запрос: ни preview/run/save, ни сохранение подключения.
function buildDraft({ includePlan = true } = {}) {
  let panelUrl = $("panelUrl").value.trim(),
    sourceId = Number($("sourceId").value),
    port = $("testPort").value,
    server = $("serverAddress").value.trim(),
    binary = $("xrayBinary").value.trim();
  if (!/^https?:\/\//i.test(panelUrl)) throw Error(L.errors.panelUrl);
  if (!Number.isInteger(sourceId) || sourceId < 1)
    throw Error(L.errors.sourceId);
  if (port && (Number(port) < 1 || Number(port) > 65535))
    throw Error(L.errors.testPort);
  if (!server) throw Error(L.errors.serverAddress);
  if (!binary) throw Error(L.errors.xrayBinary);

  let inbound = {
    ...(config.inbound || {}),
    mode: "clone",
    source_id: sourceId,
  };
  if (port) inbound.test_port = Number(port);
  else delete inbound.test_port;

  let previous = config.testing || {};
  let testing = {
    ...previous,
    server_address: server,
    xray_binary: binary,
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

  if (!includePlan) {
    // Режим сохранения подключения: план и параметры не трогаем.
    return stripRealityIdentity({
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
    });
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
      if (!item.values.length) throw Error(`${s.title}: ${L.errors.noValues}`);
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

  // REALITY-список требует параметр security со значением reality (иначе
  // сервер отклонит черновик). Выбор мог его потерять — например, «Копия
  // inbound» фиксирует только live-значения, — поэтому достраиваем его здесь,
  // на единственной границе сборки черновика.
  if (realityCandidates.length) {
    let security = parameters.security;
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
    parameters.security = security;
  }

  let requireTcp = $("requireTcpConnect").value === "true",
    minRate = Number($("minSuccessRate").value) / 100;
  testing.combination_strategy = $("combinationStrategy").value;
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

  return stripRealityIdentity({
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
  });
}

// Точки вызова: preview / run start / save используют полный черновик.
function read() {
  return buildDraft({ includePlan: true });
}

// ---------- Сеть ----------

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

async function saveConnection() {
  await withBusy(["save-connection"], async () => {
    try {
      config = await call(
        "/api/config",
        "POST",
        buildDraft({ includePlan: false }),
      );
      await reloadRegistry();
      notify(
        "connectionStatus",
        registry.live_error
          ? "Конфигурация сохранена, но API панели недоступен: " +
            registry.live_error
          : "Конфигурация сохранена, данные панели обновлены. Перейдите к разделу «Параметры».",
        "ok",
      );
    } catch (error) {
      notify("connectionStatus", "Ошибка: " + error.message);
      bindFieldErrors(error.message);
    }
  });
}

async function loadInbounds() {
  await withBusy(["load-inbounds"], async () => {
    try {
      let rows = await call("/api/inbounds", "POST", {
          url: $("panelUrl").value.trim(),
          verify_tls: $("verifyTls").value === "true",
          trust_env: $("trustEnv").value === "true",
        }),
        select = $("sourceId"),
        current = select.value;
      let options = $("inboundIds");
      options.innerHTML = rows
        .map(
          (row) =>
            '<option value="' +
            row.id +
            '" label="' +
            esc(row.remark || "без названия") +
            '"></option>',
        )
        .join("");
      select.value = current || config.inbound?.source_id || "";
      $("inboundResult").innerHTML =
        "<table><tr><th>Идентификатор</th><th>Название</th><th>Протокол</th><th>Порт</th><th>Включён</th></tr>" +
        rows
          .map(
            (row) =>
              "<tr><td>" +
              row.id +
              "</td><td>" +
              esc(row.remark || "") +
              "</td><td>" +
              row.protocol +
              "</td><td>" +
              row.port +
              "</td><td>" +
              (row.enable ? "Да" : "Нет") +
              "</td></tr>",
          )
          .join("") +
        "</table>";
    } catch (error) {
      notify("inboundResult", "Ошибка API: " + error.message);
    }
  });
}

async function reloadRegistry() {
  try {
    registry = await call("/api/registry");
    presets = registry.parameters || {};
    Object.values(presets).forEach((s) => {
      if (
        Object.hasOwn(s, "current") &&
        !s.values.some((v) => same(v, s.current))
      )
        s.values.unshift(s.current);
    });
    renderMeta();
    renderPresets();
    renderCards();
  } catch (e) {
    $("registryMeta").textContent = "Ошибка реестра: " + e.message;
  }
}

// ---------- План: компактная сортируемая таблица конфигураций ----------

const planValue = (value) =>
  typeof value === "string" ? value || "∅" : JSON.stringify(value);

function planCard(label, value, note = "") {
  return (
    '<div class="plan-kpi"><b>' +
    esc(label) +
    "</b><strong>" +
    esc(value) +
    "</strong><small>" +
    esc(note) +
    "</small></div>"
  );
}

// Сортируемая таблица: клик по заголовку сортирует строки по этому столбцу.
function makeSortable(table) {
  const headers = [...table.querySelectorAll("tr:first-child th")];
  headers.forEach((th, index) => {
    th.classList.add("sortable");
    th.addEventListener("click", () => {
      const direction = th.dataset.sortDir === "asc" ? "desc" : "asc";
      headers.forEach((h) => delete h.dataset.sortDir);
      th.dataset.sortDir = direction;
      const body = [...table.rows].slice(1);
      body.sort((a, b) => {
        const av = a.cells[index]?.textContent ?? "";
        const bv = b.cells[index]?.textContent ?? "";
        const an = Number(av.replace(",", ".").replace(/[^\d.-]/g, ""));
        const bn = Number(bv.replace(",", ".").replace(/[^\d.-]/g, ""));
        const numeric =
          av !== "" && bv !== "" && Number.isFinite(an) && Number.isFinite(bn);
        const cmp = numeric
          ? an - bn
          : av.localeCompare(bv, "ru", { numeric: true });
        return direction === "asc" ? cmp : -cmp;
      });
      body.forEach((row) => table.append(row));
    });
  });
}

function renderPlan(data) {
  let strategyNames = {
      mutation: "Поиск рабочих мутаций",
      pairwise: "Попарное покрытие",
      exhaustive: "Полный перебор",
    },
    strategy = strategyNames[data.strategy] || data.strategy,
    repeats = Number($("runsPerCombination").value) || 1,
    strategyNote = data.adaptive
      ? "поколений: " +
        data.mutation_generations +
        " · ширина отбора: " +
        data.beam_width
      : "фиксированный план",
    capped = data.truncated
      ? "обрезан лимитом " + data.limit
      : "лимит " + data.limit,
    coverage =
      data.designed_combinations !== undefined
        ? "до ограничения: " + data.designed_combinations
        : "изменяемых: " +
          data.mutable_parameters +
          " · фиксированных: " +
          data.fixed_parameters,
    cards = [
      planCard("СТРАТЕГИЯ", strategy, strategyNote),
      planCard("КОНФИГУРАЦИИ", String(data.planned_combinations), capped),
      planCard(
        "ЗАПУСКИ",
        String(data.planned_runs),
        "повторов на конфигурацию: " + repeats,
      ),
      planCard("ПОЛНОЕ ПРОСТРАНСТВО", String(data.raw_combinations), coverage),
    ].join(""),
    rows = (data.preview || [])
      .map((item, index) => {
        let chipsHtml = Object.entries(item || {})
          .map(
            (entry) =>
              '<span class="tag">' +
              esc(entry[0]) +
              ": " +
              esc(planValue(entry[1])) +
              "</span>",
          )
          .join("");
        return (
          "<tr><td>" +
          String(index + 1) +
          '</td><td><div class="config-chips">' +
          (chipsHtml ||
            '<span class="muted-cell">нет изменяемых параметров</span>') +
          "</div></td></tr>"
        );
      })
      .join(""),
    note = data.adaptive
      ? "Сначала проверяется исходная конфигурация и начальные кандидаты, затем развиваются только лучшие успешные варианты."
      : "Показаны первые конфигурации, которые войдут в запуск.";
  $("result").innerHTML =
    '<div class="plan-kpis">' +
    cards +
    '</div><p class="plan-note">' +
    esc(note) +
    '</p><div class="plan-table"><table><tr><th>№</th><th>Параметры конфигурации</th></tr>' +
    (rows ||
      '<tr><td colspan="2" class="muted-cell">Конфигурации не сформированы.</td></tr>') +
    "</table></div>";
  if (data.warnings?.length) {
    let noteNode = document.createElement("div");
    noteNode.className = "warning";
    noteNode.setAttribute("role", "note");
    noteNode.textContent =
      "Предупреждения предварительного просмотра (без обращения к панели):\n" +
      data.warnings.join("\n");
    noteNode.style.whiteSpace = "pre-wrap";
    $("result").prepend(noteNode);
  }
  makeSortable($("result").querySelector(".plan-table table"));
}

async function previewPlan() {
  await withBusy(["preview", "save"], async () => {
    try {
      $("result").innerHTML = '<p class="hint">Расчёт плана…</p>';
      let data = await call("/api/preview", "POST", read());
      renderPlan(data);
      setTab("plan");
    } catch (error) {
      notify("result", "Ошибка: " + error.message);
      bindFieldErrors(error.message);
    }
  });
}

async function save() {
  await withBusy(["preview", "save"], async () => {
    try {
      config = await call("/api/config", "POST", read());
      notify("result", "YAML config сохранён.", "ok");
      notify(
        "connectionStatus",
        "Конфигурация сохранена. Теперь можно загрузить список inbound.",
        "ok",
      );
    } catch (error) {
      notify("result", "Ошибка: " + error.message);
      bindFieldErrors(error.message);
    }
  });
}

// ---------- Запуск: карточка статуса, прогресс, ETA ----------

let runTimer = null;
let runActive = false;
let activeRunId = null;
const metricValue = (value, suffix = "", digits = 1) =>
  Number.isFinite(value) ? `${Number(value).toFixed(digits)}${suffix}` : "—";
const runClock = { startedAt: null, done0: 0 };

function formatEta(seconds) {
  if (!Number.isFinite(seconds) || seconds <= 0) return L.etaNever;
  let m = Math.floor(seconds / 60),
    s = Math.round(seconds % 60);
  return m ? `${m} мин ${s} с` : `${s} с`;
}

function etaSeconds(planned, done) {
  // Оценка по среднему темпу выполненных запусков: темп = выполнено / время,
  // ETA = оставшиеся запуски / темп.
  if (!planned || !runClock.startedAt || done <= runClock.done0) return null;
  const elapsed = (Date.now() - runClock.startedAt) / 1000;
  const pace = (done - runClock.done0) / elapsed;
  if (!Number.isFinite(pace) || pace <= 0) return null;
  return Math.max(0, (planned - done) / pace);
}

function statusCard(label, value, note = "") {
  return `<div class="metric"><b>${esc(label)}</b><strong>${esc(
    value,
  )}</strong><small>${esc(note)}</small></div>`;
}

// Перерисовка карточек (renderRun, renderDashboard) заменяет DOM целиком, поэтому
// раскрытые блоки переживают её по ключу: снимок data-key до перерисовки и
// восстановление open после неё. Оба сборщика обязаны ходить через эту пару.
function openDetailsKeys(root) {
  return new Set(
    [...root.querySelectorAll("details[open]")].map((item) => item.dataset.key),
  );
}

function restoreOpenDetails(root, keys) {
  root.querySelectorAll("details").forEach((item) => {
    item.open = keys.has(item.dataset.key);
  });
}

function detailsBlock(key, summary, payload) {
  if (payload === undefined || payload === null || payload === "") return "";
  return `<details class="run-details" data-key="${esc(
    key,
  )}"><summary>${esc(summary)}</summary><pre class="run-details-body">${esc(
    JSON.stringify(payload, null, 2),
  )}</pre></details>`;
}

function renderRun(d) {
  let total = d.planned_runs || d.planned_combinations || 1,
    done = d.completed || 0,
    planned = d.planned_runs ?? d.planned_combinations ?? "?",
    status = L.status[d.status] || d.status;
  $("runProgress").max = total;
  $("runProgress").value = done;

  runActive = ["running", "stopping"].includes(d.status);
  activeRunId = d.id ?? activeRunId;
  clearTimeout(runTimer);
  runTimer = null;
  if (runActive) {
    if (!runClock.startedAt || done < runClock.done0) {
      runClock.startedAt = Date.now();
      runClock.done0 = done;
    }
    runTimer = setTimeout(pollRun, 1500);
  } else {
    runClock.startedAt = null;
  }

  const eta = etaSeconds(planned === "?" ? null : planned, done);
  let lines =
    `${L.statusLabel}: ${esc(status)}\n` +
    `${L.runsLabel}: ${esc(done)} / ${esc(planned)}` +
    (d.test_id !== undefined
      ? `\n${L.currentConfiguration}: ${esc(d.test_id)} / ${esc(
          d.planned_combinations,
        )}`
      : d.planned_combinations !== undefined
        ? `\n${L.configurationLimit}: ${esc(d.planned_combinations)}`
        : "") +
    (d.generation !== undefined
      ? `\n${L.mutationGeneration}: ${esc(d.generation)}`
      : "") +
    (d.mutable_parameters !== undefined
      ? `\n${L.mutableFixed}: ${esc(d.mutable_parameters)} / ${esc(
          d.fixed_parameters,
        )}`
      : "") +
    `\n${L.failedLabel}: ${esc(d.failed || 0)}` +
    `\n${L.etaLabel}: ${esc(formatEta(eta))}` +
    (d.result_directory
      ? `\n${L.resultsLabel}: ${esc(d.result_directory)}`
      : "") +
    (d.error ? `\n${L.errorLabel}: ${esc(d.error)}` : "");
  let skipped = d.skipped ?? d.summary?.skipped ?? 0;
  lines += `\n${L.skippedLabel}: ${esc(skipped)}`;
  let warnings = d.warnings ?? d.summary?.warnings;
  if (warnings?.length)
    lines += `\n${L.warningsLabel}:\n${esc(warnings.join("\n"))}`;

  let resultNode = $("runResult");
  const openKeys = openDetailsKeys(resultNode);
  resultNode.innerHTML =
    `<div class="status-card-head"><span class="badge badge-${esc(
      d.status,
    )}">${esc(status)}</span><span class="status-card-eta">${esc(
      L.etaLabel,
    )}: ${esc(formatEta(eta))}</span></div>` +
    `<pre class="status-card-lines">${lines}</pre>` +
    detailsBlock("lastConfiguration", L.lastConfiguration, d.last_configuration) +
    detailsBlock("lastMetrics", L.lastMetrics, d.last_result) +
    detailsBlock("summary", L.summary, d.summary);
  restoreOpenDetails(resultNode, openKeys);
}

// Поллинг: запросы уходят только при активном запуске; renderRun() сам
// планирует следующий опрос лишь пока статус running/stopping. pollRun.manual
// разрешает один принудительный цикл (кнопка «Статус», старт, остановка).
async function pollRun() {
  if (!runActive && runTimer === null && !pollRun.manual) return;
  pollRun.manual = false;
  try {
    let [status, dashboard] = await Promise.all([
      call("/api/run/status"),
      call("/api/run/dashboard"),
    ]);
    renderRun(status);
    renderDashboard(dashboard);
  } catch (e) {
    notify("runResult", "Ошибка статуса: " + e.message);
  }
}

async function startRun() {
  await withBusy(["start-run", "stop-run", "poll-run"], async () => {
    try {
      notify("runResult", "Подготовка временного inbound и плана…", "ok");
      runClock.startedAt = null;
      renderRun(await call("/api/run/start", "POST", read()));
      renderDashboard({ records: 0 });
      refreshRuns();
    } catch (error) {
      notify("runResult", "Ошибка запуска: " + error.message);
      bindFieldErrors(error.message);
    }
  });
}

async function stopRun() {
  await withBusy(["stop-run", "poll-run"], async () => {
    try {
      renderRun(await call("/api/run/stop", "POST", {}));
      pollRun.manual = true;
      pollRun();
    } catch (error) {
      notify("runResult", "Ошибка остановки: " + error.message);
    }
  });
}

// ---------- Дашборд кандидатов: сортировка и отметка «лучшая» ----------

function renderDashboard(data) {
  let node = $("runDashboard");
  if (!data.records) {
    node.classList.remove("visible");
    node.innerHTML = "";
    return;
  }
  const openKeys = openDetailsKeys(node);
  let best = data.best_score || {},
    p95 = data.best_p95 || {},
    fastest = data.fastest || {},
    cards = [
      statusCard(
        "Завершено",
        String(data.records) + " / " + String(data.planned_runs || "?"),
        "запусков",
      ),
      statusCard(
        "Доля успешных",
        data.attempted
          ? metricValue((data.success_rate ?? 0) * 100, "%", 0)
          : "—",
        "по всем повторам",
      ),
      statusCard(
        "Лучший балл",
        metricValue(best.score, "", 3),
        best.short_label || best.label || "нет успешных",
      ),
      statusCard(
        "Минимальный p95",
        metricValue(p95.p95_ms, " мс"),
        p95.short_label || p95.label || "нет данных",
      ),
      statusCard(
        "Максимальная скорость",
        metricValue(fastest.download_mbps, " Мбит/с"),
        fastest.short_label || fastest.label || "нет данных",
      ),
      statusCard("Пропущено", String(data.skipped ?? 0), "без сетевого теста"),
    ].join("");
  const bestLabels = new Set(
    [best.label, p95.label, fastest.label].filter(Boolean),
  );
  let rows = data.candidates
    .map((candidate) => {
      const isBest = bestLabels.has(candidate.label);
      return (
        "<tr" +
        (isBest ? ' class="best-row"' : "") +
        "><td>" +
        esc(candidate.label) +
        "</td><td>" +
        candidate.tests +
        '</td><td class="' +
        (candidate.successful ? "good" : "bad") +
        '">' +
        candidate.successful +
        "/" +
        candidate.tests +
        "</td><td>" +
        metricValue(candidate.score, "", 3) +
        "</td><td>" +
        metricValue(candidate.p95_ms, " мс") +
        (candidate.p95_stddev_ms !== null &&
        candidate.p95_stddev_ms !== undefined
          ? " ± " + metricValue(candidate.p95_stddev_ms, " мс")
          : "") +
        "</td><td>" +
        metricValue(candidate.download_mbps, " Мбит/с") +
        (candidate.download_stddev_mbps !== null &&
        candidate.download_stddev_mbps !== undefined
          ? " ± " + metricValue(candidate.download_stddev_mbps, " Мбит/с")
          : "") +
        "</td></tr>"
      );
    })
    .join("");
  node.classList.add("visible");
  node.innerHTML =
    '<div class="dashboard-grid">' +
    cards +
    '</div><div class="candidate-table"><table><tr><th>Конфигурация</th><th>Повторы</th><th>Успех</th><th>Балл</th><th>p95</th><th>Скорость</th></tr>' +
    rows +
    "</table></div>";
  node.querySelectorAll(".candidate-table tr").forEach((row, index) => {
    if (!index) return;
    const candidate = data.candidates[index - 1];
    if (!candidate) return;
    const cell = row.cells[0];
    cell.classList.add("config-cell");
    const details = document.createElement("details");
    details.className = "configuration-details";
    details.dataset.key = candidate.label;
    const summary = document.createElement("summary");
    summary.textContent =
      (candidate.short_label || "#" + candidate.number) +
      (bestLabels.has(candidate.label) ? " · " + L.bestMark : "");
    const full = document.createElement("div");
    full.className = "configuration-full";
    full.textContent = candidate.label;
    details.append(summary, full);
    cell.replaceChildren(details);
  });
  restoreOpenDetails(node, openKeys);
  makeSortable(node.querySelector(".candidate-table table"));
}

// ---------- История запусков: бейдж и панель активного запуска ----------

let lastHistoryRefresh = 0;

function openRunDashboard() {
  setTab("run");
  pollRun.manual = true;
  pollRun();
  $("runDashboard").scrollIntoView({ behavior: "smooth", block: "start" });
}

async function refreshRuns() {
  lastHistoryRefresh = Date.now();
  let node = $("runHistory");
  try {
    let runs = await call("/api/runs");
    if (!runs.length) {
      node.innerHTML =
        '<div class="history-empty">Запусков пока нет. После первой проверки здесь появятся отчёты.</div>';
      return;
    }
    let labels = {
      "results.xlsx": "XLSX",
      "results.csv": "CSV",
      "summary.csv": "Сводка CSV",
      "results.json": "JSON",
      "results.jsonl": "Журнал",
      "errors.jsonl": "Ошибки",
      "diagnostics.jsonl": "Диагностика",
    };
    let rows = runs
      .map((run) => {
        let links = run.files
          .map(
            (file) =>
              '<a href="/api/runs/' +
              encodeURIComponent(run.id) +
              "/download/" +
              encodeURIComponent(file) +
              '" download>' +
              esc(labels[file] || file) +
              "</a>",
          )
          .join("");
        const isActive = run.id === activeRunId;
        const statusCell = isActive
          ? `<span class="badge badge-active">${
              esc(L.historyStatuses[run.status] || run.status) || esc(run.status)
            }</span>`
          : esc(run.status);
        const dashboardCell = isActive
          ? `<button type="button" class="secondary open-dashboard" data-run-id="${esc(
              run.id,
            )}">${esc(L.openDashboard)}</button>`
          : "";
        return (
          "<tr" +
          (isActive ? ' class="active-run"' : "") +
          "><td>" +
          esc(run.id) +
          "</td><td>" +
          statusCell +
          "</td><td>" +
          Number(run.records) +
          '</td><td><div class="report-links">' +
          (links || '<span class="muted-cell">Файлы ещё создаются</span>') +
          "</div>" +
          dashboardCell +
          "</td></tr>"
        );
      })
      .join("");
    node.innerHTML =
      "<table><tr><th>Запуск</th><th>Статус</th><th>Повторы</th><th>Скачать</th></tr>" +
      rows +
      "</table>";
    node
      .querySelector(".open-dashboard")
      ?.addEventListener("click", openRunDashboard);
  } catch (error) {
    node.textContent = "Ошибка загрузки истории: " + error.message;
  }
}

// ---------- Инициализация ----------

function initialise() {
  let p = config.panel || {},
    i = config.inbound || {},
    t = config.testing || {},
    o = config.output || {},
    q = t.quality_gates || {},
    s = t.screening || {},
    to = config.timeouts || {},
    speed = t.speed_test || {};
  $("panelUrl").value = p.url || "";
  $("sourceId").value = i.source_id || "";
  $("testPort").value = i.test_port ?? "";
  $("serverAddress").value = t.server_address || "";
  $("tlsSni").value = t.tls_server_name || "";
  $("verifyPeerName").value = t.verify_peer_cert_by_name || "";
  $("xrayBinary").value = t.xray_binary || "xray";
  $("verifyTls").value = String(p.verify_tls ?? true);
  $("trustEnv").value = String(p.trust_env ?? false);
  $("outputDir").value = o.directory || "./results";
  $("urls").value = (t.urls || []).join("\n");
  $("combinationStrategy").value = t.combination_strategy || "mutation";
  $("mutationGenerations").value = t.mutation_generations || 2;
  $("beamWidth").value = t.beam_width || 8;
  $("childrenPerParent").value = t.children_per_parent || 8;
  $("maxCombinations").value = t.max_combinations || 50;
  $("runsPerCombination").value = t.runs_per_combination || 5;
  $("maxFailedRuns").value = t.max_failed_runs || 1;
  $("requestTimeout").value = to.request ?? 5;
  $("tcpConnectTimeout").value = to.tcp_connect ?? 3;
  $("screeningTimeout").value = to.screening ?? 8;
  $("screeningRequests").value = s.requests || 1;
  $("minSuccessRate").value =
    (q.min_success_rate ?? s.min_success_rate ?? 1) * 100;
  $("maxLatencyP95").value = q.max_latency_p95_ms || 0;
  $("requireTcpConnect").value = String(
    q.require_tcp_connect ?? s.require_tcp_connect ?? true,
  );
  $("latencyRequests").value = t.latency?.requests || 3;
  $("stabilityRequests").value = t.stability?.requests || 5;
  $("pingEnabled").value = String(t.ping?.enabled ?? true);
  $("pingRequests").value = t.ping?.requests || 4;
  // Значения по умолчанию для замера скорости.
  if (speed.enabled === undefined) {
    speed.enabled = true;
    t.speed_test = speed;
  }
  $("speedEnabled").value = String(speed.enabled ?? false);
  $("speedUrl").value =
    speed.url || "https://mirror.nforce.com/pub/speedtests/25mb.bin";
  $("speedMegabytes").value = (speed.max_bytes || 5000000) / 1000000;
  selected = new Set(
    Object.keys(config.parameters || {}).filter((k) => presets[k]),
  );
  draftValues = {};
  mutationFlags = {};
  Object.entries(config.parameters || {}).forEach(([k, v]) => {
    if (presets[k]) {
      mutationFlags[k] = v.mutate !== false;
      if (v.values) draftValues[k] = v.values;
    }
  });
  customs = Object.entries(config.parameters || {})
    .filter(([k]) => !presets[k])
    .map(([name, v]) => ({ ...v, name }));
  let reality = t.reality || {};
  $("realityTarget").value = reality.target || "";
  $("realityServerNames").value = (reality.server_names || []).join(", ");
  realityCandidates = reality.candidates || [];
  renderMeta();
  renderPresets();
  renderCards();
  showRealityCandidates();
  if (p.url && i.source_id) loadInbounds();
  else
    $("inboundResult").textContent =
      "Введите адрес панели и загрузите список inbound, затем сохраните конфигурацию.";
  // Поллинг запускается только если сервер держит активный запуск; в простое
  // повторные запросы /api/run/status не выполняются.
  pollRun.manual = true;
  pollRun().then(refreshRuns);
}

function setTab(name) {
  document.querySelectorAll("[data-tab-panel]").forEach((panel) => {
    panel.hidden = panel.dataset.tabPanel !== name;
  });
  document.querySelectorAll("[data-tab]").forEach((tab) => {
    let active = tab.dataset.tab === name;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
  });
  if (name === "run") refreshRuns();
}

Promise.all([call("/api/config"), call("/api/registry")])
  .then(([c, r]) => {
    config = c;
    registry = r;
    presets = r.parameters || {};
    Object.values(presets).forEach((s) => {
      if (
        Object.hasOwn(s, "current") &&
        !s.values.some((v) => same(v, s.current))
      )
        s.values.unshift(s.current);
    });
    initialise();
  })
  .catch((e) => notify("result", "Ошибка загрузки: " + e.message));

document
  .querySelector('[data-action="preview"]')
  ?.addEventListener("click", previewPlan);
document
  .querySelector('[data-action="save"]')
  ?.addEventListener("click", save);
document
  .querySelector('[data-action="save-connection"]')
  ?.addEventListener("click", saveConnection);
document
  .querySelector('[data-action="start-run"]')
  ?.addEventListener("click", startRun);
document
  .querySelector('[data-action="stop-run"]')
  ?.addEventListener("click", stopRun);
document
  .querySelector('[data-action="poll-run"]')
  ?.addEventListener("click", () => {
    pollRun.manual = true;
    pollRun();
  });

setTab("connection");
