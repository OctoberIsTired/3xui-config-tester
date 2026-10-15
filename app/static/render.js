// 3xui-config-tester Web UI — presentation layer: parameter cards, plan, run dashboard, history and boot code. Loads after api.js and draft.js.
"use strict";

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
    ? (registry.environment?.panel_access === "available"
        ? "Документированный каталог загружен, но настройки источника не получены: "
        : "Документированный каталог загружен, но API панели недоступен: ") +
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
  $("routeStatus").textContent = registry.environment?.message ||
    (registry.live_error ? "Доступ к панели не подтверждён. Проверьте текущий VPN/маршрут и авторизацию." :
      "Панель доступна через текущий маршрут. Системные настройки сети не меняются.");
}

function profileDomain(name) {
  let spec = presets[name] || {}, values = selectedValues(name, spec);
  if (!selected.has(name) || mutationFlags[name] === false)
    return [config.parameters?.[name]?.baseline ?? spec.current ?? values[0]].filter((value) => value !== undefined);
  return values;
}

// UI only marks definitely inactive fields. The backend owns feasibility and
// handles constraints for mixed domains and higher-order interactions.
function conditionPossible(rule) {
  if (!rule || typeof rule !== "object") return true;
  if (rule.all) return rule.all.every(conditionPossible);
  if (rule.any) return rule.any.some(conditionPossible);
  if (rule.not) return true;
  let entries = rule.parameter ? [[rule.parameter, rule]] : Object.entries(rule);
  return entries.every(([name, check]) => {
    if (!check || typeof check !== "object") return true;
    let values = profileDomain(name);
    if (check.exists !== undefined) return check.exists ? Boolean(values.length) : !values.length;
    if (!values.length) return true;
    return values.some((value) => {
      if (Object.hasOwn(check, "equals") && !same(value, check.equals)) return false;
      if (Object.hasOwn(check, "not_equals") && same(value, check.not_equals)) return false;
      if (check.in && !check.in.some((allowed) => same(value, allowed))) return false;
      if (check.not_in && check.not_in.some((denied) => same(value, denied))) return false;
      return true;
    });
  });
}

function inactiveReason(spec) {
  if (conditionPossible(spec.conditions)) return "";
  const text = formatCondition(spec.conditions);
  return text ? "Требуется: " + text : "Не выполнены условия выбранного профиля";
}

function formatCondition(rule) {
  function label(name) {
    if (name === "network") return "транспорт";
    if (name === "security") return "защита";
    const title = presets[name]?.title;
    if (!title) return null;
    return /^[А-ЯЁ]/.test(title) ? title[0].toLowerCase() + title.slice(1) : title;
  }
  function valueText(value) {
    if (value === true) return "включён";
    if (value === false) return "выключен";
    if (value === null || value === "") return "не задано";
    if (typeof value === "number") return Number.isFinite(value) ? String(value) : null;
    if (typeof value !== "string") return null;
    return ({tcp:"TCP", kcp:"KCP", ws:"WebSocket", grpc:"gRPC", xhttp:"XHTTP",
      httpupgrade:"HTTP Upgrade", tls:"TLS", reality:"REALITY", none:"без защиты"})[value] || value;
  }
  function join(parts, mode) {
    if (!parts.length || parts.some((part) => !part)) return null;
    const text = parts.map((part) => mode === "and" && part.mode === "or" ? `(${part.text})` : part.text)
      .join(mode === "and" ? " и " : " или ");
    return {text, mode: parts.length > 1 ? mode : parts[0].mode};
  }
  function atom(name, check) {
    const subject = label(name);
    if (!subject || !check || typeof check !== "object" || Array.isArray(check)) return null;
    const allowed = new Set(["parameter", "equals", "not_equals", "in", "not_in", "exists"]);
    if (Object.keys(check).some((key) => !allowed.has(key))) return null;
    const parts = [];
    for (const key of ["equals", "not_equals", "in", "not_in", "exists"]) {
      if (!Object.hasOwn(check, key)) continue;
      let text;
      if (key === "exists") {
        if (typeof check[key] !== "boolean") return null;
        text = subject + (check[key] ? " задан" : " не задан");
      } else if (key === "in" || key === "not_in") {
        if (!Array.isArray(check[key]) || !check[key].length) return null;
        const values = check[key].map(valueText);
        if (values.some((value) => value === null)) return null;
        text = subject + (key === "not_in" ? " — кроме " : " ") + values.join(" или ");
      } else {
        const value = valueText(check[key]);
        if (value === null) return null;
        text = name === "security" && check[key] === "none" ?
          (key === "not_equals" ? "с защитой" : "без защиты") :
          subject + (key === "not_equals" ? " — кроме " : " ") + value;
      }
      parts.push({text, mode:"atom"});
    }
    return join(parts, "and");
  }
  function parse(node) {
    if (!node || typeof node !== "object" || Array.isArray(node)) return null;
    for (const [key, mode] of [["all", "and"], ["any", "or"]]) {
      if (Object.hasOwn(node, key)) {
        if (Object.keys(node).length !== 1 || !Array.isArray(node[key])) return null;
        return join(node[key].map(parse), mode);
      }
    }
    if (Object.hasOwn(node, "not")) {
      if (Object.keys(node).length !== 1) return null;
      const child = parse(node.not);
      return child ? {text:`не (${child.text})`, mode:"atom"} : null;
    }
    if (typeof node.parameter === "string") return atom(node.parameter, node);
    return join(Object.entries(node).map(([name, check]) => atom(name, check)), "and");
  }
  return parse(rule)?.text || null;
}

function showStrategySettings() {
  const adaptive = $("combinationStrategy").value === "adaptive";
  document.querySelectorAll(".adaptive-settings").forEach((node) => { node.hidden = !adaptive; });
  $("searchGoal").disabled = !adaptive;
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
      `${k} ${s.title} ${s.help} ${s.group}`.toLowerCase().includes(query) &&
      ($("showInactive")?.checked || !inactiveReason(s)),
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
      const inactive = inactiveReason(s);
      if (inactive) item.classList.add("inactive-parameter");
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
      }${live}${inactive ? `<small class="warning" title="${esc(JSON.stringify(s.conditions))}">${esc(inactive)}</small>` : ""}</span>`;
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
        ? ` · <span title="${esc(JSON.stringify(spec.conditions))}">Требуется: ${esc(formatCondition(spec.conditions) || "не выполнены условия выбранного профиля")}</span>`
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
  // У string-поля values — подсказки, а не домен: сохранённое значение вне
  // подсказок (SNI, введённый вручную) должно оставаться видимым чипом, иначе
  // syncDraft соберёт пустой набор и потеряет его молча. У enum домен закрытый
  // и подсказками не расширяется.
  let options =
    spec.type === "string"
      ? spec.values.concat(active.filter((value) => !spec.values.some((x) => same(x, value))))
      : spec.values;
  return (
    '<article class="param" data-key="' +
    name +
    '" data-kind="preset">' +
    header +
    chips(name, options, active) +
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
  const fieldDrafts = new Map();
  node.querySelectorAll(".param").forEach((article) => {
    const key = article.dataset.key || "custom:" + article.dataset.index;
    fieldDrafts.set(key, [...article.querySelectorAll(".range-min,.range-max,.range-step,.c-name,.c-type,.c-target,.c-mutate,.c-values,.c-path,.c-conditions")]
      .map((input) => ["." + input.classList[0], input.value]));
  });
  node.innerHTML =
    [...selected].map((k) => card(k, presets[k])).join("") +
    customs.map(customCard).join("");
  if (!node.innerHTML)
    node.innerHTML = '<p class="hint">Выберите характеристики выше.</p>';
  node.querySelectorAll(".param").forEach((article) => {
    const key = article.dataset.key || "custom:" + article.dataset.index;
    (fieldDrafts.get(key) || []).forEach(([selector, value]) => {
      const input = article.querySelector(selector);
      if (input) input.value = value;
    });
  });
  node.querySelectorAll('.param[data-kind="preset"]').forEach((article) => {
    const reason = inactiveReason(presets[article.dataset.key] || {});
    article.hidden = Boolean(reason && !$("showInactive")?.checked);
    article.classList.toggle("inactive-parameter", Boolean(reason));
    if (reason) {
      const note = document.createElement("p");
      note.className = "warning";
      note.textContent = reason;
      note.title = JSON.stringify(presets[article.dataset.key]?.conditions || {});
      article.prepend(note);
    }
  });
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
        renderPresets();
        renderCards();
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

async function saveConnection() {
  await withBusy(["save-connection"], async () => {
    try {
      config = await call(
        "/api/config",
        "POST",
        buildDraft({ includePlan: false }),
      );
      await reloadRegistry();
      const access = registry.environment?.panel_access;
      notify(
        "connectionStatus",
        !registry.live_error
          ? "Конфигурация сохранена, данные панели обновлены. Перейдите к разделу «Параметры»."
          : access === "available"
            ? "Конфигурация сохранена, но настройки источника не загружены: " +
              registry.live_error
            : "Конфигурация сохранена, но API панели недоступен: " +
              registry.live_error,
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
      adaptive: "Адаптивный поиск с подтверждением",
      pairwise: "Попарное покрытие",
      exhaustive: "Полный перебор",
    },
    strategy = strategyNames[data.strategy] || data.strategy,
    repeats = Number($("runsPerCombination").value) || 1,
    strategyNote = data.strategy === "adaptive"
      ? "Скрининг → сравнение → новые сессии подтверждения"
      : data.adaptive
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
        data.planned_runs_is_upper_bound ? "верхняя граница попыток; фактическое число зависит от результатов" : "повторов на конфигурацию: " + repeats,
      ),
      planCard("RAW ВЕРХНЯЯ ГРАНИЦА", String(data.raw_combinations), "включает неактивные сочетания; " + coverage),
      ...(data.coverage ? [planCard("ПОКРЫТИЕ ПАР", `${data.coverage.covered_pairs ?? 0} / ${data.coverage.total_pairs ?? "?"}`,
        `неопределённых: ${data.coverage.unknown_pairs ?? "?"}; ${data.coverage.coverage_complete ? "завершено" : "ограничено бюджетом"}`)] : []),
      ...(data.budgets ? [planCard("БЮДЖЕТ", `${data.budgets.time_budget_seconds / 60} мин`,
        `${data.budgets.request_budget} HTTP · ${data.budgets.traffic_budget_bytes / 1000000} МБ · ${data.budgets.apply_budget} применений`)] : []),
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
    note = data.strategy === "adaptive"
      ? "Локальный предварительный план: независимые профили и сочетания остаются в поиске без успешного baseline. Сетевое подтверждение ещё не выполнено. Один inbound, последовательная проверка на порту " + (data.ports || []).join(", ") + "."
      : data.adaptive
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
let selectedDashboardRunId = null;
let dashboardCursor = 0;
let pollingRun = false;
let pollFailures = 0;
let lastRunStatus = "idle";
const recentRunSummaries = new Map();
const DASHBOARD_PAGE_SIZE = 100;
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

function terminationReasonLabel(reason) {
  if (!reason) return "";
  return ({
    frontier_exhausted: "Проверен выбранный набор кандидатов",
    profile_space_exhausted: "Проверен сформированный набор кандидатов",
    budget_exhausted: "Исчерпан бюджет",
    first_confirmed: "Найдена подтверждённая конфигурация",
    stopped: "Остановлено пользователем",
    environment_unavailable: "Недоступно окружение проверки",
    cleanup_pending: "Ожидается восстановление inbound",
    coverage_budget_exhausted: "Исчерпан бюджет построения покрытия",
  })[reason] || "Причина указана в подробной сводке";
}

function formatBudget(budget) {
  if (!budget || typeof budget !== "object") return "";
  const limits = budget.limits || {};
  const numeric = (value) => typeof value === "number" && Number.isFinite(value) && value >= 0;
  const shownNumber = (value) => value.toLocaleString("ru-RU", {maximumFractionDigits: 1});
  return [
    ["candidates", "Кандидаты", ""], ["requests", "HTTP-запросы", ""],
    ["traffic_bytes", "Трафик", " байт"], ["api_applies", "Применений к панели", ""],
    ["client_starts", "Запусков Xray", ""], ["elapsed_seconds", "Время", " с"],
  ].filter(([key]) => numeric(budget[key])).map(([key, label, unit]) =>
    `${label}: ${shownNumber(budget[key])}${numeric(limits[key]) ? " / " + shownNumber(limits[key]) : ""}${unit}`
  ).join("\n");
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

// ---------- Продолжение исчерпанного прогона ----------

// «Продолжить с бюджетом ×2» удваивает видимые поля бюджета: новые лимиты
// видны в форме до отправки, и их можно поправить перед нажатием второй кнопки.
const BUDGET_INPUT_IDS = ["maxCombinations", "requestBudget", "applyBudget", "trafficBudget", "timeBudget"];

function doubleBudgetInputs() {
  BUDGET_INPUT_IDS.forEach((id) => {
    const value = Number($(id).value);
    if (Number.isFinite(value) && value > 0) $(id).value = String(Math.round(value * 2 * 10) / 10);
  });
}

// Действие показывается только у завершённого запуска, который остановился
// именно на исчерпанном бюджете: остальные причины продолжать нечем.
function continuationActions(runId, reason) {
  if (!runId || runActive || reason !== "budget_exhausted") return "";
  const id = esc(runId);
  return (
    '<div class="actions continuation-actions">' +
    `<button type="button" class="secondary" data-action="continue-run" data-run-id="${id}" onclick="continueRun('${id}', false)">${esc(L.continueRun)}</button>` +
    `<button type="button" data-action="continue-run" data-run-id="${id}" onclick="continueRun('${id}', true)">${esc(L.continueRunDoubled)}</button>` +
    `<small class="field-help">${esc(L.continuationHint)}</small></div>`
  );
}

function renderRun(d) {
  let total = d.planned_runs || d.planned_combinations || 1,
    done = d.completed || 0,
    planned = d.planned_runs ?? d.planned_combinations ?? "?",
    status = L.status[d.status] || d.status;
  $("runProgress").max = total;
  $("runProgress").value = done;

  runActive = ["starting", "running", "stopping", "cleanup"].includes(d.status);
  lastRunStatus = d.status;
  syncActionAvailability();
  activeRunId = d.run_id ?? d.id ?? activeRunId;
  const finishedReason = d.termination_reason || d.summary?.termination_reason;
  if (activeRunId) recentRunSummaries.set(activeRunId, {
    termination_reason: finishedReason,
    budget: d.budget || d.summary?.budget,
  });
  clearTimeout(runTimer);
  runTimer = null;
  if (runActive) {
    if (!runClock.startedAt || done < runClock.done0) {
      runClock.startedAt = Date.now();
      runClock.done0 = done;
    }
    if (!pollingRun) runTimer = setTimeout(pollRun, 1500);
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
    (d.test_inbound_id !== undefined
      ? `\n${L.testInbound}: #${esc(d.test_inbound_id)}, ${L.portLabel} ${esc(
          d.test_inbound_port ?? "?",
        )}`
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
  if (d.phase || d.stage) lines += `\nЭтап: ${esc(d.fidelity || d.phase || d.stage)}`;
  if (d.confirmed_candidates !== undefined) lines += `\nПодтверждено в наблюдаемых окнах: ${esc(d.confirmed_candidates)}`;
  if (d.termination_reason || d.summary?.termination_reason)
    lines += `\nПричина завершения: ${esc(terminationReasonLabel(finishedReason))}`;
  if (d.resumed) lines += `\n${esc(L.resumedLabel)}`;
  const budgetText = formatBudget(d.budget || d.summary?.budget);
  if (budgetText) lines += `\nРасход бюджета:\n${esc(budgetText)}`;
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
    detailsBlock("summary", L.summary, d.summary || (d.budget ? {budget: d.budget, coverage: d.coverage} : null)) +
    continuationActions(activeRunId, finishedReason);
  restoreOpenDetails(resultNode, openKeys);
  // Кнопки карточки статуса создаются здесь, поэтому состояние доступности
  // применяется и после перерисовки, а не только к кнопкам из разметки.
  syncActionAvailability();
}

function syncActionAvailability() {
  if (inflightRequests) return;
  const blocked = runActive || lastRunStatus === "cleanup_pending";
  document.querySelectorAll('[data-action="start-run"]').forEach((button) => {
    button.disabled = blocked;
  });
  // Продолжение — тоже запуск: пока активен любой прогон или ждёт cleanup,
  // кнопка недоступна, включая кнопки, отрисованные вместе с карточкой статуса.
  document.querySelectorAll('[data-action="continue-run"]').forEach((button) => {
    button.disabled = blocked;
  });
  document.querySelectorAll('[data-action="stop-run"]').forEach((button) => { button.disabled = !runActive; });
}

// Поллинг: запросы уходят только при активном запуске; renderRun() сам
// планирует следующий опрос лишь пока статус running/stopping. pollRun.manual
// разрешает один принудительный цикл (кнопка «Статус», старт, остановка).
async function pollRun() {
  if (pollingRun) return;
  if (!runActive && runTimer === null && !pollRun.manual) return;
  pollRun.manual = false;
  pollingRun = true;
  clearTimeout(runTimer);
  runTimer = null;
  try {
    let [status, dashboard] = await Promise.all([
      call("/api/run/status"),
      call(dashboardUrl()),
    ]);
    renderRun(status);
    renderDashboard(dashboard);
    pollFailures = 0;
  } catch (e) {
    pollFailures += 1;
    notify("runResult", "Ошибка статуса: " + e.message);
  } finally {
    pollingRun = false;
    if (runActive || pollFailures) {
      const delay = Math.min(30000, 1500 * 2 ** Math.min(pollFailures, 4));
      runTimer = setTimeout(pollRun, delay);
    }
  }
}

function dashboardUrl() {
  const path = selectedDashboardRunId ? `/api/runs/${encodeURIComponent(selectedDashboardRunId)}/dashboard` : "/api/run/dashboard";
  return `${path}?cursor=${dashboardCursor}&limit=${DASHBOARD_PAGE_SIZE}`;
}

async function changeDashboardPage(cursor) {
  dashboardCursor = Math.max(0, cursor);
  try { renderDashboard(await call(dashboardUrl())); }
  catch (error) { notify("runResult", "Ошибка результатов: " + error.message); }
}

async function startRun() {
  await withBusy(["start-run", "stop-run", "poll-run"], async () => {
    try {
      notify("runResult", "Подготовка временного inbound и плана…", "ok");
      runClock.startedAt = null;
      selectedDashboardRunId = null;
      dashboardCursor = 0;
      renderRun(await call("/api/run/start", "POST", read()));
      setTab("run");
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

// Продолжение исчерпанного прогона: тот же каталог и чекпойнт, новые лимиты
// берутся из формы — поэтому перед отправкой бюджет можно поправить, а кнопка
// «×2» лишь удваивает текущие поля.
async function continueRun(runId, doubled) {
  if (doubled) doubleBudgetInputs();
  await withBusy(["continue-run", "start-run", "stop-run", "poll-run"], async () => {
    try {
      notify("runResult", L.continuationPending, "ok");
      runClock.startedAt = null;
      selectedDashboardRunId = runId;
      dashboardCursor = 0;
      renderRun(await call(`/api/runs/${encodeURIComponent(runId)}/continue`, "POST", read()));
      setTab("run");
      renderDashboard(await call(dashboardUrl()));
      await refreshRuns();
    } catch (error) {
      notify("runResult", L.continuationFailed + error.message);
      bindFieldErrors(error.message);
    }
  });
}

// ---------- Дашборд кандидатов: сортировка и отметка «лучшая» ----------

function renderDashboard(data) {
  let node = $("runDashboard");
  if (!data.records) {
    if (data.cleanup_pending || data.status === "cleanup_pending") {
      node.classList.add("visible");
      node.innerHTML = '<p class="warning">Восстановление inbound не завершено. Используйте кнопку «Восстановить / удалить копию» в истории. Новый эксперимент ожидает cleanup.</p>';
      return;
    }
    if (selectedDashboardRunId) {
      node.classList.add("visible");
      node.innerHTML = '<p class="hint">В этом сохранённом запуске ещё нет завершённых сетевых измерений.</p>';
      return;
    }
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
      statusCard("Подтверждено", String(data.confirmed_candidates ?? 0), "в наблюдаемых окнах"),
      statusCard("Предварительно доступно", String(data.preliminary_candidates ?? 0), "ожидает подтверждения"),
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
        "</td><td>" +
        esc(qualificationLabel(candidate.qualification)) +
        '<small class="candidate-context">' +
        esc(`${candidate.phase || "search"} / ${candidate.fidelity || "full"} · окно сети ${candidate.environment_epoch ?? 0} · HTTP ${metricValue(candidate.sample_count, "", 0)}`) +
        (candidate.reason_code ? `<br>${esc(typeof candidate.reason_code === "string" ? candidate.reason_code : JSON.stringify(candidate.reason_code))}` : "") +
        "</small>" +
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
    `</div><p class="hint">${selectedDashboardRunId ? "Сохранённый запуск: " + esc(selectedDashboardRunId) : "Текущий запуск"}. Этапы и окна сети показаны отдельно. Отсутствие замера скорости обозначено «—». Успех запросов не устанавливает причину блокировки.</p>` +
    (data.journal?.corrupt_records ? `<p class="warning">Повреждённых завершённых записей: ${data.journal.corrupt_records}. Они не включены в метрики.</p>` : "") +
    '<div class="candidate-table"><table><tr><th>Конфигурация</th><th>Попытки</th><th>Подтверждение</th><th>Успех</th><th>Балл</th><th>p95</th><th>Скорость</th></tr>' +
    rows +
    "</table></div>" +
    `<div class="actions dashboard-pages"><button type="button" class="secondary" ${data.cursor ? "" : "disabled"} onclick="changeDashboardPage(${Math.max(0, (data.cursor || 0) - DASHBOARD_PAGE_SIZE)})">← Предыдущие</button><span>${(data.cursor || 0) + 1}–${(data.cursor || 0) + (data.candidates || []).length} из ${data.candidate_count ?? data.candidates.length}</span><button type="button" class="secondary" ${data.next_cursor === null || data.next_cursor === undefined ? "disabled" : ""} onclick="changeDashboardPage(${data.next_cursor ?? 0})">Следующие →</button></div>`;
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

function qualificationLabel(value) {
  const labels = {preliminary: "Предварительно доступно", viable: "Прошло сравнение", screened: "Прошло скрининг",
    confirmed: "Подтверждено", confirmed_in_observed_windows: "Подтверждено в окнах", unstable: "Нестабильно",
    unconfirmed: "Не подтверждено", failed: "Отказ", legacy_measured: "Прежние измерения"};
  return labels[value] || value || "Не подтверждено";
}

// ---------- История запусков: бейдж и панель активного запуска ----------

let lastHistoryRefresh = 0;

async function openRunDashboard(runId = null) {
  setTab("run");
  selectedDashboardRunId = typeof runId === "string" ? runId : null;
  dashboardCursor = 0;
  try { renderDashboard(await call(dashboardUrl())); }
  catch (error) { notify("runResult", "Ошибка результатов: " + error.message); }
  $("runDashboard").scrollIntoView({ behavior: "smooth", block: "start" });
}

async function recoverRun(runId) {
  await withBusy(["recover-run", "start-run"], async () => {
    try {
      selectedDashboardRunId = runId;
      dashboardCursor = 0;
      renderRun(await call(`/api/runs/${encodeURIComponent(runId)}/recover`, "POST", {}));
      notify("runResult", "Проверяется принадлежность ресурса, затем удаляется копия или восстанавливается снимок.", "ok");
      setTab("run");
      await refreshRuns();
    } catch (error) { notify("runResult", "Ошибка восстановления: " + error.message); }
  });
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
        const recent = recentRunSummaries.get(run.id) || {};
        const reason = run.termination_reason || run.summary?.termination_reason || recent.termination_reason;
        const budgetText = formatBudget(run.budget || run.summary?.budget || recent.budget);
        const reasonText = reason ? `<small class="candidate-context">${esc(terminationReasonLabel(reason))}</small>` : "";
        const budgetDetails = budgetText ? `<small class="candidate-context" style="white-space:pre-line">${esc(budgetText)}</small>` : "";
        const statusCell = (isActive
          ? `<span class="badge badge-active">${
              esc(L.historyStatuses[run.status] || run.status) || esc(run.status)
            }</span>`
          : esc(L.historyStatuses[run.status] || run.status)) + reasonText + budgetDetails;
        const dashboardCell = `<button type="button" class="secondary open-dashboard" data-run-id="${esc(
              run.id,
            )}">${esc(L.openDashboard)}</button>`
          ;
        const recoveryCell = run.cleanup_pending ? `<button type="button" class="danger recover-run" data-action="recover-run" data-run-id="${esc(run.id)}">Восстановить / удалить копию</button>` : "";
        // Сохранённый прогон, исчерпавший бюджет, продолжается и после
        // перезагрузки страницы: чекпойнт лежит в каталоге запуска.
        const continuationCell = (!isActive && !run.cleanup_pending && reason === "budget_exhausted")
          ? `<button type="button" class="secondary continue-run" data-action="continue-run" data-run-id="${esc(run.id)}">${esc(L.historyContinue)}</button>`
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
          recoveryCell +
          continuationCell +
          "</td></tr>"
        );
      })
      .join("");
    node.innerHTML =
      "<table><tr><th>Запуск</th><th>Статус</th><th>Повторы</th><th>Скачать</th></tr>" +
      rows +
      "</table>";
    node
      .querySelectorAll(".open-dashboard")
      .forEach((button) => button.addEventListener("click", () => openRunDashboard(button.dataset.runId)));
    node.querySelectorAll(".recover-run").forEach((button) =>
      button.addEventListener("click", () => recoverRun(button.dataset.runId)));
    node.querySelectorAll(".continue-run").forEach((button) =>
      button.addEventListener("click", () => continueRun(button.dataset.runId, false)));
    // История рисует свои кнопки заново: пока активен прогон, продолжение
    // недоступно, и это состояние надо применить сразу, а не после опроса.
    syncActionAvailability();
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
  $("topology").value = i.topology || "direct";
  let clonePorts = Array.isArray(t.ports) && t.ports.length
    ? t.ports.join(", ")
    : Array.isArray(t.port_range) && t.port_range.length
      ? t.port_range.join("-")
      : "";
  $("clonePorts").value = clonePorts || String(i.test_port || "9443");
  $("serverAddress").value = t.server_address || "";
  $("tlsSni").value = t.tls_server_name || "";
  $("verifyPeerName").value = t.verify_peer_cert_by_name || "";
  $("xrayBinary").value = t.xray_binary || "xray";
  $("validateConfig").value = String(t.validate_config ?? true);
  $("verifyTls").value = String(p.verify_tls ?? true);
  $("trustEnv").value = String(p.trust_env ?? false);
  $("outputDir").value = o.directory || "./results";
  $("urls").value = (t.urls || []).join("\n");
  $("combinationStrategy").value = t.combination_strategy || "adaptive";
  const adaptive = t.adaptive || {};
  $("searchGoal").value = adaptive.goal || "first_confirmed";
  $("timeBudget").value = (adaptive.time_budget_seconds ?? 600) / 60;
  $("requestBudget").value = adaptive.request_budget ?? 600;
  $("trafficBudget").value = (adaptive.traffic_budget_bytes ?? 30000000) / 1000000;
  $("applyBudget").value = adaptive.apply_budget ?? 250;
  $("explorationFraction").value = (adaptive.exploration_fraction ?? .25) * 100;
  $("confirmationWindows").value = adaptive.confirmation_windows ?? 3;
  $("confirmationRequests").value = adaptive.confirmation_requests ?? 5;
  $("confirmationDelay").value = adaptive.window_delay_seconds ?? 2;
  $("searchSeed").value = adaptive.seed ?? 0;
  showStrategySettings();
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

Object.entries({preview: previewPlan, save, "save-connection": saveConnection,
  "start-run": startRun, "stop-run": stopRun,
  "poll-run": () => { pollRun.manual = true; pollRun(); },
}).forEach(([action, callback]) => {
  document.querySelectorAll(`[data-action="${action}"]`).forEach((button) => button.addEventListener("click", callback));
});

setTab("connection");
