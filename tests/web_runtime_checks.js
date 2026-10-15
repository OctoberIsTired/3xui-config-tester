// Run with Node.js. The UI globals use a synthetic DOM and no network.
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const root = path.resolve(__dirname, "..");
const controls = new Map();
const timers = [];
const document = {
  getElementById(id) {
    if (!controls.has(id)) controls.set(id, {value: "", textContent: "", className: "", classList: {add() {}, remove() {}}});
    return controls.get(id);
  },
  querySelectorAll() { return []; },
};
const sandbox = {document, console, setTimeout: (fn, delay) => {timers.push(delay); return 1;}, clearTimeout() {}, assert, timers};
vm.createContext(sandbox);
const sources = ["api.js", "draft.js", "render.js"].map((name) => fs.readFileSync(path.join(root, "app", "static", name), "utf8"));
// Boot is browser-only; exercise the shared functions without auto-fetching.
sources[2] = sources[2].split('Promise.all([call("/api/config"), call("/api/registry")])')[0];
vm.runInContext(sources.join("\n"), sandbox);
const result = vm.runInContext(`(async () => {
  for (const invalid of ["9443.5", "1e3", "true", "0", "65536", "9443-9000"]) {
    assert.throws(() => parseClonePorts(invalid));
  }
  assert.equal(parseClonePorts("9443").ports.join(","), "9443");
  config = {panel:{}, inbound:{}, testing:{adaptive:{comparison_requests:7, negative_resample_fraction:.2}}, parameters:{}};
  const inputs = {panelUrl:"https://panel.example.test", sourceId:"1", testPort:"9443", clonePorts:"9443",
    topology:"direct", serverAddress:"vpn.example.test", xrayBinary:"xray", outputDir:"./results",
    combinationStrategy:"adaptive", searchGoal:"compare", timeBudget:"2", requestBudget:"60", trafficBudget:"3",
    applyBudget:"12", explorationFraction:"25", confirmationWindows:"3", confirmationRequests:"5",
    confirmationDelay:"2", searchSeed:"9", maxCombinations:"10", urls:"https://example.com",
    verifyTls:"true", trustEnv:"false", minSuccessRate:"100", requestTimeout:"5", tcpConnectTimeout:"3",
    screeningTimeout:"8", mutationGenerations:"2", beamWidth:"8", childrenPerParent:"8", runsPerCombination:"5",
    maxFailedRuns:"1", screeningRequests:"1", latencyRequests:"3", stabilityRequests:"5", pingRequests:"4",
    speedMegabytes:"5", requireTcpConnect:"true", speedEnabled:"false"};
  Object.entries(inputs).forEach(([id,value]) => { $(id).value=value; });
  const draft = buildDraft();
  assert.equal(draft.inbound.topology,"direct");
  assert.equal(draft.inbound.test_port,9443);
  assert.equal(draft.testing.ports.join(","),"9443");
  assert.equal(draft.testing.adaptive.time_budget_seconds,120);
  assert.equal(draft.testing.adaptive.traffic_budget_bytes,3000000);
  assert.equal(draft.testing.adaptive.comparison_requests,7);
  assert.equal(draft.testing.adaptive.negative_resample_fraction,.2);
  assert.equal(draft.testing.adaptive.goal,"compare");
  presets={network:{values:["xhttp","ws"],current:"xhttp"},security:{values:["tls"],current:"tls"}};
  selected=new Set(["network","security"]); draftValues={network:["xhttp"],security:["tls"]}; mutationFlags={};
  assert.equal(conditionPossible({network:{equals:"ws"}}),false);
  assert.equal(conditionPossible({all:[{network:{equals:"xhttp"}},{security:{equals:"tls"}}]}),true);
  draftValues.network=["xhttp","ws"];
  assert.equal(conditionPossible({network:{equals:"ws"}}),true);
  const visionCondition={all:[{parameter:"network",equals:"tcp"},{parameter:"security",in:["tls","reality"]}]};
  assert.equal(formatCondition(visionCondition),"транспорт TCP и защита TLS или REALITY");
  assert.equal(inactiveReason({conditions:visionCondition}),"Требуется: транспорт TCP и защита TLS или REALITY");
  assert.equal(formatCondition({any:[{network:{equals:"tcp"}},{network:{equals:"xhttp"}}]}),"транспорт TCP или транспорт XHTTP");
  assert.equal(formatCondition({not:{security:{equals:"none"}}}),"не (без защиты)");
  assert.equal(formatCondition({network:{unrecognized:"tcp"}}),null);
  assert.equal(formatCondition({unknown:{equals:"tcp"}}),null);
  assert.equal(inactiveReason({conditions:{all:[{network:{equals:"tcp"}},{unknown:{equals:"tcp"}}]}}),"Не выполнены условия выбранного профиля");
  assert.equal(qualificationLabel("confirmed_in_observed_windows"),"Подтверждено в окнах");
  assert.equal(metricValue(null," Мбит/с"),"—");
  assert.equal(metricValue(null,"",0),"—");
  assert.equal(metricValue(0,"",0),"0");
  assert.equal(terminationReasonLabel("frontier_exhausted"),"Проверен выбранный набор кандидатов");
  assert.equal(terminationReasonLabel("profile_space_exhausted"),"Проверен сформированный набор кандидатов");
  assert.equal(terminationReasonLabel("first_confirmed"),"Найдена подтверждённая конфигурация");
  const budgetText=formatBudget({requests:4,traffic_bytes:4096,client_starts:2,elapsed_seconds:12.4,
    limits:{requests:60,traffic_bytes:30000000,elapsed_seconds:120}});
  assert.equal(budgetText.includes("HTTP-запросы: 4 / 60"),true);
  const compactBudget=budgetText.replace(/[\\s\\u00a0\\u202f]/g,"");
  assert.equal(compactBudget.includes("Трафик:4096/30000000байт"),true);
  assert.equal(budgetText.includes("Запусков Xray: 2"),true);
  assert.equal(budgetText.includes("Время: 12,4 / 120 с"),true);
  assert.equal(budgetText.includes("Кандидаты"),false);
  assert.equal(budgetText.includes("Применений"),false);
  assert.equal(formatBudget({requests:null,api_applies:undefined}),"");
  assert.equal(continuationActions("20261015-120000-abc123ef","frontier_exhausted"),"");
  assert.equal(continuationActions("","budget_exhausted"),"");
  runActive=false;
  const continuation=continuationActions("20261015-120000-abc123ef","budget_exhausted");
  assert.equal(continuation.includes("continueRun('20261015-120000-abc123ef', false)"),true);
  assert.equal(continuation.includes("continueRun('20261015-120000-abc123ef', true)"),true);
  assert.equal(continuation.split('data-action="continue-run"').length-1,2);
  runActive=true;
  assert.equal(continuationActions("20261015-120000-abc123ef","budget_exhausted"),"");
  runActive=false;
  $("maxCombinations").value="10"; $("requestBudget").value="60"; $("applyBudget").value="12";
  $("trafficBudget").value="3"; $("timeBudget").value="2";
  doubleBudgetInputs();
  assert.equal($("maxCombinations").value,"20");
  assert.equal($("requestBudget").value,"120");
  assert.equal($("applyBudget").value,"24");
  assert.equal($("trafficBudget").value,"6");
  assert.equal($("timeBudget").value,"4");
  $("requestBudget").value=""; doubleBudgetInputs();
  assert.equal($("requestBudget").value,"");
  call=async () => {throw Error("synthetic offline");}; notify=()=>{}; runActive=true; pollRun.manual=true;
  await pollRun();
  assert.equal(pollFailures,1); assert.equal(timers.at(-1),3000); assert.equal(pollingRun,false);
  call=async (url) => url.includes("dashboard") ? {records:0} : {status:"idle"};
  renderRun=(status)=>{runActive=status.status==="running";}; renderDashboard=()=>{};
  await pollRun();
  assert.equal(pollFailures,0); assert.equal(pollingRun,false); assert.equal(runTimer,null);
})()`, sandbox);
Promise.resolve(result).then(() => console.log("UI runtime checks passed"), error => {console.error(error);process.exitCode=1;});
