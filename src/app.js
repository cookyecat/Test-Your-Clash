import { targets, escape as e, summarize, classify, leaves, nextDue, csv, filterNodeNames, batchSelect, probeStats, normalizeSamples } from "./model.js";
import { dnsTopology } from "./dns-view.js";
import { history, save } from "./store.js";
let lang = localStorage.getItem("net-lang") || (navigator.language.startsWith("zh") ? "zh" : "en");
const t = (zh, en) => lang === "zh" ? zh : en, $ = (id) => document.getElementById(id);
let releaseLock = null;
let resultTimer = null, persistTimer = null;
const pendingSaves = /* @__PURE__ */ new Map();
let routeIndex = 0, historySearch = "", historyKind = "all";
let helperPolling = false, syncedAt = null, pollError = "";
const draft = { mode: "https", target: "cloudflare", duration: 1800, interval: 15, timeout: 5e3, workers: 4 };
const fingerprint = (p, c) => JSON.stringify({ mode: c.mode, tun: c.tun, port: c["mixed-port"], nodes: Object.entries(p).map(([n, v]) => [n, v.type, v.now, v.all]).sort() });
let page = "monitor", tab = "continuous", conn = null, proxies = {}, config = {}, connections = [], snapshot = null, selected = /* @__PURE__ */ new Set(), scope = "", search = "", sort = "name", filter = "all", run = null, records = [], error = "", detailName = "", timer = null, inflight = /* @__PURE__ */ new Map(), busy = false, helperHistory = [];
const stateText = (s) => ({ ok: t("响应", "Responding"), fail: t("探测失败", "Probe failed"), error: t("采集错误", "Collection error"), skipped: t("缺测", "Gap"), running: t("监测中", "Running"), paused: t("已暂停", "Paused"), done: t("已完成", "Completed"), cancelled: t("已停止", "Stopped"), interrupted: t("已中断", "Interrupted") })[s] || t("待测", "Pending");
const ms = (n) => Number.isFinite(n) ? Math.round(n) + " ms" : "—", time = (n) => n ? new Date(n).toLocaleString(lang === "zh" ? "zh-CN" : "en-GB") : "—";
function toast(s) {
  $("toast").textContent = s;
  $("toast").style.display = "block";
  setTimeout(() => $("toast").style.display = "none", 5e3);
}
const active = () => run && ["running", "paused"].includes(run.state);
function samples(name) {
  return run?.rows.find((r) => r.name === name)?.samples || [];
}
function stats(name) {
  return probeStats(run?.rows.find((r) => r.name === name));
}
function probeMode() { return run?.options.mode || draft.mode; }
function lossLabel() { return probeMode() === "icmp" ? t("ICMP 丢包率", "ICMP loss") : t("HTTPS 失败率", "HTTPS failure"); }
const pct = n => Number.isFinite(n) ? n.toFixed(1) + "%" : "—";

function trend(ss) {
  const a = ss.slice(-24);
  return `<div class="trend" aria-label="${t("近期探测时间条", "Recent probe history")}">${(a.length ? a : Array(24).fill({ state: "pending" })).map((s) => `<span class="tick ${e(s.state)}" title="${e(time(s.at) + " · " + stateText(s.state) + " " + ms(s.ms))}"></span>`).join("")}</div>`;
}
function options(items, value) {
  return items.map(([v, label]) => `<option value="${e(v)}" ${String(v) === String(value) ? "selected" : ""}>${e(label)}</option>`).join("");
}
function render() {
  const tableScroll = document.querySelector(".table-wrap:has(.nodes)")?.scrollTop || 0;
  document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
  $("app").innerHTML = `<div class="shell"><aside><div class="brand">◈ ${t("网络状态台", "Observatory")}<b>NETWORK OBSERVATORY</b></div><button class="nav ${page === "topology" ? "active" : ""}" data-page="topology">⌘ ${t("网络拓扑", "Network map")}</button><button class="nav ${page === "monitor" ? "active" : ""}" data-page="monitor">▥ ${t("节点稳定性", "Node stability")}</button><div class="aside-note">${t("数据留在你的设备上", "Your data stays on your device")}<br>LOCAL FIRST · V5.1.0</div></aside><main><header><span>${t("本机网络 / 工作台", "LOCAL NETWORK / WORKSPACE")}</span><div><span class="badge">${conn ? e(conn.kind === "helper" ? t("本机助手", "Local helper") : t("控制器直连", "Direct controller")) : t("尚未连接", "Not connected")}</span><button id="language">${lang === "zh" ? "EN" : "中文"}</button><button id="connectButton">${conn ? t("连接管理", "Connection") : t("连接本机", "Connect")}</button></div></header><div class="page"><div class="heading"><div><div class="eyebrow">${page === "monitor" ? "OBSERVE • COMPARE • UNDERSTAND" : "FOLLOW THE CONNECTION"}</div><h1>${page === "monitor" ? t("让稳定性，看得见。", "Stability, in plain sight.") : t("每一条连接，都有来路。", "Every connection has a path.")}</h1><p>${page === "monitor" ? t("观察真实代理请求，找到失败发生的时刻。", "Observe real proxy requests. See exactly when they fail.") : t("连接记录与配置路径，分开呈现。", "Observed connections and configured routes, clearly distinguished.")}</p></div>${conn ? `<button id="refresh">↻ ${t("刷新", "Refresh")}</button>` : ""}</div>${error ? `<div class="notice" role="alert">${e(error)}</div>` : ""}${page === "monitor" ? monitor() : topology()}<footer><span>NETWORK OBSERVATORY · 5.1.0</span><span>${t("本地数据 · 无遥测", "Local data · No telemetry")}</span></footer></div></main></div>`;
  wire();
  const table = document.querySelector(".table-wrap:has(.nodes)");
  if (table) table.scrollTop = tableScroll;
}
function monitor() {
  return `<div class="tabs">${[["continuous", t("持续监测", "Monitor")], ["quick", t("快速测试", "Quick test")], ["history", t("历史记录", "History")]].map(([id, label]) => `<button data-tab="${id}" class="${tab === id ? "active" : ""}">${label}</button>`).join("")}</div>${tab === "history" ? historyView() : !conn && !run ? `<section class="panel"><div class="empty"><div class="symbol">▥</div><h2>${t("先连接，再开始观察", "Connect to start observing")}</h2><p>${t("直接连接 Clash / Mihomo，即可测量节点的 HTTPS 稳定性。Mac 助手可让监测在关闭网页后继续。", "Connect to Clash / Mihomo to monitor HTTPS stability. The optional Mac helper keeps monitoring after you close this page.")}</p><button class="primary" data-connect>${t("连接控制器", "Connect controller")}</button><p>${t("无需上传订阅、节点配置或密钥。", "No subscriptions, node configurations or secrets are uploaded.")}</p></div></section>` : workspace()}`;
}
function selectableNames() {
  return run ? run.rows.map((r) => r.name) : leaves(proxies, scope);
}
function filteredNames() {
  return filterNodeNames(selectableNames(), search, filter, stats);
}
function changeSelection(names, mode = "add") {
  if (active()) return;
  try {
    selected = batchSelect(selected, names, mode);
    render();
  } catch {
    toast(t("每次最多 500 个节点；请缩小范围，或先清空选择后选取前 500 个。", "Maximum 500 nodes per session. Narrow the filter, or clear selection and choose the first 500."));
  }
}
function workspace() {
  const names = selectableNames(), shown = filteredNames().sort((a, b) => sort === "failure" ? (stats(b).loss ?? -1) - (stats(a).loss ?? -1) || a.localeCompare(b) : a.localeCompare(b));
  const all = names.map(stats), tested = all.reduce((n, s) => n + s.tested, 0);
  const visibleSelected = shown.filter((n) => selected.has(n)).length;
  return `${run ? `<div class="metrics">${[[stateText(run.state), t("任务状态", "Session status"), run.executor === "helper" ? t("助手执行 · 关闭网页后继续", "Helper · continues after closing") : t("浏览器执行 · 离开前台暂停", "Browser · pauses in background")], [Math.floor(((run.finished || Date.now()) - run.started) / 6e4) + " min", t("观察时间", "Elapsed"), time(run.started)], [tested, t("有效样本", "Valid samples"), t("仅成功和探测失败", "Success + probe failure only")], [pct(tested ? all.reduce((n, s) => n + s.fail, 0) / tested * 100 : null), lossLabel(), t("不包含采集错误", "Excludes collection errors")]].map(([v, l, d]) => `<div class="metric"><small>${l}</small><strong>${e(v)}</strong><p>${e(d)}</p></div>`).join("")}</div>` : ""}<section class="panel monitor-panel"><div class="live-status" role="status">${pollError ? e(t("更新失败，保留上次数据：", "Update failed; showing previous data: ") + pollError) : run ? `${active() ? "● " : ""}${stateText(run.state)} · ${t("数据更新", "Updated")} ${syncedAt ? time(syncedAt) : "—"} · ${t("页面每秒检查新结果；采样频率见设置", "Checks for results every second; sampling interval is shown below")}` : t("选择节点 → 选择测试方式 → 开始。结果会自动刷新。", "Select nodes → choose probe type → start. Results update automatically.")}</div><div class="toolbar">${!active() ? `<label class="field">${t("节点范围", "Scope")}<select id="scope" aria-label="${t("节点范围", "Scope")}">${options([["", t("全部节点", "All nodes")], ...Object.entries(proxies).filter(([, p]) => p.all).map(([n]) => [n, n])], scope)}</select></label><label class="field">${t("测试方式", "Probe type")}<select id="mode">${options([["https",t("代理 HTTPS", "Proxy HTTPS")], ...(conn?.kind === "helper" && tab !== "quick" ? [["icmp",t("入口 ICMP / Ping", "Ingress ICMP / Ping")]] : [])], draft.mode)}</select></label><label class="field">${t("HTTPS 目标", "HTTPS target")}<select id="target" ${draft.mode === "icmp" ? "disabled" : ""}>${options(Object.keys(targets).map((n) => [n, n]), draft.target)}</select></label><label class="field">${t("观察时长", "Duration")}<select id="duration">${options([[1800, t("30 分钟", "30 minutes")], [7200, t("2 小时", "2 hours")], [28800, t("8 小时", "8 hours")], [0, t("直到停止", "Until stopped")]], draft.duration)}</select></label>` : `<div><b>${e(run.options.mode === "icmp" ? "ICMP / Ping" : run.options.target)} · ${e(run.options.interval)} s</b><p>${t("运行参数已固定", "Session settings are fixed")} · ${run.rows.length} ${t("节点", "nodes")}</p></div>`}<div class="actions">${active() ? `<button id="pause" ${run.executor === "helper" ? "hidden" : ""}>${run.state === "paused" ? t("继续", "Resume") : t("暂停", "Pause")}</button><button id="stop">■ ${t("停止", "Stop")}</button>` : `${run ? `<button id="new">${t("新建监测", "New session")}</button><button id="retry">${t("复测异常", "Retry failures")}</button>` : ""}<button class="primary" id="start" ${!conn || !selected.size || selected.size > 500 ? "disabled" : ""}>▶ ${tab === "quick" ? t("开始 3 轮测试", "Start 3 rounds") : t("开始监测", "Start monitoring")} · ${selected.size} ${t("个节点", "nodes")}</button>`}<button id="export" ${!run ? "disabled" : ""}>${t("导出", "Export")}</button></div></div>${!active() ? `<details open><summary>${t("采样设置", "Sampling settings")}</summary><div class="advanced"><label class="field">${t("每节点间隔", "Interval per node")}<select id="interval">${options((draft.mode === "icmp" ? [1,2,5,10,15,30,60,300] : [15,30,60,300]).map((n) => [n, n + " s"]), draft.interval)}</select></label><label class="field">${t("超时", "Timeout")}<select id="timeout">${options((draft.mode === "icmp" ? [1000,2000,3000,5000,8000] : [3000,5000,8000]).map((n) => [n, n / 1e3 + " s"]), draft.timeout)}</select></label><label class="field">${t("并发", "Concurrency")}<select id="workers">${options((draft.mode === "icmp" ? [2,4,8,16,32,64,128] : [2,4,8]).map((n) => [n, n]), draft.workers)}</select></label></div><p>${t("ICMP 从物理网卡探测节点入口，不经过代理；禁 Ping 不等于代理不可用。HTTPS 测代理请求失败率。采集错误和缺测不计入丢包。", "ICMP probes the node ingress over the physical interface, not through the proxy. Blocked ping does not mean a broken proxy. HTTPS measures request failures. Errors and gaps are excluded.")}</p></details>` : ""}<div class="list-tools"><input id="search" placeholder="${t("搜索节点…", "Search nodes…")}" value="${e(search)}" aria-label="${t("搜索节点", "Search nodes")}"><select id="resultFilter" aria-label="${t("结果筛选", "Result filter")}">${options([["all", t("全部结果", "All results")], ["issues", t("仅异常", "Issues only")]], filter)}</select><select id="sort" aria-label="${t("排序", "Sort")}">${options([["name", t("按名称", "By name")], ["failure", t("失败优先", "Failures first")]], sort)}</select></div><p class="probe-consent">${t("点击开始即确认按所选方式发送探测请求，可随时停止。", "Click Start to confirm requests using the selected probe type. You can stop at any time.")}</p><div class="bulk-selection ${active() ? "running-selection" : ""}"><div><strong>${t("已选", "Selected")} ${selected.size} / 500</strong><span>${t("当前筛选", "Matching")} ${shown.length} · ${t("筛选外已选", "Selected outside filter")} ${selected.size - visibleSelected}</span></div><div class="bulk-buttons"><button class="primary" id="selectAll" ${active() ? "disabled" : ""}>${t("全选筛选结果", "Select all matches")} (${shown.length})</button>${shown.length > 500 ? `<button id="selectFirst" ${active() ? "disabled" : ""}>${t("选取前 500 个", "Select first 500")}</button>` : ""}<button id="selectScope" ${active() ? "disabled" : ""}>${t("全选当前范围", "Select entire scope")} (${names.length})</button><button id="invert" ${active() ? "disabled" : ""}>${t("反选筛选结果", "Invert matches")}</button><button id="clear" ${active() ? "disabled" : ""}>${t("清空全部", "Clear all")}</button></div><p>${active() ? t("运行中不能更改节点；停止后可重新选择。", "Selection is locked while running. Stop to change nodes.") : t("先选策略组或搜索，再点全选。切换策略组会保留已选节点，可累加多个组；不受滚动位置限制。", "Choose a group or search, then select all. Selections accumulate across groups and include off-screen rows.")}</p>${selected.size > 20 ? `<p>${t("大批量探测使用有界并发；超时较多时实际采样间隔会延长，缺测不计为失败。", "Large batches use bounded concurrency. Timeouts can lengthen actual sampling intervals; gaps are not failures.")}</p>` : ""}</div><div class="table-wrap"><table class="nodes"><thead><tr><th><input id="selectMatches" type="checkbox" aria-label="${t("全选或取消当前筛选", "Select or deselect matching nodes")}" ${shown.length && visibleSelected === shown.length ? "checked" : ""} ${active() || !shown.length ? "disabled" : ""}></th><th>${t("节点", "Node")}</th><th>${lossLabel()}</th><th>${t("近 20 次失败率", "Last 20 failure %")}</th><th>${t("有效 / 成功 / 失败", "Valid / OK / Failed")}</th><th>${t("最新 / 平均延迟", "Last / Mean")}</th><th>${t("连续失败", "Failure streak")}</th><th>${t("近期采样", "Recent samples")}</th><th>${t("状态 / 最后采样", "Status / Last sample")}</th></tr></thead><tbody>${shown.map((n) => {
    const s = stats(n), ss = samples(n);
    return `<tr><td><input type="checkbox" data-select="${e(n)}" ${selected.has(n) ? "checked" : ""} aria-label="${e(n)}" ${active() ? "disabled" : ""}></td><td><button class="node-name" data-detail="${e(n)}">${e(n)}</button><div class="node-type">${e(proxies[n]?.type || "HTTPS")}</div></td><td><b class="${s.fail ? "bad" : "good"}">${pct(s.loss)}</b></td><td><b class="${s.recentLoss > 0 ? "bad" : "good"}">${pct(s.recentLoss)}</b><div class="node-type">${s.recentTested} ${t("有效样本", "valid samples")}</div></td><td>${s.tested} / ${s.ok} / <span class="${s.fail ? "bad" : ""}">${s.fail}</span><div class="node-type">${t("采集错误", "Errors")} ${s.error} · ${t("缺测", "Gaps")} ${s.skipped}</div></td><td>${ms(s.lastMs)} / ${ms(s.mean)}</td><td class="${s.streak ? "bad" : ""}">${s.streak}</td><td>${trend(ss)}</td><td class="status">${stateText(s.lastState)}<div class="node-type">${time(s.lastAt)}</div></td></tr>`;
  }).join("") || `<tr><td colspan="9" class="empty">${t("暂无节点，请连接控制器或更换筛选条件。", "No nodes. Connect a controller or change the filter.")}</td></tr>`}</tbody></table></div><div class="legend"><span><i style="background:#76b396"></i>${t("成功", "Success")}</span><span><i style="background:#cd6d69"></i>${t("探测失败", "Probe failure")}</span><span><i style="background:#d6ae63"></i>${t("采集错误", "Collection error")}</span><span><i style="background:#dce3de"></i>${t("缺测 / 未测", "Gap / pending")}</span><span>${t("近期率按最近 20 次记录计算，剔除错误和缺测；— 表示暂无有效样本", "Recent rate uses the last 20 observations, excluding errors and gaps; — means no valid samples")}</span></div></section>`;
}
function historyView() {
  return `<section class="panel"><div class="panel-head"><h2>${t("本机观察记录", "Local observations")}</h2><button id="import">${t("导入 JSON", "Import JSON")}</button></div><div class="list-tools"><input id="historySearch" value="${e(historySearch)}" placeholder="${t("节点 / 目标 / 日期", "Node / target / date")}"><select id="historyKind">${options([["all", t("全部任务", "All sessions")], ["quick", t("快速测试", "Quick tests")], ["continuous", t("持续监测", "Monitoring")]], historyKind)}</select></div>${records.filter((r) => (historyKind === "all" || historyKind === "quick" === !!r.quick) && [r.options.target, time(r.started), ...r.rows.map((row) => row.name)].some((v) => String(v).toLowerCase().includes(historySearch.toLowerCase()))).map((r) => `<div class="history-row"><div><b>${e(r.options.target)} · ${r.rows.length} ${t("节点", "nodes")}</b><small>${time(r.started)} · ${stateText(r.state)} · ${e(r.executor)}</small></div><button data-history="${e(r.id)}">${t("查看", "Open")}</button></div>`).join("")}${helperHistory.map((r) => `<div class="history-row"><div>${e(r.options.target)} · ${time(r.started_at)}<small>${t("助手记录", "Helper history")}</small></div><button data-helper-history="${e(r.id)}">${t("查看", "Open")}</button></div>`).join("")}${!records.length && !helperHistory.length ? `<div class="empty">${t("还没有记录。完成第一次观察后会保存在这里。", "Your observations will appear here after your first session.")}</div>` : ""}</section>`;
}
function topology() {
  if (!conn && !snapshot) return `${dnsTopology(snapshot, config, t)}<div class="panel empty"><h2>${t("连接你的网络", "Connect your network")}</h2><p>${t("读取真实连接链、策略组和运行配置。", "Read actual connection chains, groups and runtime configuration.")}</p><button class="primary" data-connect>${t("连接本机", "Connect")}</button></div>`;
  const groups = Object.entries(proxies).filter(([, p]) => p.all), c = connections[routeIndex] || connections[0], chain = c?.chains ? [...c.chains].reverse() : c?.chain || [];
  return `${dnsTopology(snapshot, config, t)}<section class="panel"><div class="panel-head"><h2>${t("业务流量路径", "Traffic path")}</h2><select id="routeConnection" aria-label="${t("选择连接", "Choose connection")}">${options(connections.map((c2, i) => [i, c2.metadata?.host || c2.host || c2.metadata?.destinationIP || c2.ip || String(i)]), routeIndex)}</select><span class="badge">${c ? t("实际连接 · 最近一条", "Observed · latest connection") : t("暂无活动连接", "No active connection")}</span></div><div class="route-board">${[[t("来源", "Source"), c?.metadata?.process || c?.process || t("本机", "This device")], [t("处理", "Processing"), "Clash · " + (config.mode || "—")], ...chain.map((n) => [t("连接链", "Chain"), n]), [t("目标", "Destination"), c?.metadata?.host || c?.metadata?.destinationIP || c?.host || c?.ip || "—"]].map(([l, v], i) => `${i ? '<span class="arrow">→</span>' : ""}<button class="route-node" data-route-detail="${e(l + ": " + v)}"><small>${l}</small><strong>${e(v)}</strong></button>`).join("")}</div><div class="legend">${t("连线来自控制器连接记录，不代表物理路由器逐跳探测。", "Edges come from controller connection records, not physical router traceroutes.")}</div></section><section class="panel"><div class="panel-head"><h2>${t("策略组", "Proxy groups")}</h2><span class="badge">${groups.length}</span></div><div class="panel-body"><dl class="kv">${groups.map(([n, p]) => `<dt>${e(n)}</dt><dd>${e(p.now || "—")}</dd>`).join("")}</dl></div></section><section class="panel"><div class="panel-head"><h2>${t("活动连接", "Active connections")}</h2><span class="badge">${connections.length}</span></div><div class="table-wrap"><table><thead><tr><th>${t("目标", "Destination")}</th><th>${t("命中规则", "Matched rule")}</th><th>${t("实际链路", "Observed chain")}</th><th>↑ / ↓</th></tr></thead><tbody>${connections.slice(0, 200).map((c2) => `<tr><td>${e(c2.metadata?.host || c2.metadata?.destinationIP || c2.host)}</td><td>${e(c2.rule || "—")}</td><td>${e((c2.chains ? [...c2.chains].reverse() : c2.chain || []).join(" → "))}</td><td>${Math.round((c2.upload || 0) / 1024)} / ${Math.round((c2.download || 0) / 1024)} KB</td></tr>`).join("")}</tbody></table></div></section>`;
}
async function request(path, { method = "GET", body, signal, timeout = 1e4 } = {}) {
  const c = conn;
  if (!c) throw Error(t("请先连接", "Connect first"));
  const r = await fetch(c.url + path, { method, headers: { ...c.kind === "helper" ? { "X-Netdash-Token": c.secret } : c.secret ? { Authorization: "Bearer " + c.secret } : {}, ...body ? { "Content-Type": "application/json" } : {} }, body: body ? JSON.stringify(body) : void 0, signal: signal || AbortSignal.timeout(timeout), cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer", targetAddressSpace: "loopback" });
  let data;
  try {
    data = await r.json();
  } catch {
    throw Error(t("接口返回无效 JSON", "Invalid JSON from controller"));
  }
  return { status: r.status, data };
}
async function api(path, opts) {
  const r = await request(path, opts);
  if (r.status >= 400) throw Error(r.data.error || r.data.message || "HTTP " + r.status);
  return r.data;
}
async function refresh() {
  if (!conn) return;
  try {
    if (conn.kind === "helper") {
      const [cat, snap] = await Promise.all([api("/api/nodes"), api("/api/snapshot")]);
      proxies = Object.fromEntries(cat.nodes.map((n) => [n.name, { type: n.type }]));
      for (const [n, g] of Object.entries(cat.groups)) proxies[n] = { all: g.members, now: g.selected, type: g.type };
      snapshot = snap;
      config = snap.clash;
      connections = snap.connections || [];
      await pollHelper();
    } else {
      const [p, c, k] = await Promise.all([api("/proxies"), api("/configs"), api("/connections")]);
      proxies = p.proxies;
      config = c;
      connections = k.connections || [];
    }
    error = "";
    render();
  } catch (err) {
    error = t("连接读取失败：", "Connection read failed: ") + err.message;
    render();
  }
}
function connectDialog() {
  if (active()) {
    toast(t("请先停止当前任务再管理连接", "Stop the current session before changing connections"));
    return;
  }
  $("connect").innerHTML = `<button class="close" data-close>✕</button><div class="eyebrow">LOCAL CONNECTION</div><h2>${t("连接你自己的设备", "Connect your device")}</h2><p>${t("地址与密钥只用于当前浏览器会话。", "Address and secret are used only in this browser session.")}</p><form id="connectForm"><label class="field">${t("控制器地址", "Controller URL")}<input id="url" value="${e(conn?.kind === "direct" ? conn.url : "http://127.0.0.1:9090")}" required></label><label class="field">Secret<input id="secret" type="password" autocomplete="off"></label><button class="primary">${t("连接并验证", "Connect & verify")}</button></form><p id="connectionError" role="alert"></p><details><summary>${t("连接失败？配置与权限说明", "Connection help & permissions")}</summary><p>${t("允许本站来源，然后在浏览器提示时授予本地网络访问。浏览器无法确定 CORS、权限拒绝与网络不可达的具体原因。也可把下载的 HTML 放入控制器 external-ui 使用。", "Allow this exact origin and grant local-network access when prompted. Browsers may not distinguish CORS, permission denial and network failure. Alternatively serve the HTML through the controller external-ui.")}</p><pre>${e('external-controller: 127.0.0.1:9090\nexternal-controller-cors:\n  allow-origins:\n    - "' + location.origin + '"\n  allow-private-network: true')}</pre></details><hr><h3>${t("可选 Mac 助手", "Optional Mac helper")}</h3><p>${t("补充系统 DNS，支持关闭网页后持续监测。需要 Python 3.9+。", "Adds system DNS and monitoring after closing the page. Requires Python 3.9+.")}</p><a href="https://github.com/cookyecat/Test-Your-Clash/releases/latest" target="_blank" rel="noreferrer">${t("下载助手", "Download helper")}</a> <button id="pair">${t("启动并授权", "Launch & authorize")}</button>${conn ? `<button id="disconnect">${t("断开连接", "Disconnect")}</button>` : ""}`;
  $("connect").showModal();
  $("connect").querySelector("[data-close]").onclick = () => $("connect").close();
  $("connectForm").onsubmit = async (ev) => {
    ev.preventDefault();
    try {
      const u = new URL($("url").value);
      if (!["http:", "https:"].includes(u.protocol) || u.username || u.password || u.search || u.hash) throw Error("Invalid controller URL");
      Object.assign(draft, {mode:"https",interval:15,timeout:5000,workers:4});
      conn = { kind: "direct", url: u.href.replace(/\/$/, ""), secret: $("secret").value };
      await api("/version");
      const p = await api("/proxies");
      if (!p.proxies) throw Error("Missing proxies");
      sessionStorage.setItem("net-connection", JSON.stringify(conn));
      run = null;
      await refresh();
      $("connect").close();
    } catch (err) {
      conn = null;
      $("connectionError").textContent = err.message + " · " + t("检查地址、Secret、CORS 和本地网络权限。", "Check URL, secret, CORS and local-network permissions.");
    }
  };
  $("pair").onclick = pair;
  if ($("disconnect")) $("disconnect").onclick = () => {
    conn = null;
    proxies = {};
    connections = [];
    snapshot = null;
    run = null;
    sessionStorage.removeItem("net-connection");
    $("connect").close();
    render();
  };
}
async function pair() {
  const challenge = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  location.href = "netstatus://connect?origin=" + encodeURIComponent(location.origin) + "&challenge=" + challenge;
  $("connectionError").textContent = t("请在 Mac 上核对来源并授权…", "Confirm the website origin on your Mac…");
  for (let i = 0; i < 40; i++) {
    await new Promise((r) => setTimeout(r, 1500));
    try {
      const r = await fetch("http://127.0.0.1:17890/api/pair", { headers: { "X-Netdash-Challenge": challenge }, signal: AbortSignal.timeout(2e3) }), d = await r.json();
      if (r.ok && d.token) {
        conn = { kind: "helper", url: "http://127.0.0.1:17890", secret: d.token };
        sessionStorage.setItem("net-connection", JSON.stringify(conn));
        await refresh();
        $("connect").close();
        return;
      }
    } catch {
    }
  }
  $("connectionError").textContent = t("连接超时，请检查助手和浏览器权限。", "Connection timed out. Check the helper and browser permissions.");
}
function persist(flush = false) {
  if (run) pendingSaves.set(run.id, run);
  if (persistTimer && !flush) return;
  clearTimeout(persistTimer);
  const commit = () => {
    persistTimer = null;
    const jobs = [...pendingSaves.values()];
    pendingSaves.clear();
    Promise.all(jobs.map(save)).then(() => history()).then((h) => records = h).catch(() => {
      error = t("无法保存历史，请导出当前结果。", "History storage unavailable. Export the current results.");
    });
  };
  if (flush) commit();
  else persistTimer = setTimeout(commit, 500);
}
async function start() {
  if (busy || active()) return;
  if (!conn) return toast(t("请先连接", "Connect first"));
  if (!selected.size || selected.size > 500) return toast(t("请选择 1–500 个节点", "Select 1–500 nodes"));
  busy = true;
  if (conn.kind === "direct" && navigator.locks) {
    const granted = await new Promise((resolve) => {
      navigator.locks.request("net-monitor:" + conn.url, { ifAvailable: true }, (lock) => {
        resolve(!!lock);
        if (lock) return new Promise((r) => releaseLock = r);
      });
    });
    if (!granted) {
      busy = false;
      return toast(t("其他标签页正在测试此控制器", "Another tab is testing this controller"));
    }
  }
  const opts = { mode: tab === "quick" || conn.kind !== "helper" ? "https" : draft.mode, target: $("target").value, interval: +$("interval").value, timeout: +$("timeout").value, workers: +$("workers").value, duration: tab === "quick" ? 0 : +$("duration").value, rounds: tab === "quick" ? 3 : 0 };
  try {
    if (conn.kind === "helper") {
      const body = { consent: true, nodes: [...selected], source: "nodes", mode: opts.mode, target: opts.target, timeout_ms: opts.timeout, concurrency: opts.workers, interval_seconds: opts.interval, duration_seconds: opts.duration, rounds: 3, group: "", purpose: "custom" };
      await api(tab === "quick" ? "/api/stability/start" : "/api/monitor/start", { method: "POST", body });
      await pollHelper(tab === "quick");
    } else {
      run = { id: crypto.randomUUID(), started: Date.now(), executor: "browser", quick: tab === "quick", fingerprint: fingerprint(proxies, config), state: "running", options: opts, rows: [...selected].map((name) => ({ name, due: Date.now(), samples: [], totals: { ok: 0, fail: 0, error: 0, skipped: 0, tested: 0 } })) };
      persist();
      schedule();
    }
    render();
  } catch (err) {
    releaseLock?.();
    releaseLock = null;
    toast(err.message);
  } finally {
    busy = false;
  }
}
function schedule() {
  clearTimeout(timer);
  if (!run || run.executor !== "browser" || run.state !== "running") return;
  const r = run, now = Date.now(), o = r.options;
  if (o.duration && now - r.started >= o.duration * 1e3) {
    stop("done");
    return;
  }
  if (o.rounds && r.rows.every((row) => row.samples.filter((s) => s.state !== "skipped").length >= o.rounds)) {
    stop("done");
    return;
  }
  const due = r.rows.filter((row) => !inflight.has(row.name) && row.due <= now && (!o.rounds || row.samples.filter((s) => s.state !== "skipped").length < o.rounds)).sort((a, b) => a.due - b.due);
  while (inflight.size < o.workers && due.length) {
    const row = due.shift(), control = new AbortController();
    inflight.set(row.name, control);
    if (now - row.due >= o.interval * 1e3) append(row, { state: "skipped", at: now, reason: "Missed interval" });
    measure(r, row, control);
  }
  timer = setTimeout(schedule, 200);
}
function append(row, s) {
  row.samples.push(s);
  if (row.totals) {
    row.totals[s.state]++;
    if (["ok", "fail"].includes(s.state)) row.totals.tested++;
  }
  const limit = Math.max(1, Math.floor(1e5 / (run?.rows.length || 1)));
  row.samples = row.samples.filter((s2) => s2.at > Date.now() - 864e5).slice(-limit);
}
async function measure(r, row, control) {
  let sample;
  try {
    const p = targets[r.options.target], q = new URLSearchParams({ url: p.url, expected: p.expected, timeout: r.options.timeout });
    const result = await request("/proxies/" + encodeURIComponent(row.name) + "/delay?" + q, { signal: AbortSignal.any([control.signal, AbortSignal.timeout(r.options.timeout + 3e3)]) });
    sample = classify(result.status, result.data);
  } catch (err) {
    sample = { state: control.signal.aborted ? "skipped" : "error", reason: err.message };
  } finally {
    if (run === r) {
      append(row, { ...sample, at: Date.now() });
      row.due = nextDue(row.due, Date.now(), r.options.interval * 1e3);
      persist();
      if (sample.state === "error" && r.state === "running") {
        error = t("控制接口异常，任务已中断；未计为节点失败。", "Controller error interrupted this session; not counted as a node failure.");
        stop("interrupted");
      }
      syncedAt = Date.now();
      updateResults();
    }
    if (inflight.get(row.name) === control) inflight.delete(row.name);
  }
}
function updateResults() {
  if (resultTimer) return;
  resultTimer = setTimeout(() => {
    resultTimer = null;
    const focus = document.activeElement;
    if ($("detail").open) return;
    const searching = focus?.id === "search", caret = searching ? focus.selectionStart : null;
    const y = scrollY;
    render();
    scrollTo(0, y);
    if (searching && $("search")) { $("search").focus({preventScroll:true}); $("search").setSelectionRange(caret, caret); }
  }, 500);
}
async function stop(state = "cancelled") {
  clearTimeout(timer);
  for (const c of inflight.values()) c.abort();
  if (run?.executor === "helper" && active()) {
    try {
      await api(run.quick ? "/api/stability/stop" : "/api/monitor/stop", { method: "POST", body: { id: run.id } });
    } catch (err) {
      toast(err.message);
      return;
    }
  }
  releaseLock?.();
  releaseLock = null;
  if (run) {
    run.state = state;
    run.finished = Date.now();
    persist(true);
  }
  render();
}
function pause() {
  if (run?.executor !== "browser" || !active()) return;
  if (run.state === "running") {
    run.state = "paused";
    clearTimeout(timer);
    for (const c of inflight.values()) c.abort();
  } else {
    run.state = "running";
    for (const row of run.rows) {
      append(row, { state: "skipped", at: Date.now(), reason: "Resumed after pause" });
      row.due = Date.now();
    }
    schedule();
  }
  persist();
  render();
}
async function pollHelper(quick = run?.quick || false, id) {
  if (conn?.kind !== "helper") return;
  const data = await api(quick ? "/api/stability" : "/api/monitor" + (id ? "?id=" + encodeURIComponent(id) : "") + (detailName ? (id ? "&" : "?") + "node=" + encodeURIComponent(detailName) : ""));
  const j = quick ? data.job : data.monitor;
  helperHistory = data.history || [];
  syncedAt = Date.now(); pollError = "";
  if (!j) return;
  const metric = j.options.mode === "icmp" ? "icmp" : "https";
  run = { id: j.id, executor: "helper", quick, state: j.state, started: Date.parse(j.started_at), finished: j.finished_at ? Date.parse(j.finished_at) : null, options: { mode: j.options.mode, target: j.options.target, interval: j.options.interval_seconds, timeout: j.options.timeout_ms }, rows: j.rows.map((row) => ({ name: row.name, summary: row[metric], samples: normalizeSamples(row.samples || row.recent || [], metric) })) };
  persist();
}
async function showDetail(name) {
  detailName = name;
  if (run?.executor === "helper") {
    try {
      await pollHelper(run.quick);
    } catch {
    }
  }
  const s = stats(name), ss = samples(name), lat = ss.filter((s2) => s2.state === "ok" && Number.isFinite(s2.ms)), max = Math.max(100, ...lat.map((s2) => s2.ms)), x = (i) => 20 + i * 500 / Math.max(1, ss.length - 1), y = (v) => 145 - 125 * v / max;
  let parts = [], part = [];
  ss.forEach((s2, i) => {
    if (s2.state === "ok" && Number.isFinite(s2.ms)) part.push(x(i) + "," + y(s2.ms));
    else {
      if (part.length) parts.push(part);
      part = [];
    }
  });
  if (part.length) parts.push(part);
  $("detail").innerHTML = `<button class="close" data-close>✕</button><div class="eyebrow">NODE DETAIL</div><h2>${e(name)}</h2><p>${t("可查询窗口内的成功延迟，失败和缺测处断开。", "Successful latency within the available window. Failures and gaps break the line.")}</p><div class="metrics"><div class="metric"><small>${t("探测成功率", "Probe success")}</small><strong>${s.rate === null ? "—" : s.rate.toFixed(1) + "%"}</strong><p>${s.ok}/${s.tested}</p></div><div class="metric"><small>P50 / P95</small><strong style="font-size:18px">${ms(s.p50)} / ${ms(s.p95)}</strong></div></div><svg class="chart" viewBox="0 0 540 170" role="img" aria-label="Latency chart"><path d="M20 20V145H520" fill="none" stroke="#dbe4db"/><text x="25" y="15">${Math.round(max)} ms</text>${parts.map((p) => `<polyline points="${p.join(" ")}" fill="none" stroke="#138365" stroke-width="2"/>`).join("")}${ss.map((s2, i) => s2.state === "ok" ? `<circle cx="${x(i)}" cy="${y(s2.ms)}" r="2" fill="#138365"/>` : `<text x="${x(i)}" y="155">${s2.state === "fail" ? "×" : "·"}</text>`).join("")}</svg>${trend(ss)}<p>${t("最近采样 · 原始记录保留窗口有限", "Recent samples · raw history retention is limited")}</p><div class="table-wrap"><table><tbody>${ss.slice(-30).reverse().map((s2) => `<tr><td>${time(s2.at)}</td><td>${stateText(s2.state)}</td><td>${ms(s2.ms)}</td><td>${e(s2.reason || "")}</td></tr>`).join("")}</tbody></table></div>`;
  $("detail").querySelector("[data-close]").onclick = () => $("detail").close();
  if (!$("detail").open) $("detail").showModal();
}
function download(name, data, type) {
  const a = document.createElement("a"), u = URL.createObjectURL(new Blob([data], { type }));
  a.href = u;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(u), 2e3);
}
function wire() {
  if ($("selectMatches")) {
    const names = filteredNames(), count = names.filter((n) => selected.has(n)).length;
    $("selectMatches").indeterminate = count > 0 && count < names.length;
    $("selectMatches").onchange = (ev) => changeSelection(names, ev.target.checked ? "add" : "remove");
  }
  document.querySelectorAll("[data-dns-detail]").forEach((b) => b.onclick = () => {
    const d = JSON.parse(b.dataset.dnsDetail);
    $("detail").innerHTML = `<button class="close" aria-label="${t("关闭", "Close")}">✕</button><div class="eyebrow">DNS EVIDENCE</div><h2>${e(d.title)}</h2><pre>${e(d.detail)}</pre><p>${t("配置证据，不代表某次请求的抓包结果。", "Configuration evidence, not a packet trace of an individual request.")}</p>`;
    $("detail").querySelector("button").onclick = () => $("detail").close();
    $("detail").showModal();
  });
  if ($("routeConnection")) $("routeConnection").onchange = (ev) => {
    routeIndex = +ev.target.value;
    render();
  };
  document.querySelectorAll("[data-route-detail]").forEach((b) => b.onclick = () => {
    $("detail").innerHTML = '<button class="close">✕</button><h2>' + e(b.dataset.routeDetail) + "</h2><p>" + t("来源：控制器活动连接记录", "Source: controller active connection record") + "</p>";
    $("detail").querySelector("button").onclick = () => $("detail").close();
    $("detail").showModal();
  });
  if ($("historySearch")) $("historySearch").oninput = (ev) => {
    historySearch = ev.target.value;
    const pos = ev.target.selectionStart;
    render();
    $("historySearch").focus();
    $("historySearch").setSelectionRange(pos, pos);
  };
  if ($("historyKind")) $("historyKind").onchange = (ev) => {
    historyKind = ev.target.value;
    render();
  };
  for (const id of ["target", "duration", "interval", "timeout", "workers"]) if ($(id)) $(id).onchange = (ev) => {
    draft[id] = id === "target" ? ev.target.value : +ev.target.value;
  };
  if ($("mode")) $("mode").onchange = ev => {
    draft.mode = ev.target.value;
    Object.assign(draft, draft.mode === "icmp" ? {interval:1,timeout:1000,workers:32} : {interval:15,timeout:5000,workers:4});
    render();
  };
  document.querySelectorAll("[data-page]").forEach((b) => b.onclick = () => {
    page = b.dataset.page;
    render();
  });
  document.querySelectorAll("[data-tab]").forEach((b) => b.onclick = () => {
    tab = b.dataset.tab;
    if (tab === "quick" && draft.mode === "icmp") Object.assign(draft, {mode:"https",interval:15,timeout:5000,workers:4});
    render();
  });
  document.querySelectorAll("[data-connect]").forEach((b) => b.onclick = connectDialog);
  $("connectButton").onclick = connectDialog;
  $("language").onclick = () => {
    lang = lang === "zh" ? "en" : "zh";
    localStorage.setItem("net-lang", lang);
    render();
  };
  if ($("refresh")) $("refresh").onclick = refresh;
  const actions = {
    start,
    stop: () => stop(),
    pause,
    new: () => {
      if (active()) return;
      run = null;
      selected.clear();
      render();
    },
    retry: () => {
      selected = new Set(run.rows.filter((r) => stats(r.name).fail > 0 || stats(r.name).error > 0).map((r) => r.name));
      run = null;
      render();
    },
    selectAll: () => changeSelection(filteredNames()),
    selectScope: () => changeSelection(selectableNames()),
    selectFirst: () => changeSelection(filteredNames().slice(0, 500)),
    invert: () => changeSelection(filteredNames(), "invert"),
    clear: () => {
      if (active()) return;
      selected.clear();
      render();
    },
    export: () => {
      if (!run) return;
      download("observation-" + run.id + ".json", JSON.stringify(run, null, 2), "application/json");
      download("summary-" + run.id + ".csv", csv([["node","mode","valid","ok","failed","failure_pct","recent_20_failure_pct","errors","gaps","current_failure_streak"], ...run.rows.map(r => {const s=stats(r.name);return [r.name,run.options.mode || "https",s.tested,s.ok,s.fail,s.loss,s.recentLoss,s.error,s.skipped,s.streak];})]), "text/csv");
      download("samples-" + run.id + ".csv", csv([["node", "timestamp", "state", "latency_ms", "reason"], ...run.rows.flatMap((r) => r.samples.map((s) => [r.name, new Date(s.at).toISOString(), s.state, s.ms, s.reason]))]), "text/csv");
    }
  };
  for (const [id, fn] of Object.entries(actions)) if ($(id)) $(id).onclick = fn;
  if ($("search")) $("search").oninput = (ev) => {
    search = ev.target.value;
    const pos = ev.target.selectionStart;
    render();
    $("search").focus();
    $("search").setSelectionRange(pos, pos);
  };
  if ($("sort")) $("sort").onchange = (ev) => {
    sort = ev.target.value;
    render();
  };
  if ($("resultFilter")) $("resultFilter").onchange = (ev) => {
    filter = ev.target.value;
    render();
  };
  if ($("scope")) $("scope").onchange = (ev) => {
    scope = ev.target.value;
    run = null;
    render();
  };
  document.querySelectorAll("[data-select]").forEach((b) => b.onchange = () => {
    changeSelection([b.dataset.select], b.checked ? "add" : "remove");
  });
  document.querySelectorAll("[data-detail]").forEach((b) => b.onclick = () => showDetail(b.dataset.detail));
  document.querySelectorAll("[data-history]").forEach((b) => b.onclick = () => {
    if (active()) return toast(t("请先停止当前任务", "Stop the active session first"));
    run = structuredClone(records.find((r) => r.id === b.dataset.history));
    tab = "continuous";
    render();
  });
  document.querySelectorAll("[data-helper-history]").forEach((b) => b.onclick = async () => {
    if (active()) return;
    await pollHelper(false, b.dataset.helperHistory);
    tab = "continuous";
    render();
  });
  if ($("import")) $("import").onclick = () => {
    if (active()) return toast(t("请先停止当前任务再导入快照", "Stop the active session before importing a snapshot"));
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json";
    input.onchange = async () => {
      try {
        const f = input.files[0];
        if (f.size > 8e6) throw Error("Maximum 8 MB");
        const d = JSON.parse(await f.text());
        if (d.schema === "network-dashboard/v1" && d.system && d.clash) {
          conn = null;
          run = null;
          selected.clear();
          sessionStorage.removeItem("net-connection");
          snapshot = d;
          config = d.clash;
          connections = d.connections || [];
          proxies = Object.fromEntries((d.groups || []).map((g) => [g.name, { all: [], now: g.selected }]));
          page = "topology";
          error = t("导入快照 · 非实时数据", "Imported snapshot · not live");
          render();
          return;
        }
        if (!d.id || !Number.isFinite(d.started) || !Array.isArray(d.rows) || d.rows.length > 500 || !d.options) throw Error("Unsupported observation format");
        for (const r of d.rows) if (typeof r.name !== "string" || !Array.isArray(r.samples) || r.samples.length > 1e5) throw Error("Invalid rows");
        d.state = "interrupted";
        d.executor = "import";
        await save(d);
        records = await history();
        render();
      } catch (err) {
        toast(err.message);
      }
    };
    input.click();
  };
}
document.addEventListener("visibilitychange", () => {
  if (document.hidden && run?.executor === "browser" && run.state === "running") pause();
});
window.addEventListener("pagehide", () => {
  if (run?.executor === "browser" && active()) {
    run.state = "interrupted";
    run.finished = Date.now();
    persist(true);
  }
});
setInterval(async () => {
  const current = run;
  if (!conn || conn.kind !== "direct" || current?.state !== "running" || document.hidden) return;
  try {
    const [p, c] = await Promise.all([api("/proxies"), api("/configs")]);
    if (run === current && fingerprint(p.proxies, c) !== current.fingerprint) {
      error = t("控制器配置已变化，请重新开始观察。", "Controller configuration changed. Start a new observation.");
      await stop("interrupted");
    }
  } catch {
    if (run === current) {
      error = t("无法校验控制器环境，任务已中断。", "Controller environment could not be verified. Session interrupted.");
      await stop("interrupted");
    }
  }
}, 1e4);
setInterval(async () => {
  if (document.hidden || !conn || conn.kind !== "helper" || busy || helperPolling) return;
  if (run?.executor === "helper" && run.state === "running") {
    try {
      helperPolling = true;
      await pollHelper();
      updateResults();
    } catch (err) {
      pollError = err.message;
      updateResults();
    } finally { helperPolling = false; }
  }
}, 1000);
async function init() {
  try {
    records = await history();
    for (const r of records) if (r.executor === "browser" && ["running", "paused"].includes(r.state)) {
      r.state = "interrupted";
      await save(r);
    }
  } catch {
    error = t("浏览器存储不可用，结果仅保留在本页。", "Browser storage unavailable; results remain in this page only.");
  }
  try {
    conn = JSON.parse(sessionStorage.getItem("net-connection") || "null");
    const h = new URLSearchParams(location.hash.slice(1));
    if (h.get("token") && location.hostname === "127.0.0.1") {
      conn = { kind: "helper", url: location.origin, secret: h.get("token") };
      sessionStorage.setItem("net-connection", JSON.stringify(conn));
      window.history.replaceState(null, "", location.pathname);
    }
  } catch {
  }
  render();
  if (conn) await refresh();
}
init();
