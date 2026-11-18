export const targets = { cloudflare: { url: "https://cp.cloudflare.com/generate_204", expected: "204" }, google: { url: "https://www.gstatic.com/generate_204", expected: "204" }, github: { url: "https://github.com/", expected: "200-399" } };
export const escape = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
export function summarize(samples = []) {
  let streak = 0, max = 0;
  const lat = [], s = { ok: 0, fail: 0, error: 0, skipped: 0 };
  for (const p of samples) {
    s[p.state] = (s[p.state] || 0) + 1;
    if (p.state === "fail") {
      max = Math.max(max, ++streak);
    } else streak = 0;
    if (p.state === "ok" && Number.isFinite(p.ms)) lat.push(p.ms);
  }
  lat.sort((a, b) => a - b);
  return { ...s, tested: s.ok + s.fail, rate: s.ok + s.fail ? s.ok / (s.ok + s.fail) * 100 : null, p50: lat.length ? lat[Math.ceil(lat.length * 0.5) - 1] : null, p95: lat.length ? lat[Math.ceil(lat.length * 0.95) - 1] : null, max };
}
export function classify(status, data) {
  if (status === 200 && Number.isFinite(data?.delay) && data.delay >= 0) return { state: "ok", ms: data.delay };
  if ([503, 504].includes(status) && typeof data?.message === "string") return { state: "fail", reason: data.message };
  return { state: "error", reason: data?.message || `HTTP ${status}` };
}
export function leaves(proxies, scope) {
  const result = /* @__PURE__ */ new Set(), seen = /* @__PURE__ */ new Set();
  function walk(n) {
    if (seen.has(n)) return;
    seen.add(n);
    const p = proxies[n];
    if (!p) return;
    if (Array.isArray(p.all)) p.all.forEach(walk);
    else if (!["Direct", "Reject", "RejectDrop", "Pass", "Compatible", "DIRECT", "REJECT"].includes(p.type)) result.add(n);
  }
  (scope ? [scope] : Object.keys(proxies)).forEach(walk);
  return [...result].sort((a, b) => a.localeCompare(b));
}
export function nextDue(due, now, interval) {
  return due + Math.max(1, Math.floor((now - due) / interval) + 1) * interval;
}
export function csv(rows) {
  return "\uFEFF" + rows.map((r) => r.map((v) => '"' + String(v ?? "").replace(/^[=+@-]/, "'$&").replaceAll('"', '""') + '"').join(",")).join("\r\n");
}
export function filterNodeNames(names, search, filter, getStats) {
  return names.filter((name) => name.toLowerCase().includes(search.toLowerCase())).filter((name) => filter === "all" || getStats(name).fail > 0 || getStats(name).error > 0);
}
export function batchSelect(current, candidates, mode = "add", limit = 500) {
  const next = new Set(current);
  for (const name of new Set(candidates)) {
    if (mode === "remove" || mode === "invert" && next.has(name)) next.delete(name);
    else next.add(name);
  }
  if (next.size > limit) throw new RangeError("selection_limit");
  return next;
}

// Support current nested helper samples and older flat samples without inventing successes.
export function normalizeSamples(samples, metric) {
  return samples.map(s => {
    const result = s[metric] || (s.state ? s : {state:'skipped'});
    const at = result.at ?? s.at;
    return {...result, at: typeof at === 'number' ? at : Date.parse(at)};
  }).sort((a,b) => a.at-b.at);
}
export function probeStats(row) {
  const samples = row?.samples || [], window = samples.slice(-20), recent = summarize(window);
  const base = summarize(samples), total = row?.summary, counts = row?.totals;
  const ok = total?.ok ?? counts?.ok ?? base.ok;
  const fail = total?.failed ?? counts?.fail ?? base.fail;
  const error = total?.errors ?? counts?.error ?? base.error;
  const skipped = total?.skipped ?? counts?.skipped ?? base.skipped;
  const tested = ok + fail, last = samples.at(-1);
  let streak = 0;
  for (let i=samples.length-1;i>=0 && samples[i].state==='fail';i--) streak++;
  const lat = samples.filter(s=>s.state==='ok' && Number.isFinite(s.ms)).map(s=>s.ms);
  return {...base,ok,fail,error,skipped,tested,rate:tested ? ok/tested*100:null,
    loss:tested ? fail/tested*100:null, recentLoss:recent.tested ? recent.fail/recent.tested*100:null,
    recentTested:recent.tested, streak:total?.current_failure_streak ?? streak,
    lastState:total?.last_state ?? last?.state,
    lastAt:total?.last_sample_at ? Date.parse(total.last_sample_at) : last?.at,
    lastMs:total ? total.last_ms : last?.state==='ok' ? last.ms:null,
    mean:total?.avg_ms ?? (lat.length ? lat.reduce((a,b)=>a+b,0)/lat.length:null)};
}
