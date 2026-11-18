import { escape as e } from "./model.js";
const strings = (value) => (Array.isArray(value) ? value : value == null ? [] : [value]).filter((v) => typeof v === "string" && v.length);
export function dnsEvidence(snapshot, config = {}) {
  const dns = snapshot?.dns || {}, tun = snapshot?.clash?.tun || config.tun || {};
  const resolvers = (Array.isArray(snapshot?.system?.resolvers) ? snapshot.system.resolvers : []).filter((r) => r && (typeof r === "string" || typeof r === "object")).map((r) => typeof r === "string" ? { nameservers: [r] } : r);
  return {
    available: !!snapshot,
    dns,
    resolvers,
    hijack: strings(tun["dns-hijack"]),
    tunEnabled: tun.enable === true,
    branches: [
      ["policy", Object.entries(dns.policy || {}).map(([domain, servers]) => `${domain} → ${strings(servers).join(", ")}`)],
      ["upstreams", strings(dns.upstreams)],
      ["fallback", strings(dns.fallback)],
      ["proxy_server", strings(dns.proxy_server)],
      ["direct", strings(dns.direct)],
      ["bootstrap", strings(dns.bootstrap)]
    ]
  };
}
export function dnsTopology(snapshot, config, t) {
  const evidence = dnsEvidence(snapshot, config), d = evidence.dns;
  const labels = { policy: t("按域名选择上游", "Domain-specific resolvers"), upstreams: t("默认上游", "Default upstreams"), fallback: t("Fallback 上游", "Fallback upstreams"), proxy_server: t("节点域名解析", "Proxy hostname resolution"), direct: t("直连域名解析", "Direct hostname resolution"), bootstrap: t("上游域名引导解析", "Upstream bootstrap resolution") };
  const hints = { policy: t("nameserver-policy · 匹配域名时使用", "nameserver-policy · for matching domains"), upstreams: "nameserver", fallback: t("fallback · 是否使用由过滤条件决定", "fallback · conditional on fallback filters"), proxy_server: "proxy-server-nameserver", direct: "direct-nameserver", bootstrap: "default-nameserver" };
  const card = (title, body, detail, unknown = false) => `<button class="dns-node ${unknown ? "unknown" : ""}" data-dns-detail="${e(JSON.stringify({ title, detail }))}"><strong>${e(title)}</strong><span>${e(body)}</span><small>${unknown ? t("未获取", "Unknown") : t("配置证据 · 点击查看", "Configuration · inspect")}</small></button>`;
  const resolverText = evidence.resolvers.flatMap((r) => strings(r.nameservers || r.servers || r.server));
  const branches = evidence.branches.filter(([key, values]) => values.length || key === "upstreams");
  return `<section class="panel dns-panel" aria-label="${t("DNS 拓扑图", "DNS topology")}"><div class="panel-head"><div><div class="eyebrow">DNS TOPOLOGY</div><h2>${t("DNS 请求，怎么走？", "Where do DNS requests go?")}</h2></div><span class="badge">${snapshot ? t("配置拓扑", "Configuration topology") : t("待补充本机数据", "Local evidence needed")}</span></div>
  <div class="dns-map">
    <div class="dns-origin">${card(t("应用 / 浏览器", "Application / browser"), t("发起域名解析", "Requests name resolution"), t("应用可以使用系统解析器，也可能使用自己的 DoH；本图不假设浏览器一定采用系统 DNS。", "Apps may use system resolvers or their own DoH. Browser DNS behavior is not inferred from system configuration."))}</div>
    <div class="dns-paths">
      <div class="dns-lane"><div class="dns-edge-label">${t("系统解析接口", "System resolver interface")} →</div>${card(t("系统 DNS", "System DNS"), resolverText.join(" · ") || t("需连接助手或导入快照", "Connect the helper or import a snapshot"), JSON.stringify(evidence.resolvers, null, 2), !resolverText.length)}<p class="dns-lane-note">${t("这是系统配置，不能证明每次查询实际采用此路径。", "This is system configuration, not proof that every query follows this path.")}</p></div>
      <div class="dns-lane"><div class="dns-edge-label">${evidence.hijack.length && evidence.tunEnabled ? t("TUN DNS 劫持配置", "Configured TUN DNS interception") : t("进入 Clash 的路径尚未验证", "Path into Clash is unverified")} ⇢</div>
      ${card("Clash DNS", d.enabled === false ? t("DNS 已禁用", "DNS disabled") : (d.mode || t("运行模式未知", "Mode unknown")) + (d.listen ? " · " + d.listen : ""), JSON.stringify({ enabled: d.enabled, mode: d.mode, listen: d.listen, tun_enabled: evidence.tunEnabled, dns_hijack: evidence.hijack, respect_rules: d.respect_rules, source: d.source, collected_at: snapshot?.collected_at }, null, 2), !snapshot)}
      <div class="dns-fork-label">${d.enabled === false ? t("以下配置未代表正在生效", "Configuration below is not active") : t("根据域名和解析用途选择；这些上游不是串行跳点", "Chosen by domain and purpose; upstreams are not sequential hops")} ↓</div>
      <div class="dns-branches">${branches.map(([key, values]) => `<div class="dns-branch">${card(labels[key], values.length ? values.slice(0, 3).join("\n") + (values.length > 3 ? `
+${values.length - 3} ${t("项", "more")}` : "") : t("未读取到配置", "Configuration unavailable"), hints[key] + "\n\n" + values.join("\n") + "\n\n" + (d.source || t("未取得配置来源", "Configuration source unavailable")), !values.length)}</div>`).join("")}</div>
      </div>
    </div>
  </div><div class="legend">${t("虚线：配置关系或尚未验证的路径 · 点击节点查看完整地址和证据 · 非 DNS 抓包结果", "Dashed lines: configured or unverified relationships · Click nodes for full endpoints and evidence · Not packet capture")}</div>
  ${!snapshot ? `<div class="dns-connect-note">${t("当前控制器不提供系统解析器与完整 DNS 上游。连接 Mac 助手，或从历史记录导入私有快照，即可填充此图。", "The controller does not expose system resolvers and full DNS upstream configuration. Connect the Mac helper or import a private snapshot from History to populate the graph.")} <button data-connect>${t("连接本机助手", "Connect local helper")}</button></div>` : ""}</section>`;
}
