import http from "node:http";
const large=process.argv.includes('--large');
const names=Array.from({length:300},(_,i)=>`${i<100?'Japan':i<200?'Singapore':'Germany'} ${String(i+1).padStart(3,'0')}`);
const largeProxies=Object.fromEntries(names.map(name=>[name,{type:'Shadowsocks'}]));
for(const [index,group] of ['Japan','Singapore','Germany'].entries())largeProxies[group]={type:'Selector',all:names.slice(index*100,(index+1)*100),now:names[index*100]};
http.createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "http://127.0.0.1:4173");
  res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
  if (req.method === "OPTIONS") {
    res.end();
    return;
  }
  res.setHeader("Content-Type", "application/json");
  const url = new URL(req.url, "http://localhost");
  let data = {};
  if (url.pathname === "/version") data = { version: "fixture" };
  else if (url.pathname === "/configs") data = { mode: "rule" };
  else if (url.pathname === "/proxies") data = { proxies: { Auto: { type: "Selector", all: ["Tokyo 01", "Singapore 02", "Frankfurt 03"], now: "Tokyo 01" }, "Tokyo 01": { type: "Shadowsocks" }, "Singapore 02": { type: "VLESS" }, "Frankfurt 03": { type: "Trojan" } } };
  else if (url.pathname === "/connections") data = { connections: [{ metadata: { host: "example.com", process: "Browser" }, chains: ["Tokyo 01", "Auto"], rule: "MATCH", upload: 12e3, download: 48e3 }] };
  else if (url.pathname.endsWith("/delay")) {
    if (decodeURIComponent(url.pathname).includes("Singapore")) {
      res.statusCode = 504;
      data = { message: "Timeout fixture" };
    } else data = { delay: decodeURIComponent(url.pathname).includes("Tokyo") ? 42 : 135 };
  } else {
    res.statusCode = 404;
    data = { message: "Not found" };
  }
  if(large && url.pathname==="/proxies")data={proxies:largeProxies};
  res.end(JSON.stringify(data));
}).listen(19090, "127.0.0.1", () => console.log("Fixture: http://127.0.0.1:19090"));
