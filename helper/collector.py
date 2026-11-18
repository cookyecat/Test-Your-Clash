"""Network dashboard: stdlib-only, local read-only collector for macOS.
Read-only by default. Selector changes require native, time-limited approval.
Active probes are explicit, fixed-target, and bounded.
"""
from __future__ import annotations
import base64, concurrent.futures, datetime, hashlib, hmac, http.client, ipaddress
import json, os, pathlib, re, secrets, signal, socket, subprocess, sys, threading, time, heapq
import urllib.parse, webbrowser, sqlite3, contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = '5.0.0'
PORT = int(os.environ.get('NETDASH_PORT', '17890'))
HOME = pathlib.Path.home()
BASE = HOME / 'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev'
HTML = pathlib.Path(globals().get('DASHBOARD_FILE', os.environ.get('NETDASH_HTML', str(pathlib.Path(__file__).with_name('network-dashboard.html')) if '__file__' in globals() else 'network-dashboard.html'))).resolve()
TOKEN = secrets.token_urlsafe(32)
STATE_LOCK = threading.Lock()
PROBE_LOCK = threading.Lock()
CACHE = {'data': None, 'at': 0.0}
PROBES: dict = {'at': None, 'results': [], 'groups': {}, 'signature': None}
HISTORY: list = []


def now():
    return datetime.datetime.now().astimezone().isoformat(timespec='seconds')


def command(args, timeout=4):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout[:240000], p.stderr[:1500]
    except subprocess.TimeoutExpired:
        return 124, '', 'command timeout'
    except (OSError, ValueError) as e:
        return 127, '', type(e).__name__ + ': ' + str(e)[:150]


def scalar(text):
    t = text.strip()
    if t.startswith(('"', "'")) and t[-1:] == t[:1]:
        return t[1:-1]
    if t in ('true', 'false'): return t == 'true'
    if t in ('null', '~'): return None
    if t == '[]': return []
    if t == '{}': return {}
    if re.fullmatch(r'-?\d+', t): return int(t)
    return t


def yaml_block(text, name):
    lines = text.splitlines()
    start = next((i for i, v in enumerate(lines) if v.strip() == name + ':' and not v.startswith(' ')), None)
    if start is None: return []
    out = []
    for line in lines[start + 1:]:
        if line and not line.startswith((' ', '#', '-')): break
        out.append(line)
    return out


def fields(lines, indent=2):
    """Read selected YAML scalar/list fields, not a general YAML interpreter."""
    result = {}
    for i, line in enumerate(lines):
        if len(line) - len(line.lstrip()) != indent or line.strip().startswith(('#', '-')): continue
        m = re.match(r'^\s*(.+?):(?:\s+(.*)|$)', line)
        if not m: continue
        key, tail = scalar(m.group(1)), (m.group(2) or '').strip()
        if tail:
            result[key] = scalar(tail)
            continue
        vals = []
        for nxt in lines[i + 1:]:
            stripped = nxt.strip()
            if not stripped or stripped.startswith('#'): continue
            level = len(nxt) - len(nxt.lstrip())
            if level < indent or (level == indent and not stripped.startswith('- ')): break
            if stripped.startswith('- ') and level <= indent + 2: vals.append(scalar(stripped[2:]))
        result[key] = vals
    return result


def read_text(path):
    try: return pathlib.Path(path).read_text(errors='replace')
    except OSError: return ''


def socket_path():
    choices = [pathlib.Path(f'/var/run/clash-verge-service/users/{os.getuid()}/verge-mihomo.sock')]
    txt = read_text(BASE / 'config.yaml')
    m = re.search(r'^external-controller-unix:\s*(.+)$', txt, re.M)
    if m: choices.append(pathlib.Path(str(scalar(m.group(1)))))
    for p in choices:
        if p.exists(): return str(p)
    return str(choices[0])


class UnixConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(socket_path())


def mihomo(path, timeout=3):
    endpoint = os.environ.get('NETDASH_CONTROLLER', '')
    parsed = urllib.parse.urlsplit(endpoint) if endpoint else None
    c = ((http.client.HTTPSConnection if parsed.scheme == 'https' else http.client.HTTPConnection)(parsed.hostname, parsed.port, timeout=timeout) if parsed else UnixConnection('localhost', timeout=timeout))
    try:
        # A local secret, if configured, stays in this process and is never exported.
        m = re.search(r'^secret:\s*(.+)$', read_text(BASE / 'config.yaml'), re.M)
        secret = os.environ.get('NETDASH_SECRET') or (str(scalar(m.group(1))) if m else '')
        headers = {'Authorization': 'Bearer ' + secret} if secret else {}
        c.request('GET', path, headers=headers)
        r = c.getresponse()
        raw = r.read(5_000_000)
        if r.status != 200:
            try:message=str(json.loads(raw).get('message',''))[:200]
            except (ValueError,AttributeError):message=''
            return {'_error': f'Mihomo HTTP {r.status}', '_status':r.status, '_message':message}
        return json.loads(raw)
    except Exception as e:
        return {'_error': type(e).__name__ + ': ' + str(e)[:160]}
    finally:
        c.close()


def safe_dns(value):
    """Keep endpoint transport and policy; remove URL credentials/query tokens."""
    if isinstance(value, list): return [safe_dns(v) for v in value]
    if not isinstance(value, str): return value
    value = re.sub(r'(?<=://)[^/@\s]+@', '[redacted]@', value)
    return re.sub(r'\?[^#\s]+', '?[redacted]', value)


def selected_chain(name, proxies):
    path, visited = [], set()
    while name and name not in visited and len(path) < 12:
        visited.add(name); path.append(name)
        p = proxies.get(name, {})
        nxt = p.get('now')
        if not nxt: break
        name = nxt
    return path


def signature(data):
    body = {'gateway': data.get('system', {}).get('gateway'), 'interface': data.get('system', {}).get('interface'), 'ipv4': data.get('system', {}).get('ipv4'), 'mode': data.get('clash', {}).get('mode'), 'tun': data.get('clash', {}).get('tun'), 'dns_config': data.get('dns'), 'groups': [(g['name'], g['chain']) for g in data.get('groups', [])], 'dns': data.get('dns', {}).get('upstreams')}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16]


def parse_resolvers(text):
    res, cur, scoped = [], None, False
    for line in text.splitlines():
        if 'for scoped queries' in line: scoped = True
        if re.match(r'resolver #', line):
            cur = {'servers': [], 'domain': '', 'flags': '', 'interface': '', 'scoped': scoped}
            res.append(cur)
        elif cur is not None:
            m = re.search(r'nameserver\[\d+\]\s*:\s*(.+)', line)
            if m: cur['servers'].append(m.group(1).strip())
            for key, pattern in [('domain', r'^\s*domain\s*:\s*(.+)'), ('flags', r'^\s*flags\s*:\s*(.+)'), ('interface', r'^\s*if_index\s*:\s*(.+)'), ('order', r'^\s*order\s*:\s*(.+)')]:
                m = re.search(pattern, line)
                if m: cur[key] = m.group(1).strip()
    return res


def collect():
    calls = {'config': '/configs', 'proxies': '/proxies', 'connections': '/connections', 'rules': '/rules', 'version': '/version'}
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        results = dict(zip(calls, ex.map(mihomo, calls.values())))
    c, p = results['config'], results['proxies'].get('proxies', {})
    connections = results['connections'].get('connections', [])
    jobs = {
        'route': ['route', '-n', 'get', 'default'],
        'dns': ['scutil', '--dns'],
        'proxy': ['scutil', '--proxy'],
        'printers': ['lpstat', '-v'],
        'queues': ['lpstat', '-p', '-l'],
    }
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        os_results = dict(zip(jobs, ex.map(command, jobs.values())))
    route = os_results['route'][1]
    match = lambda pat, txt: (re.search(pat, txt).group(1).strip() if re.search(pat, txt) else '')
    iface = match(r'interface:\s*(\S+)', route)
    gateway = match(r'gateway:\s*(\S+)', route)
    interface_text = command(['ifconfig', iface])[1] if re.fullmatch(r'[a-zA-Z0-9]+', iface or '') else ''
    native_resolvers = parse_resolvers(os_results['dns'][1])
    system_proxy_text = os_results['proxy'][1]
    exceptions_match = re.search(r'ExceptionsList\s*:.*?\{(.*?)\}', system_proxy_text, re.S)
    exceptions = re.findall(r'\d+\s*:\s*(.+)', exceptions_match.group(1)) if exceptions_match else []
    merged = read_text(BASE / 'clash-verge.yaml')
    dns_lines = yaml_block(merged, 'dns')
    dns = fields(dns_lines)
    policy_lines = []
    for i, line in enumerate(dns_lines):
        if line.strip() == 'nameserver-policy:':
            for sub in dns_lines[i + 1:]:
                if sub.strip() and len(sub) - len(sub.lstrip()) < 4: break
                policy_lines.append(sub)
            break
    policy = fields(policy_lines, 4)
    app = read_text(BASE / 'verge.yaml')
    profile_doc = read_text(BASE / 'profiles.yaml')
    current = match(r'^current:\s*(\S+)', profile_doc)
    override = None
    profile_section = '\n'.join(yaml_block(app, 'profile_dns_settings'))
    if current:
        mm = re.search(r'^\s{2}' + re.escape(current) + r':\s*\n(.*?)(?=^\s{2}\S|\Z)', profile_section, re.M | re.S)
        if mm:
            en = re.search(r'enabled:\s*(true|false)', mm.group(1))
            if en: override = en.group(1) == 'true'
    if override is None:
        m = re.search(r'^enable_dns_settings:\s*(true|false)', app, re.M)
        if m: override = m.group(1) == 'true'
    rawrules = results['rules'].get('rules', [])
    last_match = next((r.get('proxy') for r in reversed(rawrules) if str(r.get('type', '')).lower() == 'match'), None)
    names = [name for name, item in p.items() if isinstance(item.get('all'), list)]
    if last_match and last_match not in names: names.insert(-1, last_match)
    names += [name for name, item in p.items() if item.get('now') and name not in names][:30]
    groups = []
    for name in names:
        if name not in p: continue
        chain = selected_chain(name, p)
        groups.append({'name': name, 'type': p[name].get('type'), 'selected': p[name].get('now'), 'chain': chain, 'leaf': chain[-1] if chain else None, 'options': len(p[name].get('all', [])), 'active': (c.get('mode') == 'global') if name == 'GLOBAL' else c.get('mode') == 'rule'})
    clean_connections = []
    for conn in sorted(connections, key=lambda x: x.get('start', ''), reverse=True)[:200]:
        md = conn.get('metadata', {})
        clean_connections.append({'host': md.get('host') or '', 'ip': md.get('destinationIP') or '', 'port': md.get('destinationPort'), 'network': md.get('network'), 'process': md.get('process') or '', 'rule': conn.get('rule') or ('GLOBAL' if c.get('mode') == 'global' else ''), 'payload': conn.get('rulePayload') or '', 'chain': list(reversed(conn.get('chains', []))), 'upload': conn.get('upload', 0), 'download': conn.get('download', 0), 'start': conn.get('start')})
    printers = []
    for line in os_results['printers'][1].splitlines():
        m = re.match(r'device for (.*?):\s*(\S+)', line)
        if not m: continue
        label, uri = m.groups()
        u = urllib.parse.urlsplit(uri)
        if not u.hostname: continue
        queue_text = os_results['queues'][1]
        qstate = 'unknown'
        if re.search(r'^printer ' + re.escape(label) + r' is idle', queue_text, re.M): qstate = 'idle'
        elif re.search(r'^printer ' + re.escape(label) + r' ', queue_text, re.M): qstate = 'busy_or_disabled'
        printers.append({'name': label, 'host': u.hostname, 'port': u.port or (631 if u.scheme in ('ipp', 'ipps') else 80), 'uri': u.scheme + '://' + u.netloc.split('@')[-1] + u.path, 'queue': qstate})
    data = {
        'schema': 'network-dashboard/v1', 'collected_at': now(), 'source': 'macOS local read-only collector', 'collector_version': VERSION,
        'clash': {'available': not bool(c.get('_error')), 'error': c.get('_error'), 'version': results['version'].get('version'), 'mode': c.get('mode'), 'mixed_port': c.get('mixed-port'), 'ipv6': c.get('ipv6'), 'tun': c.get('tun', {}), 'allow_lan': c.get('allow-lan'), 'rules_count': len(rawrules), 'fallback': last_match},
        'system': {'interface': iface, 'gateway': gateway, 'ipv4': match(r'\binet\s+([\d.]+)', interface_text), 'ipv6_present': bool(re.search(r'\binet6\s+', interface_text)), 'resolvers': native_resolvers, 'proxy': {'http_enabled': match(r'HTTPEnable\s*:\s*(\d+)', system_proxy_text) == '1', 'https_enabled': match(r'HTTPSEnable\s*:\s*(\d+)', system_proxy_text) == '1', 'host': match(r'HTTPProxy\s*:\s*(\S+)', system_proxy_text), 'port': match(r'HTTPPort\s*:\s*(\d+)', system_proxy_text), 'exceptions': exceptions}},
        'dns': {'mode': dns.get('enhanced-mode'), 'enabled': dns.get('enable'), 'ipv6': dns.get('ipv6'), 'respect_rules': dns.get('respect-rules'), 'listen': dns.get('listen'), 'override': override, 'upstreams': safe_dns(dns.get('nameserver', [])), 'bootstrap': safe_dns(dns.get('default-nameserver', [])), 'proxy_server': safe_dns(dns.get('proxy-server-nameserver', [])), 'direct': safe_dns(dns.get('direct-nameserver', [])), 'fallback': safe_dns(dns.get('fallback', [])), 'policy': {k: safe_dns(v) for k, v in policy.items()}, 'source': 'Clash Verge generated configuration (not all DNS fields are exposed by runtime API)', 'config_mtime': datetime.datetime.fromtimestamp((BASE / 'clash-verge.yaml').stat().st_mtime).astimezone().isoformat(timespec='seconds') if (BASE / 'clash-verge.yaml').exists() else None},
        'groups': groups, 'connections': clean_connections, 'connections_total': len(connections), 'rules': [{'index': i + 1, 'type': r.get('type'), 'payload': r.get('payload'), 'policy': r.get('proxy')} for i, r in enumerate(rawrules)],
        'traffic': {'upload': results['connections'].get('uploadTotal'), 'download': results['connections'].get('downloadTotal')},
        'printers': printers, 'read_errors': {k: v[2][:150] for k, v in os_results.items() if v[0] != 0},
        'sources': ['Mihomo /configs /proxies /connections /rules /version', 'scutil --dns / --proxy', 'route / ifconfig / lpstat', 'clash-verge.yaml DNS section'],
    }
    data['signature'] = signature(data)
    with STATE_LOCK:
        data['probes'] = json.loads(json.dumps(PROBES))
        data['history'] = HISTORY[-20:].copy()
    return data


def snapshot(force=False):
    with STATE_LOCK:
        if not force and CACHE['data'] and time.monotonic() - CACHE['at'] < 4:
            d = dict(CACHE['data']); d['probes'] = json.loads(json.dumps(PROBES)); d['history'] = HISTORY[-20:].copy(); return d
    data = collect()
    with STATE_LOCK: CACHE.update(data=data, at=time.monotonic())
    return data


def dns_probe(domain, server, label):
    started = time.monotonic()
    args = ['dig'] + (['@' + server] if server else []) + [domain, 'A', '+time=2', '+tries=1', '+noall', '+answer', '+comments', '+stats']
    rc, out, err = command(args, 4)
    answers = re.findall(r'\bIN\s+A\s+([\d.]+)', out)
    status_match = re.search(r'status:\s*(\w+)', out)
    status = status_match.group(1) if status_match else 'NO_RESPONSE'
    return {'id': label, 'kind': 'dns', 'target': domain, 'state': 'ok' if rc == 0 and answers else 'fail', 'ms': round((time.monotonic() - started) * 1000), 'detail': f'{status}; ' + (', '.join(answers[:4]) if answers else (err[:90] or '没有 A 记录')), 'server': server or 'system'}


def https_probe(url, port, label):
    start = time.monotonic()
    if not isinstance(port, int) or not 1 <= port <= 65535:
        return {'id': label, 'kind': 'https', 'state': 'unknown', 'target': url, 'detail': '未发现可用 mixed-port'}
    rc, out, err = command(['curl', '-q', '-sS', '--proxy', f'http://127.0.0.1:{port}', '--noproxy', '', '--connect-timeout', '4', '--max-time', '7', '-o', '/dev/null', '-w', '%{http_code}|%{time_appconnect}|%{time_total}', url], 9)
    bits = out.strip().split('|')
    code = int(bits[0]) if bits and bits[0].isdigit() else 0
    tls = float(bits[1]) if len(bits) > 1 and re.fullmatch(r'[\d.]+', bits[1]) else 0
    state = 'ok' if rc == 0 and 200 <= code < 400 else ('warn' if rc == 0 and code >= 400 else 'fail')
    return {'id': label, 'kind': 'https', 'target': url, 'state': state, 'ms': round((time.monotonic() - start) * 1000), 'http': code, 'tls_ms': round(tls * 1000), 'detail': f'HTTP {code} · TLS {round(tls*1000)} ms' if code else (err.split('\n')[0][:160] or f'curl exit {rc}'), 'meaning': 'HTTPS 连通性，不验证登录、模型推理或 SSE'}


def printer_probe(printer):
    start = time.monotonic()
    host, port = printer['host'], printer['port']
    # Only discovered LAN printers; never send print jobs.
    if not (host.rstrip('.').endswith('.local') or (re.fullmatch(r'[\d.]+', host) and ipaddress.ip_address(host).is_private)):
        return {'id': 'printer', 'kind': 'ipp', 'target': host, 'state': 'unknown', 'detail': '仅允许已配置的 .local 或私网打印机'}
    rc, out, err = command(['dscacheutil', '-q', 'host', '-a', 'name', host], 4)
    addresses = re.findall(r'^ip_address:\s*([\d.]+)', out, re.M)
    ip = addresses[0] if addresses else (host if re.fullmatch(r'[\d.]+', host) else None)
    rc, text, err = command(['ipptool', '-t', '-T', '5', printer['uri'], '/usr/share/cups/ipptool/get-printer-attributes.test'], 8)
    ok = rc == 0 and '[PASS]' in text
    return {'id': 'printer', 'kind': 'ipp', 'target': host, 'state': 'ok' if ok else 'fail', 'ip': ip, 'ms': round((time.monotonic() - start) * 1000), 'detail': ('Get-Printer-Attributes 通过 · 未打印' if ok else ('属性查询失败；不等同于 DNS 故障' if ip else '名称解析或 IPP 查询未通过')), 'meaning': '只读取打印机属性；不验证实际出纸'}


def node_probe(leaf, url):
    start = time.monotonic()
    result = mihomo('/proxies/' + urllib.parse.quote(leaf, safe='') + '/delay?' + urllib.parse.urlencode({'url': url, 'timeout': 4500}), 6)
    delay = result.get('delay')
    return {'leaf': leaf, 'state': 'ok' if isinstance(delay, (int, float)) else 'fail', 'ms': delay, 'wall_ms': round((time.monotonic() - start) * 1000), 'target': url, 'detail': '单节点 HTTPS 探测，不改变策略选择' if delay is not None else str(result.get('message') or result.get('_error') or 'No result')[:180]}


def run_probes():
    if not PROBE_LOCK.acquire(blocking=False): return None
    try:
        data = snapshot(True)
        resolvers = data['system']['resolvers']
        server = next((r['servers'][0] for r in resolvers if r['servers']), None)
        tasks = [lambda: dns_probe('www.qq.com', server, 'dns_cn'), lambda: dns_probe('www.gstatic.com', server, 'dns_global'), lambda: https_probe('https://www.gstatic.com/generate_204', data['clash']['mixed_port'], 'https_google'), lambda: https_probe('https://www.cloudflare.com/cdn-cgi/trace', data['clash']['mixed_port'], 'https_general')]
        if data['printers']: tasks.append(lambda: printer_probe(data['printers'][0]))
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
            results = list(ex.map(lambda f: f(), tasks))
        groups = {}
        nodes = []
        probe_names = list(dict.fromkeys(['Gemini', data['clash'].get('fallback') or '🔰 手动选择']))
        for name in probe_names:
            g = next((x for x in data['groups'] if x['name'] == name), None)
            if g and g['leaf'] not in ('DIRECT', 'REJECT') and g['leaf'] not in nodes: nodes.append(g['leaf'])
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            for r in ex.map(lambda leaf: node_probe(leaf, 'https://www.cloudflare.com/cdn-cgi/trace'), nodes): groups[r['leaf']] = r
        probe = {'at': now(), 'results': results, 'groups': groups, 'signature': data['signature'], 'note': 'DNS / HTTPS / IPP'}
        with STATE_LOCK:
            PROBES.clear(); PROBES.update(probe)
            HISTORY.append({'at': probe['at'], 'ok': sum(r['state'] == 'ok' for r in results), 'total': len(results), 'details': [{'id': r['id'], 'state': r['state'], 'ms': r.get('ms')} for r in results], 'groups': {g['name']: g['leaf'] for g in data['groups'] if g['name'] in ('Gemini', '🔰 手动选择')}})
            del HISTORY[:-20]
            CACHE['at'] = 0
        return snapshot(True)
    finally:
        PROBE_LOCK.release()



# v2: public static frontend + local, origin-bound helper. No remote shell/API proxy.
import platform, shutil
STATE_DIR = pathlib.Path(os.environ.get('NETDASH_STATE_DIR', str(HOME / 'Library/Application Support/Network Status Helper')))
STATE_FILE = STATE_DIR / 'session.json'
SESSIONS = {}  # token -> exact approved origin, expiry, owner
GRANTS = {}    # (origin, one-time challenge) -> token and expiry
AUTH_LOCK = threading.Lock()
COLLECT_LOCK = threading.Lock()
LAN_LOCK = threading.Lock()
LAN = {'at': None, 'devices': [], 'source': 'not-collected', 'complete': False}
LOCAL_ORIGIN = f'http://127.0.0.1:{PORT}'
MASTER_TOKEN = secrets.token_urlsafe(40)
LOCAL_TOKEN = secrets.token_urlsafe(32)
SERVER = None


def valid_origin(value):
    if value == LOCAL_ORIGIN: return True
    if not isinstance(value, str) or len(value) > 400: return False
    try:
        u = urllib.parse.urlsplit(value)
        return (u.scheme == 'https' and bool(u.hostname) and not u.username and
                not u.password and not u.path and not u.query and not u.fragment and
                value == f'https://{u.netloc}' and '\\' not in value and
                not any(ord(x) < 33 or ord(x) > 126 for x in value))
    except ValueError: return False


def cleanup_auth():
    ts = time.time()
    for key in list(GRANTS):
        if GRANTS[key]['until'] < ts: del GRANTS[key]
    for key in list(SESSIONS):
        if SESSIONS[key]['until'] < ts: del SESSIONS[key]


def make_grant(origin, challenge):
    if not valid_origin(origin) or not re.fullmatch(r'[A-Za-z0-9_-]{32,100}', challenge or ''):
        raise ValueError('Invalid pairing origin or challenge')
    with AUTH_LOCK:
        cleanup_auth()
        if len(SESSIONS) > 32: raise ValueError('Too many sessions; restart the helper')
        token = secrets.token_urlsafe(32)
        SESSIONS[token] = {'origin': origin, 'until': time.time() + 8 * 3600, 'owner': False}
        GRANTS[(origin, challenge)] = {'token': token, 'until': time.time() + 120}
    return token


def safe_private_v4(value):
    try:
        ip = ipaddress.ip_address(value)
        return ip.version == 4 and any(ip in ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
    except ValueError: return False


def read_neighbors():
    """Passive table only. Table membership is NOT proof a device is online."""
    rc, text, _ = command(['arp', '-an'], 3)
    devices = []
    for line in text.splitlines():
        m = re.search(r'^(.*?)\s*\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+(\S+)\s+on\s+(\S+)', line)
        if not m: continue
        name, address, mac, interface = m.groups()
        if not safe_private_v4(address) or mac in ('(incomplete)', 'ff:ff:ff:ff:ff:ff'): continue
        try:
            if int(mac.split(':')[0], 16) & 1: continue
        except ValueError: continue
        devices.append({'ip':address, 'name':name.strip() if name.strip() != '?' else '',
                        'interface': interface, 'kind':'device', 'source':'ARP cache',
                        'state':'cached', 'seen_at':now()})
    return devices[:128]


def local_lan(data, confirm=False):
    devices = read_neighbors()
    by_ip = {d['ip']: d for d in devices}
    gateway = data.get('system', {}).get('gateway', '')
    own = data.get('system', {}).get('ipv4', '')
    iface = data.get('system', {}).get('interface', '')
    for address, kind, label in ((gateway,'gateway','默认网关'),(own,'computer','这台电脑')):
        if safe_private_v4(address):
            by_ip.setdefault(address, {'ip':address, 'interface':iface, 'state':'configured', 'seen_at':now(), 'source':'system route/interface'})
            by_ip[address].update(kind=kind, name=label)
    for printer in data.get('printers', [])[:8]:
        # mDNS resolution only on explicit discovery, not every refresh.
        ip = printer.get('ip')
        if confirm and not ip:
            _, out, _ = command(['dscacheutil','-q','host','-a','name',printer.get('host','')], 3)
            mm = re.search(r'^ip_address:\s*([\d.]+)', out, re.M)
            ip = mm.group(1) if mm else None
        if safe_private_v4(ip or ''):
            by_ip.setdefault(ip, {'ip':ip, 'interface':iface, 'state':'resolved', 'seen_at':now()})
            by_ip[ip].update(kind='printer', name=printer['name'], source='configured printer + mDNS', host=printer.get('host'))
    devices = list(by_ip.values())
    # Bound active verification to already-known neighbors on the default interface.
    # No subnet/port sweep; no arbitrary address supplied by the website.
    if confirm:
        chosen = [d for d in devices if d.get('interface') == iface and d['ip'] != own][:24]
        def verify(d):
            rc, out, _ = command(['ping','-n','-c','1','-W','800',d['ip']], 2)
            m = re.search(r'time[=<]([\d.]+)', out)
            d.update(state='responded' if rc == 0 else 'unconfirmed', checked_at=now(),
                     ping_ms=float(m.group(1)) if m else None)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex: list(ex.map(verify, chosen))
    return {'at':now(), 'devices':devices, 'source':'ARP cache + system routes + configured printers',
            'complete':False, 'verification':'known-neighbor ping' if confirm else 'passive',
            'note':'非完整设备扫描；缓存不等于在线，未响应 ICMP 也不等于离线。不会推断交换机端口、Wi-Fi 关联或真实物理链路。'}


_collect_v1 = collect

def collect():
    if sys.platform != 'darwin':
        return {'schema':'network-dashboard/v1', 'collector_version':VERSION, 'collected_at':now(),
                'source':'unsupported platform', 'clash':{'available':False,'error':'完整本地采集器目前仅支持 macOS'},
                'system':{},'dns':{},'groups':[],'connections':[],'rules':[],'printers':[],
                'probes':{'results':[],'groups':{}},'history':[],'lan':{'devices':[],'complete':False}}
    with COLLECT_LOCK:
        data = _collect_v1()
        data['platform'] = 'macOS'
        if LAN['at'] and LAN.get('interface') == data['system'].get('interface') and LAN.get('gateway') == data['system'].get('gateway') and age_seconds(LAN['at']) < 900:
            data['lan'] = json.loads(json.dumps(LAN))
        else:
            data['lan'] = local_lan(data)
        data['capabilities'] = {'system':True, 'mihomo':data['clash']['available'], 'lan':'passive+opt-in-known-neighbors', 'write_config':False, 'node_stability':True, 'selector_control':'native-consent', 'persistent_history':True}
        return data


def age_seconds(value):
    try: return time.time() - datetime.datetime.fromisoformat(value).timestamp()
    except Exception: return float('inf')


# v3 node stability: asynchronous, round-robin, fixed targets, never changes selectors.
import math, statistics, copy
STABILITY_LOCK = threading.RLock()
STABILITY_CANCEL = threading.Event()
STABILITY_JOB = None
STABILITY_OWNER = None
STABILITY_HISTORY = []
STABILITY_LAST_START = 0.0
MAX_BATCH_NODES = 500
MAX_BATCH_SAMPLES = 10000
STABILITY_TARGETS = {
    'cloudflare': {'label':'Cloudflare', 'url':'https://cp.cloudflare.com/generate_204', 'expected':'204'},
    'google': {'label':'Google', 'url':'https://www.gstatic.com/generate_204', 'expected':'204'},
    'github': {'label':'GitHub', 'url':'https://github.com/', 'expected':'200-399'},
    'claude': {'label':'Claude API', 'url':'https://api.anthropic.com/v1/models', 'expected':'200-499','kind':'api'},
    'claude_web': {'label':'Claude 网页', 'url':'https://claude.ai/', 'expected':'200-499','kind':'web'},
    'gemini': {'label':'Gemini API', 'url':'https://generativelanguage.googleapis.com/v1beta/models', 'expected':'200-499','kind':'api'},
    'gemini_web': {'label':'Gemini 网页', 'url':'https://gemini.google.com/', 'expected':'200-499','kind':'web'},
    'chatgpt': {'label':'ChatGPT 网页', 'url':'https://chatgpt.com/', 'expected':'200-499','kind':'web'},
    'openai': {'label':'OpenAI API', 'url':'https://api.openai.com/v1/models', 'expected':'200-499','kind':'api'},
}


# Service checks run from this Mac via its existing rule path or system/TUN path.
# Fixed GET targets only. No cookies, account tokens, body logging or inference.
SERVICE_PRESETS = {
    'claude': {'label':'Claude','group':'Claude','targets':['claude_web','claude']},
    'gemini': {'label':'Gemini','group':'Gemini','targets':['gemini_web','gemini']},
    'chatgpt': {'label':'ChatGPT','group':'Chatgpt','targets':['chatgpt','openai']},
}
SERVICE_LOCK = threading.RLock()
SERVICE_CANCEL = threading.Event()
SERVICE_JOB = None
SERVICE_OWNER = None
SERVICE_LAST_START = 0.0


def classify_service_result(rc, metrics, route):
    """Keep response headers, body completion and current reachability separate."""
    def value(key):
        try:
            number = float(metrics.get(key, 0) or 0)
            return number if math.isfinite(number) and number >= 0 else 0.0
        except (TypeError, ValueError):
            return 0.0
    def status(key):
        number = value(key)
        return int(number) if number.is_integer() and 100 <= number <= 599 else None
    code = status('http_code') or status('response_code')
    proxy_status = status('http_connect') if route == 'mixed' else None
    tls = value('time_appconnect')
    result = {
        'http_status': code, 'proxy_status': proxy_status, 'curl_exit': rc,
        'timings': {k: round(value(v)*1000, 2) if value(v) > 0 else None for k,v in {
            'dns_ms':'time_namelookup', 'tcp_ms':'time_connect',
            'tls_ready_ms':'time_appconnect', 'first_byte_ms':'time_starttransfer',
            'total_ms':'time_total'}.items()},
        'tls_reached': bool(tls > 0 or code), 'network_reachable': bool(code),
        'headers_received': bool(code),
        'transfer_state': 'complete' if code and rc == 0 else 'limited' if code and rc == 63 else 'incomplete' if code else 'not_started',
        'remote_ip': str(metrics.get('remote_ip') or '')[:80],
        'dns_scope': 'proxy' if route == 'mixed' else 'system',
    }
    if route == 'mixed':
        result['timings']['dns_ms'] = None  # curl resolved loopback, not the service
    if code:
        if rc == 63:
            result['body_limited'] = True
        if code in (401,407): state,access,label='warn','authentication',f'网络已通 · HTTP {code} 需身份验证'
        elif code == 403: state,access,label='warn','restricted','网络已通 · HTTP 403 受限'
        elif code == 429: state,access,label='warn','rate_limited','网络已通 · HTTP 429 限流'
        elif code >= 500: state,access,label='warn','server_error',f'网络已通 · 服务返回 {code}'
        elif code >= 400: state,access,label='warn','client_error',f'网络已通 · HTTP {code}'
        elif code >= 300: state,access,label='ok','redirect',f'HTTPS 可达 · HTTP {code} 跳转'
        else: state,access,label='ok','response',f'HTTPS 可达 · HTTP {code}'
        if rc not in (0,63):
            state = 'warn'
            label += ' · 正文中断'
        result.update(state=state, access=access, label=label,
                      failure_stage='body' if rc not in (0,63) else None)
    else:
        if rc in (5,6): stage,label='dns','域名解析失败'
        elif rc in (51,60): stage,label='certificate','TLS 证书验证失败'
        elif rc == 7 or value('time_connect') == 0: stage,label='connect','TCP 连接未建立'
        elif route == 'mixed' and proxy_status != 200:
            stage,label='proxy_tunnel','代理隧道未建立'
            if proxy_status: label += f' · CONNECT {proxy_status}'
        elif not tls: stage,label='tls','TLS 握手未完成'
        else: stage,label='response','等待响应失败'
        result.update(state='fail', access='unavailable', label=label, failure_stage=stage)
    return result


def service_curl_args(target,route,port,source_port):
    if target not in STABILITY_TARGETS or not STABILITY_TARGETS[target].get('kind'):
        raise ValueError('未知服务端点')
    if route not in ('mixed','system'):raise ValueError('未知路径')
    if route=='mixed' and (type(port) is not int or not 1<=port<=65535):raise ValueError('Clash HTTP 端口不可用')
    fields=('http_code','http_connect','time_namelookup','time_connect','time_appconnect','time_starttransfer','time_total','remote_ip')
    fmt=';'.join(k+'=%{'+k+'}' for k in fields)
    args=['curl','-q','--silent','--show-error','--proto','=https','--connect-timeout','5','--max-time','9',
          '--max-filesize','1048576','--output',os.devnull,'--write-out',fmt,'--local-port',str(source_port)]
    if route=='mixed':args+=['--proxy',f'http://127.0.0.1:{port}','--noproxy','']
    else:args+=['--noproxy','*']
    return args+[STABILITY_TARGETS[target]['url']]


def service_https_sample(target,route,port):
    host=urllib.parse.urlsplit(STABILITY_TARGETS[target]['url']).hostname
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as reserve:
        reserve.bind(('127.0.0.1',0));source_port=reserve.getsockname()[1]
    args=service_curl_args(target,route,port,source_port)
    env={k:v for k,v in os.environ.items() if k.lower() not in ('http_proxy','https_proxy','all_proxy','no_proxy')}
    trace=None;p=None; started=time.monotonic()
    try:
        p=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
        while p.poll() is None:
            if SERVICE_CANCEL.is_set() or time.monotonic()-started>11:
                p.terminate()
                try:p.wait(timeout=1)
                except subprocess.TimeoutExpired:p.kill()
                p.communicate(timeout=2)
                return {'state':'skipped' if SERVICE_CANCEL.is_set() else 'error', 'label':'已停止' if SERVICE_CANCEL.is_set() else '本机探测超时',
                        'network_reachable':None,'http_status':None,'trace':trace}
            if trace is None:
                data=mihomo('/connections',.35)
                for c in data.get('connections',[]):
                    m=c.get('metadata',{})
                    if str(m.get('sourcePort'))==str(source_port) and (m.get('host') in (host,'',None)):
                        trace={'source':'Mihomo connection observation','rule':str(c.get('rule') or '')[:80],
                               'payload':str(c.get('rulePayload') or '')[:300],
                               'chain':list(reversed([str(n)[:300] for n in c.get('chains',[])][:12]))}
                        break
            SERVICE_CANCEL.wait(.18)
        out,_=p.communicate(timeout=2)  # stderr can include host-specific details; never export it
        metrics=dict(x.split('=',1) for x in out[-2500:].split(';') if '=' in x)
        result=classify_service_result(p.returncode,metrics,route)
        if p.returncode in (45,127):result.update(state='error',label='本机探测未执行',network_reachable=None,failure_stage='local')
        result.update(trace=trace,at=now())
        return result
    except (OSError,ValueError,subprocess.SubprocessError):
        return {'state':'error','label':'本机探测未执行','network_reachable':None,'http_status':None,'trace':trace,'at':now()}
    finally:
        if p is not None and p.poll() is None:
            p.kill();p.communicate()


def result_validity(job, context_reader=None):
    """A time-valid record is not current until its environment is checked.

    context_reader may cache one OS/controller read for a batch of history records.
    This function never sends network probes or modifies stored samples.
    """
    state = job.get('state')
    if state in ('running','cancelled','interrupted'):
        return {'state': state, 'checked_at': now()}
    try:
        start = datetime.datetime.fromisoformat(job['started_at'].replace('Z','+00:00'))
        end = datetime.datetime.fromisoformat(job['finished_at'].replace('Z','+00:00'))
        epoch = time.time()
        valid_time = (state == 'done' and start.tzinfo is not None and end.tzinfo is not None and
                      start <= end and start.timestamp() <= epoch+30 and
                      -30 <= epoch-end.timestamp() <= 900)
    except (KeyError, TypeError, ValueError, AttributeError):
        valid_time = False
    if not valid_time:
        return {'state':'stale','checked_at':now()}
    if not job.get('context'):
        return {'state':'unverified','checked_at':now()}
    try:
        current = context_reader() if context_reader else context_fingerprint()[0]
    except RuntimeError:
        current = None
    return {'state': 'unverified' if current is None else
                     'current' if current == job['context'] else 'config_changed',
            'checked_at':now()}


def service_validity(job):
    return result_validity(job)


def services_view():
    # Avoid holding the result lock while reading OS/Mihomo state.
    with SERVICE_LOCK:
        job = copy.deepcopy(SERVICE_JOB)
    if job is not None:
        job['validity'] = service_validity(job)
    return {'job':job,'presets':copy.deepcopy(SERVICE_PRESETS)}


def services_worker(targets,route,port,context):
    global SERVICE_LAST_START
    try:
        # At most two in-flight requests; do not submit the full job in advance.
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            iterator=iter(targets);pending={}
            def fill():
                while len(pending)<2 and not SERVICE_CANCEL.is_set():
                    target=next(iterator,None)
                    if target is None:break
                    pending[pool.submit(service_https_sample,target,route,port)]=target
                    with SERVICE_LOCK:
                        next(r for r in SERVICE_JOB['results'] if r['target']==target)['state']='running'
            def check_context():
                if SERVICE_CANCEL.is_set(): return
                try: current,_ = context_fingerprint()
                except RuntimeError: current = None
                if current != context:
                    with SERVICE_LOCK:
                        SERVICE_JOB.update(state='interrupted',reason='检测期间网络配置改变，已停止后续端点；请重测当前路径')
                    SERVICE_CANCEL.set()
            check_context()
            fill()
            while pending:
                done,_=concurrent.futures.wait(pending,timeout=.2,return_when=concurrent.futures.FIRST_COMPLETED)
                for future in done:
                    target=pending.pop(future)
                    try:result=future.result()
                    except Exception:result={'state':'error','label':'本机探测异常','network_reachable':None}
                    with SERVICE_LOCK:
                        row=next(r for r in SERVICE_JOB['results'] if r['target']==target)
                        row.update(result);SERVICE_JOB['completed']+=1
                if done: check_context()
                fill()
        try:after,_=context_fingerprint()
        except RuntimeError:after=None
        with SERVICE_LOCK:
            if SERVICE_JOB['state'] == 'running':
                SERVICE_JOB['state']='cancelled' if SERVICE_CANCEL.is_set() else 'done'
            if after!=context and not SERVICE_CANCEL.is_set():
                SERVICE_JOB.update(state='interrupted',reason='检测期间网络配置改变，请重测当前路径')
            for r in SERVICE_JOB['results']:
                if r['state']=='pending':r.update(state='skipped',label='未检测')
    except Exception:
        with SERVICE_LOCK:
            SERVICE_JOB.update(state='interrupted',reason='本机检测中断，请重新检测')
            for r in SERVICE_JOB['results']:
                if r['state'] in ('pending','running'):r.update(state='skipped',label='未完成')
    finally:
        with SERVICE_LOCK:SERVICE_JOB['finished_at']=now()
        SERVICE_LAST_START=time.monotonic();PROBE_LOCK.release()


def start_services(payload,owner):
    global SERVICE_JOB,SERVICE_OWNER,SERVICE_LAST_START
    if payload.get('consent') is not True:raise ValueError('请确认开始服务检测')
    names=payload.get('services',['claude','gemini','chatgpt'])
    if not isinstance(names,list) or not 1<=len(names)<=3 or not all(isinstance(n,str) and n in SERVICE_PRESETS for n in names) or len(set(names))!=len(names):
        raise ValueError('服务只支持 Claude、Gemini、ChatGPT')
    route=payload.get('route','mixed')
    if route not in ('mixed','system'):raise ValueError('未知检测路径')
    if time.monotonic()-SERVICE_LAST_START<10:raise ValueError('请间隔 10 秒再检测服务')
    if not PROBE_LOCK.acquire(False):raise RuntimeError('已有检测进行中，请完成或停止后再试')
    try:
        config=mihomo('/configs');context,_=context_fingerprint()
        port=config.get('mixed-port') or config.get('port')
        if route=='mixed' and (type(port) is not int or not 1<=port<=65535):raise ValueError('Clash HTTP 端口不可用，可改测系统 / TUN 路径')
        targets=[t for name in names for t in SERVICE_PRESETS[name]['targets']]
        with SERVICE_LOCK:
            SERVICE_CANCEL.clear();SERVICE_OWNER=owner
            SERVICE_JOB={'id':secrets.token_hex(12),'state':'running','route':route,'services':names,
                         'started_at':now(),'finished_at':None,'context':context,'mode':config.get('mode'),
                         'proxy_address':f'127.0.0.1:{port}' if route=='mixed' else None,
                         'completed':0,'total':len(targets),'results':[
                             {'target':t,'host':urllib.parse.urlsplit(STABILITY_TARGETS[t]['url']).hostname,
                              'label':STABILITY_TARGETS[t]['label'],'state':'pending','http_status':None,
                              'network_reachable':None,'trace':None} for t in targets]}
            first=services_view()
        threading.Thread(target=services_worker,args=(targets,route,port,context),daemon=True).start()
        return first
    except Exception:
        PROBE_LOCK.release();raise


def stop_services(owner,override=False):
    with SERVICE_LOCK:
        if SERVICE_JOB and SERVICE_JOB['state']=='running':
            if owner!=SERVICE_OWNER and not override:raise PermissionError('请在发起检测的页面停止')
            SERVICE_CANCEL.set()
    return services_view()


def yaml_scalar_safe(s):
    s=s.strip()
    if s.startswith('"'):
        try:return json.loads(s)
        except (ValueError,TypeError):return None
    if s.startswith("'"):
        return s[1:-1].replace("''", "'") if s.endswith("'") else None
    return scalar(re.sub(r'\s+#.*$', '', s))


def proxy_endpoints(text):
    """Read only name/server/port from expanded Clash YAML. Never export credentials.
    Unsupported flow-style or provider-only entries remain unavailable, not guessed.
    """
    result={}; current=None; field_indent=None
    def commit():
        if isinstance(current,dict) and isinstance(current.get('name'),str) and isinstance(current.get('server'),str):
            result[current['name']]={k:current[k] for k in ('server','port','dialer-proxy') if k in current}
    for line in yaml_block(text,'proxies'):
        m=re.match(r'^(\s*)-\s+(name|server|type|port):\s*(.*?)\s*$',line)
        if m:
            commit();current={};field_indent=len(m.group(1))+2
            if m.group(2) in ('name','server','port'):current[m.group(2)]=yaml_scalar_safe(m.group(3))
            continue
        if current is not None:
            m=re.match(r'^(\s*)(name|server|port|dialer-proxy):\s*(.*?)\s*$',line)
            if m and len(m.group(1))==field_indent:current[m.group(2)]=yaml_scalar_safe(m.group(3))
    commit();return result


def stability_catalog():
    raw=mihomo('/proxies')
    if raw.get('_error'):raise RuntimeError('无法读取 Mihomo 节点；请检查 Clash 是否运行')
    proxies=raw.get('proxies',{})
    config=mihomo('/configs')
    if config.get('_error'):raise RuntimeError('无法读取 Mihomo 配置')
    ep=proxy_endpoints(read_text(BASE/'clash-verge.yaml'))
    groups={n:dict(selected=p.get('now'), type=p.get('type'), members=p.get('all',[]), chain=selected_chain(n,proxies), leaf=selected_chain(n,proxies)[-1]) for n,p in proxies.items() if isinstance(p.get('all'),list)}
    chosen={}
    for n,p in proxies.items():
        if p.get('now'):
            ch=selected_chain(n,proxies)
            if ch:chosen.setdefault(ch[-1],[]).append(n)
    excluded={'direct','reject','rejectdrop','pass','compatible','dns','selector','urltest','fallback','loadbalance','relay'}
    nodes=[]
    for name,p in proxies.items():
        if 'all' in p or str(p.get('type','')).replace('-','').lower() in excluded:continue
        if not isinstance(name,str) or len(name)>300:continue
        nodes.append({'name':name,'type':p.get('type','Unknown'),'selected_by':chosen.get(name,[]),
                      'icmp_available':name in ep and not ep[name].get('dialer-proxy')})
    providers=mihomo('/providers/proxies')
    provider_map={}
    for name,provider in (providers.get('providers') or {}).items():
        if not isinstance(provider,dict):continue
        for item in (provider.get('proxies') or []):
            if isinstance(item,dict) and isinstance(item.get('name'),str):provider_map.setdefault(item['name'],[]).append(str(name)[:120])
    for node in nodes:node['providers']=provider_map.get(node['name'],[])
    for group in groups.values():
        group['direct_nodes']=[n['name'] for n in nodes if n['name'] in group['members']]
    return {'version':VERSION,'nodes':nodes,'groups':groups,'targets':STABILITY_TARGETS, 'mode':config.get('mode'),
            'max_nodes':MAX_BATCH_NODES,'max_samples':MAX_BATCH_SAMPLES,'rounds':[1,3,5,10,20],
            'concurrency':[2,4,8],'capabilities':{'batch_revalidation':True,'targeted_retry':True,'continuous_monitor':True},'services':SERVICE_PRESETS,'timeout_ms':[3000,5000,8000]}


def context_fingerprint():
    # Include automatic selections and runtime proxy settings, but never probe
    # histories/counters: a measurement must not invalidate its own batch.
    c=mihomo('/configs')
    if c.get('_error'):raise RuntimeError('Mihomo 连接已中断')
    rc,out,_=command(['route','-n','get','default'],3)
    if rc != 0:raise RuntimeError('无法读取当前网络路由')
    iface=re.search(r'interface:\s*(\S+)',out)
    gateway=re.search(r'gateway:\s*(\S+)',out)
    cfg=read_text(BASE / 'clash-verge.yaml')
    raw=mihomo('/proxies')
    if raw.get('_error'):raise RuntimeError('Mihomo 节点列表不可用')
    groups = sorted((n, str(p.get('type','')), p.get('now'),
                     sorted(str(v) for v in p.get('all', [])))
                    for n,p in raw.get('proxies',{}).items()
                    if isinstance(p,dict) and isinstance(p.get('all'),list))
    dns_rc,dns_text,_=command(['scutil','--dns'],3)
    proxy_rc,proxy_text,_=command(['scutil','--proxy'],3)
    if dns_rc != 0 or proxy_rc != 0:raise RuntimeError('无法校验系统 DNS / 代理配置')
    # Ignore changing reachability flags; resolver addresses/scope are the facts.
    resolvers=[{k:r.get(k) for k in ('servers','domain','interface','scoped','order')}
               for r in parse_resolvers(dns_text)]
    s={'groups':groups,'mode':c.get('mode'),'tun':c.get('tun',{}),
       'interface':iface.group(1) if iface else '',
       'gateway':gateway.group(1) if gateway else '',
       'ports':{k:c.get(k) for k in ('mixed-port','port','socks-port','ipv6','interface-name')},
       'system_dns':resolvers,'system_proxy':proxy_text,
       'config_hash':hashlib.sha256(cfg.encode()).hexdigest()}
    return hashlib.sha256(json.dumps(s,sort_keys=True).encode()).hexdigest()[:20],s['interface']


def validate_stability(payload,catalog):
    names=payload.get('nodes')
    if not isinstance(names,list) or not names or len(names)>MAX_BATCH_NODES or not all(isinstance(n,str) for n in names):
        raise ValueError(f'请选择 1–{MAX_BATCH_NODES} 个节点')
    if len(set(names))!=len(names):raise ValueError('节点不能重复')
    available={n['name'] for n in catalog['nodes']}
    if any(n not in available for n in names):raise ValueError('节点已不在当前订阅中；刷新列表后重试')
    rounds=payload.get('rounds',5); timeout=payload.get('timeout_ms',5000)
    if type(rounds) is not int or rounds not in (1,3,5,10,20):raise ValueError('次数只支持 1、3、5、10 或 20')
    if len(names)*rounds>MAX_BATCH_SAMPLES:raise ValueError('本批样本数超过上限，请先初筛再复测')
    if type(timeout) is not int or timeout not in (3000,5000,8000):raise ValueError('超时只支持 3、5 或 8 秒')
    mode=payload.get('mode','https');target=payload.get('target','cloudflare')
    if mode not in ('https','icmp','both'):raise ValueError('未知测试方式')
    if not isinstance(target,str) or target not in STABILITY_TARGETS:raise ValueError('未知检测目标')
    if mode in ('https','both') and STABILITY_TARGETS[target].get('kind') and rounds>10:
        raise ValueError('服务端点每节点最多 10 轮')
    concurrency=payload.get('concurrency',4)
    if type(concurrency) is not int or concurrency not in (2,4,8):raise ValueError('并发数只支持 2、4 或 8')
    # Service front doors are more sensitive than connectivity targets.
    concurrency=min(concurrency,2) if STABILITY_TARGETS[target].get('kind') else concurrency
    group=payload.get('group','')
    if not isinstance(group,str) or len(group)>300:raise ValueError('策略组格式不正确')
    baseline=None;selected=None
    if group:
        g=catalog.get('groups',{}).get(group)
        if not g:raise ValueError('策略组已不存在')
        allowed=set(g.get('direct_nodes',[]))|{g.get('leaf')}
        if any(n not in allowed for n in names):raise ValueError('候选不属于这个策略组；请重新选择')
        baseline=g.get('leaf');selected=g.get('selected')
    parent=payload.get('parent_id')
    if parent is not None and (not isinstance(parent,str) or len(parent)>100):raise ValueError('复测批次格式不正确')
    purpose=payload.get('purpose','quick')
    if purpose not in ('quick','confirm','custom','observe','screen','refine','retry'):raise ValueError('未知测试方案')
    if purpose=='screen' and (rounds>3 or mode!='https'):raise ValueError('批量初筛使用 1 或 3 轮 HTTPS')
    if purpose=='observe' and len(names)>20:raise ValueError('间隔复测请选择至多 20 个候选')
    return {'nodes':names,'rounds':rounds,'timeout_ms':timeout,'mode':mode,'target':target,'interval_ms':1000,'concurrency':concurrency,
            'group':group,'baseline':baseline,'selected_before':selected,'parent_id':parent,'purpose':purpose}


def public_ipv4(value):
    try:
        ip=ipaddress.ip_address(value)
        return ip.version==4 and ip.is_global and not ip.is_multicast and not ip.is_reserved
    except (ValueError,TypeError):return False


def resolve_ingress(endpoint,iface):
    if not endpoint:return {'state':'unavailable','reason':'入口地址未出现在展开配置中'}
    if endpoint.get('dialer-proxy'):return {'state':'unavailable','reason':'链式代理入口不作直达测量'}
    if not re.fullmatch(r'en\d+',iface or ''):return {'state':'unavailable','reason':'未找到可绑定的物理网卡'}
    server=endpoint.get('server','')
    if not isinstance(server,str) or len(server)>253:return {'state':'unavailable','reason':'入口地址格式不支持'}
    if public_ipv4(server):addresses=[server]
    else:
        try:socket.inet_pton(socket.AF_INET6,server);return {'state':'unavailable','reason':'当前入口 ICMP 测试仅支持 IPv4'}
        except OSError:pass
        try:host=server.encode('idna').decode('ascii')
        except UnicodeError:return {'state':'unavailable','reason':'入口域名格式不支持'}
        if not re.fullmatch(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?',host):
            return {'state':'unavailable','reason':'入口域名格式不支持'}
        rc,text,_=command(['dig','+time=2','+tries=1','+short',host,'A'],4)
        addresses=[line.strip() for line in text.splitlines() if public_ipv4(line.strip())]
        if not addresses:return {'state':'unavailable','reason':'入口 IPv4 解析失败'}
    address=addresses[0]
    # Ensure a scoped physical route exists. Do not fall back to the TUN path.
    rc,route,_=command(['route','-n','get','-ifscope',iface,address],3)
    if rc!=0 or not re.search(r'interface:\s*'+re.escape(iface)+r'\b',route):
        return {'state':'unavailable','reason':'该入口没有可验证的物理网卡路由'}
    return {'state':'ready','ip':address,'interface':iface,'port':endpoint.get('port'),'resolved_count':len(addresses)}


def parse_ping(rc,out,err):
    summary=re.search(r'(\d+) packets transmitted,\s*(\d+) (?:packets )?received',out)
    if not summary:return {'state':'error','error':'probe_unavailable','label':'ICMP 测试未执行','ms':None,'sent':0,'received':0}
    sent,received=map(int,summary.groups())
    if sent!=1 or received not in (0,1):return {'state':'error','error':'invalid_summary','label':'ICMP 统计不可用','ms':None,'sent':0,'received':0}
    timing=re.search(r'time[=<]\s*([\d.]+)\s*ms',out)
    if not timing:
        timing=re.search(r'(?:round-trip|rtt).*?=\s*[\d.]+/([\d.]+)/',out)
    return {'state':'ok' if received else 'fail','error':None if received else 'no_reply',
            'label':'回包' if received else '未回包','ms':float(timing.group(1)) if timing else None,'sent':sent,'received':received}


def icmp_deadline_command(args, timeout):
    """Darwin ping6 has no timeout flag; SIGINT requests its packet summary."""
    try:
        process=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:out,err=process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.send_signal(signal.SIGINT)
            try:out,err=process.communicate(timeout=.75)
            except subprocess.TimeoutExpired:
                process.kill();out,err=process.communicate()
        return process.returncode,out[:240000],err[:1500]
    except (OSError,ValueError) as e:return 127,'',type(e).__name__


def icmp_sample(ingress,timeout_ms=1500):
    if ingress.get('state')!='ready':
        return {'state':'skipped','label':ingress.get('reason','入口不可用'),'error':'ingress_unavailable','ms':None,'sent':0,'received':0}
    seconds=timeout_ms/1000
    if ':' in ingress['ip']:
        args=['/sbin/ping6','-n','-B',ingress['interface'],'-c','1']
        if ipaddress.ip_address(ingress['ip']).is_link_local:args.extend(['-I',ingress['interface']])
        rc,out,err=icmp_deadline_command(args+[ingress['ip']],seconds)
    else:
        rc,out,err=command(['/sbin/ping','-n','-b',ingress['interface'],'-c','1','-W',str(timeout_ms),'-t',str(math.ceil(seconds)),ingress['ip']],seconds+1)
    result=parse_ping(rc,out,err)
    if result['state']=='ok' and result.get('ms') is not None and result['ms']>timeout_ms:
        result.update(state='fail',error='timeout',label='超时',ms=None,received=0)
    return result


def https_sample(name,target,timeout):
    started=time.monotonic()
    result=mihomo('/proxies/'+urllib.parse.quote(name,safe='')+'/delay?'+urllib.parse.urlencode({
        'url':STABILITY_TARGETS[target]['url'],'timeout':timeout,'expected':STABILITY_TARGETS[target]['expected']}),timeout/1000+2)
    delay=result.get('delay')
    wall=round((time.monotonic()-started)*1000)
    if type(delay) in (int,float) and math.isfinite(delay) and delay>=0:
        return {'state':'ok','ms':delay,'wall_ms':wall,'error':None,'label':'HTTPS 已响应' if STABILITY_TARGETS[target].get('kind') else '完成',
                'http_status':None,'measurement':'mihomo_https_response'}
    # Transport to localhost failed => no node-level sample, never report as packet loss.
    if (result.get('_error') and not result.get('_status')) or result.get('_status') in (400,401,403,404,429):
        return {'state':'error','ms':None,'wall_ms':wall,'error':'local_api','label':'本机控制接口不可用'}
    if result.get('_status') not in (503,504):
        return {'state':'error','ms':None,'wall_ms':wall,'error':'local_api','label':'无效控制器响应'}
    message=str(result.get('message') or result.get('_message') or result.get('_error') or '')
    timeout_error='timeout' in message.lower() or result.get('_status')==504
    return {'state':'fail','ms':None,'wall_ms':wall,'error':'timeout' if timeout_error else 'connection_error',
            'label':'超时' if timeout_error else '连接失败'}


def metric_summary(samples,kind):
    records=[s.get(kind,{}) for s in samples if s.get(kind,{}).get('state') in ('ok','fail')]
    ok=[r for r in records if r['state']=='ok'];fail=len(records)-len(ok)
    lat=[r['ms'] for r in ok if isinstance(r.get('ms'),(int,float))]
    diffs=[];prev=None;streak=0;longest=0
    for s in samples:
        r=s.get(kind,{})
        if r.get('state')=='fail':streak+=1;longest=max(longest,streak);prev=None
        elif r.get('state')=='ok':
            streak=0;ms=r.get('ms')
            if isinstance(ms,(int,float)) and prev is not None:diffs.append(abs(ms-prev))
            prev=ms if isinstance(ms,(int,float)) else None
        else:prev=None;streak=0
    ordered=sorted(lat)
    return {'tested':len(records),'ok':len(ok),'failed':fail,
            'failure_pct':round(fail/len(records)*100,1) if records else None,
            'p50_ms':round(statistics.median(lat),1) if lat else None,
            'p95_ms':round(ordered[math.ceil(.95*len(ordered))-1],1) if lat else None,
            'jitter_ms':round(statistics.mean(diffs),1) if diffs else None,
            'max_failure_streak':longest,
            'errors':sum(s.get(kind,{}).get('state')=='error' for s in samples),
            'skipped':sum(s.get(kind,{}).get('state')=='skipped' for s in samples)}


def job_view(include_history=True):
    with STABILITY_LOCK:
        if not STABILITY_JOB:return {'job':None,'history':copy.deepcopy(STABILITY_HISTORY[-120:]) if include_history else [],'history_included':include_history}
        job=copy.deepcopy(STABILITY_JOB)
    for row in job['rows']:
        row['https']=metric_summary(row['samples'],'https')
        row['icmp']=metric_summary(row['samples'],'icmp')
    return {'job':job,'history':copy.deepcopy(STABILITY_HISTORY[-120:]) if include_history else [],'history_included':include_history}


def stability_view(include_history=True):
    """Public read path: raw job_view remains cheap for the worker/persistence."""
    data = job_view(include_history)
    checked = []
    def read_context_once():
        if not checked:
            try: checked.append(context_fingerprint()[0])
            except RuntimeError: checked.append(None)
        return checked[0]
    if data.get('job'):
        data['job']['validity'] = result_validity(data['job'], read_context_once)
    for job in data.get('history', []):
        job['validity'] = result_validity(job, read_context_once)
    return data


def stability_worker(options,context,iface,endpoints):
    global STABILITY_LAST_START
    try:
        if endpoints and options['mode'] in ('icmp','both'):
            with STABILITY_LOCK:STABILITY_JOB['phase']='resolving'
            ingress_cache={}
            for row in STABILITY_JOB['rows']:
                if STABILITY_CANCEL.is_set():break
                ep=endpoints.get(row['name']);key=json.dumps(ep,sort_keys=True)
                if key not in ingress_cache:ingress_cache[key]=resolve_ingress(ep,iface)
                with STABILITY_LOCK:row['ingress']=copy.deepcopy(ingress_cache[key])
        for round_idx in range(1,options['rounds']+1):
            if STABILITY_CANCEL.is_set():break
            try:new_context,_=context_fingerprint()
            except RuntimeError:
                with STABILITY_LOCK:STABILITY_JOB.update(state='interrupted',reason='Mihomo 连接已中断')
                break
            if context!=new_context:
                with STABILITY_LOCK:STABILITY_JOB.update(state='interrupted',reason='网络或配置已改变；本轮保留为独立样本')
                break
            with STABILITY_LOCK:STABILITY_JOB.update(phase='testing',round=round_idx)
            # ICMP probes shared by identical entrance IP, once per round.
            ping_cache={}
            if options['mode'] in ('icmp','both'):
                for row in STABILITY_JOB['rows']:
                    if STABILITY_CANCEL.is_set():break
                    ing=row.get('ingress',{});key=(ing.get('ip'),ing.get('interface'))
                    if key not in ping_cache:ping_cache[key]=icmp_sample(ing,options['timeout_ms'])
            names=options['nodes']
            shift=(round_idx-1)%len(names)
            rotated=names[shift:]+names[:shift]
            def measure(name):
                if STABILITY_CANCEL.is_set():return name,None
                sample={'round':round_idx,'at':now()}
                if options['mode'] in ('https','both'):
                    sample['https']=https_sample(name,options['target'],options['timeout_ms'])
                if options['mode'] in ('icmp','both'):
                    row=next(r for r in STABILITY_JOB['rows'] if r['name']==name);ing=row.get('ingress',{})
                    sample['icmp']=copy.deepcopy(ping_cache.get((ing.get('ip'),ing.get('interface')),{'state':'skipped','ms':None,'label':'已停止'}))
                return name,sample
            # Bounded dispatch: only concurrency active futures, not 500 pending requests.
            # Stop never drains a pre-filled all-node queue. Check context periodically
            # even during a long first round, not only at round boundaries.
            concurrency=options.get('concurrency',2)
            node_iter=iter(rotated);rows_by_name={r['name']:r for r in STABILITY_JOB['rows']}
            last_context=time.monotonic(); local_unavailable=False
            with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
                pending={}
                def fill():
                    while len(pending)<concurrency and not STABILITY_CANCEL.is_set():
                        n=next(node_iter,None)
                        if n is None:break
                        pending[ex.submit(measure,n)]=n
                    with STABILITY_LOCK:STABILITY_JOB['active_nodes']=list(pending.values())
                fill()
                while pending:
                    finished,_=concurrent.futures.wait(pending,timeout=.25,return_when=concurrent.futures.FIRST_COMPLETED)
                    for f in finished:
                        pending.pop(f,None);name,sample=f.result()
                        if sample is not None:
                            with STABILITY_LOCK:
                                row=rows_by_name[name]
                                row['samples'].append(sample);row['samples'].sort(key=lambda s:s['round'])
                                STABILITY_JOB['completed']+=1
                            if sample.get('https',{}).get('error')=='local_api':local_unavailable=True
                    if local_unavailable:
                        with STABILITY_LOCK:STABILITY_JOB.update(state='interrupted',reason='本机控制接口不可用；未计入节点失败率')
                        STABILITY_CANCEL.set()
                    if time.monotonic()-last_context>=8 and not STABILITY_CANCEL.is_set():
                        try:current_context,_=context_fingerprint()
                        except RuntimeError:current_context=None
                        if current_context!=context:
                            with STABILITY_LOCK:STABILITY_JOB.update(state='interrupted',reason='网络或配置已改变；停止后续探测')
                            STABILITY_CANCEL.set()
                        last_context=time.monotonic()
                    fill()
            if any(s.get('https',{}).get('error')=='local_api' for r in STABILITY_JOB['rows'] for s in r['samples'][-1:]):
                with STABILITY_LOCK:STABILITY_JOB.update(state='interrupted',reason='本机控制接口不可用；未计入节点失败率')
                break
            if round_idx<options['rounds']:STABILITY_CANCEL.wait(options['interval_ms']/1000)
        if not STABILITY_CANCEL.is_set() and STABILITY_JOB['state'] == 'running':
            try: final_context,_ = context_fingerprint()
            except RuntimeError: final_context = None
            if final_context != context:
                with STABILITY_LOCK:
                    STABILITY_JOB.update(state='interrupted',reason='完成校验发现网络或配置已改变；保留样本，请重新测试')
        with STABILITY_LOCK:
            if STABILITY_JOB['state']=='running':STABILITY_JOB['state']='cancelled' if STABILITY_CANCEL.is_set() else 'done'
    except Exception as e:
        with STABILITY_LOCK:STABILITY_JOB.update(state='interrupted',reason='测试中断：'+type(e).__name__)
    finally:
        try:
            with STABILITY_LOCK:
                STABILITY_JOB.update(finished_at=now(),phase='finished',active_nodes=[])
                saved=job_view()['job'];STABILITY_HISTORY.append(saved);del STABILITY_HISTORY[:-120]
                try:
                    if save_test_history() is False: raise OSError('history write failed')
                except OSError:
                    STABILITY_JOB['persistence']='failed'
                    saved['persistence']='failed'
        finally:
            STABILITY_LAST_START=time.monotonic()
            PROBE_LOCK.release()


def is_immediate_refinement(payload,owner):
    # Explicit subset retry may start without waiting after a cancelled batch.
    # It is a NEW job with new samples/context; the old denominator stays intact.
    with STABILITY_LOCK:
        j=STABILITY_JOB
        if not j or j.get('state') not in ('done','cancelled','interrupted') or STABILITY_OWNER!=owner:return False
        o=j.get('options',{})
        names=payload.get('nodes')
        allowed={r.get('name') for r in j.get('rows',[])}|{o.get('baseline')}
        retry = payload.get('purpose') == 'retry'
        if retry:
            allowed.discard(None)
            # Same measurement budget/transport, no arbitrary additional nodes.
            if (payload.get('rounds',5)!=o.get('rounds') or
                payload.get('mode','https')!=o.get('mode')): return False
            limit=MAX_BATCH_NODES
        else:
            if j.get('state') != 'done' or payload.get('purpose') not in ('refine','confirm'):return False
            limit=11
        return (payload.get('parent_id')==j.get('id') and payload.get('target')==o.get('target') and
                payload.get('group','')==o.get('group','') and payload.get('timeout_ms',5000)==o.get('timeout_ms',5000) and
                isinstance(names,list) and bool(names) and len(names)<=limit and
                all(isinstance(n,str) and n in allowed for n in names))


def start_stability(payload,owner):
    global STABILITY_JOB,STABILITY_OWNER,STABILITY_LAST_START
    if time.monotonic()-STABILITY_LAST_START<10 and not is_immediate_refinement(payload,owner):
        raise ValueError('请间隔 10 秒再开始新测试')
    if not PROBE_LOCK.acquire(False):raise RuntimeError('已有诊断或节点测试正在运行')
    try:
        cat=stability_catalog();options=validate_stability(payload,cat)
        context,iface=context_fingerprint()
        if options['mode'] in ('icmp','both') and sys.platform!='darwin':raise ValueError('入口 ICMP 当前需要 macOS 助手')
        if payload.get('consent') is not True:raise ValueError('请确认开始主动测试')
        eps=proxy_endpoints(read_text(BASE/'clash-verge.yaml'))
        with STABILITY_LOCK:
            STABILITY_OWNER=owner;STABILITY_CANCEL.clear()
            STABILITY_JOB={'id':secrets.token_hex(12),'state':'running','phase':'starting','started_at':now(),'finished_at':None,
                 'options':options,'interface':iface,'context':context,'environment':safe_environment(),'round':0,'completed':0,'total':len(options['nodes'])*options['rounds'],
                 'rows':[{'name':n,'samples':[],'ingress':None,'endpoint_id':endpoint_identity(eps.get(n))} for n in options['nodes']]}
            first=job_view()
        threading.Thread(target=stability_worker,args=(options,context,iface,eps),daemon=True).start()
        return first
    except Exception:
        PROBE_LOCK.release();raise


def cancel_stability(owner,override=False):
    with STABILITY_LOCK:
        if STABILITY_JOB and STABILITY_JOB['state']=='running':
            if owner!=STABILITY_OWNER and not override:raise PermissionError('请在发起测试的页面停止')
            STABILITY_CANCEL.set();STABILITY_JOB['phase']='stopping'
    return job_view()


# V4: persistent batches + a narrowly scoped, separately authorized selector control.
HISTORY_FILE = STATE_DIR / 'node-test-history.json'
CONTROL_LOCK = threading.RLock()
NATIVE_PROMPT_LOCK = threading.Lock()
CONTROL_GRANTS = {}
CONTROL_GENERATIONS = {}  # confirmation plans belong to one permission lifetime
SWITCH_PLANS = {}
LAST_SWITCH = {}

def endpoint_identity(endpoint):
    if not endpoint:return None
    fields={k:endpoint.get(k) for k in ('server','port','dialer-proxy')}
    return hashlib.sha256(json.dumps(fields,sort_keys=True).encode()).hexdigest()[:16]

def safe_environment():
    rc,route,_=command(['route','-n','get','default'],3)
    interface=re.search(r'interface:\s*(\S+)',route)
    gateway=re.search(r'gateway:\s*(\S+)',route)
    conf=mihomo('/configs')
    dns='\n'.join(yaml_block(read_text(BASE/'clash-verge.yaml'),'dns'))
    return {'interface':interface.group(1) if interface else '', 'gateway':gateway.group(1) if gateway else '',
            'mode':conf.get('mode'), 'dns_signature':hashlib.sha256(dns.encode()).hexdigest()[:12]}

def clear_test_history():
    global STABILITY_JOB
    with STABILITY_LOCK:
        if STABILITY_JOB and STABILITY_JOB.get("state")=="running":raise RuntimeError("测试进行中")
        STABILITY_JOB=None;STABILITY_HISTORY.clear();save_test_history()

def load_test_history():
    try:
        if not HISTORY_FILE.exists() or HISTORY_FILE.stat().st_size>32_000_000:return
        entries=json.loads(HISTORY_FILE.read_text())
        if not isinstance(entries,list):return
        valid=[]
        for j in entries[-120:]:
            if not isinstance(j,dict) or not isinstance(j.get('id'),str):continue
            if j.get('state') not in ('done','cancelled','interrupted'):continue
            if not isinstance(j.get('rows'),list) or len(j['rows'])>MAX_BATCH_NODES:continue
            if age_seconds(j.get('started_at'))>30*86400:continue
            if not all(isinstance(r,dict) and isinstance(r.get('samples'),list) and len(r['samples'])<=20 for r in j['rows']):continue
            valid.append(j)
        with STABILITY_LOCK:STABILITY_HISTORY[:]=valid
    except (OSError,ValueError,TypeError):pass

def save_test_history():
    # Called only with helper-owned data. Never store auth tokens, subscription URLs or API keys.
    try:
        STATE_DIR.mkdir(parents=True,exist_ok=True);os.chmod(STATE_DIR,0o700)
        entries=[j for j in STABILITY_HISTORY[-120:] if age_seconds(j.get('started_at'))<=30*86400]
        text=json.dumps(entries,ensure_ascii=False)
        while len(text.encode())>24_000_000 and entries:
            entries=entries[1:];text=json.dumps(entries,ensure_ascii=False)
        STABILITY_HISTORY[:]=entries
        temp=HISTORY_FILE.with_suffix('.tmp')
        fd=os.open(temp,os.O_CREAT|os.O_TRUNC|os.O_WRONLY,0o600)
        with os.fdopen(fd,'w') as f:f.write(text)
        os.chmod(temp,0o600);os.replace(temp,HISTORY_FILE)
        return True
    except OSError:return False

def native_control_prompt(origin):
    if sys.platform!='darwin':return False
    message=('允许这个网站在 15 分钟内切换 Mihomo 策略组吗？\n\n'+origin+
             '\n\n每次切换仍需在页面确认。仅能更改一个手动策略组的选择；不重启 Clash、不清理连接、不更改 DNS。')
    script='on run argv\n display dialog (item 1 of argv) with title "网络状态台 · 节点控制授权" buttons {"取消", "允许 15 分钟"} default button "取消" cancel button "取消" with icon caution\nend run'
    try:return subprocess.run(['/usr/bin/osascript','-e',script,message],capture_output=True,timeout=90).returncode==0
    except (OSError,subprocess.TimeoutExpired):return False

def control_status(owner):
    with CONTROL_LOCK:
        remaining=max(0,int(CONTROL_GRANTS.get(owner,0)-time.time()))
        return {'enabled':remaining>0,'expires_in':remaining,'last_action':copy.deepcopy(LAST_SWITCH.get(owner)),
                'capability':'selector-only','native_prompt':True}

def revoke_control(owner):
    """End one control lifetime; old confirmations never survive reauthorization."""
    with CONTROL_LOCK:
        CONTROL_GRANTS.pop(owner, None)
        CONTROL_GENERATIONS[owner] = CONTROL_GENERATIONS.get(owner, 0) + 1
        for key in list(SWITCH_PLANS):
            if SWITCH_PLANS[key]['owner'] == owner:
                del SWITCH_PLANS[key]


def require_control(owner):
    with AUTH_LOCK:
        cleanup_auth()
        if owner not in SESSIONS:
            raise PermissionError('页面会话已失效，请重新连接')
        if not control_status(owner)['enabled']:
            raise PermissionError('节点控制未授权或已到期，请先授权')

def authorize_control(owner,origin,payload):
    if payload.get('consent') is not True:raise ValueError('请先确认开启节点控制')
    if not NATIVE_PROMPT_LOCK.acquire(False):raise RuntimeError('请先处理 Mac 上的授权窗口')
    try:
        with CONTROL_LOCK:
            generation = CONTROL_GENERATIONS.get(owner, 0)
        if not native_control_prompt(origin):raise PermissionError('未获得 Mac 本机授权')
        with AUTH_LOCK:
            cleanup_auth();session=SESSIONS.get(owner)
            if not session or session['origin']!=origin:raise PermissionError('页面会话已失效')
            with CONTROL_LOCK:
                if generation != CONTROL_GENERATIONS.get(owner, 0):
                    raise PermissionError('授权请求已撤销，请重新发起')
                revoke_control(owner)
                CONTROL_GRANTS[owner]=time.time()+900
        return control_status(owner)
    finally:NATIVE_PROMPT_LOCK.release()

def build_switch_plan(owner,payload):
    require_control(owner)
    if PROBE_LOCK.locked():raise RuntimeError('请先停止当前诊断或测试')
    raw=mihomo('/proxies');proxies=raw.get('proxies',{})
    if raw.get('_error'):raise RuntimeError('无法读取策略组')
    undo=payload.get('undo') is True
    last=LAST_SWITCH.get(owner) if undo else None
    if undo:
        if not last or not last.get('verified') or last.get('undone'):raise ValueError('没有可恢复的切换')
        group,target=last['group'],last['from']
    else:group,target=payload.get('group'),payload.get('node')
    if not all(isinstance(x,str) and 0<len(x)<=300 for x in (group,target)):raise ValueError('策略组或节点无效')
    g=proxies.get(group,{})
    if str(g.get('type','')).lower()!='selector':raise ValueError('只支持手动选择策略组')
    if target not in g.get('all',[]):raise ValueError('节点不是该策略组的直接成员')
    previous=g.get('now')
    if target==previous:raise ValueError('当前已选中这个节点')
    if undo:
        if previous!=last['to']:raise RuntimeError('策略组已被其他操作修改，不能恢复旧选择')
    elif target not in proxies or 'all' in proxies[target] or target in ('DIRECT','REJECT','PASS','COMPATIBLE'):
        raise ValueError('请从候选列表选择实际代理节点')
    related=[]
    for name,item in proxies.items():
        if 'all' in item and group in selected_chain(name,proxies):related.append(name)
    data=snapshot(True)
    dns_refs=[]
    dns=data.get('dns',{})
    for role in ('upstreams','bootstrap','proxy_server','direct','fallback'):
        for endpoint in (dns.get(role) or []):
            if isinstance(endpoint,str) and '#' in endpoint:
                policy=endpoint.rsplit('#',1)[-1].split('&',1)[0]
                if group in selected_chain(policy,proxies):dns_refs.append({'role':role,'endpoint':safe_dns(endpoint)})
    for pattern,values in (dns.get('policy') or {}).items():
        for endpoint in values if isinstance(values,list) else [values]:
            if isinstance(endpoint,str) and '#' in endpoint and group in selected_chain(endpoint.rsplit('#',1)[-1].split('&',1)[0],proxies):
                dns_refs.append({'role':'policy:'+str(pattern),'endpoint':safe_dns(endpoint)})
    context,_=context_fingerprint()
    return {'group':group,'from':previous,'to':target,'affected_groups':sorted(related), 'dns_dependencies':dns_refs,
            'unchanged_groups':[n for n in ('Claude','Gemini','Chatgpt','🔰 手动选择') if n in proxies and n not in related],
            'context':context,'undo':undo,'mode':data.get('clash',{}).get('mode')}

def preview_switch(owner,payload):
    with CONTROL_LOCK:
        generation = CONTROL_GENERATIONS.get(owner, 0)
    plan=build_switch_plan(owner,payload)
    with AUTH_LOCK:
        require_control_session = SESSIONS.get(owner)
        if not require_control_session or require_control_session['until'] <= time.time():
            raise PermissionError('页面会话已失效，请重新连接')
        with CONTROL_LOCK:
            if generation != CONTROL_GENERATIONS.get(owner, 0) or CONTROL_GRANTS.get(owner,0) <= time.time():
                raise PermissionError('控制授权已改变，请重新预览')
            for key in list(SWITCH_PLANS):
                if SWITCH_PLANS[key]['until']<time.time():del SWITCH_PLANS[key]
            if len(SWITCH_PLANS)>=40:raise RuntimeError('待确认操作过多')
            key=secrets.token_urlsafe(24)
            SWITCH_PLANS[key]={'owner':owner,'plan':plan,'until':time.time()+90,'generation':generation}
    return dict(plan,action_id=key,expires_in=90)

def put_selector(group,node):
    c=UnixConnection('localhost',timeout=4)
    try:
        headers={'Content-Type':'application/json'}
        m=re.search(r'^secret:\s*(.+)$',read_text(BASE/'config.yaml'),re.M)
        if m:headers['Authorization']='Bearer '+str(scalar(m.group(1)))
        c.request('PUT','/proxies/'+urllib.parse.quote(group,safe=''),body=json.dumps({'name':node}).encode(),headers=headers)
        response=c.getresponse();response.read(4096)
        if response.status not in (200,204):raise RuntimeError('Mihomo 拒绝切换（HTTP '+str(response.status)+'）')
    except (OSError,http.client.HTTPException):raise RuntimeError('控制连接中断；请刷新确认当前选择后再操作')
    finally:c.close()

def apply_switch(owner,payload):
    require_control(owner)
    if payload.get('confirm') is not True:raise ValueError('请确认本次节点切换')
    key=payload.get('action_id')
    if not isinstance(key,str) or len(key)>100:raise ValueError('操作凭证无效')
    with CONTROL_LOCK:
        record=SWITCH_PLANS.get(key)
        if not record or record['owner']!=owner or record['until']<time.time():raise PermissionError('确认已过期，请重新预览')
        del SWITCH_PLANS[key]
    if not PROBE_LOCK.acquire(False):raise RuntimeError('测试或诊断正在运行，未切换')
    try:
        plan=record['plan'];context,_=context_fingerprint()
        if context!=plan['context']:raise RuntimeError('配置或网络已改变，请重新确认')
        raw=mihomo('/proxies');g=raw.get('proxies',{}).get(plan['group'],{})
        if g.get('now')!=plan['from'] or plan['to'] not in g.get('all',[]):raise RuntimeError('策略组选项已改变，请重新确认')
        if str(g.get('type','')).lower()!='selector':raise ValueError('策略组已不是手动选择类型')
        # Serialize the write with revocation; expensive reads above may outlive a grant.
        # Lock order is AUTH_LOCK -> CONTROL_LOCK throughout the control boundary.
        with AUTH_LOCK:
            session = SESSIONS.get(owner)
            if not session or session['until'] <= time.time():
                raise PermissionError('页面会话已失效，未切换')
            with CONTROL_LOCK:
                if CONTROL_GRANTS.get(owner,0) <= time.time() or record.get('generation') != CONTROL_GENERATIONS.get(owner,0):
                    raise PermissionError('控制授权已失效，未切换')
                put_selector(plan['group'],plan['to'])
        check=mihomo('/proxies/'+urllib.parse.quote(plan['group'],safe=''))
        verified=check.get('now')==plan['to']
        action={'group':plan['group'],'from':plan['from'],'to':plan['to'],'at':now(),'verified':verified,'undone':plan['undo']}
        with CONTROL_LOCK:LAST_SWITCH[owner]=action
        CACHE['at']=0
        return {'applied':True,'verified':verified,'selected':check.get('now'),'action':action,
                'message':'已切换并回读确认' if verified else '已提交，尚未回读确认；请刷新当前选择'}
    finally:PROBE_LOCK.release()


# Continuous monitoring is independent from finite comparison batches. SQLite
# keeps exact lifetime counters while retaining only 24 hours of raw samples.
# Neither page visibility nor the lifetime of its pairing token drives this loop.
MONITOR_LOCK = threading.RLock()
MONITOR_READ_LOCK = threading.Lock()
MONITOR_CANCEL = threading.Event()
MONITOR_JOB = None
MONITOR_OWNER_ORIGIN = None
MONITOR_DB_PATH = STATE_DIR / 'node-monitor.sqlite3'
MONITOR_INITIALIZED_PATH = None
MONITOR_VIEW_CACHE = {}
MONITOR_LAST_START = 0.0
MONITOR_STARTING = False
MONITOR_RAW_SECONDS = 86400
MONITOR_RAW_LIMIT = 3_000_000
MONITOR_STATES = {None: 0, 'ok': 1, 'fail': 2, 'error': 3, 'skipped': 4}
MONITOR_ICMP_INTERVALS = (1,2,5,10,15,30,60,300)
MONITOR_ICMP_CONCURRENCY = (2,4,8,16,32,64,128,256)
MONITOR_ICMP_TIMEOUTS = (1000,2000,3000,5000,8000)


def monitor_iso(stamp):
    return datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).isoformat(timespec='milliseconds')


def monitor_timestamp(value):
    try:return datetime.datetime.fromisoformat(value).timestamp()
    except (ValueError,TypeError,OverflowError):return 0.0


@contextlib.contextmanager
def monitor_db():
    MONITOR_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(MONITOR_DB_PATH.parent, 0o700)
    db = sqlite3.connect(MONITOR_DB_PATH, timeout=10)
    try:
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('PRAGMA busy_timeout=10000')
        db.execute('PRAGMA max_page_count=131072')  # 512 MiB at the normal 4 KiB page size.
        with db:yield db
    finally:db.close()


def monitor_empty_metric():
    return {'tested':0,'ok':0,'failed':0,'errors':0,'skipped':0,'failure_pct':None,
            'max_failure_streak':0,'current_failure_streak':0,'max_failure_span_seconds':0,
            'last_state':None,'mean_ms':None,'latency_count':0,'latency_sum':0,
            'streak_started_at':None,'last_sample_at':None,'last_ms':None,'min_ms':None,
            'avg_ms':None,'max_ms':None,'last_ok_at':None,'last_fail_at':None,'last_label':None}


def monitor_metric_add(summary, result, stamp, gap=False):
    state = result.get('state')
    if gap or state not in ('ok','fail'):
        summary['current_failure_streak']=0;summary['streak_started_at']=None
    if state in ('ok','fail'):
        summary['tested']+=1;summary['ok' if state=='ok' else 'failed']+=1
        summary['failure_pct']=round(100*summary['failed']/summary['tested'],3)
    elif state in ('error','skipped'):
        summary['errors' if state=='error' else 'skipped']+=1
    if state=='fail':
        summary['last_fail_at']=monitor_iso(stamp)
        if not summary['current_failure_streak']:summary['streak_started_at']=stamp
        summary['current_failure_streak']+=1
        summary['max_failure_streak']=max(summary['max_failure_streak'],summary['current_failure_streak'])
        summary['max_failure_span_seconds']=max(summary['max_failure_span_seconds'], max(0,stamp-(summary['streak_started_at'] or stamp)))
    elif state=='ok':
        summary['last_ok_at']=monitor_iso(stamp)
        summary['current_failure_streak']=0;summary['streak_started_at']=None
        ms=result.get('ms')
        if type(ms) in (int,float) and math.isfinite(ms) and ms>=0:
            summary['latency_count']+=1;summary['latency_sum']+=ms
            summary['mean_ms']=round(summary['latency_sum']/summary['latency_count'],1)
            summary['avg_ms']=summary['mean_ms']
            summary['min_ms']=min(summary.get('min_ms') if summary.get('min_ms') is not None else ms,ms)
            summary['max_ms']=max(summary.get('max_ms') if summary.get('max_ms') is not None else ms,ms)
    if state:
        summary['last_state']=state;summary['last_sample_at']=monitor_iso(stamp)
        value=result.get('ms')
        summary['last_ms']=value if state=='ok' and type(value) in (int,float) and math.isfinite(value) and value>=0 else None
        summary['last_label']=str(result.get('label') or '')[:160] or None


def monitor_public_metric(summary):
    return {k:v for k,v in (monitor_empty_metric()|summary).items() if k not in ('latency_count','latency_sum','streak_started_at')}


def monitor_session_metadata(job):
    with MONITOR_LOCK:
        return {k:copy.deepcopy(v) for k,v in job.items() if k not in ('rows','owner_origin','revision','owns_probe_lock','_node_index')}


def monitor_update_job(job,*,increments=None,**changes):
    """Publish related metadata together; snapshots cannot observe half an update."""
    with MONITOR_LOCK:
        for key,amount in (increments or {}).items():job[key]=job.get(key,0)+amount
        job.update(changes)
        return job.get('round',0)


def monitor_persist_session(job):
    with MONITOR_LOCK:
        data = monitor_session_metadata(job)
        identity=job['id'];started=monitor_timestamp(job['started_at']);origin=job.get('owner_origin','')
        rows=copy.deepcopy(job['rows'])
    with monitor_db() as db:
        db.execute('INSERT INTO monitor_session(id,started,data,owner_origin) VALUES(?,?,?,?) '
                   'ON CONFLICT(id) DO UPDATE SET data=excluded.data',
                   (identity,started,json.dumps(data,ensure_ascii=False),origin))
        for index,row in enumerate(rows):
            db.execute('INSERT INTO monitor_total(session_id,node_index,data) VALUES(?,?,?) '
                       'ON CONFLICT(session_id,node_index) DO NOTHING',
                       (identity,index,json.dumps(row,ensure_ascii=False)))


def load_monitor_history():
    global MONITOR_INITIALIZED_PATH,MONITOR_JOB,MONITOR_OWNER_ORIGIN
    with MONITOR_LOCK:
        path=str(MONITOR_DB_PATH.resolve())
        if MONITOR_INITIALIZED_PATH==path:return
        with monitor_db() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('PRAGMA journal_size_limit=8388608')
            db.executescript('''
                CREATE TABLE IF NOT EXISTS monitor_session(id TEXT PRIMARY KEY,started REAL,data TEXT,owner_origin TEXT);
                CREATE TABLE IF NOT EXISTS monitor_total(session_id TEXT,node_index INTEGER,data TEXT,
                    PRIMARY KEY(session_id,node_index),FOREIGN KEY(session_id) REFERENCES monitor_session(id) ON DELETE CASCADE);
                CREATE TABLE IF NOT EXISTS monitor_sample(session_id TEXT,node_index INTEGER,ts REAL,round INTEGER,
                    h_state INTEGER,h_ms REAL,i_state INTEGER,i_ms REAL,gap_before INTEGER,h_ts REAL,i_ts REAL,
                    FOREIGN KEY(session_id) REFERENCES monitor_session(id) ON DELETE CASCADE);
                CREATE INDEX IF NOT EXISTS monitor_samples_node_time ON monitor_sample(session_id,node_index,ts);
                CREATE INDEX IF NOT EXISTS monitor_samples_time ON monitor_sample(ts);
                CREATE TABLE IF NOT EXISTS monitor_meta(key TEXT PRIMARY KEY,value REAL);
            ''')
            columns={row[1] for row in db.execute('PRAGMA table_info(monitor_sample)')}
            if 'i_address' not in columns:db.execute('ALTER TABLE monitor_sample ADD COLUMN i_address TEXT')
            for identity,text in db.execute('SELECT id,data FROM monitor_session').fetchall():
                record=json.loads(text)
                if record.get('state')=='running':
                    rows=[json.loads(r[0]) for r in db.execute('SELECT data FROM monitor_total WHERE session_id=?',(identity,))]
                    actual=[r.get('last_sample_at') for r in rows if r.get('last_sample_at')]
                    latest=max(actual,key=monitor_timestamp) if actual else record.get('last_sample_at') or record['started_at']
                    kind='icmp' if record['options']['mode']=='icmp' else 'https'
                    record['completed_samples']=sum(sum(r[kind].get(s,0) for s in ('tested','errors','skipped')) for r in rows)
                    record.update(state='interrupted',phase='finished',reason='本机助手已重启，记录已保留',last_sample_at=latest if actual else record.get('last_sample_at'),finished_at=latest,next_sample_at=None)
                    db.execute('UPDATE monitor_session SET data=? WHERE id=?',(json.dumps(record,ensure_ascii=False),identity))
            latest=db.execute('SELECT id FROM monitor_session ORDER BY started DESC LIMIT 1').fetchone()
        os.chmod(MONITOR_DB_PATH,0o600)
        MONITOR_INITIALIZED_PATH=path;MONITOR_VIEW_CACHE.clear()
        MONITOR_JOB=monitor_load_session(latest[0]) if latest else None
        MONITOR_OWNER_ORIGIN=MONITOR_JOB.get('owner_origin') if MONITOR_JOB else None
        monitor_prune(time.time())


def monitor_load_session(identity,connection=None):
    with contextlib.nullcontext(connection) if connection is not None else monitor_db() as db:
        item=db.execute('SELECT data,owner_origin FROM monitor_session WHERE id=?',(identity,)).fetchone()
        if not item:return None
        job=json.loads(item[0]);job['owner_origin']=item[1]
        job['rows']=[json.loads(x[0]) for x in db.execute('SELECT data FROM monitor_total WHERE session_id=? ORDER BY node_index',(identity,))]
    job['completed_samples']=sum(sum(r[k].get(s,0) for s in ('tested','errors','skipped')) for r in job['rows'] for k in [ 'icmp' if job['options']['mode']=='icmp' else 'https' ])
    stamps=[r.get('last_sample_at') for r in job['rows'] if r.get('last_sample_at')]
    if stamps:job['last_sample_at']=max(stamps,key=monitor_timestamp)
    job['revision']=0
    job.setdefault('last_round_seconds',None)
    return job


def monitor_prune(stamp):
    with MONITOR_LOCK:return monitor_prune_locked(stamp)


def monitor_prune_locked(stamp):
    # Keep a small grace period so a cached rolling snapshot still has every
    # matching raw record when the user selects another timeline node.
    cutoff=monitor_timestamp(monitor_iso(stamp))-MONITOR_RAW_SECONDS-30
    with monitor_db() as db:
        deleted=db.execute('DELETE FROM monitor_sample WHERE ts<?',(cutoff,)).rowcount
        count=db.execute('SELECT COUNT(*) FROM monitor_sample').fetchone()[0]
        truncated=count>MONITOR_RAW_LIMIT
        if count>MONITOR_RAW_LIMIT:
            excess=count-MONITOR_RAW_LIMIT
            boundary=db.execute('SELECT ts FROM monitor_sample ORDER BY ts,rowid LIMIT 1 OFFSET ?',(excess-1,)).fetchone()[0]
            db.execute('DELETE FROM monitor_sample WHERE rowid IN (SELECT rowid FROM monitor_sample ORDER BY ts,rowid LIMIT ?)',(excess,))
            cutoff=max(cutoff,boundary+0.001)
        db.execute('INSERT INTO monitor_meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=MAX(value,excluded.value)',('retained_after',cutoff))
        removed=db.execute('DELETE FROM monitor_session WHERE id NOT IN (SELECT id FROM monitor_session ORDER BY started DESC LIMIT 12)').rowcount
    if truncated or removed:MONITOR_VIEW_CACHE.clear()
    elif deleted:
        for identity in list(MONITOR_VIEW_CACHE):
            if MONITOR_VIEW_CACHE[identity].get('state')!='running':MONITOR_VIEW_CACHE.pop(identity,None)


def monitor_record_sample(job,name,sample,round_index,gap=False):
    monitor_record_samples(job,[(name,sample)],round_index,gap)


def monitor_record_samples(job,records,round_index,gap=False):
    """Commit a complete bounded wave and publish its counters only after success."""
    if not records:return
    with MONITOR_LOCK:
        indices=job.setdefault('_node_index',{name:i for i,name in enumerate(job['options']['nodes'])})
        changed={};inserts=[];latest=job.get('last_sample_at')
        for name,sample in records:
            stamp=monitor_timestamp(sample['at']);index=indices[name]
            row=changed.setdefault(index,copy.deepcopy(job['rows'][index]))
            sample_gap=bool(sample.get('gap_before',gap))
            for kind in ('https','icmp'):
                if kind in sample:monitor_metric_add(row[kind],sample[kind],monitor_timestamp(sample[kind].get('at')) or stamp,sample_gap)
            row['last_sample_at']=sample['at']
            if sample.get('address'):
                row['address']=sample['address'];row['interface']=sample.get('interface');row['measurement_key']=sample.get('measurement_key')
            values=[]
            for kind in ('https','icmp'):
                result=sample.get(kind,{});ms=result.get('ms')
                values.extend([MONITOR_STATES.get(result.get('state'),3),ms if type(ms) in (int,float) and math.isfinite(ms) and ms>=0 else None])
            observed=[monitor_timestamp(sample.get(k,{}).get('at')) or stamp if k in sample else None for k in ('https','icmp')]
            inserts.append((job['id'],index,stamp,sample.get('round',round_index),*values,int(sample_gap),*observed,sample.get('address')))
            if not latest or stamp>=monitor_timestamp(latest):latest=sample['at']
        with monitor_db() as db:
            db.executemany('INSERT INTO monitor_sample(session_id,node_index,ts,round,h_state,h_ms,i_state,i_ms,gap_before,h_ts,i_ts,i_address) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',inserts)
            db.executemany('UPDATE monitor_total SET data=? WHERE session_id=? AND node_index=?',[(json.dumps(row,ensure_ascii=False),job['id'],index) for index,row in changed.items()])
        for index,row in changed.items():job['rows'][index]=row
        job['completed_samples']+=len(records);job['last_sample_at']=latest;job['revision']=job.get('revision',0)+1


def normalize_monitor_address(host):
    if not isinstance(host,str) or not host or len(host)>253 or any(ord(c)<33 or ord(c)==127 for c in host):
        raise ValueError('请输入 IP 或域名')
    if any(c in host for c in '/@%\\[]') or host.startswith('-'):raise ValueError('地址只能包含 IP 或域名')
    try:
        address=ipaddress.ip_address(host)
        mapped=address.ipv4_mapped if address.version==6 else None
        check=mapped or address
        if check.is_multicast or check.is_unspecified or (check.version==4 and (check.is_reserved or int(check)==0xffffffff)):
            raise ValueError('请使用单个主机的 IP 地址')
        return address.compressed
    except ValueError as error:
        if ':' in host or re.fullmatch(r'[\d.]+',host):raise ValueError('IP 地址格式不正确') from error
    try:ascii_host=host.rstrip('.').encode('idna').decode('ascii').lower()
    except UnicodeError:raise ValueError('域名格式不正确')
    if not ascii_host or len(ascii_host)>253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',part) for part in ascii_host.split('.')):
        raise ValueError('域名格式不正确')
    return ascii_host


def validate_monitor(payload,catalog=None):
    source=payload.get('source','nodes');mode=payload.get('mode','icmp' if source=='addresses' else 'https')
    if source not in ('nodes','addresses'):raise ValueError('未知地址来源')
    icmp=mode=='icmp';interval=payload.get('interval_seconds',5 if icmp else 60);duration=payload.get('duration_seconds',0 if icmp else 7200)
    intervals=MONITOR_ICMP_INTERVALS if icmp else (15,30,60,300)
    if type(interval) is not int or interval not in intervals:raise ValueError('请选择列表中的探测间隔')
    if type(duration) is not int or duration not in (0,1800,7200,28800,86400):raise ValueError('请选择 30 分钟、2 小时、8 小时、24 小时或直到停止')
    concurrency=payload.get('concurrency',128 if icmp else 4);timeout=payload.get('timeout_ms',1000 if icmp else 5000)
    if icmp and (type(concurrency) is not int or concurrency not in MONITOR_ICMP_CONCURRENCY):raise ValueError('请选择列表中的并发数量')
    if icmp and (type(timeout) is not int or timeout not in MONITOR_ICMP_TIMEOUTS):raise ValueError('请选择列表中的超时时间')
    if source=='addresses':
        if not icmp:raise ValueError('IP / 域名列表使用 ICMP 探测')
        records=payload.get('addresses')
        if not isinstance(records,list) or not records or len(records)>2000:raise ValueError('请添加 1–500 个地址')
        addresses=[];seen=set()
        for record in records:
            if not isinstance(record,dict):raise ValueError('地址格式不正确')
            host=normalize_monitor_address(record.get('host'))
            label=record.get('label',host)
            if not isinstance(label,str) or len(label)>300 or any(ord(c)<32 or ord(c)==127 for c in label):raise ValueError('备注格式不正确')
            if host not in seen:seen.add(host);addresses.append({'host':host,'label':label.strip() or host})
        if len(addresses)>500:raise ValueError('每次最多探测 500 个地址')
        return {'source':source,'addresses':addresses,'nodes':[a['host'] for a in addresses],'group':'','mode':'icmp',
                'target':'cloudflare','timeout_ms':timeout,'concurrency':concurrency,'interval_seconds':interval,'duration_seconds':duration}
    # Reuse catalog/group membership while giving ICMP its own resource limits.
    adjusted={**payload,'rounds':1,'purpose':'custom','parent_id':None}
    if icmp:adjusted.update(timeout_ms=3000,concurrency=4)
    base=validate_stability(adjusted,catalog or {'nodes':[],'groups':{}})
    if base['mode']!='icmp' and STABILITY_TARGETS[base['target']].get('kind') and interval<60:raise ValueError('AI 服务目标的持续探测间隔至少 60 秒')
    if icmp:base.update(concurrency=concurrency,timeout_ms=timeout)
    return {k:v for k,v in base.items() if k not in ('rounds','interval_ms','purpose','parent_id')}|{'source':source,'interval_seconds':interval,'duration_seconds':duration}


def monitor_icmp_context(options):
    """Only the physical path and selected endpoints identify a direct ping run."""
    rc,out,_=command(['route','-n','get','default'],3)
    if rc!=0:rc,out,_=command(['route','-n','get','-inet6','default'],3)
    if rc!=0:raise RuntimeError('无法读取当前网络路由')
    iface=re.search(r'interface:\s*(\S+)',out);gateway=re.search(r'gateway:\s*(\S+)',out)
    interface=iface.group(1) if iface else ''
    if not re.fullmatch(r'en\d+',interface):raise RuntimeError('未找到物理网卡')
    identity={'interface':interface,'gateway':gateway.group(1) if gateway else ''}
    if options.get('source','nodes')=='nodes':
        endpoints=proxy_endpoints(read_text(BASE/'clash-verge.yaml'))
        identity['endpoints']={name:endpoints.get(name) for name in options['nodes']}
    return hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest()[:20],interface


def monitor_direct_ingress(host,iface):
    if not re.fullmatch(r'en\d+',iface or ''):return {'state':'unavailable','reason':'未找到物理网卡'}
    try:host=normalize_monitor_address(host)
    except ValueError:return {'state':'unavailable','reason':'地址格式不正确'}
    try:addresses=[ipaddress.ip_address(host)]
    except ValueError:
        addresses=[]
        for record_type in ('A','AAAA'):
            rc,out,_=command(['dig','+time=2','+tries=1','+short',host,record_type],3)
            for line in out.splitlines():
                try:
                    value=normalize_monitor_address(line.strip());address=ipaddress.ip_address(value)
                    if address not in addresses:addresses.append(address)
                except ValueError:pass
            if addresses:break
        if not addresses:return {'state':'unavailable','reason':'域名解析失败'}
    address=addresses[0];args=['route','-n','get']
    if address.version==6:args.append('-inet6')
    args.extend(['-ifscope',iface,address.compressed])
    rc,route,_=command(args,3)
    if rc!=0 or not re.search(r'interface:\s*'+re.escape(iface)+r'\b',route):
        return {'state':'unavailable','reason':'没有可用的物理网卡路由'}
    return {'state':'ready','ip':address.compressed,'interface':iface,'family':address.version,'resolved_count':len(addresses)}


def monitor_owner_origin(owner):
    with AUTH_LOCK:
        cleanup_auth();session=SESSIONS.get(owner)
        if not session:raise PermissionError('页面会话已失效，请重新连接')
        return session['origin']


def monitor_can_stop(job,owner,override=False):
    if not job or job.get('state')!='running':return False
    if override:return True
    try:return bool(owner and monitor_owner_origin(owner)==job.get('owner_origin'))
    except PermissionError:return False


def monitor_window_summaries(job,anchor,connection=None):
    anchor=monitor_timestamp(monitor_iso(anchor))
    identity=job['id']
    with MONITOR_LOCK:cached=copy.deepcopy(MONITOR_VIEW_CACHE.get(identity))
    # A single grouped SQL query per window, never one scan per node. Cache also
    # bounds polling cost for large subscriptions between finished waves.
    revision=job.get('revision',0)
    if (cached and cached.get('state')==job.get('state') and 0<=anchor-cached['anchor']<15 and
        0<=time.monotonic()-cached.get('computed_at',0)<15 and
        (cached['revision']==revision or job.get('state')=='running' and cached['revision']>0)):
        return cached['rows'],cached['anchor'],cached['watermark']
    result=[{} for _ in job['rows']]
    with contextlib.nullcontext(connection) if connection is not None else monitor_db() as db:
        watermark=db.execute('SELECT COALESCE(MAX(rowid),0) FROM monitor_sample').fetchone()[0]
        retained=db.execute('SELECT value FROM monitor_meta WHERE key=?',('retained_after',)).fetchone()
        retained=retained[0] if retained else anchor-MONITOR_RAW_SECONDS
        for label,duration in (('15m',900),('1h',3600),('24h',86400)):
            start=anchor-duration;needed=max(start,monitor_timestamp(job['started_at']))
            complete=retained<=needed+0.000001
            for windows in result:
                windows[label]={'from':monitor_iso(start),'to':monitor_iso(anchor),'coverage_start':monitor_iso(max(needed,retained)),
                                'complete':complete,'https':monitor_empty_metric(),'icmp':monitor_empty_metric()}
            columns=[]
            for prefix in ('h','i'):
                columns.extend([f'SUM({prefix}_state={state} AND {prefix}_ts>={start!r} AND {prefix}_ts<={anchor!r})' for state in (1,2,3,4)])
                columns.append(f'AVG(CASE WHEN {prefix}_state=1 AND {prefix}_ts>={start!r} AND {prefix}_ts<={anchor!r} THEN {prefix}_ms END)')
            query='SELECT node_index,'+','.join(columns)+' FROM monitor_sample WHERE session_id=? AND ts>=? AND ts<=? GROUP BY node_index'
            for record in db.execute(query,(identity,start,anchor)):
                index=record[0]
                if index>=len(result):continue
                for number,kind in enumerate(('https','icmp')):
                    ok,failed,errors,skipped,mean=record[1+number*5:6+number*5]
                    metric=result[index][label][kind]
                    metric.update(tested=ok+failed,ok=ok,failed=failed,errors=errors,skipped=skipped,
                                  failure_pct=round(100*failed/(ok+failed),3) if ok+failed and complete else None,
                                  mean_ms=round(mean,1) if mean is not None else None,max_failure_streak=None,
                                  current_failure_streak=None,max_failure_span_seconds=None)
                    if start<=monitor_timestamp(job['rows'][index][kind].get('last_sample_at'))<=anchor:
                        metric['last_state']=job['rows'][index][kind].get('last_state')
            for windows in result:
                for kind in ('https','icmp'):windows[label][kind]=monitor_public_metric(windows[label][kind])
    with MONITOR_LOCK:
        MONITOR_VIEW_CACHE[identity]={'revision':revision,'state':job.get('state'),'anchor':anchor,'watermark':watermark,
                                    'computed_at':time.monotonic(),'rows':copy.deepcopy(result)}
        while len(MONITOR_VIEW_CACHE)>12:MONITOR_VIEW_CACHE.pop(next(iter(MONITOR_VIEW_CACHE)))
    return result,anchor,watermark


def monitor_timeline(job,node,anchor,connection=None,watermark=None):
    index=job['options']['nodes'].index(node)
    since=max(monitor_timestamp(job['started_at']),anchor-MONITOR_RAW_SECONDS)
    width=max(60,math.ceil(max(1,anchor-since)/96/60)*60)
    # Anchor buckets at observation start so a short first session is visible.
    count=min(96,max(1,math.ceil(max(1,anchor-since)/width)))
    buckets=[{'at':monitor_iso(since+i*width),'end_at':monitor_iso(min(anchor,since+(i+1)*width)),
              'https':monitor_empty_metric(),'icmp':monitor_empty_metric(),'gaps':0} for i in range(count)]
    states={v:k for k,v in MONITOR_STATES.items()}
    with contextlib.nullcontext(connection) if connection is not None else monitor_db() as db:
        query='SELECT ts,h_state,h_ms,i_state,i_ms,gap_before,h_ts,i_ts FROM monitor_sample WHERE session_id=? AND node_index=? AND ts>=? AND ts<=?'
        args=[job['id'],index,since,anchor]
        if watermark is not None:query+=' AND rowid<=?';args.append(watermark)
        for ts,hs,hm,is_,im,gap,ht,it in db.execute(query+' ORDER BY ts',args):
            for kind,state,ms,observed in (('https',hs,hm,ht),('icmp',is_,im,it)):
                if state and observed is not None and since<=observed<=anchor:
                    bucket=buckets[min(count-1,int((observed-since)//width))]
                    bucket['gaps']+=int(bool(gap))
                    monitor_metric_add(bucket[kind],{'state':states.get(state,'error'),'ms':ms},observed,bool(gap))
    for bucket in buckets:
        for kind in ('https','icmp'):bucket[kind]=monitor_public_metric(bucket[kind])
    return buckets


def monitor_view(owner=None,override=False,session_id=None,node=None):
    try:load_monitor_history()
    except (OSError,sqlite3.Error,ValueError):
        raise RuntimeError('无法读取持续探测记录，请检查本机磁盘空间与文件权限；其他诊断仍可使用')
    # Establish one WAL read snapshot while totals and raw rows are synchronized,
    # then release the worker lock before potentially expensive aggregation.
    # A separate read lock lets simultaneous pages share the rolling cache.
    with MONITOR_READ_LOCK:
        with monitor_db() as db:
            with MONITOR_LOCK:
                db.execute('BEGIN')
                db.execute('SELECT value FROM monitor_meta LIMIT 1').fetchone()
                current=copy.deepcopy(MONITOR_JOB)
            return monitor_view_snapshot(current,db,owner,override,session_id,node)


def monitor_view_snapshot(current,db,owner=None,override=False,session_id=None,node=None):
    job=current if not session_id or (current and current['id']==session_id) else monitor_load_session(session_id,db)
    if session_id and not job:raise ValueError('持续探测记录已不存在')
    active=None
    if current and current.get('state')=='running':
        active={k:current.get(k) for k in ('id','state','options','started_at')}
        active['mode']=current['options']['mode'];active['source']=current['options'].get('source','nodes')
        active['can_stop']=monitor_can_stop(current,owner,override)
    history=[]
    for text, in db.execute('SELECT data FROM monitor_session ORDER BY started DESC LIMIT 12'):
        entry=json.loads(text)
        history.append({k:entry.get(k) for k in ('id','state','started_at','finished_at','last_sample_at','options','completed_samples','reason')})
    if job:
        anchor=time.time() if job.get('state')=='running' else monitor_timestamp(job.get('finished_at') or job['started_at'])
        windows,as_of,watermark=monitor_window_summaries(job,anchor,db)
        selected=node if node in job['options']['nodes'] else job['options']['nodes'][0]
        timeline=monitor_timeline(job,selected,as_of,db,watermark)
        recent=monitor_recent_samples(job,selected,db)
        for index,row in enumerate(job['rows']):
            row['https']=monitor_public_metric(row['https']);row['icmp']=monitor_public_metric(row['icmp'])
            row['windows']=windows[index];row['timeline']=timeline if row['name']==selected else []
            row['recent']=recent if row['name']==selected else monitor_recent_samples(job,row['name'],db)
        job['elapsed_seconds']=max(0,round(anchor-monitor_timestamp(job['started_at']),1))
        job['can_stop']=monitor_can_stop(job,owner,override)
        job['as_of_at']=monitor_iso(as_of);job['timeline_node']=selected
        for private in ('owner_origin','revision','owns_probe_lock','_node_index'):job.pop(private,None)
    return {'monitor':job,'active':active,'history':history,'capabilities':monitor_capabilities()}


def monitor_capabilities():
    return {'continuous_monitor':True,'monitor_parallel':True,'monitor_sources':['nodes','addresses'],
            'icmp_intervals':list(MONITOR_ICMP_INTERVALS),'icmp_concurrency':list(MONITOR_ICMP_CONCURRENCY),
            'icmp_timeouts':list(MONITOR_ICMP_TIMEOUTS)}


def monitor_recent_samples(job,node,db):
    index=job['options']['nodes'].index(node);result=[]
    states={1:'ok',2:'fail',3:'error',4:'skipped'}
    labels={1:'回包',2:'未回包',3:'采集错误',4:'未执行'}
    query='SELECT ts,h_state,h_ms,i_state,i_ms,h_ts,i_ts,i_address FROM monitor_sample WHERE session_id=? AND node_index=? ORDER BY ts DESC,rowid DESC LIMIT 60'
    for stamp,hs,hm,is_,im,ht,it,address in db.execute(query,(job['id'],index)):
        sample={'at':monitor_iso(stamp),'address':address}
        for kind,state,ms,at in (('https',hs,hm,ht),('icmp',is_,im,it)):
            if state and at is not None:sample[kind]={'state':states.get(state,'error'),'ms':ms if state==1 else None,'at':monitor_iso(at),'label':labels.get(state,'采集错误')}
        result.append(sample)
    return result


def start_monitor(payload,owner):
    global MONITOR_JOB,MONITOR_OWNER_ORIGIN,MONITOR_LAST_START,MONITOR_STARTING
    load_monitor_history()
    origin=monitor_owner_origin(owner)
    with MONITOR_LOCK:
        if MONITOR_STARTING or MONITOR_JOB and MONITOR_JOB.get('state')=='running':raise RuntimeError('已有持续探测正在运行')
        previous=MONITOR_JOB;MONITOR_STARTING=True
    owns_probe_lock=False
    try:
        options=validate_monitor(payload,stability_catalog() if payload.get('source','nodes')=='nodes' else None)
        if options['mode']!='icmp':
            if time.monotonic()-MONITOR_LAST_START<10:raise ValueError('请间隔 10 秒再开始新的持续探测')
            if not PROBE_LOCK.acquire(False):raise RuntimeError('已有诊断或节点测试正在运行')
            owns_probe_lock=True
        if payload.get('consent') is not True:raise ValueError('请确认开始持续探测')
        if options['mode'] in ('icmp','both') and sys.platform!='darwin':raise ValueError('入口 ICMP 当前需要 macOS 助手')
        context,iface=monitor_icmp_context(options) if options['mode']=='icmp' else context_fingerprint()
        eps=proxy_endpoints(read_text(BASE/'clash-verge.yaml')) if options.get('source')=='nodes' else {}
        labels={a['host']:a['label'] for a in options.get('addresses',[])}
        started=time.time();duration=options['duration_seconds']
        job={'id':secrets.token_hex(12),'state':'running','phase':'starting','reason':None,'started_at':monitor_iso(started),
             'finished_at':None,'last_sample_at':None,'next_sample_at':monitor_iso(started),
             'deadline_at':monitor_iso(started+duration) if duration else None,'options':options,
             'interface':iface,'context':context,'owner_origin':origin,'rounds_completed':0,'round':0,
             'completed_samples':0,'missed_intervals':0,'missed_samples':0,'last_round_seconds':None,'persistence':'saved','revision':0,
             'in_flight':0,'physical_samples':0,'owns_probe_lock':owns_probe_lock,
             'rows':[{'name':n,'label':labels.get(n,n),'host':n if options.get('source')=='addresses' else eps.get(n,{}).get('server'),
                      'address':n if options.get('source')=='addresses' else eps.get(n,{}).get('server'),
                      'last_sample_at':None,'https':monitor_empty_metric(),'icmp':monitor_empty_metric()} for n in options['nodes']]}
        monitor_persist_session(job);monitor_prune(started)
        with MONITOR_LOCK:
            MONITOR_JOB=job;MONITOR_OWNER_ORIGIN=origin;MONITOR_CANCEL.clear()
        MONITOR_LAST_START=time.monotonic()
        first=monitor_view(owner)
        threading.Thread(target=monitor_worker,args=(options,context,iface,eps),daemon=True).start()
        return first
    except (OSError,sqlite3.Error):
        with MONITOR_LOCK:MONITOR_JOB=previous
        if owns_probe_lock:PROBE_LOCK.release()
        raise RuntimeError('无法保存持续探测记录；请检查本机磁盘空间')
    except Exception:
        with MONITOR_LOCK:MONITOR_JOB=previous
        if owns_probe_lock:PROBE_LOCK.release()
        raise
    finally:
        with MONITOR_LOCK:MONITOR_STARTING=False


def stop_monitor(owner,override=False,session_id=None):
    with MONITOR_LOCK:
        if MONITOR_JOB and MONITOR_JOB.get('state')=='running':
            if session_id is not None and session_id!=MONITOR_JOB['id']:raise ValueError('当前正在运行另一项持续探测，请刷新后停止')
            if not monitor_can_stop(MONITOR_JOB,owner,override):raise PermissionError('请从发起持续探测的网站或本地面板停止')
            MONITOR_CANCEL.set();MONITOR_JOB['phase']='stopping'
    return monitor_view(owner,override)


def monitor_schedule_next(previous_due,completed_at,interval):
    following=previous_due+interval
    missed=max(0,math.ceil((completed_at-following)/interval))
    return following+missed*interval,missed


def monitor_icmp_worker(options,context,iface,endpoints):
    """Independent target clocks: a timeout occupies only that target's slot."""
    job=MONITOR_JOB;interval=options['interval_seconds'];started=monitor_timestamp(job['started_at'])
    deadline=monitor_timestamp(job.get('deadline_at')) or float('inf')
    grouped={}
    for name in options['nodes']:
        endpoint=endpoints.get(name) if options.get('source','nodes')=='nodes' else None
        key=json.dumps({'server':endpoint.get('server'),'dialer-proxy':endpoint.get('dialer-proxy')} if endpoint else {'name':name},sort_keys=True)
        target=grouped.setdefault(key,{'names':[],'host':name if options.get('source')=='addresses' else (endpoint or {}).get('server'),
                                       'endpoint':endpoint,'due':started,'completed':0,'missed':0,'gap':False,'ingress':None,'expires':0})
        target['names'].append(name)
    targets=list(grouped.values());queue=[(started,i,i) for i in range(len(targets))];heapq.heapify(queue)
    serial=len(targets);pending={};wave=[];invalid=False;last_clock=started
    last_flush=time.monotonic();last_checked=last_flush;last_persist=last_flush;last_prune=last_flush
    monitor_update_job(job,schedule='independent',unique_targets=len(targets))
    def check_context():
        nonlocal invalid,last_checked
        try:invalid=invalid or monitor_icmp_context(options)[0]!=context
        except RuntimeError:invalid=True
        last_checked=time.monotonic()
        return not invalid
    def measure(target):
        if MONITOR_CANCEL.is_set() or time.time()>=deadline:return None
        if target['ingress'] is None or time.monotonic()>=target['expires']:
            if options.get('source')=='addresses':ingress=monitor_direct_ingress(target['host'],iface)
            else:
                endpoint=target['endpoint']
                if endpoint and ':' in str(endpoint.get('server','')) and not endpoint.get('dialer-proxy'):
                    ingress=monitor_direct_ingress(endpoint['server'],iface)
                else:ingress=resolve_ingress(endpoint,iface)
            target['ingress']=ingress
            target['expires']=time.monotonic()+(300 if ingress.get('state')=='ready' else 30)
        ingress=target['ingress']
        if MONITOR_CANCEL.is_set() or time.time()>=deadline:return None
        result=icmp_sample(ingress,options['timeout_ms']);stamp=monitor_iso(time.time())
        result['at']=stamp
        address=ingress.get('ip') or target['host']
        return {'at':stamp,'icmp':result,'address':address,'interface':ingress.get('interface'),
                'measurement_key':str(ingress.get('interface') or iface)+'|'+str(address)}
    def add_missed(target,amount):
        if amount<=0:return
        target['missed']+=amount;target['gap']=True
        monitor_update_job(job,increments={'missed_samples':amount*len(target['names'])},missed_intervals=max(t['missed'] for t in targets))
    def collect(future,target_index,scheduled_due):
        nonlocal serial
        target=targets[target_index];sample=future.result()
        finished=time.time();following,missed=monitor_schedule_next(scheduled_due,finished,interval)
        # A long in-flight timeout/sleep already leaves a gap before this
        # observation. Break its streak now, not on the next healthy cadence.
        add_missed(target,missed);target['due']=following
        if sample is not None:
            target['completed']+=1
            sample['round']=target['completed'];sample['gap_before']=target['gap'];target['gap']=False
            wave.extend((name,copy.deepcopy(sample)) for name in target['names'])
            if sample['icmp'].get('state') in ('ok','fail'):monitor_update_job(job,increments={'physical_samples':1})
        if following<deadline:heapq.heappush(queue,(following,serial,target_index));serial+=1
    def flush():
        nonlocal last_flush
        if not wave:return
        check_context()
        if invalid:
            for _,sample in wave:sample['icmp']={'state':'error','ms':None,'error':'context_unverified','label':'网络路径已变化','at':sample['at']}
        monitor_record_samples(job,wave,0);wave.clear()
        monitor_update_job(job,rounds_completed=min(t['completed'] for t in targets),round=max(t['completed'] for t in targets))
        last_flush=time.monotonic()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=options['concurrency']) as pool:
            while not MONITOR_CANCEL.is_set() and not invalid:
                current=time.time()
                if current<last_clock-2:
                    monitor_update_job(job,state='interrupted',reason='系统时间已回拨');break
                last_clock=current
                if current>=deadline:break
                if time.monotonic()-last_checked>=10 and not check_context():break
                ready=[future for future in pending if future.done()]
                for future in ready:
                    target_index,scheduled_due=pending.pop(future);collect(future,target_index,scheduled_due)
                dispatch_due=bool(queue and queue[0][0]<=time.time())
                if wave and (len(wave)>=512 or time.monotonic()-last_flush>=1 or not pending and not dispatch_due):flush()
                if invalid:break
                while len(pending)<options['concurrency'] and queue and queue[0][0]<=time.time() and not MONITOR_CANCEL.is_set():
                    due,_,index=heapq.heappop(queue);target=targets[index];current=time.time()
                    if current>=deadline:break
                    missed=max(0,int((current-due)//interval));add_missed(target,missed);due+=missed*interval
                    pending[pool.submit(measure,target)]=(index,due)
                monitor_update_job(job,phase='testing' if pending else 'waiting',in_flight=len(pending),
                                   next_sample_at=monitor_iso(queue[0][0]) if queue else None)
                tick=time.monotonic()
                if tick-last_persist>=5:monitor_persist_session(job);last_persist=tick
                if tick-last_prune>=60:monitor_prune(time.time());last_prune=tick
                if not pending and not queue:break
                wait=.05 if pending else min(.25,max(0,queue[0][0]-time.time()),max(0,deadline-time.time()))
                if pending:concurrent.futures.wait(pending,timeout=wait,return_when=concurrent.futures.FIRST_COMPLETED)
                else:MONITOR_CANCEL.wait(wait)
            # Active subprocesses have their own bounded deadline. Save the work
            # already sent; no new address is dispatched after stop/deadline.
            for future in concurrent.futures.as_completed(list(pending)):
                index,due=pending[future];collect(future,index,due)
            pending.clear();flush()
        if invalid:monitor_update_job(job,state='interrupted',reason='网络路径或节点入口已变化')
    except (OSError,sqlite3.Error):
        monitor_update_job(job,state='interrupted',reason='无法保存新的探测记录',persistence='error')
    except Exception:
        monitor_update_job(job,state='interrupted',reason='本机探测异常')
    finally:
        state=job['state']
        if state=='running':state='cancelled' if MONITOR_CANCEL.is_set() else 'done'
        monitor_update_job(job,state=state,phase='finished',finished_at=monitor_iso(time.time()),next_sample_at=None,in_flight=0)
        try:monitor_persist_session(job);monitor_prune(time.time())
        except (OSError,sqlite3.Error):monitor_update_job(job,persistence='error')
        with MONITOR_LOCK:MONITOR_VIEW_CACHE.clear()


def monitor_worker(options,context,iface,endpoints):
    if options['mode']=='icmp':return monitor_icmp_worker(options,context,iface,endpoints)
    job=MONITOR_JOB;interval=options['interval_seconds'];due=monitor_timestamp(job['started_at'])
    deadline=monitor_timestamp(job.get('deadline_at')) or float('inf')
    last_clock=due;gap_pending=False
    try:
        while not MONITOR_CANCEL.is_set():
            current=time.time()
            if current<last_clock-2:
                monitor_update_job(job,state='interrupted',phase='finished',finished_at=monitor_iso(current),next_sample_at=None,reason='系统时间向前回拨，已结束本次记录');break
            last_clock=current
            if current>=deadline:
                if due<deadline:monitor_update_job(job,increments={'missed_intervals':max(0,math.ceil((deadline-due)/interval))})
                break
            if current<due:
                monitor_update_job(job,phase='waiting',next_sample_at=monitor_iso(due))
                MONITOR_CANCEL.wait(min(1,due-current,deadline-current));continue
            if current-due>=interval:
                missed=int((current-due)//interval);monitor_update_job(job,increments={'missed_intervals':missed});due+=missed*interval;gap_pending=True
            try:new_context,_=context_fingerprint()
            except RuntimeError:
                monitor_update_job(job,state='interrupted',phase='finished',finished_at=monitor_iso(time.time()),next_sample_at=None,reason='无法校验本机网络环境，已结束本次记录');break
            if new_context!=context:
                monitor_update_job(job,state='interrupted',phase='finished',finished_at=monitor_iso(time.time()),next_sample_at=None,reason='网络或代理配置变化，已结束本次记录');break
            round_index=monitor_update_job(job,increments={'round':1},phase='testing',next_sample_at=None);round_started=time.monotonic()
            names=options['nodes'];shift=(round_index-1)%len(names);node_iter=iter(names[shift:]+names[:shift]);wave=[]
            ping_cache={};ping_locks={};ingress_cache={};ingress_locks={};ping_registry_lock=threading.Lock()
            def measure(name):
                if MONITOR_CANCEL.is_set():return None
                sample={}
                if options['mode'] in ('https','both'):
                    sample['https']=https_sample(name,options['target'],options['timeout_ms'])
                    sample['https']['at']=monitor_iso(time.time())
                if options['mode'] in ('icmp','both'):
                    endpoint=endpoints.get(name);endpoint_key=json.dumps(endpoint,sort_keys=True)
                    with ping_registry_lock:ingress_lock=ingress_locks.setdefault(endpoint_key,threading.Lock())
                    with ingress_lock:
                        if endpoint_key not in ingress_cache:ingress_cache[endpoint_key]=resolve_ingress(endpoint,iface)
                        ing=ingress_cache[endpoint_key]
                    key=(ing.get('ip'),ing.get('interface'),ing.get('reason'))
                    with ping_registry_lock:lock=ping_locks.setdefault(key,threading.Lock())
                    with lock:
                        if key not in ping_cache:
                            ping_cache[key]=icmp_sample(ing,options['timeout_ms'])
                            ping_cache[key]['at']=monitor_iso(time.time())
                        sample['icmp']=copy.deepcopy(ping_cache[key])
                sample['at']=monitor_iso(time.time())
                return name,sample
            invalid=False;local_error=False;context_check=time.monotonic();wave_count=0
            def flush_wave():
                nonlocal invalid,wave_count,context_check
                try:invalid=invalid or context_fingerprint()[0]!=context
                except RuntimeError:invalid=True
                context_check=time.monotonic()
                for name,sample in wave:
                    if invalid:
                        for kind in ('https','icmp'):
                            if kind in sample:sample[kind]={'state':'error','ms':None,'error':'context_unverified','at':sample[kind].get('at',sample['at'])}
                monitor_record_samples(job,wave,round_index,gap_pending)
                wave_count+=len(wave);wave.clear()
            with concurrent.futures.ThreadPoolExecutor(max_workers=options['concurrency']) as pool:
                pending={}
                def fill():
                    while len(pending)<options['concurrency'] and not MONITOR_CANCEL.is_set() and not invalid and not local_error and time.time()<deadline:
                        name=next(node_iter,None)
                        if name is None:break
                        pending[pool.submit(measure,name)]=name
                fill()
                while pending:
                    ready,_=concurrent.futures.wait(pending,timeout=.25,return_when=concurrent.futures.FIRST_COMPLETED)
                    for future in ready:
                        pending.pop(future);result=future.result()
                        if result:
                            wave.append(result)
                            local_error=local_error or result[1].get('https',{}).get('error')=='local_api'
                    if wave and (time.monotonic()-context_check>=10 or len(wave)>=32):flush_wave()
                    fill()
            flush_wave()
            gap_pending=False
            monitor_update_job(job,increments={'rounds_completed':int(wave_count==len(names))},last_round_seconds=round(time.monotonic()-round_started,3))
            if invalid:
                monitor_update_job(job,state='interrupted',phase='finished',finished_at=monitor_iso(time.time()),next_sample_at=None,reason='环境变化后的样本未计入失败率，已结束本次记录');break
            if local_error:
                monitor_update_job(job,state='interrupted',phase='finished',finished_at=monitor_iso(time.time()),next_sample_at=None,reason='本机控制接口不可用，已结束本次记录');break
            completed=time.time();due,missed=monitor_schedule_next(due,completed,interval)
            gap_pending=missed>0
            monitor_update_job(job,increments={'missed_intervals':missed},phase='waiting',next_sample_at=monitor_iso(due) if due<deadline else None)
            monitor_persist_session(job);monitor_prune(completed)
    except (OSError,sqlite3.Error):
        monitor_update_job(job,state='interrupted',phase='finished',finished_at=monitor_iso(time.time()),next_sample_at=None,reason='无法保存新的探测记录，已停止',persistence='error')
    except Exception:
        monitor_update_job(job,state='interrupted',phase='finished',finished_at=monitor_iso(time.time()),next_sample_at=None,reason='本机探测异常，已保留完成的记录')
    finally:
        with MONITOR_LOCK:
            state=job.get('state')
            if state=='running':state='cancelled' if MONITOR_CANCEL.is_set() else 'done'
            monitor_update_job(job,state=state,phase='finished',finished_at=monitor_iso(time.time()),next_sample_at=None)
        try:monitor_persist_session(job)
        except (OSError,sqlite3.Error):monitor_update_job(job,persistence='error')
        with MONITOR_LOCK:MONITOR_VIEW_CACHE.clear()
        if job.get('owns_probe_lock',True) and PROBE_LOCK.locked():PROBE_LOCK.release()


class Handler(BaseHTTPRequestHandler):
    server_version = 'NetworkStatusHelper/' + VERSION
    def log_message(self, *args): pass
    def good_host(self): return self.headers.get('Host') == f'127.0.0.1:{PORT}'
    def origin(self): return self.headers.get('Origin') or LOCAL_ORIGIN
    def authorized(self, owner=False):
        token = self.headers.get('X-Netdash-Token', '')
        with AUTH_LOCK:
            cleanup_auth()
            record = SESSIONS.get(token)
            return bool(record and record['origin'] == self.origin() and (not owner or record['owner']))
    def admin(self):
        return not self.headers.get('Origin') and hmac.compare_digest(self.headers.get('X-Netdash-Admin',''), MASTER_TOKEN)
    def cors_allowed(self):
        o = self.origin()
        if o == LOCAL_ORIGIN: return True
        path = urllib.parse.urlsplit(self.path).path
        if path in ('/health','/api/pair'): return valid_origin(o)
        with AUTH_LOCK:
            cleanup_auth()
            return any(r['origin'] == o for r in SESSIONS.values())
    def response(self, status, body, kind='application/json; charset=utf-8'):
        self.send_response(status)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('X-Frame-Options','DENY')
        if self.headers.get('Origin') and self.cors_allowed():
            self.send_header('Access-Control-Allow-Origin',self.origin())
            self.send_header('Vary','Origin')
        self.end_headers()
        try:self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):pass
    def reply(self, status, obj): self.response(status,json.dumps(obj,ensure_ascii=False).encode())
    def body(self):
        length = int(self.headers.get('Content-Length','0'))
        limit=512000 if urllib.parse.urlsplit(self.path).path in ('/api/stability/start','/api/monitor/start') else 4096
        if length < 0 or length > limit: raise ValueError('Payload too large')
        value=json.loads(self.rfile.read(length) or b'{}')
        if not isinstance(value,dict):raise ValueError('JSON object required')
        return value
    def guard(self):
        return self.good_host() and valid_origin(self.origin())
    def do_OPTIONS(self):
        if not self.guard() or not self.cors_allowed(): return self.reply(403,{'error':'origin/host denied'})
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin',self.origin())
        self.send_header('Access-Control-Allow-Methods','GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers','Content-Type, X-Netdash-Token, X-Netdash-Challenge')
        self.send_header('Access-Control-Allow-Private-Network','true')
        self.send_header('Vary','Origin')
        self.end_headers()
    def do_GET(self):
        if not self.guard():return self.reply(403,{'error':'origin/host denied'})
        u = urllib.parse.urlsplit(self.path)
        if u.path == '/health': return self.reply(200,{'service':'network-status-helper','version':VERSION,'pairing_required':True})
        if u.path == '/api/pair':
            challenge = self.headers.get('X-Netdash-Challenge','')
            with AUTH_LOCK:
                cleanup_auth()
                grant = GRANTS.pop((self.origin(),challenge), None)
            if not grant:return self.reply(202,{'pending':True})
            return self.reply(200,{'token':grant['token'],'expires_in':8*3600})
        if u.path in ('/','/index.html','/network-dashboard.html'):
            if self.headers.get('Origin') not in (None,LOCAL_ORIGIN):return self.reply(403,{'error':'local UI only'})
            try:return self.response(200,HTML.read_bytes(),'text/html; charset=utf-8')
            except OSError:return self.reply(404,{'error':'Local HTML not found'})
        if u.path == '/favicon.ico':return self.response(204,b'','image/x-icon')
        if u.path == '/api/control/status':
            if not self.authorized():return self.reply(401,{'error':'请连接本机助手'})
            return self.reply(200,control_status(self.headers.get('X-Netdash-Token','')))
        if u.path == '/api/services':
            if not self.authorized():return self.reply(401,{'error':'请连接本机助手'})
            return self.reply(200,services_view())
        if u.path == '/api/monitor':
            if not self.authorized():return self.reply(401,{'error':'请连接本机助手'})
            query=urllib.parse.parse_qs(u.query)
            try:return self.reply(200,monitor_view(self.headers.get('X-Netdash-Token',''),self.authorized(owner=True),query.get('id',[None])[0],query.get('node',[None])[0]))
            except ValueError as e:return self.reply(400,{'error':str(e)})
            except RuntimeError as e:return self.reply(503,{'error':str(e)})
            except (OSError,sqlite3.Error):return self.reply(503,{'error':'无法读取本机持续探测记录'})
        if u.path in ('/api/nodes','/api/stability'):
            if not self.authorized():return self.reply(401,{'error':'请连接本机助手'})
            try:return self.reply(200,stability_catalog() if u.path=='/api/nodes' else stability_view(urllib.parse.parse_qs(u.query).get('history',['1'])[0]!='0'))
            except RuntimeError as e:return self.reply(503,{'error':str(e)})
        if u.path != '/api/snapshot':return self.reply(404,{'error':'not found'})
        if not self.authorized():return self.reply(401,{'error':'请先通过本地助手授权本页面'})
        try:return self.reply(200,snapshot())
        except Exception as e:return self.reply(500,{'error':type(e).__name__})
    def do_POST(self):
        if not self.guard():return self.reply(403,{'error':'origin/host denied'})
        path = urllib.parse.urlsplit(self.path).path
        try:data=self.body()
        except Exception:return self.reply(400,{'error':'invalid JSON'})
        if path == '/api/grant':
            if not self.admin():return self.reply(403,{'error':'native helper only'})
            try:
                make_grant(data.get('origin'),data.get('challenge'))
                return self.reply(200,{'approved':True})
            except ValueError as e:return self.reply(400,{'error':str(e)})
        if path == '/api/local-session':
            if not self.admin():return self.reply(403,{'error':'native helper only'})
            newtoken=secrets.token_urlsafe(32)
            with AUTH_LOCK:
                cleanup_auth()
                SESSIONS[newtoken]={'origin':LOCAL_ORIGIN,'until':time.time()+24*3600,'owner':True}
            return self.reply(200,{'token':newtoken})
        if not self.authorized():return self.reply(401,{'error':'unauthorized'})
        if path.startswith('/api/control/'):
            owner=self.headers.get('X-Netdash-Token','')
            try:
                if path=='/api/control/authorize':return self.reply(200,authorize_control(owner,self.origin(),data))
                if path=='/api/control/revoke':
                    revoke_control(owner)
                    return self.reply(200,control_status(owner))
                if path=='/api/control/preview':return self.reply(200,preview_switch(owner,data))
                if path=='/api/control/apply':return self.reply(200,apply_switch(owner,data))
                return self.reply(404,{'error':'not found'})
            except PermissionError as e:return self.reply(403,{'error':str(e)})
            except ValueError as e:return self.reply(400,{'error':str(e)})
            except RuntimeError as e:return self.reply(409,{'error':str(e)})
        if path=='/api/history/clear':
            if data.get('consent') is not True:return self.reply(400,{'error':'请确认清除本机测试历史'})
            if not PROBE_LOCK.acquire(False):return self.reply(409,{'error':'测试进行中'})
            try:clear_test_history()
            finally:PROBE_LOCK.release()
            return self.reply(200,{'cleared':True})
        if path == '/api/disconnect':
            revoke_control(self.headers.get('X-Netdash-Token',''))
            with AUTH_LOCK:SESSIONS.pop(self.headers.get('X-Netdash-Token',''),None)
            return self.reply(200,{'disconnected':True})
        if path == '/api/stop':
            if not self.authorized(owner=True):return self.reply(403,{'error':'请从本地面板停止助手'})
            self.reply(200,{'stopped':True})
            threading.Thread(target=SERVER.shutdown,daemon=True).start();return
        if path in ('/api/services/start','/api/services/stop'):
            try:
                result=start_services(data,self.headers.get('X-Netdash-Token','')) if path.endswith('/start') else stop_services(self.headers.get('X-Netdash-Token',''),self.authorized(owner=True))
                return self.reply(202 if path.endswith('/start') else 200,result)
            except ValueError as e:return self.reply(400,{'error':str(e)})
            except PermissionError as e:return self.reply(403,{'error':str(e)})
            except RuntimeError as e:return self.reply(409,{'error':str(e)})
        if path in ('/api/monitor/start','/api/monitor/stop'):
            try:
                result=start_monitor(data,self.headers.get('X-Netdash-Token','')) if path.endswith('/start') else stop_monitor(self.headers.get('X-Netdash-Token',''),self.authorized(owner=True),data.get('id'))
                return self.reply(202 if path.endswith('/start') else 200,result)
            except ValueError as e:return self.reply(400,{'error':str(e)})
            except PermissionError as e:return self.reply(403,{'error':str(e)})
            except RuntimeError as e:return self.reply(409,{'error':str(e)})
            except (OSError,sqlite3.Error):return self.reply(503,{'error':'无法保存本机持续探测记录'})
        if path in ('/api/stability/start','/api/stability/stop'):
            try:
                result=start_stability(data,self.headers.get('X-Netdash-Token','')) if path.endswith('/start') else cancel_stability(self.headers.get('X-Netdash-Token',''),self.authorized(owner=True))
                return self.reply(202 if path.endswith('/start') else 200,result)
            except ValueError as e:return self.reply(400,{'error':str(e)})
            except PermissionError as e:return self.reply(403,{'error':str(e)})
            except RuntimeError as e:return self.reply(409,{'error':str(e)})
        if path == '/api/probe':
            if PROBES.get('at') and age_seconds(PROBES['at']) < 15:return self.reply(429,{'error':'请至少间隔 15 秒再诊断'})
            try:
                result=run_probes()
                return self.reply(200,result) if result else self.reply(409,{'error':'诊断进行中'})
            except Exception as e:return self.reply(500,{'error':type(e).__name__})
        if path == '/api/lan':
            if PROBE_LOCK.locked():return self.reply(409,{'error':'请等当前诊断或节点测试结束'})
            if data.get('consent') is not True:return self.reply(400,{'error':'请确认仅检测你有权管理的当前局域网'})
            if LAN.get('at') and age_seconds(LAN['at'])<30:return self.reply(429,{'error':'请至少间隔 30 秒刷新局域网'})
            if not LAN_LOCK.acquire(False):return self.reply(409,{'error':'局域网查询进行中'})
            try:
                d=snapshot(True); result=local_lan(d,True)
                result.update(interface=d['system'].get('interface'),gateway=d['system'].get('gateway'))
                LAN.clear();LAN.update(result);CACHE['at']=0
                return self.reply(200,snapshot(True))
            except Exception as e:return self.reply(500,{'error':type(e).__name__})
            finally:LAN_LOCK.release()
        return self.reply(404,{'error':'not found'})


def serve():
    global SERVER
    os.umask(0o077)
    STATE_DIR.mkdir(parents=True,exist_ok=True)
    load_test_history()
    try:load_monitor_history()
    except (OSError,sqlite3.Error,ValueError):pass
    SESSIONS[LOCAL_TOKEN]={'origin':LOCAL_ORIGIN,'until':time.time()+24*3600,'owner':True}
    try:SERVER=ThreadingHTTPServer(('127.0.0.1',PORT),Handler)
    except OSError:
        print('Local helper port is occupied. No other process was modified.');return
    SERVER.daemon_threads=True
    STATE_FILE.write_text(json.dumps({'pid':os.getpid(),'port':PORT,'admin':MASTER_TOKEN,'local_token':LOCAL_TOKEN,'version':VERSION}))
    os.chmod(STATE_FILE,0o600)
    try:SERVER.serve_forever()
    except KeyboardInterrupt:pass
    finally:
        MONITOR_CANCEL.set()
        with MONITOR_LOCK:
            if MONITOR_JOB and MONITOR_JOB.get('state')=='running':
                MONITOR_JOB.update(state='interrupted',phase='finished',reason='本机助手已停止，记录已保留',finished_at=now(),next_sample_at=None)
                try:monitor_persist_session(MONITOR_JOB)
                except (OSError,sqlite3.Error):pass
        SERVER.server_close()
        try:
            current=json.loads(STATE_FILE.read_text())
            if current.get('pid')==os.getpid():STATE_FILE.unlink()
        except (OSError,ValueError):pass


if __name__ == '__main__':
    if os.environ.get('NETDASH_SNAPSHOT_ONLY')=='1':print(json.dumps(snapshot(True),ensure_ascii=False))
    else:serve()
