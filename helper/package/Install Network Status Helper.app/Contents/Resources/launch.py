"""macOS native launcher for a read-only local helper. Never executes website commands."""
from __future__ import annotations
import json, os, pathlib, re, subprocess, sys, time, urllib.parse, urllib.request, urllib.error

RESOURCE = pathlib.Path(__file__).resolve().parent
STATE = pathlib.Path.home()/'Library/Application Support/Network Status Helper/session.json'
ORIGIN='http://127.0.0.1:17890'

VERSION="4.3.0"

def http(path, body=None, admin=None, token=None, timeout=2):
    headers={'Content-Type':'application/json'} if body is not None else {}
    if admin:headers['X-Netdash-Admin']=admin
    if token:headers['X-Netdash-Token']=token
    request=urllib.request.Request(ORIGIN+path, data=json.dumps(body).encode() if body is not None else None,headers=headers)
    # Explicitly ignore HTTP_PROXY and system proxy for the local control channel.
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request,timeout=timeout) as r:return json.load(r)

def dialog(message):
    # Text is an argv item, never interpolated into AppleScript source.
    script='on run argv\n display dialog (item 1 of argv) with title "网络状态台 · 本地助手" buttons {"取消", "允许"} default button "取消" cancel button "取消" with icon caution\nend run'
    return subprocess.run(['/usr/bin/osascript','-e',script,message],capture_output=True,timeout=120).returncode==0

def validate(raw):
    u=urllib.parse.urlsplit(raw)
    if u.scheme!='netstatus' or u.hostname not in ('open','connect') or u.path not in ('','/') or u.username or u.password:raise ValueError('Invalid request')
    if u.hostname=='open':return None,None
    q=urllib.parse.parse_qs(u.query,strict_parsing=True)
    origin=q.get('origin',[''])[0];challenge=q.get('challenge',[''])[0]
    o=urllib.parse.urlsplit(origin)
    if (o.scheme!='https' or not o.hostname or o.username or o.password or o.path or o.query or o.fragment or
        origin!='https://'+o.netloc or len(origin)>400 or '\\' in origin or not origin.isascii() or any(ord(c)<33 for c in origin)):
        raise ValueError('Only a complete HTTPS origin is supported')
    if not re.fullmatch('[A-Za-z0-9_-]{32,100}',challenge):raise ValueError('Invalid one-time challenge')
    return origin,challenge

def ensure():
    try:health=http('/health')
    except Exception:health=None
    if health and health.get('service')=='network-status-helper':
        state=json.loads(STATE.read_text())
        if health.get('version')==VERSION:return state
        # Native reinstall upgrades only this helper. Never restart Clash or system networking.
        session=http('/api/local-session',{},state['admin'])
        try:job=http('/api/stability',token=session['token']).get('job')
        except Exception:job=None
        try:service_job=http('/api/services',token=session['token']).get('job')
        except Exception:service_job=None
        try:
            monitor_view=http('/api/monitor',token=session['token'],timeout=15)
            monitor_job=monitor_view.get('active') or monitor_view.get('monitor')
        except urllib.error.HTTPError as exc:
            if exc.code==404:monitor_job=None
            else:raise RuntimeError('暂时无法确认持续监测状态，请刷新页面后重试更新。') from exc
        except Exception as exc:
            raise RuntimeError('暂时无法确认持续监测状态，请刷新页面后重试更新。') from exc
        if monitor_job and monitor_job.get('state')=='running':
            raise RuntimeError('持续监测正在运行，请先在页面停止并保存，再更新助手。')
        if (job and job.get('state')=='running') or (service_job and service_job.get('state')=='running'):
            raise RuntimeError('检测正在运行，请停止后再次打开助手。')
        http('/api/stop',{},token=session['token'])
        for _ in range(30):
            time.sleep(.2)
            try:http('/health')
            except Exception:break
        else:raise RuntimeError('旧助手仍在退出，请稍后再次打开。')
    env=os.environ.copy();env['NETDASH_HTML']=str(RESOURCE/'index.html');env['NETDASH_PORT']='17890'
    logdir=STATE.parent;logdir.mkdir(parents=True,exist_ok=True);os.chmod(logdir,0o700)
    with (logdir/'helper.log').open('ab') as log:
        subprocess.Popen([sys.executable,str(RESOURCE/'collector.py')],env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
    for _ in range(30):
        time.sleep(.2)
        try:
            if http('/health').get('version')==VERSION:return json.loads(STATE.read_text())
        except Exception:pass
    raise RuntimeError('无法启动只读助手。请确认 Python 3.9+ 与本机 17890 端口未被其他程序占用。')

def main():
    if sys.version_info<(3,9):raise RuntimeError('需要 Python 3.9 或更新版本')
    raw=sys.argv[1] if len(sys.argv)>1 else 'netstatus://open'
    if len(raw)>1600:raise ValueError('Request too long')
    origin,challenge=validate(raw)
    if origin and not dialog('允许这个网站读取当前电脑的网络状态吗？\n\n'+origin+'\n\n包括：DNS、代理策略、连接域名与局域网设备记录。仅授权当前会话，8 小时失效；不修改网络设置。\n\n注意：同一域名下不同路径/仓库共享网页来源。只授权你信任的网站。'):
        return
    state=ensure()
    if origin:
        http('/api/grant',{'origin':origin,'challenge':challenge},state['admin'])
    else:
        fresh=http('/api/local-session',{},state['admin'])
        url=ORIGIN+'/#token='+fresh['token']
        result=subprocess.run(['/usr/bin/open','-a','Google Chrome',url],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if result.returncode:subprocess.run(['/usr/bin/open',url],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

if __name__=='__main__':
    try:main()
    except Exception as e:
        msg=type(e).__name__+': '+str(e)[:300]
        try:dialog(msg)
        except Exception:pass
        sys.exit(1)
