"""loopback 全栈测速 + alloc/MB 基线采集（框架支线 P0 护栏）。

## 拓扑（--topo，默认 == 改造前唯一拓扑）

| --topo | 链路 | 帧粒度上限（chunk payload） |
|---|---|---|
| `vless-xhttp-reality`（默认） | socks → vless(mlkem-enc) over xhttp+reality | 无协议帧层（h2 帧由 hyper 决定，不计） |
| `ss2022-tcp` | socks → ss2022(AES-128-GCM) 裸 TCP，无 TLS | 65535 B（`xray-proxy-ss/src/stream.rs:36` MAX_CHUNK_PAYLOAD） |
| `vmess-tls-ws` | socks → vmess(AEAD) over TLS+ws（自签证书 + pinned sha256） | 8110 B（`xray-proxy-vmess/src/encoding/body_chunk.rs:252` = 8192−16 tag−2 size−64 padding） |

不传 `--topo` 时输出与改造前逐字节同口径（`--xray/--tag/--runs/--alloc-stats/
--floor` 语义不变）。

## 判据纪律（硬性，per docs/benchmarks/baseline.md 2026-10-27 节）

本机 loopback 逐窗口摆动 ~20%，**绝对值不可跨窗口/跨机比较**——同一二进制跨两个
窗口也能量出差 20%（本次实测同一二进制 4 轮 161-195 MB/s）。唯一合法判据 = **同窗口内
交错 A/B**：`--ab <A_BIN>` 让 A/B 各自完整起停进程，**每轮 A/B 相邻成对、轮序逐轮反相**
（抵顺序偏差：同二进制 A 先跑实测比后跑快 21%），判据取**逐对比值的中位**（相邻两次 =
时间窗最紧），并输出轮间离散度与每轮窗口时间戳。拿两个不同窗口的绝对值相减会得出假
回归（历史两次假回归都源于此）。

## 帧粒度（--frames，独立读数源）

以 `XRAY_P7LM_TRACE=1` 的桥接批埋点为**实测**源（逐批 `bytes=` + `phase=`），按 phase
统计 批数 / 总字节 / 均批大小，帧数 = Σ⌈批字节 ÷ 该拓扑 chunk 上限⌉（只把批粒度换算成
帧数，不引入协议常量以外的新假设）。
⚠️ trace 有实测税（历史达数十 % 吞吐）——**该 pass 的吞吐数字无效**，只取帧粒度。

## 用法

  # 默认拓扑（与旧版一致）
  python tools/loopback_alloc_bench.py --xray target/release/xray.exe --tag r1 --runs 3 --alloc-stats
  # 新拓扑 + 帧粒度
  python tools/loopback_alloc_bench.py --xray ... --tag ss1 --topo ss2022-tcp --runs 1 --alloc-stats --frames
  # 双向（下载窗口、上传窗口各自独立采样，不混口径）
  python tools/loopback_alloc_bench.py --xray ... --tag ss2 --topo ss2022-tcp --bidir --runs 2
  # 同窗口交错 A/B（唯一合法判据形态；--xray 为 B 侧，--ab 为 A 侧）
  python tools/loopback_alloc_bench.py --xray new.exe --ab old.exe --ab-runs 3 --topo ss2022-tcp

输出：每轮 speed 行 + 分方向/分进程 alloc/MB + site 归集 + floor 检查（stdout，直接贴报告）。
退出码: 0=通过  1=floor 或 A/B 比值不达标  2=A/B 无判据（--ab-runs 1）  3=轮间离散度超限（CONTAMINATED）
"""
import argparse, base64, hashlib, json, os, re, statistics, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WORK = 'D:/tmp/enc8x'
UUID = '6ea1458e-8c33-4a0e-9a72-8e4b9c1e5d01'
SRV_PORT, CLI_SOCKS, HTTP_PORT = 18453, 11081, 18100
SINK_PORT = 18101                      # --bidir 上传落点（本进程内 ThreadingHTTPServer）
BIG = os.path.join(WORK, 'big.bin')
SIZE_MB = 200
PREFIX = '[xray-alloc-stats]'

SITES_PREFIX = '[xray-alloc-sites]'

STATS_RE = re.compile(
    r't=([\d.]+)s alloc_n=(\d+) alloc_bytes=(\d+) '
    r'dealloc_n=(\d+) dealloc_bytes=(\d+) live_bytes=(-?\d+)')

SITES_RE = re.compile(
    r't=([\d.]+)s site=(\S+) alloc_n=(\d+) alloc_bytes=(\d+) '
    r'd_n=(\d+) d_bytes=(\d+)')

# 桥接批埋点（crates/xray-transport/src/bridge.rs:476 起，warn 级穿透 loglevel）
P7LM_RE = re.compile(r'bytes=(\d+) phase="?(\w+)"?')

DEFAULT_TOPO = 'vless-xhttp-reality'
# chunk_cap = 该拓扑单帧明文上限（帧粒度换算用；None = 无协议帧层）
TOPOLOGIES = {
    'vless-xhttp-reality': {'label': 'via-enc-chain', 'chunk_cap': None},
    'ss2022-tcp': {'label': 'via-ss2022-tcp', 'chunk_cap': 65535},
    'vmess-tls-ws': {'label': 'via-vmess-tls-ws', 'chunk_cap': 8110},
}

# 自签 interop 证书（control-plane 测试资产，非红线）
CERT = 'D:/tmp/interop_cert.pem'
KEY = 'D:/tmp/interop_key.pem'
# 固定 bench PSK：仅 127.0.0.1 loopback 用，可复现优先（非生产密钥）
SS_PSK = base64.b64encode(bytes(range(16))).decode()
VMESS_SECURITY = 'aes-128-gcm'
DISPERSE_THRESH = 0.15                 # 轮间离散度阈值（baseline.md 校准纪律）
DUMPS_PERIOD_S = 1.5                   # 等最后一条周期采样落地


def read_keys():
    with open(os.path.join(WORK, 'vlessenc.txt')) as f:
        lines = [l.strip() for l in f if l.strip()]
    dec = [l for l in lines if '"decryption"' in l][-1].split('"')[3]
    enc = [l for l in lines if '"encryption"' in l][-1].split('"')[3]
    with open(os.path.join(WORK, 'x25519.txt')) as f:
        t = f.read()
    priv = re.search(r'PrivateKey: (\S+)', t).group(1)
    pub = re.search(r'\(PublicKey\): (\S+)', t).group(1)
    return dec, enc, priv, pub


def cert_pin():
    """leaf DER sha256（allowInsecure 已配置期硬错，interop_matrix 同配方）。"""
    with open(CERT) as f:
        der = base64.b64decode(''.join(l for l in f.read().splitlines() if '-----' not in l))
    return hashlib.sha256(der).hexdigest()


def build_configs(topo, keys):
    """按拓扑产出 (srv_cfg, cli_cfg)；srv_cfg=None 表示单进程拓扑。"""
    dec, enc, rpriv, rpub = keys
    if topo == 'ss2022-tcp':
        srv = {
            'log': {'loglevel': 'warning'},
            'inbounds': [{
                'tag': 'ss-in', 'listen': '127.0.0.1', 'port': SRV_PORT,
                'protocol': 'shadowsocks',
                'settings': {'method': '2022-blake3-aes-128-gcm',
                             'password': SS_PSK, 'network': 'tcp'},
                'sniffing': {'enabled': True, 'destOverride': ['http', 'tls', 'quic'],
                             'metadataOnly': False}}],
            'outbounds': [{'protocol': 'freedom',
                           'settings': {'finalRules': [{'action': 'allow'}]}}]}
        cli = {
            'log': {'loglevel': 'warning'},
            'inbounds': [{'listen': '127.0.0.1', 'port': CLI_SOCKS, 'protocol': 'socks',
                          'settings': {'udp': True}}],
            'outbounds': [{
                'protocol': 'shadowsocks',
                'settings': {'servers': [{'address': '127.0.0.1', 'port': SRV_PORT,
                            'method': '2022-blake3-aes-128-gcm', 'password': SS_PSK}]}}]}
        return srv, cli
    if topo == 'vmess-tls-ws':
        ws = {'path': '/bench', 'poolSize': 0}   # poolSize 0 = 严格对齐 Go 无预连接池
        srv = {
            'log': {'loglevel': 'warning'},
            'inbounds': [{
                'tag': 'vmess-in', 'listen': '127.0.0.1', 'port': SRV_PORT,
                'protocol': 'vmess',
                'settings': {'clients': [{'id': UUID, 'alterId': 0}]},
                'streamSettings': {
                    'network': 'ws', 'security': 'tls',
                    'tlsSettings': {'certificates': [{'certificateFile': CERT,
                                                      'keyFile': KEY}]},
                    'wsSettings': dict(ws)},
                'sniffing': {'enabled': True, 'destOverride': ['http', 'tls', 'quic'],
                             'metadataOnly': False}}],
            'outbounds': [{'protocol': 'freedom',
                           'settings': {'finalRules': [{'action': 'allow'}]}}]}
        cli = {
            'log': {'loglevel': 'warning'},
            'inbounds': [{'listen': '127.0.0.1', 'port': CLI_SOCKS, 'protocol': 'socks',
                          'settings': {'udp': True}}],
            'outbounds': [{
                'protocol': 'vmess',
                'settings': {'vnext': [{'address': '127.0.0.1', 'port': SRV_PORT,
                    'users': [{'id': UUID, 'alterId': 0, 'security': VMESS_SECURITY}]}]},
                'streamSettings': {
                    'network': 'ws', 'security': 'tls',
                    'tlsSettings': {'serverName': 'localhost',
                                    'pinnedPeerCertSha256': cert_pin()},
                    'wsSettings': dict(ws)}}]}
        return srv, cli
    # 默认拓扑：与改造前逐字一致（历史基线口径，禁改）
    srv = {
        'log': {'loglevel': 'warning'},
        'inbounds': [{
            'tag': 'xhttp-reality-enc', 'listen': '127.0.0.1', 'port': SRV_PORT,
            'protocol': 'vless',
            'settings': {'clients': [{'id': UUID}], 'decryption': dec},
            'streamSettings': {
                'network': 'xhttp', 'security': 'reality',
                'realitySettings': {
                    'fingerprint': 'chrome', 'target': 'www.mozilla.org:443',
                    'serverNames': ['www.mozilla.org'], 'privateKey': rpriv,
                    'shortIds': ['46d92137']},
                'xhttpSettings': {'host': '', 'path': 'enc8x-test', 'mode': 'auto'}},
            'sniffing': {'enabled': True, 'destOverride': ['http', 'tls', 'quic'],
                         'metadataOnly': False}}],
        'outbounds': [{'protocol': 'freedom',
                       'settings': {'finalRules': [{'action': 'allow'}]}}]}
    cli = {
        'log': {'loglevel': 'warning'},
        'inbounds': [{'listen': '127.0.0.1', 'port': CLI_SOCKS, 'protocol': 'socks',
                      'settings': {'udp': True}}],
        'outbounds': [{
            'protocol': 'vless',
            'settings': {'vnext': [{'address': '127.0.0.1', 'port': SRV_PORT,
                'users': [{'id': UUID, 'encryption': enc}]}]},
            'streamSettings': {
                'network': 'xhttp', 'security': 'reality',
                'realitySettings': {'serverName': 'www.mozilla.org', 'publicKey': rpub,
                                    'shortId': '46d92137', 'fingerprint': 'chrome'},
                'xhttpSettings': {'host': '', 'path': 'enc8x-test', 'mode': 'auto'}}}]}
    return srv, cli


def parse_stats_line(line):
    m = STATS_RE.search(line)
    if not m:
        return None
    t, an, ab, dn, db, live = m.groups()
    return dict(t=float(t), alloc_n=int(an), alloc_bytes=int(ab),
                dealloc_n=int(dn), dealloc_bytes=int(db), live_bytes=int(live))


def parse_sites_line(line):
    m = SITES_RE.search(line)
    if not m:
        return None
    t, site, an, ab, dn, db = m.groups()
    return dict(t=float(t), site=site, alloc_n=int(an), alloc_bytes=int(ab),
                d_n=int(dn), d_bytes=int(db))


def last_sites(log_path):
    """每站点最后一条累计快照；空 dict = 站点归集未开启（旧二进制/未设 env）。"""
    out = {}
    with open(log_path, 'rb') as f:
        for raw in f:
            line = raw.decode(errors='replace')
            if SITES_PREFIX in line:
                s = parse_sites_line(line)
                if s:
                    out[s['site']] = s
    return out


def sites_report(name, start, end, total_delta_bytes):
    """窗口差分按站点归集：top-N（Δbytes 降序）+ 字节占比 + 未标记桶。"""
    if not start and not end:
        print(f'sites[{name}]=N/A (XRAY_ALLOC_STATS_SITES 未开启)')
        return
    rows, sum_bytes = [], 0
    for site, e in (end or {}).items():
        s = (start or {}).get(site)
        d = e['alloc_bytes'] - (s['alloc_bytes'] if s else 0)
        dn = e['alloc_n'] - (s['alloc_n'] if s else 0)
        sum_bytes += d
        rows.append((d, dn, site))
    rows.sort(reverse=True)
    print(f'sites[{name}]:')
    for d, dn, site in rows:
        share = f' share={d / total_delta_bytes * 100:.1f}%' if total_delta_bytes > 0 else ''
        print(f'  site={site:<16} d_bytes={d:>12} d_n={dn:>9}{share}')
    untagged = total_delta_bytes - sum_bytes
    untagged_name = '(untagged)'
    share = f' share={untagged / total_delta_bytes * 100:.1f}%' if total_delta_bytes > 0 else ''
    print(f'  site={untagged_name:<16} d_bytes={untagged:>12}{share}'
          f'  # 守卫范围外: hyper/tokio/队列/握手等')


def last_stats(log_path):
    """日志里最后一条 stats 行；无则 None（计数未开启的旧二进制）。"""
    found = None
    with open(log_path, 'rb') as f:
        for raw in f:
            line = raw.decode(errors='replace')
            if PREFIX in line:
                s = parse_stats_line(line)
                if s:
                    found = s
    return found


def frame_counts(log_path, chunk_cap):
    """按 phase 归集桥接批：{phase: [批数, 总字节, 帧数]}；帧数需 chunk_cap。"""
    out = {}
    with open(log_path, 'rb') as f:
        for raw in f:
            m = P7LM_RE.search(raw.decode(errors='replace'))
            if not m:
                continue
            nbytes, phase = int(m.group(1)), m.group(2)
            row = out.setdefault(phase, [0, 0, 0])
            row[0] += 1
            row[1] += nbytes
            if chunk_cap:
                row[2] += -(-nbytes // chunk_cap)   # ceil：一批超上限会拆多帧
    return out


def curl(url, socks=None, timeout=130):
    cmd = ['curl', '-sS', '-o', 'NUL', '--max-time', str(timeout),
           '-w', '%{speed_download} %{size_download} %{time_total}']
    if socks:
        cmd += ['-x', socks]
    cmd.append(url)
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
    if r.returncode != 0:
        raise RuntimeError(f'curl failed rc={r.returncode}: {r.stderr}')
    speed, size, total = r.stdout.split()
    return float(speed), int(size), float(total)


def curl_put(url, path, socks=None, timeout=130):
    cmd = ['curl', '-sS', '-o', 'NUL', '-T', path, '--max-time', str(timeout),
           '-w', '%{speed_upload} %{size_upload} %{time_total}']
    if socks:
        cmd += ['-x', socks]
    cmd.append(url)
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
    if r.returncode != 0:
        raise RuntimeError(f'curl put failed rc={r.returncode}: {r.stderr}')
    speed, size, total = r.stdout.split()
    return float(speed), int(size), float(total)


class _SinkHandler(BaseHTTPRequestHandler):
    """--bidir 上传落点：吞掉请求体，丢弃内容（不落盘）。"""
    protocol_version = 'HTTP/1.1'

    def do_PUT(self):
        # 按 Content-Length 读满即返回：socket 上 EOF 要等关连接，读到 EOF 会挂死
        remain = int(self.headers.get('Content-Length') or 0)
        while remain > 0:
            chunk = self.rfile.read(min(remain, 1 << 16))
            if not chunk:
                break
            remain -= len(chunk)
        self.send_response(200)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def log_message(self, *a):
        pass


def start_sink():
    srv = ThreadingHTTPServer(('127.0.0.1', SINK_PORT), _SinkHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def take_sample(logs):
    return {'stats': {n: last_stats(p) for n, p in logs.items()},
            'sites': {n: last_sites(p) for n, p in logs.items()}}


def run_phase(runs, do_run, logs, label, suffix=''):
    """一个采样窗：窗首快照 → N 轮传输 → 等尾批采样 → 窗末快照。"""
    start = take_sample(logs)
    for proc in logs:
        print(f'window_start_{proc}{suffix}={json.dumps(start["stats"][proc])}')
    total_bytes, speeds = 0, []
    for i in range(runs):
        speed, size, total = do_run()
        total_bytes += size
        speeds.append(speed)
        print(f'[{label}] #{i+1}: speed={speed} B/s ({speed/1e6:.1f} MB/s) '
              f'size={size} time={total}s', flush=True)
    time.sleep(DUMPS_PERIOD_S)          # 等最后一条周期采样落地
    end = take_sample(logs)
    return {'suffix': suffix, 'bytes': total_bytes, 'speeds': speeds,
            'start': start, 'end': end}


def phase_alloc_mb(phase, proc):
    """该窗口内某进程的 alloc/MB；计数未开或无采样 → None。"""
    start = phase['start']['stats'].get(proc)
    end = phase['end']['stats'].get(proc)
    if not start or not end or phase['bytes'] <= 0:
        return None
    mb = phase['bytes'] / 1024 / 1024
    return (end['alloc_bytes'] - start['alloc_bytes']) / mb


def report_phase(phase, logs, chunk_cap, frames_on):
    suffix = phase['suffix']
    mb = phase['bytes'] / 1024 / 1024
    print(f'transferred={phase["bytes"]} bytes ({mb:.1f} MiB)')
    for proc, log in logs.items():
        start, end = phase['start']['stats'].get(proc), phase['end']['stats'].get(proc)
        alloc_mb = phase_alloc_mb(phase, proc)
        if alloc_mb is None:
            print(f'alloc/MB[{proc}{suffix}]=N/A (计数未开启或无采样)')
        else:
            d_bytes = end['alloc_bytes'] - start['alloc_bytes']
            d_n = end['alloc_n'] - start['alloc_n']
            print(f'alloc/MB[{proc}{suffix}] = {d_bytes / mb:.0f} '
                  f'(Δalloc_bytes={d_bytes}, Δalloc_n={d_n}, {mb:.1f} MiB)')
            sites_report(f'{proc}{suffix}', phase['start']['sites'].get(proc),
                         phase['end']['sites'].get(proc), d_bytes)
        if frames_on:
            report_frames(proc, suffix, log, mb, chunk_cap)


def report_frames(proc, suffix, log, mb, chunk_cap):
    counts = frame_counts(log, chunk_cap)
    if not counts:
        print(f'frames[{proc}{suffix}]=N/A (XRAY_P7LM_TRACE 未开启或无批)')
        return
    for trace_phase, (n, nbytes, frames) in sorted(counts.items()):
        mean = nbytes / n if n else 0
        line = (f'frames[{proc}{suffix}] {trace_phase}: batches={n} bytes={nbytes} '
                f'mean_batch={mean:.0f}B batches/MiB={n / mb:.1f}')
        if chunk_cap:
            line += f' frames/MiB={frames / mb:.1f}'
        print(line)


def bench_once(exe, tag, topo, runs, alloc_stats, bidir=False, frames_on=False):
    """完整起停一次链路并采集；返回 {'phases': [采样窗], 'logs': {proc: log 路径}}。"""
    meta = TOPOLOGIES[topo]
    srv_cfg, cli_cfg = build_configs(topo, read_keys())
    sp = os.path.join(WORK, f'srv-{tag}.json')
    cp = os.path.join(WORK, f'cli-{tag}.json')
    json.dump(srv_cfg, open(sp, 'w'), indent=1)
    json.dump(cli_cfg, open(cp, 'w'), indent=1)

    if not os.path.exists(BIG) or os.path.getsize(BIG) != SIZE_MB * 1024 * 1024:
        print(f'generating {SIZE_MB}MB file...')
        open(BIG, 'wb').write(os.urandom(SIZE_MB * 1024 * 1024))

    env = dict(os.environ)
    if alloc_stats:
        env['XRAY_ALLOC_STATS'] = '1'
        env['XRAY_ALLOC_STATS_INTERVAL_MS'] = '1000'
        env['XRAY_ALLOC_STATS_SITES'] = '1'  # 站点归集随 --alloc-stats 一并开启
    if frames_on:
        env['XRAY_P7LM_TRACE'] = '1'

    srv_log = os.path.join(WORK, f'srv-{tag}.log')
    cli_log = os.path.join(WORK, f'cli-{tag}.log')
    logs = {'srv': srv_log, 'cli': cli_log}
    httpd = subprocess.Popen([sys.executable, '-m', 'http.server', str(HTTP_PORT),
                              '--bind', '127.0.0.1'], cwd=WORK,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sink = start_sink() if bidir else None
    time.sleep(1.0)
    ps = subprocess.Popen([exe, 'run', '-c', sp],
                          stdout=open(srv_log, 'wb'), stderr=subprocess.STDOUT, env=env)
    time.sleep(2.0)
    pc = subprocess.Popen([exe, 'run', '-c', cp],
                          stdout=open(cli_log, 'wb'), stderr=subprocess.STDOUT, env=env)
    time.sleep(2.0)
    # 单窗默认拓扑不带后缀，保持旧版逐字输出
    phases = []
    socks = f'socks5h://127.0.0.1:{CLI_SOCKS}'
    dl_url = f'http://127.0.0.1:{HTTP_PORT}/big.bin'
    ul_url = f'http://127.0.0.1:{SINK_PORT}/sink'
    try:
        phases.append(run_phase(runs, lambda: curl(dl_url, socks=socks), logs,
                                meta['label'], '-dl' if bidir else ''))
        if bidir:
            phases.append(run_phase(runs, lambda: curl_put(ul_url, BIG, socks=socks),
                                    logs, meta['label'], '-ul'))
    finally:
        for p in (pc, ps, httpd):
            p.terminate()
        if sink:
            sink.shutdown()
            sink.server_close()          # 释放端口，--ab --bidir 逐轮重绑
    # 终止后再采一窗末，锁住尾批分配（旧版口径）；末窗以重采结果为准
    phases[-1]['end'] = take_sample(logs)
    for phase in phases:
        for proc in logs:
            print(f'window_end_{proc}{phase["suffix"]}'
                  f'={json.dumps(phase["end"]["stats"][proc])}')
    return {'phases': phases, 'logs': logs}


def utc_now():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def dispersion(vals):
    if len(vals) < 2:
        return 0.0
    mid = statistics.median(vals)
    return (max(vals) - min(vals)) / mid if mid else 0.0


def run_ab(args, topo):
    """同窗交错 A/B：每轮 A/B 相邻成对（顺序逐轮反相），判据取**逐对比值的中位**。

    反相理由：同二进制 A 先跑、B 后跑实测差 21%（本次自测）——顺序偏差只有反相能抵掉；
    逐对比值只用相邻两次（时间窗最紧）的量，比「两侧各取中位再相除」更抗窗口漂移。
    """
    tol = args.ab_tol
    sides = {'A': args.ab, 'B': args.xray}
    res = {'A': [], 'B': []}
    pairs = []
    # 编译进程是窗口串扰的头号来源（实测把同一二进制打成 CONTAMINATED）；只警告不拒跑
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from ab_gate import compiler_procs
        procs, _ = compiler_procs()
        if procs:
            print(f'ab WARN: 检测到编译进程 {sorted(set(procs))}——窗口会被串扰，'
                  f'建议等编译结束再跑', file=sys.stderr)
    except Exception as e:            # 扫描器不可用不影响测量，但必须可见
        print(f'ab WARN: 编译进程扫描不可用（{e}），无法预警窗口串扰', file=sys.stderr)
    t_begin = utc_now()
    for r in range(args.ab_runs):
        order = ('A', 'B') if r % 2 == 0 else ('B', 'A')   # 逐轮反相，抵顺序偏差
        round_speed = {}
        for side in order:
            t0 = utc_now()
            out = bench_once(sides[side], f'{args.tag}-ab{r + 1}{side}', topo, 1,
                             alloc_stats=True, bidir=args.bidir, frames_on=False)
            phase = out['phases'][0]
            speed = phase['speeds'][0] / 1e6
            alloc = {p: phase_alloc_mb(phase, p) for p in out['logs']}
            res[side].append({'speed': speed, 'alloc_mb': alloc, 't0': t0,
                              't1': utc_now()})
            round_speed[side] = speed
            print(f'ab round {r + 1}{side} (order {"/".join(order)}): '
                  f'speed={speed:.1f} MB/s alloc_MB={alloc} '
                  f'window={t0}..{res[side][-1]["t1"]}', flush=True)
        pairs.append((round_speed['A'], round_speed['B']))
    t_end = utc_now()
    speeds = {s: [x['speed'] for x in res[s]] for s in res}
    med = {s: statistics.median(speeds[s]) for s in res}
    disp = {s: dispersion(speeds[s]) for s in res}
    pair_ratios = [b / a for a, b in pairs if a]
    ratio = statistics.median(pair_ratios) if pair_ratios else 0.0
    delta = ratio - 1
    print(f'ab: rounds={args.ab_runs} topo={topo} tol={tol:.0%} '
          f'window={t_begin}..{t_end} order=反相交替')
    for s in ('A', 'B'):
        print(f'ab {s} ({sides[s]}): median={med[s]:.1f} MB/s '
              f'dispersity={disp[s]:.1%} runs={[round(v, 1) for v in speeds[s]]}')
    print(f'ab pair ratios(B/A)={[round(v, 3) for v in pair_ratios]} '
          f'median={ratio:.3f}')
    for proc in ('srv', 'cli'):
        va = [x['alloc_mb'][proc] for x in res['A'] if x['alloc_mb'][proc]]
        vb = [x['alloc_mb'][proc] for x in res['B'] if x['alloc_mb'][proc]]
        if va and vb:
            ma, mb2 = statistics.median(va), statistics.median(vb)
            print(f'ab alloc/MB[{proc}]: A={ma:.3f} B={mb2:.3f} '
                  f'ratio(B/A)={mb2 / ma:.3f} ({(mb2 / ma - 1):+.1%})')
    if args.ab_runs < 2:                 # 无轮可反相、无离散度 → 不给判据
        print(f'ab INDETERMINATE: rounds=1 无法抵顺序偏差也无离散度，'
              f'ratio(B/A)={ratio:.3f} 仅供参考（建议 --ab-runs 3）', file=sys.stderr)
        sys.exit(2)
    print(f'ab ratio(B/A)={ratio:.3f} ({delta:+.1%}) -> '
          f'{"PASS" if abs(delta) <= tol else "FAIL"}')
    if max(disp.values()) > DISPERSE_THRESH:
        print(f'ab CONTAMINATED: 轮间离散度 {max(disp.values()):.1%} > '
              f'{DISPERSE_THRESH:.0%}（串扰或窗口漂移，读数不可判）', file=sys.stderr)
        sys.exit(3)
    if abs(delta) > tol:
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--xray', required=True, help='被测二进制（A/B 模式下 = B 侧）')
    ap.add_argument('--tag', required=True)
    ap.add_argument('--runs', type=int, default=3)
    ap.add_argument('--alloc-stats', action='store_true')
    ap.add_argument('--floor', type=float, default=120.0,
                    help='min acceptable throughput MB/s (best run); below -> exit 1')
    ap.add_argument('--topo', default=DEFAULT_TOPO, choices=sorted(TOPOLOGIES),
                    help=f'链路拓扑（默认 {DEFAULT_TOPO} = 改造前唯一拓扑）')
    ap.add_argument('--bidir', action='store_true',
                    help='下载窗 + 上传窗各测一遍（alloc/MB 分窗口，不混口径）')
    ap.add_argument('--frames', action='store_true',
                    help='额外读 XRAY_P7LM_TRACE 批埋点算帧粒度（该 pass 吞吐无效）')
    ap.add_argument('--ab', metavar='A_BIN', help='A 侧二进制；--xray 为 B 侧')
    ap.add_argument('--ab-runs', type=int, default=3, help='A/B 各跑几轮（交错）')
    ap.add_argument('--ab-tol', type=float, default=0.05,
                    help='|ratio(B/A)-1| 判定阈值（默认 5%%）')
    args = ap.parse_args()

    if args.ab:
        run_ab(args, args.topo)          # 交错模式自带读数输出，比值不达标已 exit 1
        return

    if args.topo != DEFAULT_TOPO:
        print(f'topo={args.topo} chunk_cap={TOPOLOGIES[args.topo]["chunk_cap"]}'
              f'{" (--frames 开启：本 pass 吞吐无效)" if args.frames else ""}')
    print(f'tag={args.tag} xray={args.xray} alloc_stats={args.alloc_stats}')
    out = bench_once(args.xray, args.tag, args.topo, args.runs, args.alloc_stats,
                     bidir=args.bidir, frames_on=args.frames)
    cap = TOPOLOGIES[args.topo]['chunk_cap']
    for phase in out['phases']:
        report_phase(phase, out['logs'], cap, args.frames)

    speeds = out['phases'][0]['speeds']
    if speeds:
        best = max(speeds) / 1e6
        print(f'floor check: best={best:.1f} MB/s vs floor={args.floor} MB/s')
        if best < args.floor:
            print(f'FLOOR FAIL: best {best:.1f} < floor {args.floor} MB/s', file=sys.stderr)
            sys.exit(1)


if __name__ == '__main__':
    main()
