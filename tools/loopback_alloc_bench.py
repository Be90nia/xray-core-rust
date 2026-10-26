"""loopback 全栈测速 + alloc/MB 基线采集（框架支线 P0 护栏）。

复刻 D:/tmp/enc8x/setup.py 的 xhttp+reality+vless(mlkem-enc) 拓扑（自包含，
不 import setup.py），叠加 XRAY_ALLOC_STATS 计数分配器采样：
- 每进程累计 alloc/dealloc 计数行由 xray 定期打 stderr（[xray-alloc-stats] 前缀）
- 采集窗口 = 窗口前采样 → 末次采样，alloc/MB = Δalloc_bytes / 下载字节

用法:
  python tools/loopback_alloc_bench.py --tag r1 --xray <exe> [--runs 3] [--alloc-stats] [--floor N]
输出: 每轮 curl speed 行 + 窗口 alloc/MB 汇总（stdout，直接贴 baseline.md）。
"""
import argparse, json, os, re, subprocess, sys, time

WORK = 'D:/tmp/enc8x'
UUID = '6ea1458e-8c33-4a0e-9a72-8e4b9c1e5d01'
SRV_PORT, CLI_SOCKS, HTTP_PORT = 18453, 11081, 18100
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--xray', required=True)
    ap.add_argument('--tag', required=True)
    ap.add_argument('--runs', type=int, default=3)
    ap.add_argument('--alloc-stats', action='store_true')
    ap.add_argument('--floor', type=float, default=120.0,
                    help='min acceptable throughput MB/s (best run); below -> exit 1')
    args = ap.parse_args()

    dec, enc, rpriv, rpub = read_keys()
    srv_cfg = {
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
    cli_cfg = {
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
    sp = os.path.join(WORK, f'srv-{args.tag}.json')
    cp = os.path.join(WORK, f'cli-{args.tag}.json')
    json.dump(srv_cfg, open(sp, 'w'), indent=1)
    json.dump(cli_cfg, open(cp, 'w'), indent=1)

    if not os.path.exists(BIG) or os.path.getsize(BIG) != SIZE_MB * 1024 * 1024:
        print(f'generating {SIZE_MB}MB file...')
        open(BIG, 'wb').write(os.urandom(SIZE_MB * 1024 * 1024))

    env = dict(os.environ)
    if args.alloc_stats:
        env['XRAY_ALLOC_STATS'] = '1'
        env['XRAY_ALLOC_STATS_INTERVAL_MS'] = '1000'
        env['XRAY_ALLOC_STATS_SITES'] = '1'  # 站点归集随 --alloc-stats 一并开启

    srv_log = os.path.join(WORK, f'srv-{args.tag}.log')
    cli_log = os.path.join(WORK, f'cli-{args.tag}.log')
    httpd = subprocess.Popen([sys.executable, '-m', 'http.server', str(HTTP_PORT),
                              '--bind', '127.0.0.1'], cwd=WORK,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    ps = subprocess.Popen([args.xray, 'run', '-c', sp],
                          stdout=open(srv_log, 'wb'), stderr=subprocess.STDOUT, env=env)
    time.sleep(2.0)
    pc = subprocess.Popen([args.xray, 'run', '-c', cp],
                          stdout=open(cli_log, 'wb'), stderr=subprocess.STDOUT, env=env)
    time.sleep(2.0)
    print(f'tag={args.tag} xray={args.xray} alloc_stats={args.alloc_stats}')
    start_srv, start_cli = last_stats(srv_log), last_stats(cli_log)
    start_sites = {'srv': last_sites(srv_log), 'cli': last_sites(cli_log)}
    print(f'window_start_srv={json.dumps(start_srv)}')
    print(f'window_start_cli={json.dumps(start_cli)}')
    total_bytes = 0
    speeds = []
    try:
        url = f'http://127.0.0.1:{HTTP_PORT}/big.bin'
        for i in range(args.runs):
            speed, size, total = curl(url, socks=f'socks5h://127.0.0.1:{CLI_SOCKS}')
            total_bytes += size
            speeds.append(speed)
            print(f'[via-enc-chain] #{i+1}: speed={speed} B/s ({speed/1e6:.1f} MB/s) '
                  f'size={size} time={total}s', flush=True)
    finally:
        time.sleep(1.5)  # 等最后一条周期采样落地
        for p in (pc, ps, httpd):
            p.terminate()
    end_srv, end_cli = last_stats(srv_log), last_stats(cli_log)
    end_sites = {'srv': last_sites(srv_log), 'cli': last_sites(cli_log)}
    print(f'window_end_srv={json.dumps(end_srv)}')
    print(f'window_end_cli={json.dumps(end_cli)}')
    mb = total_bytes / 1024 / 1024
    print(f'transferred={total_bytes} bytes ({mb:.1f} MiB)')

    for name, start, end in (('srv', start_srv, end_srv), ('cli', start_cli, end_cli)):
        if not start or not end:
            print(f'alloc/MB[{name}]=N/A (计数未开启或无采样)')
            continue
        d_bytes = end['alloc_bytes'] - start['alloc_bytes']
        d_n = end['alloc_n'] - start['alloc_n']
        print(f'alloc/MB[{name}] = {d_bytes / mb:.0f} '
              f'(Δalloc_bytes={d_bytes}, Δalloc_n={d_n}, {mb:.1f} MiB)')
        sites_report(name, start_sites[name], end_sites[name], d_bytes)

    if speeds:
        best = max(speeds) / 1e6
        print(f'floor check: best={best:.1f} MB/s vs floor={args.floor} MB/s')
        if best < args.floor:
            print(f'FLOOR FAIL: best {best:.1f} < floor {args.floor} MB/s', file=sys.stderr)
            sys.exit(1)


if __name__ == '__main__':
    main()
