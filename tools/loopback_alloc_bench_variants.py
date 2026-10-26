"""A/B 变体归因测速（audit-2026-10-25 perf-framework-cost 专用）。

在 tools/loopback_alloc_bench.py 基础上加 --variant 拓扑旋钮，做差分归因：
- full        : 与原脚本完全一致（vless+mlkem-enc over xhttp+reality）
- plain-xhttp : vless 加密关（decryption/encryption=none），仍走 xhttp+reality
                → full − plain = mlkem-enc 成本
- tcp-tls     : vless plain over 裸 TCP+TLS（自签证书 allowInsecure）
                → plain-xhttp − tcp-tls = xhttp/h2 传输层成本
- direct      : 单进程 socks→freedom（无第二跳）
                → 直接量出 socks+dispatcher+freedom 基线

另：采集完整 [xray-alloc-stats] 1s 采样序列（原脚本只取首末两条），
用于区分握手期 vs relay 稳态期的分配速率。

用法:
  python tools/loopback_alloc_bench_variants.py --variant full --xray <exe> \
      --runs 3 --alloc-stats --tag t1
"""
import argparse, json, os, re, subprocess, sys, time

WORK = 'D:/tmp/enc8x'
CERT = 'D:/tmp/interop_cert.pem'
KEY = 'D:/tmp/interop_key.pem'
UUID = '6ea1458e-8c33-4a0e-9a72-8e4b9c1e5d01'
SRV_PORT, CLI_SOCKS, HTTP_PORT = 18453, 11081, 18100
BIG = os.path.join(WORK, 'big.bin')
SIZE_MB = 200
PREFIX = '[xray-alloc-stats]'

STATS_RE = re.compile(
    r't=([\d.]+)s alloc_n=(\d+) alloc_bytes=(\d+) '
    r'dealloc_n=(\d+) dealloc_bytes=(\d+) live_bytes=(-?\d+)')


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


def all_stats(log_path):
    out = []
    with open(log_path, 'rb') as f:
        for raw in f:
            line = raw.decode(errors='replace')
            if PREFIX in line:
                s = parse_stats_line(line)
                if s:
                    out.append(s)
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


def stream(security, network, dec, enc, rpriv, rpub):
    """构造 streamSettings（srv 用 target 侧，cli 用 dial 侧）。"""
    if variant_security(security) == 'reality':
        srv = {'network': network, 'security': 'reality',
               'realitySettings': {
                   'fingerprint': 'chrome', 'target': 'www.mozilla.org:443',
                   'serverNames': ['www.mozilla.org'], 'privateKey': rpriv,
                   'shortIds': ['46d92137']}}
        cli = {'network': network, 'security': 'reality',
               'realitySettings': {'serverName': 'www.mozilla.org',
                                   'publicKey': rpub, 'shortId': '46d92137',
                                   'fingerprint': 'chrome'}}
        return srv, cli
    srv = {'network': network, 'security': 'tls',
           'tlsSettings': {'certificates': [{'certificateFile': CERT,
                                             'keyFile': KEY}]}}
    cli = {'network': network, 'security': 'tls',
           'tlsSettings': {'serverName': 'localhost',
                           'pinnedPeerCertSha256': cert_pin()}}
    return srv, cli


def cert_pin():
    """leaf DER sha256（allowInsecure 已配置期硬错，interop_matrix 同配方）。"""
    import base64, hashlib
    with open(CERT) as f:
        der = base64.b64decode(
            ''.join(l for l in f.read().splitlines() if '-----' not in l))
    return hashlib.sha256(der).hexdigest()


def variant_security(security):
    return security


def build_configs(variant):
    dec, enc, rpriv, rpub = read_keys()
    if variant == 'direct':
        cli_cfg = {
            'log': {'loglevel': 'warning'},
            'inbounds': [{'listen': '127.0.0.1', 'port': CLI_SOCKS,
                          'protocol': 'socks', 'settings': {'udp': True}}],
            'outbounds': [{'protocol': 'freedom',
                           'settings': {'finalRules': [{'action': 'allow'}]}}]}
        return None, cli_cfg
    if variant == 'tcp-tls':
        dec = enc = 'none'
        network = 'tcp'
    else:
        network = 'xhttp'
    srv_stream, cli_stream = stream('reality' if variant != 'tcp-tls' else 'tls',
                                    network, dec, enc, rpriv, rpub)
    vdec = dec if variant == 'full' else 'none'
    venc = enc if variant == 'full' else 'none'
    xhttp_srv = {'host': '', 'path': 'enc8x-test', 'mode': 'auto'}
    srv_cfg = {
        'log': {'loglevel': 'warning'},
        'inbounds': [{
            'tag': 'vless-in', 'listen': '127.0.0.1', 'port': SRV_PORT,
            'protocol': 'vless',
            'settings': {'clients': [{'id': UUID}], 'decryption': vdec},
            'streamSettings': srv_stream,
            'sniffing': {'enabled': True, 'destOverride': ['http', 'tls', 'quic'],
                         'metadataOnly': False}}],
        'outbounds': [{'protocol': 'freedom',
                       'settings': {'finalRules': [{'action': 'allow'}]}}]}
    if variant != 'tcp-tls':
        srv_cfg['inbounds'][0]['streamSettings']['xhttpSettings'] = xhttp_srv
    cli_cfg = {
        'log': {'loglevel': 'warning'},
        'inbounds': [{'listen': '127.0.0.1', 'port': CLI_SOCKS,
                      'protocol': 'socks', 'settings': {'udp': True}}],
        'outbounds': [{
            'protocol': 'vless',
            'settings': {'vnext': [{'address': '127.0.0.1', 'port': SRV_PORT,
                'users': [{'id': UUID, 'encryption': venc}]}]},
            'streamSettings': cli_stream}]}
    if variant != 'tcp-tls':
        cli_cfg['outbounds'][0]['streamSettings']['xhttpSettings'] = xhttp_srv
    return srv_cfg, cli_cfg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--xray', required=True)
    ap.add_argument('--variant', required=True,
                    choices=['full', 'plain-xhttp', 'tcp-tls', 'direct'])
    ap.add_argument('--tag', required=True)
    ap.add_argument('--runs', type=int, default=3)
    ap.add_argument('--alloc-stats', action='store_true')
    ap.add_argument('--floor', type=float, default=0.0)
    args = ap.parse_args()

    srv_cfg, cli_cfg = build_configs(args.variant)
    sp = cp = None
    if srv_cfg:
        sp = os.path.join(WORK, f'srv-{args.tag}.json')
        cp = os.path.join(WORK, f'cli-{args.tag}.json')
        json.dump(srv_cfg, open(sp, 'w'), indent=1)
        json.dump(cli_cfg, open(cp, 'w'), indent=1)
    else:
        cp = os.path.join(WORK, f'cli-{args.tag}.json')
        json.dump(cli_cfg, open(cp, 'w'), indent=1)

    if not os.path.exists(BIG) or os.path.getsize(BIG) != SIZE_MB * 1024 * 1024:
        print(f'generating {SIZE_MB}MB file...')
        open(BIG, 'wb').write(os.urandom(SIZE_MB * 1024 * 1024))

    env = dict(os.environ)
    if args.alloc_stats:
        env['XRAY_ALLOC_STATS'] = '1'
        env['XRAY_ALLOC_STATS_INTERVAL_MS'] = '1000'

    srv_log = os.path.join(WORK, f'srv-{args.tag}.log')
    cli_log = os.path.join(WORK, f'cli-{args.tag}.log')
    httpd = subprocess.Popen([sys.executable, '-m', 'http.server', str(HTTP_PORT),
                              '--bind', '127.0.0.1'], cwd=WORK,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    ps = None
    if sp:
        ps = subprocess.Popen([args.xray, 'run', '-c', sp],
                              stdout=open(srv_log, 'wb'),
                              stderr=subprocess.STDOUT, env=env)
        time.sleep(2.0)
    pc = subprocess.Popen([args.xray, 'run', '-c', cp],
                          stdout=open(cli_log, 'wb'),
                          stderr=subprocess.STDOUT, env=env)
    time.sleep(2.0)
    print(f'tag={args.tag} variant={args.variant} xray={args.xray} '
          f'alloc_stats={args.alloc_stats}')
    start_cli = all_stats(cli_log)[-1:] or [None]
    start_srv = all_stats(srv_log)[-1:] or [None] if sp else [None]
    total_bytes = 0
    speeds = []
    try:
        url = f'http://127.0.0.1:{HTTP_PORT}/big.bin'
        for i in range(args.runs):
            speed, size, total = curl(url, socks=f'socks5h://127.0.0.1:{CLI_SOCKS}')
            total_bytes += size
            speeds.append(speed)
            print(f'[{args.variant}] #{i+1}: speed={speed} B/s '
                  f'({speed/1e6:.1f} MB/s) size={size} time={total}s', flush=True)
    finally:
        time.sleep(1.5)
        for p in (pc, ps, httpd):
            if p:
                p.terminate()
    mb = total_bytes / 1024 / 1024
    print(f'transferred={total_bytes} bytes ({mb:.1f} MiB)')

    for name, log, start in (('srv', srv_log, start_srv[0]),
                             ('cli', cli_log, start_cli[0])):
        if ps is None and name == 'srv':
            continue
        series = all_stats(log)
        if not series:
            print(f'alloc/MB[{name}]=N/A (计数未开启或无采样)')
            continue
        end = series[-1]
        s = start or series[0]
        d_bytes = end['alloc_bytes'] - s['alloc_bytes']
        d_n = end['alloc_n'] - s['alloc_n']
        print(f'alloc/MB[{name}] = {d_bytes / mb / 1e6:.3f} '
              f'(Δalloc_bytes={d_bytes}, Δalloc_n={d_n}, {mb:.1f} MiB)')
        print(f'series[{name}]: ' + ' | '.join(
            f"t{int(x['t'])}:{(x['alloc_bytes'])//2**20}MB/{x['alloc_n']}"
            for x in series))

    if speeds and args.floor > 0 and max(speeds) / 1e6 < args.floor:
        print(f'FLOOR FAIL: best={max(speeds)/1e6:.1f} < {args.floor}')
        sys.exit(1)


if __name__ == '__main__':
    main()
