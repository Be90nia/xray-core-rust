"""同窗交错 A/B 吞吐对比闸（baseline.md 2026-10-27 校准纪律的工装）。

背景：本机 loopback 跑分随窗口漂 ~20%，同二进制跨窗也漂 ~20%——绝对值不可跨窗比较，
只有同窗口内交错 A/B 看比值才有意义。本工具把该纪律固化：
- 严格 A,B,A,B,... 交替（每侧每轮 = 一次 loopback_alloc_bench --runs 1，200MB 全链路）
- 启动前扫 cargo/rustc/cl 编译进程，默认拒跑（--force 覆盖并记录）
- 每轮记录编译进程计数 + 时间戳
- 任一侧轮间离散度 (max-min)/median > 15% -> CONTAMINATED，exit 3
- 判定用中位数比值 B/A（抗离群）：ratio < 1 - tol 即 FAIL，exit 1
- 结果存 reports/bench/ab-<UTC>-<tag>.json

用法:
  python tools/ab_gate.py --b target/release/xray.exe --tag mytest [--rounds 5] [--tol 0.05]
  python tools/ab_gate.py --a target/release/xray.exe --b D:/Project/Xray-core/target/xray-go.exe

场景（--scenario）:
  minvless  自建最小拓扑：裸 vless+tcp loopback，200MB×2 curl 取均值。任意 Xray 兼容二进制
            （Rust/Go）都能跑，跨二进制对比用这个（默认）。
  loopback  复用 tools/loopback_alloc_bench.py（xhttp+reality+vless mlkem-enc 基线拓扑）。
            与 baseline.md 数字同拓扑，但密钥取 ML-KEM-768 变体，旧 Go 二进制不支持——
            仅限 Rust↔Rust 对比。

退出码: 0=PASS  1=FAIL(比值超阈)  2=环境/运行错误  3=CONTAMINATED  4=检测到编译活动拒跑
"""
import argparse, hashlib, json, os, re, socket, statistics, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, 'loopback_alloc_bench.py')
REPORT_DIR = os.path.join(HERE, '..', 'reports', 'bench')
CONTAM_THRESH = 0.15          # 轮间离散度阈值（baseline.md 校准纪律）
SPEED_RE = re.compile(r'\[via-enc-chain\] #1: speed=([\d.]+) B/s \(([\d.]+) MB/s\)')
COMPILERS = ('cargo.exe', 'rustc.exe', 'cl.exe')
RUN_TIMEOUT = 200             # 单轮 subprocess 上限（bench 内部 curl max-time 130s + 启动开销）

# --- minvless 自建最小场景 ---
WORK = 'D:/tmp/abgate'
UUID = '3f2b8a64-9c1d-4e7a-b5f2-8d6c0a91e4b7'
SRV_PORT, CLI_SOCKS, HTTP_PORT = 18454, 11082, 18101
BIG = os.path.join(WORK, 'big.bin')
SIZE_MB, NCURL = 200, 2       # 每轮 2 次 200MB 下载取均值（拉长测量窗降噪声）


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def compiler_procs():
    """tasklist 数 cargo/rustc/cl 进程；tasklist 不可用返回 (None, [])。"""
    try:
        out = subprocess.run(['tasklist', '/FO', 'CSV', '/NH'], capture_output=True,
                             text=True, timeout=30).stdout
    except Exception as e:
        return None, [f'tasklist failed: {e}']
    found = []
    for line in out.splitlines():
        name = line.split(',')[0].strip('"').lower() if ',' in line else ''
        if name in COMPILERS:
            found.append(name)
    return found, []


def load_sample():
    procs, err = compiler_procs()
    n = {c: procs.count(c) for c in COMPILERS} if procs is not None else None
    return {'ts': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'compilers': n, 'err': err}


def run_loopback(tag, side, idx, exe):
    """跑一轮单侧基准（200MB xhttp+reality+vless 全链路），返回 MB/s。"""
    rtag = f'{tag}-{side.lower()}{idx}'
    cmd = [sys.executable, BENCH, '--xray', exe, '--tag', rtag, '--runs', '1']
    t0 = time.time()
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=RUN_TIMEOUT)
    wall = time.time() - t0
    m = SPEED_RE.search(r.stdout)
    if not m:
        tail = '\n'.join((r.stdout + r.stderr).splitlines()[-15:])
        raise RuntimeError(f'round {side}#{idx}: bench 无速度行 (rc={r.returncode}, {wall:.1f}s)\n{tail}')
    return float(m.group(1)) / 1e6, wall


def run_minvless(tag, side, idx, exe):
    """跑一轮单侧基准（裸 vless+tcp，200MB×2 curl 均值），返回 MB/s。"""
    rtag = f'{tag}-{side.lower()}{idx}'
    os.makedirs(WORK, exist_ok=True)
    if not os.path.exists(BIG) or os.path.getsize(BIG) != SIZE_MB * 1024 * 1024:
        print(f'  generating {SIZE_MB}MB file...', flush=True)
        open(BIG, 'wb').write(os.urandom(SIZE_MB * 1024 * 1024))
    srv_cfg = {'log': {'loglevel': 'warning'},
               'inbounds': [{'listen': '127.0.0.1', 'port': SRV_PORT, 'protocol': 'vless',
                             'settings': {'clients': [{'id': UUID}], 'decryption': 'none'}}],
               'outbounds': [{'protocol': 'freedom',
                              'settings': {'finalRules': [{'action': 'allow'}]}}]}
    cli_cfg = {'log': {'loglevel': 'warning'},
               'inbounds': [{'listen': '127.0.0.1', 'port': CLI_SOCKS, 'protocol': 'socks',
                             'settings': {'udp': True}}],
               'outbounds': [{'protocol': 'vless',
                              'settings': {'vnext': [{'address': '127.0.0.1', 'port': SRV_PORT,
                                  'users': [{'id': UUID, 'encryption': 'none'}]}]}}]}
    sp, cp = os.path.join(WORK, f'srv-{rtag}.json'), os.path.join(WORK, f'cli-{rtag}.json')
    json.dump(srv_cfg, open(sp, 'w'), indent=1)
    json.dump(cli_cfg, open(cp, 'w'), indent=1)
    t0 = time.time()
    httpd = subprocess.Popen([sys.executable, '-m', 'http.server', str(HTTP_PORT),
                              '--bind', '127.0.0.1'], cwd=WORK,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    ps = subprocess.Popen([exe, 'run', '-c', sp],
                          stdout=open(os.path.join(WORK, f'srv-{rtag}.log'), 'wb'),
                          stderr=subprocess.STDOUT)
    time.sleep(2.0)
    pc = subprocess.Popen([exe, 'run', '-c', cp],
                          stdout=open(os.path.join(WORK, f'cli-{rtag}.log'), 'wb'),
                          stderr=subprocess.STDOUT)
    time.sleep(2.0)
    speeds = []
    try:
        for _ in range(NCURL):
            r = subprocess.run(['curl', '-sS', '-o', 'NUL', '--max-time', '130',
                                '-w', '%{speed_download}',
                                '-x', f'socks5h://127.0.0.1:{CLI_SOCKS}',
                                f'http://127.0.0.1:{HTTP_PORT}/big.bin'],
                               capture_output=True, text=True, timeout=140)
            if r.returncode != 0:
                raise RuntimeError(f'round {side}#{idx}: curl rc={r.returncode}: '
                                   f'{r.stderr.strip()[-300:]} (日志 {WORK}/{{srv,cli}}-{rtag}.log)')
            speeds.append(float(r.stdout.strip()) / 1e6)
    finally:
        for p in (pc, ps, httpd):
            p.terminate()
    wall = time.time() - t0
    return sum(speeds) / len(speeds), wall


def run_side(tag, side, idx, exe, scenario):
    return (run_loopback if scenario == 'loopback' else run_minvless)(tag, side, idx, exe)


def summarize(vals):
    med = statistics.median(vals)
    mad = statistics.median(abs(v - med) for v in vals) if med else 0.0
    if len(vals) >= 3:
        q = statistics.quantiles(vals, n=4, method='inclusive')
        iqr = q[2] - q[0]
    else:
        iqr = max(vals) - min(vals)
    spread = (max(vals) - min(vals)) / med if med else float('inf')
    return med, mad, iqr, spread


def main():
    ap = argparse.ArgumentParser(
        description='同窗交错 A/B 吞吐对比闸（中位数比值判定，编译污染检测）',
        epilog='退出码: 0=PASS 1=FAIL 2=ERROR 3=CONTAMINATED 4=REFUSED(编译活动)')
    ap.add_argument('--a', dest='bin_a', default='target/release/xray.exe',
                    help='基准侧二进制（默认 target/release/xray.exe）')
    ap.add_argument('--b', dest='bin_b', required=True, help='对照侧二进制（必填）')
    ap.add_argument('--rounds', type=int, default=5, help='交错轮数（每轮 A,B 各一次，默认 5）')
    ap.add_argument('--tol', type=float, default=0.05,
                    help='允许 B 比 A 慢的比例（默认 0.05 = 5%%）')
    ap.add_argument('--tag', default='ab', help='存档 tag（默认 ab）')
    ap.add_argument('--scenario', choices=('minvless', 'loopback'), default='minvless',
                    help='minvless=裸 vless+tcp（跨二进制，默认）；loopback=基线拓扑（仅 Rust↔Rust）')
    ap.add_argument('--force', action='store_true',
                    help='检测到编译进程仍强行运行（记入报告）')
    args = ap.parse_args()

    for p in (args.bin_a, args.bin_b):
        if not os.path.exists(p):
            print(f'ERROR: 二进制不存在: {p}', file=sys.stderr)
            sys.exit(2)

    # --- 启动前污染检查 ---
    pre, pre_err = compiler_procs()
    forced = False
    if pre is None:
        print(f'WARN: 无法扫描进程（{pre_err}），跳过预检', flush=True)
    elif pre:
        if not args.force:
            print(f'REFUSED: 检测到编译活动 {sorted(set(pre))} x{len(pre)} —— loopback 跑分会被压低约20%。\n'
                  f'  等编译结束再跑，或确认知情用 --force。', file=sys.stderr)
            sys.exit(4)
        forced = True
        print(f'WARN: --force 覆盖预检（{sorted(set(pre))} x{len(pre)}），已记入报告', flush=True)

    sha_a, sha_b = sha256(args.bin_a), sha256(args.bin_b)
    print(f'AB-GATE start tag={args.tag} rounds={args.rounds} tol={args.tol}\n'
          f'  A={args.bin_a} sha256={sha_a[:16]}..\n'
          f'  B={args.bin_b} sha256={sha_b[:16]}..', flush=True)

    # --- 严格交错 A,B,A,B,... ---
    rounds, load_notes = [], []
    try:
        for i in range(1, args.rounds + 1):
            for side, exe in (('A', args.bin_a), ('B', args.bin_b)):
                mbps, wall = run_side(args.tag, side, i, exe, args.scenario)
                s = load_sample()
                rounds.append({'round': i, 'side': side, 'mbps': round(mbps, 2),
                               'wall_s': round(wall, 1), 'load': s})
                load_notes.append(s)
                print(f'  round {i}{side}: {mbps:.1f} MB/s ({wall:.1f}s, '
                      f'compilers={json.dumps(s["compilers"])})', flush=True)
    except (subprocess.TimeoutExpired, RuntimeError, OSError) as e:
        print(f'ERROR: {e}', file=sys.stderr)
        sys.exit(2)

    a_vals = [r['mbps'] for r in rounds if r['side'] == 'A']
    b_vals = [r['mbps'] for r in rounds if r['side'] == 'B']
    med_a, mad_a, iqr_a, spread_a = summarize(a_vals)
    med_b, mad_b, iqr_b, spread_b = summarize(b_vals)
    ratio = med_b / med_a if med_a else float('inf')
    verdict = 'PASS' if ratio >= 1 - args.tol else 'FAIL'

    # --- 污染判定 ---
    comp_during = sorted({c for s in load_notes for c, n in (s['compilers'] or {}).items() if n})
    contam = []
    if spread_a > CONTAM_THRESH:
        contam.append(f'A 侧轮间离散度 {spread_a*100:.1f}% > {CONTAM_THRESH*100:.0f}%')
    if spread_b > CONTAM_THRESH:
        contam.append(f'B 侧轮间离散度 {spread_b*100:.1f}% > {CONTAM_THRESH*100:.0f}%')
    if contam or comp_during:
        print('CONTAMINATED: ' + '; '.join(contam + ([f'轮中见编译进程 {comp_during}'] if comp_during else [])),
              file=sys.stderr)

    # --- 逐轮明细 + 统计 ---
    print('\nper-round raw values:')
    for r in rounds:
        print(f'  r{r["round"]}{r["side"]}: {r["mbps"]:.2f} MB/s')
    for name, vals, med, mad, iqr, spread in (
            ('A', a_vals, med_a, mad_a, iqr_a, spread_a), ('B', b_vals, med_b, mad_b, iqr_b, spread_b)):
        print(f'{name}: median={med:.2f} MAD={mad:.2f} IQR={iqr:.2f} '
              f'spread(max-min/med)={spread*100:.1f}% values={[round(v, 2) for v in vals]}')
    print(f'median ratio B/A = {ratio:.4f} (tol={args.tol}) -> verdict={verdict}')

    # --- 存档 ---
    ts = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    os.makedirs(REPORT_DIR, exist_ok=True)
    archive = os.path.abspath(os.path.join(REPORT_DIR, f'ab-{ts}-{args.tag}.json'))
    doc = {'tool': 'tools/ab_gate.py', 'utc': ts, 'tag': args.tag, 'hostname': socket.gethostname(),
           'a': {'path': os.path.abspath(args.bin_a), 'sha256': sha_a, 'rounds': a_vals,
                 'median': round(med_a, 3), 'mad': round(mad_a, 3), 'iqr': round(iqr_a, 3),
                 'spread': round(spread_a, 4)},
           'b': {'path': os.path.abspath(args.bin_b), 'sha256': sha_b, 'rounds': b_vals,
                 'median': round(med_b, 3), 'mad': round(mad_b, 3), 'iqr': round(iqr_b, 3),
                 'spread': round(spread_b, 4)},
           'rounds_detail': rounds, 'ratio_median': round(ratio, 4), 'tol': args.tol,
           'verdict': verdict, 'contaminated': bool(contam or comp_during),
           'contamination_reason': contam, 'compilers_seen_during_run': comp_during,
           'forced': forced, 'preflight_compilers': sorted(set(pre)) if pre else [],
           'scenario': ('loopback_alloc_bench.py --runs 1 (200MB xhttp+reality+vless(mlkem-enc) 全链路)'
                        if args.scenario == 'loopback' else
                        f'自建裸 vless+tcp loopback ({SIZE_MB}MB×{NCURL} curl 均值)')}
    with open(archive, 'w') as f:
        json.dump(doc, f, indent=1, ensure_ascii=False)

    print(f'AB-GATE-SUMMARY: tag={args.tag} ratio_B_over_A={ratio:.4f} tol={args.tol} verdict={verdict} '
          f'median_a={med_a:.1f}MB/s median_b={med_b:.1f}MB/s spread_a={spread_a*100:.1f}% '
          f'spread_b={spread_b*100:.1f}% rounds={args.rounds} forced={str(forced).lower()} '
          f'contaminated={str(bool(contam or comp_during)).lower()} archive={os.path.relpath(archive)}')
    if contam:
        sys.exit(3)
    sys.exit(0 if verdict == 'PASS' else 1)


if __name__ == '__main__':
    main()
