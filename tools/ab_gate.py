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
  remote    真机双客户端 A/B（同节点同 URL）。每侧测量窗前直连同机路径取一次
            /cdn-cgi/trace：colo 取 body 的 colo= 字段（cf-ray 尾段在 Argo/Tiered Cache
            下是回源出口 colo，只作存在性证据），同轮 A/B 入口 colo 不同 ⇒ 该轮作废
            （--edge-gate off 只记录不作废）；作废轮不计 median，作废 > 半数 ⇒
            CONTAMINATED。非 CF 目标（trace 无 colo=）记 colo='n/a' 不作废（直连无
            CF 边缘环节）。相邻轮 colo 变化在归档 edge.changes 标注。

退出码: 0=PASS  1=FAIL(比值超阈)  2=环境/运行错误  3=CONTAMINATED  4=检测到编译活动拒跑
"""
import argparse, hashlib, json, os, re, socket, statistics, subprocess, sys, time
from urllib.parse import urlparse

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

# --- remote 场景（bd dm2wo：真机 A/B，用户自测口径）---
# 本机受控测速 <17MB/s 无效（见 MEMORY），绝对值须在用户真机/真节点上取；
# 本仓只提供等配置双端脚手架，数字归用户。
REMOTE = {'url': None, 'a_cfg': None, 'b_cfg': None, 'a_socks': 10808, 'b_socks': 10809,
          'ncurl': 3, 'max_time': 60}
REMOTE_WORK = 'D:/tmp/abgate-remote'
TRACE_TIMEOUT = 10            # 单次 /cdn-cgi/trace 取证上限秒（300 字节级请求）


def cf_trace_sample():
    """直连（不经 SOCKS）取一次 /cdn-cgi/trace，返回本侧测量窗的入口边缘证据。

    - colo 必须取 trace body 的 colo= 字段：cf-ray 尾段在 Argo/Tiered Cache zone 上是
      回源出口 colo 而非入口 colo（research-cf-edge-bench.md §2.4 坑1 / §5-T5），
      故 cf-ray 只作存在性证据记进 cf_ray_tail。
    - 直连而不是走 A/B 的 SOCKS：A/B 客户端同机同网，其隧道入口边缘由本机路由决定，
      与直连 trace 同路径；走 SOCKS 反而测到节点侧回源出口，不是入口取证。
    - 非 CF 目标（直连裸 IP 节点等，trace 无 colo=）⇒ colo='n/a' 且不作废：直连路径
      没有 CF 边缘环节，不存在「边缘漂移」可言（research-cf-edge-bench.md §7.4）。
    - rtt_ms 用 curl timing 的 time_connect - time_namelookup（TCP 握手 ≈1 RTT），
      与 trace 同一连接路径，方法记 rtt_method。
    """
    os.makedirs(REMOTE_WORK, exist_ok=True)
    p = urlparse(REMOTE['url'])
    port = p.port or (443 if p.scheme == 'https' else 80)
    turl = f'{p.scheme}://{p.hostname}:{port}/cdn-cgi/trace'
    body_path = os.path.join(REMOTE_WORK, 'trace-body.txt')
    try:
        r = subprocess.run(
            ['curl', '-sS', '-o', body_path, '-D', '-', '--max-time', str(TRACE_TIMEOUT),
             '-w', '%{time_namelookup} %{time_connect}', turl],
            capture_output=True, text=True, timeout=TRACE_TIMEOUT + 10)
    except (subprocess.TimeoutExpired, OSError) as e:
        return {'colo': 'n/a', 'cf_ray_tail': None, 'rtt_ms': None, 'rtt_method': None,
                'err': f'{type(e).__name__}: {e}'}
    rtt = None
    try:
        tn, tc = (float(x) for x in r.stdout.strip().splitlines()[-1].split())
        rtt = round((tc - tn) * 1000, 1)
    except (ValueError, IndexError):
        pass
    colo, ray, err = 'n/a', None, None
    if r.returncode != 0:
        err = f'trace rc={r.returncode}: {r.stderr.strip()[-200:]}'
    else:
        try:
            body = open(body_path, encoding='utf-8', errors='replace').read()
        except OSError:
            body = ''
        m = re.search(r'(?m)^colo=([^\s]+)', body)
        if m:
            colo = m.group(1)
        else:
            err = 'trace 无 colo=（非 CF 目标/未走 CF）'
        mr = re.search(r'(?im)^cf-ray:\s*[0-9a-f]+-([A-Za-z]{3})', r.stdout)
        if mr:
            ray = mr.group(1)
    return {'colo': colo, 'cf_ray_tail': ray, 'rtt_ms': rtt,
            'rtt_method': 'tcp_connect_curl' if rtt is not None else None, 'err': err}


def edge_gate_classify(rounds, gate_on):
    """CF 入口边缘作废闸（纯逻辑，remote 专用；--self-test 桩测同一份实现）。

    规则（research-cf-edge-bench.md §7.2 R3/R4）：
    - 同一轮内 A/B 的入口 colo 均有效且不同 ⇒ 该轮作废（仅 gate_on 时生效；
      gate off 仍记录 colo 但不作废，reason 记 colo_mismatch_detected_but_gate_off）；
    - 任一侧 colo='n/a'（非 CF 目标/trace 失败）⇒ 不作废——没有入口漂移证据；
    - 相邻轮之间 colo 变化 ⇒ 记入 changes（标注，不作废；轮内不一致记 MIXED）。
    就地给每条 rec 写 voided/void_reason；返回 (voided_rounds:set, changes:list[str])。
    """
    by_round = {}
    for r in rounds:
        by_round.setdefault(r['round'], []).append(r)
    voided_rounds = set()
    for rnd in sorted(by_round):
        recs = by_round[rnd]
        colos = [r.get('colo') or 'n/a' for r in recs]
        valid = [c for c in colos if c != 'n/a']
        mismatch = bool(valid) and len(valid) == len(colos) and len(set(valid)) > 1
        if mismatch and gate_on:
            voided_rounds.add(rnd)
            reason = 'colo_mismatch(' + ' '.join(f"{r['side']}={r['colo']}" for r in recs) + ')'
        elif mismatch:
            reason = 'colo_mismatch_detected_but_gate_off'
        else:
            reason = None
        for r in recs:
            r['voided'] = rnd in voided_rounds
            r['void_reason'] = reason
    changes = []
    prev = None
    for rnd in sorted(by_round):
        colos = sorted({(r.get('colo') or 'n/a') for r in by_round[rnd]})
        cur = colos[0] if len(colos) == 1 else 'MIXED'
        if cur == 'n/a':
            continue
        if prev and cur != prev[1]:
            changes.append(f'round {prev[0]}->{rnd}: colo {prev[1]}->{cur}')
        prev = (rnd, cur)
    return voided_rounds, changes


def self_test():
    """--self-test：边缘闸纯逻辑桩测（零网络/零二进制/零子进程）。"""
    ok = True

    def check(name, cond):
        nonlocal ok
        print(f'  [{"PASS" if cond else "FAIL"}] {name}', flush=True)
        ok = ok and bool(cond)

    # 用例1（票面验收）：同轮 A/B 入口 colo 不同 ⇒ 该轮作废，且不计入 median
    rounds = [{'round': 1, 'side': 'A', 'mbps': 10.0, 'colo': 'SJC'},
              {'round': 1, 'side': 'B', 'mbps': 12.0, 'colo': 'LAX'},
              {'round': 2, 'side': 'A', 'mbps': 10.0, 'colo': 'SJC'},
              {'round': 2, 'side': 'B', 'mbps': 11.0, 'colo': 'SJC'}]
    v, ch = edge_gate_classify(rounds, gate_on=True)
    check('同轮 A=SJC/B=LAX ⇒ 轮1 作废', v == {1})
    check('作废原因含双侧 colo', 'SJC' in rounds[0]['void_reason'] and 'LAX' in rounds[0]['void_reason'])
    check('轮2（同 colo）不作废', 2 not in v and rounds[2]['voided'] is False)
    kept_a = [r['mbps'] for r in rounds if r['side'] == 'A' and not r['voided']]
    check('作废轮不计入 median 样本', kept_a == [10.0])
    check('相邻轮 colo 变化被标注', ch == ['round 1->2: colo MIXED->SJC'])

    # 用例2：gate off ⇒ 仍记录 colo 但不作废
    rounds2 = [{'round': 1, 'side': 'A', 'mbps': 10.0, 'colo': 'SJC'},
               {'round': 1, 'side': 'B', 'mbps': 12.0, 'colo': 'LAX'}]
    v2, _ = edge_gate_classify(rounds2, gate_on=False)
    check('gate off ⇒ 不作废但记 reason', v2 == set() and
          rounds2[0]['void_reason'] == 'colo_mismatch_detected_but_gate_off')

    # 用例3：非 CF 目标（colo=n/a）⇒ 不作废（直连无 CF 边缘环节）
    rounds3 = [{'round': 1, 'side': 'A', 'mbps': 10.0, 'colo': 'n/a'},
               {'round': 1, 'side': 'B', 'mbps': 12.0, 'colo': 'n/a'}]
    v3, ch3 = edge_gate_classify(rounds3, gate_on=True)
    check('colo=n/a 双侧 ⇒ 不作废、无漂移标注', v3 == set() and ch3 == [])

    # 用例4：trace 单侧失败（一侧 n/a 一侧有效）⇒ 无证据不作废
    rounds4 = [{'round': 1, 'side': 'A', 'mbps': 10.0, 'colo': 'n/a'},
               {'round': 1, 'side': 'B', 'mbps': 12.0, 'colo': 'SJC'}]
    v4, _ = edge_gate_classify(rounds4, gate_on=True)
    check('单侧 n/a ⇒ 不作废', v4 == set())

    # 用例5：作废轮 > 半数 ⇒ 触发既有 CONTAMINATED 语义（exit 3）
    rounds5 = [{'round': i, 'side': s, 'mbps': 10.0,
                'colo': ('SJC', 'LAX')[s == 'B'] if i <= 3 else 'SJC'}
               for i in range(1, 6) for s in ('A', 'B')]
    v5, _ = edge_gate_classify(rounds5, gate_on=True)
    check(f'作废 {len(v5)}/5 > 半数 ⇒ CONTAMINATED 判据', len(v5) * 2 > 5)

    print('AB-GATE SELF-TEST: ' + ('PASS' if ok else 'FAIL'), flush=True)
    sys.exit(0 if ok else 1)



def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def compiler_procs():
    """tasklist 数 cargo/rustc/cl 进程；tasklist 不可用返回 (None, [])。"""
    try:
        # 不传 text=True：tasklist 在本机输出非 UTF-8（中文系统代码页），
        # 严格解码会在读线程抛 UnicodeDecodeError 使 stdout 变 None。
        raw = subprocess.run(['tasklist', '/FO', 'CSV', '/NH'], capture_output=True,
                             timeout=30).stdout
    except Exception as e:
        return None, [f'tasklist failed: {e}']
    out = raw.decode('utf-8', 'replace')
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


def wait_socks(host, port, timeout_s, proc):
    """等客户端 SOCKS 端口可连（proc 提前退出直接失败）。"""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f'client exited early rc={proc.returncode}')
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f'SOCKS {host}:{port} 在 {timeout_s}s 内未就绪')


def run_remote(tag, side, idx, exe):
    """跑一轮单侧（真机）：起该侧客户端二进制 → 经其 SOCKS 下载固定 URL，返回 MB/s。

    两侧用同一节点、同一 URL、同一 payload 次数，交替执行——比值才有意义。
    """
    cfg = REMOTE['a_cfg'] if side == 'A' else REMOTE['b_cfg']
    socks = REMOTE['a_socks'] if side == 'A' else REMOTE['b_socks']
    rtag = f'{tag}-{side.lower()}{idx}'
    os.makedirs(REMOTE_WORK, exist_ok=True)
    log_path = os.path.join(REMOTE_WORK, f'cli-{rtag}.log')
    t0 = time.time()
    with open(log_path, 'wb') as log:
        pc = subprocess.Popen([exe, 'run', '-c', cfg], stdout=log, stderr=subprocess.STDOUT)
        speeds = []
        try:
            wait_socks('127.0.0.1', socks, 15, pc)
            for _ in range(REMOTE['ncurl']):
                r = subprocess.run(
                    ['curl', '-sS', '-o', 'NUL', '--max-time', str(REMOTE['max_time']),
                     '-w', '%{speed_download}', '-x', f'socks5h://127.0.0.1:{socks}',
                     REMOTE['url']],
                    capture_output=True, text=True, timeout=REMOTE['max_time'] + 10)
                if r.returncode != 0:
                    raise RuntimeError(
                        f'round {side}#{idx}: curl rc={r.returncode}: '
                        f'{r.stderr.strip()[-300:]} (日志 {log_path})')
                speeds.append(float(r.stdout.strip()) / 1e6)
        finally:
            pc.terminate()
            try:
                pc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pc.kill()
    wall = time.time() - t0
    return sum(speeds) / len(speeds), wall


def run_side(tag, side, idx, exe, scenario):
    if scenario == 'remote':
        return run_remote(tag, side, idx, exe)
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
    ap.add_argument('--b', dest='bin_b', help='对照侧二进制（必填；--self-test 时可省）')
    ap.add_argument('--rounds', type=int, default=5, help='交错轮数（每轮 A,B 各一次，默认 5）')
    ap.add_argument('--tol', type=float, default=0.05,
                    help='允许 B 比 A 慢的比例（默认 0.05 = 5%%）')
    ap.add_argument('--tag', default='ab', help='存档 tag（默认 ab）')
    ap.add_argument('--scenario', choices=('minvless', 'loopback', 'remote'), default='minvless',
                    help='minvless=裸 vless+tcp（跨二进制，默认）；loopback=基线拓扑（仅 Rust↔Rust）；'
                         'remote=真机（双侧客户端各连同一真节点，数字归用户自测）')
    ap.add_argument('--url', help='remote：下载目标 URL（两侧同一 URL）')
    ap.add_argument('--a-config', help='remote：A 侧客户端配置 json 路径')
    ap.add_argument('--b-config', help='remote：B 侧客户端配置 json 路径')
    ap.add_argument('--a-socks', type=int, default=10808, help='remote：A 侧客户端 SOCKS 端口（默认 10808）')
    ap.add_argument('--b-socks', type=int, default=10809, help='remote：B 侧客户端 SOCKS 端口（默认 10809）')
    ap.add_argument('--ncurl', type=int, default=3, help='remote：每轮下载次数（取均值，默认 3）')
    ap.add_argument('--max-time', type=int, default=60, help='remote：单次下载上限秒（默认 60）')
    ap.add_argument('--edge-gate', choices=('on', 'off'), default='on',
                    help='remote：CF 入口边缘作废闸（同轮 A/B colo 不同⇒该轮作废；默认 on）。'
                         'off=仍记录 colo/RTT 但不作废。仅 remote 场景生效')
    ap.add_argument('--self-test', action='store_true',
                    help='边缘闸纯逻辑自测（零网络/零二进制，验证后退出）')
    ap.add_argument('--emit-md', action='store_true', help='额外写一份 markdown 结果表（归档同目录）')
    ap.add_argument('--force', action='store_true',
                    help='检测到编译进程仍强行运行（记入报告）')
    args = ap.parse_args()

    if args.self_test:
        self_test()
    if not args.bin_b:
        ap.error('--b 为必填（对照侧二进制；--self-test 可省）')

    if args.scenario == 'remote':
        missing = [n for n, v in (('--url', args.url), ('--a-config', args.a_config),
                                  ('--b-config', args.b_config)) if not v]
        if missing:
            print(f'ERROR: remote 场景缺参数: {missing}', file=sys.stderr)
            sys.exit(2)
        for cfg in (args.a_config, args.b_config):
            if not os.path.exists(cfg):
                print(f'ERROR: 配置不存在: {cfg}', file=sys.stderr)
                sys.exit(2)
        REMOTE.update(url=args.url, a_cfg=args.a_config, b_cfg=args.b_config,
                      a_socks=args.a_socks, b_socks=args.b_socks,
                      ncurl=args.ncurl, max_time=args.max_time)

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
                edge = cf_trace_sample() if args.scenario == 'remote' else None
                if edge:
                    print(f'  round {i}{side}: edge colo={edge["colo"]} '
                          f'cf_ray={edge["cf_ray_tail"] or "-"} '
                          f'rtt={edge["rtt_ms"] if edge["rtt_ms"] is not None else "-"}ms', flush=True)
                mbps, wall = run_side(args.tag, side, i, exe, args.scenario)
                s = load_sample()
                rec = {'round': i, 'side': side, 'mbps': round(mbps, 2),
                       'wall_s': round(wall, 1), 'load': s}
                if edge:
                    rec.update(speed_mbs=rec['mbps'], colo=edge['colo'],
                               cf_ray_tail=edge['cf_ray_tail'], rtt_ms=edge['rtt_ms'],
                               rtt_method=edge['rtt_method'], trace_err=edge['err'])
                rounds.append(rec)
                load_notes.append(s)
                print(f'  round {i}{side}: {mbps:.1f} MB/s ({wall:.1f}s, '
                      f'compilers={json.dumps(s["compilers"])})', flush=True)
    except (subprocess.TimeoutExpired, RuntimeError, OSError) as e:
        print(f'ERROR: {e}', file=sys.stderr)
        sys.exit(2)

    voided_rounds, edge_changes = set(), []
    if args.scenario == 'remote':
        voided_rounds, edge_changes = edge_gate_classify(rounds, gate_on=args.edge_gate == 'on')
        if voided_rounds:
            print(f'EDGE-GATE: 作废轮 {sorted(voided_rounds)}（gate={args.edge_gate}，不计入 median）', flush=True)
        for c in edge_changes:
            print(f'EDGE-CHANGE: {c}', flush=True)

    # 作废轮不计入 median（非 remote 无 voided 字段，get() 为 None ⇒ 全量，零变化）
    a_vals = [r['mbps'] for r in rounds if r['side'] == 'A' and not r.get('voided')]
    b_vals = [r['mbps'] for r in rounds if r['side'] == 'B' and not r.get('voided')]
    if not a_vals or not b_vals:
        # 全轮被边缘闸作废 ⇒ 无可比样本：先落归档保证据，按既有 CONTAMINATED 语义退出（exit 3）
        ts_a = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
        os.makedirs(REPORT_DIR, exist_ok=True)
        archive = os.path.abspath(os.path.join(REPORT_DIR, f'ab-{ts_a}-{args.tag}.json'))
        with open(archive, 'w') as f:
            json.dump({'tool': 'tools/ab_gate.py', 'utc': ts_a, 'tag': args.tag,
                       'scenario': f'{args.scenario}（全轮被 CF 边缘闸作废）',
                       'edge_gate': args.edge_gate, 'rounds_detail': rounds,
                       'voided_rounds': sorted(voided_rounds), 'edge_changes': edge_changes,
                       'verdict': 'CONTAMINATED'}, f, indent=1, ensure_ascii=False)
        print(f'CONTAMINATED: 作废轮 {sorted(voided_rounds)} 覆盖全部 {args.rounds} 轮，无样本可比；'
              f'归档 {os.path.relpath(archive)}', file=sys.stderr)
        sys.exit(3)
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
    if voided_rounds and len(voided_rounds) * 2 > args.rounds:
        contam.append(f'CF 入口边缘作废轮 {len(voided_rounds)}/{args.rounds} > 半数（colo 漂移）')
    if contam or comp_during:
        print('CONTAMINATED: ' + '; '.join(contam + ([f'轮中见编译进程 {comp_during}'] if comp_during else [])),
              file=sys.stderr)

    # --- 逐轮明细 + 统计 ---
    print('\nper-round raw values:')
    for r in rounds:
        print(f'  r{r["round"]}{r["side"]}: {r["mbps"]:.2f} MB/s'
              + (f'  [VOIDED {r["void_reason"]}]' if r.get('voided') else ''))
    for name, vals, med, mad, iqr, spread in (
            ('A', a_vals, med_a, mad_a, iqr_a, spread_a), ('B', b_vals, med_b, mad_b, iqr_b, spread_b)):
        print(f'{name}: median={med:.2f} MAD={mad:.2f} IQR={iqr:.2f} '
              f'spread(max-min/med)={spread*100:.1f}% values={[round(v, 2) for v in vals]}')
    print(f'median ratio B/A = {ratio:.4f} (tol={args.tol}) -> verdict={verdict}')

    # --- 存档 ---
    ts = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    os.makedirs(REPORT_DIR, exist_ok=True)
    archive = os.path.abspath(os.path.join(REPORT_DIR, f'ab-{ts}-{args.tag}.json'))
    if args.scenario == 'loopback':
        scenario_desc = 'loopback_alloc_bench.py --runs 1 (200MB xhttp+reality+vless(mlkem-enc) 全链路)'
    elif args.scenario == 'remote':
        scenario_desc = (f'真机双端客户端 A/B（同一节点同一 URL={REMOTE["url"]}，'
                         f'每轮 {REMOTE["ncurl"]} 次下载取均值，单次上限 {REMOTE["max_time"]}s，'
                         f'SOCKS A={REMOTE["a_socks"]} B={REMOTE["b_socks"]}）')
    else:
        scenario_desc = f'自建裸 vless+tcp loopback ({SIZE_MB}MB×{NCURL} curl 均值)'
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
           'scenario': scenario_desc}
    if args.scenario == 'remote':
        doc['edge_gate'] = args.edge_gate
        doc['edge'] = {'voided_rounds': sorted(voided_rounds), 'changes': edge_changes,
                       'colo_source': '/cdn-cgi/trace body colo=（同机直连取证，非 SOCKS；'
                                      'cf-ray 尾段仅存证——Argo/Tiered Cache 下它是回源出口 colo）',
                       'rtt_method': 'curl timing: time_connect - time_namelookup'
                                     '（TCP 握手 ≈1 RTT，与 trace 同连接路径）'}
    with open(archive, 'w') as f:
        json.dump(doc, f, indent=1, ensure_ascii=False)

    if args.emit_md:
        md_path = archive[:-5] + '.md'
        lines = [
            f'# A/B 吞吐结果 {ts} ({args.tag})',
            '',
            f'- 场景: {scenario_desc}',
            f'- 主机: {socket.gethostname()}  交错轮数: {args.rounds}  容差: {args.tol}',
            f'- A (基准): `{args.bin_a}` sha256 `{sha_a[:16]}..`',
            f'- B (对照): `{args.bin_b}` sha256 `{sha_b[:16]}..`',
            f'- 判定: **{verdict}**  B/A 中位比 = {ratio:.4f}'
            f'{"  (CONTAMINATED)" if (contam or comp_during) else ""}',
            '',
            (f'| 轮次 | A MB/s | B MB/s | A colo | B colo | 作废 |'
             if args.scenario == 'remote' else '| 轮次 | A MB/s | B MB/s |'),
            ('|---|---|---|---|---|---|' if args.scenario == 'remote' else '|---|---|---|'),
        ]
        for i in range(1, args.rounds + 1):
            av = next((r['mbps'] for r in rounds if r['round'] == i and r['side'] == 'A'), None)
            bv = next((r['mbps'] for r in rounds if r['round'] == i and r['side'] == 'B'), None)
            if args.scenario == 'remote':
                ra = next((r for r in rounds if r['round'] == i and r['side'] == 'A'), None)
                rb = next((r for r in rounds if r['round'] == i and r['side'] == 'B'), None)
                lines.append(f'| {i} | {av:.2f} | {bv:.2f} | {ra["colo"]} | {rb["colo"]} '
                             f'| {ra["void_reason"] or ""} |')
            else:
                lines.append(f'| {i} | {av:.2f} | {bv:.2f} |')
        lines += [
            '',
            f'| 侧 | 中位数 | MAD | IQR | 轮间离散度 |',
            '|---|---|---|---|---|',
            f'| A | {med_a:.2f} | {mad_a:.2f} | {iqr_a:.2f} | {spread_a*100:.1f}% |',
            f'| B | {med_b:.2f} | {mad_b:.2f} | {iqr_b:.2f} | {spread_b*100:.1f}% |',
            '',
            f'污染: {contam or "无"}{"；轮中编译进程 " + ",".join(comp_during) if comp_during else ""}',
        ]
        if args.scenario == 'remote':
            lines.append(f'CF 边缘: gate={args.edge_gate} 作废轮={sorted(voided_rounds) or "无"}'
                         + (f'；漂移: ' + '; '.join(edge_changes) if edge_changes else ''))
        lines += ['']
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        print(f'AB-GATE-MD: {os.path.relpath(md_path)}')

    print(f'AB-GATE-SUMMARY: tag={args.tag} ratio_B_over_A={ratio:.4f} tol={args.tol} verdict={verdict} '
          f'median_a={med_a:.1f}MB/s median_b={med_b:.1f}MB/s spread_a={spread_a*100:.1f}% '
          f'spread_b={spread_b*100:.1f}% rounds={args.rounds} forced={str(forced).lower()} '
          f'contaminated={str(bool(contam or comp_during)).lower()} archive={os.path.relpath(archive)}')
    if args.scenario == 'remote':
        print(f'AB-GATE-EDGE: gate={args.edge_gate} voided={len(voided_rounds)}/{args.rounds} '
              f'voided_rounds={sorted(voided_rounds)} changes={edge_changes}')
    if contam:
        sys.exit(3)
    sys.exit(0 if verdict == 'PASS' else 1)


if __name__ == '__main__':
    main()
