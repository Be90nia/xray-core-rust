"""CF IP 优选快照（只读消费外部优选产出的 IP 池——不自建优选器；bd lgcyo 工具侧）。

输入一个 IP 池文件（每行一个 IP，空行与 # 注释忽略，如 D:/tmp/ip_pool_expanded.txt），
对每个 IP 产出四元组 (ip, colo, rtt_ms, small_file_mbs)：

  colo            以该 IP 为解析结果访问 https://<host>/cdn-cgi/trace（curl --resolve，
                  SNI/Host 仍是域名 ⇒ pinned-edge L1+L2 两层同时满足），取 body 的
                  colo= 字段。禁用 cf-ray 尾段当 colo：Argo/Tiered Cache zone 上那是
                  回源出口 colo 而非入口（research-cf-edge-bench.md §2.4 / §5-T5）。
  rtt_ms          到该 IP 的 RTT = TCP 握手计时（对 ip:trace端口 连接 N 次取均值，
                  SYN→SYN/ACK 恰 1 个 RTT），方法标注 tcp_connect_443。不用 ICMP：
                  CF anycast 对 ICMP 普遍降优/限速（数字虚高），且 Windows ping 输出
                  随 locale 编码难稳定解析（票面允许「不好测就换 TCP 并标注方法」）。
  small_file_mbs  经该 IP 下载一个小文件的吞吐。默认 CF 官方测速端点
                  speed.cloudflare.com/__down?bytes=3145728（3MiB，1-5MiB 档，避免大
                  文件拖时间；cf speedtest / NTrace-core 同款端点）。

输出 reports/bench/cf-edge-snapshot-<UTC>.json + .md，按「好线路 / 中间带 / 坏线路」
分组：默认按样本 rtt 中位数与吞吐中位数切分（rtt<=中位 且 mbs>=中位 ⇒ good；两维皆劣
⇒ bad）；--good-rtt-max 与 --good-mbs-min 成对给出时改用显式阈值。
失败 IP 记 status=unreachable（带失败阶段详情），不影响其余 IP。并发默认 4（低并发，
避免自己把线路打爆/触发风控——CFST discussion #382：测速即可能触发干扰）。

⚠️ 与 ab_gate 的语义分工：本工具池子应全是 CF IP；某 IP 的 trace 无 colo=（该 IP 实际
不是 CF 边缘/被劫持）⇒ 该 IP 记 unreachable，不进分组。「直连裸 IP 节点 ⇒ colo=n/a
不作废」的语义属于 tools/ab_gate.py --scenario remote 的作废闸，不在本工具。

用法:
  python tools/cf_edge_snapshot.py --pool D:/tmp/ip_pool_expanded.txt
  python tools/cf_edge_snapshot.py --pool pool.txt --limit 5                        # 冒烟
  python tools/cf_edge_snapshot.py --pool pool.txt --good-rtt-max 200 --good-mbs-min 5
  python tools/cf_edge_snapshot.py --self-test

退出码: 0=完成（含全部 unreachable）  2=输入错误（池缺失/为空/阈值不成对）
"""
import argparse, concurrent.futures, json, os, re, socket, statistics, subprocess, sys, time
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR = os.path.join(HERE, '..', 'reports', 'bench')

TRACE_SAMPLE = (  # /cdn-cgi/trace 真实形态样例（字段裁剪，供 --self-test 桩测）
    'fl=8f9p1\nh=speed.cloudflare.com\nip=203.0.113.9\nts=2026.11.07\n'
    'visit_scheme=https\nufo=\nloc=CN\ntls=TLSv1.3\nsni=plaintext\nwarp=\n'
    'gateway=\nrbi=\nkex=X25519\ncolo=SJC\n')


def load_pool(path):
    """读 IP 池：每行一个 IP，容忍行尾 # 注释与空白；去重保序。"""
    seen, out = set(), []
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith('#'):
                continue
            ip = s.split()[0].rstrip(',')
            if ip and ip not in seen:
                seen.add(ip)
                out.append(ip)
    return out


def parse_colo(body):
    """trace body → colo；无 colo= ⇒ None（非 CF 目标/未命中该 IP）。"""
    m = re.search(r'(?m)^colo=([^\s]+)', body or '')
    return m.group(1) if m else None


def resolve_arg(url, ip):
    """curl --resolve 参数 host:port:ip（host/port 取自 URL 本身；不改 Host/SNI）。"""
    p = urlparse(url)
    port = p.port or (443 if p.scheme == 'https' else 80)
    return f'{p.hostname}:{port}:{ip}'


def trace_colo(url, ip, timeout):
    try:
        r = subprocess.run(['curl', '-sS', '--resolve', resolve_arg(url, ip),
                            '--max-time', str(timeout), url],
                           capture_output=True, text=True, timeout=timeout + 5)
    except (subprocess.TimeoutExpired, OSError) as e:
        return None, f'trace {type(e).__name__}: {e}'
    if r.returncode != 0:
        return None, f'trace rc={r.returncode}: {r.stderr.strip()[-150:]}'
    colo = parse_colo(r.stdout)
    if not colo:
        return None, 'trace 无 colo=（该 IP 非 CF 边缘/未命中）'
    return colo, None


def tcp_rtt(ip, port, samples, timeout):
    """TCP 握手计时取均值（每次 ≈1 RTT）；全失败 ⇒ None。"""
    ts = []
    for _ in range(samples):
        t0 = time.perf_counter()
        try:
            socket.create_connection((ip, port), timeout=timeout).close()
            ts.append((time.perf_counter() - t0) * 1000)
        except OSError:
            pass
    return round(sum(ts) / len(ts), 1) if ts else None


def dl_speed(url, ip, timeout):
    try:
        r = subprocess.run(['curl', '-sS', '-o', os.devnull, '--max-time', str(timeout),
                            '-w', '%{speed_download}', '--resolve', resolve_arg(url, ip), url],
                           capture_output=True, text=True, timeout=timeout + 5)
    except (subprocess.TimeoutExpired, OSError) as e:
        return None, f'download {type(e).__name__}: {e}'
    if r.returncode != 0:
        return None, f'download rc={r.returncode}: {r.stderr.strip()[-150:]}'
    try:
        return float(r.stdout.strip()) / 1e6, None
    except ValueError:
        return None, 'download speed_download 解析失败'


def probe_ip(ip, args, rtt_port):
    row = {'ip': ip, 'status': 'ok', 'colo': None, 'rtt_ms': None,
           'rtt_method': None, 'small_file_mbs': None, 'error': None}
    errs = []
    row['colo'], e = trace_colo(args.trace_url, ip, args.trace_timeout)
    if e:
        errs.append(e)
    row['rtt_ms'] = tcp_rtt(ip, rtt_port, args.rtt_samples, args.trace_timeout)
    row['rtt_method'] = 'tcp_connect_443' if row['rtt_ms'] is not None else None
    if row['rtt_ms'] is None:
        errs.append('tcp rtt 全失败')
    mbs, e = dl_speed(args.dl_url, ip, args.dl_timeout)
    row['small_file_mbs'] = round(mbs, 2) if mbs is not None else None
    if e:
        errs.append(e)
    if errs:
        row['status'] = 'unreachable'
        row['error'] = '; '.join(errs)
    return row


def group_rows(rows, good_rtt_max=None, good_mbs_min=None):
    """纯逻辑分组（供 --self-test）：good=两维皆优，bad=两维皆劣，其余 middle；
    unreachable/缺字段样本不参与。返回 (good, middle, bad, thresholds_desc)。"""
    ok = [r for r in rows if r['status'] == 'ok'
          and r['rtt_ms'] is not None and r['small_file_mbs'] is not None]
    if good_rtt_max is not None and good_mbs_min is not None:
        rt, mt = good_rtt_max, good_mbs_min
        desc = f'显式阈值: rtt_ms<={rt} 且 small_file_mbs>={mt}'
    elif ok:
        rt = statistics.median(r['rtt_ms'] for r in ok)
        mt = statistics.median(r['small_file_mbs'] for r in ok)
        desc = f'中位数阈值: rtt_ms<={rt:.1f} 且 small_file_mbs>={mt:.2f}（n={len(ok)}）'
    else:
        return [], [], [], '无可用样本（全部 unreachable/缺字段）'
    good, mid, bad = [], [], []
    for r in ok:
        r_good = r['rtt_ms'] <= rt and r['small_file_mbs'] >= mt
        r_bad = r['rtt_ms'] > rt and r['small_file_mbs'] < mt
        (good if r_good else bad if r_bad else mid).append(r)
    return good, mid, bad, desc


def self_test():
    """--self-test：纯逻辑桩测（零网络零子进程），含「A/B colo 不同 ⇒ 该轮作废」模拟
    （复用 ab_gate.edge_gate_classify 同一份闸逻辑，禁双份实现）。"""
    ok = True

    def check(name, cond):
        nonlocal ok
        print(f'  [{"PASS" if cond else "FAIL"}] {name}', flush=True)
        ok = ok and bool(cond)

    check('parse_colo 正常 trace', parse_colo(TRACE_SAMPLE) == 'SJC')
    check('parse_colo 非 CF（无 colo=）⇒ None', parse_colo('fl=xx\nh=example.com\n') is None)
    check('resolve_arg 缺省 443', resolve_arg('https://a.example.top/cdn-cgi/trace', '1.2.3.4')
          == 'a.example.top:443:1.2.3.4')
    check('resolve_arg 带端口', resolve_arg('https://a.example.top:8443/x', '1.2.3.4')
          == 'a.example.top:8443:1.2.3.4')

    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, 'pool.txt')
        open(p, 'w', encoding='utf-8').write('# 注释\n1.1.1.1\n\n2.2.2.2 # 行尾注\n1.1.1.1\n')
        check('load_pool 去重/注释/行尾注', load_pool(p) == ['1.1.1.1', '2.2.2.2'])

    rows = [{'ip': 'a', 'status': 'ok', 'rtt_ms': 40.0, 'small_file_mbs': 9.0},
            {'ip': 'b', 'status': 'ok', 'rtt_ms': 60.0, 'small_file_mbs': 3.0},
            {'ip': 'c', 'status': 'ok', 'rtt_ms': 45.0, 'small_file_mbs': 2.0},
            {'ip': 'e', 'status': 'ok', 'rtt_ms': 58.0, 'small_file_mbs': 8.0},
            {'ip': 'd', 'status': 'unreachable', 'rtt_ms': None, 'small_file_mbs': None}]
    g, m, b, _ = group_rows(rows)
    check('中位数分组 good=[a] bad=[b] mid=[c,e]',
          [r['ip'] for r in g] == ['a'] and [r['ip'] for r in b] == ['b']
          and sorted(r['ip'] for r in m) == ['c', 'e'])
    check('unreachable 不入组', all(r['ip'] != 'd' for r in g + m + b))
    g2, _, b2, _ = group_rows(rows, good_rtt_max=45, good_mbs_min=8)
    check('显式阈值分组 good=[a] bad=[b]',
          [r['ip'] for r in g2] == ['a'] and [r['ip'] for r in b2] == ['b'])

    sys.path.insert(0, HERE)
    from ab_gate import edge_gate_classify
    rounds = [{'round': 1, 'side': 'A', 'mbps': 10.0, 'colo': 'SJC'},
              {'round': 1, 'side': 'B', 'mbps': 12.0, 'colo': 'LAX'}]
    v, _ = edge_gate_classify(rounds, gate_on=True)
    check('模拟 A/B colo 不同 ⇒ 该轮作废', v == {1} and rounds[0]['voided'])
    v2, _ = edge_gate_classify(rounds, gate_on=False)
    check('gate off ⇒ 记录不作废', v2 == set() and rounds[0]['voided'] is False)

    print('CF-EDGE-SNAPSHOT SELF-TEST: ' + ('PASS' if ok else 'FAIL'), flush=True)
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(
        description='CF IP 优选快照（只读消费 IP 池 → (ip, colo, rtt, 小文件吞吐)，不自建优选器）',
        epilog='退出码: 0=完成（含全部 unreachable）  2=输入错误')
    ap.add_argument('--pool', help='IP 池文件（每行一个 IP；--self-test 时可省）')
    ap.add_argument('--trace-url', default='https://speed.cloudflare.com/cdn-cgi/trace',
                    help='colo 取证 URL（默认 CF 官方测速域；可换自有 CF zone 域名）')
    ap.add_argument('--dl-url', default='https://speed.cloudflare.com/__down?bytes=3145728',
                    help='小文件下载 URL（默认 3MiB；bytes= 控制大小，1-5MiB 档）')
    ap.add_argument('--concurrency', type=int, default=4, help='并发数（默认 4，低并发防打爆线路）')
    ap.add_argument('--rtt-samples', type=int, default=3, help='RTT TCP 握手采样次数（默认 3 取均值）')
    ap.add_argument('--trace-timeout', type=int, default=10, help='单次 trace 上限秒（默认 10）')
    ap.add_argument('--dl-timeout', type=int, default=20, help='单次下载上限秒（默认 20）')
    ap.add_argument('--good-rtt-max', type=float, help='好线路 RTT 上限 ms（须与 --good-mbs-min 成对）')
    ap.add_argument('--good-mbs-min', type=float, help='好线路吞吐下限 MB/s（须与 --good-rtt-max 成对）')
    ap.add_argument('--limit', type=int, help='只测池中前 N 个 IP（冒烟用）')
    ap.add_argument('--out-dir', default=REPORT_DIR, help='归档目录（默认 reports/bench）')
    ap.add_argument('--self-test', action='store_true', help='纯逻辑自测（零网络零子进程）')
    args = ap.parse_args()

    if args.self_test:
        self_test()
    if not args.pool:
        ap.error('--pool 为必填（IP 池文件；--self-test 可省）')
    if (args.good_rtt_max is None) != (args.good_mbs_min is None):
        ap.error('--good-rtt-max 与 --good-mbs-min 必须成对给出')
    if not os.path.exists(args.pool):
        print(f'ERROR: IP 池文件不存在: {args.pool}', file=sys.stderr)
        sys.exit(2)
    pool = load_pool(args.pool)
    if not pool:
        print(f'ERROR: IP 池为空: {args.pool}', file=sys.stderr)
        sys.exit(2)
    if args.limit:
        pool = pool[:args.limit]
    rtt_port = urlparse(args.trace_url).port or 443

    print(f'CF-EDGE-SNAPSHOT pool={args.pool} n={len(pool)} concurrency={args.concurrency} '
          f'trace={args.trace_url} dl={args.dl_url}', flush=True)
    rows = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = {ex.submit(probe_ip, ip, args, rtt_port): ip for ip in pool}
        done = 0
        for fut in concurrent.futures.as_completed(futs):
            row = fut.result()
            rows.append(row)
            done += 1
            rtt = '-' if row['rtt_ms'] is None else f'{row["rtt_ms"]}ms'
            mbs = '-' if row['small_file_mbs'] is None else f'{row["small_file_mbs"]}'
            err = f'  ERR: {row["error"]}' if row['error'] else ''
            print(f'  [{done}/{len(pool)}] {row["ip"]} colo={row["colo"] or "-"} '
                  f'rtt={rtt} mbs={mbs}{err}', flush=True)
    order = {ip: i for i, ip in enumerate(pool)}
    rows.sort(key=lambda r: order[r['ip']])

    good, mid, bad, desc = group_rows(rows, args.good_rtt_max, args.good_mbs_min)
    n_ok = sum(1 for r in rows if r['status'] == 'ok')
    ok_rows = [r for r in rows if r['status'] == 'ok'
               and r['rtt_ms'] is not None and r['small_file_mbs'] is not None]
    ts = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    os.makedirs(args.out_dir, exist_ok=True)
    base = os.path.abspath(os.path.join(args.out_dir, f'cf-edge-snapshot-{ts}'))
    doc = {'tool': 'tools/cf_edge_snapshot.py', 'utc': ts, 'pool': os.path.abspath(args.pool),
           'count': len(pool), 'ok': n_ok, 'unreachable': len(rows) - n_ok,
           'trace_url': args.trace_url, 'dl_url': args.dl_url,
           'rtt_method': 'tcp_connect_443（TCP 握手计时 ×%d 均值，非 ICMP）' % args.rtt_samples,
           'colo_source': 'trace body colo=（curl --resolve 钉 IP；非 cf-ray 尾段）',
           'concurrency': args.concurrency, 'rows': rows,
           'medians': {'rtt_ms': round(statistics.median(r['rtt_ms'] for r in ok_rows), 1) if ok_rows else None,
                       'small_file_mbs': round(statistics.median(r['small_file_mbs'] for r in ok_rows), 2) if ok_rows else None},
           'groups': {'good': [r['ip'] for r in good], 'middle': [r['ip'] for r in mid],
                      'bad': [r['ip'] for r in bad], 'thresholds': desc}}
    with open(base + '.json', 'w', encoding='utf-8') as f:
        json.dump(doc, f, indent=1, ensure_ascii=False)

    def tbl(rs):
        out = ['| ip | colo | rtt_ms | MB/s |', '|---|---|---|---|']
        for r in sorted(rs, key=lambda x: -(x['small_file_mbs'] or 0)):
            rtt = '-' if r['rtt_ms'] is None else r['rtt_ms']
            mbs = '-' if r['small_file_mbs'] is None else r['small_file_mbs']
            out.append(f'| {r["ip"]} | {r["colo"] or "-"} | {rtt} | {mbs} |')
        return out

    lines = [f'# CF 边缘快照 {ts}', '',
             f'- 池: `{args.pool}`（{len(pool)} IP；ok {n_ok} / unreachable {len(rows) - n_ok}）',
             '- colo 来源: trace body `colo=`（curl --resolve 钉 IP；**非** cf-ray 尾段'
             '——Argo/Tiered Cache 下那是回源出口 colo）',
             f'- RTT 方法: TCP 握手计时 ×{args.rtt_samples} 均值（tcp_connect_443，非 ICMP：'
             'CF anycast 对 ICMP 降优/限速且 Windows ping 输出随 locale 编码）',
             f'- 下载: `{args.dl_url}`',
             f'- 分组: {desc}', '']
    for title, grp in ((f'好线路 ({len(good)})', good), (f'中间带 ({len(mid)})', mid),
                       (f'坏线路 ({len(bad)})', bad)):
        lines += [f'## {title}'] + (tbl(grp) if grp else ['（空）']) + ['']
    unreach = [r for r in rows if r['status'] == 'unreachable']
    lines += [f'## unreachable ({len(unreach)})', '| ip | 失败详情 |', '|---|---|']
    lines += [f'| {r["ip"]} | {r["error"] or "-"} |' for r in unreach] or ['（无）']
    lines += ['', '注: 「直连裸 IP 节点 ⇒ colo=n/a 不作废」语义属 tools/ab_gate.py --scenario remote'
                  ' 的作废闸；本工具池子应全是 CF IP，trace 无 colo= 的 IP 记 unreachable。']
    with open(base + '.md', 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    print(f'CF-EDGE-SNAPSHOT-SUMMARY: n={len(pool)} ok={n_ok} unreachable={len(rows) - n_ok} '
          f'good={len(good)} middle={len(mid)} bad={len(bad)} thresholds="{desc}" '
          f'archive={os.path.relpath(base + ".json")}')


if __name__ == '__main__':
    main()
