#!/usr/bin/env python3
"""R3 内存维度（MemWiring）E1 采集：连接 churn 后「驻留是否回落」。

拓扑（生产主路：xray.exe run -c → Config::build() → start_full）：
    python sock → socks(client xray) → <proto> tcp → server xray → freedom → echo

测量口径：
- `[xray-alloc-stats]` 的 live_bytes（分配器级存活字节，比 RSS 灵敏两档）；
- psutil RSS / num_handles（fd 泄漏）。

判据：
- 若「建/拆」成对，churn 结束后 live_bytes 应回到 warmup 后基线附近；
- 若某表只建不删（或删的任务未接线），live_bytes 稳态抬升 ≈ 每连接保留字节 × 连接数。

用法：
  python mem_wiring_churn.py --proto vmess
  python mem_wiring_churn.py --proto vless --conns 6000 --idle 60
"""
import argparse
import json
import os
import re
import socket
import subprocess
import threading
import time

import psutil

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.normpath(os.path.join(HERE, '..', 'tmp', 'memwiring'))
XRAY = 'D:/Project/Xray-core-rust/target/release/xray.exe'
UUID = 'b831381d-6324-4d53-ad4f-8cda48b30811'

STATS_RE = re.compile(
    r't=([\d.]+)s alloc_n=(\d+) alloc_bytes=(\d+) dealloc_n=(\d+) '
    r'dealloc_bytes=(\d+) live_bytes=(-?\d+)')


# ---------------------------------------------------------------- topology
def echo_server(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port))
    srv.listen(128)

    def handle(c):
        try:
            while True:
                data = c.recv(65536)
                if not data:
                    break
                c.sendall(data)
        except OSError:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv


def server_cfg(proto, listen):
    if proto == 'vmess':
        inbound = {'listen': '127.0.0.1', 'port': listen, 'protocol': 'vmess',
                   'settings': {'clients': [{'id': UUID, 'alterId': 0, 'security': 'auto'}]},
                   'streamSettings': {'network': 'tcp'}}
    else:
        inbound = {'listen': '127.0.0.1', 'port': listen, 'protocol': 'vless',
                   'settings': {'clients': [{'id': UUID}], 'decryption': 'none'},
                   'streamSettings': {'network': 'tcp'}}
    return {'log': {'loglevel': 'warning'}, 'inbounds': [inbound],
            'outbounds': [{'protocol': 'freedom', 'settings': {'finalRules': [{'action': 'allow'}]}}]}


def client_cfg(proto, socks_port, srv_port):
    if proto == 'vmess':
        out = {'protocol': 'vmess',
               'settings': {'vnext': [{'address': '127.0.0.1', 'port': srv_port,
                                       'users': [{'id': UUID, 'alterId': 0,
                                                  'security': 'auto'}]}]},
               'streamSettings': {'network': 'tcp'}}
    else:
        out = {'protocol': 'vless',
               'settings': {'vnext': [{'address': '127.0.0.1', 'port': srv_port,
                                       'users': [{'id': UUID, 'encryption': 'none'}]}]},
               'streamSettings': {'network': 'tcp'}}
    return {'log': {'loglevel': 'warning'},
            'inbounds': [{'listen': '127.0.0.1', 'port': socks_port, 'protocol': 'socks',
                          'settings': {'auth': 'noauth', 'udp': False}}],
            'outbounds': [out]}


def spawn(tag, cfg, alloc_stats):
    path = os.path.join(WORK, f'{tag}.json')
    with open(path, 'w') as f:
        json.dump(cfg, f)
    log = open(os.path.join(WORK, f'{tag}.log'), 'wb')
    env = dict(os.environ)
    if alloc_stats:
        env['XRAY_ALLOC_STATS'] = '1'
        env['XRAY_ALLOC_STATS_INTERVAL_MS'] = '1000'
    p = subprocess.Popen([XRAY, 'run', '-c', path], stdout=log, stderr=subprocess.STDOUT, env=env)
    return p, os.path.join(WORK, f'{tag}.log')


def wait_port(port, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f'port {port} not ready')


# ---------------------------------------------------------------- load
class Counter:
    def __init__(self):
        self.ok = 0
        self.fail = 0
        self.lock = threading.Lock()


def one_conn(socks_port, echo_port, payload):
    s = socket.create_connection(('127.0.0.1', socks_port), timeout=5)
    try:
        s.sendall(b'\x05\x01\x00')
        if s.recv(2) != b'\x05\x00':
            raise OSError('socks greeting')
        s.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1')
                  + echo_port.to_bytes(2, 'big'))
        rep = s.recv(10)
        if len(rep) < 2 or rep[1] != 0:
            raise OSError(f'socks connect rc={rep[1] if len(rep) > 1 else "?"}')
        s.sendall(payload)
        got = 0
        while got < len(payload):
            chunk = s.recv(65536)
            if not chunk:
                raise OSError('short echo')
            got += len(chunk)
    finally:
        s.close()


def churn(socks_port, echo_port, total, threads, delay_ms, counter):
    payload = b'x' * 128
    per = max(1, total // threads)

    def worker(n):
        for _ in range(n):
            try:
                one_conn(socks_port, echo_port, payload)
                with counter.lock:
                    counter.ok += 1
            except OSError:
                with counter.lock:
                    counter.fail += 1
            if delay_ms:
                time.sleep(delay_ms / 1000.0)

    ts = [threading.Thread(target=worker, args=(per,), daemon=True) for _ in range(threads)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()


# ---------------------------------------------------------------- sampling
def stats_snapshot(log_path, samples=3, gap=1.2):
    """取日志尾部的最后一条 [xray-alloc-stats] 行（近 samples 秒的中位数不明显，取末条）。"""
    time.sleep((samples - 1) * gap)
    last = None
    with open(log_path, 'rb') as f:
        for raw in f:
            line = raw.decode('utf-8', 'replace')
            if line.startswith('[xray-alloc-stats]'):
                m = STATS_RE.search(line)
                if m:
                    last = int(m.group(6))
    return last


def proc_snapshot(pid):
    p = psutil.Process(pid)
    rss = p.memory_info().rss / (1024 * 1024)
    try:
        h = p.num_handles()
    except (AttributeError, psutil.Error):
        h = -1
    return rss, h


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--proto', default='vmess', choices=['vmess', 'vless'])
    ap.add_argument('--conns', type=int, default=6000)
    ap.add_argument('--threads', type=int, default=12)
    ap.add_argument('--delay-ms', type=int, default=0)
    ap.add_argument('--idle', type=int, default=60, help='churn 后观察窗秒数')
    ap.add_argument('--warmup', type=int, default=300)
    ap.add_argument('--srv-port', type=int, default=61406)
    ap.add_argument('--socks-port', type=int, default=61405)
    ap.add_argument('--echo-port', type=int, default=61407)
    a = ap.parse_args()

    os.makedirs(WORK, exist_ok=True)
    procs = []
    try:
        echo = echo_server(a.echo_port)
        srv, srv_log = spawn('srv', server_cfg(a.proto, a.srv_port), True)
        procs.append(srv)
        cli, cli_log = spawn('cli', client_cfg(a.proto, a.socks_port, a.srv_port), True)
        procs.append(cli)
        wait_port(a.srv_port)
        wait_port(a.socks_port)
        time.sleep(2)

        print(f'[mem] topology up proto={a.proto} srv={a.srv_port} socks={a.socks_port}')
        c = Counter()
        churn(a.socks_port, a.echo_port, a.warmup, 4, 0, c)
        print(f'[mem] warmup ok={c.ok} fail={c.fail}')
        time.sleep(3)

        base_live_srv = stats_snapshot(srv_log)
        base_live_cli = stats_snapshot(cli_log)
        base_rss = {'srv': proc_snapshot(srv.pid), 'cli': proc_snapshot(cli.pid)}
        print(f'[mem] baseline live srv={base_live_srv} cli={base_live_cli} rss/handles={base_rss}')

        c2 = Counter()
        t0 = time.time()
        churn(a.socks_port, a.echo_port, a.conns, a.threads, a.delay_ms, c2)
        dur = time.time() - t0
        print(f'[mem] churn ok={c2.ok} fail={c2.fail} in {dur:.1f}s '
              f'({c2.ok / max(dur, 0.001):.1f} conn/s)')
        time.sleep(3)

        post_live_srv = stats_snapshot(srv_log)
        post_live_cli = stats_snapshot(cli_log)
        post_rss = {'srv': proc_snapshot(srv.pid), 'cli': proc_snapshot(cli.pid)}
        print(f'[mem] post-churn live srv={post_live_srv} cli={post_live_cli} rss/handles={post_rss}')

        # 观察窗：无流量，看残留是否回落（清理任务若存在且接线，应在此窗内生效）
        series = []
        for i in range(max(1, a.idle // 5)):
            time.sleep(5)
            live_srv = stats_snapshot(srv_log)
            rss = proc_snapshot(srv.pid)
            series.append((5 * (i + 1), live_srv, rss[0], rss[1]))
            print(f'[mem] idle t={series[-1][0]}s srv_live={live_srv} srv_rss={rss[0]:.1f}MB '
                  f'srv_handles={rss[1]}')

        print('\n=== SUMMARY ===')
        print(f'proto={a.proto} conns={c2.ok} fail={c2.fail} churn={dur:.1f}s '
              f'rate={c2.ok / max(dur, 0.001):.1f}/s')
        for name, b, p in (('srv', base_live_srv, post_live_srv),
                           ('cli', base_live_cli, post_live_cli)):
            if b is not None and p is not None:
                print(f'{name}: live {b} -> {p} (delta {p - b:+d} B, '
                      f'{(p - b) / max(c2.ok, 1):+.1f} B/conn)')
        print(f'srv rss {base_rss["srv"][0]:.1f} -> {post_rss["srv"][0]:.1f} MB, '
              f'handles {base_rss["srv"][1]} -> {post_rss["srv"][1]}')
        print(f'cli rss {base_rss["cli"][0]:.1f} -> {post_rss["cli"][0]:.1f} MB, '
              f'handles {base_rss["cli"][1]} -> {post_rss["cli"][1]}')
        if series:
            print(f'idle tail: live={series[-1][1]} rss={series[-1][2]:.1f}MB')
    finally:
        for p in procs:
            p.terminate()
        time.sleep(0.5)
        for p in procs:
            if p.poll() is None:
                p.kill()


if __name__ == '__main__':
    main()
