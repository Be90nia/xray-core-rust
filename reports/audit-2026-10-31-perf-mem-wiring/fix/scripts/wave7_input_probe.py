"""Wave7 input-face probe: SOCKS4 USERID / HTTP request-head floods + 0snlt response-direction.

三张票的反证仪器（bd dp2dm / y5cy9 / 0snlt）：

  socks4   —— 发 0x04 后持续灌非 NUL 字节（永不写 USERID 终止符），记 xray 进程
              CPU 秒 + RSS 峰值 + 实际喂进去的字节数。
  httphead —— 发请求行后灌不带 CRLF 终止的头字节（1MB 量级），记同三项；可 --conns N 并发。
  behavior —— 构造请求 → 记录服务端回写的原始字节 / 是否静默断链（Rust 与 Go 各跑一遍）。

用法：
  python wave7_input_probe.py --mode socks4   --exe <xray.exe> [--dur 10]
  python wave7_input_probe.py --mode httphead --exe <xray.exe> [--conns 1] [--mb 1]
  python wave7_input_probe.py --mode behavior --exe <xray.exe>
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

import psutil

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
TMP = os.path.join(ROOT, "reports", "audit-2026-10-31-perf-mem-wiring", "fix", "tmp")
SOCKS_PORT = 47610
HTTP_PORT = 47611


def config(socks_port=SOCKS_PORT, http_port=HTTP_PORT):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            },
            {
                "tag": "http-in",
                "listen": "127.0.0.1",
                "port": http_port,
                "protocol": "http",
                "settings": {},
            },
        ],
        "outbounds": [{"protocol": "freedom"}],
    }


def start_xray(exe, tag):
    os.makedirs(TMP, exist_ok=True)
    cfg_path = os.path.join(TMP, f"cfg-{tag}.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(config(), f, indent=2)
    log_path = os.path.join(TMP, f"xray-{tag}.log")
    logf = open(log_path, "wb")
    proc = subprocess.Popen([exe, "run", "-c", cfg_path], stdout=logf, stderr=subprocess.STDOUT)
    for _ in range(100):
        if proc.poll() is not None:
            raise SystemExit(f"xray died: see {log_path}")
        try:
            socket.create_connection(("127.0.0.1", HTTP_PORT), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    return proc, log_path


def cpu_of(proc):
    t = psutil.Process(proc.pid).cpu_times()
    return t.user + t.system


def sampler(proc, stop_evt, out, interval=0.05):
    ps = psutil.Process(proc.pid)
    peak = 0.0
    while not stop_evt.is_set():
        try:
            peak = max(peak, ps.memory_info().rss / (1024 * 1024))
        except psutil.Error:
            break
        time.sleep(interval)
    out.append(peak)


def flush_flood(sock, payload, budget, stop_evt):
    """持续写 payload 直到异常 / 预算耗尽 / stop。返回实际写入字节数。"""
    sent = 0
    sock.settimeout(2.0)
    while sent < budget and not stop_evt.is_set():
        try:
            sock.sendall(payload)
        except OSError:
            break
        sent += len(payload)
    return sent


def mode_flood(conns, setup, mb_per_conn, dur):
    budget = int(mb_per_conn * 1024 * 1024)
    stop = threading.Event()
    results = []
    gate = threading.Event()

    def worker(idx):
        try:
            sock = setup(idx)
            gate.wait(10)
            results.append(flush_flood(sock, b"A" * 65536, budget, stop))
            sock.close()
        except OSError as e:  # 建连/发送失败也计入（服务端先关就是这种形态）
            results.append(f"ERR {e}")

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(conns)]
    for t in threads:
        t.start()
    time.sleep(0.3)
    gate.set()
    time.sleep(dur)
    stop.set()
    for t in threads:
        t.join(5)
    return results


def measure(proc, run):
    """跑一轮攻击，返回 CPU 秒 / RSS 峰值 / 墙钟。"""
    rss = []
    stop = threading.Event()
    th = threading.Thread(target=sampler, args=(proc, stop, rss), daemon=True)
    th.start()
    c0 = cpu_of(proc)
    t0 = time.time()
    detail = run()
    wall = time.time() - t0
    cpu = cpu_of(proc) - c0
    stop.set()
    th.join(1)
    return {
        "cpu_s": round(cpu, 3),
        "rss_peak_mb": round(rss[0], 1) if rss else -1.0,
        "wall_s": round(wall, 2),
        "detail": detail,
    }


def mode_socks4(exe, dur, conns):
    proc, log = start_xray(exe, "socks4")

    def setup(_idx):
        s = socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=5)
        # VER=4, CMD=1(CONNECT), DSTPORT=80, DSTIP=127.0.0.1 —— 之后只灌 USERID 字节
        s.sendall(b"\x04\x01" + struct.pack(">H", 80) + bytes([127, 0, 0, 1]))
        return s

    try:
        res = measure(proc, lambda: mode_flood(conns, setup, 1024, dur))
    finally:
        proc.terminate()
        proc.wait(10)
    print(json.dumps({"mode": "socks4", "exe": os.path.basename(exe), **res,
                      "log": log}, ensure_ascii=False))


def mode_httphead(exe, dur, conns, mb):
    proc, log = start_xray(exe, "httphead")

    def setup(_idx):
        s = socket.create_connection(("127.0.0.1", HTTP_PORT), timeout=5)
        s.sendall(b"GET http://127.0.0.1:9/ HTTP/1.1\r\n")
        return s

    try:
        res = measure(proc, lambda: mode_flood(conns, setup, mb, dur))
    finally:
        proc.terminate()
        proc.wait(10)
    print(json.dumps({"mode": "httphead", "conns": conns, "mb_per_conn": mb,
                      "exe": os.path.basename(exe), **res, "log": log}, ensure_ascii=False))


def ask(sock, payload, wait=1.5):
    """发请求，回 (原始响应字节, 是否被对端关闭)。"""
    sock.settimeout(wait)
    try:
        sock.sendall(payload)
    except OSError as e:
        return f"<send failed {e}>", True
    data = b""
    closed = False
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        except OSError as e:
            return f"{data!r} <recv failed {e}>", True
        if not chunk:
            closed = True
            break
        data += chunk
        if len(data) > 8192:
            break
    return repr(data), closed


CASES = [
    ("missing-host origin-form",
     b"GET / HTTP/1.1\r\nProxy-Connection: keep-alive\r\n\r\n"),
    ("bad content-length origin-form (Host 齐, 测校验次序)",
     b"GET / HTTP/1.1\r\nHost: 127.0.0.1:9\r\nContent-Length: abc\r\n\r\n"),
    ("bad content-length absolute-form",
     b"GET http://127.0.0.1:9/ HTTP/1.1\r\nHost: 127.0.0.1:9\r\nContent-Length: abc\r\n\r\n"),
    ("control: absolute-form no Host header",
     b"GET http://127.0.0.1:9/ HTTP/1.1\r\n\r\n"),
]


def mode_behavior(exe):
    proc, log = start_xray(exe, "behavior")
    rows = []
    try:
        for name, payload in CASES:
            s = socket.create_connection(("127.0.0.1", HTTP_PORT), timeout=5)
            body, closed = ask(s, payload)
            s.close()
            rows.append({"case": name, "response": body, "closed": closed})
    finally:
        proc.terminate()
        proc.wait(10)
    print(json.dumps({"mode": "behavior", "exe": os.path.basename(exe), "rows": rows,
                      "log": log}, ensure_ascii=False, indent=2))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["socks4", "httphead", "behavior"])
    ap.add_argument("--exe", required=True)
    ap.add_argument("--dur", type=float, default=10.0)
    ap.add_argument("--conns", type=int, default=1)
    ap.add_argument("--mb", type=float, default=1.0)
    a = ap.parse_args()
    if a.mode == "socks4":
        mode_socks4(a.exe, a.dur, a.conns)
    elif a.mode == "httphead":
        mode_httphead(a.exe, a.dur, a.conns, a.mb)
    else:
        mode_behavior(a.exe)
    return 0


if __name__ == "__main__":
    sys.exit(main())
