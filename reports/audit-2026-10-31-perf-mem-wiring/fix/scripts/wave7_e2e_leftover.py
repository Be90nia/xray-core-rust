"""Wave7 缓冲读正确性取证：头/体同段到达、CONNECT 后紧跟隧道数据都不能丢字节。

bd y5cy9 的修法把请求头改成 8KB 块读，多读的字节必须留在同一个读器里。本脚本
用真实 http 入站 + freedom 出站验证两条路径：

  post-body      —— 请求头 + Content-Length body **一次 write** 打入；上游必须收到完整
                    body（块读把多余字节吃掉就会丢）。
  connect-pipe   —— CONNECT 请求头 + 隧道首批 payload **一次 write** 打入；目标必须收到
                    该 payload（`into_link_io` 的 peeked 回放路径）。

用法：python wave7_e2e_leftover.py --exe <xray.exe>
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
TMP = os.path.join(ROOT, "reports", "audit-2026-10-31-perf-mem-wiring", "fix", "tmp")
HTTP_PORT = 47620


def config(http_port=HTTP_PORT):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": http_port,
            "protocol": "http",
            "settings": {},
        }],
        "outbounds": [{"protocol": "freedom"}],
    }


def start_xray(exe, tag):
    os.makedirs(TMP, exist_ok=True)
    cfg = os.path.join(TMP, f"cfg-{tag}.json")
    with open(cfg, "w", encoding="utf-8") as f:
        json.dump(config(), f)
    log = open(os.path.join(TMP, f"xray-{tag}.log"), "wb")
    proc = subprocess.Popen([exe, "run", "-c", cfg], stdout=log, stderr=subprocess.STDOUT)
    for _ in range(100):
        if proc.poll() is not None:
            raise SystemExit(f"xray died: see {TMP}")
        try:
            socket.create_connection(("127.0.0.1", HTTP_PORT), timeout=0.2).close()
            return proc
        except OSError:
            time.sleep(0.1)
    raise SystemExit("xray did not listen")


def http_sink():
    """收一个 POST，回 200 并报告收到的 body 字节数。"""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    got = {}

    def run():
        conn, _ = srv.accept()
        conn.settimeout(3)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        length = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":")[1])
        while len(body) < length:
            chunk = conn.recv(4096)
            if not chunk:
                break
            body += chunk
        got["body_len"] = len(body)
        payload = f"got={len(body)}".encode()
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(payload)).encode()
            + b"\r\nConnection: close\r\n\r\n" + payload
        )
        conn.close()
        srv.close()

    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1], got


def echo_once():
    """收若干字节后原样回显（CONNECT 隧道的对端）。"""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    got = {}

    def run():
        conn, _ = srv.accept()
        conn.settimeout(3)
        data = conn.recv(64)
        got["bytes"] = data
        conn.sendall(data)
        conn.close()
        srv.close()

    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1], got


def case_post_body():
    port, got = http_sink()
    body = b"hello world"
    req = (
        f"POST http://127.0.0.1:{port}/submit HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\nContent-Length: {len(body)}\r\n\r\n"
    ).encode() + body
    s = socket.create_connection(("127.0.0.1", HTTP_PORT), timeout=5)
    s.settimeout(5)
    s.sendall(req)  # 头 + body 同一个 write（≥ 大概率同段）
    resp = b""
    while True:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        resp += chunk
    s.close()
    time.sleep(0.2)
    return {
        "case": "post-body",
        "upstream_body_len": got.get("body_len"),
        "client_status": resp.split(b"\r\n")[0].decode("latin-1") if resp else "",
        "client_body": resp.partition(b"\r\n\r\n")[2].decode("latin-1"),
        "pass": got.get("body_len") == len(body) and b" 200 " in resp,
    }


def case_connect_pipe():
    port, got = echo_once()
    payload = b"PINGPONG"
    req = (
        f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
    ).encode() + payload
    s = socket.create_connection(("127.0.0.1", HTTP_PORT), timeout=5)
    s.settimeout(5)
    s.sendall(req)  # CONNECT 头 + 隧道首批同段
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = s.recv(4096)
        if not chunk:
            break
        resp += chunk
    echoed = resp.partition(b"\r\n\r\n")[2]
    while len(echoed) < len(payload):
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        echoed += chunk
    s.close()
    time.sleep(0.2)
    return {
        "case": "connect-pipe",
        "upstream_first_bytes": (got.get("bytes") or b"").decode("latin-1"),
        "tunnel_echo": echoed.decode("latin-1"),
        "status_line": resp.split(b"\r\n")[0].decode("latin-1") if resp else "",
        "pass": got.get("bytes") == payload and echoed == payload,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True)
    a = ap.parse_args()
    proc = start_xray(a.exe, "leftover")
    try:
        rows = [case_post_body(), case_connect_pipe()]
    finally:
        proc.terminate()
        proc.wait(10)
    print(json.dumps({"exe": os.path.basename(a.exe), "rows": rows}, ensure_ascii=False, indent=2))
    return 0 if all(r["pass"] for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
