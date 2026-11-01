#!/usr/bin/env python3
"""bd nip4p 端到端：VLESS Reverse Proxy 真实回连 + 数据往返。

拓扑（单进程、loopback）：
    socks 客户端 →[socks-in]→ 路由 rvs1 → PortalOutbound（portal 侧）
      → 反向 carrier（command=Rvs, v1.rvs.cool）→ [portal-in] vless 入站
      ⇄ BridgeWorker（bridge 侧 monitor，2s 一次）
      → 路由 rvs1(bridge 侧 inbound tag) → freedom → 目标 HTTP 服务

判据：经 socks 拿到的 HTTP 响应体 = 目标服务内容（数据真的过了反向隧道）。
用法: python reverse_roundtrip.py <xray.exe>
"""
import json
import os
import socket
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
SOCKS_PORT = 28080
PORTAL_PORT = 28443
TARGET_PORT = 28081
MARK = "REVERSE-TUNNEL-OK"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = MARK.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # 静音
        pass


def start_target():
    srv = HTTPServer(("127.0.0.1", TARGET_PORT), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def wait_port(port, timeout=20.0):
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(0.5)
            try:
                s.connect(("127.0.0.1", port))
                return True
            except OSError:
                time.sleep(0.2)
    return False


def socks_http_get(proxy_port, host, port, path="/", timeout=10.0):
    """最小 SOCKS5（无认证）+ HTTP/1.0 GET。"""
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        raise RuntimeError("socks: no-auth handshake rejected")
    req = b"\x05\x01\x00\x03" + bytes([len(host)]) + host.encode() + port.to_bytes(2, "big")
    s.sendall(req)
    rep = s.recv(4)
    if len(rep) < 2 or rep[1] != 0:
        raise RuntimeError(f"socks: connect failed rep={rep!r}")
    atyp = rep[3] if len(rep) > 3 else 1
    s.recv(4 if atyp == 1 else 16 if atyp == 4 else s.recv(1)[0])
    s.recv(2)
    s.sendall(f"GET {path} HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
    chunks = []
    while True:
        b = s.recv(4096)
        if not b:
            break
        chunks.append(b)
    s.close()
    return b"".join(chunks)


def build_config(uid):
    return {
        "log": {"loglevel": "debug"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": SOCKS_PORT,
                "protocol": "socks",
                "settings": {"udp": False},
            },
            {
                "tag": "portal-in",
                "listen": "127.0.0.1",
                "port": PORTAL_PORT,
                "protocol": "vless",
                "settings": {
                    "decryption": "none",
                    "clients": [{"id": uid, "reverse": {"tag": "rvs1"}}],
                },
                "streamSettings": {"network": "tcp"},
            },
        ],
        "outbounds": [
            {"tag": "freedom-out", "protocol": "freedom", "settings": {}},
            {
                "tag": "rvs-bridge-out",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "127.0.0.1",
                            "port": PORTAL_PORT,
                            "users": [{"id": uid, "reverse": {"tag": "rvs1"}}],
                        }
                    ]
                },
                "streamSettings": {"network": "tcp"},
            },
        ],
        "routing": {
            "rules": [
                {"type": "field", "domain": ["v1.rvs.cool"], "outboundTag": "rvs-bridge-out"},
                {"type": "field", "inboundTag": ["rvs1"], "outboundTag": "freedom-out"},
                {"type": "field", "inboundTag": ["socks-in"], "outboundTag": "rvs1"},
            ]
        },
    }


def main():
    xray = sys.argv[1]
    uid = str(uuid.uuid4())
    cfg_path = os.path.join(HERE, "reverse-roundtrip.generated.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(build_config(uid), f, indent=2)

    srv = start_target()
    log_path = os.path.join(HERE, "reverse-roundtrip.log")
    log = open(log_path, "wb")
    proc = subprocess.Popen([xray, "run", "-c", cfg_path], stdout=log, stderr=log)
    ok, detail = False, ""
    try:
        if not wait_port(SOCKS_PORT):
            detail = "socks inbound never listened"
        else:
            # bridge monitor 每 2s 拨一次 carrier；picker 空时 dispatch 报错 → 重试
            end = time.time() + 40
            last = ""
            while time.time() < end:
                try:
                    resp = socks_http_get(SOCKS_PORT, "127.0.0.1", TARGET_PORT)
                    if MARK.encode() in resp:
                        ok, detail = True, resp.split(b"\r\n\r\n", 1)[-1].decode(errors="replace")
                        break
                    last = resp[:200].decode(errors="replace")
                except Exception as e:  # noqa: BLE001
                    last = f"{type(e).__name__}: {e}"
                time.sleep(1.0)
            if not ok:
                detail = f"no tunneled payload within 40s; last={last}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()
        srv.shutdown()

    print(f"RESULT={'PASS' if ok else 'FAIL'} detail={detail}")
    print(f"xray_log={log_path}")
    if not ok:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            tail = f.readlines()[-40:]
        print("---- log tail ----")
        print("".join(tail))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
