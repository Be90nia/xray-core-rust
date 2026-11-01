"""E1: 桥接写侧无超时 —— 客户端只写不读（零窗口）时 connIdle 是否生效。

场景: socks 入站 -> freedom 出站 -> 本地 flood 服务器（持续推流）。
客户端完成 SOCKS5 CONNECT 后停止读取（SO_RCVBUF 极小），静默 > connIdle(2s)。
判定:
  * t=+6s 用 netstat 查客户端那条 TCP 连接状态 —— ESTABLISHED = xray 没关它
  * 随后恢复读取，看上游是否能继续推流（能 = 桥未返回，连接未释放）

对照: 同场景但客户端持续读取（不 stall）作 control，证明 harness 本身能跑通。
"""

import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = r"D:/Project/Xray-core-rust"
XRAY = os.path.join(ROOT, "target", "release", "xray.exe")
SOCK_PORT = 21080
FLOOD_PORT = 21081
CONN_IDLE_SECS = 2
FLOOD_TOTAL = 64 * 1024 * 1024


class Flood:
    def __init__(self, limit=FLOOD_TOTAL):
        self.sent = 0
        self.err = None
        self.done = False
        self.limit = limit
        self.ready = threading.Event()

    def serve(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", FLOOD_PORT))
        srv.listen(4)
        self.ready.set()
        conn, _ = srv.accept()
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 64 * 1024)
        chunk = b"x" * 8192
        try:
            while self.sent < self.limit:
                conn.sendall(chunk)
                self.sent += len(chunk)
        except OSError as e:
            self.err = repr(e)
        finally:
            self.done = True
            conn.close()
        srv.close()


def netstat_state(local_port):
    try:
        out = subprocess.run(
            ["netstat", "-ano", "-p", "TCP"],
            capture_output=True,
            timeout=20,
        ).stdout
        if isinstance(out, bytes):
            out = out.decode("gbk", "replace")
    except Exception:
        return []
    rows = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[1].endswith(f":{local_port}"):
            rows.append((parts[1], parts[2], parts[3]))
    return rows


def socks_connect():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
    s.connect(("127.0.0.1", SOCK_PORT))
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        raise SystemExit("socks greeting failed")
    s.sendall(
        b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", FLOOD_PORT)
    )
    rep = s.recv(10)
    if len(rep) < 2 or rep[1] != 0:
        raise SystemExit(f"socks connect failed: {rep!r}")
    return s


def start_xray():
    cfg = {
        "log": {"loglevel": "debug"},
        "policy": {"levels": {"0": {"connIdle": CONN_IDLE_SECS}}},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": SOCK_PORT,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }
        ],
        "outbounds": [{"protocol": "freedom", "settings": {}}],
    }
    path = os.path.join(tempfile.gettempdir(), "e1_bridge_stall.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    proc = subprocess.Popen(
        [XRAY, "run", "-c", path],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    time.sleep(2.5)
    if proc.poll() is not None:
        print(proc.stdout.read().decode("gbk", "replace"))
        raise SystemExit("xray failed to start")
    return proc


def scenario(stall: bool):
    flood = Flood()
    threading.Thread(target=flood.serve, daemon=True).start()
    flood.ready.wait(5)
    proc = start_xray()
    try:
        s = socks_connect()
        cport = s.getsockname()[1]
        if stall:
            time.sleep(6)
            rows = netstat_state(cport)
            print(f"[stall] client tcp {cport} state at t=+6s (connIdle={CONN_IDLE_SECS}s): {rows}")
            print(f"[stall] flood sent={flood.sent} err={flood.err} done={flood.done}")
            before = flood.sent
        got, eof, t0 = 0, False, time.time()
        s.settimeout(3.0)
        while time.time() - t0 < 4.0:
            try:
                b = s.recv(1 << 16)
            except socket.timeout:
                break
            if not b:
                eof = True
                break
            got += len(b)
        elapsed = time.time() - t0
        print(
            f"[{'stall' if stall else 'control'}] resume bytes={got} eof={eof} "
            f"in {elapsed:.2f}s flood_sent={flood.sent} err={flood.err} done={flood.done}"
        )
        s.close()
        if stall:
            extra = flood.sent - before
            print(f"[stall] upstream advanced {extra} bytes after resume")
            print(
                "VERDICT:",
                "LEAK — connIdle 未关闭连接（写侧阻塞，桥 join! 等四腿）"
                if (rows and rows[0][2] == "ESTABLISHED" and extra > 8 * 1024 * 1024)
                else "CLOSED — connIdle 生效",
            )
    finally:
        proc.terminate()


if __name__ == "__main__":
    scenario(stall=False)
    print("-" * 60)
    scenario(stall=True)
