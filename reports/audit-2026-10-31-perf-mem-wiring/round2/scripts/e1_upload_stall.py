"""E1#2: 上传方向写阻塞 —— 已触发的 connIdle 不能终止连接（join! 等四腿）。

场景: socks 入站 -> freedom 出站 -> 本地「只 accept 不 read」服务器。
客户端持续上传（对端零窗口 -> 桥上 up_writer 阻塞在 write_all，up_reader 阻塞在
通道 send），随后静默 > connIdle(2s)。
判定: 用 blocking recv 直接观测客户端 socket 是否被 xray 关闭——
      * recv 超时（无 EOF）= 连接仍在（connIdle 触发了也没拆掉）
      * recv 返回 b'' = 已关闭（正确语义）
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
SOCK_PORT = 21082
BLACKHOLE_PORT = 21083
CONN_IDLE_SECS = 2
UPLOAD_BUDGET = 8 * 1024 * 1024

state = {"accepted": False}


def blackhole_server(ready: threading.Event):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    srv.bind(("127.0.0.1", BLACKHOLE_PORT))
    srv.listen(4)
    ready.set()
    conn, _ = srv.accept()
    state["accepted"] = True
    # 永不 read，永不应答
    time.sleep(120)
    conn.close()


def socks_connect():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16384)
    s.connect(("127.0.0.1", SOCK_PORT))
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        raise SystemExit("socks greeting failed")
    s.sendall(
        b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", BLACKHOLE_PORT)
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
    path = os.path.join(tempfile.gettempdir(), "e1_upload_stall.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    proc = subprocess.Popen(
        [XRAY, "run", "-c", path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    time.sleep(2.5)
    if proc.poll() is not None:
        print(proc.stdout.read().decode("gbk", "replace"))
        raise SystemExit("xray failed to start")
    return proc


def netstat_by_pid(pid, remote_port=None):
    out = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True).stdout
    out = out.decode("gbk", "replace")
    rows = []
    for p in (l.split() for l in out.splitlines()):
        if len(p) >= 5 and p[4] == str(pid):
            if remote_port is None or p[2].endswith(f":{remote_port}"):
                rows.append((p[1], p[2], p[3]))
    return rows


def main():
    ready = threading.Event()
    threading.Thread(target=blackhole_server, args=(ready,), daemon=True).start()
    ready.wait(5)
    proc = start_xray()
    try:
        s = socks_connect()
        cport = s.getsockname()[1]
        chunk = b"u" * 8192
        sent, t0 = 0, time.time()
        s.setblocking(False)
        # 持续上传直到对端窗口塞满（send 阻塞）——最多 6s
        while time.time() - t0 < 6:
            try:
                sent += s.send(chunk)
            except BlockingIOError:
                time.sleep(0.05)
            except OSError as e:
                print("send error:", e)
                break
        s.setblocking(True)
        print(f"uploaded={sent} bytes (budget={UPLOAD_BUDGET}) accepted={state['accepted']}")
        # 静默等待 connIdle(2s) 触发 + 2s 余量
        time.sleep(CONN_IDLE_SECS + 2)
        up1 = netstat_by_pid(proc.pid, BLACKHOLE_PORT)
        print(f"xray pid={proc.pid} sockets->{BLACKHOLE_PORT} at t=+{CONN_IDLE_SECS+2}s: {up1}")
        # 直接观测客户端 socket 是否关闭（服务器永不下发数据 -> 无数据缓冲干扰）
        s.settimeout(3.0)
        try:
            b = s.recv(64)
            closed = b == b""
            print(f"recv -> {len(b)} bytes, closed={closed}")
        except socket.timeout:
            closed = False
            print("recv -> TIMEOUT (无 EOF)")
        s.close()
        time.sleep(3)
        up2 = netstat_by_pid(proc.pid, BLACKHOLE_PORT)
        print(f"xray sockets->{BLACKHOLE_PORT} after client close (+3s): {up2}")
        pinned = [r for r in up2 if r[2] == "ESTABLISHED"]
        print(
            "VERDICT:",
            ("LEAK — 客户端可见 EOF 但 xray 仍钉着 outbound socket（up_writer 阻塞在写、join! 不返回）"
             if not closed or pinned
             else "CLOSED — connIdle 生效且 outbound 已释放"),
        )
    finally:
        proc.terminate()


if __name__ == "__main__":
    sys.exit(main())
