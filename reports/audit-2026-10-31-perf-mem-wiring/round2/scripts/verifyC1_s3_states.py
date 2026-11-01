"""S3 下行阻塞态的细粒度状态机观测：每 0.5s 打一次 xray 的全量 TCP 表。

目的：判定「客户端停读（下行写臂堵住）」时 xray 到底有没有在 connIdle 期限内
拆掉连接——按 状态(laddr->raddr) 归类，不限于 ESTABLISHED。
"""
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

import psutil

REPO = r"D:/Project/Xray-core-rust"
XRAY = os.path.join(REPO, "target/release/xray.exe")
TMP = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tmp"))
SOCKS_PORT = 21281
TARGET_PORT = 22082
CONN_IDLE = 2.0


def flood_server(port, stop_evt):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    keep = []
    while not stop_evt.is_set():
        try:
            c, _ = srv.accept()
        except OSError:
            break
        keep.append(c)

        def pump(c=c):
            buf = b"x" * (256 * 1024)
            try:
                while not stop_evt.is_set():
                    c.sendall(buf)
            except OSError:
                pass

        threading.Thread(target=pump, daemon=True).start()
    for c in keep:
        try:
            c.close()
        except OSError:
            pass


def socks_connect(port):
    s = socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=10)
    s.sendall(b"\x05\x01\x00")
    s.recv(2)
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", port))
    rep = s.recv(10)
    if len(rep) < 2 or rep[1] != 0:
        raise RuntimeError(f"socks connect failed {rep!r}")
    return s


def table(pid):
    try:
        allc = psutil.Process(pid).net_connections(kind="tcp")
    except Exception as e:  # noqa: BLE001
        return f"ERR {e}"
    rows = []
    for c in allc:
        lp = c.laddr.port if c.laddr else 0
        rp = c.raddr.port if c.raddr else 0
        if lp in (SOCKS_PORT, TARGET_PORT) or rp in (SOCKS_PORT, TARGET_PORT):
            rows.append(f"{lp}->{rp}:{c.status}")
    return sorted(rows) or ["(none)"]


def main():
    stop = threading.Event()
    threading.Thread(target=flood_server, args=(TARGET_PORT, stop), daemon=True).start()
    cfg = {
        "log": {"loglevel": "warning"},
        "policy": {"levels": {"0": {"connIdle": 2, "uplinkOnly": 2, "downlinkOnly": 2}}},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": SOCKS_PORT,
                "protocol": "socks",
                "settings": {"udp": False, "auth": "noauth"},
            }
        ],
        "outbounds": [{"protocol": "freedom"}],
    }
    cfg_path = os.path.join(TMP, "cfg-verifyc1-s3states.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    log = open(os.path.join(TMP, "log-verifyc1-s3states.txt"), "w", encoding="utf-8")
    proc = subprocess.Popen([XRAY, "run", "-c", cfg_path], stdout=log, stderr=subprocess.STDOUT, cwd=REPO)
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=0.5).close()
                break
            except OSError:
                time.sleep(0.1)
        pid = proc.pid
        time.sleep(0.8)
        print(f"xray pid={pid}; baseline: handles={psutil.Process(pid).num_handles()} table={table(pid)}")
        cli = socks_connect(TARGET_PORT)
        got = 0
        cli.settimeout(10)
        while got < 1024 * 1024:
            d = cli.recv(65536)
            if not d:
                print("EOF during pre-read!")
                break
            got += len(d)
        print(f"client pre-read {got}B, now stops reading (t=0)")
        t0 = time.time()
        for i in range(16):
            time.sleep(0.5)
            t = time.time() - t0
            h = psutil.Process(pid).num_handles()
            print(f"  t=+{t:4.1f}s handles={h} {table(pid)}")
        print("--- client resumes reading")
        cli.settimeout(5)
        extra = 0
        eof = False
        try:
            while extra < 64 * 1024 * 1024:
                d = cli.recv(65536)
                if not d:
                    eof = True
                    break
                extra += len(d)
        except (socket.timeout, OSError):
            pass
        print(f"resumed: extra={extra}B eof={eof}")
        cli.close()
        time.sleep(3)
        print(f"after client close +3s: handles={psutil.Process(pid).num_handles()} {table(pid)}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        stop.set()
        log.close()


if __name__ == "__main__":
    sys.exit(main())
