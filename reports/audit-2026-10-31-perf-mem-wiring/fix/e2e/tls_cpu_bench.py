#!/usr/bin/env python3
"""bd slv4n 定量：rustls 适配层（tokio-rustls buffered 逐 record 拷贝）在真实链路上
吃掉多少 CPU。对照组 = 同链路 security=none（裸 TCP），差值即「TLS 全部代价」
（crypto + 拷贝）。

观测：客户端进程 CPU 秒（Get-Process TotalProcessorTime）+ 墙钟 + 字节数。

用法：python tls_cpu_bench.py [MB]
"""
import json
import pathlib
import socket
import struct
import subprocess
import sys
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
FIX = HERE / "fixtures"
OUT = HERE.parent / "tmp"
OUT.mkdir(parents=True, exist_ok=True)
RS = r"D:/Project/Xray-core-rust/target-G6Tls/release/xray.exe"

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
SRV_PORT = 28610
SOCKS_PORT = 28611
SINK_PORT = 28612


def f(n):
    return str(FIX / n).replace("\\", "/")


def server_cfg(security):
    tls = {}
    if security == "tls":
        tls = {"certificates": [{"certificateFile": f("leaf.pem"), "keyFile": f("leaf.key")}]}
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "in",
                "port": SRV_PORT,
                "listen": "127.0.0.1",
                "protocol": "vless",
                "settings": {"clients": [{"id": UUID}], "decryption": "none"},
                "streamSettings": {"network": "tcp", "security": security, "tlsSettings": tls},
            }
        ],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }


def client_cfg(security):
    tls = {}
    if security == "tls":
        tls = {
            "serverName": "test.example",
            "disableSystemRoot": True,
            "certificates": [{"certificateFile": f("ca.pem"), "usage": "verify"}],
        }
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "port": SOCKS_PORT,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": "127.0.0.1",
                            "port": SRV_PORT,
                            "users": [{"id": UUID, "encryption": "none"}],
                        }
                    ]
                },
                "streamSettings": {"network": "tcp", "security": security, "tlsSettings": tls},
            }
        ],
    }


def wait_port(port, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.4):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def cpu_seconds(pid):
    out = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            f"(Get-Process -Id {pid}).TotalProcessorTime.TotalSeconds",
        ],
        capture_output=True,
        text=True,
    )
    return float(out.stdout.strip().replace(",", "."))


class Sink(threading.Thread):
    """读并丢弃（单向下行），不回声。"""

    def __init__(self, port):
        super().__init__(daemon=True)
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(4)
        self.total = 0
        self.done = threading.Event()

    def run(self):
        while not self.done.is_set():
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            try:
                c.settimeout(30)
                while True:
                    buf = c.recv(1 << 20)
                    if not buf:
                        break
                    self.total += len(buf)
            except OSError:
                pass
            finally:
                c.close()

    def stop(self):
        self.done.set()
        try:
            self.sock.close()
        except OSError:
            pass


def socks_push(mb):
    chunk = b"\0" * (1 << 20)
    s = socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=10)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.sendall(b"\x05\x01\x00")
    assert s.recv(2) == b"\x05\x00"
    # 目标是 sock-side 的 127.0.0.1:SINK_PORT（IPv4，避免域名解析差异）
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", SINK_PORT))
    reply = s.recv(10)
    if len(reply) < 2 or reply[1] != 0:
        raise RuntimeError(f"socks reply {reply.hex()}")
    payload = chunk * mb
    t0 = time.perf_counter()
    s.sendall(payload)
    s.shutdown(socket.SHUT_WR)
    try:
        s.recv(1)
    except OSError:
        pass
    wall = time.perf_counter() - t0
    s.close()
    return wall, len(payload)


def run(security, mb):
    srv_cfg = OUT / f"cpu_bench_{security}_srv.json"
    cli_cfg = OUT / f"cpu_bench_{security}_cli.json"
    srv_cfg.write_text(json.dumps(server_cfg(security), indent=2), encoding="utf-8")
    cli_cfg.write_text(json.dumps(client_cfg(security), indent=2), encoding="utf-8")

    sink = Sink(SINK_PORT)
    sink.start()
    srv = subprocess.Popen(
        [RS, "run", "-c", str(srv_cfg)],
        stdout=open(OUT / f"cpu_bench_{security}_srv.log", "w", encoding="utf-8"),
        stderr=subprocess.STDOUT,
    )
    try:
        if not wait_port(SRV_PORT):
            raise RuntimeError("server never listened")
        cli = subprocess.Popen(
            [RS, "run", "-c", str(cli_cfg)],
            stdout=open(OUT / f"cpu_bench_{security}_cli.log", "w", encoding="utf-8"),
            stderr=subprocess.STDOUT,
        )
        try:
            if not wait_port(SOCKS_PORT):
                raise RuntimeError("client socks never listened")
            time.sleep(0.5)
            cpu0 = cpu_seconds(cli.pid)
            wall, sent = socks_push(mb)
            time.sleep(0.5)
            cpu1 = cpu_seconds(cli.pid)
        finally:
            cli.kill()
            cli.wait()
    finally:
        srv.kill()
        srv.wait()
        sink.stop()

    recv = sink.total
    return {
        "security": security,
        "mb": mb,
        "sent_bytes": sent,
        "sink_bytes": recv,
        "wall_s": round(wall, 3),
        "mbps": round(sent / 1e6 / wall, 1),
        "cli_cpu_s": round(cpu1 - cpu0, 3),
        "cli_cpu_us_per_mb": round((cpu1 - cpu0) * 1e6 / (sent / 1e6), 1),
        "core_fraction": round((cpu1 - cpu0) / wall, 3),
    }


def main():
    mb = int(sys.argv[1]) if len(sys.argv) > 1 else 128
    rows = []
    for security in ("none", "tls"):
        for _ in range(3):
            r = run(security, mb)
            rows.append(r)
            print(json.dumps(r, ensure_ascii=False), flush=True)
    (OUT / "cpu_bench_results.json").write_text(
        json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print("\nwritten", OUT / "cpu_bench_results.json")


if __name__ == "__main__":
    main()
