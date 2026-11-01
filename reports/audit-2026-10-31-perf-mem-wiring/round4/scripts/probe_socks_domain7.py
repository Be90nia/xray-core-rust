"""捕获 Rust 实例全量 stdout 到文件（域名目标 socks UDP）→ 定位丢包点。"""
import os
import socket
import subprocess
import sys
import time

from mocksrv import UdpEcho, socks5_udp_associate, wait_port

RUST = r"D:\Project\Xray-core-rust\target\release\xray.exe"
OUT_DIR = r"D:\Project\Xray-core-rust\reports\audit-2026-10-31-perf-mem-wiring\round4\tmp"
ECHO_PORT = 28082
PORT = 28087


def main():
    echo = UdpEcho(ECHO_PORT)
    echo.start()
    cfg = {
        "log": {"loglevel": "debug"},
        "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": PORT,
                      "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }
    cfg_path = os.path.join(OUT_DIR, "rust_domcap.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        import json
        json.dump(cfg, f)
    log_path = os.path.join(OUT_DIR, "rust_domcap.log")
    env = dict(os.environ, RUST_LOG="debug")
    with open(log_path, "wb") as lf:
        p = subprocess.Popen([RUST, "run", "-c", cfg_path], stdout=lf,
                             stderr=subprocess.STDOUT, env=env)
    try:
        if not wait_port(PORT, tcp=True):
            print("no listen")
            return
        time.sleep(2.0)
        bnd, bport, ctrl, _ = socks5_udp_associate("127.0.0.1", PORT)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(6.0)
        dom = b"localhost"
        fd = (b"\x00\x00\x00" + bytes([3, len(dom)]) + dom
              + ECHO_PORT.to_bytes(2, "big") + b"domain-target")
        u.sendto(fd, (bnd, bport))
        try:
            d, _ = u.recvfrom(65535)
            print("reply:", d.hex())
        except Exception as e:  # noqa: BLE001
            print("reply err:", type(e).__name__)
        time.sleep(6.0)
        u.close()
        ctrl.close()
    finally:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
        echo.stop()
    print("log ->", log_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
