"""抓 Rust socks UDP 域名目标丢包的全量日志（落文件后按关键词筛）。"""
import socket
import subprocess
import sys
import time

from mocksrv import Instance, UdpEcho, socks5_udp_associate, wait_port

ECHO_PORT = 28082
OUT = r"D:\Project\Xray-core-rust\reports\audit-2026-10-31-perf-mem-wiring\round4\tmp\rust_domain_full.log"


def main():
    echo = UdpEcho(ECHO_PORT)
    echo.start()
    port = 28087
    cfg = {
        "log": {"loglevel": "debug"},
        "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": port,
                      "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }
    inst = Instance("rust", "g5file", cfg).start()
    try:
        if not wait_port(port, tcp=True):
            print("no listen")
            return
        time.sleep(1.5)
        bnd, bport, ctrl, _ = socks5_udp_associate("127.0.0.1", port)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(4.0)
        dom = b"localhost"
        fd = (b"\x00\x00\x00" + bytes([3, len(dom)]) + dom
              + ECHO_PORT.to_bytes(2, "big") + b"domain-target")
        u.sendto(fd, (bnd, bport))
        try:
            u.recvfrom(65535)
        except Exception:  # noqa: BLE001
            pass
        time.sleep(2.0)
        with open(OUT, "w", encoding="utf-8") as f:
            f.write("\n".join(inst.drain(3.0)))
        print(f"full log -> {OUT}")
        u.close()
        ctrl.close()
    finally:
        inst.stop()
        echo.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
