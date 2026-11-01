"""深挖 Rust socks5 UDP 域名型目标丢包：常驻实例 + 全量日志。"""
import socket
import sys
import time

from mocksrv import Instance, UdpEcho, socks5_udp_associate, wait_port

ECHO_PORT = 28082


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
    inst = Instance("rust", "g5deep", cfg).start()
    try:
        if not wait_port(port, tcp=True):
            print("no listen")
            return
        time.sleep(2.0)
        print("--- startup (full) ---")
        for l in inst.drain(2.0):
            print("  ", l[:300])
        bnd, bport, ctrl, rep = socks5_udp_associate("127.0.0.1", port)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(4.0)

        # 对照 1：IPv4 目标
        f4 = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") \
            + ECHO_PORT.to_bytes(2, "big") + b"ipv4-target"
        u.sendto(f4, (bnd, bport))
        try:
            d, _ = u.recvfrom(65535)
            print(f"ipv4 reply={d!r}")
        except Exception as e:  # noqa: BLE001
            print(f"ipv4 reply err={type(e).__name__}")

        # 目标 2：域名目标（长等待：区分「慢但通」与「永不通」）
        dom = b"localhost"
        fd = (b"\x00\x00\x00" + bytes([3, len(dom)]) + dom
              + ECHO_PORT.to_bytes(2, "big") + b"domain-target")
        t0 = time.time()
        u.sendto(fd, (bnd, bport))
        u.settimeout(20.0)
        try:
            d, _ = u.recvfrom(65535)
            print(f"domain reply={d!r} after {time.time() - t0:.1f}s")
        except Exception as e:  # noqa: BLE001
            print(f"domain reply err={type(e).__name__} after {time.time() - t0:.1f}s")

        time.sleep(1.5)
        print("--- after (full) ---")
        for l in inst.drain(2.0):
            print("  ", l[:300])
        print(f"echo.seen={echo.seen}")
        u.close()
        ctrl.close()
    finally:
        inst.stop()
        echo.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
