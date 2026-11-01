"""判别 Rust socks5 UDP 域名目标丢包的机制：
V1 domain="127.0.0.1"（字面量 IP 作域名）
V2 domain="localhost"（本机名）
V3 domain="nonexistent.invalid"（不可解析）
对照：ATYP=1 IP 目标
"""
import socket
import sys
import time

from mocksrv import Instance, UdpEcho, socks5_udp_associate, wait_port

ECHO_PORT = 28082


def frame_ip(payload):
    return (b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1")
            + ECHO_PORT.to_bytes(2, "big") + payload)


def frame_domain(dom, payload):
    d = dom.encode()
    return (b"\x00\x00\x00" + bytes([3, len(d)]) + d
            + ECHO_PORT.to_bytes(2, "big") + payload)


def main():
    side = sys.argv[1] if len(sys.argv) > 1 else "rust"
    echo = UdpEcho(ECHO_PORT)
    echo.start()
    port = 28086 if side == "go" else 28087
    cfg = {
        "log": {"loglevel": "debug"},
        "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": port,
                      "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }
    inst = Instance(side, "g5disc", cfg).start()
    try:
        if not wait_port(port, tcp=True):
            print("no listen")
            return
        time.sleep(1.0)
        bnd, bport, ctrl, _ = socks5_udp_associate("127.0.0.1", port)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(4.0)
        for name, fr in [
            ("V1_domain_ip_literal", frame_domain("127.0.0.1", b"v1")),
            ("V2_domain_localhost", frame_domain("localhost", b"v2")),
            ("V3_domain_invalid", frame_domain("nonexistent.invalid", b"v3")),
            ("V4_atyp1_ip", frame_ip(b"v4")),
        ]:
            n0 = len(echo.seen)
            u.sendto(fr, (bnd, bport))
            try:
                d, _ = u.recvfrom(65535)
                got = d[-2:].decode("latin-1", "replace")
            except Exception as e:  # noqa: BLE001
                got = f"ERR:{type(e).__name__}"
            time.sleep(0.4)
            print(f"[{side}] {name}: reply_payload={got!r} echo_new={len(echo.seen) - n0}")
        u.close()
        ctrl.close()
    finally:
        inst.stop()
        echo.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
