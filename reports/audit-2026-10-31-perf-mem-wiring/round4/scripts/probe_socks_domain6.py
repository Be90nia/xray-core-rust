"""隔离式：每种目标形态用全新实例（排除前一个包污染链路）。

W1 仅 IPv4 目标（基线）
W2 仅 domain="localhost"
W3 仅 domain="127.0.0.1"
W4 IPv4 首包 + domain="localhost" 次包（顺序效应）
W5 IPv4 首包 + IPv4 次包（同目标连发，基线）
"""
import socket
import sys
import time

from mocksrv import Instance, UdpEcho, socks5_udp_associate, wait_port

ECHO_PORT = 28082
PORT = {"go": 28086, "rust": 28087}


def frame_ip(payload):
    return (b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1")
            + ECHO_PORT.to_bytes(2, "big") + payload)


def frame_domain(dom, payload):
    d = dom.encode()
    return (b"\x00\x00\x00" + bytes([3, len(d)]) + d
            + ECHO_PORT.to_bytes(2, "big") + payload)


def run_variant(side, frames):
    echo = UdpEcho(ECHO_PORT)
    echo.start()
    port = PORT[side]
    cfg = {
        "log": {"loglevel": "debug"},
        "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": port,
                      "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }
    inst = Instance(side, "w6", cfg).start()
    out = []
    try:
        if not wait_port(port, tcp=True):
            return ["no listen"]
        time.sleep(1.0)
        bnd, bport, ctrl, _ = socks5_udp_associate("127.0.0.1", port)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(4.0)
        for label, fr in frames:
            n0 = len(echo.seen)
            u.sendto(fr, (bnd, bport))
            try:
                d, _ = u.recvfrom(65535)
                got = d[-3:].decode("latin-1", "replace")
            except Exception as e:  # noqa: BLE001
                got = f"ERR:{type(e).__name__}"
            time.sleep(0.4)
            out.append(f"{label}: reply={got!r} echo_new={len(echo.seen) - n0}")
        u.close()
        ctrl.close()
    finally:
        inst.stop()
        echo.stop()
        time.sleep(0.4)
    return out


def main():
    side = sys.argv[1] if len(sys.argv) > 1 else "rust"
    variants = {
        "W1_ip_only": [("ip1", frame_ip(b"w1"))],
        "W2_domain_localhost": [("dom_localhost", frame_domain("localhost", b"w2"))],
        "W3_domain_ip_literal": [("dom_ipliteral", frame_domain("127.0.0.1", b"w3"))],
        "W4_ip_then_domain": [("ip1", frame_ip(b"w4a")),
                              ("dom_localhost", frame_domain("localhost", b"w4b"))],
        "W5_ip_twice": [("ip1", frame_ip(b"w5a")), ("ip2", frame_ip(b"w5b"))],
    }
    for name, frames in variants.items():
        res = run_variant(side, frames)
        print(f"[{side}] {name}: " + " | ".join(res), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
