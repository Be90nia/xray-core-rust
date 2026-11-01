"""G5 机制定位：socks5 UDP 帧目标为域名（ATYP=3）→ 两侧日志。"""
import socket
import sys
import time

from mocksrv import Instance, UdpEcho, socks5_udp_associate, wait_port

ECHO_PORT = 28082


def main():
    echo = UdpEcho(ECHO_PORT)
    echo.start()
    for side in ("go", "rust"):
        port = 28086 if side == "go" else 28087
        cfg = {
            "log": {"loglevel": "debug"},
            "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": port,
                          "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        }
        inst = Instance(side, "g5diag", cfg).start()
        try:
            if not wait_port(port, tcp=True):
                print(f"[{side}] no listen")
                continue
            time.sleep(0.6)
            bnd, bport, ctrl, rep = socks5_udp_associate("127.0.0.1", port)
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.settimeout(5.0)
            dom = b"localhost"
            frame = (b"\x00\x00\x00" + bytes([3, len(dom)]) + dom
                     + ECHO_PORT.to_bytes(2, "big") + b"domain-target")
            u.sendto(frame, (bnd, bport))
            try:
                data, _ = u.recvfrom(65535)
                print(f"[{side}] reply={data!r}")
            except Exception as e:  # noqa: BLE001
                print(f"[{side}] reply err={type(e).__name__}: {e}")
            time.sleep(0.8)
            print(f"[{side}] echo.seen={echo.seen}")
            for l in inst.drain(1.0):
                print("   ", l[:220])
            u.close()
            ctrl.close()
        finally:
            inst.stop()
    echo.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
