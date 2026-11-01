"""Rust 客户端回复路径取证：Rust 客户端 → Go 服务端，回包固定应答。

目的：独立复现「Rust 客户端把对端裸应答当 XUDP 帧解析 → invalid session status」
这一失败面（Rust socks 入站 → dispatch → vless 出站 → Go 服务端 → 上游固定应答）。
"""
import json
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vxudp_probe import (Instance, PORT_UPSTREAM, PORT_SOCKS, PORT_TUNNEL,  # noqa: E402
                          PAYLOAD, client_cfg, server_cfg, socks5_udp_associate,
                          socks5_udp_frame, socks5_udp_recv, tunnel_inbound,
                          tunnel_outbound, wait_port)

FIXED_REPLY = (b"\x12\x34\x81\x80" + b"\x00\x01\x00\x00\x00\x00\x00\x00"
               + b"\x07example\x03com\x00" + b"\x00\x01\x00\x01"
               + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x4c\x00\x04"
               + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x4c\x00\x04"
               + b"\x01\x02\x03\x04")


class Rec(threading.Thread):
    def __init__(self, port):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.sock.settimeout(0.2)
        self.seen = []
        self._stop = False
        self.start()

    def run(self):
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            self.seen.append({"len": len(data), "hex": data.hex()})
            try:
                self.sock.sendto(FIXED_REPLY, addr)
            except OSError:
                pass

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def main():
    proto = sys.argv[1] if len(sys.argv) > 1 else "vless"
    up = Rec(PORT_UPSTREAM)
    tun_port = PORT_TUNNEL["go"]
    socks_port = PORT_SOCKS["rust"]
    inbound = tunnel_inbound(proto)
    inbound["port"] = tun_port
    srv = Instance("go", f"RP_{proto}_srv", server_cfg(tun_port, inbound)).start()
    ccfg = client_cfg(socks_port, tunnel_outbound(proto, tun_port))
    ccfg["log"]["loglevel"] = "debug"
    cli = Instance("rust", f"RP_{proto}_cli", ccfg).start()
    try:
        wait_port(tun_port)
        wait_port(socks_port)
        time.sleep(1.2)
        bnd, bport, ctrl = socks5_udp_associate("127.0.0.1", socks_port)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(6.0)
        u.sendto(socks5_udp_frame("127.0.0.1", PORT_UPSTREAM, PAYLOAD), (bnd, bport))
        got = socks5_udp_recv(u, 5.0)
        time.sleep(1.5)
        print(f"=== upstream={up.seen}")
        print(f"=== client_reply_len={len(got['payload']) if got else 0}")
        print("----- RUST CLIENT LOG -----")
        cli_lines = cli.drain(1.5)
        for l in cli_lines:
            print("  ", l[:240])
        print("----- GO SERVER LOG (tail) -----")
        for l in srv.drain(1.0)[-8:]:
            print("  ", l[:240])
        u.close()
        ctrl.close()
    finally:
        cli.stop()
        srv.stop()
        up.stop()


if __name__ == "__main__":
    main()
