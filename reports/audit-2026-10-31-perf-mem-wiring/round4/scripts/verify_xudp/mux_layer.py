"""Go→Rust（cone 默认）失败层定位：抓 Rust 服务端全量 debug 日志。

cone 默认 → Go 客户端发 VLESS command=Mux + XUDP/mux 帧；
Rust 服务端 decode 出 command=Mux → handle_mux_relay → MuxCarrierHandler →
mux ServerWorker。本脚本打印全量日志，定位失败发生在 mux 解帧还是更早。
"""
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vxudp_probe import (Instance, PORT_UPSTREAM, PORT_SOCKS, PORT_TUNNEL,  # noqa: E402
                          PAYLOAD, client_cfg, server_cfg, socks5_udp_associate,
                          socks5_udp_frame, socks5_udp_recv, tunnel_inbound,
                          tunnel_outbound, wait_port)


class Rec:
    def __init__(self, port):
        import threading
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.sock.settimeout(0.2)
        self.seen = []
        self._stop = False
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            self.seen.append(len(data))

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def main():
    proto = sys.argv[1] if len(sys.argv) > 1 else "vless"
    up = Rec(PORT_UPSTREAM)
    tun_port = PORT_TUNNEL["rust"]
    socks_port = PORT_SOCKS["go"]
    inbound = tunnel_inbound(proto)
    inbound["port"] = tun_port
    scfg = server_cfg(tun_port, inbound)
    scfg["log"]["loglevel"] = "trace"
    srv = Instance("rust", f"MX_{proto}_srv", scfg).start()
    cli = Instance("go", f"MX_{proto}_cli",
                   client_cfg(socks_port, tunnel_outbound(proto, tun_port))).start()
    try:
        wait_port(tun_port)
        wait_port(socks_port)
        time.sleep(1.2)
        srv.drain(1.0)          # 丢弃探测连接噪声
        bnd, bport, ctrl = socks5_udp_associate("127.0.0.1", socks_port)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(6.0)
        u.sendto(socks5_udp_frame("127.0.0.1", PORT_UPSTREAM, PAYLOAD), (bnd, bport))
        got = socks5_udp_recv(u, 5.0)
        time.sleep(1.5)
        print(f"=== upstream_seen={up.seen} reply_len="
              f"{len(got['payload']) if got else 0}")
        print("----- RUST SERVER FULL LOG (all lines) -----")
        for l in srv.lines:
            print("  ", l[:260])
        u.close()
        ctrl.close()
    finally:
        cli.stop()
        srv.stop()
        up.stop()


if __name__ == "__main__":
    main()
