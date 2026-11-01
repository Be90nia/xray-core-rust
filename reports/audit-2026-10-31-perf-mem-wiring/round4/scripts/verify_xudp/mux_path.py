"""Go→Rust（cone 默认开）失败层定位：Rust 服务端全量日志。

cone 默认开 → Go 客户端发 VLESS command=Mux(v1.mux.cool) + mux 帧（带 GlobalID），
Rust 服务端 vless inbound → handle_mux_relay → MuxCarrierHandler → mux ServerWorker。
本脚本抓 Rust 侧全部日志（不按关键词过滤），定位失败发生在 mux 解帧还是更早。
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
                self.sock.sendto(data, addr)
            except OSError:
                pass

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def main():
    up = Rec(PORT_UPSTREAM)
    tun_port = PORT_TUNNEL["rust"]
    socks_port = PORT_SOCKS["go"]
    inbound = tunnel_inbound("vless")
    inbound["port"] = tun_port
    scfg = server_cfg(tun_port, inbound)
    scfg["log"]["loglevel"] = "trace"
    srv = Instance("rust", "MP_srv", scfg).start()
    cli = Instance("go", "MP_cli", client_cfg(socks_port, tunnel_outbound("vless", tun_port))).start()
    try:
        wait_port(tun_port)
        wait_port(socks_port)
        time.sleep(1.2)
        srv.drain(0.8)
        cli.drain(0.8)
        bnd, bport, ctrl = socks5_udp_associate("127.0.0.1", socks_port)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(6.0)
        u.sendto(socks5_udp_frame("127.0.0.1", PORT_UPSTREAM, PAYLOAD), (bnd, bport))
        got = socks5_udp_recv(u, 5.0)
        time.sleep(1.5)
        print(f"=== upstream={up.seen} reply_len={len(got['payload']) if got else 0}")
        print("----- RUST SERVER FULL LOG -----")
        for l in srv.drain(2.5):
            print("  ", l[:250])
        print("----- GO CLIENT LOG -----")
        for l in cli.drain(1.5)[-12:]:
            print("  ", l[:250])
        u.close()
        ctrl.close()
    finally:
        cli.stop()
        srv.stop()
        up.stop()


if __name__ == "__main__":
    main()
