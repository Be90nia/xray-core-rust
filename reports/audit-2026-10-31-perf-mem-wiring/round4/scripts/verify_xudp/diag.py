"""诊断：单个用例全量日志（找 harness 缺陷 vs 产品缺陷）。"""
import json
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vxudp_probe import (Instance, PORT_UPSTREAM, PORT_SOCKS, PORT_TUNNEL, UdpRecorder,  # noqa: E402
                          PAYLOAD, client_cfg, server_cfg, socks5_udp_associate,
                          socks5_udp_frame, socks5_udp_recv, tunnel_inbound,
                          tunnel_outbound, wait_port)


def one(proto, client_side, server_side, label):
    up = UdpRecorder(PORT_UPSTREAM)
    up.start()
    tun_port = PORT_TUNNEL[server_side]
    socks_port = PORT_SOCKS[client_side]
    inbound = tunnel_inbound(proto)
    inbound["port"] = tun_port
    srv = Instance(server_side, f"{label}_srv", server_cfg(tun_port, inbound)).start()
    cli = Instance(client_side, f"{label}_cli",
                   client_cfg(socks_port, tunnel_outbound(proto, tun_port))).start()
    try:
        wait_port(tun_port)
        wait_port(socks_port)
        time.sleep(1.0)
        bnd, bport, ctrl = socks5_udp_associate("127.0.0.1", socks_port)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(6.0)
        u.sendto(socks5_udp_frame("127.0.0.1", PORT_UPSTREAM, PAYLOAD), (bnd, bport))
        got = socks5_udp_recv(u, 5.0)
        time.sleep(1.0)
        print(f"===== {label} upstream={up.seen} reply_len={len(got['payload']) if got else 0}")
        print("----- SERVER LOG -----")
        for l in srv.drain(1.2):
            print("  ", l[:220])
        print("----- CLIENT LOG -----")
        for l in cli.drain(1.2):
            print("  ", l[:220])
        u.close()
        ctrl.close()
    finally:
        cli.stop()
        srv.stop()
        up.stop()


if __name__ == "__main__":
    proto = sys.argv[1]
    cs = sys.argv[2]
    ss = sys.argv[3]
    one(proto, cs, ss, f"DIAG_{proto}_{cs}_{ss}")
