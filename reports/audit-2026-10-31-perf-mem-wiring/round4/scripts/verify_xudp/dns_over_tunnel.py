"""DNS over UDP through the tunnel：Rust 客户端 → Go 服务端（dns 出站）。

用途：判定「DNS over UDP 经隧道」的用户可见后果（客户端能否拿到应答，
mock DNS 上游收到的是裸报文还是裹了 XUDP 帧的垃圾）。
"""
import json
import os
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vxudp_probe import (Instance, PORT_SOCKS, PORT_TUNNEL, client_cfg,  # noqa: E402
                          socks5_udp_associate, socks5_udp_frame, socks5_udp_recv,
                          tunnel_inbound, tunnel_outbound, wait_port)

MOCKDNS_PORT_BASE = 28230   # 每用例 +1，避免上一轮 mock 残留端口串扰


def build_query(qname="example.com", qid=0x1234):
    buf = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in qname.split("."):
        buf += bytes([len(label)]) + label.encode()
    buf += b"\x00" + struct.pack("!HH", 1, 1)
    return buf


class MockDns(threading.Thread):
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
            # 只在收到裸 DNS（首字节不是 XUDP 帧特征）时应答
            if len(data) >= 12 and data[2] == 0x01:
                resp = (b"\x12\x34\x81\x80" + b"\x00\x01\x00\x00\x00\x00\x00\x00"
                        + b"\x07example\x03com\x00" + b"\x00\x01\x00\x01"
                        + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x4c\x00\x04"
                        + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x4c\x00\x04"
                        + b"\x01\x02\x03\x04")
                try:
                    self.sock.sendto(resp, addr)
                except OSError:
                    pass

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def one(client_side, server_side, proto="vless", port_offset=0):
    mockdns_port = MOCKDNS_PORT_BASE + port_offset
    up = MockDns(mockdns_port)
    tun_port = PORT_TUNNEL[server_side]
    socks_port = PORT_SOCKS[client_side]
    inbound = tunnel_inbound(proto)
    inbound["port"] = tun_port
    # 服务端：隧道入站 → dns 出站（指向 mock DNS）
    scfg = {
        "log": {"loglevel": "debug"},
        "inbounds": [inbound],
        "outbounds": [{"tag": "dns-out", "protocol": "dns",
                       "settings": {"servers": [f"127.0.0.1:{mockdns_port}"]}}],
    }
    srv = Instance(server_side, f"DNS_{server_side}_srv", scfg).start()
    cli = Instance(client_side, f"DNS_{client_side}_cli",
                   client_cfg(socks_port, tunnel_outbound(proto, tun_port))).start()
    obs = {"case": f"{proto} {client_side}->{server_side}(dns-out)"}
    try:
        wait_port(tun_port)
        wait_port(socks_port)
        time.sleep(1.0)
        bnd, bport, ctrl = socks5_udp_associate("127.0.0.1", socks_port)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(6.0)
        q = build_query()
        u.sendto(socks5_udp_frame("127.0.0.1", mockdns_port, q), (bnd, bport))
        got = socks5_udp_recv(u, 5.0)
        time.sleep(1.0)
        obs["upstream_seen"] = up.seen
        obs["upstream_raw_dns"] = bool(up.seen and len(up.seen[0]["hex"]) >= 24
                                       and up.seen[0]["hex"][4:6] == "0100")
        obs["client_reply_len"] = len(got["payload"]) if got else 0
        obs["dns_resolved"] = bool(got and got["payload"][:2] == b"\x12\x34"
                                   and (got["payload"][2] & 0x80) != 0)
        u.close()
        ctrl.close()
    finally:
        cli.stop()
        srv.stop()
        up.stop()
    print(f"[{obs['case']}] {json.dumps(obs, ensure_ascii=False)[:500]}", flush=True)
    return obs


if __name__ == "__main__":
    res = []
    for idx, (cs, ss) in enumerate((("rust", "go"), ("go", "rust"),
                                    ("rust", "rust"), ("go", "go"))):
        try:
            res.append(one(cs, ss, port_offset=idx))
        except Exception as e:  # noqa: BLE001
            print(f"[{cs}->{ss}] harness_error {type(e).__name__}: {e}")
        time.sleep(0.4)
    out = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       "..", "..", "tmp", "verify_xudp", "dns_over_tunnel.json"))
    with open(out, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)
    print("results ->", out)
