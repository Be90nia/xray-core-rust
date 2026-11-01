"""决定性探针：ownLink 判定（Rust vs Go）+ TCP/UDP 帧不对称机制。

H1【判别式】dns 出站带 drop 规则（qType=1）+ 唯一出站=dns：
   Go  ownLink 命中 → 原始字节直转上游（绕过规则）→ 上游收到查询 → 有应答
   Rust ownLink 未命中 → 规则生效 → 丢弃 → 上游零查询 → 无应答
   两侧应答/上游查询数的差异即为 ownLink 判定差异的直接证据。

H2【判别式】同配置但规则改成 return rCode=5：
   Go  ownLink 命中 → 直转上游 → 正常 A 记录应答
   Rust ownLink 未命中 → 回 rcode=5 应答

H3 TCP 客户端 + rewriteNetwork=udp → Rust 走 XUDP 分支的日志证据。
"""
import json
import socket
import struct
import sys
import time

from mocksrv import PORTS, Instance, MockDns, build_query


def start(side, name, cfg):
    inst = Instance(side, name, cfg).start()
    time.sleep(1.5)
    logs = inst.drain(1.0)
    return inst, logs


def cfg_only_dns(rule):
    return {
        "log": {"loglevel": "debug"},
        "dns": {"servers": [{"address": "127.0.0.1", "port": PORTS["mockdns"]}]},
        "inbounds": [{"tag": "dns-in", "listen": "127.0.0.1", "port": 28090,
                      "protocol": "dokodemo-door",
                      "settings": {"address": "127.0.0.1", "port": 53,
                                   "network": "tcp,udp"}}],
        "outbounds": [{"tag": "dns-out", "protocol": "dns",
                       "settings": {"network": "udp", "address": "127.0.0.1",
                                    "port": PORTS["mockdns"], "rules": [rule]}}],
    }


def h1_h2(rule, label):
    print(f"=== {label}  rule={rule}")
    up = MockDns(PORTS["mockdns"]).start()
    for side in ("go", "rust"):
        inst, logs = start(side, f"h_{label}_{side}", cfg_only_dns(rule))
        if not inst.alive():
            print(f"  [{side}] NOT ALIVE")
            for l in logs[:6]:
                print("     ", l[:200])
            inst.stop()
            continue
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(8.0)
        s.sendto(build_query("h.test", 1, 0x1234), ("127.0.0.1", 28090))
        try:
            data, _ = s.recvfrom(65535)
            reply = data.hex()
        except Exception as e:  # noqa: BLE001
            reply = f"ERR:{type(e).__name__}"
        time.sleep(0.6)
        after = inst.drain(1.0)
        print(f"  [{side}] reply={reply}")
        print(f"  [{side}] upstream_queries={len(up.queries)} raw={up.queries}")
        for l in after:
            if "dns" in l.lower() or "ip query" in l.lower():
                print("     ", l[:200])
        up.queries.clear()
        s.close()
        inst.stop()
    up.stop()


def h3_tcp_client_udp_upstream():
    print("=== H3 TCP 客户端 + rewriteNetwork=udp → Rust 帧分支证据")
    up = MockDns(PORTS["mockdns"]).start()
    cfg = {
        "log": {"loglevel": "debug"},
        "dns": {"servers": [{"address": "127.0.0.1", "port": PORTS["mockdns"]}]},
        "inbounds": [{"tag": "dns-in", "listen": "127.0.0.1", "port": 28091,
                      "protocol": "dokodemo-door",
                      "settings": {"address": "127.0.0.1", "port": 53,
                                   "network": "tcp,udp"}}],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "dns-out", "protocol": "dns",
             "settings": {"rewriteNetwork": "udp", "rewriteAddress": "127.0.0.1",
                          "rewritePort": PORTS["mockdns"]}},
        ],
        "routing": {"rules": [{"type": "field", "inboundTag": ["dns-in"],
                               "outboundTag": "dns-out"}]},
    }
    for side in ("go", "rust"):
        inst, _ = start(side, f"h3_{side}", cfg)
        if not inst.alive():
            print(f"  [{side}] NOT ALIVE")
            inst.stop()
            continue
        q = build_query("h3.test", 1, 0x1234)
        s = socket.create_connection(("127.0.0.1", 28091), timeout=8.0)
        s.settimeout(8.0)
        s.sendall(struct.pack("!H", len(q)) + q)
        try:
            hdr = s.recv(2)
            ln = struct.unpack("!H", hdr)[0]
            buf = b""
            while len(buf) < ln:
                buf += s.recv(ln - len(buf))
            reply = buf.hex()
        except Exception as e:  # noqa: BLE001
            reply = f"ERR:{type(e).__name__}"
        time.sleep(0.8)
        print(f"  [{side}] reply={reply} upstream_queries={len(up.queries)}")
        for l in inst.drain(1.0):
            print("     ", l[:200])
        up.queries.clear()
        s.close()
        inst.stop()
    up.stop()


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which in ("all", "h1"):
        h1_h2({"action": "drop", "qType": "1"}, "h1_drop")
    if which in ("all", "h2"):
        h1_h2({"action": "return", "rCode": 5, "qType": "1"}, "h2_return5")
    if which in ("all", "h3"):
        h3_tcp_client_udp_upstream()
