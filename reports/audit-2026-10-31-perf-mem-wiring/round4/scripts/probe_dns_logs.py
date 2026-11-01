"""机制定位探针：
P1 Go 侧 qType 数组形态是否拒启
P2 Rust DNS 出站 TCP 客户端路径的日志
P3 Rust ownLink：DNS app 上游查询回环到 dns 出站时携带的 inbound tag
"""
import socket
import struct
import sys
import time

from mocksrv import PORTS, Instance, MockDns, build_query

GO = r"D:\tmp\go2617\xray.exe"
RUST = r"D:\Project\Xray-core-rust\target\release\xray.exe"


def start(side, name, cfg):
    inst = Instance(side, name, cfg).start()
    time.sleep(2.0)
    logs = inst.drain(1.5)
    return inst, logs


def p1_qtype_array():
    print("=== P1: qType 数组形态启动行为")
    cfg = {
        "log": {"loglevel": "warning"},
        "dns": {"servers": [{"address": "127.0.0.1", "port": PORTS["mockdns"]}]},
        "inbounds": [{"tag": "dns-in", "listen": "127.0.0.1", "port": 28070,
                      "protocol": "dokodemo-door",
                      "settings": {"address": "127.0.0.1", "port": 53, "network": "tcp,udp"}}],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "dns-out", "protocol": "dns",
             "settings": {"rules": [{"action": "return", "rCode": 5, "qType": [16]}]}},
        ],
        "routing": {"rules": [{"type": "field", "inboundTag": ["dns-in"],
                               "outboundTag": "dns-out"}]},
    }
    for side in ("go", "rust"):
        inst, logs = start(side, "p1_qtype", cfg)
        alive = inst.alive()
        print(f"  [{side}] alive={alive}")
        for l in logs[:8]:
            print("     ", l[:220])
        inst.stop()
    # 对照：Go PortList 形态（字符串）
    cfg2 = dict(cfg)
    cfg2["outbounds"] = [
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "dns-out", "protocol": "dns",
         "settings": {"rules": [{"action": "return", "rCode": 5, "qType": "16"}]}},
    ]
    for side in ("go", "rust"):
        inst, logs = start(side, "p1_qtype_str", cfg2)
        alive = inst.alive()
        print(f"  [{side}] qType=字符串 alive={alive}")
        for l in logs[:6]:
            print("     ", l[:220])
        inst.stop()


def p2_tcp_client():
    print("=== P2: Rust DNS 出站 + TCP 客户端（控制组：默认出站 freedom）")
    up = MockDns(PORTS["mockdns"]).start()
    cfg = {
        "log": {"loglevel": "debug"},
        "dns": {"servers": [{"address": "127.0.0.1", "port": PORTS["mockdns"]}]},
        "inbounds": [{"tag": "dns-in", "listen": "127.0.0.1", "port": 28071,
                      "protocol": "dokodemo-door",
                      "settings": {"address": "127.0.0.1", "port": 53, "network": "tcp,udp"}}],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "dns-out", "protocol": "dns",
             "settings": {"network": "udp", "address": "127.0.0.1", "port": PORTS["mockdns"]}},
        ],
        "routing": {"rules": [{"type": "field", "inboundTag": ["dns-in"],
                               "outboundTag": "dns-out"}]},
    }
    for side in ("go", "rust"):
        inst, logs = start(side, "p2_tcpclient", cfg)
        q = build_query("p2.test", 1, 0x1234)
        s = socket.create_connection(("127.0.0.1", 28071), timeout=6.0)
        s.settimeout(6.0)
        s.sendall(struct.pack("!H", len(q)) + q)
        try:
            hdr = s.recv(2)
            ln = struct.unpack("!H", hdr)[0]
            buf = b""
            while len(buf) < ln:
                buf += s.recv(ln - len(buf))
            print(f"  [{side}] reply={buf.hex()}")
        except Exception as e:  # noqa: BLE001
            print(f"  [{side}] reply error: {e}")
        time.sleep(0.8)
        for l in inst.drain(1.0):
            print("     ", l[:200])
        print(f"  [{side}] upstream_queries={len(up.queries)}")
        up.queries.clear()
        s.close()
        inst.stop()
    up.stop()


def p3_ownlink():
    print("=== P3: 唯一出站=dns（ownLink 回环）Rust 日志")
    up = MockDns(PORTS["mockdns"]).start()
    cfg = {
        "log": {"loglevel": "debug"},
        "dns": {"servers": [{"address": "127.0.0.1", "port": PORTS["mockdns"]}]},
        "inbounds": [{"tag": "dns-in", "listen": "127.0.0.1", "port": 28072,
                      "protocol": "dokodemo-door",
                      "settings": {"address": "127.0.0.1", "port": 53, "network": "tcp,udp"}}],
        "outbounds": [{"tag": "dns-out", "protocol": "dns",
                       "settings": {"network": "udp", "address": "127.0.0.1",
                                    "port": PORTS["mockdns"]}}],
    }
    for side in ("go", "rust"):
        inst, logs = start(side, "p3_ownlink", cfg)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(8.0)
        s.sendto(build_query("p3.test", 1, 0x1234), ("127.0.0.1", 28072))
        try:
            data, _ = s.recvfrom(65535)
            print(f"  [{side}] reply={data.hex()}")
        except Exception as e:  # noqa: BLE001
            print(f"  [{side}] reply error: {e}")
        time.sleep(0.8)
        for l in inst.drain(1.2):
            if "dns" in l.lower() or "ip query" in l.lower() or "inbound" in l.lower():
                print("     ", l[:220])
        print(f"  [{side}] upstream_queries={len(up.queries)}")
        up.queries.clear()
        s.close()
        inst.stop()
    up.stop()


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which in ("all", "p1"):
        p1_qtype_array()
    if which in ("all", "p2"):
        p2_tcp_client()
    if which in ("all", "p3"):
        p3_ownlink()
