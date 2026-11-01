"""经典「本地 DNS 服务器」配置的最小复现（两侧同字节配置）。

配置形态（Xray 文档标准形态）：
  inbounds : dokodemo-door(udp,tcp) → 127.0.0.1:<mock>
  outbounds: [{"protocol":"dns"}]                 ← 唯一出站
  dns      : {"servers":["127.0.0.1:<mock>"]}     ← 上游也是同一个 mock

期望（Go）：DNS app 的上游查询经 dispatcher 回环到 dns 出站 → ownLink 命中 →
            原样字节转发给上游 → 上游应答 → 客户端拿到 A 记录。
Rust 实测：ownLink 未命中 → dns 出站对「自己的上游查询」再次套规则 → Hijack →
            再次 lookup_ip → 无限回环 → 4s 超时 → 客户端零应答。
"""
import json
import socket
import sys
import time

from mocksrv import PORTS, Instance, MockDns, build_query

PORT = {"go": 28100, "rust": 28101}
MOCK = 28062


def cfg(side):
    return {
        "log": {"loglevel": "debug"},
        "dns": {"servers": [f"127.0.0.1:{MOCK}"]},
        "inbounds": [{"tag": "dns-in", "listen": "127.0.0.1", "port": PORT[side],
                      "protocol": "dokodemo-door",
                      "settings": {"address": "127.0.0.1", "port": MOCK,
                                   "network": "tcp,udp"}}],
        "outbounds": [{"protocol": "dns", "tag": "dns-out"}],
    }


def run(side):
    up = MockDns(MOCK).start()
    c = cfg(side)
    c["inbounds"][0]["port"] = PORT[side]
    inst = Instance(side, "classic_dns", c).start()
    try:
        time.sleep(2.0)
        logs = inst.drain(1.0)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(15.0)
        t0 = time.time()
        s.sendto(build_query("classic.test", 1, 0x1234), ("127.0.0.1", PORT[side]))
        try:
            data, _ = s.recvfrom(65535)
            res = f"reply={data.hex()} ({time.time() - t0:.1f}s)"
        except Exception as e:  # noqa: BLE001
            res = f"ERR:{type(e).__name__} ({time.time() - t0:.1f}s)"
        time.sleep(1.0)
        after = inst.drain(1.5)
        print(f"[{side}] {res}")
        print(f"[{side}] mock_upstream_queries={len(up.queries)}")
        for l in after:
            if any(k in l.lower() for k in ("ip query", "dns", "warn", "error")):
                print(f"[{side}]   {l[:220]}")
        s.close()
    finally:
        inst.stop()
        up.stop()
        time.sleep(0.4)


def main():
    for side in ("go", "rust"):
        run(side)
    return 0


if __name__ == "__main__":
    sys.exit(main())
