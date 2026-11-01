"""诊断 Rust 侧 DNS 上游查询未发出：抓日志。"""
import socket
import sys
import time

from mocksrv import PORTS, Instance, MockDns, build_query


def cfg():
    return {
        "log": {"loglevel": "debug"},
        "dns": {"servers": [{"address": "127.0.0.1", "port": PORTS["mockdns"]}]},
        "inbounds": [{"tag": "dns-in", "listen": "127.0.0.1", "port": PORTS["rust_dnsout"],
                      "protocol": "dokodemo-door",
                      "settings": {"address": "127.0.0.1", "port": 53, "network": "tcp,udp"}}],
        "outbounds": [{"tag": "dns-out", "protocol": "dns",
                       "settings": {"network": "udp", "address": "127.0.0.1",
                                    "port": PORTS["mockdns"]}}],
    }


def main():
    up = MockDns(PORTS["mockdns"]).start()
    inst = Instance("rust", "dnsdiag", cfg()).start()
    time.sleep(2.0)
    print("--- startup ---")
    for l in inst.drain(1.5):
        print("  ", l[:300])
    q = build_query("a.test", 1, 0x1234)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(6.0)
    s.sendto(q, ("127.0.0.1", PORTS["rust_dnsout"]))
    try:
        data, _ = s.recvfrom(65535)
        print("reply:", data.hex())
    except Exception as e:  # noqa: BLE001
        print("reply error:", e)
    time.sleep(1.0)
    print("--- after query ---")
    for l in inst.drain(1.5):
        print("  ", l[:300])
    print("upstream queries:", up.queries)
    s.close()
    inst.stop()
    up.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
