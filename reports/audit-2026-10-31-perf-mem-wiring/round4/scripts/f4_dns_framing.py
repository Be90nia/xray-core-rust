"""F 组：DNS 出站 client-side/upstream-side 网络不对称 + serveStale / useSystemHosts /
disableFallback / DNS-over-TCP 上游。

F1 UDP 客户端 + TCP 上游（rewriteNetwork=tcp）→ 帧形态不对称
F2 TCP 客户端 + UDP 上游（rewriteNetwork=udp）→ F1 的镜像（已在 E7 观测，此处复现）
F3 serveStale：TTL 过期 + 上游下线 → 是否返回过期答案
F4 useSystemHosts=true
F5 disableFallback + 一死一活两个 nameserver
F6 上游 tcp:// 走 TCP（应答一致性已在 C3 覆盖，此处补上游字节）
"""
import json
import socket
import struct
import sys
import time

from f2_dns import RESULTS, record, udp_query, tcp_query, summarize, SIDE_PORT
from mocksrv import PORTS, Instance, MockDns, MockDnsTcp


def start_side(side, cfg, name):
    inst = Instance(side, name, cfg).start()
    time.sleep(1.2)
    inst.drain(0.6)
    return inst, inst.alive()


def cfg_base(side, ob_settings=None, dns=None, network="tcp,udp", dst_port=53):
    settings = {}
    if ob_settings:
        settings.update(ob_settings)
    d = {"servers": [{"address": "127.0.0.1", "port": PORTS["mockdns"]}]}
    if dns:
        d.update(dns)
    return {
        "log": {"loglevel": "debug"},
        "dns": d,
        "inbounds": [{"tag": "dns-in", "listen": "127.0.0.1", "port": SIDE_PORT[side],
                      "protocol": "dokodemo-door",
                      "settings": {"address": "127.0.0.1", "port": dst_port,
                                   "network": network}}],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "dns-out", "protocol": "dns", "settings": settings},
        ],
        "routing": {"rules": [{"type": "field", "inboundTag": ["dns-in"],
                               "outboundTag": "dns-out"}]},
    }


def case_f1_udp_client_tcp_upstream(side):
    """F1 UDP 客户端 + TCP 上游。"""
    up = MockDnsTcp(PORTS["mockdns"]).start()
    cfg = cfg_base(side, ob_settings={"rewriteNetwork": "tcp",
                                      "rewriteAddress": "127.0.0.1",
                                      "rewritePort": PORTS["mockdns"]})
    inst, ok = start_side(side, cfg, "f1_udp_tcp")
    try:
        if not ok:
            record("F1_udp_client_tcp_upstream", side, {"error": "not alive"})
            return
        resp = udp_query(SIDE_PORT[side], "f1.test", 1, timeout=8.0)
        time.sleep(0.5)
        obs = summarize(resp, up)
        logs = inst.drain(0.8)
        obs["log_tail"] = [l[:180] for l in logs if "dns" in l.lower()][:4]
        record("F1_udp_client_tcp_upstream", side, obs)
    finally:
        inst.stop()
        up.stop()


def case_f2_tcp_client_udp_upstream(side):
    """F2 TCP 客户端 + UDP 上游。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = cfg_base(side, ob_settings={"rewriteNetwork": "udp",
                                      "rewriteAddress": "127.0.0.1",
                                      "rewritePort": PORTS["mockdns"]})
    inst, ok = start_side(side, cfg, "f2_tcp_udp")
    try:
        if not ok:
            record("F2_tcp_client_udp_upstream", side, {"error": "not alive"})
            return
        resp = tcp_query(SIDE_PORT[side], "f2.test", 1, timeout=8.0)
        time.sleep(0.5)
        obs = summarize(resp, up)
        logs = inst.drain(0.8)
        obs["log_tail"] = [l[:180] for l in logs if "dns" in l.lower()][:4]
        record("F2_tcp_client_udp_upstream", side, obs)
    finally:
        inst.stop()
        up.stop()


def case_f3_serve_stale(side):
    """F3 serveStale：TTL=1 → 过期 → 上游下线 → 再查。"""
    up = MockDns(PORTS["mockdns"], ttl=1).start()
    cfg = cfg_base(side, dns={"serveStale": True})
    inst, ok = start_side(side, cfg, "f3_stale")
    try:
        if not ok:
            record("F3_serve_stale", side, {"error": "not alive"})
            return
        r1 = udp_query(SIDE_PORT[side], "f3.test", 1, timeout=8.0)
        time.sleep(2.5)                       # TTL=1 → 过期
        up.stop()                             # 上游下线
        r2 = udp_query(SIDE_PORT[side], "f3.test", 1, timeout=8.0)
        time.sleep(0.5)
        obs = summarize(r2, up)
        obs["first_resp_hex"] = r1.hex() if r1 else None
        obs["second_resp_hex"] = r2.hex() if r2 else None
        record("F3_serve_stale", side, obs)
    finally:
        inst.stop()
        up.stop()


def case_f4_use_system_hosts(side):
    """F4 useSystemHosts=true → 上游查询数（是否查系统 hosts）。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = cfg_base(side, dns={"useSystemHosts": True})
    inst, ok = start_side(side, cfg, "f4_syshosts")
    try:
        if not ok:
            record("F4_use_system_hosts", side, {"error": "not alive"})
            return
        resp = udp_query(SIDE_PORT[side], "f4.test", 1, timeout=8.0)
        time.sleep(0.5)
        record("F4_use_system_hosts", side, summarize(resp, up))
    finally:
        inst.stop()
        up.stop()


def case_f5_disable_fallback(side):
    """F5 两个 nameserver（一死一活）+ disableFallback=true → 死的那次是否仍回落。"""
    dead = MockDns(PORTS["mockdns"], mode="silent").start()
    cfg = cfg_base(side, dns={"servers": [
        {"address": "127.0.0.1", "port": PORTS["mockdns"], "skipFallback": True},
        {"address": "127.0.0.1", "port": 28099},
    ]})
    inst, ok = start_side(side, cfg, "f5_nofallback")
    try:
        if not ok:
            record("F5_disable_fallback_two_ns", side, {"error": "not alive"})
            return
        resp = udp_query(SIDE_PORT[side], "f5.test", 1, timeout=12.0)
        time.sleep(0.5)
        record("F5_disable_fallback_two_ns", side, summarize(resp, dead))
    finally:
        inst.stop()
        dead.stop()


def case_f6_tcp_upstream_bytes(side):
    """F6 上游 tcp:// → 上游收到的查询字节（wire 级）。"""
    up = MockDnsTcp(PORTS["mockdns"]).start()
    cfg = cfg_base(side, dns={"servers": [{"address": f"tcp://127.0.0.1:{PORTS['mockdns']}"}]})
    inst, ok = start_side(side, cfg, "f6_tcpbytes")
    try:
        if not ok:
            record("F6_tcp_upstream_bytes", side, {"error": "not alive"})
            return
        resp = udp_query(SIDE_PORT[side], "f6.test", 1, timeout=8.0)
        time.sleep(0.5)
        record("F6_tcp_upstream_bytes", side, summarize(resp, up))
    finally:
        inst.stop()
        up.stop()


def case_f7_qtype_array(side):
    """F7 qType 数组形态（Rust 扩展方言）→ 启动行为。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = cfg_base(side, ob_settings={"rules": [{"action": "return", "rCode": 5,
                                                 "qType": [16]}]})
    inst, ok = start_side(side, cfg, "f7_qarr")
    try:
        logs = inst.drain(1.0)
        alive = inst.alive()
        if not alive:
            record("F7_qtype_array_form", side, {
                "alive": False,
                "startup_err": [l[:200] for l in logs
                                if "failed" in l.lower() or "error" in l.lower()][:2],
            })
            return
        resp = udp_query(SIDE_PORT[side], "f7.test", 16, timeout=8.0)
        time.sleep(0.4)
        obs = summarize(resp, up)
        obs["alive"] = True
        record("F7_qtype_array_form", side, obs)
    finally:
        inst.stop()
        up.stop()


def case_f8_dns_inbound_protocol(side):
    """F8 "dns" 作为 inbound 协议 → 启动行为（Go 无此协议）。"""
    cfg = {
        "log": {"loglevel": "debug"},
        "dns": {"servers": [{"address": "127.0.0.1", "port": PORTS["mockdns"]}]},
        "inbounds": [{"tag": "dns-in", "listen": "127.0.0.1", "port": 28079,
                      "protocol": "dns",
                      "settings": {"servers": [f"127.0.0.1:{PORTS['mockdns']}"]}}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    }
    inst, ok = start_side(side, cfg, "f8_dnsin")
    try:
        logs = inst.drain(1.0)
        alive = inst.alive()
        obs = {"alive": alive}
        if not alive:
            obs["startup_err"] = [l[:200] for l in logs
                                  if "failed" in l.lower() or "error" in l.lower()][:2]
            record("F8_dns_inbound_protocol", side, obs)
            return
        resp = udp_query(28079, "f8.test", 1, timeout=8.0)
        time.sleep(0.5)
        obs["resp_hex"] = resp.hex() if resp else None
        obs["resp_len"] = len(resp) if resp else None
        record("F8_dns_inbound_protocol", side, obs)
    finally:
        inst.stop()


CASES = [
    ("F1_udp_client_tcp_upstream", case_f1_udp_client_tcp_upstream),
    ("F2_tcp_client_udp_upstream", case_f2_tcp_client_udp_upstream),
    ("F3_serve_stale", case_f3_serve_stale),
    ("F4_use_system_hosts", case_f4_use_system_hosts),
    ("F5_disable_fallback_two_ns", case_f5_disable_fallback),
    ("F6_tcp_upstream_bytes", case_f6_tcp_upstream_bytes),
    ("F7_qtype_array_form", case_f7_qtype_array),
    ("F8_dns_inbound_protocol", case_f8_dns_inbound_protocol),
]


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    for name, fn in CASES:
        if only and only != name:
            continue
        for side in ("go", "rust"):
            try:
                fn(side)
            except Exception as e:  # noqa: BLE001
                record(name, side, {"harness_error": f"{type(e).__name__}: {e}"})
            print(f"[done] {name} {side}", flush=True)
    out = "dns_framing_results.json" if not only else f"dns_framing_{only}.json"
    path = f"D:/Project/Xray-core-rust/reports/audit-2026-10-31-perf-mem-wiring/round4/tmp/{out}"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(list(RESULTS), f, indent=2, ensure_ascii=False)
    print("results ->", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
