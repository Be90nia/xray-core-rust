"""修正组：DNS 规则面用 Go 兼容的 qType 字符串形态（PortList）+ Rust TCP 分支定位。

E1-E5: rules 用 "qType": "16"/"1"（两侧都能启动）→ 比应答字节 + 上游查询字节
E6: Rust DNS 出站 TCP 分支——不 rewrite network（上游 TCP）→ 判定 Rust TCP 帧分支是否本身可用
E7: Rust TCP 客户端 + dns 出站 rewrite network=udp → 复现（与 Go 对照）
E8: Rust 唯一出站=dns 的 ownLink 判定——加第二个 freedom 出站是否恢复（C2 已证）
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
    ok = False
    for _ in range(60):
        for l in inst.drain(0.2):
            low = l.lower()
            if "listening" in low or "started" in low:
                ok = True
        if ok:
            break
    time.sleep(0.4)
    if not inst.alive():
        return inst, False
    return inst, True


def cfg_base(side, rules=None, ob_settings=None, dns=None, dst_port=53,
             network="tcp,udp"):
    settings = {"network": "udp", "address": "127.0.0.1", "port": PORTS["mockdns"]}
    if ob_settings:
        settings.update(ob_settings)
    if rules is not None:
        settings["rules"] = rules
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


def case_e1_txt_direct(side):
    """E1 TXT + direct 规则（qType 字符串形态）→ 上游查询字节 + 应答字节。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = cfg_base(side, rules=[{"action": "direct", "qType": "16"}])
    inst, ok = start_side(side, cfg, "e1_txt_direct")
    try:
        if not ok:
            record("E1_txt_direct_qtype_str", side, {"error": "instance not alive"})
            return
        resp = udp_query(SIDE_PORT[side], "e1.test", 16, timeout=8.0)
        time.sleep(0.4)
        record("E1_txt_direct_qtype_str", side, summarize(resp, up))
    finally:
        inst.stop()
        up.stop()


def case_e2_return_rcode5(side):
    """E2 return + rCode=5（qType 字符串形态）→ 应答 rcode。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = cfg_base(side, rules=[{"action": "return", "rCode": 5, "qType": "1"}])
    inst, ok = start_side(side, cfg, "e2_ret5")
    try:
        if not ok:
            record("E2_return_rcode5_qtype_str", side, {"error": "instance not alive"})
            return
        resp = udp_query(SIDE_PORT[side], "e2.test", 1, timeout=8.0)
        time.sleep(0.4)
        record("E2_return_rcode5_qtype_str", side, summarize(resp, up))
    finally:
        inst.stop()
        up.stop()


def case_e3_drop(side):
    """E3 drop 规则（qType 字符串形态）→ 是否回包。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = cfg_base(side, rules=[{"action": "drop", "qType": "1"}])
    inst, ok = start_side(side, cfg, "e3_drop")
    try:
        if not ok:
            record("E3_drop_qtype_str", side, {"error": "instance not alive"})
            return
        resp = udp_query(SIDE_PORT[side], "e3.test", 1, timeout=5.0)
        time.sleep(0.4)
        record("E3_drop_qtype_str", side, summarize(resp, up))
    finally:
        inst.stop()
        up.stop()


def case_e4_hijack(side):
    """E4 hijack 规则显式（qType 字符串形态）→ 应答字节。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = cfg_base(side, rules=[{"action": "hijack", "qType": "1"}])
    inst, ok = start_side(side, cfg, "e4_hijack")
    try:
        if not ok:
            record("E4_hijack_qtype_str", side, {"error": "instance not alive"})
            return
        resp = udp_query(SIDE_PORT[side], "e4.test", 1, timeout=8.0)
        time.sleep(0.4)
        record("E4_hijack_qtype_str", side, summarize(resp, up))
    finally:
        inst.stop()
        up.stop()


def case_e5_domain_rule(side):
    """E5 domain 规则（full:e5.test）→ 命中与否。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = cfg_base(side, rules=[{"action": "return", "rCode": 5,
                                 "domain": "full:e5.test"}])
    inst, ok = start_side(side, cfg, "e5_domain")
    try:
        if not ok:
            record("E5_domain_rule_full", side, {"error": "instance not alive"})
            return
        r_hit = udp_query(SIDE_PORT[side], "e5.test", 1, timeout=8.0)
        time.sleep(0.3)
        r_miss = udp_query(SIDE_PORT[side], "other.test", 1, timeout=8.0)
        time.sleep(0.4)
        obs = summarize(r_miss, up)
        obs["hit_resp_hex"] = r_hit.hex() if r_hit else None
        obs["miss_resp_hex"] = r_miss.hex() if r_miss else None
        record("E5_domain_rule_full", side, obs)
    finally:
        inst.stop()
        up.stop()


def case_e6_tcp_upstream_no_rewrite(side):
    """E6 Rust TCP 分支：上游 TCP 且不 rewrite network → 上游查询字节 + 应答。"""
    up = MockDnsTcp(PORTS["mockdns"]).start()
    cfg = cfg_base(side, ob_settings={"network": None, "address": None, "port": None},
                   dst_port=PORTS["mockdns"], network="tcp")
    # 去掉 network/address/port 的 rewrite（置 None → 序列化时剔除）
    cfg["outbounds"][1]["settings"] = {"rules": []}
    cfg["dns"] = {"servers": [{"address": f"tcp://127.0.0.1:{PORTS['mockdns']}"}]}
    inst, ok = start_side(side, cfg, "e6_tcp_no_rw")
    try:
        if not ok:
            record("E6_tcp_client_tcp_upstream", side, {"error": "instance not alive"})
            return
        resp = tcp_query(SIDE_PORT[side], "e6.test", 1, timeout=8.0)
        time.sleep(0.5)
        obs = summarize(resp, up)
        logs = inst.drain(0.8)
        obs["log_tail"] = [l[:170] for l in logs if "dns" in l.lower()][:4]
        record("E6_tcp_client_tcp_upstream", side, obs)
    finally:
        inst.stop()
        up.stop()


def case_e7_tcp_client_udp_upstream(side):
    """E7 TCP 客户端 + dns 出站 rewrite network=udp → 与 Go 对照。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = cfg_base(side, network="tcp,udp")
    inst, ok = start_side(side, cfg, "e7_tcpcli_udpu")
    try:
        if not ok:
            record("E7_tcp_client_udp_upstream", side, {"error": "instance not alive"})
            return
        resp = tcp_query(SIDE_PORT[side], "e7.test", 1, timeout=8.0)
        time.sleep(0.5)
        obs = summarize(resp, up)
        logs = inst.drain(0.8)
        obs["log_tail"] = [l[:170] for l in logs if "dns" in l.lower()][:5]
        record("E7_tcp_client_udp_upstream", side, obs)
    finally:
        inst.stop()
        up.stop()


def case_e8_udp_client_udp_upstream(side):
    """E8 UDP 客户端 + dns 出站 rewrite network=udp → 正常路径对照。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = cfg_base(side, network="tcp,udp")
    inst, ok = start_side(side, cfg, "e8_udpcli")
    try:
        if not ok:
            record("E8_udp_client_udp_upstream", side, {"error": "instance not alive"})
            return
        resp = udp_query(SIDE_PORT[side], "e8.test", 1, timeout=8.0)
        time.sleep(0.4)
        record("E8_udp_client_udp_upstream", side, summarize(resp, up))
    finally:
        inst.stop()
        up.stop()


def case_e9_cname_direct(side):
    """E9 CNAME + direct 规则 → 上游查询字节 + 应答字节（含 CNAME 记录）。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = cfg_base(side, rules=[{"action": "direct", "qType": "5"}])
    inst, ok = start_side(side, cfg, "e9_cname")
    try:
        if not ok:
            record("E9_cname_direct", side, {"error": "instance not alive"})
            return
        resp = udp_query(SIDE_PORT[side], "e9.test", 5, timeout=8.0)
        time.sleep(0.4)
        record("E9_cname_direct", side, summarize(resp, up))
    finally:
        inst.stop()
        up.stop()


def case_e10_a_query_string_qtype(side):
    """E10 A + qType "1" 显式 hijack 语义 → 应答 + 上游字节。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = cfg_base(side, rules=[{"action": "hijack", "qType": "1"}])
    inst, ok = start_side(side, cfg, "e10_a")
    try:
        if not ok:
            record("E10_a_hijack_explicit", side, {"error": "instance not alive"})
            return
        resp = udp_query(SIDE_PORT[side], "e10.test", 1, timeout=8.0)
        time.sleep(0.4)
        record("E10_a_hijack_explicit", side, summarize(resp, up))
    finally:
        inst.stop()
        up.stop()


CASES = [
    ("E1_txt_direct_qtype_str", case_e1_txt_direct),
    ("E2_return_rcode5_qtype_str", case_e2_return_rcode5),
    ("E3_drop_qtype_str", case_e3_drop),
    ("E4_hijack_qtype_str", case_e4_hijack),
    ("E5_domain_rule_full", case_e5_domain_rule),
    ("E6_tcp_client_tcp_upstream", case_e6_tcp_upstream_no_rewrite),
    ("E7_tcp_client_udp_upstream", case_e7_tcp_client_udp_upstream),
    ("E8_udp_client_udp_upstream", case_e8_udp_client_udp_upstream),
    ("E9_cname_direct", case_e9_cname_direct),
    ("E10_a_hijack_explicit", case_e10_a_query_string_qtype),
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
    out = "dns_rules_results.json" if not only else f"dns_rules_{only}.json"
    path = f"D:/Project/Xray-core-rust/reports/audit-2026-10-11-perf-mem-wiring/round4/tmp/{out}"
    path = path.replace("2026-10-11", "2026-10-31")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(list(RESULTS), f, indent=2, ensure_ascii=False)
    print("results ->", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
