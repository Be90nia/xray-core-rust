"""DNS 控制组：区分「Rust DNS app 上游查询被路由回 dns 出站 → ownLink 失效」与「DNS 语义本身差异」。

C1: outbounds = [dns]（dns 为唯一/默认出站）→ DNS app 的上游查询被路由回 dns 出站
C2: outbounds = [freedom(default), dns] + routing inboundTag→dns-out → 上游查询走 freedom
另修正上游 tcp:// 端口写法（Go 用 URL 内端口，port 字段单独给会被忽略）。
"""
import json
import sys
import time

from f2_dns import RESULTS, record, udp_query, tcp_query, summarize, SIDE_PORT
from mocksrv import PORTS, Instance, MockDns, MockDnsTcp


def start_side(side, cfg, name):
    inst = Instance(side, name, cfg).start()
    ok = False
    for _ in range(60):
        for l in inst.drain(0.2):
            if "listening" in l.lower() or "started" in l.lower():
                ok = True
        if ok:
            break
    time.sleep(0.4)
    return inst


def cfg_dns_only(side):
    return {
        "log": {"loglevel": "debug"},
        "dns": {"servers": [{"address": "127.0.0.1", "port": PORTS["mockdns"]}]},
        "inbounds": [{"tag": "dns-in", "listen": "127.0.0.1", "port": SIDE_PORT[side],
                      "protocol": "dokodemo-door",
                      "settings": {"address": "127.0.0.1", "port": 53,
                                   "network": "tcp,udp"}}],
        "outbounds": [{"tag": "dns-out", "protocol": "dns",
                       "settings": {"network": "udp", "address": "127.0.0.1",
                                    "port": PORTS["mockdns"]}}],
    }


def cfg_freedom_default(side):
    return {
        "log": {"loglevel": "debug"},
        "dns": {"servers": [{"address": "127.0.0.1", "port": PORTS["mockdns"]}]},
        "inbounds": [{"tag": "dns-in", "listen": "127.0.0.1", "port": SIDE_PORT[side],
                      "protocol": "dokodemo-door",
                      "settings": {"address": "127.0.0.1", "port": 53,
                                   "network": "tcp,udp"}}],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "dns-out", "protocol": "dns",
             "settings": {"network": "udp", "address": "127.0.0.1",
                          "port": PORTS["mockdns"]}},
        ],
        "routing": {"rules": [{"type": "field", "inboundTag": ["dns-in"],
                               "outboundTag": "dns-out"}]},
    }


def case_c1_dns_only_outbound(side):
    """C1 唯一出站 = dns（经典「本地 DNS 服务器」配置）。"""
    up = MockDns(PORTS["mockdns"]).start()
    inst = start_side(side, cfg_dns_only(side), "c1_dns_only")
    try:
        t0 = time.time()
        resp = udp_query(SIDE_PORT[side], "c1.test", 1, timeout=10.0)
        dt = round(time.time() - t0, 2)
        time.sleep(0.5)
        obs = summarize(resp, up)
        obs["client_wait_s"] = dt
        logs = inst.drain(0.8)
        obs["log_warnings"] = [l[:150] for l in logs
                               if "WARN" in l or "Error" in l or "error" in l][:4]
        record("C1_dns_only_outbound_resolve", side, obs)
    finally:
        inst.stop()
        up.stop()


def case_c2_freedom_default(side):
    """C2 默认出站 = freedom（上游查询不经 dns 出站）。"""
    up = MockDns(PORTS["mockdns"]).start()
    inst = start_side(side, cfg_freedom_default(side), "c2_freedom_def")
    try:
        t0 = time.time()
        resp = udp_query(SIDE_PORT[side], "c2.test", 1, timeout=10.0)
        dt = round(time.time() - t0, 2)
        time.sleep(0.5)
        obs = summarize(resp, up)
        obs["client_wait_s"] = dt
        record("C2_freedom_default_resolve", side, obs)
    finally:
        inst.stop()
        up.stop()


def case_c3_tcp_upstream_url(side):
    """C3 上游 tcp://host:port（URL 内带端口）→ 上游查询字节 + 应答字节。"""
    up = MockDnsTcp(PORTS["mockdns"]).start()
    cfg = cfg_freedom_default(side)
    cfg["dns"] = {"servers": [{"address": f"tcp://127.0.0.1:{PORTS['mockdns']}"}]}
    inst = start_side(side, cfg, "c3_tcp_up")
    try:
        resp = udp_query(SIDE_PORT[side], "c3.test", 1, timeout=10.0)
        time.sleep(0.5)
        record("C3_upstream_tcp_url", side, summarize(resp, up))
    finally:
        inst.stop()
        up.stop()


def case_c4_tc1_control(side):
    """C4 上游回 TC=1（控制组：上游查询走 freedom，不受 ownLink 影响）。"""
    up = MockDns(PORTS["mockdns"], mode="truncated").start()
    cfg = cfg_freedom_default(side)
    inst = start_side(side, cfg, "c4_tc1")
    try:
        resp = udp_query(SIDE_PORT[side], "c4.test", 1, timeout=12.0)
        time.sleep(1.0)
        obs = summarize(resp, up)
        logs = inst.drain(0.8)
        obs["log_tc_mentions"] = [l[:170] for l in logs
                                  if "truncat" in l.lower() or "tcp" in l.lower()][:4]
        record("C4_upstream_tc1_control", side, obs)
    finally:
        inst.stop()
        up.stop()


def case_c5_cache_control(side):
    """C5 缓存命中（控制组）。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = cfg_freedom_default(side)
    inst = start_side(side, cfg, "c5_cache")
    try:
        r1 = udp_query(SIDE_PORT[side], "c5.test", 1, timeout=8.0)
        time.sleep(0.3)
        r2 = udp_query(SIDE_PORT[side], "c5.test", 1, timeout=8.0)
        time.sleep(0.5)
        obs = summarize(r2, up)
        obs["first_resp_hex"] = r1.hex() if r1 else None
        obs["second_resp_hex"] = r2.hex() if r2 else None
        record("C5_cache_hit_control", side, obs)
    finally:
        inst.stop()
        up.stop()


def case_c6_hosts_control(side):
    """C6 静态 hosts（控制组）。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = cfg_freedom_default(side)
    cfg["dns"]["hosts"] = {"static.test": "10.20.30.40"}
    inst = start_side(side, cfg, "c6_hosts")
    try:
        resp = udp_query(SIDE_PORT[side], "static.test", 1, timeout=8.0)
        time.sleep(0.4)
        record("C6_hosts_static_control", side, summarize(resp, up))
    finally:
        inst.stop()
        up.stop()


def case_c7_txt_direct_control(side):
    """C7 TXT + direct 规则（控制组）。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = cfg_freedom_default(side)
    cfg["outbounds"][1]["settings"]["rules"] = [{"action": "direct", "qType": [16]}]
    inst = start_side(side, cfg, "c7_txt")
    try:
        resp = udp_query(SIDE_PORT[side], "c7.test", 16, timeout=8.0)
        time.sleep(0.4)
        record("C7_txt_direct_control", side, summarize(resp, up))
    finally:
        inst.stop()
        up.stop()


def case_c8_return_rcode_control(side):
    """C8 return + rCode=5（控制组）。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = cfg_freedom_default(side)
    cfg["outbounds"][1]["settings"]["rules"] = [{"action": "return", "rCode": 5,
                                                  "qType": [1]}]
    inst = start_side(side, cfg, "c8_ret")
    try:
        resp = udp_query(SIDE_PORT[side], "c8.test", 1, timeout=8.0)
        time.sleep(0.4)
        record("C8_return_rcode5_control", side, summarize(resp, up))
    finally:
        inst.stop()
        up.stop()


def case_c9_nxdomain_control(side):
    """C9 上游 NXDOMAIN（控制组）。"""
    up = MockDns(PORTS["mockdns"], mode="noanswer").start()
    cfg = cfg_freedom_default(side)
    inst = start_side(side, cfg, "c9_nx")
    try:
        resp = udp_query(SIDE_PORT[side], "c9.test", 1, timeout=10.0)
        time.sleep(0.4)
        record("C9_nxdomain_control", side, summarize(resp, up))
    finally:
        inst.stop()
        up.stop()


def case_c10_client_tcp_control(side):
    """C10 客户端走 TCP（控制组）。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = cfg_freedom_default(side)
    inst = start_side(side, cfg, "c10_ctcp")
    try:
        resp = tcp_query(SIDE_PORT[side], "c10.test", 1, timeout=8.0)
        time.sleep(0.4)
        record("C10_client_over_tcp_control", side, summarize(resp, up))
    finally:
        inst.stop()
        up.stop()


def case_c11_strategy_v4_control(side):
    """C11 queryStrategy=UseIPv4（控制组）：上游 qtype。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = cfg_freedom_default(side)
    cfg["dns"]["queryStrategy"] = "UseIPv4"
    inst = start_side(side, cfg, "c11_v4")
    try:
        resp = udp_query(SIDE_PORT[side], "c11.test", 1, timeout=8.0)
        time.sleep(0.4)
        obs = summarize(resp, up)
        obs["upstream_qtypes"] = [p[3] for p in up.parsed if len(p) == 5]
        record("C11_strategy_useipv4_control", side, obs)
    finally:
        inst.stop()
        up.stop()


def case_c12_strategy_v6_control(side):
    """C12 queryStrategy=UseIPv6（控制组）：上游 qtype。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = cfg_freedom_default(side)
    cfg["dns"]["queryStrategy"] = "UseIPv6"
    inst = start_side(side, cfg, "c12_v6")
    try:
        resp = udp_query(SIDE_PORT[side], "c12.test", 28, timeout=8.0)
        time.sleep(0.4)
        obs = summarize(resp, up)
        obs["upstream_qtypes"] = [p[3] for p in up.parsed if len(p) == 5]
        record("C12_strategy_useipv6_control", side, obs)
    finally:
        inst.stop()
        up.stop()


def case_c13_disable_cache_control(side):
    """C13 disableCache（控制组）：上游查询次数。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = cfg_freedom_default(side)
    cfg["dns"]["disableCache"] = True
    inst = start_side(side, cfg, "c13_nocache")
    try:
        udp_query(SIDE_PORT[side], "c13.test", 1, timeout=8.0)
        time.sleep(0.3)
        udp_query(SIDE_PORT[side], "c13.test", 1, timeout=8.0)
        time.sleep(0.5)
        record("C13_disable_cache_control", side, summarize(None, up))
    finally:
        inst.stop()
        up.stop()


CASES = [
    ("C1_dns_only_outbound_resolve", case_c1_dns_only_outbound),
    ("C2_freedom_default_resolve", case_c2_freedom_default),
    ("C3_upstream_tcp_url", case_c3_tcp_upstream_url),
    ("C4_upstream_tc1_control", case_c4_tc1_control),
    ("C5_cache_hit_control", case_c5_cache_control),
    ("C6_hosts_static_control", case_c6_hosts_control),
    ("C7_txt_direct_control", case_c7_txt_direct_control),
    ("C8_return_rcode5_control", case_c8_return_rcode_control),
    ("C9_nxdomain_control", case_c9_nxdomain_control),
    ("C10_client_over_tcp_control", case_c10_client_tcp_control),
    ("C11_strategy_useipv4_control", case_c11_strategy_v4_control),
    ("C12_strategy_useipv6_control", case_c12_strategy_v6_control),
    ("C13_disable_cache_control", case_c13_disable_cache_control),
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
    out = "dns_control_results.json" if not only else f"dns_control_{only}.json"
    path = f"D:/Project/Xray-core-rust/reports/audit-2026-10-31-perf-mem-wiring/round4/tmp/{out}"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(list(RESULTS), f, indent=2, ensure_ascii=False)
    print("results ->", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
