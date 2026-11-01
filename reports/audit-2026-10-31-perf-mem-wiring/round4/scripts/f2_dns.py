"""DNS 面差分：本地 DNS 服务（dokodemo→dns 出站）+ DNS 客户端出站 wire 对比。

共同面（Go 26.10.17 无 dns 入站协议，故用 dokodemo-door + dns 出站，两侧同构）：
- 入站 dokodemo-door（tcp,udp）→ 唯一出站 dns（= 默认出站）
- 顶层 dns app → mock 上游（记录原始查询字节）
每条用例：同一份客户端字节 → 两侧各跑一次 → 比应答字节 + 比上游收到的查询字节。
"""
import json
import socket
import struct
import sys
import time

from mocksrv import (PORTS, Instance, MockDns, MockDnsTcp, build_query, parse_query,
                     wait_port)

RESULTS = []
SIDE_PORT = {"go": PORTS["go_dnsout"], "rust": PORTS["rust_dnsout"]}


def record(case, side, obs):
    RESULTS.append({"case": case, "side": side, "obs": obs})


def base_cfg(side, servers, dns_extra=None, rules=None):
    dns = {"servers": servers}
    if dns_extra:
        dns.update(dns_extra)
    ob_settings = {"network": "udp", "address": "127.0.0.1", "port": PORTS["mockdns"]}
    if rules is not None:
        ob_settings["rules"] = rules
    return {
        "log": {"loglevel": "debug"},
        "dns": dns,
        "inbounds": [{"tag": "dns-in", "listen": "127.0.0.1", "port": SIDE_PORT[side],
                      "protocol": "dokodemo-door",
                      "settings": {"address": "127.0.0.1", "port": 53,
                                   "network": "tcp,udp"}}],
        "outbounds": [{"tag": "dns-out", "protocol": "dns", "settings": ob_settings}],
    }


def start_side(side, cfg, name):
    inst = Instance(side, name, cfg).start()
    # UDP 端口 wait_port 不能证明已监听（UDP connect 恒成功）→ 睡固定时长后查存活
    time.sleep(1.2)
    inst.drain(0.6)
    return inst


def udp_query(port, qname, qtype=1, qid=0x1234, timeout=5.0, edns=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(build_query(qname, qtype, qid, edns=edns), ("127.0.0.1", port))
    try:
        data, _ = s.recvfrom(65535)
    except socket.timeout:
        data = None
    except ConnectionResetError:
        data = None
    finally:
        s.close()
    return data


def tcp_query(port, qname, qtype=1, qid=0x1234, timeout=5.0):
    q = build_query(qname, qtype, qid)
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(struct.pack("!H", len(q)) + q)
    try:
        hdr = s.recv(2)
        if len(hdr) < 2:
            return None
        ln = struct.unpack("!H", hdr)[0]
        buf = b""
        while len(buf) < ln:
            chunk = s.recv(ln - len(buf))
            if not chunk:
                break
            buf += chunk
        data = buf if len(buf) == ln else None
    except (socket.timeout, ConnectionResetError, OSError):
        data = None
    finally:
        s.close()
    return data


def summarize(resp, upstream):
    out = {
        "resp_hex": resp.hex() if resp else None,
        "resp_len": len(resp) if resp else None,
        "upstream_queries": len(upstream.queries),
        "upstream_parsed": [list(p) for p in upstream.parsed],
        "upstream_raw": upstream.queries,
    }
    if resp:
        try:
            qid, flags, qname, qtype, has_edns = parse_query(resp)
            out["resp_header"] = {"id": qid, "flags": hex(flags), "rcode": flags & 0xF,
                                  "qd": (flags >> 15) & 1, "aa": (flags >> 10) & 1,
                                  "tc": (flags >> 9) & 1, "rd": (flags >> 8) & 1,
                                  "ra": (flags >> 7) & 1}
        except Exception as e:  # noqa: BLE001
            out["resp_parse_error"] = str(e)
    return out


# ───────────────────────── 用例 ─────────────────────────
def case_dns_a(side):
    """D1 A 查询（默认规则 → Hijack → 内部 DNS 客户端 → mock 上游）。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = base_cfg(side, [{"address": "127.0.0.1", "port": PORTS["mockdns"]}])
    inst = start_side(side, cfg, "dns_a")
    try:
        resp = udp_query(SIDE_PORT[side], "a.test", 1)
        time.sleep(0.4)
        record("D1_dns_A_hijack", side, summarize(resp, up))
    finally:
        inst.stop()
        up.stop()


def case_dns_aaaa(side):
    """D2 AAAA 查询。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = base_cfg(side, [{"address": "127.0.0.1", "port": PORTS["mockdns"]}])
    inst = start_side(side, cfg, "dns_aaaa")
    try:
        resp = udp_query(SIDE_PORT[side], "aaaa.test", 28)
        time.sleep(0.4)
        record("D2_dns_AAAA_hijack", side, summarize(resp, up))
    finally:
        inst.stop()
        up.stop()


def case_dns_cname_default(side):
    """D3 CNAME 查询（默认规则 → Return → 空应答，不打上游）。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = base_cfg(side, [{"address": "127.0.1", "port": PORTS["mockdns"]}])
    inst = start_side(side, cfg, "dns_cname")
    try:
        resp = udp_query(SIDE_PORT[side], "c.test", 5)
        time.sleep(0.4)
        record("D3_dns_CNAME_default_return", side, summarize(resp, up))
    finally:
        inst.stop()
        up.stop()


def case_dns_txt_direct(side):
    """D4 TXT 查询 + 规则 direct → 原样转发上游，比应答字节 + 上游查询字节。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = base_cfg(side, [{"address": "127.0.0.1", "port": PORTS["mockdns"]}],
                   rules=[{"action": "direct", "qType": [16]}])
    inst = start_side(side, cfg, "dns_txt_direct")
    try:
        resp = udp_query(SIDE_PORT[side], "t.test", 16)
        time.sleep(0.4)
        record("D4_dns_TXT_direct_forward", side, summarize(resp, up))
    finally:
        inst.stop()
        up.stop()


def case_dns_hosts(side):
    """D5 静态 hosts 映射。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = base_cfg(side, [{"address": "127.0.0.1", "port": PORTS["mockdns"]}],
                   dns_extra={"hosts": {"static.test": "10.20.30.40"}})
    inst = start_side(side, cfg, "dns_hosts")
    try:
        resp = udp_query(SIDE_PORT[side], "static.test", 1)
        time.sleep(0.4)
        obs = summarize(resp, up)
        record("D5_dns_hosts_static", side, obs)
    finally:
        inst.stop()
        up.stop()


def case_dns_strategy_v4(side):
    """D6 queryStrategy=UseIPv4 → 上游只应收到 A 查询。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = base_cfg(side, [{"address": "127.0.0.1", "port": PORTS["mockdns"]}],
                   dns_extra={"queryStrategy": "UseIPv4"})
    inst = start_side(side, cfg, "dns_strat_v4")
    try:
        resp = udp_query(SIDE_PORT[side], "s.test", 1)
        time.sleep(0.4)
        obs = summarize(resp, up)
        obs["upstream_qtypes"] = [p[3] for p in up.parsed if len(p) == 5]
        record("D6_dns_strategy_useipv4", side, obs)
    finally:
        inst.stop()
        up.stop()


def case_dns_strategy_v6(side):
    """D7 queryStrategy=UseIPv6 → 上游只应收到 AAAA 查询。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = base_cfg(side, [{"address": "127.0.0.1", "port": PORTS["mockdns"]}],
                   dns_extra={"queryStrategy": "UseIPv6"})
    inst = start_side(side, cfg, "dns_strat_v6")
    try:
        resp = udp_query(SIDE_PORT[side], "s6.test", 28)
        time.sleep(0.4)
        obs = summarize(resp, up)
        obs["upstream_qtypes"] = [p[3] for p in up.parsed if len(p) == 5]
        record("D7_dns_strategy_useipv6", side, obs)
    finally:
        inst.stop()
        up.stop()


def case_dns_cache_hit(side):
    """D8 缓存命中：同域两次查询 → 上游只应收到一次（默认启用缓存）。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = base_cfg(side, [{"address": "127.0.0.1", "port": PORTS["mockdns"]}])
    inst = start_side(side, cfg, "dns_cache")
    try:
        r1 = udp_query(SIDE_PORT[side], "cache.test", 1)
        time.sleep(0.3)
        r2 = udp_query(SIDE_PORT[side], "cache.test", 1)
        time.sleep(0.5)
        obs = summarize(r2, up)
        obs["first_resp_hex"] = r1.hex() if r1 else None
        obs["second_resp_hex"] = r2.hex() if r2 else None
        record("D8_dns_cache_hit", side, obs)
    finally:
        inst.stop()
        up.stop()


def case_dns_disable_cache(side):
    """D9 disableCache=true → 两次查询都打上游。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = base_cfg(side, [{"address": "127.0.0.1", "port": PORTS["mockdns"]}],
                   dns_extra={"disableCache": True})
    inst = start_side(side, cfg, "dns_nocache")
    try:
        udp_query(SIDE_PORT[side], "nc.test", 1)
        time.sleep(0.3)
        udp_query(SIDE_PORT[side], "nc.test", 1)
        time.sleep(0.5)
        obs = summarize(None, up)
        record("D9_dns_disable_cache", side, obs)
    finally:
        inst.stop()
        up.stop()


def case_dns_nxdomain(side):
    """D10 上游 NXDOMAIN → 应答 rcode。"""
    up = MockDns(PORTS["mockdns"], mode="noanswer").start()
    cfg = base_cfg(side, [{"address": "127.0.0.1", "port": PORTS["mockdns"]}])
    inst = start_side(side, cfg, "dns_nx")
    try:
        resp = udp_query(SIDE_PORT[side], "nx.test", 1, timeout=6.0)
        time.sleep(0.4)
        record("D10_dns_nxdomain", side, summarize(resp, up))
    finally:
        inst.stop()
        up.stop()


def case_dns_tcp_client(side):
    """D11 客户端走 TCP（RFC 1035 长度前缀帧）→ 应答字节。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = base_cfg(side, [{"address": "127.0.0.1", "port": PORTS["mockdns"]}])
    inst = start_side(side, cfg, "dns_tcp")
    try:
        resp = tcp_query(SIDE_PORT[side], "tcp.test", 1)
        time.sleep(0.4)
        record("D11_dns_client_over_tcp", side, summarize(resp, up))
    finally:
        inst.stop()
        up.stop()


def case_dns_tcp_upstream(side):
    """D12 上游走 TCP（tcp:// 形式）→ 上游收到的查询字节 + 应答字节。"""
    up = MockDnsTcp(PORTS["mockdns"]).start()
    cfg = base_cfg(side, [{"address": "tcp://127.0.0.1", "port": PORTS["mockdns"]}])
    inst = start_side(side, cfg, "dns_tcp_up")
    try:
        resp = udp_query(SIDE_PORT[side], "tcpup.test", 1, timeout=6.0)
        time.sleep(0.4)
        record("D12_dns_upstream_over_tcp", side, summarize(resp, up))
    finally:
        inst.stop()
        up.stop()


def case_dns_tc1(side):
    """D13 上游回 TC=1（截断）→ 是否回退 TCP / 应答形态。"""
    up = MockDns(PORTS["mockdns"], mode="truncated").start()
    cfg = base_cfg(side, [{"address": "127.0.0.1", "port": PORTS["mockdns"]}])
    inst = start_side(side, cfg, "dns_tc1")
    try:
        resp = udp_query(SIDE_PORT[side], "tc.test", 1, timeout=8.0)
        time.sleep(0.8)
        obs = summarize(resp, up)
        logs = inst.drain(0.8)
        obs["log_tc_mentions"] = [l[:160] for l in logs
                                  if "truncat" in l.lower() or "tcp" in l.lower()][:4]
        record("D13_dns_upstream_tc1_truncated", side, obs)
    finally:
        inst.stop()
        up.stop()


def case_dns_return_rcode(side):
    """D14 规则 return + rCode=5 → 应答 rcode。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = base_cfg(side, [{"address": "127.0.0.1", "port": PORTS["mockdns"]}],
                   rules=[{"action": "return", "rCode": 5, "qType": [1]}])
    inst = start_side(side, cfg, "dns_ret5")
    try:
        resp = udp_query(SIDE_PORT[side], "r.test", 1)
        time.sleep(0.4)
        record("D14_dns_return_rcode5", side, summarize(resp, up))
    finally:
        inst.stop()
        up.stop()


def case_dns_drop(side):
    """D15 规则 drop → 不回包。"""
    up = MockDns(PORTS["mockdns"]).start()
    cfg = base_cfg(side, [{"address": "127.0.0.1", "port": PORTS["mockdns"]}],
                   rules=[{"action": "drop", "qType": [1]}])
    inst = start_side(side, cfg, "dns_drop")
    try:
        resp = udp_query(SIDE_PORT[side], "d.test", 1, timeout=4.0)
        time.sleep(0.4)
        record("D15_dns_drop_no_reply", side, summarize(resp, up))
    finally:
        inst.stop()
        up.stop()


def case_dns_silent_upstream(side):
    """D16 上游静默（不回包）→ 客户端可见行为（超时 / 无应答）。"""
    up = MockDns(PORTS["mockdns"], mode="silent").start()
    cfg = base_cfg(side, [{"address": "127.0.0.1", "port": PORTS["mockdns"]}])
    inst = start_side(side, cfg, "dns_silent")
    try:
        t0 = time.time()
        resp = udp_query(SIDE_PORT[side], "silent.test", 1, timeout=12.0)
        dt = time.time() - t0
        time.sleep(0.4)
        obs = summarize(resp, up)
        obs["client_wait_s"] = round(dt, 2)
        record("D16_dns_upstream_silent", side, obs)
    finally:
        inst.stop()
        up.stop()


CASES = [
    ("D1_dns_A_hijack", case_dns_a),
    ("D2_dns_AAAA_hijack", case_dns_aaaa),
    ("D3_dns_CNAME_default_return", case_dns_cname_default),
    ("D4_dns_TXT_direct_forward", case_dns_txt_direct),
    ("D5_dns_hosts_static", case_dns_hosts),
    ("D6_dns_strategy_useipv4", case_dns_strategy_v4),
    ("D7_dns_strategy_useipv6", case_dns_strategy_v6),
    ("D8_dns_cache_hit", case_dns_cache_hit),
    ("D9_dns_disable_cache", case_dns_disable_cache),
    ("D10_dns_nxdomain", case_dns_nxdomain),
    ("D11_dns_client_over_tcp", case_dns_tcp_client),
    ("D12_dns_upstream_over_tcp", case_dns_tcp_upstream),
    ("D13_dns_upstream_tc1_truncated", case_dns_tc1),
    ("D14_dns_return_rcode5", case_dns_return_rcode),
    ("D15_dns_drop_no_reply", case_dns_drop),
    ("D16_dns_upstream_silent", case_dns_silent_upstream),
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
    out = "dns_results.json" if not only else f"dns_results_{only}.json"
    path = f"D:/Project/Xray-core-rust/reports/audit-2026-10-31-perf-mem-wiring/round4/tmp/{out}"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(RESULTS, f, indent=2, ensure_ascii=False)
    print("results ->", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
