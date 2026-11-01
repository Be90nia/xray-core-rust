"""族 1：配置面双跑差分（同一份 JSON 喂 Go 26.10.17 与 Rust HEAD）。

每例 = 一份 JSON → 顺序跑 Go、跑 Rust（同一端口，先后，不并发）→ 比「启动/拒启」与报错类别。
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import (  # noqa: E402
    RUST_PORT_BASE,
    TMP,
    kill_proc,
    run_once,
    summarize,
    write_cfg,
)

GO_PORT = 25000
RUST_PORT = 25050


def base(port):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "in-1",
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }
        ],
        "outbounds": [{"tag": "out-1", "protocol": "freedom", "settings": {}}],
        "policy": {"levels": {"0": {}}},
        "routing": {"rules": [{"type": "field", "inboundTag": ["in-1"], "outboundTag": "out-1"}]},
    }


def case(name, mutate, note=""):
    """mutate(cfg) -> cfg or raw string"""
    cfg = base(GO_PORT)
    raw = mutate(cfg)
    if raw is None:
        raw = cfg  # 多数 mutator 用 dict.update() 就地改并返回 None
    return {"name": name, "note": note, "raw": raw}


CASES = []


def add(name, mutate, note=""):
    CASES.append(case(name, mutate, note))


# --- 未知协议名 ---
add("unknown_outbound_protocol", lambda c: c["outbounds"].append(
    {"tag": "out-x", "protocol": "nosuchproto", "settings": {}}), "出站协议名不存在")
add("unknown_inbound_protocol", lambda c: c["inbounds"].append(
    {"tag": "in-x", "listen": "127.0.0.1", "port": GO_PORT + 1,
     "protocol": "nosuchproto", "settings": {}}), "入站协议名不存在")
add("protocol_case_typo", lambda c: c["outbounds"].append(
    {"tag": "out-x", "protocol": "Freedom", "settings": {}}), "协议名大小写错")

# --- 缺失必需字段 ---
add("vless_outbound_no_vnext", lambda c: c["outbounds"].append(
    {"tag": "out-x", "protocol": "vless", "settings": {"vnext": []}}), "vnext 空数组")
add("vless_outbound_missing_vnext", lambda c: c["outbounds"].append(
    {"tag": "out-x", "protocol": "vless", "settings": {}}), "vnext 缺失")
add("socks_inbound_missing_settings", lambda c: c["inbounds"].append(
    {"tag": "in-x", "listen": "127.0.0.1", "port": GO_PORT + 2, "protocol": "socks"}),
    "socks settings 缺失")
add("missing_outbounds", lambda c: {k: v for k, v in c.items() if k != "outbounds"}, "outbounds 缺失")
add("missing_inbounds", lambda c: {k: v for k, v in c.items() if k != "inbounds"}, "inbounds 缺失")
add("empty_outbounds", lambda c: c.update({"outbounds": []}), "outbounds 空数组")

# --- 错类型 ---
add("port_as_string", lambda c: c["inbounds"][0].update({"port": "25000"}), "port 是字符串")
add("port_as_float", lambda c: c["inbounds"][0].update({"port": 25000.5}), "port 是小数")
add("port_as_bool", lambda c: c["inbounds"][0].update({"port": True}), "port 是布尔")
add("loglevel_as_int", lambda c: c["log"].update({"loglevel": 3}), "loglevel 是数字")
add("udp_as_string", lambda c: c["inbounds"][0]["settings"].update({"udp": "false"}), "udp 是字符串")
add("inbounds_as_object", lambda c: c.update({"inbounds": {"tag": "x"}}), "inbounds 是对象不是数组")
add("outbounds_as_object", lambda c: c.update({"outbounds": {"tag": "x"}}), "outbounds 是对象不是数组")
add("settings_as_string", lambda c: c["outbounds"][0].update({"settings": "none"}), "settings 是字符串")

# --- 越界 ---
add("port_too_large", lambda c: c["inbounds"][0].update({"port": 70000}), "port > 65535")
add("port_negative", lambda c: c["inbounds"][0].update({"port": -1}), "port 负数")
add("port_zero", lambda c: c["inbounds"][0].update({"port": 0}), "port = 0")
add("port_max_ok", lambda c: c["inbounds"][0].update({"port": 65535}), "port = 65535")

# --- 重复 tag / 空 tag ---
add("dup_tag_inbound", lambda c: c["inbounds"].append(
    dict(c["inbounds"][0])), "入站 tag 重复")
add("dup_tag_outbound", lambda c: c["outbounds"].append(
    {"tag": "out-1", "protocol": "freedom", "settings": {}}), "出站 tag 重复")
add("empty_tag_inbound", lambda c: c["inbounds"][0].update({"tag": ""}), "入站 tag 空串")
add("empty_tag_outbound", lambda c: c["outbounds"][0].update({"tag": ""}), "出站 tag 空串")
add("missing_tag_inbound", lambda c: c["inbounds"][0].pop("tag"), "入站 tag 缺失")
add("missing_tag_outbound", lambda c: c["outbounds"][0].pop("tag"), "出站 tag 缺失")

# --- 未知枚举值 ---
add("unknown_log_level", lambda c: c["log"].update({"loglevel": "verbose"}), "loglevel 非法枚举")
add("unknown_domain_strategy", lambda c: c["outbounds"][0]["settings"].update(
    {"domainStrategy": "AsIs2"}), "freedom domainStrategy 非法")
add("unknown_sniff_dest_override", lambda c: c["inbounds"][0].update(
    {"sniffing": {"enabled": True, "destOverride": ["http", "bogus"]}}), "sniffing destOverride 非法项")
add("unknown_policy_level", lambda c: c.update(
    {"policy": {"levels": {"0": {"timeout": {"handshake": 1}}, "bogus": {}}}}), "policy level 非法")

# --- 数值上下界 ---
add("bufferSize_huge", lambda c: c["outbounds"][0].update(
    {"settings": {"bufferSize": 2147483647}}), "bufferSize = i32::MAX")
add("bufferSize_negative", lambda c: c["outbounds"][0].update(
    {"settings": {"bufferSize": -1}}), "bufferSize 负数")
add("bufferSize_zero", lambda c: c["outbounds"][0].update(
    {"settings": {"bufferSize": 0}}), "bufferSize = 0")
add("concurrency_zero", lambda c: c["outbounds"][0].update(
    {"settings": {"concurrency": 0}}), "concurrency = 0")
add("concurrency_huge", lambda c: c["outbounds"][0].update(
    {"settings": {"concurrency": 999999999}}), "concurrency 极大")
add("concurrency_negative", lambda c: c["outbounds"][0].update(
    {"settings": {"concurrency": -1}}), "concurrency 负数")
add("policy_bufferSize_huge", lambda c: c.update(
    {"policy": {"levels": {"0": {"bufferSize": 2147483647}}}}), "policy bufferSize i32::MAX")
add("policy_bufferSize_negative", lambda c: c.update(
    {"policy": {"levels": {"0": {"bufferSize": -1}}}}), "policy bufferSize 负数")

# --- duration ---
add("duration_seconds", lambda c: c["policy"].update(
    {"levels": {"0": {"timeout": {"handshake": 10}}}}), "duration 秒")
add("duration_composite", lambda c: c["policy"].update(
    {"levels": {"0": {"timeout": {"handshake": "1m30s"}}}}), "duration 复合单位 1m30s")
add("duration_bogus", lambda c: c["policy"].update(
    {"levels": {"0": {"timeout": {"handshake": "abc"}}}}), "duration 非法串")
add("duration_zero", lambda c: c["policy"].update(
    {"levels": {"0": {"timeout": {"handshake": 0}}}}), "duration = 0")
add("duration_negative", lambda c: c["policy"].update(
    {"levels": {"0": {"timeout": {"handshake": -5}}}}), "duration 负数")
add("duration_ms", lambda c: c["policy"].update(
    {"levels": {"0": {"timeout": {"handshake": 500}}}}), "duration 毫秒")

# --- 嵌套层级错误 ---
add("routing_rules_not_array", lambda c: c.update(
    {"routing": {"rules": {"type": "field"}}}), "routing.rules 是对象")
add("routing_rule_missing_type", lambda c: c.update(
    {"routing": {"rules": [{"inboundTag": ["in-1"]}]}}), "routing rule 缺 type")
add("dns_servers_not_array", lambda c: c.update(
    {"dns": {"servers": "8.8.8.8"}}), "dns.servers 是字符串")
add("dns_server_bad_addr", lambda c: c.update(
    {"dns": {"servers": ["not-an-ip"]}}), "dns server 地址非法")
add("inbound_streamSettings_not_object", lambda c: c["inbounds"][0].update(
    {"streamSettings": "tcp"}), "streamSettings 是字符串")

# --- 顶层畸形 ---
add("json_trailing_comma", lambda c: '{"inbounds": [], "outbounds": [],}', "JSON 尾逗号")
add("json_truncated", lambda c: '{"inbounds": [], "outbounds": [', "JSON 截断")
add("json_not_object", lambda c: "[]", "JSON 是数组不是对象")
add("json_empty_file", lambda c: "", "空文件")
add("json_bom_garbage", lambda c: "\ufeffnot json at all", "BOM + 乱码")

# --- 路由 / DNS 语义 ---
add("routing_rule_unknown_domain_strategy", lambda c: c.update(
    {"routing": {"domainStrategy": "Bogus", "rules": [
        {"type": "field", "outboundTag": "out-1"}]}}), "routing.domainStrategy 非法")
add("routing_rule_unknown_inbound_tag", lambda c: c.update(
    {"routing": {"rules": [
        {"type": "field", "inboundTag": ["nope"], "outboundTag": "out-1"}]}}), "路由引用不存在 inbound tag")
add("routing_rule_unknown_outbound_tag", lambda c: c.update(
    {"routing": {"rules": [
        {"type": "field", "inboundTag": ["in-1"], "outboundTag": "nope"}]}}), "路由引用不存在 outbound tag")
add("routing_bad_ip_cidr", lambda c: c.update(
    {"routing": {"rules": [
        {"type": "field", "ip": ["999.1.1.1/24"], "outboundTag": "out-1"}]}}), "路由 ip 非法 CIDR")
add("routing_unknown_rule_type", lambda c: c.update(
    {"routing": {"rules": [
        {"type": "bogus", "outboundTag": "out-1"}]}}), "路由 rule type 非法")
add("dns_query_strategy_bogus", lambda c: c.update(
    {"dns": {"servers": ["8.8.8.8"], "queryStrategy": "Bogus"}}), "dns queryStrategy 非法")


ERR_CATS = [
    ("json_parse", re.compile(r"(parsing .*json|invalid character|unexpected end of JSON|json:)", re.I)),
    ("unknown_protocol", re.compile(r"(unknown protocol|invalid protocol|not supported|unrecognized protocol)", re.I)),
    ("missing_field", re.compile(r"(missing|required|empty .*(vnext|settings)|no .* specified)", re.I)),
    ("bad_value", re.compile(r"(invalid|must be|out of range|unexpected)", re.I)),
    ("type_mismatch", re.compile(r"(cannot unmarshal|expected .* got|type .* mismatch)", re.I)),
    ("port_range", re.compile(r"(port|listen)", re.I)),
    ("dup_tag", re.compile(r"(duplicate|already exists|duplicated)", re.I)),
    ("unknown_enum", re.compile(r"(unknown|invalid).*(value|level|strategy|enum)", re.I)),
    ("duration", re.compile(r"(duration|timeout|parse)", re.I)),
]


def err_cat(text):
    if not text:
        return "NO_OUTPUT"
    for name, rx in ERR_CATS:
        if rx.search(text):
            return name
    return "OTHER"


def main():
    out = []
    for i, c in enumerate(CASES):
        payload = c["raw"]
        if isinstance(payload, (dict, list)):
            payload = json.dumps(payload, indent=2, ensure_ascii=False)
        cfg_path = write_cfg("f1_%02d_%s" % (i, c["name"]), payload)
        r_go = run_once("go", cfg_path, timeout=8)
        r_rs = run_once("rust", cfg_path, timeout=8)
        s_go = summarize(r_go)
        s_rs = summarize(r_rs)
        out.append(
            {
                "case": c["name"],
                "note": c["note"],
                "go": s_go,
                "rs": s_rs,
                "same": s_go["verdict"] == s_rs["verdict"],
            }
        )
        print(
            "[%02d] %-38s GO=%-14s RUST=%-14s %s"
            % (i, c["name"], s_go["verdict"], s_rs["verdict"],
               "SAME" if s_go["verdict"] == s_rs["verdict"] else "**DIFF**"),
            flush=True,
        )
    with open(os.path.join(TMP, "f1_results.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    n_diff = sum(1 for o in out if not o["same"])
    print("\nF1 total=%d diff=%d" % (len(out), n_diff))


if __name__ == "__main__":
    main()
