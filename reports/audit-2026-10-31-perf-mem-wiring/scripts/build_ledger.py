"""把 settings-ledger 的分母与人工定性结论合成最终台账（status + finding + evidence）。

分母来自 settings_ledger.py（每 crate 的 `.get("key")` 站点，剔测试与 HTTP 头）。
定性 = FINDINGS 表（人工逐条核对「写入点 → 运行期读点」后填写，禁猜）。
输出 settings-ledger.tsv（列：crate key sites status finding evidence）与三态分布汇总。
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "settings-keys.raw.tsv")
OUT = os.path.join(HERE, "settings-ledger.tsv")

# (crate, json key) -> (status, finding, evidence)
# status: OK=有运行期消费点 / A=解析后零消费 / B=读了但不影响行为 / C=解析失败或类型不符静默默认
FINDINGS = {
    ("xray-transport-quic", "keepAlive"): (
        "A", "F01",
        "crates/xray-transport-quic/src/config.rs:86 写入 keep_alive；build_transport_config"
        "（同文件 143-246）只消费 keep_alive_period_ms，keep_alive 全仓 0 读",
    ),
    ("xray-transport-hysteria", "udpHop"): (
        "A", "F02",
        "crates/xray-transport-hysteria/src/quic_params.rs:88-105 解析校验 → QuicParams.udp_hop；"
        "该 proto 字段全仓无运行期读（真实实现走 finalmask: "
        "crates/xray-transport/src/finalmask/mod.rs:866）",
    ),
    ("xray-transport-splithttp", "downloadSettings"): (
        "A", "F03",
        "crates/xray-transport-splithttp/src/register.rs:405-411 解析成 Config；唯一消费点 "
        "crates/xray-transport-splithttp/src/dialer.rs:386-387 只用 is_some() 推断 mode，"
        "子配置 host/path/headers/mode 全部丢弃（Go: transport/internet/splithttp/dialer.go:355-362 全量生效）",
    ),
    ("xray-transport-grpc", "permitWithoutStream"): (
        "A", "F04",
        "crates/xray-transport-grpc/src/config.rs:118 写入；仅 config.rs:197/212 的 proto 互转读，"
        "h2 keepalive 装配（transport.rs:315-330）不读该字段（Go: transport/internet/grpc/dial.go:161-165 传入 keepalive Params）",
    ),
    ("xray-proxy-ss", "uot"): (
        "A", "F05",
        "crates/xray-proxy-ss/src/dispatcher.rs:396-399 解析为 UdpOverTcpConfig.enabled，"
        "dispatcher.rs:717+ pump_ss2022_udp 恒走裸 UDP 无 uot 分支；.enabled 仅测试断言",
    ),
    ("xray-proxy-ss", "uotVersion"): (
        "A", "F05",
        "crates/xray-proxy-ss/src/dispatcher.rs:399 → UdpOverTcpConfig.version；运行期 0 读（同 F05）",
    ),
    ("xray-proxy-vless", "level"): (
        "A", "F06",
        "crates/xray-proxy-vless/src/plugin.rs:328 → VlessOutboundConfig.level"
        "（def crates/xray-proxy-vless/src/dispatcher.rs:52，写点 174）；全仓非测试 0 读",
    ),
    ("xray-proxy-vmess", "level"): (
        "A", "F06",
        "crates/xray-proxy-vmess/src/dispatcher.rs:210 → VmessOutboundConfig.level（def :54，写点 174 同型）；"
        "全仓非测试 0 读（inbound MemoryUser.level 另有其路，与此无关）",
    ),
    ("xray-proxy-hysteria", "masquerade"): (
        "B", "F07",
        "crates/xray-proxy-hysteria/src/plugin.rs:259-261 用 str_field 只认字符串 → "
        "HysteriaInboundConfig.masq_type（config.rs:272/397）；inbound.rs:200-206 构造内部 "
        "HysteriaConfig 时不带 masq，start() 只读 config.masq → 值被丢弃",
    ),
    ("xray-proxy-hysteria", "alpn"): (
        "B", "F08",
        "crates/xray-proxy-hysteria/src/plugin.rs:245/280 → config.alpn；非测试读仅 "
        "config.rs:156/409 的空值校验，dispatcher.rs:426-430 的 ProtoConfig 无 alpn 字段 → 从不下传，"
        "ALPN 实际只由 tlsSettings.alpn 决定",
    ),
    ("xray-transport-hysteria", "masquerade"): (
        "B", "F09",
        "crates/xray-transport-hysteria/src/proto_config.rs:26-70 展开为 MasqType::Proxy{url,rewrite_host,insecure}，"
        "但 crates/xray-transport-hysteria/src/hub.rs:104 用 `Self::Proxy { .. }` 丢弃全部字段 → "
        "ProxyMasqHandler 恒 503，无反代（Go: transport/internet/hysteria/hub.go 真反代）",
    ),
    ("xray-proxy-ss", "method"): (
        "C", "F10",
        "缺省静默 aes-128-gcm：crates/xray-core/src/inbound.rs:5074、crates/xray-proxy-ss/src/plugin.rs:204；"
        "Go 缺省即 UNKNOWN → 硬错（D:/Project/Xray-core/infra/conf/shadowsocks.go:99）",
    ),
    ("xray-proxy-ss", "password"): (
        "C", "F11",
        "users[] 项缺 password → unwrap_or(\"\") 静默接受：crates/xray-core/src/inbound.rs:5085、"
        "crates/xray-proxy-ss/src/plugin.rs:232；from_proto（crates/xray-proxy-ss/src/config.rs:341-356）"
        "不校验空串 → 用 KDF(\"\") 作为凭据；Go 硬错（infra/conf/shadowsocks.go:71-73）",
    ),
    ("xray-proxy-trojan", "password"): (
        "C", "F12",
        "clients[] 项缺 password → unwrap_or(\"\")：crates/xray-core/src/inbound.rs:4733、"
        "crates/xray-proxy-trojan/src/plugin.rs:195 → key=hex(sha224(\"\")) 公开可算；"
        "Go 硬错（infra/conf/trojan.go:70-71）",
    ),
    ("xray-transport-websocket", "header"): (
        "C", "F13",
        "非字符串 header 值静默跳过：crates/xray-transport-websocket/src/register.rs:675-682；"
        "Go 侧 header 为 map[string]string，类型不符即 JSON 反序列化报错",
    ),
    ("xray-transport-websocket", "headers"): ("C", "F13", "同 header（register.rs:655-656 二选一入口）"),
    ("xray-transport-httpupgrade", "header"): (
        "C", "F13",
        "非字符串 header 值静默跳过：crates/xray-transport-httpupgrade/src/register.rs:611-618",
    ),
    ("xray-transport-httpupgrade", "headers"): ("C", "F13", "同 header（register.rs:600-601）"),
    ("xray-proxy-hysteria", "udpIdleTimeout"): (
        "C", "F14",
        "目标主路（框架装配）消费：plugin.rs:256/283 → udp_idle_timeout_secs；"
        "生产主路 xray-core/outbound.rs:2606-2615 的 parse_hysteria_config 只取 server/auth/sni → "
        "默认可执行文件对该键静默忽略（Go 期望写在 streamSettings.hysteriaSettings）",
    ),
}


def main():
    rows = []
    with open(SRC, encoding="utf-8") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 3:
                continue
            crate, key, sites = parts[0], parts[1], parts[2]
            st, fid, ev = FINDINGS.get((crate, key), ("OK", "-", ""))
            rows.append([crate, key, sites, st, fid, ev])
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("crate\tkey\tsites\tstatus\tfinding\tevidence\n")
        for r in rows:
            fh.write("\t".join(r) + "\n")
    from collections import Counter, defaultdict
    per = defaultdict(Counter)
    tot = Counter()
    for r in rows:
        per[r[0]][r[3]] += 1
        tot[r[3]] += 1
    print("crate\tkeys\tOK\tA\tB\tC")
    for crate in sorted(per):
        c = per[crate]
        print(f"{crate}\t{sum(c.values())}\t{c['OK']}\t{c['A']}\t{c['B']}\t{c['C']}")
    print(f"TOTAL\t{sum(tot.values())}\t{tot['OK']}\t{tot['A']}\t{tot['B']}\t{tot['C']}")


if __name__ == "__main__":
    main()
