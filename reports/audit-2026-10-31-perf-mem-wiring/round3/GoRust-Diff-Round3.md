# 第三轮差分审计：Go 26.10.17 ↔ Rust HEAD 同输入双跑

- 仓库 `D:/Project/Xray-core-rust`，分支 `feature/fix-inbound-parity`，HEAD `5fe98b90`
- 基准二进制：Go `D:/tmp/go2617/xray.exe`（Xray 26.10.17，`92ccc93-dirty`）
- 被测二进制：Rust `target/release/xray.exe`（`git_rev=5fe98b907c7b550d4a70202abb475e26ee89013d` = HEAD，**版本一致**；version 字符串自称 `26.10.11` 属上游版本号滞后，按判定口径不报）
- 方法：同一份输入字节 → 两边各起实例 → 比可观测行为。**所有差异均两侧真跑过**（无源码推导代替实测）
- 端口段：Go 25000-25053 / Rust 25050-25088（GoDiff 专用，未越界）；清理只按 PID（全程无 `-Name` / taskkill 通配）
- 环境说明：本轮全部串行执行，无并发实例干扰（曾出现 1 个游离 `xray.exe`，核实为前序探针超时残留，已按 PID 确认消失，后续全部用例在其之后跑）

---

## 0 一句话结论

**Rust 的 SOCKS5 与 VLESS 入站不把「域名字段形态的 IP 字面量」归一化成 IP 地址**，导致 `routing.rules[].ip` 条件在真实客户端流量下**永远不命中**——屏蔽规则被静默绕过，流量照直走 freedom。这是本轮唯一 **blocker 级**发现（两个协议各一条），且是 **fail-open** 方向（Go 拦截、Rust 放行）。

其余 13 条配置面差异全部同根：Rust 生产主路在装配期大量 **warn + skip / fallback 到 PatternRouter**，Go 则 **拒启**。前一轮已登记 30 条里，票 `vaye2`（路由解析失败静默降级 PatternRouter，屏蔽规则失效）已覆盖「路由规则非法 → 降级」这一支；本轮的新发现是**另一支**：路由规则**完全合法**、也**确实被装载**，但 `ip` 条件因地址未归一化而匹配不上——**降级路径根本不是根因**，修 `vaye2` 修不到这里。

---

## 1 台账总览

| 族 | 用例总数 | 双跑成功 | 差异数 | blocker | 建议 | 口径差异 |
|---|---|---|---|---|---|---|
| 族 1 配置面 | 61 | 61 | 16（复核后 14 有效） | 0 | 13 | 1 |
| 族 2 协议行为 | 43 | 43 | 2（另 4 条为假阳性，已剔除） | 0 | 2 | 0 |
| 族 3 错误与降级 | 16 + 5 专项 | 21 | 3（含 2 条与族 1 同根） | 0 | 1 | 2 |
| 专项探针 | 41 | 41 | 8 | 2 | 3 | 3 |
| **合计** | **162** | **162** | **26（去重后 21 条独立差异）** | **2** | **16** | **5** |

失败用例：0。所有 162 例两侧均真实启动/退出并产出可观测输出，无「哪边跑不起来」的用例。

去重说明：族 1 的 14 条有效差异中，13 条共享同一根因（装配期 fail-open），逐条列在 §2；族 3 的 `dns_dead_server_domain` 与族 1 的 DNS 用例同根；专项探针的 `ip_*` 5 条与族 3 的 blackhole 用例同根（= blocker 主条目）。

---

## 2 差异表（按用户可见后果排序；「Rust 更宽松」置顶）

### 2.1 Blocker

| # | 场景 | 差异类型 | Go 行为（实测输出） | Rust 行为（实测输出） | 位置 file:line | 用户可见后果 | 严重度 | 建议 |
|---|---|---|---|---|---|---|---|---|
| B1 | SOCKS5 入站，客户端把目标 IP 以**域名字段形态**发送（`ATYP=0x03` + `"192.168.89.180"`），路由规则 `{"type":"field","ip":["192.168.89.180"],"outboundTag":"out-black"}` | 路由 `ip` 条件不命中 → 屏蔽规则静默失效 | `app/dispatcher: taking detour [out-black] for [tcp:192.168.89.180:25053]` → payload **不回显**（被 blackhole 丢弃） | `DEBUG target=192.168.89.180:25053 resolving domain via system DNS` → payload **回显**（流量走 freedom 直连） | `crates/xray-proxy-socks/src/protocol.rs:248`（`Host::Domain(domain)` 恒返回域类型，未做 IP 归一化）；上游 `crates/xray-core/src/inbound.rs:387`、`crates/xray-core/src/wiring.rs:196` | **屏蔽/分流规则被绕过**：本该走 blackhole/代理的流量在 Rust 上直连泄漏。同 `ATYP=0x01`（真 IPv4 字面量）两侧一致拦截 → 说明只有「客户端把 IP 塞进域名字段」这条路径漏 | **blocker** | 向 Go 对齐：在 `parse_address_port` 的 domain 分支加 IP 字面量归一化（Go `common/protocol/address.go:213-217`：`maybeIPPrefix(domain[0])` → `net.ParseAddress` → `Family().IsIP()` 则返回 IP 地址）。Go 的判据是「首字符为 `[` 或数字」即尝试解析，成功即视为 IP |
| B2 | 同 B1，但走 **VLESS 入站**（生产主协议，`ATYP=0x02` + `"192.168.89.180"`） | 同根因（VLESS 侧同样未归一化） | `proxy/vless/inbound: received request for tcp:192.168.89.180:25049` → `taking detour [out-black] for [tcp:192.168.89.180:25049]` → payload **不回显** | `DEBUG target=192.168.89.180:25049 resolving domain via system DNS` → payload **回显**（走 freedom 直连，**未按路由规则拦截**） | `crates/xray-proxy-vless/src/encoding/mod.rs:174`（`Address::Domain(domain)`，与 socks 同型缺口） | VLESS 客户端若以域名字段传 IP，`ip` 类路由规则（geoip/CIDR 分流、广告屏蔽、CN 直连）全部失效。**VLESS 是生产主协议 → 影响面比 SOCKS 更大** | **blocker** | 同 B1，抽公共归一化函数（建议落 `xray-common::net::address` 或 `xray-common::protocol`），socks/vless/http/trojan 共用 |

B1/B2 最小复现（各一条命令）：

```
python reports/audit-2026-10-31-perf-mem-wiring/round3/scripts/probe_lan_ip.py
# socks_atyp1_ipv4_literal      GO(echo=False) RUST(echo=False) SAME
# socks_atyp3_domain_ip_literal GO(echo=False) RUST(echo=True)  **DIFF**

python reports/audit-2026-10-31-perf-mem-wiring/round3/scripts/probe_vless_lan2.py
# vless_atyp1_ipv4_literal      GO(echo=False) RUST(echo=False) SAME
# vless_atyp2_domain_ip_literal GO(echo=False) RUST(echo=True)  **DIFF**
```

**测量方法学（两个干扰变量都已排除，此为取得决定性证据的关键）**：

1. **不用 127.0.0.1**：freedom 对 loopback 有独立的 block 逻辑（Go `proxy/freedom: blocked target`；Rust `freedom: target blocked by final rule, blackholing connection`）。若用环回地址，Rust 也会表现为「不回显」——但那是 freedom 拦的、不是路由拦的，会把「路由是否命中」这个变量**完全掩盖**。改用本机 LAN IP `192.168.89.180` 后变量分离。
2. **freedom 显式 `finalRules:[{"action":"allow"}]`**：Rust 的 VLESS 入站默认注入 `BlockPrivate` 规则（`crates/xray-core/src/functions.rs:944-947` 记：vless/vmess/trojan 入站 → BlockPrivate 含 127.0.0.0/8），会二次掩盖路由判定。显式 allow 后只剩路由这一个变量。

排除这两个干扰后，B1/B2 均为**单变量决定性实测**：同一份客户端字节、同一份路由规则，Go 走 `detour [out-black]`、Rust 走 freedom 直连。

补充对照（证明不是「Rust 路由整体失效」而是**只有 ip 条件失效**）：`port` / `network` / `inboundTag` 三类路由条件两侧**都正常拦截**（`probe_routing.py`：`rule_port_match_blackhole`、`rule_network_tcp_blackhole`、`rule_inboundtag_blackhole` 全部 SAME）；`ATYP=0x01`（真 IPv4 字面量）两侧**都正常拦截**。唯一漏的正是「域名字段形态的 IP 字面量」这一条。

---

### 2.2 建议级：配置面「Go 拒启 / Rust 放行」（Rust 更宽松 = fail-open）

以下 13 条**共享同一根因**：Rust 生产主路（`xray_conf::Config::build()` → `xray_core::start_full`）在装配期把「这条配置项我处理不了」降级成 `WARN` + 跳过 / fallback，进程照常启动并对外服务；Go 26.10.17 则在 `Failed to start:` 阶段拒启。

| # | 场景 | 差异类型 | Go 行为（实测输出） | Rust 行为（实测输出） | 位置 file:line | 用户可见后果 | 严重度 | 建议 |
|---|---|---|---|---|---|---|---|---|
| C1 | 出站协议名不存在 `{"protocol":"nosuchproto"}` | 装配期 fail-open | `Failed to start: ... infra/conf: failed to build ...`（exit 23） | `WARN outbound protocol not yet supported, skipping tag=out-x protocol=nosuchproto` → **正常监听 25000** | `crates/xray-core/src/arm_builders/mod.rs`（`OUTBOUND_CTORS` 未命中 → warn+skip） | 写错协议名 → 服务照常起，但该出站被静默丢弃，流量落到默认出站**直连**（与票 `o91s4` 同族，但本条是**协议名本身不存在**，前轮票覆盖的是「已支持协议的构造失败」） | 建议 | 向 Go 对齐：未命中构造表应 fail-visible 拒启 |
| C2 | 入站协议名不存在 `{"protocol":"nosuchproto"}` | 装配期 fail-open | `Failed to start: ... infra/conf: failed to build inbound ...`（exit 23） | `WARN inbound protocol not yet supported, skipping tag=in-x protocol=nosuchproto` → 正常监听 | `crates/xray-core/src/arm_builders/mod.rs`（`INBOUND_CTORS` 未命中 → warn+skip） | 写错入站协议名 → **该入站零监听**（用户以为端口在监听，实际没有；与前轮票 `vdl95`「未知协议 inbound 零监听」重叠，**本条是实测确认，票面已有**） | 建议 | 同 C1；本条为 `vdl95` 的实测补证，不新开票 |
| C3 | 出站 `settings.vnext` 缺失或为空数组（vless） | 装配期 fail-open | `Failed to start: ... vless "vnext" should have one and only one member`（exit 23） | `WARN failed to parse outbound config, skipping tag=out-x protocol=vless error=vless "vnext" should have one and only one member...` → 正常监听 | `crates/xray-core/src/outbound.rs`（`build_single_outbound` 失败 → warn+skip） | 协议配置写错 → 该出站静默消失，流量直连 | 建议 | 同 C1 |
| C4 | `settings` 是字符串 `"none"`（类型错） | 装配期 fail-open | `Failed to start: ... failed to build outbound ...`（exit 23） | `WARN secrets collection: outbound settings unparsable, skipped protocol=freedom error=invalid type: string "none", expected struct FreedomOutboundSettings` → 正常监听 | `crates/xray-conf/src/protocols.rs:1366`（`dispatch_outbound_settings` → untagged enum 全不匹配 → None → 跳过） | 同 C3 | 建议 | 同 C1 |
| C5 | `socks.settings.udp` 是字符串 `"false"`（类型错） | 装配期 fail-open | `Failed to start: ... failed to build inbound ...`（exit 23） | `WARN secrets collection: inbound settings unparsable, skipped protocol=socks error=invalid type: string "false", expected a boolean` → 正常监听 | 同 C4（`crates/xray-conf/src/protocols.rs:1394` 附近） | 同 C2 | 建议 | 同 C1 |
| C6 | 出站 tag 重复（两个 `tag:"out-1"`） | 装配期 fail-open | `Failed to start: main: failed to create server > app/proxyman/outbound: existing tag found: out-1`（exit 23） | **无任何错误输出**，正常监听 | `crates/xray-core/src/arm_registry.rs`（`register_outbounds` → `BoundedRegistry::insert` 对重复键静默覆盖） | 重复 tag → 后者静默覆盖前者，配置里写的两条规则语义丢失且**零提示**。注：前轮 §7 已复核「重复 tag 报 registry full」为 REJECTED，并记录「覆盖丢 cancel 令牌 → 孤儿监听器」，**本条是该结论的实测确认** | 建议 | 同 C1；与前轮结论合并，不新开票 |
| C7 | `freedom.settings.domainStrategy` 非法枚举 `"AsIs2"` | 装配期 fail-open | `Failed to start: ... failed to build outbound ...`（exit 23） | `WARN failed to parse outbound config, skipping tag=out-1 protocol=freedom error=unsupported domain strategy: AsIs2` → 正常监听 | `crates/xray-core/src/outbound.rs`（`parse_freedom_config` 失败 → warn+skip） | 唯一的 outbound 被跳过 → 无可用出站；服务仍起、仍监听 | 建议 | 同 C1 |
| C8 | `routing.rules` 是对象不是数组 | 装配期 fail-open | `Failed to start: ... infra/conf/serial: ...`（exit 23） | **无错误输出**，正常监听 | `crates/xray-core/src/wiring.rs`（router 构造失败 → 静默） | 路由段整体失效 → 全部流量走默认出站 | 建议 | 同 C1 |
| C9 | 路由规则缺 `type` 字段 | 路由降级 | `Failed to start: ... failed to build router ...`（exit 23） | `WARN full Router init failed, falling back to PatternRouter error=routing config JSON parse: neither outboundTag nor balancerTag is specified in routing rule` → 正常监听 | `crates/xray-core/src/wiring.rs`（Router init 失败 → fallback PatternRouter） | 整份路由规则被丢弃 → 屏蔽规则失效（**即前轮票 `vaye2` 的根因**，本条为实测补证） | 建议 | 票 `vaye2` 已覆盖，**不新开票** |
| C10 | 路由 `ip` 非法 CIDR `"999.1.1.1/24"` | 路由降级 | `Failed to start: ... failed to build router ...`（exit 23） | `WARN full Router init failed, falling back to PatternRouter error=routing config JSON parse: routing rule ip: 无效的 IP 地址: 999.1.1.1` → 正常监听 | 同 C9 | 同 C9（票 `vaye2`） | 建议 | 同 C9 |
| C11 | 路由规则 `type` 非法 `"bogus"` | 路由降级 | `Failed to start: ... app/router: this rule has no effective fields`（exit 23） | `WARN full Router init failed, falling back to PatternRouter error=router init: this rule has no effective fields` → 正常监听 | 同 C9 | 同 C9（票 `vaye2`） | 建议 | 同 C9 |
| C12 | 路由 `domainStrategy` 非法 `"Bogus"` | 路由降级 | `Failed to start: ... app/router: this rule has no effective fields`（exit 23） | `WARN full Router init failed, falling back to PatternRouter error=router init: this rule has no effective fields` → 正常监听 | 同 C9 | 同 C9（票 `vaye2`） | 建议 | 同 C9 |
| C13 | 顶层 JSON 是数组 `[]`（不是对象） | 顶层解析宽松 | `Failed to start: ...`（exit 23） | **正常监听**（顶层结构被当空配置处理） | `crates/xray-conf/src/serial.rs`（顶层解析未约束为 object） | 空/畸形配置被当「无入站无出站」放行，服务起但什么都不做 | 建议 | 向 Go 对齐：顶层必须是 object |

**C1-C13 汇总**：一条修复即可覆盖全部 13 条——装配期「构造表未命中 / settings 解析失败 / router init 失败」一律 **fail-visible 拒启**（或至少 **拒绝该条并让整体启动失败**），而不是 warn+skip。这与前轮 SUMMARY §5 给出的止血方向（4 张 P0 共用「一条装配期 fail-visible 门」）完全一致，本轮从**另一条独立路径**（真实二进制双跑）再次证实该结论。

---

### 2.3 建议级：HTTP 入站错误响应对齐

| # | 场景 | 差异类型 | Go 行为（实测输出） | Rust 行为（实测输出） | 位置 file:line | 用户可见后果 | 严重度 | 建议 |
|---|---|---|---|---|---|---|---|---|
| C14 | HTTP 入站，缺 `Host` 头 `GET / HTTP/1.1\r\n\r\n` | 错误响应缺失 | `HTTP/1.1 400 Bad Request\r\nConnection: close\r\n` | **空响应**（直接关连接） | `crates/xray-proxy-http/src/server.rs`（HTTP/1.1 要求 Host，解析失败路径不回 400） | 客户端拿到「连接被重置」而非可读的 400；curl/pac 脚本看到的错误信息完全不可诊断 | 建议 | 向 Go 对齐：缺 Host 回 400 |
| C15 | HTTP 入站，`Content-Length` 非法 `"abc"`（或负数 `-1`） | 错误响应方向相反 | **空响应**（Go 直接断链，日志 `failed to read http request > bad Content-Length "abc"`） | `HTTP/1.1 400 Bad Request` | 同 C14 | 与 C14 恰好**方向相反**：Go 静默断链、Rust 回 400。两边各有一类请求得不到正确错误响应 | 建议 | 向 Go 对齐（Go 的行为更保守，断链即可）；或统一两侧为「400 + 可读 reason」 |

注：C14/C15 是「**两边都不一致**」的对齐缺口，不是 fail-open。

---

### 2.4 口径差异（Rust 更严格 / Rust 更优，供 PM 判断）

| # | 场景 | 差异类型 | Go 行为（实测输出） | Rust 行为（实测输出） | 位置 file:line | 用户可见后果 | 严重度 | 建议 |
|---|---|---|---|---|---|---|---|---|
| S1 | 入站 `port` = 70000（越界） | Rust 更严格 | **启动但不监听**（`Xray 26.10.17 started`，进程活着，25000 端口无监听） | `Error: failed to load config: ... failed to parse json config ... data did not match any variant of untagged enum Raw`（exit 23，拒启） | `crates/xray-conf/src/protocols.rs`（port 走 `u16` 严格反序列化） | Go 侧是**更糟的行为**：进程活着但端口不监听，supervisor 以为服务正常、用户以为端口在监听。Rust 的拒启是正确方向 | 口径差异 | **Rust 保持**（拒启优于假启动） |
| S2 | `dns.servers` = `{"address": null}` / `{"port": 53}`（缺 address） | **Go 崩溃，Rust 干净报错** | `panic: runtime error: invalid memory address or nil pointer dereference` @ `infra/conf/fakedns.go:79`（**exit 2，堆栈 dump**） | `ERROR invalid app config kind=dns invalid dns config: invalid type: null, expected a string`（exit 1，干净报错） | Go 侧 `D:/Project/Xray-core/infra/conf/fakedns.go:79`；Rust 侧 `crates/xray-app-dns/src/` | Rust 在此处**优于** Go：Go 是 nil 解引用 panic（配置一错就崩栈），Rust 是可读的启动失败 | 口径差异（Rust 更优） | **Rust 保持**；此条同时是 Go 上游的缺陷，值得回传给 Go 仓 |
| S3 | `dns.servers` = `"127.0.0.1:1"`（带端口） | 口径不同 | `Failed to start: ... app/dns: failed to create nameserver > parse "127.0.0.1:1": first path segment in URL cannot contain colon`（exit 23） | **正常启动**（Rust 的 DNS server 接受 `host:port` 形态） | `crates/xray-app-dns/src/`（Rust DNS 配置解析支持带端口） | Rust 更宽松：接受 Go 拒启的写法。但 Rust 后续对该 nameserver 的实际行为未在本轮测出（见「未覆盖范围」） | 口径差异 | 向 Go 对齐（Go 26.10.17 明确拒启）；但 Rust 的写法更实用，**建议 PM 拍板**：若保留 Rust 扩展，须在文档标注与 Go 不兼容 |
| S4 | `dns.servers` = `""`（空串）/ `{"address": ""}` | 口径不同 | 正常启动（Go 接受空 nameserver） | `ERROR invalid app config kind=dns dns wire format error: empty nameserver host`（exit 1，拒启） | `crates/xray-app-dns/src/` | Rust 更严格，但空 nameserver 本就是无意义配置，Rust 拒启合理 | 口径差异 | **Rust 保持** |
| S5 | `dns.servers` = `"not-an-ip-at-all"` / `"localhost"` / IPv6 各种形态 | 口径一致（都接受） | 正常启动 | 正常启动 | — | 无差异 | 无 | 无需动作 |

---

## 3 族 2 协议行为差分（43 例，2 条有效差异）

43 例覆盖 SOCKS5(14) / HTTP(12) / VLESS(9) / Trojan(4) / VMess(3) 的畸形帧、超长、截断、零长、重复握手、非法版本/命令/枚举字段、鉴权失败、半关闭、早退。

**41 例两侧完全一致**（含：零长连接、非法 ATYP、非法 CMD、截断帧、非法版本字节、VLESS 重复握手、Trojan 错密码、VMess 垃圾字节、HTTP 各种畸形请求行、超长 path/header、chunked、Expect: 100-continue 等）。两侧在这些场景下的**连接结果、返回字节、进程存活**全部逐字节一致。**未发现 Rust panic/崩溃**。

有效差异 2 条 = §2.3 的 C14/C15（HTTP 入站错误响应）。

已剔除的 4 条假阳性：`socks5_request_bad_version` / `port_zero` / `ipv6` / `domain_long` —— 首次比较把 SOCKS5 应答的 **BND.ADDR/BND.PORT（10 字节应答里的后 6 字节）** 误当作 payload 比对，而该字段含**出站连接的临时端口**，两侧天然不同。修正比较口径（只比 REP 码 + payload + 存活）后 4 例均 SAME。

---

## 4 族 3 错误与降级语义差分（16 例 + 5 专项）

16 例覆盖：路由命中/不命中/引用不存在出站/blackhole、路由 domainStrategy、DNS 服务器不可达、DNS 未配置、出站拨号失败（socks/vmess）、首个出站即死、纯 blackhole 出站、代理链多跳、目标不可达。

**13 例两侧一致**，包括：
- 目标端口无人监听 → 两侧都先回 SOCKS 成功再在数据面断（Go `WinError 10054`，Rust 同）
- 出站拨号失败（socks/vmess 指向死端口）→ 两侧同样先回成功
- 代理链 `freedom → 死 socks` → 两侧同样
- 不可路由目标 `192.0.2.1` → 两侧同样超时

3 条差异：
1. `routing_match_to_blackhole` → **= B1**（Rust 未按 `ip` 规则拦截）
2. `routing_match_to_nonexistent_outbound` → 规则引用不存在的 outboundTag：Go `Warning: app/dispatcher: non existing outTag: out-nope` 后断链；Rust 无该警告且**流量直连**（`data=70696e670a` = payload 回显）。**根因与 B1 同源**（该用例的规则用 `ip` 条件 → Rust 未命中 → 落到默认 freedom），但**暴露面独立**：Go 对「tag 不存在」有明确告警，Rust 侧完全没有。建议作为 B1 的补充证据，不单开票。
3. `dns_dead_server_domain` → Go 拒启（`app/dns: failed to create nameserver > parse "127.0.0.1:1"`），Rust 放行。**= S3**。

---

## 5 关键代码定位

| 差异 | 根因位置 | Go 对照 |
|---|---|---|
| B1 | `crates/xray-proxy-socks/src/protocol.rs:244-248`（domain 分支恒返回 `Host::Domain`，无 IP 归一化） | `D:/Project/Xray-core/common/protocol/address.go:213-217` |
| B2 | `crates/xray-proxy-vless/src/encoding/mod.rs:168-175`（`Address::Domain(domain)`，同型缺口） | `D:/Project/Xray-core/proxy/vless/encoding/encoding.go:120`（`addrParser.ReadAddressPort` → 同一个 `readAddress`，故 Go 两侧都归一化） |
| B1/B2 下游 | `crates/xray-core/src/inbound.rs:387`、`crates/xray-core/src/wiring.rs:196`（`Address::Domain` → `with_target_domain`，`target_ips` 为空 → `IPMatcherCondition::apply` 恒 false，`crates/xray-app-router/src/condition.rs:219-222`） | — |
| C1-C7 | `crates/xray-core/src/arm_builders/mod.rs` + `crates/xray-core/src/outbound.rs`（构造失败 → warn+skip）+ `crates/xray-core/src/arm_registry.rs`（`BoundedRegistry::insert` 重复键静默覆盖） | `D:/Project/Xray-core/infra/conf/xray.go`（`Build()` 返回 error → `Failed to start`） |
| C9-C12 | `crates/xray-core/src/wiring.rs`（Router init 失败 → fallback PatternRouter） | `D:/Project/Xray-core/app/router/config.go` |
| C14/C15 | `crates/xray-proxy-http/src/server.rs`（HTTP/1.1 解析失败的错误响应路径） | `D:/Project/Xray-core/proxy/http/server.go` |

Go 的归一化判据（`common/protocol/address.go:213-217` + `:155-157`）：

```go
if maybeIPPrefix(domain[0]) {        // 首字符为 '[' 或 '0'-'9'
    addr := net.ParseAddress(domain)
    if addr.Family().IsIP() {
        return addr, nil             // 成功 → 返回 IP 地址而非域名
    }
}
```

---

## 6 未覆盖范围（如实声明）

1. **B2（VLESS）已用 LAN IP + `finalRules:[{action:allow}]` 做过决定性实测**（`probe_vless_lan2.py`：Go `detour [out-black]` 不回显 / Rust 回显），**归因强度与 B1 对等**。但 VLESS 侧未覆盖 XTLS Vision 加密流、mux command、UDP command 三条子路径。
2. **S3（Rust 接受 `host:port` 形态 nameserver）的运行期行为未测**：Rust 接受该写法后，实际是把它当 UDP nameserver 还是纯忽略，本轮未测（探针只测到「能启动」）。
3. **DNS 解析路径未做 Go↔Rust 抓包对拍**：族 3 的 DNS 用例只到「启动/拒启 + 客户端可见结果」层，未做 wire 级对比。
4. **UDP 面未覆盖**：本轮族 2/族 3 全为 TCP。UDP（dokodemo-door / socks UDP associate / VLESS XUDP）不在本轮。
5. **TLS/REALITY 层未覆盖**：畸形 TLS ClientHello、证书链、REALITY 握手均未测。
6. **多跳代理链只测了 1 层链 + 死链**：`proxySettings` 指向真实可达的第二跳未测。
7. **HTTP/Trojan/VMess 入站的「域名字段 IP 字面量」未单测**：B1/B2 的同型缺口按代码结构存在于 `xray-common::protocol` 层的所有地址解析点，但本轮只对 socks/vless 做了决定性实测；http/trojan/vmess 的对应路径**未实测**（属 B1/B2 修复时应一并覆盖的验收面，非本轮已证事实）。
8. **未做性能/内存计量**（按契约非目标）。
9. **未验证 32/32 与 interop 12/12 回归**：本轮只读审计、零代码改动，不需要回归；但 B1/B2 的修复**必须**以 32/32 + interop 12/12 双闸验收。
   - **修复面风险（已核查，比初判低）**：归一化应只做在**入站解码**侧（把 domain 字段里的 IP 字面量转成 `Address::IPv4/IPv6`）。入站不重新编码 wire，故**出站字节不变**。
   - **出站侧无需改**：Rust 的 VLESS 出站用 `Destination` 携带的 `Address`（`crates/xray-proxy-vless/src/outbound/handler.rs:101-121` → `self.destination`），类型已正确区分 IPv4/IPv6/Domain → `write_address_port` 天然写对 ATYP。（初判曾担心「Rust 客户端把 IP 一律编码成 Domain 会导致 wire 字节变化」，核查后确认**不成立**：`plugin.rs:350` 的 `Address::Domain` 是 **vnext 服务器地址**，不是目标地址。）
   - **行为变化点**：目标从「按域名做一次系统 DNS 解析」变为「直接按 IP 拨号」。这正是 Go 的行为（Go 的 `readAddress` 在解析阶段就归一化，后续按 IP 拨号）。对 `domainStrategy: AsIs` 的配置，Rust 当前的「domain 形态 IP 字面量仍走一次系统 DNS」是多余的一次解析，且会让 `target_ips` 为空 → 触发 B1/B2。
   - 修复后需回归：`ip`/`geoip` 类路由规则的命中面会**变宽**（原本漏掉的现在命中）——这是修复目的，但也意味着**原先依赖「漏匹配」的部署配置行为会变**，需 PM 知悉。
10. **未审 Rust 内部实现风格**（按契约非目标）。

---

## 7 复现方式

```bash
cd reports/audit-2026-10-31-perf-mem-wiring/round3/scripts

python f1_config.py      # 族 1：61 例配置面双跑（~10 min）
python f1_verify.py      # 族 1 差异复核：补「是否真在监听」+ 完整错误文本（~30 s）
python f2_protocol.py    # 族 2：43 例协议畸形帧双跑（~45 s）
python f3_degrade.py     # 族 3：16 例错误/降级语义双跑（~55 s）

python probe_lan_ip.py   # ★ B1 最小复现（决定性：LAN IP 目标 + finalRules allow）
python probe_vless_lan2.py # ★ B2 最小复现（同上，VLESS 侧）
python probe_atyp.py     # B1 分因：ATYP=IPv4 vs 域名字段
python probe_ip_cond.py  # ip 条件 8 种写法对比
python probe_routing.py  # 路由条件 7 种写法对比（port/network/inboundTag 都正常）
python probe_scope.py    # domainStrategy 三态 + HTTP 入站
python probe_tag.py      # 不存在 outboundTag + 默认 domainStrategy
python probe_http.py     # HTTP 入站错误响应对齐
python probe_dnsform.py  # DNS server 地址形态 14 种
python probe_dnspanic.py # Go DNS panic 复现
python probe_vless_ip.py # VLESS 侧 loopback 版（会被 freedom 的 BlockPrivate 掩盖，仅作对照）
```

产物：`tmp/f1_results.json`（族 1 原始）、`tmp/f1_verify.json`（族 1 复核）、`tmp/f2_results.json`、`tmp/f3_results.json`；各用例的配置文件与日志在 `tmp/`。

---

## 8 给 PM 的三个决策点

1. **B1/B2 是否立即开票**：这是本轮唯一 blocker，且是 fail-open（屏蔽规则绕过 → 流量直连泄漏）。前轮票 `vaye2`（路由降级）**修不到它**，建议新开 P0。修法建议落公共归一化函数（`xray-common`），一次覆盖 socks/vless/http/trojan。
2. **C1-C13 是否合并成一条「装配期 fail-visible 门」**：与前轮 SUMMARY §5 的止血建议同向，但本轮提供了**独立路径的实测证据**（前轮是代码层推导，本轮是真实二进制双跑）。建议按前轮方案一次收口，13 条作为该门的验收用例清单。
3. **S1-S5（Rust 更严格）是否保留**：本轮 5 条全部建议 Rust 保留，其中 S2（Go panic）建议回传 Go 上游。唯一需拍板的是 S3（Rust 接受 `host:port` 形态 nameserver）——保留 Rust 扩展则须在文档标注与 Go 不兼容。
