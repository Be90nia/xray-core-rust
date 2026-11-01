# 第四轮差分审计：UDP 面 + DNS 面（Go 26.10.17 ↔ Rust HEAD）

- 仓库 `D:/Project/Xray-core-rust`，分支 `feature/fix-inbound-parity`，HEAD `5fe98b90`
- 基准二进制：Go `D:/tmp/go2617/xray.exe`（Xray 26.10.17，`92ccc93-dirty`）
- 被测二进制：Rust `target/release/xray.exe`（`git_rev=5fe98b907c7b550d4a70202abb475e26ee89013d` = HEAD）
- 方法：同一份输入字节 → 两侧各起一个实例 → 比可观测行为（应答字节 + 上游收到的原始查询字节）。
  **所有差异均两侧真跑过**（无源码推导代替实测）；机制归因均经定向判别实验确认。
- 端口段：UdpDnsDiff 专用 **28050-28099**（实际用 28060-28089）；实例清理只按 PID（`Popen.terminate()`），
  无 `-Name` / taskkill / 通配。
- 环境：本机 Windows（10.0.26200）+ Go/Rust 二进制；mock DNS 上游与 UDP echo 均为本脚本自建的
  Python 服务（记录原始字节），不依赖外网。
- 脚本与原始结果：`round4/scripts/*.py`、`round4/tmp/*.json`

---

## 0 一句话结论

**UDP 面基本一致（16/17 例逐字节相同），DNS 面的「应答内容」也逐字节一致；真正的差异全部集中在
三条路径上：① Rust 的 DNS `ownLink` 判定失效 → DNS app 的上游查询回环进 dns 出站后再次被 Hijack，
形成无限回环 → 本地 DNS 服务器在 Rust 上完全无应答（Go 正常）；② Rust 的 DNS 出站按「上游网络」
而非「客户端网络」选择帧格式 → TCP 客户端 + UDP 上游时零应答（Go 正常）；③ Rust 的 UDP 域名目标
只取解析结果的首个地址 → 域名型 UDP 目标静默丢包（Go 正常）。**
另有一条 Rust 更宽松的配置方言差异（`qType` 数组形态 Go 拒启 / Rust 接受）、一条 Rust 独占协议差异、
一条 Rust 严格方向的截断处理差异。

---

## 1 台账总览

| 族 | 用例总数 | 两侧均真实运行 | 差异数 | blocker | 建议 | 口径差异 |
|---|---|---|---|---|---|---|
| UDP 面（同侧对照 + 跨侧对打） | 17 | 17 | 2（1 功能 + 1 观测） | 0 | 1 | 1 |
| DNS 面（语义对照 + 装配对照） | 47 | 44（另 3 例 Go 侧装配期拒启，见下注） | 5（2 功能 + 1 配置 + 1 独占协议 + 1 严格方向） | 0 | 3 | 2 |
| **合计** | **64** | **61** | **7** | **0** | **4** | **3** |

失败用例：0（61 例两侧均真实启动/跑完并产出可观测输出）。

> **D4/D14/D15 三例的 Go 侧未启动**：这三例最初用 `qType: [16]` 数组形态写规则，Go 在**装配期拒启**
> （exit 23）——该「拒启 vs 接受」现象本身即差异 D4。已用 Go 兼容的字符串形态 `"qType": "16"` 重跑为
> E1/E2/E3/E10（+ E4-E10 其余规则面），**全部逐字节一致**，证明规则语义无差异、差异只在方言形态。

**「Rust 更宽松」置顶检查**：本轮唯一一条 Rust 更宽松项是 **F7（`qType` 数组形态）**——Go 在装配期
拒启（exit 23），Rust 接受并生效。它不是安全 fail-open（不影响拦截/放行判定），但会让「同一份配置
能否跨实现复用」出现分歧，故仍按判定口径置顶列出。其余 5 条为 Rust 功能缺失 / 独占行为。

---

## 2 差异表（按用户可见后果排序）

| # | 场景 | 类型 | Go 行为（实测） | Rust 行为（实测） | 位置 file:line | 用户可见后果 | 严重度 | 建议 |
|---|---|---|---|---|---|---|---|---|
| **D1** | **本地 DNS 服务器**：入站 `dokodemo-door(udp,tcp)` + **唯一出站 = `dns`**（Xray 文档标准形态）；顶层 `dns.servers` 指向同一 mock 上游 | 缺陷 | 客户端查询立即得到 A 记录应答 `12348580000100010000000002633104746573740000010001c00c000100010000012c000401020304`；mock 上游收到 **1** 条查询 | 客户端 **15s 超时零应答**；mock 上游收到 **0** 条查询；日志连续 3 次 `WARN ip query: c1.test (qType 1): dns wire format error: udp dial recv timeout after 4s` + `record not found` | Go：`app/dns/nameserver.go:184`（`session.ContextWithInbound(ctx, &session.Inbound{Tag: c.tag})`）+ `app/dns/dns.go:219-227`（`IsOwnLink` 比对 client tag）+ `proxy/dns/dns.go:242-247`（ownLink 命中 → 原样转发）；Rust：`crates/xray-core/src/functions.rs:816-828`（`DispatcherDnsDialer::dial_udp` 派发上游查询时 **不带 inbound tag** → `AccessContext.inbound_tag` 为空）+ `crates/xray-app-dns/src/server.rs:142-147`（`is_own_link` 空 tag 直接 false）+ `crates/xray-app-dns/src/jsonconf.rs:460`（nameserver client tag 缺省为空串，Go 用 `xray.system.<uuid>`/ns.Tag） | **Rust 上「本地 DNS 服务器」完全不可用**：所有 A/AAAA 查询 4s 超时回环、客户端零应答，DNS 解析整体失效（表现为「域名解析不了」，但进程不崩、不报错给用户） | 建议（Rust 功能缺失，Go 正常；非 fail-open） | 三处对齐 Go：① DNS app 派发上游查询时把 **client tag** 作为 inbound tag 带入（对齐 `nameserver.go:184`）；② nameserver client tag 缺省改用服务级 tag / `xray.system.<uuid>`（对齐 `app/dns/dns.go:143-146`）；③ `is_own_link` 用「本服务 client tag 集合」判定（对齐 `IsOwnLink`）。**注意**：仅 ① 修不生效——Rust client tag 缺省为空串，② 必改 |
| **D2** | DNS 出站（`protocol: "dns"`）**客户端走 TCP**（`dokodemo-door` network=tcp,udp，客户端用 RFC1035 长度前缀帧）且上游被 rewrite 为 UDP（`rewriteNetwork: "udp"`） | 缺陷 | 客户端拿到 A 记录 `12348580000100010000000002653704746573740000010001c00c000100010000012c000401020304`；mock 上游收到 **1** 条查询 | 客户端 **零应答**（8s 超时）；mock 上游收到 **0** 条查询；日志无任何告警 | Go：`proxy/dns/dns.go:163`（`srcNetwork := ob.Target.Network` 决定**客户端侧**帧格式）+ `:203`（`dest.Network` 决定**上游侧**帧格式）——两侧独立；Rust：`crates/xray-core/src/outbound.rs:1697`（`if upstream.is_udp()` **一个分支同时决定客户端侧与上游侧**格式） | 用 TCP 访问 DNS 服务器的客户端（DNS over TCP / 大应答场景）在 Rust 上**全部无应答**，且上游连查询都收不到；Rust 侧无日志 → 现场表现为「DNS 服务无响应」，排查成本高 | 建议（Rust 功能缺失，Go 正常） | 拆成两个判据：客户端侧帧格式按 **入站 link 的网络**（Go `srcNetwork`），上游侧按 **rewrite 后的 dest 网络**（Go `dest.Network`）；Rust 现在把两者绑在一起 |
| **D3** | SOCKS5 UDP ASSOCIATE 帧的目标为**域名型**（ATYP=3，如 `localhost`） | 缺陷 | 正常转发并回包 `b'\x00\x00\x00\x03\tlocalhostm\xb2domain-target'`；目标收到 `domain-target` | **静默丢弃**：目标根本没收到包（echo `seen=[]`），客户端 20s 超时；Rust 无任何日志 | Go：`proxy/socks/server.go:214-221`（`payload.UDP` 目标地址 → dispatcher，`transport/internet/udp` 拨号侧多地址择优）；Rust：`crates/xray-proxy-freedom/src/udp.rs:288-308`（`resolve_udp_domain` 只取 `lookup_host(...).next()` **第一个地址**）+ `crates/xray-proxy-freedom/src/udp.rs:194-222`（`resolve_socket_addr` 同样只取第一个） | 客户端用域名指 UDP 目标时 Rust **静默丢包**：无应答、无日志、无错误码；本机 `localhost` 解析首项是 `::1`（`getaddrinfo` 顺序），Rust 固定打 `::1` → 目标只监听 IPv4 时全部丢失。判别实验：echo 只监听 IPv4 → Go 成功 / Rust 失败；echo 只监听 IPv6 → Go 失败 / Rust 成功（两侧取的是**不同**的解析结果） | 建议（Rust 静默丢包，Go 正常） | Rust 侧按 **可达性择优**取地址（试第一个失败再试下一个），而非只取首个；或在丢帧时补 `warn` 级日志（含域名 + 解析到的地址），避免「静默」 |
| **D4** | DNS 出站规则的 `qType` 写成**数组形态** `{"qType":[16]}` | 配置方言差异（**Rust 更宽松**） | **装配期拒启**：`Failed to start: ... failed to build outbound config with tag dns-out > infra/...: json: cannot unmarshal array into Go value of type uint32`（exit 23） | 正常启动并按规则生效：客户端得到 `rcode=5` 应答 `12348585000100000000000002663704746573740000100001` | Go：`infra/conf/dns_proxy.go:24`（`QType *PortList`，仅接受串/数字）+ `infra/conf/common.go:246-250`（`PortList.UnmarshalJSON`）；Rust：`crates/xray-conf/src/protocols.rs:1284-1290`（`q_type: Option<Value>` 数组/串双接受） | 同一份配置在 Go 上拒启、在 Rust 上运行 → 跨实现复用配置时行为分叉；Rust 侧「能跑」反而掩盖了配置不兼容 | 建议（Rust 更宽松；非 fail-open） | Rust 侧对 Go 不接受的形态发 `warn`（本仓已有 `warn_unknown_dns_outbound_keys` 同款先例）；或直接按 Go `PortList` 收窄形态。另：本轮 D4/D14/D15 因该形态在 Go 侧拒启而作废，已用 Go 兼容的字符串形态重跑（E1/E2 → 两侧**逐字节一致**） |
| **D5** | 把 `"dns"` 当作**入站协议**（`{"protocol":"dns","port":...}`） | 口径差异（Rust 独占） | **装配期拒启**：`Failed to start: ... failed to build inbound conf`（exit 23）——Go 26.10.17 无此入站协议 | 正常启动并监听（`dns inbound listening (UDP+TCP)`）；但本次 A 查询**未获应答**（Rust 独占协议疑似未完成） | Go：`infra/conf/xray.go:28-39`（inbound 协议表无 `dns`）；Rust：`crates/xray-core/src/arm_builders/mod.rs:266`（`("inbound:dns", ...)`）+ `crates/xray-core/src/inbound.rs:5469-5506`（`parse_dns_inbound_config`：`servers` 形态与 Go 不兼容） | Rust 独占协议：配置在 Go 上不可用、在 Rust 上「起得来但没答上」；若用户照抄 Rust 文档示例到 Go 上会直接拒启 | 口径差异（建议 PM 拍板：保留 Rust 独占并文档标注，或删除以免两实现配置面分叉） | 与 PM 确认该协议在 Rust 侧的定位（若为过渡产物，删除；若保留，文档标注 Go 不兼容 + 补 A/AAAA 应答） |
| **D6** | SOCKS5 UDP 收到 `FRAG≠0` 的分片帧 | 观测差异 | 丢弃该帧，并打 Info：`proxy/socks: failed to parse UDP request > proxy/socks: discarding fragmented payload` | 同样丢弃该帧（行为一致），但**无任何日志/计数**（debug 级文本在生产 loglevel 下不可见） | Go：`proxy/socks/server.go:251-256`；Rust：`crates/xray-proxy-socks/src/protocol.rs:320-326`（`decode_udp_packet` 拒分片）+ `crates/xray-proxy-socks/src/udp.rs:226-233`（仅 debug 日志） | 行为无差（两侧都丢），但 Rust 侧排障时看不到「收到分片」的任何痕迹 | 吹毛 | 提为 info/warn 或加计数器（与 Go 的 Info 对齐） |
| **D7** | DNS 上游回 **TC=1（截断）**（mock 上游恒回 TC=1） | 口径差异（Rust 更严格） | EDNS0 重发一次后仍截断 → **按截断应答原样返回空应答**：`12348580000100000000000002746304746573740000010001`（rcode=0, ANCOUNT=0，客户端拿到「有应答但无记录」） | EDNS0 重发一次后仍截断 → **追加 TCP 兜底**（Rust 独有增强）→ 上游无 TCP 监听时整体失败：客户端**零应答**，日志 `ERROR dial failed: freedom dial: ... 127.0.0.1:28060: ... 10061` + `WARN ip query: ... tcp fallback read len: early eof` | Go：`app/dns/nameserver_udp.go:118-137`（只有 EDNS0 重发，**无 TCP 分支**，截断应答直接入 cache）；Rust：`crates/xray-app-dns/src/nameserver/udp.rs:9-18`（有意追加 TCP 兜底）+ `crates/xray-app-dns/src/nameserver/udp.rs:287-303`（`finish_udp_response` → `tcp_fallback_query`） | **上游只监听 UDP 且回截断**时：Go 客户端拿到空应答（NOERROR/0 记录，客户端据此可判定「无记录」），Rust 客户端**一直等到超时**（零应答）→ 表现为「DNS 偶发无响应」。Rust 的 TCP 兜底本身是有意增强（代码注释自述「golang 没有我们可以有」），但兜底失败时未回落 Go 的「返回截断应答」语义 | 口径差异（建议级；Rust 严格方向） | TCP 兜底失败时**回落 Go 语义**（把截断应答按原样返回），而不是整体失败；或给 TCP 兜底设独立短超时 + 失败回落 |

### 已验证**无差异**的关键面（两侧逐字节一致）

- **DNS 应答逐字节一致**（明确回答契约问题）：**是**。在两侧同构、配置形态 Go 兼容的对照组里，
  应答字节**完全相同**：应答头标志位（`0x8580` / `0x8180` / `0x8585` / `0x8583`）、TTL（上游 300s /
  hosts 10s）、Answer RDATA、Question 回显、压缩指针（`c00c`）、rcode 全部一致；
  **上游收到的查询字节也一致**（含 EDNS0 重发包的 ID/OPT 布局）。
  例（A 查询，C2/E4/E8/E10）：
  `12348580000100010000000002633204746573740000010001c00c000100010000012c000401020304`（两侧同）。
  例（hosts 命中，C6）：`...0000010001c00c000100010000000a00040a141e28`（两侧同，TTL=10）。
  例（NXDOMAIN，C9）：`...00000000000002633904746573740000010001`（rcode=3，两侧同）。
  例（CNAME 直通，E9）：`...c00c000500010000012c001305616c696173076578616d706c6503636f6d00`（两侧同）。
  例（TCP 上游 + TCP 客户端，E6/C3/F6）：应答与上游查询字节均两侧同。
  例（TC=1 截断上游，C4）：上游收到 2 条查询（首包无 EDNS + 重发带 OPT），**字节完全相同**；
  差异只在收尾：Go 把截断应答原样作为空应答返回（`rcode=0, ANCOUNT=0`），
  Rust 追加 TCP 兜底（TCP 不通 → 整体失败、无应答）——Rust 侧为**有意增强**（代码注释自述
  「golang 没有我们可以有」），但代价是「上游 UDP-only + 截断」场景 Rust 无应答而 Go 有空应答。
  **注**：D1/D2 两个缺陷使 Rust 在这些拓扑下**根本没有应答**——故「一致」仅在 Rust 能应答的拓扑成立。
- **UDP 面**：socks5 UDP payload 往返、2048 字节大包、零长包（两侧都丢）、3 包连发、
  目标不可达（都不回包、进程都存活）、ctrl 连接关闭后会话收割、dokodemo-door UDP 转发、
  跨侧对打（Rust 客户端↔Go 服务端、Go 客户端↔Rust 服务端）**全部逐字节一致**。
- **DNS 语义面**：hosts 静态映射、`queryStrategy` UseIPv4/UseIPv6（上游 qtype 一致：仅 A / 仅 AAAA）、
  缓存命中（两次查询上游只收 1 条）、`disableCache`（两次查询上游收 2 条）、`serveStale`
  （TTL=1 过期后上游下线，两侧都返回过期应答）、NXDOMAIN rcode=3、规则动作
  drop / return(rCode=5) / hijack / direct、TXT 直通、CNAME 直通 —— **全部一致**。
- **上游查询 wire 级**：UDP 与 TCP 上游下 Rust/Go 发出的查询字节**逐字节相同**（含 ID 生成、
  EDNS0 OPT 布局、TC=1 后的重发包）。

---

## 3 机制定位（定向判别实验）

| 实验 | 目的 | 结果 |
|---|---|---|
| C1/P3（唯一出站=dns） | 判定 D1 是否 ownLink | Go：`from DNS accepted udp:127.0.0.1:28060 [xray.system.a0decea8-... >> dns-out]` → 上游收到 1 条查询 → 客户端拿到 A 记录；Rust：无 `>> dns-out` 记录、上游 0 条查询、连续 4s 超时 → ownLink 未命中 → 回环再 Hijack |
| H1/H2（echo 只监听 IPv4 / 只监听 IPv6） | 判定 D3 是否「只取首个解析地址」 | Go：IPv4-only 成功、IPv6-only 失败（Go 选 IPv4）；Rust：IPv4-only 失败、IPv6-only 成功（Rust 选 `getaddrinfo` 首项 `::1`）。**两侧取的是不同地址**——D3 成立 |
| W1-W5（隔离式：每形态全新实例） | 排除 D3 的「前包污染」解释 | W1(IP)=两侧成功、W3(domain=IP字面量)=两侧成功、W2(domain=localhost)=仅 Go 成功、W4(IP→domain)=Rust 第二包丢、W5(IP→IP)=两侧成功 → D3 与目标地址族相关，与顺序无关 |
| E6 vs E7（TCP 客户端，TCP 上游 vs UDP 上游） | 判定 D2 是否帧分支判据 | E6（TCP/TCP）两侧**一致成功**；E7（TCP/UDP）Go 成功、Rust 零应答 → D2 成立（判据必须是客户端侧网络，不是上游网络） |
| E1-E10（Go 兼容 `qType` 串形态） | 复核 D4 作废的 D4/D14/D15 | 全部**两侧逐字节一致** → 规则语义无差异，差异只在方言（D4） |
| F7（`qType` 数组形态） | 确认 D4 | Go 拒启（exit 23，明确报 `cannot unmarshal array into Go value of type uint32`）、Rust 生效 → D4 成立 |
| C4/D13（上游恒回 TC=1） | 确认 D7 | 两侧**上游查询字节完全相同**（首包无 OPT + 重发带 OPT，2 条）；收尾不同：Go 按截断应答原样返回空应答，Rust 追加 TCP 兜底 → 上游无 TCP 监听时零应答 → D7 成立 |

---

## 4 复现方式

```bash
cd reports/audit-2026-10-31-perf-mem-wiring/round4/scripts

python f1_udp.py            # UDP 面同侧对照 8 例 → tmp/udp_results.json
python f3_udp_cross.py      # 跨侧 socks UDP 对打 4 例 → tmp/udp_cross_results.json
python f5_xudp.py           # XUDP(VMess UDP) 跨侧 5 例 → tmp/xudp_results.json
python f2_dns.py            # DNS 装配/语义对照 16 例 → tmp/dns_results.json
python f2b_dns_control.py   # DNS 对照组 13 例 → tmp/dns_control_results.json
python f2c_dns_rules.py     # DNS 规则面（Go 兼容形态）10 例 → tmp/dns_rules_results.json
python f4_dns_framing.py    # DNS 帧/特性面 8 例 → tmp/dns_framing_results.json

python probe_ownlink.py     # ★ D1 判别（drop/return 规则 × ownLink）
python probe_dns_logs.py    # ★ D1/D2 日志取证（qType 形态 + TCP 客户端 + ownLink）
python probe_socks_domain6.py   # ★ D3 隔离复现（W1-W5）
python probe_resolve_first_addr.py  # ★ D3 判别（IPv4-only / IPv6-only echo）
python probe_socks_domain3.py      # D3 全量日志
```

---

## 5 未覆盖范围（如实声明）

1. **VMess/XUDP 跨侧 UDP 转发**：G1-G3 中两侧**都失败**（Go 侧报 `vmess decode header: io error: early eof`，
   Rust 侧无应答）——行为一致故**未构成差异**，但「VMess over XUDP 的 UDP 转发在两侧都不通」这一共同事实
   未深究（可能与本轮客户端配置写法有关），留作下一轮。
2. **TUIC / Hysteria2 / WireGuard 的 UDP 面**：本轮未跑（需证书/内核态环境；wireguard 属 Linux-only，
   见 LinuxE2E 代理）。因此「Rust UDP 面一致性」结论目前只覆盖 socks5 / dokodemo / VMess 三族。
3. **DoH / DoT 上游**：未做（需自签 TLS 上游）。本轮 DNS 上游只覆盖 UDP 与 TCP 两种。
4. **DNS 大应答 / EDNS 协商 / 分片**：只覆盖了「上游回 TC=1」这一种截断形态；未构造 >512B 正常应答、
   未构造 EDNS 协商失败路径。
5. **DNS 缓存 TTL 衰减到秒级的精确边界**：只验证了 TTL=1 + serveStale 的定性行为，未逐秒比对 TTL 递减。
6. **抓包（scapy / pcap）**：本轮**未做**。原因：两侧差异均可在「mock 上游收到的原始查询字节」与
   「客户端收到的原始应答字节」两个层面取证（等效 wire 级证据，且比 pcap 更精确——直接拿到
   应用层字节而非链路层）；D3/D2 的根因也已由定向判别实验定位。**未做**的是链路层视角
   （如 IP 分片、UDP 校验和、TTL 跳变）。
7. **Windows 特有的 ICMP/端口不可达语义**：U7（目标不可达）两侧都是「不回包」，未区分
   「超时」与「ICMP 触发的 socket reset」的时序细节。
8. **并发/多客户端 UDP 会话**：只测了单客户端；未做同端口多源并发（round2 已有 socks UDP 会话容量票 `tini5`，
   不重复）。
9. **Go 侧 `dns` 出站 `rules` 数组形态的其它写法**（如 `qType: "16,28"` 区间）：只测了单值串与数组。

---

## 6 给 PM 的三个决策点

1. **D1（ownLink）是否立即开票**：Rust 上「本地 DNS 服务器」这一 Xray 经典形态**完全无应答**且无
   错误提示给用户（只有 debug/warn 日志），影响面是「DNS 解析整体失效」——建议 P1。修法需要同时动
   `xray-app-dns`（client tag 缺省值 + 上游查询的 inbound tag 传递）与 `xray-core`（`DispatcherDnsDialer`），
   两处缺一不可。**建议**：因涉及 DNS 核心路径，修完须以「本地 DNS 服务器形态双跑 + 32/32 + interop 12/12」验收。
2. **D2（帧分支判据）**：改动面小（`outbound.rs` 一处判据拆分），但要确认「客户端侧网络」在 Rust 的
   link 契约里如何取（当前 `dispatch_dns_link` 只拿到 `upstream`，拿不到入站 link 网络 → 需要把
   src network 一起传进来）。建议与 D1 同批处理（都在 DNS 出站路径）。
3. **D5（Rust 独占 `dns` 入站协议）**：保留并文档标注 Go 不兼容，还是删除以免两实现配置面分叉？
   本轮实测该协议在 Rust 侧「能启动但不答 A 查询」，建议先查清是否半成品再定去留。
