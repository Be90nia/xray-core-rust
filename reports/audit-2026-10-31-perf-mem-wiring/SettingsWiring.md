# SettingsWiring —— 协议/传输 settings 键「解析点 → 运行期消费点」全量台账

> 审计轮：2026-10-31 perf/mem/wiring（R3 路）
> 仓库：`D:/Project/Xray-core-rust`（分支 `feature/fix-inbound-parity`，HEAD `5fe98b90`）
> Go 基准：`D:/Project/Xray-core` @ `92ccc939`（v26.10.17）
> 只读审计，**未改任何代码**。

## 0. 结论摘要

| 项 | 数 |
|---|---|
| 覆盖 crate | 16 个 `xray-proxy-*` + 9 个 `xray-transport-*`（含 `xray-transport` 共享解析面） |
| 分母：(crate, settings 键) 去重对 | **329** |
| 原始取键站点（`.get("k")` + helper 闭包传键） | 442 |
| OK（有运行期消费点） | 310 |
| **A 类：解析后零消费** | **8** |
| **B 类：读了但无效果** | **3** |
| **C 类：解析失败/类型不符静默默认** | **8** |
| 其中**生产主路**可达（`xray.exe run -c` → `Config::build` → `start_full`） | 11 条：F01/F02/F03/F04/F05/F06/F09/F10/F11/F12/F13 |
| 仅**目标主路**（框架装配 `framework-assembly`，未进默认构建） | 3 条：F07/F08/F14 |
| 安全相关 | 5 条（F11、F12 为 P1） |

**最重要的两条**：ss 入站 `users[].password` 与 trojan 入站 `clients[].password` 缺省时静默取 `""`，凭据因此变成**公开可计算的常量**（`KDF("")` / `hex(sha224(""))`），而 Go 在配置层直接拒启（`infra/conf/shadowsocks.go:71-73`、`:96`、`infra/conf/trojan.go:70-71`）。这两条在默认生产主路可达。

## 1. 方法与复算

### 1.1 三步法（先台账后定性）

1. **分母**（可复算）：`scripts/settings_ledger.py`
   - 扫描 16 `/xray-proxy-*/src` + 10 `/xray-transport-*/src` 全部 `.rs`
   - 抓两类取键形态：`.get("k")` 与 `get_str/get_str2/get_bool/get_i32/get_i64/get_u64/str_field/alpn_field(..."k"...)`（helper 闭包传键，此前纯 `.get` 正则会漏）
   - 剔测试模块（只切文件**末尾**的 `#[cfg(test)] mod <name>`，保留文件中段 `#[cfg(test)]` 辅助函数——否则 vless `server.rs` 等文件中段的 `#[cfg(test)] fn handshake_timeout` 会把后半文件整段吞掉，产生假阴性）
   - 剔 HTTP 头 / wire 字段白名单（`host`/`content-type`/`grpc-status`/`sec-websocket-*` 等 30 项）
   - 输出 `scripts/settings-keys.raw.tsv`
2. **字段读写计数**：`scripts/field_usage.py`
   - 扫每个 crate 所有 `pub struct` 字段，统计 `.field` 的**读**（非 `=`）与**写**（`.field = ` + 结构体字面量 `field:`）
   - 输出 `scripts/field_usage.tsv`（1402 行）→ 直接挑出 `written_never_read` 52 条候选
3. **逐条定位消费点**：`scripts/field_reads.py` / `scripts/field_matrix.py`
   - 按「字段 → 全仓 `.field` 读点」列出非测试站点，区分 crate 内 / 跨 crate（关键：tuic `udp_relay_mode` 在 `xray-proxy-tuic` 内 0 读但在 `xray-core/src/outbound.rs:2692` 有读 → 不算 A 类）
4. **定性合成**：`scripts/build_ledger.py`（人工核对结论 → status/finding/evidence）
   - 产物 `scripts/settings-ledger.tsv`：`crate / key / sites / status / finding / evidence`

复算：

```bash
python reports/audit-2026-10-31-perf-mem-wiring/scripts/settings_ledger.py   # 分母
python reports/audit-2026-10-31-perf-mem-wiring/scripts/field_usage.py       # 字段读写计数
python reports/audit-2026-10-31-perf-mem-wiring/scripts/build_ledger.py      # 三态分布
```

### 1.2 三态判据（本报告口径）

- **OK**：写入结构体后，存在**非测试**的运行期读点，且该读点位于行为路径（建连/握手/编解码/调度/内存分配/策略查询）上。
- **A（解析后零消费）**：键被读、值被存，但全仓无非测试读点（或读点只在 `to_proto/from_proto` 互转、日志、测试）。
- **B（读了但无效果）**：有非测试读点，但读到的值在到达行为前被丢弃（`..` 丢弃字段、仅做空值校验、只参与 `Debug`）。
- **C（解析失败静默默认）**：键缺失/类型不符/解空时用 `unwrap_or(...)`/`unwrap_or_default()`/静默跳过，而 Go 同处**硬错**或语义明显不同 → 配置漂移无告警。

### 1.3 「生产主路」口径

按 CLAUDE.md §3.5.4 双主路：默认可执行文件 = `xray_conf::Config::build()` → `xray_core::start_full`（`arm_builders` 构造表）；协议 settings 是 `Option<Value>` 原样透传到 `arm_builders`，**由 `xray-core` 的 `parse_*_config` / `build_*_users` 解析**。各 `xray-proxy-*/src/plugin.rs` 的 `parse_section` 属**目标主路**（框架装配 `framework-assembly`，尚未进默认构建）。本报告每条 finding 标注在哪条路上可达。

## 2. 全量键台账（按 crate × 三态）

| crate | 键数 | OK | A | B | C |
|---|---|---|---|---|---|
| xray-proxy-anytls | 2 | 2 | 0 | 0 | 0 |
| xray-proxy-blackhole | 4 | 4 | 0 | 0 | 0 |
| xray-proxy-dns | 13 | 13 | 0 | 0 | 0 |
| xray-proxy-dokodemo | 10 | 10 | 0 | 0 | 0 |
| xray-proxy-freedom | 26 | 26 | 0 | 0 | 0 |
| xray-proxy-http | 12 | 12 | 0 | 0 | 0 |
| xray-proxy-hysteria | 17 | 14 | 0 | 2 | 1 |
| xray-proxy-loopback | 2 | 2 | 0 | 0 | 0 |
| xray-proxy-socks | 9 | 9 | 0 | 0 | 0 |
| xray-proxy-ss | 15 | 11 | 2 | 0 | 2 |
| xray-proxy-trojan | 14 | 13 | 0 | 0 | 1 |
| xray-proxy-tuic | 11 | 11 | 0 | 0 | 0 |
| xray-proxy-tun | 12 | 12 | 0 | 0 | 0 |
| xray-proxy-vless | 23 | 22 | 1 | 0 | 0 |
| xray-proxy-vmess | 13 | 12 | 1 | 0 | 0 |
| xray-proxy-wireguard | 7 | 7 | 0 | 0 | 0 |
| xray-transport-grpc | 11 | 10 | 1 | 0 | 0 |
| xray-transport-httpupgrade | 7 | 5 | 0 | 0 | 2 |
| xray-transport-hysteria | 34 | 32 | 1 | 1 | 0 |
| xray-transport-kcp | 4 | 4 | 0 | 0 | 0 |
| xray-transport-naive | 10 | 10 | 0 | 0 | 0 |
| xray-transport-quic | 13 | 12 | 1 | 0 | 0 |
| xray-transport-splithttp | 47 | 46 | 1 | 0 | 0 |
| xray-transport-tcp | 2 | 2 | 0 | 0 | 0 |
| xray-transport-websocket | 11 | 9 | 0 | 0 | 2 |
| **合计** | **329** | **310** | **8** | **3** | **8** |

逐键三态与证据：`scripts/settings-ledger.tsv`（329 行，含 `evidence` 列 file:line）。

**分母口径说明**：

- 该表统计的是「各 crate **自己**解析 settings 的位置」。部分传输键的真实解析在共享层：`xray-transport/src/dialer.rs`（`socket_options()` 全部 `sockopt.*`）、`xray-transport/src/tcp/hub.rs`（`tcpSettings.acceptProxyProtocol`）、`xray-transport/src/memory_settings.rs`（`finalmask.quicParams.*`）、`xray-transport/src/headers/conn.rs`（`tcpSettings.header.*`）。这些已在正文按面核对（见 §3.6/§4），但不计入上表的 crate 键数，避免与 crate 内 `transport_json` 解析重复计数。
- `xray-conf/src/protocols.rs` 的 45 个协议结构体**不在生产路径**（R1 已证），故不进分母。

## 3. NOT-WIRED 详情（8 列）

> 列：crate | 配置键(JSON path) | 严重度 | 解析点 | 期望消费点(Go) | 实际消费点 | 生产后果 | 验证方式
> 严重度：blocker(P0)/P1/P2/建议(P3)/吹毛。本表无 P0。

### 3.1 A 类：解析后零消费

| crate | 键 | 严重度 | 解析点 | 期望消费点(Go) | 实际消费点 | 生产后果 | 验证方式 |
|---|---|---|---|---|---|---|---|
| `xray-transport-quic` | `quicSettings.keepAlive` (bool) | 建议 | `crates/xray-transport-quic/src/config.rs:86` → `QuicConfig.keep_alive` | Go v26.10.17 **已无 quic transport**（`D:/Project/Xray-core/transport/internet/` 无 `quic/`，无 `quicSettings` 注册） | **无**（`config.rs:143-246 build_transport_config` 只消费 `keep_alive_period_ms`；`keep_alive` 全仓 0 读） | 该键属 Rust-only 遗留面：`network:"quic"` 在 Rust 能起、在 Go 报未知传输；`keepAlive:true` 无任何效果，只有 `keepAlivePeriod` 生效 | `python scripts/field_matrix.py` 输入 `ALL keep_alive` → 命中仅 wireguard/hysteria 同名字段，quic crate 0 读 |
| `xray-transport-hysteria` | `streamSettings.finalmask.quicParams.udpHop` | 建议（**方言键**） | `crates/xray-transport-hysteria/src/quic_params.rs:88-105`（含 `interval>=5`、端口 1..65535 校验）→ `QuicParams.udp_hop`（Rust 私扩展 `protos/transport/internet/config.proto:94` tag 100，注释自述「Go 无此字段」） | Go 的 hop 实现在 **finalmask**：`transport/internet/finalmask/udphop/conn.go:78`（`NewUDPHopConn`）；Go `QuicParams` proto 无 `udp_hop` | **无运行期读**（写入点 `quic_params.rs:20/144`、`dialer.rs:119`；`xray-transport/src/memory_settings.rs:212` 另有一份解析同样只存） | 用户按 Rust 方言写 `quicParams.udpHop` → 校验通过、**端口跳动不发生**；正确开关是 `finalmask.udp[{type:"udphop"}]`（已实现在 `crates/xray-transport/src/finalmask/mod.rs:866`）。反方向风险：Go 会**忽略**该未知键，Rust 会因 `interval<5` **拒启** → 同一份 config 在两端口径相反 | `python scripts/xsearch.py udp_hop udpHop` → 13 处，除写入与测试外无消费；`field_matrix` `xray-transport-hysteria udp_hop` → reads=0 |
| `xray-transport-splithttp` | `splithttpSettings.downloadSettings.*`（嵌套 host/path/mode/headers/tls 全套） | P2 | `crates/xray-transport-splithttp/src/register.rs:405-411`（只取里层 `splithttpSettings` 递归解析成 `Box<Config>` 存入 `Config.download_settings`） | `D:/Project/Xray-core/transport/internet/splithttp/dialer.go:355-362`（`ToMemoryStreamConfig(DownloadSettings)` → 下行用**独立** transport 配置，含独立 host/path/mode/headers） | **仅存在性**：`crates/xray-transport-splithttp/src/dialer.rs:386-387` 用 `is_some()` 做 mode 推断；子配置字段 0 读 | 下行请求仍走上行同一套 host/path/mode/header。用户按 Go 文档拆「上行伪装 A、下行伪装 B」时，**下行配置静默失效**（CDN 路径分流/落地机分离不成立） | `python scripts/field_reads.py xray-transport-splithttp download_settings` → 仅 `dialer.rs:386`；`xsearch downloadSettings` 全仓 → 仅 register.rs 解析点 |
| `xray-transport-grpc` | `grpcSettings.permitWithoutStream` / `permit_without_stream` | 建议 | `crates/xray-transport-grpc/src/config.rs:118` → `Config.permit_without_stream` | `D:/Project/Xray-core/transport/internet/grpc/dial.go:161-165`（并入 keepalive `Params.PermitWithoutStream`） | **无**（仅 `config.rs:197/212` 的 `to/from_proto` 互转读；h2 keepalive 装配 `transport.rs:315-330` 不看它） | h2 空闲无活动流时 keepalive ping 不发出 → 中间盒/负载均衡按空闲断链，长连接会话被早掐；`IdleTimeout`/`HealthCheckTimeout` 生效会掩盖该缺失 | `python scripts/field_matrix.py` → `permit_without_stream reads=2 writes=0`，两处均 config.rs 互转 |
| `xray-proxy-ss` | `uot` / `uotVersion` | 建议（**方言键**） | `crates/xray-proxy-ss/src/dispatcher.rs:396-399` → `UdpOverTcpConfig{enabled, version}`（`ss2022/outbound.rs:75-80`）；生产出站经 `xray_proxy_ss::parse_ss_config`（`crates/xray-core/src/arm_builders/outbound.rs:308`）走同一解析 → **生产主路可达** | Go **无该键**：`proxy/shadowsocks_2022/config.proto` 的 `ClientConfig` 只有 `address/port/method/key`；`infra/conf/shadowsocks.go` 无 `uot` | **无**（`dispatcher.rs:717+ pump_ss2022_udp` 恒走裸 UDP 数据报；`.enabled/.version` 只在 `tests/ss2022_uot_multi_e2e.rs:100-101` 被断言「已解析」） | 用户写 `uot:true` 期望把 UDP 塞进 TCP 穿透 UDP 封锁 → 实际仍发裸 UDP；失败时只是「连不上」，无任何提示。默认 `xray.exe` 同样如此 | `python scripts/field_reads.py xray-proxy-ss enabled udp_over_tcp` → 非测试读 0（`dispatcher.rs:352` 是写） |
| `xray-proxy-vless` | 出站 `vnext[0].users[0].level`（扁平形态 `level`） | 建议 | `crates/xray-proxy-vless/src/plugin.rs:328`（框架路）与 `crates/xray-core/src/outbound.rs:975`（生产路 `parse_vless_config`）→ `VlessOutboundConfig.level`（def `dispatcher.rs:73`，setter `:173-174`） | Go：出站 user `Level` 进 `protocol.User.Level`，被 stats/策略按级计数（`infra/conf/vless.go` flat 分支搬 `level`） | **无**（全仓非测试 0 读；inbound 侧 `MemoryUser.level` 是另一条已接线路） | 出站用户的 level 丢弃（**生产主路同样丢弃**：`outbound.rs` 解析后 `.with_level(level)` 写入即止）→ 按 level 的统计/策略分档对出站不生效 | `python scripts/field_matrix.py` → `xray-proxy-vless level` 仅命中 inbound `u.level` 与测试 |
| `xray-proxy-vmess` | 出站 `vnext[0].users[0].level` / 扁平 `level` | 建议 | `crates/xray-proxy-vmess/src/dispatcher.rs:210` → `VmessOutboundConfig.level`（def `:66`，setter `:111-112`，解析侧 `.with_level` 在 `:237`） | 同 F06（Go `infra/conf/vmess.go:112-134` flat 分支搬 `level`） | **无**（非测试 0 读） | 同 F06 | 同 F06（`xray-proxy-vmess level`） |

### 3.2 B 类：读了但无效果

| crate | 键 | 严重度 | 解析点 | 期望消费点(Go) | 实际消费点 | 生产后果 | 验证方式 |
|---|---|---|---|---|---|---|---|
| `xray-transport-hysteria` | `streamSettings.hysteriaSettings.masquerade`（`type:"proxy"` + `url` + `rewriteHost` + `insecure`） | P2（隐蔽性） | `crates/xray-transport-hysteria/src/proto_config.rs:26-70` → `MasqType::Proxy{url, rewrite_host, insecure}` | `D:/Project/Xray-core/transport/internet/hysteria/hub.go` 的 masq switch：`proxy` 走 `httputil.ReverseProxy`（真反代，含 `RewriteHost`/`InsecureSkipVerify`） | **读到即丢**：`crates/xray-transport-hysteria/src/hub.rs:104` `Self::Proxy { .. } => Arc::new(ProxyMasqHandler)`，三个字段进不了 handler → 恒 503 类兜底 | 主动探测/浏览器误访命中 hysteria 端口时看到的是固定 503，而非配置的上游页面；「伪装成真站点」反被静态差异暴露。已有 ponytail 注释承认是 shortcut | 读 `hub.rs:104`（`{ .. }` 丢弃）+ `hub.rs:41-62 from_config`（字段确实被填入）；`field_reads masq_url_rewrite_host` → 唯一读点是 `hub.rs:46`（from_config 内部） |
| `xray-proxy-hysteria` | 出站/入站 `alpn`（`settings.alpn` / 框架段） | 建议 | `crates/xray-proxy-hysteria/src/plugin.rs:245/280` → `HysteriaConfig.alpn`（`config.rs:96/376`） | Go hysteria 的 ALPN 只来自 `tlsSettings.alpn`（`transport/internet/hysteria` 无 alpn 字段）；Rust 等价面=`xray_transport_hysteria` 的 TLS 配置 | **只做空值校验**：非测试读仅 `config.rs:156/409`（`if self.alpn.is_empty()`）；`dispatcher.rs:426-430` 组 `ProtoConfig{auth, udp_idle_timeout, ..Default}`，`ProtoConfig` 无 alpn 字段（`proto_config.rs:6-15`） | 用户在 hysteria settings 写 `alpn:["h2"]` 期望改变握手 ALPN → 无效果（真正生效的是 `tlsSettings.alpn`）。属「多一个会骗人的旋钮」 | `python scripts/field_reads.py xray-proxy-hysteria alpn` → 4 读全在 config.rs 校验 + 测试；`xsearch ProtoConfig` 确认无 alpn 字段 |
| `xray-proxy-hysteria` | `settings.masquerade`（**字符串**形态，框架装配路） | 建议 | `crates/xray-proxy-hysteria/src/plugin.rs:259-261`（`str_field(settings,"masquerade")`）→ `HysteriaInboundConfig.masq_type`（`config.rs:272`，setter `:397`） | Go 形态是**对象** `Masquerade{type,dir,url,rewriteHost,insecure,content,headers,statusCode}`（`infra/conf/transport_internet.go:498-510` → `:542-549` 展平），且写在 `streamSettings.hysteriaSettings.masquerade` | **零运行期读**（`.masq_type` 仅测试断言）；`crates/xray-proxy-hysteria/src/inbound.rs:200-206` 把 `HysteriaInboundConfig` 转内部 `HysteriaConfig` 时**只带 server_name/alpn/udpIdleTimeout**，不带 masq；`start()`（`inbound.rs:270-278`）只读 `self.config.masq`（框架路恒 `None`）→ 落 `MasqType::NotFound` | 框架装配路写 `settings.masquerade:"file"` 被解析、校验、然后丢弃（伪装回落 404）。写 Go 式**对象**则被 `str_field`（只认 string）直接判 None → **静默更彻底**。生产主路（`xray-core/inbound.rs:5255+`）读 `hysteriaSettings.masquerade` 对象，不受此影响 | 读 `plugin.rs:259-261` + `inbound.rs:200-206` + `field_reads masq_type`（0 非测试读） |

### 3.3 C 类：解析失败 / 类型不符静默默认

| crate | 键 | 严重度 | 解析点 | 期望消费点(Go) | 实际消费点 | 生产后果 | 验证方式 |
|---|---|---|---|---|---|---|---|
| `xray-proxy-ss` | 入站 `users[] / clients[].password`（缺 / 空串） | **P1（安全）** | `crates/xray-core/src/inbound.rs:5085` `c.get("password")…unwrap_or("")`（生产主路）；`crates/xray-proxy-ss/src/plugin.rs:232`（框架路） | Go 硬错：`D:/Project/Xray-core/infra/conf/shadowsocks.go:71-73`（users 分支）「Shadowsocks password is not specified.」 | 值直接进 `MemoryAccount::from_proto`（`crates/xray-proxy-ss/src/config.rs:341-356`）**不校验空串** → `key = password_to_cipher_key(b"", key_size)` | 该用户凭据变成**公开可计算的常量**（空口令 KDF）。任何知道 method 的人都能算 key 并认证成功，绕过运营者本意的密码。配置少写一个 `password` 即 fail-open，且启动无任何告警 | 读 `inbound.rs:5085`、`plugin.rs:232`、`config.rs:341-356`；`python scripts/xsearch.py "password.is_empty"`（ss crate 无命中） |
| `xray-proxy-trojan` | 入站 `clients[] / users[].password`（缺 / 空串） | **P1（安全）** | `crates/xray-core/src/inbound.rs:4733` `c.get("password")…unwrap_or("")`（生产主路）；`crates/xray-proxy-trojan/src/plugin.rs:195`（框架路） | Go 硬错：`D:/Project/Xray-core/infra/conf/trojan.go:70-71`「Trojan password is not specified.」 | `TrojanMemoryAccount::new("")`（`config.rs`）→ 校验键 = `hex(sha224(""))`，**公开常量**（`hex_sha224` 在 `config.rs`，无空值校验） | 同 F11：漏写 password 即得到一个「谁都能算出来」的 trojan 用户，且 `validator.add` 不校验空口令。凭据面失守而非拒绝服务 | 读 `inbound.rs:4733`、`plugin.rs:195`、`crates/xray-proxy-trojan/src/config.rs` 的 `MemoryAccount::new/hex_sha224`（无空值分支） |
| `xray-proxy-ss` | `settings.method`（缺省，入站） | P2 | `crates/xray-core/src/inbound.rs:5074`、`crates/xray-proxy-ss/src/plugin.rs:204`：`unwrap_or("aes-128-gcm")` | Go：缺省 `cipherFromString("")` → `CipherType_UNKNOWN` → 硬错 `infra/conf/shadowsocks.go:99`「unknown cipher method」 | 静默用 `aes-128-gcm` 建账户 | 同一份缺 `method` 的配置：Rust 起得来、Go 起不来 → 两端行为分叉；运营者以为设了 2022 加密实际是 legacy AEAD。也掩盖「method 拼错成不是 2022- 前缀」的笔误（只有拼错且非 2022 前缀时才硬错） | 读两处 `unwrap_or`；对比 Go `shadowsocks.go:99` |
| `xray-transport-websocket` | `wsSettings.header` / `headers`（值非字符串） | 建议 | `crates/xray-transport-websocket/src/register.rs:675-682`（注释「非 string 值跳过」） | Go `WebSocketConfig.Headers` 是 `map[string]string`，JSON 类型不符即反序列化**报错** | 该 header **整条静默丢弃**，其余 header 照用 | 伪装头少一项（例如 `{"X-Foo": 1}` 想写数字）→ 出站请求头与预期不一致，指纹/伪装形态漂移，无告警 | 读 `register.rs:675-682`；`field_matrix`/grep 该注释 |
| `xray-transport-httpupgrade` | `httpupgradeSettings.header` / `headers`（值非字符串） | 建议 | `crates/xray-transport-httpupgrade/src/register.rs:611-618`（同款「非 string 值跳过」） | 同上（Go `HttpUpgradeConfig.Headers map[string]string`） | 同 F13 | 同 F13 | 读 `register.rs:611-618` |
| `xray-proxy-hysteria` | `settings.udpIdleTimeout`（**生产主路**忽略） | 建议 | 框架路消费：`crates/xray-proxy-hysteria/src/plugin.rs:256/283` → `udp_idle_timeout_secs`（`dispatcher.rs:428` 消费）；生产路：`crates/xray-core/src/outbound.rs:2606-2615` 的 `parse_hysteria_config` **只取** `server_addr/auth/server_name` | Go：`udpIdleTimeout` 属 `streamSettings.hysteriaSettings`（`infra/conf/transport_internet.go` HysteriaConfig），不在 outbound settings | 生产主路对该键**完全无解析点**（连"解析后丢弃"都没有）→ 静默默认 60s | 生产部署写 `settings.udpIdleTimeout: 5` 期望快速回收 UDP 关联 → 恒 60s（`proto_config.rs:13-15` 默认）；同 `settings.alpn`/`settings.masquerade` 一并被忽略（同根因，见 F07/F08） | 读 `xray-core/src/outbound.rs:2606-2615`（返回值仅三元组）+ `plugin.rs:283` 对照 |

### 3.4 补充观察（非 settings 键，但同属「读了不影响行为」，供交叉引用）

| 位置 | 事实 | 影响 |
|---|---|---|
| `crates/xray-proxy-hysteria/src/config.rs:78-126` | `with_obfs` / `with_brutal_up` / `with_brutal_down` / `with_alpn` 四个 builder + `obfs`/`brutal_up_bps`/`brutal_down_bps` 三字段**全仓 0 读**（写点只有 def/`new()`/setter） | 死 API：真实生效面是 `transport.with_obfs(...)`（`arm_builders/outbound.rs:384`）与 `finalmask.quicParams`。留着会诱导后续有人「用 HysteriaConfig.obfs 打开混淆」而实际无效 |
| `crates/xray-transport-quic/*` | Go v26.10.17 已移除 quic transport；Rust 仍注册 `"quic"`/`quicSettings`（`register.rs:22-40`、`dialer.rs:552 protocol_settings_key`） | parity 观察：同一 config 在 Rust 可用、在 Go 报未知传输；本 crate 13 个键里 `keepAlive` 无效（F01），其余窗口/MTU/CC 键均真实生效 |
| `crates/xray-transport/src/finalmask/*` | `udphop` 已实现并接到 `finalmask.udp[{type:"udphop"}]`（`mod.rs:866`，票 4kq9） | 说明 F02 是「同一能力两条配置面，一条死」——修法应是删死面或把它转译成 finalmask，而非再实现一遍 |

## 4. 性能/功能开关「配置了但不生效」小节（供 R2 交叉引用）

按「用户会当性能/功能旋钮」排序，全部来自上文 NOT-WIRED：

| 旋钮 | 位置 | 用户预期 | 实际 |
|---|---|---|---|
| `quicParams.udpHop` | F02 | 源端口/目的端口周期性跳动（抗封锁、抗 QoS 打点） | 端口固定；真开关是 `finalmask.udp[udphop]` |
| `splithttpSettings.downloadSettings.*` | F03 | 下行独立 host/path/mode（CDN 分流、下行单独加速） | 下行复用上行配置 |
| `grpcSettings.permitWithoutStream` | F04 | 无活动流时仍发 keepalive | 不发 → 空闲长连接被中间盒掐 |
| `quicSettings.keepAlive` | F01 | 开启 QUIC keepalive | 无效（只 `keepAlivePeriod` 生效） |
| `hysteriaSettings.masquerade.type=proxy` | F09 | 反代到真实站点（隐蔽性） | 恒 503 |
| 出站 `level`（vless/vmess） | F06 | 按 level 分档统计/策略 | 丢弃 |
| `uot` | F05 | UDP over TCP 穿透 UDP 封锁 | 裸 UDP |

**已核实生效的性能旋钮（对照用，避免 R2 误判）**：`sockopt.{mark,tcpFastOpen,tcpKeepAliveIdle/Interval,tcpMptcp,tcpCongestion,tcpWindowClamp,tcpMaxSeg,tcpUserTimeout,penetrate(例外见下),receiveBufferSize,sendBufferSize,tproxy,reusePort,v6only,dialerProxy,happyEyeballs,domainStrategy,addressPortStrategy,customSockopt,interface,acceptProxyProtocol}` 全部有非测试消费点（`crates/xray-transport/src/sockopt/{linux,freebsd,darwin,windows,mod}.rs`、`system_dialer.rs`、`system_listener.rs`）；`kcpSettings.{mtu,tti,cwndMultiplier,maxSendingWindow}` 生效（`connection.rs:164`、`sending.rs:317`、`config.rs:51`）；`splithttp.*` 的 20 个 xPadding/session/seq/uplink 键全部有消费点；`hysteria quicParams.{brutalUp,brutalDown,congestion,bbrProfile,disablePathMTUDiscovery,maxIncomingStreams,窗口/超时}` 生效（`quinn_adapter.rs:303-330,627-631`、`dialer.rs:57-119`）；`wsSettings.{ed,heartbeatPeriod,poolSize,acceptProxyProtocol,header,path,host}` 生效。

唯一「同名易混」提醒：`sockopt.penetrate` 解析后**全仓 0 读**——Go 侧也只用于 splithttp 把 socket 设置复制给 downloadSettings（`transport/internet/splithttp/dialer.go:357`），属 Go 同形的弱语义；因 F03 未实现 downloadSettings 的独立 socket 面，Rust 该字段彻底无用（建议随 F03 一并处理，不单独计 finding）。

## 5. 安全相关（按优先级）

| # | 面 | 事实 | 生产主路可达 | 修法方向 |
|---|---|---|---|---|
| F11 | ss 入站用户口令 | `users[]/clients[]` 缺 `password` → `""` → `KDF("")` **公开常量**；Go 拒启 | ✅（`inbound.rs:5085`） | 在 `parse_ss_inbound_config` / `parse_legacy_user` 加空口令硬错（对齐 Go 文案），并给 `MemoryAccount::from_proto` 加空串断言 |
| F12 | trojan 入站用户口令 | `clients[]/users[]` 缺 `password` → `hex(sha224(""))` **公开常量**；Go 拒启 | ✅（`inbound.rs:4733`） | 同 F11：`build_trojan_users` / `parse_users` 空口令硬错 |
| F10 | ss method 缺省 | 静默 `aes-128-gcm`，Go 硬错 | ✅（`inbound.rs:5074`） | 缺省按 Go 走 UNKNOWN 硬错；只有显式 `2022-` 前缀才进 2022 面 |
| F09 | hysteria masquerade=proxy | 探测者恒见 503 而非上游页面（伪装面静态差异） | ✅（`hub.rs:104`） | 接 hyper 反代（`url`/`rewriteHost`/`insecure` 已解析在手） |
| F13 | ws/httpupgrade header 类型 | 非字符串值整条静默丢 → 伪装头缺项 | ✅（两侧 transport） | 非字符串值改硬错（对齐 Go `map[string]string` 反序列化失败） |

> 已排除（不报）：`xray-crypto/auth_reader` 的 `transfer_type` 只存不读（Go 同形）；`xray-transport-splithttp` 的 `xmux` 全量解析零消费（R1 已报）；`xray-tls` `echForceQuery` 零调用（R1 已报）；ss2022 容差硬编码 30（已报）；freedom `finalRules` 丢项（已报）。

## 6. 覆盖范围声明

**查了**：

- 16 个 `xray-proxy-*` 全部 `src/**/*.rs` 的取键站点（442 处 → 329 去重对），逐 key 核对「字段写入 → 非测试读点 → 是否落在行为路径」。
- 10 个 `xray-transport-*` 同名面 + 共享解析层 `xray-transport/src/{dialer.rs(全部 sockopt 键), system_dialer.rs, system_listener.rs, tcp/hub.rs, memory_settings.rs, headers/conn.rs, finalmask/mod.rs 注册表}`。
- 生产主路的解析实现：`xray-core/src/{inbound.rs,outbound.rs,arm_builders/*}` 中与上述键对应处（ss/trojan/hysteria/vless/vmess/tuic/dns 等），据此判定「生产主路可达」。
- 重点抽查键：`concurrency`/`xudpConcurrency`（`xray-core/src/outbound.rs:609-638`、`xray-app-proxyman/src/outbound/handler.rs:115-225` 生效）、`mux.*`、`sockopt.*`、`congestion`、`up/down`(brutal)、`mtu`、`keepAlive`、`domainStrategy`、`followRedirect`、`acceptProxyProtocol`、`padding`(splithttp xPadding 20 键)、`udpHop`、`permitWithoutStream`、`downloadSettings`。

**没查（明确未覆盖）**：

1. **`sniffing` 面**：解析在 `xray-core`/`xray-conf` 的 inbound 段，不在 16 个协议 crate 内；本轮不覆盖（另有 R1/嗅探票面）。
2. **`mux` 内部行为**：`crates/xray-mux` 的 `concurrency`/`xudpConcurrency`/`maxConnection` 只核到「有读点」这一级，未逐条验算语义（`is_full`/活跃数族在 `txno` 票面）。
3. **`xray-conf/src/protocols.rs` 45 个结构体**：R1 已证不在生产路径，未重复统计。
4. **跨语言行为等价**：未做 Go↔Rust 实机对拍；本报告的「期望消费点(Go)」全部来自 Go 静态源码定位，属 E2 证据（源码推导），非 E1（实测）。
5. **传输层「解析成功但语义细节不同」**：如 `kcpSettings.uplinkCapacity/downlinkCapacity`（Go `KCPConfig.Build` 收但现代 Go 运行期不消费，`header`/`seed` Go 亦不消费）——同形，未计入 NOT-WIRED。
6. **`interface` 解析失败降级为 warn**（`xray-transport/src/dialer.rs:388-397`：`resolve_interface_index` 失败即 `LOG.warn` + 忽略；Go 在 sockopt apply 阶段 `net.InterfaceByName` 失败 → 连接错误）：属「Go 硬错 → Rust warn 继续」的降级，已在本轮观察到但未单列 finding（影响面限于需要绑定网卡的部署；建议单独跟票）。

## 7. 一句话给 R2

性能旋钮里**真正会骗人**的只有 4 个：`quicParams.udpHop`（死）、`downloadSettings.*`（只有存在性生效）、`permitWithoutStream`（死）、hysteria `masquerade:proxy`（恒 503）；其余 sockopt/kcp/splithttp-xPadding/hysteria-quicParams 键都真的接进了行为路径，测性能时不必怀疑它们。
