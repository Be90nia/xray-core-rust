# 协议级配置全链审计：Shadowsocks / SS2022 / SOCKS / HTTP（第五轮）

- 审计代理：CfgSsSocks（只读代码，唯一写动作 = 本文件）
- Go 基准：`D:/Project/Xray-core/infra/conf/{shadowsocks,socks,http}.go`（v26.7.28，权威字段清单）；Rust 仓库：`D:/Project/Xray-core-rust`
- 方法：逐协议 ①列 Go infra/conf 全部 JSON 字段 ②读 Rust 生产解析点逐键比对 ③grep 生产消费点 ④字段级表格判定（✅生效 / ⚠️解析未消费 / ❌未解析 / 🔧默认值或语义偏离）。已知旧账（socks `ip` 死字段、UDP 127.0.0.1 等）只入表不重复展开。

## 0. 解析层地图（生产链 vs 平行层）

生产解析**不走** `xray-conf/src/protocols.rs` 强类型层，而是逐协议手写 `serde_json::Value` 提取：

| 侧 | 协议 | 生产解析点 | 消费点 |
|---|---|---|---|
| inbound | shadowsocks(含2022) | xray-core/src/inbound.rs:2409-2509 | serve_ss:824 / serve_ss_udp:974 / serve_ss2022_udp:1089 |
| outbound | shadowsocks(含2022) | xray-proxy-ss/src/dispatcher.rs:301-385 | make_ss_dial_fn:413 |
| inbound | socks | xray-core/src/inbound.rs:2085-2110 | serve_socks5:72 + xray-proxy-socks/server.rs 握手 |
| outbound | socks | xray-core/src/outbound.rs:1190-1228 | xray-proxy-socks client.rs dial + dispatcher.rs make_dial_fn |
| inbound | http | xray-core/src/inbound.rs:2260-2283 | serve_http:383 + xray-proxy-http/server.rs:275 |
| outbound | http | xray-proxy-http/src/client.rs:75-124 | make_http_dial_fn:127 |

`xray-conf/protocols.rs` 强类型层（`dispatch_inbound/outbound_settings`:1242-1280）字段覆盖**更全**（SS `users`/`network`、socks `ip`、SS 出站顶层简写等都有），但全仓 grep 无任何生产调用方（仅本 crate 测试；xray-cli 只用 `merge_config_from_files` 做 dump）。**该层与生产手写解析存在系统性字段差异，"校验通过≠生产生效"**——本报告判定一律以生产解析点为准。

---

## 1. Shadowsocks 入站（含 SS2022）

Go 基准：`ShadowsocksServerConfig`（shadowsocks.go:43-51）+ `ShadowsocksUserConfig`（:35-41）+ Build（:53-113）+ buildShadowsocks2022（:115-179）。

| # | JSON 键 | Go 语义 | Rust 生产解析 | inbound 消费 | 判定 |
|---|---|---|---|---|---|
| 1 | `method`(顶层) | 2022 分流（:60 精确 List）+ legacy cipher | inbound.rs:2414，**缺省默认 `"aes-128-gcm"`**；:2415 `starts_with("2022-blake3-")` 前缀分流 | serve_ss 分流 | 🔧 Go 缺省报 unknown cipher method（:84-87），Rust 静默默认；前缀宽于精确 List |
| 2 | `password`(顶层) | 单用户密码/PSK（:44） | :2441（缺失报错）；:2456（2022，缺失报错） | 密钥派生 | 🔧 **空串放行**，Go :76-78/:84-86 报错 |
| 3 | `level`(顶层) | User.Level（:89-91） | ❌ 未解析（legacy 单用户/clients 均不读） | 无 policy 挂钩 | ❌ |
| 4 | `email`(顶层) | User.Email（:47,:89） | 单用户硬编码 `"u@ss.local"`（:2448）/ `"u@ss2022.local"`（:2506）；clients 分支 ✓（:2425） | validator 邮箱索引 | ⚠️ 单用户路径丢弃 |
| 5 | `users` **（Go 主键）** | 用户数组（:48） | ❌ **未解析**（legacy :2421 与 2022 多用户 :2487 均只读 `clients`） | — | ❌ [P1] F-SS1 |
| 6 | `clients` | users 别名（:49） | ✓ :2421 / :2487 | validator / MultiUserInbound | ✅（主次颠倒：Go 主键反而只字不认） |
| 7 | `users[].method` | 2022 多用户须为空否则报错（:139-141） | clients 分支不读、不校验 | — | ⚠️ 校验缺失 |
| 8 | `users[].password` | 多用户 PSK（:144-146） | ✓ :2490 | MultiUserInbound EIH | ✅ |
| 9 | `users[].level` | User.Level（:147） | ✓ :2492 → Ss2022User.level | 存储后无 policy 消费 | ⚠️ 解析未消费 |
| 10 | `users[].email` | User.Email（:148） | ✓ :2491 | validator | ✅ |
| 11 | `users[].address`/`port` | relay 判定+目的地（:159-178，键 `address`/`port`） | ❌ relay 改读 `destinations[]`+`server`/`server_port`（:2460,:2466-2467） | — | ❌ [P1] F-SS2（Go 形态 relay 静默落入单用户） |
| 12 | `network` | NetworkList（:50）→ Server.Network() 门 TCP/UDP（proxy/shadowsocks/server.go:81-87，空=TCP-only） | ❌ 未解析；serve_ss :845-861 恒 bind UDP 双栈 | — | ❌ [P2] F-SS3 |
| 13 | `uot`/`uotVersion` | **Go 无此键**（infra/conf 零命中） | 入站不解析 | — | ℹ️ 见出站 #14 |
| 14 | `destinations[]`(Rust 方言) | Go 无 | ✓ :2460-2467 | RelayInbound | ✅ 方言可用，与 Go 配置不兼容（见 #11） |

另：transport 承载分支（grpc/ws 等 listener）仅 Legacy 模式接线，2022 回落裸 TCP（inbound.rs:1943-1961，warn）。

## 2. Shadowsocks 出站（含 SS2022）

Go 基准：`ShadowsocksClientConfig`（:192-202）+ `ShadowsocksServerTarget`（:185-191）+ Build（:204-276）。

| # | JSON 键 | Go 语义 | Rust 生产解析 | outbound 消费 | 判定 |
|---|---|---|---|---|---|
| 1-6 | 顶层 `address`/`port`/`level`/`email`/`method`/`password` | 折叠为 servers[0]（:205-217） | ❌ 无 `servers` 即报 "missing servers array"（dispatcher.rs:303-313） | — | ❌ [P2] F-SS4 |
| 7 | `servers` | 恰 1 个否则报错（:218-221） | ✓ 取 servers[0]，数量不校验（:310） | — | ✅（🔧 多 server 静默取首个） |
| 8 | `servers[].address` | 端点地址（:186，nil 报错 :223-225） | ✓ :304-307 | 连接目标 | ✅（🔧 恒包 Address::Domain :381，IP 字符串仍可解析） |
| 9 | `servers[].port` | :187，0 报错（:227-229） | ✓ :308-313（**0 放行**） | 连接 | ✅（🔧 port=0 校验缺失） |
| 10 | `servers[].level` | User.Level（:188） | ✓ :330/:379 | dial 链无消费 | ⚠️ 解析未消费 |
| 11 | `servers[].email` | User.Email（:189） | ✓ :331/:380 | dial 链无消费 | ⚠️ 解析未消费 |
| 12 | `servers[].method` | 白名单分流（:222/:238-245） | ✓ :314-317；2022 判定 from_name().is_ok()（:328，精确） | 加密器 | ✅（白名单见 §3） |
| 13 | `servers[].password` | 密码/PSK；2022 支持 iPSK:uPSK | ✓ :318-321；拆分 :343-349 → with_identity | 密钥派生/EIH | ✅（🔧 2022 空密码不拒，Go :233-235 报错） |
| 14 | `uot`/`uotVersion`（仅2022） | **Go 无此键**（Rust 扩展，对标 proto UdpOverTcp；Go conf 层从不填） | ✓ 解析 :332-341 → udp_over_tcp | ❌ **拨号零消费**：make_ss_dial_fn UDP 分支 :507-528 恒原生 UDP，全仓无第二读取点 | ⚠️ [P2] F-SS5 |
| 15 | legacy 路径无 UoT | Go 旧 ClientConfig 无此字段 | ✓ 保持默认 false（:368-385） | 同上 | ✅ |

## 3. method 白名单对齐

- legacy AEAD 5 方法 + 别名（`aead_*`/`chacha20-ietf-poly1305`/`xchacha20-ietf-poly1305`）+ 大小写不敏感：Go `cipherFromString`（:17-32）↔ Rust `CipherType::from_name`（xray-proxy-ss/src/config.rs:57-70）——逐别名比对**全对齐** ✅。
- SS2022 3 方法精确区分大小写：Go `C.Contains(shadowaead_2022.List)`（:60）↔ Rust `CipherKind2022::from_name`（xray-proxy-ss/src/ss2022/key.rs:22-29）——对齐 ✅。
- 分流点偏差：入站前缀 `starts_with("2022-blake3-")`（inbound.rs:2415）vs 出站精确 from_name（dispatcher.rs:328）；非法名两实现均最终报错，仅文案/路径不同 🔧。

## 4. SS2022 多 PSK 专项

| 能力 | Go | Rust | 判定 |
|---|---|---|---|
| 单用户 PSK | :116-123 | Ss2022Inbound::new（inbound.rs:2506） | ✅ |
| iPSK:uPSK 出站格式 | sing 层拆分 | dispatcher.rs:343-349 → with_identity | ✅ |
| 多用户 EIH（TCP） | MultiUserServerConfig | MultiUserInbound（inbound.rs:2487-2500） | ✅（键名见 F-SS1） |
| 多用户 EIH（UDP） | — | serve_ss:855-859 udp_user_table → serve_ss2022_udp:1089 | ✅ |
| relay 中继 | users[]+address/port（:159-178） | destinations[]+server/server_port（:2460-2467）；relay UDP 未接（serve_ss:854-856 None） | ❌ F-SS2 |

---

## 5. SOCKS 入站

Go 基准：`SocksServerConfig`（socks.go:30-37）+ Build（:39-67）；UDP 门禁 proxy/socks/protocol.go:171-175。

| # | JSON 键 | Go 语义 | Rust 生产解析 | inbound 消费 | 判定 |
|---|---|---|---|---|---|
| 1 | `auth` | noauth→NO_AUTH / password→PASSWORD / **未知静默 noauth**（:40-50） | ✓ :2091（`=="password"`→Password，其余 NoAuth） | 握手 method 协商（server.rs:357 select_method） | ✅（静默默认行为与 Go 一致） |
| 2 | `users` | 账户数组（:33） | ✓ :2093-2099 | accounts 表 + RFC1929 | ✅ |
| 3 | `accounts` | users 别名（:34,:51-53） | ✓ :2095 `users.or_else(accounts)` | 同上 | ✅ |
| 4 | `users[].user`/`pass` | SocksAccount（:14-15） | ✓ :2096-2097 | 认证 | ✅ |
| 5 | `udp` | UdpEnabled；false 时拒绝 ASSOCIATE（protocol.go:171-175 statusCmdNotSupport） | ✓ 解析 :2107 | ❌ **零消费**：ASSOCIATE 无条件成功（xray-proxy-socks/server.rs:247-271 无检查）；relay 无条件 spawn（inbound.rs:129-146） | ⚠️ [P1] F-SK1 |
| 6 | `ip` | ASSOCIATE 响应 BND.ADDR（protocol.go:197-201） | ❌ 未解析（:2084 注释自认"无消费方暂不解析"）；响应恒 127.0.0.1（server.rs:249-251） | — | ❌ **已知旧账**（表列不展开） |
| 7 | `userLevel` | ForLevel(config.UserLevel) 策略（server.go:55-58） | ✓ :2108 → ServerConfig.user_level（xray-proxy-socks/config.rs:92） | ❌ socks 服务链无 policy_for_level（对比 http inbound.rs:1867 有） | ⚠️ [P2] F-SK2 |

## 6. SOCKS 出站

Go 基准：`SocksRemoteConfig`（:69-73）+ `SocksClientConfig`（:75-85）+ Build（:87-137）。

| # | JSON 键 | Go 语义 | Rust 生产解析 | outbound 消费 | 判定 |
|---|---|---|---|---|---|
| 1-6 | 顶层 `address`/`port`/`level`/`email`/`user`/`pass` | 折叠 servers[0]（:88-97） | ❌ 无 servers 即报错（outbound.rs:1199-1202） | — | ❌ [P2] F-SK3（同 F-SS4 族） |
| 7 | `servers` | 恰 1 个（:98-100） | ✓ 取首个，数量不校验（:1203） | — | ✅（🔧） |
| 8 | `servers[].address`/`port` | :70-71 | ✓ :1206-1217 | 连接目标 | ✅ |
| 9 | `servers[].users` | ≤1（:102-104） | ✓ users[0]（:1219-1227），数量不校验 | — | ✅（🔧） |
| 10 | `users[].user`/`pass` | RFC1929 | ✓ :1222-1224 → new_with_auth | 方法协商+认证 | ✅ |
| 11 | `users[].level`/`email` | protocol.User（:106-110） | ❌ 未解析 | — | ❌ P3 |
| 附注 | streamSettings | Go 出站走 internet dialer（TLS/WS 有效） | socks 分支不接 stream_settings（outbound.rs:578-590 无 with_stream_settings；client.rs:62 裸 TcpStream::connect） | — | ⚠️ [P2] F-SK4（TLS+socks 配置静默无效） |
| 附注 | UDP 出站 | Go client.go:146-152 支持 UDP ASSOCIATE | Rust 出站 dial_fn 仅 TCP 分支（xray-proxy-socks/dispatcher.rs 全文无 UDP） | — | ⚠️ 能力缺口（非字段，注记） |

## 7. HTTP 入站

Go 基准：`HTTPServerConfig`（http.go:25-30）+ Build（:32-50）。任务点名的 `timeout`：**Go v26.7.28 无此字段**（v2ray 遗留已删，超时走 policy handshake），Rust 亦无——双侧一致 ✅。

| # | JSON 键 | Go 语义 | Rust 生产解析 | inbound 消费 | 判定 |
|---|---|---|---|---|---|
| 1 | `users` **（Go 主键）** | 账户数组（:26） | ❌ **未解析**（:2266 只读 `accounts`） | — | ❌ [P1] F-HT1：Go 风格 users 配置 → accounts 空 → **Basic 认证静默关闭（开放代理）** |
| 2 | `accounts` | users 别名（:27,:38-40） | ✓ :2266-2271 | Basic auth（server.rs 握手） | ✅ |
| 3 | `users[].user`/`pass` | HTTPAccount（:14-15） | ✓ :2268-2269 | 同上 | ✅（🔧 空 user 跳过 vs Go 插入 "" 键，边缘） |
| 4 | `allowTransparent` | 允许绝对 URI/透明（:28） | ✓ :2273-2276 | server.rs:275（origin-form 门禁） | ✅ |
| 5 | `userLevel` | handshake 策略（server.go policy） | ✓ :2277-2281 | inbound.rs:1864-1868 policy_for_level→handshake 超时 | ✅ |
| 6 | `timeout` | Go 无此字段 | 无 | — | ✅ 对齐（不存在） |

## 8. HTTP 出站

Go 基准：`HTTPRemoteConfig`（:52-56）+ `HTTPClientConfig`（:58-67）+ Build（:69-127）。

| # | JSON 键 | Go 语义 | Rust 生产解析 | outbound 消费 | 判定 |
|---|---|---|---|---|---|
| 1-6 | 顶层 `address`/`port`/`level`/`email`/`user`/`pass` | 折叠 servers[0]（:71-81） | ❌ 无 servers 即报错（client.rs:77-80） | — | ❌ [P2] F-HT2（同 F-SS4 族） |
| 7 | `servers` | 恰 1 个（:82-84） | ✓ 取首个（:81），数量不校验 | — | ✅（🔧） |
| 8 | `servers[].address`/`port` | :53-54 | ✓ :82-93 | 连接目标 | ✅ |
| 9 | `servers[].users` | ≤1（:86-88） | ✓ users[0]（:99-110） | — | ✅（🔧） |
| 10 | `users[].user`/`pass` | Proxy-Authorization Basic | ✓ :99-110 → with_auth | CONNECT 头（client.rs:145-150） | ✅ |
| 11 | `users[].level`/`email` | protocol.User（:90-96） | ❌ 未解析 | — | ❌ P3 |
| 12 | `headers` | 自定义 CONNECT 头 + 模板填充（:66 → client.go:37/64/98-104/220-222） | ❌ **未解析** | — | ❌ [P2] F-HT3 |

---

## 9. 缺陷清单（全部 patch 外既有账，本轮新证）

| 编号 | 级别 | 位置 | 缺陷 | 修复建议 |
|---|---|---|---|---|
| F-HT1 | [P1] | crates/xray-core/src/inbound.rs:2266 | HTTP 入站不解析 Go 主键 `users`，仅认 `accounts` → 认证静默关闭成开放代理 | 仿 socks :2093-2095 `get("users").or_else(get("accounts"))` |
| F-SK1 | [P1] | crates/xray-proxy-socks/src/server.rs:247（解析 inbound.rs:2107） | socks `udp:false` 解析后零消费，ASSOCIATE 无条件成功中继（Go protocol.go:171-175 拒绝） | 握手处 `if cmd==UDP && !config.udp_enabled → STATUS_CMD_NOT_SUPPORT` |
| F-SS1 | [P1] | crates/xray-core/src/inbound.rs:2421,2487 | SS 入站不解析 Go 主键 `users`（只认 Rust 方言 `clients`）→ Go 标准 SS2022 多用户配置静默退化为单用户 PSK，用户 PSK 全部丢弃 | 两处改 `get("clients").or_else(get("users"))`（trojan :2210-2212 已有同款先例） |
| F-SS2 | [P1] | crates/xray-core/src/inbound.rs:2460-2467 | SS2022 relay 配置形态偏离 Go：Go `users[]`+`address`/`port`（shadowsocks.go:159-178），Rust 读 `destinations[]`+`server`/`server_port` → Go 形态 relay 配置静默落入单用户模式 | 兼容读 users[]（address/port），方言键保留为 fallback |
| F-SS3 | [P2] | crates/xray-core/src/inbound.rs:845-861 | SS 入站 `network` 未解析，恒 TCP+UDP 双栈；Go 空=TCP-only、`network:"tcp"` 可关 UDP | 解析 network 并门控 serve_ss UDP bind |
| F-SS4 | [P2] | crates/xray-proxy-ss/src/dispatcher.rs:303 | SS 出站不支持 Go 顶层 `address`/`port`/`method`/`password` 简写（Go :205-217 折叠），合法 Go 配置被拒 | servers 缺失时按顶层键折叠 |
| F-SS5 | [P2] | crates/xray-proxy-ss/src/dispatcher.rs:332-341 vs :507-528 | SS2022 出站 `uot`/`uotVersion` 解析后拨号零消费（UDP 恒原生 socket）——Rust 扩展自身也未接线 | 实现或删除；至少 warn |
| F-SK2 | [P2] | crates/xray-proxy-socks/src/config.rs:92 | socks 入站 `userLevel` 解析未消费（无 policy_for_level；Go server.go:55-58 有） | serve 链接 policy（参照 http inbound.rs:1867） |
| F-SK3 | [P2] | crates/xray-core/src/outbound.rs:1199 | socks 出站顶层 `address`/`user`/`pass` 简写不支持（Go :88-97） | 同 F-SS4 族 |
| F-SK4 | [P2] | crates/xray-core/src/outbound.rs:578-590 | socks 出站分支不接 streamSettings（TLS/WS 静默无效；对比 ss/vmess/http 分支均接） | 补 with_stream_settings + dialer dial |
| F-HT2 | [P2] | crates/xray-proxy-http/src/client.rs:77 | http 出站顶层简写不支持（Go :71-81） | 同 F-SS4 族 |
| F-HT3 | [P2] | crates/xray-proxy-http/src/client.rs:75-124 | http 出站 `headers` 未解析，自定义头静默丢弃（Go client.go:98-104/220-222 模板填充） | 解析 map→Header 列表，CONNECT 时附加 |
| P3 群 | [P3] | 见各表 🔧 | 空密码放行(SS)、单用户 email 硬编码、port=0 放行、servers/users 数量不校验、clients[].method 不校验(2022 须空)、出站 users[].level/email 丢弃、多 server 静默取首个 | 逐项补 Go 对齐校验 |

## 10. 统计

- 字段级表格规模：6 张主表 + 2 张专项表，共 **68 个字段行**（SS 入站 14 / SS 出站 15 / SOCKS 入站 7 / SOCKS 出站 11+2 附注 / HTTP 入站 6 / HTTP 出站 12 + 白名单/多PSK 专项）。
- 判定分布：✅ 生效 38；⚠️ 解析未消费/校验缺失 9；❌ 未解析 15；🔧 默认值/语义偏离（含与 ✅ 并注）12。
- 缺陷统计：**P1×4（F-HT1 / F-SK1 / F-SS1 / F-SS2），P2×8（F-SS3/4/5、F-SK2/3/4、F-HT2/3），P3×7 项**；另有 2 项已知旧账（socks `ip` 死字段、UDP relay 恒 127.0.0.1）按要求仅表列。
- **TOP3**：
  1. **F-HT1** HTTP 入站 `users` 键不解析 → 认证静默关闭（配置形态即安全降级）；
  2. **F-SK1** socks `udp:false` 不消费 → UDP ASSOCIATE 恒开（攻击面大于配置声明）；
  3. **F-SS1+F-SS2** SS2022 Go 形态多用户/中继配置静默退化单用户（用户 PSK/中继语义整层丢失）。
- 系统性注记：`xray-conf/protocols.rs` 强类型层字段覆盖完整但零生产调用（§0），三协议"两套解析层"并存且互不一致——任何"配置合法"结论都必须落到 inbound.rs/outbound.rs/proxy crate 手写解析点才成立。
