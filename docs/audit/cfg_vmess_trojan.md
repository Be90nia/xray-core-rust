# VMess + Trojan 协议配置全链审计（第五轮：字段级）

- 日期：2026-09-06；基线：D:/Project/Xray-core（v26.7.28，infra/conf/vmess.go + trojan.go 权威）；目标：D:/Project/Xray-core-rust @ ae3e714
- 范围：VMess inbound（users/clients/default）+ outbound（vnext/users/平铺形式/security 加密族/experiments）；Trojan inbound（users/clients/fallbacks）+ outbound（servers/平铺形式/password 校验）
- 方法：逐字段列出 Go infra/conf Config JSON 键 → 读 Rust 解析点（xray-conf/protocols.rs 结构体 + 生产实际解析点 xray-core/inbound.rs、outbound.rs、xray-proxy-vmess/dispatcher.rs、xray-proxy-trojan）逐键比对 → grep 生产消费点（dispatcher/server/client/handler）→ 字段级判定。所有行号为当日 HEAD 实测。
- 关键事实：**xray-conf 的强类型 settings 结构体（VMessInboundSettings 等）在生产路径零调用**——`dispatch_inbound_settings`/`dispatch_outbound_settings`（protocols.rs:1242/1261）仅测试调用；运行时全部为 xray-core 内 ad-hoc `serde_json::Value` 手解析。因此本审计以生产解析点为准，typed 结构体仅作对照（见 P3-21 双轨漂移）。
- 判定符号：✅ 生效 ｜ ⚠️ 解析未消费/部分消费 ｜ ❌ 未解析·Go 支持 Rust 不支持 ｜ 🔧 默认值/语义偏离 Go。

## 严重度统计

| 级别 | 数量 |
|---|---|
| P1 | 4 |
| P2 | 4 |
| P3 | 13 |

TOP3：
1. **[P1] VMess inbound `users` 键被静默丢弃**（Go 一等别名键；Rust 仅读 `clients` → 零报错、零用户启动、所有握手被拒，全程无一条日志）
2. **[P1] VMess/Trojan outbound 平铺形式不支持**（Go 顶层 address/port/id/security / password 直配是 V2Ray 传统写法且被 Go 显式支持；Rust 报 "missing vnext array"/"missing servers array" 启动失败）
3. **[P1] Trojan fallbacks `dest` 数字形式/缺省静默落到硬编码 127.0.0.1:80**（Go 数字 dest N → "localhost:N"；Rust 非字符串一律 `unwrap_or("127.0.0.1:80")` → `{"dest":8080}` 静默错路由到 80 端口）

---

## 1. VMess

### 1.1 Go 基准字段清单（infra/conf/vmess.go）

- `VMessAccount`（:26-29）：`id` / `security` / `experiments`；Build（:33-48）security 仅映射 `aes-128-gcm`/`chacha20-poly1305`/`auto`，**其余一切值（含 none/zero）落 default → SecurityType_AUTO**（Go enum 仅 UNKNOWN=0/AUTO=2/AES128_GCM=3/CHACHA20_POLY1305=4，headers.pb.go:27-31，无 NONE/ZERO）。`experiments` 经 `strings.Contains` 解析为 AuthenticatedLength / NoTerminationSignal 两个布尔（proxy/vmess/account.go:54-67）。
- `VMessDefaultConfig`（:50-52）：`level`（byte）。
- `VMessInboundConfig`（:61-65）：`users` / `clients`（`[]json.RawMessage`，clients 非 nil 时覆盖 users，:72-74）/ `default`。user JSON 同时 unmarshal 进 `protocol.User`（level/email）与 `VMessAccount`（id/security/experiments）。
- `VMessOutboundConfig`（:115-124）：`address`/`port`/`level`/`email`/`id`/`security`/`experiments`/`vnext`。**顶层 address 非 nil → 构造单元素 Receivers（平铺形式，:121-127）**；vnext 必须恰 1 个（:130）、每 receiver users 必须恰 1 个（:135）。

### 1.2 VMess inbound 字段表（生产解析点：crates/xray-core/src/inbound.rs `build_vmess_validator` :2367-2410；消费点：xray-proxy-vmess/inbound、validator）

| 字段 | Go 语义 | Rust 解析 | inbound 消费 | 判定 |
|---|---|---|---|---|
| `users` | 一等键，clients 缺席时的载体（vmess.go:62,72-74） | **不解析**（:2377 仅读 `clients`） | — | ❌ **P1-1** |
| `clients` | 一等键，非 nil 覆盖 users | ✅ :2377 | validator 入表 | ✅ |
| `id` | uuid.ParseString（≤30B 非标派生 v5） | `UUID::parse` :2391-2393（xray-common/uuid/mod.rs:55 同 Go 语义，含派生测试 inbound.rs:4262） | cmd_key=MD5 入表（validator.rs:135） | ✅ |
| `alterId` | **Go 无此字段**（unknown key 静默忽略） | 解析数字/字符串，≠0 直接报错拒启（:2383-2390） | fail-fast | 🔧 P3-9（注释声明故意；Go 配置能起、Rust 拒启） |
| `security` | 解析进 Account，但服务端不消费（解密算法由请求头 security 字节驱动） | 不解析 | — | ✅ 等价（服务端语义本不需要） |
| `experiments`/`testsEnabled` | Contains→NoTerminationSignal 布尔，**服务端响应消费**（inbound.go:217 不写终止 chunk） | 不解析；MemoryAccount 字段恒 false（account.rs:45-46 无配置来源） | ❌ | ❌ **P2-6**（与出站同一条断链） |
| `email` | protocol.User.Email；access log/stats 标识 | :2380 | 无任何消费（inbound 模块 grep `\.email` 零命中） | ⚠️ P3-13 |
| `level` | protocol.User.Level（缺省=0）；vmess Process 恒 `ForLevel(0)`（inbound.go:230） | :2381（缺省取 default_level） | 无消费（policy 层缺） | ⚠️ P3-13 + 🔧 P3-10 |
| `default.level` | 仅用于 `GetOrGenerateUser` 未知 email 动态用户（inbound.go:35-38,150-156）；**已配置 user 缺 level 时仍是 0** | :2372-2376 解析，:2381 作为 user 缺省 level | ✅ 但语义偏 | 🔧 P3-10 |

### 1.3 VMess outbound 字段表（生产解析点：crates/xray-proxy-vmess/src/dispatcher.rs `parse_vmess_config` :134-201 + `make_vmess_dial_fn` :218-300；注册点 xray-core/src/outbound.rs:599-603）

| 字段 | Go 语义 | Rust 解析 | outbound 消费 | 判定 |
|---|---|---|---|---|
| 平铺 `address`/`port`/`id`/`security`/`level`/`email`/`experiments` | 顶层 address 非 nil → 构造 Receivers[0]（vmess.go:121-127，兼容 V2Ray 传统配置） | **不支持**：:136-139 无 `vnext` 直接报 "missing vnext array"，顶层键全不看 | — | ❌ **P1-2** |
| `vnext` | 必须恰 1 个成员 | ✅ :136-146（错误文案 Go 对齐） | server_destination 拨号 | ✅ |
| `vnext[].users` 恰 1 | :135-137 硬校验 | ✅ :155-163 | — | ✅ |
| `vnext[].address` | nil → error | ✅ :148-152 必填 | ✅ 拨号 | ✅ |
| `vnext[].port` | 允许缺省 0（运行时拨号失败） | :153-156 必填 + u16 范围校验 | ✅ | ✅（偏严 P3，并入 P3-15 类，不单列） |
| `users[0].id` | UUID.ParseString | ✅ :164-167（from_str=parse，无入/出站不对称） | ✅ header/cmd_key | ✅ |
| `users[0].security` | 3 值 + 其余→AUTO（含 none/zero，Go conf 层同样落 AUTO） | `parse_security` :122-128 同映射（额外接受 `@shadowsocks.org` 后缀=无害超集）；`resolve_security` :396-410 Auto→AES/CHACHA 与 Go GetSecurityType（headers.go:83-87）一致 | ✅ header security 字节 + body cipher | ✅ |
| security=auto 的选项位 | resolve 后再判定：**CHUNK_MASKING + GLOBAL_PADDING 均置位**（outbound.go:108-115 + headers.go 先 resolve） | `use_masking` :231-234 看**未 resolve** 的 `config.security` → auto 全关；:237-244 内层 matches! 含 Auto 死分支佐证非故意 | ❌ | 🔧 **P2-5**（wire 兼容、指纹偏离） |
| `users[0].experiments` | Contains→AUTH_LEN option（outbound.go:117-119）+ 不写终止 chunk（:180） | **不解析**（:168-173 只读 id/security/level/email）；协议层 auth_len/NO_TERMINATION 已实现（body_chunk.rs:167-185、client.rs:197-204）纯配置断链 | ❌ | ❌ **P2-6** |
| `users[0].level`/`email` | ServerEndpoint.User；`ForLevel(user.Level)`（outbound.go:136）+ stats email | ✅ :172-173 → with_level/with_email（:190-192） | **零读取**（config.level/.email 全库无消费者） | ⚠️ P3-11 |
| `users[0].alterId` | 静默忽略 | ≠0 拒绝（:176-184） | fail-fast | 🔧 P3-9 |

---

## 2. Trojan

### 2.1 Go 基准字段清单（infra/conf/trojan.go）

- `TrojanServerTarget`（:19-27）：`address`/`port`/`level`/`email`/`password`/`flow`。
- `TrojanClientConfig`（:31-39）：同上六键平铺 + `servers`；Build（:42-90）顶层 address 非 nil → 构造单元素 servers（**平铺形式**，:44-52）；servers 恰 1（:57-58）；**address nil → error（:66）**；**port==0 → error "Invalid Trojan port."（:69-71）**；**password=="" → error "Trojan password is not specified."（:72-74）**；flow 非空 → `PrintRemovedFeatureError` 硬错（:73-75）。
- `TrojanInboundFallback`（:93-100）：`name`/`alpn`/`path`/`type`/`dest`（RawMessage，数字或字符串）/`xver`。Build 推断（:139-175）：path 必须空或 `/` 开头否则 error（:158-160）；type=="" 且 dest 非空 → `serve-ws-none`→"serve"、绝对路径或 `@`→"unix"（`@@` Linux 补零）、纯数字→`localhost:N` 且 SplitHostPort 成功→"tcp"（:161-172）；type 仍空 → error（:173-175）；**xver>2 → error（:176-178）**。
- `TrojanUserConfig`（:103-111）：`password`/`level`/`email`/`flow`（flow 非空硬错，:134-136；**password 无空值校验**）。
- `TrojanServerConfig`（:113-118）：`users`/`clients`/`fallbacks`；clients 非 nil 覆盖 users（:124-126）。
- 运行时消费：`ForLevel(user.Level)`（server.go:228-229）；fallback `dialer.DialContext(ctx, fb.Type, fb.Dest)`（server.go:456-457，"unix" 走 unix socket）；validator email 唯一（trojan/validator.go:18-24，重复 → Add error → 启动失败）。

### 2.2 Trojan inbound 字段表（生产解析点：crates/xray-core/src/inbound.rs `build_trojan_users` :2204-2230 + trojan 分支 :1757-1817；消费点：xray-proxy-trojan/server.rs）

| 字段 | Go 语义 | Rust 解析 | inbound 消费 | 判定 |
|---|---|---|---|---|
| `users`/`clients` | 别名，clients 非 nil 覆盖 | ✅ :2210-2213 `get("clients").or(get("users"))` | — | ✅ |
| `password` | 无空值/类型校验外的检查（空串允许） | :2221；类型错（数字）→ `unwrap_or("")` 静默 | ✅ sha224 hex 入表 | ✅（形状错静默 → P3-17） |
| `email` | validator 唯一性校验；log/stats | :2222；主路径（HashMap 按 key_hash）**不查 email 重复**；transport 分支 warn skip（:1788-1793） | ✅ 日志（server.rs:463,470） | ⚠️ P3-18（Go 重复 email 拒启） |
| `level` | `ForLevel(user.Level)`（server.go:229） | :2223 | **不消费**（无 policy 接线） | ⚠️ P3-14 |
| `flow` | 非空 → 硬错（trojan.go:134-136） | :2216-2219 warn + 继续（注释声明故意，测试 inbound.rs:4183 认账） | — | 🔧 P3-16 |
| `fallbacks` | 6 键 + 推断 + 校验（见 2.3） | trojan 分支 :1761-1780 | ✅ serve_trojan/serve_trojan_conn | 见 2.3 |

### 2.3 Trojan fallbacks 字段表（解析点：inbound.rs:1761-1780；消费点：xray-proxy-trojan/server.rs `do_fallback` :342-352 → xray-transport/src/fallback.rs）

| 字段 | Go 语义 | Rust 解析 | 消费 | 判定 |
|---|---|---|---|---|
| `name`/`alpn`/`path` | 决策树 SNI→ALPN→Path 三级精确+通配 | ✅ :1766-1768 | ✅ FallbackPolicy（fallback.rs:110-235 与 Go napfb 同构） | ✅ |
| `dest` | RawMessage 数字或字符串；数字 N→`localhost:N`；**缺省→error** | :1771-1773 `as_str().unwrap_or("127.0.0.1:80")`——**数字类型 None→硬编码默认值** | do_fallback 拨号 | ❌ **P1-4** |
| `type` | `""`→按 dest 推断 unix/tcp/serve（:161-175） | :1769 原样接收，**无推断** | **恒 TcpStream::connect（fallback.rs:89-92）**——`"unix"` 的 socket 路径被当 TCP 主机名拨号；`""`+`host:port` 恰好等价 tcp | ❌ **P2-7** |
| `xver` | 0/1/2，>2 error（:176-178） | :1774 无范围校验，`as u8` 截断 | ✅ PROXY header 编码（transport/fallback.rs `encode_proxy_header`） | ✅（缺校验 → P3-19） |
| `path` 校验 | 空或 `/` 开头，否则 error | 无 | — | ⚠️ P3-19 |
| transport 分支 SNI/ALPN | Go 从 TLS 连接取 | :1806 传 `String::new(), String::new()`（hub 内终结 TLS 取不到） | name/alpn 匹配退化为仅 path/通配 | ⚠️ P3-20 |

### 2.4 Trojan outbound 字段表（生产解析点：crates/xray-core/src/outbound.rs `parse_trojan_config` :900-944；消费点：xray-proxy-trojan/dispatcher.rs `make_dial_fn`；注册点 outbound.rs:564-568）

| 字段 | Go 语义 | Rust 解析 | outbound 消费 | 判定 |
|---|---|---|---|---|
| 平铺 `address`/`port`/`level`/`email`/`password`/`flow` | 顶层 address 非 nil → Servers[0]（trojan.go:44-52） | **不支持**：:902-905 无 `servers` 报 "missing servers array"，顶层键全不看 | — | ❌ **P1-3** |
| `servers` 恰 1 | :57-58 | ✅ :907-911（文案 Go 对齐） | — | ✅ |
| `servers[].address` | nil → error | ✅ :920-924 必填 | ✅ 拨号 | ✅ |
| `servers[].port` | **0 → error "Invalid Trojan port."**（:69-71） | :925-928 缺 key 才报错；`"port":0` 放行 → 运行时拨号失败 | ✅ | ⚠️ P3-15 |
| `servers[].password` | **空串 → error "not specified"**（:72-74） | :930-934 缺 key 才报错；`"password":""` 放行 | ✅ hex(sha224) 请求头 | ⚠️ **P2-8**（Go 构建期硬校验缺失；空密码 hash 可预测） |
| `servers[].level`/`email` | ServerEndpoint.User；`ForLevel`（client.go:90） | ✅ :936-937 → with_level/with_email | **零读取**（dispatcher.rs:73-83 builder 后无消费者） | ⚠️ P3-12 |
| `servers[].flow` | 非空 → 硬错（:73-75，遍历全部 servers） | :913-918 warn + 继续（文档化故意） | — | 🔧 P3-16 |


### 2.5 发现明细（P1/P2）

#### [P1-1] VMess inbound `users` 键静默丢弃 → 零用户启动
- 位置：`crates/xray-core/src/inbound.rs:2377`；Go 对照 `infra/conf/vmess.go:62,72-74`（Users 为一等键）
- 证据：`if let Some(clients) = v.get("clients").and_then(|c| c.as_array())`——`{"users":[{...}]}` 时 Some→None 分支，0 用户入表，inbound 正常监听；同文件 trojan 侧 :2210-2213 有 `clients.or(users)` 双读，vmess 侧漏配，属不对称实现。
- 影响：Go 合法配置在 Rust 下静默产出"零用户服务器"，所有 VMess 握手被拒且无启动期任何告警（普通分支日志甚至不含 users 数），排障成本极高。
- 修复：与 build_trojan_users 对齐：`v.get("clients").or_else(|| v.get("users"))`（附带统一 presence 语义）。

#### [P1-2] VMess outbound 平铺形式（顶层 address/port/id/security）不支持
- 位置：`crates/xray-proxy-vmess/src/dispatcher.rs:136-139`；Go 对照 `infra/conf/vmess.go:115-127`
- 证据：parse_vmess_config 仅接受 `vnext`，缺失即 `"missing vnext array"`；Go `if c.Address != nil { c.Receivers = [...] }` 显式支持平铺。xray-conf `VMessOutboundSettings`（protocols.rs:385-401）解析全部平铺键但生产零调用（双轨漂移的实证）。
- 影响：V2Ray 系生成器的传统 VMess 直配写法在 Rust 全部拒启（响亮失败，好于静默）。
- 修复：parse_vmess_config 前置 `if v.get("address").is_some() { 合成 vnext 单元素 }`，对齐 vmess.go:121-127。

#### [P1-3] Trojan outbound 平铺形式（顶层 address/port/password）不支持
- 位置：`crates/xray-core/src/outbound.rs:902-905`；Go 对照 `infra/conf/trojan.go:44-52`
- 证据：parse_trojan_config 仅接受 `servers`；Go `if c.Address != nil { c.Servers = [...] }`。注意 `xray-conf/src/outbound_security.rs:220-227` 的 `extract_trojan_address` 明知顶层 address 形态（私网豁免判定用了它），解析器却不认——同一 crate 内自相矛盾。
- 影响：同 P1-2，Go 合法配置拒启。
- 修复：同 P1-2 模式：顶层 address 在场 → 合成单元素 servers。

#### [P1-4] Trojan fallbacks `dest` 数字形式/缺省静默落 127.0.0.1:80
- 位置：`crates/xray-core/src/inbound.rs:1771-1773`；Go 对照 `infra/conf/trojan.go:143-175`
- 证据：`fb.get("dest").and_then(|v| v.as_str()).unwrap_or("127.0.0.1:80")`——JSON 数字 dest（Go 明确支持，`{"dest":8080}`→"localhost:8080"）as_str 为 None → 恒取硬编码默认；dest 键缺省（Go error "please fill in a valid value"）同样静默默认。
- 影响：`{"dest":8080}` 类配置的 fallback 流量被静默转发到 127.0.0.1:80（错后端），无任何告警；缺省 dest 则掩盖配置错误。
- 修复：`dest.as_u64()` 分支合成 `localhost:{n}`；两分支皆缺 → 拒启（对齐 Go error）。

#### [P2-5] security=auto 出站缺 CHUNK_MASKING/GLOBAL_PADDING（指纹偏离）
- 位置：`crates/xray-proxy-vmess/src/dispatcher.rs:231-244`；Go 对照 `proxy/vmess/outbound/outbound.go:108-115` + `common/protocol/headers.go:83-87`
- 证据：`use_masking = matches!(config.security, Aes128Gcm | Chacha20Poly1305)` 用的是**未 resolve** 的配置值；Go 先经 `GetSecurityType()` 把 AUTO 解析为 AES/CHACHA 再判 → 默认 auto 配置 Go 双位全开、Rust 全关。:237-244 内层 matches! 含 `SecurityType::Auto` 死分支（use_masking 已排除 Auto），佐证非故意。
- 影响：wire 兼容（选项位自描述），但默认配置下 chunk 长度掩码/填充指纹与 Go 客户端系统性不同——恰在抗探测面上。
- 修复：改用 `let security = resolve_security(config.security)?` 的返回值做两次 matches!，一行对齐。

#### [P2-6] experiments/testsEnabled 全链断链
- 位置：`crates/xray-proxy-vmess/src/dispatcher.rs:168-173`（出站不解析）、`crates/xray-core/src/inbound.rs:2377-2400`（入站不解析）；Go 对照 `vmess.go:28` + `proxy/vmess/account.go:54-67` + `outbound/outbound.go:117-119,180` + `inbound/inbound.go:217`
- 证据：协议层能力完整（body_chunk.rs:167-185 auth_len size parser、client.rs:197-204/server.rs:196-223 三选项位、account.rs:59-68 两个 builder），但唯一来源 `Account::from_proto` 的 tests_enabled 无任何配置写入点——`experiments` 键在入/出站两侧均被丢弃。
- 影响：AuthenticatedLength/NoTerminationSignal 两个流量整形实验配置即死配置；服务端侧 Go 的 `!account.NoTerminationSignal` 行为差（Rust 恒发终止 chunk，客户端双兼容无断裂）。
- 修复：出站 parse 读 `users[0].experiments` contains → 置 `request_option::AUTHENTICATED_LENGTH` / `NO_TERMINATION_SIGNAL`；入站 matched account 带上两布尔。

#### [P2-7] Trojan fallback `type` 无推断且 unix 型恒走 TcpStream
- 位置：`crates/xray-core/src/inbound.rs:1765-1775`（无推断）+ `crates/xray-proxy-trojan/src/server.rs:342-352`、`crates/xray-transport/src/fallback.rs:89-92`（消费恒 TCP）；Go 对照 `trojan.go:161-175` + `proxy/trojan/server.go:456-457`
- 证据：`Fallback.r#type` 结构体字段在（fallback.rs:20-26，注释还引了 Go `DialContext(ctx, fb.Type, ...)`），但 `do_fallback` 签名无 type 参数，`fallback_to_dest` 内 `TcpStream::connect(dest)`——`"type":"unix"`（dest=/path/to.sock）把 socket 路径当 TCP 主机名解析，必败。
- 影响：unix 型 fallback 静默坏；`""`+`host:port` 恰好碰对；Go 的推断/校验（path、dest 必填、xver≤2）整体缺失。
- 修复：`Fallback.type`=="unix" 走 `tokio::net::UnixStream::connect`；补 Go 同款三校验。

#### [P2-8] Trojan outbound 空 password 放行
- 位置：`crates/xray-core/src/outbound.rs:930-934`；Go 对照 `infra/conf/trojan.go:72-74`
- 证据：仅缺 key 报 "missing servers[0].password"；`"password":""` → `MemoryAccount::new("")` 正常构建（hex(sha224("")) 为已知常量）。
- 影响：Go 构建期硬校验缺失，错配延迟到运行时认证失败；空密码 hash 可预测，属信任边界上的校验缺口。
- 修复：`if password.is_empty() { return Err("Trojan password is not specified.") }`。

### 2.6 横切注记

- **双轨解析漂移（P3-21）**：`xray-conf/src/protocols.rs` 的 VMess/Trojan settings 结构体（:79-119,385-446）与 `dispatch_inbound/outbound_settings`（:1242,1261）生产零调用，运行时为 xray-core 内 4 处 ad-hoc Value 手解析。typed 层"支持"的键（如 vmess `users`、出站平铺键族）与运行时行为脱节，本轮 3 个 P1 均发生在这条缝上。建议后续收敛：解析逻辑归一 xray-conf（typed 层落地消费）或删除死结构体。
- **policy/stats 面板（P3-11~14 根因）**：入站 user.level→ForLevel、出站 user.level/email→policy+stats 的接线整体缺席，属已报 app 层 policy 键族问题的协议面投影，本轮仅按字段记账。

### 2.7 确认干净清单（✅ 抽样逐条验证）

- vmess `clients` 别名/恰一校验/错误文案 Go 对齐；`vnext[].users` 恰一（dispatcher.rs:141,161）。
- UUID 语义双侧一致：`UUID::parse`=FromStr（uuid/mod.rs:55,112），≤30B 非标派生 v5 与 Go ParseString 对齐且有对拍测试（inbound.rs:4262-4264）。
- security 三值映射与 AUTO 兜底：none/zero/任意未知串 → AUTO，与 Go conf 层等价（Go enum 本无 NONE/ZERO，headers.pb.go:27-31）；`@shadowsocks.org` 后缀为无害超集；Auto→AES(有 AES-NI)/CHACHA 解析与 GetSecurityType 一致。
- cmd_key=MD5(uuid||magic) 入/出站一致；auth_id 匹配含 replay/negative/invalid time 分类（validator.rs:160-168）。
- trojan `users`/`clients` 别名正确（inbound.rs:2210-2213）；入站空密码与 Go 同宽（双方均允许）；hex(sha224(password)) 派生双侧对齐。
- trojan servers 恰一校验+Go 对齐文案（outbound.rs:907-911）；servers[].address 必填。
- fallback 决策树 SNI→ALPN→Path 三级精确+通配与 Go napfb 同构（fallback.rs:110-235）；xver PROXY v1/v2 编码实现（transport/fallback.rs:17-19）。
- trojan validator Add 语义与 Go 一致（email 小写唯一检查+hash 入表，validator.rs:102-111）。
- `flow` 硬错→warn 的放宽为注释+测试双认账的文档化决定（outbound.rs:991-998、inbound.rs:4183-4185），非静默漂移。

### 2.8 与前四轮不重复声明

freedom destinationOverride/proxyProtocol、dokodemo address 过严+followRedirect、socks address 死字段、httpupgrade TLS acceptor、出站 mux.enabled/concurrency、app 层键族（policy/observatory/burst/fakedns 池/geodata/version/commander/metrics tag）、XUDP GlobalID、ss UDP 127.0.0.1、uTLS 指纹清单、REALITY maxTimeDiff/MinClientVer·MaxClientVer、ss2022 键族——均未重复收录。本轮 21 条全部为 vmess/trojan 配置链新发现。
