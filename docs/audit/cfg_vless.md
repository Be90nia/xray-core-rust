# VLESS 配置全链审计（第五轮：协议级配置）

- **基线（权威）**：Go `D:/Project/Xray-core/infra/conf/vless.go`（VLessInboundConfig/OutboundConfig v26.7）、`proxy/vless/account.proto`、`proxy/vless/inbound/inbound.go`、`proxy/vless/outbound/outbound.go`、`infra/conf/transport_security.go`（REALITYConfig）。
- **对象**：`D:/Project/Xray-core-rust`（生产构建路径）。
- **架构注记（判定前提）**：Rust 生产路径 = `xray-core/src/inbound.rs` 的 `build_vless_validator/build_vless_decryption/build_vless_fallbacks`（hand-parse entry.data JSON）+ `xray-core/src/outbound.rs::parse_vless_config`（hand-parse）+ `xray-proxy-vless` crate。`xray-conf/src/protocols.rs` 的强类型 `VLessInboundSettings/VLessOutboundSettings` 是**平行解析层，生产不消费**（仅 conf 层自测引用）——下表"解析点"以生产路径为准。
- **判定图例**：✅ 生效 ｜ ⚠️ 解析未消费/部分消费 ｜ ❌ 未解析/未接线 ｜ 🔧 默认值或校验偏离 Go ｜ N/A Go 无此字段。

---

## ① inbound settings 级 + client 字段

### 表 1-1 inbound settings 级（Go `vless.go:33-40` VLessInboundConfig）

| Go 字段 | Go 语义 | Rust 解析点（生产） | Rust 消费点 | 判定 |
|---|---|---|---|---|
| `users`（旧名） | `clients!=nil` 时 clients 覆盖，否则按 users 处理（vless.go:44-47） | **仅读 `clients`**（inbound.rs:2124），无 users 回退 | 同左 | ❌ **[P2-1]** |
| `clients` | 用户数组（RawMessage） | inbound.rs:2124 | `build_vless_validator`→validator（inbound.rs:2132） | ✅ |
| `decryption` | `"none"` / `mlkem768x25519plus.*`；**缺省/空串报错**（vless.go:158-161） | inbound.rs:2161 `unwrap_or("none")`（缺省/空串均静默按 none） | `VlessInboundOptions.decryption`→ENC 握手（server.rs:63,231） | ✅ 消费 ｜ 🔧 缺省偏离 **[P3-10]** |
| `fallbacks` | 与 `decryption!="none"` **互斥报错**（vless.go:157-159） | inbound.rs:2239（无互斥检查） | `handle_connection_with_fallback`（inbound.rs:1728-1730） | ✅ 消费 ｜ 🔧 互斥未查 **[P3-15]** |
| `flow`（settings 级） | 校验 ∈{`""`,XRV}（vless.go:45-50）；**客户端空 flow 继承此值**（vless.go:63-65） | production **零读取**（build_vless_validator 无 `v.get("flow")`） | 无 | ❌ **[P2-3]** |
| `testseed`（settings 级） | client `len(Testseed)<4` 时填充（vless.go:67-69）→ `NewVisionWriter`（encoding/addons.go:71） | **零读取**（validator 构造 ProtoAccount 用 `..Default::default()`，inbound.rs:2131-2135） | `VisionConn` 硬编码 `DEFAULT_PADDING_SEED=[900,500,900,256]`（vision.rs:36，恰为 Go 缺省值） | ❌ **[P2-4]** |

### 表 1-2 inbound client（user 对象，Go `json.Unmarshal(rawUser, protocol.User)` + `vless.Account` proto）

| Go 字段 | Go 语义 | Rust 解析点 | Rust 消费点 | 判定 |
|---|---|---|---|---|
| `id` | UUID 必填，解析失败报错（vless.go:54-56） | inbound.rs:2126 | `UUID::parse` 失败→`InvalidUuid` 启动报错（account.rs:71） | ✅ |
| `email` | 唯一性：重复→**Add 报错→启动失败**（inbound/inbound.go:66-68） | inbound.rs:2127 | email_index（validator.rs:100-107）；重复→**warn+整用户跳过（UUID 不入表）**（inbound.rs:2133-2135） | ⚠️ **[P2-6]** |
| `level` | user.Level→policy 限速 | inbound.rs:2128 | MemoryUser.level 存储，policy 未接入（前轮已知 app 层键族） | ⚠️ |
| `flow` | ∈{`""`,XRV}，非法**报错**（vless.go:58-64）；运行时驱动 Vision | inbound.rs:2129 | server.rs:332（==XRV→Vision 包装 407-416）；**无配置校验** | ✅ 消费 ｜ 🔧 校验缺 **[P3-12]** |
| `encryption` | inbound **禁止非空**，报错（vless.go:83-85） | **硬编码 `"none"`** 忽略（inbound.rs:2131） | 无 | 🔧 **[P3-11]** |
| `alterId` | —（VLESS 无此字段，VMess 专属；account.proto 仅 id/flow/encryption/xorMode/seconds/padding/reverse/testpre/testseed） | 未解析 | 无 | N/A（两侧一致） |
| `xorMode`/`seconds`/`padding`（user 级 JSON 直设） | proto unmarshal 可带入 MemoryAccount | 未解析（ProtoAccount 硬编码默认） | 无 | ⚠️ **[P3-13]**（边缘） |
| `reverse`（inbound client） | tag 必填、禁 sniffing（vless.go:86-96） | 未解析（忽略该字段） | Rust reverse 走程序化 `ReverseRegistry`（register.rs:525-528），config 不接线 | ⚠️ |
| `testseed`（client 级） | `<4` 时被 settings 填充→VisionWriter | 未解析 | 同 P2-4 | ❌ **[P2-4]** |

### 表 1-3 inbound fallback 子结构（Go `vless.go:24-31` VLessInboundFallback）

| Go 字段 | Go 语义 | Rust 解析点 | Rust 消费点 | 判定 |
|---|---|---|---|---|
| `name` | SNI 匹配 | inbound.rs:2245 | FallbackPolicy 三级 map（handler.rs:22-29）→server.rs:313 | ✅ |
| `alpn` | ALPN 匹配 | inbound.rs:2246 | 同上 | ✅ |
| `path` | HTTP path 匹配；**必须空或以 `/` 开头**（vless.go:196-198） | inbound.rs:2247（无校验） | 同上 | ✅ 消费 ｜ 🔧 校验缺 **[P3-15]** |
| `type` | Go 自动推断 unix/`serve-ws-none`/tcp（vless.go:200-212）；unix socket/serve 型目标 | **完全忽略**（FallbackDest 无 type，inbound/handler.rs:33-38） | `fallback_to_dest` 直连 TCP（server.rs:315-317） | ❌ **[P2-8]** |
| `dest` | **number 或 string**；纯数字→`localhost:port`（vless.go:209-210） | inbound.rs:2248-2250 仅收 string；**number→warn 跳过整条**；纯数字串原样透传 | connect(fb.dest) | ❌ **[P2-8]** |
| `xver` | PROXY protocol 版本；**>2 报错**（vless.go:216-218） | inbound.rs:2251 `.min(2)` 钳制 | PROXY protocol 注入（server.rs:316） | ✅ 消费 ｜ 🔧 钳制 vs 报错 |

### ① 结论/发现（inbound）

- **[P2-1] `users` 旧名回退缺失（静默空用户表）**｜crates/xray-core/src/inbound.rs:2124｜Go `if c.Clients != nil { c.Users = c.Clients }`：clients 缺席时 users 生效；Rust 只读 `clients`，`{"users":[...]}` 配置→0 用户载入、启动成功、**所有连接认证拒绝**。同仓 trojan（inbound.rs:2211-2212）/socks（inbound.rs:2096-2098）都做了 `clients.or(users)`，唯 vless 漏做，证伪"有意设计"｜影响：legacy 配置全静默拒服｜修复：`v.get("clients").or_else(|| v.get("users"))` 一行对齐 trojan 写法。
- **[P2-3] settings 级 `flow` 继承断链**｜inbound.rs:2114-2137｜Go settings.flow 既校验又填充空 flow 客户端；Rust 生产零读取：`settings.flow="xtls-rprx-vision"` + client 无 flow→flow=""→不启用 Vision，静默降级｜影响：依赖继承的配置 Vision 静默关闭（抗指纹探测弱化）｜修复：validator 构建时 `flow = client.flow 或 settings.flow`，并复用 Go 白名单校验。
- **[P2-4] `testseed` 全链死字段**｜inbound.rs:2124-2136 + xray-proxy-vless/src/encryption/vision.rs:36｜Go：settings/client testseed→MemoryAccount→`NewVisionWriter(testseed)`（addons.go:71；`<4` 用缺省 `[900,500,900,256]`，proxy.go:307-309）；Rust：两级配置都不解析，`account.testseed` 字段存在但 VisionConn 恒用 `DEFAULT_PADDING_SEED` 常量（恰等 Go 缺省值，缺省行为无损，**自定义值静默失效**）｜影响：padding 量定制无效（抗指纹参数）｜修复：validator 透传 testseed→VisionConn 构造加种子参数。
- **[P2-6] 重复 email：warn+跳过 vs Go 启动失败**｜inbound.rs:2133-2135 + validator.rs:100-107｜Go `validator.Add` 报错→handler 初始化失败（inbound.go:66-68）；Rust `add()` 在 email 冲突时**先于 uuid_index 插入即返回 Err**，调用方仅 warn→该用户 UUID 未注册，运行期认证必拒且无启动级信号｜影响：静默单用户不可用｜修复：启动路径将 add 错误升级为构建失败（对齐 Go）。
- **[P3-10] `decryption` 缺省/空串静默按 none**｜inbound.rs:2161-2163｜Go 缺省报 `please add/set "decryption":"none"`（vless.go:158-161）；Rust `unwrap_or("none")`+空串放行（方向宽松，兼容本仓大量无 decryption 的测试配置）｜建议：保持宽容但启动时 info 提示。
- **[P3-11] inbound client `encryption` 非空不拒**｜inbound.rs:2131｜Go 报错（vless.go:83-85）；Rust 硬编码 none 忽略——脏配置静默吞｜修复：解析时校验报错。
- **[P3-12] flow 非法值不校验（双侧）**｜inbound.rs:2129 / outbound.rs:877｜Go 白名单（`""`/XRV[/XRV-udp443]）非法报错；Rust 生产路径无校验：inbound 任意 flow 静默按无 Vision；outbound 接受任意串（standalone handler outbound/handler.rs:114-122 有校验但生产走 dispatcher.rs 不经过）。注：Go 实际**拒绝 `"none"`**（出站 switch 仅 `""`/XRV/XRV-udp443，vless.go:288-297），Rust 反而接受 `"none"`（FLOW_NONE，lib.rs:35）——宽松方向偏离。
- **[P3-15] fallback 校验三缺**｜inbound.rs:2239-2256｜①`decryption!="none"`+fallbacks 互斥未查（Go vless.go:157-159 报错）②path 以 `/` 开头未校验 ③xver>2 钳制而非报错。

---

## ② outbound settings 级 + vnext/user + ENC 字段族

### 表 2-1 outbound settings 级（Go `vless.go:245-258` VLessOutboundConfig）

| Go 字段 | Go 语义 | Rust 解析点（生产） | Rust 消费点 | 判定 |
|---|---|---|---|---|
| `vnext` | **必须恰好 1 个**（vless.go:270-273） | outbound.rs:846-852（恰好 1 校验 ✅） | parse→VlessOutboundConfig→make_vless_dial_fn（outbound.rs:558-562） | ✅ |
| `address`/`port`/`level`/`email`/`id`/`flow`/`encryption`/`reverse`/`testpre`/`testseed`（**settings 级简化形态**，无 vnext 时） | Go：`c.Address!=nil` 时自动合成 vnext=[{address,port,users:[{}]}]，并把 id/flow/encryption/level/email/testpre/testseed/reverse 填入 user（vless.go:262-267,278-291,316-322） | **未实现**：outbound.rs:846-849 缺 vnext 直接报 `missing vnext array` | 无 | ❌ **[P2-2]** |
| `seed` | Go 解析进结构体但 Build 中**注释掉不消费**（vless.go:284 `//account.Seed = c.Seed`） | 未解析（outbound.rs 无 `seed` 读取） | 无 | ✅ 等价（Go 侧同为死字段） |

### 表 2-2 vnext 子结构 + user 对象（Go `VLessOutboundVnext` vless.go:239-243 + user unmarshal）

| Go 字段 | Go 语义 | Rust 解析点 | Rust 消费点 | 判定 |
|---|---|---|---|---|
| `vnext[].address` | 必填 | outbound.rs:855-858 | dial | ✅ |
| `vnext[].port` | uint16 | outbound.rs:861-864（u16 范围检查 ✅） | dial | ✅ |
| `vnext[].users` | **恰好 1 个**（vless.go:274-276） | outbound.rs:869-871 | 同上 | ✅ |
| `users[].id` | UUID 必填 | outbound.rs:873-875 + `UUID::from_str` | user_uuid | ✅ |
| `users[].flow` | ∈{`""`,XRV,XRV-udp443}（vless.go:288-297） | outbound.rs:877-878 | dispatcher.rs:193 addons.flow；==XRV→VisionConn（dispatcher.rs:215-217）；**无校验** | ✅ 消费 ｜ 🔧 校验缺（见 P3-12）+ udp443 偏差（见 P2-9） |
| `users[].encryption` | `none`/`mlkem768x25519plus.*`，非法**报错**（vless.go:300-318,371-374） | outbound.rs:879-882 + `parse_client_encryption`（params.rs:36-95）；**任何非法形态→None→静默按 none** | enc_params→ClientInstance::init(keys,xor_mode,seconds,padding)→ENC 握手（dispatcher.rs:148-155,175-178） | ✅ 消费 ｜ 🔧 非法值偏离 **[P2-7]** |
| `users[].level`/`email` | user.Level/Email→policy/stats | outbound.rs:884-886 读入局部变量后**丢弃**（未传入 VlessOutboundConfig，builder with_level/with_email 无人调） | 无 | ⚠️ 死读 **[P3-14]** |
| `users[].testpre` | →handler.testpre→**预连接池**（outbound/outbound.go:131,159-165） | 未解析 | `PreConnectPool` 已实现+单测（preconnect.rs:48-125）但 **config→池零接线**（parse_vless_config 不读、make_vless_dial_fn 不建池） | ❌ **[P2-5]** |
| `users[].testseed` | →MemoryAccount.Testseed→VisionWriter | 未解析 | 同 P2-4 | ❌ **[P2-4]** |
| `users[].reverse` | vnext 形态**显式拒绝**（vless.go:299-302，应走简化形态） | 未解析（不拒也不读） | 无 | ⚠️ |
| `users[].xorMode`/`seconds`/`padding`（JSON 直设） | proto unmarshal 带入（随后被 encryption 串解析覆盖/并存） | 未解析 | ENC 参数全部从 encryption 串派生 | ⚠️ **[P3-13]** |

### 表 2-3 ENC 字段族（Go 26.7 vless ENC：decryption 串 inbound / encryption 串 outbound）

| Go 字段/段 | Go 语义 | Rust 解析点 | Rust 消费点 | 判定 |
|---|---|---|---|---|
| 前缀 `mlkem768x25519plus` + 段数≥4 | 不满足→报错（server vless.go:158-166 / client vless.go:327-330） | params.rs:58,124（server 返回 None→build_vless_decryption 报错 ✅；client 返回 None→**静默 none** ⚠️） | — | ✅ server ｜ 🔧 client **[P2-7]** |
| `native`/`xorpub`/`random` → XorMode 0/1/2 | xorpub=1,random=2（vless.go:169-176/332-339） | params.rs:60-67,136-142 | ServerInstance::init（inbound.rs:2168-2170）/ClientInstance::init（dispatcher.rs:154）→XorConn（Go 同构层次 CommonConn{XorConn{conn}}，v54 已闭环） | ✅ |
| server 秒段 `<from>[-<to>]s` | SecondsFrom/To→0-RTT ticket 有效期窗口（vless.go:121-130） | params.rs:126-134（`s` 后缀可省、`-` splitn ✅） | ticket 协商 rand[from,to)/100（v46 SessionStore，server.rs:59-63 共享实例） | ✅ |
| client rtt 段 `1rtt`/`0rtt` | 0rtt→Seconds=1，1rtt→0（vless.go:340-347） | params.rs:69-75（同映射） | ClientInstance 0-RTT 会话 | ✅ |
| padding（短 part `<20` 字符累计 `len+1`） | 切片公式 `[27+len(s[2]):]` + `[:padding-1]`（vless.go:131-150/345-364；依赖 mode 恒 6 字符） | params.rs:78-95,144-152（**同一公式**，且 mode 白名单同为 6 字符→等价） | Server/ClientInstance init | ✅ |
| keys：client 32B(X25519 pub)/1184B(ML-KEM ek)；server 32B(X25519 seed)/64B(ML-KEM seed) | base64 RawURL，长度错→报错（vless.go:138-143/352-357） | params.rs:82-90,146-152（同长度白名单；**keys 为空→None**，server 报错 ✅ / client 静默 none ⚠️） | handshake | ✅ |
| tickets/0-RTT 会话、replay 防护 | Go server.go:36-41 Sessions | v46 已实装（SessionStore+FIFO+replay LoadOrStore 拒） | server.rs:227-234 handshake | ✅ |
| 互操作证据 | — | interop_enc.py 双向 4/4 PASS（v54）、0-RTT 会话 curl×3（v46） | — | ✅ |

### ② 结论/发现（outbound/ENC）

- **[P2-2] outbound 简化形态（settings 级 address/port/id/flow/encryption/level/email/reverse/testpre/testseed）整体未实现**｜crates/xray-core/src/outbound.rs:846-849｜Go `c.Address!=nil` 合成 vnext（vless.go:262-267）；Rust 缺 vnext 直接构建失败（**响亮报错**，非静默）｜影响：该形态配置全部拒启（v26 文档化写法之一）｜修复：parse_vless_config 先查 settings 级 address 合成 vnext 再走同一解析。
- **[P2-5] `testpre` 预连接未接线**｜outbound.rs:844-895（不读 testpre）+ crates/xray-proxy-vless/src/outbound/preconnect.rs:48-125（池实现完整、仅单测引用）｜Go outbound.go:131/159-165 按 testpre 预建 N 连接省握手延迟；Rust 生产零接线→配置静默失效（性能特性，非正确性）｜修复：parse_vless_config 读 testpre→make_vless_dial_fn 建 PreConnectPool 并在 dial 前 acquire/fill_deficit。
- **[P2-7] outbound 非法 `encryption` 静默按 none**｜outbound.rs:893-894 + params.rs:36-43｜Go 任何非法形态（含缺省空串、`mlkem768x25519plus.*` 写错 mode/rtt/keys）→**配置报错**（vless.go:371-374）；Rust `parse_client_encryption` 对全部非法形态返回 None→当 "none" 用→对 ENC 服务器握手期才以难懂错误失败｜影响：配置期校验缺口、排障成本高｜修复：`encryption!="" && !="none" && parse==None` 时报错（保留缺省=none 的宽容）。
- **[P2-9] flow `xtls-rprx-vision-udp443` 静默降级为普通 VLESS**｜dispatcher.rs:193,215 + encoding/mod.rs:206｜Go outbound.go:251-255：XRV-udp443→allowUDP443=true 且**截断为 XRV 走 Vision**；Rust 生产：≠XRV→不包 VisionConn、addons.flow 非 XRV→线上写空 addons（服务器视为无 flow）→客户端既无 Vision 也无 UDP443 直连语义，配置被接受且无告警｜影响：伪装/padding 丢失 + UDP443 直连策略失效｜修复：识别 `-udp443` 后缀→按 XRV 处理 + 本地 UDP443 直连标记（路由层后续接线）。
- **[P3-13] user 级 `xorMode`/`seconds`/`padding` JSON 直设被忽略**｜inbound.rs:2131-2135 / outbound.rs:877-886｜Go proto unmarshal 可带入（v26.7 实际依赖 encryption 串派生，属边缘写法）。
- **[P3-14] outbound `level`/`email` 死读**｜outbound.rs:884-886｜读入局部变量后丢弃；VlessOutboundConfig 有字段+builder（dispatcher.rs:56-57,113-121）但 parse 不传、stats/policy 无消费（app 层已知缺口）。
- **[P3-16] ENC 前缀族之外的 `seed`（outbound）**：Go 注释掉不消费（vless.go:284），Rust 不解析——**行为等价，双端皆死，无需修**。

---

## ③ realitySettings 双侧盘点（任务指定"已知项勿重复报，表里列出"）

已知项（前四轮已报，本轮仅列状态，不重复开缺陷）：**maxTimeDiff 三重偏差、minClientVer/maxClientVer 断链、uTLS 指纹清单缺 android/randomized**。

### 表 3-1 inbound `realitySettings`（Go `transport_security.go:25-52` REALITYConfig 服务端侧）

| Go 字段 | Go 语义 | Rust 解析点（inbound.rs:1434-1490） | 判定 |
|---|---|---|---|
| `dest`/`target` | 必填；int→localhost:port；`@`/`/`→unix 类型；缺失报错（Build:62-92） | 解析 target/dest（int/string），缺省静默 `localhost:443`；unix 形态不支持 | ⚠️ 🔧【已知组】 |
| `type` | unix/tcp 推断结果 | 未解析 | ❌【已知组】 |
| `xver` | >2 报错 | `.min(2)` 钳制（inbound.rs:1472） | 🔧【已知组】 |
| `serverNames` | **必填**+SNI 白名单校验（Build:95-97） | **未解析未校验**（server_tls 无 SNI 参数，xray-reality/server.rs:313-318） | ❌【已知组】 |
| `privateKey` | base64url 32B 必填 | inbound.rs:1439-1446（32B 校验 ✅） | ✅ |
| `shortIds` | hex≤16 字符；非法报错；**空列表报错**（Build:141-149） | hex_decode_8 解析 ✅；非法条目**静默跳过**；空列表→默认全零白名单（inbound.rs:1457-1460） | ⚠️【已知组】 |
| `maxTimeDiff` | 默认 43200 | inbound.rs:1478-1480 解析（默认 43200 ✅） | ⚠️【已知：三重偏差】 |
| `minClientVer`/`maxClientVer` | 版本门槛（默认 26.3.27） | 未解析 | ❌【已知：断链】 |
| `mldsa65Seed` | v26.7 后量子签名 seed（Build:154+） | 未解析 | ❌ **[P3-17] 新发现** |
| `masterKeyLog`/`limitFallbackUpload`/`limitFallbackDownload` | SSLKEYLOG 调试/fallback 限速 | 未解析 | ❌ [P3-17]（info 级） |

### 表 3-2 outbound `realitySettings`（客户端侧，xray-reality/src/register.rs:99-145）

| Go 字段 | Go 语义 | Rust 解析点 | 判定 |
|---|---|---|---|
| `serverName` | 必填 SNI | register.rs:113-115 | ✅ |
| `publicKey` | base64url 32B 必填 | register.rs:117-127 | ✅ |
| `shortId` | hex 可空 | register.rs:131-139 | ✅ |
| `fingerprint` | uTLS 指纹（默认 chrome） | register.rs:128-129 | ⚠️【已知：清单缺 android/randomized】 |
| `spiderX` | 爬虫路径伪装 | 未解析 | ❌【已知组】 |
| `mldsa65Verify`/`password` | v26.7 后量子验证 | 未解析 | ❌ [P3-17] |
| `show` | 调试显示 | 未解析 | ❌（info 级，随 P3-17 归档） |

---

## ④ 确认干净清单（逐字段验证为 ✅ 的部分）

1. inbound `clients[].id`：解析+UUID 校验失败报错，与 Go 等价（inbound.rs:2126 + account.rs:71）。
2. inbound `decryption` 合法 ENC 串全链：mode→XorMode、秒段→ticket 窗口、padding 切片公式（与 Go 逐字节同构）、keys 长度白名单、ServerInstance 握手/replay 防护（v46/v54 互操作 4/4 实证）。
3. outbound `encryption` 合法 ENC 串全链：1rtt/0rtt→seconds、32B/1184B keys、ClientInstance 握手（dispatcher.rs:148-178）。
4. outbound `vnext`/`users` 恰好 1 个的强制校验（outbound.rs:851,869，对齐 vless.go:270-276，含对齐文案）。
5. outbound `vnext[].address/port`、`users[].id` 解析与拨号消费。
6. inbound/outbound `flow==XRV` 的 Vision 通路（server.rs:332/407-416、dispatcher.rs:215-217）。
7. fallback `name/alpn/path` 三级匹配与 PROXY protocol `xver` 注入（handler.rs:22-29、server.rs:313-317）。
8. REALITY inbound `privateKey`/`shortIds`(hex)/`dest`(int→localhost:port) 与 outbound `serverName`/`publicKey`/`shortId`。
9. outbound `seed`：Go 侧注释死字段，Rust 不解析=行为等价（无需修）。
10. `alterId`：VLESS 无此字段（VMess 专属），两侧一致 N/A。

## ⑤ 统计

- **字段级表格规模**：7 张表 ≈ **70 行字段**（inbound settings 6 + fallback 6 + client 9 + outbound settings 3 + vnext/user 10 + ENC 8 + reality 17）。
- **判定分布**：✅ 生效 34 ｜ ⚠️ 解析未消费/部分 11 ｜ ❌ 未解析/未接线 13 ｜ 🔧 默认值或校验偏离 10 ｜ N/A 2（多数字段双判定并列，按主判定计）。
- **缺陷统计（本轮新发现，排除前四轮已知项）**：P0=0，P1=0，**P2=8，P3=9**；其中正确性/可用性静默类 6（P2-1/3/4/6/8/9），配置期校验缺口 2（P2-2 响亮报错可接受度较高、P2-7 静默降级），接线缺失 1（P2-5）。
- **TOP3**：
  1. **[P2-1] `users` 旧名回退缺失**——唯一"启动成功但全量拒绝服务"的静默故障，且同仓 trojan/socks 均已做回退，一行可修。
  2. **[P2-8] fallback `dest` number 类型丢弃 + `type` 全忽略**——Go 合法配置（`"dest":8080`、unix socket、`serve-ws-none`）在 Rust 静默失效或运行期连接失败，fallback 作为 TLS 伪装防线整体打折。
  3. **[P2-3] settings 级 `flow` 继承断链**——合法惯用写法静默关闭 Vision，抗探测能力下降且无任何告警。
