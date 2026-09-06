# 配置全链审计（第五轮）：QUIC / KCP / Hysteria(2) / TUIC / WireGuard / Naive / AnyTLS / DomainSocket

- 日期：2026-09-06 ｜ 基准：Go `D:/Project/Xray-core`（infra/conf/*.go，v26.7.28 口径）vs Rust `D:/Project/Xray-core-rust`
- 方法：对每个协议 ①列 Go infra/conf 该协议 Config 全部 JSON 字段 → ②读 Rust parse 结构体逐字段比对键名 → ③grep 生产消费点（inbound.rs / outbound.rs / dispatcher / dialer / hub）→ ④字段级判定
- 判定图例：✅生效 ｜ ⚠️解析未消费 ｜ ❌未解析 ｜ 🔧默认值/校验偏离 ｜ 🧩Rust 扩展（Go v26 无此协议/键）

## 0. Go v26 基线关键事实（决定多张表的判定口径）

| 事实 | Go 证据 | 对 Rust 的影响 |
|---|---|---|
| QUIC 传输已移除：`network:"quic"` → `PrintRemovedFeatureError` | infra/conf/transport_internet.go:25-30（Build 分支 :990-991） | Rust 保留 QUIC 传输 = **扩展**（Rust 在 xray-transport/src/dialer.rs:390-394 仅 warn 不阻断） |
| mkcp header & seed 已移除：出现即硬报错 | transport_method.go:539-543 | Rust 同样硬报错（对齐） |
| congestion/readBufferSize/writeBufferSize 三键在 v26 结构体中**不存在** | transport_method.go:523-531（无此字段） | Go json 忽略未知键 ≈ Rust 忽略；差异仅在 Rust 文档注释失真 |
| domainsocket 传输整体移除 | transport/internet/ 无 domainsocket 目录；infra/conf 全库 grep 零命中 | Rust 键映射保留但无实现（见 §7） |
| hysteria 传输 congestion/up/down/udphop 弃用告警（迁 finalmask/quicParams），version!=2 硬报错 | transport_method.go:765-792 | Rust 静默忽略 + 不校验 version（见 §3） |
| QUIC 参数族真实归属 = finalmask.quicParams | transport_finalmask.go:930-946（QuicParamsConfig） | Rust quic_params.rs 全字段对齐（见 §3.4） |
| TUIC / Naive / AnyTLS 在 Go 全库零引用 | grep `"naive"|"anytls"|"tuic"` 无匹配 | 三者均为 Rust 扩展，审结构与文档一致性 |

---

## 1. kcpSettings（双侧行为一致：dial 与 listen 共用 parse_kcp_config，xray-transport-kcp/src/register.rs:151/:77）

Go 基线：`KCPConfig`（infra/conf/transport_method.go:523-569）。Rust 解析：`parse_kcp_config`（register.rs:221-266），产物 `prost kcp::Config`（config.rs:16-23 默认值 = Go init()：mtu 1350/tti 50/up 5/down 20/cwnd 1/maxSendingWindow 2MiB）。

| 字段 | Go v26 语义 | Rust 解析名/位置 | inbound 消费 | outbound 消费 | 判定 |
|---|---|---|---|---|---|
| mtu | u32；Build 校验 ≥21（:550-551） | `mtu` register.rs:242-243 | listener→Kcp 状态机 ✅ | dial→Kcp 状态机 ✅ | ✅生效，🔧缺校验 |
| tti | u32；校验 10..=1000（:552-554） | `tti` register.rs:244-245 | ✅（读侧 interval） | ✅ | ✅生效，🔧缺校验 |
| uplinkCapacity | u32（:525-526） | `uplinkCapacity` register.rs:246-247 | ✅（ConfigExt 发送窗口） | ✅ | ✅ |
| downlinkCapacity | u32（:527） | `downlinkCapacity` register.rs:248-249 | ✅（接收窗口） | ✅ | ✅ |
| cwndMultiplier | u32；校验 ≥1（:555-557） | `cwndMultiplier` register.rs:250-251 | ✅ | ✅ | ✅生效，🔧缺校验 |
| maxSendingWindow | u32；校验 GetSendingBufferSize()!=0（:558-559） | `maxSendingWindow` register.rs:252-253 | ✅ | ✅ | ✅生效，🔧缺校验 |
| congestion | v26 无此键（json 静默忽略） | **不解析**；doc 注释 :216 声称接受 | — | — | 🔧文档失真（行为与 Go 等价） |
| readBufferSize | v26 无此键 | **不解析**；doc 注释 :217 声称接受 | — | — | 🔧文档失真 |
| writeBufferSize | v26 无此键 | **不解析**；doc 注释 :218 声称接受 | — | — | 🔧文档失真 |
| header | 移除；出现硬报错（:539-543） | register.rs:231-237 硬报错，文案对齐 `removed_feature_message` | — | — | ✅对齐移除语义 |
| seed | 同上 | register.rs:231-237（同一分支） | — | — | ✅对齐移除语义 |

### 1.1 header 伪装类型族（Rust 真身在 finalmask，不在 kcpSettings）

Go v26：kcpSettings.header 移除后，header 族迁移到 `finalmask.udp[] type:"mkcp-legacy"`，实现于 transport/internet/finalmask/mkcp/header/（ID 0-5）。Rust：`HeaderId`（xray-transport/src/finalmask/mkcp/header.rs:26-33）+ `build_mkcp_legacy_udpmask`（finalmask/mod.rs:643-670）。

| header id | Go finalmask ID | Rust HeaderId | 消费点 | 判定 |
|---|---|---|---|---|
| dns | 0 | Dns=0 | mkcp-legacy 链 encode/decode ✅（双侧） | ✅对齐 |
| dtls | 1 | Dtls=1 | 同上 | ✅对齐 |
| srtp | 2 | Srtp=2 | 同上（tests/mask_roundtrip.rs:30-33 双 mask 叠加回归） | ✅对齐 |
| utp | 3 | Utp=3 | 同上 | ✅对齐 |
| wechat | 4 | Wechat=4 | 同上 | ✅对齐 |
| wireguard | 5 | Wireguard=5 | 同上 | ✅对齐 |
| none/strip（旧 kcp header type none→noop） | v26 finalmask **无此变体** | 同样无（空 header + value 走 aes128gcm 分支，mod.rs:643-644） | — | ✅对齐（Go 亦删） |

注：`xray-transport/src/headers/{srtp,utp,wechat,dtls,wireguard,noop}.rs` 为**零消费死代码**（TCP header 认证只支持 http，conn.rs:541 测试断言 type=srtp 报错）——见 §8 P3。

---

## 2. quicSettings（🧩Rust 扩展：Go v26 已移除该传输）

Rust 解析：`QuicConfig::from_json`（xray-transport-quic/src/config.rs:35-58）；消费：dial transport.rs:63+72、listen transport.rs:107+118。

| 字段 | Go 语义（移除前/扩展口径） | Rust 解析 | inbound 消费 | outbound 消费 | 判定 |
|---|---|---|---|---|---|
| keepAlive | 旧 Go quic keep-alive | `keepAlive` config.rs:48-53 | ✗（零读点） | ✗ | ⚠️解析未消费（扩展域，P3） |
| congestion | —（Rust 扩展：bbr/cubic/new_reno） | `congestion` config.rs:53-56 | ✅ build_transport_config（:107-118） | ✅（:63-72） | ✅（扩展） |
| security | QUIC 强制 tls | stream 层 `security` | 强制校验 tls（transport.rs:96-105） | 同（:44-56） | ✅（扩展） |
| key | 旧 Go quic 密钥混淆 | 不解析 | — | — | 🧩不支持（quinn 无 header 混淆，config.rs:20 注释明示） |
| header(type) | 旧 Go quic 头伪装 | 不解析 | — | — | 🧩不支持（同上） |

另：`network:"quic"` 在 Rust 走 removed_feature_warnings 仅告警（dialer.rs:390-394），与 Go 硬报错不同——属 §0 既定宽容策略。

---

## 3. Hysteria / hysteria2

### 3.1 hysteriaSettings（传输层，Go infra/conf/transport_method.go:761-807）

Rust 解析：`parse_hysteria_config`（xray-transport-hysteria/src/register.rs:271-317，dial 路径消费 :193）。

| 字段 | Go 语义 | Rust 解析 | 消费 | 判定 |
|---|---|---|---|---|
| version | 必须 =2 否则 error（:779-781） | `version` 读入（:298-301），**无校验** | 无消费 | 🔧默认值偏离（P2-4） |
| auth | 鉴权 token | `auth`（:281-284） | Hysteria-Auth 头 ✅ | ✅ |
| congestion | 弃用：warn 后迁 finalmask（:782-784） | 不解析（静默） | — | 🧩静默（Go 至少 warn，行为无害） |
| up / down | 弃用：同上 | 不解析 | — | 🧩同上 |
| udphop | 弃用：同上 | 不解析 | — | 🧩同上 |
| udpIdleTimeout | 2..=600 校验，默认 60（:788-792） | `udpIdleTimeout` 默认 60（:285-289） | 仅出站 dial 读（客户端无意义）；**入站不读** | ⚠️入站缺失（P2-6/7） |
| masquerade{type,dir,url,rewriteHost,insecure,content,headers,statusCode} | 服务端伪装 | `masquerade`/`masqType` → apply_masquerade_json | inbound：MasqType::from_config ✅（inbound.rs:2543-2554）；outbound 解析但无害（服务端概念） | ✅入站生效 |

### 3.2 hysteria/hysteria2 入站 settings（proxy 层，Go HysteriaServerConfig infra/conf/hysteria.go:33-68）

Rust：`parse_hysteria_inbound_config`（xray-core/src/inbound.rs:2520-2562）；kind 别名 `"hysteria"|"hysteria2"`（inbound.rs:1984，别名🧩扩展）。

| 字段 | Go 语义 | Rust 解析 | 消费 | 判定 |
|---|---|---|---|---|
| auth（单字符串） | —（Go 无顶层 auth，走 users[]） | `auth`（:2529） | StaticAuthValidator 单 token ✅ | ✅（🧩形态差异） |
| users[]/clients[][{auth,level,email}] | 多用户 + Validator | **不解析**（MultiUserValidator/HysteriaInboundConfig.users 已实现但核心装配不构造，proxy config.rs:274+/:436+） | 能力在场、链路断 | ❌未解析（P2-6） |
| version | 必须 =2 | 不读 | — | 🔧（并入 P2-4） |
| server_name | — | 🧩扩展键（:2530） | TLS SNI ✅ | 🧩 |
| cert/key（PEM 内联） | — | 🧩扩展键（:2587-2592） | quinn TLS server ✅；缺省自签 | 🧩 |

### 3.3 hysteria 出站 settings（proxy 层，Go HysteriaClientConfig hysteria.go:13-30）

Rust：`parse_hysteria_config`（xray-core/src/outbound.rs:1895-1917）→ 装配（outbound.rs:612-634）。

| 字段 | Go 语义 | Rust 解析 | 消费 | 判定 |
|---|---|---|---|---|
| servers[0].address/port | server endpoint | ✅（:1898-1904） | 拨号地址 ✅ | ✅ |
| auth（别名 password） | —（Go 走 users） | ✅ `auth` 或 `password`（:1905-1908） | Hysteria-Auth ✅ | ✅ |
| serverName/server_name/sni | — | ✅三拼写（:1909-1913） | TLS SNI ✅ | ✅ |
| version | 必须 =2 | 不读 | — | 🔧（并入 P2-4） |
| insecure/certificate | — | **不解析**；rustls 恒 NoVerifier（outbound.rs:616-618） | 证书校验永远跳过 | 🧩安全口径（无键位，恒 insecure）——随 P3 备案 |

### 3.4 finalmask.quicParams（Go transport_finalmask.go:930-946 + transport_internet.go Build quicParams 段的 Rust 对应）

Rust：`parse_quic_params`（xray-transport-hysteria/src/quic_params.rs:32-155）；消费：inbound inbound.rs:2533-2537 → HysteriaConfig.quic_params；outbound outbound.rs:624-630；终值进 quinn TransportConfig/CC 槽（quinn_adapter.rs:274-310）。

| 字段 | Go 校验/语义 | Rust | 判定 |
|---|---|---|---|
| congestion（""/brutal/reno/bbr/force-brutal） | force-brutal 需 up | :116-131 同校验 | ✅ |
| bbrProfile（conservative/standard/aggressive，空→standard） | 小写化 | :60-73 | ✅ |
| brutalUp/brutalDown（Bandwidth 串；>0 时 ≥65536） | "100 mbps"→Bps | :52-64 + parse_bandwidth_bps | ✅ |
| udpHop.ports / .interval（PortList/Int32Range，interval ≥5） | 数字/区间/列表 | :85-101 | ✅ |
| init/Max Stream/Connection ReceiveWindow（>0 时 ≥16384） | 四窗口 | :103-111 | ✅ |
| maxIdleTimeout ∈[4,120]∪{0}、keepAlivePeriod ∈[2,60]∪{0} | 秒 | :113-122 | ✅ |
| maxIncomingStreams（>0 时 ≥8） | — | :123-126 | ✅ |
| disablePathMTUDiscovery | bool | :129-134 | ✅ |
| debug | 设 HYSTERIA_*_DEBUG 环境变量 | :151-152 解析后**忽略**（无 env 日志门面） | ⚠️解析未消费（自觉注释备案） |

**quicParams 全族双侧消费对称，13/13 对齐 Go，是本轮质量最高的一段。**

### 3.5 hysteria2 惯例键（任务点名：obfs/obfsPassword）

| 键 | Go | Rust | 判定 |
|---|---|---|---|
| obfs/obfsPassword | Go 无 | 结构体能力在（HysteriaConfig.obfs + with_obfs，proxy config.rs:115-119）但**无 JSON 入口**（仅测试调用）；实际混淆入口 = finalmask.udp[] salamander（outbound.rs:620-622 / inbound.rs:2557-2559 双侧 ✅） | ❌键未解析（P2-8）；功能经 finalmask 等价可用 |

---

## 4. TUIC（🧩Rust 扩展，Go 全库零引用；键名对齐官方 tuic-client snake_case）

### 4.1 出站（xray-core/src/outbound.rs:1946-2012 解析；:643-665 装配 TuicConnectOptions + build_tuic_rustls_config）

| 字段 | Rust 解析 | 消费 | 判定 |
|---|---|---|---|
| servers[0].address / port | :1954-1959 | server_addr（域名保留到 dial 时解析） ✅ | ✅ |
| uuid | :1960-1964（格式校验） | Authenticate ✅ | ✅ |
| password | :1965-1966 必填 | Authenticate ✅ | ✅ |
| server_name | :1967-1968（默认=address） | SNI ✅ | ✅ |
| congestion_control（bbr/cubic/new_reno） | :1971-1977 非法值硬报错 | TuicConnectOptions.congestion_control ✅（outbound.rs:647） | ✅ |
| alpn | :1978-1983；空→[h3,tuic] | rustls alpn ✅（:2044-2048） | ✅ |
| reduce_rtt / zero_rtt_handshake（别名） | :1986-1989 双拼写 | rustls resumption 开关 ✅（:2050-2057） | ✅ |
| udp_relay_mode（native/quic） | :1990-1996 非法硬报错 | TuicConnectOptions.udp_relay_mode ✅ | ✅ |
| heartbeat | :1997 默认 3s | TuicConnectOptions.heartbeat ✅ | ✅ |
| insecure | :1998 | NoVerifier ✅（:2032-2036） | ✅ |
| certificate（PEM） | :1999 | 附加信任根 ✅（:2038-2053） | ✅ |
| fingerprint | :2000-2002 warn 显式忽略 | —（rustls 无 uTLS） | ⚠️显式告警忽略（合理备案） |

### 4.2 入站（xray-core/src/inbound.rs:2732-2762 → TuicInboundHandler）

| 字段 | Rust 解析 | 消费 | 判定 |
|---|---|---|---|
| uuid / password | 必填硬校验（:2738-2744） | Authenticate ✅ | ✅ |
| serverName | camelCase（:2745-2747，与出站 server_name 风格不一致） | SNI/自签 CN ✅ | ✅（🔧风格混用 P3） |
| certificate/cert + key | **无 JSON 入口**：TuicInboundConfig.cert_der/key_der 恒 None（:2749-2751）→ 永远自签（xray-proxy-tuic/src/inbound.rs:119-130） | — | ❌入站证书键缺失（P3） |
| congestion_control 等服务端参数 | 不解析（官方 tuic server 有 congestion_control；Rust CC 仅出站语义） | — | 🧩扩展口径备案 |

---

## 5. WireGuard（Go 基线：infra/conf/wireguard.go:17-68）

Rust：出站 `parse_wireguard_config`（xray-core/src/outbound.rs:2064-2086）；入站 `parse_wireguard_inbound_config`（inbound.rs:2650-2685）。结构体全字段在（xray-proxy-wireguard/src/config.rs:102-136），消费链路多数已建，**断点全在 JSON 解析层**。

| 字段 | Go 语义 | Rust 解析 | inbound 消费 | outbound 消费 | 判定 |
|---|---|---|---|---|---|
| secretKey | 必填，base64/hex | ✅ 两侧必填（outbound.rs:2066-2067 / inbound.rs:2653-2655） | ✅ | ✅ | ✅ |
| peers[].publicKey | 必填 | ✅（出站必填；入站缺省空串） | ✅ user/peer 会话 | ✅ | ✅ |
| peers[].endpoint | `host:port` | ✅（出站必填；入站缺省空串） | 监听对端 | resolve_endpoint_addr（proxy outbound.rs:80-155，域名走 DNS+domainStrategy） | ✅ |
| peers[].preSharedKey | 可选 PSK | ❌ 不读 | Tunnel::from_config 消费在场（tunnel.rs:125-130） | 同 | ❌未解析（P1-2） |
| peers[].keepAlive | 秒，0=禁 | ❌ 不读 | 消费在场（tunnel.rs:112-124） | 同 | ❌未解析（P1-2） |
| peers[].allowedIPs | 默认 ["0.0.0.0/0","::0/0"] | ❌ 不读（恒空） | 入站路由 CIDR 消费在场（proxy inbound.rs:102-106） | 出站单 peer 传空表 | ❌未解析（P1-2） |
| peers[].level/email | user 元数据 | ❌ 不读 | — | — | ❌未解析（Go server 用户记账用） |
| address | interface 地址（CIDR） | ✅ 两侧；默认 `10.0.0.2/32` | netstack 本机地址 ✅ | ✅ | 🔧默认值偏离 Go bogon（10.0.0.1 + fd59:…:1，wireguard.go:86-90） |
| mtu | 默认 1420 | ❌ 不读（JSON 恒缺→effective_mtu 恒 1420，config.rs:143-148） | netstack MTU 消费在场（proxy inbound.rs:121） | 同（proxy outbound.rs:108-109） | ❌未解析（P1-2） |
| reserved | 空或 3 字节（校验 :118-121） | ❌ 不读（恒空） | driver.set_reserved 消费在场（proxy outbound.rs:114；收发 wire format dispatcher.rs:427-441） | 同 | ❌未解析——**Warp 场景功能性失效**（P1-2） |
| domainStrategy | FORCE_IP/IP4/IP6/IP46/IP64 | ❌ 不读（恒 ForceIp） | — | endpoint DNS 解析消费在场（proxy outbound.rs:155） | ❌未解析（P1-2） |
| noKernelTun | 强制 userspace | ❌ 不读 | Rust 恒 smoltcp userspace netstack（语义天然满足） | 同 | 🧩语义性 no-op |
| port（inbound 监听 UDP） | Go 用 inbound port | 🧩settings `port` 默认 51820（inbound.rs:2678-2679） | UDP bind ✅ | — | 🧩 |
| is_client / num_workers | proto 字段（Go conf 无 num_workers 键） | ❌ 不读（is_client 恒 false；num_workers 恒 0→CPU 数，driver.rs:65-74） | num_workers 消费在场（proxy inbound.rs:124-125） | 同（proxy outbound.rs:110-112） | ❌未解析（P3） |

---

## 6. Naive / AnyTLS（🧩Rust 扩展；审配置结构与文档一致性）

### 6.1 Naive（仅出站；xray-transport-naive/src/uri.rs:39-61 + core outbound.rs:1824-1834/:726-730）

| 字段 | 文档口径（uri.rs:37 注释） | 解析 | 消费 | 判定 |
|---|---|---|---|---|
| server | ✅ | 必填（:41） | host ✅ | ✅ |
| port | ✅ | 必填+u16 范围（:42-44） | ✅ | ✅ |
| username / password | ✅ | 必填（:45-46） | Basic auth ✅ | ✅ |
| sni | ✅ | 可选，默认=host（:48-50） | TLS SNI ✅ | ✅ |
| fingerprint | ✅ | 可选，默认 HelloChrome133（uri.rs:26；:173-181 测试锚定） | uTLS 指纹 ✅ | ✅ |
| 入站 | — | 无（naive 语义 client-only） | — | 🧩合理 |

结构与文档注释一致，无缺陷。

### 6.2 AnyTLS

出站（xray-core/src/outbound.rs:1776-1821，ClientConfig client.rs:34-52）：

| 字段 | 解析 | 消费 | 判定 |
|---|---|---|---|
| server / server_port | 必填（:1778-1787） | 地址 ✅ | ✅ |
| sni | 可选默认=server（:1788-1791） | SNI ✅ | ✅ |
| insecure | 可选（:1792-1795） | NoVerifier vs webpki 根 ✅ | ✅ |
| password | 可选缺省空（:1796-1799） | sha256 后发认证帧 ✅（client.rs:83-112） | ✅ |
| idle_check_interval/idle_timeout/min_idle_sessions | 无 JSON 入口（硬编码推荐值 client.rs:64-66） | 会话池 ✅ | 🧩备案 |

入站（xray-core/src/inbound.rs:2606-2649 + :1988-2001）：

| 字段 | 解析 | 消费 | 判定 |
|---|---|---|---|
| cert / key（PEM） | ✅；缺省自签 | TLS acceptor ✅ | ✅ |
| **password** | ❌ **无此键**；AnytlsMockServer 读掉认证帧**不校验** sha256（server.rs:109-113「mock 不校验密码」） | — | ❌**入站零认证**（P1-1，本轮最高危） |

---

## 7. domainsocket / dsSettings

| 项 | Go v26 | Rust | 判定 |
|---|---|---|---|
| 传输本体 | 已移除（transport/internet 无目录，conf 零引用） | **无实现**：全仓库无 register_transport_dialer/listener("domainsocket") | 🧩半成品（P2-3） |
| network:"domainsocket" 键映射 | —（报移除错误） | protocol_settings_key 映射在（dialer.rs:341），dsSettings 值会装入 transport_json（dialer.rs:157-190） | ❌映射在、消费死 |
| 运行时行为 | 配置期硬报错 | 拨号/监听时 NotFound："domainsocket dialer not registered"（dialer.rs:471-478）；**启动期不报错** | 🔧与 Go 移除语义偏离 |
| dsSettings 字段族（path/abstract） | — | 无任何解析器读取 | ❌未解析（无从谈起） |

---

## 8. 缺陷清单（P0/P1/P2/P3 ｜ file:line ｜ 证据 ｜ 影响 ｜ 修复建议）

**P0**：无。

**P1**
1. [P1] crates/xray-proxy-anytls/src/server.rs:109-113（+ xray-core/src/inbound.rs:2606-2649、client.rs:83-112）｜入站 settings 只解析 cert/key，无 password 键；MockServer 读掉 34B 认证帧头后注释自述「mock 不校验密码」｜anytls 入站对任意密码客户端开放=公开转发器；出站/入站认证不对称｜settings 增加 password → handler 携带 sha256 期望 → 读完认证帧常数时间比对，不匹配即拒。
2. [P1] crates/xray-core/src/outbound.rs:2064-2086 + inbound.rs:2650-2685（Go 基线 wireguard.go:17-68）｜wireguard JSON 只读 secretKey/peers[].{publicKey,endpoint}/address；preSharedKey/keepAlive/allowedIPs/mtu/reserved/domainStrategy 六键静默丢弃，而消费链路全部在场（tunnel.rs:125-130、proxy inbound.rs:102-106/:121、proxy outbound.rs:108-115/:155、dispatcher.rs:427-441）｜reserved 恒空 → Cloudflare Warp 类节点直接不可用；mtu/allowedIPs/PSK/keepalive/domainStrategy 全部假默认｜两侧解析补六键；reserved 校验空或 3 字节（对齐 Go :118-121）；allowedIPs 缺省补 Go 默认双全零路由。

**P2**
3. [P2] crates/xray-transport/src/dialer.rs:341（+ :471-478）｜"domainsocket"→"dsSettings" 键映射保留但无 transport 注册，运行时 NotFound、启动期静默｜遗留配置带病启动、首次连接才失败；与 Go 移除语义（配置期报错）不符｜实现 Unix socket dialer/listener，或删映射 + removed_feature_warnings 报移除文案。
4. [P2] crates/xray-transport-hysteria/src/register.rs:298-301（Go transport_method.go:779-781、hysteria.go:20-23/46-49）｜hysteria version 读入默认 0 后不校验 ≠2，proxy 两侧也不读｜version:1/3 非法配置静默运行，掩盖配置错误、破坏与 Go 的版本互斥语义｜transport+proxy 解析处补 `version != 0 && version != 2` 硬报错。
5. [P2] crates/xray-transport-kcp/src/register.rs:221-266（Go transport_method.go:549-560）｜六字段直通无 mtu≥21/tti∈[10,1000]/cwndMultiplier≥1/发送缓冲非0 校验；且 :216-218 doc 注释声称接受 congestion/readBufferSize/writeBufferSize（实际不读，Go v26 亦无此三键）｜畸形配置带病运行（部分被 ConfigExt clamp 吸收，config.rs:40-45）；文档失真误导｜补四项 Go 阈值校验；删失真注释。
6. [P2] crates/xray-core/src/inbound.rs:2520-2562（Go hysteria.go:33-68）｜hysteria 入站不解析 users[]/clients[]/level/email 与 settings 级 udpIdleTimeout（Go 2..=600 校验默认 60，transport_method.go:788-792；Rust 仅出站 transport dial 读、客户端语义无效，register.rs:285-289）；MultiUserValidator+HysteriaInboundConfig 能力在场（proxy config.rs:274+/:436+）但核心装配不构造｜多用户入站不可用（仅单 token）；UDP 空闲超时不可配｜parse 补 users/clients → new_with_inbound_config 装配 MultiUserValidator；补 udpIdleTimeout。
7. [P2] crates/xray-proxy-hysteria/src/config.rs:115-119（with_obfs 仅测试调用）｜hysteria2 惯例键 obfs/obfsPassword 无 JSON 入口；混淆真实入口=finalmask.udp[] salamander（outbound.rs:620-622 / inbound.rs:2557-2559 双侧 ✅）｜hysteria2 惯例用户静默无混淆｜兼容读 obfs/obfsPassword → salamander，或文档明示迁移键。

**P3**
8. [P3] crates/xray-core/src/outbound.rs:1946-2012 vs inbound.rs:2732-2762｜TUIC 出站 snake_case 对齐官方 tuic-client、入站却用 serverName；入站 cert_der/key_der 字段在（xray-proxy-tuic/src/inbound.rs:37-40）但无 JSON 入口恒自签（:119-130）｜键名风格混用；入站无法配真证书｜入站补 certificate/cert+key 键 + server_name/serverName 双拼写。
9. [P3] crates/xray-transport-quic/src/config.rs:48-53（消费 transport.rs:63/:107 只进 build_transport_config→只读 congestion，config.rs:60-79）｜quicSettings.keepAlive 解析未消费，长闲置连接被静默断链｜扩展域（Go 已移除 QUIC，transport_internet.go:25-30）｜keep_alive→quinn keep_alive_interval 或删字段备案。
10. [P3] crates/xray-transport/src/headers/mod.rs:4-9｜srtp/utp/wechat/dtls/wireguard/noop 六个空 Config struct 零消费（TCP header 认证只支持 http，conn.rs:541 断言 srtp 报错）；真 header 族在 finalmask/mkcp/header.rs（与 Go ID 0-5 全对齐）｜死代码误导维护者｜删六 struct 或 mod.rs 注明「header 族仅 finalmask mkcp-legacy」。
11. [P3] xray-core/src/outbound.rs:2064-2086｜wireguard is_client/num_workers（proto 扩展字段）无 JSON 入口，恒 Default；address 默认 10.0.0.2/32 偏离 Go bogon 对（wireguard.go:86-90）｜语义窄化，无功能损失｜随 P1-2 一并补。

---

## 9. 统计与结论

- **字段表格规模**：12 张表、约 **92 个字段行**（kcp 11 + header 族 7 + quic 5 + hysteria 传输 7 + hysteria 入站 5 + hysteria 出站 5 + quicParams 9 键族13项 + hysteria2 扩展键 1 + tuic 出站 12 + tuic 入站 4 + wireguard 13 + naive 6 + anytls 出 5/入 2 + ds 4，去重计 92）。
- **判定分布**：✅生效/对齐 ≈ 55 ｜ ⚠️解析未消费 2（quicParams.debug、quic keepAlive）｜ ❌未解析 19（wireguard 6 键 + hysteria 入站键族 + hysteria2 obfs 键 + tuic 入站证书 + dsSettings 全族 + level/email 等）｜ 🔧默认值/校验偏离 6（hysteria version、kcp 四校验、WG address 默认、domainsocket 语义）｜ 🧩扩展备案 9。
- **缺陷统计**：P0=0，P1=2，P2=5，P3=4；文档失真 1（kcp doc 注释，并入 P2-5）。
- **TOP3**：
  1. **anytls 入站零认证**（P1-1）——生产入口挂着「mock 不校验密码」的服务器，任意密码可用，等同公开转发器。
  2. **wireguard JSON 键族断供**（P1-2）——六键静默丢弃且消费链路齐全，reserved 恒空使 Warp 类节点完全不可用；「结构体有、消费有、唯独 JSON 解析层断线」的同款系统性病。
  3. **domainsocket 半成品**（P2-3）——键映射在、实现在、运行时才 NotFound，与 Go 配置期硬报错的移除语义相悖。
- **正面结论**：finalmask.quicParams 全族双侧对称消费且校验逐条对齐 Go；kcpSettings 主干六键双侧对称生效、header/seed 移除语义与文案精确对齐；mkcp header 伪装族 6/6 ID 对齐；TUIC 出站全键消费并双拼写兼容；naive 结构与文档一致。
