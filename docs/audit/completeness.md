# 功能完善度审计（对照 Go Xray-core v26.7.28 基准）

- 审计代理：CompleteAudit（只读代码，唯一写动作 = 本文件）
- Go 基准：`D:/Project/Xray-core`（v26.7.28）；Rust 仓库：`D:/Project/Xray-core-rust`
- 方法：以 Go 目录结构（app/、proxy/、transport/internet/、infra/conf/）为基准清单，逐域盘点 Rust 侧实现与配置字段覆盖；全仓 `todo!|unimplemented!|Unsupported|TODO|NotImplemented|ponytail:` 扫描作为线索源；每条发现给出 file:line 证据。

## 0. 线索源扫描结果

- `todo!` / `unimplemented!`：**全仓 0 命中**。
- `Unsupported`：34 处，绝大多数为**平台门控**（tun 仅 Linux/Android/FreeBSD，对齐 Go fail-fast）、错误枚举变体名（ss/tuic 协议错误）、以及 proxyman「平行世界」stub（见 §8）。无生产热路径占位。
- `NotImplemented`/`not implemented`：49 处，集中在 trait 默认 stub（vless/vmess 的 Processor trait、hysteria DialerFactory、features NoopManager、router NotImplementedSelector）。其中 **NotImplementedSelector 被生产装配点使用**（发现 F1）。
- `ponytail:`：144 处。多数为「文档化取舍」非功能缺口；少数为真实缺口（F2/F3 等）。
- 过期注释（声称未实现、实际已实现）：xray-app-dispatcher/src/lib.rs:24（称嗅探器"全 stub"，实际 sniffer.rs 已全量实现并被 default.rs:480 装配）、xray-proxy-vless/src/encryption/{client,server}.rs:3-5（称"仅骨架"，实际 mod.rs 已完整实现 0-RTT）、xray-app-dns/src/nameserver/mod.rs:33-35（称"仅 FakeDNSServer 实现"，实际 udp/tcp/dot/doh/quic/local 全存在）、xray-transport-httpupgrade/src/register.rs:158-159（见 F2）。建议统一清理，避免误导后续审计。

## 1. 总览

Go 目录 ↔ Rust crate 对照：**app 13/13、proxy 15/15（目录级）、transport/internet 14/14、finalmask 子模块 10/10 全部有对应实现**，另有 8 个 Rust 独有 crate（anytls/tuic/naive/mixed/tun-ok/quic/h2/crypto 等，见 §7）。整体完成度高；缺口集中在：**生产装配线未接完的"最后一环"**（balancer selector、FakeDNS 注入、freedom finalRules、httpupgrade TLS）、Go v26 新特性（mldsa65、VLESS reverse、verifyPeerCertByName）、以及少量配置字段。

| 维度 | 判定 |
|---|---|
| ① 协议 inbound/outbound | ✅ 基本完整（发现 F3/F4 两个装配缺陷；loopback stub） |
| ② 传输 | ⚠️ httpupgrade 入站 TLS 断线（F2）、xhttp H3 缺、CF 指纹组为已知 FAIL |
| ③ 安全 tls/reality/enc | ⚠️ 字段级缺口（mldsa65、verifyPeerCertByName、spiderX、ENC padding 简化） |
| ④ 应用 | ⚠️ balancer 装配（F1）、FakeDNS 未注入（F5）、rule_set/observatory/sysstats 部分 |
| ⑤ 配置兼容 | ⚠️ 整体覆盖高（含 removed-feature 文案逐条对齐），细节缺口见 §6 |

---

## 2. 协议矩阵（inbound/outbound）

Rust 生产注册点：入站 `crates/xray-core/src/inbound.rs:1676-2076`（spawn_one_inbound match），出站 `crates/xray-core/src/outbound.rs:530-745`（try_build_handler match）。

| 协议 | Go 侧 | Rust 入站 | Rust 出站 | 判定与证据 |
|---|---|---|---|---|
| vless | ✅ | ✅ | ✅ | fallbacks napfb（inbound.rs:2239-2254 + serve_vless 提取 SNI/ALPN inbound/server.rs:126-132）；ENC（inbound.rs:1696-1699 + encryption/mod.rs）；REALITY（inbound.rs:1739-1744）。子项缺口见 F6/F7（ENC padding、account reverse/testpre） |
| vmess | ✅ | ✅ | ✅ | AES-128-GCM + ChaCha20（vmess/src/dispatcher.rs:120-124）；`none/zero` 已被 Go 移除，Rust 拒绝 = 对齐；alterId>0 硬错（inbound.rs:2389-2391），Go infra/conf/vmess.go 已无 AlterId 字段 = 对齐 |
| trojan | ✅（Go 打 deprecated 警告） | ✅ | ✅ | fallback 决策树直连 TLS 路径提取 name/alpn（trojan/src/server.rs:405-415,478）；transport-hub 路径传空 = Go 非 `*tls.Conn` 同语义（server.rs:433-434） |
| shadowsocks | ✅ | ✅ | ✅ | AEAD 全常规加密 + UDP；Go v26 的 shadowsocks_2022 由 `"shadowsocks"`+`2022-blake3-*` method 承载（Go infra/conf/shadowsocks.go 同名路由），Rust 在同入口分流（inbound.rs:2453-2509 单用户/多用户/中继三模式 + UDP inbound.rs:836-871）。chacha2022 拒绝 = 对齐（Go proxy/shadowsocks_2022 全目录 grep `Chacha20` 零命中，Go 本身仅 AES 系） |
| socks | ✅ | ✅ | ✅ | 密码认证 + UDP associate（inbound.rs:120-133） |
| http | ✅ | ✅ | ✅ | Basic auth（inbound.rs:1859-1874；client.rs:145-149） |
| dokodemo | ✅ | ✅ | ✅ | followRedirect + SNI 覆盖 + port_map + 预定义地址（inbound.rs:578-593,661-671）+ UDP |
| freedom | ✅ | —（Go 无入站） | ⚠️ | fragment(tlshello/maxSplit)/noises/sendThrough/destOverride 完整（freedom/src/{fragment,udp,handler}.rs）；**finalRules 与 domainStrategy 生产未消费 → F3**；freedom 入站为 Rust 扩展（Go 无） |
| blackhole | ✅（仅出站） | Rust 扩展入站 | ✅ | response http/none（inbound.rs:2801-2804） |
| dns（出站） | ✅ | Rust 扩展入站 | ⚠️ | rewriteServer 字段级覆盖 ✅（proxy-dns/src/handler.rs:30-141）；**规则 domain 匹配缺失 → F4** |
| loopback | ✅ | 注册 ✅ | ⚠️ | 回环执行为 stub：sink 未注入仅 log（xray-proxy-loopback/src/lib.rs:213-217,249-253）；sniffing 注入 TODO（outbound.rs:705-709） |
| wireguard | ✅ | ✅ | ✅ | peers(publicKey/pre_shared_key/endpoint/keep_alive/allowed_ips)+mtu+num_workers+reserved+domainStrategy（wireguard/src/config.rs:105-171，IPC 生成 wireguard.rs:83-117）；smoltcp netstack 双端 |
| hysteria | ✅ | ✅ | ✅ | 入站 auth/masq/quicParams（inbound.rs:2520-2533）+ 出站 QuinnHysteriaTransport（outbound.rs:612-636）；`hysteriaSettings.version` 字段未消费（parse 只读 auth/server_name，inbound.rs:2527-2528）P2 |
| tun | ✅ | ✅ Linux 门控 | ✅ Linux 门控 | 非 Linux 硬错 = Go NewTun fail-fast 对齐（inbound.rs:1656-1659,2834-2856；outbound.rs:742-745） |
| naive / anytls / tuic / mux（出站） | ❌（Go 无） | ✅ 扩展 | ✅ 扩展 | Rust 独有（见 §7） |
| mixed | ❌（Go 无） | ✅ 扩展 | — | UDP associate 不支持（inbound.rs:339-341），P2 |

**发现（协议域）**

**[P1] F3: freedom 出站 finalRules / domainStrategy 仅在测试路径 Handler::process 消费，生产 TCP 路径未接** | crates/xray-core/src/outbound.rs:531-556；crates/xray-proxy-freedom/src/dispatcher.rs:30-53
- 证据：生产装配走 `make_freedom_dial_fn_with_config`（outbound.rs:534）→ `make_dial_fn_with_config` 只消费 `fragment` 并用 `SocketOptions::default()` 拨号（dispatcher.rs:38-53），注释自认"domain_strategy 当前解析即存储，dial 未消费"（dispatcher.rs:33）；而消费 finalRules/domainStrategy 的 `FreedomHandler::process`（handler.rs:40-58,142-146,233,288）未被任何生产装配点调用（outbound.rs 装配的是 `FreedomDispatchBridge::from_bridge`，outbound.rs:546-554）。
- 影响：Go v26 新增的 freedom `finalRules`（按 IP/端口 Block/Return，Go infra/conf/freedom_test.go:56-58 佐证）与 `domainStrategy: UseIP/ForceIP/...` 家族选择在配置中被静默忽略——配置接受、行为缺失。
- 修复建议：把 finalRules/domainStrategy 逻辑下沉进 `make_dial_fn_with_config`（或让 FreedomDispatchBridge TCP 分支改调 handler 路径），一处接线全路径生效。

**[P1] F4: dns 出站规则 domain 匹配未实现，规则作用域被静默放大** | crates/xray-proxy-dns/src/config.rs:159-172
- 证据：`pub fn apply(&self, q_type: u16, _domain: &str) -> bool { ...; true }` —— `_domain` 忽略，注释"domain 匹配留切片2，当前视为匹配"。
- 影响：配置了 `domains: [...]` 的 DNS 规则（如仅对特定域名 Hijack/Return）对**所有**查询生效；Hijack 场景会把本应直连上游的查询全部劫持，属明确行为缺陷。
- 修复建议：接 `xray_geodata::matcher::domain`（仓库已有 FullMatcher/SuffixMatcher 基建，hosts.rs:85-88 同类用法），空 domains 保持恒真。

**[P2] loopback 回环链路为 stub** | crates/xray-proxy-loopback/src/lib.rs:213-217,249-253；crates/xray-core/src/outbound.rs:705-709
- 证据：`sink 未注入时仅 log`（lib.rs:214）；dial 签名无 link 参数用空 pipe 构造（lib.rs:250-253）；outbound.rs:706-709 `TODO(loopback-sniffing)` 注明 functions.rs 装配 sink 传 None、sniffing 参数未接。
- 影响：`loopback` 出站配置可注册但数据不回环（Go loopback.go:56-62 完整）。修复建议：LoopbackSink 注入 + DispatcherLoopbackSink::with_sniffing 接线（TODO 注释已给出路径）。

---

## 3. 传输层

Rust 传输目录对照 Go `transport/internet`：tcp ✅、websocket ✅、httpupgrade ⚠️（F2）、grpc ✅、splithttp/xhttp ⚠️（H3 缺 + 已知 CF 组）、kcp/mkcp ✅、hysteria ✅、quic/h2 = Rust 保留（Go 已移除，见 §7）、finalmask ✅（子模块 1:1：fragment/noise/salamander(+gecko)/sudoku/xdns/xicmp/xmc/realm/mkcp-legacy(header dns·dtls·srtp·utp·wechat·wireguard + aes128gcm/original)/custom/sudoku）。

- **tcp**：rawSettings/tcpSettings `header`(http obfs, headers/http.rs + authenticator.rs) + `acceptProxyProtocol`（proxy_protocol.rs）+ tcpmask 装配（tcp/src/register.rs:46-55）+ happy_eyeballs.rs + system_dialer sockopt 全字段。✅
- **ws**：Go v26 WebSocketConfig 仅 host/path/headers/acceptProxyProtocol/heartbeatPeriod（transport_method.go:613-618，maxEarlyData/earlyDataHeaderName 已移除）；Rust 全覆盖 + `ed` 路径参数 early-data（ws/src/register.rs:387-390,532-536；server.rs:178-188,247-251）+ permessage-deflate（deflate.rs）。✅
- **grpc**：serviceName(含 `/A/B/Tun|TunMulti` 自定义路径)/multiMode/authority/idle_timeout/health_check_timeout/permit_without_stream/initial_windows_size/user_agent 双写法全解析（grpc/src/config.rs:52-102）。连接池缺失为已接受项。✅
- **mkcp**：mtu/tti/uplinkCapacity/downlinkCapacity/congestion/readBufferSize/writeBufferSize/cwndMultiplier/maxSendingWindow（kcp/src/register.rs:213-257）；`header`/`seed` 硬错——Go 同样 PrintRemovedFeatureError（Go transport_method.go:537-539 vs Rust register.rs:233-243，文案语义对齐），迁移目标 finalmask/udp `mkcp-legacy`+`header-*` Rust 已有（finalmask/mod.rs:663-669,900-914，ID 0-5 与 Go finalmask/header/config.go:614-624 一致）。✅
- **splithttp**：客户端 packet-up/stream-up/stream-one/stream-down 四模式（dialer.rs:1-130；client.rs:296-378）、服务端 session/UploadQueue/30s-TTL/ placements(path/query/header/cookie/body)/x_padding 校验（server 侧 session.rs/meta.rs/payload.rs）、配置含 xmux/downloadSettings/sc*/sessionIDTable/sessionIDLength（config.rs:158-216）。✅ 主体。缺口：
  - **[P2] xhttp HTTP/3 未实现** | crates/xray-transport-splithttp/src/client.rs:22 —— "HTTP/3 / QUIC → 切片 G（可选）"。Go xhttp 支持 H3 下载流。影响：`network=xhttp` + ALPN h3 场景退化为 h2/h1。
  - **[P2] packet-up/stream-up 过 CF 指纹**：已知 FAIL 组（#1/#7/#18，Argo+xhttp），属互操作层而非字段缺失，此处仅登记不计分。
- **hysteria 传输**：salamander obfs + quicParams（congestion/brutalUp/bbrProfile/udp_hop 等，memory_settings.rs:80-199）生产接线于 hysteria 出站（outbound.rs:620-633）。`xray-transport-hysteria/src/dialer.rs:159` 的 HysteriaDialerFactory stub 为非生产平行 trait，不计缺。
- **[P1] F2: httpupgrade 入站 TLS acceptor 构建后被丢弃（security=tls 入站不终结 TLS）** | crates/xray-transport-httpupgrade/src/register.rs:89,129,152-165
  - 证据：`let tls_acceptor = build_tls_acceptor(settings)?;`（:89，且 build_tls_acceptor :172-178 实际已能返回 Some）→ 传入 `do_handshake(tcp, &server, &tls_acceptor, remote)`（:129）→ 但签名参数为 `_tls_acceptor: &Option<tokio_rustls::TlsAcceptor>` 且函数体（:160-165）从未使用它，直接对裸 TCP 做 upgrade 握手。上方注释"当前 build_tls_acceptor 返回 Unsupported"（:158-159,170-171）已过期，与真实行为相反。
  - 影响：`httpupgrade + security=tls` 的入站完全不可用（TLS 客户端字节被当明文 HTTP 解析，握手必败）；配置静默失效而非报错。Go httpupgrade/hub.go 的 TLS listener 正常。
  - 修复建议：do_handshake 内 `if let Some(acc) = tls_acceptor { let tls = acc.accept(tcp).await?; ... }`，同时删除两条过期 ponytail 注释。
  - 附带 **[P2]**：accept 循环内 `do_handshake(...).await` 串行执行（register.rs:106-129），单个慢握手客户端阻塞全部新 accept（Go 每连接 goroutine）。建议 spawn。

---

## 4. 安全层

### 4.1 TLS（xray-tls）

已覆盖（grep 证据）：serverName/alpn/allowInsecure/dangerous verifier（client_config.rs:70-88）、disableSystemRoot（:128-132）、minVersion/maxVersion/clamp 1.0/1.1（config.rs:388-400）、cipherSuites Go 套件名映射（config.rs:340-356）、curvePreferences（config.rs:360-384）、rejectUnknownSni（server_config.rs:183-186）、pinnedPeerCertSha256（client_config.rs:178-182）、echServerKeys/echConfigList 解析（ech.rs:372-391）、证书 usage 解析（certificate.rs:181-185）、uTLS 指纹经 btls：Chrome 131/120/133、Firefox 120/148、Safari 26.3、iOS 13/14/18.4、Edge 106/133、360 11.0、QQ 11.1（btls_client.rs:5-17）。私钥 DER/PKCS8 内容嗅探为已修复项。

**发现：**

**[P1] F6: uTLS 指纹不支持时静默回退标准 rustls，且缺 android / randomized 族** | crates/xray-tls/src/btls_client.rs:19
- 证据："其他指纹将 fallback 到标准 rustls"（btls_client.rs:19）；清单（:6-17）无 `android`、`randomized`、`randomizednoalpn`、`uniformrandom`（Go uTLS 全支持，REALITY 用户常用 randomized）。
- 影响：`fingerprint: "android"` 等配置不报错、不发对应 ClientHello——抗指纹能力静默归零，配置语义失真（Go 会生成对应指纹）。
- 修复建议：不支持指纹时返回 InvalidData 硬错（把静默降级变成显式失败）；按需补 randomized 族（rustls 侧可对 ClientHello 做扩展乱序/裁剪近似）。

**[P2] F7a: Go v26 TLS 字段缺失** | 对照 Go infra/conf/transport_security.go:248-318
- 缺失（crates/xray-tls 全目录 grep 零命中）：`masterKeyLog`（SSLKEYLOGFILE 调试）、`enableSessionResumption`、`verifyPeerCertByName`（client_config.rs:16 注明"未实现（Go v26 新增）"）、证书级 `ocspStapling`/`oneTimeLoading`/`buildChain`。
- 影响：均为可选项；ocspStapling（刷新秒数）缺失使证书级 OCSP 装订配置无效果（OCSP stapler 本体在 ocsp-stapling feature 已有）。修复建议：优先补证书级 ocspStapling 解析传递给 stapler；其余按需。

**[P2] F7b: ECH 状态存疑** | crates/xray-tls/src/ech.rs:372-391 vs crates/xray-tls/src/client_config.rs:16
- 证据：echServerKeys/echConfigList 解析与测试已存在（ech.rs），但模块文档仍写"ECH 留待 115 另 issue"（client_config.rs:16）。两者矛盾，需专项验证 ECH 握手是否端到端生效（解码≠握手集成）。

### 4.2 REALITY（xray-reality + xray-tls/btls_reality）

已覆盖：client publicKey/shortId/fingerprint/serverName（xray-reality/src/register.rs:113-121）；server privateKey/shortIds/maxTimeDiff/dest·target/xver/serverNames（xray-core/src/inbound.rs:1422-1488,1516-1569，fallback_to_dest + PROXY protocol）；ClientHello 改写走 ssl_add_message_cbb trampoline（v45 清理后）。

**发现：**

**[P2] F8: REALITY mldsa65（Go v26 后量子签名）未实现** | crates/xray-reality/src/mitm.rs:162-170；crates/xray-reality/src/error.rs:108-109
- 证据：`generate_reality_ed25519_cert_mldsa65(...) -> Err(RealityError::Mldsa65NotImplemented)`；对照 Go infra/conf/transport_security.go:40（server `mldsa65Seed`）、:50（client `mldsa65Verify`）、:153-161（校验）。
- 影响：使用 mldsa65Seed/mldsa65Verify 的 REALITY 配置不可用（服务端证书签名、客户端校验）。修复建议：引入 ML-DSA-65 crate 后补 mitm 签名路径；短期至少在配置解析处显式报错（当前配置被静默忽略更劣）。

**[P2] F9: REALITY 其余客户端/服务端字段缺失** | xray-reality/src/util.rs:47-51；全仓 grep `spiderX|minClientVer|maxClientVer|limitFallback` 零命中
- 证据：`get_path_locked` 注释"deterministic for now; random selection deferred"（util.rs:48-50）→ `spiderX` 配置被忽略；`minClientVer/maxClientVer`（Go 服务端版本门控）、`limitFallbackUpload/Download`（Go fallback 限速）均未消费。
- 影响：功能可用性不受损（spiderX 为伪装参数），但字段静默无效。修复建议：至少对未知字段打 warn。

### 4.3 VLESS ENC（Go proxy/vless/encryption 对应物）

已覆盖（对照 memory v46/v54 已闭环项 + 代码）：xor_mode 0/1/2 全通（xor_conn.rs 含 Go 官方库 fixture 逐字节单测 testdata/xor_conn_go_fixture.txt）；client+server 0-RTT（mod.rs:316-416 快路径、:591-599 ServerSession nfs_keys replay、common_conn.rs:85-106 new_zero_rtt/new_server_zero_rtt、xor_conn.rs:11-14 skip 语义）；server 侧 inbound 生产接线（inbound.rs:1696-1699）。

**[P2] F10: ENC padding lens/gaps 解析但不按配置整形发送** | crates/xray-proxy-vless/src/encryption/mod.rs:85-87,317,648
- 证据：`padding 配置（阶段 A 简化，默认空）`（:85-87）；client"padding：最小 34 字节（不分段发送）"（:317）；server"padding 分段发送：简化为一次发送"（:648）。
- 影响：互操作正确（padding 是机会性的，双方按 encryptedLength 协商），但 Go 的流量整形（lens/gaps 随机分段）防探测效果未复刻。修复建议：按 PaddingTriple 实现分段采样发送。

**[P2] F11: VLESS account `reverse`（VLESS Reverse Proxy，Go v26 替代 legacy reverse 的新特性）与 `testpre` 未实现** | Go infra/conf/vless.go:251-255；Rust 全仓 grep `"reverse"|"testpre"` 于 vless crate 零命中
- 影响：Go v26 主打的 VLESS 反向代理在 Rust 不可用（legacy reverse 配置入口两边都已按 removed 拒绝，对齐 ✅，见 built.rs:139-143 vs Go xray.go:607-608）。修复建议：VLESS Reverse 为独立特性，需单独立项。

---

## 5. 应用层

| App | Go 目录 | Rust crate | 判定 |
|---|---|---|---|
| dispatcher | app/dispatcher | xray-app-dispatcher + xray-core wiring | ✅ 嗅探 HTTP/TLS/QUIC/uTP/BitTorrent/DNS 全实现（sniffer.rs:236-887）并生产装配（default.rs:436-516 sniff_connection）；FakeDNS 嗅探接口就绪（见 F5）；UDP443 策略（default.rs:598-600）；per-user policy level deferred（default.rs:695-697）P2 |
| router | app/router | xray-app-router | ⚠️ 9 类条件匹配器全实现（condition.rs，ProcessName 四平台 proc/lsof/procstat :438-880）、4 种 balancer 策略 + LeastLoad 三模式 + WeightManager（strategy_leastload.rs:12-17）；**生产装配缺陷 → F1**；rule_set 未接入（wiring.rs:403-404 proto 缺字段；rule_set.rs:93-95 remote 下载 not implemented）P2 |
| dns | app/dns | xray-app-dns | ✅ UDP/TCP/DoT/DoH(+h2c)/DoQ/localhost/fakedns/system 全 nameserver（nameserver/mod.rs:283-320）、localTLDs 规则、useSystemHosts（jsonconf.rs:238-241）、queryStrategy 别名全集（jsonconf.rs:272-285）、serveStale/serveExpiredTtl、hosts/Geosite。缺口：域名 server 地址需 bootstrap 解析（跳过+warn，jsonconf.rs:11-12,196-199）P2；`tcp+local` 未走 system resolver（tcp.rs:236-238）P2；FakeDNS 多池（pools[]）仅单池（init.rs:85-89）P2 |
| fakedns | infra/conf + dispatcher | xray-conf init.rs + xray-app-dns/fakedns + dispatcher | ⚠️ **引擎未注入生产 dispatcher → F5** |
| stats | app/stats | xray-app-stats | ✅ Counter/Channel/OnlineMap + 7 个 RPC（GetStats/Online/OnlineIpList/GetAllOnlineUsers/QueryStats/GetSysStats，command.rs:4-5）。**[P2] F13: SysStats 内存/GC 字段恒 0**（command.rs:17-25，sysinfo 因 Defender 拦截推迟；Provider trait 可注入 :138-141） |
| commander | app/commander | xray-app-commander | ⚠️ **[P2] F14**: 五服务注册（Handler/Logger/Stats/Routing/Observatory，grpc.rs:3-18）；HandlerService 出站真实（OutboundRuntime，:69-87）但 inbound/alter/users 返回 UNIMPLEMENTED（:12）；RoutingService Subscribe/TestRoute/AddRule UNIMPLEMENTED（:17）；TestRoute FieldSelectors 投影简化（grpc.rs:632-633） |
| metrics | app/metrics | xray-app-metrics | ✅ Prometheus 文本（traffic inbound/outbound/user + observation，metrics.rs:288-309,505-509） |
| observatory | app/observatory | xray-app-observatory | ⚠️ **[P2] F12: 探测仅 TCP connect**，"暂不实现 TLS 握手，仅返回 TCP 连接延迟"（observer.rs:969-972）；Go 按 probeUrl 走完整 HTTP(S) GET 并判状态码。影响：alive/delay 语义弱化、无法探测应用层故障。burst observatory 已有（burst/ 子目录 + xray-conf built.rs:174） |
| policy | app/policy | xray-app-policy | ✅ levels timeouts/buffer/statsUserUp/Down/Online + system（manager.rs 测试 :76-249 全对齐 Go 缺省值） |
| reverse | app/reverse | xray-app-reverse | ✅ 语义对齐：Go v26 配置入口已移除（xray.go:607-608 PrintRemovedFeatureError），Rust 同样硬错（xray-conf/src/built.rs:139-143，文案逐字对齐）；feature 注册保留（register.rs:50）。Go 新替代 VLESS Reverse 见 F11 |
| proxyman | app/proxyman | xray-app-proxyman | ⚠️ 平行实现未接生产（生产= xray-core spawn_inbounds/register_outbounds + DefaultDispatcher）；crate 内 stub：chained proxy 未实现（outbound/handler.rs:469-472）、Unix socket worker stub（inbound/worker.rs:688-692）、UoT 桥接简化（outbound/handler.rs:327-331）、MemoryUser 最小字段（command/mod.rs:50-52） |
| geodata | app/geodata | xray-app-geodata | ⚠️ **[P2] F15: downloader HTTPS 未实现**（downloader.rs:227-231 "HTTPS 暂未实现…不偷偷 fallback"返回 DownloadFailed）→ geodata 自动更新对 https 源（GitHub 常规）不可用；cron scheduler ✅（scheduler.rs 对齐 robfig/cron 5 域） |
| log / version | app/log, app/version | xray-app-log, xray-app-version | ✅（FileHandler per-write open 为性能注记，instance.rs:370） |
| mux / xudp | common/mux, common/xudp | xray-mux, xray-xudp, xray-core MuxBridge | ✅ 生产 MuxBridge（outbound.rs:591-598 + Phase2b 回填 :256-267）；**[P2] F16: xudp-over-mux hit 路径流身份不保留**（xray-mux/src/worker.rs:298-302"数据不丢，流身份不保留"）；xray-mux/src/handler.rs:31-33 的 DialingWorkerFactory pending 为非生产路径 |

**发现（应用域）**

**[P1] F1: 生产路由装配硬编码 NotImplementedSelector，负载均衡策略全部失效** | crates/xray-core/src/wiring.rs:376,388-389；crates/xray-core/src/functions.rs:149-153；crates/xray-app-router/src/balancing.rs:250-255
- 证据：生产装配链 functions.rs:150 `build_router_adapter_from_json(&a.data)`（routing app 唯一接线点）→ wiring.rs:376 `build_router_adapter_from_json_with_observer(routing_json, None)`（**observer 也恒为 None**，LeastPing/LeastLoad 连观测数据都没有）→ wiring.rs:388-389 固定 `let ohm: Arc<dyn OutboundHandlerSelector> = Arc::new(NotImplementedSelector);`；而 `NotImplementedSelector::select_outbounds` 恒返回 `Err(NotHandlerSelector)`（balancing.rs:252-255）。Random/RoundRobin/LeastLoad 的 `pick_outbound` 都经 `ohm.select_outbounds(selectors)` 取候选 → 必然 Err → 空结果走 fallbackTag（router.rs:328-332 自己注释了该行为链）。
- 影响：配置解析接受 `balancers`（wiring.rs:400 明确解析该字段），但任何 balancer 规则在生产中选不出非 fallback 出站——配置被静默降级。
- 修复建议：装配点改传真实 selector 适配器（SimpleOhm 已有 snapshot/get_handler 能力，outbound.rs:1351-1362 同款用法），按 selectors 过滤真实出站 tag。

**[P1] F5: FakeDNS 引擎已构建但从未注入 dispatcher（fakeDns 配置静默无效）** | crates/xray-core/src/register.rs:642-651,684-689；crates/xray-app-dispatcher/src/default.rs:595-597,650-653
- 证据：`fake_dns_factory` 构建 `FakeDnsFeature{holder}` 并提供 `engine()`（register.rs:687-689，注释"dispatcher 嗅探注入经 FakeDnsFeature::engine 取引擎视图"）；`DefaultDispatcher` 有 `fdns: Option<Arc<dyn FakeDnsEngine>>` 字段与 setter（default.rs:597,651-653，嗅探消费逻辑 default.rs:467-516 完整）。但 crates/xray-core 全目录对 `.fdns`/`engine()` 的调用除定义/测试外**为零**——引擎从未接到 dispatcher。
- 影响：`"fakeDns": {...}` + `destOverride:["fakedns"]` 配置全链路（post-process 填默认池 init.rs:82-100 → feature 构建 → 嗅探改写）在最后一环断裂，FakeDNS 完全不生效且无警告。
- 修复建议：instance 装配时 `feature("fakeDns")` → `FakeDnsFeature::engine()` → `dispatcher.set_fdns(...)`。

---

## 6. 配置兼容（infra/conf 覆盖度）

总体覆盖度高，且 **removed-feature 语义逐条对齐 Go v26**（均验证）：
- 全局 `transport` 字段硬错（built.rs:131-135 ↔ Go xray.go:624-626）；legacy `reverse` 硬错（built.rs:139-143 ↔ Go xray.go:607-608）；`h2/h3/http` 与 `quic` 网络、`xtls` security 的 removed 文案（xray-transport/src/dialer.rs:357-378 测试逐字对齐 Go）；mkcp `header/seed` 硬错（见 §3 kcp）；`allowInsecure` 移除说明（client_config.rs:81 注释，Go transport_internet.go:698-700 同步移除语义）。
- 多格式配置 json/yaml/toml + 多文件合并 + env 展开（xray-conf/src/{confloader,serial,yaml,toml_config,vformat}.rs）；FakeDNS 后处理 lint stage（init.rs 对齐 Go infra/conf/fakedns.go:73-134）。
- 逐域字段覆盖：vless/trojan/ss/socks/http/dokodemo/freedom/blackhole/loopback/wireguard/hysteria settings、ws/grpc/httpupgrade/mkcp/splithttp/xhttp settings、sockopt（mark/tcpFastOpen/tcpKeepAlive*/tcpMptcp/tcpCongestion/tproxy/reusePort/v6only/dialerProxy/happyEyeballs 四参数/tcpWindowClamp/tcpMaxSeg/penetrate/tcpUserTimeout/customSockopt，dialer.rs:164-247）——见 §2-§5 各域。

配置域缺口汇总（前文已列的 F1-F15 不重复）：
- **[P2] sockopt `interface` JSON 字段未接入**（bind_if_index 字段已备无 JSON 入口，dialer.rs:170-172）。
- **[P2] `hysteriaSettings` 键未进 protocol_settings_key 映射**（dialer.rs:333-343 无 "hysteria" 分支），hysteria 靠 settings 顶层 auth 字段 + finalmask 工作正常，但 streamSettings 内嵌 hysteriaSettings 的用户字段（version/congestion/up/down/udphop）不会经 StreamSettings 泛化解析；当前仅 quicParams/finalmask 路径生效（outbound.rs:620-633）。
- **[P2] Go conf 顶层 `interface` 值格式、`env` 字段（xray.go:396 EnvConfig）** 未在 Rust xray-conf 顶层发现对应解析（仅 vformat env 展开），建议核对 `env` 用例。

---

## 7. Rust 侧超出 Go 基准（不计缺口，防误报）

- 保留 Go 已移除能力（超集）：`h2/http`、`quic` 传输网络（Rust lint 警告 removed 后仍可拨号，grpc/src/register.rs:56-57 注册 "http"/"h2"；quic crate 注册）——方向是向后兼容旧配置，与 Go 硬错不同，建议文档标注差异。
- 扩展协议：`anytls`、`tuic`、`naive`、`mixed`、`hysteria2` 别名、`mux`/`dns` 出站生产桥；`uot`（已知接受项）。
- xray-crypto/xray-buf/xray-features/xray-proto/xray-cli 等基建 crate 为架构需要。

## 8. 占位清单（🔧，非生产路径或已文档化）

- vless/vmess `InboundProcessor/OutboundProcessor/Noop*Processor` trait stub（vless/src/{inbound,outbound}/handler.rs:152-183、vmess/src/{inbound,outbound}/handler.rs:26-49）——平行 trait，生产走 serve_* 直连路径，不接 Link。
- xray-transport-hysteria `HysteriaDialerFactory` stub（dialer.rs:159-160）——生产走 QuinnHysteriaTransport（outbound.rs:630）。
- xray-tls/src/grpc.rs `new_grpc_utls -> UtlsNotImplemented`（:71-73）——gRPC 指纹经 btls 路径覆盖，此为平行接口；建议标记 dead 或删除防误读。
- proxyman crate stubs（§5 表）。
- platform-gated：tun/xicmp（已知接受项）。

## 9. 已知接受项（本次未列为发现）

xicmp linux_impl 占位、Rust client grpc 无连接池、Windows loopback TCP 病理（OS 层）、uot 为 Rust 扩展、近期已修复清单（CommonConn poll_write、TLS dirty flush、ss2022 sing wire 四缺陷、私钥 DER 嗅探、xor_mode 0/2、ENC 0-RTT 双侧、dns 族过滤、UDP 路由 inbound_tag）均未发现回归。

---

## 统计与 TOP3

| 严重度 | 数量 |
|---|---|
| P0 | 0 |
| P1 | 6（F1-F6） |
| P2 | 约 15（F7a/F7b/F8-F16 及 §6 两条、xhttp H3、geodata HTTPS、mixed UDP、observatory 探测、SysStats、commander 子方法、mux xudp-hit、loopback、sockopt interface、hysteriaSettings、ECH 存疑、httpupgrade accept 串行） |

**TOP3：**
1. **F1 路由 balancer 生产装配 NotImplementedSelector**（wiring.rs:388-389）——唯一装配点使 Random/RoundRobin/LeastLoad 全部必然失败，配置静默降级为 fallbackTag。
2. **F2 httpupgrade 入站 TLS acceptor 被丢弃**（httpupgrade/src/register.rs:89,129,155-165）——`security=tls` 的 httpupgrade 入站不可用，且过期注释声称"返回 Unsupported"与真实行为相反。
3. **F5 FakeDNS 引擎从未注入 dispatcher**（xray-core/register.rs:684-689 定义 engine() 却无调用方）——fakeDns 配置全链路就绪但最后一环断裂，静默无效。
