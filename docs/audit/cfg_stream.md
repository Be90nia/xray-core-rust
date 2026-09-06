# streamSettings 全传输配置审计(cfg_stream)

- 轮次: 第五轮·协议级配置全链审计(streamSettings 传输族)
- Rust 仓库: D:/Project/Xray-core-rust;Go 权威基准: D:/Project/Xray-core/infra/conf/(transport_internet.go / transport_method.go / transport_security.go / transport_sockopt.go)
- 方法: 逐字段 "Go JSON 键 → Rust 解析 → 生产消费点(inbound/outbound)" 三段比对;每条结论均有 file:line 证据
- 誊写说明: 调查证据与报告主体由原审计代理 CfgStream 完成(其输出流两度超时,报告经 Main 重启后分四步落盘);誊写核对与交叉引用/统计一致性修正由誊写代理 TranscribeStream 完成
- 判定图例: ✅生效 | ⚠️解析未消费/部分消费 | ❌未解析 | 🔧默认值偏离 | 🚫Go已移除(Rust对齐/分歧)

## 0. 基线说明(任务清单老字段裁定)

当前 Go 基线(v26.7.x)已相对旧版移除以下字段,Rust 侧同样不存在 → 两侧一致,不构成缺陷:
- wsSettings: `maxEarlyData` / `earlyDataHeader` / `browserForwarding` → 已被 `path?ed=N` 提取取代(Go transport_method.go:626-637;Rust websocket/register.rs extract_ed_from_path 对齐)
- splithttpSettings: `maxUploadSize` / `maxConcurrentUploads` / `uplinkPacketDownloader` → 已删除
- kcpSettings: `header` / `seed` → Go PrintRemovedFeatureError 硬报错;Rust 同样硬报错(kcp/register.rs:233-241,文案逐字对齐) ✅
- `network: quic` / `h2` / `http` → Go 硬报错 removed(transport_internet.go:988-991);Rust warn 后继续(quic 仍实现,h2/http 映射 grpcSettings)→ 有意分歧
- 旧 KCP `resize` / `congestion` / 读写缓冲字段 → 当前 Go 基线已无,Rust 亦无 ✅

## 1. tcpSettings(Go TCPConfig,transport_method.go:232-235)

| 字段 | Go 语义 | Rust 解析 | inbound 消费 | outbound 消费 | 判定 |
|---|---|---|---|---|---|
| header.type | none→noop / http→伪装;tcpHeaderLoader 按 type 分发 | xray-transport/src/headers/conn.rs:274 auth_from_json,type none/http,未知 type 报错(对齐 loader) | tcp/hub.rs:189 wrap_server ✅ | tcp/register.rs:58-62 wrap_client ✅ | ✅ |
| header.type=http.request | version/method/path/headers;缺省 Chrome 套装(AuthenticatorRequest.Build 默认 Host/UA/Sec-CH-UA 等) | headers/conn.rs 全字段覆盖;null header 值报错(对齐 Go "empty HTTP header value") | 服务端按 response 校验 ✅ | client 注入 ✅ | ✅ |
| header.type=http.response | version/status/reason/headers;status/reason 任一非空才设 200/OK | headers/conn.rs 对齐 | ✅ | - | ✅ |
| acceptProxyProtocol | TCPConfig 级;accept 后读 PROXY header 取真实源地址 | **任何代码不解析**(全仓 grep 仅 ws/httpupgrade 各自 transport 级键) | ❌ | - | ❌ P1(发现#2) |

## 2. wsSettings(Go WebSocketConfig,transport_method.go:613-619)

| 字段 | Go 语义 | Rust 解析(websocket/register.rs:393-444) | inbound | outbound | 判定 |
|---|---|---|---|---|---|
| host | Host header(客户端注入;服务端校验) | obj["host"] | server.rs:135+ 校验 Host 不符 404 ✅ | client.rs:119-125 覆盖 Host ✅ | ✅ |
| path | URL 路径(自动补 /) | obj["path"]+normalized | (host,path) 匹配 ✅ | build_request URI ✅ | ✅ |
| headers | 额外 header;含 host(大小写不敏感)→提升为 Host 并删除(Go deprecated warn) | register.rs:418-431 header/headers 双写法+host 提升 | XFF 提取 | client.rs:128 逐个注入 ✅ | ✅ |
| acceptProxyProtocol | 服务端 accept 后读 PROXY header | register.rs:432-435 | server.rs:124-127 read_proxy_protocol ✅ | 忽略(客户端无意义) | ✅ |
| heartbeatPeriod | 心跳 ping 周期秒,0=不启用 | register.rs:405-408 | server.rs:216-219 按匹配 config 启动 ✅ | ws_bridge.rs:253 ping 任务 ✅ | ✅ |
| path?ed=N | 提取 Early Data 上限(Atoi 语义;其余 query 保留重编码) | register.rs:268-280 extract_ed_from_path 逐条对齐(有单测) | 服务端解 Sec-WebSocket-Protocol early data(Go hub.go:55-59 同不按 ed 限长) | **ed 出站未消费**:dial_ws 硬编码 early_data=None(register.rs:196-206);Go delayDialConn 0-RTT(dialer.go:24-28,183-187)无对应 | ⚠️ P2(发现#8) |

## 3. httpupgradeSettings(Go HttpUpgradeConfig,transport_method.go:655-659)

| 字段 | Go 语义 | Rust 解析(httpupgrade/register.rs:286-330) | inbound | outbound | 判定 |
|---|---|---|---|---|---|
| host | Host header/校验 | obj["host"] | hub.rs:81 is_valid_http_host ✅ | register.rs:213-217 配置优先否则 dest ✅ | ✅ |
| path | URL 路径 | obj["path"]+extract_ed+normalized | 按 path 校验 ✅ | 请求行 ✅ | ✅ |
| headers | 额外 header;**含 host → Go 硬报错**(transport_method.go:673-675) | header/headers 双写法;**未拒绝 host 键** | - | dialer.rs:53-56 注入(可能双 Host) | ⚠️ P3(发现#16) |
| acceptProxyProtocol | 服务端读 PROXY header | register.rs:313-316 | register.rs:118-120 ✅ | 忽略 | ✅ |
| path?ed=N | 提取 Early Data(ed>0 → 客户端延迟读 101 响应,Go dialer.go:114-117) | register.rs:305-309 ✅ | - | register.rs:256-258 ed>0 走 deferred 读(0-RTT) ✅ | ✅ |

## 4. 顶层 streamSettings 键(Go StreamConfig,transport_internet.go:43-64)

| JSON 键 | Go 语义 | Rust 解析 | 判定 |
|---|---|---|---|
| network | 协议名 | dialer.rs:146 | ✅ |
| method | network 的 deprecated 别名(Go :77-79) | 不读取 | ❌ P2(发现#14) |
| security | none/tls/reality;xtls 硬报错 | dialer.rs:147;xtls→warn(宽容分歧) | ✅ |
| tlsSettings / realitySettings | TLSConfig / REALITYConfig | dialer.rs:165 security_json(tlsSettings 优先,realitySettings 兜底) | ✅ |
| rawSettings | TCPConfig 别名(Go :146-148 RAWSettings→TCPSettings) | 不读取(network=tcp 只读 tcpSettings 键) | ❌ P2(发现#15) |
| tcpSettings/wsSettings/grpcSettings/httpupgradeSettings/splithttpSettings/kcpSettings | 各协议 Settings | dialer.rs:332-344 protocol_settings_key | ✅ |
| xhttpSettings | splithttpSettings 别名 | dialer.rs:151-153 or_else 兜底(混用配置不丢) | ✅ |
| quicSettings | Go transport 已移除 | dialer.rs:340 映射存在 | 🚫分歧保留 |
| dsSettings | domainSocket | dialer.rs:341 映射存在但无实现→dial NotFound | ❌ P2(发现#12) |
| hysteriaSettings | HysteriaConfig | xray-transport-hysteria parse(双侧消费) | ✅(深审归 CfgQuicKcpMisc) |
| sockopt / finalmask | SocketConfig / FinalMask | dialer.rs:168/174 | ✅(sockopt 见 §7) |
| address / port | StreamConfig 顶层 Address/Port | 不读取(Go 侧近乎死字段) | ❌ P3 |

## 5. grpcSettings(Go GRPCConfig 8 字段,transport_method.go:578-587)

| 字段 | Go 语义 | Rust 解析(grpc/config.rs:65-105,camel/snake 双写法) | inbound | outbound | 判定 |
|---|---|---|---|---|---|
| serviceName | 服务名(裸名或 /A/B/Tun 自定义路径,path_escape 对齐) | ✅ service_name()+tun/multi stream 名解析对齐 Go config.go:17-58 | **cfg 解析后丢弃**(transport.rs:100-102),accept_h2 不校验 :path,任意 POST 放行(Go hub.go:131-132 按 serviceName 注册路由,错 path 拒绝) | normalize_grpc_path(transport.rs:203+)✅ | ⚠️入站未消费 P1(发现#3) |
| multiMode | TunMulti 多路模式 | ✅ | 入站同上未消费 | transport.rs:203-206 选 Tun/TunMulti ✅ | ⚠️入站未消费(并#3) |
| authority | HTTP/2 :authority 伪 header | ✅ 解析(config.rs:97) | - | **零消费**:dial_h2 请求只有 method/uri/content-type/te(transport.rs:47-49),无 :authority | ❌ P1(发现#4) |
| user_agent | User-Agent(别名 chrome/firefox/edge/golang) | ✅ 解析 | - | **零消费**(h2 请求无 user-agent header) | ❌ P1(并#4) |
| idle_timeout | gRPC keepalive Time 秒(<=0 归零) | ✅ 解析 | - | **零消费**(无 keepalive 机制) | ❌ P1(并#4) |
| health_check_timeout | keepalive Timeout 秒 | ✅ 解析 | - | **零消费** | ❌ P1(并#4) |
| permit_without_stream | 无活动 stream 仍发 keepalive | ✅ 解析 | - | **零消费** | ❌ P1(并#4) |
| initial_windows_size | h2 初始窗口字节(<0 归零) | ✅ 解析 | - | **零消费**(h2::client::handshake 默认窗口) | ❌ P1(并#4) |

## 6. splithttpSettings / xhttpSettings(Go SplitHTTPConfig 30 字段,transport_method.go:257-289)

| 字段 | Go 语义 | Rust 解析(splithttp/register.rs:235-346) | inbound | outbound | 判定 |
|---|---|---|---|---|---|
| host | URL authority/Host(优先级 host>serverName>address) | ✅ | hub/handler.rs:91-95 host 互含校验 ✅ | register.rs:63-69 authority+SNI(config.host 优先)✅ | ✅ |
| path | URL 路径(可带 query) | ✅ | base_path 匹配 ✅ | normalized_path/query ✅ | ✅ |
| mode | auto/packet-up/stream-up/stream-one(空→auto) | ✅(空串由 resolve_mode 归 auto) | 按 mode 路由 ✅ | dialer.rs:240-247 resolve_mode(auto+REALITY→stream-up/one)✅ | ✅ |
| headers | 额外 header;**含 host → Go 硬报错**(:336-338) | header/headers 双写法;**未拒绝 host 键** | - | config.rs:568-572 注入+缺省 Chrome 伪装头套装 | ⚠️ P3(发现#16) |
| xPaddingBytes | 填充字节数范围(禁 0) | ✅ parse_range | 服务端校验(非 obfs 分支) | 出站填充 ✅ | ✅ |
| xPaddingObfsMode | 混淆模式开关 | ✅ | **校验桩**:hub/handler.rs:379-381、payload.rs:88-90 `if x_padding_obfs_mode { return true }` 恒放行,反主动探测失效 | config.rs:645 出站按配置 placement/key/header ✅ | ⚠️ P1(发现#6) |
| xPaddingKey / xPaddingHeader | 混淆参数名(默认 x_padding/X-Padding) | ✅(Go 空串默认值由出站 config.rs:633-644 兜底) | 校验桩同上 | ✅ | ✅(入站随#6) |
| xPaddingPlacement / xPaddingMethod | queryInHeader/cookie/header/query;repeat-x/tokenish | ✅ | 校验桩同上 | ✅ | 同上 |
| uplinkHTTPMethod | 上行 method(默认 POST;GET 仅 packet-up) | ✅ | - | config.rs:757/794-798 ✅ | ✅ |
| sessionIDPlacement / sessionIDKey | **Go JSON 键为 sessionIDPlacement/sessionIDKey**(:271-272);path/cookie/header/query | **键名错位**:读的是 "sessionPlacement"/"sessionKey"(register.rs:300-301)→Go 键静默丢失,回落 path | meta.rs:70-120 按 placement 提取 ✅(但 Go 键进不来) | build_*_request_meta ✅ | ❌ P1(发现#5) |
| seqPlacement / seqKey | seq 位置(默认 path;键 x_seq/X-Seq) | ✅ 键名一致 | meta.rs:110+ ✅ | ✅ | ✅ |
| sessionIDTable / sessionIDLength | 字符集(预定义 HEX 等查表)/长度范围(ASCII 校验、from>0) | ✅ register.rs:307-335(查表+ASCII 拒绝+from>0 拒绝对齐 Go :409-424) | - | generate_session_id ✅ | ✅ |
| uplinkDataPlacement / uplinkDataKey | 上行数据位置(auto/body/cookie/header,非 packet-up 限 body) | ✅ | payload.rs:20-30 + handler.rs:306 ✅ | ✅ | ✅ |
| uplinkChunkSize | 上行分块范围(placement 依赖默认) | ✅ 解析+normalized | - | **零消费**:流式上传不分块(dialer.rs:46-48 文档化简化) | ⚠️ P2(发现#17) |
| noGRPCHeader | stream 上传不加 Content-Type: application/grpc | ✅ | - | config.rs build_stream_request_meta 生效(单测 config.rs:1333) | ✅ |
| noSSEHeader | 服务端响应不加 text/event-stream | **解析缺键**:register.rs:288-345 无 noSSEHeader 读取,`..Config::default()` 恒 false;而字段存在且服务端消费(hub/handler.rs:269) | 恒加 SSE header | - | ❌ P1(发现#7) |
| scMaxEachPostBytes | 单 POST body 上限范围(默认 1M) | ✅ | hub.rs:147-149 ✅ | dialer.rs:324/491 切片阈值 ✅ | ✅ |
| scMinPostsIntervalMs | 两次 POST 最小间隔 | ✅ | - | dialer.rs:104-106 固定 sleep(非范围随机,dialer.rs:46 文档化) | ✅🔧P3 |
| scMaxBufferedPosts | 服务端最大缓冲 POST 数(默认 30) | ✅ | hub.rs:146 ✅ | - | ✅ |
| scStreamUpServerSecs | stream-up 服务端推送周期范围(默认 20-80s) | ✅ 解析+normalized(config.rs:288) | **零消费**(hub/transport 无调用) | - | ⚠️ P2(发现#10) |
| serverMaxHeaderBytes | 服务端请求头上限(默认 8192;负值报错) | ✅ 解析+normalized(config.rs:327) | **零消费**(无 header 大小限制) | - | ⚠️ P2(发现#11) |
| xmux.maxConcurrency/maxConnections/cMaxReuseTimes/hMaxRequestTimes/hMaxReusableSecs/hKeepAlivePeriod | h2 连接复用策略;空对象→默认预设(maxConnections 3/hMaxRequestTimes 600-900/hMaxReusableSecs 1800-3000,Go :452) | ✅ register.rs:261-278 默认预设对齐 Go v26.7.28 | - | **零消费**:normalized_xmux() 全仓无调用,客户端无连接复用策略 | ⚠️ P2(发现#12) |
| downloadSettings | 嵌套 StreamConfig 独立下载通道(host/TLS/network 全量) | register.rs:282-285 **仅取嵌套 splithttpSettings**;network/security/address/port 全忽略 | - | 仅 resolve_mode 读 is_some(dialer.rs:306-307);下载 GET 仍走主 host/scheme | ⚠️ P2(发现#18) |
| extra | conf 层整包合并(Go :317-326) | 不读取 | - | - | ❌ P2(发现#19) |

## 7. kcpSettings(Go KCPConfig,transport_method.go:523-532)

| 字段 | Go 语义 | Rust 解析(kcp/register.rs:209-261) | inbound | outbound | 判定 |
|---|---|---|---|---|---|
| mtu / tti / uplinkCapacity / downlinkCapacity / cwndMultiplier / maxSendingWindow | KCP 会话参数(解析入 proto Config,校验在会话层) | ✅ 逐键解析入 prost Config | listener→KCP Config ✅ | dialer→KCP Config ✅(深审归 CfgQuicKcpMisc) | ✅ |
| header / seed | 🚫 Go PrintRemovedFeatureError(mkcp header & seed→finalmask/udp) | ✅ 同样硬报错,文案逐字对齐(register.rs:233-241+单测 427-446) | - | - | 🚫对齐 ✅ |

## 8. quicSettings / domainsocket

| 项 | Go 基线 | Rust 现状 | 判定 |
|---|---|---|---|
| network=quic + quicSettings | 🚫 已移除,conf 硬报错(transport_internet.go:990-991) | warn 后仍实现(xray-transport-quic);QuicConfig 仅 keep_alive/congestion 两键(header/key 自认不支持) | 🚫有意分歧;深审归 CfgQuicKcpMisc |
| network=domainsocket + dsSettings(path/acceptProxyProtocol) | 合法传输,unix socket 拨号/监听 | protocol_settings_key 映射存在(dialer.rs:341)但无 crate 注册 dialer/listener→出站 NotFound,入站不支持 | ❌ P2 整传输缺失(发现#13,fail-fast) |

## 9. tlsSettings(Go TLSConfig 18 字段,transport_security.go:300-322)

| 字段 | Go 语义 | Rust 解析+消费 | inbound | outbound | 判定 |
|---|---|---|---|---|---|
| serverName | SNI(客户端) | client_config.rs:73-77 解析;各 dialer resolve_sni(tcp/register.rs:120-127)缺省用 dest | - | ✅ | ✅ |
| allowInsecure | 🚫 Go v26 已移除(Build 硬报错,引导 pcs/vcn) | 保留兼容:warn+跳过证书验证(NoCertificateVerification,client_config.rs:81-89) | - | ✅(行为分歧:宽容) | 🚫对齐偏差(有意) |
| certificates[] | 见 §11 | ✅ | ✅ | ✅ | ✅ |
| alpn | 协商列表;含 fromMitm 时仅允许单元素(Go 校验) | client_config.rs:95-104 缺省 [h2,http/1.1];server_config.rs:224 同;fromMitm 校验无 | ✅ | ✅ | ✅(校验差异 P3) |
| enableSessionResumption | 会话恢复开关 | **全仓零解析**:rustls 恒启用内存会话缓存,false 无法关闭 | ✅恒开 | ✅恒开 | ❌ P2(发现#20) |
| disableSystemRoot | 仅信任配置证书 | client_config.rs:146-151 custom_root_store(certificates 全量入池,空池全拒对齐 Go) | - | ✅ | ✅ |
| minVersion / maxVersion | TLS 版本上下限 | xray-tls/config.rs:321+ security_params(provider+版本列表,双侧调用) | ✅ | ✅ | ✅ |
| cipherSuites | 冒号分隔套件名 | config.rs:341-357;rustls 不支持项 warn 跳过,全不可用保留默认 | ✅ | ✅ | ✅🔧 |
| curvePreferences | 曲线偏好 | config.rs:360-381;含 x25519mlkem768 | ✅ | ✅ | ✅ |
| fingerprint | uTLS 指纹(出站伪装) | **仅 xray-transport-tcp wrap_security 消费**(tcp/register.rs:87-101→u_client/btls)与 REALITY;ws(client.rs:76 utls::client 无指纹)/httpupgrade(register.rs:246 同)/grpc(transport.rs:42-49 裸 tokio-rustls)/splithttp(hyper-rustls)出站全部静默标准 rustls | - | ⚠️仅 tcp/reality 生效 | ❌ P1(发现#1) |
| rejectUnknownSni | 服务端拒未知 SNI | server_config.rs:183-186→SniCertResolver.select | ✅ | - | ✅ |
| masterKeyLog | SSLKEYLOGFILE 调试输出 | 零解析 | - | - | ❌ P3(发现#26) |
| pinnedPeerCertSha256 | 证书钉扎(逗号分隔 hex,容忍冒号;32B 校验) | client_config.rs:176-193+PinnedServerCertVerifier(叶子直过/CA 根完整验证,语义对齐 Go verifyPeerCert) | - | ✅ | ✅ |
| verifyPeerCertByName | 按名称钉扎(Go v26 新) | 零解析(模块文档自认未实现,client_config.rs:16) | - | - | ❌ P2(发现#21) |
| echServerKeys | 服务端 ECH 私钥(base64) | parse 函数在(xray-tls/ech.rs:368)但 build_server_config **未接入**(btls 上游导出缺口,ech.rs:12-13 自注);仅 CLI 用 | ❌ | - | ⚠️ P2(发现#22) |
| echConfigList | 客户端 ECH config list | tcp/register.rs:98-100→u_client apply_ech(btls SSL_set1_ech_config_list);rustls fallback warn;DNS:// 形态按 Go 降级 invalid | - | ✅(仅 tcp 路径) | ✅(限 tcp) |
| echSockopt | ECH 专用 socket 设置 | 零解析 | - | - | ❌ P3 |
| REALITY 门控 | security=reality 仅允许 tcp/splithttp/grpc(transport_internet.go:104-106 硬报错) | xray-conf 无此校验;ws+kcp+reality 等组合会按标准 TLS 握手 REALITY 服务端→运行时失败 | - | - | ❌ P2(发现#23) |

## 10. realitySettings(Go REALITYConfig 22 字段,transport_security.go:27-50)

已知项按指示仅列表不重报(前四轮已立案):maxTimeDiff 三重偏差 / minClientVer·maxClientVer 断链 / fingerprint 清单缺 android·randomized / ss2022 键族。

| 字段 | Go 语义 | Rust(xray-reality/config.rs:78-131 RealityConfig 结构体) | 判定 |
|---|---|---|---|
| 服务端: show/target/dest/type/xver/serverNames/privateKey/shortIds/mldsa65Seed/limitFallbackUpload/limitFallbackDownload | 目标伪装+白名单+限速回退 | 字段全集齐(含 LimitFallback after_bytes/bytes_per_sec/burst_bytes_per_sec :54-59);消费在 reality crate(前轮已深审) | ✅ |
| 服务端: masterKeyLog | SSLKEYLOGFILE | 字段在(:125),消费随 tls 侧同缺 | ⚠️ P3 |
| 服务端: minClientVer/maxClientVer/maxTimeDiff | 客户端版本/时间窗 | 字段在(:90-92);缺陷已立案勿重报 | (已知) |
| 客户端: fingerprint/serverName/password→publicKey/shortId/mldsa65Verify/spiderX(含 spiderY p/c/t/i/r 参数解析) | uTLS 伪装+密钥+spider 行为 | 字段全集齐(:102-123);password→publicKey 回退在 parse;消费在 u_client(前轮已深审) | ✅ |

## 11. certificates[]子字段(Go TLSCertConfig 7 字段,transport_security.go:250-258)

| 字段 | Go 语义 | Rust(xray-tls/certificate.rs) | 判定 |
|---|---|---|---|
| certificateFile / certificate | 磁盘/内联证书(readFileOrString 二选一,均空报错) | :272-276 file_or_inline 对齐 | ✅ |
| keyFile / key | 磁盘/内联私钥 | :291-295 对齐 | ✅ |
| usage | encipherment/verify/issue;未知→encipherment | :181-185 entry_usage(大小写不敏感+默认分支对齐,单测 :549-559);verify 条目→服务端 mTLS CA 池(Rust 扩展,Go v26 无服务端 mTLS) | ✅ |
| ocspStapling | OCSP 装订刷新周期 | 零解析(handshake 层 ocsp-stapling feature 在,但配置键不读取) | ❌ P2(发现#24) |
| oneTimeLoading | 一次性加载(内联证书 Go 强制 true) | 零解析(Rust 无文件热重载,语义恒一次性,但键不可配) | ❌ P2(并#24) |
| buildChain | 从文件构建链 | 零解析 | ❌ P2(并#24) |

## 12. sockopt(Go SocketConfig 20 字段,transport_sockopt.go:45-67)

| 字段 | Go 语义 | Rust 解析(dialer.rs:174-285) | 消费 | 判定 |
|---|---|---|---|---|
| mark | SO_MARK | ✅ :206 | apply_outbound/inbound(sockopt/mod.rs:404/489) | ✅ |
| tcpFastOpen | interface{}:bool→256/-1;数字=队列长度(非 0 即启用) | ✅ 解析但收窄:as_bool 或 ==1(:209-211)→ tcpFastOpen:2 被当 false | TCP_FASTOPEN_CONNECT(linux) | ✅🔧P3(发现#25) |
| tproxy | **字符串**枚举 "tproxy"/"redirect"/""(Build :80-87) | **按 bool 解析**(:218 as_bool)→ 标准配置 `"tproxy":"tproxy"` 静默失效 | sockopt/linux.rs:65 IP_TRANSPARENT(永不触发) | ❌ P1(发现#9) |
| acceptProxyProtocol | accept 后读 PROXY header | **零解析**;DefaultListener::with_accept_proxy_protocol(system_listener.rs:245)全仓零调用,恒 false | 入站真实源地址 | ❌ P1(发现#2) |
| domainStrategy | asis/useip*/forceip* 11 值(大小写不敏感,非法硬报错) | ✅ parse_domain_strategy(:289-308,非法 warn+AsIs 宽容) | system_dialer.rs:628 lookup_for_ip 预解析 ✅ | ✅ |
| dialerProxy | 经指定出站转发 | ✅ | DIALER_PROXY_HOOK(system_dialer.rs:577)✅ | ✅ |
| tcpKeepAliveInterval / tcpKeepAliveIdle | keepalive 参数 | ✅ | apply ✅ | ✅ |
| tcpCongestion / tcpWindowClamp / tcpMaxSeg / tcpUserTimeout / penetrate | Linux TCP 选项(其余平台解析存储) | ✅(:222-241) | linux 门控 apply(Go 同) | ✅ |
| v6only | IPV6_V6ONLY | ✅ | apply ✅ | ✅ |
| interface | 绑定接口名 | (已立案勿重报:bind_if_index 无 JSON 入口) | - | (已知) |
| tcpMptcp | MPTCP | ✅ | apply ✅ | ✅ |
| customSockopt[] | system/network/level/opt/value/type 全字符串透传 | ✅ | apply_custom_sockopt 按 system/network 过滤 setsockopt ✅ | ✅ |
| addressPortStrategy | srv/txt 改写目标 7 值 | ✅ parse(:253-256) | check_address_port_strategy ✅ | ✅ |
| happyEyeballs | prioritizeIPv6/tryDelayMs/interleave/maxConcurrentTry(缺省 interleave=1/maxConcurrentTry=4) | ✅(:227-248,缺省值对齐 Go UnmarshalJSON) | 竞争拨号 ✅ | ✅ |
| trustedXForwardedFor | XFF 白名单 | ✅(:250 附近,单测 dialer.rs:677-692) | httpupgrade 入站 apply_trusted_x_forwarded_for(server.rs:97)✅;ws 入站 XFF 提取恒启用未按白名单门控(server.rs:134) | ⚠️ P3 |
| reusePort | (当前 Go SocketConfig 已无此键) | Rust 仍解析(:221) | listener 侧 | 🚫多余容错,无碍 |

## 13. 发现清单(30 条,均 file:line 证据)

格式:[P] | file:line | 证据 | 影响 | 修复建议

- [P1] #1 tlsSettings.fingerprint 出站仅 tcp/REALITY 生效 | crates/xray-transport-websocket/src/client.rs:76(utls::client 无指纹参)/crates/xray-transport-httpupgrade/src/register.rs:246(同)/crates/xray-transport-grpc/src/transport.rs:42-49(裸 tokio-rustls)/crates/xray-transport-splithttp/src/register.rs:176-193(hyper-rustls) | 消费点唯一在 xray-transport-tcp/src/register.rs:87-101(u_client/btls) | ws/httpupgrade/grpc/splithttp 出站配 fingerprint 全部静默走标准 rustls 指纹,CDN/uTLS 伪装失效(Go 全 transport 走 uTLS) | 四 dialer 统一走 xray_tls::utls::u_client;注意 ws/httpupgrade 为已知回归敏感区(memory: u_client 改动曾回归 10 节点),需带矩阵验证
- [P1] #2 sockopt.acceptProxyProtocol 与 tcpSettings.acceptProxyProtocol 双入口全断 | 解析:crates/xray-transport/src/dialer.rs:174-285 无该键;transport 级:全仓仅 ws/httpupgrade 各自解析;开关:crates/xray-transport/src/system_listener.rs:245 with_accept_proxy_protocol 零调用恒 false;Go: transport_method.go:234 + transport_sockopt.go:50 | raw TCP/dokodemo 落地 PROXY 协议场景入站全部拿不到真实源地址(回程/审计错位),Go 主流 nginx/HAProxy 前置部署直接失效 | socket_options() 增解析 acceptProxyProtocol 并传入 DefaultListener::with_accept_proxy_protocol;tcp hub 同步
- [P1] #3 grpc 入站不校验 serviceName/multiMode(任意 POST 放行) | crates/xray-transport-grpc/src/transport.rs:100-102(cfg 解析后丢弃)、accept_h2 :128-146 仅查 method=POST | Go hub.go:131-132 按 serviceName 注册路由,错 path 拒;Rust 反主动探测/多服务隔离缺失,扫描器可借道 | accept_h2 传 cfg,校验 req.uri().path()==normalize_grpc_path(cfg) 否则 404
- [P1] #4 grpc 出站 6 字段解析未消费 | crates/xray-transport-grpc/src/config.rs:97-105 解析 authority/user_agent/idle_timeout/health_check_timeout/permit_without_stream/initial_windows_size;transport.rs:22-96 dial_h2 无一引用(无 :authority、无 user-agent、无 keepalive、默认窗口) | Go dial.go+grpc-go 全消费;CDN 侧 authority/UA 指纹特征不符,长连接行为偏离 | dial_h2 加 :authority/user-agent header;h2 client 配置窗口;keepalive 可后置(标注 ponytail: 优先 authority+UA)
- [P1] #5 splithttp sessionIDPlacement/sessionIDKey 键名错位 | crates/xray-transport-splithttp/src/register.rs:300-301 读 "sessionPlacement"/"sessionKey";Go 键为 "sessionIDPlacement"/"sessionIDKey"(transport_method.go:271-272) | Go 标准键静默丢失→session 回落 path placement;query/header/cookie 隐匿配置失效,与 Go 服务端协商错位 | get_str 改读 Go 键(可保留旧键兼容双读)
- [P1] #6 splithttp xPaddingObfsMode 服务端校验桩恒放行 | crates/xray-transport-splithttp/src/hub/handler.rs:379-381、payload.rs:88-90 `if ctx.config.x_padding_obfs_mode { return true; }` | obfs_mode=true 恰是用户开启反主动探测的场景;无 x_padding 的裸客户端也可过检,探测隔离失效 | 补 xpadding 校验分支(x_padding 长度/取值校验),失败 4xx
- [P1] #7 splithttp noSSEHeader 解析缺键 | crates/xray-transport-splithttp/src/register.rs:288-345 无 "noSSEHeader" 读取,`..Config::default()` 恒 false;而 Config.no_sse_header 存在(config.rs:168)且服务端消费(hub/handler.rs:269) | 该键静默忽略,SSE 响应头恒在,伪装分支不可用 | parse 增 no_sse_header: get_bool("noSSEHeader")
- [P2] #8 ws path?ed=N 出站 0-RTT 未接线 | crates/xray-transport-websocket/src/register.rs:196-206 dial_ws 硬编码 early_data=None,而 ed 已解析(含 path 提取,register.rs:268-280) | Go Ed>0 客户端走 delayDialConn 延迟拨号+Sec-WebSocket-Protocol 头携带 early data(websocket/dialer.go:24-28,183-187);Rust 首写 payload 走普通 WS 帧 | 0-RTT 首包优化缺失(Go 服务端两种形态都收,互操作无损) | dial_ws 接入 early_data 透传
- [P1] #9 sockopt tproxy 类型错位(string vs bool) | crates/xray-transport/src/dialer.rs:218 `obj.get("tproxy").and_then(|v| v.as_bool())`;Go transport_sockopt.go:50 字符串枚举+Build :80-87 | 标准写法 `"sockopt":{"tproxy":"tproxy"}` 静默失效→IP_TRANSPARENT(sockopt/linux.rs:65)永不设置,透明代理入站全废 | 解析改字符串匹配("tproxy"/"redirect"→true 或枚举),兼容 bool
- [P2] #10 splithttp scStreamUpServerSecs 解析未消费 | 解析 register.rs:341+normalized config.rs:288;hub/transport 零调用 | stream-up 服务端周期推送缺失(Go 防中断),长闲置流可能被中间盒掐 | hub stream-up 会话接入周期写
- [P2] #11 splithttp serverMaxHeaderBytes 解析未消费 | config.rs:327-333 normalized 存在;hub 无调用 | 服务端无请求头上限,超大 header 可打内存(Go 431 拒) | hub 读 header 前/后按上限校验
- [P2] #12 splithttp xmux 6 字段解析未消费 | register.rs:261-278+normalized_xmux(config.rs:451)全仓零调用 | 连接复用策略缺失(anti-TSPU 调优失效),行为回退单连接 | 客户端接入 xmux 策略或文档化声明偏差
- [P2] #13 domainsocket 传输未实现 | dialer.rs:341 映射存在;无 crate 注册 domainsocket dialer/listener→出站 NotFound | network:"domainsocket" 配置完全不可用(Go 合法传输;fail-fast 不算静默,故 P2) | dial_system 加 unix socket 分支+DS listener
- [P2] #14 streamSettings.method 旧别名不解析 | dialer.rs:146 仅读 network;Go transport_internet.go:77-79 method→network | 旧配置静默回落 tcp | from_json 增 method 兜底
- [P2] #15 rawSettings 顶层键不解析 | dialer.rs:146-153 仅按 network 读 tcpSettings/xhttpSettings;Go :146-148 rawSettings→TCPSettings | network:"tcp"+rawSettings 配置静默丢 header/acceptProxyProtocol | transport_json 兜底 or_else rawSettings
- [P2] #16 httpupgrade/splithttp headers 含 host 未按 Go 报错 | Go transport_method.go:673-675(httpupgrade)/:336-338(splithttp)硬报错;Rust parse 后原样保留 | 客户端可能发出双 Host 头(先写 Host 再遍历 headers),行为未定义 | parse_headers 后检测 host 键报错
- [P2] #17 splithttp uplinkChunkSize 解析未消费 | dialer.rs:46-48 文档化(流式上传不分块) | 与 Go wire 分块节奏不同(功能兼容),服务端 scMaxEachPostBytes 兜底 | 文档化保留;后续按 chunk 切
- [P2] #18 splithttp downloadSettings 降级消费 | register.rs:282-285 仅取嵌套 splithttpSettings;network/security/address/port 忽略;dialer.rs:306-307 仅 resolve_mode 用 is_some,下载 GET 仍走主 host/scheme | CDN 分流下载(主小流+下载大流分离)不可用 | downloadSettings 按 StreamSettings::from_json 独立建 client
- [P2] #19 splithttp extra 不解析 | Go transport_method.go:317-326 extra 整包合并(host/path/mode 保留外层);Rust 无读取 | 模板化配置(extra 复用)静默失效 | parse 前 merge extra 子对象
- [P2] #20 tlsSettings.enableSessionResumption 零解析 | 全仓无该键;rustls 恒内存会话缓存 | false 无法关闭会话恢复(隐私/轮换场景) | ClientConfig.resumption 按键开关
- [P2] #21 tlsSettings.verifyPeerCertByName 未实现 | client_config.rs:16 文档自认 | Go v26 新钉扎方式不可用(有 pcs 替代,故 P2) | verifier 增名称匹配分支
- [P2] #22 tlsSettings.echServerKeys 服务端未接入 | parse 在(ech.rs:368)但 server_config 无调用(ech.rs:12-13 btls 导出缺口自注) | ECH 服务端部署不可用(客户端 echConfigList 可用) | 等 btls 导出或 rustls ECH 支持后接线
- [P2] #23 REALITY network 门控缺失 | Go transport_internet.go:104-106 仅 tcp/splithttp/grpc;Rust xray-conf 无校验 | ws+kcp+reality 等非法组合不做标准 TLS→运行时握手失败,报错不友好 | conf 层 Build 校验 reality 白名单 network
- [P2] #24 certificates ocspStapling/oneTimeLoading/buildChain 零解析 | xray-tls/certificate.rs 仅读 certificate(File)/key(File)/usage;Go transport_security.go:250-257 | 三个证书行为键静默忽略(OCSP 装订配置不可控;热重载/OCSP ticker 本身也是 TODO,server_config.rs:169-173 自注) | 先解析存储;OCSP 周期接入 ocsp-stapling feature
- [P3] #25 tcpFastOpen 数值语义收窄 | dialer.rs:209-211 仅 bool/==1;Go 数字=队列长度非 0 即启用 | tcpFastOpen:2 被当 false(Go 启用) | 非 0 数值即 true
- [P3] #26 tlsSettings.masterKeyLog/echSockopt 零解析 | Go :313/:322 | SSLKEYLOGFILE 调试与 ECH sockopt 不可用(调试向) | 按需补
- [P3] #27 streamSettings.address/port 顶层键零解析 | Go StreamConfig :44-45(近乎死字段) | 无实际影响 | 可忽略
- [P3] #28 splithttp scMinPostsIntervalMs 固定 sleep 非范围随机 | dialer.rs:46/104-106 文档化 | 与 Go 随机节奏有差(功能兼容) | 文档化保留
- [P3] #29 ws 入站 XFF 提取未按 sockopt.trustedXForwardedFor 门控 | websocket/server.rs:134 注释"从 XFF 提取首个 IP 覆盖 remote(对齐 Go)";白名单仅 httpupgrade 接线(server.rs:97) | 可伪造源 IP 直达 ws 入站(Go dokodemo 语义为白名单信任) | ws 侧接白名单过滤
- [P3] #30 tlsSettings.alpn fromMitm 唯一性校验缺失 | Go transport_security.go:359-364 硬报错;Rust 无 | 极端配置下 MITM ALPN 行为未定义 | conf 层校验

### 已知项(前四轮已立案,本轮仅表列不重报)
sockopt interface / uTLS 清单缺 android·randomized / REALITY maxTimeDiff 三重偏差 / REALITY minClientVer·maxClientVer 断链 / httpupgrade 入站 TLS acceptor 丢弃 / ss2022 键族(F-W)/ XUDP GlobalID / mux.enabled·concurrency / freedom destinationOverride·proxyProtocol / dokodemo address·followRedirect / socks UDP 127.0.0.1

## 14. 确认干净清单(逐字段验证生效,双侧)

- wsSettings: host/path/headers(+host 提升)/acceptProxyProtocol/heartbeatPeriod — 双侧全链路;path?ed=N 提取双侧对齐(出站 0-RTT 发送未接线,见发现#8)
- httpupgradeSettings: host/path/headers/acceptProxyProtocol/ed(deferred 0-RTT)— 双侧全链路
- tcpSettings.header type=http 伪装: request/response 全子字段(version/method/path/status/reason/headers)+Chrome 缺省+null 值报错 — 出站 wrap_client(tcp/register.rs:58)+入站 wrap_server(tcp/hub.rs:189)
- kcpSettings: mtu/tti/uplinkCapacity/downlinkCapacity/cwndMultiplier/maxSendingWindow;header/seed removed 硬报错文案逐字对齐
- splithttpSettings(22/30 生效): host/path/mode(resolve_mode 含 REALITY auto 分支)/headers(+缺省 Chrome UA 套装)/xPaddingBytes/xPaddingObfsMode·Key·Header·Placement·Method(出站)/uplinkHTTPMethod/sessionIDTable·Length(查表+校验)/seqPlacement·seqKey/uplinkDataPlacement·Key/noGRPCHeader/scMaxEachPostBytes/scMaxBufferedPosts/scMinPostsIntervalMs
- tlsSettings: serverName/alpn/minVersion/maxVersion/cipherSuites/curvePreferences/pinnedPeerCertSha256(叶子直过+CA 根验证)/disableSystemRoot/rejectUnknownSni/echConfigList(btls)
- certificates: certificateFile/certificate/keyFile/key/usage(默认分支对齐)
- sockopt: mark/domainStrategy(11 值)/dialerProxy/tcpKeepAliveInterval·Idle/tcpCongestion/tcpWindowClamp/tcpMaxSeg/tcpUserTimeout/penetrate/v6only/tcpMptcp/customSockopt/addressPortStrategy/happyEyeballs(缺省 interleave=1/maxConcurrentTry=4 对齐)
- 顶层: network/security/tlsSettings·realitySettings 双键/六协议 settings 键映射/xhttpSettings 兜底/sockopt/finalmask;removed 文案(h2·http·quic·xtls·kcp header·seed·allowInsecure)warn 对齐

## 15. 统计与 TOP3

- 字段表格规模: 13(顶层)+4+6+5(tcp/ws/httpupgrade)+8(grpc)+30+xmux6(splithttp)+2(kcp)+2(quic/ds)+18(tls)+12(reality)+6(certificates)+16(sockopt) ≈ **148 项字段级判定**,12 张表
- 缺陷统计: **P1×8,P2×16(含 cert 3 键合 1 条 #24、grpc 6 字段合 1 条 #4),P3×6;合计 30 条**;已立案勿重报 11 项(见本节末与 §10 注)
- TOP3:
  1. **#2 acceptProxyProtocol 双入口全断**(sockopt+tcpSettings 均零解析,listener 开关零调用)——PROXY 协议前置部署的真实源地址全线丢失,P0 级使用面,P1 定级因 fail-silent 面窄于数据损坏
  2. **#3+#4 grpcSettings 双侧断链**——入站不校验 serviceName(反探测失效)+出站 authority/user_agent 等 6 字段不生效(CDN 指纹与长连接行为偏离 Go)
  3. **#1 tlsSettings.fingerprint 非 tcp 出站静默忽略**——ws/httpupgrade/grpc/splithttp 四族出站 uTLS 伪装全失效,与用户"配了 fingerprint"的安全预期直接相悖
