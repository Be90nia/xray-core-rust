# 出站协议与传输层可用性审计（transport-outbound）

> 审计日期：2026-10-19 | 审计者：TransportAudit（只读，未改任何产品代码）
> 范围：xray-proxy-freedom / vless / vmess / ss / trojan / tuic / anytls / hysteria 出站桥接；xray-transport-{websocket,httpupgrade,splithttp,grpc,kcp,quic,hysteria} 客户端拨号；TLS/uTLS/REALITY 指纹路径。
> 对照：Go 权威源码 D:/Project/Xray-core（v26.9.9）。
> 方法：silent-failure-hunter 八模式扫描 + 逐路径读码 + Go 逐条对照。serena rust-LS 故障降级 grep/read（不影响结论，行号均经实读核对）。

## 结论汇总

**12 项 finding：P0×2、P1×7、P2×3，另附吹毛×2、已核验非缺陷×8。**

最高价值项（「未实现/未消费但配置可写、运行期静默降级」）：
1. **VLESS / VMess 出站 UDP 命令恒为 TCP**——UDP 流量经这两个出站 = XUDP 帧当 TCP 载荷发往「UDP 目标地址的 TCP 连接」，全部静默挂死（P0×2）。
2. **`security:"xtls"` 及一切未知 security 字符串 → 全传输层静默裸连**，零告警（Go 启动硬错）（P1）。
3. **freedom finalRules 非法条目被 `.ok()` 静默丢弃**——Block 规则失效=安全语义静默失效（Go 启动硬错）（P1）。
4. **hysteria 出站证书验证硬编码 NoVerifier**，tlsSettings 验证语义全部丢弃（P1）。
5. **splithttp `downloadSettings` 配置可写但下载连接不消费其 host/path/TLS**（P1）。
6. **出站解析失败/未知协议 warn+跳过注册**，路由引用该 tag 的流量每条连接静默断链（Go 启动硬错）（P1）。
7. **UDP dispatch 链路无空闲超时**（Go 1 分钟闲置终止）（P1）。

---

## P0

### P0-1 VLESS 出站 UDP：请求头恒写 `VlessCommand::Tcp`，UDP 流量静默协议错配

- **根因**：`crates/xray-proxy-vless/src/dispatcher.rs:376-391`（`establish_conn`）——`encode_request_header` 第四参硬编码 `VlessCommand::Tcp`，整个 dial 闭包无任何 `dest.network()` 检查：

```rust
    encode_request_header(
        &mut conn,
        VERSION,
        &config.user_uuid,
        VlessCommand::Tcp,          // ← 恒 TCP，无 UDP 分支
        Some(&target_addr),
        Some(target_port.value()),
        &addons,
    )
```

- **触发条件**：任一 UDP 流被路由/分流到 vless 出站（无 mux 时）：SOCKS UDP ASSOCIATE、dokodemo UDP、ss-2022 UDP inbound → `UdpDispatchSession` → routing → vless outbound（`xray-core/src/outbound.rs:751-765` 注册为纯 `DialBridge`，UDP 无专门分支）。link 里的 XUDP 帧字节被当作 TCP payload 写入 vless 连接，请求头声称 TCP 目标=UDP 目标地址。
- **用户可见现象**：DNS/QUIC/游戏等 UDP 应用经该出站全部超时无响应；服务端（Go）按 TCP 命令向「UDP 目标地址」发起 TCP 连接——对 53 端口常被拒、对 443 可能意外连上 TCP 服务返回 TLS 垃圾。**全程零错误日志、零配置报错**——最典型的「已接线但路径不可用」。
- **Go 对照**：`proxy/vless/outbound/outbound.go:214-217`：`command := RequestCommandTCP; if target.Network == net.Network_UDP { command = RequestCommandUDP }`；且 `:303-306` UDP+crgn 时自动转 `v1.mux.cool` Mux 命令。Go 完整支持 VLESS UDP。
- **快速验证**：配置 socks inbound + vless outbound（freedom 服务端或本地回环 Go 服务端），路由 UDP → vless；`dig @1.1.1.1 example.com` 经代理 → 超时；同配置改 freedom 出站 → 正常。或直接读 `VlessCommand` 枚举全体调用方确认出站无 UDP 引用。

### P0-2 VMess 出站 UDP：`Command::Tcp` + `Network::TCP` 双硬编码，同病

- **根因**：`crates/xray-proxy-vmess/src/dispatcher.rs:261-267`（`make_vmess_dial_fn`）：

```rust
            let header = RequestHeader::new(
                VERSION,
                Command::Tcp,                                              // ← 恒 TCP
                Destination::new(target_addr, target_port, Network::TCP),  // ← network 强改 TCP
                security,
            )
            .with_option(option);
```

  dial 闭包（:227-316）无 `dest.network()` 检查；`VmessConn` pump 仅做 chunk AEAD，无 XUDP 帧处理。
- **触发条件**：同 P0-1——UDP 流路由到 vmess 出站。
- **用户可见现象**：同 P0-1，UDP 应用经 vmess 出站全部静默挂死。
- **Go 对照**：`proxy/vmess/outbound/outbound.go:88-91`：`if target.Network == net.Network_UDP { command = protocol.RequestCommandUDP }`；`:146-149` cone 自动转 Mux。Go 完整支持 VMess UDP。
- **快速验证**：同 P0-1 拓扑换 vmess；或 grep `Command::Udp` 在 vmess crate 的出站调用方=0。

---

## P1

### P1-1 anytls 出站 UDP 静默当 TCP dial（协议 TCP-only 应硬错而非静默损坏）

- **根因**：`crates/xray-proxy-anytls/src/dispatcher.rs` `make_dial_fn`（`dest_to_socks` :96-110 附近）——`Destination → SocksAddr` 转换丢弃 network 语义，`client.dial(&socks)` 恒开 TCP session；无 UDP 检查/拒绝。注意 `AnytlsOutboundHandler::can_handle`（outbound.rs:84-86）虽只认 TCP，但生产注册走 `DialBridge::dispatch` 路径（`xray-core/src/outbound.rs:889-909`），**不经过 can_handle 门**。
- **触发条件**：UDP 流路由到 anytls 出站。
- **用户可见现象**：XUDP 帧被当 TCP 载荷发进 anytls session，UDP 应用静默挂死；无报错。
- **Go 对照**：Go xray-core 无 anytls；上游 anytls 协议本身 TCP-only。正确语义应是对 UDP 目标**硬错拒绝**（如 tuic `UdpRelayMode` 解析层拒绝非法值的做法），当前为静默损坏。
- **快速验证**：路由 UDP → anytls 出站 + `dig`；观察 `client.dial` 无 network 参数。

### P1-2 `security:"xtls"` / 未知 security 字符串 → 静默裸连（Go 启动硬错）

- **根因**：`crates/xray-transport/src/dialer.rs:145`（`security` 原样存字符串）+ `dialer.rs:166-168`：

```rust
    pub fn is_tls(&self) -> bool {
        matches!(self.security.as_str(), "tls" | "reality")
    }
```

  一切非 `tls`/`reality` 的值（含 legacy `"xtls"`、拼错的 `"tls "`/`"TLS"`）折叠为「无 TLS」。消费端如 `crates/xray-transport-tcp/src/register.rs:88-90`：

```rust
    // security=none（或空）原样返回。
    if !settings.is_tls() {
        return Ok(conn);
    }
```

  **无任何 warn/error**。ws/grpc/splithttp 同构（`build_client_config` 对未知 security 返 None → 明文）。
- **触发条件**：老 v2rayN/v2ray 客户端导出的 `security:"xtls"` 配置；或 security 字段任意手误。配置正常启动。
- **用户可见现象**：对 TLS 端口发明文 VLESS → 服务端立即断连/黑洞，客户端反复重连失败，日志里只有「dial failed」类下游错误，**没有任何一条指向 security 字段被忽略**。
- **Go 对照**：`infra/conf/transport_internet.go:129-132`：`case "xtls": return nil, errors.PrintRemovedFeatureError("Legacy XTLS", ...)`；`default: return nil, errors.New("Unknown security ...")`——**配置加载即硬错**。
- **快速验证**：任意 outbound streamSettings 配 `"security": "xtls"` → Rust 启动成功且拨号发明文（tcpdump 无 ClientHello）；Go 同配置启动即报错。

### P1-3 freedom finalRules 非法条目 `.ok()` 静默丢弃（Go 硬错；另 dialerProxy 语义反向偏差）

- **根因**（两处生产装配路径）：
  - `crates/xray-proxy-freedom/src/handler.rs:46-48`（`FreedomHandler::new`）：
    ```rust
        let final_rules =
            config.final_rules.iter().filter_map(|rc| FinalRule::build(rc).ok()).collect();
    ```
  - `crates/xray-core/src/outbound.rs:710-713`（生产 FreedomDispatchBridge 装配，注释自认「失败跳过」）：
    ```rust
                    .iter()
                    .filter_map(|rc| xray_proxy_freedom::FinalRule::build(rc).ok())
                    .collect()
    ```
- **触发条件**：`finalRules[]` 任一条 `action` 拼错（如 `"blok"`）、network/port 字段非法。
- **用户可见现象**：本应 Block 的目标**静默直连放行**——广告/私网封锁语义失效且无任何日志；其余合法条目仍生效（更难察觉）。
- **Go 对照**：`infra/conf/freedom.go:185-190`：`r.Build()` err → `return nil, err`（配置加载失败）；`proxy/freedom/freedom.go:199-204`：`buildFinalRule` err → `return errors.New("failed to build final rule")`（NewHandler 失败）。Go 启动即拒。
- **附带偏差（方向相反）**：Go `freedom.go:193-197` 在 `sockopt.dialerProxy` 设置时**忽略 finalRules 并打警告**（freedom 非最终出站）；Rust `outbound.rs:735-740` 无条件 `.with_final_rules(...)`——dialerProxy 链上 Rust 仍执行 Block 黑洞，Go 放行。行为反向不一致。
- **快速验证**：freedom outbound 配 `[{"action":"blok","port":"53"}]` → 启动成功、UDP/53 正常放行（Go 版同配置拒绝启动）；配合法 block 规则 + `dialerProxy` → Rust 仍黑洞、Go 放行。

### P1-4 hysteria 出站证书验证硬编码 NoVerifier（tlsSettings 验证语义静默丢弃）

- **根因**：`crates/xray-core/src/outbound.rs:850-855`（hysteria 分支）：

```rust
            let tls_config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
```

  无条件跳过服务端证书验证；`parse_hysteria_config`（:2462-2500）也只取 address/port/auth/serverName，**不解析任何 insecure/certificate/pinned 字段**。对比同文件 tuic 分支（:915-931、`build_tuic_rustls_config` :2834-2870）完整实现了 insecure/pin/webpki 三态。
- **触发条件**：使用 hysteria 出站即恒定触发。
- **用户可见现象**：无直接功能异常；任何中间人（假证书）劫持 hysteria QUIC 连接**照常握手成功**——安全语义静默降级，且用户配置的 tlsSettings.allowInsecure=false 形同虚设。
- **Go 对照**：`transport/internet/hysteria/dialer.go:327-358`：`tlsConfig := tls.ConfigFromStreamSettings(streamSettings)`，标准 xray TLS 配置语义（allowInsecure 可控、默认验证）。
- **快速验证**：hysteria 出站 + mitmproxy/自签 CA 中间 → 握手成功无告警；对照 tuic 出站同场景被拒。

### P1-5 splithttp `downloadSettings` 配置可写、仅参与 mode 选择、下载连接不消费其内容

- **根因**：
  - 解析：`crates/xray-transport-splithttp/src/register.rs:336-340`（递归解析 `downloadSettings.splithttpSettings`，host/path 存进 `Config.download_settings`）。
  - 消费：**全仓只有 `dialer.rs:311` `config.download_settings.is_some()` 一处**（影响 auto→stream-up 推断）。三条下载路径全部用主 base_uri 建流：
    ```rust
    // dialer.rs:157-159（dial_stream_up；dial_packet_up:69-70、dial_h3_* 同构）
        let (download_reader, _, _) =
            client.open_stream(&base_uri, &session_id, None, Some(close_rx)).await?;
    ```
    同一个 `DefaultDialerClient`（主配置构建，register.rs:234-237），downloadSettings 的 host/path/TLS 无任何代码读取。
- **触发条件**：xhttp 配置带 `downloadSettings`（CDN 分流下载的官方玩法，v2rayN 常见下发）。
- **用户可见现象**：①下载分流静默失效——全部流量走主线路（性能级不可用，用户配置的快线/纯下载线白配）；②若主线路前置（如某些 CF 回源形态）拒绝 GET 下载流，则下载方向挂死、上传正常——半可用态最难排查。mode 恰好也被 flip 成 stream-up（Go 同规则），更掩盖「downloadSettings 没生效」这一事实。
- **Go 对照**：`transport/internet/splithttp/dialer.go:352-395`：独立 `dest2`/`tlsConfig2`/`httpClient2`，`errors.LogInfo(ctx, "XHTTP is downloading from %s ...", dest2, ...)`——下载明确走第二目的地且有日志。
- **快速验证**：配 `downloadSettings.host=<另一域名>` 抓包：GET 仍发往主 host；Rust 无 "downloading from" 类日志。

### P1-6 出站配置解析失败 / 未知协议 → warn+跳过注册；路由引用该 tag 每连接静默断链

- **根因**：
  - `crates/xray-core/src/outbound.rs:206-218`：`BuildError::Unsupported`/`Parse` → `tracing::warn!(... "skipping")` 后继续。测试固化该行为：`outbound.rs:3415-3430` `register_vless_invalid_uuid_skipped`（invalid UUID → handler 不注册）。
  - 下游：`crates/xray-app-dispatcher/src/default.rs:1250-1255`——路由命中不存在 tag：
    ```rust
                        None => {
                            // Go default.go:469-470 DO NOT CHANGE：路由指定的 outboundTag
                            // 不存在时不得落默认出站（如 VLESS Reverse Proxy）。
                            tracing::warn!(tag = %route.outbound_tag, "non existing outTag");
                            outbound_writer.shutdown();
                            return;
                        },
    ```
    （断链方向正确、不落默认出站——问题在**启动期不拦**，把错误推迟到每条连接。）
- **触发条件**：vless UUID 打错 / `servers` 缺 address / 协议名不支持（如 `vless` 拼成 `veless`）。
- **用户可见现象**：实例正常启动；指向该出站的全部分流在连接建立瞬间被重置，客户端侧表现为目标站「连接被重置」，服务端仅 warn 级日志。
- **Go 对照**：未知协议/UUID 解析失败在 `infra/conf` Build 阶段返回 error → `core.LoadConfig` 失败，**进程拒绝启动**（fail-fast）。
- **快速验证**：配 invalid-UUID vless + 路由规则指向其 tag → Rust 启动绿、`curl` 经该分流即断 + 日志 `non existing outTag`；Go 同配置启动报错。

### P1-7 UDP dispatch 链路无空闲超时（Go 1 分钟闲置终止会话）

- **根因**：
  - `crates/xray-app-dispatcher/src/udp_session.rs:21-24` 自注：**「ponytail: 无内置空闲超时……若后续出现长生命周期无控制连接的 UDP 入站（tun/fakeDNS），再补 idle deadline」**。
  - `crates/xray-proxy-freedom/src/udp.rs:429-436`（`pump_response`）`sock.recv_from` 裸循环无 deadline；`udp.rs:141` `let _ = resp_task.await;`——relay 任务生命周期完全取决于入站侧何时关 duplex。UDP dispatch 的 duplex（udp_session.rs:80 `tokio::io::duplex`）不带 idle_timeout（TCP dispatch 管道有，default.rs:983/1089）。
- **触发条件**：UDP 会话建立后停止流量但控制面存活——dokodemo UDP 长驻、tun/fakeDNS 类入站、或 ss-2022 UDP 关联的 TCP 控制连接未断。
- **用户可见现象**：无即时现象；每条僵尸会话滞留 1 个 relay task + 1 个 UDP socket（fd），长跑进程 fd/内存缓慢上涨；被 NAT 保活的空洞会话同样滞留。
- **Go 对照**：`transport/internet/udp/dispatcher.go:102`：`entry.timer = signal.CancelAfterInactivity(ctx, entry.terminate, time.Minute)`——**1 分钟无流量终止会话**。
- **快速验证**：dokodemo UDP 发一包后静置 10 分钟，`proc` 观察任务数/fd 不回落（Go 版 1 分钟回收）。[INFERENCE] socks UDP 场景随 TCP 控制连接 abort 收敛，泄漏面以 dokodemo/tun 为主。

---

## P2（性能级/低可见性）

### P2-1 splithttp H1/H2 每次拨号新建 client + TCP+TLS+h2 握手，连接不复用

- **根因**：`crates/xray-transport-splithttp/src/register.rs:234-237`——`DefaultDialerClient::new(...)` 在每次 `dial_splithttp` 内构造；下载/上传流同生共死，h2 连接不跨 dispatch 复用（`dialer.rs:69-70` 注释「hyper 连接按不可复用处理」）。
- **现象**：CDN 场景每条代理连接多付 1-2 RTT 的 TCP+TLS+h2 建链（对 CF 高 RTT 账单明显）；短连接高频场景吞吐显著低于 Go。
- **Go 对照**：`transport/internet/splithttp/dialer.go:352-395` `getHTTPClient(ctx, dest, ...)` 按 destination 缓存 client/连接（`globalDialerAccess` 全局表）。
- **验证**：同 host 连续开 10 条连接抓包：Rust 10 次完整握手，Go 1-2 次。

### P2-2 removed transports（h2/http）宽容 warn 继续启动，且 "h2"/"http" 被 grpc dialer 劫持

- **根因**：`crates/xray-transport/src/dialer.rs:129-135`（`removed_feature_warnings` → `xray_common::log::warning` 后继续解析，注释自认「Go infra/conf 硬报错；Rust 保留宽容行为」）；`dialer.rs:462` `"http" | "h2" | "grpc" => Some("grpcSettings")` + `xray-transport-grpc/src/register.rs:51-53` 把 `"grpc"/"h2"/"http"` 三个名字注册到同一 grpc dialer。
- **现象**：legacy `network:"h2"` + `httpSettings` 配置：启动成功（仅 warn）→ 配置被静默解释为 gRPC（httpSettings 键名不匹配 grpcSettings 而丢失）→ 拨号走 gun 协议对普通 h2 服务端 → 连接失败/挂起，错误无指向性。`network:"quic"` Go 已移除、Rust 仍全功能支持（功能冗余型偏差，暂无害）。
- **Go 对照**：`infra/conf/transport_internet.go:988-991` removed-feature 硬错（Rust 测试 `removed_warnings_*` 逐字对齐了 Go 文案但只降级为 warn）。
- **验证**：配 `network:"h2"` 启动 + 拨号；对照 Go 启动报 "has been removed"。

### P2-3 静默失败低可见性簇（debug 级日志吞根因）

- `crates/xray-proxy-vmess/src/dispatcher.rs:337-341`：`decode_response_header_async` 失败 → `tracing::debug!` + shutdown——响应头解密失败（密钥/算法不匹配）只留 debug 行，生产默认日志级别下连接「无声死」。
- `crates/xray-transport-splithttp/src/dialer.rs:98-101,127-129`（packet-up 上行 pump）：`post_packet` 失败/pipe 读错 → `debug!` + break——上传通道死亡后下行 GET 仍开着，靠写端背压（pipe 满）才让上层感知，错误根因（CDN 拒绝 POST 等）默认级别不可见。
- 对照：Go 侧同类失败走 `errors.LogWarningInner(ctx, ...)` 且 splitConn onClose 整链拆除，失败语义即时传播。
- **验证**：RUST_LOG 非 debug 下模拟 CDN 502/假 vmess key，观察连接死而无日志。

---

## 吹毛（可不改）

| # | 位置 | 问题 |
|---|---|---|
| C1 | `crates/xray-transport-grpc/src/register.rs:61-62,79-82,93-96` | 三处注释称「当前返回 Unsupported」，实际 dial/listen 已实现且测试断言非 Unsupported（register.rs:199-221）——注释过期误导审计。 |
| C2 | `crates/xray-transport-kcp/src/dialer.rs:77-85` | `dial_kcp(factory, dest)` stub 返 `Err(Unsupported)` 为死代码：生产注册走 `register.rs:67-77` 的完整实现（同名不同签名）。建议删除防误读。 |

## 已核验为「与 Go 一致 / 非缺陷」清单（避免重复审计）

1. **非法指纹名 → 标准 TLS**（ws `client.rs:125-127`、httpupgrade、tcp、grpc、splithttp 同构）：Go `transport/internet/{websocket,dialer.go:75,grpc/dial.go:135-139,splithttp/dialer.go:135-139,httpupgrade/dialer.go:68}` 全部是 `GetFingerprint` 返 nil → 标准 TLS 的**同款语义**（REALITY 例外：Go `reality.go:158-161` 硬错，Rust `xray-reality/client.rs:449-451` 同为硬错）。✔ 对齐。
2. **u_client 清单外指纹硬错**（`xray-tls/src/utls.rs:509-511`「不再静默回退 rustls」；`fingerprint.rs:148`+`btls_client.rs:1613-1617` 测试锁定）。历史静默回退已修复。✔
3. **路由指向不存在的 outbound**：Rust `default.rs:1250-1255` shutdown 不落默认出站 = Go `default.go:469-470` DO NOT CHANGE 语义。✔
4. **TUIC 出站 UDP**：专用 `TuicUdpDispatch`（`outbound.rs:2511-2540`，票 z9gp，注释明言修复过「UDP 被当 TCP 载荷静默发出」）。✔ 唯一做了 UDP 专桥的 QUIC 族出站。
5. **trojan / ss / freedom / hysteria 出站 UDP 分支完备**：trojan `dispatcher.rs:131-146`（TrojanUdpFramedConn）、ss `dispatcher.rs:496-500`（XUDP-over-TCP）、freedom `udp.rs relay_policy`、hysteria `dispatcher.rs:346-354`（tcp()/udp() 按 network 分派）。✔
6. **KCP / Hysteria / QUIC transport 客户端拨号已实装**：kcp `register.rs:65-77` 完整链（配置→UDP hub→Connection）；hysteria `register.rs:35-45`（quinn+h3）；quic `transport.rs:45-110`（强制 TLS 硬错 + 16s 超时）。旧「Unsupported」注释均过期。✔
7. **grpc/quic 拨号超时**：grpc `transport.rs:70-74`（16s TCP connect 包装）+ h2 keepalive PING/PONG（:185-221，含 H5 修的 20s 默认 pong timeout）；quic `transport.rs:64-108`（DNS+握手整段 16s）。✔ 无缺超时裸 connect。
8. **ws/httpupgrade CDN 细节**：Host 三级回退（httpupgrade register.rs:220-235，Go dialer.go:83-89）、SNI/Host 与拨号目标解耦、ALPN 强制 http/1.1 防 CDN 协商 h2、45s keepalive + SO_RCVBUF（88m0/0kqj）。✔ 对齐。

## 覆盖说明（未审范围）

- 入站侧（handle_plain_http 模板已在 InboundAudit 范围）；mux 内部（MuxBridge 仅审了 UDP443 skip 装配）；密码学正确性（契约非目标）；性能基准未跑（契约非目标，P2-1/P2-5 为代码级推断）。
- `FreedomHandler`（proxyman `ProxyOutbound` 路径，handler.rs）与 `FreedomDispatchBridge`（生产注册路径）双实现并存，本次以生产路径（outbound.rs:728-747）为准；proxyman 路径未深审。
