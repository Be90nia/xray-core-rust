# 可观测性与统计正确性审计（第二轮补漏）

> 范围：①流量统计计数点 ②日志级别 vs Go ③连接元数据入日志 ④metrics/route stats ⑤panic 路径（网络输入可达）。
> 基准：D:/Project/Xray-core (v26.7.28)。第一轮已报告项不重复（socks 认证绕过、http 握手无界、tuic 帧长、vless ENC 锁等见 docs/audit/AUDIT_SUMMARY.md）。
> 审计方式：只读代码 + Go 基准对照；未改任何源码。

---

## 发现清单

### [P1] 用户级流量统计与在线 IP 统计在生产路径整体未接线 | crates/xray-app-dispatcher/src/default.rs:713-734

**证据**：dispatcher 只注册/包装 `{inbound,outbound}>>>{tag}>>>traffic>>>...` 四类 per-tag counter：

```rust
// default.rs:719-726
let inbound_uplink = inbound_tag
    .and_then(|tag| get_or_register_counter_opt(self.stats.as_ref(), &format!("inbound>>>{tag}>>>traffic>>>uplink")));
...
let outbound_downlink = outbound_tag
    .and_then(|tag| get_or_register_counter_opt(self.stats.as_ref(), &format!("outbound>>>{tag}>>>traffic>>>downlink")));
```

全仓 grep `user>>>` 的注册/累加点：**零个生产位置**（仅 xray-app-stats 自身测试、command.rs 解析器、register.rs 单测）。policy 层 `statsUserUplink/statsUserDownlink/statsUserOnline` 已完整解析（xray-conf/app_config.rs:56-61 → register.rs:427-435 → xray-features/policy.rs:99-108），消费端 command.rs `get_users_stats`/`get_stats`（`user>>>{email}>>>traffic>>>uplink`）、commander、xray-cli `stats`/`stats-online`（api_exec.rs:622 `user>>>{}>>>online`）全部就绪——但中间的生产计数端缺失。同样 `register_online_map`/`get_or_register_online_map` 在生产代码零调用。

**Go 对照**：app/dispatcher/default.go:160-178 `Dispatch` 内按 per-user policy `p.Stats.UserUplink/UserDownlink` 把 `SizeStatWriter` 挂到 inboundLink/outboundLink.Writer；default.go:190-227 `WrapLink`/`trackOnlineIP` 注册 `user>>>{email}>>>online` OnlineMap。

**影响**：配置 `statsUserUplink/Downlink/Online` 后静默无效：`xray api stats --name "user>>>a>>>traffic>>>uplink"` 恒 NotFound，`QueryStats`/`GetUsersStats` 恒空，面板/计费类下游全空转。配置不报错、行为无提示。

**修复建议**：在 dispatcher 拼装 link 处（default.rs:728-734 或 wiring.rs:348-349 附近）按 access.email + policy_for_level(user.level).stats 包装用户 counter（uplink 挂 inbound 侧 writer、downlink 挂 outbound 侧 writer，与 Go 同位）；email 非空且 user_online 时 `get_or_register_online_map("user>>>{email}>>>online")` 并 AddIP/RemoveIP。注意 `Manager::MAX_REGISTRY_ENTRIES=1024`（manager.rs:53）：用户数超过后 register 失败被 `.ok()` 吞掉、静默不计——修复时需一并放宽或至少 warn。

---

### [P1] metrics 导出器未注入 StatsCollector，/metrics 恒为空 | crates/xray-core/src/register.rs:397-410

**证据**：

```rust
// register.rs:397-410
fn metrics_factory() -> FeatureFactory {
    Arc::new(|data: &[u8]| {
        ...
        let feature = xray_app_metrics::MetricsFeature::new(config);
        Ok(Arc::new(feature) as Arc<dyn Feature>)
    })
}
```

`MetricsFeature` 默认 collector 是 `EmptyStats`（xray-app-metrics/feature.rs:38-43「返回空快照」）；`with_stats_collector`（feature.rs:71-74）全仓唯一调用点是测试 feature_start.rs:78。metrics feature 内部聚合/parse/Prometheus 格式化逻辑（metrics.rs `aggregate_counters`/`parse_counter_name`/`format_prometheus`）本身正确（与 Go app/stats/command/command.go:117-133、app/metrics/metrics.go:175-199 的 4 段 `>>>` 解析语义一致，<4 段跳过），但没有数据源。

**影响**：配置 `"metrics": {"listen": ...}` 后 Prometheus 抓取永远没有 `xray_traffic_bytes`（所有计数为 0 被 `>0` 过滤），观测黑盒；与 P1-1 叠加后整个指标面不可用。

**修复建议**：metrics_factory 构建 feature 后 `with_stats_collector(Arc::new(适配器))`，适配器在 `collect()` 里 `visit_counters` → `aggregate_counters`（stats manager 已有 `AppStatsFeature::manager()` 访问器，register.rs:517-519）；observatory 同理 `with_obs_collector`。

---

### [P1] anytls 出站对 >255 字节域名编码时 panic（网络输入可达） | crates/xray-proxy-anytls/src/socks.rs:56-62

**证据**：

```rust
// socks.rs:56-60  SocksAddr::encode
Self::Domain(host, port) => {
    buf.push(atyp::DOMAIN);
    let host_bytes = host.as_bytes();
    // 域名长度用单字节（RFC 1928 限制 255 字节）
    buf.push(u8::try_from(host_bytes.len()).expect("domain too long"));
```

触发链：HTTP inbound `parse_host_port`（xray-proxy-http/src/server.rs:331-357）对 `CONNECT <host>:443` / Host 头的域名**无长度校验**，任意长字符串直接进 `Address::Domain(String)` → dispatcher 路由到 anytls 出站 → dispatcher.rs:92-96 `dest_to_socks_addr` → client.rs:139 `target.encode()` panic。对比同类编码点全部做了安全截断：vless encoding/mod.rs:148 `u8::try_from(...).unwrap_or(255)` + `&bytes[..len]`、trojan protocol.rs:102 同、vmess mod.rs:249 同、socks protocol.rs:166 `min(255)`。anytls 是唯一 `expect` 硬 panic 的。

**影响**：远端客户端一条 `CONNECT` 请求（Host ≥256 字节）即触发 panic。panic 发生在连接级 spawn 任务内，tokio 任务隔离使其不等价进程崩溃，但每次触发零成本、稳定复现，属远程 DoS 候选；且若 panic 点在未来改动中持锁，将连锁毒化 `expect("poisoned")` 调用点。

**修复建议**：与 vless/trojan/vmess 对齐为截断或显式报错：

```rust
let len = u8::try_from(host_bytes.len()).unwrap_or(255);
buf.push(len);
buf.extend_from_slice(&host_bytes[..len as usize]);
```

---

### [P2] per-tag 流量计数层级与 Go 语义偏差：payload 级（不含 overhead）且无 policy 门控 | crates/xray-core/src/wiring.rs:347-350

**证据**：Rust 的 per-tag 计数挂 dispatcher link（协议解码后的 payload 通道）：

```rust
// wiring.rs:347-350
let reader = maybe_wrap_reader(self.inbound_counter("downlink"), link.reader);
let writer = maybe_wrap_writer(self.inbound_counter("uplink"), link.writer);
```

（出站同：default.rs:967-984 挂 `outbound>>>{tag}` 于 link reader/writer。）Go 的 per-tag 计数挂**裸连接**：app/proxyman/inbound/worker.go:104-110 `stat.CounterConnection{ReadCounter: uplinkCounter, WriteCounter: downlinkCounter}` 包裹 accept 原始 conn，出站同 handler.go:356-363——计数含 TLS record、协议帧头等全部 overhead；且仅在 `policy.ForSystem().Stats.InboundUplink` 等开启时才取 counter（always.go:21-44，默认 false）。

Rust：(a) 计数点在协议解码之后，`inbound>>>{tag}>>>uplink` 不含 TLS/协议开销；(b) 只要有 stats app 就无条件注册计数（default.rs:719、wiring.rs:286-291），不看 `policy_for_system().inbound_uplink`。方向映射本身正确（in up=写、in down=读、out 对称，与 Go 一致）。

**影响**：与 Go 同流量数字系统性偏小（TLS 入站可差数个百分点），运维侧按 Go 口径做的告警/对账失真；默认未开 system stats 的配置下 Rust 仍持续计数并暴露 counters（Go 则 counter 不存在、QueryStats NotFound），行为可观测面不一致；每连接白付 4 次 AtomicI64 add。xray-core/src/functions.rs:2331-2342 的 e2e 只断言 >0，掩盖不了层级差。

**修复建议**：两选一并落注释：①对齐 Go——counter 获取前查 `for_system()` 开关，计数点下沉到 inbound accept 连接包装层（等价 Go CounterConnection）；②保留 payload 级但在文档/统计名上明确口径差异。若走 ②，至少补 system policy 门控消除默认开销差异。

---

### [P2] 拒绝类日志级别 debug ≠ Go AtInfo（vmess 全路径、vless transport/reality 包装路径），且协议层拒绝不产生 access「rejected」记录 | crates/xray-proxy-vmess/src/inbound/server.rs:151-153

**证据**（v48 已把 plain vless 路径 debug→info，以下为漏网同族点）：

```rust
// xray-proxy-vmess/src/inbound/server.rs:151-153
if let Err(e) = result {
    tracing::debug!(error = %e, "vmess connection ended with error");
}
```

```rust
// crates/xray-core/src/inbound.rs:1731-1733（vless transport 路径）
if let Err(e) = xray_proxy_vless::handle_connection_with_fallback(...).await {
    tracing::debug!(error = %e, "vless transport connection ended with error");
// crates/xray-core/src/inbound.rs:1559（reality 路径，Verified 之后）
tracing::debug!(error = %e, "reality vless connection ended with error");
// crates/xray-core/src/inbound.rs:1842-1846（vmess transport 路径，同 debug）
```

认证失败（vmess `UserNotFound`/`InvalidAuth`、vless `InvalidRequestUserId`）全部经由这些 `Err` 分支落 debug。Go 对照：vmess proxy/vmess/inbound/inbound.go:249-250 与 vless inbound.go:521-522 均为 `errors.New("invalid request from ", connection.RemoteAddr()).Base(err).AtInfo()`——级别 info 且**携带来源地址**（Rust 消息无 remote addr）。此外 Go 在这些拒绝点同步 `log.Record(&log.AccessMessage{Status: AccessRejected, ...})`（vmess inbound.go:240-249、trojan server.go:189-204、socks server.go:125-132）；Rust 的 access `status:"rejected"` 只有 dispatcher「no outbound handler」一处（default.rs:835-843、926-935），协议层认证拒绝不产生任何 access 记录。

**影响**：默认配置（tracing info）下 vmess/vless 暴破尝试完全不可见（debug 被滤），v48 修复只覆盖 plain vless 一条路径，同一攻击面在其余三条路径仍盲；开了 access log 的部署也看不到 rejected 条目，审计/封禁链路缺数据源。

**修复建议**：四处 debug→info 并补 `peer` 字段（handle_* 已有 peer 参数的透传即可）；中长期在协议拒绝分支统一回调 access sink 记 `rejected`（对应 Go AccessMessage），socks/vmess/trojan/vless 四协议同改。

---

### [P2] 直连 tracing 日志完全绕过 `loglevel` 配置，连接元数据（目标地址/用户邮箱/peer）默认 info 级对外输出 | crates/xray-cli/src/bin/xray.rs:188-194

**证据**：

```rust
// xray.rs:190-191
let _ = fmt()
    .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
```

`loglevel` 只作用于 xray-app-log 管道（instance.rs:620 `severity <= error_log_level` 门控 General），而生产代码大量直接 `tracing::info!/warn!` 不经过该管道。典型逐连接元数据输出：

```rust
// xray-proxy-trojan/src/server.rs:470
info!(peer = %peer, user = %user.email, dest = %dest, "trojan dispatching");
// xray-app-dispatcher/src/default.rs:886
tracing::info!(tag = %tag, "taking platform initialized detour for [%final_dest]");
// xray-core/src/outbound.rs:1118
tracing::info!(target = %domain, resolved = %ip, "target strategy resolved");
```

Go 对照：连接级「accepted/rejected + 目标地址」只走 access log（Info 级，受 loglevel 默认 warning 隐藏；`access:"none"` 可整体关闭）。Rust 这些直连日志不受 `loglevel:"warning"/"error"` 也不受 `access:"none"` 约束——xray.rs:188 注释自述「默认 level=info」。

**影响**：运营者按 Go 习惯配 `loglevel: warning` / `access: none` 后，stderr 仍默认逐连接打印访问目标、用户邮箱、peer IP——既是日志级别语义与 Go 的系统性偏差（②），也是连接元数据在 info 级的暴露面（③，代理服务里目标域名本身即敏感信息）；高 QPS 下还有 stderr 写放大。

**修复建议**：短期把逐连接类日志（trojan dispatching/udp relay start、detour、target strategy）降为 `debug!`，或改为经 AccessLogSink 走可配置管道；长期在 log feature 初始化时把 `error_log_level` 映射成全局 EnvFilter 默认值（如 warning → `EnvFilter::new("warn")`），使 tracing 与 loglevel 单一事实源。

---

### [P3] >255 域名下行编码：长度字段声明值与实际写入数据不一致（与 Go 同病） | crates/xray-proxy-socks/src/protocol.rs:165-167

**证据**：

```rust
// protocol.rs:165-167（socks UDP relay 下行）
buf.push(bytes.len().min(255) as u8);
buf.extend_from_slice(bytes);   // 声明 ≤255，实际全量写入
```

vmess response header 同型（encoding/server.rs:411-413 `buf.push(domain.len() as u8)` 回绕 + 全量 extend）。Go `byte(len(...))` + 全量 append 行为一致——即 Go 同样腐坏，非 Rust 引入的分歧，仅作记录：一旦上层（P2-3 修复前）有 >255 域名流经 UDP relay/vmess 响应，帧即错位。建议随 P1-3 修复顺手改为「截断 or 拒绝」二选一。

---

## ⑤ panic 路径普查（网络输入可达性人工复核）

全仓非测试代码 `.unwrap()/.expect(/panic!/unreachable!` 统计（排除 `#[cfg(test)]`/`mod tests`/`tests/`，`stress_tests.rs` 为 `#![cfg(test)]` 已剔除）：**共 317 处 / 107 文件**。

| crate | 处数 | crate | 处数 |
|---|---|---|---|
| xray-transport-hysteria | 43 | xray-proxy-vless | 13 |
| xray-proxy-ss | 30 | xray-proxy-tuic | 8 |
| xray-transport | 29 | xray-core | 6 |
| xray-transport-splithttp | 28 | xray-app-version | 5 |
| xray-geodata | 24 | xray-app-dns | 5 |
| xray-tls | 21 | xray-app-router | 5 |
| xray-proxy-vmess | 20 | xray-common | 5 |
| xray-app-dispatcher | 15 | xray-app-proxyman | 3 |
| xray-buf | 15 | xray-proxy-freedom | 3 |
| xray-transport-kcp | 15 | xray-conf | 3 |
| 其余 20 crate | 各 ≤2 | | |

**热路径逐点复核结论**（网络输入可达判据：输入字节直接决定切片/解码路径）：

- `ss2022/packet.rs`（12 处）：全部有前置 `MIN_PLAINTEXT`/`PACKET_HEADER_LEN + eih_len` 长度检查（packet.rs:167-169、197-199、424-426），`try_into().unwrap()` 切片长度由检查保证 → 安全。
- `kcp/segment.rs`（11 处）：Data/Ack/Cmd parse 入口分别有 `body.len() < 14/13/12` 卫语句（segment.rs:194-196、315-317、414-416）→ 安全。
- `splithttp/hub/handler.rs`（9 处）：base64url 解码先 `vals.iter().any(Option::is_none)` 再 unwrap（handler.rs:450-455）→ 安全；`Response::builder`/`.parse()` 为常量头。
- `vmess aead/validator/encoding`（20 处）：锁中毒 `expect("poisoned")`、固定长度 HMAC key、enum 不变量 expect → 非网络触发。
- `geodata matcher`（17 处）：锁中毒 + `len==1` 前置断言 → 输入为本地配置。
- `transport/cnc.rs`（4×`unreachable!`）：状态机 match 穷尽分支，前置 `matches!` 保证 → 安全。
- `hysteria conn.rs / 拥塞控制 bbr/brutal`（43 处）：状态机 `is_none` 卫语句后 unwrap；拥塞算术溢出在 release（wrap）下不 panic，输入为对端带宽/RTT 但有界换算 → 可接受。
- `dispatcher/buf/tls-ech/mux/grpc/httpupgrade/dokodemo/tun` 等：锁中毒、`Some/None` 前置检查后 unwrap、常量地址 parse、`unsafe` 状态重建 → 非网络触发。tun netstack.rs:718 的 family-mismatch panic 输入来自本机内核 TUN，非远端。

**结论：网络输入可达的 panic 仅 P1-3（anytls 域名编码）一处。** 其余 317 处中约 40% 为 std 锁中毒 expect——平时无害，但任何一处真 panic 都会沿「poisoned → expect 级联 panic」放大，长期建议统一 parking_lot（项目已有先例铁律）或 `lock().unwrap_or_else(|e| e.into_inner())`。

---

## 核对为无问题项（避免后人重扫）

- **QueryStats / GetStats reset 语义**：`c.set(0)` 返回旧值（counter.rs:34-38），与 Go `value = c.Set(0)` 等价 ✓。
- **GetUsersStats 聚合口径**：仅以「有 IP 的在线 map」为种子、traffic 只回填已存在用户——与 Go command.go:88-118 完全一致（两者都会丢「只有流量无在线 IP」的用户，属 Go 原语义）✓。
- **计数方向映射**：in up=写/in down=读/out 对称，与 Go CounterConnection 的 Read/WriteCounter 分配一致 ✓；sniff 首包缓存位于 counter 包装层之上，无重复计数 ✓。
- **metrics parse_counter_name**：对 <4 段跳过与 Go metrics.go:182-185 一致（Rust 注释称「Go 会 panic」不实，仅注释错误，行为等价）；`+=` vs Go 覆盖仅在 tag 含 `>>>` 时可区分，不可达 ✓。
- **route stats**：Rust router 命中事件走 webhook（rule.rs:75-78，Rust 扩展）；Go router 无命中计数，无错计 ✓。
- **xray-app-log 管道自身**：access 仅在 access_logger 注册时输出、General 按 severity 门控、maskAddress 挂钩（instance.rs:601-628）与 Go 行为一致 ✓。

---

## 严重度统计与 TOP3

**统计**：P0 × 0；P1 × 3；P2 × 3；P3 × 1（另 1 条记录性备注不计）。合计 7 项发现。

**TOP3**：
1. **用户级统计 + 在线 IP 整体未接线（P1）**——policy/API/CLI 全链路就绪但计数端为零，功能面整体空转，修复价值最大。
2. **metrics 导出器空转（P1）**——一行 `with_stats_collector` 接线即可点亮，与 TOP1 同为「下半截缺失」型。
3. **anytls >255 域名 panic（P1）**——唯一网络输入可达 panic，远端一条 CONNECT 即触发。
