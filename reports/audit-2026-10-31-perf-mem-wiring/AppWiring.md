# App 域「配置 → 装配 → 运行期效果」第三层断线审计

- 审计对象：`crates/xray-app-*` 的 8 个域（stats / policy / observatory / reverse / dns / log / router / metrics）
- 审计层位：**第三层**——配置解析了（已由前轮覆盖）、装配跑了（已由前轮覆盖），但**运行期效果不存在**
- 基线：repo `D:/Project/Xray-core-rust` @ `5fe98b90`（`feature/fix-inbound-parity`），二进制 `target/release/xray.exe` `git_rev=5fe98b907c7b...`（与 HEAD 一致，实测 `xray.exe version`）
- Go 基准：`D:/Project/Xray-core` @ `92ccc939`（v26.10.17）
- 只读：本轮未改动任何生产代码；E1 脚本与产物在 `reports/audit-2026-10-31-perf-mem-wiring/{scripts,tmp}/`

---

## 0. 域 × 功能效果矩阵

图例：**生效** = 配置改变运行期行为（有 E1/E2 证据）；**部分** = 仅某一路径/某一档位生效；**失效** = 装配完成但运行期无任何效果。

| 域 | 功能点 | 配置键 | 装配点 file:line | 运行期消费点 file:line | 效果 | 证据 |
|---|---|---|---|---|---|---|
| stats | inbound/outbound tag 流量计数 | `policy.system.stats{Inbound,Outbound}{Uplink,Downlink}` | `wiring.rs:551-572`（inbound）、`default.rs:1426-1443`（outbound routed）、`default.rs:1063-1105`（dispatch 直连） | 计数包 `maybe_wrap_reader/writer` → `AppStatsFeature::collect`（`register.rs:698-707`）→ `/metrics`、`/debug/vars`、gRPC | 生效 | **E1**：B 案 `/metrics` 得 `xray_traffic_bytes{type="inbound",tag="socks-in",direction="uplink"} 5`；A 案无该指标 |
| stats | per-user 流量计数 | `policy.levels.N.statsUser{Uplink,Downlink}` | `register.rs:492-501` → `Policy.stats`；`default.rs:1248` 取 `policy_for_level(access.level).stats` | `default.rs:1453-1468` 按 `access.email` 懒注册 `user>>>email>>>traffic>>>*` | 生效 | E2：`vless` 侧 `access.email/level` 有生产者（`xray-proxy-vless/src/inbound/server.rs:405,867`）；`AppStatsFeature` 真实 manager 注入 `functions.rs:371-373` |
| stats | per-user 在线 IP（online map） | `policy.levels.N.statsUserOnline` | `register.rs:492-501`；`default.rs:1470-1483` | `get_or_register_online_map("user>>>email>>>online")` + `OnlineIpGuard`（`default.rs:854-860`）随连接结束 `RemoveIP`；读侧 `command.rs:392-410` / `:423-447` | 生效 | E2：guard 生命周期与连接 fut 绑定；`dispatcher` 测试 `default.rs:3340-3481` 覆盖开/关两态 |
| stats | stats gRPC API（GetStats/QueryStats/GetAllOnlineUsers） | `api.services: ["StatsService"]` | `register.rs:764-767`（声明 marker）+ `functions.rs:506-512`（注入真实 `DefaultStatsService`） | `xray-app-commander/src/grpc.rs:404,1028` 注册 tonic `StatsServiceServer` | 生效 | E2：后端非 no-op；`declared-but-no-backend`/`backend-but-not-declared` 两态在 `commander.rs:1297-1355` 有实现 |
| policy | system 统计门（四门） | `policy.system.stats*` | `register.rs:513-530` → `SystemStats`；`default.rs:1244-1247`、`wiring.rs:552-564` 取 `for_system()` | 门控 counter 懒注册（关 = 永不注册） | 生效 | **E1**：A（无 policy 块）零计数指标；B（四门全开）指标出现 |
| policy | 连接空闲超时 | `policy.levels.N.connIdle` | `convert.rs:39-43` → `TimeoutPolicy.connection_idle` | 仅出站桥 `xray-transport/src/bridge.rs:347,592,698`（`bridge_link_with_stream_full`/`_link`）；注入 `arm_builders/outbound.rs:64-66,113-115`（freedom，出站 `userLevel`）、`xray-core/src/outbound.rs:411-413`（其余出站固定 **level 0**） | 部分 | **E1**：`connIdle=2` → 空闲 6s 后代理连接被拆（`conn_alive_after_idle=false`）；无 policy 默认 300s → 仍存活 |
| policy | 连接缓冲上限 | `policy.levels.N.bufferSize` | `register.rs:503-509`（KB→字节）→ `convert.rs:69-77` → `Policy.buffer.connection` | 只有两处 pipe：`default.rs:1043-1047`（`dispatch_with_access`，生产入站**不走**该函数）与 `default.rs:1993-1998`（代理链 pipe，**硬编码** `BufferPolicy::default()`） | **失效** | E2：生产入站 `xray-core/src/inbound.rs:629`（socket 双半部直接 `Link::new`）→ `wiring.rs:638` `dispatch_link`，全程无 dispatcher pipe；`dispatch_with_access` 生产唯一调用方是 DNS TCP 拨号（`functions.rs:794`） |
| policy | 半关闭窗口 | `policy.levels.N.uplinkOnly/downlinkOnly` | `convert.rs:44-52` | 只有 `bridge_link_with_stream_full`（`bridge.rs:398-400,443,497`）；注入点同 connIdle | 部分 | E2：per-user level 从不参与——`dispatch_link` 只取 `.stats`（`default.rs:1248`），`timeout` 被丢弃 |
| policy | 握手超时 | `policy.levels.N.handshake` | `arm_builders/inbound.rs:79,120,381,975` `handshake_timeout_for(policy, config.user_level)` | 入站握手 `tokio::time::timeout`（如 `xray-core/src/inbound.rs:612-620`） | 部分 | E2：只认**入站级** `userLevel`（socks/http/hysteria settings），不认认证用户的 `users[].level`；freedom 出站按 `settings.userLevel`（`arm_builders/outbound.rs:64-66`） |
| observatory | 定时探测（interval/url + 出站选择） | `observatory.{subjectSelector,probeInterval,probeUrl}` | `functions.rs:452-463` 注入 `RealOutboundProbeExecutor` + `RealOutboundSelector`（`OhmTagSelector`） | `observer.rs:253-258`（interval）、`:1489`（url）、探测循环 `:253-300` | 生效 | **E1**（间接）：配 `subjectSelector` 后进程正常启动 —— `ObservatoryFeature::start` 缺 IO 会 `StartFailed`（`feature.rs:88-101`），能启动即证明 `set_io` 生效 |
| observatory | 观测结果 → balancer（leastping/leastload） | `routing.balancers[].strategy` + `observatory` app | `functions.rs:290-298` 建 `ObservatoryProviderBridge` | `wiring.rs:721-731` 传入 `Router::init`；`router.rs:364-400` 建策略；`strategy_leastping.rs:47-80` 读快照 | 生效 | E2：无 observatory 时落 `StubLeastPing/Load`（`router.rs:421-434`），有则真策略 |
| observatory | 观测状态对外暴露（metrics/debug） | `observatory` app 存在 | 无装配点 | `metrics` 侧永远拿不到（见 metrics 行） | **失效** | **E1**：见 metrics 第 3 行 |
| observatory | burstObservatory 探测 | `burstObservatory.*` | `functions.rs:464-473` `bf.set_io(RealOutboundProbeExecutor)` | `burst/healthping_stats.rs` + `burst_observer.rs` | 生效 | E2：与主 observatory 同源注入，`set_io` 有"已注入跳过"保护 |
| reverse | app/reverse portal + bridge | `reverse` app（proto） | `register.rs:598-611`（factory）**无** `set_deps` 调用 | `reverse.rs:207-216`：`deps` 为 `None` → `tracing::warn!` + `Ok(())`，`Reverse` 从不构造 | **失效** | E2：全仓 `.set_deps(` 仅 `reverse.rs:502,534`（测试）；生产零调用 |
| reverse | vless inbound 反向接入（portal 侧 Rvs） | vless 入站 + `users[].reverse.tag` | 生产装配**未设置** `enable_reverse` / `reverse_registry` / `reverse_ohm`（`xray-core/src/arm_builders/inbound.rs`、`inbound.rs` 零命中） | `xray-proxy-vless/src/inbound/server.rs:775-790` 直接 warn+close | **失效** | E2：字段默认 `false/None`（`server.rs:56-69,1880-1882`）；全仓无生产赋值点 |
| reverse | vless outbound 反向拨号（bridge 侧发 Rvs） | outbound `users[].reverse.tag` | `xray-core/src/outbound.rs:977-1019` → `VlessOutboundConfig.reverse` | `xray-proxy-vless/src/dispatcher.rs:329-346` 反向域名 → `command=Rvs` | 生效 | E2：反向域名未装配时**显式报错**，不静默当 TCP |
| reverse | 反向 carrier 保活/重连（ReverseMonitor） | — | 无 | `ReverseMonitor::new` 仅 `reverse.rs:147-217`（测试） | **失效** | E2：全仓无生产方式实例化 |
| dns | 静态 hosts | `dns.hosts` | `jsonconf.rs:312-317` | `server.rs:262-281` `StaticHosts::lookup`（含域名替换 + `#rcode`） | 生效 | E2：`server.rs:1158-1175` 契约测试 |
| dns | 查询族策略 | `dns.queryStrategy` / per-server `queryStrategy` | `jsonconf.rs:210-211,459` | `server.rs:242-259`（服务级钳制）、`nameserver/mod.rs:216-234`（client 级） | 生效 | E2：`UseSys` 走 `check_routes()` |
| dns | 缓存 / 禁用缓存 / serveStale / 负缓存 | `dns.disableCache`、`serveStale`、`serveExpiredTTL`、`negativeTtlSecs` | `jsonconf.rs:462-464` → `NameServerConfig`；`udp.rs:128-138` 建 `CacheController` | `udp.rs:377` → `cached::query_ip`（`cached.rs:106-190`）；`cache_controller.rs:189` disable 短路 | 生效 | E2：cache 命中/过期/负缓存均有 `cached.rs:407-567` 用例 |
| dns | server 选择 + disableFallback | `dns.servers[].domains`、`disableFallback`、`disableFallbackIfMatch` | `jsonconf.rs:327-328`、`server.rs:55-57` | `server.rs:190-212` `sort_clients`；`:197` 兜底门控 | 生效 | E2（前轮已覆盖匹配器构造；本轮确认两个字段确有运行期读者） |
| dns | 系统 hosts 合并 | `dns.useSystemHosts` | `jsonconf.rs:313-317` | 同 hosts 查询路径 | 生效 | E2 |
| log | access log 落盘 | `log.access` | `register.rs:246-299` → `LogConfig`；`functions.rs:399-402` 装 `LogInstanceSink` | `instance.rs:858-866` → `Access` 通道 → `FileHandler::write_line`（`instance.rs:489-520`） | 生效 | **E1**：文件得 2 行 `2026/10/31 ... from ... accepted tcp:localhost:2504 [socks-in -> direct]` |
| log | DNS 查询日志 | `log.dnsLog` | `instance.rs:780-790` 注册 `Channel::Dns`；`register.rs:267` | `instance.rs:861-866` 门控 `LogEntry::Dns` —— **全仓无 `LogEntry::Dns` 生产者**（仅测试构造 `instance.rs:1166-1230,1400,1418,1596`） | **失效** | **E1**：`dnsLog=true` + 两次域名目标经 DNS 解析 → access.log 只有 2 行 access，无任何 DNS 行 |
| log | 地址掩码 | `log.maskAddress` | `register.rs:299` → `LogConfig.mask_address` | `instance.rs:888-933` `mask_entry`（access/dns/general 逐字段） | 生效 | E2：`mask.rs:147-264` 覆盖 half/full/自定义 |
| log | 等级过滤 | `log.loglevel` | `register.rs:246-267` | `instance.rs:689-700` `general_level_filter` + `instance.rs:870-880` `handle` 内 severity 门 | 生效 | E2：`Unknown` 归一到 Warning（Go 缺省） |
| log | 日志写失败可见性 | `log.access`/`log.error` 不可写 | `FileHandlerCreator::create` 不 open（`instance.rs:551-566`） | `instance.rs:519-540`（Windows）/`:489-517`（unix）open/write 失败**只** `dropped+=1` | **失效（静默）** | **E1**：`access: "Z:/definitely-missing-dir/access.log"` → 进程正常监听、stdout 零告警、访问日志全程丢失（Go 在 `common/log/logger.go:168-174` 启动期 open 失败即返错） |
| router | domainStrategy 解析选路 | `routing.domainStrategy` | `wiring.rs:787-789`（JSON→proto）| `router.rs:183-212` `pick_route_resolved` → `dns.lookup_ip`（`:213-227`）；派发侧 `default.rs:1338` | 生效 | E2：`functions.rs:340-348` 注入 `DnsClient`；`IpIfNonMatch` 两轮语义在 `:196-206` |
| router | 规则 webhook 通知 | `routing.rules[].webhook` | `wiring.rs:955` `parse_webhook_config` → `rule.rs:128-130` | `rule.rs:80-83`（`Rule::apply` 命中即 `fire`）← `router.rs:168` | 生效（失败静默） | E2：`let _ = wh.fire(&ev)` 丢弃错误；`webhook.rs:173-264` 同步阻塞 HTTP（5s 超时）跑在路由热路径 |
| router | ruleTag（API 增删/去重） | `routing.rules[].ruleTag` | `wiring.rs:922` | `router.rs:94-95,238-265`；`commander/src/grpc.rs:684-708` | 生效 | E2 |
| router | balancer（random/roundrobin/leastping/leastload） | `routing.balancers[]` | `wiring.rs:962-1000`（含 leastload settings→TypedMessage） | `router.rs:346-419` `build_balancer` + `balancing.rs:99-260` | 生效 | E2：未知 strategy 拒启（`wiring.rs:991-998`）；空 selector 拒启 |
| router | attributes 匹配 | `routing.rules[].attrs` | `wiring.rs:948-954` | `condition.rs:474` 读 `ctx.get_attributes()`；生产者仅 router-command/TestRoute（`commander/src/grpc.rs:865`） | 部分 | E2：与 Go 一致——Go 侧 attributes 也只有 `app/router/command` 注入（`features/routing/session/context.go:143`） |
| metrics | `/metrics` + `/debug/vars` HTTP 服务 | `metrics.listen` | `register.rs:445-471` → `MetricsFeature`；`functions.rs:376-379` 注入 stats 收集器 | `metrics.rs:419-503` 真 bind/listen/serve；`serve_one` `:527-563` | 生效 | **E1**：两案均能 GET 到 Prometheus 文本与 expvar JSON |
| metrics | stats 聚合口径 | 同上 | `register.rs:698-707` `StatsCollector for AppStatsFeature` | `metrics.rs:57-110` `parse_counter_name`/`aggregate_counters` | 生效 | **E1**：`type/tag/direction` 三维正确 |
| metrics | observatory 状态暴露 | observatory app 存在 | **无**（`MetricsFeature::with_obs_collector` 仅测试：`tests/feature_start.rs:161`、`tests/prometheus_e2e.rs:114`） | `metrics.rs:548-552` `obs.as_ref().and_then(...)` 恒 `None` → `debug.rs:169-173` 输出 `null`、`metrics.rs:296-303` 段落不产生 | **失效** | **E1**：配 `observatory{subjectSelector:["direct"],probeInterval:"1s"}` + 3.5s 运行 → `/debug/vars` `"observatory": null`，`/metrics` 无 `xray_observation_extra`（Go：`app/metrics/metrics.go:157,204-217` 会输出 outbound 状态） |
| metrics | `metrics.tags` | `metrics.tags` | `xray-conf/src/app_config.rs:159`（Rust 独有字段） | 全仓无读者（proto `Metrics.Config` 只有 `tag`/`listen`） | **失效** | E2：`grep -rn "tags" xray-core/src` 对 metrics 零命中 |

---

## 1. Findings 详情（8 列）

严重度：blocker=必修 / 建议=应修 / 吹毛=可不改。**「看似在用的证据」= 谁在调；「实际失效的证据」= 结果流向哪里 / 谁从没被调。**

| # | 域 | 功能点 | 严重度 | 看似在用的证据（file:line） | 实际失效的证据（file:line） | 生产可达性 | E1/E2 + 命令 | 建议一行 |
|---|---|---|---|---|---|---|---|---|
| 1 | reverse | app/reverse portal+bridge | **blocker** | factory 建 `ReverseFeature`（`register.rs:598-611`）；`Feature::start` 被 Instance 正常调用（`reverse.rs:188-227`）；`Reverse::init/start` 实现完整（`reverse.rs:181-190`） | `set_deps` **零生产调用**（全仓只 `reverse.rs:502,534` 测试）→ `start` 走 `deps==None` 分支：`tracing::warn!` + `Ok(())`（`reverse.rs:207-216`），`self.inner` 永远 `None`，`close` 也是空转 | 高（任何声明 `reverse` app 的配置） | E2：`grep -rn "\.set_deps(" crates` → 仅 reverse.rs 两处测试 | 在 `functions.rs` 装配段给 `ReverseFeature` 注入 dispatcher + registrar（与 observatory `set_io` 同型），或让它 `StartFailed` 而非 warn |
| 2 | reverse | vless inbound portal 侧（Rvs 接入） | **blocker** | inbound 侧完整实现：注册表查找 → ohm 取 `PortalOutbound` → dispatch（`xray-proxy-vless/src/inbound/server.rs:756-830`） | 生产装配从不设 `enable_reverse=true` / `reverse_registry` / `reverse_ohm`（`xray-core/src/arm_builders/inbound.rs` 与 `inbound.rs` 对这三个词零命中）→ 收到 `command=Rvs` 直接 `warn + close`（`server.rs:775-783`） | 高（v26 唯一的反向代理形态就是 vless reverse） | E2：字段默认 `false/None`（`server.rs:56-69`） | `arm_builders` 的 vless 入站构造按 outbound `reverse.tag`/入站用户 reverse 配置填这三个字段，否则整块能力等于不存在 |
| 3 | reverse | ReverseMonitor（carrier 保活） | 建议 | 状态机实现完整（`xray-proxy-vless/src/outbound/reverse.rs:49-120`）；`lib.rs:66` 导出 | `ReverseMonitor::new` 只在同文件测试出现（`:147-217`），生产无实例化 → 反向隧道无连接数维护/重连 | 中（依赖 #1/#2 修好后才暴露） | E2 | 随 #1/#2 一起接：bridge worker 启动处建 monitor |
| 4 | policy | `bufferSize` 全链路 | **blocker** | 解析完整：`register.rs:503-509`（KB→字节、负值=-1）→ `convert.rs:69-77` → `Policy.buffer.connection`；`pipe.rs:107-108` 支持 `limit` | 唯一消费点 `default.rs:1043-1047` 在 `DefaultDispatcher::dispatch_with_access`，而生产入站走 `inbound.rs:629`→`wiring.rs:638` 的 `dispatch_link`（无 pipe）；另一处 `default.rs:1993-1998` 硬编码 `BufferPolicy::default()`（连配置的 level-0 都不读，只读 env） | 高（任何配了 `bufferSize` 的部署） | E2：`grep -n "dispatch_with_access" crates/xray-core/src/functions.rs` → 只有 DNS TCP 拨号 `:794` | 在 `dispatch_link` 建链/桥接处按 `policy_for_level(access.level).buffer` 建 pipe，或删掉 `bufferSize` 的解析避免假承诺 |
| 5 | policy | per-user level 的 timeout/buffer | **blocker** | `dispatch_link` 明确按 `access.level` 查策略（`default.rs:1236-1238`），`access.level` 有真实生产者（`xray-proxy-vless/src/inbound/server.rs:405,867`、`xray-proxy-trojan/src/server.rs:636`） | 查到的 `Policy` **只取 `.stats`**（`default.rs:1248`），`timeout`/`buffer` 丢弃；`wrap_bridge` 对所有非 freedom 出站固定 `policy_for_level(pm, 0)`（`xray-core/src/outbound.rs:411-413`），freedom 用出站 `settings.userLevel`（`arm_builders/outbound.rs:64-66`） | 高（多 level 用户配置） | **E1**（对照）：level 0 `connIdle=2` 生效；E2：`default.rs:1250-1530` 段内 `policy` 无 `timeout`/`buffer` 使用点 | 把 `access.level` 的 `timeout` 传给该连接实际使用的桥；分 level 限流才有意义 |
| 6 | log | `dnsLog` | 建议 | 装配齐备：`register.rs:267` 落 `enable_dns_log`；`instance.rs:780-790` 注册 `Channel::Dns`；`handle` 有 Dns 分支与门（`instance.rs:861-866`） | `LogEntry::Dns` **零生产者**（全仓构造仅 `instance.rs:1166-1230,1400,1418,1596`，全在 `#[cfg(test)]`）；DNS 侧只发 raw `tracing::info!(target:"xray.dns")`（`server.rs:272,362,542,659`），不进 LogInstance → 不进 access 文件、不受 `loglevel`/`maskAddress` 管 | 高（`dnsLog:true` + 文件 access log） | **E1**：`python reports/audit-2026-10-31-perf-mem-wiring/scripts/e1_log_dnslog.py` → 2 次域名目标解析、access.log 仅 2 行 access、0 行 DNS | 在 `DnsService::lookup_ip`/`serial_query` 处 `LogInstance::handle(LogEntry::Dns{..})`（Go `app/dns/dns.go` 同点），或直接删掉该配置面 |
| 7 | log | 日志写失败可见性 | **blocker**（日志证据缺失） | `FileHandler` 有 `dropped` 计数（`instance.rs:563-565`）；`dropped_total()` 可查（`instance.rs:845-848`） | `create` 不 open（`instance.rs:551-566`），写时 per-write open，失败只 `dropped += 1`（`instance.rs:519-540` Windows / `:489-517` unix），**无任何日志/启动失败**；对比 Go `common/log/logger.go:168-174` 启动期 open 失败 → 返错 → 启动失败 | 高（路径打错/权限不足/磁盘满） | **E1**：`access:"Z:/definitely-missing-dir/access.log"` → 进程正常监听、stdout 只有 2 行 INFO、无告警 | `FileHandlerCreator::create` 里试 open 一次并把错误上抛（否则"日志已开"是假象）；`dropped` 增到阈值时至少 warn 一次 |
| 8 | metrics | observatory 状态暴露 | 建议 | `ObservationCollector` trait 完整（`metrics.rs:112-120`）；`/debug/vars` 与 `/metrics` 都有产出路径（`debug.rs:169-173`、`metrics.rs:296-303`）；`with_obs_collector` 存在（`feature.rs:88-90`） | 生产**无注入点**：`with_obs_collector` 仅测试调用（`tests/feature_start.rs:161`、`tests/prometheus_e2e.rs:114`），`feature.rs:55,111` 的 `obs` 恒 `None` → `"observatory": null`、`xray_observation_extra` 永不出现 | 高（配了 observatory + metrics 的部署） | **E1**：`python .../scripts/e1_observatory_metrics.py` → `debug_vars_observatory: null`、`metrics_has_observation_section: false` | 在 `functions.rs` metrics 注入 stats 的同一段加 `set_obs_collector(ObservatoryProviderBridge...)`（需要一个 `&self` 版 setter） |
| 9 | metrics | `metrics.tags` | 吹毛 | 配置面存在（`xray-conf/src/app_config.rs:159`） | 无读者：proto `Metrics.Config` 只有 `tag`/`listen`，`xray-core` 侧对 metrics 的 `tags` 零命中 | 高（但该字段 Go 没有） | E2 | 删字段，或补语义 |
| 10 | router | webhook 失败静默 + 热路径阻塞 | 建议 | 触发点接好：`Rule::apply` 命中即发（`rule.rs:76-84`）← `router.rs:165-175` | `let _ = wh.fire(&ev)`（`rule.rs:82`）丢弃 `Err`：连不上/非 2xx 无任何日志（`webhook.rs:173-264` 内部只有成功 `debug!`，失败只返回 Err）；且 `fire` 是同步阻塞 HTTP（5s 超时）跑在选路必经路径 | 中 | E2 | 失败按 Go `errors.LogWarning/LogInfo`（`webhook.go:183-191`）记一条；发送改 `spawn` 异步 |
| 11 | stats | per-user 计数依赖 level 开关 | 吹毛 | `default.rs:1453-1483` 三开关齐全 | 开关取自 `policy_for_level(access.level).stats`（`default.rs:1248`），用户配 `users[].level` 但 level 段未写 `statsUserUplink` → 默认 `false`（`convert.rs:61-67`），per-user 计数静默为零（Go 语义相同，但配置者极易误判） | 高 | E2 | 文档标注 or 启动期 warn"配了用户 level 但该 level 无 stats 段" |

---

## 2. 安全后果（按契约升 P0/P1 的部分）

| 等级 | 项 | 后果 | 判据 |
|---|---|---|---|
| **P1** | #7 日志写失败静默 | 运维看到"access log 已配置"、文件存在与否都可能为空，事故时**无访问证据**；Go 会在启动期直接失败，Rust 不 | 契约「任何导致日志证据缺失的升 P1」 |
| **P1** | #1/#2 reverse 全链失效 | 用户以为配了反向代理（内网穿透/隐蔽通道），实际 portal 侧一律 close；**依赖该通道的运维面完全不存在**，但配置检查/启动均通过（仅一条 warn） | 契约「装配跑通但运行期不存在」+ 隐蔽通道断裂 |
| **P2** | #6 `dnsLog` 失效 | 排查 DNS 污染/劫持时**无 DNS 证据**（且 raw `tracing` 路径绕过 `maskAddress`，若将来有人把日志接回 access 文件会**裸写 IP，绕过掩码**） | 契约「日志证据缺失」的次要分支 |
| **P2** | #4/#5 bufferSize / per-user timeout 失效 | 运维按"给低等级用户更小缓冲/更短窗口"设计容量与限流，实际按默认 512KiB / 300s 跑 → **背压与断流行为与配置不符**，容量误判可能放大内存占用 | 配置不生效导致资源/限流语义漂移 |
| **P3** | #10 webhook 失败静默 | 依赖 webhook 做命中审计/告警的链路静默残缺 | 通知链证据缺失 |

**凭据泄露：本轮未发现**（access log 掩码 `mask_entry` 覆盖 from/to/reason/content；`maskAddress` 生效路径确认）。

---

## 3. E1 复现命令

```bash
# 1) stats 生效（正）/ policy.system 门（反）+ policy.connIdle 生效（对照）
python reports/audit-2026-10-31-perf-mem-wiring/scripts/e1_stats_policy.py
#   A_no_policy                    → conn_alive_after_idle=true, /metrics 无 xray_traffic_bytes
#   B_policy_connidle2_stats_on    → conn_alive_after_idle=false,
#                                    xray_traffic_bytes{type="inbound",tag="socks-in",direction="uplink"} 5

# 2) metrics 不暴露 observatory 状态（配了 observatory 也不暴露）
python reports/audit-2026-10-31-perf-mem-wiring/scripts/e1_observatory_metrics.py
#   → debug_vars_observatory=null, metrics_has_observation_section=false

# 3) access log 真写 + dnsLog 无产出
python reports/audit-2026-10-31-perf-mem-wiring/scripts/e1_log_dnslog.py
#   → access_log_lines=2（格式正确），DNS 行 0

# 4) access log 路径不可写时不报错（日志静默丢失）
#    配置 log.access="Z:/definitely-missing-dir/access.log" → 进程正常监听，stdout 无告警
```

原始产物：`reports/audit-2026-10-31-perf-mem-wiring/tmp/`（`e1_*_debug_vars.json`、`e1_*_metrics.txt`、`e1_log_access.log`、各 `e1_*.json` 配置）。

---

## 4. 未覆盖范围

1. **无法 E1 验证 per-user 计数/online map**（#11、stats 第 2/3 行）：需 vless/trojan 入站 + 认证用户的最小互通环境；本轮只给 E2（代码路径 + 现有测试）。堵塞点：需要 Go/Rust 双端 vless 用户配置，超出单脚本成本。
2. **observatory 观测数据本身是否正确**（延迟/存活判定）：`ObservatoryService` gRPC 零注入（已由前轮报告），无对外读口；本轮只用"配了 subjectSelector 且进程能启动"反证探测执行体已注入，未验证探测结果内容。
3. **`stats` 计数器与 Go 在 mux/UDP/XUDP 场景下的计数一致性**：属于协议数据面口径，未在 8 个 app 域内。
4. **policy 的 `handshake` 在每种入站（vless/trojan/vmess/http/hysteria）上是否都接线**：只抽查 socks 与 `arm_builders` 的调用点，未逐协议验证。
5. **reverse 修好后的端到端互通**（bridge→portal 真链路）：本轮只判"当前不可能工作"，未做修复验证。
6. 平台差异（Windows vs Unix 文件日志路径）按禁报项不报；`#[cfg(unix)]` 分支只做了代码阅读，未在 unix 实机跑。
