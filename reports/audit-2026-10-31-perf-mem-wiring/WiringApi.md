# R1 接线普查（协议/功能面）— WiringApi

- 日期：2026-10-31
- 分支/HEAD：`feature/fix-inbound-parity` @ `5fe98b90`
- 性质：只读审计，未改任何产品代码
- 生产口径：**生产主路** = `xray.exe run -c` → `xray_conf::Config::build()` → `xray_core::start_full`；**目标主路** = `xray-cli --features framework`（`start_full_with_outbound_handlers`）。每条发现标注在哪条路上可达。

---

## 0. 方法与三源覆盖

| 源 | 做法 | 结果 |
|---|---|---|
| ① `#[allow(dead_code)]` 自供清单 | 全 `crates/**/*.rs` 正则扫描（含属性后首行符号名） | **118 条命中**，逐条定性见 §1（覆盖率 100%） |
| ② stub / NotImplemented 占位 | 扫 `NotImplemented` / `unimplemented!` / `todo!` / `Stub*` / `Noop*` （排除注释行） | 195 行命中 → 去重后 16 个 stub 面，逐条定性见 §2 |
| ③ 图谱零入边 | `codebase-memory-mcp query_graph`：全 Function 节点 11136 个（`/src/` 内），CALLS 边 dst 去重 3632 个 → 零入边 **8115/11136** | 图谱 CALLS 覆盖严重不足（trait 动态分发/宏展开/跨 crate 未建边），**不能直接当死代码清单**，仅作候选池；改用「pub fn 定义 vs 全仓词法引用」补强（详见 §3） |

§3 的补强扫描（文本级，可信度高）：2912 个 `pub`/`pub(crate) fn` 名，逐名统计全仓引用行（排除定义行、`use` 行），得 **68 个「无非测试引用」候选**，逐个定性。

**未用 `cargo build`/单测绿作为接线证据**——本报告所有「生产可达性」结论均以「构造点 grep 命令 + 输出行」呈现。

---

## 1. Findings（8 列，严重度：P0 功能失效/正确性 · P1 安全或静默失效 · P2 性能/资源 · P3 债务）

| # | 标题 | 严重度 | 位置 | 现状（代码做了什么） | 断裂点 | 生产可达性证据 | 建议修法（一行） | 复现/验证 |
|---|---|---|---|---|---|---|---|---|
| W-01 | routing `ruleSet` 加载后即丢弃，`ruleSetTag` 完全不解析 → 规则静默变 catch-all | **P0** | `crates/xray-core/src/wiring.rs:1016-1067`（registry 局部变量）、`:809-823`（规则解析无 `ruleSetTag`）、`crates/xray-app-router/src/rule.rs:96`（`condition.as_ref().is_none_or(...)`＝空条件恒真） | 顶层 `ruleSet` 数组被逐条校验并用 `RuleSetRegistry::load()` 真加载，但 `registry` 是函数局部量，`parse_routing_json_to_proto_in` 结束即 drop；注释自供「Registry 不会被 Router 使用」。`rules[]` 里**没有任何 `ruleSetTag` 解析分支**（只读 outboundTag/balancerTag/domain/domains/ip/port/network/protocol/user/inboundTag/attrs/process）。**注意：Go 26.10.17 无此功能**（`app/router/` 无 `rule_set.go`，`config.proto` 无 `rule_set` 字段 → `grep -rn "RuleSet\|rule_set" *.go` 全仓 0 命中），故 `rule_set.rs:5` 的「对应 Go `app/router/rule_set.go`」「Go xray-core v1.8+ 支持」属**错误的来源标注**——这是 Rust 侧半实现扩展，没有上游可对拍，也因此不会有人发现它不生效。 | **装配环断裂**：解析（有）→ 装配（registry 丢弃）→ 运行期消费（Router 无 rule_set 引用字段）。规则里只剩 `ruleSetTag` 时条件链为空 → `ConditionChan` 零成员 → `apply()` 恒真（`condition.rs:92` `iter().all(...)` 空集为 true，注释 `:59` 自承「空 chan 视为永真」）→ 该规则变成无条件 catch-all，把**本该被 geo 规则限定的流量全量导向该出站**（若 outboundTag 是 block/直连，等于分流与屏蔽同时失效）。 | `grep -rn "ruleSetTag" crates/` → **0 命中**；`grep -rn "RuleSetRegistry" crates` → 仅 `lib.rs:64`（re-export）、`rule_set.rs`（自测）、`wiring.rs:1022`（局部构造后弃用）。Go 侧反证：`D:/Project/Xray-core/app/router/` 无 rule_set 文件、`config.proto` 无该字段。 | 要么补齐 proto `RoutingRule.rule_set` 与 matcher 接线；要么在 `ruleSetTag` 出现时**拒启**（fail-visible），禁止静默 catch-all。同时修正 `rule_set.rs` 的错误来源注释。 |
| W-02 | gRPC `RoutingService` 后端永不注入（声明了也不暴露） | **P1** | `crates/xray-app-commander/src/commander.rs:345`（`set_routing_service`）、`:503-504`（`declared(ROUTING).then(...).flatten()`）；后端实现齐全：`crates/xray-app-router/src/command/mod.rs:21-112`（`RoutingService` + `get_balancer_info`/`override_balancer_target`/`test_route`/`add_rule`/`list_rule`/`remove_rule` 共 8 个真实 op） | 服务端注册表按「声明 ∧ 后端 Some」双条件暴露；`routing_service` 字段初值 `None`，全仓**无任何调用点**赋值 → `flatten()` 恒 `None` → 即使 `api.services` 写 `RoutingService`，该 gRPC 服务也不会注册。 | **装配环断裂**：后端实现（有，8 op 全实现）→ 生产注入点（无）→ 注册（`None` 被 `flatten` 掉，且**不 warn**）。 | `grep -rn "set_routing_service" crates` → 仅 `commander.rs:345`（定义）；`grep -rn "RoutingService::new\|RoutingService::with_router" crates` → 0 命中外调用方（仅 `command/mod.rs` 自测）。 | 在 `xray-core/src/functions.rs` 的 commander 注入块（`:499-521`）加 `commander.set_routing_service(...)`（用 `RoutingService::with_router(Arc<dyn Router>)`）。 |
| W-03 | gRPC `ObservatoryService` 后端永不注入 | **P1** | `crates/xray-app-commander/src/commander.rs:350`、`:505-507`；后端实现齐全：`crates/xray-app-observatory/src/command.rs:41-55`（`DefaultObservatoryService::new(provider)` 已实现 `GetOutboundStatus`） | 同 W-02：字段恒 `None` → ObservatoryService 永不暴露，`xray api` 观测面命令恒 UNIMPLEMENTED。 | 同上（后端有、注入点无、`flatten` 静默） | `grep -rn "set_observatory_service\|DefaultObservatoryService::new" crates` → 前者仅定义；后者仅 `command.rs` 自测。 | 同上，接 `ObservatoryFeature` 的 `ObservationProvider`（`functions.rs:294-297` 已有同源 bridge 可复用）。 |
| W-04 | api outbound 模式（`listen` 缺省）注册不到 SimpleOhm → 连接到不了 API server | **P1** | `crates/xray-app-commander/src/commander.rs:370`（`set_dispatch_registrar`）、`:638-651`（None → 只 warn）、`crates/xray-app-commander/src/server.rs:258`（`SimpleOhmDispatchRegistrar` 真实实现） | `serve_grpc` 的 outbound 分支需要 `dispatch_registrar: Some`，否则打 warn「connections routed to tag X will not reach the API server」。该 setter **全仓仅测试调用一次**（`commander.rs:1102`）。`SimpleOhmDispatchRegistrar` 真实实现早已存在但无人装配。 | **装配环断裂**：实现（有）→ 生产构造点（无）→ 运行期（走 `None` warn 分支，API 连接黑洞）。 | `grep -rn "set_dispatch_registrar" crates` → `commander.rs:370`(def) + `commander.rs:1102`(test)。生产主路无命中。 | functions.rs commander 注入块加 `commander.set_dispatch_registrar(Arc::new(SimpleOhmDispatchRegistrar(Arc::clone(&ohm))))`。 |
| W-05 | splithttp `xmux` 配置全量解析后零消费 | **P2** | `crates/xray-transport-splithttp/src/config.rs:430`（`normalized_xmux` 零调用）、`:127/:137`（`normalized_max_concurrency`/`normalized_c_max_reuse_times` 仅自测）、`client.rs:24` 注释自供「xmux 多路复用 → 切片 E」 | `xmux`（maxConcurrency / maxConnectionReuseTimes / hMaxRequestTimes …）解析进 `XmuxConfig` 并双向映射 proto，但**没有任何消费方**：连接复用策略不看这些值。 | **消费环断裂**：配置（有）→ 装配（有）→ 运行期复用决策（不读）。用户 `xmux` 调优静默无效。 | `grep -rn "normalized_max_concurrency\|c_max_reuse_times" crates` → 仅 `config.rs` 定义 + 自测行。 | 在 splithttp client 的连接复用/换链判定处消费 `normalized_xmux()`；若短期不做，配置期 warn。 |
| W-06 | `tlsSettings.echForceQuery` 解析函数零调用，行为硬编码 `Full` | **P2** | `crates/xray-tls/src/ech.rs:477`（`parse_ech_force_query` 零调用）、`:521`（硬编码 `EchForceQuery::Full`） | 三种取值 full/half/none 的解析与校验都写好（含 Go 同形错误串），但装配处直接传 `EchForceQuery::Full`，配置键**从不被读取**。 | **解析→装配断裂**：JSON 键不进代码路径。写 `echForceQuery: none` 的配置在 Rust 侧照旧发起 ECH 查询（Go 语义是跳过 ECH）。 | `grep -rn "parse_ech_force_query\|echForceQuery" crates` → 仅 `ech.rs` 定义 + 自测。 | tls client 配置装配处调用 `parse_ech_force_query(tls_json)` 并把结果传入 `resolve_client_ech_config_list`。 |
| W-07 | `xray.location.cert` 环境变量解析后零消费 → `certificateFile` 相对路径解析与 Go 不一致 | **P2** | `crates/xray-common/src/platform/mod.rs:24`（`CERT_LOCATION`）、`:56`（`get_cert_path` 零调用）；对照 `crates/xray-tls/src/certificate.rs:256`（`entry_certs_and_key` 直接读原路径） | `CERT_LOCATION` LazyLock 已建，但 `get_cert_path()` 无调用点。Go 侧 `platform.GetCertLocation(file)` 被 `common/platform/filesystem/file.go:79 ReadFile` 消费（在 env 目录 + exe 目录里搜文件名）。Rust 直接 `std::fs::read(原路径)`。 | **配置→消费断裂**。同一份配置：Go 用 `XRAY_LOCATION_CERT` 目录找 `cert.pem`，Rust 按进程 CWD/绝对路径找 → 启动报「文件不存在」或（更糟）读到 CWD 下同名文件。 | `grep -rn "get_cert_path\|CERT_LOCATION" crates` → 仅 `xray-common/src/platform/mod.rs:24,50-57`。Go 侧：`grep -rn GetCertLocation .` → `common/platform/{windows,others}.go` + `filesystem/file.go:79`。 | `read_file_or_string`（`certificate.rs`）改走 `platform::get_cert_path(file)` 语义（env 目录 → exe 目录 → 原路径）。 |
| W-08 | vmess session history 清理任务未接线 → 无界增长 | **P2** | `crates/xray-proxy-vmess/src/encoding/server.rs:64`（`CLEANUP_INTERVAL`）`:87` 注释自供「待 `spawn_cleanup` 后台任务上线」 | `SessionHistory` 每次连接 `add_if_not_exists`（`:237`），过期条目靠 `has_expired` 惰性判定；Go 每 30s 后台清一次。Rust 的常量与清理入口都未接线。 | **装配环断裂**：长期运行下 `HashMap` 只增不减（每条连接一个 session id）。 | `grep -rn "CLEANUP_INTERVAL\|spawn_cleanup" crates` → 仅 `server.rs:64`（定义）+ 注释。 | 在 vmess inbound 启动处挂周期清理（走 `PluginContext` 托管口）。 |
| W-09 | ss2022 `timestamp_tolerance` 配置面未接线（硬编码 30s） | **P2** | `crates/xray-proxy-ss/src/ss2022/inbound.rs:167`、`:315`（两处 `timestamp_tolerance` 字段 dead）；`:194`、`:343` 构造用字面量 `30` | `check_timestamp(timestamp, tolerance)` 真在跑（`:522/:637`），但传入的 tolerance 恒 30，构造器里的字段既不被自己读也不被外部写（配置解析路径不传值）。 | **配置→消费断裂**：用户改容差不生效；时钟偏差 >30s 的客户端一律被拒，且无提示说明容差被忽略。 | `grep -rn "timestamp_tolerance" crates/xray-proxy-ss` → 字段定义 2 处 + `:194/:343` 字面量 30 + 传参链，无任何 JSON/配置读取点。 | 从 ss2022 settings JSON 读 `timestampTolerance`（Go 亦有）填字段，或删除该字段并文档化不可配。 |
| W-10 | hysteria `ClientManager::clean_inactive` 零调用 → client 池无界 | **P2** | `crates/xray-transport-hysteria/src/dialer.rs:351` | `get_or_create` 按 `host\|udp_addr` 建 `HysteriaClient` 并常驻 HashMap；`clean_inactive`（Go `clientManager.clean()`）无调用点、无定时任务。 | **装配环断裂**：每访问一个新目标域就永久留一个 client（含 QUIC 连接引用）。目标域基数大时资源单调增长。 | `grep -rn "clean_inactive" crates` → 仅 `dialer.rs:351`（定义）。 | 挂周期清理任务或 client 侧按 Inactive 自回收。 |
| W-11 | BBR 拥塞面 two 处未接线：`apply_profile_locked` 零调用、`remove_obsolete_packets` 空体 | **P2** | `crates/xray-transport-quic/src/congestion_swappable/bbr/bbr_sender.rs:304`、`crates/xray-transport-quic/src/congestion_swappable/bbr/bandwidth_sampler.rs:215` | `apply_profile_locked`（profile 切换应用 logic）无调用点；`remove_obsolete_packets(&mut self, _less_than)` 函数体**是空的 `{}`**（Go 里它会清 app-limited 记录）。`app_limited_packets.insert(...)`（`:218`）只增。 | **消费环断裂 + 简化实现**：profile 配置项无效果；app-limited 集合随包号单调增长（长连接内存缓慢上涨，且 BBR 采样被陈旧包污染）。 | `grep -rn "apply_profile_locked\|remove_obsolete_packets" crates` → 各 1 处（仅定义）。 | 接线 profile 切换点；按 Go 实现清 `app_limited_packets`。 |
| W-12 | `--unix` flag 仅校验 + warn，splithttp UDS 监听未贯通 | **P2** | `crates/xray-cli/src/run.rs:226-237` | `--unix PATH` 只在「无 splithttp inbound」时报错；有则只打 warn「listener is not yet wired through `xray-core::start_full`; flag is consumed at config-validation time only」。`config_uses_splithttp`（`:285`）是这段逻辑的唯一调用方（Windows 构建下因此 dead_code）。 | **消费环断裂（已自供降级）**：flag 被接受但不产生监听。属 fail-visible（warn），非静默黑洞。 | `grep -rn "config_uses_splithttp\|unix_socket" crates/xray-cli` → 仅 `run.rs:170/227/228/285`。 | 待 splithttp UDS listener 落地后接线；或将 flag 改为硬错（当前 warn 会让用户以为生效）。 |
| W-13 | browser dialer 整模块零生产构造点 | **P3** | `crates/xray-transport/src/browser_dialer.rs`：`BrowserDialer::new`(`:107`)、`add_connection`(`:136`)、`is_active`(`:131`)、`dial_get`(`:171`)、`dial_packet`(`:200`)、`upgrade_tcp_to_ws`(`:289`) | 模块完整实现（含 `browser_dialer.html` 模板、CSRF token 校验、连接池），`lib.rs:87` 导出，但全仓无 `BrowserDialer::new` 调用点；`platform::browser_dialer_address()`（`env.rs:188`）也无消费方。splithttp `dialer.rs:362` 注释自供「browser_dialer.HasBrowserDialer() 分支未实现」。 | **装配环断裂**：环境变量 `xray.browser.dialer` 被解析后仅参与 `warn_unsupported_env_flags`。 | `grep -rn "BrowserDialer::new" crates` → 0 命中（仅定义）。`grep -rn "browser_dialer_address" crates` → 定义 + 自测。 | 明确标注「本构建不支持 browser dialer」并在配置期 fail-visible，或删除模块（现有 `warn_unsupported_env_flags` 已覆盖 env 面）。 |
| W-14 | `xray-proxy-dokodemo::server::Server` 装配面整片未接线（生产走 xray-core 自实现） | **P3** | `crates/xray-proxy-dokodemo/src/server.rs:34,43,63,125,131,137`（6 处 dead_code） | 该 crate 的 `Server`/`Config`/`build_destination*`/`is_network_allowed` 无引用；生产 dokodemo 走 `xray-core/src/inbound.rs` 的 `serve_dokodemo` + `serve_dokodemo_udp_on`（`arm_builders/inbound.rs:446,483`）。 | **同功能两套实现**：crate 面是平行世界，随 Go 上游改动会悄悄腐烂。 | `grep -rn "predefined_to_address\|build_destination_ex\|build_udp_destination\|is_network_allowed" crates` → 仅 `proxy-dokodemo/src/server.rs` 定义。生产：`arm_registry.rs:334` → `in_entries::dokodemo_entry` → `arm_builders/inbound.rs:446/483`。 | 标注 `udf-promotion`/删除重复面，或在 crate 头写明「生产不走本 crate」。 |
| W-15 | proxyman worker 层（`TcpWorker`/`UdpWorker`/`UdpSession`）与 `set_proxy`/`set_socket_options` 全测试专用 | **P3** | `crates/xray-app-proxyman/src/inbound/worker.rs:115,245,521`；`inbound/mod.rs:148`；`outbound/handler.rs:266,276` | 三种 worker 类型的 `::new` 调用全部落在 `#[cfg(test)]`（`worker.rs:909` 之后）；`set_proxy`/`set_socket_options` 无任何调用点。生产 inbound 是 `xray-core::InboundRuntime`，生产出站是 `SimpleOhm` + `DialBridge`。 | **平行世界**（CLAUDE.md §3.5.4 已记）：CLAUDE.md 记载的「proxyman 3 真 bug」同源。 | `grep -rn "TcpWorker::new\|UdpWorker::new\|UdpSession::new" crates` → 全部在 `worker.rs:909+`（测试）；`grep -rn "set_proxy(" crates` → 仅定义。 | 保持现状但补 crate 头声明，避免后续被当生产面维护。 |
| W-16 | `HysteriaDialerFactory` trait 只有 Stub 实现 | **P3** | `crates/xray-transport-hysteria/src/dialer.rs:162`（trait）、`:374`（`StubDialerFactory`，返回 ConnectionClosed） | trait 定义 + 唯一实现是 stub；生产出站走 `QuinnHysteriaTransport`（`impl HysteriaTransport`，不是 `HysteriaDialerFactory`），见 `register.rs:277`。 | **抽象层空转**：trait 面无人实现真语义。 | `grep -rn "impl HysteriaDialerFactory" crates` → 仅 `dialer.rs:376`（Stub）。 | 删除 trait，或补 quinn 实现并接到 `register.rs`。 |
| W-17 | `new_grpc_utls` 恒返回 `Err(UtlsNotImplemented)`，仅测试调用 | **P3** | `crates/xray-tls/src/grpc.rs:69`、`:53/:70/:93` | `GrpcUtlsCredentials` trait + 工厂都恒报未实现；生产 gRPC transport 不走它（无调用点）。 | **能力占位**：若将来有人按 Go 的 grpcSettings utls 接线，会得到恒 Err。 | `grep -rn "new_grpc_utls" crates` → `grpc.rs:69`(def) + `:113`(test)。 | 保留占位即可，但补 `// 未接线` 注释与 trace 级 warning，避免误以为可用。 |
| W-18 | `.import`/冗余 accessor 群：实现完整但零生产调用（列全见 §1） | **P3** | 见 §1 的 C 类清单 | 包括 `is_truncated`(proxy-dns)、`composite_matches_reverse`(geodata)、`notify_data_input/output`、`is_terminated`、`udp_send`/`iface_mut`(tun)、`into_aead`、`with_server`、`write/read_raw_chunk`(ss)、`datagram_supported`(tuic)、`set_remote_addr`(ws)、`bridge_link_with_link_default`、`set_inner`、`run_once`、`get_cert_path`(见 W-07)、`load_all`、`server_worker`、`option_enables`、`ipv4_from_bytes`/`ipv6_from_bytes`、`is_empty_or_expired`、`new_tcp_local_name_server`、`with_source_ip`、`with_response_command`、`into_uuid`、`with_gateway`/`with_original_target`、`needs_resolution`/`ipv4_only`(freedom)、`with_brutal_up`、`with_processor`(vmess)、`from_tunnel`、`force_session_key_rotation`、`unregister_reality_hooks`、`from_header`/`as_header`(grpc)、`clean_inactive`(见 W-10)、`normalized_xmux`(见 W-05)、`add_connection`/`dial_get`/`dial_packet`/`upgrade_tcp_to_ws`/`is_active`(见 W-13)、`send_intent_str`(udf)、`set_outbound_registrar`(commander，见 §2-②) | 全部为 API 完整性/备用面；**逐个已确认无生产构造点** | 见 §1 每行的「证据」列 | 无需动作（只报告不删）。 |

---

## 1b. §① `#[allow(dead_code)]` 118 条逐条定性（覆盖率 100%）

分档：**A**=真断线（生产不可达/被 stub 顶替）｜**B**=实现存在但未接线｜**C**=无害保留（cfg/测试/API 完整性/保活字段）

### xray-transport-hysteria（27）
| file:line | 符号 | 档 | 定性 |
|---|---|---|---|
| config.rs:22/27/32/37/42/47/54/59/64/138/143/148/153 | URLHost/URLPath/RequestHeaderAuth/ResponseHeaderUDPEnabled/CommonHeaderCCRX/CommonHeaderPadding/StatusAuthOK/FrameTypeTCPRequest/MaxDatagramFrameSize/Auth*Padding/Tcp*Padding | **C** | 注释称「当前链路未触达」，实测**已被消费**：`quinn_adapter.rs:844/851/865/866/882-889/1002/1008/1032-1035/1097-1104`、`conn.rs:173/188`、`register.rs:200`。`allow` 属过宽残留。 |
| conn.rs:754/758 | `clean_handle`/`run_handle` | C | 保活句柄，drop 即回收（注释成立） |
| context.rs:64 | `auth` | C | 测试 ctx 载体 |
| dialer.rs:138 | `HysteriaTransport` trait | C | 真实现 `QuinnHysteriaTransport`（`hysteria_transport.rs:116`）**且生产使用**（`arm_builders/outbound.rs:377`、`register.rs:277`）→ `allow` 是过宽残留下级对象；真 stub 见 W-16（`HysteriaDialerFactory`） |
| hub.rs:442/444/447/449 | `config`/`quic_params`/`validator`/`on_new_conn` | **C（附警示）** | 生产 inbound 走 `register.rs:93` `QuinnListenerFactory`，`hub.rs` 该装配 struct 无构造点；字段注释自供「hub 收口批接线」「observatory 观测点待接线」。功能面无损失，但 `on_new_conn` 未接线＝新连接无观测钩子（与 observatory 接线相关，P3）。 |
| hysteria_transport.rs:314/316 | `driver_task`/`send_req` | C | 保活（drop 即 H3_NO_ERROR 关连接） |
| quinn_adapter.rs:143 | `endpoint` | C | 保活 |
| quinn_adapter.rs:1073 | `salamander_key` | C | 真 obfs 走 `with_obfs`（`register.rs:279` 已接线），该字段属另一配置 struct 的冗余拷贝 |
| salamander_socket.rs:42 | `SALT_LEN` | C | 文档锚点常量 |
| udphop.rs:138 | `recv_handles` | C | 保活 |

### xray-transport（19）
| file:line | 符号 | 档 | 定性 |
|---|---|---|---|
| system_listener.rs:716 | `sockopt` | C | Unix accept 由内核 socket 生效 |
| system_listener.rs:918 | `UnixAddrSpec::Abstract` | C | 非 linux/android 平台 dead（`abstract_sockaddr_path` 才构造）；**构造点存在**（`cfg(linux/android)`） |
| finalmask/salamander_gecko.rs:184 / udphop.rs:119 / xdns/server.rs:99 / tcp/hub.rs:40,246 / udp/dispatcher.rs:95 | `fx: Arc<FxScope>` | C | 托管句柄字段，生命周期语义持有 |
| finalmask/xdns/dns.rs:19/21/23/25/37/92/117/163/480/510 | RR_TYPE_*/EXTENDED_RCODE_*/to_string_repr/trim_suffix/rcode/decode_rdata_txt/encode_rdata_txt | C | RFC1035 codec 完整面（单测覆盖）；`to_string_repr`/`trim_suffix` 注释称「xdns 旧路径消费」，实测无引用 → 纯 API 面，`allow` 成立 |
| finalmask/xdns/domain.rs:63 | `len_limit` | C | Go 字段对位（原始配置值保存） |

### xray-transport-quic（15）
| file:line | 符号 | 档 | 定性 |
|---|---|---|---|
| congestion_swappable/quinn_bridge.rs:180 | `is_empty` | C | 对称 API（测试面） |
| congestion_swappable/types.rs:166 | `Rtt::set` | C | 测试/探针预留 |
| bbr/bbr_sender.rs:141,145,153,155,158,170,172,176,178,180,182,184 | `clock`/`BbrInner`/`num_loss_events_in_round`/`bytes_lost_in_round`/`min_rtt_timestamp`/`congestion_window_gain`(+const)/`last_cycle_start`/`is_at_full_bandwidth`/`rounds_without_bandwidth_gain`/`bandwidth_at_last_round`/`exiting_quiescence` | **B（低）** | 注释「生产泵仅消费部分」「待批次接线」＝ BBR 状态面部分未参与决策。**非立即故障**，但 STARTUP 退出判定/带宽增益自适应面实际是常量行为。 |
| bbr/bbr_sender.rs:304 | `apply_profile_locked` | **B** | 见 W-11（profile 切换无效果） |

### xray-proxy-wireguard（7）
| file:line | 符号 | 档 | 定性 |
|---|---|---|---|
| outbound.rs:37/40 | `tag`/`driver` | C | 日志/生命周期对位 |
| peer.rs:38 | `index` | C | 调试面标识 |
| users.rs:284/293/326/336 | `make_keypair`/`test_driver`/`make_registry`/`peer_cfg` | C | 同 mod 测试 helper |

### xray-app-proxyman（6）
| file:line | 符号 | 档 | 定性 |
|---|---|---|---|
| inbound/worker.rs:115/245/521 | `UdpSession`/`TcpWorker`/`UdpWorker` | **C（平行世界）** | 三者 `::new` 全在 `#[cfg(test)]`（`worker.rs:909+`）→ 见 W-15 |
| outbound/handler.rs:518 | `TestCounter` | C | 测试用 counter |
| outbound/uot.rs:146 | `decode_request` | C | dispatch 内联承担解码（`try_parse_packet` 才是活路径） |
| outbound/uot.rs:215 | `fx` | C | 托管句柄 |

### xray-proxy-dokodemo（6）
| file:line | 符号 | 档 | 定性 |
|---|---|---|---|
| server.rs:34/43/63/125/131/137 | `config`/`predefined_to_address`/`build_destination_ex`/`build_destination`/`build_udp_destination`/`is_network_allowed` | **B（重复面）** | 见 W-14：整 crate 装配面未接线，生产自实现 |

### xray-core（5）
| file:line | 符号 | 档 | 定性 |
|---|---|---|---|
| inbound.rs:2867 | `DnsUdpRecvBatch::iovs` | C | 仅经 `msg_hdr.msg_iov` 指针间接引用，持所有权保地址固定（SAFETY 注释成立） |
| outbound.rs:1461 | `StubHandler::new` | C | 「stub 备件（历史 stub 同款语义）」；`register.rs` 现用真 factory |
| register.rs:135 | `APP_KINDS` | C | 文档性清单锚点 |
| register.rs:1012/1025 | `SimpleFeature`/`simple_feature_factory` | C | noop 备件（注释成立，无引用） |

### xray-app-router（4）
| file:line | 符号 | 档 | 定性 |
|---|---|---|---|
| balancing.rs:165 | `Balancer.ohm` | **C** | 见 §2-① 核实：ohm 经 `router.rs:360-418` 注入各 strategy（`ohm.clone()`），`Balancer.ohm` 只是冗余副本；**balancer 整体功能在线**（`functions.rs:298` 生产传真 ohm） |
| condition.rs:804 | `mod lsof_parser` | C | 仅 macOS + tests |
| condition.rs:898 | `mod proc_macos` | C | Go 明确 macOS 不支持进程查找 |
| condition.rs:931 | `mod proc_freebsd` | **C（需核）** | 注释「接线已对齐 Go 仅 linux/windows」；但 Go 有 `find_process_freebsd.go` → 若目标含 FreeBSD，`process` 条件失效。当前 CI 平台面无关，标 P3。 |

### xray-proxy-tuic（4）
| file:line | 符号 | 档 | 定性 |
|---|---|---|---|
| client.rs:149/152/155/158 | `pool`/`key`/`uuid`/`password` | **B（低）** | 注释「连接池引用保活防 drop 关连接」「Go 对齐配置面字段」；生产 `TuicClient` 走 `src/outbound.rs`（auth 由 `TuicOutboundHandler` 侧完成）。属装配面预留，非断线。 |

### xray-app-reverse（3）
| file:line | 符号 | 档 | 定性 |
|---|---|---|---|
| relay.rs:62 / timer.rs:42 / worker.rs:170 | `fx` | C | 托管句柄 |
| （另见 §3）worker.rs:428 `server_worker` | — | C | 无非测试引用；反向 worker 访问器 |

### xray-proxy-vless（3）
| file:line | 符号 | 档 | 定性 |
|---|---|---|---|
| encryption/common_conn.rs:73 | `inner_conn_mut` | C | passthrough 预留 |
| encryption/vision_conn.rs:79 | `uplink_state` | C | 与 downlink_state 对称 |
| encryption/vision_conn.rs:1051 | `server_splice_read_switch_on_client_direct` | C | 历史 revert 的场景脚本未挂 runner（**注意：vision splice 是红线面，勿动**） |

### xray-transport-kcp（3）
| file:line | 符号 | 档 | 定性 |
|---|---|---|---|
| connection.rs:111 | `ConnectionInner.config` | C | 真调参在构造期读（`:164-165` tti/mtu）；字段冗余 |
| listener.rs:267 | `push` | C | 测试辅助队列入口 |
| receiving.rs:206 | `config` | C | 同 connection.rs:111（`sending.rs:309-327` 才消费 config） |

### xray-proxy-ss（2）
| file:line | 符号 | 档 | 定性 |
|---|---|---|---|
| ss2022/inbound.rs:167 / :315 | `timestamp_tolerance` | **B** | 见 W-09：容差硬编码 30，配置面未接线 |

### xray-reality（2）
| file:line | 符号 | 档 | 定性 |
|---|---|---|---|
| probe.rs:470 | `spawn_alert_after_ccs` | C | 单测 silent 路径专用 |
| server.rs:497 | `mirror_record_lens` | C | 仅 rustls 路径消费（btls/iOS 平台 dead） |

### xray-transport-splithttp（2）
| file:line | 符号 | 档 | 定性 |
|---|---|---|---|
| mux.rs:324/333 | `id`/`close` | C | 测试 fake 保 trait 完整实现 |

### 单条（10）
| file:line | 符号 | 档 | 定性 |
|---|---|---|---|
| udf-frame/skeleton-infra/examples/end_to_end.rs:301 | `NoDriver` | C | example 内测试桩 |
| xray-app-commander/src/grpc.rs:883 | `ListenSpec::Unix` | **C（allow 已失效）** | 实测**被构造**（`grpc.rs:901-906 parse_listen_spec`）并被 `serve_grpc` 分支消费（`:580-615`，Windows 走 `#[cfg(not(unix))]` Err）→ `allow` 注释「当前 gRPC 接线仅 TCP」**已过期** |
| xray-app-dispatcher/src/default.rs:2106 | `SimpleOhm::add` | **C（allow 已失效）** | 跨 crate 生产调用：`xray-core/src/functions.rs:442`、`outbound.rs:211/507`、`commander/src/server.rs:266`（经 `SimpleOhmDispatchRegistrar`，但该链因 W-04 生产不可达；`functions.rs` 两条独立可达） |
| xray-cli/src/run.rs:284 | `config_uses_splithttp` | C | `#[cfg(unix)]` 才调用（`run.rs:228`）→ 仅 Windows 构建 dead |
| xray-crypto/src/auth_reader.rs:41 | `transfer_type` | **C（Go 同形）** | 对照 `Xray-core/common/crypto/auth.go`：Reader 的 `transferType`（`:95/:107`）**在 Go 里也从未被读**；只有 Writer 读（`:345`）。Rust `auth_writer.rs:212` 已消费 → 语义对齐 |
| xray-frame/src/config.rs:545 | `port` | C | 测试内 struct 字段（用于字段名断言） |
| xray-proxy-anytls/src/server.rs:88 | `fx` | C | 托管句柄 |
| xray-proxy-tun/src/inbound.rs:88 | `TUN_RECV_BUF_SIZE` | C | 调优预留（netstack 按 slice 收） |
| xray-proxy-vmess/src/encoding/server.rs:63 | `CLEANUP_INTERVAL` | **B** | 见 W-08 |

**① 汇总：118/118 已定性 → A=0 条；B=26 条（落在 6 个面上：BBR 状态面 12 + `apply_profile_locked` 1 + dokodemo 未接线 6 + ss2022 容差 2 + vmess 清理 1 + tuic 预留 4）；C=92 条**（其中 2 条的 `allow` 注释已过期：`grpc.rs:883`、`default.rs:2106`）。

---

## 2. §② stub / 占位面定性（重点：生产是否真构造 stub）

| stub 面 | 位置 | 生产构造了吗 | 定性 |
|---|---|---|---|
| `xray-proxy-vless::inbound::handler::StubProcessor` | `handler.rs:146` | **否**（全仓 0 构造点）。真实体是 `VlessInboundProcessor`（`handler.rs:163`，`process()` 委托 `inbound::server::handle_connection`） | C（未接线备件；且 `InboundHandler` 自身在本仓无生产构造——vless 生产走 `xray-core` 的 `serve_vless`） |
| `xray-proxy-vless::outbound::handler::StubProcessor` | `outbound/handler.rs:163` | **否**（0 构造点） | C |
| `xray-proxy-vmess::NoopInboundProcessor` / `NoopOutboundProcessor` | `inbound/handler.rs:38`、`outbound/handler.rs:39` | **否**：`InboundHandler::new`（`inbound/handler.rs:69`）与 `OutboundHandler::new`（`outbound/handler.rs:69`）**仅在 vmess 自身单测构造**（`inbound/handler.rs:129`、`outbound/handler.rs:133/147`）。生产 vmess 走 `xray-core` serve 路径 | C（真 stub，但无生产入口；`with_processor` 注入点也 0 调用） |
| `xray-proxy-ss::server::NoopInboundProcessor` | `server.rs:35` | `with_users`（`:77`）用它，但 `with_users` 无生产调用点 | C — **注意名字骗人**：其实现是**真实解码委托**（`crate::protocol::decode_tcp_request_header` / `decode_udp_packet`），不是 no-op |
| `xray-transport-hysteria::dialer::StubDialerFactory` | `dialer.rs:374` | **否**（仅 `dialer.rs:450` 单测） | C；真链路 `QuinnHysteriaTransport`（见 §1） |
| `xray-transport-hysteria::hub::StubListenerFactory` | `hub.rs:525` | **否**（仅 `hub.rs:665` 单测）。生产 `register.rs:93` 用 `QuinnListenerFactory` | C |
| `xray-proxy-hysteria::outbound::NoopTransport` / `dispatcher::MockTransport` / `CaptureTransport` | `outbound.rs:191`、`dispatcher.rs:596/690` | **否**（测试替身） | C |
| `xray-tls::grpc::UtlsNotImplemented` | `error.rs:65`、`grpc.rs:53/70/93` | **无调用方**（`new_grpc_utls` 仅测试） | C → 见 W-17 |
| `xray-features::stats::NoopManager` | `stats.rs:320` | **否**。生产用 `xray-core/src/register.rs:568` 的 `AppStatsFeature`（真 counter/online_map/channel），`functions.rs:371` 只在该 feature 缺失时 `None` | C（Go `NoopManager` 同形兜底类） |
| `xray-features::stats::EmptyStats`(内部委托 NoopManager) | `stats.rs:365-378` | 未在清单内，作旁证 | C |
| `xray-app-commander::outbound::StubOutboundHandler` | `outbound.rs:105` | **优先级 3 兜底**：`grpc.rs:181-186` 在 `runtime == None` 时用它。生产 `functions.rs:500` **必设** `set_outbound_runtime`；且优先级 1（proxyman service，`functions.rs:517` 已注入）会先命中 → 生产不可达 | C（但属「respond OK while doing nothing」形态：若将来 runtime 注入被跳过，AddOutbound 会假成功） |
| `xray-app-observatory::NoopOutboundSelector` | `observer.rs:396` | 仅 `feature.rs` 测试 + `observer.rs` 测试 | C |
| `xray-app-router::balancing::NotImplementedSelector` | `balancing.rs:257` | **生产仅在无 ohm 的兼容入口**：`wiring.rs:701 build_router_adapter_from_json`（其唯一生产调用方是 `functions.rs:4558`＝**测试内**）+ `Router::empty`（测试）。生产主路走 `build_router_adapter_from_json_with_ohm`（`functions.rs:298`） | C —— **balancer 未失效，核实结论见 §2-①** |
| `xray-transport-quic` BBR `remove_obsolete_packets` 空体 | `bandwidth_sampler.rs:215` | 无调用 | **B** → W-11 |
| `xray-frame::plugin` 的 `Stub` / `transport::finalmask::xicmp` 的 `Stub` / `portmap::*Stub` | 测试模块内 | 测试替身 | C（禁报口径内） |

### §2-① 线索定案：balancer 是否整体失效 → **否，功能在线**

```
$ grep -rn "build_router_adapter_from_json_with_ohm" crates/
crates/xray-core/src/functions.rs:298:  => 生产主路（routing app 存在时）
crates/xray-core/src/wiring.rs:721        => 定义
（其余 3 处均为 wiring.rs 自测）
$ sed -n '360,418p' crates/xray-app-router/src/router.rs
"random" => RandomStrategy::new(..., ohm.clone(), ...)
"leastping" => LeastPingStrategy::new(..., ohm.clone(), ...)
"leastload" => LeastLoadStrategy::new(..., ohm.clone(), ...)
"roundrobin" => RoundRobinStrategy::new(..., ohm.clone(), ...)
Ok(Balancer::new(br.outbound_selector.clone(), strategy, ohm.clone(), br.fallback_tag.clone()))
```
- ohm 由 `functions.rs:280 Arc::new(SimpleOhm::new())` 建，`OhmOutboundSelector`（`wiring.rs:650`，裸指针 + `unsafe impl Send/Sync`）把真实 `SimpleOhm` 接进 balancer；指针存活由 `dispatcher.init`（`functions.rs:356` `Arc::clone(&ohm)`）保证 ≥ RouterAdapter 生命周期。
- `Balancer.ohm` 字段确实无人读（策略各自持 ohm），但**不构成功能断线** → C。
- **附带观察（非本次范围，交 R2/安全）**：`OhmOutboundSelector` 用裸指针跨 `Arc` 边界，正确性依赖「dispatcher 活得更久」这一装配不变量，无编译期保证。

---

## 3. §③ 图谱零入边 + 词法补强（68 个候选逐个定性）

图谱口径失效说明（须记录）：`MATCH (f:Function) WHERE NOT ()-[:CALLS]->(f)` 在 11136 个 `/src/` 函数节点里命中 **8115**（73%），其中包含大量**在生产中被 trait 对象/宏调用的方法**（如 `is_active` 有 27 处引用却仍可能零入边）。故图谱只用于**生成候选池**，判定改用「全仓词法引用 + 构造点 grep」。

词法补强结果：2912 个 `pub`/`pub(crate) fn` 名中 **68 个无任何非测试引用**。逐个定性：

| 候选 | 位置 | 档 | 定性 |
|---|---|---|---|
| `set_routing_service` / `set_observatory_service` / `set_outbound_registrar` | commander.rs:345/350/334 | **A** | W-02/W-03；`set_outbound_registrar` 只喂 `impl HandlerManager for Commander`（`commander.rs:699-727`），而 `HandlerManager` 在生产无人使用 → 整 impl 死 |
| `set_dispatch_registrar` | commander.rs:370 | **A** | W-04（仅测试） |
| `serve_dokodemo_udp` | inbound.rs:1673 | C | 薄包装（body 仅 `serve_dokodemo_udp_on(...).await`）；生产用 `serve_dokodemo_udp_on`（`arm_builders/inbound.rs:483`）→ **dokodemo UDP 功能在线** |
| `load_all` | rule_set.rs:101 | C | 生产逐条 `load`（`wiring.rs:1063`） |
| `server_worker` | reverse/worker.rs:428 | C | 访问器 |
| `write_disconnect` / `deregister` / `connect_response` | xmc/protocol.rs:189、realm/http.rs:205/253 | **C（P3 提醒）** | finalmask realm/xmc 协议的**客户端子集**未接线（只实现 register/connect 方向）。`deregister`/`connect_response` 缺失 = realm 会话生命周期/server 侧响应未实现。标 P3。 |
| `clean_inactive` | hysteria/dialer.rs:351 | **B** | W-10 |
| `notify_data_input` / `notify_data_output` | kcp/connection.rs:612/617 | C | 内部直接 `inner.data_input.notify_one()`（`:320-472` 多处），pub 包装冗余 |
| `is_terminated` | kcp/state.rs:74 | C | 访问器（`is_locally_closed` 才是活判据） |
| `remove_obsolete_packets` | bbr/bandwidth_sampler.rs:215 | **B** | W-11（空体） |
| `datagram_supported` | tuic/udp.rs:269 | C | 访问器；tuic native datagram 可用性探测未接（P3） |
| `is_truncated` | proxy-dns/dns_message.rs:53 | C | 死访问器；TC 重试逻辑在 `xray-app-dns`（真接线，见 `nameserver/udp.rs:199-311` + `tcp_fallback_tests.rs`） |
| `needs_resolution` / `ipv4_only` | freedom/config.rs:143/149 | C | freedom 实际经 `sockopt::DomainStrategy`（`handler.rs:88`、`dispatcher.rs:56/277/344`）→ 语义在，helper 冗余 |
| `with_brutal_up` | proxy-hysteria/config.rs:102 | C | builder setter（配置直接赋字段） |
| `into_aead` / `with_server` / `write_raw_chunk` / `read_raw_chunk` | ss/validator.rs:85、inbound.rs:50、stream.rs:315/747 | C | API 面（raw chunk 是 ss 内部 chunk 原语，生产走 stream 封装） |
| `force_session_key_rotation` / `from_tunnel` / `iface_mut`(×2) / `udp_send` | wg/tunnel.rs:228、peer.rs:59、tun+wg netstack、tun/netstack.rs:399 | C | 访问器；tun UDP 回包走 `with_udp_socket`/`send_slice`（`netstack.rs:174/257`） |
| `with_processor`(×2) | vmess handler 74 | C | 见 §2 |
| `parse_ech_force_query` | tls/ech.rs:477 | **B** | W-06 |
| `unregister_reality_hooks` | tls/btls_reality.rs:262 | C | RAII `RealityHooksGuard`（`:286-295`）已做 compare-and-remove，pub fn 冗余 |
| `from_header` / `as_header` | grpc/encoding.rs:62/70 | **C（P3 提醒）** | 生产解码恒传 `None`（`transport.rs:432/912`）→ `compressed=1` 帧直接 Decompression 错。Go grpc 默认不压缩，故当前互通无碍；若对端启用 gzip 会断。 |
| `set_remote_addr` | ws_bridge.rs:113 | C | 访问器（PROXY protocol 覆盖路径未接） |
| `composite_matches_reverse` | geodata/matcher/mod.rs:234 | C | Go `CompositeMatchesReverse` 对位；本仓多 matcher 合并走 `ConditionChan`，未用逆序扁平化 → 若将来接「更远匹配优先」需回看 |
| `bridge_link_with_link_default` | transport/bridge.rs:803 | C | 旧 API 兼容包装 |
| `is_empty_or_expired` | dns/dnscommon.rs:131 | C | helper |
| `new_tcp_local_name_server` | dns/nameserver/tcp.rs:296 | **C（P3 提醒）** | Go 的 local/system resolver 变体未接线（注释自供「留 follow-up」）→ `local` nameserver 走普通 TCP |
| `option_enables` / `ipv4_from_bytes` / `ipv6_from_bytes` | dns | C | helper |
| `set_inner` | dispatcher/default.rs:1588 | C | 访问器（`with_inner` 才是活路径） |
| `set_proxy`(×2) / `set_socket_options` | proxyman | C | 见 W-15 |
| `sample_count` / `diff_count` | dispatcher/default.rs:2446/2451 | C | 仅测试读（回放面观测指标） |
| `next_fire_in` / `schedule_for_test` | geodata/scheduler.rs:75/121 | C | 前者仅测试引用；后者自述 test-only |
| `do_check_with_duration` | observatory/burst_observer.rs:317 | C | `#[doc(hidden)]` Go 兼容签名占位 |
| `with_source_ip` | router/context.rs:158 | C | builder 冗余（source_ips 另有入口） |
| `run_once` | common/log/general_logger.rs:130 | C | `handle_message` 自动启动，该方法冗余 |
| `get_cert_path` | common/platform/mod.rs:56 | **B** | W-07 |
| `with_response_command` / `into_uuid` / `with_gateway`(×2) / `with_original_target` | common/protocol:383、session:132/284/407/419 | C | builder/访问器冗余 |
| `fallback_caps` / `installed_caps` / `push_file` / `payload_mut` / `expected_file` / `spawn_count` | xray-frame | C | 观测/门禁辅助面（`installed_caps` 注释称 G7 自检用，当前无调用方 → P3：文档承诺的自检未实现） |
| `send_intent_str` | udf-frame/view.rs:816 | C | udf 侧重载，主仓不消费（不在主仓接线义务内） |
| `upgrade_tcp_to_ws` / `add_connection` / `dial_get` / `dial_packet` / `is_active`(browser_dialer) | browser_dialer.rs | **B** | W-13 |
| `normalized_xmux` | splithttp/config.rs:430 | **B** | W-05 |

**③ 汇总：68/68 已定性 → A=5（commander 4 setter + set_dispatch_registrar），B=8（W-05/06/07/10/11 + browser dialer + xmux/其它见上），C=55。**

---

## 4. 结论分级清单

### A 类 · 真断线（生产不可达 / 被 stub 顶替）— 5 条
1. **W-01 routing `ruleSet`/`ruleSetTag`**（P0，最严重，非 dead_code 面，由 §1 图谱/语义复核发现）
2. W-02 gRPC RoutingService 后端永不存在
3. W-03 gRPC ObservatoryService 后端永不存在
4. W-04 api outbound 模式注册链断（dispatch_registrar 无生产注入）
5. `Commander::set_outbound_registrar` + `impl HandlerManager for Commander` 整块死（备用 API，P3 级 A）

### B 类 · 能力存在但未接线 — 9 条
W-05 xmux｜W-06 echForceQuery｜W-07 xray.location.cert｜W-08 vmess 清理｜W-09 ss2022 容差｜W-10 hysteria client 池清理｜W-11 BBR profile/app-limited｜W-13 browser dialer｜W-14 dokodemo crate 重复面
（另：tuic client 装配面预留、bbr 状态面部分常量、realm `deregister`/`connect_response`、dns `local` resolver 变体 —— P3）

### C 类 · 无害保留 — dead_code 92 条 + 词法候选 55 条 + stub 面 15 条

> 统计口径：dead_code 全集 118（B 26 + C 92）；词法候选 68（A 5 + B 8 + C 55）；stub 面 16（B 1 + C 15）。A/B/C 三档条目有交叉（同一缺陷可能同时被「dead_code」与「词法」两源命中，如 `normalized_xmux`），故**不求和去重后的「发现数」应以 §1 Findings 的 W 编号为准：A 5 条、B 9 条、其余 P3 债务若干**。

---

## 5. 未覆盖范围（诚实声明）

1. **未跑任何构建/测试**（契约：只读审计 + 主代理统一验证）。所有结论基于源码 grep/词法统计，未用运行期证据（如 `RUST_LOG` 观测 balancer 是否真被选到）。
2. **未覆盖 trait 对象级动态分发面**：图谱零入边不可信，我仅对 `pub fn` 做了词法补强；**私有的 `fn`（非 pub）与 trait 方法实现未逐条扫**——`impl Trait for X` 的方法名若与 trait 声明同形，词法扫描无法区分「trait 调用」与「死代码」。
3. **未覆盖配置字段级「解析但未消费」全量普查**：仅抽查了 xmux/echForceQuery/ss2022 tolerance/ruleSetTag/kcp（kcp 已确认消费）。其余 settings 键（如各协议 `sockopt`、`mux`、`sniffing` 子项）未逐键比对。
4. `xray-cli --features framework`（目标主路）只按其调用点核对，未做对其与生产主路的差异面普查（该面由 `assembly_path_equivalence.rs` 契约测试负责）。
5. windows/unix 平台分支差异按「禁报」口径排除；`--unix`、`proc_macos/freebsd`、`config_uses_splithttp` 的 dead 均属 `cfg` 面。
