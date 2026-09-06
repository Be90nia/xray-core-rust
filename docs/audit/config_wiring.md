# 配置解析→装配消费全链审计（第二轮）

- 审计代理：ConfigAudit（只读代码，唯一写动作 = 本文件）
- Go 基准：`D:/Project/Xray-core`（v26.7.28）；Rust 仓库：`D:/Project/Xray-core-rust`
- 方法：对 `xray-conf` 全部强类型 app 配置结构体逐字段与 Go `infra/conf` 对应 JSON 键对照；沿 `Config::build()`（built.rs）→ `Instance::new_from_built` / `start_full`（functions.rs/instance.rs）→ `register.rs` factory → `wiring.rs`/`outbound.rs`/`inbound.rs` 装配链，对每个 build 产物验证消费点；serde 键匹配性按 serde 语义（无 `rename`/`alias` = 按 Rust 字段名匹配，未知键静默忽略）判定。第一轮 F1-F16 及已知接受项不重复。

## 0. 已验证无问题项（防误报，勿重查）

- 出站顶层 `targetStrategy`：built.rs:224-231 校验 → outbound.rs:523-527 解析 → `wrap_dial_with_target_strategy`（outbound.rs:354-356）生产消费 ✅
- 出站顶层 `sendThrough`：parse_send_through（outbound.rs:279-301）→ `wrap_dial_with_send_through`（outbound.rs:358-362）+ freedom UDP 分支 `with_send_through` ✅
- routing 顶层 `domainStrategy`：wiring.rs:422-424 解析 → router.rs:177-183 消费 ✅
- sniffing 五字段：`destOverride`/`domainsExcluded`/`ipsExcluded`/`metadataOnly`/`routeOnly` 键名正确（config.rs:219-236 显式 rename），wiring.rs:237-257 构建 SniffingRequest，default.rs:392-416 `should_override` 消费 ✅（CIDR 缺陷见 F-W9）
- log 全字段：`loglevel/access/error/dnsLog/maskAddress` 键名正确（app_config.rs:16 rename_all）→ register.rs:243-289 → LogInstance（dnsLog instance.rs:613、mask instance.rs:451-466）✅
- `env` 顶层字段：config.rs:87 解析、built.rs:125-129 注入进程环境（对应 Go xray.go:532-536）✅（第一轮 §6 称"未发现解析"不准确，此处修正）
- FakeDNS 后处理 stage：init.rs:42-121 与 Go fakedns.go:73-134 语义对齐（默认池填充/destOverride 告警）✅
- MuxConfig 空串 `xudpProxyUDP443` → reject：default.rs:2121-2122 与 Go xray.go:111-117 对齐 ✅
- outbound `proxySettings`/`transportLayer` 门控：built.rs:292-329 对齐 Go xray.go:244-252,316-327 ✅
- observatory IO 注入主链：functions.rs:223-233 DepBag 二次注入 → feature.rs:119-129 `init_dependencies` 消费（bd f23r）✅（burst 无此覆写，见 F-W3）

---

## 1. 发现清单

### [P1] F-W1: app 强类型配置结构缺 camelCase rename，Go 标准 policy 键族静默全丢 | crates/xray-conf/src/app_config.rs:42-87
- 证据：`PolicyLevel`/`PolicySystem`/`PolicyConfig` derive 仅 `#[serde(default)]`，**无 `rename_all`/`alias`**（app_config.rs:42-44,65-67）。字段名 `conn_idle`/`uplink`/`downlink`/`buffer_size`/`stats_user_uplink`/`stats_user_online` 按 serde 默认匹配 JSON 键 `conn_idle`/`uplink`/…；而 Go 基准键为 `connIdle`/`uplinkOnly`/`downlinkOnly`/`bufferSize`/`statsUserUplink`/`statsUserDownlink`/`statsUserOnline`（Go infra/conf/policy.go:8-15）、system 键 `statsInboundUplink` 等四键（policy.go:55-60）。解析路径无归一化：顶层 Config 强类型解析（config.rs:40）→ 未知键已在此丢弃 → built.rs:167 重序列化 → policy_factory `serde_json::from_slice`（register.rs:322）。
- 影响：**Go 标准写法 `{"policy":{"levels":{"0":{"handshake":4,"connIdle":300,"uplinkOnly":0,"downlinkOnly":15,"statsUserUplink":true}},"system":{"statsInboundUplink":true}}}` 中仅 `handshake` 恰好同名生效**；connIdle/downlinkOnly 等连接超时静默回落默认，`statsUserUplink/Downlink/Online` 与 system 四开关静默为 false —— 用户/入站流量统计、Stats API/Metrics 的 traffic 计数被静默关闭。第一轮 §5 判 policy ✅ 依据的是 manager.rs 默认值对齐（manager.rs 测试），未覆盖 JSON 键名层。
- 修复建议：`PolicyLevel`/`PolicySystem` 加 `#[serde(rename_all = "camelCase")]` 并补 `uplink`→`uplinkOnly` 的 alias（或字段直接更名对齐 Go 键）；同法处理本文件其余结构（见 F-W2/F-W4/F-W5/F-W6）；为每个结构补"Go 标准 JSON 往返断言值"的单测（现有测试只断言容器 `is_some()`，见 F-W4 证据）。

### [P1] F-W2: observatory/burstObservatory 键族静默失效，Go 标准配置整体 no-op | crates/xray-conf/src/app_config.rs:94-120; crates/xray-core/src/register.rs:348-390
- 证据：`ObservatoryConfig` 字段 `subject_outbound`/`probe_url`/`probe_interval`/`probe_timeout`（app_config.rs:96-108，无 rename）；Go 键为 `subjectSelector`（**列表**）/`probeURL`/`probeInterval`/`enableConcurrency`（Go infra/conf/observatory.go:13-16）。`BurstObservatoryConfig` 字段 `subject_outbound`/`ping_config`（app_config.rs:114-119，无 rename）；Go 键为 `subjectSelector`/`pingConfig`（observatory.go:24-26）。观测：built.rs:516-517 与 config.rs:354-355 的测试喂的正是 Go 标准键 `{"burstObservatory":{"subjectSelector":["p1"]}}`，但**只断言容器存在/不报错，未断言值被捕获**——键名丢弃逃过全部测试。
- 影响：Go 标准 observatory 配置 → `subject_selector` 空/`probe_url` 空/`probe_interval` 0 → ObservatoryFeature::start 因 selector 空 no-op（feature.rs:76-78），探测永不启动且无告警。附带两处次级偏差：① `enable_concurrency: false` 硬编码（register.rs:361），Go v26 并发探测开关无对应；② `probe_timeout` 是 Go 不存在的死字段，即使 Rust 方言下也无消费（register.rs:353-360 只读另外三个字段）；③ Go `subjectSelector` 是前缀选择出站集合，Rust 降级为单 tag 语义。
- 修复建议：结构体 rename_all=camelCase + `subjectSelector` 改列表类型对齐 Go；删除或实现 `probe_timeout`；enable_concurrency 落配置；修测试断言捕获值。

### [P1] F-W3: BurstObservatoryFeature 探测 executor 在生产装配无任何注入路径：Go 键静默 no-op，Rust 方言键反而启动硬失败 | crates/xray-app-observatory/src/burst_feature.rs:59-93; crates/xray-core/src/functions.rs:231-233; crates/xray-core/src/instance.rs:274-276
- 证据：executor 仅经 `set_io` 注入（burst_feature.rs:59-61），而 xray-core 全目录对 burst feature 的 `set_io` 调用为零；functions.rs:231-233 的二次依赖注入对**所有** feature 调 `init_dependencies(&bag2)`，但 `BurstObservatoryFeature` **未覆写 `init_dependencies`**（全文件无该 impl；对比 ObservatoryFeature 在 feature.rs:114-129 有覆写）。`start()` 逻辑：subject 空 → `Ok(())` 静默 no-op（:74-76）；subject 非空且 executor 缺失 → `StartFailed`（:89-93）；instance.start() 对 feature start 错误直接 `?` 传播（instance.rs:274-276）→ functions.rs:283 `instance.start()?` 整个启动失败。
- 影响：两难——① Go 标准键配置（F-W2 键名被丢）→ subject 为空 → **静默 no-op**，burstObservatory 配置完全无效且无告警；② 用户若通过阅读 Rust 源码改用方言键 `subject_outbound` → start 必 StartFailed → **整个 xray 进程启动失败**。两条路都不可用。第一轮并发组已报 burst_observer.rs:220（锁内同步探测），本条是装配层断裂，正交。
- 修复建议：仿 ObservatoryFeature 给 BurstObservatoryFeature 实现 `init_dependencies`（从 DepBag 取 OutboundTagSelector + 构造 ProbeExecutor），并补"config→instance.start 成功"的装配级测试（现有 burst 测试均为手动 set_io 的单测）。

### [P1] F-W4: 出站级 mux 配置未实现 Go 语义：mux.enabled 静默无复用，concurrency/xudpConcurrency 全仓零消费 | crates/xray-core/src/outbound.rs:490-507
- 证据：`mux_json` 的唯一生产消费点是 `parse_udp443_policies`（outbound.rs:490-507），只读 `cfg.enabled` + `cfg.xudp_proxy_udp_443` 两字段生成 UDP443 分发前置策略；`MuxConfig.concurrency`（config.rs:254）与 `xudp_concurrency`（config.rs:257-258）在生产路径**零消费**（唯一使用者是 proxyman 平行世界的 proto 转换 handler.rs:218-233，该 crate 未接生产，第一轮已述）。真正的 mux 复用只存在于 Rust 扩展的专用 `"mux"` 协议出站（outbound.rs:591-594 MuxBridge）。Go 基准：出站 `mux` 由 proxyman/outbound handler 在 NewHandler 时从 `senderSettings.MultiplexSettings` 构建复用客户端（outbound.rs:487-489 的注释自己引用了该链路 handler.go:122-168）。
- 影响：Go 标准配置 `{"protocol":"vless", ..., "mux":{"enabled":true,"concurrency":8}}` 在 Rust 被接受、解析，但**不会为该出站建立任何复用连接**（连接数/握手次数特征与 Go 不同），且无任何告警；`xudpConcurrency`（负数禁用语义，Go proxyman 侧有效）同样无效。用户无从得知需要改用 Rust 专属的 `"mux"` 出站写法。
- 修复建议：在 `try_build_handler` 出口按 `mux.enabled` 把 dial_fn 包一层 mux 客户端（复用 MuxBridge），至少先对 `enabled:true` 打 warn 声明未实现，消除静默。

### [P2] F-W5: fakeDns 键名不匹配，用户 ipPool/poolSize 恒被默认池覆盖 | crates/xray-conf/src/app_config.rs:186-195; crates/xray-core/src/register.rs:654-671
- 证据：`FakeDnsConfig` 字段 `ip_pool`/`pool_size`（app_config.rs:191-194，无 rename）；Go 键为 `ipPool`/`poolSize`（Go infra/conf/fakedns.go:13-16 `FakeDNSPoolElementConfig`）。register.rs:897 的测试直接喂 `{"ipPool":"198.18.0.0/15","poolSize":1024}`，两键均被丢，`build_fake_dns_holder` 走 `ip_pool: None` → 默认池 240.0.0.0/4+65535；测试仅断言 feature_name 故通过。yaml.rs:68-72 同病（只断言 `fake_dns.is_some()`）。
- 影响：与 F5（引擎未注入）正交：即使 F5 修复，用户自定义池（如标准的 198.18.0.0/15，避免与真实 240/4 冲突网段）仍恒为默认池，FakeDNS 映射的地址段与用户路由规则可能错配。另 Go `pools[]` 多池数组整体无承载（第一轮已记 init.rs 多池缺口，不重复）。
- 修复建议：rename 对齐 Go 键 + 修两处测试断言实际捕获值。

### [P2] F-W6: metrics 键 `tag` 被丢弃（无 tag/listen 必填校验），Go tag-路由模式不可用 | crates/xray-conf/src/app_config.rs:127-136; crates/xray-core/src/register.rs:397-411
- 证据：`MetricsConfig` 字段 `listen`/`tags: Option<Vec<String>>`（app_config.rs:129-135，无 rename）——Go 键 `tag`（单数字符串，Go infra/conf/metrics.go:9）被丢，Rust 期望的 `tags` 是自造复数键；metrics_factory 显式 `tag: String::new()`（register.rs:403）。Go Build 硬校验 `tag=="" && listen==""` 报错、tag 空时默认 "Metrics"（metrics.go:13-20）；Rust 无任何校验。
- 影响：Go 标准写法 `{"metrics":{"tag":"metrics_out"}}`（经入站路由暴露 /metrics）在 Rust 完全无对应实现——metrics feature 仅 listen 直连 HTTP 模式，tag 模式静默 inert；空配置也不报错，用户得不到"metrics 未生效"的信号。
- 修复建议：字段改 `tag: Option<String>` 并对齐 Go 校验；tag 模式若短期不做，Build 时对仅配置 tag 的场景显式报 Unsupported。

### [P2] F-W7: geodata 顶层键族与 Go 完全不同（{code,dir} vs {cron,outbound,assets}），自动更新无法经配置启用 | crates/xray-conf/src/app_config.rs:152-161; crates/xray-core/src/register.rs:691-703
- 证据：Rust `GeodataConfig { code, dir }`（app_config.rs:154-160）；Go `GeodataConfig { Cron *string json:"cron"; Outbound string json:"outbound"; Assets []*GeodataAssetConfig json:"assets" }`（Go infra/conf/geodata.go:42-45）。register.rs:695-697 注释自认："当前 shape 为 {code, dir}，**对齐 Go {cron, outbound, assets} 见 bd issue 待后续修复**"，且 `cron` 为空时 `GeodataInstance.start_with_callback` 直接早退不调度（register.rs:698-699）。
- 影响：Geodata 自动更新（cron 调度 + 指定出站下载 + assets 清单）整条配置面不可用——`cron`/`outbound`/`assets` 三键静默丢弃，功能只能靠代码内默认行为；与第一轮 F15（downloader HTTPS 未实现）叠加后该 feature 实际完全死置。
- 修复建议：按 Go 形状重写 GeodataConfig 三字段并接 `start_with_callback`；`code`/`dir` 若无 Go 对应来源应删除或降级为内部默认。

### [P2] F-W8: version 顶层配置形状不匹配且 feature 为 no-op | crates/xray-conf/src/app_config.rs:144-149; crates/xray-core/src/register.rs:47
- 证据：Rust `VersionConfig { version }`（app_config.rs:146-148）；Go `VersionConfig { MinVersion string json:"min"; MaxVersion string json:"max" }`（Go infra/conf/version.go:10-13，proto 另有 core_version，app/version/config.pb.go:26-28）。Rust 注册 `simple_feature_factory("version")` = no-op SimpleFeature（register.rs:47,743-750）。
- 影响：`{"version":{"min":"26.0.0","max":"26.9.9"}}` 之类配置两边语义都落空：Go 键被丢、Rust 键 `version` 也无任何消费者。低危（该配置罕见），但属"接受即应消费或拒绝"的契约缺口。
- 修复建议：对齐 {min,max} 并在 Instance 启动时做版本区间校验；或 Build 时对该字段显式 Unsupported。

### [P2] F-W9: ipsExcluded 的 CIDR 条目静默丢弃，仅裸 IP 生效 | crates/xray-core/src/wiring.rs:250-254
- 证据：`exclude_for_ip: cfg.ips_excluded.0.iter().filter_map(|s| s.parse().ok()).collect()` —— `parse::<IpAddr>` 对 `173.194.0.0/16` 之类网段解析失败被 `filter_map` 静默滤掉；Go 侧 `geodata.ParseIPRules(c.IPsExcluded)` 支持网段/CIDR 语义（Go infra/conf/xray.go:87-90）。消费端 should_override 也只做精确相等匹配（default.rs:411-415）。
- 影响：排除私网/运营商网段类常规写法（`"ipsExcluded":["192.168.0.0/16"]`）静默无效，嗅探覆盖行为与 Go 不一致，且无告警。
- 修复建议：改存 `IpNet`（ipnet crate 或手写解析），should_override 做 CIDR 包含判断；解析失败的条目打 warn。

### [P2] F-W10: balancer `strategy.settings` 在 JSON→proto 边界被整段丢弃（消费端已就绪） | crates/xray-core/src/wiring.rs:520-538
- 证据：balancers 解析只取 `tag`/`selector`/`strategy.type`/`fallbackTag`，`strategy_settings: None` 硬编码（wiring.rs:531）；Go `StrategyConfig{Type, Settings *json.RawMessage}` 完整透传进 proto `StrategySettings`（Go infra/conf/router.go:16-19,46-64）。而 Rust 引擎侧 `build_balancer` **已具备**反序列化 StrategyLeastLoadConfig 的代码，None 时走默认（xray-app-router/src/router.rs:334-362，注释"当前不解析：用 default 兜底"）。
- 影响：LeastLoad 的 `baselines`/`expectedNodes`/`rttCost`/`maxRTT` 等调优参数全部静默回落默认——即使将来 F1（NotImplementedSelector）修复，leastload 行为仍与用户配置不符。
- 修复建议：wiring.rs 解析 `strategy.settings` 原始 JSON 塞入 proto bytes（TypedMessage），打通 router.rs 已有的反序列化分支。

### [P2] F-W11: commander api 配置三重偏差：tag 必填缺失、Go 六服务名仅认两个、services 门控失效 | crates/xray-core/src/register.rs:608-635
- 证据：① Go `APIConfig.Build` 对空 tag 硬错 "API tag can't be empty."（Go infra/conf/api.go:23-25）；Rust 空 tag 静默默认 "api"（register.rs:611）。② Go services 六个合法名：reflectionservice/handlerservice/loggerservice/statsservice/observatoryservice/routingservice（api.go:29-42）；Rust 只认 "HandlerService"/"ReflectionService" 为 marker，**LoggerService/StatsService/ObservatoryService/RoutingService 落 `other` 分支 warn "unknown api service, ignored"**（register.rs:616-627）——Go 标准配置必然触发误告警。③ services 列表在 Go 侧决定实际注册哪些 gRPC 服务；Rust 实际注册集固定五服务（grpc.rs，第一轮 F14 已述），config 列表仅存 marker 不门控。
- 影响：Go 标准 api 配置在 Rust 产生 2-4 条误导性 "unknown api service" 告警；权限面与 Go 不同（配置只列 HandlerService 时 Rust 仍暴露全部服务）。
- 修复建议：services 大小写不敏感匹配六个 Go 名并按列表门控 gRPC 注册集；补 tag 必填校验。

### [P2] F-W12: Build 期校验差异族——Go 硬错 vs Rust 静默（含一处"注释声称 warn 实无 warn"） | crates/xray-core/src/outbound.rs:500-505; crates/xray-core/src/wiring.rs:248
- 证据：① `destOverride` 未知协议：Go Build 硬错 `unknown protocol`（xray.go:77-79）；Rust 原样透传进 `override_destination_for_protocol`（wiring.rs:248），拼错的协议永不匹配、静默无嗅探覆盖。② `xudpProxyUDP443` 非法值：Go Build 硬错（xray.go:115-117）；Rust `Udp443Policy::from_mux(true,"bogus") → None` 后 `parse_udp443_policies` 直接不插入、**无任何日志**（outbound.rs:500-505；default.rs:2126-2127 测试注释自称"降级告警跳过"，实际无 warn 语句）。③ metrics tag|listen 必填缺失（见 F-W6）。④ burst `pingConfig` 必填：Go Build 硬错 "BurstObservatory requires a valid pingConfig"（observatory.go:30-32）；Rust 静默默认设置 + no-op（burst_feature.rs:42-44,74-75）。
- 影响：配置错误在 Go 是启动期显式失败，在 Rust 全部降级为静默错误行为，排障成本高且与 Go 基准诊断体验不一致。
- 修复建议：四处补 Build 期校验；至少为 xudpProxyUDP443 非法值补上注释声称的 warn。

### [P2] F-W13: inbound 端口必填校验过严：Unix Domain Socket / tun 无端口合法配置被拒 | crates/xray-conf/src/built.rs:188-197
- 证据：`ports.is_empty()` 一律 `ConfError::Build{"inbound 'x' has no port"}`，无任何协议/listen 类型豁免（built.rs:188-197）；Go 侧：tun 入站跳过端口校验（xray.go:141-142），listen 为绝对路径或 `@` 开头的 Unix Domain Socket 时端口可省且必须省（xray.go:150-165），仅裸 IP/anyip 才要求端口（xray.go:143-147,156-158）。
- 影响：dokodemo-over-UDS（tun2socks 常见形态）与 tun 入站的标准配置在 Rust 启动即失败，Go 合法。Rust `Address` 注释自称支持 Unix socket 路径（config.rs:148-150），但 Build 层先拦死。
- 修复建议：built.rs 按 Go 决策树豁免 tun 与 unix-socket listen 的端口要求，下游 spawn_inbounds 补 UDS listener（或显式 Unsupported）。

### [P2] F-W14: healthping pingConfig 子键/类型双重偏差：`sampling`→`samplingCount` 键名不符，duration 字符串不支持导致整段配置静默弃用 | crates/xray-app-observatory/src/burst/healthping_settings.rs:12-21; crates/xray-app-observatory/src/burst_feature.rs:42-43
- 证据：Rust `HealthPingConfig` rename_all=camelCase，采样键为 `samplingCount`（healthping_settings.rs:13-21）；Go JSON 键为 **`sampling`**（`SamplingCount int json:"sampling"`，Go infra/conf/router_strategy.go:51）。interval 类型 Rust 为 `i64`（纳秒），Go `duration.Duration` 同时接受 int 纳秒与 `"1m"` 字符串（Go cfgcommon/duration 语义）；Rust `serde_json::from_value::<HealthPingConfig>(v).ok()`（burst_feature.rs:42-43）在任一子字段类型不符时**整体失败 → None → 全部默认值**，无告警。
- 影响：Go 标准写法 `{"pingConfig":{"interval":"1m","sampling":2}}` 在 Rust：`sampling` 键丢弃、`"1m"` 字符串致整段 pingConfig 弃用——探测周期/采样数全部静默回落默认（60s/10 次），与配置意图不符且无从发现。
- 修复建议：`sampling` 加 alias；interval 用自定义 deserialize_with 兼容 Go duration 字符串与 int 双形态；解析失败时 warn 而非静默取默认。

---

## 2. 与第一轮报告的关系

- F-W1/F-W2 与第一轮 §5 policy/observatory 判定结论不同：第一轮以 manager.rs/observer.rs 运行时默认值对齐为准判 ✅，本轮证实**JSON 解析层键名不匹配导致标准配置根本到不了运行时**，属第一轮未覆盖的切面。
- F-W3 与第一轮并发组 burst_observer.rs:220（锁内同步探测）正交：那条假设 scheduler 已启动，本条是 scheduler 在生产装配下根本无法启动。
- F-W4 与第一轮 F16（xudp-over-mux hit 路径流身份）正交：F16 假设 mux 链路已建立，本条是出站级 mux 配置根本不产生复用。
- F-W5 与第一轮 F5（FakeDNS 引擎未注入）正交，即使 F5 修复仍存在。
- F-W7 与第一轮 F15（geodata HTTPS 下载器）正交：F15 是下载实现缺失，本条是配置入口整体错形。
- F-W11 与第一轮 F14（commander 子方法 UNIMPLEMENTED）正交：F14 是服务能力缺失，本条是 api 配置解析语义偏差。

## 3. 统计与 TOP3

| 严重度 | 数量 |
|---|---|
| P0 | 0 |
| P1 | 4（F-W1 policy 键族 / F-W2 observatory 键族 / F-W3 burst 装配断裂 / F-W4 出站级 mux） |
| P2 | 10（F-W5 ~ F-W14） |

共同根因：xray-conf 的强类型 app 结构体除 LogConfig 外普遍缺 `rename_all = "camelCase"`，且测试只断言容器存在不断言字段捕获值（built.rs:516-517、config.rs:354-355、yaml.rs:68-72、register.rs:897 四处实测均漏检）。

**TOP3：**
1. **F-W1 policy JSON 键族静默失效**——用户面最广的标准配置块，connIdle/bufferSize/statsUser*/system 四开关全丢，连接超时与流量统计被静默关闭。
2. **F-W3+FW2 observatory/burstObservatory 配置→装配双断**——Go 键静默 no-op、方言键启动硬失败，且 F-W2 键名丢弃使两者在标准配置下无法区分"没配"与"配了没用"。
3. **F-W4 出站级 mux 静默无复用**——Go 主流配置写法被接受但完全不生效，连接特征差异显著，属"解析了但没消费"在协议行为面的最大单点。
