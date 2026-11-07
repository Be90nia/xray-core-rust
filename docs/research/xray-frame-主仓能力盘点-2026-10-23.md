# xray-frame 视角：主仓 crates/ 能力盘点（2026-10-23）

> 任务 A 底料 · 只读盘点，零代码改动。
> **范围**：`crates/` 下除 udf-frame 外全部 crate。实测目录 55 个 = 53 个 `xray-*` crate + `udf-frame`；**`crates/xray-frame` 当前不存在**（`glob crates/*` 含 hidden/gitignore 关闭双向证实），任务书所引「crates/xray-frame/src/lib.rs 四条继承线」在主仓无对应实体——见 §5 风险 1。故本表行数 = 53（= 目录数 55 − udf-frame − 不存在的 xray-frame）。
> **判定口径**（对齐 `docs/architecture/udf-frame继承派生规划-2026-10-23.md` §0，不推翻）：
> **A** = udf 已写好、适配本仓，git dep 接线即用（logx/FxScope/SyncStore/池化域/std-ext 十三域/testing/shutdown/config）；
> **B** = udf 有契约/纪律，xray 按自身形态特化（池管理面/互喂/埋点规范/config-reload 模式）；
> **C** = udf 没有、纯 xray 装配语义（plugin/error/accept/deadline/observe/reload 及全部协议 wire 面）。
> **批次口径**（对齐 impl-plan P0-P4）：P0 骨架/设计输入 · P1 通用件+blackhole/loopback 改写+A 类接线 · P2 17 协议迁移（logx 存量起步）· P3 app 层收口 · P4 持续提炼。
> **工具声明**：read/glob/grep 直读约 40 个一手文件（lib.rs/Cargo.toml/关键设施），serena-cli 不适用（批量结构盘点非符号级查询），cbm 图谱未用（全量盘点需一手行号）。所有行号均来自本次实读，未读文件标「未取证」。

---

## 1. 结论

1. **53 个 crate 全部盘点完毕**：公共设施层 14 + transport 层 10 + 协议层 16 + app 层 13。判定分布：**B（继承派生）约 8 个**（buf 管理面、conf、geodata、app-log、app-stats、app-geodata、app-reverse、ws/splithttp/tuic 池管理面），**A（直接接线点）不出现在 crate 级**——A 全部落在 crate 内的子件级（retry/scheduler/cache/clock/logx 接线点，见 §3 映射表），crate 级判定因此以 **C（自有，约 45 个）为绝对多数**，这是 Go 复刻仓的必然形态：wire 面与装配宿主 udf 都没有。
2. **最大阻碍不是缺口而是顺序**：①xray-frame crate 尚未创建（P0 未落地），本盘点只能对着「未来的接缝」分类；②udf-frame 锁定 rev `f507ee23` CI 红（规划文档头注），A 类接线前置不绿；③数据面热路径（xray-buf 池/copy、bridge splice、btls）是红线不可派生，只能管理面侧挂（plan §2.2 已拍板）。
3. **主仓对 xray-frame 的真正价值是三类输入**：C 类件的原型（xray-core Instance/register + xray-features registry + proxyman 注册表 + geodata swap 热替换）、B 类特化的对象（xray-buf 分层池、conf 三格式装配、CPU 密集互喂点）、以及一张「禁止清单」（§4 不能继承/派生项）。

## 2. 主体盘点表（53 行）

### 2.1 公共设施层（14）

| crate | 现有职责 | 关键入口/trait（文件:行） | 判定 | 阻碍与依赖 | 批次 |
|---|---|---|---|---|---|
| **xray-common** | 契约词汇+通用件库（28 个子模块：net/protocol/session 词汇 + retry/cache/uuid/dice/drain/errors/log/signal/task 设施） | `retry.rs:8` Strategy；`cache/mod.rs:11` LruCache；`uuid/mod.rs:14` UUID（v4+v5 SHA1 派生 parse :66）；`drain/mod.rs:27` Drainer（防时序指纹排空）；`errors/mod.rs:23` Error（severity+因果链）；`session/mod.rs:594` Session；`dice.rs:11` DeterministicDice；`protocol/time.rs:25` now()；`log/mod.rs:54` Handler+:80 register_handler+:85 log（tracing 双写）；`lib.rs:37` ensure_default_crypto_provider（进程级 rustls provider 唯一安装口） | **B**（分子模块分流：词汇面 C、通用件面 A 接线候选） | session/net 词汇被全仓引用，替换=全仓改写；uuid/dice 是 wire 耦合（VLESS 认证/drain 种子）实现不可换，仅新增需求可走 std-ext id | A 接线 P1，词汇面 P2-P3 |
| **xray-features** | Feature trait + 工厂注册表 + 各功能域 trait（dns/routing/inbound/outbound/policy/stats/extension） | `feature.rs:65` `trait Feature: Any+Send+Sync`（TypeId 键）；`registry.rs:40` FeatureFactory/:63 register_feature/:89 create_feature（type_url 字符串键+prost Any bytes）；`deps.rs:25` OutboundTagSelector+:50 DepBag；`dns.rs:45` DnsClient；`inbound.rs:14` InboundHandler；`outbound.rs:15` OutboundHandler；`routing.rs:17` Router；`stats.rs:46` Counter/:67 OnlineMap/:142 Channel/:196 Manager；`policy.rs:221` PolicyManager；`extension.rs:63` ContextReceiver | **C**（契约词汇=装配语义；plugin 件原型） | udf plugin 是 reducer/ScriptedRuntime 形态，Feature 是 TypeId 容器形态，互不继承；`#[async_trait]` 风格与新风格不一致（app-router lib.rs 注释点名） | P0-P1（plugin/accept 件设计输入） |
| **xray-buf** | MultiBuffer 缓冲 + 分层池 + copy/pipe/readv（数据面心脏） | `alloc.rs:21-27` 四层 2K/8K/32K/128K+TLS_MAX_PER_TIER=8+SHARD_COUNT=8；`alloc.rs:122` alloc/:167 release（只收容量恰等层大小）；`io.rs:79` Reader/:103 Writer（MultiBuffer 异步 trait）；`copy.rs:59` copy；`pipe.rs:953`；`readv.rs:658`；`timeout.rs:19` TimeoutReaderWrapper/:62 TimeoutWriterWrapper | **B（仅管理面）+ 热路径不可派生** | plan §2.2 拍板：BufferPool 接缝+XrayBufPool 包 alloc/release+PoolBase 管理面（水位/审计/resize）；TLS_CACHE/分层/copy/pipe 红线零改动（性能锚 154-167 MB/s；vision 雷区 CLAUDE.md §5） | P1（管理面） |
| **xray-crypto** | 协议加密框架（AEAD 块封装/认证读写器/chunk） | `lib.rs:13-19` mods；authenticator.rs:360/auth_reader.rs:612/auth_writer.rs:575；chunk.rs:405；aead.rs:1582；cryption_io.rs:487；key_cache.rs:133；`lib.rs:52` rand_between/:84 rand_bytes_between（rejection sampling，bd 6vqk） | **C**（wire 语义） | authenticator 框架与协议分帧强耦合；key_cache → std-ext cache（A 候选）；rand_* 是 Go 对齐原语不可换 | P2（key_cache 接线 P1） |
| **xray-transport** | 传输 IO 边界核心（Link/Connection/Dialer/Listener 注册表 + splice 泵 + accept 纪律） | `link.rs:25` Link；`dialer.rs:35` Dialer/:76 TransportDialFn+全局 dialer 注册表；`listener_registry.rs:35` TransportListener/:51 TransportListenFn/:80 register_transport_listener/:118 listen_tcp；`accept_policy.rs:24` AcceptErrorKind/:38 classify/:62 backoff_if_resource/:75 supervise_accept_loop；`bridge.rs:45` bridge_connections（splice 泵，1967 行）；connection.rs:676 Connection trait | **B/C 分诊**：accept 面（listener_registry+accept_policy）=xray-frame accept 件原型（C）；bridge splice=红线不可派生；sockopt/happy_eyeballs/filelocker 平台设施 C | bridge.rs 是 v49/v50/v52 三轮挂死战役战场，禁改 poll/waker 语义；dialer/listener 注册表是 plugin-dialer 接缝的现成形状 | accept 件 P1；splice 不动 |
| **xray-mux** | mux.cool 协议（帧/会话/worker） | `lib.rs:16-23` mods；`client.rs:275` ClientWorker（16s monitor）；`session.rs:153` Session（id u16）；frame.rs:1073；worker.rs:1482；handler.rs:390 | **C** | wire 不变铁律 + carrier 判据=destination 域名（memory 实测铁律，禁改 VlessCommand 形态） | P2 |
| **xray-tls** | TLS 配置/双栈装配（rustls+btls）/指纹/ECH | `lib.rs:49` `pub use utls::ConnInterface`；`utls.rs:58` ConnInterface；btls_client.rs:1942；btls_reality.rs:603；fingerprint.rs:540；ech.rs:863；tls_session_cache.rs；`lib.rs:39-44` 注释点名 TLS 热重载（ArcSwap）技术债 | **C** | btls 冷编红线（BORING_BSSL_ASSUME_PATCHED+5-10min）；ws/httpupgrade 指纹红线；热重载缺口反而是 xray-frame reload 件的需求输入 | 不派生；tls_session_cache 管理面 P3 评估 |
| **xray-reality** | REALITY 伪装协议（crypto/server/mitm/register） | `lib.rs:14-37` 模块注记+已知缺口；crypto.rs:969；server.rs:2812（server_tls+server_tls_btls bd tce2）；mitm.rs:491；register.rs:612 | **C** | btls 粘性+vendor patch 邻接；mldsa65 服务端接线缺口在案（lib.rs:32-37） | 不动 |
| **xray-geodata** | GeoIP/GeoSite 类型+加载+匹配 | `lib.rs:23` pb re-export/:32 matcher；`src/loader.rs:170 GeoDataLoader`；rule_parser.rs:665；weak_cache.rs:202 | **B** | 匹配/解析 CPU 密集 → plan §2.3 PooledThreadPool 互喂候选；weak_cache → std-ext cache（A 候选） | P1（互喂试点）/P2 |
| **xray-xudp** | XUDP GlobalID + 配置 | `lib.rs:34` GLOBAL_ID_LEN=8/blake3；`lib.rs:44` XudpConfig（env 一次性初始化） | **C** | 协议语义；env 名收敛在 common::platform::env（bd 037f） | P2 |
| **xray-proto** | prost 生成 protobuf 镜像 | `lib.rs:14-100+` include! 树 | **C-无派生面**（生成物） | `protos/` 只读红线（CLAUDE.md §4） | — |
| **xray-conf** | 配置解析装配（JSON/YAML/TOML → BuiltConfig） | `lib.rs` 门面（load_str/build_config/dispatch_*_settings）；confloader.rs:18 load_file；serial.rs:211 build_config；protocols.rs:35（各协议 settings 结构体集）；init.rs:34 register_builtin_stages；built.rs:86 BuiltConfig | **B** | udf config 域（skeleton/config.rs:617+parse.rs:328+infra/config.rs:495）有契约；xray 特化=三格式+proto 双向+built 中间态；reload 件 ← udf config 域模式（plan §3） | P3（reload 件输入） |
| **xray-core** | 装配宿主（Instance/register/wiring/构建层） | `instance.rs:58` Instance（Vec<Arc<dyn Feature>>+TypeId 表）；`register.rs:32` register_all_features/:72 register_all_transports；`functions.rs:136` start_from_built/:159 start_full；wiring.rs:2511；inbound.rs:11388/outbound.rs:6888 | **C** | plugin/reload 件的直接原型来源；构建层巨文件是装配语义 NOT 业务 | P0（设计输入） |
| **xray-cli / xray-stress** | 二进制壳 / 压测 harness | cli `lib.rs:13-24`（run/version/identity/distro；run.rs:593）；stress `lib.rs:8-9`（只消费公开 API） | **C-壳** | 壳层是 FxScope/shutdown 接线点（A），本身无派生面 | P3 |

### 2.2 transport 层（10）

| crate | 协议/职责 | 核心入口 | 判定 | 耦合点/插件化 | 批次 |
|---|---|---|---|---|---|
| xray-transport-tcp | 裸 TCP + security（TLS/REALITY）包装注册 | `lib.rs:13-21`（独立 crate 防循环依赖）；register.rs:185 | **C** | **红线：register.rs 4 维不动**（CLAUDE.md §4） | 不动 |
| xray-transport-websocket | RFC 6455 WS 传输 | `lib.rs:26-34`；pool.rs:161 WsConnectionPool（HashMap<PoolKey,VecDeque>）；register.rs:1302；ws_bridge.rs:467 | **C**+池面 **B** | 指纹红线（ws 握手形态）；池管理面可套 PoolBase | P2（池面 P1 评估） |
| xray-transport-splithttp | HTTP 分包传输（三模式+xmux） | `lib.rs:14-26`；mux.rs:44 XmuxConn/:52 XmuxClient/:146 XmuxManager/:267 ManagerPool；h3_client.rs:811 | **C**+池面 **B** | 与 reality/tls/quic 多重依赖；xmux 池可套管理面 | P2-P3 |
| xray-transport-quic | quinn QUIC 传输 | `lib.rs:13-19`；congestion_swappable（BBR/Brutal 槽 s8ti）；udp_gso.rs:158 | **C** | quinn+rustls 栈 | P3 |
| xray-transport-hysteria | Hysteria 传输算法层（udphop/BBR/Brutal/quinn_adapter） | `lib.rs:12-30`；quinn_adapter.rs:2079；udphop | **C** | 拥塞算法 Go 1:1 翻译，不可框架化 | 不动 |
| xray-transport-grpc | gRPC（H2 Hunk framing） | `lib.rs:14-24`；encoding.rs:1024；register 门控 feature | **C** | h2 栈 | P3 |
| xray-transport-httpupgrade | 伪 WS Upgrade+raw 流 | `lib.rs:15-24`；dialer.rs:397 build/parse_upgrade | **C** | 指纹红线 | P2 |
| xray-transport-naive | naiveproxy 客户端（btls+h2 CONNECT+padding） | `lib.rs:6-9`；dial.rs:470 | **C** | Go 无此协议，互操作特有 | P3 |
| xray-transport-kcp | mKCP（Segment/State/RTT/窗口） | `lib.rs:12-30`；`dialer.rs:26` init_global_conv/:34 next_conv（全局 conv u16） | **C** | 通用 KCP crate 字节级不兼容（lib.rs:52-60 点名），必须 1:1 | 不动（抓包验收族） |
| xray-transport（已列 §2.1） | — | — | — | — | — |

### 2.3 协议层 proxy（16，一行级）

| 协议 crate | 核心 trait/编解码入口 | 能否插件化（耦合点） | 批次 |
|---|---|---|---|
| xray-proxy-vless | `lib.rs:36-47`；encoding/（头编解码+Addons）、encryption/（Vision splice）、validator.rs:301 Validator、dispatcher.rs:1694 make_dial_fn | 壳可插件化；耦合：xray_common session/xray_buf io/xray_tls/freedom；**vision gate 雷区禁碰** | P2 |
| xray-proxy-vmess | `lib.rs:13-31`；aead/（KDF+AuthID 反重放）、encoding（ShakeSizeParser）、validator.rs:318 TimedUserValidator | 壳可插件化；wire 耦合深（AEAD 头）但纯算法已独立可测 | P2 |
| xray-proxy-trojan | `lib.rs:9-20`；protocol.rs:731 帧编解码、validator.rs:322、fallback.rs:299 | 可插件化；依赖 crypto+xray-tls | P2 |
| xray-proxy-ss | `lib.rs:11-17`；protocol.rs:708、stream.rs:1317、ss2022/（sing 对齐 wire）、validator.rs:617 | 可插件化；**ss 战役活跃中（memory：服务端分支待审），迁移排序需 PM 结合战役节奏** | P2 后段 |
| xray-proxy-socks | `lib.rs:9-14`；protocol.rs:513、server.rs:1060、udp.rs:662 | 可插件化（最干净协议之一） | P2 先行 |
| xray-proxy-http | `lib.rs:9-14`；client.rs:972、server.rs:1610 | 可插件化；hyper/h2 依赖 | P2 |
| xray-proxy-dokodemo | `lib.rs:9-13`；server.rs:406（impl InboundHandler）、fakeudp.rs:159 | 可插件化；Linux TPROXY 平台耦合 | P2 |
| xray-proxy-freedom | `lib.rs:9-16`；dispatcher.rs:1193 make_dial_fn 族、fragment.rs:663、udp.rs:1058 | 可插件化；**splice 直连面禁动**（bridge 红线） | P2 |
| xray-proxy-blackhole | `lib.rs:13-18`；handler.rs:168 Handler::process（Writer 回写）、dispatcher.rs:269 | **可，且已拍板为 P1 改写试点**（plan §4） | **P1** |
| xray-proxy-loopback | `lib.rs:16-21`（单文件 579 行）；依赖 app-dispatcher DispatchHandler | **可，P1 试点第二件** | **P1** |
| xray-proxy-hysteria | `lib.rs:8-20`；inbound.rs:568、outbound.rs:252、protocol.rs:602 Defragger | 可；依赖 transport-hysteria/quinn 栈 | P3 |
| xray-proxy-anytls | `lib.rs:13-18`（anytls-rs 0.3.6 wrapper）；client.rs:371 | 可；外部 crate wrapper | P3 |
| xray-proxy-tuic | `lib.rs:6-19`；pool.rs:97 QuinnConnectionPool（锁外 await 纪律 bd 4zjf）、protocol/、udp.rs:426 | 可；quinn 栈+自有连接池（池面 B） | P3 |
| xray-proxy-wireguard | `lib.rs:8-24`；driver.rs:1111、netstack.rs:1055（smoltcp）、tunnel.rs:600（boringtun） | 壳可插件化；重栈（boringtun+smoltcp）整体内聚 | P3 |
| xray-proxy-tun | `lib.rs:8-17`；inbound.rs:2670、netstack.rs:1284、device.rs 平台门控 | 壳可插件化；OS 级设备耦合最深 | P3-P4 |
| xray-proxy-dns | `lib.rs:9-16`；handler.rs:713 decide_action、dns_message.rs:557 | 可；依赖 xray-geodata matcher | P3 |

### 2.4 app 层（13）

| crate | 现有职责 | 关键入口/trait | 判定 | 阻碍与依赖 | 批次 |
|---|---|---|---|---|---|
| xray-app-log | 日志实例（access/dns/general 分发+IP 掩码） | `lib.rs:10-17`；`instance.rs:250` LogHandler trait；mask.rs:279；feature.rs:116 | **B** | 底层接 logx（A 类件）；业务面（三类消息+HandlerCreatorRegistry+掩码）xray 特化 | P2 起（logx 存量迁移，plan §1） |
| xray-app-stats | 流量计数/在线 IP/pub-sub | `lib.rs:10-30`；counter.rs:165 Counter(AtomicI64)、online_map.rs:296、channel.rs:494、manager.rs:505 | **B** | 注册表/快照态 → SyncStore（A）；语义 → observe 件（C） | P3 |
| xray-app-metrics | Prometheus/HTTP 导出 | `lib.rs:10-20`（MetricsHttpServer/StatsCollector/ObservationCollector trait 注入）；metrics.rs:933 | **C**（observe 件原型） | trait 注入形态已就绪，观察面映射直接 | P3（P4 提炼候选） |
| xray-app-policy | 按 level 查运行时策略 | `lib.rs:9-14`；manager.rs:271；policy.rs:221（features 侧 trait） | **C** | 纯装配 | P3 |
| xray-app-proxyman | inbound/outbound handler 注册表+worker | `lib.rs:10-20`；inbound/outbound Manager（HashMap+RwLock）；stats.rs:190 counter_name | **C**（plugin registry 原型） | worker 层依赖 transport+mux 全链路 | P0-P1（设计输入） |
| xray-app-dispatcher | 分发核心（sniff+stats+fakeDNS+splice 准入） | `lib.rs:10-24`；default.rs:4705 DefaultDispatcher+DispatchHandler trait；sniffer.rs:1867；stats.rs:492 SizeStat* | **C** | 数据面耦合（buf/session）；INBOUND_SPLICE/SPLICE_ADMISSIONS 是 splice 准入面（红线邻接） | P3 |
| xray-app-router | 路由引擎（9 Condition+4 均衡策略+webhook） | `lib.rs:9-30`；router.rs:962；condition.rs:1735；strategy_leastload.rs:825 | **C**（B 面：匹配 CPU 密集→互喂候选） | geoip/geosite 匹配是启动期重活 | P3 |
| xray-app-dns | DNS 应用服务（nameserver/hosts/fakedns/缓存控制） | `lib.rs:8-11`；server.rs:1659 DnsService；cache_controller.rs:464；hosts.rs:435 | **C**（A 接线点：cache/scheduler） | cache_controller 可换 std-ext cache+scheduler | P3 |
| xray-app-geodata | cron 下载+原子 swap 热更新 | `lib.rs:9-16`；`instance.rs:16` Scheduler trait；`scheduler.rs:28` CronScheduler；`swap.rs:221` swap_all（Stage/Tx 回滚）；downloader.rs:785 | **B** | 调度→std-ext scheduler（A）；下载重试→std-ext retry/backoff（A）；swap_all=xray-frame reload 件原型（C） | P1（A 接线）/P3（reload 件输入） |
| xray-app-observatory | outbound 健康探测 | `lib.rs:10-17`（ProbeExecutor/OutboundSelector trait）；observer.rs:1559；status.rs:254 | **C**（observe 件原型） | observer 内 `now_unix_secs` → std-ext clock（A 点位） | P3 |
| xray-app-commander | gRPC 命令注册中心（不引 tonic） | `lib.rs:9-19`（GrpcServerRegistrar 注入）；grpc.rs:1806 | **C** | 依赖 commander 生态最后接线 | P4 |
| xray-app-reverse | portal/bridge 反向代理 | `lib.rs:9-19`；worker.rs:1001（pipe 16KiB+mux）；`timer.rs:35` InactivityTimer（Go CancelAfterInactivity 等价，含 SetTimeout） | **B/C**：timer/deadline→udf clock 契约→deadline 件；业务 C | InactivityTimer 注释点名 xray_common 版无 set_timeout 回调——deadline 件需求输入 | P3 |
| xray-app-version | 版本兼容检查 | `lib.rs:9-13`；version.rs:313 compare_versions | **C**（trivial） | — | P4 |

## 3. 特别关注 15 面：主仓现状 ↔ udf 对应件

| 面 | 主仓现状（文件:行） | udf 对应件 | 判定与改造路径 |
|---|---|---|---|
| 内存池/缓冲池 | xray-buf/alloc.rs:21-27（分层+TLS+分片）、:122 alloc、:167 release | skeleton-infra/pool.rs:864 + memgov.rs:777 + pooled_thread_pool.rs:128 | **B**（plan §2.2 拍板：BufferPool 接缝+PoolBase 管理面；热路径零改动） |
| 连接 ID 生成 | kcp dialer.rs:34 next_conv（全局 u16）；mux session.rs:153（id u16）；xudp lib.rs:34（blake3 8B）；common/uuid/mod.rs:14（认证凭据） | std-ext/id.rs:374 | 协议 ID 字段 wire 耦合**不可换实现**；新增 ID 需求走 std-ext id（A） |
| 重试与退避 | common/retry.rs:8 Strategy（Timed/ExponentialBackoff）+retry/retry_timed | std-ext/retry.rs:299 + backoff.rs:85 | **A**（新代码直接用；存量随 P2 迁移） |
| 超时与 deadline | buf/timeout.rs:19/:62 包装器；app-reverse/timer.rs:35 InactivityTimer；common/signal/mod.rs:684（未逐行，未取证） | skeleton/clock.rs:330 + infra clock 契约 | deadline 是 C 类自有件，基于 clock 契约（plan §3）；timer.rs 注释已点名现版缺 set_timeout |
| 限流 | **主仓无通用件**（grep 全仓仅 ss2022 测试名 + wireguard/boringtun 的 rate_limiter 参数两处） | std-ext/ratelimit.rs:333 | **A 补位**（纯增量） |
| 缓存 | common/cache/mod.rs:11 LruCache；geodata weak_cache.rs:202；crypto key_cache.rs:133；tls tls_session_cache.rs；app-dns cache_controller.rs:464 | std-ext/cache.rs:633 | **A**（新代码先行；TLS 会话缓存等 wire 邻接面缓行） |
| 调度器 | app-geodata instance.rs:16 Scheduler trait + scheduler.rs:28 CronScheduler | std-ext/scheduler.rs:624 | **A**（CronScheduler 是 trait 注入形态，换实现零侵入） |
| 时钟 | common/protocol/time.rs:25 now；observatory now_unix_secs（lib.rs re-export） | std-ext/clock.rs:143 + skeleton/clock.rs:330 | **A** |
| 统计与可观测 | features/stats.rs:46/:67/:142/:196 四 trait；app-stats 实现；app-metrics metrics.rs:933；observatory | log-embed + audit.rs:114（SyncStore 快照） | **C** observe 件（P4 提炼候选）；stats 状态环 → SyncStore（A） |
| 错误分类与传播 | common/errors/mod.rs:23 Error（severity+链）+ 各 crate 独立 error.rs（23+ 个） | infra/journal.rs:1265（事件流） | **C** error 件；错误事件流可落 journal（B 面） |
| accept 与连接接入 | transport/listener_registry.rs:35/:80/:118；accept_policy.rs:24/:38/:62/:75（分类/退避/panic 监督）；features/inbound.rs:14 | infra/shutdown.rs:511（停机）+ scheduler | **C** accept 件（plan §3：accept←scheduler）；accept_policy 的错误分类+退避纪律直接进件设计 |
| 配置装配与热重载 | conf 全链（serial.rs:211 build_config、init.rs:34 register_builtin_stages）；features/registry.rs:63 type_url 工厂；core/register.rs:32；**app-geodata swap.rs:221 swap_all（Stage/Tx 回滚热替换）** | skeleton/config.rs:617 + infra/config.rs:495 + parse.rs:328 | **B+C**：装配接 config 域模式；reload 件以 swap_all 为原型（C，P3） |
| DNS 解析与路由 | features/dns.rs:45 DnsClient；app-dns（nameserver/cache/hosts/fakedns）；proxy-dns handler.rs:713；router condition.rs:1735 | std-ext cache/scheduler | 业务件 **C**；其缓存/调度/重试点位 A 接线 |
| 协议编解码框架 | crypto authenticator.rs:360/chunk.rs:405（AEAD 分帧框架）；common/protocol/mod.rs:617（Address/Destination/User 编码） | 无对应 | **C**：编解码本体 wire 耦合不可框架化；「插件壳+生命周期」才是 xray-frame plugin 件的领地 |
| 传输层 mux | xray-mux 全 crate（frame.rs:1073/session.rs:1241/client.rs:1500/worker.rs:1482）+ splithttp mux.rs:44-267（xmux）+ tuic pool.rs:97 | 无对应 | **C**（wire 不变）；xmux/tuic/ws 三个连接池的管理面（水位/审计）**B** 可套 PoolBase |
| TLS/REALITY 装配 | xray-tls（utls.rs:58 ConnInterface、fingerprint.rs:540、ech.rs:863）+ xray-reality（server.rs:2812） | 无对应 | **C，禁派生**（btls 冷编+指纹红线）；TLS 热重载缺口 → reload 件需求输入 |
| 日志 | common/log/mod.rs:54-116（Handler 注册+tracing 双写）+ app-log（instance.rs:250 LogHandler+mask.rs:279）+ 全仓散装（plan 记 642 处） | logx.rs:885 + log-embed 埋点规范 | **A**（logx 唯一入口，plan §1 拍板；P0/P1 不动存量、P2 起迁移） |

## 4. 差距分析

### 4.1 不能继承/派生的项（点名）

1. **数据面热路径 buf/copy**：xray-buf buffer.rs（1053 行）/copy.rs:59/pipe.rs:953/readv.rs:658 + alloc.rs:23 TLS_CACHE。理由：性能锚 154-167 MB/s 不可回退（docs/benchmarks/baseline.md）；vision splice gate 双 revert 史实（CLAUDE.md §5，d8562b56+a427613b）。任何「把池搬进 udf 再换回来」都是伪装的热路径改动——只能按 plan §2.2 管理面侧挂（PoolBase 水位/审计），分配路径一行不动。
2. **transport 粘性代码**：xray-transport-tcp/register.rs（红线：4 维不动）；xray-transport/bridge.rs:45 bridge_connections 及 splice 泵全路径（1967 行；v49 丢唤醒/v50 WakerBug/v52 Windows loopback 病理三轮战役战场，poll/waker 语义禁改）；ws/httpupgrade 握手指纹形态（memory 红线：指纹不动）。
3. **btls 冷编相关**：xray-tls/btls_client.rs:1942、btls_reality.rs:603、xray-reality/server.rs:2812。理由：构建依赖 BORING_BSSL_ASSUME_PATCHED+已打补丁树（CLAUDE.md §5），冷编 5-10min；udf CI 无 btls——任何派生件引 btls 即把构建债传染进父基座。禁派生，禁上浮。
4. **协议 wire 编解码本体（32 族）**：Rust↔Go 互通铁律（wire 不变）；实证：kcp lib.rs:52-60 点名通用 KCP crate 字节级不兼容必须 1:1 翻译。插件化只作用于「壳+生命周期」，永不作用于「字节」。
5. **Go 反射 DI 的 Rust 特化物**：features/registry.rs:40（type_url 字符串键工厂）+ core/wiring.rs（2511 行）。Go 用 reflect 扫参注入，Rust 已特化为 TypeId+type_url 双轨（feature.rs 头注/registry.rs 头注）——udf 无此形态，属 C 类自有，不存在继承对象。
6. **session 全量上下文**：common/session/mod.rs:594 Session（inbound/outbound 全字段，mod 1211 行）。xray-frame 插件 Context 按规划用 serde_json::Value 进出（plan §3 禁引 xray 类型）——两种形态互斥，Session 不可继承，只能在插件边界做窄投影。

### 4.2 可用 udf 机制改造的项（路径一句话 → 落点）

| 现状 | 改造路径 | 落到哪个 udf 件 |
|---|---|---|
| common/retry.rs 自造重试 | 新代码停造轮子，存量随迁移替换 | std-ext retry/backoff（A） |
| 限流全仓缺位（§3 取证） | 直接补位，无存量包袱 | std-ext ratelimit（A） |
| CronScheduler/Timer 散点 | trait 注入形态已就绪，换实现 | std-ext scheduler（A） |
| LruCache/weak_cache/key_cache 三处自造缓存 | 新代码统一走一件，旧三处按 P2+ 收编 | std-ext cache（A） |
| 时钟散点（time.rs/now_unix_secs） | 统一 clock 契约，为 deadline 件铺底 | std-ext/skeleton clock（A） |
| 池无管理面（水位/审计/resize） | 接缝+管理面包裹，分配路径不动 | skeleton-infra PoolBase/PoolManaged（B，plan §2.2） |
| geodata 匹配/规则/DNS 启动期 CPU 密集 | 借 worker 内缓冲跑→RAII 还 | PooledThreadPool 互喂（B，plan §2.3） |
| 642 处散装 log + 双写 Handler | 装配/插件层唯一入口+埋点 target 规范 | logx + log-embed（A） |
| 706 处裸 tokio::spawn（plan 记载） | 托管口唯一化+clippy 禁令 | FxScope（A） |
| 各处自拼停机序 | 宿主停机三段式接缝 | skeleton-infra shutdown（A） |
| InactivityTimer/buf timeout 各自为政 | 收敛为 deadline 件（基于 clock 契约） | xray-frame deadline.rs（C，P4 提炼候选） |
| app-geodata swap_all 热替换 + TLS 热重载缺口 | reload 件原型与需求都已在主仓现成 | xray-frame reload.rs（C，P4 提炼候选） |

## 5. 风险与未知（需 PM 另行取证）

1. **「crates/xray-frame 四条继承线」与主仓现状矛盾**：任务书称其为本仓唯一已接线代码，但 `crates/xray-frame` 目录不存在（glob 两口径证实）。可能在 udf-frame 仓、独立 worktree 或尚未落盘。**未取证**——P0 派单前必须先澄清实体位置，否则 A 类接线的「对面」不存在。
2. **udf-frame `f507ee23` CI 红**（规划文档头注：ubuntu Test std-ext 3s 快败 + windows Test skeleton-infra 56s 败）：A 类全部接线的前置闸门，失败性质（环境路径 vs 产品代码）待日志取证。
3. **只读了声明面**：session/mod.rs 全文、signal/task/net 详情、transport/retry.rs、bridge.rs 全文、三个连接池实现体（ws pool.rs 635/tuic pool.rs 384/splithttp mux.rs 565）未逐行读；相关行的池面 B 判定基于模块文档与类型声明，实现体改造点待 P1 取证。
4. **642 处散装 log / 706 处裸 spawn** 引自规划文档（2026-10-23），本盘点未独立复数。
5. **ss 战役交叉**：xray-proxy-ss 处于活跃战役（服务端分支待审、禁部署），其 P2 迁移排序必须与 ss 战役节奏合并决策，本报告不排序。
6. **批次列为建议值**：以 impl-plan P0-P4 与 udf 规划 §4 为准绳；任何 A 类接线动主仓文件前仍受「未获明确动词授权不写码」铁律约束（本报告为盘点底料，非实施授权）。

---
*盘点人：MainRepoSurvey（代码语境搜索岗，只读）· 2026-10-23 · 全部行号一手实读*
