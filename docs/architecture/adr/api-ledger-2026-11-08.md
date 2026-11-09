# API 记账表——批次 B `2b2407da..HEAD` 全量台账（140 项）

> 2026-11-08 审计整改波 P3 交付物（原表只录整改波 8 项 + `PIPE_BUF_CAP` = 批次 B 9 项）；
> **2026-11-09 由 [bd 1rc1o](https://github.com/Be90nia/xray-core-rust)（1rc1o-a 半）补全为
> 全量台账**——批次 B 区间其余 131 项逐条入账，欠账清零。
> 区间 `2b2407da..HEAD`，快照 rev **`HEAD = 7ff0e785`**。新表行号从略
> （pzjpj 锚点纪律：定位 = 符号名 + 文件路径，rev 已钉）；既有 A/B/C/补录表保留其各自
> 快照 rev（`aa0252a3`/`a5871ebb`）的行号，原样不动。
>
> **枚举口径（可复现命令）**：
>
> ```bash
> git diff -U0 2b2407da..HEAD -- crates \
>   | grep -E '^\+\s*pub (async fn|fn|struct|enum|trait|const|static|type|mod|use)' \
>   | grep -vE '^\+\s*pub\((crate|super)\)'
> ```
>
> 命中 **166 行**。计数规则：
> 1. 每命中行 = 1 声明；cfg 门控同名双定义按 1 个符号计（本轮 1 处：
>    `net::disable_icmp_unreachable_report` Windows 实作 / 非 Windows no-op）。
> 2. `pub use` 按**被导出符号**计数而非 use 行；被导出符号已在定义 crate 入账的
>    再导出 / 可见性延展 = 0 项（本轮 5 条 use 行全部属此，逐条见文末对照表）。
> 3. `pub mod` 每条 = 1 项（新公共模块面）。
> 4. 新类型的固有方法**随类型合记 1 项**（批次 A「N 项合记」先例）；既有类型上的
>    新方法 / 签名变更 / 可见性变更逐项单列。
>
> **本表合计 = 140 项（批次 B 9 + 本票补 131）**。逐条对照见文末
> 「枚举行数 ↔ 台账项数对照表」。

## 权威边界

- 本表只记 **pub 面变更**（新增 / 签名变更 / private→pub / 迁移上浮 / 新模块 /
  再导出效果）；`pub(crate)` / `pub(super)` 与私有项不入账。
- **ADR-0004 组件 scope 类型迁移按批记一行，不逐行膨胀**：B1 = 7 组并行，站点按
  crate 列名 = `xray-transport-splithttp` / `xray-transport-websocket` /
  `xray-transport-httpupgrade` / `xray-transport-hysteria`（含 quinn_adapter）/
  `xray-transport-naive` / `xray-proxy-tun` 六族 + `xray-app-dispatcher` 独立组
  （触 8 crate 12 站）。本表只登记已落地的 pub 面投影：`scope::ComponentScope`
  本体（B0'）+ `DefaultDispatcher::scope` 返回类型迁移（B1 组 1，已提交）+
  quinn_adapter / SessionMap::scope 的 B1 参数类型迁移标注（在飞批次）；迁移语义以
  [ADR-0004](adr-0004-component-scope-holder-contract.md) 为权威。

## A. 常量入 ADR-0002 既定地址（`xray-frame::budget`）——3 项

| 项 | 位置 | 归属理由 |
|---|---|---|
| `QUIC_CONN_RECEIVE_WINDOW_BOOKED_BYTES` | `crates/xray-frame/src/budget.rs:113`（= 32 MiB） | 纯常量簿，[ADR-0002](adr-0002-memory-budget-ownership-split.md) 裁决后的既定地址（判据 1 不成立：QUIC 缓冲口径属 Xray 语义 ⇒ 判据 2 归派生层）。值 = 实现缺省 `xray_transport_quic::config::DEFAULT_CONNECTION_RECEIVE_WINDOW`，**交叉断言钉住**（`xray-core::memory_budget::tests::quic_receive_window_ledger_enters_hard_account`:652）|
| `QUIC_STREAM_RECEIVE_WINDOW_BYTES` | `crates/xray-frame/src/budget.rs:119`（= 16 MiB） | 同上（同址；流窗是**连接窗信用内**的子份额，doc 明记「不单独入账」，防重复记账）|
| `XDNS_FRAG_WORST_CASE_BYTES` | `crates/xray-frame/src/budget.rs:196`（= 43,155,456） | 同上（同址；账面算式从实现常量计算，`xdns::frag::WORST_CASE_BYTES` 交叉断言——`memory_budget::tests::xdns_frag_ledger_matches_impl`:1368，改任一上限即红）|

## B. 派生层迁移中件的读数/写入口——2 项（`xray-common::mem_probe`）

| 项 | 位置 | 归属理由 |
|---|---|---|
| `MemoryPlan::effective_max_conns` | `crates/xray-common/src/mem_probe.rs:266` | 归属已由件头 §3.5.5 三判据 + 3 步迁移清单举证（`mem_probe.rs:27-57`，A-03）：档位策略归 `xray-frame::budget::plan`，本项是**读数 API**（`EFFECTIVE_MAX_CONNS` AtomicUsize，0 = 未覆写、回落到派生值），随迁移清单第 2 步平移，**无新归属决策** |
| `set_effective_max_conns` | `crates/xray-common/src/mem_probe.rs:282` | 同上：进程级生效连接数写入口（`limit.max(1)`，返回落库值）；迁移清单第 2 步点名迁 `xray_frame::budget::plan`。消费点 `xray-core::memory_budget`（降档后写生效值，D-02 执行点）|

## C. 无新归属裁决（既有 crate 内的停机接线 / 交叉断言所需可见性）——3 项

| 项 | 位置 | 归属理由 |
|---|---|---|
| `close_shared_client_endpoints` | `crates/xray-transport-quic/src/transport.rs:145` | 停机接线：`Instance::close()`（`xray-core/src/instance.rs:411`）收尾调它 drain 进程级 `SHARED_CLIENT_ENDPOINTS`（旧端点每个 8 MiB 内核缓冲 ×2 不再钉住进程）。**不引入机制**，故无需 ADR；多实例共享池语义已登记为观察项（rescore-security N-2）|
| `DEFAULT_STREAM_RECEIVE_WINDOW` | `crates/xray-transport-quic/src/config.rs:13`（= 16 MiB） | **private → pub**（行为面不变，doc 自陈「pub 是为了登记簿交叉断言」，同 `handshake_gate::MAX_INFLIGHT_HANDSHAKES` 先例）；QUIC 传输语义留协议 crate（§3.5.3 方向件），只开可见性 |
| `DEFAULT_CONNECTION_RECEIVE_WINDOW` | `crates/xray-transport-quic/src/config.rs:18`（= 32 MiB） | 同上；doc 区分「应用层真缓冲 vs socket `SO_RCVBUF`」不同账（bd 2026-11-08 D-03）|

## 补录项（2026-11-08 P3 波新增：核实后入账）

| 项 | 现状 | 结论 |
|---|---|---|
| `bridge::PIPE_BUF_CAP` | `crates/xray-transport/src/bridge.rs:33`（= 64，模块级 `pub const`） | **入账（第 9 项，2026-11-08 P3 波）**：原为函数内私有，提 pub 的唯一理由是簿交叉断言的事实源（D-05：禁簿值自证）。`xray-core::memory_budget::bridge_backpressure_ledger_matches_impl` 已改为 `(PIPE_BUF_CAP + 2) * 512KiB * 2` 推导（PM 亲跑该测试 1 passed）。行为面由 `crates/xray-transport/tests/bridge_backpressure_entry_cap.rs` 钉住，值未变 |

---

以下为 **bd 1rc1o-a 本票补录（131 项）**。行格式：项 / crate / 性质 / 三判据结论 /
实义理由 / 落点（HEAD=`7ff0e785` 文件） / 消费方状态。

## D. 票面点名补录 3 项（AuditArch3，2026-11-08 复核）

| 项（符号） | crate | 性质 | 三判据结论 | 实义理由 | 落点（HEAD） | 消费方状态 |
|---|---|---|---|---|---|---|
| `MuxCarrierHandler::new` | xray-core | 签名变更（增 `plugin_ctx: Arc<PluginContext>`） | 留主仓（判据 2：装配 wiring 绑 core 出入站分发语义；同件原地改形，无新归属裁决） | carrier 后台任务需 ctx 取 fx 托管口（§3.5.6 ①类接管）；旧 `(inner)` 签名拿不到托管口 | `crates/xray-core/src/wiring.rs` | 生产 wiring 装配消费（`snap.set_default`）；mux 修复 9hl0s 配套 |
| `QuinnQuicListener::new` | xray-transport-hysteria | 签名变更（增 `scope` 参数）；**注：参数类型 ADR-0004 B1 已迁 `compat::ManagedScope` → `scope::ComponentScope`（ADR-0004 B1 批产物，批次在飞，HEAD 快照仍 ManagedScope）** | 留主仓（§3.5.3 QUIC/hysteria 方向件；§3.5.6 ①类托管接线，无新归属裁决） | listener 持每连接任务账本（accept 泵 / auth h3 任务），`close` 关闸；旧 `new(endpoint)` 无账本 | `crates/xray-transport-hysteria/src/quinn_adapter.rs` | register 循环构造注入；hysteria 入站全量经此 |
| `SessionMap::scope` | xray-transport-splithttp | 新访问器（→ `&compat::ManagedScope`）；**注：暴露内部账本句柄，ADR-0004 §2.2 Q2 判本轮不扩注入** | 留主仓（splithttp hub 传输语义；Q2 判定 = transport 族账本对宿主不可见、无 drain 面） | hub 级托管口（ctx 内 SessionMap 持有）供 hub 内部 spawn（每连接删除消息任务 ②豁免 bd kwevg 的对照面） | `crates/xray-transport-splithttp/src/hub/session.rs` | 仅 hub 内部消费；无宿主消费（Q2 判定） |

## E. `xray-frame::budget` 常量簿（36 项）

| 项（符号） | crate | 性质 | 三判据结论 | 实义理由 | 落点（HEAD） | 消费方状态 |
|---|---|---|---|---|---|---|
| `XRAY_BUDGET_BYTES` / `MAX_PER_CONN_BUFFER_BYTES` / `MAX_EXPLICIT_SOCKET_BUFFER_BYTES` / `QUIC_UDP_DEFAULT_RECV_BUFFER_BYTES` / `SOCKET_KERNEL_BOOKKEEPING_FACTOR` / `QUIC_UDP_DEFAULT_RECV_BUFFER_BOOKED_BYTES`（6 项合记） | xray-frame | 迁移上浮（ADR-0002 执行：`xray-core::memory_budget` → `xray-frame::budget`，批次 A 已在旧地址录过同名项） | 判据 2（QUIC/缓冲/池分账绑 Xray 语义；ADR-0002 已裁地址，无新裁决） | 登记簿单一事实源搬家，值随搬 | `crates/xray-frame/src/budget.rs` | `xray-core::memory_budget` pub use 全量转出 + 各执行点（sockopt / quic）交叉断言 |
| `HANDSHAKE_INFLIGHT_MAX` / `DNS_CACHE_MAX_ENTRIES` / `TLS_SESSION_CACHE_MAX_ENTRIES` / `FINALMASK_XMC_POOL_MAX_BYTES` / `NEW_POOLS_TOTAL_MAX_BYTES` / `RESERVE_MARGIN_MIN_BYTES`（6 项合记） | xray-frame | 迁移上浮（同上） | 判据 2（同上，ADR-0002 既定地址） | 同上；唯 `HANDSHAKE_INFLIGHT_MAX` 值 128→64（按预算反解握手额度，aec0c730） | `crates/xray-frame/src/budget.rs` | 同上（handshake_gate / dns / tls 执行点交叉断言） |
| `DNS_PENDING_MAX_ENTRIES` / `DNS_PENDING_EST_BYTES` / `HYPER_MAX_IDLE_PER_HOST_CONNECTIONS` / `HYPER_IDLE_CONN_EST_BYTES`（4 项合记） | xray-frame | 拆分新增（原 `DNS_PENDING_MAX_BYTES` / `HYPER_MAX_IDLE_PER_HOST_BYTES` 字节口径各拆为条数 × 估值两常量） | 判据 2（同上，ADR-0002 既定地址） | 条数口径与实现真容量对齐，`条数 × est` 算式可交叉断言（纯字节估计无法对账） | `crates/xray-frame/src/budget.rs` | 簿内 DNS/hyper 分账算式 + `app-dns` singleflight / hyper 连接池对齐 |
| `HANDSHAKE_TASK_EST_BYTES` / `DNS_CACHE_ESTIMATE_BYTES` / `TLS_SESSION_CACHE_ESTIMATE_BYTES` / `MIN_VIABLE_CONCURRENCY`（4 项合记） | xray-frame | 新增常量 | 判据 2（估值与降档算式绑 Xray 分账） | 握手任务 55KiB / DNS 5MiB / 会话 128×20KiB 估值供预算反解；`MIN_VIABLE_CONCURRENCY=8` 是降档并发下限钳（D-01 正解模型） | `crates/xray-frame/src/budget.rs` | `check_startup_budget` / `budget_report` 算式 + 降档接线 |
| `XRAY_BUF_POOL_TOTAL_MAX_BYTES` / `SPLITHTTP_SHARED_BLOCK_POOL_MAX_BYTES` / `HYSTERIA_UDPHOP_SHARED_POOL_MAX_BYTES` / `BRIDGE_BACKPRESSURE_BOUND_PER_CONN_BYTES` / `DNS_SINGLEFLIGHT_UNBOUNDED_NOTE`（5 项合记） | xray-frame | 新增常量 | 判据 2（进程级池/桥上界 = Xray 池分账） | xray-buf 8MiB / splithttp 2MiB / udphop 128×1500 / 桥背压 66×512KiB×2（D-05 事实源 = `bridge::PIPE_BUF_CAP` 推导）；note 是单飞无界警示文案（账本 WARN 引用） | `crates/xray-frame/src/budget.rs` | 簿 + `SharedPoolRegistry` 上界对账 + bridge/udphop/pool_stream 执行点 |
| `H2_MAX_SEND_BUF_PER_CONN_BYTES` / `SPLITHTTP_H2_CLIENT_FLOW_WINDOW_BYTES` / `SPLITHTTP_H2_SERVER_STREAM_WINDOW_BYTES` / `WS_PER_CONN_BUFFER_BOOKED_BYTES` / `DOH3_SESSION_SOCKET_BOOKED_BYTES` / `SPLITHTTP_ENDPOINT_BOOKED_BYTES`（6 项合记） | xray-frame | 新增常量 | 判据 2（h2/ws/DoH3 每连接预约口径 = Xray 传输分账） | h2 窗钉 enc8x（16/32MiB）+ ws 64KiB + DoH3 socket 预约（=QUIC booked）+ endpoint 预约算式入账 | `crates/xray-frame/src/budget.rs` | 簿 + splithttp/websocket/quic 实现值交叉断言 |
| `startup_fixed_floor_bytes` / `startup_fixed_floor_bytes_for` / `startup_fixed_floor_bytes_for_with_inflight`（3 项合记） | xray-frame | 新增函数 | 判据 2（启动期固定地板算式） | 装配期按 listener 数（×档位核数、×握手额度变体）预扣非连接内存，预算门拒启判据的一部分 | `crates/xray-frame/src/budget.rs` | `check_startup_budget` / `budget_report_with` |
| `effective_handshake_inflight` / `set_effective_handshake_inflight`（2 项合记） | xray-frame | 新增读写对 | 判据 2（握手在飞额度生效值） | 预算门按预算反解额度后落值（720c0a1a「握手闸读生效值」），读侧给闸执行点 | `crates/xray-frame/src/budget.rs` | 写 = 预算门装配；读 = `handshake_gate::effective_inflight_limit` |

## F. `xray-frame` 其余（10 项）

| 项（符号） | crate | 性质 | 三判据结论 | 实义理由 | 落点（HEAD） | 消费方状态 |
|---|---|---|---|---|---|---|
| `ComponentScope`（含 new / spawn / reap / fx_scope / close_gate / drain / in_flight / live_refs 8 法；1 项 = 9 声明合记） | xray-frame | 新类型（**ADR-0004 B0' 批产物**，d2ed4436） | 判据 1 不成立（持有者契约绑 Xray 组件生命周期 / 两词分档 / Go 对拍档位）、判据 2 命中归 xray-frame；机制本体 = udf `FxScope` 组合包装零复制（件头契约九条为唯一权威） | 组件自持任务账本时的**持有者契约唯一落点**：close_gate（关闸档）与 drain（排空档）两词分档 + live_refs 环诊断锚 | `crates/xray-frame/src/scope.rs` | dispatcher（B1 组 1 已迁，bd os4kz）+ transport 六族（B1 在飞）；`compat::ManagedScope` 过渡并存、B1' 删 |
| `SharedPoolRegistry`（含 shared / get_or_init；1 项 = 3 声明合记） | xray-frame | 新类型（ARCH-05，b3431fad） | 判据 2（尺寸 class 分桶 = Xray 池类别分账；登记簿本体为进程级 LazyLock 机制） | 多个进程级共享池按尺寸 class 登记上限，防同类池各自无界 | `crates/xray-frame/src/pool.rs` | udphop / splithttp pool_stream 池类别注册；`with_pool` 装配门（r9z0g）配套 |
| `MAX_POOL_CLASSES` | xray-frame | 新增常量 | 判据 2（同上） | 登记簿 class 容量上限（= 8），超限 fail-visible | `crates/xray-frame/src/pool.rs` | `get_or_init` 超限拒绝 |
| `UNBOUNDED_RETENTION` | xray-frame | 新增常量（ARCH-04，2d4305da） | 判据 2（随宿主模块 `xray-frame::cache` 归属；零 xray 语义常量，udf 提炼随宿主模块评估，不单独裁决） | 「不过期」条目的物理保留下限哨兵（365d），防无上限宽限窗被当成永活 | `crates/xray-frame/src/cache.rs` | frame cache + `app-dns::cache_controller`（同源消费） |
| `HandshakeDeadline::new` | xray-frame | 变更（`(limit, idle_limit)` → `(limit)`，构造期 fail-fast 校验保留） | 判据 2（握手时限机制留派生层；无新归属裁决） | 空闲时限面拆给独立 `IdleDeadline`，单一职责分型后总时限构造不再混持两值 | `crates/xray-frame/src/deadline.rs` | 入站握手时限装配 |
| `set_global_secrets` / `global_secrets`（2 项合记） | xray-frame | 新增读写对（掩码表贯通，1a4b08ba） | 判据 2（密钥集合来自 REALITY shortId / uuid 等装配面 = Xray 语义；机制 = udf logx 掩码，A 类接线） | 进程级脱敏密钥表注入口：各协议装配期喂入，日志面共享读 | `crates/xray-frame/src/logging.rs` | `xray-common::log`（`set_secrets` 接线，三通道共享） |
| `disable_icmp_unreachable_report` | xray-frame | 新增函数（cfg 双定义：Windows 实作 / 非 Windows no-op，73bb85a1 net.rs 合并 ioctl） | 留主仓（§3.5.3 网络方向件：Windows `SIO_*` ioctl 不进 udf） | 合并散落的 Windows UDP/ICMP connreset 类 ioctl 为单一入口，拨号面统一调 | `crates/xray-frame/src/net.rs` | UDP/DNS 拨号装配面 |
| `pub mod budget` / `pub mod net`（2 项合记） | xray-frame | 新模块面 | 判据 2（随宿主件） | budget = ADR-0002 上浮落点声明；net = 合并 ioctl 公共入口 | `crates/xray-frame/src/lib.rs` | 全仓 |

## G. `xray-common`（22 项）

| 项（符号） | crate | 性质 | 三判据结论 | 实义理由 | 落点（HEAD） | 消费方状态 |
|---|---|---|---|---|---|---|
| `FALLBACK_AVAILABLE_BYTES` / `ENV_MEM_LIMIT_MB` / `ENV_MAX_CONNS` / `PER_CONN_UPPER_BYTES` / `BRIDGE_GATE_MIN_BYTES` / `BRIDGE_GATE_MAX_BYTES`（6 项合记） | xray-common | 新增常量 | 判据 2（件头 A-03/D-05 已逐条举证：探测机制零语义部分待上浮 udf；档位策略 / `XRAY_` env 前缀 / 闸 = 预算 ÷ 8 绑 Xray 分账） | 兜底 512MB、两级 env 覆写键、每连接满载上界 3MiB、桥方向闸 4–32MiB——整机分账与背压闸的参数簿 | `crates/xray-common/src/mem_probe.rs` | `xray-core::memory_budget`（D-01/D-02）+ `xray-transport::bridge` 方向闸；迁移清单第 2 步 = 1rc1o-b（押后） |
| `MemoryTier`（含 from_available / as_str / label / total_budget；1 项 = 5 声明合记） | xray-common | 新类型 | 判据 2（四档 40/96/192/512MiB 绑 Xray 分账） | 可用内存 → 档位枚举 + 每档总预算派生（档位策略部分，非探测机制） | `crates/xray-common/src/mem_probe.rs` | `MemoryPlan::from_available` |
| `MemoryPlan`（含 from_available / detect / cached / summary；1 项 = 5 声明合记） | xray-common | 新类型 | 判据 2（派生产式与 budget 同址才谈得上对账——件头原话） | 一次探测一次派生：总预算 → 桥闸 → 连接数上限（`effective_max_conns` 已在 B 节单列） | `crates/xray-common/src/mem_probe.rs` | `check_startup_budget` / `budget_report`（D-02）+ dispatcher 降档接线 |
| `probe_available` | xray-common | 新增函数 | **判据 1 命中 → udf 提炼候选**（件头迁移清单第 1 步：`skeleton_infra::mem_probe`，三平台 CI 绿后主仓换依赖） | 六级探测（`XRAY_` env → cgroup v2/v1 → meminfo → GlobalMemoryStatusEx → 兜底，不 panic 不返 0） | `crates/xray-common/src/mem_probe.rs` | `MemoryPlan::detect` / `cached` |
| `VERSION_X` / `VERSION_Y` / `VERSION_Z`（3 项合记） | xray-common | 迁移（版本单源 73bb85a1：`xray-core::version` → `xray-common::version`；Z 11→17 对拍基准升 26.10.17） | 判据 2（对拍基准版本 = Xray 语义；core 侧转出禁两份定义） | 版本号单一事实源上收 base crate，CLI banner / 对拍口径共用 | `crates/xray-common/src/version.rs` | `xray-core::version` pub use 转出 + CLI banner |
| `BRIDGE_UP_READ` / `BRIDGE_UP_WRITE` / `BRIDGE_DOWN_WRITE` / `XHTTP_SRV_H2CONN` / `XHTTP_CLI_H2CONN`（5 项合记） | xray-common | 新增常量（S3 分配归因闭环，7437ad04） | 判据 2（位点 = bridge / xhttp Xray 数据面组件） | alloc_site 位点登记簿 6–10 号：桥双向 + xhttp 两端 h2 连接的分配归因 | `crates/xray-common/src/alloc_site.rs` | alloc 归因表 / 内存账本按位点分账 |
| `SITE_NAMES` | xray-common | 变更（`[&str; 6]` → `[&str; 11]` 扩容） | 判据 2（同上） | 位点名表与新 5 位点同步（11 项含旧 6），禁表与常量漂移 | `crates/xray-common/src/alloc_site.rs` | 归因表输出 |
| `redact_url` | xray-common | 新增函数（bd dqxy3；**c4d1s A-06 已按 §3.5.5 举证**） | **判据 1 命中 → udf 提炼候选**（件头明示「留仓无举证即打回」；过渡期留 xray-common，迁移时删本地副本） | URL 结构脱敏（剥 userinfo/query/fragment，畸形输入回落 `<redacted>`），与 logx 按字面量打码分工 | `crates/xray-common/src/redact.rs` | `xray-core` 配置期错误文案（geodata 资产 URL 校验） |
| `pub mod mem_probe` / `pub mod redact` / `pub mod version`（3 项合记） | xray-common | 新模块面 | 判据 2（随宿主件） | 三模块公开声明 | `crates/xray-common/src/lib.rs` | 全仓 |

## H. `xray-core`（7 项；另 D 节 1 项）

| 项（符号） | crate | 性质 | 三判据结论 | 实义理由 | 落点（HEAD） | 消费方状态 |
|---|---|---|---|---|---|---|
| `BudgetReport`（含 is_ok / summary；1 项 = 3 声明合记） | xray-core | 新类型 | **判据 3 举证留 xray-core**（吃 `xray_conf::BuiltConfig`，上浮 = frame→conf 反向依赖，同 `check_startup_budget` 既证） | 预算门结构化报告（违例逐条 + 可过/拒判定），替代裸 `Result<(), String>` 便于分档单测 | `crates/xray-core/src/memory_budget.rs` | 预算门 + `memory_budget_degrade_wiring` 测试 |
| `budget_report` / `budget_report_with`（2 项合记） | xray-core | 新增函数 | 判据 3 同上 | 报告算式入口；`_with` 变体注入档位计划（单测按档位钉行为） | `crates/xray-core/src/memory_budget.rs` | 预算门 + 簿测试群 |
| `check_startup_budget` | xray-core | 变更（同符号文件内移位 + re-export 面重组，签名不变；批次 A 已录，留 core 举证仍成立） | 判据 3 同上 | 装配期预算门本体（生产与框架两路共用入口） | `crates/xray-core/src/memory_budget.rs` | `start_full` 入口拒启 |
| `OutboundTable` trait / `register_outbounds<T: OutboundTable>`（2 项合记） | xray-core | 新 trait + 签名变更（泛型化） | 判据 2/3（绑 core 出站装配表语义；表注入解耦生产 `SimpleOhm` 与框架路） | 出站注册改经表抽象，任一条目失败即 `Err` 整配置拒启（o91s4 fail-visible） | `crates/xray-core/src/outbound.rs` | 生产 `register_outbounds` → `SimpleOhm`；框架路 `start_full_with_outbound_handlers` |
| `arm_protocol_keys` | xray-core | 新增函数 | 判据 3（装配表语义自检面，留 core） | 返回 in/outbound 构造表全键集，供契约测试比对两主路键集 | `crates/xray-core/src/arm_registry.rs` | `assembly_path_equivalence` 测试（生产侧键集） |

## I. `xray-cli`（4 项）

| 项（符号） | crate | 性质 | 三判据结论 | 实义理由 | 落点（HEAD） | 消费方状态 |
|---|---|---|---|---|---|---|
| `project_assembly` / `AssemblyProjection`（2 项合记） | xray-cli | 新增函数 + 新类型 | 判据 3 留 xray-cli（framework-assembly 装配面语义；测试专用投影，非生产路径） | 真实复现 `run_framework` ①②③ 段的运行时投影，作双主路一致性台账的断言面（bd gjqm7 收口） | `crates/xray-cli/src/framework.rs` | `xray-core::tests::assembly_path_equivalence`（dev-dep 闭环） |
| `project_derivation` / `framework_family_names`（2 项合记） | xray-cli | 新增函数 | 判据 3 同上 | 派生/未注册键集投影 + 框架桥 family 名字典序清单（台账观测面） | `crates/xray-cli/src/framework.rs` | 同上（差异台账断言） |

## J. `xray-app-*`（9 项）

| 项（符号） | crate | 性质 | 三判据结论 | 实义理由 | 落点（HEAD） | 消费方状态 |
|---|---|---|---|---|---|---|
| `DefaultDispatcher::scope` | xray-app-dispatcher | 变更（返回类型 `&ManagedScope` → `&ComponentScope`；**ADR-0004 B1 组 1 批产物**，069cb2d4） | 无新归属裁决（ADR-0004 既裁；dispatcher = 排空档） | 后台任务托管从自持 JoinSet 迁框架件（双账本 = 两套停机语义，已删）；宿主停机编排取句柄 drain | `crates/xray-app-dispatcher/src/default.rs` | 宿主停机编排（dial-bridge 等组件各自持账本） |
| `SF_MAX_ENTRIES` / `MAX_PENDING_QUERIES`（2 项合记） | xray-app-dns | 新增常量（singleflight 锁与零分配查表，21c093be） | 留主仓（DNS 语义） | singleflight 槽表上限 4096（表满 = 本次查询不做去重的显式降级）+ udp pending 表上限 512（与 budget `DNS_PENDING_MAX_ENTRIES` 同值对齐） | `crates/xray-app-dns/src/cache_controller.rs` / `nameserver/udp.rs` | cached.rs singleflight / udp nameserver |
| `from_proto_i32` | xray-app-reverse | 变更（`Result<Self, _>` → `Self`，非法 i32 归一化回退） | 留主仓（proto wire 枚举映射语义） | 越权闸 9b334cff：proto 反序列化面容错归一，不向上抛配置错误 | `crates/xray-app-reverse/src/config.rs` | reverse 越权闸配置解析 |
| `Rule::apply` | xray-app-router | 变更（`Option<String>` → `Result<Option<String>, RouterError>`） | 留主仓（router 语义；2d7d1427「router 不吞错」trssj） | 规则求值内部错误不再静默吞成「无命中」，fail-visible 上抛 | `crates/xray-app-router/src/rule.rs` | 路由匹配主路径 |
| `WebhookEvent::from_context` | xray-app-router | 新增构造器 | 留主仓（webhook 投影自 `RoutingContext`） | 事件字段（目标域/IP/tag/时刻）改由上下文投影，替代手工拼 event | `crates/xray-app-router/src/webhook.rs` | `fire` 内部 |
| `fire` / `is_duplicate`（2 项合记） | xray-app-router | 变更（入参 `(event)` → `(ctx, outbound_tag)`；去重键改 email） | 留主仓（同上） | 旁路发送不阻塞路由不 panic；去重窗按 email 判 | `crates/xray-app-router/src/webhook.rs` | 路由出站命中点 |
| `Manager::with_registry_limit` | xray-app-stats | 新增构造变体 | 留主仓（stats registry 容量注入 = D-03 caps+WARN 面） | 过订容量如实注入登记上限，账本告警可见而非静默无界 | `crates/xray-app-stats/src/manager.rs` | Manager 构造（memory_budget caps 注入） |

## K. `xray-mux`（2 项）

| 项（符号） | crate | 性质 | 三判据结论 | 实义理由 | 落点（HEAD） | 消费方状态 |
|---|---|---|---|---|---|---|
| `global_xudp_manager` / `with_xudp_manager`（2 项合记） | xray-mux | 新增读数 + builder 注入点（mux 会话修复 9hl0s，9b334cff） | 留主仓（XUDP/mux 协议语义） | XUDP manager 进程级单例读数 + worker 缺省改注入（替自持单例，可测可替换） | `crates/xray-mux/src/session.rs` / `worker.rs` | mux worker/inbound 装配 |

## L. `xray-proxy-*`（6 项）

| 项（符号） | crate | 性质 | 三判据结论 | 实义理由 | 落点（HEAD） | 消费方状态 |
|---|---|---|---|---|---|---|
| `has_account_bytes` | xray-proxy-socks | 新增方法 | 留主仓（socks 协议语义） | 凭证比对走 `&[u8]` 零拷贝路径（`has_account` 委托，免 String 分配） | `crates/xray-proxy-socks/src/config.rs` | `has_account` 委托 |
| `write_address_port_ss` | xray-proxy-ss | 变更（返回 `Result<()>`，fail-visible） | 留主仓（SS wire 语义；SS-2022 COW 族 9b334cff） | 超长域/畸形地址不再静默截断，编码失败上抛（255 域名 roundtrip 测试钉住） | `crates/xray-proxy-ss/src/protocol.rs` | client / ss2022 packet 编码全路径 |
| `MAX_FRAG_TOTAL` | xray-proxy-tuic | 新增常量（TUIC UDP 复用按 spec，54e369e4 w06sd） | 留主仓（TUIC wire 语义 spec 钉） | 分片总数上限 = 16（spec 值），超限拒绝 | `crates/xray-proxy-tuic/src/protocol/packet.rs` | `frag_total` 校验 + server 容量算式（1024 assoc ≈ 1MiB） |
| `accepted_connections` | xray-proxy-tuic | 新增读数 | 留主仓（观测面） | server 已接纳连接计数句柄（集成断言用） | `crates/xray-proxy-tuic/src/server.rs` | core 出站集成测试 |
| `sweep_tcp_listens` / `sweep_listens`（2 项合记） | xray-proxy-tun / xray-proxy-wireguard | 新增方法（两 crate 同族各 1） | 留主仓（tun/wg netstack 方向件） | 半开 listen 槽位空闲老化回收（Established 不回收），防扫描堆积 | `crates/xray-proxy-tun/src/netstack.rs` / `crates/xray-proxy-wireguard/src/netstack.rs` | 各自 inbound 泵周期调用 |

## M. `xray-tls`（2 项）

| 项（符号） | crate | 性质 | 三判据结论 | 实义理由 | 落点（HEAD） | 消费方状态 |
|---|---|---|---|---|---|---|
| `KeylogSink` | xray-tls | 新类型别名（masterKeyLog，4w092） | 留主仓（btls/uTLS 对拍调试面） | `SSLKEYLOGFILE` 注入回调类型，对拍抓包必需 | `crates/xray-tls/src/btls_client.rs` | btls/utls keylog 安装（指纹族 connector 全量） |
| `TLS_SESSION_CACHE_CAPACITY` | xray-tls | 新增常量 | 留主仓（rustls 会话缓存事实源；与 budget `TLS_SESSION_CACHE_MAX_ENTRIES=128` 交叉对齐） | 会话缓存容量显式化（128 条 LRU + 24h TTL 双界），条目超 8KiB 需按实测下调 | `crates/xray-tls/src/tls_session_cache.rs` | 进程级会话缓存单例 + 簿断言 |

## N. `xray-transport-hysteria`（5 项；另 D 节 1 项）

| 项（符号） | crate | 性质 | 三判据结论 | 实义理由 | 落点（HEAD） | 消费方状态 |
|---|---|---|---|---|---|---|
| `AUTH_READ_TIMEOUT` / `MAX_MASQ_BODY_BYTES`（2 项合记） | xray-transport-hysteria | 新增常量 | 留主仓（§3.5.3 hysteria 传输语义） | auth 首读 10s 超时 + masquerade body 8MiB 上限（慢速读取/ oversized 伪装面防护） | `crates/xray-transport-hysteria/src/config.rs` | 入站 auth / masq 面 |
| `MAX_UDP_SESSIONS` | xray-transport-hysteria | 新增常量 | 留主仓（同上） | udp 会话容量闸 4096，触顶 fail-visible 拒新 | `crates/xray-transport-hysteria/src/conn.rs` | conn 内闸（dispatcher udp_session 另有同名私有常量分账） |
| `dropped_over_cap` | xray-transport-hysteria | 新增读数 | 留主仓（观测面） | 超容量丢弃计数器（2 的幂次 WARN），DoS 观测 | `crates/xray-transport-hysteria/src/conn.rs` | conn 内部 + 测试 |
| `POOL_IDLE_CAP` | xray-transport-hysteria | 新增常量 | 留主仓（udphop 池调参；独立池件 = udf `ObjectPool`，ADR-0001） | udphop 共享池 idle 上限 128 块（×1500B = 192,000B，簿值对账） | `crates/xray-transport-hysteria/src/udphop.rs` | 池构造 + 簿 + cli 装配 |

## O. `xray-transport-quic`（3 项；批次 B 3 项已录）

| 项（符号） | crate | 性质 | 三判据结论 | 实义理由 | 落点（HEAD） | 消费方状态 |
|---|---|---|---|---|---|---|
| `QUIC_HANDSHAKE_TIMEOUT` | xray-transport-quic | 新增常量 | 留主仓（QUIC 传输语义） | 握手超时 8s 显式化（REALITY 监听路径原裸等，对齐此口径） | `crates/xray-transport-quic/src/transport.rs` | quic transport + reality server 对齐 |
| `is_bbr` / `apply_bbr`（2 项合记） | xray-transport-quic | 新增探测 + 变更（`profile` 参数退场为 `_profile`） | 留主仓（拥塞控制方向件；真 BBR hfb94） | CC 槽位按 `slot` 判定/应用 BBR，不再按 profile 形参路由 | `crates/xray-transport-quic/src/congestion_swappable/quinn_bridge.rs` | hysteria CC 槽位装配 |

## P. `xray-transport-splithttp`（8 项；另 D 节 1 项）

| 项（符号） | crate | 性质 | 三判据结论 | 实义理由 | 落点（HEAD） | 消费方状态 |
|---|---|---|---|---|---|---|
| `pub mod pool_stream` / `POOL_BYTE_BUDGET`（2 项合记） | xray-transport-splithttp | 新模块面 + 常量（读侧按帧取池块，720c0a1a 1a2yy） | 留主仓（splithttp 传输消费件；池机制本体 = udf `ObjectPool` 白拿，ADR-0001） | 读侧进程级块池（2MiB 预算），替代逐读分配 | `crates/xray-transport-splithttp/src/pool_stream.rs` / `lib.rs` | 读侧帧池；账本 `SPLITHTTP_SHARED_BLOCK_POOL_MAX_BYTES` 对齐 |
| `H2_INITIAL_STREAM_WINDOW` / `H2_INITIAL_CONNECTION_WINDOW` / `H2_MAX_SEND_BUF_SIZE` / `H2_SERVER_INITIAL_STREAM_WINDOW` / `H2_SERVER_INITIAL_CONNECTION_WINDOW` / `H2_SERVER_MAX_SEND_BUF_SIZE`（6 项合记） | xray-transport-splithttp | 新增常量 | 留主仓（h2 窗钉 enc8x 调参留协议 crate；值与 budget `SPLITHTTP_H2_*` 簿交叉对齐） | 客户端 32/32/16MiB + 服务端 16/32/16MiB 窗/send_buf 显式常量（hyper 缺省 400KB 钉窗教训） | `crates/xray-transport-splithttp/src/transport.rs` | h2 客户端/服务端构造 |

## Q. `xray-transport-websocket`（1 项）

| 项（符号） | crate | 性质 | 三判据结论 | 实义理由 | 落点（HEAD） | 消费方状态 |
|---|---|---|---|---|---|---|
| `ws_config` | xray-transport-websocket | 新增函数 | 留主仓（ws 传输调参） | 每连接缓冲 64KiB 统一配置面（bd i37bz），读写两侧共用一份 | `crates/xray-transport-websocket/src/config.rs` | client.rs 连接构造 + server.rs `accept_hdr_async_with_config` |

## R. `xray-transport` 根（13 项；批次 B 1 项已录）

| 项（符号） | crate | 性质 | 三判据结论 | 实义理由 | 落点（HEAD） | 消费方状态 |
|---|---|---|---|---|---|---|
| `effective_inflight_limit` | xray-transport | 新增函数 | 留主仓（accept 门执行点；值源 `budget::effective_handshake_inflight`） | 闸构造读生效握手额度（720c0a1a），不再硬编码常量 | `crates/xray-transport/src/handshake_gate.rs` | `HandshakeGate` 构造 |
| `ignore_already_exists` | xray-transport | 新增函数（9wipb；**首个消费点 tcp/register.rs 属红线授权触碰（bd k2tq1）**） | 留主仓（注册面纪律辅助） | 注册 `AlreadyExists` → 放行、其余错误转 `Err`：注册静默失败改 fail-visible 的统一辅助 | `crates/xray-transport/src/lib.rs` | reality / grpc / httpupgrade / websocket / tcp 等 register.rs 全量 |
| `bind_udp_no_connreset` / `bind_std_udp_no_connreset`（2 项合记） | xray-transport | 新增函数（DNS 放大修复族，2d4305da） | 留主仓（§3.5.3 方向件：Windows `SIO_UDP_CONNRESET` 关闭） | UDP socket 关闭 connreset 事件上报，防 WSAECONNRESET 噪声与反射放大面 | `crates/xray-transport/src/udp/mod.rs` | UDP nameserver / DNS 面拨号 |
| `ConnAddrs` / `wrap_conn_client` / `wrap_conn_server`（3 项合记） | xray-transport | 新类型 + 两签名变更（增 `addrs: ConnAddrs` 参数；mask 层序修正 1jt9v） | 留主仓（finalmask 红线区符号补形） | mask 判定需要连接本地/远端地址，包装入口显式传入 | `crates/xray-transport/src/finalmask/mod.rs` | TCP mask 管理器包装路径 |
| `decode_status_error` | xray-transport | 变更（`mut resp`——排空 body 再读 status） | 留主仓（finalmask 传输语义；yqyi6） | 响应体不排空会拖死连接复用，读错误前先 drain | `crates/xray-transport/src/finalmask/realm/http.rs` | DoH/realm http 错误面 |
| `FRAG_SIZE` / `FRAG_CLIENT_ID_SIZE` / `FRAG_COUNT` / `WORST_CASE_BYTES` / `pub mod frag`（5 项合记） | xray-transport | 新模块面 + 常量（xdns 分片 wire 语义） | 留主仓（xdns wire 语义事实源；budget `XDNS_FRAG_WORST_CASE_BYTES`（批次 A 已录）交叉断言到 `WORST_CASE_BYTES`） | 分片 4096 / client id 16384 / 4096 片 / 最坏字节算式——分片编码与簿值唯一来源 | `crates/xray-transport/src/finalmask/xdns/frag.rs` / `xdns/mod.rs` | xdns 分片编码 + 簿断言 |

---

## 枚举行数 ↔ 台账项数对照表

| 步骤 | 数 |
|---|---|
| 枚举命中行（口径命令如头部） | **166** |
| − `pub use` 再导出（5 行 → 0 项，逐条见下） | −5 |
| − 新类型固有方法折叠（MemoryTier 4 + MemoryPlan 4 + ComponentScope 8 + BudgetReport 2 + SharedPoolRegistry 2 = 20 行随宿主合记） | −20 |
| − cfg 同名双定义（`net::disable_icmp_unreachable_report` Windows 实作 / 非 Windows no-op，2 行 → 1 项） | −1 |
| **= 台账项合计** | **140** |
| 其中：批次 B 已录（上文 A/B/C/补录 4 表） | 9 |
| 其中：本票补（D 节 3 + E–R 节 128） | 131 |

`pub use` 5 行逐条（均为「定义点已计」故 0 项）：

1. `xray-core/src/lib.rs` `pub use arm_registry::arm_protocol_keys;` — crate 根再导出，H 节定义点已计。
2. `xray-core/src/memory_budget.rs` `pub use xray_frame::budget::{…}` — **38 符号**（34 常量 + 4 函数；`effective_handshake_inflight` 未转出）全量转出，模块 doc 明示「登记簿常量单一事实源 = `xray_frame::budget`，此处只转出不复制」（§3.5.2 禁两份定义）；全部已在 E 节入账。
3. `xray-core/src/version.rs` `pub use xray_common::version::{VERSION_X, VERSION_Y, VERSION_Z};` — 版本单源转出；G 节已计。
4. `xray-frame/src/lib.rs` `pub use pool::{…}` — 相对旧行新增被导出符号仅 `SharedPoolRegistry`，F 节定义点已计。
5. `xray-frame/src/lib.rs` `pub use scope::{…}` — 相对旧行新增仅 `ComponentScope`，F 节定义点已计。

## 冲突清单

无。全部 131 项归属与既有裁决一致（ADR-0001 池派生件 / ADR-0002 预算地址 /
ADR-0004 scope 契约与批次 / §3.5.3 方向件正面裁决 / §3.5.5 件头举证
（mem_probe A-03、redact A-06）），无与现票面结论相抵、需改判上报的条目。
一处计数口径说明：票面 NOTES 建议「本表合计 = 12 项（批次 B 9 + 本票补 3）」
系**仅补 3 项**时的口径；本票按 PM 拆分裁决扩为全量台账后，合计以实际行数
140 为准（头部已加该行）。

## 记账口径备注

- 「无需 ADR」≠「无需遵守纪律」：全部行仍受 §3.5.2 查重与 §3.5.5 三判据约束，
  只是不产生**新的**归属裁决。
- 迁移上浮行（E1 / G 版本单源）在批次 A 台账（[api-ledger-2026-11-06.md](api-ledger-2026-11-06.md)）
  旧地址已有同名项；本表记录的是**本轮地址变更**这一 pub 面事实，非重复入账。
- 逐项核实方法：`git diff -U0 2b2407da..HEAD -- crates` 过滤声明行（口径见头部），
  每条落地文件以 `git show HEAD:` 核对签名与 doc；**未引用工作树**（工作树有他代理
  在飞的 ADR-0004 B1 批次未提交改动，其类型迁移以「在飞」标注，不冒充已落地）。
- 本表为批次快照（`2b2407da..HEAD` 全量）；后续批次新增公开 API 另起批次表。
