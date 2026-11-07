# xray-frame ↔ udf-frame 机制差距底料（2026-10-23）

> 任务：udf-frame 机制全集 × xray-frame 现有接线差距盘点，供 PM 汇总工作列表。只读调研，未改任何产品文件，未 commit。

## 结论（首行）

udf 机制面共 **32 个公开模块域**（skeleton 5 + skeleton-infra 14 + std-ext 13），约 2 万行（20,257 行含 218 行死文件），可归纳为 **8 类机制**：数据流契约（skeleton 核心）、异步托管（fx）、停机编排（shutdown）、池化域（pool×3）、状态持久化（journal）、观测栈（logx/tracingx/audit/embed）、内存治理（memgov）、十三域纯 std 散件（std-ext）。**xray-frame 已接线仅 4 条冒烟线**（契约词汇 / 池化契约+ThreadPool impl / FxScope / logx 门面），全部是「类型可见性断言」，无一条生产接线。最大缺口：**插件机制件全部待建**——udf 侧只有承载插件形态的「原料」（BoundedRegistry / ShutdownCoordinator / EffectRuntime 可换 / PoolManaged 契约 / combine 组合器），没有 Plugin trait / Registry（依赖序）/ Context / PluginError / 生命周期状态机 / handler 注册面，这正是 impl-plan P0 的范围。

---

## 0. 取证口径

| 项 | 值 |
|---|---|
| udf-frame | 本地仓 `D:/Project/Xray-core-rust/crates/udf-frame`，HEAD `155f4ab`（main），独立 git 仓，主仓 `.git/info/exclude` 排除（bd Xray-core-rust-zhj8） |
| xray-frame | **master 工作树无此目录**；存在于主仓 `feature/framework` 分支 commit `7af5c451`，取证方式 `git show feature/framework:crates/xray-frame/{Cargo.toml,src/lib.rs}`（只读，未切分支未改工作树） |
| 覆盖核对 | 全部 43 个 src 文件逐一扫 `pub` 声明行（文件:行）；行数与模块数按 `wc -l` + 目录列表核对（§2.4）；examples/tests/README 按目录清单与 Cargo.toml required-features 盘点 |
| 工具声明 | serena-cli 0 次；降级原因：本任务为跨 40+ 文件的**批量声明行扫描**（需逐行号证据），按模式检索 grep 直接产出 file:line 证据，语义级符号导航（def/refs）无用武之地 |
| 未取证项 | 逐条标「未取证」；未跑 udf 测试/构建（只读契约） |

---

## 1. udf 机制全集表

图例：**契约**=trait/数据词汇（skeleton 层）；**实现**=行为件。建议接法：**A** 直接用 / **B** 继承派生 / **C** 不用（xray-frame 自建）。规划文档（`docs/architecture/udf-frame继承派生规划-2026-10-23.md` §0-§3）已定大类；细粒度判定为本报告分析，标 `[推断]`。

### 1.1 skeleton（udf-skeleton，lib 名 `skeleton`；零依赖零 feature；契约层）

#### 1.1.1 核心数据流（src/lib.rs）

| 件 | 位置 | 契约/实现 | feature | 公开 API 摘要 | 适配成本 | 建议接法 |
|---|---|---|---|---|---|---|
| `Reducer` | lib.rs:86 | 契约 | 无 | `State: Clone+Send`(:89) / `Action: Send`(:91) / `Op`(:94) / `initial()`(:102) / `reduce(&state, action, &mut EffectBuf)->State`(:105)；纯函数禁 IO 结构性保证 | 低——插件 reducer 直接实现 | B（插件逻辑层状态迁移用，P2 决策） |
| `EffectId(pub u64)` | lib.rs:117 | 数据词汇 | 无 | Copy+Eq+Hash 效果句柄 | 零（已接线） | A（已接） |
| `Effect<A, Op=Infallible>` | lib.rs:122 | 数据词汇 | 无 | `Emit`（store 直回灌不入账本）/`Run`/`Cancel` 三变体 | 低 | B（插件效果词表宿主定义） |
| `EffectBuf<A, Op>` | lib.rs:148 | 数据词汇 | 无 | `new`(:154)/`push`(:161)/`clear`(:166)/`is_empty`(:171)/`pop_front`(:177) | 低 | B（随 Reducer 走） |
| `EffectRuntime<A, Op>` | lib.rs:204 | 契约 | 无 | `run(effect, back: &ActionSender)`(:208)；panic 如实传播 | 低——解释器可插拔=效果托管插件化 | A（解释器位置可换后端） |
| `NoFx` | lib.rs:217 | 实现 | 无 | 零效果缺省解释器（:219 impl） | 零 | A |
| `ActionSender<A>` | lib.rs:227 | 数据词汇 | 无 | `new`(:242)/`dispatch(A)->bool`(:304)，`#[must_use]` 停机显式化 | 低 | B |
| `Subscription<S>` | lib.rs:315 | 数据词汇 | 无 | Drop=注销（:331 impl）；`#[must_use]` 拦裸调用 | 低 | A |
| `Driver<S, A>` | lib.rs:354 | 契约 | 无 | `bind(sender)`(:356)/`render(&state)`(:358)；宿主主循环接缝 | 低；headless 可不用 | C [推断]（xray 装配层无帧循环语义，暂无消费位） |
| `Store` | lib.rs:395 | 契约 | 无 | `dispatch`(:404)/`snapshot`(:406)/`subscribe`(:429)/`sender`(:431)/`close`(:433)/`is_closed`(:435)；**非 dyn-safe**（:386 注明，subscribe 泛型参）；同步排空/停机闸/回灌预算 64/fail-visible 四条 | 低；非 dyn-safe 限制 Box<dyn Store> | A（SyncStore 装配层状态环） |
| `JournalPort<A>` | lib.rs:503 | 契约 | 无 | `Err`(:505)/`State`(:506)/`append`(:513)/`persist_snapshot`(:517)/`restore`(:521)；后端自换 | 低 | B（插件状态持久化端口） |
| `Restore<A, S>` | lib.rs:526 | 数据词汇 | 无 | `Empty`/`FromInitial`/`FromSnapshot` 三态 | 零 | A |

#### 1.1.2 基础端口域（skeleton/src/ 五模块）

| 件 | 位置 | 契约/实现 | feature | 公开 API 摘要 | 适配成本 | 建议接法 |
|---|---|---|---|---|---|---|
| `Clock` trait | clock.rs:56 | 契约 | 无 | `now_instant`(:61)/`now_system`(:67) 双面分流 | 零 | A（deadline 等通用件的时间源契约） |
| `SystemClock` | clock.rs:82 | 实现 | 无 | std 直通 | 零 | A |
| `MockClock` | clock.rs:128 | 实现 | 无 | 冻结钟+`advance`；确定性测试地基 | 零 | A（dev-dep） |
| `EnvSource` trait | config.rs:92 | 契约 | 无 | `get(key)->Result<String, EnvError>`(:95) | 零 | A（插件配置 env 覆盖口） |
| `EnvError` | config.rs:48 | 数据词汇 | 无 | `Missing`/`NotUnicode(OsString)` 保真原始字节 | 零 | A |
| `StdEnv` | config.rs:123 | 实现 | 无 | std::env 直包 | 零 | A |
| `MockEnv` | config.rs:157 | 实现 | 无 | `with(key, val)` 罐装 | 零 | A（dev-dep） |
| `ConfigPort` | config.rs:259 | 契约 | 无 | `Config` 关联类型(:261)/`load(&dyn EnvSource)`(:266)；缺必填报 Missing 禁静默默认 | 低——插件配置装配即实现此口 | B（每插件一个 ConfigPort） |
| `ConfigError` | config.rs:276 | 数据词汇 | 无 | `Missing/NotUnicode/Parse/Serialize/File`，Display 含键名，source 链 | 零 | A |
| `LogPathResolver` | logpath.rs:23 | 契约 | 无 | `log_root()->PathBuf`(:27) | 零 | A（装配层日志根目录） |
| `Json` 值面 | parse.rs:42 | 数据词汇 | 无 | `#[non_exhaustive]` 保序 JSON 值 | 低 | C [推断]（配置走 serde_json::Value 已够，Json 面暂无消费位） |
| `JsonPort` | parse.rs:97 | 契约 | 无 | `Err`(:99)/`encode`(:101)/`decode`(:103) | 零 | C [推断]（同上；mock 形态有参考价值） |
| `SqlDialectPort` | parse.rs:157 | 契约 | 无 | `quote_ident`(:161)/`placeholder`(:163) | — | C（xray 无 SQL 面） |
| `MdTag`/`MdEvent`/`MarkdownPort` | parse.rs:174/235/283 | 契约 | 无 | Markdown 事件流端口 | — | C（无消费位） |
| `PoolMetrics` | pool.rs:42 | 数据词汇 | 无 | max/idle/borrowed/watermark/dropped_overflow | 低 | A（池读侧统一形状） |
| `PoolResizeError` | pool.rs:64 | 数据词汇 | 无 | `ZeroMax/IdleCapZero/IdleCapGtMax` | 零 | A |
| `PoolAuditKind`/`PoolAuditEvent` | pool.rs:104/120 | 数据词汇 | 无 | Resized/ResizeRejected 事件 + seq 单调 | 零 | A |
| `PoolAuditTicket` | pool.rs:132 | 数据词汇 | 无 | Drop=关流 | 零 | A |
| `PoolManaged` | pool.rs:237 | 契约 | 无 | `Tuning`(:239)/`Metrics: Borrow<PoolMetrics>`(:242)/`resize`(:246)/`metrics`(:249)/`subscribe_audit`(:253)——池类件管理面三挂点 | 低——**插件化核心**：资源型插件统一管理面 | B（已接线，待真用） |

### 1.2 skeleton-infra（udf-skeleton-infra，lib 名 `skeleton_infra`；default=["runtime","pool"]；13 子开关 + full）

feature 门：`runtime`/`pool`(连带 memgov)/`memgov`/`journal`(serde)/`tokio`/`testing`(tokio+runtime)/`log-fs`/`log`(log-fs+log+tracing+tracing-subscriber+tracing-log)/`tracing`/`log-embed`/`compose`/`config-json`/`config-toml`（Cargo.toml [features] 全表）。

#### 1.2.1 停机与异步托管

| 件 | 位置 | 契约/实现 | feature | 公开 API 摘要 | 适配成本 | 建议接法 |
|---|---|---|---|---|---|---|
| `ShutdownCoordinator` | shutdown.rs:257 | 实现 | **常驻零 feature** | `new`(:273)/`with_default_timeout`(:288)/`register(name, FnOnce)`(:298)/`register_with_timeout`(:306)/`shutdown()->ShutdownReport`(:348)/`is_shutdown`(:426)；注册窗/编排窗互斥，串行序、panic 隔离、超时=放弃等待非中断 | 低——**插件停机编排现成** | A（每插件一个 register） |
| `RegisterError`/`OutcomeKind`/`ComponentOutcome`/`ShutdownReport` | shutdown.rs:57/77/88/95 | 数据词汇 | 常驻 | `Closed`/`Duplicate`；`Stopped/Failed/Timeout`；`is_clean`(:101) | 零 | A |
| `FxScope` | fx.rs:199 | 实现 | `tokio` | `new`(:210)/`with_concurrency`(:223)/`with_source`(:230)/`token`(:239)/`close`(:245)/`is_closed`(:253)/`in_flight`(:258)/`spawn`(:264 返回 Result，闸关报 ScopeClosed)/`shutdown`(:297 async 全排空)/`shutdown_timeout`(:304 async 超时 abort) | 低——**插件异步任务唯一托管口** | A（已接线，待真用） |
| `Spawned<T>` | fx.rs:330 | 实现 | `tokio` | `abort`(:357)/`is_finished`(:362)/join 经内部 oneshot（TaskError 隔离） | 零 | A |
| `CancelSource`/`CancelToken`/`cancel_pair` | fx.rs:68/87/123 | 实现 | `tokio` | 幂等 cancel(:74)/观察面(:93)/构造(:123) | 零 | A（插件判停令牌） |
| `TaskError`/`ScopeClosed` | fx.rs:33/56 | 数据词汇 | `tokio` | `Cancelled`/`Panicked(msg)`；闸关 spawn 显式拒 | 零 | A |
| `expect_idle` | fx.rs:368 | 实现 | `tokio` | in_flight≠0 panic（泄漏断言） | 零 | A（测试形态） |

#### 1.2.2 状态环与持久化

| 件 | 位置 | 契约/实现 | feature | 公开 API 摘要 | 适配成本 | 建议接法 |
|---|---|---|---|---|---|---|
| `SyncStore<S, A, Op>` | runtime.rs:233 | 实现 | `runtime`（默认） | `new(root, fx)`(:549)/`restore_from`(:601)；impl Store 六方法 dispatch(:351)/snapshot(:379)/subscribe(:426)/sender(:453)/close(:463)/is_closed(:474)；`subscribe_local`(:691 本地订阅 LocalSubscription)；计数读侧族：`subscriber_count`(:721)/`rejected_after_close`(:730)/`pending_actions`(:737)/`subscriber_panics`(:744)/`subscriber_panic_last_cause`(:753)/`subscriptions_after_close`(:761)/`runtime_panic_count`(:769)/`reducer_panic_count`(:781)/`feedback_budget_exceeded`(:794)；`subscribe_events`(:868)/`take_events`(:890) | 低；**装配层专用非数据面**（规划已定） | A |
| `LocalSubscription` | runtime/local_subs.rs:113 | 实现 | `runtime` | 本地线程订阅票据（Drop=注销） | 零 | A |
| `AuditEvent`/`AuditEventKind`/`AuditTicket` | audit.rs:39/49/97 | 数据词汇 | `runtime` | seq+kind 生命周期事件（Dispatch 含 feedback_depth 链深/ReducerPanic/RuntimePanic/FeedbackBudgetExceeded 等） | 低——观测插件化数据源 | A |
| `Journal` trait | journal.rs:155 | 实现 | `journal` | `State`(:160)/`append_action`(:180)/`restore_stream`(:189)/`append_snapshot`(:196)/`replay`(:203 双层 Result) | 低 | B（后端可换状态持久化） |
| `JsonlJournal<A, S>` | journal.rs:238 | 实现 | `journal` | `create`(:272)/`open`(:301 崩溃残行截断 fail-visible)/`flush`(:366)/`with_snapshot_every`(:378)；impl Journal(:435) + impl **JournalPort**(:566 双 trait 同屏无歧义) | 低 | B |
| `Replay<'j, A>`/`ReplayError`/`JournalError`/`DynJournal`/`SnapshotStream` | journal.rs:621/103/35/209/213 | 实现/词汇 | `journal` | 懒解析迭代器 + `skipped_unknown`(:674 fail-visible 计数) | 零 | A |

#### 1.2.3 池化域（pool + memgov 联动）

| 件 | 位置 | 契约/实现 | feature | 公开 API 摘要 | 适配成本 | 建议接法 |
|---|---|---|---|---|---|---|
| `PoolBase` | pool.rs:99 | 实现 | `pool`（默认） | `new(max, idle_cap)`(:115)/`resize`(:142)/`metrics`(:161)/`subscribe_audit`(:236)；管理面公共逻辑（校验/水位线/审计/溢出计数）写一次；`AUDIT_RING_DEFAULT_CAP`(:38) | 低——**BufferPool 管理面继承的底座**（规划 §2.2） | B（已接线，待派生） |
| `MemoryPool<T, F>` | memgov.rs:441（`#[cfg(feature="pool")] mod memory_pool` :325，re-export :666→`skeleton_infra::memgov::MemoryPool`） | 实现 | `pool` | `new(max, idle_cap, factory)`(:462)/`acquire(timeout)->PoolGuard`(:487 **超时必填 D21 无默认无限等**)/`resize(MemoryTuning)`(:533)/`metrics`(:562)；RAII `PoolGuard`(:609) 只还真借的；panic 自动还缓冲；锁不嵌套+`#[repr(C)]` align(64) 伪共享防 | 低；**装配层非热路径**（连接表/会话缓存/插件态）；数据面热路径 xray-buf 不动（红线） | B（规划 §2.2 拍板） |
| `MemoryTuning`/`MemoryPoolMetrics`/`PoolAcquireTimeout`/`PoolGuard` | memgov.rs:349/359/376/609 | 数据词汇 | `pool` | 调参二参封顶+逐调用超时 | 零 | B |
| `ThreadPool` | pool.rs:570 | 实现 | `pool` | `new(ThreadPoolTuning)`(:583)/`with_policy`(:592)/`execute`(:647)/`resize`(:692)/`metrics`(:723)/`shutdown`(:747)/`subscribe_audit`(:770)；worker panic 摘除另册池不砖 | 零（已接线 impl 断言） | A（CPU 密集同步段，规划 §2.3 互喂） |
| `ThreadPoolTuning`/`ThreadPoolMetrics`/`Task`/`RejectedTask` | pool.rs:375/519/353/357 | 数据词汇 | `pool` | core/max/queue_cap 三参 | 零 | A |
| `RejectPolicy` + 四策略 | pool.rs:403（`AbortPolicy`:450/`CallerRunsPolicy`:453/`DiscardPolicy`:456/`DiscardOldestPolicy`:459） | 实现 | `pool` | `on_reject(task, &PoolHandle)->Result<(), Task>`(:406)；`PoolHandle`(:411) 仅 offer/pop_oldest（:427/:432 封死策略自指递归） | 零 | A |
| `PooledThreadPool<T, F>` | pooled_thread_pool.rs:67 | 实现 | `pool` | `new(mem, threads, borrow_timeout)`(:84 构造期必填)/`mem_pool`(:114)/`threads`(:119)/`borrow_rejected`(:125)；worker 内借缓冲→跑→RAII 还 | 低 | A（geodata/规则匹配等启动期 CPU 段，规划 §2.3） |

#### 1.2.4 观测栈

| 件 | 位置 | 契约/实现 | feature | 公开 API 摘要 | 适配成本 | 建议接法 |
|---|---|---|---|---|---|---|
| `mask_secrets` | logx.rs:157 | 实现 | `log-fs` | 密钥掩码（按长度降序替换） | 低——进出站配置密钥日志掩码调用点 | A |
| `DefaultPathResolver` | logx.rs:221 | 实现 | `log-fs` | `new(project_name)`(:231 家目录解析失败 Err 禁静默落 cwd)；实现 skeleton::LogPathResolver | 零 | A |
| `FileSink`/`FileSinkWriter` | logx.rs:339/442 | 实现 | `log-fs`/`log` | `new(root)`(:356 按日懒开)/`dropped_lines`(:371 写失败丢弃计数 fail-visible)；Writer 壳多把并行写内部锁串行 | 零 | A |
| `HomeDirUnresolvable` | logx.rs:181 | 数据词汇 | `log-fs` | 显式错误 | 零 | A |
| `init_tracing_default`/`init_tracing_from_env` | logx.rs:75/86 | 实现 | `log` | 全局 subscriber 一次成型（`AlreadyInit`:56 单例拒绝） | 低；**装配层一次 init，插件层禁** | A（已接线待真用） |
| `init_with_file`/`LogInitError` | logx.rs:592/272 | 实现 | `log` | 双 sink（console+文件）init | 零 | A（已接线待真用） |
| `bridge_events_to_tracing` | tracingx.rs:45 | 实现 | `tracing` | store 审计事件流→tracing 桥（常挂 ~21ns） | 低 | A（observe 件数据源） |
| `embed_event!` 宏 | lib.rs:53-76（cfg log-embed 开=tracing::event! 转发，关=展开为空） | 实现 | `log-embed` | 埋点纪律：只埋行为决策点/字段化禁格式化/target `skeleton::<域>[::<段>]`；std-ext 同款副本 35 调用点 | 中——宏是文本作用域双副本，xray 侧需自备同款或提炼单源化 [推断] | B（埋点规范对齐 `xray_frame::<域>`） |

#### 1.2.5 内存治理与组合器

| 件 | 位置 | 契约/实现 | feature | 公开 API 摘要 | 适配成本 | 建议接法 |
|---|---|---|---|---|---|---|
| `BoundedRegistry<K, V>` | memgov.rs:50 | 实现 | `memgov` | `new(max, evict)`(:58 max==0 panic)/`insert`(:73 fail-closed)/`get`(:91)/`remove`(:96)/`len`(:101)/`is_empty`(:106)/`capacity`(:111)/`iter`(:116 升序确定序) | 低——**udf 侧最接近 Registry 的现成件**（KV 容器形态） | A（连接表/插件实例表候选） |
| `Eviction`/`BoundError` | memgov.rs:18/31 | 数据词汇 | `memgov` | `Reject`/`PopFirst` 二态 | 零 | A |
| `CountingAllocator` | memgov.rs:131（GlobalAlloc :184） | 实现 | `memgov` | `live_bytes`(:135)/`live_allocs`(:140)/`peak_bytes`(:146)/`reset_peak`(:151)/`total_allocs`(:162)/`total_deallocs`(:168)；全局计数仅串行上下文有效 | 零 | A（基准/泄漏测量） |
| `LeakGuard`/`LeakReport`/`expect_empty` | memgov.rs:233/287/296 | 实现 | `memgov` | `arm`(:242 计数器不在岗诚实降级)/`check`(:258) | 零 | A（测试形态） |
| `combine`/`Combine` | compose.rs:97/246 | 实现 | `compose` | 闭包五件套（get/set/wrap/unwrap/call）组装父子分片；`Reduce` impl(:268) `initial` panic「分片非根」(:274)；零 dyn 零装箱 | 中——形态偏底层，32 协议是否走 Reducer 分片是 P2 设计决策 [推断] | B（插件状态分片候选机制） |
| `ConfigFile<C>` | config.rs:108 | 实现 | `config-json` | `new`(:117)/`layer(Value)`(:125)/`default_layer`(:172)/`file_layer`(:182)/`save`(:196)；serde_json::Value 统一值面层叠合并 | 低 | A |
| `load_toml`/`save_toml`/`file_layer_toml` | config.rs:238/253/218 | 实现 | `config-toml` | TOML↔值面直译；Datetime 显式拒（`TomlValueUnsupported`） | 零 | A（xray config json/toml 双格式候选） |
| `backoff_delay` | backoff.rs:24 | 实现 | 常驻 | 线性退避 `min(base*n, max)`；**注意**：std-ext 同名件(:32)才是现役（带埋点），本文件见 §2.4 死文件注记 | 零 | A（用 std-ext 版） |

#### 1.2.6 测试替身

| 件 | 位置 | 契约/实现 | feature | 公开 API 摘要 | 适配成本 | 建议接法 |
|---|---|---|---|---|---|---|
| `TestStore<S, A, Op>` | testing.rs:181 | 实现 | `testing` | `new(root)`(:237)/`dispatch`(:256)/`receive(ExpectedEffect)`(:269)/`state`(:307)；效果 FIFO 回收逐条断言 | 低 | A（dev-dep；插件 reducer 逐动作断言形态） |
| `ScriptedRuntime`/`Script`/`ExpectedEffect` | testing.rs:104/28/210 | 实现 | `testing` | 脚本步 `Emit/Panic/Never`(:30-34) FIFO 消费；`feed`(:124)/`scope`(:129) | 零 | A |
| `MockJson`/`MockSqlDialect`/`MockMarkdown`/`MockParseError` | parse_mock.rs:115/186/259/71 | 实现 | `testing` | 脚本化解析替身（push_decode/decoded_inputs 等对称记录面） | 零 | A（dev-dep） |

### 1.3 std-ext（udf-std-ext，lib 名 `std_ext`；默认零 feature 十三域全开；仅 `log-embed` 一个可选门）

| 域 | 关键件（文件:行） | 公开 API 摘要 | 适配成本 | 建议接法 |
|---|---|---|---|---|
| `backoff` | `backoff_delay` backoff.rs:32 | 确定性线性退避+埋点 | 零 | A |
| `cache` | `LruCache` cache.rs:339（new:346/insert:354/get:361 touch/peek:367 不 touch/contains:379/remove:385/pop_lru:391/iter:414）；`TtlCache` :438（new:470/insert:480 ttl==0 panic/get:524 惰性过期/`expired` 计数） | O(1) arena 双向链零 unsafe；**单线程 &mut 如实声明** | 低；多线程场景需外包锁 [推断] | A |
| `clock` | `format_duration` clock.rs:42；`rfc3339` 子模块 :86（`format_rfc3339`:96/`parse_rfc3339`:155/`parse_rfc3339_weak`:173/`TimeParseError`:21） | 时长人读+RFC3339 双向恒 UTC | 零 | A |
| `encode` | `HexCase`:33/`hex_encode`:103/`hex_decode`:133；`Base64Alphabet`:160/`base64_encode`:249/`base64_decode`:307；`strip_bom`:440/`detect_unicode_scheme`:474；`Utf16Endianness`:487/`encode_utf16_bytes`:549/`decode_utf16_bytes`:583 | 显式策略禁静默（BOM 矛盾 Err） | 零 | A（ss2022 等协议 hex/base64 候选） |
| `fsx` | `walk` fsx.rs:148（builder max_depth:172/min_depth:178/follow_links:185/sort:191；`DirEntry`:91）；`copy_tree`:545（`SymlinkPolicy`:458）；`rm_all`:700；`TempDir`:777（close:788 显式清理）；`temp_dir_in`:811；`atomic_write` fsx/atomic.rs:59 | 崩溃安全原子写（同卷 rename） | 零 | A（geodata 更新候选） |
| `hash` | `HASH_VERSION`:67/`stable64`:104（FNV-1a 64 RFC 9923）/`stable64_io`:128/`xxh64`:212 | 算法集版本化=输出永不变承诺 | 零 | A（conn_id 指纹派生，规划已提名） |
| `id` | `Id(u128)` id.rs:139；`IdGen` :236（new:290 指纹+Clock/gen:308 同指纹严格递增，同毫秒 4096 配额 fail-closed/fingerprint:332）；`IdParseError`:173 | UUIDv7 确定性变体 RFC 9562 | 零 | A（conn_id，规划已提名） |
| `iter` | `zip_longest`:133（`EitherOrBoth`:83）/`interleave`:217/`minmax`:318（`MinMaxResult`:97）/`dedup`:392/`dedup_by`:415/`process_results`:546 | itertools 语义子集 | 零 | A |
| `paths` | `normalize_lexical`:133/`simplify`:204（Windows verbatim 剥除）/`canonicalize_compat`:236/`relative_to`:268（`RelError`:40 显式）/'`ensure_inside`':328（containment）/`home_dir`:410/`config_dir`:481/`cache_dir`:497/`data_dir`:514 | dunce 同形+XDG | 零 | A |
| `ratelimit` | `TokenBucket` ratelimit.rs:163（new:192/try_acquire:229/acquire:264 阻塞版/capacity:215/refill_rate:221；`TryAcquireError`:94 含 `wait()` 建议:109） | 令牌桶 MockClock 确定性+零自旋 | 低；异步场景 acquire 是阻塞语义需放阻塞线程或改用 try_acquire+FxScope 定时 [推断] | B |
| `retry` | `Sleeper` retry.rs:66/`RetryPolicy`:89（new:106/with_budget:129）/`retry`:220/`retry_if`:245/`RetryError`:141（`into_last`:163） | 同步重试编排 fail-visible 耗尽回灌 | 低；同步形态（Sleeper 阻塞） | B |
| `scheduler` | `Scheduler` scheduler.rs:206（new:221 MockClock 注入/after:247/every:269/tick:327 确定性驱动/next_deadline:418/close:428/is_closed:456/panic_count:462/worker_passes:467 零自旋证据/spawn_worker:475）；`TaskHandle`:504（cancel:513/detach:524）；`WorkerHandle`:536（join:546） | 同步任务调度（超载退化固定延迟无补发） | 低 | A（accept 辅助/deadline 候选，规划已提名） |
| `text` | `decode_bytes` text.rs:57（`DecodeStrategy`:9 严格/损失化显式选择）/`truncate_chars`:95/`to_snake_case`:275 等五 case 转换/`edit_distance`:361/`edit_distance_normalized`:399 | UTF-8 边界安全 | 零 | A |

### 1.4 覆盖核对（目录列表 × 行数 × 公开模块数）

| crate | src 文件 | 行数 | 声明模块 | 死文件（未声明不编译） |
|---|---|---|---|---|
| skeleton | 6 | 2,146 | 5（clock/config/logpath/parse/pool）+ lib 内 12 公开件 | 无 |
| skeleton-infra | 24 | 10,277 | 14（config/shutdown/audit/runtime/fx/testing/parse_mock/journal/logx/tracingx/memgov/pool/pooled_thread_pool/compose） | **backoff.rs（68 行）/text.rs（150 行）lib.rs 无 `mod` 声明**——批 5 拆分残留（grep `mod (backoff|text)` 零命中实证）；其 API 已由 std-ext 承载 |
| std-ext | 19 | 8,834 | 13（backoff/cache/clock/encode/fsx/hash/id/iter/paths/ratelimit/retry/scheduler/text）+ fsx/atomic + clock/rfc3339 | 无 |
| 合计 | 49 文件 | 20,257 | 32 公开模块域 | 218 行 |

tests/examples 盘点：skeleton tests 1（pool.rs）；infra tests 20 + examples 25（含 required-features 门控全表，见 Cargo.toml [[example]] 各条）+ benches 1；std-ext tests 12 + examples 4。全部为 feature 门控验证资产，本报告未逐文件读（标注：测试形态参考仅抽样——testing 模块自身即测试形态承载）。

---

## 2. 插件化机制专章（重点）

### 2.1 udf 侧已有的「插件承载机制」逐个评估

udf **没有 Plugin/Registry/Context 名义的插件机制**（全仓 grep 无 plugin 字样的公开件），但有 **7 个可承载插件形态的原料**：

| # | udf 机制 | 能承载的插件形态 | 证据 |
|---|---|---|---|
| 1 | **`EffectRuntime` 解释器可换** + NoFx/ScriptedRuntime 双先例 | 效果托管插件化：同一 reducer 词汇下解释器后端自换（测试脚本→真实 tokio）——插件「副作用出口」可插拔的契约已成立 | skeleton lib.rs:204 契约单方法；testing.rs:104 脚本实现；fx 域承载真实现 |
| 2 | **`JournalPort` 后端自换**（+ 实现层 `Journal` 全功能面双 trait 分工） | 持久化插件化：JSONL/SQLite/网络后端可插，契约零格式绑定 | skeleton lib.rs:503 端口 + journal.rs:155 实现层 + JsonlJournal 双 impl(:435/:566) |
| 3 | **`PoolManaged` 三挂点契约**（resize/metrics/subscribe_audit） | 资源型插件统一管理面：任何池类件（连接池/缓冲池/对象池）实现此契约即获统一调参/观测/审计——ThreadPool、MemoryPool、PooledThreadPool 三先例 | skeleton pool.rs:237；infra pool.rs:783（ThreadPool impl） |
| 4 | **`ShutdownCoordinator` 注册-编排两窗** | 停机半边生命周期：`register(name, FnOnce)` 注册窗（Closed/Duplicate 显式拒）+ 编排窗（注册序串行、逐组件超时、panic 隔离、报告）——**这是 udf 最像插件生命周期管理面的件**，但只有 stop 半边（无 init/start 序） | shutdown.rs:257-428 |
| 5 | **`BoundedRegistry` 有界注册表** | 插件实例/连接表的**容器**：fail-closed 插入+确定序迭代+泄漏断言面——但它是 KV 容器，**无依赖解析、无类型化查表、无生命周期钩子** | memgov.rs:50-119 |
| 6 | **`combine` 父子分片组合器** | 状态分片式插件：子 feature 的 reduce 委托组合进父状态（插件逻辑层拆分机制）；零 dyn 零装箱；`initial` panic 钉死「分片非根」纪律 | compose.rs:97/246/274 |
| 7 | **端口域三先例**（EnvSource→StdEnv/MockEnv、LogPathResolver→DefaultPathResolver、JsonPort/SqlDialectPort/MarkdownPort→Mock 三件套） | 「契约+参考实现+测试替身同族」的端口插件化范式——配置端口、日志端口、解析端口的插件形态已有完整先例可抄 | skeleton config.rs:92-188、logpath.rs:23；infra parse_mock.rs 全文件 |

辅助件（间接承载）：`FxScope`（插件异步任务唯一托管口+三段停机）、`RejectPolicy` 策略族（行为点 trait+预置实现族开放的先例，pool.rs:403-484）、审计事件流+tracingx 桥+log-embed 埋点规范（观测插件化三件）、`ConfigFile` 分层装配（配置来源可叠层）。

### 2.2 xray-frame 长协议插件集（32 族）可复用 udf 的哪些机制作骨架

| 插件骨架需求 | 复用件 | 接法 |
|---|---|---|
| 插件异步任务托管 | `FxScope`（tokio feature 已引） | 每插件 spawn 走共享 scope 或 per-plugin scope；`CancelToken` 判停；clippy `disallowed_methods` 禁裸 spawn（infra 自用先例 skeleton-infra Cargo.toml [lints.clippy]） |
| 插件停机 | `ShutdownCoordinator.register` | 装配器为每插件注册停机闭包；超时/panic 隔离白拿 |
| 插件配置端口 | `ConfigPort`+`EnvSource`（契约）+ `ConfigFile`（json/toml 层叠） | 每插件实现 ConfigPort；但**缺 per-plugin 段路由**（见缺口 #7） |
| 插件日志/观测 | `logx` 门面 + `log-embed` 规范 + `subscribe_events`/`tracingx` | 装配层一次 init；插件埋点 target 对齐 `xray_frame::<域>`；审计事件流接桥 |
| 插件状态环 | `SyncStore`（runtime）+ `Reducer`/`combine` | 插件注册表/连接表/统计快照走 store 环；分片组合走 combine |
| 插件状态持久化 | `JournalPort`+`JsonlJournal` | 后端自换 |
| 资源型插件管理面 | `PoolManaged`+`PoolBase` | BufferPool 接缝继承管理面（规划 §2.2 拍板形态） |
| 注册表容器 | `BoundedRegistry` | 插件实例表/连接表容器（fail-closed） |
| 测试形态 | `TestStore`/`ScriptedRuntime`/`MockClock`/`MockEnv` | 插件 reducer 逐动作断言+确定性时间线 |
| 通用散件 | id/hash/scheduler/clock/ratelimit/retry 等 | conn_id（id+hash）、accept/deadline（scheduler+clock）、出站限速（ratelimit） |

### 2.3 缺口清单（udf 没有、xray-frame 必须自建的插件机制件）

每项一句职责；「零 xray 类型」列 = 是否需要遵守提炼判据（impl-plan P1 建件纪律）：

| # | 缺口件 | 职责 | 零 xray 类型？ |
|---|---|---|---|
| 1 | `Plugin` trait | 插件身份与装配入口：name/version/deps/build(ctx)——impl-plan §1 已定 v0.1 形态（plugin.rs:38-43 草案） | 是（P4 提炼候选） |
| 2 | `PluginRegistry` | 编译期静态注册+查表分发+**deps 依赖序拓扑排序**（注册序≠启动序）；dispatcher 中央 match 臂的替代终点 | 是（提炼候选） |
| 3 | `PluginContext` | 插件装配一站式聚合：配置摘取+FxScope 句柄+日志柄+池化柄+**handler 登记面**（inbound/outbound 产出注册进 Context） | 是（提炼候选） |
| 4 | `PluginError`+`ErrorKind` | 跨插件统一错误类型（`#[from]` io::Error 等），error.rs 规划件 | 是（提炼候选） |
| 5 | 生命周期状态机 | init/start/stop 三相编排（`ShutdownCoordinator` 只有 stop 半边；启动序+deps 序+失败传播无现成件） | 是（提炼候选） |
| 6 | handler trait + 查表分发 | inbound/outbound handler 的 trait 形状与注册进 Context 的查表机制（替代 xray-core 各 crate 的中央 match） | **否**（handler 签名含 xray 连接/流量类型——协议语义层，留插件） |
| 7 | per-plugin 配置段路由 | 从全局 config 按插件名摘取自己的段再走该插件的 ConfigPort（`ConfigFile` 是整体层叠，无段路由语义） | 是（提炼候选） |
| 8 | version 兼容语义 | `Plugin::version()` 字段预留但 udf 无校验语义；需定兼容策略（semver 检查或仅日志留痕） | 是 |
| 9 | 插件契约测试模板 | 注册/停机/错误传播/依赖缺失四类断言的测试骨架（TestStore 只覆盖 reducer 单环） | 是（dev 侧，提炼候选） |

设计决策留白（PM 拍板项，非缺口）：① 32 协议插件是否走 `Reducer` 分片形态（combine 已可承载，但闭包五件套形态对 32 族协议的重用成本未评估）[推断]；② Registry 用 `BoundedRegistry` 底座还是另造（容量语义：插件数小而固定，Eviction::Reject fail-closed 合用）[推断]。

### 2.4 已发现的上游残留（不影响接线，报告义务）

- `skeleton-infra/src/backoff.rs`（68 行，`pub fn backoff_delay`:24）与 `src/text.rs`（150 行，`decode_bytes`:52 等）**未被 lib.rs 声明为模块，不参与编译**——批 5-1 拆 std-ext 后残留死文件；现役件在 std-ext（backoff.rs:32 / text.rs:57）。行数盘点已含此 218 行，API 面以其 std-ext 版为准。

---

## 3. 现有四条继承线差距表

xray-frame 现状取证（feature/framework @7af5c451）：`lib.rs` 仅 `pub use skeleton::EffectId;`（:28）+ 4 个冒烟测试（:32-49）；`Cargo.toml` 三 path 依赖（udf-skeleton / udf-skeleton-infra features=["tokio","log"] / udf-std-ext）；主仓 workspace members 已注册（主仓 Cargo.toml:83 @该分支）。

| # | 继承线 | 当前接法（冒烟证据） | 生产可用还缺什么 |
|---|---|---|---|
| 1 | **契约词汇** | `pub use skeleton::EffectId` + EffectId(42) 构造断言（lib.rs:28,34-37） | ① xray-frame 自身词汇层未定：Action enum/Op 效果词表/State 形状（谁是装配层被管理的共享态）② 错误类型（PluginError，P0 规划件）③ Store/Driver/JournalPort 契约均未消费——装配层状态环不存在 ④ 测试形态：无 TestStore 用例 |
| 2 | **池化契约+ThreadPool impl** | `assert_pool_managed::<skeleton_infra::pool::ThreadPool>()` 类型级断言（lib.rs:39-46） | ① `BufferPool` 接缝 trait 未建（规划 §2.2：alloc/release 接缝 + XrayBufPool impl + ManagedBufferPool<B: BufferPool>(B, PoolBase) 管理面继承）② MemoryPool 特化未接（连接表/会话缓存/插件态候选位无一处真用）③ 池审计挂点未接宿主观测（subscribe_audit→tracing/日志）④ acquire 超时策略选型未定 ⑤ 红线约束落位：数据面 xray-buf+TLS_CACHE 不动的隔离测试未建 |
| 3 | **FxScope** | `FxScope::new()` 可构造断言（lib.rs:48-51） | ① 裸 spawn 禁令未 clippy 化（主仓无 disallowed_methods 配置；infra 自用先例在）② 托管拓扑未定：全局单 scope vs per-plugin scope；与 `ShutdownCoordinator` 的编排次序未接（FxScope.shutdown 是 async，coordinator.shutdown 是同步 FnOnce 闭包——接线需 spawn 或 block_on 策略）③ in_flight 泄漏断言未进测试（expect_idle/LeakGuard 无用例）④ Spawned 句柄的 join/abort 责任规范未定 |
| 4 | **logx 门面** | `LogInitError: Send+Sync` 类型断言（lib.rs:53-57） | ① 真 init 未接线（`init_tracing_from_env`/`init_with_file` 无调用位；日志根目录 DefaultPathResolver+LogPathResolver 无装配点）② `mask_secrets` 调用点未布（进出站密钥配置打印面）③ `log` feature 依赖树影响未评估：log+tracing+tracing-subscriber+tracing-log 四件进主仓树，与现有 xray-app-log 的日志栈关系未查（未取证）④ 存量 642 处散装 log 迁移策略（规划定 P2 起）未起步 ⑤ log-embed 埋点 target 规范 `xray_frame::<域>` 无一件落样 |

通用缺口（四线共有）：① 装配组合根不存在（lib.rs 头注自述「P0 骨架随后续派单填充」）② path 依赖形态的 CI 缺料（bd zhj8：submodule/单 crate 门面/拆仓三选一待拍板）③ 依赖 rev 未锁（规划文档写 f507ee23，本地 HEAD 已 155f4ab——两处不一致待 PM 定锚）。

---

## 4. 风险与未知

1. **xray-frame 只在分支**：master 工作树无 `crates/xray-frame/`；本报告该侧结论以 `feature/framework` @7af5c451 的 git show 为准。合主线前 CI 必红（bd zhj8 已记），依赖形态拍板前该分支不可合。
2. **rev 锚不一致**：规划文档 §4 写 `rev = f507ee23`，本地 udf HEAD 已 `155f4ab`（+fe5728a CI flake 治理 9 项修复）。规划头注自述该 rev CI run #3 红（ubuntu std-ext 3s 快败 + windows infra 56s）。**本次未跑 udf 测试/CI 验证**，155f4ab 是否绿未取证；接线前须以最新 CI 结论定锚。
3. **log feature 依赖树**：xray-frame 已引 `features=["tokio","log"]`，会把 log/tracing/tracing-subscriber/tracing-log 拉进主仓依赖树；与主仓现有日志设施（xray-app-log 等）的初始化单例冲突面（`AlreadyInit`）未评估——P1 接 logx 时必查。未取证。
4. **Store 非 dyn-safe**：`subscribe(impl FnMut)` 泛型参数（skeleton lib.rs:386-388 注明）——插件侧若需 `Box<dyn Store>` 不可行，设计 PluginContext 时须以泛型或具体 SyncStore 类型承载。
5. **combine 形态成本**：闭包五件套（get/set/wrap/unwrap/call）对 32 族协议的适配工时无实测；是否走 Reducer 分片形态建议 P0 做一个示例插件实测后再定（impl-plan P0 验收本含示例插件端到端）。
6. **死文件残留**：skeleton-infra 218 行未编译残留（§2.4）——上游清理项，接 git dep 前可提请 udf 侧顺手清（或忽略，零行为影响）。
7. **ratelimit/retry 的同步阻塞语义**：acquire 阻塞版与 retry 的 Sleeper 阻塞睡在 tokio 异步上下文不可直用——接入时需 try_acquire 轮询+FxScope 定时或专用阻塞线程。异步版 udf 无（推断，依据 ratelimit.rs:66 Sleeper trait 契约「足额等待」）。

---

*取证完成度：udf 三 crate 49 个 src 文件全部扫过声明行；examples/tests 只做清单盘点未逐文件读；主仓产品代码（xray-buf/transport 等）未读（非本票范围）。工具：grep（批量声明行检索）+ read/git show；serena-cli 未用（批量扫描场景见 §0 声明）。*
