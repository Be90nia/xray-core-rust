# ADR-0004：组件自有 scope 持有件——统一持有者契约（close 只关闸 / drain 才 abort / Drop 不作保证）

- 状态：**Accepted**（PM 拍板 2026-11-09；六项裁决见 §3；本目录 README 索引补录并入 B3 文档批）
- 日期：2026-11-09
- 关联：bd os4kz（本票 · 结构性根因）· bd hnicl（症状票 · splithttp/tun 两处环，**归口为本 ADR 实施批次的验收项**，见 §2.8）· bd xosi9（② reason 模板）· bd s3tig（进程级 scope 收割）· bd a9xgp（arm scope 登记与排空先例）· bd 4a1zy（`compat::ManagedScope` 组合包装先例）· CLAUDE.md §3.5.2 / §3.5.3 / §3.5.5 / §3.5.6 · docs/architecture/xray-frame-强约束插件模型-2026-10-23.md §2.4 坑约束表

> 本 ADR 落**契约与归属 + 裁决**，不落实现。迁移批次见 §2.5，由 fullstack-engineer 另票执行。

## 背景

### 问题

本轮把 6 个组件接进托管口之后，全仓出现 **12 处「组件自有 scope 持有件」**——每个组件自己持一份 `xray_frame::compat::ManagedScope`，自己写字段、自己写 `close`、自己写 doc。三处语义分叉，其中两处**可观测断言与实现不符**：

| 派 | 站数 | 声称语义 | 实际 |
|---|---|---|---|
| **A** | 6 | `close()` 关闸；「句柄丢弃 ⇒ 在途任务 abort」 | 部分站点 Drop-abort **不可达**（环）；部分站点 abort **时点不确定** |
| **B** | 1 | `close()` 关闸 + **显式 `shutdown_timeout` 排空** | 与声称一致（唯一正解样板） |
| **C** | 2 | 组件把**自己 scope 的句柄移进自己托管的任务** | 自引用环 ⇒ 该 scope 的 `Arc<FxScope>` 永不强引用归零 ⇒ **Drop-abort 恒不可达** |

派 C 两处 loci 与票面一致：
- `crates/xray-proxy-tun/src/inbound.rs:405-410`：`let driver_scope = scope.clone();` 后把 `driver_scope` **移进 `scope.spawn(...)` 的任务体**（该任务就住在同一本账里）。
- `crates/xray-transport-splithttp/src/transport.rs:1023-1057` + `hub/session.rs:143-172`：每连接任务持 `Arc<HandlerContext>` → `Arc<SessionMap>` → `SessionMap.scope` ⇒ 任务住在账本里、任务又强引用账本的 owner。

票面「12 处」= **12 个持有件字段**（下表 §2.4 逐行列全）。需要更正票面一处口径：**派 C 的两条是「持有件内部的自引用环 loci」，不是第 13/14 个持有件**；而 `crates/xray-transport-naive/src/inbound.rs:88`（`InboundSlot.scope`）在票面的分派清单里未出现（票面只在建议 4 的迁移顺序中提到「naive InboundSlot」），但代码里它同样是「派 A 声称 + 派 C 环」的混合体（本 ADR 实读补入并列为 §2.4 #9）。

### 后果（为什么不是文档小修）

- `SplithttpListener::close()`（`transport.rs:1326-1337`）只 `scope.close()`（关闸），**全仓无任何 `shutdown_timeout` 兜它** ⇒ 停机 / RemoveInbound 后在途连接任务继续服务到 EOF，与字段 doc「句柄丢弃时 scope 归零 ⇒ 在途连接任务 abort」反向。
- 同族站点：`websocket/register.rs:315-327`、`httpupgrade/register.rs:502-511`、`hysteria/register.rs:235-243`、`hysteria/quinn_adapter.rs:421-428`——四处 `close()` 同样只关闸，同样无 drain 兜底。
- 派 C 两处使「Drop 兜底 abort」**恒不可达** ⇒ 架构层「停机收敛」在不同 crate 给出不同答案，审计无法用一条判据核（每站 doc 各写一遍，三种答法）。

### 对拍基线（Go 26.10.17，`D:/Project/Xray-core`）

Go 侧 transport listener 的 `Close()` 一律是「关接入面 + 释放传输资源」，**不杀已建立连接**：

| Go 站 | 实现 | 行 |
|---|---|---|
| TCP | `func (v *Listener) Close() error { return v.listener.Close() }` | `transport/internet/tcp/hub.go:132-134` |
| WebSocket | `func (ln *Listener) Close() error { return ln.listener.Close() }` | `transport/internet/websocket/hub.go:154-156` |
| HTTPUpgrade | `func (s *server) Close() error { return s.innnerListener.Close() }` | `transport/internet/httpupgrade/hub.go:30-32` |
| XHTTP | h3 分支 `ln.h3server.Close()`；否则 `ln.listener.Close()` | `transport/internet/splithttp/hub.go:588-591` |
| Hysteria | `errors.Combine(l.listener.Close(), l.tr.Close(), l.pktConn.Close())` | `transport/internet/hysteria/hub.go:192-194` |

入站 worker 侧：`tcpWorker.Close()` = 关 hub + 关 proxy（`app/proxyman/inbound/worker.go:151-171`）；`udpWorker.Close()` = 关 hub + 关 checker + 关 proxy（`:433-462`）；`AlwaysOnInboundHandler.Close()` = 逆序关 worker + 关 mux + 关 proxy（`:190-200`）。**Go 侧无「listener close ⇒ abort 已建立连接」这一档**（h3 分支例外，见 §2.4 #4）。

Rust 侧现状相反的一半在更上一层：arm scope 停机排空**确实 abort 在途**（`crates/xray-core/src/inbound.rs:3766`，`arm.arm_scope().shutdown_timeout(ARM_SCOPE_DRAIN_TIMEOUT)`，5s 档，`:3693`）——这是 bd a9xgp 已定的 Rust 侧口径，与 Go 的分层不同。**两者都要保留**（协议/arm 族维持现有 Rust 排空口径，transport 族维持 Go 的关闸口径），见 §2.2 Q1 档位表与 §3 P1（PM 拍板 = 分档）。

## 决策

### 2.1 归属裁决（CLAUDE.md §3.5.5 三判据，顺序固定，不跳步）

**判据 1（零 xray 语义 → udf）：对「持有件契约」不成立。**

- *机制面*已在 udf 且**不得复制**：`skeleton_infra::fx::FxScope` 已是唯一托管机制——`spawn_tracked`（`'static + Send` 标准写法，`fx.rs:315-380`）、`close()`（**只关 accepting 闸**，拒新 spawn、放行在途，`fx.rs:296-303`）、`shutdown_timeout`（三段：关闸 → `abort_all` → 等净，`fx.rs:443-470`，内部 `close_and_take` 见 `fx.rs:498-503`）、`in_flight()`（独立计数，`fx.rs:138-146`、`:310-313`）、scope drop ⇒ JoinSet drop ⇒ **abort 全组**（`fx.rs:329` 对照表 + `:891` 用例 `tracked_drop_aborts_all`）。
- *契约面*（谁 close、close 与 drain 的区别、Drop 允许做什么、环禁令、账本唯一 owner）**含 xray 语义**：它绑 xray 侧的组件生命周期（transport listener / inbound handler / dispatcher / tun）、xray 的停机编排面（arm scope 登记表 + `Instance::close` 逆序关停）、以及 Go 对拍分档。udf 是零 xray 语义的地基，**不收**。
- ⇒ **不上浮 udf**（机制已有）、**不复制机制**（组合包装 `FxScope`）。

**判据 2（否则 → 派生层 `xray-frame`）：成立 ⇒ 契约与持有件形态归 `xray-frame`。**

- 消费方横跨 8 个 crate（`xray-transport-splithttp` / `-hysteria` / `-websocket` / `-httpupgrade` / `-naive`、`xray-proxy-tun`、`xray-app-dispatcher`），无一有 `PluginContext` 注入面（各 crate `clippy.toml` 明载「ctx 不可达」）⇒ 公共底座只能是 `xray-frame`（已被这 8 个 crate 作为 **normal dependency** 引用，依赖方向单向、无环）。
- `xray-frame` 已有 scope 语义面（`crates/xray-frame/src/scope.rs`：`ArmScope` / `ConnScope` / `ArmScopeRegistry`）⇒ 持有者契约与 scope 模型同域。

**判据 3（连派生层都不合适 → 留主仓最近消费方）：不成立，无需举证。** 12 处跨 8 crate、无「最近消费方」可言；公共祖先 = `xray-frame`。

**结论**：持有者契约 + 持有件类型落 `xray-frame`。

### 2.2 契约形状（持有者契约到底规定什么）

三问，各给可判定答案：

**Q1 谁 close（责任面）**——每个持有件必须声明它的 **stop 面**：

| stop 面形态 | 谁负责 | 允许的收口动作 |
|---|---|---|
| 组件自有 async close（如 `TunInboundHandler::close`、`NaiveInboundHandler::close`） | 组件自身 | `close_gate()` + `drain(timeout)` |
| 组件自有 sync close（`TransportListener::close`，trait 为同步 `fn close(&self) -> io::Result<()>`，`crates/xray-transport/src/listener_registry.rs:35-42`） | 组件自身只能关闸 | `close_gate()`；**无 async 面 ⇒ 不得声称 abort** |
| 无 close 面（dispatcher / dial bridge / udp session） | **外部 stop 面**（宿主 watcher / 宿主 drop） | `drain(timeout)` 或依赖 Drop 兜底（须写明） |

规则：**同一持有件只能有一个 stop 面**（禁「组件 close + 宿主 watcher」双排空口径打架）。

**PM 拍板 P1 落定的档位归属（2026-11-09）**——本契约的**分档**如下，**全排空档属线行为变更、须独立对拍票，不夹带在契约归一里**：

| 档 | 组件族 | `close`/`stop` 的语义 | 依据 |
|---|---|---|---|
| **关闸档** | **transport 族**：splithttp / hysteria / websocket / httpupgrade / naive | 只 `close_gate()`：拒新连接，**不杀已建立连接**（在途按 Go 口径服务到 EOF） | Go 26.10.17 `listener.Close()` 一律不杀已建立连接（§背景 对拍基线 5 处） |
| **排空档** | **arm / dispatcher / tun 族** | `drain(timeout)`：关闸 + abort 在途 + 等净；停机后 `in_flight == 0` | Rust 现行口径（bd a9xgp：`arm.arm_scope().shutdown_timeout`，`inbound.rs:3766`） |

⇒ **同一进程内两种停机观感是刻意分层**（R2），非缺陷；须在 B3 文档批写明，避免下一轮审计又判成「不一致缺陷」。

**过渡例外（PM 补裁 2026-11-09，实施中发现的 Q1 ↔ §2.4 张力）**：`transport-naive` 的 `InboundHandler::close`（`inbound.rs` 的 async close 面）**当前实现有显式 `drain(100ms)`**，其行行为属**排空**而非关闸——与上表「transport 族 = 关闸档」的目标态不一致。**B1 按 §2.4 #9 处置列执行：保留 drain、只改名 `shutdown_timeout`→`drain`、doc 写实现事实**（`close()` 显式排空为唯一「在途归零」口；Drop 不作中止保证）；**Q1 的关闸档是目标态，属线行为变更，须独立对拍票**（与 P1 同款纪律：不夹带在契约归一里）。B3 文档批须逐字写明「naive 现行为 = 排空档（过渡），目标态 = 关闸档（待对拍票）」，否则下次审计会把过渡态判成缺陷或把目标态当已实现。

**Q2 close 是关闸还是排空（语义必须用不同名字表达）**——两个动词，**不可混用、不可同名**：

- `close_gate()`：**同步、幂等**；只关 accepting 闸（拒新 spawn，放行在途）；**不断在途**、不等净、不 abort。语义 = Go `listener.Close()`。
- `drain(timeout)`：**异步三段**（关闸 → abort 在途 → 等净），返回 udf `ShutdownReport`（panic 载荷 + 未完成数）。**这是唯一能声称「在途归零」的口**。

**Q3 Drop 允许做什么**——Drop 只允许释放**与任务存活无关**的资源（socket、QUIC endpoint、文件句柄）；**不得**被当作「在途任务终止」的实现手段。理由：`FxScope` 的 abort-on-drop 只在「最后一份 `Arc<FxScope>` 归零」时可达（`fx.rs:329`），而账本常被多持有者共享（listener / hub / accept 泵各持一份克隆）⇒ Drop-abort 是**时点不确定**的 best-effort；派 C 两处更是**恒不可达**。

⇒ **契约禁令**：任何 doc / 注释不得写「句柄丢弃即 abort 在途」「Drop 兜底 abort 在途」这类**依赖 Drop 的断言**。可写的事实性表述：「Drop 时 `FxScope` 若为最后一份强引用，则 JoinSet drop ⇒ abort 全组（udf 语义）」。

**Q4 环禁令（派 C 的结构性根因）**——被托管任务**不得持有其所在账本的 owner 强引用**。可行形态只有两种：

1. **快照/弱引用**：任务只持所需状态的副本，或持 `Weak`（升级失败即放弃——语义必须逐站写明）。
2. **子账本**：确需向同一账本再 spawn 的任务（如 tun driver 要 spawn TCP relay / UDP session），其子任务住**另一本账**（driver 持子账本句柄）。约束：**父 drain 必须显式级联子账本**（udf `FxScope` 无父子语义 ⇒ 级联要手工接线，漏接线 = 停机残留 ⇒ 必须配 in_flight 断言兜住）。

**唯一禁止形态**：任务住在账本 A 里、同时持账本 A 的 owner 强引用（自引用环）。

**Q5 单账本（禁双份账本）**——一个组件恰一本账。持有件可以有多个**克隆句柄**（同一本账），但**owner 恰一个**；账本 owner 由 stop 面负责 drain。

### 2.3 API 草案（组件 scope 持有件在 xray-frame 的形态）

**候选 A（推荐 ⇒ PM 已拍板采纳，见 §3 P3）——`xray_frame::scope::ComponentScope`（由 `compat::ManagedScope` 迁位 + 改名 + 语义显式化）**：

```rust
// crates/xray-frame/src/scope.rs（与 ArmScope / ConnScope 同域）
pub struct ComponentScope { /* label + Arc<FxScope> + LogFacade + 收割节流 */ }

impl ComponentScope {
    pub fn new(label: impl Into<Arc<str>>) -> Self;

    /// 托管 spawn：拒发（scope 已关）⇒ Err(ScopeClosed) + fail-visible 日志。
    pub fn spawn<F>(&self, fut: F) -> Result<Spawned<()>, ScopeClosed>;

    /// 关闸（同步、幂等）：拒新 spawn，放行在途。**不断在途、不等净**。
    pub fn close_gate(&self);

    /// 排空（异步三段）：关闸 → abort 在途 → 等净；返回 udf ShutdownReport。
    /// **唯一可声称「在途归零」的口**。
    pub async fn drain(&self, timeout: Duration) -> ShutdownReport;

    /// 在途任务数（排空断言锚）。
    pub fn in_flight(&self) -> usize;

    /// 底层 udf FxScope 句柄（供组合件复用，如 pool::spawn_idle_pruner）。
    pub fn fx_scope(&self) -> &FxScope;

    /// 诊断面：该账本当前有多少份强引用（环破除的唯一可观测锚，见 §2.6 A4）。
    ///
    /// `#[doc(hidden)]`（PM 拍板 P6）：**诊断用**，非稳定 API；未来若 udf 提供等价
    /// 能力则随上游收敛删除。语义 = `Arc::strong_count` + 1（自身这份）。
    #[doc(hidden)]
    pub fn live_refs(&self) -> usize;
}
```

- 机制零复制：内部仍是 udf `FxScope` + `LogFacade` fail-visible 上报（沿用 `compat::ManagedScope` 现状，`compat.rs:287-390`），只加 **xray 语义**：①方法名把「关闸 / 排空」钉死；②Drop 语义 doc 钉死「不作保证」；③环禁令 + 单账本写入件头。
- 落点理由：`scope.rs` 已是 scope 语义面（arm / conn / registry）。`ComponentScope` 与 arm/conn **不构成寿命链**：arm→conn 是父子级联（父关级联子），`ComponentScope` 是**并列的组件内账本**，不参与级联（udf `FxScope` 无父子语义），故其 drain 责任自带（§2.2 Q1）。
- `compat` 模块保留**进程级**能力入口（`CompatCaps` / `install` / `spawn` / `spawn_scope` / `reap_into` / `REAP_EVERY`）——那是「ctx 不可达站点的进程级兜底」，与「组件持有件」是不同轴，**不混居**。
- **过渡期并存（PM 批次边界改判）**：B0' 先落 `ComponentScope`，`compat::ManagedScope` **临时并存**以免与在飞代理的施工同文件冲突；**终态不留兼容别名**——B1' 删 `compat::ManagedScope` 且 `grep -rn "compat::ManagedScope" crates` 归零（§2.5）。并存期属**实施中间态**，不是本 ADR 的终态设计。

**候选 B——保留 `compat::ManagedScope` 只改方法名 + 补契约文档**：改动最小、零迁移风险；但 `compat` 模块的章程是「进程级能力入口」，把「组件持有者契约」放进去会让两类 scope 语义继续混居（这正是本次分裂的成因之一）；且命名 `ManagedScope` 不表达「持有者契约」。

**候选 C——`trait ScopeHolder` + 统一登记**：抽象度最高；但 12 处持有件形态异质（字段 / `Arc<字段>` / `ParkMutex<Option<字段>>`），trait 化只换来一层间接而无行为收益（YAGNI）。

**推荐 A（PM 已拍板采纳，见 §3 P3）**，理由：①单类型干净切换（`compat::ManagedScope` 随迁移删除，不留并行 API——符合「只扩展不 fork」与「不留兼容别名」纪律；**过渡期并存仅为实施中间态**，见 §2.5）；②契约的**可判定性**落在方法名上（`close_gate` vs `drain` 不可混用，编译期即分档）；③落点与既有 scope 语义面同域。

**候选 D——把契约升到 udf**：否决（§2.1 判据 1：含 xray 语义 + 机制已有 + 提炼回路需独立 PR + 三平台 CI 绿 + 主仓换依赖复测 32/32，成本与收益不成比例）。

### 2.4 迁移映射表（12 处持有件）

图例：**现状** = 读码事实（附证据）；**目标** = §2.2 契约下的语义；**改动形态** = 落地手段；**风险** = 主要失败模式。

| # | 站点（`file:line`） | 现状语义 | 目标语义 | 改动形态 | 风险 |
|---|---|---|---|---|---|
| 1 | `xray-transport-splithttp/src/transport.rs:1317-1318`（`SplithttpListener.scope`） | 派A。`close()` 只 `scope.close()`（`:1326-1337`），无 drain；字段 doc 称「句柄丢弃时 scope 归零 ⇒ 在途连接任务 abort」。**该字段是 hub 账本的别名**（`transport.rs:281-282` `hub_scope = ctx.sessions.scope().clone()`、`listener_scope = hub_scope.clone()`），而 hub 账本被每连接任务经 `Arc<HandlerContext>`→`Arc<SessionMap>`→scope 强引用 ⇒ **Drop-abort 不可达** ⇒ 在途连接继续到 EOF | 关闸语义显式（`close_gate`）；**不声称 abort**；abort 责任归 hub 账本 owner（#2）与 stop 面 | 类型换 `ComponentScope`；`close()` 调 `close_gate()`；删伪断言 doc | 破环改动触及每连接任务的捕获链（`ctx: Arc<HandlerContext>`），漏改 ⇒ 环残留 |
| 2 | `xray-transport-splithttp/src/hub/session.rs:86-87`（`SessionMap.scope`） | 派A+派C。owner = `SessionMap`；每连接任务持 `Arc<HandlerContext>`→`Arc<SessionMap>`（`hub.rs:151` `sessions: Arc<SessionMap>`）；reap 定时器任务持 `self_clone: Arc<SessionMap>`（`session.rs:143-172`）⇒ **双环**，owner 永不归零 | 账本 owner 上移到 hub/listener 级（`SessionMap` 不再持 scope）；reap 定时器迁到该账本且**不持 owner 强引用** | 字段搬迁；任务捕获改弱引用/快照 | reap 依赖 `self.remove(&sid)`（`session.rs:166`）⇒ 弱引用升级失败即放弃（语义变化：hub 已死则无需 reap） |
| 3 | `xray-transport-hysteria/src/register.rs:226-227`（`HysteriaTransportListener.scope`） | 派A。`close()` = abort accept 任务 + `scope.close()` 关闸（`:235-243`），无 drain；accept 泵持 `conn_scope` 克隆 ⇒ 最后引用归零晚于 listener drop ⇒ abort **时点不确定** | 关闸语义显式；「abort 发生在 accept 泵退出后」写为**实现事实**，非契约保证 | 类型换；`close()` 调 `close_gate()`；doc 改写 | 低（行为不变，仅语义显式化） |
| 4 | `xray-transport-hysteria/src/quinn_adapter.rs:381-382`（`QuinnQuicListener.scope`） | 派A。`close()` 只 `scope.close()` + `ep.close()`（`:421-428`），无 drain；**线行为档位与 TCP 族不同**——Go XHTTP h3 分支 `ln.h3server.Close()` 会断已建立 h3 连接（`splithttp/hub.go:588-591`） | 关闸语义显式；**h3 档单列**（PM 拍板 P1：transport 族 = 关闸档，Go 口径，不杀已建立连接 ⇒ h3 分支亦按关闸档，**不因 Go h3 会断连而保留断连**） | 类型换；`close_gate()`；doc 标注 h3 档 | 若统一改成「不 abort」会偏离 Go h3 行为（对拍风险，见 §3 P1 备注） |
| 5 | `xray-transport-websocket/src/register.rs:310-311`（`WsTransportListener.scope`） | 派A。`close()` = `close_notify.notify_one()` + `scope.close()`（`:315-327`），无 drain；accept 泵持 `loop_scope`（`:210-211`）⇒ abort 时点不确定 | 关闸语义显式；握手在途按 Go 语义继续（established conn continue） | 类型换；`close_gate()`；doc 改写 | 低 |
| 6 | `xray-transport-httpupgrade/src/register.rs:497-498`（`HttpUpgradeListener.scope`） | 派A。`close()` = abort accept 任务 + `scope.close()`（`:502-511`），无 drain | 同 #5 | 类型换；`close_gate()`；doc 改写 | 低 |
| 7 | `xray-proxy-tun/src/inbound.rs:177`（`TunInboundHandler.scope`，`ParkMutex<Option<ManagedScope>>`） | 派B（**样板**）+ 派C。`close()` 走 `scope.shutdown_timeout(100ms)` 三段排空（`:431`）⇒ 行为正确；但 `driver_scope` 被移进自己 spawn 的任务（`:405-410`）⇒ 环 ⇒ Drop-abort 不可达（close 路径仍有效） | 保留显式排空（改名 `drain`）；**破环**：driver 与其派生任务用**子账本**（父 drain 须级联子账本） | 类型换；`shutdown_timeout`→`drain`；driver 子账本化 + 级联接线 | 子账本无自动级联 ⇒ 漏级联 ⇒ 停机残留（须 `in_flight` 断言兜住） |
| 8 | `xray-transport-hysteria/src/udphop.rs:260`（`UdpHopPacketConn.prune_scope`） | 直接持 field。**close() 已 drain**（`:509` `shutdown_timeout(100ms)`）⇒ 事实正解，但票面归为「直接持 field」；hop 任务不持 scope ⇒ 无环；doc `:564-566` 称「自带 Drop=abort 语义，无需显式收口」与 close 已 drain **自相矛盾** | 显式排空为唯一保证；Drop-abort 降级为实现事实；doc 自洽 | 类型换；`drain` 改名；doc 修正 | 低 |
| 9 | `xray-transport-naive/src/inbound.rs:88`（`InboundSlot.scope`，`Arc<ManagedScope>`） | **票面分派清单未列**（票面建议 4 的迁移顺序提到「naive InboundSlot」）。派A+派C：每连接任务持 `conn_scope`（`:187-188`、`:206`）⇒ 环 ⇒ Drop-abort 不可达；`close()` 已 drain 100ms（`:255`）⇒ 行为正确、doc 假（`:86-87` 称「slot 摘除即 scope Drop 兜底 abort」） | 显式排空为唯一保证；破环（弱引用/快照） | 类型换；`drain` 改名；捕获链改弱引用 | `service_fn` 闭包需 scope 句柄（`:206-213`）⇒ 升级失败路径要定义（连接中止 vs 放行） |
| 10 | `xray-app-dispatcher/src/default.rs:933`（`DefaultDispatcher.scope`） | 直接持 field。排空**不在组件自身**而在宿主 watcher（`crates/xray-core/src/functions.rs:585` `dispatcher.scope().shutdown_timeout(DISPATCHER_DRAIN_TIMEOUT)`）⇒ 组件无 close 面但有宿主兜底；无环 | 归入「外部 stop 面」档（§2.2 Q1 第三行）；类型换 + `drain` 改名 | 类型换；`drain` 改名；契约注明「排空责任在宿主 watcher」 | 低 |
| 11 | `xray-app-dispatcher/src/default.rs:1725`（`DialBridge.scope`） | 直接持 field。chained task **不持** scope（`:2046` 克隆仅用于调用 `spawn`，任务体只捕获 `chained_fut`）⇒ 无环；无 close 面 ⇒ 靠 bridge drop ⇒ Drop-abort 可达但 best-effort | 「bridge drop ⇒ abort chained task」写为**实现事实**（非契约保证）；建议补显式 stop 面或明确接受 best-effort | 类型换；`drain` 改名；doc 标注 | 低（若要求强保证则需新增 stop 面 = 新增 API） |
| 12 | `xray-app-dispatcher/src/udp_session.rs:104`（`UdpDispatchSession.scope`） | 直接持 field。会话 drop ⇒ abort（任务只捕获 `dispatcher`/`access`，**不持会话** ⇒ 无环）；无显式 close 面 | 「会话寿命 = 账本寿命，drop 终止为实现事实」写入契约 | 类型换；`drain` 改名；doc 标注 | 低 |

**附：12 处之外的一处明确排除**——`crates/xray-transport-hysteria/src/udphop.rs:142-146` 的**进程级** `static SCOPE: LazyLock<ManagedScope>`（进程级池老化 pruner）：属 §3.5.6 **②豁免**（任务必须活得比任何组件久），**不进本持有件契约**（无 close 面、寿命 = 进程）。契约文档需显式排除此类，避免审计误判。

### 2.5 实施批次切分（后续 fullstack 票；本单不实施）

> **PM 批次边界改判（2026-11-09）**：原 B0 含「全仓机械替换 12 处类型路径 + 删除 `compat::ManagedScope`」，但 zct77 代理正在改 `crates/xray-transport-splithttp/{transport.rs,hub/session.rs}`，**同文件并发必冲突**。故原 B0 拆为 **B0' / B1 / B1'** 三批。

| 批 | 内容 | 依赖 | 可并行 |
|---|---|---|---|
| **B0'** | **框架件（本批不碰任何站点 crate）**：`xray-frame` 落 `scope::ComponentScope`（`close`→`close_gate`、`shutdown_timeout`→`drain`、增 `live_refs` 诊断面 + `#[doc(hidden)]`、件头写完整契约）+ 单测覆盖 **A2 / A3 / A4**。**与 `compat::ManagedScope` 临时并存**（过渡期，非终态别名）；不删旧类型、不替换任何站点类型路径 | 无 | — |
| **B1** | **逐站替换类型路径**（**7 组按 crate 并行** = transport 六族 + dispatcher 独立组；**splithttp 组排在 zct77 完成之后**）：每站把持有件类型换成 `ComponentScope`、调用点改 `close_gate()` / `drain()`、删伪断言 doc、补该站 stop 面归属 | B0' | ✅ **7 组并行**（splithttp 组串行在 zct77 之后） |
| **B1'** | **末批（终态收口）**：删除 `compat::ManagedScope` + `grep -rn "compat::ManagedScope" crates` 归零 ⇒ 合规「**不留兼容别名**」终态（**已完成**：B1' 收口 `8202b2ef`，`grep -rn ManagedScope crates` 归零） | B1 全部完成 | — |
| **B2** | 环破除 + 排空落位（依赖 B1 对应站）：tun（driver 子账本 + 父 drain 级联子）、naive（弱引用/快照）、splithttp（hub 账本 owner 上移 + 每连接任务捕获链改弱引用/快照）；并给 transport 族补「无 drain ⇒ 不得声称 abort」收口 | B1 各站 | ✅ 3 组并行 |
| **B3** | 可观测面 + 静态门 + 文档同步：站点断言集（**实测覆盖见 §验证方式（二）实测表——未达逐站**）；`tools/check_scope_claims.py` 静态门（禁「Drop 即 abort 在途」类伪断言文案、禁 `compat::ManagedScope` 残留）；文档同步（CLAUDE.md §3.5.6 spawn 三分类口径 + §3.5.2 白拿清单、插件模型文档 §2.4 坑约束表、**本目录 README「允许 `Proposed` 草案入目录」一行 + ADR-0004 索引行**——PM 拍板 P5） | B1 + B2 | ✅ |
| **B4**（可选） | transport listen API 注入 scope 句柄（让宿主可见 transport 账本 ⇒ 宿主可 drain）——**另票**，PM 拍板 P2 = 本轮不做 | PM P2 | — |

**过渡期并存说明（PM 批次边界改判）**：B0' 期间 `xray_frame::compat::ManagedScope` 与 `xray_frame::scope::ComponentScope` **并存**，用于避开与在飞代理（zct77）的同文件并发冲突。**并存属实施中间态，不是本 ADR 的终态设计**——终态由 **B1'** 收口：删旧类型 + `grep` 归零，符合「只扩展不 fork / 不留兼容别名」纪律。

### 2.6 断言与不变量（必须可观测）

| 编号 | 不变量 | 可观测锚 | 判定命令形态 |
|---|---|---|---|
| **A1** | 组件 stop 后账本在途归零（排空档站点） | `ComponentScope::in_flight() == 0` + `drain` 报告 `timed_out == 0` | 目标态要求 = 每站各有单测（**实测覆盖 = 12 站中 5 站，逐站见 §验证方式（二）**）：`cargo test -p <crate> --lib <站名>`（如 `cargo test -p xray-proxy-tun --lib tun_scope_drain_idle`） |
| **A2** | 关闸 ≠ 排空 | `close_gate()` 后 `spawn` 必 `Err(ScopeClosed)`；**且**在途任务未被 abort（同一测试内断言 `in_flight` 未归零 / 任务仍可 join） | `cargo test -p xray-frame --lib scope::tests::close_gate_rejects_new_spawns_but_keeps_in_flight` |
| **A3** | 排空是唯一「在途归零」保证 | `drain()` 返回 `ShutdownReport{ panicked, timed_out }`；`timed_out > 0` ⇒ error 级上报（沿用 `compat.rs:373-386` 现行口径） | `cargo test -p xray-frame --lib scope::tests::drain_reports_timeout_and_panics` |
| **A4** | 环已破（唯一可证伪锚） | owner 释放后该账本强引用计数归零：`ComponentScope::live_refs() == 1`（只剩 stop 面自身）⇒ 无环 | 目标态要求 = 每站各有单测（**实测覆盖 = 12 站中 3 站（#1+#2 同账本计一站），逐站见 §验证方式（二）**）：`cargo test -p <crate> --lib <站名>_scope_has_no_self_reference`（须先有 A4 的 `live_refs` 诊断面） |
| **A5** | 伪断言禁令 | 全仓无「Drop 即 abort 在途 / 句柄丢弃即 abort」类文案 | CI 静态门：`python tools/check_scope_claims.py`（退出码非零 = 红） |
| **A6** | 单账本 | 一个组件恰一本账（多克隆句柄允许，owner 恰一） | 评审 + `live_refs` 断言配合；静态门 `tools/check_scope_claims.py` 兼查「同一组件多本账」 |

**质量需求（QAS 六元组）**

- **S1 停机收敛**（触发：RemoveInbound / `Instance::close`；环境：生产形态入站在途 N 条连接；响应：排空档 ⇒ 组件 stop 后账本 `in_flight` 归零且连接被中止，关闸档 ⇒ 已建立连接按 Go 语义继续至 EOF 而新连接被拒；度量：`in_flight` 计数 + `ShutdownReport.timed_out` + 连接终局时刻；监控：组件 stop 报告，`timed_out > 0` 记 error）。
- **S2 关闸语义**（触发：listener `close()`；环境：账本有在途任务；响应：新 `spawn` 被拒（`Err(ScopeClosed)`）+ 在途不受影响；度量：spawn 返回值 + `in_flight` 不变；监控：拒发 fail-visible 日志）。

### 2.7 遗留风险与反模式

**B2 实施后的语义变化（2026-11-09，必读）**：三站环破除（tun 弱引用 / naive 弱引用 / splithttp owner 上移 + 弱引用）使 `JoinSet` drop 触发的在途中止**从「不可达」变回「可达」**。实态：
- `close()` / `close_gate()` 语义**未变**（transport 族关闸档：拒新 spawn、不杀在途）；
- 但 owner 掉出（listener/slot 释放，≈ 实例拆除）时，在途连接任务现在会被 abort；破环前它们是**泄漏、永不中止**。
- ⇒ 与 Go 的差异：Go 的 `listener.Close()` 不杀已建立连接，且这些连接归 handler/worker 存活；我们现为「实例拆除即中止」。此差异属**线行为**，须由对拍票裁决是否恢复 Go 口径（与 §3.1 P1「全排空档需独立对拍票」同款纪律）；在此之前以本节为唯一权威描述，禁按「Drop 永不 abort」写任何断言或注释。
- 钉死面：各站 A2 断言（`close_gate` 后 spawn 必 `Err` 且在途未 abort）钉住 stop 面；若将来把某站改成排空档，该站 A2 测试**应当变红**（预期信号，非回归）。

**反模式（评审打回项，写入 CLAUDE.md §3.5.2 白拿清单）**

1. **伪 Drop 断言**：doc / 注释写「Drop / 句柄丢弃即 abort 在途」——与实现不符（环 / 时点不确定 / 多持有者）⇒ 打回。
2. **close 一名两义**：一个 `close()` 同时被当「关闸」与「排空」⇒ 打回（必须 `close_gate` vs `drain`）。
3. **自引用环**：被托管任务持有所在账本 owner 的强引用 ⇒ 打回（销毁「Drop 兜底」路径 + 泄漏账本）。
4. **双份账本**：同一组件两本 scope（listener 一本 + hub 一本）⇒ 打回（账本 owner 恰一，克隆句柄允许）。
5. **新 crate 自造 scope 持有件**：绕过 `xray_frame::scope::ComponentScope` ⇒ 打回（沿用 §3.5.2「白拿清单」纪律）。

**遗留风险**

- **R1 transport 族账本对宿主不可见（PM 拍板 P2 已定）**：transport crate 无 ctx 注入面 ⇒ 宿主（arm scope）**触达不到** transport 账本 ⇒ transport 账本无 drain 面。**PM 裁决**：本轮**不扩** `TransportListenFn` 注入；「无 drain ⇒ 不得声称 abort」写进契约正文（§2.2 Q3 + §2.4 各 transport 行）；「扩 listen API 注入句柄」另票（B4）。
- **R2 arm 族与 transport 族档位不同（PM 拍板 P1 已定）**：协议/arm/dispatcher/tun 族停机 abort 在途（Rust 口径，bd a9xgp），transport 族不 abort（Go 26.10.17 口径）⇒ 同一进程内两种停机观感。**PM 裁决 = 分档保留**：全排空档属**线行为变更**，须独立对拍票，不夹带在契约归一里。**保留分层是刻意选择**，但须在文档显式写明（§2.2 Q1 档位表 + B3 插件模型文档），避免下一轮审计又判成「不一致缺陷」。
- **R3 子账本无自动级联**：udf `FxScope` 无父子语义 ⇒ tun 的父子级联要手工接线，漏接线 = 停机残留 ⇒ 必须配 A1 断言。
- **R4 `live_refs` 诊断面是新增公开 API（PM 拍板 P6 已定）**：为证伪「环已破」所必需。**PM 裁决**：新增 `live_refs()`，标 `#[doc(hidden)]` **或**标注「诊断用」；成本 = 一点公开面 + 未来若 udf 提供等价能力则随上游收敛删除。
- **R5 契约靠文档 + 静态门，非类型系统强制**：`close_gate` / `drain` 的分档靠方法名 + 评审 + CI 门；类型系统层面无法阻止「在 `close_gate` 里顺手 abort」。缓解 = A2 断言 + 静态门。
- **R6 ADR 目录体例冲突（PM 拍板 P5 已解）**：本目录 README 原载「状态字段取值 Accepted / Superseded；**草案不进本目录**」，与本票要求草案落 `docs/architecture/adr/` 冲突。**PM 裁决**：允许 `Proposed` 状态草案进本目录（README 加一行「允许 `Proposed` 草案入目录」+ 索引补录行），本 ADR 拍板后转 `Accepted`；**README 与索引的改动并入 B3 文档批**（不在 B0' 范围内）。

### 2.8 与 bd hnicl 的关系

- **hnicl = 症状票**（点两处）：splithttp / tun 的「注释与实现不符 + 自引用环」，并给出两个二选一修法（环打破 / 明确 abandon）。
- **os4kz = 结构性根因票**（点全仓）：12 处各造一份持有件 + 三派语义 + 归属未裁 ⇒ 归一化与裁决归本 ADR。
- **收口路径**：本 ADR 拍板后，hnicl 的两条修法**不再二选一**——按本契约二者都做但分层：
  - 环打破 ⇒ 本 ADR §2.4 #2 / #7 / #9 的「破环」列（子账本 / 弱引用 / 快照）；
  - 「明确 abandon」⇒ 本 ADR §2.2 Q3 的**伪 Drop 断言禁令**（A5 静态门把「Drop 兜底」文案清零）。
- **建议**：hnicl 改为 **os4kz 实施批次的验收项**（B2 完成 + A4/A5 断言落地即销号），不单独立票修；os4kz 在 B3 完成后销号。
- **PM 裁决（2026-11-09）采纳该建议**：**hnicl 归口为本 ADR 实施批次的验收项，不再单独立票修**。销号判据固定为两条同时成立：① **B2 完成**（splithttp / tun / naive 三处环破除落地）；② **A4（`live_refs` 环破除断言）+ A5（伪 Drop 断言静态门）落地**。两条齐备 ⇒ hnicl 销号；os4kz 在 B3 完成后销号。

### 2.9 已知缺口（2026-11-10 审计实测登记 · **不改变本 ADR 任何裁决**）

> 本节只登记实测事实与欠账，不是新裁决，也不改 §2.1–§2.8 / §3 的任何条款与 Accepted 状态；缺口由另票修复（bd bbvuo 追踪）。

**G1｜站点断言未逐站落地**：§2.6 的 A1/A2/A4 三不变量在 B1/B2 交付后**并未逐站有断言**。实测（2026-11-10 重数，命令与逐站清单见 §验证方式（二））：12 站共 13 条站点级断言，A1 覆盖 5 站、A2 覆盖 6 站、A4 覆盖 3 站；`#11 dispatcher DialBridge.scope` 三项全无，`#2 splithttp SessionMap.scope` 无独立断言（与 #1 同一本账）。**读本节与 §验证方式（二）时禁把「有断言」推广成「全覆盖」。**

**G2｜A2 断言是机制级近重复，缺「生产 accept 路径真入账」断言**：现存 4 个 A2 族（splithttp `transport.rs:1403`、hysteria `register.rs:587` + `quinn_adapter.rs:2848`、websocket `register.rs:1672`、httpupgrade `register.rs:1472`）与框架断言 `xray-frame/src/scope.rs:721` **同构**：都自建一个 `ComponentScope`（或直接构造 listener 结构体）→ spawn 一个 sleep/pending 任务 → `close_gate()` → 断言新 `spawn` 回 `Err` 且在途未 abort。它们证明的是 udf `FxScope` 机制，**没有一条**驱动生产的 accept 环把真实连接任务放进该站账本（即生产路径上 `in_flight` 真的 0→1）。⇒ 「关闸语义确实作用在该组件的真实任务上」仍无断言，需补 accept 路径入账断言（另票，不在本 ADR 范围）。

**G3｜「①类待迁移」欠账与 ②类豁免在门面不可区分**：全仓 **25 处** `#[allow(clippy::disallowed_methods)]` 的 reason 以「①类待迁移（bd xosi9 改判）」自称①类欠账，但 `tools/check_quality_gates.py` 门 (h) 与 ② 类豁免**计法完全相同**（只核「调用集合 ⊆ 登记集合」），门绿 ⇒ 只证明登记齐备，**不证明①类已收口**。25 处分布（crate: 处数）= `xray-transport-splithttp` 6 / `xray-transport-httpupgrade` 4 / `xray-transport-hysteria` 6 / `xray-mux` 2 / `xray-transport-websocket` 2 / `xray-transport-kcp` 1 / `xray-transport-naive` 1 / `xray-transport-quic` 1 / `xray-transport`（finalmask `xicmp.rs` 1 + `xmc/conn.rs` 1）2；完整 `file:line` 清单见 `reports/2026-11-10-fixes/bbvuo.md`。**处置口径 = 转显式待迁票**（PM 建票、按站迁移）；本 ADR 不改这些站点的文案、不动其代码。

## 3. PM 拍板裁决记录（2026-11-09）

> 本节记录 PM 对六项待决问题的裁决与其理由。**裁决即已落定**，实施按此执行；原「待拍板」措辞全部作废。

### 3.1 P1｜组件 close 的档位归属 = **选项①（分档）**

- **裁决**：**transport 族**（splithttp / hysteria / websocket / httpupgrade / naive）= **关闸档**（Go 26.10.17 口径，**不杀已建立连接**）；**arm / dispatcher / tun 族** = **排空档**（Rust 现行口径，abort 在途）。**全排空档属线行为变更，须独立对拍票，不夹带在契约归一里。**
- **理由**：Go 26.10.17 的 `listener.Close()` 一律不杀已建立连接（§背景 对拍基线 5 处实读）；arm 族现行 abort 口径是 bd a9xgp 已定结论。两边都保留 ⇒ 同一进程两种停机观感是**刻意分层**（R2），不是缺陷，须在 B3 文档批写明。
- **落点**：§2.2 Q1 档位表（新增）、§2.4 各 transport 行「目标语义」列。

### 3.2 P2｜transport 账本对宿主可见性 = **选项①（本轮不扩注入）**

- **裁决**：**本轮不扩 `TransportListenFn` 注入**；transport 账本对宿主不可见这一事实**写进契约**（「无 drain ⇒ 不得声称 abort」）；扩注入**另票 B4**。
- **理由**：transport crate 无 ctx 注入面（各 crate `clippy.toml` 明载「ctx 不可达」），扩注入要动 `crates/xray-transport/src/listener_registry.rs` trait 与 8 个 transport 实现 ⇒ 本轮不做；契约先把「不可见 ⇒ 不得声称 abort」钉死。
- **落点**：§2.2 Q3、§2.4 各 transport 行「目标语义」列、§2.7 R1。

### 3.3 P3｜持有件类型落点与命名 = **选项①**

- **裁决**：`xray_frame::scope::ComponentScope`（迁位自 `compat::ManagedScope`，`close` → `close_gate`、`shutdown_timeout` → `drain`、增 `live_refs` 诊断面）；`compat` **保留纯进程级能力面**（`CompatCaps` / `install` / `spawn` / `spawn_scope` / `reap_into` / `REAP_EVERY`）；**终态不留兼容别名**。
- **理由**：契约落 `scope.rs` 与 arm/conn 同域；`compat` 专注进程级兜底（其章程即如此）；单类型干净切换符合「只扩展不 fork / 不留兼容别名」纪律。
- **落点**：§2.3 候选 A（已标「PM 已拍板采纳」）、§2.5 B0'/B1/B1'。

### 3.4 P4｜环破除允许的形态 = **选项①（两种）**

- **裁决**：允许 **弱引用/快照** 与 **子账本** 两种形态；**子账本必须由父 drain 显式级联**（udf `FxScope` 无父子语义 ⇒ 手工接线）+ **A1 断言兜底**。
- **理由**：契约面留两条路（禁第三种「同账本自持 owner」）；tun driver 需向同一账本 spawn 派生任务（`inbound.rs:879/957/1040/1221/1235`），只准弱引用/快照则无处安放派生任务。
- **落点**：§2.2 Q4（两种形态 + 禁止形态）、§2.5 B2、§2.7 R3。

### 3.5 P5｜ADR 目录体例冲突 = **允许 `Proposed` 草案进本目录**

- **裁决**：允许 `Proposed` 状态草案进 `docs/architecture/adr/`（README 加一行说明 + 索引补录行），本 ADR 拍板后转 `Accepted`；**README 与索引的改动并入 B3 文档批**。
- **理由**：本目录 README 原载「状态字段取值 Accepted / Superseded；草案不进本目录」，与「草案落本目录以便评审」的流程冲突；PM 择「允许 + 事后补规」而非「草案另置」。
- **落点**：§2.7 R6（已改为「已解」）、§2.5 B3 文档同步项。

### 3.6 P6｜`live_refs` 诊断面 = **选项①（新增）**

- **裁决**：新增 `live_refs()` 诊断面，标 `#[doc(hidden)]` **或**标注「诊断用」；它是 **A4「环已破」的唯一可证伪锚**。
- **理由**：udf `FxScope` 无等价面（`Arc::strong_count` 不可从外部观测）；只有「stop 后 `in_flight == 0`」**证伪力不足**（环存在时 `drain` 仍能归零 ⇒ 断言假绿）。
- **落点**：§2.3 API 草案（`live_refs` + `#[doc(hidden)]`）、§2.6 A4、§2.7 R4。

### 3.7 PM 批次边界改判（并行施工冲突）

- **原 B0**（含「全仓机械替换 12 处类型路径 + 删除 `compat::ManagedScope`」）**拆为 B0' / B1 / B1'**：zct77 代理正在改 `crates/xray-transport-splithttp/{transport.rs,hub/session.rs}`，同文件并发必冲突 ⇒ B0' 只落框架件（**不碰任何站点 crate**）、B1 逐站替换（**splithttp 组排在 zct77 完成之后**）、B1' 末批删旧类型收口终态。
- **过渡期并存**（B0' 期间 `compat::ManagedScope` 与 `scope::ComponentScope` 共存）**属实施中间态，不是终态别名**——终态由 B1' 收口（删旧类型 + `grep` 归零）。
- **落点**：§2.5 批次表 + 过渡期并存说明。

### 3.8 PM 裁决：B1 的 dispatcher 组 = **独立第 7 组**（2026-11-09）

- **裁决**：`xray-app-dispatcher` 的 3 处持有件（`default.rs:933` / `default.rs:1725` / `udp_session.rs:104`）**独立成组**（B1 第 7 组），与 transport 六族**并行**。**B1 = 7 组并行**（transport 六族 + dispatcher 一组）。
- **理由**：①与 transport 六族**无共享文件、无语义耦合**；②dispatcher 属**排空档**（arm 族口径，P1 裁决），与 transport 族**关闸档不同档**——混进任一族会把两档语义搅浑，独立成组最干净。
- **落点**：§2.5 B1 行（7 组并行）、§3.8（本节）。

## 后果

**正面**

- 停机收敛有**一条判据**：组件 stop 后账本 `in_flight == 0`（排空档）或「已建立连接继续至 EOF」（关闸档）——审计可用统一口径核，不再逐站读 doc 猜语义。
- 12 处持有件语义归一（`close_gate` vs `drain` 不可混用），Go 对拍分档写进契约（transport 族关闸 / arm 族排空）。
- 派 C 的环有结构性修法（子账本 / 弱引用 / 快照）且**可证伪**（A4 `live_refs` 断言）。
- 新 crate 自造持有件有评审 + CI 门双闸（§2.7 反模式 5）。

**负面**

- B1 是**破坏性重命名**（`compat::ManagedScope` → `scope::ComponentScope`，`close` → `close_gate`，`shutdown_timeout` → `drain`），触 8 crate 12 站 + `xray-frame` 自身 + `CLAUDE.md` §3.5.6 白拿清单 + 各 crate `clippy.toml` 注释 ⇒ 单次机械 diff 需完整走 CI（含 32/32 协议对拍与 interop）。**按 PM 批次改判，此重命名拆到 B1（7 组并行 = transport 六族 + dispatcher 独立组，splithttp 组排在 zct77 之后）+ B1'（删旧类型收口）**，B0' 只落框架件。
- **过渡期并存**（B0' 期间两类型共存）带来**一次性重复门面**：同一机制有两个公开名，站点在 B1 完成前可能混用 ⇒ 风险靠「B0' 件头写明 `ComponentScope` 为终态名 + B1' 强制归零」控制，且 B0'/B1 期间**不新增**任何站点使用 `ManagedScope` 的新点。
- 语义显式化后，**「关闸档」站点的在途连接继续到 EOF 成为被文档承认的行为**（不再被伪断言掩盖）——这正是现状实况，但**显式化后可能被误读成新缺陷** ⇒ 须在插件模型文档写清「Go 对拍档」。
- 新增 `live_refs` 公开诊断面（A4 所需，标 `#[doc(hidden)]`）。
- 契约无法由类型系统强制（R5），需靠 CI 门与评审长期维持。

**维护义务**

- `ComponentScope` 的契约文档（件头）是**唯一权威**；任何站点 doc 与之冲突 ⇒ 以件头为准，站点 doc 只写「本组件属于哪一档 + 特殊事实」。
- 新增 transport / handler 类组件 ⇒ 必须从 `xray_frame::scope::ComponentScope` 起手，并在 PR 描述里回答 §2.2 六问。

**迁移路径**（不在本单实施）

B0'（框架件）→ B1（**7 组并行** = transport 六族 + dispatcher 独立组，splithttp 组排在 zct77 之后）→ B1'（删旧类型收口终态）→ B2（3 组并行破环）→ B3（断言 + 静态门 + 文档）→（可选）B4。

## 备选否决

- **上浮 udf（把持有者契约写进 `skeleton_infra::fx`）**：机制已有（`FxScope` 的 close/shutdown/drop 语义完备），契约含 xray 语义（组件生命周期 / Go 分档 / arm 编排），且提炼回路需独立 PR + 三平台 CI 绿 + 主仓换依赖复测 32/32 ⇒ 收益不成比例（§2.1 判据 1、§2.3 候选 D）。
- **只写文档不动 API（现状 + 12 处 doc 修正）**：不解决「close 一名两义」（三派分裂的根因是**同一个 `close()` 被当两种语义用**），也不解决环 ⇒ 审计仍无一条判据可核 ⇒ 否决。
- **`trait ScopeHolder` 统一 12 处**：持有件形态异质（字段 / `Arc<字段>` / `ParkMutex<Option<字段>>`），trait 只增间接层、不改行为 ⇒ YAGNI 否决。
- **把「Drop 兜底 abort」文档改成事实表述即收口**：派 C 的环下 Drop-abort **恒不可达**（不是措辞问题）⇒ 事实表述也救不了两处 ⇒ 必须破环（§2.2 Q4）。
- **组件 close 一律 drain（票面建议 2 的直译）**：transport 族与 Go 26.10.17 的 `listener.Close()` 语义冲突（Go 不杀已建立连接）⇒ 改线行为属**独立对拍变更**，不得夹带在契约归一里 ⇒ 本 ADR 采纳**分档**（§2.2 Q1/Q2），**PM 拍板 P1 = 分档**（§3.1）。
- **保留 `compat::ManagedScope` 与新件并存（双 API）作为终态**：违反「只扩展不 fork」与「不留兼容别名」纪律 ⇒ 否决。**过渡期并存仅为实施中间态**（PM 批次边界改判，§3.7），终态由 **B1'** 收口：删旧类型 + `grep` 归零。

## 验证方式

**（一）契约自测（框架侧，B0' 交付）**

- `cargo test -p xray-frame --lib scope` —— 覆盖 A2（关闸拒发 + 放行在途）、A3（排空三段 + 报告）、A4 诊断面（`live_refs`）。
- `cargo test -p xray-frame --lib compat` —— `compat` 进程级能力入口（`CompatCaps` / `install` / `spawn` / 收割节流）行为不变（B0' 新增 `ComponentScope` 不得回归既有面；`ManagedScope` 在 B0' 期间**保持原样不动**）。
- `cargo test --workspace --all-targets` —— 全仓编译与测试（迁移面 8 crate 12 站）。
- `cargo clippy --workspace --all-targets -- -D warnings` —— 各 crate `clippy.toml` 的 `disallowed-methods` 理由文本须同步改写（引用旧名会误导）。

**（二）站点断言（B1/B2 交付）——实测覆盖表（2026-11-10 按代码重数）**

> 本节原列 5 条命令并声称覆盖 12 站中的每一站，与代码实测不符（当时只覆盖 4 个 crate，且 `dispatcher_scope_drain_idle` 这条测试**不存在**，实测名见下表）。现改为**实测数字 + 逐站清单**：读者据此可知**哪站有断言、哪站没有**，不把下表读成「已全覆盖」。
>
> 复现命令：`grep -rn "scope_drain_idle\|scope_has_no_self_reference" crates --include=*.rs`（5 命中）+ A2 命名族 `*a2_gate_closes_but_keeps_in_flight` / `*close_gate_rejects_new_spawns_but_keeps_in_flight` + A1 命名族 `*_a1_*`；合计**站点级断言 13 条，覆盖 §2.4 的 12 站中 11 站**（#2 与 #1 同一本账，#11 零断言）。

| #（§2.4） | 站 | A1（stop 后 in_flight 归零） | A2（关闸 ≠ 排空） | A4（无自引用环） |
|---|---|---|---|---|
| 1 | splithttp `SplithttpListener.scope` | — | ✅ `splithttp_close_gate_rejects_new_spawns_but_keeps_in_flight`（`transport.rs:1403`） | ✅ `splithttp_scope_has_no_self_reference`（`transport.rs:1377`） |
| 2 | splithttp `SessionMap.scope` | — | — | △ 与 #1 同一本账（B2 后 owner 在 hub，`SessionMap` 只持 `ScopeRef` 弱引用，`hub/session.rs:119`）⇒ 由 #1 的 A4 覆盖 |
| 3 | hysteria `HysteriaTransportListener.scope` | — | ✅ `hysteria_listener_scope_a2_gate_closes_but_keeps_in_flight`（`register.rs:587`） | — |
| 4 | hysteria `QuinnQuicListener.scope` | — | ✅ `quinn_listener_scope_a2_gate_closes_but_keeps_in_flight`（`quinn_adapter.rs:2848`） | — |
| 5 | websocket `WsTransportListener.scope` | — | ✅ `ws_listener_scope_a2_gate_closes_but_keeps_in_flight`（`register.rs:1672`） | — |
| 6 | httpupgrade `HttpUpgradeListener.scope` | — | ✅ `httpupgrade_listener_scope_a2_gate_closes_but_keeps_in_flight`（`register.rs:1472`） | — |
| 7 | tun `TunInboundHandler.scope` | ✅ `tun_scope_drain_idle`（`inbound.rs:1504`） | — | ✅ `tun_scope_has_no_self_reference`（`inbound.rs:1479`） |
| 8 | hysteria `UdpHopPacketConn.prune_scope` | ✅ `idle_pruner_is_hosted_by_connection_scope`（`udphop.rs:1161`：托管恰 2 项 + `close` 后归零） | — | — |
| 9 | naive `InboundSlot.scope` | ✅ `naive_scope_drain_idle`（`inbound.rs:496`） | — | ✅ `naive_scope_has_no_self_reference`（`inbound.rs:527`） |
| 10 | dispatcher `DefaultDispatcher.scope` | ✅ `dispatcher_scope_drains_and_rejects_after_shutdown`（`default.rs:2787`） | ✅ 同一条（`drain` 后 `spawn` 必 `Err`） | — |
| 11 | dispatcher `DialBridge.scope` | — | — | — |
| 12 | dispatcher `UdpDispatchSession.scope` | ✅ `udp_session_scope_a1_drain_zeroes_in_flight`（`udp_session.rs:1027`） | — | — |

- **框架机制面（非站点，B0' 交付，全部存在）**：`xray-frame/src/scope.rs` A2 `close_gate_rejects_new_spawns_but_keeps_in_flight`（`:721`）、A3 `drain_reports_timeout_and_panics`（`:753`）、A1 机制 `drain_aborts_and_zeroes_in_flight`（`:865`）、A4 机制 `scope_ref_does_not_keep_ledger_alive`（`:594`）/ `scope_ref_spawn_after_owner_dropped_returns_closed`（`:617`）。
- **按不变量数的实际覆盖**：A1 = **5 站**（#7/#8/#9/#10/#12）；A2 = **6 站**（#1/#3/#4/#5/#6/#10）；A4 = **3 站**（#1(+#2)/#7/#9）。
- **缺断言的站（逐名）**：`#11 dispatcher DialBridge.scope` —— A1/A2/A4 三项全无（该站无 close 面，现有 `DialBridge` 测试只钉数据面/管限/洪水，不涉 scope 不变量）；`#2 splithttp SessionMap.scope` —— 无独立断言，唯一相关锚是 #1 的 A4。
- **A1 缺**：`#1 #2 #3 #4 #5 #6 #11`；**A4 缺**：`#3 #4 #5 #6 #8 #10 #11 #12`。
- 逐条命令（替换上面原列表）：`cargo test -p xray-transport-splithttp --lib scope`、`cargo test -p xray-transport-hysteria --lib listener_scope`、`cargo test -p xray-transport-websocket --lib ws_listener_scope`、`cargo test -p xray-transport-httpupgrade --lib listener_scope`、`cargo test -p xray-proxy-tun --lib scope`、`cargo test -p xray-transport-naive --lib scope`、`cargo test -p xray-app-dispatcher --lib scope`。

**（三）静态门（B3 交付）**

- `python tools/check_scope_claims.py` —— 禁「Drop / 句柄丢弃即 abort 在途」类伪断言文案（A5）+ 禁 `compat::ManagedScope` 残留 + 兼查单账本（A6）。
- `grep -rn "compat::ManagedScope" crates --include=*.rs` ⇒ **B1' 完成后 0 命中**（类型路径唯一；B0'/B1 过渡期允许命中）。
- `grep -rniE "drop.{0,20}abort.{0,20}在途|句柄丢弃.{0,20}abort" crates --include=*.rs` ⇒ B3 完成后 **0 命中**。

**（四）反向自检锚（改了实现必红）**

- 把某站的 `drain` 改回「只 `close_gate`」⇒ 该站 A1 断言必红（`in_flight != 0`）。
- 把某站任务改回持 owner 强引用 ⇒ 该站 A4 断言必红（`live_refs > 1`）。
- 把 `close_gate` 实现成 abort ⇒ A2 断言必红（在途被提前 abort）。

**（五）文档一致性（评审 + CI，B3 文档批交付）**

- 本目录 README：**加一行「允许 `Proposed` 草案入目录」**（PM 拍板 P5）+ 索引补 ADR-0004 行（状态 Accepted）。
- `CLAUDE.md` §3.5.6 spawn 三分类口径补「组件自有 scope 持有件」一行 + §3.5.2 白拿清单补 `xray_frame::scope::ComponentScope`；插件模型文档 §2.4 坑约束表补「持有者契约六问」+ §2.2 Q1 档位表（关闸档 / 排空档分层）。
- 文档同步**清单**（本单只列不改）：见交付件《2026-11-09-os4kz-adr0004.md》§5。
