//! 两级 scope 模型（面 6 · 能力收敛方案 §2 面 6）：arm scope（inbound 级）
//! → connection scope（每连接）。
//!
//! 派生三段式（ADR-1）：
//! - **udf 基件**：`skeleton_infra::fx::FxScope`（spawn 唯一托管口：生命周期集 + accepting 闸 +
//!   in_flight 计数）、`skeleton_infra::fx::{CancelSource, CancelToken,
//!   cancel_pair}`（取消对）、`CancelToken::run_until_cancelled` （取消 = None 形状）。
//! - **派生方式**：**组合包装**（arm 级 = 新 `FxScope` + 外接关闭广播 [`ArmScope`]；子 scope = 新
//!   `FxScope` + 外接取消源；父关 → 级联取消子）。 **不动父仓**——udf 的 `cancel_pair` /
//!   `run_until_cancelled` 已是足够扩展点。
//! - **主仓消费**：`crates/xray-core/src/inbound.rs`（mux link ×4 / SS 泵 ×1 / 监控壳 ×2 / vision
//!   ×2 / tun ×1）。
//!
//! **为何两级能表达 mux link 的跨连接生命周期**：mux carrier 的任务寿命 =
//! "直到 carrier 连接关闭"，与触发它的那个 inbound 连接不同寿命，但与 **arm
//! scope**（inbound 级）同寿命。旧判定"迁 = scope 归属改挂非宿主连接，语义不等
//! 价"成立的原因是**只有一层 scope**（挂 arm scope 会让 carrier 随 inbound 一起
//! 死，或挂连接 scope 会随连接死）。两级模型下：carrier 任务归 **arm scope**，
//! 每连接任务归 **connection scope**（连接断 → 该连接任务结束，不影响 sibling
//! 连接）。
//!
//! **父闸信号的实现事实**（udf `FxScope` 语义边界）：`FxScope::close()` 只关
//! accepting 闸（拒新 spawn、放行在途），**不发取消信号、零通知**；且
//! `FxScope::with_source` 会消费外部 `CancelSource` → 外部无从触发其取消面。
//! 故父 → 子级联以 xray-frame 侧自建的关闭广播承担：arm 级 scope 一律经
//! [`ArmScope`] 持有（`close` = 关闸 + `watch` 广播同一同步段落账），子 scope
//! 经 [`ConnScope::child_of`] 订阅信号**事件驱动**级联取消——替代旧 20ms 闸位
//! 轮询（每连接 ≈50 次/秒空转唤醒，bd mzput），稳态零唤醒。
//!
//! **第三类 scope：组件自有账本**（[`ComponentScope`]，ADR-0004）——组件
//! （transport listener / inbound handler / dispatcher / tun …）自持一本任务账本时
//! 必须持本件：它承载**持有者契约**（谁 close / 关闸 vs 排空两词分档 / Drop 不作
//! abort 保证 / 环禁令 / 单账本 / Go 对拍分档），机制本体仍是 udf `FxScope`
//! （组合包装，禁复制）。组件账本与 arm→conn 的寿命链**并列**，不参与级联。

use std::{
    future::Future,
    sync::{Arc, LazyLock, atomic::AtomicUsize},
    time::Duration,
};

use skeleton_infra::fx::{
    CancelSource, CancelToken, FxScope, ScopeClosed, ShutdownReport, Spawned, cancel_pair,
};
use tokio::sync::watch;

use crate::logging::LogFacade;

/// scope 域日志门面（进程级单例）：spawn 拒发与任务 panic 的上报口，target
/// `xray_frame::scope`。克隆 = 空 Vec + 空 HashMap（零堆分配）。
fn scope_log() -> LogFacade {
    static LOG: LazyLock<LogFacade> = LazyLock::new(|| LogFacade::new("scope", Vec::new()));
    LOG.clone()
}

/// arm 级父 scope（关闭信号中枢）：内嵌 udf `FxScope`（托管语义零变化）+
/// `watch` 关闭广播。**父级关闭事件必须经 [`ArmScope::close`]**——裸
/// `FxScope::close()` 无通知，绕过本件的关闸不会级联到 conn scope。
pub struct ArmScope {
    /// 内嵌托管 scope（spawn/闸/排空语义 = udf 原样）。
    fx: Arc<FxScope>,
    /// 关闭广播（true = 已关）。`send_replace` 对零订阅者无害；每接收端独立
    /// 版本账 → 关闭前后订阅都读得到终值（无丢失唤醒）。
    closed: watch::Sender<bool>,
    /// 收割节流计数（O29）：arm scope 每连接 spawn 一次，逐次收割 = 每次 spawn
    /// 两次同一把 scope 锁；每 [`crate::compat::REAP_EVERY`] 次摊一次。
    tick: AtomicUsize,
}

impl ArmScope {
    /// 新建 arm scope（内部自建 udf `FxScope`；返回 `Arc` 便于跨任务共享）。
    pub fn new() -> Arc<Self> {
        let (closed, _) = watch::channel(false);
        Arc::new(Self { fx: Arc::new(FxScope::new()), closed, tick: AtomicUsize::new(0) })
    }

    /// 内嵌托管 scope（token / in_flight / `expect_idle` 等观察与 builder 面）。
    pub fn fx(&self) -> &Arc<FxScope> {
        &self.fx
    }

    /// 托管任务（udf `FxScope::spawn_tracked` + 收割：先清已完成条目再入集，
    /// bd 86i4h 阶段1——条目数跟随在途数而非累计 spawn 数；收割按
    /// [`crate::compat::REAP_EVERY`] 摊薄，O29）。
    ///
    /// `#[inline(always)]`：薄透传不落真实栈帧——debug 构建不内联，本仓 xray-core
    /// inbound 深轮询链的测试线程栈余量已薄（mzput 实证：一层透传帧即可击穿
    /// 2MB 默认档），透传面必须栈中性；`always` 钉死决策防未来重编译翻转。
    #[inline(always)]
    pub fn spawn<T>(
        &self,
        fut: impl Future<Output = T> + Send + 'static,
    ) -> Result<Spawned<T>, ScopeClosed>
    where
        T: Send + 'static,
    {
        crate::compat::spawn_reaping_ticked(
            &self.fx,
            &scope_log(),
            "arm scope",
            Some(&self.tick),
            fut,
        )
    }

    /// accepting 闸读侧（true = 已关）。
    pub fn is_closed(&self) -> bool {
        self.fx.is_closed()
    }

    /// 停机排空（超时档；udf `FxScope::shutdown_timeout` 透传，内部自行关闸）。
    ///
    /// bd a9xgp：入口先广播关闭信号（同 [`Self::close`] 的父闸账）——排空形态的
    /// 停机与 close 形态**同必级联**到 conn scope（子 scope 监视任务 observe 广播
    /// → 取消），调用方不再需要「先 close 再 shutdown_timeout」的两步纪律。
    /// 幂等：重复广播仅多一次无害唤醒。
    ///
    /// 返回 udf `ShutdownReport`（udf `51c2428b`/issue#13 起：排空中收割到的任务
    /// panic 载荷与未完成数不再丢弃，由调用方决定上报形态）。
    pub async fn shutdown_timeout(&self, d: Duration) -> ShutdownReport {
        self.closed.send_replace(true);
        self.fx.shutdown_timeout(d).await
    }

    /// 关闭：关 accepting 闸 + 广播关闭信号（同一同步段落账，子 scope 观察
    /// 到广播时闸必已关）。幂等：闸 CAS 幂等；watch 重复写同值仅多一次无害
    /// 唤醒，接收端读终值即知已关。广播不触碰本 scope 自身取消令牌（udf
    /// close 契约「close 只关闸不取消」保持）。
    pub fn close(&self) {
        self.fx.close();
        self.closed.send_replace(true);
    }
}

/// 连接级子 scope（生命周期 = 父 scope 存活期 ∧ 自身显式关闭）。
pub struct ConnScope {
    /// 本 scope 的托管任务（udf `FxScope`）。
    fx: Arc<FxScope>,
    /// 本 scope 的取消源（`close` / 父关 → cancel；共享给监视任务）。
    source: Arc<CancelSource>,
    /// 本 scope 的观察令牌（任务内携带判停）。
    token: CancelToken,
}

impl ConnScope {
    /// 独立连接 scope（无父；`close` 即终点）。
    pub fn new() -> Self {
        let (source, token) = cancel_pair();
        Self { fx: Arc::new(FxScope::new()), source: Arc::new(source), token }
    }

    /// 从父 scope 派生（父 [`ArmScope::close`] → 本 scope 级联取消 → 本 scope
    /// 任务结束）。
    pub fn child_of(parent: &Arc<ArmScope>) -> Self {
        let scope = Self::new();
        // 订阅先行（无丢失唤醒的关键序）：watch 每接收端独立版本账——订阅即得
        // 当前值；此后的 send 必使本接收端版本落后，`changed()` 立即就绪。
        let mut closed = parent.closed.subscribe();
        // 父已关（注册前关闭窗口）：同步取消 + 关闸，不 spawn 监视任务——
        // 观察零延迟、与父关闭时刻的先后无关。
        if *closed.borrow_and_update() {
            scope.source.cancel();
            scope.fx.close();
            return scope;
        }
        // 生命周期锚：监视任务持父 Arc（旧闸位轮询持 `Arc<FxScope>` 同款）→
        // 子任务存活期间父 scope 不 drop，父内嵌 `FxScope` 寿命语义不变。
        let parent = Arc::clone(parent);
        let source = Arc::clone(&scope.source);
        let token = scope.token.clone();
        // 父关闭监视任务：挂起在 `changed()`（事件驱动，无定时器、无轮询）→
        // 父关 → 级联取消本 scope。任务归本 scope 托管 → 本 scope 先关时监视
        // 任务自身了结（不泄漏 in_flight 计数）。
        scope
            .fx
            .spawn_tracked(async move {
                let _parent = parent;
                tokio::select! {
                    // biased：取消优先裁决（本 scope 先关 → 监视任务立即了结）。
                    biased;
                    _ = token.cancelled() => return,
                    _ = wait_closed(&mut closed) => {}
                }
                source.cancel();
            })
            .expect("新建 scope 的 accepting 闸必开（构造期不可能已关）");
        scope
    }

    /// 托管任务（等价 `ctx.spawn`，但归属本连接 scope；含增量收割，bd 86i4h）。
    ///
    /// 返回的句柄 join 后得 `Option<T>`：`None` = 任务被 scope 取消（父关 /
    /// 本 scope 关闭）而非正常完成——取消语义必须与"完成"可区分（禁静默把
    /// 取消当成功）。
    pub fn spawn<T>(
        &self,
        fut: impl Future<Output = T> + Send + 'static,
    ) -> Result<Spawned<Option<T>>, ScopeClosed>
    where
        T: Send + 'static,
    {
        let token = self.token.clone();
        crate::compat::spawn_reaping(&self.fx, &scope_log(), "conn scope", async move {
            token.run_until_cancelled(fut).await
        })
    }

    /// 取消令牌观察面（任务内携带判停）。
    pub fn token(&self) -> CancelToken {
        self.token.clone()
    }

    /// 显式关闭本 scope（连接结束）：取消 + 关闸（拒新 spawn）。
    pub fn close(&self) {
        self.source.cancel();
        self.fx.close();
    }

    /// 停机（取消 + abort 在途任务 + 等净）。
    pub async fn shutdown(&self) {
        self.source.cancel();
        // udf `shutdown` 带 `#[must_use]`（报告含 panic 清单）：本件只做关闭，
        // 报告面归 `shutdown_timeout` 路径（带域日志）；此处显式让渡。
        let _ = self.fx.shutdown().await;
    }

    /// 在途任务数（泄漏断言锚）。
    pub fn in_flight(&self) -> usize {
        self.fx.in_flight()
    }

    /// accepting 闸读侧（true = 可 spawn）。
    pub fn is_closed(&self) -> bool {
        self.fx.is_closed()
    }
}

impl Default for ConnScope {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ConnScope {
    /// 析构 = 关闭（取消 + 关闸）：scope 主人走了 → 其任务不得继续跑
    /// （否则 in_flight 永归零不了 = 泄漏）。
    fn drop(&mut self) {
        self.source.cancel();
        self.fx.close();
    }
}

/// 父关闭等待（watch 终值读法，无丢失唤醒论证）：
/// `borrow_and_update` 把「已读版本」推进到当前值；此后首次 `send` 使接收端
/// 版本落后 → `changed()` 就绪（翻转发生在 borrow 与 changed 的首次 poll 之间
/// 也一样——watch 以版本号判定，不依赖等待起点）。循环处理「读时 false、
/// changed 醒来仍是 false」的重复写伪唤醒，直至读到 true。
/// 发送端全亡（父中枢先于本任务 drop）按已关兜底取消（fail-closed）。
async fn wait_closed(closed: &mut watch::Receiver<bool>) {
    loop {
        if *closed.borrow_and_update() {
            return;
        }
        if closed.changed().await.is_err() {
            return;
        }
    }
}

/// arm scope 登记表（宿主停机编排面，bd a9xgp）：装配期按装配序登记每个 arm
/// 的 [`ArmScope`] 句柄，宿主 `close` 在 token cancel 后经
/// [`ArmScopeRegistry::close_all_reverse`] **逆序显式 close**——广播父闸 →
/// `ConnScope` 级联取消在途连接。裸 token cancel（不经宿主 close）形态由各 arm
/// 的停机监视任务兜底（消费方自建），本表只承载宿主编排面。
///
/// **同 tag upsert**（bd il9lh MW-5）：本表是**每宿主实例一份**，tag 是入站身份
/// （宿主 slot 表按 tag 唯一，重复 tag 直接 `AlreadyExists`）——同名多条 = 重复
/// 而非「多实例」。gRPC `AddInbound` 每次「`RemoveInbound` + 同 tag `AddInbound`」
/// 会在表里留下 1 条永久条目（本表只增不减 → 每重启一次 +1，条目永不回收）。
/// 故登记按 tag upsert：旧条目摘除、新的挂到登记序末尾（`close_all_reverse` 仍是
/// 「后登记先关」= 后起的 arm 先停）。
///
/// 登记泄漏口径：条目仅在 `close_all_reverse` 出清；宿主未 close 即退出 = 随表
/// drop（arm scope 及其任务随之结束，语义等同既有 Arc 归零 Drop 兜底）。
pub struct ArmScopeRegistry {
    /// 登记序 = 装配序；(tag, scope)。close 幂等，重复关闭均无害。
    entries: std::sync::Mutex<Vec<(String, Arc<ArmScope>)>>,
}

impl ArmScopeRegistry {
    /// 空表（宿主实例构造期建一份，`Arc` 注入装配链）。
    pub fn new() -> Self {
        Self { entries: std::sync::Mutex::new(Vec::new()) }
    }

    /// 登记一个 arm scope（**同 tag upsert**：旧条目替换、新的挂登记序末尾）。
    ///
    /// 语义澄清见类型文档：同名 = 重复登记（gRPC 重启同 tag 入站），不是多实例。
    /// 旧条目被替换时**显式 close**（幂等）：移除路径（`RemoveInbound` → per-inbound
    /// token cancel → 停机监视 `shutdown_timeout`）已关过一次时本调用无害；未关
    /// 时则避免它成为宿主 close 编排表外的孤儿 arm（表外 = 宿主停机不再关它）。
    /// 同一 scope 重复登记 = 幂等，**不关闸**（否则刚登记的 arm 当场被关）。
    ///
    /// 并发：全段在同一把毒锁容忍的互斥锁内完成（无 await、无锁序交叉）——
    /// gRPC 并发 `AddInbound`/`RemoveInbound` 不引入竞态或死锁。
    pub fn register(&self, tag: impl Into<String>, scope: Arc<ArmScope>) {
        let tag = tag.into();
        // 毒锁容忍（装配/停机期不得因别处 panic 拒绝登记或拒关停）：
        // 同 arm_builders intern 表先例，poison = 数据仍自洽（纯 Vec）直接取用。
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pos) = guard.iter().position(|(t, _)| *t == tag) {
            let (_, old) = guard.remove(pos);
            if !Arc::ptr_eq(&old, &scope) {
                old.close();
                tracing::debug!(tag = %tag, "arm scope replaced (same tag re-registered)");
            }
        }
        guard.push((tag, scope));
    }

    /// 逆序（后装配先关）显式 close 全部并清空登记，返回关闭条数（日志锚）。
    /// close 幂等：已被停机监视任务先关的 arm 在此重复 close 无害。
    pub fn close_all_reverse(&self) -> usize {
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let taken = std::mem::take(&mut *guard);
        drop(guard);
        let count = taken.len();
        for (tag, scope) in taken.into_iter().rev() {
            scope.close();
            tracing::debug!(tag = %tag, "arm scope closed (reverse registration order)");
        }
        count
    }

    /// 当前登记数（诊断面；`close_all_reverse` 后为 0）。
    pub fn registered(&self) -> usize {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl Default for ArmScopeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ArmScopeRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArmScopeRegistry").field("registered", &self.registered()).finish()
    }
}

/// 组件自有 scope 持有件（ADR-0004 §2.3 候选 A · PM 已拍板采纳 P3）：组件内
/// 账本的**持有者契约**唯一落点——组件（transport listener / inbound handler /
/// dispatcher / tun …）自持一本任务账本时必须持本件，禁自造（§2.7 反模式 5）。
///
/// **本件头是持有者契约的唯一权威**（ADR-0004 维护义务）：站点 doc 只写「本组件
/// 属于哪一档 + 特殊事实」，与本件头冲突以本件头为准；新增 transport / handler
/// 类组件必须从本件起手，并在 PR 描述里回答 ADR §2.2 六问。
///
/// # 契约九条（逐条可核对：审阅者不翻别的文件即可判真伪）
///
/// **① 归属（ADR §2.1 三判据）**——**机制在 udf，禁复制**；持有者契约含 xray
/// 语义 ⇒ 归 **xray-frame 派生层**（判据 1 不成立：契约绑 xray 侧组件生命周期 +
/// 停机编排面 + Go 对拍分档；判据 2 成立：消费方横跨 8 crate、公共祖先 =
/// xray-frame；判据 3 不适用）。本件 = **组合包装** udf [`FxScope`]（spawn /
/// accepting 闸 / 在途计数 / 三段排空全部转调，零重写）。
///
/// **② stop 面归属（ADR §2.2 Q1）**——每个持有件**恰一个 stop 面**（禁「组件
/// close + 宿主 watcher」双排空口径打架）：
///
/// | stop 面形态 | 谁负责 | 允许的收口动作 |
/// |---|---|---|
/// | 组件自有 async close | 组件自身 | `close_gate()` + `drain(timeout)` |
/// | 组件自有 sync close（`TransportListener::close`） | 组件自身只能关闸 | `close_gate()` |
/// | 无 close 面（dispatcher / dial bridge / udp session） | 外部 stop 面（宿主 watcher / 宿主 drop） | `drain(timeout)` 或依赖 Drop 兜底（须写明） |
///
/// **③ 档位分档（ADR §2.2 Q1 档位表 · PM P1）**——**关闸档**（transport 族：
/// splithttp / hysteria / websocket / httpupgrade / naive）：只 `close_gate()`，拒新
/// 连接、**不杀已建立连接**（Go 26.10.17 `listener.Close()` 口径，在途服务到 EOF）；
/// **排空档**（arm / dispatcher / tun 族）：`drain(timeout)` = 关闸 + abort 在途 +
/// 等净，停机后 `in_flight == 0`（Rust 现行口径，bd a9xgp）。同进程两种停机观感 =
/// **刻意分层**，非缺陷。
///
/// **④ 两词不可混用（ADR §2.2 Q2）**——[`close_gate`](Self::close_gate)：同步、
/// 幂等，只关 accepting 闸（拒新 spawn、放行在途），**不断在途、不等净、不
/// abort**；[`drain`](Self::drain)：异步三段（关闸 → abort 在途 → 等净），返回
/// udf `ShutdownReport`，**唯一能声称「在途归零」的口**。禁一个 `close()` 同时
/// 被当两种语义用。
///
/// **⑤ Drop 不作保证（ADR §2.2 Q3）**——Drop 只允许释放**与任务存活无关**的资源
/// （socket / QUIC endpoint / 文件句柄），**不得**当作「在途任务终止」的实现手段
/// （udf 的 abort-on-drop 只在「最后一份 `Arc<FxScope>` 归零」时可达 ⇒ 多持有者
/// 共享时**时点不确定**、自引用环时**恒不可达**）。**禁**写「句柄丢弃即 abort
/// 在途」「Drop 兜底 abort 在途」这类依赖 Drop 的断言；可写的事实性表述：「Drop
/// 时 `FxScope` 若为最后一份强引用，则 JoinSet drop ⇒ abort 全组（udf 语义）」。
///
/// **⑥ 无 drain 面 ⇒ 不得声称 abort（ADR §2.2 Q3 + PM P2 / R1）**——transport
/// 族账本对宿主**不可见**（transport crate 无 ctx 注入面 ⇒ 宿主触达不到该账本
/// ⇒ 无 drain 面）⇒ 该族**不得**声称 abort 在途；「扩 listen API 注入句柄」另票。
///
/// **⑦ 环禁令（ADR §2.2 Q4 + PM P4）**——被托管任务**不得持有其所在账本的 owner
/// 强引用**（自引用环 ⇒ 该账本强引用永不归零 ⇒ Drop-abort 恒不可达）。可行形态
/// **只有两种**：①**弱引用 / 快照**（任务只持所需状态的副本，或持 `Weak`；升级
/// 失败即放弃——语义须逐站写明）；②**子账本**（确需向同一账本再 spawn 的任务住
/// **另一本账**；**父 drain 必须显式级联子账本**——udf `FxScope` 无父子语义 ⇒
/// 手工接线，漏接线 = 停机残留 ⇒ 须配 `in_flight` 断言兜住）。**第三种形态
/// （同账本自持 owner）禁止**。可观测锚 = [`live_refs`](Self::live_refs)。
///
/// **⑧ 单账本（ADR §2.2 Q5）**——一个组件恰一本账；可有多个**克隆句柄**（同一本
/// 账），但 **owner 恰一**，owner 由 stop 面负责 drain（禁「listener 一本 + hub
/// 一本」双份账本）。
///
/// **⑨ 诊断面（ADR §2.3 + PM P6）**——[`live_refs`](Self::live_refs) 是 A4
/// 「环已破」的**唯一可证伪锚**（只看「stop 后 `in_flight == 0`」证伪力不足：环
/// 存在时 `drain` 仍能归零 ⇒ 断言假绿）；标 `#[doc(hidden)]` = 诊断用、非稳定
/// API，未来若 udf 提供等价能力则随上游收敛删除。
#[derive(Clone)]
pub struct ComponentScope {
    /// 日志域标识（拼进每条报告；`Arc<str>` 便于克隆进 'static future）。
    label: Arc<str>,
    /// 账本本体 = udf `FxScope`（spawn / accepting 闸 / 在途计数 / 三段排空；
    /// 机制零复制，本件只组合调用）。
    scope: Arc<FxScope>,
    /// 域日志门面（scope 域单例，克隆零堆分配）：拒发 / panic / 排空结果的上报口。
    log: LogFacade,
    /// 收割节流计数（O29）：随本件共享（克隆同一份），每
    /// [`crate::compat::REAP_EVERY`] 次 spawn 摊一次 `try_reap`。
    tick: Arc<AtomicUsize>,
}

impl ComponentScope {
    /// 新建组件账本（label 进每条报告前缀）。
    pub fn new(label: impl Into<Arc<str>>) -> Self {
        Self {
            label: label.into(),
            scope: Arc::new(FxScope::new()),
            log: scope_log(),
            tick: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// 托管 spawn：闸已关（拒发）时记 warn 并回 `Err(ScopeClosed)`（禁静默放弃）。
    ///
    /// 走 [`crate::compat::spawn_reaping_ticked`]（udf `try_reap` + 入集，收割按本
    /// 账本的 `tick` 摊薄）：已完成条目出集，panic 载荷落日志（udf `task_body`
    /// 自带 `catch_unwind` 归一 ⇒ 本件**不再包任务体**）。
    pub fn spawn<F>(&self, fut: F) -> Result<Spawned<()>, ScopeClosed>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        crate::compat::spawn_reaping_ticked(
            &self.scope,
            &self.log,
            &self.label,
            Some(&self.tick),
            fut,
        )
    }

    /// 增量收割已完成条目（udf `try_reap`）并上报 panic；返回收割条数。
    ///
    /// [`Self::spawn`] 每次调用前已自动收割；本体供**无 spawn 的空闲期**显式
    /// 触发（调用方自定节拍），确保滞留窗口有界。
    pub fn reap(&self) -> usize {
        crate::compat::reap_into(&self.scope, &self.log, &self.label)
    }

    /// 暴露底层 [`FxScope`] 句柄：供「拿不到 PluginContext 但持有本件」的宿主把
    /// 托管任务喂给统一托管口（如 `crate::pool::spawn_idle_pruner`）。
    #[must_use]
    pub fn fx_scope(&self) -> &FxScope {
        &self.scope
    }

    /// **关闸**（同步、幂等）：只关 accepting 闸（拒新 spawn，放行在途）。
    ///
    /// **不断在途、不等净、不 abort**（ADR-0004 §2.2 Q2）。语义 = Go
    /// `listener.Close()`。要「在途归零」只能用 [`Self::drain`]。
    pub fn close_gate(&self) {
        self.scope.close();
    }

    /// **排空**（异步三段：关闸 → abort 在途 → 等净，带 timeout）。
    ///
    /// **唯一能声称「在途归零」的口**（ADR-0004 §2.2 Q2）。任务是**被取消**而非
    /// 被等完成（abortable 段零残留）；不可让渡的在途段会让等净超时 → 报告
    /// `timed_out > 0` + 一条 error 上报（禁静默）；成功 = 一条 info 报告
    /// （`drained N`）。返回 udf `ShutdownReport` 供调用方断言。
    pub async fn drain(&self, timeout: Duration) -> ShutdownReport {
        let pending = self.scope.in_flight();
        let report = self.scope.shutdown_timeout(timeout).await;
        for msg in &report.panicked {
            self.log.error(format!("{}: background task panicked: {msg}", self.label));
        }
        if report.timed_out > 0 {
            self.log.error(format!(
                "{}: shutdown incomplete ({pending} task(s) in flight, {} unfinished at deadline)",
                self.label, report.timed_out
            ));
        } else {
            self.log.info(format!("{}: drained {pending} background task(s)", self.label));
        }
        report
    }

    /// 在途任务数（排空断言锚）。
    pub fn in_flight(&self) -> usize {
        self.scope.in_flight()
    }

    /// **诊断面**（环破除锚，ADR-0004 §2.6 A4 · PM P6）：本账本（内嵌 udf
    /// [`FxScope`]）的**强引用持有者数**（每个本件句柄持一份，stop 面自身那一份
    /// 计入读数）。
    ///
    /// 读数：`1` = 只有 stop 面持有 ⇒ **无自引用环**；`> 1` = 有克隆句柄（**可能**
    /// 是合法克隆，**也可能**是派 C 自引用环 ⇒ 须逐个核）。**静止点**读才有判据
    /// 意义（运行期含合法克隆句柄）。
    ///
    /// `#[doc(hidden)]`：**诊断用**，非稳定 API；未来若 udf 提供等价能力则随上游
    /// 收敛删除（ADR-0004 R4）。
    #[doc(hidden)]
    #[must_use]
    pub fn live_refs(&self) -> usize {
        Arc::strong_count(&self.scope)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fmt,
        sync::{Mutex, PoisonError},
    };

    use super::*;

    /// bd il9lh MW-5：同 tag 连续登记 K 次 → 表内恒 1 条（修前 = K 条永久条目），
    /// 且**最后登记的** scope 才是存活的那条。
    #[test]
    fn register_same_tag_upserts_single_entry() {
        let reg = ArmScopeRegistry::new();
        let mut scopes = Vec::new();
        for _ in 0..5 {
            let scope = ArmScope::new();
            reg.register("in-1", Arc::clone(&scope));
            scopes.push(scope);
        }
        assert_eq!(reg.registered(), 1, "same tag must upsert, not append");
        // 被替换的旧 scope 已显式 close（不留孤儿 arm）。
        for old in &scopes[..scopes.len() - 1] {
            assert!(old.is_closed(), "replaced scope must be closed");
        }
        // 最后登记的那条仍开着（未被误关）。
        assert!(!scopes.last().expect("non-empty").is_closed(), "latest scope must stay open");
    }

    /// 同一 scope 重复登记 = 幂等：**不得**把刚登记的 arm 关掉。
    #[test]
    fn register_same_scope_twice_keeps_it_open() {
        let reg = ArmScopeRegistry::new();
        let scope = ArmScope::new();
        reg.register("in-1", Arc::clone(&scope));
        reg.register("in-1", Arc::clone(&scope));
        assert_eq!(reg.registered(), 1);
        assert!(!scope.is_closed(), "same-scope re-register must not close it");
    }

    /// 不同 tag 各自成条（upsert 不得误伤多入站场景）。
    #[test]
    fn register_distinct_tags_keep_all_entries() {
        let reg = ArmScopeRegistry::new();
        reg.register("in-1", ArmScope::new());
        reg.register("in-2", ArmScope::new());
        assert_eq!(reg.registered(), 2);
        assert_eq!(reg.close_all_reverse(), 2);
        assert_eq!(reg.registered(), 0);
    }

    /// 并发登记同 tag：N 线程 × M 次 → 终态恒 1 条（无竞态/死锁）。
    #[test]
    fn concurrent_register_same_tag_keeps_single_entry() {
        let reg = std::sync::Arc::new(ArmScopeRegistry::new());
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let reg = std::sync::Arc::clone(&reg);
                std::thread::spawn(move || {
                    for _ in 0..50 {
                        reg.register("in-1", ArmScope::new());
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("register thread must not panic");
        }
        assert_eq!(reg.registered(), 1, "concurrent same-tag register must upsert");
    }

    /// 并发登记 + 注销（`close_all_reverse`）：不得死锁/ panic；终态条目数 ≤ 1。
    #[test]
    fn concurrent_register_and_close_all_no_deadlock() {
        let reg = std::sync::Arc::new(ArmScopeRegistry::new());
        let mut handles = Vec::new();
        for i in 0..4 {
            let reg = std::sync::Arc::clone(&reg);
            handles.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    reg.register(format!("in-{i}"), ArmScope::new());
                }
            }));
        }
        let closer = {
            let reg = std::sync::Arc::clone(&reg);
            std::thread::spawn(move || {
                for _ in 0..50 {
                    reg.close_all_reverse();
                }
            })
        };
        for h in handles {
            h.join().expect("register thread must not panic");
        }
        closer.join().expect("close thread must not panic");
        assert!(reg.registered() <= 4, "entries must stay bounded, got {}", reg.registered());
    }

    // ==== ADR-0004 §2.6 断言 A2/A3/A4：组件账本持有者契约 ====

    /// ADR-0004 §2.6 A2：**关闸 ≠ 排空**——`close_gate()` 后 `spawn` 必回
    /// `Err(ScopeClosed)`，而在途任务**不被 abort**（自然跑完）。
    #[tokio::test]
    async fn close_gate_rejects_new_spawns_but_keeps_in_flight() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let scope = ComponentScope::new("test-close-gate");
        let done = Arc::new(AtomicBool::new(false));
        let task_done = Arc::clone(&done);
        let handle = scope
            .spawn(async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                task_done.store(true, Ordering::SeqCst);
            })
            .expect("新建账本即 accepting");
        assert_eq!(scope.in_flight(), 1, "spawn 后在途数必须可见");

        scope.close_gate();
        assert!(scope.spawn(async {}).is_err(), "关闸后必须拒发新任务");
        assert_eq!(scope.in_flight(), 1, "关闸**不断**在途");
        assert!(!done.load(Ordering::SeqCst), "关闸不得 abort 在途任务");

        // 在途任务自然跑完（未被 abort）⇒ join 得正常值（Err = 被取消）。
        handle.join().await.expect("在途任务不得被取消");
        assert!(done.load(Ordering::SeqCst), "在途任务应自然完成");
        assert_eq!(scope.in_flight(), 0, "任务结束后在途归零");
    }

    /// ADR-0004 §2.6 A3：**排空是唯一「在途归零」保证**——`drain()` 返回 udf
    /// `ShutdownReport{ panicked, timed_out }`；`timed_out > 0` 走 error 级上报。
    ///
    /// 构造（确定性，不靠固定 spin 余量）：① panic 任务——先跑到 panic 再排空
    /// （否则 abort 抢先，载荷根本没产生）；② 不可让渡的 spin 任务——abort 只在
    /// 任务回到 Pending 后生效 ⇒ 排空必真超时。
    #[test]
    fn drain_reports_timeout_and_panics() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let captured = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = Arc::clone(&captured);
        std::thread::spawn(move || {
            // `set_default` 是线程局部门面 + `block_on`：future 恒在调用线程 poll，
            // 捕获必定命中（多线程 runtime 上任务跨 worker 迁移会逃出捕获窗）。
            let _guard = tracing::subscriber::set_default(Capture(sink));
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async move {
                let scope = ComponentScope::new("test-drain");

                // ① panic 任务：先跑到终局（载荷入账本集合面），再排空。
                let boom = scope.spawn(async { panic!("drain-boom") }).expect("spawn accepted");
                while !boom.is_finished() {
                    tokio::task::yield_now().await;
                }

                // ② 不可让渡的在途任务（poll 不让渡 → abort 落不了地 → 必超时）。
                //    `started` 闸：任务**真跑起来**后才排空——未启动就被 abort 的任务
                //    是「取消」而非「超时」（abort 落不了地的前提 = 它在跑）。
                let started = Arc::new(AtomicBool::new(false));
                let hold = Arc::new(AtomicBool::new(true));
                let (task_started, task_hold) = (Arc::clone(&started), Arc::clone(&hold));
                scope
                    .spawn(async move {
                        task_started.store(true, Ordering::SeqCst);
                        while task_hold.load(Ordering::Relaxed) {
                            std::hint::spin_loop();
                        }
                    })
                    .expect("spawn accepted");
                while !started.load(Ordering::SeqCst) {
                    tokio::task::yield_now().await;
                }

                let report = scope.drain(Duration::from_millis(50)).await;
                assert!(report.timed_out > 0, "不可让渡的在途任务必须计入排空超时: {report:?}");
                assert!(
                    report.panicked.iter().any(|m| m.contains("drain-boom")),
                    "排空报告必须带 panic 载荷: {:?}",
                    report.panicked
                );

                // 放行 → 剩余任务收尾（超时退回 = abort 兜底，禁留活口）。
                hold.store(false, Ordering::Relaxed);
                for _ in 0..200 {
                    if scope.in_flight() == 0 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                assert_eq!(scope.in_flight(), 0, "超时后剩余任务必须收尾");
            });
        })
        .join()
        .expect("测试线程");

        let lines = captured.lock().unwrap_or_else(PoisonError::into_inner).join("\n");
        assert!(
            lines.contains("shutdown incomplete"),
            "排空超时必须 error 级上报（禁静默）: {lines:?}"
        );
        assert!(lines.contains("test-drain"), "报告必须带域标识: {lines:?}");
        assert!(lines.contains("background task panicked"), "panic 载荷必须上报: {lines:?}");
    }

    /// ADR-0004 §2.6 A4：**环破除锚**——`live_refs()` = 本账本强引用持有者数：
    /// 归 1 = 只有 stop 面持有（无自引用环）；> 1 = 存在克隆句柄。
    ///
    /// 反向锚：构造「任务持 owner 强引用」（ADR-0004 §2.2 Q4 的派 C 形态）⇒
    /// 读数 > 1；环破除（任务终局、克隆句柄释放）后归 1。
    #[tokio::test]
    async fn live_refs_detects_self_reference() {
        let scope = ComponentScope::new("test-live-refs");
        assert_eq!(scope.live_refs(), 1, "静止点读数 = 只有 stop 面持有（无环）");

        // 派 C 形态：克隆句柄住进本账本的任务体 = 任务强引用账本 owner。
        let holder = scope.clone();
        let handle = scope
            .spawn(async move {
                let _keep = holder;
                std::future::pending::<()>().await;
            })
            .expect("spawn accepted");
        assert!(
            scope.live_refs() > 1,
            "任务持 owner 强引用 ⇒ live_refs > 1（环存在）: {}",
            scope.live_refs()
        );

        // 环破除：任务终局 ⇒ 克隆句柄释放 ⇒ 读数归 1。
        handle.abort();
        for _ in 0..200 {
            if scope.in_flight() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(scope.in_flight(), 0, "被 abort 的任务必须终局");
        assert_eq!(scope.live_refs(), 1, "环破除 ⇒ live_refs 归 1（只剩 stop 面）");
    }

    /// 事件捕获订阅器（只把日志文本收进 `Vec`；线程局部安装，不抢全局槽）——
    /// 口径同 `compat.rs` 测试面的同名件。
    struct Capture(Arc<Mutex<Vec<String>>>);

    impl tracing::Subscriber for Capture {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            struct Text(String);
            impl tracing::field::Visit for Text {
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    self.0.push_str(&format!("{}={value} ", field.name()));
                }

                fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
                    self.0.push_str(&format!("{}={value:?} ", field.name()));
                }
            }
            let mut text = Text(String::new());
            event.record(&mut text);
            self.0.lock().unwrap_or_else(PoisonError::into_inner).push(text.0);
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }
}
