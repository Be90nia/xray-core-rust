//! L2 能力层·缓冲池接缝（P1-1；坑约束 4/9/12 落点）。
//!
//! 三件套：
//! - [`BufferPool`]：xray-frame 契约层的池接缝——只约定「怎么拿缓冲/怎么还」，
//!   **不约定分配算法**。分层策略（TIER_SIZES）与 TLS 缓存归 xray-buf
//!   （`crates/xray-buf/src/alloc.rs`，**分配路径一行不动**的红线）；管理面 （resize
//!   事前校验/水位线 O(1)/审计 seq 环/溢出丢弃计数）**白拿** udf [`PoolBase`]，本文件零重写（§3.5.2
//!   禁重复造轮子）。
//! - [`XrayBufPool`]：xray-buf 适配器——在分配路径**外侧**挂 udf 管理面记账，
//!   `xray_buf::alloc`/`xray_buf::release` 原样调用。
//! - [`ManagedBufferPool`]：管理面继承壳——任意 [`BufferPool`] 实现外套 `PoolBase` 账本，并
//!   [`PoolManaged`] 化（resize/metrics/subscribe_audit 三挂点；拍板③：不额外叠 Send+Sync 约束，超
//!   trait 已含）。
//!
//! 强约束映射（模型 §2）：**L2** 池能力只经 `ctx.pool()` 句柄取得，插件拿不到
//! 裸 `xray_buf::alloc`（L3-10 per-crate `disallowed-methods` 归 P2 批次落地）；
//! **L4** 借还配平由 [`PooledBuffer`] RAII + udf `note_return` 的
//! `borrowed == 0` fail-fast 断言兜底；**L5/坑约束 12** 管理面挂在分配路径
//! 外侧，xray-buf 分配路径字节级不动（红线隔离测试：`tests/pool_isolation.rs`）。

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, LazyLock, Mutex},
    time::Duration,
};

use bytes::BytesMut;
use skeleton::{
    clock::Clock,
    pool::{PoolAuditEvent, PoolAuditTicket, PoolManaged, PoolMetrics, PoolResizeError},
};
use skeleton_infra::{
    fx::{FxScope, ScopeClosed, Spawned},
    objpool::ObjectPool,
    pool::{AUDIT_RING_DEFAULT_CAP, PoolBase},
};

/// RAII 归还闭包：池在借出时把「还回去要做什么」封进 [`PooledBuffer`]。
type Release = Box<dyn FnOnce(BytesMut) + Send>;

/// [`BufferPool::acquire`] 的失败面：池满（并发借出达 `max`）。
///
/// PM 拍板①：立即 `Err`，不阻塞不等待 idle_cap——xray-buf 是无限池语义
/// （`alloc` 永不失败），`max` 是管理面给的**并发借出界**，不是存储容量。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolError {
    /// 并发借出已达 `max`（水位线已达 1.0）。
    Exhausted,
}

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exhausted => write!(
                f,
                "buffer pool exhausted: concurrent borrows at max (acquire refused immediately, no blocking)"
            ),
        }
    }
}

impl std::error::Error for PoolError {}

/// RAII 归还句柄（坑约束 4 的 L4 断言点）：Drop 归还一次；显式
/// [`PooledBuffer::release`] 仅供提前释放语义表达，与 Drop 等价。
///
/// 归还路径恰执行一次：句柄被消费后所有权上不可能二次归还；账本级重复归还
/// （记账 bug）由 udf `PoolBase::note_return` 的 `borrowed == 0` assert
/// fail-fast 拦截。
///
/// payload 只支持 `bytes::BytesMut`（PM 拍板②：泛型化留 v2——接缝消费者 P2
/// 全是 BytesMut，无第二 payload 类型需求）。
pub struct PooledBuffer {
    payload: Option<BytesMut>,
    release: Option<Release>,
}

impl PooledBuffer {
    fn new(payload: BytesMut, release: Release) -> Self {
        Self { payload: Some(payload), release: Some(release) }
    }

    /// 拆解（[`ManagedBufferPool`] 组合壳专用）：取 payload 与内层归还闭包，
    /// 内层 RAII 由外壳重组装接管。crate 内私有。
    fn into_parts(mut self) -> (BytesMut, Release) {
        // new() 恒双 Some；None 分支 = 半消费句柄（所有权下不可达），fail-fast。
        match (self.payload.take(), self.release.take()) {
            (Some(payload), Some(release)) => (payload, release),
            _ => panic!("PooledBuffer::into_parts on half-consumed handle (bookkeeping bug)"),
        }
    }

    /// 归还（恰一次）：显式 release 与 Drop 共用。双 None = 显式归还后的
    /// 正常二次 Drop（跳过）；单 None = 半消费（所有权下不可达），fail-fast。
    fn return_now(&mut self) {
        match (self.payload.take(), self.release.take()) {
            (Some(bytes), Some(release)) => release(bytes),
            (None, None) => {},
            _ => panic!("PooledBuffer half-consumed: payload/release mismatch (bookkeeping bug)"),
        }
    }

    /// 缓冲载荷（借出期内只读借用）。
    pub fn payload(&self) -> &BytesMut {
        self.payload
            .as_ref()
            .expect("PooledBuffer payload taken while handle alive (bookkeeping bug)")
    }

    /// 缓冲载荷（可变：写数据面内容）。
    pub fn payload_mut(&mut self) -> &mut BytesMut {
        self.payload
            .as_mut()
            .expect("PooledBuffer payload taken while handle alive (bookkeeping bug)")
    }

    /// 显式提前归还（消费句柄；不调用则 Drop 归还，两者等价且都恰一次）。
    pub fn release(mut self) {
        self.return_now();
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        self.return_now();
    }
}

/// 缓冲池接缝（xray-frame 契约层，坑约束 4 落点）：只约定「怎么拿/怎么还」，
/// 不约定分配算法——分层策略与 TLS 缓存归 xray-buf（零改动红线），管理面
/// 白拿 udf [`PoolBase`]（[`ManagedBufferPool`]）。
pub trait BufferPool: Send + Sync {
    /// 借一块容量 ≥ `size` 的缓冲；池满（并发借出达 `max`）立即
    /// [`PoolError::Exhausted`]（拍板①：不阻塞不等待）。
    ///
    /// 并发窗注：check-then-act 窗内可能短暂超界——udf [`PoolBase`] 借出侧
    /// 无 CAS 原语（白拿纪律禁自写），超界以 `watermark > 1.0` 显式留痕
    /// （udf 契约定义的合法中间态）。严格界收紧归 P2 接线实测后裁决。
    fn acquire(&self, size: usize) -> Result<PooledBuffer, PoolError>;

    /// 归还（RAII：句柄 Drop 即归还；显式调用仅供提前释放语义表达）。
    fn release(&self, buf: PooledBuffer);
}

/// xray-buf 适配器：把 udf [`PoolBase`] 管理面挂在 xray-buf 分配路径**外侧**。
///
/// **分配路径一行不动**（坑约束 12）：`xray_buf::alloc`/`xray_buf::release`
/// 原样调用，本类型只在其外侧记账。
///
/// **记账口径（审计 A-03）**：接缝**不持有闲槽**（物理存储归 xray-buf 分层池）⇒
/// 只记 `borrowed` / `watermark` 两个读数；`idle` 恒 `0`、`dropped_overflow` 恒 `0`，
/// 物理去留 100% 委托 `xray_buf::release`。⚠️ 不能用 `PoolBase::note_return()` 的
/// keep 裁决当去留闸：它把归还计入 `idle`（为「自持闲槽」的实现方设计），接缝借出
/// 侧无闲槽可减 ⇒ `idle` 变「累计归还数」，撞 `idle_cap` 后永久 keep=false，
/// 缓冲再也回不到池（修复前实测 `idle==64`/`dropped_overflow==36`）。
pub struct XrayBufPool {
    base: Arc<PoolBase>,
}

impl XrayBufPool {
    /// 构造（非法参数 panic fail-fast——透传 [`PoolBase::new`] 纪律：
    /// `max == 0` / `idle_cap == 0` / `idle_cap > max`）。
    pub fn new(max: usize, idle_cap: usize) -> Self {
        Self { base: Arc::new(PoolBase::new(max, idle_cap)) }
    }

    /// 管理面读数（白拿直透）。
    pub fn metrics(&self) -> PoolMetrics {
        self.base.metrics()
    }

    /// 运行时调参（白拿直透：事前校验，拒绝不改状态）。
    pub fn resize(&self, max: usize, idle_cap: usize) -> Result<(), PoolResizeError> {
        self.base.resize(max, idle_cap)
    }

    /// 开审计流（白拿直透：容量环取 [`AUDIT_RING_DEFAULT_CAP`]）。
    pub fn subscribe_audit(
        &self,
        f: impl FnMut(&PoolAuditEvent) + Send + 'static,
    ) -> PoolAuditTicket {
        self.base.subscribe_audit(AUDIT_RING_DEFAULT_CAP, f)
    }

    /// 取走环内审计事件（白拿直透：随取随清）。
    pub fn take_audit_events(&self) -> Vec<PoolAuditEvent> {
        self.base.take_audit_events()
    }
}

impl BufferPool for XrayBufPool {
    fn acquire(&self, size: usize) -> Result<PooledBuffer, PoolError> {
        let m = self.base.metrics();
        if m.borrowed >= m.max {
            return Err(PoolError::Exhausted);
        }
        let bytes = xray_buf::alloc::alloc(size);
        self.base.note_borrow();
        let base = Arc::clone(&self.base);
        Ok(PooledBuffer::new(
            bytes,
            Box::new(move |bytes| {
                // 物理去留 100% 委托 xray-buf：接缝不持闲槽 ⇒ 没有「槽满」可言，
                // 归还恒回池（不设 keep 闸，审计 A-03）。
                xray_buf::alloc::release(bytes);
                // 借出数 -1。`note_return` 的 keep 判决是给自持闲槽的实现方用的，
                // 它把归还计入 idle ⇒ 接缝的 idle 立即消账（恒 0）。
                // keep=false 只在并发窗内 borrowed 曾超 max 时出现（acquire 的
                // check-then-act 窗口，见 trait 文档），此时缓冲并未丢弃——物理
                // 释放已先行，`dropped_overflow` 在那条路径上表达的是「超上界归还」。
                if base.note_return() {
                    base.note_idle_delta(-1);
                }
            }),
        ))
    }

    fn release(&self, buf: PooledBuffer) {
        buf.release();
    }
}

/// 管理面继承壳：接缝（`B`）+ [`PoolBase`] 管理面 = 池管理的白拿组合。
///
/// 记账口径同 [`XrayBufPool`]：外壳**不持闲槽** ⇒ 只记 `borrowed`/`watermark`，
/// `idle` 恒 `0`、`dropped_overflow` 恒 `0`；物理去留由**最内层**存储裁决
/// （`inner_release` 恒被调用，外壳不做 keep 闸——旧实现丢掉了内层 keep 结果，
/// 同时自己把归还计成闲槽，两层账本都在说假话，审计 A-03/A-04）。
///
/// 调参面走 [`PoolManaged`]（`Tuning = (usize, usize)`）——不设 inherent
/// `resize(max, idle_cap)`：双参形与 tuple 形并存会互相遮蔽（ThreadPool
/// 先例靠命名 struct 避撞，此处按契约直接单面）。
pub struct ManagedBufferPool<B: BufferPool> {
    inner: B,
    base: Arc<PoolBase>,
}

impl<B: BufferPool> ManagedBufferPool<B> {
    /// 构造（非法参数 panic fail-fast——透传 [`PoolBase::new`] 纪律）。
    pub fn new(inner: B, max: usize, idle_cap: usize) -> Self {
        Self { inner, base: Arc::new(PoolBase::new(max, idle_cap)) }
    }

    /// 管理面读数（白拿直透）。
    pub fn metrics(&self) -> PoolMetrics {
        self.base.metrics()
    }

    /// 开审计流（白拿直透）。
    pub fn subscribe_audit(
        &self,
        f: impl FnMut(&PoolAuditEvent) + Send + 'static,
    ) -> PoolAuditTicket {
        self.base.subscribe_audit(AUDIT_RING_DEFAULT_CAP, f)
    }

    /// 取走环内审计事件（白拿直透）。
    pub fn take_audit_events(&self) -> Vec<PoolAuditEvent> {
        self.base.take_audit_events()
    }
}

impl<B: BufferPool> BufferPool for ManagedBufferPool<B> {
    fn acquire(&self, size: usize) -> Result<PooledBuffer, PoolError> {
        let m = self.base.metrics();
        if m.borrowed >= m.max {
            return Err(PoolError::Exhausted);
        }
        // 内层账本由内层自己记（inner.acquire 内 note_borrow）；外壳账本在
        // 内层成功后才记——内层拒绝时外壳零污染。
        let (bytes, inner_release) = self.inner.acquire(size)?.into_parts();
        self.base.note_borrow();
        let base = Arc::clone(&self.base);
        Ok(PooledBuffer::new(
            bytes,
            Box::new(move |bytes| {
                // 外壳只做借出数/水位线记账（idle 恒 0，理由同 XrayBufPool）。
                if base.note_return() {
                    base.note_idle_delta(-1);
                }
                // 物理去留归最内层（恒调用，不设 keep 闸）。
                inner_release(bytes);
            }),
        ))
    }

    fn release(&self, buf: PooledBuffer) {
        buf.release();
    }
}

impl<B: BufferPool> PoolManaged for ManagedBufferPool<B> {
    /// 无特有读数 → 核心形直用（`Borrow<T> for T` 天然满足，零包装）。
    type Metrics = PoolMetrics;
    /// 三参封顶的面内特化：`(max, idle_cap)`。
    type Tuning = (usize, usize);

    fn resize(&self, tuning: Self::Tuning) -> Result<(), PoolResizeError> {
        self.base.resize(tuning.0, tuning.1)
    }

    fn metrics(&self) -> Self::Metrics {
        self.base.metrics()
    }

    fn subscribe_audit(&self, f: impl FnMut(&PoolAuditEvent) + Send + 'static) -> PoolAuditTicket {
        self.base.subscribe_audit(AUDIT_RING_DEFAULT_CAP, f)
    }
}

/// 低频老化任务托管口（bd vi2h5 缺陷 2 / bd jovl4 缺口 3）：宿主用既有托管口
/// [`FxScope`] 起周期 `prune_idle` 任务——**池不起后台线程**（udf 纪律）纪律
/// 不变，老化由**托管任务**承担：任务生命周期随 scope（scope drop / shutdown
/// ⇒ 任务随 JoinSet abort，无孤儿循环）。
///
/// **双时钟注入**：`clock` 驱动龄判定（`prune_idle_with_clock`——测试注入
/// `MockClock` 确定性推进，无需真实等待）；tokio 虚拟时间（`start_paused`）驱动
/// tick 节奏。两钟正交：宿主可只造一次 pruner，测试与生产共用同一构造路。
///
/// 语义边界：本口面向**真实持槽的池**（udf `ObjectPool` 系——idle 槽驻留即
/// 内存驻留）；接缝 [`XrayBufPool`]/[`ManagedBufferPool`] **不持闲槽**（物理
/// 存储归 xray-buf 分层池，其自身带惰性收缩 `maybe_sweep`），无需本口。
/// 现役两池（hysteria udphop / splithttp pool_stream）宿主接线时以本口为
/// 唯一托管入口（禁在协议 crate 自起裸 spawn——坑约束 5）。
///
/// **归属（ADR-1 派生件，bd ki2vo）**：udf issue #23「skeleton-infra 提供 FxScope
/// 托管的池老化任务」已判 `NOT_PLANNED`——上游要求由消费方派生，理由是该任务
/// 需要同时握 `ObjectPool` 与 `FxScope` 两件，属装配层关注点。故本口按派生纪律
/// 留 `xray-frame`（组合包装 udf `ObjectPool::prune_idle_with_clock` +
/// `FxScope::spawn_tracked`，不复制任何 udf 机制）。若上游日后落同一件，删本口、
/// 消费点换 udf 版即可（调用面已按此形状设计：pool/clock/period/max_idle_age）。
pub fn spawn_idle_pruner<T: Send + 'static>(
    scope: &FxScope,
    pool: Arc<ObjectPool<T>>,
    clock: Arc<dyn Clock>,
    period: Duration,
    max_idle_age: Duration,
) -> Result<Spawned<()>, ScopeClosed> {
    scope.spawn_tracked(async move {
        let mut ticker = tokio::time::interval(period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // interval 首 tick 立即完成——首轮老化无需等一个周期。
        loop {
            ticker.tick().await;
            let pruned = pool.prune_idle_with_clock(max_idle_age, clock.as_ref());
            if pruned > 0 {
                tracing::debug!(
                    target: "xray_frame::pool",
                    pruned,
                    max_idle_age_secs = max_idle_age.as_secs(),
                    "idle objects pruned"
                );
            }
        }
    })
}

// ── 进程级共享块池注册表（bd ccy5d / ARCH-05）────────────────────────────

/// 进程级**共享块池注册表**：同尺寸 class（块字节数）全进程唯一一份
/// [`ObjectPool`]，不同尺寸 class 各自独立成池、互不串用（毒化防护）。
///
/// 与 [`BufferPool`]/[`ManagedBufferPool`] 同族（L2 池能力层）：后两者管
/// 「借还契约 + 管理面记账」，本件管「**进程级共享的表**」——同一进程的 N 个
/// 消费方（流/连接）对同尺寸块的借还落在同一份池上，池常驻上界从「每消费方
/// 一份」的乘积面（N × cap）收敛为**进程级常量**（账本：`crate::budget` 的
/// `SPLITHTTP_SHARED_BLOCK_POOL_MAX_BYTES` / `HYSTERIA_UDPHOP_SHARED_POOL_MAX_BYTES`）。
///
/// **归属（ADR-1 三判据 · bd ccy5d）**：keyed 共享表是零方向语义的机制件，
/// 但池的 key 形态（chunk 尺寸 class、协议侧预算公式与 reset 钩子）带网络方向
/// 语义——按 §3.5.3 方向件纪律**不进 udf**，机制本体落本件（派生层）。两消费方
/// （splithttp `pool_stream` / hysteria `udphop`）只留各自的池构造参数，
/// **禁在协议 crate 自造第二张表**（§3.5.2）。
///
/// 语义（沿 bd kw2si 的 splithttp 静态表原样上浮；2026-11-07 起 splithttp 改调
/// 本件，hysteria 从每连接一份改挂本件）：
/// - **按尺寸 class 分桶**：key = 块字节数。一个 class 的异形块（reset 归一
///   前后的膨胀块）只可能落回自己的池，永不串入其他 class——一个消费方的膨胀 尺寸不能污染另一个；
/// - **first-wins**：同 class 首个 `get_or_init` 的构造结果全进程复用，后到者
///   的构造闭包不执行——同尺寸块的构造形状必须一致（等重块共享的前提）；
/// - **借还不经表**：表锁只在取池时走（每流/每连接一次），借还热路径只碰 `Arc`
///   克隆结果，共享不新增锁成本；
/// - **`Mutex` 中毒恢复**（`into_inner`）：表操作本身不 panic，真毒化（构造池 validate
///   panic）后恢复表继续服务，不放大故障。
pub struct SharedPoolRegistry {
    pools: Mutex<HashMap<usize, Arc<ObjectPool<Vec<u8>>>>>,
}

impl SharedPoolRegistry {
    /// 进程级单例。
    #[must_use]
    pub fn shared() -> &'static Self {
        static REGISTRY: LazyLock<SharedPoolRegistry> =
            LazyLock::new(|| SharedPoolRegistry { pools: Mutex::new(HashMap::new()) });
        &REGISTRY
    }

    /// 取/建 `block_size` class 的共享池：同尺寸全进程唯一一份（first-wins）。
    ///
    /// `build` 只在该 class **首次**取池时执行；闭包内的池参数（max/idle_cap/
    /// factory/reset）即该 class 的进程级预算承诺，登记面见 `crate::budget`。
    pub fn get_or_init(
        &self,
        block_size: usize,
        build: impl FnOnce() -> Arc<ObjectPool<Vec<u8>>>,
    ) -> Arc<ObjectPool<Vec<u8>>> {
        let mut pools = self.pools.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        pools.entry(block_size).or_insert_with(build).clone()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        borrow::Borrow,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use skeleton::pool::PoolAuditKind;
    use skeleton_infra::objpool::ResetPhase;

    use super::*;

    // ── 构造 fail-fast（PoolBase::new 纪律透传）─────────────────────────

    #[test]
    #[should_panic(expected = "PoolBase::new")]
    fn pool_new_panics_on_zero_max() {
        let _ = XrayBufPool::new(0, 1);
    }

    #[test]
    #[should_panic(expected = "PoolBase::new")]
    fn pool_new_panics_on_zero_idle_cap() {
        let _ = XrayBufPool::new(4, 0);
    }

    #[test]
    #[should_panic(expected = "PoolBase::new")]
    fn pool_new_panics_on_idle_cap_over_max() {
        let _ = XrayBufPool::new(4, 8);
    }

    // ── resize 事前校验：拒绝不改状态 ───────────────────────────────────

    #[test]
    fn pool_resize_rejects_without_state_change() {
        let pool = XrayBufPool::new(8, 8);
        let before = pool.metrics();
        assert_eq!(pool.resize(0, 1), Err(PoolResizeError::ZeroMax));
        assert_eq!(pool.resize(4, 0), Err(PoolResizeError::IdleCapZero));
        assert_eq!(
            pool.resize(4, 8),
            Err(PoolResizeError::IdleCapExceedsMax { idle_cap: 8, max: 4 })
        );
        assert_eq!(pool.metrics(), before, "拒绝路径不改任何状态");

        assert!(pool.resize(16, 16).is_ok(), "合法调参即刻生效");
        assert_eq!(pool.metrics().max, 16);
    }

    // ── 水位线读数（O(1) 契约面 + 借还记账）────────────────────────────

    #[test]
    fn pool_metrics_watermark_tracks_borrows() {
        let pool = XrayBufPool::new(8, 8);
        let bufs: Vec<_> = (0..4).map(|_| pool.acquire(64).expect("within max")).collect();
        let m = pool.metrics();
        assert_eq!((m.borrowed, m.idle, m.dropped_overflow), (4, 0, 0));
        assert_eq!(m.watermark, 0.5, "borrowed/max = 4/8");

        drop(bufs); // Drop 路径归还
        let m = pool.metrics();
        // 接缝不持闲槽 ⇒ idle 恒 0（「已归还次数」不是「闲槽数」，审计 A-03）。
        assert_eq!((m.borrowed, m.idle, m.dropped_overflow), (0, 0, 0));
        assert_eq!(m.watermark, 0.0);
    }

    // ── 拍板①：池满立即 Err，归还即恢复 ────────────────────────────────

    #[test]
    fn pool_exhausted_err_then_recovers_after_return() {
        let pool = XrayBufPool::new(2, 2);
        let a = pool.acquire(64).expect("first");
        let _b = pool.acquire(64).expect("second");
        assert!(matches!(pool.acquire(64), Err(PoolError::Exhausted)));
        drop(a);
        assert!(pool.acquire(64).is_ok(), "归还即恢复（不阻塞不等待）");
    }

    // ── 归还恒达底层池（接缝不做去留裁决，审计 A-03 主锚）─────────────────
    //
    // 底层池 = 真持有 `BytesMut` 的实现（计数 + 物理存储）：证明「越过 idle_cap 的
    // 归还仍进底层」且「归还的块能再次取出」。旧实现在第 idle_cap 笔之后把归还
    // 挡在接缝里（缓冲就地 drop），本单测当场红。

    #[derive(Default)]
    struct InnerStore {
        released: AtomicUsize,
        stored: Mutex<Vec<BytesMut>>,
    }

    struct RecordingPool {
        store: Arc<InnerStore>,
    }

    impl BufferPool for RecordingPool {
        fn acquire(&self, size: usize) -> Result<PooledBuffer, PoolError> {
            let bytes = self
                .store
                .stored
                .lock()
                .expect("test lock")
                .pop()
                .unwrap_or_else(|| BytesMut::with_capacity(size));
            let store = Arc::clone(&self.store);
            Ok(PooledBuffer::new(
                bytes,
                Box::new(move |bytes| {
                    store.released.fetch_add(1, Ordering::Relaxed);
                    store.stored.lock().expect("test lock").push(bytes);
                }),
            ))
        }

        fn release(&self, buf: PooledBuffer) {
            buf.release();
        }
    }

    #[test]
    fn pool_routes_every_return_to_inner_storage_past_idle_cap() {
        const IDLE_CAP: usize = 64;
        let store = Arc::new(InnerStore::default());
        let pool =
            ManagedBufferPool::new(RecordingPool { store: Arc::clone(&store) }, 1024, IDLE_CAP);

        let mut addr = 0;
        for i in 0..200 {
            let buf = pool.acquire(4096).expect("within max");
            addr = buf.payload().as_ptr() as usize;
            buf.release();
            assert_eq!(
                store.released.load(Ordering::Relaxed),
                i + 1,
                "第 {i} 次归还必须到达底层池（idle_cap={IDLE_CAP} 不封顶、不去留裁决）"
            );
            assert_eq!(store.stored.lock().expect("test lock").len(), 1, "底层物理留存 1 块");
        }
        let m = pool.metrics();
        assert_eq!((m.borrowed, m.idle, m.dropped_overflow), (0, 0, 0), "外层只记借出/水位线");

        let again = pool.acquire(4096).expect("within max");
        assert_eq!(
            again.payload().as_ptr() as usize,
            addr,
            "归还的块必须能再次取出（底层物理存储 LIFO）"
        );
    }

    // ── 审计 seq 单调 + 票据纪律 ────────────────────────────────────────

    #[test]
    fn pool_audit_seq_monotonic_with_bound_ticket() {
        let pool = XrayBufPool::new(4, 4);
        let _ticket = pool.subscribe_audit(|_| {}); // 绑定持有（must_use 纪律）
        let a = pool.acquire(64).expect("acquire");
        a.release();
        let events = pool.take_audit_events();
        assert!(events.len() >= 2, "借/还各发射一件：{events:?}");
        assert!(events.windows(2).all(|w| w[0].seq < w[1].seq), "seq 单调：{events:?}");
        assert_eq!(events[0].kind, PoolAuditKind::Borrowed);
        assert_eq!(events[1].kind, PoolAuditKind::Returned);
    }

    // ── ManagedBufferPool：三挂点契约 + 借还配平 + 双层账本 ─────────────

    #[test]
    fn pool_managed_trait_surface_and_core_metrics() {
        fn assert_pool_managed<T: PoolManaged<Tuning = (usize, usize), Metrics = PoolMetrics>>() {}
        assert_pool_managed::<ManagedBufferPool<XrayBufPool>>();

        let shell = ManagedBufferPool::new(XrayBufPool::new(64, 64), 64, 64);
        assert_eq!(shell.resize((0, 1)), Err(PoolResizeError::ZeroMax));
        assert!(shell.resize((32, 32)).is_ok());
        assert_eq!(
            shell.metrics().borrow(),
            &PoolMetrics { max: 32, idle: 0, borrowed: 0, dropped_overflow: 0, watermark: 0.0 }
        );

        let _t = shell.subscribe_audit(|_| {});
        shell.acquire(64).expect("acquire").release();
        assert!(!shell.take_audit_events().is_empty(), "审计挂点经壳可达");
    }

    #[test]
    fn pool_managed_shell_balances_over_inner() {
        let shell = ManagedBufferPool::new(XrayBufPool::new(128, 128), 128, 128);
        let bufs: Vec<_> = (0..8).map(|_| shell.acquire(4096).expect("within max")).collect();
        assert_eq!(shell.metrics().borrowed, 8);
        for b in bufs {
            b.release();
        }
        let m = shell.metrics();
        assert_eq!((m.borrowed, m.idle, m.dropped_overflow), (0, 0, 0), "外壳只记借出/水位线");

        // 内层先爆时外壳透传 Err：内层 max=2，第 3 次借出被内层拒绝，
        // 被拒借出外壳零记账（外壳停在 2，不是 3）。
        let shell2 = ManagedBufferPool::new(XrayBufPool::new(2, 2), 8, 8);
        let _x = shell2.acquire(64).expect("inner 1/2");
        let _y = shell2.acquire(64).expect("inner 2/2");
        assert!(matches!(shell2.acquire(64), Err(PoolError::Exhausted)), "内层拒绝透传外壳");
        assert_eq!(shell2.metrics().borrowed, 2, "被拒的借出外壳零记账");
    }

    // ── 线程面（trait supertrait 透传；拍板③不额外叠加）────────────────

    #[test]
    fn pool_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<XrayBufPool>();
        assert_send_sync::<ManagedBufferPool<XrayBufPool>>();
        fn assert_send<T: Send>() {}
        assert_send::<PooledBuffer>();
    }

    // ── 低频老化托管口（vi2h5 缺陷 2 / jovl4 缺口 3）────────────────────

    /// 双时钟注入的确定性推进：tokio 虚拟时间驱动 tick（`start_paused`），
    /// `MockClock` 驱动龄判定——无需真实等待即可断言「周期到 ⇒ 超龄 idle 被
    /// 释放」。
    #[tokio::test(start_paused = true)]
    async fn idle_pruner_releases_aged_idle_on_tick() {
        use skeleton::clock::MockClock;

        let clock = Arc::new(MockClock::new());
        let scope = FxScope::new();
        let pool = Arc::new(ObjectPool::new(4, 4, Vec::<u8>::new));
        {
            let mut b = pool.acquire();
            b.push(1u8);
        } // 归还 1 件入 idle（last_used = 构造期附近）
        assert_eq!(pool.metrics().core.idle, 1, "前置：1 件常驻 idle");

        let spawned = spawn_idle_pruner(
            &scope,
            Arc::clone(&pool),
            clock.clone(),
            Duration::from_secs(30),
            Duration::from_secs(60),
        )
        .expect("scope 初始 accepting，spawn 必成");

        // 推进虚拟时钟使对象超龄（60s 窗）+ 推进 tokio 时间跨过一个 tick。
        clock.advance(Duration::from_secs(120));
        tokio::time::advance(Duration::from_secs(30)).await;
        // 让出调度：pruner 任务在 tick 唤醒后完成本轮 prune。
        tokio::task::yield_now().await;

        let m = pool.metrics();
        assert_eq!(m.core.idle, 0, "tick 后超龄 idle 必须被释放");
        assert_eq!(m.pruned, 1, "prune 计数留痕");

        // 托管语义：scope 关闸 + 排空 ⇒ pruner 随 JoinSet 收割，无孤儿循环。
        drop(spawned);
        let _ = scope.shutdown().await;
    }

    // ── 共享块池注册表（bd ccy5d）────────────────────────────────────────

    /// 注册表契约：同尺寸 class 全进程唯一一份；不同尺寸 class 独立成池。
    /// **反向自检锚点**：把 `get_or_init` 的 key 换成常量（全员共池），
    /// `!Arc::ptr_eq` 断言必红。
    #[test]
    fn shared_registry_buckets_by_size_class() {
        // 局部注册表（不碰进程单例的既存 bucket，读数可精确断言）。
        let registry = SharedPoolRegistry { pools: Mutex::new(HashMap::new()) };
        let build = || Arc::new(ObjectPool::new(4, 4, Vec::<u8>::new));

        let a1 = registry.get_or_init(4096, build);
        let a2 = registry.get_or_init(4096, build);
        assert!(Arc::ptr_eq(&a1, &a2), "同尺寸 class 必须命中同一份池（first-wins 复用）");

        let b = registry.get_or_init(1500, build);
        assert!(!Arc::ptr_eq(&a1, &b), "不同尺寸 class 禁串池（毒化防护，bd ccy5d）");

        // 进程单例同契约：同一尺寸两次取池 ⇒ 同一份（消费方契约的表侧锚）。
        let s1 = SharedPoolRegistry::shared().get_or_init(7777, build);
        let s2 = SharedPoolRegistry::shared().get_or_init(7777, build);
        assert!(Arc::ptr_eq(&s1, &s2), "进程单例：同尺寸 class 全进程唯一一份");
    }

    /// 毒化防护（bd ccy5d 验收）：一个 class 里的膨胀块（异形块）只落回自己的
    /// 池（归一后入 idle），**另一个 class 的池零接触**——膨胀尺寸不跨 class
    /// 污染。**反向自检锚点**：全员共池（key 换常量）时 B 池的 idle/borrowed
    /// 读数必被 A 的异形块污染，本断言必红。
    #[test]
    fn inflated_block_in_one_class_never_leaks_to_another() {
        let registry = SharedPoolRegistry { pools: Mutex::new(HashMap::new()) };
        // reset 钩子做容量归一（消费方形状：异形块换定长零块）。
        let normalize = |chunk: usize| {
            move |buf: &mut Vec<u8>| {
                if buf.len() != chunk {
                    *buf = vec![0u8; chunk];
                }
            }
        };
        let a = registry.get_or_init(4096, || {
            Arc::new(ObjectPool::with_reset(
                4,
                4,
                || vec![0u8; 4096],
                normalize(4096),
                ResetPhase::OnReturn,
            ))
        });
        let b = registry.get_or_init(1500, || {
            Arc::new(ObjectPool::with_reset(
                4,
                4,
                || vec![0u8; 1500],
                normalize(1500),
                ResetPhase::OnReturn,
            ))
        });

        // 消费方 A 把膨胀块（3× 尺寸）塞回自己的 class。
        let inflated = vec![0xAu8; 4096 * 3];
        assert!(a.insert(inflated).is_none(), "idle 额度内归一收下");
        let m_a = a.metrics();
        assert_eq!(m_a.core.idle, 1, "A 池归一后收下 1 块");
        let recycled = a.acquire();
        assert_eq!(recycled.len(), 4096, "膨胀块必须归一到 class 尺寸才可复用");

        // B 池零接触：A 的膨胀块没有串进来。
        let m_b = b.metrics();
        assert_eq!(m_b.core.idle, 0, "B class 不得收到 A 的块");
        assert_eq!(m_b.core.borrowed, 0, "B class 无在外块");
        assert_eq!(b.metrics().constructed, 0, "B class 零构造（无借出即无工厂调用）");
    }
}
