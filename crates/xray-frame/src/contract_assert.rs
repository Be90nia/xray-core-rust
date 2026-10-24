//! L4 契约测试夹具（模型 §2.2 L4 行）：宏
//! [`assert_plugin_contract`](crate::assert_plugin_contract)
//! （`#[macro_export]` 挂根）。
//!
//! 每协议 crate 的集成测试必须调用本宏（缺 = CI 红，规范源 §2.2 L4）。
//! 逐条断言：
//! ① 必选方法集可调——name 非空且稳定（两次调用一致）、version 非空、
//!    deps/contract 可调；
//! ② `clauses` 与 `not_applicable` 不得重叠、N/A 理由非空（P1-7 拍板 P2.2：
//!    允许声明 N/A 但必须有理由字段）；
//! ③ `extra` 键值非空；
//! ④ lifecycle 三相可调且不 panic（`Err` 同样视为失败上抛）。
//!
//! 宏体走 `#[doc(hidden)]` 辅助面（[`assert_contract_for`] /
//! [`contract_test_context`]）——从外部 crate 的集成测试可直接调用，最小暴露。
//! 注意：④ 在非 async 上下文调用 lifecycle；start 内需要 spawn 托管任务的
//! 插件应在 tokio runtime 内调用本宏。
//!
//! # 行为夹具（P1-L4：规范源 §3 夹具表）
//!
//! 四个可执行行为断言面（声明面之外的「跑起来验证」），同样从外部 crate
//! 的集成测试调用：[`assert_conn_id_present`](crate::assert_conn_id_present)
//! （坑约束 3：非零/唯一/单调）、[`assert_deadline_effective`](crate::assert_deadline_effective)
//! （坑约束 2：期限内 Ok / 不完成 Err(Elapsed)，真超时必红）、
//! [`assert_log_fields`](crate::assert_log_fields)（坑约束 3/10/11：target
//! 前缀 + 四元组 + secrets 掩码）、[`assert_pool_discipline`](crate::assert_pool_discipline)
//! （坑约束 4/9：借 N 还 N 配平）。正/负用例见 `tests/l4_fixtures.rs`。
//!
//! **默认构造确定性**：[`contract_test_context`] 用固定指纹
//! [`DETERMINISTIC_FINGERPRINT`] + MockClock 冻结于 ms=1——`next_conn_id()`
//! 连发恒不撞 IdGen 同毫秒 fail-closed 配额臂（每毫秒配额 ≈2553 个），序列
//! 跨运行逐位可回放。调用方 crate **不要**再写 catch_unwind 重掷指纹的重试
//! helper；自定义时钟/指纹走 [`contract_test_context_with`]。
//!
//! # 条款声明态（B6 审计标注，bd 7dce，2026-10-24）
//!
//! 12 条坑约束的「声明 vs 断言」现状三态：**已实现**（有通用行为夹具，接线即
//! 断言；协议性不适用走 `not_applicable` 逐 crate 登记）、**部分**（断言面只
//! 覆盖条款子面，或无通用夹具、靠部分 crate 自写测试补位）、**仅声明**（只有
//! [`ClauseId`](crate::plugin::ClauseId) 枚举位，无任何执行断言面——补夹具
//! 前，条款声明不得当作「已受约束」）。
//!
//! | 条款 | 声明态 | 断言面与缺口 |
//! |---|---|---|
//! | 1 AuthErrorClassified | 仅声明 | 无通用夹具——认证失败分类是协议行为面语义，四夹具不覆盖 |
//! | 2 HandshakeDeadline | 已实现 | [`assert_deadline_effective`](crate::assert_deadline_effective)（双入口正向 + pending 必掐真超时）；协议性 N/A 先例：freedom 无协商握手 |
//! | 3 ConnIdPresent | 已实现 | [`assert_conn_id_present`](crate::assert_conn_id_present)（非零 / 严格递增） |
//! | 4 PoolDiscipline | 部分 | [`assert_pool_discipline`](crate::assert_pool_discipline) 管借还配平；N/A 豁免口已启用（先例 blackhole 零缓冲桩）——覆盖依赖 crate 诚实声明 |
//! | 5 SpawnManaged | 仅声明 | 无协议 crate 通用夹具（框架自测 `tests/fx_managed_spawn.rs` 管托管机制本身，不验插件接线） |
//! | 6 StopRegistered | 仅声明 | 停机注册归 L5 装配门（P0-8）管辖，L4 无运行期夹具 |
//! | 7 ConfigSectionOnly | 部分 | 无通用夹具；blackhole/vmess 以 crate 自写装配门负向测试补位，覆盖不统一 |
//! | 8 ErrorClassifiedNoPanicEscape | 仅声明 | 无通用夹具——错误归类与 panic 隔离语义无执行断言面 |
//! | 9 BoundedResources | 部分 | 仅经 [`assert_pool_discipline`](crate::assert_pool_discipline) 覆盖借还记账面；「资源上有界」本身（容量/内存上限）无通用断言 |
//! | 10 LogDiscipline | 已实现 | [`assert_log_fields`](crate::assert_log_fields)（target 前缀 + 四元组） |
//! | 11 SecretMasking | 已实现 | [`assert_log_fields`](crate::assert_log_fields)（secrets 表不可见）；协议性 N/A 先例：freedom 无协议凭据 |
//! | 12 HotPathFreeze | 仅声明 | review 门 + 装配门（人工/装配期），无运行期夹具——条款文档自述 |
//!
//! 已知未接线实例：`xray-proxy-ss` 无 `impl Plugin` 面，豁免清单见该 crate
//! `tests/plugin_contract.rs` 头注释。

use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use skeleton::{
    clock::{Clock, MockClock, SystemClock},
    config::StdEnv,
    pool::PoolMetrics,
};
use skeleton_infra::fx::FxScope;

use crate::{
    context::PluginContext,
    deadline::{HandshakeDeadline, with_deadline},
    logging::LogFacade,
    plugin::{Plugin, PluginContract},
    pool::{BufferPool, ManagedBufferPool},
};

/// 夹具默认指纹（确定性拍板）：counter 基址 = `(0xC0FFEE >> 13) & 0xFFF` =
/// 0x607 = 1543 → 每毫秒 id 配额 4096 − 1543 ≈ **2553 个**，`assert_conn_id_present!`
/// 的 n 连发（乃至多测试并行累计）恒不撞 IdGen 同毫秒 fail-closed 配额臂。
/// 协议 crate 侧无需知道本值；需要自定指纹时走
/// [`contract_test_context_with`]。
#[doc(hidden)]
pub const DETERMINISTIC_FINGERPRINT: u64 = 0xC0FFEE;

/// 夹具默认时钟起点（确定性拍板）：MockClock 推进到 ms=1——首调即走 IdGen
/// 跨毫秒臂（counter 满额重置），时间戳字段非零，跨运行逐位可回放。
fn deterministic_test_clock() -> Arc<dyn Clock> {
    let clock = MockClock::new();
    clock.advance(Duration::from_millis(1));
    Arc::new(clock)
}

/// 宏辅助：构造 lifecycle 三相调用可用的最小 [`PluginContext`]（空配置根——
/// 三相本体契约上不消费段数据；段路由/配置解析走 build 期，不在此覆盖）。
///
/// **默认构造是确定性的**（固定指纹 [`DETERMINISTIC_FINGERPRINT`] + MockClock
/// 冻结于 ms=1）：`next_conn_id()` 连发 N=64（及远超此数）恒不撞 IdGen 同毫秒
/// 配额臂，跨运行序列逐位可回放。**不要在调用方 crate 里写重试/catch_unwind
/// 重掷指纹的 helper**——配额风险已在构造侧消除；确需自定义时钟/指纹时改用
/// [`contract_test_context_with`]。
#[doc(hidden)]
pub fn contract_test_context(plugin_name: &'static str) -> PluginContext {
    contract_test_context_with(plugin_name, deterministic_test_clock(), DETERMINISTIC_FINGERPRINT)
}

/// 宏辅助：显式口子——自定义时钟与指纹（例如需要推进时钟验证跨毫秒序列、
/// 或复用生产指纹）。不传本变体即得确定性默认构造（见
/// [`contract_test_context`]）；指纹须避开 IdGen counter 基址 0xFFF 邻域的
/// 同毫秒 fail-closed 臂（见 `std_ext::id`）。
#[doc(hidden)]
pub fn contract_test_context_with(
    plugin_name: &'static str,
    clock: Arc<dyn Clock>,
    fingerprint: u64,
) -> PluginContext {
    PluginContext::new(
        plugin_name,
        Arc::new(FxScope::new()),
        clock,
        fingerprint,
        Arc::new(StdEnv),
        serde_json::json!({}),
        LogFacade::new(plugin_name, vec![]),
    )
}

/// 宏辅助：对插件实例执行契约断言（条款面 + lifecycle 三相）。
/// 断言失败 = panic，消息带 `[contract:<类型>]` 前缀可定位。
#[doc(hidden)]
pub fn assert_contract_for<P: Plugin>(plugin: &P, type_name: &str) {
    // ① 必选方法集可调；name 非空且稳定；version 非空。
    let name = plugin.name();
    assert!(!name.is_empty(), "[contract:{type_name}] name() 为空");
    assert_eq!(plugin.name(), name, "[contract:{type_name}] name() 不稳定（两次调用不同）");
    assert!(!plugin.version().is_empty(), "[contract:{type_name}] version() 为空");
    let _ = plugin.deps();
    let contract: &PluginContract = plugin.contract();

    // ② clauses 与 not_applicable 不得重叠；N/A 理由非空。
    for (clause, reason) in contract.not_applicable {
        assert!(
            !reason.trim().is_empty(),
            "[contract:{type_name}] 条款 {clause:?} 声明 N/A 但理由为空"
        );
        assert!(
            !contract.clauses.contains(clause),
            "[contract:{type_name}] 条款 {clause:?} 同时出现在 clauses 与 not_applicable"
        );
    }

    // ③ extra 键值非空。
    for (key, desc) in contract.extra {
        assert!(
            !key.is_empty() && !desc.is_empty(),
            "[contract:{type_name}] extra 条款键或值为空: ({key:?}, {desc:?})"
        );
    }

    // ④ lifecycle 三相可调且不 panic（Err 升级为 panic，fail-visible）。
    let lifecycle = plugin.lifecycle();
    let ctx = contract_test_context(name);
    lifecycle
        .init(&ctx)
        .unwrap_or_else(|e| panic!("[contract:{type_name}] lifecycle init 失败: {e}"));
    lifecycle
        .start(&ctx)
        .unwrap_or_else(|e| panic!("[contract:{type_name}] lifecycle start 失败: {e}"));
    lifecycle.stop().unwrap_or_else(|e| panic!("[contract:{type_name}] lifecycle stop 失败: {e}"));
}

/// L4 契约测试夹具：对插件类型执行全量契约断言（①-④，见
/// [`crate::contract_assert`] 模块文档）。
///
/// 插件类型须实现 `Default`（夹具自行构造实例）。
///
/// ```ignore
/// // 每协议 crate 的 tests/plugin_contract.rs：
/// use xray_proxy_blackhole::BlackholePlugin;
/// use xray_frame::assert_plugin_contract;
///
/// #[test]
/// fn plugin_contract_holds() {
///     assert_plugin_contract!(BlackholePlugin);
/// }
/// ```
#[macro_export]
macro_rules! assert_plugin_contract {
    ($plugin:ty) => {{
        let plugin = <$plugin as ::std::default::Default>::default();
        $crate::contract_assert::assert_contract_for(&plugin, ::std::any::type_name::<$plugin>());
    }};
}

// ── 行为夹具一：conn_id（坑约束 3）──

/// 宏辅助：断言 conn_id 序列满足坑约束 3——非零（UUIDv7 ver=7 位面恒非零；
/// 0 = 生成器未接线或被旁路）、严格递增（同指纹契约；唯一性由严格递增蕴含）。
#[doc(hidden)]
pub fn assert_conn_id_sequence<I: IntoIterator<Item = u128>>(name: &str, ids: I) {
    let ids: Vec<u128> = ids.into_iter().collect();
    assert!(!ids.is_empty(), "[conn-id:{name}] 序列为空（至少取 1 个 id）");
    for (i, id) in ids.iter().enumerate() {
        assert!(*id != 0, "[conn-id:{name}] 第 {} 个 id 为 0（生成器未接线或被旁路）", i + 1);
    }
    for (i, pair) in ids.windows(2).enumerate() {
        assert!(
            pair[1] > pair[0],
            "[conn-id:{name}] 第 {} 个 id 非单调递增：prev={} cur={}（同指纹契约：严格递增）",
            i + 2,
            pair[0],
            pair[1]
        );
    }
}

/// 宏辅助：从 ctx 连续取 `n` 个 [`PluginContext::next_conn_id`] 并跑
/// [`assert_conn_id_sequence`]（坑约束 3 的 L4 执行面）。
#[doc(hidden)]
pub fn assert_conn_id_present_for(ctx: &PluginContext, n: usize, name: &str) {
    assert!(n > 0, "[conn-id:{name}] 取用数必须大于 0");
    let ids: Vec<u128> = (0..n).map(|_| ctx.next_conn_id()).collect();
    assert_conn_id_sequence(name, ids);
}

/// L4 行为夹具：经 `PluginContext::next_conn_id()` 连续取 `n` 个 id，断言
/// 非零、单进程内唯一、单调不倒退（坑约束 3）。
///
/// ```ignore
/// // 协议 crate 的 tests/conn_id.rs：
/// use xray_frame::assert_conn_id_present;
///
/// #[test]
/// fn conn_ids_are_unique_and_monotonic() {
///     let ctx = /* 插件测试上下文 */;
///     assert_conn_id_present!(ctx, 64);
/// }
/// ```
#[macro_export]
macro_rules! assert_conn_id_present {
    ($ctx:expr, $n:expr) => {
        $crate::contract_assert::assert_conn_id_present_for(&$ctx, $n, ::std::stringify!($ctx));
    };
}

// ── 行为夹具二：deadline（坑约束 2）──

/// 宏辅助：验证 deadline 入口真实生效（坑约束 2，须在 tokio runtime 内 await）。
///
/// 双入口 × 双场景：
/// - 正向：`work()` 经 [`with_deadline`] 与 [`HandshakeDeadline::guard`] 都必须 在 `d` 内完成 →
///   Ok；
/// - 负向（夹具自造 pending 任务）：永不完成的任务必须被掐成 `Err(Elapsed)`， 且墙钟真实等待 ≥
///   `d`（真超时必红——提前返回 = 超时形同虚设）。
#[doc(hidden)]
pub async fn assert_deadline_effective_for<T, F, Fut>(name: &str, d: Duration, work: F)
where
    F: Fn() -> Fut,
    Fut: Future<Output = T>,
{
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);

    // 正向①：with_deadline 入口——期限内完成 → Ok。
    assert!(
        with_deadline(Arc::clone(&clock), work(), d).await.is_ok(),
        "[deadline:{name}] 期限内未完成（deadline 判负了合法工作）：d={d:?}"
    );

    // 正向②：HandshakeDeadline::guard 入口同构。
    let guard = HandshakeDeadline::new(d, d);
    assert!(
        guard.guard(Arc::clone(&clock), work()).await.is_ok(),
        "[deadline:{name}] guard 入口期限内未完成：d={d:?}"
    );

    // 负向①：pending 任务必被掐成 Err(Elapsed)，且真实等待 ≥ d（真超时必红）。
    let t0 = Instant::now();
    let timed_out: Result<T, _> =
        with_deadline(Arc::clone(&clock), std::future::pending(), d).await;
    assert!(
        timed_out.is_err(),
        "[deadline:{name}] 永不完成的任务未被 deadline 掐断（超时形同虚设）"
    );
    let waited = t0.elapsed();
    assert!(waited >= d, "[deadline:{name}] 超时在 d={d:?} 前返回（实际 {waited:?}）——假超时");

    // 负向②：guard 入口同构。
    let t0 = Instant::now();
    let timed_out: Result<T, _> = guard.guard(clock, std::future::pending()).await;
    assert!(timed_out.is_err(), "[deadline:{name}] guard 入口未掐断 pending 任务（超时形同虚设）");
    let waited = t0.elapsed();
    assert!(waited >= d, "[deadline:{name}] guard 入口超时早于 d={d:?}（实际 {waited:?}）——假超时");
}

/// L4 行为夹具：deadline 语义在当前 runtime 真实生效（坑约束 2）。
/// 展开为 [`assert_deadline_effective_for`] 调用，**调用方须 `.await`**（即在
/// async 上下文/tokio runtime 内）。
///
/// ```ignore
/// // 协议 crate 的 tests/handshake.rs：
/// #[tokio::test]
/// async fn handshake_deadline_holds() {
///     xray_frame::assert_deadline_effective!(
///         Duration::from_millis(200),
///         || async { /* 插件真实握手步骤（应在此窗口内完成） */ }
///     ).await;
/// }
/// ```
#[macro_export]
macro_rules! assert_deadline_effective {
    ($d:expr, $work:expr) => {
        $crate::contract_assert::assert_deadline_effective_for(::std::stringify!($work), $d, $work)
    };
}

// ── 行为夹具三：日志字段（坑约束 3/10/11）──

/// 宏内部：单条捕获事件（target + message 全文；结构化断言面，不受 fmt
/// 输出格式影响）。
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct CapturedLog {
    /// 事件 target（LogFacade 契约上为 `xray_frame::<域>`）。
    pub target: String,
    /// message 字段全文。
    pub message: String,
}

/// 宏内部：最小捕获订阅者（线程局部 `set_default` 可捕获——emit 面是运行期
/// 手工 Metadata 分发，无 callsite interest 缓存，捕获确定性成立）。
#[doc(hidden)]
#[derive(Clone, Default)]
pub struct CaptureSubscriber {
    events: Arc<Mutex<Vec<CapturedLog>>>,
}

struct CaptureVisitor {
    message: String,
}

impl tracing::field::Visit for CaptureVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_owned();
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        }
    }
}

impl tracing::Subscriber for CaptureSubscriber {
    fn enabled(&self, _meta: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = CaptureVisitor { message: String::new() };
        event.record(&mut visitor);
        self.events.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(CapturedLog {
            target: event.metadata().target().to_owned(),
            message: visitor.message,
        });
    }
}

/// 宏辅助：对捕获事件集断言（坑约束 3/10/11）——存在一条
/// `target == xray_frame::<domain>` 的事件、其 message 含四元组全文、
/// 全部事件的 target/message 均不含 secrets 表内字符串。
#[doc(hidden)]
pub fn assert_log_fields_in_captures(
    captured: &[CapturedLog],
    domain: &str,
    conn_id: &str,
    stage: &str,
    peer: &str,
    dest: &str,
    secrets: &[&str],
) {
    assert!(!captured.is_empty(), "[log-fields:{domain}] 捕获为空——订阅者未接线或 emit 未发生");
    for (key, value) in [("conn_id", conn_id), ("stage", stage), ("peer", peer), ("dest", dest)] {
        assert!(
            !value.is_empty(),
            "[log-fields:{domain}] 字段 {key} 为空——空串 contains 恒真，断言失真"
        );
    }
    let wanted = format!("xray_frame::{domain}");
    assert!(
        captured.iter().any(|event| {
            event.target == wanted
                && event.message.contains(conn_id)
                && event.message.contains(stage)
                && event.message.contains(peer)
                && event.message.contains(dest)
        }),
        "[log-fields:{domain}] 四元组未完整出现在 target={wanted} 的事件里（captured={captured:?}）"
    );
    for secret in secrets {
        assert!(
            !captured
                .iter()
                .any(|event| event.message.contains(secret) || event.target.contains(secret)),
            "[log-fields:{domain}] secret 泄漏进输出：掩码表内的 {secret:?} 可见于捕获（captured={captured:?}）"
        );
    }
}

/// 宏辅助：emit 全流程执行面——构造带 secrets 表的门面，发出含四元组的
/// 单条 info，经线程局部捕获后跑 [`assert_log_fields_in_captures`]。
#[doc(hidden)]
pub fn assert_log_fields_emitted(
    domain: &str,
    conn_id: &str,
    stage: &str,
    peer: &str,
    dest: &str,
    secrets: &[&str],
) {
    let sink = CaptureSubscriber::default();
    let facade = LogFacade::new(domain, secrets.iter().map(|s| Arc::from(*s)).collect());
    {
        let _guard = tracing::subscriber::set_default(sink.clone());
        facade.info(format!("conn_id={conn_id} stage={stage} peer={peer} dest={dest}"));
    }
    let captured = sink.events.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
    assert_log_fields_in_captures(&captured, domain, conn_id, stage, peer, dest, secrets);
}

/// L4 行为夹具：经 `LogFacade::emit` 发出带 conn_id/stage/peer/dest 的消息，
/// 断言 target 前缀 `xray_frame::`、四元组均在输出里、secrets 表内字符串
/// 不可见（坑约束 3/10/11）。
///
/// ```ignore
/// // 协议 crate 的 tests/log.rs：
/// use xray_frame::assert_log_fields;
///
/// #[test]
/// fn log_carries_quadruple_and_masks_secrets() {
///     assert_log_fields!(
///         domain: "blackhole", conn_id: 0x1234, stage: "Handshake",
///         peer: "203.0.113.7:443", dest: "example.com:80",
///         secrets: ["s3cret"]
///     );
/// }
/// ```
#[macro_export]
macro_rules! assert_log_fields {
    (domain: $domain:expr, conn_id: $conn_id:expr, stage: $stage:expr,
     peer: $peer:expr, dest: $dest:expr $(, secrets: [$($secret:expr),* $(,)?])? $(,)?) => {{
        let secrets: &[&str] = &[$($($secret),*)?];
        $crate::contract_assert::assert_log_fields_emitted(
            $domain,
            &::std::format!("{}", $conn_id),
            $stage,
            $peer,
            $dest,
            secrets,
        );
    }};
}

// ── 行为夹具四：池纪律（坑约束 4/9）──

/// 宏辅助：断言池读数已配平（借还闭环）：`borrowed` 归零且零溢出丢弃。
#[doc(hidden)]
pub fn assert_pool_settled(name: &str, metrics: PoolMetrics) {
    assert!(
        metrics.borrowed == 0,
        "[pool-discipline:{name}] 借还不配平：borrowed={} 应归零（dropped_overflow={}）",
        metrics.borrowed,
        metrics.dropped_overflow
    );
    assert!(
        metrics.dropped_overflow == 0,
        "[pool-discipline:{name}] 溢出丢弃非零：dropped_overflow={}（借还闭环内不该丢缓冲）",
        metrics.dropped_overflow
    );
}

/// 宏辅助：借 `borrows` 块 → 中途记账核对（borrowed == borrows）→ 全部归还
/// （RAII Drop）→ 终态跑 [`assert_pool_settled`]。
#[doc(hidden)]
pub fn assert_pool_discipline_for<B: BufferPool>(
    pool: &ManagedBufferPool<B>,
    borrows: usize,
    name: &str,
) {
    assert!(borrows > 0, "[pool-discipline:{name}] borrows 必须大于 0");
    let initial = pool.metrics();
    assert!(
        initial.borrowed == 0,
        "[pool-discipline:{name}] 传入池已有 {} 块在外（脏池，断言基线不成立）",
        initial.borrowed
    );
    let mut handles = Vec::with_capacity(borrows);
    for i in 0..borrows {
        handles.push(pool.acquire(64).unwrap_or_else(|e| {
            panic!("[pool-discipline:{name}] 第 {} 块 acquire 失败: {e}", i + 1)
        }));
    }
    let mid = pool.metrics();
    assert!(
        mid.borrowed == borrows,
        "[pool-discipline:{name}] 借出记账未生效：borrowed={}（应为 {borrows}）",
        mid.borrowed
    );
    drop(handles);
    assert_pool_settled(name, pool.metrics());
}

/// L4 行为夹具：借 `n` 块 → 还 `n` 块 → `PoolMetrics` 终态配平
/// （`borrowed=0` 且 `dropped_overflow=0`；坑约束 4/9）。借还不配平必红。
///
/// ```ignore
/// // 协议 crate 的 tests/pool.rs：
/// use xray_frame::{pool::ManagedBufferPool, assert_pool_discipline};
///
/// #[test]
/// fn pool_borrows_balance() {
///     let pool = ManagedBufferPool::new(/* 内层 BufferPool */ todo!(), 8, 8);
///     assert_pool_discipline!(pool, 4);
/// }
/// ```
#[macro_export]
macro_rules! assert_pool_discipline {
    ($pool:expr, $n:expr) => {
        $crate::contract_assert::assert_pool_discipline_for(&$pool, $n, ::std::stringify!($pool));
    };
}
