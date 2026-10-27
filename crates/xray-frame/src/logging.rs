//! 装配层日志唯一入口（P0-7；坑约束 #10/#11）。
//!
//! 纪律（udf logx 模块注释同源）：**装配层一次 init，插件层禁调**；插件日志
//! 只经 [`LogFacade`]——target 构造期钉死为 `xray_frame::<域>`，emit 先过
//! `mask_secrets` 再发射，调用方无法绕过掩码或自选 target。
//!
//! # 运行期 target 的分发通路（实现注记）
//!
//! `tracing::event!` 的 callsite 是编译期 const（tracing-0.1.44 macros.rs:885
//! `static __CALLSITE`，target/level 必须常量——E0435 实证），运行期插件域
//! 进不了宏。故 emit 走手工 Metadata 分发：target 泄漏为 `&'static str`，
//! 按 level 泄漏一份 `Metadata<'static>`（每门面 ≤5 份，有界），经
//! `Dispatch::event` 发射——事件 target 真实为 `xray_frame::<域>`，
//! `RUST_LOG=xray_frame::<域>=level` 按域过滤可用。代价：无静态 interest
//! 快路径（每次过 `event_enabled`，由订阅者级别过滤兜底）。
//!
//! B6 取证（2026-10-23 `cargo tree -p xray-frame -i log`）：log v0.4.33 经
//! udf-skeleton-infra（log feature → tracing-log → tracing-subscriber）已在
//! 依赖树内，无新增第三方。init 单例冲突面按 PM 拍板：**装配点由 xray-frame
//! 统一收口**（xray-app-log 后续改为经 logx 初始化，P1-10 联动）。
//! 文件 sink 的路径 resolver 注入随 P3 配置链落地（v0.1 只走 env init，
//! 不触文件 sink，不落包目录）。

use std::{
    collections::HashMap,
    fmt,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU8, Ordering},
    },
};

use skeleton_infra::logx::mask_secrets;

/// 手工 FieldSet 的引导 callsite：只贡献一个稳定地址当 Identifier 键
/// （等价 `identify_callsite!(&ANCHOR)`，tracing 未 re-export 该宏，直构
/// Identifier——其字段 pub 是宏静态构造的官方通道）。本 callsite 从不注册，
/// interest/metadata 不会被订阅者查询；真正分发的元数据是各门面按 level
/// 泄漏的运行期 Metadata。
static ANCHOR: AnchorCallsite = AnchorCallsite;
struct AnchorCallsite;

impl tracing::callsite::Callsite for AnchorCallsite {
    fn set_interest(&self, _: tracing::subscriber::Interest) {}

    fn metadata(&self) -> &tracing::Metadata<'static> {
        &ANCHOR_METADATA
    }
}

/// 引导 callsite 的常备元数据（自身字段面，永不分发；只被查询的话才初始化）。
static ANCHOR_METADATA: std::sync::LazyLock<tracing::Metadata<'static>> =
    std::sync::LazyLock::new(|| {
        let fields =
            tracing::field::FieldSet::new(&["message"], tracing::callsite::Identifier(&ANCHOR));
        tracing::Metadata::new(
            "xray_frame_anchor",
            "xray_frame_anchor",
            tracing::Level::TRACE,
            None,
            None,
            None,
            fields,
            tracing::metadata::Kind::EVENT,
        )
    });

/// 域规范日志门面：target = `xray_frame::<域>`（对齐 udf log-embed 纪律
/// `skeleton::<域>`）；域 = 插件名或 infra 域（assembly/registry/context）。
///
/// 手写 `Clone`（nn8os 2b）：spawn 进 FxScope 的任务持不得引用 ctx——发射前
/// 克隆门面捕获进 'static future。target/掩码表同源克隆，emit 输出与原门面
/// 逐字一致；metas 分发缓存不共享（std Mutex 无 Clone）——克隆体持空缓存，
/// 首次 emit 自行重建（有界：每门面 ≤5 份）。
pub struct LogFacade {
    /// 构造期钉死并泄漏为 'static（`Metadata<'static>` 的 target 参数要求）；
    /// 每门面一次，量级 = 插件数。
    target: &'static str,
    /// 装配期注入的掩码表（进出站密钥等）；emit 面强制过滤。
    secrets: Vec<Arc<str>>,
    /// 按 level 缓存的运行期分发元数据（每门面 ≤5 份，有界）。
    metas: Mutex<HashMap<u8, &'static tracing::Metadata<'static>>>,
}

impl Clone for LogFacade {
    fn clone(&self) -> Self {
        Self {
            target: self.target,
            secrets: self.secrets.clone(),
            // 分发缓存不共享（std Mutex 无 Clone）：克隆体空缓存，首 emit 重建。
            metas: Mutex::new(HashMap::new()),
        }
    }
}

impl LogFacade {
    pub fn new(domain: &str, secrets: Vec<Arc<str>>) -> Self {
        Self {
            target: Box::leak(format!("xray_frame::{domain}").into_boxed_str()),
            secrets,
            metas: Mutex::new(HashMap::new()),
        }
    }

    fn metadata_for(&self, level: tracing::Level) -> &'static tracing::Metadata<'static> {
        let key = match level {
            tracing::Level::ERROR => 0,
            tracing::Level::WARN => 1,
            tracing::Level::INFO => 2,
            tracing::Level::DEBUG => 3,
            tracing::Level::TRACE => 4,
        };
        let mut metas = self.metas.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        metas.entry(key).or_insert_with(|| {
            let fields =
                tracing::field::FieldSet::new(&["message"], tracing::callsite::Identifier(&ANCHOR));
            Box::leak(Box::new(tracing::Metadata::new(
                "xray_frame_emit",
                self.target,
                level,
                None,
                None,
                None,
                fields,
                tracing::metadata::Kind::EVENT,
            )))
        })
    }

    /// 唯一输出面：message 先过 `mask_secrets` 再发射，target 强制覆写。
    pub fn emit(&self, level: tracing::Level, message: impl fmt::Display) {
        let secret_refs: Vec<&str> = self.secrets.iter().map(|s| s.as_ref()).collect();
        let masked = mask_secrets(&message.to_string(), &secret_refs);
        let metadata = self.metadata_for(level);
        let message_field =
            metadata.fields().field("message").expect("message field declared in emit metadata");
        let values = [(&message_field, Some(&masked as &dyn tracing::field::Value))];
        let valueset = metadata.fields().value_set(&values);
        tracing::dispatcher::get_default(|dispatch| {
            dispatch.event(&tracing::Event::new(metadata, &valueset));
        });
    }

    pub fn error(&self, message: impl fmt::Display) {
        self.emit(tracing::Level::ERROR, message);
    }

    pub fn warn(&self, message: impl fmt::Display) {
        self.emit(tracing::Level::WARN, message);
    }

    pub fn info(&self, message: impl fmt::Display) {
        self.emit(tracing::Level::INFO, message);
    }

    pub fn debug(&self, message: impl fmt::Display) {
        self.emit(tracing::Level::DEBUG, message);
    }
}

/// 装配层 init（插件层禁调——udf 纪律「装配层一次 init，插件层禁」）。
/// 兜底恒含 `skeleton=off` 预设；重复调用 `Err(AlreadyInit)`（禁静默覆盖）。
pub fn init_from_env(
    default_level: log::LevelFilter,
) -> Result<(), skeleton_infra::logx::AlreadyInit> {
    skeleton_infra::logx::init_tracing_from_env(default_level)
}

// =========================================================================
// 热路径门面（面 4 · 能力收敛方案 §2 面 4）：栈缓冲零分配
// =========================================================================
//
// 派生三段式（ADR-1）：
// - **udf 基件**：`skeleton_infra::logx::{ChannelRegistry, ChannelSink}`（三通道 分发 + 默认静默 +
//   丢弃计数）、`logx::mask_secrets`（掩码）。
// - **派生方式**：**组合包装**（udf 分发件 + 调用方栈缓冲）+ 新类型 （[`HotBuf`] /
//   [`HotLog`]）。udf `ChannelSink` 已是 trait，**不再扩 trait**。
// - **主仓消费**：transport 热路径豁免点（bridge / record_framer / finalmask / udp hub / splithttp
//   upload_queue 等）与裸 `debug!` 点。
//
// **零分配论证（防回归，改本段前先读）**：
// 1. **级别判定在格式化之前** → 未命中级别时零成本（连格式化都不发生）。
// 1b. **判定与 metadata 缓存读全程无锁**（bd 9doy9）：级别上限存 `AtomicU8`
//    （Relaxed 单变量开关），metadata 走 `OnceLock` 一次性整表——快路径零锁
//    零分配，锁竞争面不存在。
// 2. **格式化写入调用方栈上的 [`HotBuf`]** → 零堆分配（`[u8; N]` 定长栈阵）。
// 3. **掩码**：热路径默认无密钥（`mask_secrets` 需 `String` 分配）→ 热路径门面
//    **不接掩码表**；有密钥时调用方退回 [`LogFacade::emit`] 慢路径（安全 > 微优化）。
// 4. **metadata 缓存复用**：每门面 ≤5 份（按 level 索引的定长数组，非 HashMap），
//    有界；首次构造泄漏一份（`Box::leak`），之后零分配。
// 5. **每包不得 clone 门面** → 调用点取 `&*STATIC`（静态门面，`static` 构造）。

/// 栈上固定容量缓冲（零堆分配；溢出截断并计数）。
///
/// 写入语义：能放下则整段写入；放不下则写入**能放下的最长前缀**（按字符
/// 边界切，避免切碎多字节字符），置 [`truncated`](Self::truncated) 标记并停止
/// 后续写入。
pub struct HotBuf<const N: usize = 256> {
    buf: [u8; N],
    len: usize,
    truncated: bool,
}

impl<const N: usize> HotBuf<N> {
    /// 新建空缓冲（栈上定长，零堆分配）。
    pub const fn new() -> Self {
        Self { buf: [0u8; N], len: 0, truncated: false }
    }

    /// 借用格式化写入（零堆分配）；溢出时截断并置标记。
    pub fn write_fmt(&mut self, args: fmt::Arguments) -> &mut Self {
        // 写失败（溢出）已由 `truncated` 记录，此处吞掉 `fmt::Error`（不是错误
        // 通道：截断是可观测的降级，不是失败）。
        let _ = fmt::Write::write_fmt(self, args);
        self
    }

    /// 缓冲内容（始终合法 UTF-8——写入单元是完整 `&str` 或其字符边界前缀）。
    pub fn as_str(&self) -> &str {
        // 写入面保证只写合法 UTF-8 字节；`from_utf8` 失败即内部不变量被破坏
        // （fail-visible，不静默替换字符）。
        std::str::from_utf8(&self.buf[..self.len]).expect("HotBuf 只写合法 UTF-8 字节")
    }

    /// 是否发生过截断。
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// 复位（复用缓冲，避免重新构造）。
    pub fn clear(&mut self) {
        self.len = 0;
        self.truncated = false;
    }
}

impl<const N: usize> Default for HotBuf<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> fmt::Write for HotBuf<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let remaining = N.saturating_sub(self.len);
        if s.len() <= remaining {
            self.buf[self.len..self.len + s.len()].copy_from_slice(s.as_bytes());
            self.len += s.len();
            return Ok(());
        }
        // 截断：写入能放下的最长前缀（字符边界内切，避免切碎多字节字符）。
        let mut end = remaining.min(s.len());
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        self.buf[self.len..self.len + end].copy_from_slice(&s.as_bytes()[..end]);
        self.len += end;
        self.truncated = true;
        Err(fmt::Error)
    }
}

/// 热路径日志门面（静态持有；**每包不得 clone**，取 `&*STATIC` 借用）。
///
/// 目标 = 调用方给定的 target（域规范 `xray_frame::<域>`，或红线站点保留的
/// 原 target）。
pub struct HotLog {
    /// 分发 target（`Metadata<'static>` 要求 `&'static str`）。
    target: &'static str,
    /// 本地级别上限（存 filter 序数，无锁读）。
    ///
    /// `Relaxed` 理由：单变量独立开关，不借它发布任何其他内存（store 端无
    /// 伴随写入需要被 load 端看见）；「level 变更后后续判断立即生效」由原子
    /// 变量的修改可见性保证——store 之后同变量的 load 读到的必然是新值。
    max_level: AtomicU8,
    /// 按 level 缓存的分发元数据（一次性整表 5 份，读路径无锁）。
    ///
    /// `'static` 来源说明（例外，非疏漏）：`tracing::Event::new` 要求
    /// `&'static Metadata<'static>`，运行期 target 的元数据无编译期静态件可挂
    /// → 只能 `'static` 化。本门面按 (门面, level) 各缓存一份，**泄漏量有界**：
    /// 稳态 = 5 × 门面数；首次填充竞态时败者构造的副本整体丢弃（引用数组
    /// drop 不回收泄漏件）→ 上界 5 × (1 + 首填并发线程数) × 门面数，仍与门面
    /// 数成正比、非无界增长；与同文件既有 [`LogFacade::metadata_for`] 同款做法。
    ///
    /// 无锁论证：快路径 [`OnceLock::get`] 是单次原子 load；泄漏件的发布同步
    /// 由 std 内部 Release/Acquire 完成（填充完成后才置 COMPLETE，读方看到的
    /// 必然是完整构造的 Metadata），读方不持任何锁（bd 9doy9：原 Mutex 每次
    /// 查缓存加解锁是热路径固定开销，锁竞争下塌缩）。
    metas: OnceLock<[&'static tracing::Metadata<'static>; 5]>,
}

impl HotLog {
    /// 静态构造（target 直接给定 → 可用于 `static HOT_LOG: HotLog = ...`）。
    pub const fn with_target(target: &'static str) -> Self {
        Self {
            target,
            max_level: AtomicU8::new(level_filter_rank(tracing::level_filters::LevelFilter::TRACE)),
            metas: OnceLock::new(),
        }
    }

    /// 域构造（target = 调用方给定的域字面量，如 `"xray_frame::transport"`）。
    ///
    /// target 必须是**调用方持有的 `'static` 字面量**（禁运行期拼接 + 泄漏：
    /// `tracing::Metadata` 的 target 契约是 `&'static str`，运行期拼 target 只能
    /// 靠泄漏制造 `'static` → 本门面改要求字面量，零泄漏）。
    pub fn new(target: &'static str) -> Self {
        Self::with_target(target)
    }

    /// 本地级别上限（默认 TRACE = 不本地过滤，只由订阅者兴趣决定）。
    pub fn with_max_level(self, level: tracing::level_filters::LevelFilter) -> Self {
        // Relaxed：见 max_level 字段注释——单变量独立开关，store 后续 load
        // 立即可见（原子变量修改可见性），无伴随数据需同步。
        self.max_level.store(level_filter_rank(level), Ordering::Relaxed);
        self
    }

    /// 分发 target（只读）。
    pub fn target(&self) -> &'static str {
        self.target
    }

    /// 级别是否放行（本地上限判定；**在格式化之前**调用 → 未命中零成本）。
    pub fn level_allows(&self, level: tracing::Level) -> bool {
        // 序号口径：level 序号 ERROR=0..TRACE=4；filter 序号 OFF=0..TRACE=5
        // （filter 比同级别大 1）→ `level_rank < filter_rank` 即"级别不放行"。
        // Relaxed：见 max_level 字段注释。
        level_rank(level) < self.max_level.load(Ordering::Relaxed)
    }

    /// 订阅者是否对该级别感兴趣（本地上限 + 订阅者兴趣）。
    ///
    /// 调用方据此**先过滤后格式化**：未命中时连 [`HotBuf::write_fmt`] 都不发生
    /// → 零分配。
    pub fn enabled(&self, level: tracing::Level) -> bool {
        if !self.level_allows(level) {
            return false;
        }
        let metadata = self.metadata_for(level);
        tracing::dispatcher::get_default(|dispatch| dispatch.enabled(metadata))
    }

    /// 发射（复用缓存 metadata；消息取自栈缓冲 → 零堆分配）。
    pub fn log<const N: usize>(&self, level: tracing::Level, buf: &HotBuf<N>) {
        if !self.enabled(level) {
            return;
        }
        self.emit(level, buf.as_str());
    }

    /// 便捷发射：内部临时栈缓冲（常量栈空间，非每包分配）。
    pub fn debug_fmt(&self, args: fmt::Arguments) {
        if !self.enabled(tracing::Level::DEBUG) {
            return;
        }
        let mut buf = HotBuf::<256>::new();
        buf.write_fmt(args);
        self.emit(tracing::Level::DEBUG, buf.as_str());
    }

    /// 内部分发（消息已是 `&str`，零分配）。
    fn emit(&self, level: tracing::Level, message: &str) {
        let metadata = self.metadata_for(level);
        let field =
            metadata.fields().field("message").expect("message field declared in hot log metadata");
        let values = [(&field, Some(&message as &dyn tracing::field::Value))];
        let valueset = metadata.fields().value_set(&values);
        tracing::dispatcher::get_default(|dispatch| {
            dispatch.event(&tracing::Event::new(metadata, &valueset));
        });
    }

    /// 按 level 取（并缓存）分发元数据；一次性整表 5 份，读路径无锁。
    fn metadata_for(&self, level: tracing::Level) -> &'static tracing::Metadata<'static> {
        let key = level_rank(level) as usize;
        // 快路径：OnceLock::get 单次原子 load（发布同步论证见 metas 字段注释）。
        if let Some(metas) = self.metas.get() {
            return metas[key];
        }
        // 慢路径：首次填充整表；竞态败者的副本整体丢弃（泄漏上界见字段注释）。
        self.metas.get_or_init(|| Self::build_metas(self.target))[key]
    }

    /// 整表构造 5 份按 level 泄漏的分发元数据（target 同源，内容不可变）。
    fn build_metas(target: &'static str) -> [&'static tracing::Metadata<'static>; 5] {
        std::array::from_fn(|rank| {
            let fields =
                tracing::field::FieldSet::new(&["message"], tracing::callsite::Identifier(&ANCHOR));
            let meta: &'static tracing::Metadata<'static> =
                Box::leak(Box::new(tracing::Metadata::new(
                    "xray_frame_hot_emit",
                    target,
                    level_from_rank(rank),
                    None,
                    None,
                    None,
                    fields,
                    tracing::metadata::Kind::EVENT,
                )));
            meta
        })
    }
}

/// 级别序号（显式枚举，不依赖 `tracing::Level` 的 `Ord` 语义）。
fn level_rank(level: tracing::Level) -> u8 {
    match level {
        tracing::Level::ERROR => 0,
        tracing::Level::WARN => 1,
        tracing::Level::INFO => 2,
        tracing::Level::DEBUG => 3,
        tracing::Level::TRACE => 4,
    }
}

/// 级别过滤上限的序号（`OFF` = 0 = 全过滤）。
const fn level_filter_rank(level: tracing::level_filters::LevelFilter) -> u8 {
    match level {
        tracing::level_filters::LevelFilter::OFF => 0,
        tracing::level_filters::LevelFilter::ERROR => 1,
        tracing::level_filters::LevelFilter::WARN => 2,
        tracing::level_filters::LevelFilter::INFO => 3,
        tracing::level_filters::LevelFilter::DEBUG => 4,
        tracing::level_filters::LevelFilter::TRACE => 5,
    }
}

/// 序号反查级别（`build_metas` 整表构造用；序号口径同 [`level_rank`]）。
fn level_from_rank(rank: usize) -> tracing::Level {
    match rank {
        0 => tracing::Level::ERROR,
        1 => tracing::Level::WARN,
        2 => tracing::Level::INFO,
        3 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    }
}
