//! 红线受控入口（面 5 · 能力收敛方案 §2 面 5）：数据面红线站点的唯一登记
//! 与执行面。
//!
//! 派生三段式（ADR-1）：**本面是六面中唯一"udf 不涉"的一面**——红线 = Xray /
//! Go 兼容专属语义，udf 零 Xray 语义，装不下也不该装（已举证）。
//! - **派生方式**：xray-frame 自有件（站点穷举 + 受控执行入口 + 台账）。
//! - **主仓消费**：`crates/xray-proxy-vless/src/encryption/vision_conn.rs` （裸
//!   `tracing::event!`）、`crates/xray-core/src/inbound.rs`（vision 装配 spawn ×2）。
//!
//! **红线本体不动**（vision gate / DIRECT 切换 / splice 语义零改动）：本面只治理
//! **调用形态**——让主仓红线站点不再需要逐 crate 各写一份 `#[allow]` 台账。
//!
//! 防滥用三道闸：
//! 1. **站点穷举**：逃逸口只接受 [`RedlineSite`] 枚举变体 → 逃逸口不可私开。
//! 2. **CI 门核对调用集合**：主仓内 `redline::spawn_unchecked` / `redline::event` 的调用文件集合 ⊆
//!    台账期望文件集合（未登记即红，见 `tests/redline_sites.rs`）。
//! 3. **命名示警**：`spawn_unchecked` 刻意带 `unchecked` + 文档首行写明"仅台账 内站点"。

use std::{
    fmt,
    future::Future,
    sync::atomic::{AtomicU64, Ordering},
};

/// 红线站点（穷举：新增站点必须在此加变体 → 逃逸口不可私开）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RedlineSite {
    /// vision splice 装配任务（core inbound；坑约束 ⑫ 数据面热路径零改动）。
    VisionSpliceSpawn,
    /// vision 数据面错误事件（vless vision_conn；坑约束 ⑫）。
    VisionSpliceEvent,
}

impl RedlineSite {
    /// 站点 id（台账键）。
    pub fn id(self) -> &'static str {
        match self {
            Self::VisionSpliceSpawn => "vision.splice.spawn",
            Self::VisionSpliceEvent => "vision.splice.event",
        }
    }

    /// 单行理由（进台账与 CI 断言；**禁空串**）。
    pub fn reason(self) -> &'static str {
        match self {
            Self::VisionSpliceSpawn => {
                "vision splice 装配任务：改挂载即改数据面（双 revert 史实），受控逃逸口保留原 spawn 语义"
            },
            Self::VisionSpliceEvent => {
                "vision 数据面读错误事件：裸 tracing::event! 绕过 crate 级宏禁令，受控入口保留原 target/level"
            },
        }
    }

    /// 对应坑约束条款号（台账交叉引用）。
    pub fn clause(self) -> &'static str {
        match self {
            Self::VisionSpliceSpawn | Self::VisionSpliceEvent => "12",
        }
    }

    /// 期望的主仓文件（CI 门核对调用集合；路径相对仓库根）。
    pub fn expected_file(self) -> &'static str {
        match self {
            Self::VisionSpliceSpawn => "crates/xray-core/src/inbound.rs",
            Self::VisionSpliceEvent => "crates/xray-proxy-vless/src/encryption/vision_conn.rs",
        }
    }

    /// 台账序号（计数数组下标；与 [`SITES`] 序一致）。
    fn ordinal(self) -> usize {
        match self {
            Self::VisionSpliceSpawn => 0,
            Self::VisionSpliceEvent => 1,
        }
    }
}

/// 红线站点台账（供 CI 门核对调用集合）。
pub const SITES: &[RedlineSite] = &[RedlineSite::VisionSpliceSpawn, RedlineSite::VisionSpliceEvent];

/// 台账规模上限（PM 拍板：只登记**真正使用框架红线逃逸口**的站点，枚举不随
/// 迁移增长；超限 = 判据失效 → 编译期拦）。
const _: () = assert!(SITES.len() <= 12, "红线站点台账超上限：需重判「穷举枚举」形态");

/// 各站点逃逸 spawn 计数（观测面：谁在用逃逸口、用了多少次）。
static SPAWN_COUNTERS: [AtomicU64; SITES.len()] = [const { AtomicU64::new(0) }; SITES.len()];

/// 受控逃逸口（**仅台账内站点可用**；函数本体在 xray-frame → 主仓 crate 级
/// `tokio::spawn` 禁用条目不命中该站点）。
///
/// 语义：与裸 `tokio::spawn` **逐字等价**（同 spawn 语义、同返回值），只多一
/// 次计数（观测面）。
#[allow(
    clippy::disallowed_methods,
    reason = "红线受控逃逸口：站点穷举登记于 SITES（CI 门核对调用集合）；主仓改调本函数即不命中其 crate 级 tokio::spawn 禁用条目"
)]
pub fn spawn_unchecked<T>(
    site: RedlineSite,
    fut: impl Future<Output = T> + Send + 'static,
) -> tokio::task::JoinHandle<T>
where
    T: Send + 'static,
{
    SPAWN_COUNTERS[site.ordinal()].fetch_add(1, Ordering::Relaxed);
    tokio::spawn(fut)
}

/// 某站点的逃逸 spawn 累计次数（观测面）。
pub fn spawn_count(site: RedlineSite) -> u64 {
    SPAWN_COUNTERS[site.ordinal()].load(Ordering::Relaxed)
}

/// 按级别分派到字面量 level 的事件臂（`tracing::event!` 的 level 位要求
/// const；target 同理 → 宏展开点必须带字面量）。
macro_rules! site_event {
    ($target:literal, $level:expr, $args:expr) => {
        match $level {
            tracing::Level::ERROR => {
                tracing::event!(target: $target, tracing::Level::ERROR, "{}", $args);
            },
            tracing::Level::WARN => {
                tracing::event!(target: $target, tracing::Level::WARN, "{}", $args);
            },
            tracing::Level::INFO => {
                tracing::event!(target: $target, tracing::Level::INFO, "{}", $args);
            },
            tracing::Level::DEBUG => {
                tracing::event!(target: $target, tracing::Level::DEBUG, "{}", $args);
            },
            tracing::Level::TRACE => {
                tracing::event!(target: $target, tracing::Level::TRACE, "{}", $args);
            },
        }
    };
}

/// 受控 raw 事件（替代主仓裸 `tracing::event!`）。
///
/// **事实依据**：`disallowed_macros` 对 proc-macro 的 `#[allow]` 无效
/// （allow 属性挂在调用点，管不到宏展开体）→ 裸 `tracing::event!` 无法靠
/// `#[allow]` 消警 → 只能走**函数式入口**（本函数）。
///
/// target 由站点钉死（保原 target → 外部日志订阅者的过滤串不变）；level 与
/// 消息由调用方给（消息走 `fmt::Arguments`，格式化在发射点发生）。
///
/// **实现注记**：`tracing::event!` 的 callsite 是编译期常量（target 与 level
/// 都必须是 const）→ 运行期 level 只能按级别分派到字面量 level 的宏臂（宏内
/// target 仍是字面量）→ 无运行期元数据构造、无泄漏。
pub fn event(site: RedlineSite, level: tracing::Level, args: fmt::Arguments) {
    match site {
        RedlineSite::VisionSpliceEvent => {
            site_event!("xray_proxy_vless::encryption::vision_conn", level, args);
        },
        RedlineSite::VisionSpliceSpawn => {
            site_event!("xray_core::inbound", level, args);
        },
    }
}
