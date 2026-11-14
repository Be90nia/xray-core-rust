//! 可用内存探测 + 内存档位派生（bd sfqlu）。
//!
//! 用户拍板（2026-11-07）：「速度和内存都自动适应，让 256MB 内存的小鸡都能流畅
//! 运行并发挥连接速度原本的能力，内存不会压爆，还能让小鸡开启其他 sing-box /
//! cf 隧道」。
//!
//! ## 一次探测 + 一次派生（无运行时重平衡）
//!
//! 探测顺序（第一个命中即用；全失效兜底 [`crate::budget::plan::FALLBACK_AVAILABLE_BYTES`]）：
//! 1. `XRAY_MEM_LIMIT_MB`（测试/运维强制档位，最高优先）
//! 2. Linux cgroup v2 `memory.max`
//! 3. Linux cgroup v1 `memory.limit_in_bytes`
//! 4. Linux `/proc/meminfo` 的 `MemAvailable`
//! 5. Windows `GlobalMemoryStatusEx().ullAvailPhys`
//! 6. 兜底 512MB（**不得 panic、不得返 0**）
//!
//! 派生面（[`crate::budget::plan::MemoryPlan`]）：总预算 → 桥每方向字节闸 → 连接数上限。改探测量即
//! 换档，不改代码（这与 `xray_frame::budget` 的「上界一律显式常量」不冲突：
//! 那条管单个容器的上界常量，本条管**整机分账总额**随机器自适）。
//!
//! ## 为什么连接数上限是主杠杆
//!
//! 每连接在途字节数（BDP）由链路 RTT × 带宽决定，砍它就直接砍吞吐（bd u440m：
//! 2MiB 闸在 RTT 161.6ms 下 −6.1%）。所以单连接窗口**不压缩**，内存靠
//! `总预算 / 每连接满载上界` 得到的连接数上限控制，触顶走 fail-visible 拒绝。
//!
//! ## 归属判定（§3.5.5 三判据，bd 2026-11-08 D-05）
//!
//! **落地状态（bd 1rc1o-b，2026-11-09）**：原住 `crates/xray-common/src/mem_probe.rs`，
//! 已按迁移清单第 2/3 步整体上浮本件——`xray-common::mem_probe` 模块与文件已删，
//! 消费点全改，**零双定义**。第 1 步（udf 上浮）**未做**，见 ①：
//!
//! **① 零 xray 语义？→ 探测机制部分是。** cgroup v2 `memory.max` / v1
//! `memory.limit_in_bytes` / `/proc/meminfo MemAvailable` / Windows
//! `GlobalMemoryStatusEx` 是**进程级平台机制**，零 xray 语义 ⇒ 归 udf 提炼候选
//! （`skeleton_infra`，与 clock/logx/shutdown 同族）。`udf-promotion-candidate`：
//! [`crate::budget::plan::probe_available`] + 三个纯解析器 + `GlobalMemoryStatusEx` FFI = 迁移清单
//! 第 1 步的提炼面；udf 有此件后本文件换依赖删本地副本（档位策略不动）。
//! 之所以暂随本件落派生层：`xray-frame` 不能反向依赖 `xray-common`（`xray-common`
//! 已依赖 `xray-frame`，唯一边 = `log::set_secrets` 写 `logging::GLOBAL_SECRETS`，
//! 已登记例外）⇒ 档位策略上浮时探测只能一起走，不能留在原地。
//!
//! **② 非零语义 → 派生层？→ 是。** 档位策略（40/96/192/512 MiB 四档、闸 = 预算/8、
//! 连接数反解）绑 Xray 自身池/缓存分账（`xray_frame::budget` 的登记簿），且 env 名带
//! `XRAY_` 前缀 ⇒ Xray 语义 ⇒ 归 `xray-frame`；派生产式与预算常量同址才谈得上对账。
//!
//! **③ 连派生层都放不合适？→ 否。** 无反向依赖 / 无第三方栈驱动契约；Windows FFI
//! 仅本文件私有函数（`GlobalMemoryStatusEx`，kernel32 由 std 恒链接，同
//! `xray-transport` `RtlGetVersion` 手写 FFI 先例）。
//!
//! **消费点**（全改完，零残留）：`xray-transport::bridge`（闸值 + 执行点读数）、
//! `xray-core::memory_budget`（预算门 + 降档写入口）、
//! `xray-core/tests/memory_budget_degrade_wiring.rs`——三者**已**依赖 `xray-frame`，
//! 零新增依赖边。
//!
//! ## 满载乘积**过订**的显式登记（bd 2026-11-08 D-01，口径经 PM 修正）
//!
//! 桥每方向字节闸（`bridge_gate`）兜的是「生产者远快于消费者」的**瞬态背压**
//! （lazy 分配，正常链路实际在途远小于闸），不是每连接常驻预算。因此
//! `max_conns × 2 × bridge_gate` 与 `total_budget` **必然过订**：四档分别为
//! 130 / 768 / 3072 / 10880 MiB vs 预算 40 / 96 / 192 / 512 MiB（3.3×–21×）。
//!
//! **处置（C 案，PM 2026-11-08 拍板）**：
//! - **不动 `max_conns` 派生**（`total_budget / PER_CONN_UPPER_BYTES` = 13/32/64/170）：
//!   用闸反解并发会把生产连接上限砍到 4/4/4/8 条（单浏览器一页 6 连接即打满），
//!   属「为账面自洽牺牲功能」⇒ 打回。**bd 3gxez（2026-11-14）补口径**：该派生值只是
//!   「未经预算门」的缺省读数——装配期执行点上限改按**账本余量**写入 （`(预算 − 固定面 − 显式
//!   socket) / 每连接 pipe 双向`）；设计表的 3MiB 单价含 2MiB 在途份额（=
//!   瞬态背压上界，见下），拿它封顶会让小内存档低于账本装得下的 条数（tiny 13 条 vs 余量 19-22
//!   条）⇒ 多设备并发即成片拒连。
//! - **过订如实进预算门 caps 栏 + WARN**（`xray-core::memory_budget`）：旧状 caps 里只有「闸
//!   per-conn」单值，乘积面不可见 ⇒ 运维无从判断最坏情形；
//!   现在把乘积上界写成一条显式记录并告警，**禁静默**。
//! - 最坏情形由闸自身兜（单连接超闸块永不阻塞；并发同时过判定只允许软超闸少量）。
//! - **全局共享配额**（进程级 in-flight 预算 `total_budget/2`，每连接 `min(per_conn_gate,
//!   全局剩余)`，乘积由构造自洽且并发不降）是正确终态，但属 bridge 数据面改造 + 必带 A/B
//!   门，**本轮不做**（另开票）。

use std::sync::LazyLock;

/// 探测全失效时的兜底可用内存（字节）。
pub const FALLBACK_AVAILABLE_BYTES: u64 = 512 * 1024 * 1024;

/// 强制可用内存（MB）；测试与运维用，优先于一切探测。
pub const ENV_MEM_LIMIT_MB: &str = "XRAY_MEM_LIMIT_MB";

/// 连接数上限覆盖（条）。
pub const ENV_MAX_CONNS: &str = "XRAY_MAX_CONNS";

const MIB: u64 = 1024 * 1024;

/// 每连接**规划**上界（字节）= `总预算 / 本值` 得连接数上限。
///
/// 依据（用户口供 2026-11-07 「连接不会特别多，10–100 条」）：3MiB = 双向 pipe
/// 缺省 512KiB × 2 + 单连接在途 ~2MiB（RTT 161.6ms 下实测 BDP 2.39–3.56MB 的
/// 常驻份额）。四档由此得 **13 / 32 / 64 / 170** 条，小 VPS 自用足够。
///
/// **只当「未经预算门」的缺省读数**（bd 3gxez）：装配期执行点上限改按账本余量口径
/// 写入（见 [`MemoryPlan::max_conns`]），本值不再是运行期天花板。
///
/// **不要**拿桥的双向闸（`2 × bridge_gate`）当每连接常驻来反解本条：闸是**瞬态
/// 背压上界**（lazy 分配，正常链路远不满），按它反解会把四档并发砍到 4/4/4/8
/// 条 = 为账面自洽牺牲功能（2026-11-08 PM 打回，D-01 口径修正）。满载乘积因此
/// **过订**，如实登记进预算门 caps 栏 + WARN，不写进执行路径。
pub const PER_CONN_UPPER_BYTES: usize = 3 * MIB as usize;

/// 桥每方向字节闸的**下限**（字节）：实测 BDP 上沿 3.56MB 之上留余量，
/// 保证「实际生效的几乎总是 BDP 而非本闸」。
pub const BRIDGE_GATE_MIN_BYTES: usize = 4 * MIB as usize;

/// 桥每方向字节闸的**上限**（字节）。
pub const BRIDGE_GATE_MAX_BYTES: usize = 32 * MIB as usize;

/// 内存档位（按**可用**内存分档；档位决定总预算）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryTier {
    /// ≤ 256MB。
    Tiny,
    /// ≤ 512MB。
    Small,
    /// ≤ 1GB。
    Medium,
    /// > 1GB。
    Large,
}

impl MemoryTier {
    /// 按可用内存分档。
    #[must_use]
    pub fn from_available(available: u64) -> Self {
        if available <= 256 * MIB {
            Self::Tiny
        } else if available <= 512 * MIB {
            Self::Small
        } else if available <= 1024 * MIB {
            Self::Medium
        } else {
            Self::Large
        }
    }

    /// 日志/报告用短名。
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tiny => "tiny",
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large",
        }
    }

    /// 档位判据（日志里跟档位一起打印，运维一眼能核）。
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Tiny => "<=256MB",
            Self::Small => "<=512MB",
            Self::Medium => "<=1GB",
            Self::Large => ">1GB",
        }
    }

    /// 本档总预算（字节）：40MB / 96MB / 192MB / `min(512MB, 可用/4)`。
    #[must_use]
    pub fn total_budget(self, available: u64) -> usize {
        match self {
            Self::Tiny => (40 * MIB) as usize,
            Self::Small => (96 * MIB) as usize,
            Self::Medium => (192 * MIB) as usize,
            // 大机器不设硬预算：按可用 1/4 且不超过 512MB（给同时跑的
            // sing-box / cloudflared 等陪跑进程留余量）。
            Self::Large => usize::try_from((available / 4).min(512 * MIB))
                .unwrap_or(BRIDGE_GATE_MAX_BYTES * 16),
        }
    }

    /// 档位「设计整机」尺寸（字节）——档位预算按此尺寸标定。
    ///
    /// 与 [`Self::from_available`] 的档位边界同源：tiny ≤256MiB、small ≤512MiB、
    /// medium ≤1GiB；large 档的预算（`available/4` 上限 512MiB）在 2GiB 处饱和。
    /// 用途：算「我们那一份整机份额」（[`conn_budget`]）的分母。
    #[must_use]
    pub fn design_available(self) -> u64 {
        match self {
            Self::Tiny => 256 * MIB,
            Self::Small => 512 * MIB,
            Self::Medium => 1024 * MIB,
            Self::Large => 2048 * MIB,
        }
    }

    /// 档位「设计」预算（字节）：40 / 96 / 192 / 512 MiB——**不随实况可用内存变**。
    ///
    /// 与 [`Self::total_budget`] 的分工：后者是**活预算**（large 档 = `min(available/4,
    /// 512MiB)`），只喂桥侧闸；整机份额派生必须用**设计值**，否则跨档边界会算出
    /// 「内存变多、连接数反而变少」（bd m2mmm 评审 B1）。
    #[must_use]
    pub fn design_budget(self) -> u64 {
        match self {
            Self::Tiny => 40 * MIB,
            Self::Small => 96 * MIB,
            Self::Medium => 192 * MIB,
            Self::Large => 512 * MIB,
        }
    }

    /// 档位「设计」连接上限（条）：**13 / 32 / 64 / 170**（设计表，不随实况变）。
    ///
    /// = `design_budget / PER_CONN_UPPER_BYTES`（3MiB/连接）取整条。
    #[must_use]
    pub fn design_conn_cap(self) -> usize {
        match self {
            Self::Tiny => 13,
            Self::Small => 32,
            Self::Medium => 64,
            Self::Large => 170,
        }
    }
}

/// 连接数预算派生结果（整机份额口径）——bd m2mmm xmux 缺省池上限的**唯一事实源**。
///
/// 派生链（每一步都可复算）：
/// 1. 档位 = [`MemoryTier::from_available`]（按**实况**可用内存）
/// 2. 档位连接上限 `K` = [`MemoryTier::design_conn_cap`]（**设计表** 13/32/64/170）
/// 3. 档位预算 `B` = [`MemoryTier::design_budget`]（**设计值** 40/96/192/512MiB）
/// 4. 整机份额 `share` = `B / 档位设计整机尺寸`（tiny 15.6% / small 18.75% / medium 18.75% / large
///    25%）
/// 5. 每连接规划占用 `per_conn` = `B / K`（≈3MiB）
/// 6. 派生连接数 `derived` = 实况可用 × `share` / `per_conn` = 实况可用 × `K` / 设计尺寸
/// 7. 生效上限 `cap` = `min(K, derived)`
///
/// **为什么 K 与份额都用设计值**（bd m2mmm 评审 B1）：`K` 若从**活预算**反推
/// （large 档 = `min(available/4, 512MiB)` / 3MiB），则 `K` 本身随实况变，而分母是
/// 常量 2048MiB ⇒ 跨档边界**非单调**（1024MiB ⇒ 64，1025MiB ⇒ 42：内存变多反而连接
/// 数变少），且 1–2GB 的机器拿不满档位。设计值 ⇒ `derived` 对 `available` 线性 ⇒ 单调。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnBudget {
    /// 档位。
    pub tier: MemoryTier,
    /// 档位连接上限（条）。
    pub tier_cap: usize,
    /// 按实况可用内存派生的连接数（条）。
    pub derived: usize,
    /// 生效连接数上限（条）= `min(tier_cap, derived)`。
    pub cap: usize,
    /// 每连接规划占用（字节，≈3MiB）。
    pub per_conn: usize,
    /// 整机份额的分子（档位预算，字节）。
    pub share_num: u64,
    /// 整机份额的分母（档位设计整机尺寸，字节）。
    pub share_den: u64,
}

/// 按「整机份额」派生连接数上限（bd m2mmm：xhttp/xmux 缺省连接池上限）。
///
/// 用户硬约束（2026-11-12）：大机器不受牵连、小机器不被压爆 ⇒ 上限随**实况**
/// 可用内存缩放：别人吃掉内存时我们的上限同比例下降（`derived` 项），但绝不
/// 超过档位上限 `tier_cap`。
#[must_use]
pub fn conn_budget(live_available: u64) -> ConnBudget {
    let available = if live_available == 0 { FALLBACK_AVAILABLE_BYTES } else { live_available };
    let tier = MemoryTier::from_available(available);
    // 档位上限与份额分子都用**设计值**（活预算反推 K ⇒ 跨档非单调，见上）。
    let tier_cap = tier.design_conn_cap();
    let share_num = tier.design_budget();
    let per_conn = (share_num / tier_cap as u64) as usize;
    let share_den = tier.design_available();
    // derived = 实况可用 × share / per_conn = 实况可用 × K / 设计尺寸（u128 防溢出）。
    let derived = ((available as u128 * tier_cap as u128) / share_den as u128) as usize;
    let cap = tier_cap.min(derived).max(1);
    ConnBudget { tier, tier_cap, derived, cap, per_conn, share_num, share_den }
}

/// 显式连接数上限（`XRAY_MAX_CONNS`）——**唯一解析点**（S3 真相源）。
///
/// 语义：**进程连接数的显式上限**。两侧消费方口径统一为「最终生效值恒受内存约束」：
/// - 桥侧槽位（[`MemoryPlan::max_conns`]）：显式值**覆盖**档位派生值（既有语义），
///   随后由装配期内存适配（[`set_effective_max_conns`]）压到内存装得下的量。
/// - xmux/xhttp 缺省池（[`xmux_pool_cap`]）：显式值只作**上界**（取 `min`）——
///   显式值不得让池开到超出「我们最多占整机一份」的量（契约 3）。
///
/// `None` = 未设（视同不额外收紧）；`0` 视同未设（否则等于全拒，运维误设即服务不可用）。
#[must_use]
pub fn explicit_max_conns() -> Option<usize> {
    std::env::var(ENV_MAX_CONNS)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
}

/// xhttp/xmux 缺省连接池上限（条）——**生效值** = 内存份额派生值 ∩ 显式上限。
///
/// 与 [`conn_budget`] 的关系：本函数只做「显式上限收紧」这一步；份额派生仍在
/// [`conn_budget`]（唯一派生面）里。
#[must_use]
pub fn xmux_pool_cap(live_available: u64) -> usize {
    xmux_pool_cap_with(live_available, explicit_max_conns())
}

/// [`xmux_pool_cap`] 的纯函数面：显式上限由调用方传入 ⇒ 单测不碰环境变量。
#[must_use]
pub fn xmux_pool_cap_with(live_available: u64, explicit_max: Option<usize>) -> usize {
    let derived = conn_budget(live_available).cap;
    match explicit_max {
        Some(n) => derived.min(n),
        None => derived,
    }
}

/// 实况可用内存（字节）：`XRAY_MEM_LIMIT_MB` 覆盖优先，其次平台探测，
/// 最后回落 [`MemoryPlan::cached`] 的探测值（探测全失效 ⇒ 512MiB 兜底）。
#[must_use]
pub fn live_available() -> u64 {
    let override_mb = std::env::var(ENV_MEM_LIMIT_MB).ok().and_then(|v| parse_mb(&v));
    let probed =
        probe_available().map(|(bytes, _)| bytes).or_else(|| Some(MemoryPlan::cached().available));
    resolve_live_available(override_mb, probed)
}

/// [`live_available`] 的纯函数面（env 覆盖 → 探测值 → 兜底），单测不碰环境变量。
fn resolve_live_available(override_mb: Option<u64>, probed: Option<u64>) -> u64 {
    match override_mb {
        Some(mb) => mb.saturating_mul(MIB),
        None => probed.unwrap_or(FALLBACK_AVAILABLE_BYTES),
    }
}

/// 一次探测 + 一次派生的全部结果（进程级缓存一份，见 [`MemoryPlan::cached`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryPlan {
    /// 有效可用内存（字节；`XRAY_MEM_LIMIT_MB` 覆盖后）。
    pub available: u64,
    /// 档位。
    pub tier: MemoryTier,
    /// 总预算（字节）。
    pub total_budget: usize,
    /// 桥**每方向**字节闸（字节）。
    pub bridge_gate: usize,
    /// 连接数上限（条；触顶 fail-visible 拒绝）。
    ///
    /// **未经预算门时的缺省读数**（= `total_budget / PER_CONN_UPPER_BYTES`）。装配期
    /// `xray-core::memory_budget` 会把执行点上限改写为**账本余量口径**
    /// （`(预算 − 固定面 − 显式 socket) / 每连接 pipe 双向`，bd 3gxez）：
    /// 3MiB 单价里的 2MiB「在途份额」是瞬态背压上界（D-01），拿它当常驻会把小内存档
    /// 压到账本余量以下（tiny 13 条 ⇒ 成片拒连）。
    pub max_conns: usize,
    /// 探测来源（日志用）。
    pub source: &'static str,
}

impl MemoryPlan {
    /// 按可用内存构造（`source` 仅日志；测试注入口）。
    #[must_use]
    pub fn from_available(available: u64) -> Self {
        Self::build(available, "injected", None)
    }

    /// 真实探测（读 env + 平台接口）。
    #[must_use]
    pub fn detect() -> Self {
        let override_mb = std::env::var(ENV_MEM_LIMIT_MB).ok().and_then(|v| parse_mb(&v));
        let max_conns = explicit_max_conns();
        match override_mb {
            Some(mb) => Self::build(mb.saturating_mul(MIB), ENV_MEM_LIMIT_MB, max_conns),
            None => {
                let (available, source) =
                    probe_available().unwrap_or((FALLBACK_AVAILABLE_BYTES, "fallback 512MB"));
                Self::build(available, source, max_conns)
            },
        }
    }

    /// 进程级缓存（探测一次；运行期不重平衡 —— 改档要重启）。
    #[must_use]
    pub fn cached() -> &'static Self {
        static PLAN: LazyLock<MemoryPlan> = LazyLock::new(MemoryPlan::detect);
        &PLAN
    }

    fn build(available: u64, source: &'static str, max_conns_override: Option<usize>) -> Self {
        // 可用内存不可能为 0：探测返 0 视同失效（否则整机预算归零 = 全拒）。
        let available = if available == 0 { FALLBACK_AVAILABLE_BYTES } else { available };
        let tier = MemoryTier::from_available(available);
        let total_budget = tier.total_budget(available);
        // 每方向闸 = 总预算/8，钳在 [4MiB, 32MiB]：四档得 5 / 12 / 24 / 32 MiB，
        // 恒 ≥ 实测 BDP 上沿 ⇒ 正常链路上闸不 binding（不砍吞吐），只在生产者
        // 远快于消费者时兜住内存。
        let bridge_gate = (total_budget / 8).clamp(BRIDGE_GATE_MIN_BYTES, BRIDGE_GATE_MAX_BYTES);
        // 连接数上限只按**每连接规划上界**反解（bd sfqlu 原式，保持并发能力）。
        // **不用** `2 × gate` 反解（D-01 口径修正 2026-11-08 PM 打回）：闸是**瞬态
        // 背压上界**（lazy 分配，正常链路远不满），拿它当每连接常驻会把四档并发
        // 砍到 4/4/4/8 条 —— 那是「为账面自洽牺牲功能」。满载乘积因此**过订**，
        // 如实登记进预算门 caps 栏 + WARN（见 `xray-core::memory_budget`）。
        // `XRAY_MAX_CONNS=0` 视同未设（否则等于全拒，运维误设即服务不可用）。
        let max_conns = match max_conns_override {
            Some(n) if n > 0 => n,
            _ => (total_budget / PER_CONN_UPPER_BYTES).max(1),
        };
        Self { available, tier, total_budget, bridge_gate, max_conns, source }
    }

    /// 单行摘要（启动日志 + 报告用）。
    ///
    /// 附「连接数预算」派生面（bd m2mmm）：档位 / 整机份额 / 每连接占用 / 派生值 /
    /// 档位上限 / 生效值，供运维一眼核对 xmux 缺省连接池上限的来源。
    #[must_use]
    pub fn summary(&self) -> String {
        let cb = conn_budget(self.available);
        format!(
            "memory plan: tier {} ({}) available {}B via {} -> budget {}B, bridge gate {}B/dir, \
             max {} conns; conn budget cap {} (tier cap {}, derived {}, share {}/{}, per-conn {}B)",
            self.tier.as_str(),
            self.tier.label(),
            self.available,
            self.source,
            self.total_budget,
            self.bridge_gate,
            self.max_conns,
            cb.cap,
            cb.tier_cap,
            cb.derived,
            cb.share_num,
            cb.share_den,
            cb.per_conn,
        )
    }

    /// 运行期**生效**的连接数上限（执行点唯一读数）。
    ///
    /// = 装配期降档值（[`set_effective_max_conns`]）优先，未写入时 = 本档派生值
    /// [`Self::max_conns`]。降档**必须走到这里**（bd 2026-11-08 D-02）：旧状
    /// 预算门算出的降档只写进 warn 文案，桥上仍读档位原值 ⇒ 运维看到的数字
    /// 不是生效的数字。装配期写入的是**账本余量口径**上限（bd 3gxez），因此通常
    /// 高于本档派生值（无配置侧重压时不会低于它）。
    #[must_use]
    pub fn effective_max_conns(&self) -> usize {
        match EFFECTIVE_MAX_CONNS.load(std::sync::atomic::Ordering::Relaxed) {
            0 => self.max_conns,
            n => n,
        }
    }
}

/// 装配期写入的降档连接数上限（0 = 未写入 ⇒ 用档位派生值）。
static EFFECTIVE_MAX_CONNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// 写入运行期生效的连接数上限（装配期一次性，`xray-core::memory_budget` 调）。
///
/// 夹到 `≥ 1`：写 0 = 全拒（运维/测试误写即服务不可用），与
/// `XRAY_MAX_CONNS=0` 视同未设同口径。返回值即实际生效值（调用方据此回填
/// 报告，免二次读全局）。
pub fn set_effective_max_conns(limit: usize) -> usize {
    let limit = limit.max(1);
    EFFECTIVE_MAX_CONNS.store(limit, std::sync::atomic::Ordering::Relaxed);
    limit
}

/// 装配期写入的运行期 UDP dispatch 会话上限（0 = 未写入 ⇒ 用实现常量上界）。
///
/// 与 [`set_effective_max_conns`] 同族（bd rmbby）：每会话有一条**常驻**缓冲
/// （池化 8KiB 读缓冲），`MAX_UDP_SESSIONS` 跨档恒定会让小内存档在会话满时
/// 静默吃穿预算 ⇒ 预算门按「余量 ÷ 每会话常驻字节」反解本档装得下的条数写进
/// 这一个读数。执行点 `xray_app_dispatcher::udp_session` 的 `establish` 读同一
/// 份值（超限 fail-visible 返回 `io::Error`，不静默丢包）；未经过预算门
/// （单测 / 直跑）时为 0 ⇒ 用实现常量上界，行为与旧版一致。
static EFFECTIVE_MAX_UDP_SESSIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// 读运行期生效的 UDP dispatch 会话上限；`None` = 预算门未写入 ⇒ 调用方用自己的
/// 实现常量上界（`xray_app_dispatcher::udp_session::MAX_UDP_SESSIONS`）。
#[must_use]
pub fn effective_max_udp_sessions() -> Option<usize> {
    match EFFECTIVE_MAX_UDP_SESSIONS.load(std::sync::atomic::Ordering::Relaxed) {
        0 => None,
        n => Some(n),
    }
}

/// 写入运行期生效的 UDP dispatch 会话上限（装配期一次性，`xray-core::memory_budget`
/// 调）。夹到 `≥ 1`（写 0 = 全拒 ⇒ 服务不可用）；返回值即实际生效值（调用方据此
/// 回填报告，免二次读全局）。
pub fn set_effective_max_udp_sessions(limit: usize) -> usize {
    let limit = limit.max(1);
    EFFECTIVE_MAX_UDP_SESSIONS.store(limit, std::sync::atomic::Ordering::Relaxed);
    limit
}

/// 解析 `XRAY_MEM_LIMIT_MB` 值（`"256"` → 256；空/非数字 → `None`）。
fn parse_mb(raw: &str) -> Option<u64> {
    let mb: u64 = raw.trim().parse().ok()?;
    (mb > 0).then_some(mb)
}

/// 平台可用内存探测（命中即返回，含来源名）。
#[must_use]
pub fn probe_available() -> Option<(u64, &'static str)> {
    probe_platform()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn probe_platform() -> Option<(u64, &'static str)> {
    let limit = cgroup_limit_v2()
        .map(|v| (v, "cgroup-v2 memory.max"))
        .or_else(|| cgroup_limit_v1().map(|v| (v, "cgroup-v1 memory.limit_in_bytes")));
    let meminfo = meminfo_available();
    // cgroup 限额是**上限**，MemAvailable 是**当下实况**：两者都在时取小
    // （限额 8GiB 但机器只剩 1GiB ⇒ 按 1GiB 归档，否则会按 512MB 预算乐观跑）。
    match (limit, meminfo) {
        (Some((limit, limit_src)), Some(avail)) => Some(if avail < limit {
            (avail, "proc-meminfo MemAvailable")
        } else {
            (limit, limit_src)
        }),
        (Some(v), None) => Some(v),
        (None, Some(avail)) => Some((avail, "proc-meminfo MemAvailable")),
        (None, None) => None,
    }
}

#[cfg(windows)]
fn probe_platform() -> Option<(u64, &'static str)> {
    windows_available_physical().map(|b| (b, "GlobalMemoryStatusEx"))
}

#[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
fn probe_platform() -> Option<(u64, &'static str)> {
    None
}

// ── 纯解析面（不碰 IO；三平台都可单测，格式对齐内核/Windows 原始输出）──

/// cgroup v2 `memory.max`：数字字节；`max`（无限制）→ `None`。
#[cfg(any(test, target_os = "linux", target_os = "android"))]
fn parse_cgroup_v2_max(raw: &str) -> Option<u64> {
    let text = raw.trim();
    if text.is_empty() || text == "max" {
        return None;
    }
    text.parse::<u64>().ok().filter(|v| *v > 0)
}

/// cgroup v1 `memory.limit_in_bytes`：数字字节；内核「无限制」哨兵
/// （≈ 2^63 附近）→ `None`，否则会被当成天文数字档。
#[cfg(any(test, target_os = "linux", target_os = "android"))]
fn parse_cgroup_v1_limit(raw: &str) -> Option<u64> {
    let v: u64 = raw.trim().parse().ok()?;
    (v > 0 && v < (1u64 << 62)).then_some(v)
}

/// `/proc/meminfo` 的 `MemAvailable: 12345 kB` → 字节。
#[cfg(any(test, target_os = "linux", target_os = "android"))]
fn parse_meminfo_available(raw: &str) -> Option<u64> {
    let line = raw.lines().find(|l| l.starts_with("MemAvailable:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    (kb > 0).then(|| kb.saturating_mul(1024))
}

// ── Linux 探测实现 ──

#[cfg(any(target_os = "linux", target_os = "android"))]
fn cgroup_limit_v2() -> Option<u64> {
    let direct = std::fs::read_to_string("/sys/fs/cgroup/memory.max").ok();
    direct.as_deref().and_then(parse_cgroup_v2_max).or_else(|| {
        let rel = proc_self_cgroup_path("0")?;
        let raw = std::fs::read_to_string(format!("/sys/fs/cgroup{rel}/memory.max")).ok()?;
        parse_cgroup_v2_max(&raw)
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn cgroup_limit_v1() -> Option<u64> {
    let direct = std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes").ok();
    direct.as_deref().and_then(parse_cgroup_v1_limit).or_else(|| {
        let rel = proc_self_cgroup_path("memory")?;
        let raw =
            std::fs::read_to_string(format!("/sys/fs/cgroup/memory{rel}/memory.limit_in_bytes"))
                .ok()?;
        parse_cgroup_v1_limit(&raw)
    })
}

/// `/proc/self/cgroup` 里本进程所在 cgroup 相对路径（`/foo/bar`；根 = 空串）。
///
/// 行格式 `hierarchy:controllers:path`；v2 用控制器字段为空的 `0::/path`，
/// v1 用控制器里含 `memory` 的行。
#[cfg(any(target_os = "linux", target_os = "android"))]
fn proc_self_cgroup_path(controller: &str) -> Option<String> {
    let raw = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let path = raw.lines().find_map(|line| {
        let mut parts = line.splitn(3, ':');
        let _hierarchy = parts.next()?;
        let controllers = parts.next()?;
        let path = parts.next()?;
        let hit = if controller == "0" {
            controllers.is_empty()
        } else {
            controllers.split(',').any(|c| c == controller)
        };
        hit.then(|| path.trim_end_matches('/').to_string())
    })?;
    Some(if path == "/" { String::new() } else { path })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn meminfo_available() -> Option<u64> {
    parse_meminfo_available(&std::fs::read_to_string("/proc/meminfo").ok()?)
}

// ── Windows 探测实现（手写 FFI：`GlobalMemoryStatusEx` 不在本 crate 已开的
//    windows-sys 特性面（只有 Win32_Networking_WinSock / Win32_System_IO），
//    为一个结构体加特性不划算）──

#[cfg(windows)]
fn windows_available_physical() -> Option<u64> {
    #[repr(C)]
    #[derive(Default)]
    struct MemoryStatusEx {
        length: u32,
        memory_load: u32,
        total_phys: u64,
        avail_phys: u64,
        total_page_file: u64,
        avail_page_file: u64,
        total_virtual: u64,
        avail_virtual: u64,
        avail_extended_virtual: u64,
    }

    // kernel32 由 std 恒链接（同 xray-transport `RtlGetVersion` 手写 FFI 先例）。
    unsafe extern "system" {
        fn GlobalMemoryStatusEx(buffer: *mut MemoryStatusEx) -> i32;
    }

    let mut status = MemoryStatusEx {
        length: std::mem::size_of::<MemoryStatusEx>() as u32,
        ..Default::default()
    };
    // SAFETY: 结构体是 `#[repr(C)]` 且 `length` 已按 Win32 契约填成本结构体大小；
    // 调用只写本栈变量，不与任何其它引用共享。
    let ok = unsafe { GlobalMemoryStatusEx(&mut status) };
    (ok != 0 && status.avail_phys > 0).then_some(status.avail_phys)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 四档总预算 + 闸 + 连接数上限（对应验收 5：256/512/1024/不设 四档）。
    ///
    /// 连接数 13/32/64/170 = `total_budget / PER_CONN_UPPER_BYTES`（3MiB）——**保持
    /// 旧派生量级**，绝不因满载乘积自洽而砍（2026-11-08 PM 打回）。
    #[test]
    fn tiers_derive_expected_budget_and_conns() {
        let tiny = MemoryPlan::from_available(256 * MIB);
        assert_eq!(tiny.tier, MemoryTier::Tiny);
        assert_eq!(tiny.total_budget, 40 * MIB as usize);
        assert_eq!(tiny.bridge_gate, 5 * MIB as usize);
        assert_eq!(tiny.max_conns, 13);

        let small = MemoryPlan::from_available(512 * MIB);
        assert_eq!(small.tier, MemoryTier::Small);
        assert_eq!(small.total_budget, 96 * MIB as usize);
        assert_eq!(small.bridge_gate, 12 * MIB as usize);
        assert_eq!(small.max_conns, 32);

        let medium = MemoryPlan::from_available(1024 * MIB);
        assert_eq!(medium.tier, MemoryTier::Medium);
        assert_eq!(medium.total_budget, 192 * MIB as usize);
        assert_eq!(medium.bridge_gate, 24 * MIB as usize);
        assert_eq!(medium.max_conns, 64);

        // 「不设」= 大盘机器：min(512MB, 可用/4)，闸钳到上沿 32MiB。
        let large = MemoryPlan::from_available(16 * 1024 * MIB);
        assert_eq!(large.tier, MemoryTier::Large);
        assert_eq!(large.total_budget, 512 * MIB as usize);
        assert_eq!(large.bridge_gate, BRIDGE_GATE_MAX_BYTES);
        assert_eq!(large.max_conns, 170);
    }

    /// D-01（口径经 PM 2026-11-08 修正）：满载乘积**过订是承认的事实**——
    /// 闸是瞬态背压上界（lazy），不是每连接常驻 ⇒ 乘积 > 预算是设计取舍，
    /// 由预算门 caps 栏 + WARN 显式登记（禁静默），**绝不反解压并发**。
    ///
    /// 本测试钉两头：① 并发数保持旧量级（≥ 13/32/64/170，防再被砍）；
    /// ② 过订倍数算得出且被打印（运维判据），四档倍数 3.25/8/16/21.25。
    // 取证数字须打印（--nocapture 人眼核对）——同 q1r4q 先例：显式 allow + 理由。
    #[allow(
        clippy::print_stdout,
        clippy::disallowed_macros,
        reason = "取证数字须打印（--nocapture 人眼核对），同 q1r4q 先例"
    )]
    #[test]
    fn full_load_product_is_registered_oversubscription() {
        for (available, conns) in
            [(256 * MIB, 13usize), (512 * MIB, 32), (1024 * MIB, 64), (16 * 1024 * MIB, 170)]
        {
            let plan = MemoryPlan::from_available(available);
            assert_eq!(plan.max_conns, conns, "{available}B 档并发能力不得回退");
            let product = plan.max_conns * 2 * plan.bridge_gate;
            println!(
                "tier {} budget {}B gate {}B/dir conns {} -> full-load product {}B ({:.2}x budget)",
                plan.tier.as_str(),
                plan.total_budget,
                plan.bridge_gate,
                plan.max_conns,
                product,
                product as f64 / plan.total_budget as f64
            );
            // 过订是事实，不是 bug——但必须能被算出来（禁把乘积塞进 max_conns 派生）。
            assert!(
                product > plan.total_budget,
                "闸是瞬态背压上界 ⇒ 满载乘积过订；若此断言红说明 gate 被改小了，\
                 须重审是否回档 bd u440m"
            );
        }
    }

    /// 大机器但不至于富余时的预算按可用 1/4（不到 512MB 上限）。
    #[test]
    fn large_tier_budget_is_quarter_of_available() {
        let plan = MemoryPlan::from_available(2 * 1024 * MIB);
        assert_eq!(plan.total_budget, 512 * MIB as usize, "2GiB 的 1/4 = 512MB（与上限相等）");
        let plan = MemoryPlan::from_available(1300 * MIB);
        assert_eq!(plan.total_budget, (1300 * MIB / 4) as usize);
    }

    /// 闸恒 ≥ 实测 BDP 上沿（3.56MB）：四档都不许低于 4MiB，否则重犯 u440m。
    #[test]
    fn bridge_gate_never_below_measured_bdp() {
        for avail in [64 * MIB, 256 * MIB, 512 * MIB, 1024 * MIB, 16 * 1024 * MIB] {
            let plan = MemoryPlan::from_available(avail);
            assert!(
                plan.bridge_gate >= BRIDGE_GATE_MIN_BYTES,
                "{avail}B 档闸 {}B 低于 4MiB：高 RTT 会被闸钉吞吐（bd u440m）",
                plan.bridge_gate
            );
            assert!(plan.bridge_gate > 0);
        }
    }

    #[test]
    fn env_limit_parsing_covers_all_tiers() {
        assert_eq!(parse_mb("256"), Some(256));
        assert_eq!(parse_mb(" 512 "), Some(512));
        assert_eq!(parse_mb("1024"), Some(1024));
        assert_eq!(parse_mb("0"), None, "0 无意义，按未设处理");
        assert_eq!(parse_mb("abc"), None);
        assert_eq!(parse_mb(""), None);
    }

    #[test]
    fn zero_and_missing_probe_fall_back_never_zero() {
        // 探测得 0（读文件失败/异常值）不得把预算归零，按兜底档处理。
        let plan = MemoryPlan::from_available(0);
        assert_eq!(plan.available, FALLBACK_AVAILABLE_BYTES);
        assert!(plan.total_budget > 0 && plan.max_conns >= 1);
        assert_eq!(plan.tier, MemoryTier::Small);
    }

    #[test]
    fn max_conns_override_wins() {
        let plan = MemoryPlan::build(256 * MIB, "test", Some(42));
        assert_eq!(plan.max_conns, 42);
        // 上限 0 视为未设（否则等于全拒），落到派生值。
        let plan = MemoryPlan::build(256 * MIB, "test", Some(0));
        assert_eq!(plan.max_conns, 13);
    }

    /// 降档值与执行点读数同一事实源（bd 2026-11-08 D-02）：未写入 = 档位派生值，
    /// 写入后 `effective_max_conns()` 立即反映（桥上 `ConnSlot` 读的就是它）。
    /// 本测试是本进程唯一写该静态的用例 ⇒ 无需串行化。
    #[test]
    fn effective_max_conns_follows_degraded_write() {
        let plan = MemoryPlan::from_available(256 * MIB);
        assert_eq!(plan.effective_max_conns(), plan.max_conns, "未装配 = 档位派生值");
        assert_eq!(set_effective_max_conns(2), 2, "写 2 生效 2");
        assert_eq!(plan.effective_max_conns(), 2, "执行点必须读降档值");
        assert_eq!(set_effective_max_conns(0), 1, "写 0 夹到 1（全拒不可接受）");
        assert_eq!(plan.effective_max_conns(), 1);
    }

    #[test]
    fn cgroup_v2_max_parses_number_and_limit_keyword() {
        assert_eq!(parse_cgroup_v2_max("1073741824\n"), Some(1024 * MIB));
        assert_eq!(parse_cgroup_v2_max("max\n"), None, "无限制 = 交给下一档探测");
        assert_eq!(parse_cgroup_v2_max(""), None);
        assert_eq!(parse_cgroup_v2_max("0"), None);
    }

    #[test]
    fn cgroup_v1_limit_ignores_unlimited_sentinel() {
        assert_eq!(parse_cgroup_v1_limit("536870912\n"), Some(512 * MIB));
        // 内核「无限制」哨兵（2^63 附近）：必须当未设，否则整机按天文数字归档。
        assert_eq!(parse_cgroup_v1_limit("9223372036854771712\n"), None);
        assert_eq!(parse_cgroup_v1_limit("0"), None);
    }

    #[test]
    fn meminfo_mem_available_parses_kb() {
        let raw = "MemTotal:        2048000 kB\nMemFree:          100000 kB\n\
                   MemAvailable:     262144 kB\nBuffers:           12345 kB\n";
        assert_eq!(parse_meminfo_available(raw), Some(256 * MIB));
        assert_eq!(parse_meminfo_available("MemTotal: 1 kB\n"), None);
    }

    /// 真机探测必须给出正数（Windows/Linux 都覆盖；macOS 等无实现平台跳过）。
    #[test]
    fn probe_returns_positive_or_none_without_panic() {
        if let Some((bytes, source)) = probe_available() {
            assert!(bytes > 0);
            assert!(!source.is_empty());
        }
        let plan = MemoryPlan::detect();
        assert!(plan.total_budget > 0 && plan.max_conns >= 1);
        assert!(plan.summary().contains("max"));
    }

    // ===== 连接数预算派生（bd m2mmm：xhttp/xmux 缺省连接池上限）=====

    /// 档位边界上「派生值 = 档位上限」：256MiB⇒13、512MiB⇒32、1GiB⇒64、
    /// 2GiB⇒170、45GiB⇒170（大盘不再增长——上限就是档位上限）。
    #[test]
    fn conn_budget_tier_boundaries_map_to_tier_caps() {
        for (available, cap) in [
            (256 * MIB, 13usize),
            (512 * MIB, 32),
            (1024 * MIB, 64),
            (2048 * MIB, 170),
            (45 * 1024 * MIB, 170),
        ] {
            let cb = conn_budget(available);
            assert_eq!(cb.cap, cap, "{available}B 档 ⇒ 连接上限 {cap}");
            assert_eq!(cb.cap, cb.tier_cap, "档位边界上派生值应等于档位上限");
            assert!(cb.derived >= cb.cap);
        }
    }

    /// 档位之间（700MiB ⇒ medium 档）：上限必须**落在档位上限之下**——
    /// 证明「实况可用内存」真的参与了派生，不是恒等于档位上限。
    #[test]
    fn conn_budget_between_tiers_is_below_tier_cap() {
        let cb = conn_budget(700 * MIB);
        assert!(cb.cap > 32 && cb.cap <= 64, "700MiB ⇒ cap ∈ (32,64]，实得 {}", cb.cap);
        assert!(cb.cap < cb.tier_cap, "派生项必须真的在起作用");
    }

    /// 别人吃掉内存 ⇒ 我们的上限同比例下降（绝不按整机富余度乐观跑）。
    #[test]
    fn conn_budget_shrinks_when_memory_is_taken() {
        let rich = conn_budget(2048 * MIB).cap;
        let poor = conn_budget(500 * MIB).cap;
        assert!(poor < rich, "500MiB 可用 ⇒ {poor} 必须远小于 2GiB 时的 {rich}");
        assert!(poor <= 32, "500MiB 落 small 档 ⇒ 上限 ≤ 32，实得 {poor}");
    }

    /// `XRAY_MEM_LIMIT_MB=256` ⇒ 实况可用 256MiB ⇒ tiny 档口径（上限 ≤ 13）。
    #[test]
    fn mem_limit_override_drives_tiny_tier_cap() {
        let avail = resolve_live_available(Some(256), Some(45 * 1024 * MIB));
        assert_eq!(avail, 256 * MIB, "env 覆盖优先于探测值");
        assert!(conn_budget(avail).cap <= 13, "tiny 档口径 ⇒ ≤ 13");
    }

    /// 探测失效 ⇒ 兜底 512MiB（不得返 0 ⇒ 不得把预算归零）。
    #[test]
    fn live_available_never_zero() {
        assert_eq!(resolve_live_available(None, None), FALLBACK_AVAILABLE_BYTES);
        assert!(live_available() > 0);
    }

    /// **单调性**（bd m2mmm 评审 B1 blocker）：可用内存变多 ⇒ 连接上限**不得**变少。
    ///
    /// 旧实现用「活预算」反推档位上限 `K`（large 档 = `min(available/4, 512MiB)/3MiB`），
    /// 分母却是常量 2048MiB ⇒ 1024MiB ⇒ 64、1025MiB ⇒ 42（内存变多反而连接数变少）。
    #[test]
    fn conn_budget_is_monotonic_in_available() {
        let mut prev = conn_budget(64 * MIB).cap;
        let mut available = 64 * MIB;
        while available <= 4096 * MIB {
            available += MIB;
            let cap = conn_budget(available).cap;
            assert!(cap >= prev, "可用 {available}B ⇒ cap {cap} < 上一档 {prev} ⇒ 预算非单调");
            prev = cap;
        }
        // 跨档边界（1GiB）两侧的具体值：内存变多 ⇒ 连接数变多。
        assert_eq!(conn_budget(1024 * MIB).cap, 64);
        assert_eq!(conn_budget(1025 * MIB).cap, 85);
        assert!(conn_budget(1025 * MIB).cap > conn_budget(1024 * MIB).cap);
    }

    /// 档位映射锚点（评审 B1 验收）：1GiB ⇒ 64、2GiB ⇒ 170、45GiB ⇒ 170。
    #[test]
    fn conn_budget_maps_large_tier_to_design_cap() {
        assert_eq!(conn_budget(1024 * MIB).cap, 64, "1GiB ⇒ 64");
        assert_eq!(conn_budget(2048 * MIB).cap, 170, "2GiB ⇒ 170");
        assert_eq!(conn_budget(45 * 1024 * MIB).cap, 170, "45GiB ⇒ 170（大盘封顶）");
        assert_eq!(conn_budget(2048 * MIB).tier_cap, 170);
    }

    /// S3：`XRAY_MAX_CONNS` 单一真相源——池上限 = 内存份额派生值 ∩ 显式上限。
    ///
    /// 显式值**只能收紧**、不得突破「我们最多占整机一份」（契约 3）。
    #[test]
    fn xmux_pool_cap_respects_explicit_limit_without_breaching_share() {
        // 未设显式上限 ⇒ = 内存份额派生值（512MiB ⇒ small 档 ⇒ 32）。
        assert_eq!(xmux_pool_cap_with(512 * MIB, None), 32);
        // 显式上限更小 ⇒ 收紧。
        assert_eq!(xmux_pool_cap_with(512 * MIB, Some(10)), 10);
        // 显式上限更大 ⇒ 仍受内存份额约束（不得突破份额上限）。
        assert_eq!(xmux_pool_cap_with(512 * MIB, Some(1000)), 32);
        // 显式上限与派生值同源 ⇒ 一致。
        assert_eq!(xmux_pool_cap_with(1024 * MIB, Some(64)), 64);
    }

    /// bd rmbby：UDP 会话上限的**执行点读数**（未写入 ⇒ `None`，调用方回落实现常量；
    /// 写入后原样读回，0 夹到 1）。
    ///
    /// 单测串行约束：本文件的其它用例不读此静态 ⇒ 写入不影响它们。
    #[test]
    fn effective_max_udp_sessions_roundtrips() {
        assert_eq!(set_effective_max_udp_sessions(1234), 1234);
        assert_eq!(effective_max_udp_sessions(), Some(1234));
        assert_eq!(set_effective_max_udp_sessions(0), 1, "写 0 = 全拒 ⇒ 夹到 1");
        assert_eq!(effective_max_udp_sessions(), Some(1));
    }
}
