//! 可用内存探测 + 内存档位派生（bd sfqlu）。
//!
//! 用户拍板（2026-11-07）：「速度和内存都自动适应，让 256MB 内存的小鸡都能流畅
//! 运行并发挥连接速度原本的能力，内存不会压爆，还能让小鸡开启其他 sing-box /
//! cf 隧道」。
//!
//! ## 一次探测 + 一次派生（无运行时重平衡）
//!
//! 探测顺序（第一个命中即用；全失效兜底 [`FALLBACK_AVAILABLE_BYTES`]）：
//! 1. `XRAY_MEM_LIMIT_MB`（测试/运维强制档位，最高优先）
//! 2. Linux cgroup v2 `memory.max`
//! 3. Linux cgroup v1 `memory.limit_in_bytes`
//! 4. Linux `/proc/meminfo` 的 `MemAvailable`
//! 5. Windows `GlobalMemoryStatusEx().ullAvailPhys`
//! 6. 兜底 512MB（**不得 panic、不得返 0**）
//!
//! 派生面（[`MemoryPlan`]）：总预算 → 桥每方向字节闸 → 连接数上限。改探测量即
//! 换档，不改代码（这与 `xray_frame::budget` 的「上界一律显式常量」不冲突：
//! 那条管单个容器的上界常量，本条管**整机分账总额**随机器自适）。
//!
//! ## 为什么连接数上限是主杠杆
//!
//! 每连接在途字节数（BDP）由链路 RTT × 带宽决定，砍它就直接砍吞吐（bd u440m：
//! 2MiB 闸在 RTT 161.6ms 下 −6.1%）。所以单连接窗口**不压缩**，内存靠
//! `总预算 / 每连接规划上界` 得到的连接数上限控制，触顶走 fail-visible 拒绝。

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
/// 常驻份额）。四档由此得 13 / 32 / 64 / 170 条，小 VPS 自用足够。
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
        let max_conns = std::env::var(ENV_MAX_CONNS).ok().and_then(|v| v.trim().parse().ok());
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
        // `XRAY_MAX_CONNS=0` 视同未设（否则等于全拒，运维误设即服务不可用）。
        let max_conns = match max_conns_override {
            Some(n) if n > 0 => n,
            _ => (total_budget / PER_CONN_UPPER_BYTES).max(1),
        };
        Self { available, tier, total_budget, bridge_gate, max_conns, source }
    }

    /// 单行摘要（启动日志 + 报告用）。
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "memory plan: tier {} ({}) available {}B via {} -> budget {}B, bridge gate {}B/dir, \
             max {} conns",
            self.tier.as_str(),
            self.tier.label(),
            self.available,
            self.source,
            self.total_budget,
            self.bridge_gate,
            self.max_conns,
        )
    }
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

// ── Windows 探测实现（手写 FFI：本 crate 不引 windows-sys 依赖）──

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
}
