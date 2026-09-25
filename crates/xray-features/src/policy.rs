//! Policy manager trait for connection limits and timeouts.
//!
//! Corresponds to Go's `features/policy` package.

use std::time::Duration;

use async_trait::async_trait;

use crate::Feature;

/// Feature type identifier for Policy.
pub const FEATURE_POLICY: &str = "policy";

/// Default handshake timeout (60 seconds).
///
/// 对应 Go `features/policy/policy.go:118 SessionDefault().Timeouts.Handshake`（60s）；
/// 注释解释 "Align Handshake timeout with nginx client_header_timeout so that this
/// value will not indicate server identity"。Rust 之前误写为 5s，偏离 Go。
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// Default connection idle timeout (5 minutes).
///
/// 对应 Go `features/policy.SessionDefault().Timeouts.ConnectionIdle`（300s）。
pub const DEFAULT_CONN_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Default uplink-only timeout (1 second).
///
/// 对应 Go `SessionDefault().Timeouts.UplinkOnly`（1s）：上行结束后下行方向的
/// 剩余存活窗口。
pub const DEFAULT_UPLINK_ONLY_TIMEOUT: Duration = Duration::from_secs(1);

/// Default downlink-only timeout (1 second).
///
/// 对应 Go `SessionDefault().Timeouts.DownlinkOnly`（1s）：下行结束后上行方向的
/// 剩余存活窗口。
pub const DEFAULT_DOWNLINK_ONLY_TIMEOUT: Duration = Duration::from_secs(1);

/// Fallback per-connection pipe buffer limit (512 KiB).
///
/// 对应 Go `defaultBufferSize` 的 GOARCH「其他」分支（x86_64 等）。
/// `XRAY_BUFSIZE` env 桥接已实现：[`BufferPolicy::default`] 经
/// [`default_buffer_connection_from_env`] 消费 env（Go policy.go:86-116
/// `defaultBufferSize atomic` + `reloadEnvSettings` 的 init 等价物）。
pub const DEFAULT_BUFFER_CONNECTION: i32 = 512 * 1024;

/// Default buffer write size.
pub const DEFAULT_BUFFER_WRITE: usize = 1024;

/// Policy for a user level, defining connection limits and timeouts.
///
/// Corresponds to Go's `features/policy.Policy` and `features/policy.SessionPolicy`.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// Connection timeout settings.
    pub timeout: TimeoutPolicy,
    /// Statistics settings.
    pub stats: StatsPolicy,
    /// Buffer settings.
    pub buffer: BufferPolicy,
}

/// Timeout policy for connection lifecycle.
///
/// Corresponds to Go's `features/policy.TimeoutPolicy`.
#[derive(Debug, Clone)]
pub struct TimeoutPolicy {
    /// Handshake timeout.
    pub handshake: Duration,
    /// Connection idle timeout.
    pub connection_idle: Duration,
    /// Uplink-only timeout.
    pub uplink_only: Duration,
    /// Downlink-only timeout.
    pub downlink_only: Duration,
}

impl Default for TimeoutPolicy {
    fn default() -> Self {
        Self {
            handshake: DEFAULT_HANDSHAKE_TIMEOUT,
            connection_idle: DEFAULT_CONN_IDLE_TIMEOUT,
            uplink_only: DEFAULT_UPLINK_ONLY_TIMEOUT,
            downlink_only: DEFAULT_DOWNLINK_ONLY_TIMEOUT,
        }
    }
}

/// Corresponds to Go's `features/policy.StatsPolicy`.
#[derive(Debug, Clone, Default)]
pub struct StatsPolicy {
    /// Whether to track user uplink traffic.
    pub user_uplink: bool,
    /// Whether to track user downlink traffic.
    pub user_downlink: bool,
    /// Whether to track online IPs per user.
    ///
    /// 对应 Go `features/policy.Stats.UserOnline`。开启后 inbound session
    /// 在 `StatsPolicy.user_online` 为 true 时通过 [`xray_app_stats`] 注册
    /// `user>>>{email}>>>online` OnlineMap 并 AddIP，会话结束时 RemoveIP。
    pub user_online: bool,
}

/// Buffer policy for connection buffering.
///
/// Corresponds to Go's `features/policy.BufferPolicy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferPolicy {
    /// Connection buffer size.
    ///
    /// `i32` 对齐 Go `Buffer.PerConnection int32`。约定：
    /// - `>= 0`：每连接字节数（**仅 dispatch 用作 pipe limit，policy 本身不起分配**）。
    /// - `-1`：无限缓冲。Go `pipe.OptionsFromContext` 见 `bp.PerConnection < 0` 分支跳过
    ///   SizeLimit； Rust 由 `xray_app_dispatcher` 直接透传到
    ///   `pipe.limit`，`pipe::PipeOption::is_full` 在 `limit < 0` 时永不触发（已对齐 Go 行为）。
    /// - `0`：不分配 per-conn 缓冲（VMessClosing/ZeroBuffer 等场景）。
    pub connection: i32,
    /// Write buffer size.
    pub write: usize,
}

impl Default for BufferPolicy {
    fn default() -> Self {
        Self { connection: *DEFAULT_BUFFER_CONNECTION_FROM_ENV, write: DEFAULT_BUFFER_WRITE }
    }
}

/// env 原始串 → MiB 整数；缺失/非数字 → None（Go `GetValueAsInt`：
/// 解析失败回退「未设置」语义，走 GOARCH 分支）。
#[must_use]
fn parse_xray_bufsize(raw: Option<&str>) -> Option<i64> {
    raw.and_then(|v| v.trim().parse::<i64>().ok())
}

/// `XRAY_BUFSIZE` → SessionDefault per-connection buffer，进程级一次读取缓存
/// （对齐 Go `defaultBufferSize atomic.Int32` init 时填充；Rust 无 SIGHUP
/// reload 机制，进程生命周期内取一次值）。
static DEFAULT_BUFFER_CONNECTION_FROM_ENV: std::sync::LazyLock<i32> =
    std::sync::LazyLock::new(|| {
        default_buffer_connection_from_env(parse_xray_bufsize(
            std::env::var("XRAY_BUFSIZE").ok().as_deref(),
        ))
    });

/// System-level policy.
///
/// 对应 Go `features/policy.System = SystemStats + Buffer`：包含全局 stats 与 buffer 配置。
/// Rust 之前只承载 stats 子结构，缺 buffer；现在补齐以对齐 Go System 结构（policy.go:52-56）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemStats {
    /// 是否开启 inbound uplink/downlink 流量统计
    /// （对应 Go `System.Stats.Inbound{Uplink,Downlink}`）。
    pub inbound_uplink: bool,
    pub inbound_downlink: bool,
    /// 是否开启 outbound uplink/downlink 流量统计
    /// （对应 Go `System.Stats.Outbound{Uplink,Downlink}`）。
    pub outbound_uplink: bool,
    pub outbound_downlink: bool,
    /// 系统级连接缓冲策略（对应 Go `System.Buffer`）。
    pub buffer: BufferPolicy,
}

/// `XRAY_BUFSIZE` env 解析 + GOARCH 分支 → 默认 buffer size（字节）。
///
/// 对应 Go `features/policy/policy.go:87-106 init()` 中 defaultBufferSize 计算。
/// 这里把 env 读取抽象为参数，调用方（装配层 `xray-app-policy`/`xray-core`）自行读
/// `XRAY_BUFSIZE`，传入此函数求值。这样测试可独立验证各分支，且不污染 xray-features
/// 全局状态。
///
/// 规则（policy.go:91-105）：
/// - `env == Some(0)`：映射为 `usize::MAX`（无限缓冲；Go `defaultBufferSize = -1`）。
/// - `env == Some(n)`：返回 `n * 1024 * 1024`（MiB）。
/// - `env == None`：按 GOARCH 分支：
///   - `arm` / `mips` / `mipsle` → `0`（低功耗设备不预分配）
///   - `arm64` / `mips64` / `mips64el` → `4096`（4 KiB cache）
///   - 其他 → `524288`（512 KiB）
#[must_use]
pub fn default_buffer_connection_from_env(env_mb: Option<i64>) -> i32 {
    match env_mb {
        Some(0) => -1, // -1 表示无限缓冲（policy.go:91-93 defaultBufferSize = -1）
        Some(n) if n > 0 => {
            let bytes = n.saturating_mul(1024 * 1024);
            // clamp 到 i32 正值上限；超出视为「错误配置 → 0」（与 Go int32 截断语义近似）
            i32::try_from(bytes.min(i32::MAX as i64)).unwrap_or(0)
        },
        // 负数（除 0）、无效输入 → 0（Go defaultBufferSize = int32(负) 截断到 0）
        Some(_) => 0,
        None => {
            #[cfg(any(target_arch = "arm", target_arch = "mips"))]
            {
                0
            }
            // 架构分支对齐 Go policy.go：arm/mips → 0，mips64 → 4KB，其余 → 512KB。
            // 注意 rustc 的 target_arch 无 "arm64"/"mips64el" 值（对应 aarch64/mips64），
            // 原写法这两个值恒不匹配；aarch64 落入 512KB 分支与 Go 的 4KB 分支存在
            // 已知偏差，改 cfg 值会变更激活行为，维持现状待专项票。
            #[cfg(target_arch = "mips64")]
            {
                (4 * 1024) as i32
            }
            #[cfg(not(any(target_arch = "arm", target_arch = "mips", target_arch = "mips64")))]
            {
                512 * 1024
            }
        },
    }
}

/// Policy manager trait.
///
/// Corresponds to Go's `features/policy.Manager`.
#[async_trait]
pub trait PolicyManager: Send + Sync {
    /// Get the policy for the given user level.
    fn policy_for_level(&self, level: u32) -> Policy;

    /// Get the system-level statistics policy.
    ///
    /// Corresponds to Go's `(*Manager).ForSystem()`.
    fn for_system(&self) -> SystemStats;
}

/// 默认 Policy Feature 实现（essentialFeatures fallback）。
///
/// 当配置中没有指定 policy app 时，Instance 使用此空实现占位。
pub struct DefaultPolicyFeature;

impl Feature for DefaultPolicyFeature {
    fn feature_name(&self) -> &'static str {
        "default_policy"
    }
}

impl PolicyManager for DefaultPolicyFeature {
    fn policy_for_level(&self, _level: u32) -> Policy {
        Policy::default()
    }

    fn for_system(&self) -> SystemStats {
        SystemStats::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_policy_constant() {
        assert_eq!(FEATURE_POLICY, "policy");
    }

    #[test]
    fn test_default_policy() {
        let policy = Policy::default();
        assert_eq!(policy.timeout.handshake, DEFAULT_HANDSHAKE_TIMEOUT);
        assert_eq!(policy.timeout.connection_idle, DEFAULT_CONN_IDLE_TIMEOUT);
        assert_eq!(policy.timeout.uplink_only, DEFAULT_UPLINK_ONLY_TIMEOUT);
        assert_eq!(policy.timeout.downlink_only, DEFAULT_DOWNLINK_ONLY_TIMEOUT);
        assert!(!policy.stats.user_uplink);
        assert!(!policy.stats.user_downlink);
        assert!(!policy.stats.user_online, "user_online must default false");
        assert_eq!(policy.buffer.connection, DEFAULT_BUFFER_CONNECTION);
    }

    #[test]
    fn test_default_stats_policy_user_online_false() {
        // 对齐 Go features/policy/policy.go:128 SessionDefault() 里 UserOnline: false
        let s = StatsPolicy::default();
        assert!(!s.user_uplink);
        assert!(!s.user_downlink);
        assert!(!s.user_online);
    }

    #[test]
    fn test_default_timeout_policy() {
        // 对齐 Go features/policy/policy.go:117-122 SessionDefault:
        // Handshake=60s, ConnectionIdle=300s, UplinkOnly=1s, DownlinkOnly=1s
        let timeout = TimeoutPolicy::default();
        assert_eq!(timeout.handshake, Duration::from_secs(60));
        assert_eq!(timeout.connection_idle, Duration::from_secs(300));
        assert_eq!(timeout.uplink_only, Duration::from_secs(1));
        assert_eq!(timeout.downlink_only, Duration::from_secs(1));
    }

    #[test]
    fn test_custom_policy() {
        let policy = Policy {
            timeout: TimeoutPolicy {
                handshake: Duration::from_secs(10),
                connection_idle: Duration::from_secs(600),
                uplink_only: Duration::from_secs(180),
                downlink_only: Duration::from_secs(180),
            },
            stats: StatsPolicy { user_uplink: true, user_downlink: true, user_online: true },
            buffer: BufferPolicy { connection: 2048, write: 2048 },
        };
        assert_eq!(policy.timeout.handshake, Duration::from_secs(10));
        assert!(policy.stats.user_uplink);
        assert!(policy.stats.user_downlink);
        assert!(policy.stats.user_online);
    }

    #[test]
    fn test_system_stats_buffer_default_aligns_go_default() {
        // 对齐 Go features/policy/policy.go:52-56 System{Buffer: defaultBufferPolicy()}
        // 及 defaultBufferPolicy() = Buffer{PerConnection: 512 * 1024}（policy.go:108-112）。
        // Rust proto 当前 SystemPolicy 未暴露 buffer 字段，所以 SystemStats.buffer 走
        // BufferPolicy::default()=512 KiB。
        let s = SystemStats::default();
        assert_eq!(s.buffer.connection, DEFAULT_BUFFER_CONNECTION);
        assert_eq!(s.buffer.connection, 512 * 1024);
        assert_eq!(s.buffer.write, DEFAULT_BUFFER_WRITE);
        // 同时验证 stats 子结构仍是 default（与原行为兼容）
        assert!(!s.inbound_uplink);
        assert!(!s.outbound_downlink);
    }

    // ====== 76q3 → 改: Buffer.connection: usize → i32，-1 直接对齐 Go int32 无限 ======

    /// `XRAY_BUFSIZE=0` → 无限缓冲，对应 Go `policy.go:91-93 defaultBufferSize = -1`。
    /// 现 `BufferPolicy.connection` 是 i32，-1 直接表达无限（不再映射为 usize::MAX）。
    #[test]
    fn test_default_buffer_env_zero_means_unlimited() {
        let size = default_buffer_connection_from_env(Some(0));
        assert_eq!(size, -1_i32, "env=0 must map to unlimited (-1_i32), got {size}");
    }
    /// `XRAY_BUFSIZE=N`（N>0）→ N MiB（policy.go:104 `defaultBufferSize = int32(size) * 1024 *
    /// 1024`）。
    #[test]
    fn test_default_buffer_env_n_mb_scales_by_mb() {
        assert_eq!(default_buffer_connection_from_env(Some(1)), 1024 * 1024);
        assert_eq!(default_buffer_connection_from_env(Some(8)), 8 * 1024 * 1024);
        assert_eq!(default_buffer_connection_from_env(Some(64)), 64 * 1024 * 1024);
        // 负数（除 0）→ 0（与 Go int32(负) 行为近似）；
        // 巨大值会被 clamp 到 i32::MAX（与 Go int32 溢出不同，但不会 panic）。
        assert_eq!(default_buffer_connection_from_env(Some(-7)), 0);
    }
    /// 未设 env：按本机 GOARCH 分支取值（policy.go:94-102）。
    /// 本机 Windows x86_64 落入「其他」分支 → 512 KiB。
    #[test]
    fn test_default_buffer_env_unset_respects_target_arch() {
        let size = default_buffer_connection_from_env(None);
        #[cfg(any(target_arch = "arm", target_arch = "mips"))]
        assert_eq!(size, 0, "arm/mips GOARCH branch expects 0");
        // rustc target_arch 无 "arm64"/"mips64el"（对应 aarch64/mips64），恒假值已删。
        #[cfg(target_arch = "mips64")]
        assert_eq!(size, 4096, "mips64 GOARCH branch expects 4 KiB");
        #[cfg(not(any(target_arch = "arm", target_arch = "mips", target_arch = "mips64")))]
        assert_eq!(size, 512 * 1024, "其他 GOARCH 分支（x86_64 等）期望 512 KiB");
    }

    /// SystemStats.buffer 默认 512 KiB（policy.go:108-112 `defaultBufferPolicy()`），验证
    /// SystemPolicy proto 未暴露 buffer 字段时 `system_stats_from_proto` 仍回落到
    /// `BufferPolicy::default()`=512 KiB。
    #[test]
    fn test_system_stats_buffer_default_roundtrip_via_default_policy() {
        // 对应 Go features/policy/policy.go:52-56 System{Buffer: defaultBufferPolicy()}
        // 与 policy.go:108-112 defaultBufferPolicy() = Buffer{PerConnection: 512*1024}
        // 已由现有 test_system_stats_buffer_default_aligns_go_default 覆盖；这里补一个
        // 走 `default_buffer_connection_from_env` 路径的反向验证：env 缺省下的 512 KiB
        // 应等于 SystemStats::default().buffer.connection（GOARCH 「其他」分支）。
        #[cfg(not(any(target_arch = "arm", target_arch = "mips", target_arch = "mips64")))]
        {
            let sys = SystemStats::default();
            assert_eq!(sys.buffer.connection, default_buffer_connection_from_env(None));
            assert_eq!(sys.buffer.connection, 512 * 1024);
        }
    }

    /// XRAY_BUFSIZE 原始串解析：有效整数/空白容忍/非数字与缺失回退 None
    /// （Go GetValueAsInt 解析失败 = 未设置语义）。
    #[test]
    fn test_parse_xray_bufsize_env_raw() {
        assert_eq!(parse_xray_bufsize(Some("4")), Some(4));
        assert_eq!(parse_xray_bufsize(Some(" 2 ")), Some(2));
        assert_eq!(parse_xray_bufsize(Some("-3")), Some(-3));
        assert_eq!(parse_xray_bufsize(Some("abc")), None, "非数字必须回退未设置");
        assert_eq!(parse_xray_bufsize(Some("")), None);
        assert_eq!(parse_xray_bufsize(None), None);
    }

    /// env 桥接端到端：BufferPolicy::default().connection 必须等于
    /// `default_buffer_connection_from_env(parse(env))`（sm80⑤ 接线：
    /// 此前 default 恒 512 KiB，XRAY_BUFSIZE 零消费）。
    /// 不 set_var：LazyLock 进程级缓存 + 测试并行会互相污染。
    #[test]
    fn test_buffer_policy_default_follows_env_bridge() {
        let env = parse_xray_bufsize(std::env::var("XRAY_BUFSIZE").ok().as_deref());
        assert_eq!(
            BufferPolicy::default().connection,
            default_buffer_connection_from_env(env),
            "BufferPolicy::default must consume XRAY_BUFSIZE via env bridge"
        );
    }

    // ====== ivst: VMessClosing 行为 + ZeroBuffer 行为单测 ======

    /// ivst · VMessClosing 行为：`UplinkOnly=0` & `DownlinkOnly=0` 表示连接断开后 buf 立即 flush
    /// （Go `testing/scenarios/policy_test.go:46 TestVMessClosing` 测试场景）。Rust 端把
    /// `timeout.uplink_only=0` 当作「无缓冲窗口期」，链路关闭后立即 ZeroBuffer。本测试断言
    /// `TimeoutPolicy{uplink_only=0, downlink_only=0, ...}` 仍能安全构造/访问，不 panic、不
    /// clamp 到默认值（与 Go 行为：proto `Some(0)` 覆盖为 0）。
    #[test]
    fn test_vmess_closing_timeout_zero_is_immediate_flush() {
        // 对应 Go testing/scenarios/policy_test.go:46 TestVMessClosing
        // policy.Config{Timeout{UplinkOnly: 0, DownlinkOnly: 0}}
        let policy = Policy {
            timeout: TimeoutPolicy {
                handshake: DEFAULT_HANDSHAKE_TIMEOUT,
                connection_idle: DEFAULT_CONN_IDLE_TIMEOUT,
                uplink_only: Duration::ZERO,
                downlink_only: Duration::ZERO,
            },
            stats: StatsPolicy::default(),
            buffer: BufferPolicy::default(),
        };
        assert_eq!(
            policy.timeout.uplink_only,
            Duration::ZERO,
            "UplinkOnly=0 must survive (Go proto Some(0) override)"
        );
        assert_eq!(
            policy.timeout.downlink_only,
            Duration::ZERO,
            "DownlinkOnly=0 must survive (Go proto Some(0) override)"
        );
        // 关键不变式：与 proto 转换一致——proto Some(0) 必须覆盖为 0 而非被 clamp 到默认 1s。
        // （对应 app/policy/convert.rs:40-43：uplink_only.is_some() → 不走 default）
        // 此处直接断言结构构造行为，避开 proto 测试。
    }

    /// ivst · ZeroBuffer 行为：`Buffer.connection=0` 表示不分配 per-connection 缓冲
    /// （Go `testing/scenarios/policy_test.go:150 TestZeroBuffer` 测试场景）。
    /// 本测试断言 connection=0 可正常表示，与无限（-1_i32）不冲突。
    #[test]
    fn test_zero_buffer_connection_zero_is_legal_value() {
        let policy = Policy {
            timeout: TimeoutPolicy::default(),
            stats: StatsPolicy::default(),
            buffer: BufferPolicy { connection: 0, write: DEFAULT_BUFFER_WRITE },
        };
        assert_eq!(policy.buffer.connection, 0, "Buffer.connection=0 is legal zero-buffer");
        // 0 ≠ -1（无限）；二者分别对应：
        //   0  = 不分配 per-conn 缓冲（VMessClosing/ZeroBuffer 场景）
        //   -1 = 无限（env=0 / proto 一致）
        assert_ne!(policy.buffer.connection, -1_i32);
        assert_ne!(policy.buffer.connection, -2_i32); // 任意负值都不是合法下限
    }

    // ====== 改（Batch10 P3 无限支持）======

    /// 默认 connection 与 Go defaultBufferSize 512 KiB 对齐。
    #[test]
    fn test_default_buffer_connection_is_positive_default() {
        let buf = BufferPolicy::default();
        assert_eq!(buf.connection, DEFAULT_BUFFER_CONNECTION);
        assert!(buf.connection > 0, "default must not be unlimited");
    }

    /// Go semantic: BufferSize=0 (env) → -1 unlimited；
    /// 这里用结构构造验证 connection=-1 可安全表示（不会 panic、不被 clamp 到 0）。
    #[test]
    fn test_buffer_connection_minus_one_is_unlimited_sentinel() {
        let buf = BufferPolicy { connection: -1, write: DEFAULT_BUFFER_WRITE };
        assert_eq!(buf.connection, -1);
        // 作为 i64 透传到 pipe.limit（dispatcher default.rs:704,769）：
        // `-1_i32 as i64 == -1_i64`，pipe.rs is_full 检查 `self.limit >= 0 && cur > limit`
        // → 永真分支出无限语义。
        let as_pipe_limit = buf.connection as i64;
        assert!(as_pipe_limit < 0, "must stay negative when widened to i64");
    }
}
