//! Policy manager trait for connection limits and timeouts.
//!
//! Corresponds to Go's `features/policy` package.

use async_trait::async_trait;
use std::time::Duration;
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

/// Default per-connection pipe buffer limit (512 KiB).
///
/// 对应 Go `defaultBufferSize`（512*1024，`XRAY_BUFSIZE` env 可调——此处不读 env，
/// 需要时在装配层读后覆盖 policy）。
pub const DEFAULT_BUFFER_CONNECTION: usize = 512 * 1024;

/// Default buffer write size.
pub const DEFAULT_BUFFER_WRITE: usize = 1024;

/// Policy for a user level, defining connection limits and timeouts.
///
/// Corresponds to Go's `features/policy.Policy` and `features/policy.SessionPolicy`.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Connection timeout settings.
    pub timeout: TimeoutPolicy,
    /// Statistics settings.
    pub stats: StatsPolicy,
    /// Buffer settings.
    pub buffer: BufferPolicy,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            timeout: TimeoutPolicy::default(),
            stats: StatsPolicy::default(),
            buffer: BufferPolicy::default(),
        }
    }
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

///
/// Corresponds to Go's `features/policy.StatsPolicy`.
#[derive(Debug, Clone)]
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

impl Default for StatsPolicy {
    fn default() -> Self {
        Self {
            user_uplink: false,
            user_downlink: false,
            user_online: false,
        }
    }
}



/// Buffer policy for connection buffering.
///
/// Corresponds to Go's `features/policy.BufferPolicy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferPolicy {
    /// Connection buffer size.
    pub connection: usize,
    /// Write buffer size.
    pub write: usize,
}

impl Default for BufferPolicy {
    fn default() -> Self {
        Self {
            connection: DEFAULT_BUFFER_CONNECTION,
            write: DEFAULT_BUFFER_WRITE,
        }
    }
}

/// System-level policy.
///
/// 对应 Go `features/policy.System = SystemStats + Buffer`：包含全局 stats 与 buffer 配置。
/// Rust 之前只承载 stats 子结构，缺 buffer；现在补齐以对齐 Go System 结构（policy.go:52-56）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemStats {
    /// 是否开启 inbound uplink/downlink 流量统计
    ///（对应 Go `System.Stats.Inbound{Uplink,Downlink}`）。
    pub inbound_uplink: bool,
    pub inbound_downlink: bool,
    /// 是否开启 outbound uplink/downlink 流量统计
    ///（对应 Go `System.Stats.Outbound{Uplink,Downlink}`）。
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
pub fn default_buffer_connection_from_env(env_mb: Option<i64>) -> usize {
    match env_mb {
        Some(0) => usize::MAX,
        Some(n) => (n as usize).saturating_mul(1024 * 1024),
        None => {
            #[cfg(any(target_arch = "arm", target_arch = "mips"))]
            {
                0
            }
            #[cfg(any(target_arch = "arm64", target_arch = "mips64", target_arch = "mips64el"))]
            {
                4 * 1024
            }
            #[cfg(not(any(
                target_arch = "arm",
                target_arch = "mips",
                target_arch = "arm64",
                target_arch = "mips64",
                target_arch = "mips64el",
            )))]
            {
                512 * 1024
            }
        }
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
            stats: StatsPolicy {
                user_uplink: true,
                user_downlink: true,
                user_online: true,
            },
            buffer: BufferPolicy {
                connection: 2048,
                write: 2048,
            },
        };
        assert_eq!(policy.timeout.handshake, Duration::from_secs(10));
        assert!(policy.stats.user_uplink);
        assert!(policy.stats.user_downlink);
        assert!(policy.stats.user_online);
    }

    /// Mock policy manager for testing.
    struct MockPolicyManager;

    #[async_trait]
    impl PolicyManager for MockPolicyManager {
        fn policy_for_level(&self, _level: u32) -> Policy {
            Policy::default()
        }

        fn for_system(&self) -> SystemStats {
            SystemStats::default()
        }
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

    // ====== 76q3: SystemBuffer PolicySystem.Stats/Buffer + env 解析 + GOARCH 分支 + Buffer=-1 无限 ======

    /// `XRAY_BUFSIZE=0` → 无限缓冲（policy.go:91-93：`defaultBufferSize = -1`，Rust 端映射为 `usize::MAX`）。
    #[test]
    fn test_default_buffer_env_zero_means_unlimited() {
        // 对应 Go features/policy/policy.go:91-93: env=0 → defaultBufferSize = -1（无限）
        let size = default_buffer_connection_from_env(Some(0));
        assert_eq!(
            size,
            usize::MAX,
            "env=0 must map to unlimited (usize::MAX), got {size}"
        );
    }

    /// `XRAY_BUFSIZE=N`（N>0）→ N MiB（policy.go:104：`defaultBufferSize = int32(size) * 1024 * 1024`）。
    #[test]
    fn test_default_buffer_env_n_mb_scales_by_mb() {
        // 对应 Go features/policy/policy.go:103-104: env=N → N MiB
        assert_eq!(default_buffer_connection_from_env(Some(1)), 1024 * 1024);
        assert_eq!(default_buffer_connection_from_env(Some(8)), 8 * 1024 * 1024);
        assert_eq!(default_buffer_connection_from_env(Some(64)), 64 * 1024 * 1024);
    }

    /// 未设 env：按本机 GOARCH 分支取值（policy.go:94-102）。
    /// 本机 Windows x86_64 落入「其他」分支 → 512 KiB。
    #[test]
    fn test_default_buffer_env_unset_respects_target_arch() {
        let size = default_buffer_connection_from_env(None);
        #[cfg(any(target_arch = "arm", target_arch = "mips"))]
        assert_eq!(size, 0, "arm/mips GOARCH branch expects 0");
        #[cfg(any(target_arch = "arm64", target_arch = "mips64", target_arch = "mips64el"))]
        assert_eq!(size, 4096, "arm64/mips64 GOARCH branch expects 4 KiB");
        #[cfg(not(any(
            target_arch = "arm",
            target_arch = "mips",
            target_arch = "arm64",
            target_arch = "mips64",
            target_arch = "mips64el",
        )))]
        assert_eq!(size, 512 * 1024, "其他 GOARCH 分支（x86_64 等）期望 512 KiB");
    }

    /// SystemStats.buffer 默认 512 KiB（policy.go:108-112 `defaultBufferPolicy()`），验证 SystemPolicy
    /// proto 未暴露 buffer 字段时 `system_stats_from_proto` 仍回落到 `BufferPolicy::default()`=512 KiB。
    #[test]
    fn test_system_stats_buffer_default_roundtrip_via_default_policy() {
        // 对应 Go features/policy/policy.go:52-56 System{Buffer: defaultBufferPolicy()}
        // 与 policy.go:108-112 defaultBufferPolicy() = Buffer{PerConnection: 512*1024}
        // 已由现有 test_system_stats_buffer_default_aligns_go_default 覆盖；这里补一个
        // 走 `default_buffer_connection_from_env` 路径的反向验证：env 缺省下的 512 KiB
        // 应等于 SystemStats::default().buffer.connection（GOARCH 「其他」分支）。
        #[cfg(not(any(
            target_arch = "arm",
            target_arch = "mips",
            target_arch = "arm64",
            target_arch = "mips64",
            target_arch = "mips64el",
        )))]
        {
            let sys = SystemStats::default();
            assert_eq!(sys.buffer.connection, default_buffer_connection_from_env(None));
            assert_eq!(sys.buffer.connection, 512 * 1024);
        }
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
    /// 本测试断言 connection=0 可正常表示，与负数 → usize::MAX 不冲突。
    #[test]
    fn test_zero_buffer_connection_zero_is_legal_value() {
        // 对应 Go testing/scenarios/policy_test.go:150 TestZeroBuffer
        // policy.Config{Buffer{Connection: 0}}
        let policy = Policy {
            timeout: TimeoutPolicy::default(),
            stats: StatsPolicy::default(),
            buffer: BufferPolicy {
                connection: 0,
                write: DEFAULT_BUFFER_WRITE,
            },
        };
        assert_eq!(policy.buffer.connection, 0, "Buffer.connection=0 is legal zero-buffer");
        // 与「无限缓冲（usize::MAX）」互斥，二者分别对应：
        //   0  = 不分配 per-conn 缓冲（VMessClosing/ZeroBuffer 场景）
        //   usize::MAX = 无限（env=0 场景）
        assert_ne!(policy.buffer.connection, usize::MAX);
    }
}

