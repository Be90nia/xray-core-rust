//! Policy manager trait for connection limits and timeouts.
//!
//! Corresponds to Go's `features/policy` package.

use async_trait::async_trait;
use std::time::Duration;
use crate::Feature;

/// Feature type identifier for Policy.
pub const FEATURE_POLICY: &str = "policy";

/// Default handshake timeout (5 seconds).
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Default connection idle timeout (5 minutes).
pub const DEFAULT_CONN_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Default uplink-only timeout (2 minutes).
pub const DEFAULT_UPLINK_ONLY_TIMEOUT: Duration = Duration::from_secs(120);

/// Default downlink-only timeout (2 minutes).
pub const DEFAULT_DOWNLINK_ONLY_TIMEOUT: Duration = Duration::from_secs(120);

/// Default buffer connection size.
pub const DEFAULT_BUFFER_CONNECTION: usize = 1024;

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

/// Statistics policy.
///
/// Corresponds to Go's `features/policy.StatsPolicy`.
#[derive(Debug, Clone)]
pub struct StatsPolicy {
    /// Whether to track user uplink traffic.
    pub user_uplink: bool,
    /// Whether to track user downlink traffic.
    pub user_downlink: bool,
}

impl Default for StatsPolicy {
    fn default() -> Self {
        Self {
            user_uplink: false,
            user_downlink: false,
        }
    }
}

/// Buffer policy for connection buffering.
///
/// Corresponds to Go's `features/policy.BufferPolicy`.
#[derive(Debug, Clone)]
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

/// System-level statistics policy.
///
/// Corresponds to Go's `features/policy.SystemStats`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SystemStats {
    /// Whether to enable stat counter for uplink traffic in inbound handlers.
    pub inbound_uplink: bool,
    /// Whether to enable stat counter for downlink traffic in inbound handlers.
    pub inbound_downlink: bool,
    /// Whether to enable stat counter for uplink traffic in outbound handlers.
    pub outbound_uplink: bool,
    /// Whether to enable stat counter for downlink traffic in outbound handlers.
    pub outbound_downlink: bool,
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
        assert_eq!(policy.buffer.connection, DEFAULT_BUFFER_CONNECTION);
        assert_eq!(policy.buffer.write, DEFAULT_BUFFER_WRITE);
    }

    #[test]
    fn test_default_timeout_policy() {
        let timeout = TimeoutPolicy::default();
        assert_eq!(timeout.handshake, Duration::from_secs(5));
        assert_eq!(timeout.connection_idle, Duration::from_secs(300));
        assert_eq!(timeout.uplink_only, Duration::from_secs(120));
        assert_eq!(timeout.downlink_only, Duration::from_secs(120));
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
            },
            buffer: BufferPolicy {
                connection: 2048,
                write: 2048,
            },
        };
        assert_eq!(policy.timeout.handshake, Duration::from_secs(10));
        assert!(policy.stats.user_uplink);
        assert!(policy.stats.user_downlink);
        assert_eq!(policy.buffer.connection, 2048);
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
    fn test_mock_policy_manager() {
        let manager = MockPolicyManager;
        let policy = manager.policy_for_level(0);
        assert_eq!(policy.timeout.handshake, DEFAULT_HANDSHAKE_TIMEOUT);
    }
}
