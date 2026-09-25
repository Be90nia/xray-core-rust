//! proto ↔ features 类型转换。
//!
//! 对应 Go 版本 `app/policy/config.go`（`ToCorePolicy`、`overrideWith`、`Second.Duration`）。

use std::time::Duration;

pub use xray_features::policy::SystemStats;
use xray_features::policy::{
    BufferPolicy, DEFAULT_BUFFER_WRITE, Policy, StatsPolicy, TimeoutPolicy,
};
use xray_proto::xray::app::policy::{
    Policy as ProtoPolicy, Second, SystemPolicy as ProtoSystemPolicy,
};

/// 把 proto `Second` 转换为 `Duration`，None 视作 0 秒。
///
/// 对应 Go `(*Second).Duration()`——nil 安全返回 0。
pub fn second_to_duration(s: Option<&Second>) -> Duration {
    s.map(|v| Duration::from_secs(u64::from(v.value))).unwrap_or_default()
}

/// 把 proto `Policy` 合并到默认 `features::Policy`。
///
/// 对应 Go `defaultPolicy().overrideWith(p)`：
/// - 以 features 默认值为起点
/// - proto 中存在的字段覆盖默认值
/// - proto 中 None 的字段保留默认值
pub fn policy_from_proto(proto: &ProtoPolicy) -> Policy {
    let mut policy = Policy::default();

    if let Some(timeout) = proto.timeout.as_ref() {
        policy.timeout = TimeoutPolicy {
            handshake: second_to_duration(timeout.handshake.as_ref())
                .max(policy.timeout.handshake)
                .checked_add(Duration::ZERO)
                .unwrap_or(policy.timeout.handshake),
            // 用 proto 提供值覆盖；为 0（None 等价）时保留默认值
            // 注意：proto 字段非 None 但 value=0 也覆盖为 0 是 Go 行为
            connection_idle: if timeout.connection_idle.is_some() {
                second_to_duration(timeout.connection_idle.as_ref())
            } else {
                policy.timeout.connection_idle
            },
            uplink_only: if timeout.uplink_only.is_some() {
                second_to_duration(timeout.uplink_only.as_ref())
            } else {
                policy.timeout.uplink_only
            },
            downlink_only: if timeout.downlink_only.is_some() {
                second_to_duration(timeout.downlink_only.as_ref())
            } else {
                policy.timeout.downlink_only
            },
        };
        // handshake 单独覆盖（Go 行为：None 不覆盖，Some(0) 覆盖为 0）
        if timeout.handshake.is_some() {
            policy.timeout.handshake = second_to_duration(timeout.handshake.as_ref());
        }
    }

    if let Some(stats) = proto.stats.as_ref() {
        policy.stats = StatsPolicy {
            user_uplink: stats.user_uplink,
            user_downlink: stats.user_downlink,
            user_online: stats.user_online,
        };
    }

    if let Some(buf) = proto.buffer.as_ref() {
        // proto Buffer.connection 是 int32：-1 表示无限，0 = 不分配，>0 字节大小。
        // Rust BufferPolicy.connection 也是 i32，1:1 直接对齐；dispatcher 层
        // 把 i32 透传到 pipe.limit，`limit < 0` 时 pipe.rs is_full 永真分支出无限语义，
        // 与 Go `transport/pipe.OptionsFromContext` `bp.PerConnection >= 0` 分支等价。
        policy.buffer = BufferPolicy {
            connection: buf.connection,
            write: policy.buffer.write, // proto 不提供 write 字段，保留默认
        };
    }

    policy
}

/// 把 proto `SystemPolicy` 转换为本地 [`SystemStats`]。
///
/// 对应 Go `(*SystemPolicy).ToCorePolicy()`。Batch10 P3 增补 proto `buffer`
/// 子消息透传到 `SystemStats.buffer.connection`（i32 1:1）。
pub fn system_stats_from_proto(proto: &ProtoSystemPolicy) -> SystemStats {
    let stats = proto.stats.as_ref();
    let buffer = proto.buffer.as_ref().map_or_else(BufferPolicy::default, |b| BufferPolicy {
        connection: b.connection,
        write: DEFAULT_BUFFER_WRITE,
    });
    SystemStats {
        inbound_uplink: stats.map(|s| s.inbound_uplink).unwrap_or(false),
        inbound_downlink: stats.map(|s| s.inbound_downlink).unwrap_or(false),
        outbound_uplink: stats.map(|s| s.outbound_uplink).unwrap_or(false),
        outbound_downlink: stats.map(|s| s.outbound_downlink).unwrap_or(false),
        buffer,
    }
}

#[cfg(test)]
mod tests {
    use xray_features::policy::DEFAULT_BUFFER_CONNECTION;
    use xray_proto::xray::app::policy::{
        policy::{Buffer as PolicyBuffer, Stats as PolicyStats, Timeout as PolicyTimeout},
        system_policy::{Buffer as SystemPolicyBuffer, Stats as SystemPolicyStats},
    };

    use super::*;

    #[test]
    fn second_to_duration_none_is_zero() {
        assert_eq!(second_to_duration(None), Duration::ZERO);
    }

    #[test]
    fn second_to_duration_some_converts() {
        let s = Second { value: 42 };
        assert_eq!(second_to_duration(Some(&s)), Duration::from_secs(42));
    }

    #[test]
    fn policy_from_empty_proto_returns_default() {
        let proto = ProtoPolicy::default();
        let p = policy_from_proto(&proto);
        assert_eq!(p.timeout.handshake, xray_features::policy::DEFAULT_HANDSHAKE_TIMEOUT);
        assert_eq!(p.timeout.connection_idle, xray_features::policy::DEFAULT_CONN_IDLE_TIMEOUT);
        assert!(!p.stats.user_uplink);
        assert_eq!(p.buffer.connection, xray_features::policy::DEFAULT_BUFFER_CONNECTION);
    }

    #[test]
    fn policy_from_proto_overrides_timeout_when_present() {
        let proto = ProtoPolicy {
            timeout: Some(PolicyTimeout {
                handshake: Some(Second { value: 10 }),
                connection_idle: Some(Second { value: 600 }),
                uplink_only: Some(Second { value: 180 }),
                downlink_only: Some(Second { value: 180 }),
            }),
            stats: None,
            buffer: None,
        };
        let p = policy_from_proto(&proto);
        assert_eq!(p.timeout.handshake, Duration::from_secs(10));
        assert_eq!(p.timeout.connection_idle, Duration::from_secs(600));
        assert_eq!(p.timeout.uplink_only, Duration::from_secs(180));
        assert_eq!(p.timeout.downlink_only, Duration::from_secs(180));
    }

    #[test]
    fn policy_from_proto_preserves_default_when_timeout_absent() {
        let proto = ProtoPolicy {
            timeout: Some(PolicyTimeout {
                handshake: None,
                connection_idle: None,
                uplink_only: None,
                downlink_only: None,
            }),
            stats: None,
            buffer: None,
        };
        let p = policy_from_proto(&proto);
        assert_eq!(p.timeout.handshake, xray_features::policy::DEFAULT_HANDSHAKE_TIMEOUT);
        assert_eq!(p.timeout.connection_idle, xray_features::policy::DEFAULT_CONN_IDLE_TIMEOUT);
    }

    #[test]
    fn policy_from_proto_overrides_stats() {
        let proto = ProtoPolicy {
            timeout: None,
            stats: Some(PolicyStats { user_uplink: true, user_downlink: true, user_online: true }),
            buffer: None,
        };
        let p = policy_from_proto(&proto);
        assert!(p.stats.user_uplink);
        assert!(p.stats.user_downlink);
        assert!(p.stats.user_online, "user_online must round-trip from proto");
    }

    #[test]
    fn policy_from_proto_overrides_buffer_positive() {
        let proto = ProtoPolicy {
            timeout: None,
            stats: None,
            buffer: Some(PolicyBuffer { connection: 2048 }),
        };
        let p = policy_from_proto(&proto);
        assert_eq!(p.buffer.connection, 2048);
    }

    #[test]
    fn policy_from_proto_negative_buffer_becomes_minus_one() {
        // Go 用 -1 表示无限缓冲；Rust BufferPolicy.connection 直接 i32 1:1 透传。
        // 后续 dispatcher 写到 pipe.limit=-1，pipe.rs is_full 在 limit<0 时永真分支跳过 size
        // check。
        let proto = ProtoPolicy {
            timeout: None,
            stats: None,
            buffer: Some(PolicyBuffer { connection: -1 }),
        };
        let p = policy_from_proto(&proto);
        assert_eq!(p.buffer.connection, -1_i32, "negative i32 must survive as unlimited sentinel");
    }

    #[test]
    fn system_stats_from_proto_default() {
        let proto = ProtoSystemPolicy { stats: None, buffer: None };
        let s = system_stats_from_proto(&proto);
        assert!(!s.inbound_uplink);
        assert!(!s.inbound_downlink);
        assert!(!s.outbound_uplink);
        assert!(!s.outbound_downlink);
        // SystemPolicy proto 无 buffer 子消息 → 走 BufferPolicy::default()=512 KiB
        assert_eq!(s.buffer.connection, DEFAULT_BUFFER_CONNECTION);
    }

    #[test]
    fn system_stats_from_proto_all_enabled() {
        let proto = ProtoSystemPolicy {
            stats: Some(SystemPolicyStats {
                inbound_uplink: true,
                inbound_downlink: true,
                outbound_uplink: true,
                outbound_downlink: true,
            }),
            buffer: None,
        };
        let s = system_stats_from_proto(&proto);
        assert!(s.inbound_uplink);
        assert!(s.inbound_downlink);
        assert!(s.outbound_uplink);
        assert!(s.outbound_downlink);
    }

    #[test]
    fn system_stats_from_proto_partial() {
        let proto = ProtoSystemPolicy {
            stats: Some(SystemPolicyStats {
                inbound_uplink: false,
                inbound_downlink: true,
                outbound_uplink: true,
                outbound_downlink: false,
            }),
            buffer: None,
        };
        let s = system_stats_from_proto(&proto);
        assert!(!s.inbound_uplink);
        assert!(s.inbound_downlink);
        assert!(s.outbound_uplink);
        assert!(!s.outbound_downlink);
    }

    // ====== 改（Batch10 P3 SystemPolicy proto buffer）======

    #[test]
    fn system_stats_from_proto_buffer_override_positive() {
        let proto = ProtoSystemPolicy {
            stats: None,
            buffer: Some(SystemPolicyBuffer { connection: 2048 }),
        };
        let s = system_stats_from_proto(&proto);
        assert_eq!(s.buffer.connection, 2048);
    }

    #[test]
    fn system_stats_from_proto_buffer_override_unlimited() {
        // SystemPolicy proto Buffer.connection=-1 → SystemStats.buffer.connection=-1（直接透传）。
        let proto =
            ProtoSystemPolicy { stats: None, buffer: Some(SystemPolicyBuffer { connection: -1 }) };
        let s = system_stats_from_proto(&proto);
        assert_eq!(s.buffer.connection, -1_i32);
    }

    #[test]
    fn system_stats_from_proto_buffer_zero_is_legal() {
        // SystemPolicy proto Buffer.connection=0 表示 ZeroBuffer；不走 default。
        let proto =
            ProtoSystemPolicy { stats: None, buffer: Some(SystemPolicyBuffer { connection: 0 }) };
        let s = system_stats_from_proto(&proto);
        assert_eq!(s.buffer.connection, 0, "Buffer=0 must survive round-trip");
        assert_ne!(s.buffer.connection, DEFAULT_BUFFER_CONNECTION);
    }

    // 编译期自检：保证新生成 SystemPolicyBuffer struct 字段存在。
    #[test]
    fn system_policy_buffer_field_exists_compile_time() {
        let buf = SystemPolicyBuffer::default();
        assert_eq!(buf.connection, 0);
        let _ = buf;
    }
}
