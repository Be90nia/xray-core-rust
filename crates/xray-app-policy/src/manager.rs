//! Policy manager 实现。
//!
//! 对应 Go 版本 `app/policy/manager.go`：按用户 level 查找运行时策略，
//! 实现 `features/policy.Manager` trait。

use std::collections::HashMap;

use thiserror::Error;
use xray_features::policy::{Policy, PolicyManager};
use xray_proto::xray::app::policy::Config;

use crate::convert::{SystemStats, policy_from_proto, system_stats_from_proto};

/// Manager 构造错误。
#[derive(Debug, Error)]
pub enum ManagerError {
    // 当前无构造失败条件，保留枚举以便后续扩展（如未来字段约束）。
}

/// Policy manager 实例。
///
/// 对应 Go `app/policy.Instance`。
pub struct Manager {
    /// 按 level 预解析的运行时策略（已经合并默认值）。
    levels: HashMap<u32, Policy>,
    /// 系统级统计策略。
    system: SystemStats,
}

impl Manager {
    /// 按配置创建 manager。
    ///
    /// 对应 Go `New(ctx, config)`。Go 源码中 `ctx` 未使用，Rust 省略。
    /// 每个 level 的 proto Policy 先与默认值合并（Go `defaultPolicy().overrideWith(p)`），
    /// 再缓存到 `levels` 表里。
    pub fn new(config: Config) -> Result<Self, ManagerError> {
        let mut levels = HashMap::with_capacity(config.level.len());
        for (lv, proto_policy) in &config.level {
            levels.insert(*lv, policy_from_proto(proto_policy));
        }
        let system = config.system.as_ref().map(system_stats_from_proto).unwrap_or_default();
        Ok(Self { levels, system })
    }
}

impl PolicyManager for Manager {
    /// 按 level 查询运行时策略；找不到时返回 `Policy::default()`。
    ///
    /// 对应 Go `(*Instance).ForLevel(level)` + `DefaultManager.ForLevel`：
    /// - 默认返回 SessionDefault（Handshake=60s, ConnectionIdle=300s ...）
    /// - level==1 强制 ConnectionIdle=600s（Go `default.go:18-20` 特判）
    fn policy_for_level(&self, level: u32) -> Policy {
        let mut p = self.levels.get(&level).cloned().unwrap_or_default();
        // sol6：Go level-1 特判仅在用户未配置 ConnectionIdle 时生效——
        // 原实现直接覆写，导致用户显式 7200s 被静默改回 600s。
        // "用户未配置" = 走默认 Policy::default().timeout.connection_idle
        // （300s，对应 Go SessionDefault.ConnectionIdle）。其他值即视为用户
        // 显式覆盖，应保留。
        if level == 1 && p.timeout.connection_idle == Policy::default().timeout.connection_idle {
            p.timeout.connection_idle = std::time::Duration::from_secs(600);
        }
        p
    }

    /// 查询系统级统计策略。
    ///
    /// 对应 Go `(*Instance).ForSystem()`。
    fn for_system(&self) -> SystemStats {
        self.system.clone()
    }
}

#[cfg(test)]
mod tests {
    use xray_proto::xray::app::policy::{
        Policy as ProtoPolicy, Second, SystemPolicy as ProtoSystemPolicy,
        policy::{Stats as PolicyStats, Timeout as PolicyTimeout},
        system_policy::Stats as ProtoSystemStats,
    };

    use super::*;

    fn proto_policy_with_stats(up: bool, down: bool, online: bool) -> ProtoPolicy {
        ProtoPolicy {
            timeout: None,
            stats: Some(PolicyStats { user_uplink: up, user_downlink: down, user_online: online }),
            buffer: None,
        }
    }

    fn proto_policy_with_handshake(sec: u32) -> ProtoPolicy {
        ProtoPolicy {
            timeout: Some(PolicyTimeout {
                handshake: Some(Second { value: sec }),
                connection_idle: None,
                uplink_only: None,
                downlink_only: None,
            }),
            stats: None,
            buffer: None,
        }
    }

    #[test]
    fn manager_new_empty_config() {
        let m = Manager::new(Config::default()).unwrap();
        assert_eq!(m.for_system(), SystemStats::default());
        assert_eq!(
            m.policy_for_level(0).timeout.handshake,
            xray_features::policy::DEFAULT_HANDSHAKE_TIMEOUT
        );
    }

    #[test]
    fn manager_returns_overridden_policy_for_known_level() {
        let cfg = Config {
            level: {
                let mut m = HashMap::new();
                m.insert(1, proto_policy_with_stats(true, false, false));
                m
            },
            system: None,
        };
        let manager = Manager::new(cfg).unwrap();
        let p = manager.policy_for_level(1);
        assert!(p.stats.user_uplink);
        assert!(!p.stats.user_downlink);
    }

    #[test]
    fn manager_returns_default_policy_for_unknown_level() {
        let cfg = Config {
            level: {
                let mut m = HashMap::new();
                m.insert(1, proto_policy_with_stats(true, true, false));
                m
            },
            system: None,
        };
        let manager = Manager::new(cfg).unwrap();
        let p = manager.policy_for_level(99);
        assert!(!p.stats.user_uplink);
        assert!(!p.stats.user_downlink);
    }

    #[test]
    fn manager_returns_system_stats_when_configured() {
        let cfg = Config {
            level: HashMap::new(),
            system: Some(ProtoSystemPolicy {
                stats: Some(ProtoSystemStats {
                    inbound_uplink: true,
                    inbound_downlink: false,
                    outbound_uplink: true,
                    outbound_downlink: false,
                }),
                buffer: None,
            }),
        };
        let manager = Manager::new(cfg).unwrap();
        let s = manager.for_system();
        assert!(s.inbound_uplink);
        assert!(!s.inbound_downlink);
        assert!(s.outbound_uplink);
        assert!(!s.outbound_downlink);
    }

    #[test]
    fn manager_default_system_stats_when_absent() {
        let cfg = Config { level: HashMap::new(), system: None };
        let manager = Manager::new(cfg).unwrap();
        assert_eq!(manager.for_system(), SystemStats::default());
    }

    #[test]
    fn manager_handshake_override_takes_effect_through_for_level() {
        let cfg = Config {
            level: {
                let mut m = HashMap::new();
                m.insert(5, proto_policy_with_handshake(42));
                m
            },
            system: None,
        };
        let manager = Manager::new(cfg).unwrap();
        let p = manager.policy_for_level(5);
        assert_eq!(p.timeout.handshake, std::time::Duration::from_secs(42));
        // 未覆盖的字段保留默认
        assert_eq!(p.timeout.connection_idle, xray_features::policy::DEFAULT_CONN_IDLE_TIMEOUT);
    }

    #[test]
    fn manager_implements_policy_manager_trait() {
        let m = Manager::new(Config::default()).unwrap();
        // 通过 trait object 验证接口可用
        let pm: &dyn PolicyManager = &m;
        let p = pm.policy_for_level(0);
        assert_eq!(p.timeout.handshake, xray_features::policy::DEFAULT_HANDSHAKE_TIMEOUT);
        // ForSystem 也通过 trait object 可用
        let s = pm.for_system();
        assert_eq!(s, SystemStats::default());
    }

    #[test]
    fn manager_user_online_policy_round_trips() {
        // proto user_online=true 必须经 Manager.for_level 透传到 features::StatsPolicy。
        // 对齐 Go features/policy/policy.go:31 UserOnline + app/dispatcher/default.go:182-184。
        let cfg = Config {
            level: {
                let mut m = HashMap::new();
                m.insert(0, proto_policy_with_stats(false, false, true));
                m
            },
            system: None,
        };
        let manager = Manager::new(cfg).unwrap();
        let p = manager.policy_for_level(0);
        assert!(p.stats.user_online);
        assert!(!p.stats.user_uplink);
        assert!(!p.stats.user_downlink);
    }
    #[test]
    fn manager_level_1_conn_idle_promoted_to_600s() {
        // 对齐 Go features/policy/default.go:18-20：level==1 时 ConnectionIdle 强制为 600s
        // （覆盖 SessionDefault 的 300s）。其它字段保持默认。
        let m = Manager::new(Config::default()).unwrap();
        let p = m.policy_for_level(1);
        assert_eq!(p.timeout.connection_idle, std::time::Duration::from_secs(600));
        // 其他超时仍是 SessionDefault 值
        assert_eq!(p.timeout.handshake, std::time::Duration::from_secs(60));
        assert_eq!(p.timeout.uplink_only, std::time::Duration::from_secs(1));
        assert_eq!(p.timeout.downlink_only, std::time::Duration::from_secs(1));
    }

    #[test]
    fn manager_level_0_keeps_default_300s() {
        // 对齐 Go SessionDefault().Timeouts.ConnectionIdle=300s（policy.go:119）。
        let m = Manager::new(Config::default()).unwrap();
        let p = m.policy_for_level(0);
        assert_eq!(p.timeout.connection_idle, std::time::Duration::from_secs(300));
        assert_eq!(p.timeout.handshake, std::time::Duration::from_secs(60));
    }
    #[test]
    fn manager_level_1_user_conn_idle_override_preserved() {
        // sol6：用户显式配 ConnectionIdle=7200s 时，level-1 强制 600s 不能覆写。
        // 仅在 ConnectionIdle 仍是 SessionDefault 值（300s）时才升级到 600s。
        let cfg = Config {
            level: {
                let mut m = HashMap::new();
                m.insert(
                    1,
                    ProtoPolicy {
                        timeout: Some(PolicyTimeout {
                            handshake: None,
                            connection_idle: Some(Second { value: 7200 }),
                            uplink_only: None,
                            downlink_only: None,
                        }),
                        stats: None,
                        buffer: None,
                    },
                );
                m
            },
            system: None,
        };
        let manager = Manager::new(cfg).unwrap();
        let p = manager.policy_for_level(1);
        assert_eq!(p.timeout.connection_idle, std::time::Duration::from_secs(7200));
    }
}
