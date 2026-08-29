//! Policy manager 实现。
//!
//! 对应 Go 版本 `app/policy/manager.go`：按用户 level 查找运行时策略，
//! 实现 `features/policy.Manager` trait。

use std::collections::HashMap;

use thiserror::Error;
use xray_features::policy::{Policy, PolicyManager};
use xray_proto::xray::app::policy::Config;

use crate::convert::{policy_from_proto, system_stats_from_proto, SystemStats};

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
        let system = config
            .system
            .as_ref()
            .map(system_stats_from_proto)
            .unwrap_or_default();
        Ok(Self { levels, system })
    }

}

impl PolicyManager for Manager {
    /// 按 level 查询运行时策略；找不到时返回 `Policy::default()`。
    ///
    /// 对应 Go `(*Instance).ForLevel(level)`。
    fn policy_for_level(&self, level: u32) -> Policy {
        self.levels.get(&level).cloned().unwrap_or_default()
    }

    /// 查询系统级统计策略。
    ///
    /// 对应 Go `(*Instance).ForSystem()`。
    fn for_system(&self) -> SystemStats {
        self.system
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_proto::xray::app::policy::{
        policy::{Stats as PolicyStats, Timeout as PolicyTimeout},
        system_policy::Stats as ProtoSystemStats,
        Policy as ProtoPolicy, Second, SystemPolicy as ProtoSystemPolicy,
    };

    fn proto_policy_with_stats(up: bool, down: bool, online: bool) -> ProtoPolicy {
        ProtoPolicy {
            timeout: None,
            stats: Some(PolicyStats {
                user_uplink: up,
                user_downlink: down,
                user_online: online,
            }),
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
        let cfg = Config {
            level: HashMap::new(),
            system: None,
        };
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
        assert_eq!(
            p.timeout.connection_idle,
            xray_features::policy::DEFAULT_CONN_IDLE_TIMEOUT
        );
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
}
