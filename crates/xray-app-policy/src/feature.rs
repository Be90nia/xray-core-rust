//! PolicyFeature —— 将 Policy app 接入 Feature 系统。
//!
//! 对应 Go `app/policy/policy.go` 中 `Manager` 作为 `features.Feature`。
//! Go 版 `Start`/`Close` 为 no-op（Manager 在 `New` 时已构建完毕）。

use xray_features::policy::{Policy, PolicyManager};
use xray_features::{Feature, FeatureError, Result};
use xray_proto::xray::app::policy::Config;

use crate::manager::{Manager, ManagerError};

/// Policy app Feature 实现。包装 [`Manager`]，实现 `Feature` + `PolicyManager`。
pub struct PolicyFeature {
    manager: Manager,
}

impl PolicyFeature {
    /// 从 proto 配置创建 PolicyFeature。
    pub fn new(config: Config) -> Result<Self> {
        let manager =
            Manager::new(config).map_err(|e: ManagerError| FeatureError::StartFailed {
                name: "policy",
                message: e.to_string(),
            })?;
        Ok(Self { manager })
    }

    /// 获取内部 Manager 引用。
    pub fn manager(&self) -> &Manager {
        &self.manager
    }
}

impl Feature for PolicyFeature {
    fn feature_name(&self) -> &'static str {
        "policy"
    }
}

impl PolicyManager for PolicyFeature {
    fn policy_for_level(&self, level: u32) -> Policy {
        self.manager.policy_for_level(level)
    }
}
