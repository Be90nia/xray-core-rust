//! ObservatoryFeature —— 将 Observatory app 接入 Feature 系统。
//!
//! 对应 Go `app/observatory/observer.go` 中 `Observer` 作为 `features.Feature`。
//!
//! ## 当前限制
//!
//! Go 版 `Start()` 从 instance context 获取 `outbound.Manager`（作为
//! `OutboundSelector`）并构造 HTTP probe executor，然后启动后台 goroutine。
//! Rust 端这些依赖通过 trait 注入，factory 无法在构造时获取——故 `start()`
//! 暂不启动探测循环。Observer 对象已构造并注册，待 Instance 接线后可由
//! 上层调用 `Observer::start(selector, executor)` 启动后台探测。

use xray_features::{Feature, Result};

use crate::config::ObservatoryConfig;
use crate::observer::Observer;

/// Observatory app Feature 实现。包装 [`Observer`]。
pub struct ObservatoryFeature {
    observer: Observer,
}

impl ObservatoryFeature {
    /// 从配置创建 ObservatoryFeature。
    pub fn new(config: ObservatoryConfig) -> Self {
        Self {
            observer: Observer::new(config),
        }
    }

    /// 获取内部 Observer 引用（供 Instance 接线 selector/executor 后启动探测）。
    pub fn observer(&self) -> &Observer {
        &self.observer
    }
}

impl Feature for ObservatoryFeature {
    fn feature_name(&self) -> &'static str {
        "observatory"
    }

    fn start(&self) -> Result<()> {
        // ponytail: probe loop requires OutboundSelector + ProbeExecutor
        // injected from the instance (outbound.Manager + dispatcher dial).
        // Not available at factory time; Observer registered for later activation.
        Ok(())
    }

    fn close(&self) -> Result<()> {
        let _ = self.observer.close();
        Ok(())
    }
}
