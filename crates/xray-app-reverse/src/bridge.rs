//! Bridge + Portal trait stub。
//!
//! 对应 Go `app/reverse/bridge.go` + `portal.go`。
//! 因 mux/pipe/signal.ActivityTimer 在 Rust 端尚未翻译，这里仅暴露 trait + 编排 stub，
//! 实际 worker 创建/连接管理由后续 Phase 完成。

use std::sync::Arc;

use crate::config::{BridgeConfig, PortalConfig};
use crate::error::ReverseError;
use crate::picker::{PickerWorker, StaticMuxPicker};

/// Bridge factory trait：构造一个 bridge。
///
/// 对应 Go `NewBridge(config, dispatcher)`。
pub trait BridgeFactory: Send + Sync {
    type Bridge: Bridge;

    fn create(&self, config: &BridgeConfig) -> Result<Self::Bridge, ReverseError>;
}

/// Bridge trait：暴露 Start/Close + worker 数量查询。
pub trait Bridge: Send + Sync {
    fn start(&self) -> Result<(), ReverseError>;
    fn close(&self) -> Result<(), ReverseError>;
    fn worker_count(&self) -> usize;
    fn tag(&self) -> &str;
    fn domain(&self) -> &str;
}

/// Portal factory trait：构造一个 portal。
pub trait PortalFactory: Send + Sync {
    type Portal: Portal;

    fn create(&self, config: &PortalConfig) -> Result<Self::Portal, ReverseError>;
}

/// Portal trait：暴露 Start/Close + picker 查询。
pub trait Portal: Send + Sync {
    fn start(&self) -> Result<(), ReverseError>;
    fn close(&self) -> Result<(), ReverseError>;
    fn tag(&self) -> &str;
    fn domain(&self) -> &str;
}

/// 配置校验 helper：tag/domain 非空。
pub fn validate_bridge_config(c: &BridgeConfig) -> Result<(), ReverseError> {
    if c.tag.is_empty() {
        return Err(ReverseError::BridgeTagEmpty);
    }
    if c.domain.is_empty() {
        return Err(ReverseError::BridgeDomainEmpty);
    }
    Ok(())
}

/// 配置校验 helper：tag/domain 非空。
pub fn validate_portal_config(c: &PortalConfig) -> Result<(), ReverseError> {
    if c.tag.is_empty() {
        return Err(ReverseError::PortalTagEmpty);
    }
    if c.domain.is_empty() {
        return Err(ReverseError::PortalDomainEmpty);
    }
    Ok(())
}

/// 判断 dest domain 是否等于 given domain（对应 Go `isDomain`）。
pub fn is_domain(dest_domain: Option<&str>, expected: &str) -> bool {
    match dest_domain {
        Some(d) => d == expected,
        None => false,
    }
}

/// 判断 dest domain 是否是内部 reverse 域名。
pub fn is_internal_domain(dest_domain: Option<&str>) -> bool {
    is_domain(dest_domain, crate::config::INTERNAL_DOMAIN)
}

/// Bridge 创建 monitor 决策：是否需要新 worker。
///
/// 对应 Go `Bridge.monitor`：worker=0 或 平均 conn > 16 时建新 worker。
pub fn should_create_bridge_worker(worker_count: usize, total_connections: u32) -> bool {
    if worker_count == 0 {
        return true;
    }
    let avg = total_connections / worker_count as u32;
    avg > 16
}

/// Portal picker 选择辅助：从 picker 中选最少连接的 worker。
///
/// 返回 picker snapshot 中的 index。
pub fn pick_portal_worker<W: PickerWorker>(
    picker: &StaticMuxPicker<W>,
) -> Result<usize, ReverseError> {
    picker.pick_available_index()
}

/// 重新导出 Arc<dyn Bridge> / Arc<dyn Portal> 类型别名。
pub type SharedBridge = Arc<dyn Bridge>;
pub type SharedPortal = Arc<dyn Portal>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_bridge_rejects_empty_tag() {
        let c = BridgeConfig {
            tag: "".into(),
            domain: "d".into(),
        };
        assert!(matches!(
            validate_bridge_config(&c),
            Err(ReverseError::BridgeTagEmpty)
        ));
    }

    #[test]
    fn validate_bridge_rejects_empty_domain() {
        let c = BridgeConfig {
            tag: "t".into(),
            domain: "".into(),
        };
        assert!(matches!(
            validate_bridge_config(&c),
            Err(ReverseError::BridgeDomainEmpty)
        ));
    }

    #[test]
    fn validate_bridge_accepts_valid() {
        let c = BridgeConfig {
            tag: "t".into(),
            domain: "d".into(),
        };
        assert!(validate_bridge_config(&c).is_ok());
    }

    #[test]
    fn validate_portal_rejects_empty_tag() {
        let c = PortalConfig {
            tag: "".into(),
            domain: "d".into(),
        };
        assert!(matches!(
            validate_portal_config(&c),
            Err(ReverseError::PortalTagEmpty)
        ));
    }

    #[test]
    fn validate_portal_rejects_empty_domain() {
        let c = PortalConfig {
            tag: "t".into(),
            domain: "".into(),
        };
        assert!(matches!(
            validate_portal_config(&c),
            Err(ReverseError::PortalDomainEmpty)
        ));
    }

    #[test]
    fn is_domain_matches() {
        assert!(is_domain(Some("reverse"), "reverse"));
    }

    #[test]
    fn is_domain_mismatch() {
        assert!(!is_domain(Some("other"), "reverse"));
    }

    #[test]
    fn is_domain_none() {
        assert!(!is_domain(None, "reverse"));
    }

    #[test]
    fn is_internal_domain_recognizes() {
        assert!(is_internal_domain(Some("reverse")));
        assert!(!is_internal_domain(Some("other")));
        assert!(!is_internal_domain(None));
    }

    #[test]
    fn should_create_when_zero_workers() {
        assert!(should_create_bridge_worker(0, 0));
    }

    #[test]
    fn should_create_when_avg_above_threshold() {
        // 1 worker, 17 connections → avg 17 > 16
        assert!(should_create_bridge_worker(1, 17));
    }

    #[test]
    fn should_not_create_when_avg_at_or_below_threshold() {
        // 2 workers, 32 connections → avg 16 (== 16, not > 16)
        assert!(!should_create_bridge_worker(2, 32));
        // 2 workers, 30 connections → avg 15
        assert!(!should_create_bridge_worker(2, 30));
    }
}
