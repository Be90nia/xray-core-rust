//! 流量计数器命名规则与 stats 提供方 trait
//!
//! 对应 Go `app/proxyman/inbound/always.go` 与 `app/proxyman/outbound/handler.go`
//! 内的 `getStatCounter` 函数——根据 `tag` 拼出 stats manager 注册名，按 policy
//! 决定是否启用上行/下行计数。Rust 端把命名规则提为独立函数，stats manager 由
//! 上层注入实现 [`StatsProvider`] trait。

use std::sync::Arc;

/// 流量计数方向（对应 Go `"uplink"` / `"downlink"` 字符串字面量）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrafficDirection {
    Uplink,
    Downlink,
}

impl TrafficDirection {
    /// 返回 Go stats name 段中的方向字符串
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Uplink => "uplink",
            Self::Downlink => "downlink",
        }
    }
}

/// Handler 分类（对应 Go stats name 前缀 `"inbound>>>"` / `"outbound>>>"`）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandlerKind {
    Inbound,
    Outbound,
}

impl HandlerKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}

/// 拼出 Go stats 注册名：`"{kind}>>>{tag}>>>traffic>>>{direction}"`
///
/// 对应 Go `"inbound>>>" + tag + ">>>traffic>>>uplink"` 与同类 4 处拼接。
#[must_use]
pub fn counter_name(kind: HandlerKind, tag: &str, direction: TrafficDirection) -> String {
    format!("{}>>>{}>>>traffic>>>{}", kind.as_str(), tag, direction.as_str())
}

/// 入站 uplink 计数器名（便捷别名）
#[must_use]
pub fn inbound_uplink_name(tag: &str) -> String {
    counter_name(HandlerKind::Inbound, tag, TrafficDirection::Uplink)
}

/// 入站 downlink 计数器名
#[must_use]
pub fn inbound_downlink_name(tag: &str) -> String {
    counter_name(HandlerKind::Inbound, tag, TrafficDirection::Downlink)
}

/// 出站 uplink 计数器名
#[must_use]
pub fn outbound_uplink_name(tag: &str) -> String {
    counter_name(HandlerKind::Outbound, tag, TrafficDirection::Uplink)
}

/// 出站 downlink 计数器名
#[must_use]
pub fn outbound_downlink_name(tag: &str) -> String {
    counter_name(HandlerKind::Outbound, tag, TrafficDirection::Downlink)
}

/// 计数器 trait（与 `xray-features::stats::Counter` 同语义，避免 crate 间循环依赖）
///
/// ponytail: 用本地 trait 避免硬绑定 xray-features（上层接入时可 #[derive] 或写 blanket impl）
pub trait Counter: Send + Sync {
    /// 当前值
    fn value(&self) -> i64;
    /// 增量并返回新值
    fn add(&self, delta: i64) -> i64;
}

/// Stats 提供方 trait（对应 Go `v.GetFeature(stats.ManagerType()).(stats.Manager)`）
///
/// 上层（如 xray-core）注入具体实现：根据 name 返回已注册的 [`Counter`]，
/// 没找到返回 `None`（不强制注册，与 Go `stats.GetOrRegisterCounter` 行为对齐）。
pub trait StatsProvider: Send + Sync {
    /// 按 name 取 counter，不存在返回 `None`
    fn get_counter(&self, name: &str) -> Option<Arc<dyn Counter>>;
}

/// 简易 no-op stats provider（始终返回 `None`，等价于 policy 未启用流量计数）
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopStatsProvider;

impl StatsProvider for NoopStatsProvider {
    fn get_counter(&self, _name: &str) -> Option<Arc<dyn Counter>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI64, Ordering};

    use super::*;

    /// 测试用 atomic counter
    struct TestCounter(AtomicI64);

    impl TestCounter {
        fn new(v: i64) -> Self {
            Self(AtomicI64::new(v))
        }
    }

    impl Counter for TestCounter {
        fn value(&self) -> i64 {
            self.0.load(Ordering::SeqCst)
        }

        fn add(&self, delta: i64) -> i64 {
            self.0.fetch_add(delta, Ordering::SeqCst) + delta
        }
    }

    #[test]
    fn counter_name_inbound_uplink() {
        assert_eq!(inbound_uplink_name("http"), "inbound>>>http>>>traffic>>>uplink");
    }

    #[test]
    fn counter_name_inbound_downlink() {
        assert_eq!(inbound_downlink_name("socks"), "inbound>>>socks>>>traffic>>>downlink");
    }

    #[test]
    fn counter_name_outbound_uplink() {
        assert_eq!(outbound_uplink_name("direct"), "outbound>>>direct>>>traffic>>>uplink");
    }

    #[test]
    fn counter_name_outbound_downlink() {
        assert_eq!(outbound_downlink_name("proxy"), "outbound>>>proxy>>>traffic>>>downlink");
    }

    #[test]
    fn counter_name_empty_tag() {
        assert_eq!(inbound_uplink_name(""), "inbound>>>>>>traffic>>>uplink");
    }

    #[test]
    fn traffic_direction_as_str() {
        assert_eq!(TrafficDirection::Uplink.as_str(), "uplink");
        assert_eq!(TrafficDirection::Downlink.as_str(), "downlink");
    }

    #[test]
    fn handler_kind_as_str() {
        assert_eq!(HandlerKind::Inbound.as_str(), "inbound");
        assert_eq!(HandlerKind::Outbound.as_str(), "outbound");
    }

    #[test]
    fn noop_provider_returns_none() {
        let p = NoopStatsProvider;
        assert!(p.get_counter("any").is_none());
    }

    #[test]
    fn test_counter_add_and_value() {
        let c = TestCounter::new(10);
        assert_eq!(c.value(), 10);
        assert_eq!(c.add(5), 15);
        assert_eq!(c.value(), 15);
        assert_eq!(c.add(-3), 12);
    }

    /// 通过 Arc<dyn Counter> 验证 trait object 可用
    #[test]
    fn counter_as_trait_object() {
        let c: Arc<dyn Counter> = Arc::new(TestCounter::new(100));
        assert_eq!(c.value(), 100);
        assert_eq!(c.add(1), 101);
    }
}
