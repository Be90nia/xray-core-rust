//! [`DepBag`] —— 装配阶段依赖注入容器。
//!
//! 对应 Go `core.New` 里 `RequireFeatures(callback)` 反射 DI：Go 通过 reflect
//! 扫描回调参数类型 + `features` 列表匹配注入；Rust 走显式 [`DepBag`]，
//! Instance 在所有 feature 注册完成后调用
//! [`Feature::init_dependencies`](crate::Feature::init_dependencies) 传同一个 bag，feature
//! 自取所需依赖。
//!
//! # 设计权衡
//!
//! - **不存 `Arc<dyn Any>`** —— `feature_typed` 已经做了这件事；DepBag 只放
//!   "运行时共享基础设施"（outbound.Manager 的 selector 视图、dispatcher 等）。
//! - **字段语义为"已就绪"** —— `outbound_selector` 为 `Some` 表示 outbound.Manager 已实例化且
//!   `select_by_prefix` 可用；`None` 表示当前阶段 proxyman 未就绪， 调用方应 fail-fast 或降级。
//! - **可扩展** —— 后续 dispatcher / dns_client / policy manager 同样按 `Option<Arc<dyn ...>>`
//!   模式追加字段，feature 按需访问。

use std::sync::Arc;

/// outbound 列表查询后端（对应 Go `outbound.HandlerSelector.Select`，参考
/// `xray-app-proxyman/src/outbound/OutboundManager::select_by_prefix`）。
///
/// 实现由 `xray-app-proxyman`（或测试 fixture）提供；observatory 通过此 trait
/// 拿到 tag 列表而不直接依赖 proxyman crate（避免循环依赖）。
pub trait OutboundTagSelector: Send + Sync {
    /// 按前缀数组筛 tag，合并去重。
    fn select_by_prefix(&self, prefixes: &[String]) -> Vec<String>;
}

/// 装配阶段依赖容器。`Instance::new_from_built` 构造并向下传递。
///
/// # 当前字段
///
/// - `outbound_selector`：可选的 outbound tag 查询后端。proxyman 尚未装配时为 `None`，依赖此依赖的
///   feature 必须按 no-op 或 fail-fast 处理。
#[derive(Default, Clone)]
pub struct DepBag {
    /// outbound tag 列表查询后端（`None` 表示 proxyman 切片未装配）。
    pub outbound_selector: Option<Arc<dyn OutboundTagSelector>>,
}

impl DepBag {
    /// 构造空 bag（默认所有依赖 `None`）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 注入 outbound tag 查询后端。
    pub fn with_outbound_selector(mut self, sel: Arc<dyn OutboundTagSelector>) -> Self {
        self.outbound_selector = Some(sel);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedSelector;
    impl OutboundTagSelector for FixedSelector {
        fn select_by_prefix(&self, _prefixes: &[String]) -> Vec<String> {
            vec!["a".into(), "b".into()]
        }
    }

    #[test]
    fn empty_bag_has_none() {
        let bag = DepBag::new();
        assert!(bag.outbound_selector.is_none());
    }

    #[test]
    fn with_outbound_selector_keeps_handle() {
        let sel: Arc<dyn OutboundTagSelector> = Arc::new(FixedSelector);
        let bag = DepBag::new().with_outbound_selector(sel);
        let got = bag.outbound_selector.unwrap();
        assert_eq!(got.select_by_prefix(&[]), vec!["a", "b"]);
    }
}
