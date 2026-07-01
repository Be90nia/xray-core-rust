//! # Feature 抽象
//!
//! 对应 Go `features.Feature`（`common.HasType` + `common.Runnable`）。
//!
//! Xray 的所有可注册组件（dns.Client / routing.Router / policy.Manager /
//! stats.Manager / inbound.Manager / outbound.Manager 等）都实现此 trait，
//! 由 [`crate`] 中的 Instance 容器统一管理生命周期。
//!
//! ## 与 Go 差异
//!
//! Go 用 `Type() interface{}` 返回占位指针（如 `dns.ClientType()` 返回
//! `(*dns.Client)(nil)`）作为类型键，依赖 Go 反射做相等比较。Rust 直接用
//! [`TypeId`](std::any::TypeId)，每个具体类型自动获得全局唯一标识，无需手写
//! `XxxType()` 工厂函数。

use std::any::{Any, TypeId};
use thiserror::Error;

/// Feature 注册/生命周期错误。
#[derive(Debug, Error)]
pub enum FeatureError {
    /// 同一 [`TypeId`](std::any::TypeId) 的 Feature 已注册过（Go 端 panic，这里返回错误更安全）。
    /// `name` 是 `std::any::type_name::<T>()` 返回的类型名。
    #[error("feature already registered: {name}")]
    AlreadyRegistered { name: &'static str },

    /// 请求的 Feature 类型未注册。`name` 兼容静态类型名与 prost `type_url`。
    #[error("feature not found: {name}")]
    NotFound { name: String },
    /// Feature 启动失败。`source` 保留原始错误链。
    #[error("feature {name} failed to start: {message}")]
    StartFailed { name: &'static str, message: String },

    /// Feature 关闭失败。聚合所有 feature 的关闭错误时使用。
    #[error("feature {name} failed to close: {message}")]
    CloseFailed { name: &'static str, message: String },
}

/// Feature 操作 Result 别名。
pub type Result<T> = std::result::Result<T, FeatureError>;

/// Xray Feature 抽象。
///
/// 实现者只需关心业务逻辑，类型标识由 [`TypeId`] 自动派生。
/// 默认 `start`/`close` 为空实现，子 trait 可按需覆盖。
///
/// # 生命周期
///
/// 1. 通过 [`Instance::add_feature`](../../xray_core/instance/struct.Instance.html#method.add_feature)
///    注册到 Instance 容器。
/// 2. `Instance::start()` 按注册顺序调用所有 feature 的 `start()`。
/// 3. `Instance::close()` 按注册逆序调用所有 feature 的 `close()`。
///
/// # 线程安全
///
/// `Send + Sync` 是硬约束：Xray 是多线程运行时，feature 必须可跨线程共享。
/// 内部状态请用 `parking_lot::RwLock` / `dashmap` / `Arc` 等并发原语保护。
pub trait Feature: Any + Send + Sync + 'static {
    /// Feature 的类型标识。同一 [`TypeId`] 在 Instance 中只能注册一个实例。
    ///
    /// 默认实现返回 `TypeId::of::<Self>()`。绝大多数情况无需覆盖；仅在需要把
    /// 多个具体类型归并到同一注册槽时（罕见），才覆盖此方法返回共同的祖先 TypeId。
    fn feature_type(&self) -> TypeId {
        TypeId::of::<Self>()
    }

    /// 人类可读的类型名，仅用于错误信息与日志。默认取 `std::any::type_name::<Self>()`。
    fn feature_name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }

    /// 启动 Feature。返回 `Err` 会导致 `Instance::start()` 中止并向上传播。
    ///
    /// 默认空实现适用于无后台任务的纯状态型 feature（如 NoopManager）。
    fn start(&self) -> Result<()> {
        Ok(())
    }

    /// 关闭 Feature，释放资源（监听端口、后台任务、文件句柄等）。
    ///
    /// 默认空实现。实现者应保证此函数可重入（多次调用不 panic）。
    fn close(&self) -> Result<()> {
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    struct NoopFeature;
    impl Feature for NoopFeature {}

    struct CounterFeature {
        name: &'static str,
    }
    impl Feature for CounterFeature {
        fn feature_name(&self) -> &'static str {
            self.name
        }
        fn start(&self) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn default_feature_type_uses_typeid() {
        let a = NoopFeature;
        let b = CounterFeature { name: "c" };
        assert_eq!(a.feature_type(), TypeId::of::<NoopFeature>());
        assert_eq!(b.feature_type(), TypeId::of::<CounterFeature>());
        assert_ne!(a.feature_type(), b.feature_type());
    }

    #[test]
    fn default_start_close_are_noop() {
        let f = NoopFeature;
        assert!(f.start().is_ok());
        assert!(f.close().is_ok());
    }

    #[test]
    fn default_feature_name_uses_type_name() {
        let f = NoopFeature;
        // type_name 返回完整路径，至少包含类型名。
        assert!(f.feature_name().contains("NoopFeature"));
    }

    #[test]
    fn custom_feature_name_override() {
        let f = CounterFeature { name: "my-counter" };
        assert_eq!(f.feature_name(), "my-counter");
    }

    #[test]
    fn reference_forwarding_works() {
        let f = CounterFeature { name: "wrapped" };
        let r: &dyn Feature = &f;
        assert_eq!(r.feature_name(), "wrapped");
        assert!(r.start().is_ok());
    }

    #[test]
    fn error_display_contains_type_info() {
        let err = FeatureError::NotFound { name: String::from("NoopFeature") };
        let msg = format!("{err}");
        assert!(msg.contains("not found"));
        assert!(msg.contains("NoopFeature"));
    }
}
