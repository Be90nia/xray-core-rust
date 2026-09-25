//! Extension and environment traits for optional features.
//!
//! Corresponds to Go's `features/extension` package.

use async_trait::async_trait;

/// Feature type identifier for Extension.
pub const FEATURE_EXTENSION: &str = "extension";

/// Extension trait for optional features.
///
/// Corresponds to Go's `features/extension.Extension`.
#[async_trait]
pub trait Extension: Send + Sync {
    /// Get the extension type name.
    fn type_name(&self) -> &str;
}

/// Environment interface for accessing configuration.
///
/// Corresponds to Go's `features/extension.Environment`.
#[async_trait]
pub trait Environment: Send + Sync {
    /// Get a configuration value by key.
    fn get_config(&self, key: &str) -> Option<String>;
}

/// Go `context.Context` 在 InjectContext 场景的最小等价：
/// 类型擦除的 feature 容器。
///
/// Go 侧 receiver 拿到 ctx 后唯一用途是 `core.RequireFeatures(ctx, ...)`
/// 按类型取依赖（如 BalancingStrategy 取 Observatory）。Rust 无
/// context.Context，这里用 `TypeId` → `Arc<dyn Any>` 表提供同等查找能力。
#[derive(Default)]
pub struct Context {
    features: std::collections::HashMap<
        std::any::TypeId,
        std::sync::Arc<dyn std::any::Any + Send + Sync>,
    >,
}

impl Context {
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册一个 feature（链式 builder）。
    pub fn with_feature<T: crate::feature::Feature>(mut self, feature: std::sync::Arc<T>) -> Self {
        self.features.insert(std::any::TypeId::of::<T>(), feature);
        self
    }

    /// 按类型取 feature，等价 `core.RequireFeatures(ctx, ...)` 单类型版本。
    pub fn require<T: crate::feature::Feature>(&self) -> Option<std::sync::Arc<T>> {
        self.features.get(&std::any::TypeId::of::<T>())?.clone().downcast::<T>().ok()
    }
}

/// 对应 Go `features/extension.ContextReceiver`（contextreceiver.go:5-7）。
///
/// Go: `InjectContext(ctx context.Context)`——宿主把携带 feature 注册表的
/// ctx 注入实现方（如 BalancingStrategy），实现方借此刻取 Observatory 等依赖。
pub trait ContextReceiver: Send + Sync {
    fn inject_context(&self, ctx: &Context);
}

/// 聚合分发器：接收 context 事件并转发给所有已添加 receiver。
///
/// 对应 Go `Balancer.InjectContext`（app/router/balancing.go:121-125）对
/// strategy 的 `if cr, ok := b.strategy.(extension.ContextReceiver)` 分发
/// 模式的多 receiver 泛化。
pub struct DefaultContextReceiver {
    receivers: parking_lot::Mutex<Vec<std::sync::Arc<dyn ContextReceiver>>>,
}

impl DefaultContextReceiver {
    pub fn new() -> Self {
        Self { receivers: parking_lot::Mutex::new(Vec::new()) }
    }

    /// 添加一个 receiver。
    pub fn add_receiver(&self, receiver: std::sync::Arc<dyn ContextReceiver>) {
        self.receivers.lock().push(receiver);
    }

    /// 把 ctx 分发给所有 receiver。
    pub fn inject(&self, ctx: &Context) {
        for r in self.receivers.lock().iter() {
            r.inject_context(ctx);
        }
    }

    /// 当前 receiver 数量。
    pub fn len(&self) -> usize {
        self.receivers.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for DefaultContextReceiver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_extension_constant() {
        assert_eq!(FEATURE_EXTENSION, "extension");
    }

    /// Mock extension for testing.
    struct MockExtension {
        name: String,
    }

    impl MockExtension {
        fn new(name: &str) -> Self {
            Self { name: name.to_string() }
        }
    }

    #[async_trait]
    impl Extension for MockExtension {
        fn type_name(&self) -> &str {
            &self.name
        }
    }

    #[test]
    fn test_mock_extension() {
        let ext = MockExtension::new("observatory");
        assert_eq!(ext.type_name(), "observatory");
    }

    /// Mock environment for testing.
    struct MockEnvironment {
        config: std::collections::HashMap<String, String>,
    }

    impl MockEnvironment {
        fn new() -> Self {
            Self { config: std::collections::HashMap::new() }
        }
    }

    #[async_trait]
    impl Environment for MockEnvironment {
        fn get_config(&self, key: &str) -> Option<String> {
            self.config.get(key).cloned()
        }
    }

    #[test]
    fn test_mock_environment_missing_key() {
        let env = MockEnvironment::new();
        assert!(env.get_config("missing").is_none());
    }

    #[test]
    fn test_extension_trait_object_safe() {
        let ext: Box<dyn Extension> = Box::new(MockExtension::new("test"));
        assert_eq!(ext.type_name(), "test");
    }

    #[test]
    fn test_environment_trait_object_safe() {
        let env: Box<dyn Environment> = Box::new(MockEnvironment::new());
        assert!(env.get_config("key").is_none());
    }

    // ---- ContextReceiver / DefaultContextReceiver 测试 ----

    /// 测试用 Feature：仅用于 Context 类型查找。
    struct MockObsFeature;

    struct AnotherFeature;

    impl crate::feature::Feature for MockObsFeature {}
    impl crate::feature::Feature for AnotherFeature {}

    /// 记录注入次数与 ctx 内 feature 命中情况的 receiver。
    struct CountingReceiver {
        calls: std::sync::atomic::AtomicUsize,
        feature_found: std::sync::atomic::AtomicBool,
    }

    impl CountingReceiver {
        fn new() -> Self {
            Self {
                calls: std::sync::atomic::AtomicUsize::new(0),
                feature_found: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    impl ContextReceiver for CountingReceiver {
        fn inject_context(&self, ctx: &Context) {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let found = ctx.require::<MockObsFeature>().is_some();
            self.feature_found.store(found, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn test_context_require_registered_feature() {
        let ctx = Context::new().with_feature(std::sync::Arc::new(MockObsFeature));
        assert!(ctx.require::<MockObsFeature>().is_some());
        // 未注册的类型查不到
        assert!(ctx.require::<AnotherFeature>().is_none());
        // 空 Context 什么都查不到
        assert!(Context::new().require::<MockObsFeature>().is_none());
    }

    #[test]
    fn test_context_receiver_dispatches_to_all() {
        let dispatcher = DefaultContextReceiver::new();
        assert!(dispatcher.is_empty());

        let r1 = std::sync::Arc::new(CountingReceiver::new());
        let r2 = std::sync::Arc::new(CountingReceiver::new());
        dispatcher.add_receiver(r1.clone());
        dispatcher.add_receiver(r2.clone());
        assert_eq!(dispatcher.len(), 2);

        let ctx = Context::new().with_feature(std::sync::Arc::new(MockObsFeature));
        dispatcher.inject(&ctx);

        assert_eq!(r1.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(r2.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        // receiver 在注入时能从 ctx 取到 feature
        assert!(r1.feature_found.load(std::sync::atomic::Ordering::SeqCst));
        assert!(r2.feature_found.load(std::sync::atomic::Ordering::SeqCst));

        // 再次注入会计数
        dispatcher.inject(&ctx);
        assert_eq!(r1.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn test_context_receiver_empty_dispatch_is_noop() {
        let dispatcher = DefaultContextReceiver::new();
        dispatcher.inject(&Context::new()); // 不 panic 即通过
        assert!(dispatcher.is_empty());
    }
}
