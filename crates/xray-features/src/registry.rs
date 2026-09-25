//! # Feature 工厂全局注册表
//!
//! 对应 Go `common.typeCreatorRegistry` + `common.RegisterConfig` + `common.CreateObject`。
//!
//! ## Go vs Rust
//!
//! - **Go**：`map[reflect.Type]ConfigCreator`，键是 `reflect.TypeOf(config)`，配置以 `interface{}`
//!   传入；feature crate 的 `init()` 调 `RegisterConfig` 自注册。
//! - **Rust**：`HashMap<&'static str, FeatureFactory>`，键是 prost `Any::type_url` （如
//!   `"type.googleapis.com/xray.app.dns.Config"`）；factory 接收原始字节数据 自行
//!   `prost::Message::decode`，避免本 crate 依赖具体配置类型。
//!
//! 用 `type_url` 字符串而非 `TypeId` 作键：`type_url` 是 prost Any 的天然标识，
//! 跨进程稳定（写入配置文件），与 Go 反射键的"序列化稳定"语义对齐。
//! `TypeId` 每次编译可能不同，不适合做配置层标识。
//!
//! ## 注册时机
//!
//! Go 在 `init()` 自动注册；Rust 没有 init，需在程序入口（如 `xray_cli::run`）
//! 显式调用 `register_feature("...type_url...", factory)`。
//! 测试场景下可手动调用，注册表是 process-wide 全局可变状态。

use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};

use parking_lot::RwLock;

use crate::{Feature, FeatureError, Result};

/// 从 prost Any 反序列化后的字节数据创建 Feature 的工厂闭包。
///
/// 等价 Go `common.ConfigCreator = func(ctx, config interface{}) (interface{}, error)`，
/// 但只接收 `&[u8]`（即 `prost_types::Any::value`），由工厂闭包内部
/// `prost::Message::decode` 为具体 Config 类型。这样可以：
///
/// 1. 避免本 crate 依赖具体 feature 的 Config 类型（无循环依赖）
/// 2. 让每个 feature crate 自己负责反序列化与构造
pub type FeatureFactory = Arc<dyn Fn(&[u8]) -> Result<Arc<dyn Feature>> + Send + Sync + 'static>;

static REGISTRY: OnceLock<RwLock<HashMap<&'static str, FeatureFactory>>> = OnceLock::new();

fn registry() -> &'static RwLock<HashMap<&'static str, FeatureFactory>> {
    REGISTRY.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Feature 注册表最大条目数。
const MAX_FEATURE_ENTRIES: usize = 1024;

/// 注册一个 Feature 工厂到全局表。
///
/// 对应 Go `common.RegisterConfig(configType, creator)`。同 `type_url`
/// 二次注册会覆盖前一个（与 Go 行为一致，便于测试重置）。
///
/// 通常在程序入口（或 feature crate 的显式 init 函数）调用一次。
///
/// # 参数
///
/// - `type_url`：prost `Any::type_url`，如 `"type.googleapis.com/xray.app.dns.Config"`。 必须是
///   `'static str`（保证注册表生命周期无界）。
/// - `factory`：闭包，输入 `&[u8]`（prost Any value），输出 `Arc<dyn Feature>`。
pub fn register_feature(type_url: &'static str, factory: FeatureFactory) -> Result<()> {
    let mut reg = registry().write();
    if reg.len() >= MAX_FEATURE_ENTRIES && !reg.contains_key(type_url) {
        return Err(FeatureError::NotFound {
            name: format!("registry full ({MAX_FEATURE_ENTRIES})"),
        });
    }
    reg.insert(type_url, factory);
    Ok(())
}

/// 查询 `type_url` 是否已注册。
pub fn is_registered(type_url: &str) -> bool {
    registry().read().contains_key(type_url)
}

/// 按 `type_url` 创建 Feature。
///
/// 对应 Go `common.CreateObject(ctx, config)` + `if feature, ok := obj.(features.Feature); ok`。
/// 输入是 prost `Any` 的两个分量（type_url + value bytes），由调用方从 `prost_types::Any`
/// 解出（避免本 crate 依赖 prost-types）。
///
/// # 错误
///
/// - [`FeatureError::NotFound`]：`type_url` 未注册
/// - 工厂内部错误透传（如 prost decode 失败、配置非法）
pub fn create_feature(type_url: &str, data: &[u8]) -> Result<Arc<dyn Feature>> {
    let factory = {
        let reg = registry().read();
        reg.get(type_url)
            .cloned()
            .ok_or_else(|| FeatureError::NotFound { name: type_url.to_string() })?
    };
    factory(data)
}

/// 清空注册表（仅供测试使用，生产代码不应调用）。
#[cfg(test)]
pub(crate) fn clear_registry_for_test() {
    registry().write().clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 全局 registry 为进程级共享状态，测试并行时 clear 会互删注册，
    /// 用锁串行化（同 transport crate TEST_LOCK 惯例）。
    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    /// 测试桩 Feature。
    struct StubFeature {
        tag: &'static str,
    }
    impl Feature for StubFeature {
        fn feature_name(&self) -> &'static str {
            self.tag
        }
    }

    /// 工厂：把 bytes 解析成 tag 后构造 StubFeature。
    /// 用 `String::from_utf8` 模拟 prost decode。
    fn stub_factory(data: &[u8]) -> Result<Arc<dyn Feature>> {
        let tag = String::from_utf8(data.to_vec()).map_err(|_| FeatureError::StartFailed {
            name: "StubFeature",
            message: "invalid utf-8".into(),
        })?;
        // 泄漏到 'static 以匹配 feature_name 的 &'static str 返回签名。
        // 仅测试用，生产 feature 用 String 字段 + 引用计数返回。
        let leaked: &'static str = Box::leak(tag.into_boxed_str());
        Ok(Arc::new(StubFeature { tag: leaked }))
    }

    #[test]
    fn register_and_create_roundtrip() {
        let _g = TEST_LOCK.lock();
        let factory: FeatureFactory = Arc::new(stub_factory);
        register_feature("type.googleapis.com/test.Stub", factory);

        assert!(is_registered("type.googleapis.com/test.Stub"));

        let feat = create_feature("type.googleapis.com/test.Stub", b"hello").unwrap();
        assert_eq!(feat.feature_name(), "hello");
    }

    #[test]
    fn create_unregistered_returns_not_found() {
        let _g = TEST_LOCK.lock();
        clear_registry_for_test();
        let err = create_feature("type.googleapis.com/test.Missing", b"").err().unwrap();
        assert!(matches!(err, FeatureError::NotFound { .. }));
        let msg = format!("{err}");
        assert!(msg.contains("test.Missing"));
    }

    fn register_overrides_previous() {
        let _g = TEST_LOCK.lock();
        clear_registry_for_test();
        let f1: FeatureFactory =
            Arc::new(|_| Ok(Arc::new(StubFeature { tag: "v1" }) as Arc<dyn Feature>));
        let f2: FeatureFactory =
            Arc::new(|_| Ok(Arc::new(StubFeature { tag: "v2" }) as Arc<dyn Feature>));
        register_feature("type.googleapis.com/test.Override", f1);
        register_feature("type.googleapis.com/test.Override", f2);

        let feat = create_feature("type.googleapis.com/test.Override", b"").unwrap();
        assert_eq!(feat.feature_name(), "v2");
    }

    #[test]
    fn factory_decode_error_propagates() {
        let _g = TEST_LOCK.lock();
        clear_registry_for_test();
        let factory: FeatureFactory = Arc::new(stub_factory);
        register_feature("type.googleapis.com/test.DecodeErr", factory);

        // 故意传非 UTF-8 字节触发 factory 内部错误。
        let err =
            create_feature("type.googleapis.com/test.DecodeErr", &[0xFF, 0xFE]).err().unwrap();
        assert!(matches!(err, FeatureError::StartFailed { .. }));
    }

    #[test]
    fn registry_is_process_wide_singleton() {
        // 不 clear，验证注册表跨测试调用持久（仅作可观察性检查，不依赖顺序）。
        let before = is_registered("type.googleapis.com/test.Stub");
        register_feature(
            "type.googleapis.com/test.SingletonCheck",
            Arc::new(|_| Ok(Arc::new(StubFeature { tag: "x" }) as Arc<dyn Feature>)),
        );
        assert!(is_registered("type.googleapis.com/test.SingletonCheck"));
        let _ = before; // 不 assert，避免依赖测试执行顺序
    }
}
