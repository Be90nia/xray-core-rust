//! 外部 API —— Xray 实例构造与启动入口。
//!
//! 对应 Go `core/functions.go`。Go 端 `StartInstance(configFormat, configBytes)`
//! 三步：`LoadConfig` → `New` → `Start`。Rust 端等价路径：
//!
//! 1. 字节流 → [`xray_conf::Config`]（由 `xray_conf::Config::from_json_str` 完成）
//! 2. [`Config::build`](xray_conf::Config::build) → [`xray_conf::BuiltConfig`]
//! 3. [`Instance::new_from_built`] → [`Instance`]
//! 4. [`Instance::start`] → 启动所有 features
//!
//! ## 切片边界
//!
//! - 仅支持 JSON 输入字节（YAML/TOML 字节解析留给文件加载路径，见
//!   [`xray_conf::load_file_with_format`] 处理 `auto`/`yaml`/`toml`）
//! - inbound/outbound handler 注入依赖各 proxy crate 切片2 + proxyman 切片2（c2v 任务）

use std::sync::Arc;

use thiserror::Error;

use crate::Instance;
use xray_features::FeatureError;

/// 外部 API 调用错误。
#[derive(Debug, Error)]
pub enum CoreFunctionError {
    /// 配置解析失败（JSON 格式错误、字段非法等）。
    #[error("config load failed: {0}")]
    ConfigLoad(String),

    /// `Config::build()` 失败（如使用了已废弃的全局 transport 字段）。
    #[error("config build failed: {0}")]
    ConfigBuild(String),

    /// `Instance::new_from_built` 期间 FeatureFactory 报错（如 prost decode 失败、配置非法）。
    #[error("instance init failed: {0}")]
    InstanceInit(String),

    /// `Instance::start` 期间某 feature 启动失败。
    #[error("instance start failed: {0}")]
    InstanceStart(String),
}

impl From<FeatureError> for CoreFunctionError {
    fn from(e: FeatureError) -> Self {
        // 语义：
        // - CloseFailed: 仅 start() 后才可能发生 → InstanceStart
        // - 其他（含 StartFailed）：factory 构造期也可能发生 → InstanceInit
        //   (factory 常用 StartFailed 作为通用错误码)
        match e {
            FeatureError::CloseFailed { .. } => CoreFunctionError::InstanceStart(e.to_string()),
            _ => CoreFunctionError::InstanceInit(e.to_string()),
        }
    }
}

impl From<xray_conf::ConfError> for CoreFunctionError {
    fn from(e: xray_conf::ConfError) -> Self {
        CoreFunctionError::ConfigBuild(e.to_string())
    }
}

/// 从已构建的 [`BuiltConfig`] 启动新实例。
///
/// 内部步骤：`Instance::new_from_built(built)` → `instance.start()` → 包装为 `Arc<Instance>`。
///
/// 对应 Go `core.New(config)` + `instance.Start()` 组合。**不阻塞**：调用方需自行管理
/// instance 生命周期（如等待信号、监听关闭事件）。
pub fn start_from_built(built: &xray_conf::BuiltConfig) -> Result<Arc<Instance>, CoreFunctionError> {
    let mut instance = Instance::new_from_built(built)?;
    instance.start()?;
    Ok(Arc::new(instance))
}

/// 从序列化配置字节启动新实例（仅支持 JSON 格式）。
///
/// 对应 Go `core.StartInstance(configFormat, configBytes)`：
///
/// 1. 字节 → `Config`（`from_json_str`）
/// 2. `Config::build()` → `BuiltConfig`
/// 3. `start_from_built(&built)`
///
/// # 参数
///
/// - `config_format`：必须是 `"json"`（大小写不敏感）。其他格式返回 `ConfigLoad` 错误，
///   建议改用文件加载路径（`xray_cli::run` + `xray_conf::load_file_with_format`）。
/// - `config_bytes`：JSON 编码的字节流。
pub fn start_instance(
    config_format: &str,
    config_bytes: &[u8],
) -> Result<Arc<Instance>, CoreFunctionError> {
    if !config_format.eq_ignore_ascii_case("json") {
        return Err(CoreFunctionError::ConfigLoad(format!(
            "unsupported format: {config_format} (only json supported for bytes input; use file path for yaml/toml)"
        )));
    }
    let json_str = std::str::from_utf8(config_bytes)
        .map_err(|e| CoreFunctionError::ConfigLoad(format!("config is not valid UTF-8: {e}")))?;
    let config = xray_conf::Config::from_json_str(json_str)
        .map_err(|e| CoreFunctionError::ConfigLoad(e.to_string()))?;
    let built = config.build()?;
    start_from_built(&built)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc as StdArc;
    use xray_features::{Feature, FeatureError, FeatureFactory, registry};

    /// 测试用 Feature：记录 start 次数。
    struct SharedCounterFeature {
        counter: StdArc<AtomicUsize>,
    }
    impl Feature for SharedCounterFeature {
        fn feature_name(&self) -> &'static str {
            "SharedCounterFeature"
        }
        fn start(&self) -> Result<(), FeatureError> {
            self.counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn start_instance_rejects_non_json_format() {
        let err = start_instance("yaml", b"{}").err().expect("should error");
        assert!(matches!(err, CoreFunctionError::ConfigLoad(_)));
        let msg = format!("{err}");
        assert!(msg.contains("only json supported"));
    }

    #[test]
    fn start_instance_rejects_invalid_utf8() {
        let err = start_instance("json", &[0xFF, 0xFE]).err().expect("should error");
        assert!(matches!(err, CoreFunctionError::ConfigLoad(_)));
    }

    #[test]
    fn start_instance_rejects_invalid_json() {
        let err = start_instance("json", b"not json").err().expect("should error");
        assert!(matches!(err, CoreFunctionError::ConfigLoad(_)));
    }

    #[test]
    fn start_from_built_with_empty_config_starts_zero_features() {
        let built = xray_conf::BuiltConfig::default();
        let inst = start_from_built(&built).expect("empty built should start cleanly");
        assert!(inst.is_running());
        assert_eq!(inst.feature_count(), 0);
    }

    #[test]
    fn start_from_built_skips_unregistered_kind() {
        let mut built = xray_conf::BuiltConfig::default();
        built.apps.push(xray_conf::BuiltEntry {
            kind: "xray.test.unregistered.kind".into(),
            data: b"{}".to_vec(),
        });
        let inst = start_from_built(&built).expect("unregistered kind should be skipped");
        assert_eq!(inst.feature_count(), 0);
    }

    #[test]
    fn start_from_built_registers_and_starts_via_factory() {
        let counter = StdArc::new(AtomicUsize::new(0));
        let counter_for_factory = counter.clone();
        let factory: FeatureFactory = Arc::new(move |_data: &[u8]| {
            Ok(Arc::new(SharedCounterFeature {
                counter: counter_for_factory.clone(),
            }) as Arc<dyn Feature>)
        });
        registry::register_feature("xray.test.shared_counter", factory);

        let mut built = xray_conf::BuiltConfig::default();
        built.apps.push(xray_conf::BuiltEntry {
            kind: "xray.test.shared_counter".into(),
            data: b"{}".to_vec(),
        });
        let inst = start_from_built(&built).expect("registered feature should start");
        assert_eq!(inst.feature_count(), 1);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "feature.start should be called once"
        );
    }

    #[test]
    fn start_from_built_factory_error_propagates() {
        let factory: FeatureFactory = Arc::new(|_data: &[u8]| {
            Err(FeatureError::StartFailed {
                name: "BadFeature",
                message: "injected failure".into(),
            })
        });
        registry::register_feature("xray.test.bad_factory", factory);

        let mut built = xray_conf::BuiltConfig::default();
        built.apps.push(xray_conf::BuiltEntry {
            kind: "xray.test.bad_factory".into(),
            data: b"{}".to_vec(),
        });
        let err = start_from_built(&built).err().expect("factory error should propagate");
        assert!(matches!(err, CoreFunctionError::InstanceInit(_)));
        let msg = format!("{err}");
        assert!(msg.contains("BadFeature") || msg.contains("injected failure"));
    }

    #[test]
    fn start_from_built_multiple_apps_in_order() {
        let order = StdArc::new(parking_lot::Mutex::new(Vec::new()));
        struct OrderedFeature {
            tag: &'static str,
            order: StdArc<parking_lot::Mutex<Vec<String>>>,
        }
        impl Feature for OrderedFeature {
            fn feature_name(&self) -> &'static str {
                self.tag
            }
            fn start(&self) -> Result<(), FeatureError> {
                self.order.lock().push(self.tag.to_string());
                Ok(())
            }
        }
        let order1 = order.clone();
        let order2 = order.clone();
        registry::register_feature(
            "xray.test.ordered.first",
            Arc::new(move |_data| {
                Ok(Arc::new(OrderedFeature {
                    tag: "first",
                    order: order1.clone(),
                }) as Arc<dyn Feature>)
            }),
        );
        registry::register_feature(
            "xray.test.ordered.second",
            Arc::new(move |_data| {
                Ok(Arc::new(OrderedFeature {
                    tag: "second",
                    order: order2.clone(),
                }) as Arc<dyn Feature>)
            }),
        );

        let mut built = xray_conf::BuiltConfig::default();
        built.apps.push(xray_conf::BuiltEntry {
            kind: "xray.test.ordered.first".into(),
            data: b"{}".to_vec(),
        });
        built.apps.push(xray_conf::BuiltEntry {
            kind: "xray.test.ordered.second".into(),
            data: b"{}".to_vec(),
        });
        let inst = start_from_built(&built).expect("ordered features should start");
        assert_eq!(inst.feature_count(), 2);
        let recorded = order.lock().clone();
        assert_eq!(recorded, vec!["first".to_string(), "second".to_string()]);
    }
}
