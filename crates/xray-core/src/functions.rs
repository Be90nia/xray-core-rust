//! 外部 API —— 简化的 Xray 调用入口。
//!
//! 对应 Go `core/functions.go`。Go 端的 `CreateObject`/`StartInstance`/`Dial`/
//! `DialUDP` 都重度依赖 `common.CreateObject(ctx, config)` 注册制反射构造
//! （protobuf `*serial.TypedMessage` 解码 + map[string]Creator 派发）。
//!
//! Rust 端在切片1 暂不实现这套反射构造机制：
//!
//! - **`CreateObject`**：依赖各 `xray-app-*` 与 `xray-proxy-*` crate 暴露统一的
//!   `From<Config> -> Feature` 构造 trait，留待切片2 引入。
//! - **`StartInstance`**：依赖 `xray_conf::Config` 的 `Build()`（protobuf 转换），
//!   留待切片2。
//! - **`Dial`/`DialUDP`**：依赖 `routing.Dispatcher` trait 实现 + `transport::Link`
//!   抽象，留待切片2。
//!
//! 当前模块仅声明 API surface（签名 + `unimplemented` 错误），让下游可尽早
//! 编写调用方代码、在切片2 接入实现。

use std::sync::Arc;

use thiserror::Error;

use crate::Instance;

/// 外部 API 调用错误。
#[derive(Debug, Error)]
pub enum CoreFunctionError {
    /// 功能尚未实现（切片边界）。`what` 描述缺失的子模块或依赖。
    #[error("unimplemented: {what}; see P7-2 切片2 roadmap")]
    Unimplemented { what: &'static str },
}

/// 根据配置构造对象（占位）。
///
/// Go 端通过 `common.CreateObject(ctx, config)` 反射派发到各协议/feature Creator。
/// Rust 切片1 不实现，统一返回 [`CoreFunctionError::Unimplemented`]。
///
/// 切片2 会引入 trait `FromConfig<T>` + 全局 Creator 注册，提供等价能力。
pub fn create_object<T>(
    _instance: &Arc<Instance>,
    _config: &T,
) -> Result<(), CoreFunctionError> {
    Err(CoreFunctionError::Unimplemented {
        what: "create_object (creator registry for features/protocols)",
    })
}

/// 从序列化配置启动新实例（占位）。
///
/// Go 端 `StartInstance(configFormat, configBytes)` 三步：LoadConfig → New → Start。
/// 切片1 缺少 `Config → Instance` 完整初始化路径，统一返回 `Unimplemented`。
pub fn start_instance(
    _config_format: &str,
    _config_bytes: &[u8],
) -> Result<Arc<Instance>, CoreFunctionError> {
    Err(CoreFunctionError::Unimplemented {
        what: "start_instance (full New(config) initialization path)",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_object_returns_unimplemented() {
        let inst = Arc::new(Instance::new());
        let cfg = 42u8;
        let err = create_object(&inst, &cfg).unwrap_err();
        assert!(matches!(err, CoreFunctionError::Unimplemented { .. }));
        assert!(err.to_string().contains("create_object"));
    }

    #[test]
    fn start_instance_returns_unimplemented() {
        match start_instance("json", b"{}") {
            Err(CoreFunctionError::Unimplemented { what }) => {
                assert!(what.contains("start_instance"));
            }
            other => {
                let _ = other;
                panic!("expected Unimplemented");
            }
        }
    }
}
