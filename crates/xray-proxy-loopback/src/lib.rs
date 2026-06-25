//! Loopback 代理协议
//!
//! 对应 Go 版本 [`proxy/loopback`](https://github.com/XTLS/Xray-core/tree/main/proxy/loopback)：
//! 把出站连接回环到指定的本机入站 tag，由 dispatcher 重新分发。
//!
//! # 当前实现范围
//!
//! 完整翻译 Go 版本的 [`Loopback`] struct、[`Config`] 解析与构造方法。
//! `Process` 函数依赖 `transport.Link` / `internet.Dialer` / `routing.Dispatcher`，
//! 这些类型在 Rust 端尚未实现。等 `xray-app-dispatcher` 提供等价 Dispatcher trait
//! 与 `xray-transport` 提供等价 Link 后，在 [`Loopback`] 之上加一层 adapter 即可接入。

use thiserror::Error;
use xray_proto::xray::proxy::loopback::Config;

/// Loopback 错误。
#[derive(Debug, Error)]
pub enum LoopbackError {
    /// 调用方未指定连接目标。
    #[error("target not specified")]
    TargetNotSpecified,
}

/// Loopback 出站处理器：把出站连接回环到指定的本机入站 tag。
///
/// 对应 Go 版本 `proxy/loopback.Loopback`。
///
/// Go 源码中 `Loopback` 持有 `routing.Dispatcher` 引用；Rust 端 Dispatcher trait
/// 尚未实现，故当前 struct 仅持有配置。`process` 方法接受 dispatcher 参数，
/// 等 trait 落地后填入签名即可。
#[derive(Debug, Clone, Default)]
pub struct Loopback {
    config: Config,
}

impl Loopback {
    /// 按 protobuf 配置创建 loopback 处理器。
    ///
    /// 对应 Go `Loopback.init(config, dispatcher)`。Go 同时持有 dispatcher 引用，
    /// Rust 端 Dispatcher trait 未实现，这里只保存配置；dispatch 由 `process` 参数传入。
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// 获取配置中指定的入站 tag（用于回环到本机对应入站处理器）。
    ///
    /// 对应 Go `l.config.InboundTag` 的访问。
    pub fn inbound_tag(&self) -> &str {
        &self.config.inbound_tag
    }

    /// 获取持有配置的不可变引用。
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// 校验目标是否有效。
    ///
    /// 对应 Go `Process` 中的前置校验：`if !ob.Target.IsValid() { return TargetNotSpecified }`。
    /// 此处把可独立测试的校验逻辑提取出来，不依赖 session/transport。
    ///
    /// 调用方应在调用未来的 `process` 之前先用此方法验证目标。
    pub fn validate_target(target_specified: bool) -> Result<(), LoopbackError> {
        if target_specified {
            Ok(())
        } else {
            Err(LoopbackError::TargetNotSpecified)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(tag: &str) -> Config {
        Config {
            inbound_tag: tag.to_string(),
        }
    }

    #[test]
    fn loopback_new_stores_tag() {
        let l = Loopback::new(cfg("my-inbound"));
        assert_eq!(l.inbound_tag(), "my-inbound");
    }

    #[test]
    fn loopback_default_has_empty_tag() {
        let l = Loopback::default();
        assert_eq!(l.inbound_tag(), "");
    }

    #[test]
    fn loopback_config_accessor() {
        let l = Loopback::new(cfg("tag-1"));
        assert_eq!(l.config().inbound_tag, "tag-1");
    }

    #[test]
    fn validate_target_accepts_specified() {
        assert!(Loopback::validate_target(true).is_ok());
    }

    #[test]
    fn validate_target_rejects_unspecified() {
        match Loopback::validate_target(false) {
            Err(LoopbackError::TargetNotSpecified) => {}
            other => panic!("expected TargetNotSpecified, got {other:?}"),
        }
    }

    #[test]
    fn loopback_clone_preserves_tag() {
        let l = Loopback::new(cfg("clone-me"));
        let l2 = l.clone();
        assert_eq!(l2.inbound_tag(), "clone-me");
    }

    #[test]
    fn loopback_with_empty_tag() {
        // 配置允许空 tag（构造时不校验，由调用方负责）
        let l = Loopback::new(Config {
            inbound_tag: String::new(),
        });
        assert_eq!(l.inbound_tag(), "");
    }
}
