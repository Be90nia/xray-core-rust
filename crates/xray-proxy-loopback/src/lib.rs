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

use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use thiserror::Error;
use xray_app_dispatcher::default::DispatchHandler;
use xray_proto::xray::proxy::loopback::Config;

/// Loopback 错误。
#[derive(Debug, Error)]
pub enum LoopbackError {
    /// 调用方未指定连接目标。
    #[error("target not specified")]
    TargetNotSpecified,
    /// Loopback sink 未注入（dispatcher 尚未接入）。
    #[error("loopback sink not injected (dispatcher hookup pending 切片3)")]
    SinkNotInjected,
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

// ========== 切片2: LoopbackHandler ==========

/// 'static + Send boxed future，与 [`DispatchHandler::dispatch`] 返回类型对齐。
pub type LoopbackFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// Loopback dispatcher 注入点。
///
/// 对应 Go `routing.Dispatcher` 接口。Loopback 需要把 outbound 链接重新注入到 dispatcher，
/// 由 dispatcher 回环到指定的本机 inbound tag。
///
/// 切片2 仅定义 trait + 测试 mock；真实实现由 `xray-app-dispatcher` 切片3 提供
/// （DefaultDispatcher 需要暴露 dispatch_loopback(tag, link) API）。
pub trait LoopbackSink: Send + Sync + Debug {
    /// 把 link 重新注入到指定的 inbound tag。
    ///
    /// 对应 Go `dispatcherInstance.DispatchLink(ctx, destination, link)`。
    /// 返回 'static future（可被 tokio::spawn）。
    fn dispatch_loopback(
        &self,
        inbound_tag: String,
        link: xray_transport::link::Link,
    ) -> LoopbackFuture<Result<(), LoopbackError>>;
}

/// Loopback 出站 handler：把出站链接回环到指定的本机入站 tag。
///
/// 对应 Go `proxy/loopback.Loopback`（实现 `proxy.Outbound` 接口）。
///
/// Go 版本持有 `routing.Dispatcher`；Rust 切片2 用 [`LoopbackSink`] trait 抽象，
/// 切片3 在 DefaultDispatcher 上实现该 trait 并注入。
pub struct LoopbackHandler {
    tag: String,
    inbound_tag: String,
    /// dispatcher 注入点；None 时 dispatch 仅 log + drop link（测试桩语义）。
    sink: Option<Arc<dyn LoopbackSink>>,
}

impl Debug for LoopbackHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoopbackHandler")
            .field("tag", &self.tag)
            .field("inbound_tag", &self.inbound_tag)
            .field("has_sink", &self.sink.is_some())
            .finish()
    }
}

impl LoopbackHandler {
    /// 用配置构造 Loopback handler。
    ///
    /// 对应 Go `Loopback.init(config, dispatcher)`——但 dispatcher 在切片2 留空，
    /// 由 [`Self::with_sink`] 注入。
    #[must_use]
    pub fn new(tag: impl Into<String>, config: Config) -> Self {
        Self {
            tag: tag.into(),
            inbound_tag: config.inbound_tag,
            sink: None,
        }
    }

    /// 直接以 tag + inbound_tag 构造（测试便利）。
    #[must_use]
    pub fn with_inbound_tag(tag: impl Into<String>, inbound_tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            inbound_tag: inbound_tag.into(),
            sink: None,
        }
    }

    /// 注入 dispatcher sink（切片3 由 DefaultDispatcher 调用）。
    #[must_use]
    pub fn with_sink(mut self, sink: Arc<dyn LoopbackSink>) -> Self {
        self.sink = Some(sink);
        self
    }

    /// 获取本 handler 的 tag。
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// 获取本 handler 回环的目标 inbound tag。
    pub fn inbound_tag(&self) -> &str {
        &self.inbound_tag
    }

    /// 是否已注入 dispatcher sink。
    pub fn has_sink(&self) -> bool {
        self.sink.is_some()
    }
}

impl DispatchHandler for LoopbackHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    /// 接收 outbound 链接，回环到指定的本机 inbound tag。
    ///
    /// 对应 Go `(*Loopback).Process(ctx, link, _)`：
    /// 1. 从 session 取 target（Go 端逻辑）
    /// 2. 构造新的 Content / Inbound session（Go 端逻辑）
    /// 3. 调 `dispatcherInstance.DispatchLink(ctx, target, link)`
    ///
    /// 切片2 简化：session/ctx 改造留切片3，本方法直接调 sink.dispatch_loopback。
    /// sink 为 None 时仅 log + drop link（测试桩）。
    fn dispatch(
        &self,
        _dest: &xray_common::net::destination::Destination,
        link: xray_transport::link::Link,
    ) -> LoopbackFuture<()> {
        let sink = self.sink.clone();
        let inbound_tag = self.inbound_tag.clone();
        Box::pin(async move {
            match sink {
                Some(s) => {
                    if let Err(e) = s.dispatch_loopback(inbound_tag.clone(), link).await {
                        tracing::warn!(inbound_tag = %inbound_tag, error = %e, "loopback dispatch failed");
                    }
                }
                None => {
                    // ponytail: 切片2 stub —— sink 未注入时仅 log，真正回环留切片3。
                    tracing::info!(
                        inbound_tag = %inbound_tag,
                        "loopback dispatch: link received (sink not injected, 切片2 stub)"
                    );
                    drop(link);
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_common::net::address::Address as XrayAddress;
    use xray_common::net::destination::Destination;
    use xray_common::net::network::Network;
    use xray_common::net::port::Port;

    /// 测试用占位 Destination（loopback 不依赖 dest 内容）。
    fn dummy_dest() -> Destination {
        Destination::new(XrayAddress::from_ipv4_bytes([127, 0, 0, 1]), Port::new(0), Network::TCP)
    }

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

    // ========== 切片2: LoopbackHandler 测试 ==========

    /// Mock sink：记录最后一次收到的 inbound_tag + 调用计数。
    #[derive(Debug, Default)]
    struct MockSink {
        calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl LoopbackSink for MockSink {
        fn dispatch_loopback(
            &self,
            inbound_tag: String,
            _link: xray_transport::link::Link,
        ) -> LoopbackFuture<Result<(), LoopbackError>> {
            let calls = self.calls.clone();
            Box::pin(async move {
                calls.lock().unwrap().push(inbound_tag);
                Ok(())
            })
        }
    }

    fn pipe_link() -> xray_transport::link::Link {
        let (r, _w) = xray_buf::pipe::new();
        let (_r2, w2) = xray_buf::pipe::new();
        xray_transport::link::Link::new(Box::new(r), Box::new(w2))
    }

    #[test]
    fn handler_new_from_config_extracts_inbound_tag() {
        let h = LoopbackHandler::new("loopback-out", cfg("target-in"));
        assert_eq!(h.tag(), "loopback-out");
        assert_eq!(h.inbound_tag(), "target-in");
        assert!(!h.has_sink());
    }

    #[test]
    fn handler_with_inbound_tag_constructor() {
        let h = LoopbackHandler::with_inbound_tag("lb", "inbound-1");
        assert_eq!(h.inbound_tag(), "inbound-1");
    }

    #[test]
    fn handler_with_sink_marks_has_sink() {
        let sink = std::sync::Arc::new(MockSink::default());
        let h = LoopbackHandler::with_inbound_tag("lb", "in").with_sink(sink);
        assert!(h.has_sink());
    }

    #[tokio::test]
    async fn handler_dispatch_without_sink_logs_and_drops_link() {
        // 无 sink: dispatch 应不 panic，链接被 drop（reader/writer 关闭）。
        let h = LoopbackHandler::with_inbound_tag("lb", "target-in");
        let link = pipe_link();
        // dispatch 返回 future，await 不应 panic。
        h.dispatch(&dummy_dest(), link).await;
        // 到达这里即视为测试桩语义正常。
    }

    #[tokio::test]
    async fn handler_dispatch_with_sink_invokes_dispatch_loopback() {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let sink = std::sync::Arc::new(MockSink {
            calls: calls.clone(),
        });
        let h = LoopbackHandler::with_inbound_tag("lb", "target-in").with_sink(sink);
        let link = pipe_link();
        h.dispatch(&dummy_dest(), link).await;
        let recorded = calls.lock().unwrap().clone();
        assert_eq!(recorded, vec!["target-in".to_string()]);
    }

    #[tokio::test]
    async fn handler_dispatch_multiple_calls_accumulate_in_sink() {
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let sink = std::sync::Arc::new(MockSink {
            calls: calls.clone(),
        });
        let h = LoopbackHandler::with_inbound_tag("lb", "in").with_sink(sink);
        for _ in 0..3 {
            h.dispatch(&dummy_dest(), pipe_link()).await;
        }
        assert_eq!(calls.lock().unwrap().len(), 3);
    }

    #[test]
    fn handler_debug_format_includes_fields() {
        let h = LoopbackHandler::with_inbound_tag("tag1", "tag2");
        let s = format!("{h:?}");
        assert!(s.contains("LoopbackHandler"));
        assert!(s.contains("tag1"));
        assert!(s.contains("tag2"));
        assert!(s.contains("has_sink: false"));
    }
}
