//! 入站代理管理
//!
//! 对应 Go `app/proxyman/inbound/`：`inbound.go`（Manager）+ `always.go`（AlwaysOnInboundHandler）+
//! `worker.go`（tcpWorker/udpWorker/dsWorker）。
//!
//! ## 当前实现范围
//!
//! 业务核心（独立可测）：
//! - [`InboundHandler`] trait — Go `inbound.Handler` 完整语义（tag/start/close/receiver/proxy）
//! - 生产入站表**不在本 crate**：xray-core 的 `InboundRuntime` 是唯一生产注册表
//! - [`AlwaysOnInboundHandler`] — Go `AlwaysOnInboundHandler`：配置载体 + counter 引用
//!
//!
//! IO 边界：
//! - worker 创建（tcpWorker/udpWorker/dsWorker）— 已在 [`worker`] 模块实现
//! - `AlwaysOnInboundHandler::start` / `close` — 迭代 workers 启停
//! - proxy.Process — 依赖具体代理 crate + Dispatcher

pub mod worker;

use std::{future::Future, pin::Pin, sync::Arc};

use xray_proto::xray::app::proxyman::ReceiverConfig;

use crate::{
    config::SniffingRequest,
    error::ProxymanError,
    stats::{Counter, StatsProvider, inbound_downlink_name, inbound_uplink_name},
};

/// Boxed future 别名（手写风格，不依赖 `async_trait`）
pub type PinFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// 入站 handler trait（对应 Go `features/inbound.Handler`）
///
/// 与 `xray_features::inbound::InboundHandler` 区别：本 trait 接受 proto
/// [`ReceiverConfig`] 引用、提供 `proxy_type_url` 暴露 TypedMessage 类型名，
/// 保持 Go 完整语义。
pub trait InboundHandler: Send + Sync {
    /// 返回 handler tag
    fn tag(&self) -> &str;

    /// 启动 handler（对应 Go `Start() error`）
    fn start(&self) -> PinFuture<Result<(), ProxymanError>>;

    /// 关闭 handler（对应 Go `Close() error`）
    fn close(&self) -> PinFuture<Result<(), ProxymanError>>;

    /// ReceiverSettings 配置（对应 Go `ReceiverSettings() *serial.TypedMessage`）
    fn receiver_settings(&self) -> Option<&ReceiverConfig>;

    /// ProxySettings 类型 URL（对应 Go `ProxySettings() *serial.TypedMessage`，
    /// 但 Rust 端只暴露 `type_url` 字符串，避免持有 `Box<dyn Any>`）
    fn proxy_type_url(&self) -> &str;
}

/// 永驻入站 handler（对应 Go `AlwaysOnInboundHandler struct`）
///
/// 持有 receiver/proxy 配置、流量计数器、嗅探配置。worker 列表当前为空——
/// 具体 TCP/UDP/Unix listener 待 `xray_transport` + `xray_internet` 接入后填充。
pub struct AlwaysOnInboundHandler {
    tag: String,
    receiver_config: Option<ReceiverConfig>,
    proxy_type_url: String,
    sniffing_request: SniffingRequest,
    uplink_counter: Option<Arc<dyn Counter>>,
    downlink_counter: Option<Arc<dyn Counter>>,
    /// 入站 workers（对应 Go `workers []worker`）。
    workers: Vec<Arc<dyn worker::Worker>>,
    /// 入站代理实例（对应 Go `proxy proxy.Inbound`）。
    proxy: Option<Arc<dyn worker::ProxyInbound>>,
}

impl std::fmt::Debug for AlwaysOnInboundHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlwaysOnInboundHandler")
            .field("tag", &self.tag)
            .field("proxy_type_url", &self.proxy_type_url)
            .field("worker_count", &self.workers.len())
            .field("has_proxy", &self.proxy.is_some())
            .field("has_uplink_counter", &self.uplink_counter.is_some())
            .field("has_downlink_counter", &self.downlink_counter.is_some())
            .finish()
    }
}

impl AlwaysOnInboundHandler {
    /// 构造（对应 Go `NewAlwaysOnInboundHandler(ctx, tag, *ReceiverConfig, proxyConfig)`）
    ///
    /// `proxy_type_url` 对应 Go `proxyConfig` 的 `proto.Message` 类型 URL。
    /// `stats` 提供方根据 tag 查 counter；若 policy 未启用或 manager 未注册，
    /// 返回的 counter 字段为 `None`（与 Go 行为一致）。
    #[must_use]
    pub fn new(
        tag: impl Into<String>,
        receiver_config: Option<ReceiverConfig>,
        proxy_type_url: impl Into<String>,
        sniffing_request: SniffingRequest,
        stats: Option<&dyn StatsProvider>,
    ) -> Self {
        let tag_str: String = tag.into();
        let (up, down) = match stats {
            Some(p) if !tag_str.is_empty() => (
                p.get_counter(&inbound_uplink_name(&tag_str)),
                p.get_counter(&inbound_downlink_name(&tag_str)),
            ),
            _ => (None, None),
        };
        Self {
            tag: tag_str,
            receiver_config,
            proxy_type_url: proxy_type_url.into(),
            sniffing_request,
            uplink_counter: up,
            downlink_counter: down,
            workers: Vec::new(),
            proxy: None,
        }
    }

    /// 引用 sniffing_request
    #[must_use]
    pub fn sniffing_request(&self) -> &SniffingRequest {
        &self.sniffing_request
    }

    /// 引用 uplink counter
    #[must_use]
    pub fn uplink_counter(&self) -> Option<&Arc<dyn Counter>> {
        self.uplink_counter.as_ref()
    }

    /// 引用 downlink counter
    #[must_use]
    pub fn downlink_counter(&self) -> Option<&Arc<dyn Counter>> {
        self.downlink_counter.as_ref()
    }

    /// 添加 worker（对应 Go `h.workers = append(h.workers, worker)`）。
    pub fn add_worker(&mut self, worker: Arc<dyn worker::Worker>) {
        self.workers.push(worker);
    }

    /// 设置代理实例（对应 Go `h.proxy = p`）。
    pub fn set_proxy(&mut self, proxy: Arc<dyn worker::ProxyInbound>) {
        self.proxy = Some(proxy);
    }

    /// worker 数量。
    #[must_use]
    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }
}

impl InboundHandler for AlwaysOnInboundHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn start(&self) -> PinFuture<Result<(), ProxymanError>> {
        let workers: Vec<Arc<dyn worker::Worker>> = self.workers.clone();
        Box::pin(async move {
            for w in workers {
                w.start().await?;
            }
            Ok(())
        })
    }

    fn close(&self) -> PinFuture<Result<(), ProxymanError>> {
        let workers: Vec<Arc<dyn worker::Worker>> = self.workers.clone();
        Box::pin(async move {
            let mut errs = Vec::new();
            for w in &workers {
                if let Err(e) = w.close().await {
                    errs.push(e.to_string());
                }
            }
            if errs.is_empty() {
                Ok(())
            } else {
                Err(ProxymanError::CloseAllFailed(errs.join("; ")))
            }
        })
    }

    fn receiver_settings(&self) -> Option<&ReceiverConfig> {
        self.receiver_config.as_ref()
    }

    fn proxy_type_url(&self) -> &str {
        &self.proxy_type_url
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_on_handler_tag_and_settings_getters() {
        let h = AlwaysOnInboundHandler::new(
            "http-in",
            None,
            "xray.proxy.http.Config",
            SniffingRequest::default(),
            None,
        );
        assert_eq!(h.tag(), "http-in");
        assert_eq!(h.proxy_type_url(), "xray.proxy.http.Config");
        assert!(h.receiver_settings().is_none());
        assert!(h.uplink_counter().is_none());
        assert!(h.downlink_counter().is_none());
    }

    #[tokio::test]
    async fn always_on_handler_start_close_are_noop_ok() {
        let h =
            AlwaysOnInboundHandler::new("t", None, "xray.test", SniffingRequest::default(), None);
        assert!(h.start().await.is_ok());
        assert!(h.close().await.is_ok());
    }
}
