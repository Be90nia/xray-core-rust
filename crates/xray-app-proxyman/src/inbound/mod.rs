//! 入站代理管理
//!
//! 对应 Go `app/proxyman/inbound/`：`inbound.go`（Manager）+ `always.go`（AlwaysOnInboundHandler）+
//! `worker.go`（tcpWorker/udpWorker/dsWorker）。
//!
//! ## 当前实现范围
//!
//! 业务核心（独立可测）：
//! - [`InboundHandler`] trait — Go `inbound.Handler` 完整语义（tag/start/close/receiver/proxy）
//! - [`InboundManager`] — Go `Manager struct`：tagged + untyped 双 map + 启停状态
//! - [`AlwaysOnInboundHandler`] — Go `AlwaysOnInboundHandler`：配置载体 + counter 引用
//!
//!
//! IO 边界：
//! - worker 创建（tcpWorker/udpWorker/dsWorker）— 已在 [`worker`] 模块实现
//! - `AlwaysOnInboundHandler::start` / `close` — 迭代 workers 启停
//! - proxy.Process — 依赖具体代理 crate + Dispatcher

pub mod worker;

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use parking_lot::RwLock;
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

/// 入站管理器（对应 Go `app/proxyman/inbound.Manager`）
pub struct InboundManager {
    state: RwLock<ManagerState>,
    running: AtomicBool,
}

#[derive(Default)]
struct ManagerState {
    tagged: HashMap<String, Arc<dyn InboundHandler>>,
    untagged: Vec<Arc<dyn InboundHandler>>,
}

impl std::fmt::Debug for InboundManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.read();
        f.debug_struct("InboundManager")
            .field("tagged_count", &state.tagged.len())
            .field("untagged_count", &state.untagged.len())
            .field("running", &self.running.load(Ordering::SeqCst))
            .finish()
    }
}

impl InboundManager {
    /// 创建空管理器（对应 Go `New(ctx, *InboundConfig) (*Manager, error)`）
    #[must_use]
    pub fn new() -> Self {
        Self { state: RwLock::new(ManagerState::default()), running: AtomicBool::new(false) }
    }

    /// 添加 handler（对应 Go `AddHandler(ctx, handler) error`）
    ///
    /// # Errors
    /// - [`ProxymanError::ExistingTag`]：tag 已存在
    pub async fn add_handler(&self, handler: Arc<dyn InboundHandler>) -> Result<(), ProxymanError> {
        let tag = handler.tag().to_string();
        {
            let mut state = self.state.write();
            if !tag.is_empty() {
                if state.tagged.contains_key(&tag) {
                    return Err(ProxymanError::ExistingTag(tag));
                }
                state.tagged.insert(tag, handler.clone());
            } else {
                state.untagged.push(handler.clone());
            }
        }
        // Go 行为：如果 manager 已在运行，立即启动新 handler
        if self.running.load(Ordering::SeqCst) {
            handler.start().await?;
        }
        Ok(())
    }

    /// 取 handler（对应 Go `GetHandler(ctx, tag) (Handler, error)`）
    ///
    /// # Errors
    /// - [`ProxymanError::HandlerNotFound`]：tag 不存在
    pub fn get_handler(&self, tag: &str) -> Result<Arc<dyn InboundHandler>, ProxymanError> {
        let state = self.state.read();
        state
            .tagged
            .get(tag)
            .cloned()
            .ok_or_else(|| ProxymanError::HandlerNotFound(tag.to_string()))
    }

    /// 移除 handler（对应 Go `RemoveHandler(ctx, tag) error`）
    ///
    /// Go 行为：先关闭 handler，再从 map 移除。
    ///
    /// # Errors
    /// - [`ProxymanError::NoClue`]：tag 为空 或 不存在（Go `common.ErrNoClue`）
    pub async fn remove_handler(&self, tag: &str) -> Result<(), ProxymanError> {
        if tag.is_empty() {
            return Err(ProxymanError::NoClue);
        }
        let handler = {
            let mut state = self.state.write();
            state.tagged.remove(tag)
        };
        match handler {
            Some(h) => {
                // Go 行为：关闭 handler 再移除
                let _ = h.close().await;
                Ok(())
            },
            None => Err(ProxymanError::NoClue),
        }
    }

    /// 列出所有 handler（对应 Go `ListHandlers(ctx) []Handler`）
    pub fn list_handlers(&self) -> Vec<Arc<dyn InboundHandler>> {
        let state = self.state.read();
        let mut out: Vec<Arc<dyn InboundHandler>> =
            Vec::with_capacity(state.untagged.len() + state.tagged.len());
        out.extend(state.untagged.iter().cloned());
        out.extend(state.tagged.values().cloned());
        out
    }

    /// 启动所有 handler（对应 Go `Start() error`）
    ///
    /// 当前实现：标记 running=true，遍历调 `start()`。具体 handler 的 `start` 是否真做事
    /// 取决于是否注入了 worker（默认 [`AlwaysOnInboundHandler`] 的 `start` 返回 Ok）。
    pub async fn start(&self) -> Result<(), ProxymanError> {
        let handlers: Vec<Arc<dyn InboundHandler>> = {
            let state = self.state.write();
            self.running.store(true, Ordering::SeqCst);
            let mut all: Vec<Arc<dyn InboundHandler>> = state.tagged.values().cloned().collect();
            all.extend(state.untagged.iter().cloned());
            all
        };
        for h in handlers {
            h.start().await?;
        }
        Ok(())
    }

    /// 关闭所有 handler（对应 Go `Close() error`）
    pub async fn close(&self) -> Result<(), ProxymanError> {
        let handlers: Vec<Arc<dyn InboundHandler>> = {
            let state = self.state.write();
            self.running.store(false, Ordering::SeqCst);
            let mut all: Vec<Arc<dyn InboundHandler>> = state.tagged.values().cloned().collect();
            all.extend(state.untagged.iter().cloned());
            all
        };
        let mut errs: Vec<String> = Vec::new();
        for h in handlers {
            if let Err(e) = h.close().await {
                errs.push(e.to_string());
            }
        }
        if errs.is_empty() { Ok(()) } else { Err(ProxymanError::CloseAllFailed(errs.join("; "))) }
    }

    /// 当前是否运行中
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// 已注册 handler 总数
    pub fn handler_count(&self) -> usize {
        let state = self.state.read();
        state.tagged.len() + state.untagged.len()
    }
}

impl Default for InboundManager {
    fn default() -> Self {
        Self::new()
    }
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

    /// 最小可测 InboundHandler 实现
    struct StubHandler {
        tag: String,
        type_url: String,
        started: AtomicBool,
        closed: AtomicBool,
    }

    impl StubHandler {
        fn new(tag: &str) -> Self {
            Self {
                tag: tag.to_string(),
                type_url: "xray.test.stub".to_string(),
                started: AtomicBool::new(false),
                closed: AtomicBool::new(false),
            }
        }

        fn is_started(&self) -> bool {
            self.started.load(Ordering::SeqCst)
        }

        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::SeqCst)
        }
    }

    impl InboundHandler for StubHandler {
        fn tag(&self) -> &str {
            &self.tag
        }

        fn start(&self) -> PinFuture<Result<(), ProxymanError>> {
            self.started.store(true, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }

        fn close(&self) -> PinFuture<Result<(), ProxymanError>> {
            self.closed.store(true, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }

        fn receiver_settings(&self) -> Option<&ReceiverConfig> {
            None
        }

        fn proxy_type_url(&self) -> &str {
            &self.type_url
        }
    }

    fn make_handler(tag: &str) -> Arc<dyn InboundHandler> {
        Arc::new(StubHandler::new(tag))
    }

    #[test]
    fn manager_new_empty() {
        let m = InboundManager::new();
        assert_eq!(m.handler_count(), 0);
        assert!(!m.is_running());
    }

    #[tokio::test]
    async fn manager_add_tagged_handler() {
        let m = InboundManager::new();
        m.add_handler(make_handler("http")).await.unwrap();
        assert_eq!(m.handler_count(), 1);
        assert!(m.get_handler("http").is_ok());
    }

    #[tokio::test]
    async fn manager_add_duplicate_tag_returns_existing_tag_error() {
        let m = InboundManager::new();
        m.add_handler(make_handler("http")).await.unwrap();
        match m.add_handler(make_handler("http")).await {
            Err(ProxymanError::ExistingTag(t)) => assert_eq!(t, "http"),
            Err(e) => panic!("expected ExistingTag, got: {e}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[tokio::test]
    async fn manager_add_untagged_handler() {
        let m = InboundManager::new();
        m.add_handler(make_handler("")).await.unwrap();
        m.add_handler(make_handler("")).await.unwrap();
        assert_eq!(m.handler_count(), 2);
    }

    #[test]
    fn manager_get_unknown_returns_not_found() {
        let m = InboundManager::new();
        match m.get_handler("missing") {
            Err(ProxymanError::HandlerNotFound(t)) => assert_eq!(t, "missing"),
            Err(e) => panic!("expected HandlerNotFound, got: {e}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[tokio::test]
    async fn manager_remove_handler() {
        let m = InboundManager::new();
        m.add_handler(make_handler("socks")).await.unwrap();
        assert!(m.remove_handler("socks").await.is_ok());
        assert_eq!(m.handler_count(), 0);
    }

    #[tokio::test]
    async fn manager_remove_unknown_returns_no_clue() {
        let m = InboundManager::new();
        match m.remove_handler("ghost").await {
            Err(ProxymanError::NoClue) => (),
            Err(e) => panic!("expected NoClue, got: {e}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[tokio::test]
    async fn manager_remove_empty_tag_returns_no_clue() {
        let m = InboundManager::new();
        match m.remove_handler("").await {
            Err(ProxymanError::NoClue) => (),
            Err(e) => panic!("expected NoClue, got: {e}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[tokio::test]
    async fn manager_list_handlers_includes_tagged_and_untagged() {
        let m = InboundManager::new();
        m.add_handler(make_handler("a")).await.unwrap();
        m.add_handler(make_handler("")).await.unwrap();
        m.add_handler(make_handler("b")).await.unwrap();
        let list = m.list_handlers();
        assert_eq!(list.len(), 3);
        let tags: Vec<&str> = list.iter().map(|h| h.tag()).collect();
        assert!(tags.contains(&"a"));
        assert!(tags.contains(&"b"));
        assert!(tags.contains(&""));
    }

    #[tokio::test]
    async fn manager_start_marks_running_and_starts_handlers() {
        let m = InboundManager::new();
        let h = Arc::new(StubHandler::new("x"));
        m.add_handler(h.clone()).await.unwrap();
        assert!(!h.is_started());
        m.start().await.unwrap();
        assert!(m.is_running());
        assert!(h.is_started());
    }

    #[tokio::test]
    async fn manager_close_marks_not_running_and_closes_handlers() {
        let m = InboundManager::new();
        let h = Arc::new(StubHandler::new("y"));
        m.add_handler(h.clone()).await.unwrap();
        m.start().await.unwrap();
        m.close().await.unwrap();
        assert!(!m.is_running());
        assert!(h.is_closed());
    }

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
