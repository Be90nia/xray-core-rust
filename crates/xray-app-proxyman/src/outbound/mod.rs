//! 出站代理管理
//!
//! 对应 Go `app/proxyman/outbound/outbound.go`：Manager 结构 + 5 个公开方法
//! + `Select` 前缀匹配（HandlerSelector 接口实现）。
//!
//! ## 当前实现范围
//!
//! 业务核心（独立可测）：
//! - [`OutboundHandler`] trait — Go `outbound.Handler` 完整语义
//! - [`OutboundManager`] — Go `Manager struct`：tagged/untagged/default + 启停
//! - [`OutboundManager::select_by_prefix`] — Go `Select(selectors) []string`
//!
//! 简化：
//! - Go `tagsCache *sync.Map` 用于并发 add/remove/select 时缓存 Select 结果。
//!   Rust 端用 `parking_lot::RwLock` 互斥访问 tagged map，无需 cache。
//!   若并发吞吐出现瓶颈，可改用 `ArcSwap<HashMap>` 优化。

pub mod handler;
pub mod proxy_outbound;
pub mod uot;

pub use handler::{OutboundHandlerEntry, UotVersion, parse_random_ip};
pub use proxy_outbound::{OutboundDialer, ProxyOutbound};
use crate::error::ProxymanError;
use crate::inbound::PinFuture;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// 出站 handler trait（对应 Go `features/outbound.Handler`）
///
/// 与 `xray_features::outbound::OutboundHandler` 区别：本 trait 暴露
/// `sender_settings` proto 引用 + `proxy_type_url` 字符串，保持 Go 完整语义。
pub trait OutboundHandler: Send + Sync {
    /// 返回 handler tag
    fn tag(&self) -> &str;

    /// 启动 handler
    fn start(&self) -> PinFuture<Result<(), ProxymanError>>;

    /// 关闭 handler
    fn close(&self) -> PinFuture<Result<(), ProxymanError>>;

    /// SenderSettings 配置（对应 Go `SenderSettings() *serial.TypedMessage`，
    /// Rust 端返回 type_url 字符串标识 SenderConfig 是否存在）
    fn sender_type_url(&self) -> Option<&str>;

    /// ProxySettings 类型 URL
    fn proxy_type_url(&self) -> &str;

    /// 分发出站流量（对应 Go `Handler.Dispatch(ctx, link)`）。
    ///
    /// 将 `link` 中的出站数据通过此 handler 的代理处理器发送。
    /// 如果未配置代理处理器，返回 [`ProxymanError::Other`]。
    fn dispatch(&self, session: xray_common::session::Session, link: xray_transport::link::Link) -> PinFuture<Result<(), ProxymanError>>;

    /// 向目标地址拨号（对应 Go `Handler.Dial(ctx, dest)`）。
    ///
    /// 如果配置了代理链 tag，通过 chained handler 拨号；否则直接拨号。
    fn dial(&self, dest: &xray_common::net::destination::Destination) -> PinFuture<std::io::Result<Box<dyn xray_transport::connection::Connection>>>;
}

/// 出站管理器（对应 Go `app/proxyman/outbound.Manager`）
pub struct OutboundManager {
    state: RwLock<ManagerState>,
    running: AtomicBool,
}

#[derive(Default)]
struct ManagerState {
    default_handler: Option<Arc<dyn OutboundHandler>>,
    tagged: HashMap<String, Arc<dyn OutboundHandler>>,
    untagged: Vec<Arc<dyn OutboundHandler>>,
}

impl std::fmt::Debug for OutboundManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.state.read();
        f.debug_struct("OutboundManager")
            .field("tagged_count", &s.tagged.len())
            .field("untagged_count", &s.untagged.len())
            .field("has_default", &s.default_handler.is_some())
            .field("running", &self.running.load(Ordering::SeqCst))
            .finish()
    }
}

impl OutboundManager {
    /// 创建空管理器（对应 Go `New(ctx, *OutboundConfig) (*Manager, error)`）
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: RwLock::new(ManagerState::default()),
            running: AtomicBool::new(false),
        }
    }

    /// 取默认 handler（对应 Go `GetDefaultHandler() Handler`）
    #[must_use]
    pub fn get_default_handler(&self) -> Option<Arc<dyn OutboundHandler>> {
        self.state.read().default_handler.clone()
    }

    /// 取 handler（对应 Go `GetHandler(tag) Handler`）
    #[must_use]
    pub fn get_handler(&self, tag: &str) -> Option<Arc<dyn OutboundHandler>> {
        self.state.read().tagged.get(tag).cloned()
    }

    /// 添加 handler（对应 Go `AddHandler(ctx, handler) error`）
    ///
    /// 第一个添加的 handler 自动成为 default。
    ///
    /// # Errors
    /// - [`ProxymanError::ExistingTag`]：tag 已存在
    pub fn add_handler(&self, handler: Arc<dyn OutboundHandler>) -> Result<(), ProxymanError> {
        let mut state = self.state.write();
        if state.default_handler.is_none() {
            state.default_handler = Some(handler.clone());
        }
        let tag = handler.tag().to_string();
        if !tag.is_empty() {
            if state.tagged.contains_key(&tag) {
                return Err(ProxymanError::ExistingTag(tag));
            }
            state.tagged.insert(tag, handler);
        } else {
            state.untagged.push(handler);
        }
        Ok(())
    }

    /// 移除 handler（对应 Go `RemoveHandler(ctx, tag) error`）
    ///
    /// # Errors
    /// - [`ProxymanError::NoClue`]：tag 为空
    pub fn remove_handler(&self, tag: &str) -> Result<(), ProxymanError> {
        if tag.is_empty() {
            return Err(ProxymanError::NoClue);
        }
        let mut state = self.state.write();
        state.tagged.remove(tag);
        if let Some(def) = &state.default_handler {
            if def.tag() == tag {
                state.default_handler = None;
            }
        }
        Ok(())
    }

    /// 列出所有 handler（对应 Go `ListHandlers(ctx) []Handler`）
    pub fn list_handlers(&self) -> Vec<Arc<dyn OutboundHandler>> {
        let state = self.state.read();
        let mut out: Vec<Arc<dyn OutboundHandler>> =
            Vec::with_capacity(state.untagged.len() + state.tagged.len());
        out.extend(state.untagged.iter().cloned());
        out.extend(state.tagged.values().cloned());
        out
    }

    /// 按前缀筛选 tag（对应 Go `Select(selectors) []string`）
    ///
    /// 返回所有 tag 中**任一**前缀命中 selectors 的 tag，按字典序排序。
    #[must_use]
    pub fn select_by_prefix(&self, selectors: &[String]) -> Vec<String> {
        let state = self.state.read();
        let mut hits: Vec<String> = state
            .tagged
            .keys()
            .filter(|tag| selectors.iter().any(|sel| tag.starts_with(sel.as_str())))
            .cloned()
            .collect();
        hits.sort();
        hits
    }

    /// 启动所有 handler（对应 Go `Start() error`）
    pub async fn start(&self) -> Result<(), ProxymanError> {
        let handlers: Vec<Arc<dyn OutboundHandler>> = {
            let state = self.state.write();
            self.running.store(true, Ordering::SeqCst);
            let mut all: Vec<Arc<dyn OutboundHandler>> = state.tagged.values().cloned().collect();
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
        let handlers: Vec<Arc<dyn OutboundHandler>> = {
            let state = self.state.write();
            self.running.store(false, Ordering::SeqCst);
            let mut all: Vec<Arc<dyn OutboundHandler>> = state.tagged.values().cloned().collect();
            all.extend(state.untagged.iter().cloned());
            all
        };
        let mut errs: Vec<String> = Vec::new();
        for h in handlers {
            if let Err(e) = h.close().await {
                errs.push(e.to_string());
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(ProxymanError::CloseAllFailed(errs.join("; ")))
        }
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

impl Default for OutboundManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubOutHandler {
        tag: String,
        type_url: String,
        started: AtomicBool,
        closed: AtomicBool,
    }

    impl StubOutHandler {
        fn new(tag: &str) -> Self {
            Self {
                tag: tag.to_string(),
                type_url: "xray.test.out".to_string(),
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

    impl OutboundHandler for StubOutHandler {
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
        fn sender_type_url(&self) -> Option<&str> {
            None
        }
        fn proxy_type_url(&self) -> &str {
            &self.type_url
        }
        fn dispatch(&self, _session: xray_common::session::Session, _link: xray_transport::link::Link) -> PinFuture<Result<(), ProxymanError>> {
            Box::pin(async { Ok(()) })
        }
        fn dial(&self, _dest: &xray_common::net::destination::Destination) -> PinFuture<std::io::Result<Box<dyn xray_transport::connection::Connection>>> {
            Box::pin(async {
                Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "stub dial"))
            })
        }
    }

    fn mk(tag: &str) -> Arc<dyn OutboundHandler> {
        Arc::new(StubOutHandler::new(tag))
    }

    #[test]
    fn manager_new_empty() {
        let m = OutboundManager::new();
        assert_eq!(m.handler_count(), 0);
        assert!(!m.is_running());
        assert!(m.get_default_handler().is_none());
    }

    #[test]
    fn first_added_becomes_default() {
        let m = OutboundManager::new();
        m.add_handler(mk("first")).unwrap();
        m.add_handler(mk("second")).unwrap();
        let def = m.get_default_handler().expect("default should be set");
        assert_eq!(def.tag(), "first");
    }

    #[test]
    fn add_duplicate_tag_errors() {
        let m = OutboundManager::new();
        m.add_handler(mk("dup")).unwrap();
        match m.add_handler(mk("dup")) {
            Err(ProxymanError::ExistingTag(t)) => assert_eq!(t, "dup"),
            Err(e) => panic!("expected ExistingTag, got: {e}"),
    Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn add_untagged_does_not_overwrite_default() {
        let m = OutboundManager::new();
        m.add_handler(mk("named")).unwrap();
        m.add_handler(mk("")).unwrap();
        m.add_handler(mk("")).unwrap();
        assert_eq!(m.handler_count(), 3);
        assert_eq!(m.get_default_handler().unwrap().tag(), "named");
    }

    #[test]
    fn get_handler_unknown_returns_none() {
        let m = OutboundManager::new();
        assert!(m.get_handler("ghost").is_none());
    }

    #[test]
    fn remove_handler() {
        let m = OutboundManager::new();
        m.add_handler(mk("a")).unwrap();
        assert!(m.remove_handler("a").is_ok());
        assert!(m.get_handler("a").is_none());
        assert_eq!(m.handler_count(), 0);
    }

    #[test]
    fn remove_default_handler_clears_default() {
        let m = OutboundManager::new();
        m.add_handler(mk("def")).unwrap();
        assert!(m.get_default_handler().is_some());
        m.remove_handler("def").unwrap();
        assert!(m.get_default_handler().is_none());
    }

    #[test]
    fn remove_empty_tag_returns_no_clue() {
        let m = OutboundManager::new();
        match m.remove_handler("") {
            Err(ProxymanError::NoClue) => (),
            Err(e) => panic!("expected NoClue, got: {e}"),
    Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn select_by_prefix_basic() {
        let m = OutboundManager::new();
        m.add_handler(mk("node1")).unwrap();
        m.add_handler(mk("node2")).unwrap();
        m.add_handler(mk("proxy")).unwrap();
        m.add_handler(mk("node10")).unwrap();

        let sels = vec!["node".to_string()];
        let hits = m.select_by_prefix(&sels);
        assert_eq!(hits, vec!["node1", "node10", "node2"]);
    }

    #[test]
    fn select_by_prefix_multiple_selectors() {
        let m = OutboundManager::new();
        m.add_handler(mk("us_node1")).unwrap();
        m.add_handler(mk("hk_node1")).unwrap();
        m.add_handler(mk("jp_proxy")).unwrap();

        let sels = vec!["us_".to_string(), "jp_".to_string()];
        let hits = m.select_by_prefix(&sels);
        assert_eq!(hits, vec!["jp_proxy", "us_node1"]);
    }

    #[test]
    fn select_by_prefix_empty_selectors_returns_empty() {
        let m = OutboundManager::new();
        m.add_handler(mk("node1")).unwrap();
        let hits = m.select_by_prefix(&[]);
        assert!(hits.is_empty());
    }

    #[test]
    fn select_by_prefix_no_match_returns_empty() {
        let m = OutboundManager::new();
        m.add_handler(mk("node1")).unwrap();
        let sels = vec!["xxx".to_string()];
        assert!(m.select_by_prefix(&sels).is_empty());
    }

    #[tokio::test]
    async fn manager_start_close_runs_handlers() {
        let m = OutboundManager::new();
        let h1 = Arc::new(StubOutHandler::new("a"));
        let h2 = Arc::new(StubOutHandler::new("b"));
        m.add_handler(h1.clone()).unwrap();
        m.add_handler(h2.clone()).unwrap();
        m.start().await.unwrap();
        assert!(h1.is_started() && h2.is_started());
        m.close().await.unwrap();
        assert!(h1.is_closed() && h2.is_closed());
        assert!(!m.is_running());
    }

    #[tokio::test]
    async fn concurrent_add_remove_select_no_panic() {
        // 简化版 Go TestTagsCache：不验证缓存语义，只验证并发不崩
        let m = Arc::new(OutboundManager::new());
        for i in 0..20 {
            m.add_handler(mk(&format!("node{i}"))).unwrap();
        }

        let m1 = m.clone();
        let h1 = tokio::spawn(async move {
            for i in 0..50 {
                let _ = m1.add_handler(mk(&format!("n{i}")));
                let _ = m1.select_by_prefix(&["n".to_string()]);
            }
        });

        let m2 = m.clone();
        let h2 = tokio::spawn(async move {
            for i in 0..50 {
                let _ = m2.remove_handler(&format!("n{i}"));
                let _ = m2.select_by_prefix(&["node".to_string()]);
            }
        });

        h1.await.unwrap();
        h2.await.unwrap();
        // 不 panic 即通过
    }
}
