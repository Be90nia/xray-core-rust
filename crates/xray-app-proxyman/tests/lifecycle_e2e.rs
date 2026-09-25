//! c2v 验收 E2E：多 inbound + outbound 动态注册 + lifecycle 管理。
//!
//! 对应 bd c2v 任务描述「能动态注册多个 inbound/outbound 并管理生命周期」。
//! 覆盖三种场景：
//! 1. 静态批量注册 → start 全部 → close 全部
//! 2. start 后动态追加 handler（验证 add 不 panic）
//! 3. remove 后 handler_count 减少 + default handler 清除

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU32, Ordering},
};

use xray_app_proxyman::{
    InboundHandler, InboundManager, OutboundHandler, OutboundManager, PinFuture, ProxymanError,
};

// ===== stub handlers =====

struct CountingInHandler {
    tag: String,
    start_count: Arc<AtomicU32>,
    close_count: Arc<AtomicU32>,
    started: AtomicBool,
}

impl CountingInHandler {
    fn new(
        tag: impl Into<String>,
        start_count: Arc<AtomicU32>,
        close_count: Arc<AtomicU32>,
    ) -> Self {
        Self { tag: tag.into(), start_count, close_count, started: AtomicBool::new(false) }
    }
}

impl InboundHandler for CountingInHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn start(&self) -> PinFuture<Result<(), ProxymanError>> {
        self.start_count.fetch_add(1, Ordering::SeqCst);
        self.started.store(true, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }

    fn close(&self) -> PinFuture<Result<(), ProxymanError>> {
        self.close_count.fetch_add(1, Ordering::SeqCst);
        self.started.store(false, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }

    fn receiver_settings(&self) -> Option<&xray_proto::xray::app::proxyman::ReceiverConfig> {
        None
    }

    fn proxy_type_url(&self) -> &str {
        "xray.test.counting_in"
    }
}

struct CountingOutHandler {
    tag: String,
    start_count: Arc<AtomicU32>,
    close_count: Arc<AtomicU32>,
}

impl CountingOutHandler {
    fn new(
        tag: impl Into<String>,
        start_count: Arc<AtomicU32>,
        close_count: Arc<AtomicU32>,
    ) -> Self {
        Self { tag: tag.into(), start_count, close_count }
    }
}

impl OutboundHandler for CountingOutHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn start(&self) -> PinFuture<Result<(), ProxymanError>> {
        self.start_count.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }

    fn close(&self) -> PinFuture<Result<(), ProxymanError>> {
        self.close_count.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }

    fn sender_type_url(&self) -> Option<&str> {
        None
    }

    fn proxy_type_url(&self) -> &str {
        "xray.test.counting_out"
    }

    fn dispatch(
        &self,
        _session: xray_common::session::Session,
        _link: xray_transport::link::Link,
    ) -> PinFuture<Result<(), ProxymanError>> {
        Box::pin(async { Err(ProxymanError::Other("test stub: no dispatch".into())) })
    }

    fn dial(
        &self,
        _dest: &xray_common::net::destination::Destination,
    ) -> PinFuture<std::io::Result<Box<dyn xray_transport::connection::Connection>>> {
        Box::pin(async {
            Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "test stub: no dial"))
        })
    }
}

// ===== E2E tests =====

/// 多 inbound + outbound 批量注册 + start/close lifecycle 完整链路。
#[tokio::test]
async fn multi_inbound_outbound_lifecycle_e2e() {
    let in_start = Arc::new(AtomicU32::new(0));
    let in_close = Arc::new(AtomicU32::new(0));
    let out_start = Arc::new(AtomicU32::new(0));
    let out_close = Arc::new(AtomicU32::new(0));

    let im = InboundManager::new();
    let om = OutboundManager::new();

    // 注册 3 inbound + 3 outbound
    for i in 0..3u32 {
        im.add_handler(Arc::new(CountingInHandler::new(
            format!("in-{i}"),
            in_start.clone(),
            in_close.clone(),
        )))
        .await
        .unwrap();
        om.add_handler(Arc::new(CountingOutHandler::new(
            format!("out-{i}"),
            out_start.clone(),
            out_close.clone(),
        )))
        .unwrap();
    }

    // 预检查：handler_count + 默认 outbound 设置
    assert_eq!(im.handler_count(), 3);
    assert_eq!(om.handler_count(), 3);
    assert!(!im.is_running());
    assert!(!om.is_running());
    assert_eq!(om.get_default_handler().expect("default").tag(), "out-0");

    // start
    im.start().await.unwrap();
    om.start().await.unwrap();

    assert!(im.is_running());
    assert!(om.is_running());
    assert_eq!(in_start.load(Ordering::SeqCst), 3, "all 3 inbound started");
    assert_eq!(out_start.load(Ordering::SeqCst), 3, "all 3 outbound started");
    assert_eq!(in_close.load(Ordering::SeqCst), 0);
    assert_eq!(out_close.load(Ordering::SeqCst), 0);

    // close
    im.close().await.unwrap();
    om.close().await.unwrap();

    assert!(!im.is_running());
    assert!(!om.is_running());
    assert_eq!(in_close.load(Ordering::SeqCst), 3, "all 3 inbound closed");
    assert_eq!(out_close.load(Ordering::SeqCst), 3, "all 3 outbound closed");
}

/// start 后动态追加 handler 不 panic（验证动态注册能力）。
#[tokio::test]
async fn dynamic_add_after_start_e2e() {
    let im = InboundManager::new();
    let om = OutboundManager::new();

    im.add_handler(Arc::new(CountingInHandler::new(
        "initial-in",
        Arc::new(AtomicU32::new(0)),
        Arc::new(AtomicU32::new(0)),
    )))
    .await
    .unwrap();
    om.add_handler(Arc::new(CountingOutHandler::new(
        "initial-out",
        Arc::new(AtomicU32::new(0)),
        Arc::new(AtomicU32::new(0)),
    )))
    .unwrap();

    im.start().await.unwrap();
    om.start().await.unwrap();

    // start 后追加新 handler（当前实现：仅入表，不立即 start）
    im.add_handler(Arc::new(CountingInHandler::new(
        "post-start-in",
        Arc::new(AtomicU32::new(0)),
        Arc::new(AtomicU32::new(0)),
    )))
    .await
    .unwrap();
    om.add_handler(Arc::new(CountingOutHandler::new(
        "post-start-out",
        Arc::new(AtomicU32::new(0)),
        Arc::new(AtomicU32::new(0)),
    )))
    .unwrap();

    assert_eq!(im.handler_count(), 2);
    assert_eq!(om.handler_count(), 2);

    // close 不 panic（应迭代所有 handler）
    im.close().await.unwrap();
    om.close().await.unwrap();
}

/// remove handler 后 count 减少，default 清除（与 manager 单测互补的 E2E 视角）。
#[tokio::test]
async fn remove_handler_decrements_count_e2e() {
    let im = InboundManager::new();
    let om = OutboundManager::new();

    im.add_handler(Arc::new(CountingInHandler::new(
        "in-a",
        Arc::new(AtomicU32::new(0)),
        Arc::new(AtomicU32::new(0)),
    )))
    .await
    .unwrap();
    im.add_handler(Arc::new(CountingInHandler::new(
        "in-b",
        Arc::new(AtomicU32::new(0)),
        Arc::new(AtomicU32::new(0)),
    )))
    .await
    .unwrap();
    om.add_handler(Arc::new(CountingOutHandler::new(
        "out-a",
        Arc::new(AtomicU32::new(0)),
        Arc::new(AtomicU32::new(0)),
    )))
    .unwrap();

    assert_eq!(im.handler_count(), 2);
    assert_eq!(om.handler_count(), 1);

    // remove inbound
    im.remove_handler("in-a").await.unwrap();
    assert_eq!(im.handler_count(), 1);
    assert!(im.get_handler("in-a").is_err());

    // remove outbound default
    om.remove_handler("out-a").unwrap();
    assert_eq!(om.handler_count(), 0);
    assert!(om.get_default_handler().is_none());
}
