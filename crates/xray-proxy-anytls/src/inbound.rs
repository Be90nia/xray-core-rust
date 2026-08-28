//! AnyTLS 入站处理器。
//!
//! 包装 [`AnytlsMockServer`]，实现 [`InboundHandler`] trait。
//!
//! ## 流程
//!
//! 1. `InboundHandler::start` 被调用
//! 2. 启动 TCP listener + TLS acceptor（[`tokio_rustls::TlsAcceptor`]）
//! 3. 每个新 TLS conn 经 anytls server session 处理：读 SOCKS5 target →
//!    `dispatch = Some` 走 [`xray_app_dispatcher::DispatchHandler::dispatch`]，
//!    `dispatch = None` 保留 mock 直连（loopback 测试）
//! 4. `close` 时停止 listener 并清理资源
//!
//! 见 bd Xray-core-rust-dax。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::info;
use xray_app_dispatcher::DispatchHandler;
use xray_features::inbound::{InboundError, InboundHandler};

use crate::server::AnytlsMockServer;

/// AnyTLS 入站 Handler。
///
/// 持有配置 + TLS acceptor，start 时启动 [`AnytlsMockServer`] 监听。
pub struct AnytlsInboundHandler {
    tag: String,
    bind_addr: SocketAddr,
    tls_acceptor: tokio_rustls::TlsAcceptor,
    /// 出站 dispatch（Some 时 session 流量经 router 分发；None 直连目标——mock）。
    dispatch: Option<Arc<dyn DispatchHandler>>,
    /// start 后实际监听端口（bind 0 时由 OS 分配），port() 返回此值。
    local_port: AtomicU16,
    /// server 句柄 + accept 任务，close 时 stop。
    slot: Mutex<Option<InboundSlot>>,
}

struct InboundSlot {
    /// MockServer 句柄（保持存活；stop 时消费）。
    server: AnytlsMockServer,
    /// accept 循环任务句柄（close 时 abort 兜底）。
    _accept_task: JoinHandle<()>,
}

impl AnytlsInboundHandler {
    /// 构造入站 Handler（mock 直连模式，loopback 测试用）。
    pub fn new(
        tag: impl Into<String>,
        bind_addr: SocketAddr,
        tls_acceptor: tokio_rustls::TlsAcceptor,
    ) -> Self {
        Self {
            tag: tag.into(),
            bind_addr,
            tls_acceptor,
            dispatch: None,
            local_port: AtomicU16::new(0),
            slot: Mutex::new(None),
        }
    }

    /// 注入出站 dispatcher（生产路径：session 流量经 router 分发而非直连）。
    #[must_use]
    pub fn with_dispatch(mut self, dispatch: Arc<dyn DispatchHandler>) -> Self {
        self.dispatch = Some(dispatch);
        self
    }

    /// 绑定地址。
    #[must_use]
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }
}

#[async_trait]
impl InboundHandler for AnytlsInboundHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(&self) -> std::result::Result<(), InboundError> {
        let mut slot = self.slot.lock().await;
        if slot.is_some() {
            return Err(InboundError::AlreadyStarted(self.tag.clone()));
        }

        let server = AnytlsMockServer::start(
            self.bind_addr,
            self.tls_acceptor.clone(),
            self.dispatch.clone(),
        )
        .await
        .map_err(|e| InboundError::ListenError(format!("anytls listen: {e}")))?;

        let local_addr = server.local_addr;
        self.local_port.store(local_addr.port(), Ordering::SeqCst);
        let tag = self.tag.clone();

        // spawn 一个 keep-alive 任务，持有 server 句柄直到 close 被调用
        let accept_task = tokio::spawn(async move {
            // 该任务仅保持存活，实际 serve 逻辑在 MockServer 内部
            // close 时通过 stop_tx 触发退出
            info!(tag = %tag, addr = %local_addr, "anytls inbound listener started");
            // 永远等待，直到 task 被 abort
            std::future::pending::<()>().await;
        });

        *slot = Some(InboundSlot {
            server,
            _accept_task: accept_task,
        });
        Ok(())
    }

    async fn close(&self) -> std::result::Result<(), InboundError> {
        let slot = self.slot.lock().await.take();
        if let Some(s) = slot {
            s._accept_task.abort();
            s.server.stop().await;
            self.local_port.store(0, Ordering::SeqCst);
            info!(tag = %self.tag, "anytls inbound closed");
        }
        Ok(())
    }

    fn port(&self) -> u16 {
        let p = self.local_port.load(Ordering::SeqCst);
        if p != 0 { p } else { self.bind_addr.port() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::PrivateKeyDer;
    use std::sync::Arc;

    use std::sync::Once;

    static INIT_CRYPTO: Once = Once::new();

    fn init_crypto() {
        INIT_CRYPTO.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn make_tls_acceptor() -> tokio_rustls::TlsAcceptor {
        init_crypto();
        let key_pair = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.into()], key_der)
            .unwrap();

        tokio_rustls::TlsAcceptor::from(Arc::new(config))
    }

    fn make_handler() -> AnytlsInboundHandler {
        AnytlsInboundHandler::new(
            "test",
            "127.0.0.1:0".parse().unwrap(),
            make_tls_acceptor(),
        )
    }

    #[test]
    fn handler_tag_and_port() {
        let h = make_handler();
        assert_eq!(h.tag(), "test");
        assert_eq!(h.port(), 0);
    }

    #[tokio::test]
    async fn start_and_close() {
        let h = make_handler();
        assert!(h.start().await.is_ok());
        // start 后 port 应反映 OS 分配的实际端口（非零）
        assert!(h.port() > 0, "port after start must be non-zero");
        // 第二次 start 应返回 AlreadyStarted
        let r = h.start().await;
        assert!(r.is_err());
        match r.unwrap_err() {
            InboundError::AlreadyStarted(tag) => assert_eq!(tag, "test"),
            other => panic!("expected AlreadyStarted, got {other:?}"),
        }
        assert!(h.close().await.is_ok());
        // close 后再 start 应成功
        assert!(h.start().await.is_ok());
    }

    #[tokio::test]
    async fn close_without_start_is_ok() {
        let h = make_handler();
        assert!(h.close().await.is_ok());
    }
}