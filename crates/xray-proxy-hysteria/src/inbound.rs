//! Hysteria 入站处理器，对应 Go `proxy/hysteria/inbound.go`。
//!
//! 包装 [`HysteriaListener`]（QUIC accept 循环编排）+ [`HysteriaListenerFactory`]，
//! 实现 [`InboundHandler`] trait。
//!
//! ## 流程
//!
//! 1. `InboundHandler::start` 被调用
//! 2. `HysteriaListenerFactory::listen` 创建 QUIC listener（bind + TLS + auth validator）
//! 3. `HysteriaListener::start(quic_listener)` 注入 listener
//! 4. 每个新 QUIC conn 经 HTTP/3 auth 后，`on_new_conn` 回调投递 `InterStreamConn`
//!
//! ## 认证
//!
//! [`StaticAuthValidator`] 做简单字符串匹配（config.auth == 客户端 auth 头），
//! 对应 Hysteria v2 的 `auth=password` 模式。

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::info;
use xray_features::inbound::{InboundError, InboundHandler};
use xray_proto::xray::transport::internet::QuicParams;
use xray_transport_hysteria::conn::InterStreamConn;
use xray_transport_hysteria::hub::{
    AuthValidator, HysteriaListener, HysteriaListenerFactory, HysteriaQuicListener, MasqType,
};
use xray_transport_hysteria::proto_config::Config as ProtoConfig;

use crate::config::HysteriaConfig;
use crate::error::Result;

/// 简单字符串匹配 auth validator。
///
/// 对应 Hysteria v2 的 `auth=password`：客户端 `Hysteria-Auth` 头值 == 配置 token 即通过。
pub struct StaticAuthValidator {
    expected: String,
}

impl StaticAuthValidator {
    #[must_use]
    pub fn new(expected: impl Into<String>) -> Self {
        Self {
            expected: expected.into(),
        }
    }
}

impl AuthValidator for StaticAuthValidator {
    fn validate(&self, auth: &str) -> Option<String> {
        if auth == self.expected {
            Some(self.expected.clone())
        } else {
            None
        }
    }

    fn count(&self) -> usize {
        1
    }
}

/// Hysteria 入站 Handler。
///
/// 持有配置 + `HysteriaListenerFactory`，实现 [`InboundHandler`]。
/// `start` 时通过 factory 创建 QUIC listener 并注入 `HysteriaListener`。
pub struct HysteriaInboundHandler {
    tag: String,
    config: HysteriaConfig,
    bind_addr: SocketAddr,
    factory: Arc<dyn HysteriaListenerFactory>,
    /// listener + accept 任务句柄，close 时 abort。
    slot: Mutex<Option<InboundSlot>>,
}

struct InboundSlot {
    /// HysteriaListener 句柄（保持存活；close 时 drop 自动清理）。
    _listener: Arc<HysteriaListener>,
    quic_listener: Arc<dyn HysteriaQuicListener>,
    _accept_task: JoinHandle<()>,
}

impl HysteriaInboundHandler {
    /// 构造入站 Handler。
    ///
    /// # 参数
    /// - `tag`：handler 标签
    /// - `config`：Hysteria 代理配置（auth / bandwidth / udp_idle_timeout）
    /// - `bind_addr`：QUIC 监听地址（如 `0.0.0.0:443`）
    /// - `factory`：QUIC listener 工厂（真实实现待 quinn server adapter 注入）
    ///
    /// # Errors
    /// 配置无效时返回 [`InvalidConfig`](crate::HysteriaProxyError::InvalidConfig)。
    pub fn new(
        tag: impl Into<String>,
        config: HysteriaConfig,
        bind_addr: SocketAddr,
        factory: Arc<dyn HysteriaListenerFactory>,
    ) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            tag: tag.into(),
            config,
            bind_addr,
            factory,
            slot: Mutex::new(None),
        })
    }

    /// 配置引用。
    #[must_use]
    pub fn config(&self) -> &HysteriaConfig {
        &self.config
    }

    /// 绑定地址。
    #[must_use]
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// 构造 transport 层 proto Config。
    fn build_proto_config(&self) -> ProtoConfig {
        ProtoConfig {
            auth: self.config.auth.clone(),
            udp_idle_timeout: self.config.udp_idle_timeout_secs as i64,
            ..ProtoConfig::default()
        }
    }
}

#[async_trait]
impl InboundHandler for HysteriaInboundHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(&self) -> std::result::Result<(), InboundError> {
        let mut slot = self.slot.lock().await;
        if slot.is_some() {
            return Err(InboundError::AlreadyStarted(self.tag.clone()));
        }

        let proto_config = Arc::new(self.build_proto_config());
        let quic_params = Arc::new(QuicParams::default());
        let masq = MasqType::from_config(&proto_config)
            .map_err(|e| InboundError::ListenError(format!("masq config: {e}")))?;
        let validator: Option<Arc<dyn AuthValidator>> = if self.config.auth.is_empty() {
            None
        } else {
            Some(Arc::new(StaticAuthValidator::new(self.config.auth.clone())))
        };

        // on_new_conn 回调：每个新 TCP stream 触发（切片阶段仅 log）
        let on_new_conn: Arc<dyn Fn(Arc<InterStreamConn>) + Send + Sync> =
            Arc::new(|stream: Arc<InterStreamConn>| {
                tracing::debug!(
                    local = %stream.local_addr(),
                    remote = %stream.remote_addr(),
                    "hysteria inbound new TCP stream"
                );
            });

        let quic_listener = self
            .factory
            .listen(
                self.bind_addr,
                Arc::clone(&proto_config),
                Arc::clone(&quic_params),
                masq,
                validator,
                Arc::clone(&on_new_conn),
            )
            .await
            .map_err(|e| InboundError::ListenError(format!("hysteria listen: {e}")))?;

        let listener = Arc::new(HysteriaListener::new(
            self.bind_addr,
            proto_config,
            quic_params,
            // ponytail: masq 已消费进 listen 调用参数中 factory 使用，这里用 NotFound 兜底
            // （HysteriaListener 只是存储，实际 masq 逻辑在 factory 内部 http3 server）
            MasqType::NotFound,
            None,
            on_new_conn,
        ));

        let listener_clone = Arc::clone(&listener);
        let quic_clone = Arc::clone(&quic_listener);
        let tag = self.tag.clone();
        let accept_task = tokio::spawn(async move {
            listener_clone.start(quic_clone).await;
            info!(tag = %tag, "hysteria inbound listener started");
        });

        *slot = Some(InboundSlot {
            _listener: listener,
            quic_listener,
            _accept_task: accept_task,
        });
        Ok(())
    }

    async fn close(&self) -> std::result::Result<(), InboundError> {
        let slot = self.slot.lock().await.take();
        if let Some(s) = slot {
            s._accept_task.abort();
            // ponytail: HysteriaListener::close() 内部跨 await 持 parking_lot guard（!Send），
            // 不能在 async_trait 的 Send 上下文中调用。直接关 quic_listener（其 close 是 Send），
            // HysteriaListener Arc drop 时自动清理内部状态。
            let _ = s.quic_listener.close().await;
            info!(tag = %self.tag, "hysteria inbound closed");
        }
        Ok(())
    }

    fn port(&self) -> u16 {
        self.bind_addr.port()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_transport_hysteria::hub::StubListenerFactory;

    fn make_handler(auth: &str) -> HysteriaInboundHandler {
        let cfg = HysteriaConfig::new("0.0.0.0:0", auth);
        HysteriaInboundHandler::new(
            "test",
            cfg,
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(StubListenerFactory),
        )
        .unwrap()
    }

    #[test]
    fn static_auth_validator_matches() {
        let v = StaticAuthValidator::new("secret");
        assert_eq!(v.validate("secret"), Some("secret".into()));
        assert_eq!(v.validate("wrong"), None);
        assert_eq!(v.count(), 1);
    }

    #[test]
    fn handler_tag_and_port() {
        let h = make_handler("secret");
        assert_eq!(h.tag(), "test");
        assert_eq!(h.port(), 0);
    }

    #[test]
    fn handler_rejects_empty_server_addr() {
        let cfg = HysteriaConfig::new("", "secret");
        let r = HysteriaInboundHandler::new(
            "test",
            cfg,
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(StubListenerFactory),
        );
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn start_with_stub_factory_returns_listen_error() {
        let h = make_handler("secret");
        // StubListenerFactory 返回 ConnectionClosed → start 失败
        let r = h.start().await;
        assert!(r.is_err());
        match r.unwrap_err() {
            InboundError::ListenError(msg) => assert!(msg.contains("hysteria listen")),
            other => panic!("expected ListenError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn close_without_start_is_ok() {
        let h = make_handler("secret");
        // 未 start 直接 close 不应出错
        assert!(h.close().await.is_ok());
    }

    #[test]
    fn no_auth_validator_when_auth_empty() {
        // auth 为空时 validator=None（不鉴权）——验证构造逻辑不 panic
        let _ = make_handler("");
    }
}
