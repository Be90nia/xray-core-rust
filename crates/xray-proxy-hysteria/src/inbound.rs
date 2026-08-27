//! Hysteria 入站处理器，对应 Go `proxy/hysteria/server.go`。
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
//! 5. `on_new_conn` 内部 spawn 异步任务：
//!    - TCP：读取 TCP 请求帧（目标地址）→ 写 TCP 响应 → 调用 dispatcher
//!    - UDP：由 QUIC datagram 通道处理（InterConn）
//!
//! ## 认证
//!
//! [`StaticAuthValidator`] 做简单字符串匹配（config.auth == 客户端 auth 头），
//! [`MultiUserValidator`] 支持多用户动态增删，对应 Go `account.Validator`。

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

use crate::config::{HysteriaConfig, HysteriaInboundConfig, MultiUserValidator};
use crate::error::Result;

/// TCP 流量调度器 trait（对应 Go `routing.Dispatcher`）。
///
/// 当 inbound 接收到客户端请求后，通过此 trait 将流量转发到目标。
/// 外部注入实现（如 xray-core 的 router），inbound 不关心具体调度逻辑。
pub trait TcpDispatcher: Send + Sync + std::fmt::Debug {
    /// 调度一个 TCP 连接到目标地址。
    ///
    /// # 参数
    /// - `dest_addr`：目标地址字符串（如 `example.com:443`）
    /// - `stream`：已建立的 QUIC stream 连接
    fn dispatch_tcp(
        &self,
        dest_addr: &str,
        stream: Arc<InterStreamConn>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send + '_>>;
}
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
///
/// 支持两种构造模式：
/// - [`new`](Self::new)：客户端配置模式（单 auth token）
/// - [`with_inbound_config`](Self::with_inbound_config)：服务端配置模式（多用户 + dispatcher）
pub struct HysteriaInboundHandler {
    tag: String,
    config: HysteriaConfig,
    bind_addr: SocketAddr,
    factory: Arc<dyn HysteriaListenerFactory>,
    /// 可选的服务端入站配置（多用户、UDP 超时等）。
    inbound_config: Option<HysteriaInboundConfig>,
    /// 可选的多用户认证器（inbound_config 模式下使用）。
    multi_validator: Option<Arc<MultiUserValidator>>,
    /// 可选的 TCP 调度器（inbound_config 模式下使用）。
    dispatcher: Option<Arc<dyn TcpDispatcher>>,
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
    /// 构造入站 Handler（客户端配置模式，单 auth token）。
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
            inbound_config: None,
            multi_validator: None,
            dispatcher: None,
            slot: Mutex::new(None),
        })
    }

    /// 注入 TCP dispatcher（builder 风格，使 on_new_conn 真实转发 TCP 流）。
    #[must_use]
    pub fn with_dispatcher(mut self, dispatcher: Option<Arc<dyn TcpDispatcher>>) -> Self {
        self.dispatcher = dispatcher;
        self
    }

    /// 构造入站 Handler（服务端配置模式，多用户 + dispatcher）。
    ///
    /// 对应 Go `NewServer(ctx, config)`。
    ///
    /// # 参数
    /// - `tag`：handler 标签
    /// - `inbound_config`：服务端入站配置（用户列表、UDP 超时等）
    /// - `factory`：QUIC listener 工厂
    /// - `dispatcher`：TCP 流量调度器（None 则仅 log）
    ///
    /// # Errors
    /// 配置无效时返回 [`InvalidConfig`](crate::HysteriaProxyError::InvalidConfig)。
    pub fn with_inbound_config(
        tag: impl Into<String>,
        inbound_config: HysteriaInboundConfig,
        factory: Arc<dyn HysteriaListenerFactory>,
        dispatcher: Option<Arc<dyn TcpDispatcher>>,
    ) -> Result<Self> {
        inbound_config.validate()?;
        let bind_addr_str = inbound_config.bind_addr.clone();
        let bind_addr: SocketAddr = bind_addr_str.parse().map_err(|e| {
            crate::error::HysteriaProxyError::InvalidConfig(format!(
                "invalid bind_addr '{}': {e}", bind_addr_str
            ))
        })?;
        // 构造内部 HysteriaConfig（复用现有 build_proto_config 逻辑）
        let config = HysteriaConfig::new(&bind_addr_str, "")
            .with_server_name(&inbound_config.server_name)
            .with_alpn(inbound_config.alpn.clone())
            .with_udp_idle_timeout(inbound_config.udp_idle_timeout_secs);
        // 构造多用户验证器
        let validator = Arc::new(MultiUserValidator::from_users(&inbound_config.users));
        Ok(Self {
            tag: tag.into(),
            config,
            bind_addr,
            factory,
            inbound_config: Some(inbound_config),
            multi_validator: Some(validator),
            dispatcher,
            slot: Mutex::new(None),
        })
    }

    /// 配置引用。
    #[must_use]
    pub fn config(&self) -> &HysteriaConfig {
        &self.config
    }

    /// 入站配置引用（服务端模式）。
    #[must_use]
    pub fn inbound_config(&self) -> Option<&HysteriaInboundConfig> {
        self.inbound_config.as_ref()
    }

    /// 多用户验证器引用。
    #[must_use]
    pub fn multi_validator(&self) -> Option<&Arc<MultiUserValidator>> {
        self.multi_validator.as_ref()
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
        let quic_params = Arc::clone(&self.config.quic_params);
        let masq = MasqType::from_config(&proto_config)
            .map_err(|e| InboundError::ListenError(format!("masq config: {e}")))?;
        let validator: Option<Arc<dyn AuthValidator>> = if let Some(ref mv) = self.multi_validator {
            Some(Arc::clone(mv) as Arc<dyn AuthValidator>)
        } else if self.config.auth.is_empty() {
            None
        } else {
            Some(Arc::new(StaticAuthValidator::new(self.config.auth.clone())))
        };

        // on_new_conn 回调：每个新 QUIC stream 触发
        // 若有 dispatcher 则 spawn 异步任务处理 TCP 请求帧，否则仅 log
        let dispatcher = self.dispatcher.clone();
        let on_new_conn: Arc<dyn Fn(Arc<InterStreamConn>) + Send + Sync> =
            Arc::new(move |stream: Arc<InterStreamConn>| {
                let remote = stream.remote_addr();
                let local = stream.local_addr();
                tracing::debug!(
                    local = %local,
                    remote = %remote,
                    "hysteria inbound new stream"
                );
                // 若有 dispatcher，spawn TCP 处理任务
                if let Some(ref disp) = dispatcher {
                    let disp = Arc::clone(disp);
                    let stream_clone = Arc::clone(&stream);
                    tokio::spawn(async move {
                        if let Err(e) = handle_tcp_stream(stream_clone, disp).await {
                            tracing::warn!(error = %e, "hysteria inbound tcp stream error");
                        }
                    });
                }
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

/// 处理入站 TCP stream：读取请求帧，写响应，调用 dispatcher。
///
/// 对应 Go `Server.Process` 的 TCP 分支。
async fn handle_tcp_stream(
    stream: Arc<InterStreamConn>,
    dispatcher: Arc<dyn TcpDispatcher>,
) -> std::io::Result<()> {
    use crate::protocol::{read_tcp_request, write_tcp_response};

    // 读取 TCP 请求帧（目标地址 + padding）
    // InterStreamConn 是 async read，需要逐步读取到 buffer 再解析
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    // 读取足够数据解析 TCP 请求帧（至少 varint + addr + varint + padding）
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "stream closed before tcp request",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        // 尝试解析 TCP 请求帧
        let mut cursor = std::io::Cursor::new(&buf);
        match read_tcp_request(&mut cursor) {
            Ok(addr) => {
                tracing::info!(
                    remote = %stream.remote_addr(),
                    dest = %addr,
                    "hysteria inbound tcp request"
                );
                // 写 TCP 响应（ok=true, 无消息）
                let mut resp_buf = Vec::new();
                write_tcp_response(&mut resp_buf, true, "")?;
                stream.write(&resp_buf).await?;
                // 调度到 dispatcher
                return dispatcher.dispatch_tcp(&addr, stream).await;
            }
            Err(crate::error::HysteriaProxyError::ProtocolParse(_)) => {
                // 数据可能不完整，继续读
                if buf.len() > 8192 {
                    // 超过合理大小仍未解析成功，放弃
                    let mut err_resp = Vec::new();
                    let _ = write_tcp_response(&mut err_resp, false, "request too large");
                    let _ = stream.write(&err_resp).await;
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "tcp request frame too large",
                    ));
                }
                continue;
            }
            Err(e) => {
                // 其他错误（地址非法等），写拒绝响应
                let mut err_resp = Vec::new();
                let _ = write_tcp_response(&mut err_resp, false, "invalid request");
                let _ = stream.write(&err_resp).await;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("tcp request parse error: {e}"),
                ));
            }
        }
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
