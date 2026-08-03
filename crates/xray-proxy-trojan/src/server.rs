//! Trojan 入站处理器（server），对应 Go `proxy/trojan/server.go`。
//!
//! ## 切片2（当前）
//!
//! 实现 [`TrojanServer`] impl `InboundHandler` + [`trojan_server_handshake`] 端到端验证。
//! Trojan 协议无握手响应——客户端发完 header 后直接发 payload，服务端验证 hash 后
//! 直接开始转发（切片2 仅验证 header 解析 + 用户校验，不转发）。
//!
//! ## 切片3 待实现
//!
//! - fallback（不合法用户重定向到 fallback dest）
//! - dispatch to outbound handler
//! - UDP ASSOCIATE
//! - TLS 包装层

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{info, warn};
use xray_app_dispatcher::default::SimpleOhm;
use xray_app_dispatcher::OutboundHandlerManager;
use xray_buf::io::{new_reader, new_writer};
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network as CommonNetwork;
use xray_common::net::port::Port;
use xray_features::inbound::{InboundError, InboundHandler};

use crate::fallback::FallbackPolicy;
use crate::protocol::{addr_type, Network, COMMAND_TCP, CRLF};
use crate::validator::{MemoryUser, Validator};
use xray_transport::link::Link;

/// 包装流，记录所有读取字节用于 fallback 回放。
struct RecordingStream<S> {
    inner: S,
    buf: Vec<u8>,
}

impl<S: AsyncRead + Unpin> AsyncRead for RecordingStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, dst: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = dst.filled().len();
        let r = Pin::new(&mut this.inner).poll_read(cx, dst);
        let after = dst.filled().len();
        if after > before {
            this.buf.extend_from_slice(&dst.filled()[before..after]);
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RecordingStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Trojan 入站服务器。
///
/// `listener` 用 `tokio::sync::Mutex`（可跨 await 点持锁），与 socks 切片2 模式一致。
pub struct TrojanServer {
    /// Handler 标签（用于路由匹配）。
    tag: String,
    /// 用户验证器（共享）。
    validator: Arc<Validator>,
    /// Fallback 决策树（可选）。
    fallbacks: Option<Arc<FallbackPolicy>>,
    /// 监听器 + accept loop 任务句柄。close 时 abort 任务取消 accept().
    slot: Mutex<Option<(Arc<TcpListener>, JoinHandle<()>)>>,
}

impl TrojanServer {
    /// 创建新 Trojan 服务器。
    #[must_use]
    pub fn new(tag: impl Into<String>, validator: Arc<Validator>) -> Self {
        Self {
            tag: tag.into(),
            validator,
            fallbacks: None,
            slot: Mutex::new(None),
        }
    }

    /// 设置 fallback 决策树。
    #[must_use]
    pub fn with_fallbacks(mut self, fallbacks: Arc<FallbackPolicy>) -> Self {
        self.fallbacks = Some(fallbacks);
        self
    }

    /// Handler 标签。
    #[must_use]
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// 用户验证器引用（用于 `add_user`/`remove_user`）。
    #[must_use]
    pub fn validator(&self) -> &Arc<Validator> {
        &self.validator
    }
}

#[async_trait::async_trait]
impl InboundHandler for TrojanServer {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn start(&self) -> std::result::Result<(), InboundError> {
        let listener = Arc::new(
            TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|e| InboundError::ListenError(format!("bind failed: {e}")))?,
        );
        let bound = listener
            .local_addr()
            .map_err(|e| InboundError::ListenError(format!("local_addr: {e}")))?;
        info!(tag = %self.tag, addr = %bound, "Trojan server started");

        let tag = self.tag.clone();
        let validator = self.validator.clone();
        let fallbacks = self.fallbacks.clone();
        let listener_clone = Arc::clone(&listener);
        let handle = tokio::spawn(async move {
            loop {
                match listener_clone.accept().await {
                    Ok((stream, peer)) => {
                        let tag = tag.clone();
                        let validator = validator.clone();
                        let fallbacks = fallbacks.clone();
                        tokio::spawn(async move {
                            let mut recorder = RecordingStream {
                                inner: stream,
                                buf: Vec::with_capacity(256),
                            };
                            match trojan_server_handshake(&mut recorder, &validator).await {
                                Ok((network, addr, port, user)) => {
                                    info!(
                                        tag = %tag,
                                        peer = %peer,
                                        network = ?network,
                                        dest_addr = ?addr,
                                        dest_port = port,
                                        user = %user.email,
                                        "Trojan handshake succeeded"
                                    );
                                }
                                Err(e) => {
                                    warn!(tag = %tag, peer = %peer, error = %e, "Trojan handshake failed");
                                    if let Some(fb_policy) = &fallbacks {
                                        // ponytail: SNI/ALPN/path 来自 TLS 层，当前未接线，用空字符串通配匹配
                                        if let Some(fb) = fb_policy.decide("", "", "") {
                                            if let Err(e) = do_fallback(recorder, &fb.dest).await {
                                                warn!(tag = %tag, peer = %peer, error = %e, "fallback failed");
                                            }
                                        }
                                    }
                                }
                            }
                        });
                    }
                    Err(e) => {
                        warn!(tag = %tag, error = %e, "accept failed");
                        break;
                    }
                }
            }
        });

        *self.slot.lock().await = Some((listener, handle));
        Ok(())
    }

    async fn close(&self) -> std::result::Result<(), InboundError> {
        if let Some((_listener, handle)) = self.slot.lock().await.take() {
            handle.abort();
            info!(tag = %self.tag, "Trojan server closed");
        }
        Ok(())
    }

    fn port(&self) -> u16 {
        // 同步方法无法读 async Mutex; 返回 0
        0
    }
}

/// Trojan 服务端握手——读取并校验 Trojan 请求头。
///
/// 流程：
/// 1. 读 56 字节 hex key
/// 2. `Validator::get_by_key` 校验用户
/// 3. 读 2 字节 CRLF
/// 4. 读 1 字节 CMD (`Network`)
/// 5. 读 addr+port（SOCKS5 格式: ATYP + addr + 2 字节 BE port）
/// 6. 读 2 字节 CRLF
///
/// 验证成功返回 `(network, addr, port, user)`，失败返回 `TrojanError`。
/// Trojan 协议无握手响应——调用方验证通过后直接开始双向转发。
///
/// # Errors
///
/// - [`TrojanError::ReadUserHash`]: 读 hex key 失败
/// - [`TrojanError::UserNotFound`]: 用户 hash 不在 validator 中
/// - [`TrojanError::ReadCrlf`]: CRLF 不匹配
/// - [`TrojanError::ReadCommand`]: CMD 非法
/// - [`TrojanError::ReadAddressPort`]: addr/port 解析失败
pub async fn trojan_server_handshake<S>(
    stream: &mut S,
    validator: &Validator,
) -> crate::Result<(Network, Address, u16, MemoryUser)>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
{
    // 1. 读 56 字节 hex key
    let mut key_buf = [0u8; 56];
    stream
        .read_exact(&mut key_buf)
        .await
        .map_err(|e| crate::TrojanError::ReadUserHash(format!("read key: {e}")))?;

    // 2. 校验 key via Validator
    let user = validator
        .get_by_key(&key_buf)
        .ok_or_else(|| crate::TrojanError::UserNotFound)?;

    // 3. 读 CRLF
    let mut crlf = [0u8; 2];
    stream
        .read_exact(&mut crlf)
        .await
        .map_err(|e| crate::TrojanError::ReadCrlf(format!("read header crlf: {e}")))?;
    if crlf != CRLF {
        return Err(crate::TrojanError::ReadCrlf(format!(
            "expected CRLF, got {crlf:?}"
        )));
    }

    // 4. 读 1 字节 CMD
    let mut cmd_buf = [0u8; 1];
    stream
        .read_exact(&mut cmd_buf)
        .await
        .map_err(|e| crate::TrojanError::ReadCommand(format!("read cmd: {e}")))?;
    let network = Network::from_command(cmd_buf[0]);

    // 5. 读 addr+port（先读 ATYP 确定后续长度）
    let mut atyp_buf = [0u8; 1];
    stream
        .read_exact(&mut atyp_buf)
        .await
        .map_err(|e| crate::TrojanError::ReadAddressPort(format!("read atyp: {e}")))?;
    let atyp = atyp_buf[0];

    // 根据 ATYP 读取剩余 addr+port 字节
    let (addr, port) = match atyp {
        addr_type::IPV4 => {
            let mut buf = [0u8; 6]; // 4 IP + 2 port
            stream
                .read_exact(&mut buf)
                .await
                .map_err(|e| crate::TrojanError::ReadAddressPort(format!("read ipv4+port: {e}")))?;
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&buf[0..4]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            (Address::IPv4(std::net::Ipv4Addr::from(ip)), port)
        }
        addr_type::DOMAIN => {
            let mut len_buf = [0u8; 1];
            stream
                .read_exact(&mut len_buf)
                .await
                .map_err(|e| crate::TrojanError::ReadAddressPort(format!("read domain len: {e}")))?;
            let len = len_buf[0] as usize;
            let mut buf = vec![0u8; len + 2]; // domain + 2 port
            stream
                .read_exact(&mut buf)
                .await
                .map_err(|e| crate::TrojanError::ReadAddressPort(format!("read domain+port: {e}")))?;
            let domain = String::from_utf8(buf[0..len].to_vec())
                .map_err(|_| crate::TrojanError::InvalidRemoteAddress)?;
            let port = u16::from_be_bytes([buf[len], buf[len + 1]]);
            (Address::Domain(domain), port)
        }
        addr_type::IPV6 => {
            let mut buf = [0u8; 18]; // 16 IP + 2 port
            stream
                .read_exact(&mut buf)
                .await
                .map_err(|e| crate::TrojanError::ReadAddressPort(format!("read ipv6+port: {e}")))?;
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[0..16]);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            (Address::IPv6(std::net::Ipv6Addr::from(ip)), port)
        }
        _ => {
            return Err(crate::TrojanError::ReadAddressPort(format!(
                "unknown atyp: {atyp:#x}"
            )));
        }
    };

    // 6. 读结尾 CRLF
    stream
        .read_exact(&mut crlf)
        .await
        .map_err(|e| crate::TrojanError::ReadCrlf(format!("read tail crlf: {e}")))?;
    if crlf != CRLF {
        return Err(crate::TrojanError::ReadCrlf(format!(
            "expected tail CRLF, got {crlf:?}"
        )));
    }

    Ok((network, addr, port, user))
}

// ============================================================================
// do_fallback: handshake failure redirect
// ============================================================================

/// Replay recorded bytes + pipe remaining stream to fallback destination.
///
/// Corresponds to Go `proxy/trojan/server.go` fallback dial + `io.Copy` bridge.
async fn do_fallback<S>(recorder: RecordingStream<S>, dest: &str) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut fallback = tokio::net::TcpStream::connect(dest).await?;
    if !recorder.buf.is_empty() {
        fallback.write_all(&recorder.buf).await?;
    }
    let (mut ori_r, mut ori_w) = tokio::io::split(recorder.inner);
    let (mut fb_r, mut fb_w) = tokio::io::split(fallback);
    tokio::try_join!(
        async { tokio::io::copy(&mut ori_r, &mut fb_w).await },
        async { tokio::io::copy(&mut fb_r, &mut ori_w).await },
    )?;
    Ok(())
}

// ============================================================================
// serve_trojan
// ============================================================================

/// Trojan inbound entry point (aligns with `xray_core::inbound::serve_socks5`).
///
/// # Parameters
/// - `listener`: bound TCP listener
/// - `ohm`: outbound handler manager (must have default handler)
/// - `users`: user map, key = `MemoryUser::key_hash()`
/// - `fallbacks`: optional fallback policy for handshake-failure redirect
///
/// # Errors
/// Only `listener.local_addr()` failure returns error; accept/handshake/dispatch errors log and continue.
pub async fn serve_trojan(
    listener: TcpListener,
    ohm: Arc<SimpleOhm>,
    users: HashMap<String, MemoryUser>,
    fallbacks: Option<Arc<FallbackPolicy>>,
    tls: Option<Arc<xray_transport::TlsAcceptor>>,
) -> std::io::Result<()> {
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;

    let validator = Arc::new(Validator::new());
    for (_, user) in users {
        if let Err(e) = validator.add(user) {
            warn!(error = %e, "skip duplicate user during serve_trojan init");
        }
    }

    info!(
        addr = %listener.local_addr()?,
        users = validator.get_count(),
        "trojan inbound listening"
    );

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "trojan accept failed");
                continue;
            }
        };

        let handler = Arc::clone(&handler);
        let validator = Arc::clone(&validator);
        let fb_policy = fallbacks.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            if let Some(acc) = tls {
                match acc.accept(stream).await {
                    Ok(tls_stream) => {
                        let recorder = RecordingStream {
                            inner: tls_stream,
                            buf: Vec::with_capacity(256),
                        };
                        handle_trojan_connection(recorder, validator, handler, fb_policy, peer).await;
                    }
                    Err(e) => warn!(error = %e, "trojan TLS accept failed"),
                }
            } else {
                let recorder = RecordingStream {
                    inner: stream,
                    buf: Vec::with_capacity(256),
                };
                handle_trojan_connection(recorder, validator, handler, fb_policy, peer).await;
            }
        });
    }
}

/// 处理单个 Trojan 连接：handshake → dispatch / fallback。
async fn handle_trojan_connection<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut recorder: RecordingStream<S>,
    validator: Arc<Validator>,
    handler: Arc<dyn xray_app_dispatcher::DispatchHandler>,
    fb_policy: Option<Arc<FallbackPolicy>>,
    peer: std::net::SocketAddr,
) {
    match trojan_server_handshake(&mut recorder, &validator).await {
        Ok((network, addr, port, user)) => {
            if matches!(network, Network::Udp) {
                warn!(peer = %peer, "trojan UDP not yet supported");
                return;
            }
            let dest = Destination::new(addr, Port::new(port), CommonNetwork::TCP);
            let (read_half, write_half) = tokio::io::split(recorder.inner);
            let link = Link::new(new_reader(read_half), new_writer(write_half));
            info!(peer = %peer, user = %user.email, dest = %dest, "trojan dispatching");
            let _ = handler.dispatch(&dest, link).await;
        }
        Err(e) => {
            warn!(peer = %peer, error = %e, "trojan handshake failed");
            if let Some(fb_policy) = &fb_policy {
                // ponytail: SNI/ALPN/path from TLS layer not wired yet; use wildcard
                if let Some(fb) = fb_policy.decide("", "", "") {
                    if let Err(e) = do_fallback(recorder, &fb.dest).await {
                        warn!(peer = %peer, error = %e, "fallback failed");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{hex_sha224, MemoryAccount};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use xray_app_dispatcher::default::{DialBridge, SimpleOhm};
    use xray_app_dispatcher::DispatchHandler;
    use xray_common::net::address::Address;
    use xray_proxy_freedom::make_freedom_dial_fn;
    use crate::protocol::{write_request_header, Network as TrojanNetwork};

    fn make_validator_with_user(password: &str) -> Arc<Validator> {
        let validator = Arc::new(Validator::new());
        let account = MemoryAccount::new(password.to_string());
        let user = MemoryUser::new("user@example.com", 0, account);
        validator.add(user).unwrap();
        validator
    }

    #[tokio::test]
    async fn handshake_valid_user_ipv4_succeeds() {
        let validator = make_validator_with_user("password");
        let server = TrojanServer::new("test", validator.clone());
        server.start().await.unwrap();

        // 客户端构造完整 Trojan header
        let key = hex_sha224("password");
        let mut header = Vec::new();
        header.extend_from_slice(&key); // 56 字节 hex
        header.extend_from_slice(&CRLF);
        header.push(COMMAND_TCP);
        header.push(addr_type::IPV4);
        header.extend_from_slice(&[127, 0, 0, 1]); // 127.0.0.1
        header.extend_from_slice(&80u16.to_be_bytes());
        header.extend_from_slice(&CRLF);

        // 连接并发送 header
        // 注意：TrojanServer start 绑定到随机端口，但我们不知道具体端口
        // 直接测试 trojan_server_handshake 函数
        let mut buf = header.clone();
        buf.extend_from_slice(b"payload data");
        let mut cursor = std::io::Cursor::new(buf);
        let result = trojan_server_handshake(&mut cursor, &validator).await;
        assert!(result.is_ok());
        let (network, addr, port, user) = result.unwrap();
        assert_eq!(network, Network::Tcp);
        match addr {
            Address::IPv4(v4) => assert_eq!(v4.octets(), [127, 0, 0, 1]),
            _ => panic!("expected IPv4"),
        }
        assert_eq!(port, 80);
        assert_eq!(user.email, "user@example.com");

        server.close().await.unwrap();
    }

    #[tokio::test]
    async fn handshake_invalid_user_fails() {
        let validator = make_validator_with_user("password");
        let bad_key = hex_sha224("wrong-password");
        let mut header = Vec::new();
        header.extend_from_slice(&bad_key);
        header.extend_from_slice(&CRLF);
        header.push(COMMAND_TCP);
        header.push(addr_type::IPV4);
        header.extend_from_slice(&[127, 0, 0, 1]);
        header.extend_from_slice(&80u16.to_be_bytes());
        header.extend_from_slice(&CRLF);

        let mut cursor = std::io::Cursor::new(header);
        let result = trojan_server_handshake(&mut cursor, &validator).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handshake_valid_user_domain_succeeds() {
        let validator = make_validator_with_user("password");
        let key = hex_sha224("password");
        let mut header = Vec::new();
        header.extend_from_slice(&key);
        header.extend_from_slice(&CRLF);
        header.push(COMMAND_TCP);
        header.push(addr_type::DOMAIN);
        let domain = b"example.com";
        header.push(domain.len() as u8);
        header.extend_from_slice(domain);
        header.extend_from_slice(&443u16.to_be_bytes());
        header.extend_from_slice(&CRLF);

        let mut cursor = std::io::Cursor::new(header);
        let result = trojan_server_handshake(&mut cursor, &validator).await;
        assert!(result.is_ok());
        let (_, addr, port, _) = result.unwrap();
        match addr {
            Address::Domain(d) => assert_eq!(d, "example.com"),
            _ => panic!("expected Domain"),
        }
        assert_eq!(port, 443);
    }

    #[tokio::test]
    async fn handshake_valid_user_ipv6_succeeds() {
        let validator = make_validator_with_user("password");
        let key = hex_sha224("password");
        let mut header = Vec::new();
        header.extend_from_slice(&key);
        header.extend_from_slice(&CRLF);
        header.push(COMMAND_TCP);
        header.push(addr_type::IPV6);
        let v6 = std::net::Ipv6Addr::LOCALHOST;
        header.extend_from_slice(&v6.octets());
        header.extend_from_slice(&443u16.to_be_bytes());
        header.extend_from_slice(&CRLF);

        let mut cursor = std::io::Cursor::new(header);
        let result = trojan_server_handshake(&mut cursor, &validator).await;
        assert!(result.is_ok());
        let (_, addr, _, _) = result.unwrap();
        match addr {
            Address::IPv6(v6) => assert_eq!(v6, std::net::Ipv6Addr::LOCALHOST),
            _ => panic!("expected IPv6"),
        }
    }

    #[tokio::test]
    async fn handshake_truncated_key_fails() {
        let validator = make_validator_with_user("password");
        // 只提供 10 字节（不够 56）
        let short = vec![0u8; 10];
        let mut cursor = std::io::Cursor::new(short);
        let result = trojan_server_handshake(&mut cursor, &validator).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handshake_truncated_header_after_valid_key_fails() {
        let validator = make_validator_with_user("password");
        let key = hex_sha224("password");
        let mut header = Vec::new();
        header.extend_from_slice(&key);
        // 缺少 CRLF + CMD + addr
        let mut cursor = std::io::Cursor::new(header);
        let result = trojan_server_handshake(&mut cursor, &validator).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handshake_invalid_crlf_after_key_fails() {
        let validator = make_validator_with_user("password");
        let key = hex_sha224("password");
        let mut header = Vec::new();
        header.extend_from_slice(&key);
        header.extend_from_slice(b"XX"); // 不是 CRLF
        let mut cursor = std::io::Cursor::new(header);
        let result = trojan_server_handshake(&mut cursor, &validator).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn handshake_unknown_atyp_fails() {
        let validator = make_validator_with_user("password");
        let key = hex_sha224("password");
        let mut header = Vec::new();
        header.extend_from_slice(&key);
        header.extend_from_slice(&CRLF);
        header.push(COMMAND_TCP);
        header.push(0x05); // 未知 ATYP
        let mut cursor = std::io::Cursor::new(header);
        let result = trojan_server_handshake(&mut cursor, &validator).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn start_close_releases_listener_port() {
        // 回归测试 68n: close 后 accept loop abort，端口释放
        let validator = make_validator_with_user("password");
        let server = TrojanServer::new("test-close", validator);
        server.start().await.unwrap();
        let port = server
            .slot
            .lock()
            .await
            .as_ref()
            .and_then(|(l, _)| l.local_addr().ok())
            .map(|a| a.port())
            .unwrap_or(0);
        assert!(port > 0, "server should bind to a port");

        server.close().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let addr = format!("127.0.0.1:{port}");
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            TcpStream::connect(&addr),
        )
        .await;
        match result {
            Ok(Ok(_)) => panic!("listener should be closed after close()"),
            Ok(Err(_)) | Err(_) => {}
        }
    }

    /// 端到端：trojan client → trojan inbound (serve_trojan) → freedom outbound → echo server。
    ///
    /// 与 socks5 e2e 同模式：验证 accept → handshake → dispatch → echo 回环。
    #[tokio::test]
    async fn serve_trojan_dispatches_to_echo_via_freedom() {
        // 1. 起 echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        // 2. 配置 dispatcher：freedom outbound → SimpleOhm default
        let ohm = Arc::new(SimpleOhm::new());
        let dial_fn = make_freedom_dial_fn();
        let bridge = Arc::new(DialBridge::new("freedom", dial_fn))
            as Arc<dyn DispatchHandler>;
        ohm.set_default(bridge);

        // 3. 构造用户表：password → MemoryUser，HashMap key = user.key_hash()
        let account = MemoryAccount::new("password");
        let user = MemoryUser::new("echo-test@example.com", 0, account.clone());
        let mut users = HashMap::new();
        users.insert(user.key_hash(), user);

        // 4. 起 trojan inbound
        let trojan_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let trojan_addr = trojan_listener.local_addr().unwrap();
        let ohm_clone = Arc::clone(&ohm);
        tokio::spawn(async move {
            let _ = serve_trojan(trojan_listener, ohm_clone, users, None, None).await;
        });

        // 5. trojan client：构造 header + payload
        let mut client = TcpStream::connect(trojan_addr).await.unwrap();
        let dest_addr = Address::IPv4(std::net::Ipv4Addr::new(127, 0, 0, 1));
        let mut header = Vec::new();
        write_request_header(
            &mut header,
            &account,
            TrojanNetwork::Tcp,
            &dest_addr,
            echo_addr.port(),
        );
        let payload = b"hello trojan proxy!";
        header.extend_from_slice(payload);
        client.write_all(&header).await.unwrap();

        // 6. 读 echo（跳过可能的 0 字节，读到 payload 长度）
        let mut got = vec![0u8; payload.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, payload, "should receive echo through trojan proxy");
    }
}