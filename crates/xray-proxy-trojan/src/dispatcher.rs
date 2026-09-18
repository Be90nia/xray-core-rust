//! Trojan outbound → DialBridge 适配器（阶段 1 切片 1e）。
//!
//! Trojan 协议：拨号到 Trojan 服务器 → 在 TCP 流上写请求头（hex(sha224(password))
//! + CRLF + cmd + addr + port + CRLF）→ 返回连接，后续双向透传。
//!
//! ## 范围
//!
//! 当前实现：Trojan over **raw TCP**（与现有 trojan_proxy_e2e 测试模式一致）。
//! 生产场景（Trojan + TLS / WS）需在上层注入 TLS-wrapped 拨号闭包。
//!
//! [`DialBridge`]: xray_app_dispatcher::default::DialBridge
//! [`DialFn`]: xray_app_dispatcher::default::DialFn

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use xray_app_dispatcher::default::DialFn;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network as XrayNetwork;
use xray_common::net::port::Port;
use xray_transport::connection::Connection;
use xray_transport::dialer::{dial, StreamSettings};
use xray_transport::sockopt::SocketOptions;

use crate::config::MemoryAccount;
use crate::protocol::{write_request_header, Network as TrojanNetwork};

/// Trojan outbound 配置。
#[derive(Debug, Clone)]
pub struct TrojanOutboundConfig {
    /// Trojan 账户（含 hex(sha224(password))）。
    pub account: MemoryAccount,
    /// Trojan 服务器地址。
    pub server_address: Address,
    /// Trojan 服务器端口。
    pub server_port: Port,
    /// 可选 streamSettings（TLS/WS/gRPC/...）。None 走 raw TCP。
    pub stream_settings: Option<StreamSettings>,
    /// 用户 level（policy/stats 系统用）。
    pub level: u32,
    /// 用户 email（stats 系统标识用）。
    pub email: String,
}

impl TrojanOutboundConfig {
    /// 构造（raw TCP，无 streamSettings）。
    #[must_use]
    pub fn new(account: MemoryAccount, server_address: Address, server_port: Port) -> Self {
        Self {
            account,
            server_address,
            server_port,
            stream_settings: None,
            level: 0,
            email: String::new(),
        }
    }

    /// 指定 streamSettings（builder 风格）。
    #[must_use]
    pub fn with_stream_settings(mut self, settings: Option<StreamSettings>) -> Self {
        self.stream_settings = settings;
        self
    }

    /// 设置用户 level（builder 风格）。
    #[must_use]
    pub fn with_level(mut self, level: u32) -> Self {
        self.level = level;
        self
    }

    /// 设置用户 email（builder 风格）。
    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = email.into();
        self
    }

    /// 构造 Trojan 服务器 Destination（拨号用）。
    #[must_use]
    pub fn server_destination(&self) -> Destination {
        Destination::tcp(self.server_address.clone(), self.server_port)
    }
}

/// 构造 Trojan 的 DialFn 闭包。
///
/// 闭包捕获 `Arc<TrojanOutboundConfig>`，每次调用：
/// 1. dial_system 到 Trojan 服务器 → `Box<dyn Connection>`
/// 2. `write_request_header` 构造 Trojan 头（hex key + CRLF + cmd + addr/port + CRLF）
/// 3. `conn.write_all(&header)` 写入连接
/// 4. 返回连接（已是带 Trojan 头的 TCP）
///
/// # Panics
///
/// 不会 panic；任何错误以 `Err(String)` 返回。
pub fn make_dial_fn(config: Arc<TrojanOutboundConfig>) -> DialFn {
    Arc::new(move |dest: &Destination| {
        let config = Arc::clone(&config);
        let target_addr = dest.address().clone();
        let target_port = dest.port().value();
        let is_udp = dest.is_udp();
        Box::pin(async move {
            // 1. dial Trojan server：有 streamSettings 走 transport dialer（ws/grpc/...），否则裸 TCP。
            let server_dest = config.server_destination();
            let sockopt = config.stream_settings.as_ref().map(|s| s.socket_options()).unwrap_or_default();
            let mut conn: Box<dyn Connection> = xray_transport::retry::exponential_backoff(5, 100, || async {
                match &config.stream_settings {
                    Some(s) => dial(&server_dest, s, &sockopt)
                        .await
                        .map_err(|e| format!("trojan dial server ({}): {e}", s.protocol)),
                    None => xray_transport::system_dialer::dial_system(&server_dest, &sockopt)
                        .await
                        .map_err(|e| format!("trojan dial server (tcp): {e}")),
                }
            })
            .await
            .map_err(|e| format!("failed to find an available destination: {e}"))?;

            // 2. 构造 Trojan 请求头（UDP dest → command UDP，Go client.go 同分支）
            let network = if is_udp { TrojanNetwork::Udp } else { TrojanNetwork::Tcp };
            let mut header = Vec::with_capacity(128);
            write_request_header(
                &mut header,
                &config.account,
                network,
                &target_addr,
                target_port,
            )
            .map_err(|e| format!("trojan write header: {e}"))?;

            // 3. 写头到连接
            conn.write_all(&header)
                .await
                .map_err(|e| format!("trojan write header: {e}"))?;

            // 4. UDP：包一层 Trojan UDP 分帧（[addr][len][CRLF][payload] per packet，
            //    Go PacketWriter/PacketReader）。write 边界≈packet 边界。
            if is_udp {
                Ok(Box::new(TrojanUdpFramedConn::new(conn, target_addr, target_port)) as Box<dyn Connection>)
            } else {
                Ok(conn)
            }
        })
    })
}

/// Trojan UDP 分帧连接：把字节流 write 按 Trojan UDP 帧格式包装、read 剥帧。
///
/// 对应 Go `protocol.go::PacketWriter`/`PacketReader`。每帧：
struct TrojanUdpFramedConn {
    inner: Box<dyn Connection>,
    addr: Address,
    port: u16,
    rbuf: Vec<u8>,
    /// 待写完的帧（UDP 帧不可分，部分写时缓存剩余）
    wpending: Vec<u8>,
    wpos: usize,
}

impl TrojanUdpFramedConn {
    fn new(inner: Box<dyn Connection>, addr: Address, port: u16) -> Self {
        Self { inner, addr, port, rbuf: Vec::new(), wpending: Vec::new(), wpos: 0 }
    }
}

impl AsyncWrite for TrojanUdpFramedConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // 1. 先把 pending 帧写完（UDP 帧不可分）
        while this.wpos < this.wpending.len() {
            let n = std::task::ready!(
                Pin::new(&mut *this.inner).poll_write(cx, &this.wpending[this.wpos..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "trojan udp: frame write stalled")));
            }
            this.wpos += n;
        }
        // 2. 构造新帧并整帧写出
        let chunk = &buf[..buf.len().min(crate::protocol::MAX_LENGTH)];
        this.wpending = Vec::with_capacity(chunk.len() + 32);
        crate::protocol::write_udp_packet(&mut this.wpending, &this.addr, this.port, chunk)
            .map_err(|e| io::Error::other(format!("trojan udp: {e}")))?;
        this.wpos = 0;
        while this.wpos < this.wpending.len() {
            let n = std::task::ready!(
                Pin::new(&mut *this.inner).poll_write(cx, &this.wpending[this.wpos..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "trojan udp: frame write stalled")));
            }
            this.wpos += n;
        }
        Poll::Ready(Ok(chunk.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

impl AsyncRead for TrojanUdpFramedConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // 缓冲里有完整帧 → 剥帧返回 payload
            if !self.rbuf.is_empty() {
                match crate::protocol::parse_udp_packet_stream(&self.rbuf) {
                    Ok(Some((_addr, _port, payload, consumed))) => {
                        let n = payload.len().min(buf.remaining());
                        buf.put_slice(&payload[..n]);
                        // 剩余 payload（buf 满时截断的部分）保留在缓冲头部
                        let keep_from = consumed - payload.len() + n;
                        self.rbuf.drain(..keep_from);
                        return Poll::Ready(Ok(()));
                    }
                    Ok(None) => {} // 数据不足一帧，继续从 inner 读
                    // 致命帧错误（ATYP 非法 / payload 超限）→ 终止会话；
                    // 对齐入站 server.rs UDP relay fatal 分支与 Go PacketReader
                    Err(e) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("trojan udp: parse frame: {e}"),
                        )));
                    }
                }
            }
            // 缓冲不足一帧 → 从 inner 再读
            let mut tmp = [0u8; 8192];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut *self.inner).poll_read(cx, &mut rb)? {
                Poll::Ready(()) => {
                    let filled = rb.filled();
                    if filled.is_empty() {
                        return if self.rbuf.is_empty() {
                            Poll::Ready(Ok(())) // EOF
                        } else {
                            // 残留半帧：协议损坏，报错
                            Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "trojan udp: truncated frame")))
                        };
                    }
                    self.rbuf.extend_from_slice(filled);
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

impl Connection for TrojanUdpFramedConn {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.remote_addr()
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_common::net::address::Address;

    #[test]
    fn config_server_destination_roundtrip() {
        let account = MemoryAccount::new("test_password".to_string());
        let cfg = TrojanOutboundConfig::new(
            account,
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(443),
        );
        let dest = cfg.server_destination();
        assert!(dest.is_tcp());
        assert_eq!(dest.port(), Port::new(443));
    }

    #[test]
    fn make_dial_fn_returns_arc_closure() {
        let account = MemoryAccount::new("test_password".to_string());
        let cfg = Arc::new(TrojanOutboundConfig::new(
            account,
            Address::new_domain("example.com"),
            Port::new(443),
        ));
        let _dial = make_dial_fn(Arc::clone(&cfg));
        assert_eq!(Arc::strong_count(&cfg), 2);
    }

    /// UDP 分帧 roundtrip：duplex 模拟 Trojan 服务器，验证
    /// write → [addr][len][CRLF][payload] 帧、read → 剥帧还原。
    #[tokio::test]
    async fn udp_framed_conn_roundtrip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client_side, mut server_side) = tokio::io::duplex(4096);
        let conn = TrojanUdpFramedConn::new(
            Box::new(xray_transport::connection::DuplexConnection::new(client_side)),
            Address::from_ipv4_bytes([8, 8, 8, 8]),
            53,
        );
        let mut framed = conn;

        // write 一个 packet → wire 上应是合法 Trojan UDP 帧
        framed.write_all(b"query-payload").await.unwrap();
        framed.flush().await.unwrap();
        let mut wire = vec![0u8; 256];
        let n = server_side.read(&mut wire).await.unwrap();
        let wire = &wire[..n];
        let (addr, port, payload, consumed) = crate::protocol::parse_udp_packet(wire).unwrap();
        assert_eq!(addr, Address::from_ipv4_bytes([8, 8, 8, 8]));
        assert_eq!(port, 53);
        assert_eq!(payload, b"query-payload");
        assert_eq!(consumed, n, "整帧消费");

        // server 回一帧 → framed.read 剥帧得 payload
        let mut resp = Vec::new();
        crate::protocol::write_udp_packet(&mut resp, &addr, 53, b"answer-payload").unwrap();
        server_side.write_all(&resp).await.unwrap();
        let mut out = vec![0u8; 128];
        let rn = framed.read(&mut out).await.unwrap();
        assert_eq!(&out[..rn], b"answer-payload");
    }

    /// 致命帧（ATYP 非法）→ read 返回 Err 终止会话，而非静默吞错挂死
    /// （对齐入站 server.rs UDP relay fatal 分支；修复前坏帧滞留 rbuf 被无限重读）。
    #[tokio::test]
    async fn udp_framed_conn_fatal_frame_terminates() {
        let (client_side, mut server_side) = tokio::io::duplex(4096);
        let mut framed = TrojanUdpFramedConn::new(
            Box::new(xray_transport::connection::DuplexConnection::new(client_side)),
            Address::from_ipv4_bytes([8, 8, 8, 8]),
            53,
        );

        // 非法 ATYP 0xFF：parse_udp_packet_stream 判致命错误（InsufficientData 才算不足）
        server_side.write_all(&[0xFF]).await.unwrap();

        let mut out = [0u8; 16];
        let result = framed.read(&mut out).await;
        assert!(
            result.is_err(),
            "fatal frame must terminate the session, got {result:?}"
        );
    }
}
