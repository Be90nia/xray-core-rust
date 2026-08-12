//! Shadowsocks outbound → DialBridge 适配器。
//!
//! 把 SS 协议接入 dispatcher 的 [`DialBridge`]：提供
//! [`make_ss_dial_fn`] 闭包，内部拨号到 SS 服务器 →
//! 写 SS 加密首帧（addr+port）→ 返回 SS 加密连接。
//!
//! ## Connection wrapper
//!
//! [`SSStream`] 不直接实现 `AsyncRead`/`AsyncWrite`（SS chunk 天然分帧），
//! 因此 [`SsConnection`] 包装 `SSStream<TcpStream>`，用
//! `write_chunk`/`read_chunk` 循环桥接到 `AsyncRead`/`AsyncWrite` trait。
//!
//! [`DialBridge`]: xray_app_dispatcher::default::DialBridge
//! [`DialFn`]: xray_app_dispatcher::default::DialFn

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use xray_app_dispatcher::default::DialFn;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_transport::connection::Connection;

use crate::client::Client;
use crate::config::MemoryAccount;
use crate::stream::SSStream;

/// SS duplex 缓冲（与 hysteria/tuic 一致：64 KiB）。
const DUPLEX_BUF_SIZE: usize = 64 * 1024;

/// SS 加密流 → Connection trait 实现。
///
/// 桥接 `SSStream<TcpStream>` 的 `write_chunk`/`read_chunk` 到
/// `AsyncRead`/`AsyncWrite`：spawn 一个 [`pump_ss_stream`] task，在 SS 加密
/// chunk 流与 `tokio::io::duplex` 明文 IO 之间双向搬运。`SsConnection` 自身只
/// 持有 duplex 客户端半 + pump task 句柄，trait 方法全部委托给 duplex。
///
/// `_pump` 字段保证桥接 task 生命周期与连接一致——drop 时自动 abort。
pub struct SsConnection {
    inner: DuplexStream,
    _pump: JoinHandle<()>,
}

impl SsConnection {
    /// 从已写完首帧（addr+port）的 `SSStream` 构造。
    /// 首帧由 `Client::dial_target` 写入，本包装只负责 body 加密透传。
    #[must_use]
    pub fn new(stream: SSStream<TcpStream>) -> Self {
        let (client_io, server_io) = tokio::io::duplex(DUPLEX_BUF_SIZE);
        let pump = tokio::spawn(pump_ss_stream(stream, server_io));
        Self {
            inner: client_io,
            _pump: pump,
        }
    }
}

impl AsyncRead for SsConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for SsConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Connection for SsConnection {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
}

/// 双向 pump：在 `SSStream`（加密 chunk 流）与 `DuplexStream`（明文 IO）之间桥接。
///
/// - up：read duplex（8KB）→ `write_chunk` → flush（明文 → 密文 chunk）
/// - down：`read_chunk` → write_all duplex（密文 chunk → 明文）
///
/// `SSStream` 的 `write_chunk`/`read_chunk` 共享单一 nonce 计数器且均需 `&mut self`，
/// 不可并发持有（也无法像 hysteria 那样 `split` 成独立读写半）。故采用 `select!` 串行
/// 推进：down 方向用 `get_mut().readable()`（cancel-safe）作就绪信号，一旦可读即在
/// handler 内完整执行 `read_chunk`（不被 `select!` 取消，避免 nonce 在 size/payload
/// 分帧中途推进导致流状态损坏）；up 方向用 cancel-safe 的 `AsyncReadExt::read`。
async fn pump_ss_stream(mut stream: SSStream<TcpStream>, server_io: DuplexStream) {
    let (mut rd, mut wr) = tokio::io::split(server_io);
    let mut up_buf = vec![0u8; 8 * 1024];
    loop {
        tokio::select! {
            // up: 明文 duplex 读 → 加密 chunk 写到 SS wire
            n = rd.read(&mut up_buf) => {
                match n {
                    Ok(0) => {
                        let _ = stream.shutdown().await;
                        break;
                    }
                    Ok(n) => {
                        if stream.write_chunk(&up_buf[..n]).await.is_err() {
                            break;
                        }
                        if stream.flush().await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!("ss pump up read error: {e}");
                        break;
                    }
                }
            }
            // down: 等 SS 底层 socket 可读（cancel-safe，不借 read_chunk 的 &mut stream）
            _ = stream.get_mut().readable() => {
                // socket 可读 → handler 内独占 stream 完整执行一次 read_chunk（不被取消）
                match stream.read_chunk().await {
                    Ok(Some(plaintext)) => {
                        if wr.write_all(&plaintext).await.is_err() {
                            break;
                        }
                        let _ = wr.flush().await;
                    }
                    Ok(None) => {
                        let _ = wr.shutdown().await;
                        break;
                    }
                    Err(e) => {
                        tracing::debug!("ss pump down read error: {e}");
                        break;
                    }
                }
            }
        }
    }
}

/// SS outbound 配置。
#[derive(Debug, Clone)]
pub struct SsOutboundConfig {
    /// SS 账户（cipher + key + password）。
    pub account: MemoryAccount,
    /// SS 服务器地址。
    pub server_address: Address,
    /// SS 服务器端口。
    pub server_port: u16,
}

impl SsOutboundConfig {
    /// 构造配置。
    #[must_use]
    pub fn new(account: MemoryAccount, server_address: Address, server_port: u16) -> Self {
        Self {
            account,
            server_address,
            server_port,
        }
    }
}

/// 解析 SS outbound settings JSON → SsOutboundConfig。
///
/// JSON 格式：`{ "servers": [{ "address": "...", "port": 8388, "method": "aes-256-gcm", "password": "..." }] }`
pub fn parse_ss_config(data: &[u8]) -> Result<SsOutboundConfig, String> {
    let v: serde_json::Value = serde_json::from_slice(data).map_err(|e| e.to_string())?;
    let servers = v
        .get("servers")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing servers array".to_string())?;
    let first = servers
        .first()
        .ok_or_else(|| "servers array is empty".to_string())?;
    let address = first
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing servers[0].address".to_string())?;
    let port = first
        .get("port")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing servers[0].port".to_string())?;
    let method = first
        .get("method")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing servers[0].method".to_string())?;
    let password = first
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing servers[0].password".to_string())?;
    let cipher_type = crate::config::CipherType::from_name(method)
        .ok_or_else(|| format!("unsupported cipher: {method}"))?;
    let port = u16::try_from(port).map_err(|_| "port out of range")?;
    let proto_account = xray_proto::xray::proxy::shadowsocks::Account {
        password: password.to_string(),
        cipher_type: cipher_type.as_i32(),
        iv_check: false,
    };
    let account = MemoryAccount::from_proto(&proto_account)
        .map_err(|e| format!("ss account: {e}"))?;
    Ok(SsOutboundConfig::new(
        account,
        Address::Domain(address.to_string()),
        port,
    ))
}

/// 构造 SS 的 DialFn 闭包。
///
/// 闭包捕获 `Arc<SsOutboundConfig>`，每次调用：
/// 1. `Client::dial_target` 拨号到 SS 服务器 + 写首帧
/// 2. 包装为 [`SsConnection`]（impl [`Connection`]）
/// 3. 返回连接
///
/// # Panics
///
/// 不会 panic；任何错误以 `Err(String)` 返回。
pub fn make_ss_dial_fn(config: Arc<SsOutboundConfig>) -> DialFn {
    Arc::new(move |dest: &Destination| {
        let config = Arc::clone(&config);
        let target_addr = dest.address().clone();
        let target_port = dest.port().value();
        Box::pin(async move {
            let client = Client::new(
                config.account.clone(),
                match &config.server_address {
                    Address::Domain(d) => d.clone(),
                    Address::IPv4(ip) => ip.to_string(),
                    Address::IPv6(ip) => ip.to_string(),
                },
                config.server_port,
            );
            let stream = client
                .dial_target(&target_addr, target_port)
                .await
                .map_err(|e| format!("ss dial: {e}"))?;
            Ok(Box::new(SsConnection::new(stream)) as Box<dyn Connection>)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CipherType;
    use xray_proto::xray::proxy::shadowsocks::Account as ProtoAccount;

    fn make_account() -> MemoryAccount {
        let p = ProtoAccount {
            password: "test".to_string(),
            cipher_type: CipherType::Aes128Gcm.as_i32(),
            iv_check: false,
        };
        MemoryAccount::from_proto(&p).expect("account")
    }

    #[test]
    fn config_construction() {
        let cfg = SsOutboundConfig::new(
            make_account(),
            Address::new_domain("example.com"),
            8388,
        );
        assert_eq!(cfg.server_port, 8388);
    }

    #[test]
    fn make_dial_fn_returns_arc_closure() {
        let cfg = Arc::new(SsOutboundConfig::new(
            make_account(),
            Address::new_domain("example.com"),
            443,
        ));
        let _dial = make_ss_dial_fn(Arc::clone(&cfg));
        assert_eq!(Arc::strong_count(&cfg), 2);
    }

    #[test]
    fn parse_ss_config_extracts_fields() {
        let data = r#"{
            "servers": [{
                "address": "ss.example.com",
                "port": 8388,
                "method": "aes-128-gcm",
                "password": "test-password"
            }]
        }"#;
        let config = parse_ss_config(data.as_bytes()).unwrap();
        assert_eq!(config.server_port, 8388);
        match &config.server_address {
            Address::Domain(d) => assert_eq!(d, "ss.example.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
    }

    #[test]
    fn parse_ss_config_missing_servers_fails() {
        let result = parse_ss_config(b"{}");
        assert!(result.is_err());
    }

    /// `SsConnection`（duplex pump）端到端：客户端 AsyncRead/AsyncWrite → 加密 chunk →
    /// SS inbound 解密 → echo → 加密回响 → 客户端读回。
    ///
    /// 直接证明 SsConnection 的 pump 走 SS 加密层：若退化为明文透传（旧行为），
    /// inbound 的 `read_chunk` 会 AEAD open 失败而 panic。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ss_connection_pump_roundtrips_through_inbound_echo() {
        use crate::inbound::SsInbound;
        use std::net::{IpAddr, SocketAddr};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};
        use xray_common::net::address::Address;

        // 1. echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = echo_listener.accept().await.expect("echo accept");
            let (mut rd, mut wr) = tokio::io::split(sock);
            let _ = tokio::io::copy(&mut rd, &mut wr).await;
        });

        // 2. SS inbound：handle_conn 握手 → read_chunk body → echo → write_chunk 回响
        let inbound_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind inbound");
        let inbound_addr = inbound_listener.local_addr().unwrap();
        let account = make_account();
        let ib = std::sync::Arc::new(SsInbound::new(account.clone(), "u@pump.local"));
        let echo_v4 = match echo_addr.ip() {
            IpAddr::V4(v4) => v4,
            _ => panic!("expected IPv4 echo addr"),
        };
        let echo_socket = SocketAddr::new(IpAddr::V4(echo_v4), echo_addr.port());

        let server_handle = tokio::spawn({
            let ib = std::sync::Arc::clone(&ib);
            async move {
                let (conn, _) = inbound_listener.accept().await.expect("inbound accept");
                let (_header, mut ss_stream) = ib.handle_conn(conn).await.expect("handshake");
                let body = ss_stream.read_chunk().await.expect("read body").expect("non-empty");
                let mut ec = TcpStream::connect(echo_socket).await.expect("connect echo");
                ec.write_all(&body).await.expect("fwd echo");
                ec.flush().await.expect("flush echo");
                let mut echoed = vec![0u8; body.len()];
                ec.read_exact(&mut echoed).await.expect("read echo back");
                ss_stream.write_chunk(&echoed).await.expect("write resp chunk");
                ss_stream.flush().await.expect("flush resp");
            }
        });

        // 3. client：dial_target（写 IV + 首帧）→ SsConnection::new → AsyncRead/Write
        let client = Client::new(account, inbound_addr.ip().to_string(), inbound_addr.port());
        let stream = client
            .dial_target(&Address::IPv4(echo_v4), echo_addr.port())
            .await
            .expect("dial_target");
        let mut conn = SsConnection::new(stream);

        let payload = b"hello ss duplex pump!";
        conn.write_all(payload).await.expect("ss write");
        conn.flush().await.expect("ss flush");

        let mut got = vec![0u8; payload.len()];
        conn.read_exact(&mut got).await.expect("ss read");

        assert_eq!(&got[..], payload, "echo through SsConnection pump");
        server_handle.await.expect("server task join");
    }
}
