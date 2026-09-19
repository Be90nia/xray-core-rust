//! QUIC transport: quinn-based bi-stream tunnel.
//!
//! 对应 Go `transport/internet/quic/dialer.go` + `transport/internet/quic/hub.go`。
//!
//! ## 拨号流程
//!
//! 1. `xray_tls::client_config::build_client_config` 构建客户端 rustls config
//! 2. `quinn::crypto::rustls::QuicClientConfig::try_from` 转为 QUIC 客户端配置
//! 3. `quinn::Endpoint::client("0.0.0.0:0")` 绑定临时 UDP socket
//! 4. `endpoint.connect_with(cfg, socket_addr, server_name)` 拨号
//! 5. `connection.open_bi()` 打开双向 stream
//! 6. `tokio::io::duplex(64*1024)` 桥接 (SendStream, RecvStream) ↔ DuplexConn
//!
//! ## 监听流程
//!
//! 1. `xray_tls::server_config::build_server_config` 构建服务端 rustls config
//! 2. `quinn::Endpoint::server(server_config, addr)` 绑定 UDP socket
//! 3. spawn accept loop：每个 QUIC 连接 → 内层 accept_bi loop → handler
//!
//! ## DNS
//!
//! quinn 需要 `SocketAddr`（不做 DNS）；若 dest 是域名，用 `tokio::net::lookup_host` 解析。

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use xray_common::net::destination::Destination;
use xray_transport::connection::Connection;
use xray_transport::dialer::StreamSettings;
use xray_transport::listener_registry::{ConnHandler, TransportListener};
use xray_transport::sockopt::SocketOptions;

/// 主动拨号 QUIC 连接。对应 Go `quic::Dial`。
///
/// `settings.security` 必须为 `"tls"`（QUIC 强制 TLS）；否则返回 `InvalidInput`。
pub async fn dial(
    dest: &Destination,
    settings: &StreamSettings,
    sockopt: &SocketOptions,
) -> io::Result<Box<dyn Connection>> {
    // 1. TLS client config（QUIC 强制 TLS，无 None 兜底）。
    let sni = dest.address().to_string();
    let tls_cfg = xray_tls::client_config::build_client_config(
        &settings.security,
        settings.security_json.as_ref(),
        &sni,
    )?
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUIC requires security=tls (got none/unsupported)",
        )
    })?;

    // fhsf：拨号外层 timeout 包装。quinn connect 内部超时仅握手阶段；DNS 解析 hang /
    // 黑洞下 `connect_with(...).await` 永不返回——必须外层 tokio::time::timeout 兜底。
    // 对齐 hysteria crate QuinnHysteriaTransport::dial_and_authenticate（同样包装）。
    let dial_timeout = std::time::Duration::from_secs(16);
    let addr_str = format!("{}:{}", dest.address(), dest.port().value());
    let socket_addr = tokio::time::timeout(dial_timeout, tokio::net::lookup_host(&addr_str))
        .await
        .map_err(|_| io::Error::new(
            io::ErrorKind::TimedOut,
            format!("quic DNS lookup timeout for {addr_str}"),
        ))?
        .map_err(|e| io::Error::other(format!("quic DNS resolution: {e}")))?
        .next()
        .ok_or_else(|| io::Error::other(format!("DNS resolution returned no addr for {addr_str}")))?;

    // 3. QUIC 特有配置（congestion 等）。
    let qc = crate::config::QuicConfig::from_json(settings.transport_json.as_ref())?;
    // 4. rustls ClientConfig → quinn ClientConfig（+ congestion control TransportConfig）。
    let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from((*tls_cfg).clone())
        .map_err(|e| io::Error::other(format!("rustls→quic client: {e}")))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client));
    client_config.transport_config(Arc::new(qc.build_transport_config()));

    // 4. Endpoint + connect（外层 timeout 覆盖 DNS+握手+鉴权整段）。
    // GSO 默认开（quinn-udp 构造期探测 UDP_SEGMENT，内核不支持自动回退单段）；
    // disableGSO=true 时经 NoGsoSocket 钳单段（见 udp_gso 模块 doc）。
    let endpoint = crate::udp_gso::make_endpoint(
        None,
        "0.0.0.0:0".parse().unwrap(),
        qc.disable_gso,
        sockopt,
    )
    .map_err(|e| io::Error::other(format!("quinn bind: {e}")))?;
    let connecting = endpoint
        .connect_with(client_config, socket_addr, &sni)
        .map_err(|e| io::Error::other(format!("quinn connect initiate: {e}")))?;
    let conn = tokio::time::timeout(dial_timeout, connecting)
        .await
        .map_err(|_| io::Error::new(
            io::ErrorKind::TimedOut,
            format!("quic handshake timeout after {dial_timeout:?}"),
        ))?
        .map_err(|e| io::Error::other(format!("quinn handshake: {e}")))?;

    let local = endpoint.local_addr().ok();
    let remote = conn.remote_address();
    // endpoint 必须保持存活——否则连接立即关闭。放进桥接任务里持有。
    let (send, recv) = conn.open_bi().await.map_err(io_err)?;
    Ok(Box::new(QuicConn::new(send, recv, local, Some(remote), endpoint)))
}

/// 监听 QUIC 入站连接。对应 Go `quic::Listen`。
///
/// accept loop：每个 QUIC 连接 → 内层 `accept_bi` loop → 每个新 bi-stream 调用 `handler`。
/// 这与 Go xray-core `hub.go` 一致：一个 QUIC 连接可承载多个 bi-stream。
pub async fn listen(
    addr: SocketAddr,
    settings: &StreamSettings,
    sockopt: &SocketOptions,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    let tls_cfg = xray_tls::server_config::build_server_config(
        &settings.security,
        settings.security_json.as_ref(),
    )?
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUIC server requires security=tls (got none/unsupported)",
        )
    })?;

    // QUIC 特有配置（congestion 等）。
    let qc = crate::config::QuicConfig::from_json(settings.transport_json.as_ref())?;
    let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from((*tls_cfg).clone())
        .map_err(|e| io::Error::other(format!("rustls→quic server: {e}")))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
    server_config.transport_config(Arc::new(qc.build_transport_config()));
    // 同 dial：GSO 默认开，disableGSO=true 走 NoGsoSocket 单段路径。
    let endpoint =
        crate::udp_gso::make_endpoint(Some(server_config), addr, qc.disable_gso, sockopt)
            .map_err(|e| io::Error::other(format!("quinn bind: {e}")))?;
    let local = endpoint.local_addr()?;

    // endpoint clone 给 listener 句柄；本体 move 进 accept task。
    let listener_endpoint = endpoint.clone();
    tokio::spawn(async move {
        loop {
            let incoming = match endpoint.accept().await {
                Some(c) => c,
                None => break, // endpoint closed
            };
            let h = handler.clone();
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(_) => return,
                };
                let local = conn.local_ip().map(|ip| SocketAddr::new(ip, 0));
                let remote = conn.remote_address();
                // 每个 QUIC 连接上接受任意数量的 bi-stream，每个 stream 都作为独立 Connection 上报。
                while let Ok((send, recv)) = conn.accept_bi().await {
                    let c = QuicConn::new(send, recv, local, Some(remote), ());
                    h(Box::new(c));
                }
            });
        }
    });

    Ok(Box::new(QuicListener {
        local,
        endpoint: listener_endpoint,
    }))
}

/// quinn (SendStream, RecvStream) + tokio DuplexStream 桥接的 Connection。
///
/// 设计与 [`xray_transport_grpc::transport::DuplexConn`] 一致：
/// - 写方向：DuplexStream → quinn SendStream
/// - 读方向：quinn RecvStream → DuplexStream
/// - `extra` 持有 endpoint（dial 路径）或 `()`（listen 路径，endpoint 在外层 task 持有）
struct QuicConn<E> {
    inner: tokio::io::DuplexStream,
    _extra: E,
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
}

impl<E: Send + Sync + Unpin> QuicConn<E> {
    /// 构造桥接：spawn 双向 copy task 把 quinn (send, recv) ↔ DuplexStream。
    fn new(
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        local: Option<SocketAddr>,
        remote: Option<SocketAddr>,
        extra: E,
    ) -> Self {
        let (client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let (mut rd, mut wr) = tokio::io::split(server);
            // s: 读 duplex-write 半边 → 写到 quinn send；EOF 时 finish() 半关闭
            let s = async {
                // read_buf 直写 BytesMut spare capacity（免中间栈 buffer），freeze 后
                // owned Bytes move 给 quinn——原 `vec![0u8; 32K] + copy_from_slice`
                // 的第二次 32KB memcpy 消除。reserve 保证每轮读预算（spare 为 0 时
                // read_buf 返回 Ok(0) 会被误判 EOF）。
                let mut buf = BytesMut::with_capacity(32 * 1024);
                loop {
                    buf.reserve(32 * 1024);
                    let n = rd.read_buf(&mut buf).await?;
                    if n == 0 {
                        let _ = send.finish();
                        break;
                    }
                    send.write_chunk(buf.split().freeze())
                        .await
                        .map_err(io_err)?;
                }
                Ok::<_, io::Error>(())
            };
            // r: 读 quinn recv → 写到 duplex-read 半边
            let r = async {
                let mut buf = vec![0u8; 32 * 1024];
                loop {
                    match recv.read(&mut buf).await {
                        Ok(Some(n)) => wr.write_all(&buf[..n]).await?,
                        Ok(None) => break,
                        Err(e) => return Err(io_err(e)),
                    }
                }
                Ok::<_, io::Error>(())
            };
            let _ = tokio::try_join!(s, r);
        });
        Self {
            inner: client,
            _extra: extra,
            local,
            remote,
        }
    }
}

impl<E: Send + Sync + Unpin> AsyncRead for QuicConn<E> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<E: Send + Sync + Unpin> AsyncWrite for QuicConn<E> {
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

impl<E: Send + Sync + Unpin> Connection for QuicConn<E> {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.remote)
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.local)
    }
}

/// QUIC listener 句柄。endpoint clone 与 accept task 共享（quinn Endpoint 内部 Arc）。
struct QuicListener {
    local: SocketAddr,
    endpoint: quinn::Endpoint,
}

impl TransportListener for QuicListener {
    fn close(&self) -> io::Result<()> {
        tracing::info!("QUIC listener close addr={}", self.local);
        // 立即关闭 QUIC 栈：accept 循环收到 None 退出，活跃连接全部断开，
        // UDP socket 释放（对齐 Go hysteria/hub.go Close=listener+transport+pktConn）。
        self.endpoint.close(quinn::VarInt::from_u32(0), b"listener closed");
        Ok(())
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

fn io_err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ensure_provider() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// quinn 客户端连指定地址（allowInsecure 跳过自签验证，1s idle timeout 快速失败）。
    fn quinn_client_connect(addr: SocketAddr) -> quinn::Endpoint {
        let client_tls = xray_tls::client_config::build_client_config(
            "tls",
            Some(&serde_json::json!({"allowInsecure": true})),
            "127.0.0.1",
        )
        .unwrap()
        .expect("client tls config");
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
            1_000,
        ))));
        let mut quic_cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
        ));
        quic_cfg.transport_config(Arc::new(transport));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quic_cfg);
        endpoint
    }

    /// close() 必须真实关闭 endpoint（票 4kjs 回归锚）：close 前可连通，close 后
    /// 新 QUIC 握手失败。修复前 close() 仅日志，endpoint 永远存活，connect 一直成功。
    #[tokio::test]
    async fn close_rejects_new_connections() {
        ensure_provider();
        let settings = StreamSettings {
            protocol: "quic".into(),
            security: "tls".into(),
            ..Default::default()
        };
        let handler: ConnHandler = Arc::new(|_| {});
        let listener = listen("127.0.0.1:0".parse().unwrap(), &settings, &Default::default(), handler)
            .await
            .expect("listen");
        let addr = listener.local_addr().unwrap();

        // close 前连通（证明服务活着，排除假阳性）。
        let mut ep = quinn_client_connect(addr);
        let pre = ep.connect(addr, "127.0.0.1").unwrap().await;
        assert!(pre.is_ok(), "pre-close connect should succeed: {:?}", pre.err());

        listener.close().unwrap();

        // close 后新握手必须失败（server 不再回应 Initial）。
        let post = ep.connect(addr, "127.0.0.1").unwrap().await;
        assert!(post.is_err(), "post-close connect must fail");
        ep.close(0u32.into(), b"test done");
    }

    /// echo 回显 handler：读到什么写回什么，EOF/错误即退。
    fn echo_handler() -> ConnHandler {
        Arc::new(|conn| {
            tokio::spawn(async move {
                let mut conn = conn;
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match conn.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        })
    }

    /// GSO 开关 × 分段边界端到端：listen 全链路消费 quicSettings.disableGSO
    /// （JSON → QuicConfig → make_endpoint 接线证明），客户端发 128 KiB
    /// （>64 段 × ~1452B，quinn 多段 Transmit / UDP_SEGMENT 内核分段的
    /// 边界场景，sing-box #4222 类错分段在此暴露）回环 echo 校验字节完整。
    async fn echo_roundtrip_with(disable_gso: bool) {
        ensure_provider();
        let settings = StreamSettings {
            protocol: "quic".into(),
            security: "tls".into(),
            transport_json: Some(serde_json::json!({ "disableGSO": disable_gso })),
            ..Default::default()
        };
        let listener = listen("127.0.0.1:0".parse().unwrap(), &settings, &Default::default(), echo_handler())
            .await
            .expect("listen");
        let addr = listener.local_addr().unwrap();

        let ep = quinn_client_connect(addr);
        let payload: Vec<u8> = (0..(128 * 1024)).map(|i| i as u8).collect();
        let work = async {
            let conn = ep.connect(addr, "127.0.0.1").unwrap().await.unwrap();
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            send.write_all(&payload).await.unwrap();
            send.finish().unwrap();
            let mut echoed = vec![0u8; payload.len()];
            recv.read_exact(&mut echoed).await.unwrap();
            echoed
        };
        let echoed = tokio::time::timeout(std::time::Duration::from_secs(10), work)
            .await
            .expect("echo roundtrip within 10s");
        assert_eq!(echoed, payload, "128 KiB echo must be byte-exact");
        ep.close(0u32.into(), b"test done");
    }

    /// 禁用 GSO（NoGsoSocket 单段路径）链路仍通、分段边界正确。
    #[tokio::test]
    async fn echo_roundtrip_gso_disabled() {
        echo_roundtrip_with(true).await;
    }

    /// 默认路径（Linux GSO 开，非 Linux 单段）回归保护：接线不得破坏现状。
    #[tokio::test]
    async fn echo_roundtrip_gso_default() {
        echo_roundtrip_with(false).await;
    }
}
