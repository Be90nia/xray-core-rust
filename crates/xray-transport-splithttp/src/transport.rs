//! SplitHTTP transport 监听入口（生产 listener）。
//!
//! 对应 Go `transport/internet/splithttp/hub.go::ListenXH`（449-582 行）：
//! - **isH3 判定**（hub.go:469）：`tlsSettings.alpn == ["h3"]` → UDP + QUIC + h3 server
//! - **TCP**（hub.go:536-545）：accept → 可选 TLS（hub.go:553-556）/ REALITY（hub.go:558-560）
//!   → hyper auto（h1 + h2c，hub.go:565-567）→ [`crate::hub::handler::handle_request`]
//! - **unix**：[`listen_splithttp_unix`]（hub.go:472-480，`port == 0` 分支）
//!
//! Go 的 `requestHandler.ServeHTTP` 与传输无关（同一 handler 服务 h1/h2/h3 三路），
//! 本文件把 hub handler 接到三种监听形态上。

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine as _;
use bytes::{Buf as _, Bytes};
use http_body_util::BodyExt as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use xray_transport::connection::Connection;
use xray_transport::dialer::StreamSettings;
use xray_transport::fallback::fallback_to_dest;
use xray_transport::listener_registry::{ConnHandler, TransportListener};
use xray_transport::sockopt::SocketOptions;

use crate::config::Config;
use crate::hub::handler::{self, HandlerContext};
use crate::hub::{HubConnHandler, ServerConn, SessionMap};

/// h1 请求头读取超时。对应 Go hub.go:570 `ReadHeaderTimeout: time.Second * 4`。
const READ_HEADER_TIMEOUT: Duration = Duration::from_secs(4);

/// duplex bridge 缓冲。与 `hub::handler::DUPLEX_BUF` 对齐（64 KiB）。
const DUPLEX_BUF: usize = 64 * 1024;

/// SplitHTTP 监听入口（listener registry 注册的目标）。
///
/// 镜像 Go `ListenXH`：isH3（alpn==["h3"]）走 QUIC，其余走 TCP + TLS/REALITY 包装。
pub async fn listen_splithttp(
    addr: SocketAddr,
    settings: &StreamSettings,
    _sockopt: &SocketOptions,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    let config = Arc::new(crate::register::parse_splithttp_config(
        settings.transport_json.as_ref(),
    )?);
    let tls_cfg = xray_tls::server_config::build_server_config(
        &settings.security,
        settings.security_json.as_ref(),
    )?;

    // isH3：Go hub.go:469 — `len(NextProtos) == 1 && NextProtos[0] == "h3"`。
    // REALITY 不进 H3（Go REALITY config 无 NextProtos，且 hub.go:558 只包装 tcp/unix
    // listener），故限定 security == "tls"。
    let is_h3 = settings.security == "tls"
        && tls_cfg
            .as_ref()
            .is_some_and(|c| c.alpn_protocols.len() == 1 && c.alpn_protocols[0] == b"h3");

    if is_h3 {
        let tls = tls_cfg.expect("is_h3 implies Some");
        listen_h3(addr, tls, &config, handler).await
    } else {
        // Tcpmask（Go splithttp/hub.go:547-549：`!isH3 && TcpmaskManager != nil`
        // 才 WrapListener——H3/QUIC 分支不接 Tcpmask）。空 manager = 恒等。
        let tcpmask = Some(Arc::new(
            xray_transport::finalmask::build_tcpmask_manager_from_json(
                settings.finalmask_json.as_ref(),
            )?,
        ));
        listen_tcp(
            addr,
            &settings.security,
            tls_cfg,
            settings.security_json.as_ref(),
            &config,
            tcpmask,
            handler,
        )
        .await
    }
}

/// Unix domain socket 监听。对应 Go hub.go:472-480（`port == net.Port(0)` 分支）。
///
/// Go 由 `ListenXH` 的 port==0 触发（address.Domain() 即 socket 路径）；Rust
/// `TransportListenFn` 的 `SocketAddr` 无法承载 unix 路径，故独立入口（与
/// `xray_transport::system_listener::listen_unix_system` 同模式）。h1/h2c/TLS/REALITY
/// 与 TCP 分支完全一致（Go hub.go:551-560 对 tcp/unix 统一包装）。
#[cfg(unix)]
pub async fn listen_splithttp_unix(
    path: &str,
    settings: &StreamSettings,
    _sockopt: &SocketOptions,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    let config = Arc::new(crate::register::parse_splithttp_config(
        settings.transport_json.as_ref(),
    )?);
    let tls_cfg = xray_tls::server_config::build_server_config(
        &settings.security,
        settings.security_json.as_ref(),
    )?;
    let reality = reality_server_config(&settings.security, settings.security_json.as_ref())?;

    let listener = tokio::net::UnixListener::bind(path)?;
    // ponytail: SocketAddr 无法表达 unix 地址，元数据用 UNSPECIFIED 占位；
// 接入 dispatcher 元数据时如需真实路径，扩 HandlerContext 字段。
    let placeholder = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
    let ctx = build_context(&config, placeholder, handler);
    tracing::info!(path, "listening UNIX domain socket for XHTTP");

    tokio::spawn(async move {
        loop {
            let stream = match listener.accept().await {
                Ok((s, _)) => s,
                Err(_) => continue,
            };
            let ctx = Arc::clone(&ctx);
            let tls = tls_cfg.clone();
            let rc = reality.clone();
            tokio::spawn(async move {
                handle_accepted_stream(stream, placeholder, placeholder, tls, rc, ctx).await;
            });
        }
    });
    Ok(Box::new(SplithttpListener { local: placeholder }))
}

async fn listen_tcp(
    addr: SocketAddr,
    security: &str,
    tls_cfg: Option<Arc<rustls::ServerConfig>>,
    security_json: Option<&serde_json::Value>,
    config: &Arc<Config>,
    tcpmask: Option<Arc<xray_transport::finalmask::TcpmaskManager>>,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    let tcp = tokio::net::TcpListener::bind(addr).await?;
    let local = tcp.local_addr()?;
    // REALITY listener：Go hub.go:558-560 `goreality.NewListener`。
    let reality = reality_server_config(security, security_json)?;
    let ctx = build_context(config, local, handler);
    tracing::info!(%local, "listening TCP for XHTTP");

    tokio::spawn(async move {
        loop {
            let (stream, peer) = match tcp.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let _ = stream.set_nodelay(true);
            // Tcpmask wrap（Go hub.go:546-549 WrapListener：mask 在 TLS/REALITY
            // 之内、最贴近 wire；wrap 失败丢连接继续 accept）。
            let stream: Box<dyn xray_transport::connection::Connection> =
                match tcpmask.as_ref() {
                    Some(m) => {
                        match xray_transport::finalmask::wrap_conn_server_into_connection(
                            m,
                            Box::new(xray_transport::connection::TcpConnection::new(stream)),
                        ) {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::debug!(error = %e, "XHTTP tcpmask wrap failed");
                                continue;
                            }
                        }
                    }
                    None => Box::new(xray_transport::connection::TcpConnection::new(stream)),
                };
            let ctx = Arc::clone(&ctx);
            let tls = tls_cfg.clone();
            let rc = reality.clone();
            tokio::spawn(async move {
                handle_accepted_stream(stream, peer, local, tls, rc, ctx).await;
            });
        }
    });
    Ok(Box::new(SplithttpListener { local }))
}

/// 单个已 accept 的流：REALITY / TLS 包装 → h1+h2c HTTP 服务。
///
/// Go hub.go:551-560：TLS 与 REALITY 互斥包装（security 二选一），
/// hub.go:564-578：同一 http.Server 同时处理明文 HTTP/1.1 与 h2c。
async fn handle_accepted_stream<S>(
    stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    tls: Option<Arc<rustls::ServerConfig>>,
    reality: Option<RealityServerConfig>,
    ctx: Arc<HandlerContext>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if let Some(rc) = reality {
        serve_reality_conn(stream, peer, local, rc, ctx).await;
    } else if let Some(tc) = tls {
        // Go hub.go:553-556 `gotls.NewListener`
        if let Ok(tls_stream) = tokio_rustls::TlsAcceptor::from(tc).accept(stream).await {
            serve_http_conn(tls_stream, peer, ctx).await;
        }
    } else {
        serve_http_conn(stream, peer, ctx).await;
    }
}

/// h1 + h2c 自动协商的 HTTP 服务。对应 Go hub.go:564-578
/// （`protocols.SetHTTP1(true)` + `SetUnencryptedHTTP2(true)` 的 http.Server）。
async fn serve_http_conn<S>(stream: S, peer: SocketAddr, ctx: Arc<HandlerContext>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let io = TokioIo::new(stream);
    let svc = service_fn(move |req| {
        let ctx = Arc::clone(&ctx);
        async move {
            Ok::<_, std::convert::Infallible>(handler::handle_request(req, peer, &ctx).await)
        }
    });
    let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(READ_HEADER_TIMEOUT);
    // ponytail: Go hub.go:571 MaxHeaderBytes（GetNormalizedServerMaxHeaderBytes）无
    // hyper 字节级对应（仅 max_headers 条数），默认值即 Go 默认 1MiB 量级，未接入。
    let _ = builder.serve_connection(io, svc).await;
}

// ===== REALITY（Go hub.go:558-560 goreality.NewListener 的 Rust 等价物） =====

/// REALITY 服务端配置（`realitySettings` JSON）。
#[derive(Clone)]
struct RealityServerConfig {
    private_key: [u8; 32],
    short_ids: Vec<[u8; 8]>,
    max_time_diff: u32,
    fallback_dest: String,
    xver: u8,
}

/// security == "reality" 时解析服务端 REALITY 配置，否则返回 None。
fn reality_server_config(
    security: &str,
    json: Option<&serde_json::Value>,
) -> io::Result<Option<RealityServerConfig>> {
    if security != "reality" {
        return Ok(None);
    }
    let json = json.ok_or_else(|| io::Error::other("reality: missing realitySettings"))?;
    let key_str = json
        .get("privateKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| io::Error::other("reality: missing privateKey"))?;
    let private_key = <[u8; 32]>::try_from(base64_url_decode(key_str)?)
        .map_err(|_| io::Error::other("reality: privateKey must be 32 bytes"))?;

    let mut short_ids = Vec::new();
    if let Some(arr) = json.get("shortIds").and_then(|x| x.as_array()) {
        for sid in arr {
            if let Some(hex_str) = sid.as_str() {
                if let Some(bytes) = hex_decode_8(hex_str) {
                    short_ids.push(bytes);
                }
            }
        }
    }
    // 无 shortIds：默认允许全零（Go REALITY 空配置兼容）
    if short_ids.is_empty() {
        short_ids.push([0u8; 8]);
    }

    // dest/target：int（端口→localhost:port）或字符串 host:port
    let dest_raw = json
        .get("target")
        .or_else(|| json.get("dest"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let fallback_dest = match dest_raw.as_u64() {
        Some(port) => format!("localhost:{port}"),
        None => dest_raw.as_str().unwrap_or("localhost:443").to_string(),
    };

    let xver = json.get("xver").and_then(|x| x.as_u64()).unwrap_or(0).min(2) as u8;
    let max_time_diff = json
        .get("maxTimeDiff")
        .and_then(|x| x.as_u64())
        .unwrap_or(43200) as u32;

    Ok(Some(RealityServerConfig {
        private_key,
        short_ids,
        max_time_diff,
        fallback_dest,
        xver,
    }))
}

/// REALITY 握手：Verified → h1/h2c 服务；Invalid → 透明转发 fallback dest。
///
/// 镜像 Go `goreality.NewListener`（xtls/reality 库内置 fallback），Rust 侧组合
/// `xray_reality::server::server_tls` + `fallback_to_dest`（与 xray-core inbound
/// 的 VLESS+REALITY 路径同构）。
async fn serve_reality_conn<S>(
    stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    rc: RealityServerConfig,
    ctx: Arc<HandlerContext>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use xray_reality::server::{server_tls, RealityServerOutcome};

    match server_tls(stream, &rc.private_key, &rc.short_ids, rc.max_time_diff).await {
        Ok(RealityServerOutcome::Verified(tls)) => serve_http_conn(tls, peer, ctx).await,
        Ok(RealityServerOutcome::Invalid { conn, record, reason }) => {
            tracing::debug!(error = ?reason, dest = %rc.fallback_dest, "splithttp reality fallback");
            let _ = fallback_to_dest(conn, &record, &rc.fallback_dest, peer, local, rc.xver).await;
        }
        Err(e) => tracing::warn!(error = %e, "splithttp reality handshake error"),
    }
}

/// base64 RawURL 解码（无 padding，兼容 std 变体）。
fn base64_url_decode(s: &str) -> io::Result<Vec<u8>> {
    let normalized = s.replace('+', "-").replace('/', "_");
    let normalized = normalized.trim_end_matches('=');
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(normalized)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s))
        .map_err(|e| io::Error::other(format!("reality: base64 privateKey: {e}")))
}

/// hex 字符串 → 8 字节 short_id。
fn hex_decode_8(s: &str) -> Option<[u8; 8]> {
    if s.len() > 16 {
        return None;
    }
    let padded = format!("{s:0<16}");
    let bytes = hex::decode(padded).ok()?;
    bytes.try_into().ok()
}

// ===== H3（Go hub.go:481-535：UDP + QUIC + http3.Server） =====

/// H3 监听：UDP socket + QUIC endpoint + h3 server accept 循环。
///
/// `quinn::Endpoint::server` 等价 Go `ListenSystemPacket` + `quic.ListenEarly` 的组合。
/// ponytail: Go QuicParams（hub.go:498-514 InitStreamReceiveWindow/BBR 等）未在 Rust
/// 配置层建模，用 quinn 默认 TransportConfig；接入时在此覆盖 transport_config。
/// ListenEarly 的 0-RTT 接受同样依赖 rustls max_early_data_size，未启用。
async fn listen_h3(
    addr: SocketAddr,
    tls: Arc<rustls::ServerConfig>,
    config: &Arc<Config>,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from((*tls).clone())
        .map_err(|e| io::Error::other(format!("rustls→quic server: {e}")))?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    let local = endpoint.local_addr()?;
    let ctx = build_context(config, local, handler);
    tracing::info!(%local, "listening QUIC for XHTTP/3");

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let ctx = Arc::clone(&ctx);
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(_) => return,
                };
                serve_h3_conn(conn, ctx).await;
            });
        }
    });
    Ok(Box::new(SplithttpListener { local }))
}

/// 单个 QUIC 连接：h3 server handshake → accept 请求循环。
async fn serve_h3_conn(conn: quinn::Connection, ctx: Arc<HandlerContext>) {
    let mut h3_conn = match h3::server::Connection::new(h3_quinn::Connection::new(conn.clone()))
        .await
    {
        Ok(c) => c,
        Err(_) => return,
    };
    while let Ok(Some(resolver)) = h3_conn.accept().await {
        let ctx = Arc::clone(&ctx);
        let peer = conn.remote_address();
        tokio::spawn(async move {
            let Ok((req, stream)) = resolver.resolve_request().await else {
                return;
            };
            serve_h3_request(req, stream, peer, ctx).await;
        });
    }
}

/// h3 服务端请求流（bidi）。split 后 send/recv 两半分属不同 task。
type H3ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// 单个 h3 请求：请求体桥接为 `ReqBody` 喂给 hub handler，响应帧序列发回。
///
/// 对应 Go `http3.Server{Handler: requestHandler}`——同一 handler 服务 h1/h2/h3。
/// stream-up 需边收上传 body 边发响应，故 split（h3 RequestStream::split 官方支持）。
async fn serve_h3_request(
    req: http::Request<()>,
    stream: H3ServerStream,
    peer: SocketAddr,
    ctx: Arc<HandlerContext>,
) {
    let (send_half, recv_half) = stream.split();
    let (parts, ()) = req.into_parts();
    let req = http::Request::from_parts(parts, H3RecvBody { stream: recv_half });

    let resp = handler::handle_request(req, peer, &ctx).await;

    let (parts, mut body) = resp.into_parts();
    let mut send = send_half;
    if send.send_response(http::Response::from_parts(parts, ())).await.is_err() {
        return;
    }
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else { break };
        if let Ok(data) = frame.into_data() {
            if send.send_data(data).await.is_err() {
                return;
            }
        }
    }
    let _ = send.finish().await;
}

/// h3 请求体 → `http_body::Body` 桥接。
///
/// `poll_recv_data` 是注册函数（非 async），可直接在 `poll_frame` 里调用。
struct H3RecvBody {
    stream: h3::server::RequestStream<h3_quinn::RecvStream, Bytes>,
}

impl hyper::body::Body for H3RecvBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, io::Error>>> {
        match self.stream.poll_recv_data(cx) {
            Poll::Ready(Ok(Some(mut chunk))) => {
                let n = chunk.remaining();
                Poll::Ready(Some(Ok(hyper::body::Frame::data(chunk.copy_to_bytes(n)))))
            }
            Poll::Ready(Ok(None)) => Poll::Ready(None),
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(io::Error::other(format!(
                "h3 recv_data: {e}"
            ))))),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ===== hub handler ↔ listener registry 适配 =====

/// 构造 hub handler 上下文（镜像 `HubListener::serve` 的构造）。
fn build_context(
    config: &Arc<Config>,
    local: SocketAddr,
    handler: ConnHandler,
) -> Arc<HandlerContext> {
    Arc::new(HandlerContext {
        config: Arc::clone(config),
        host: config.host.clone(),
        base_path: config.normalized_path(),
        local_addr: local,
        sessions: Arc::new(SessionMap::new()),
        conn_handler: Arc::new(ConnHandlerAdapter(handler)),
        max_buffered_posts: config.normalized_sc_max_buffered_posts() as usize,
        sc_max_each_post_bytes: config.normalized_sc_max_each_post_bytes().to as usize,
    })
}

/// `ConnHandler`（registry 的 `Arc<dyn Fn(Box<dyn Connection>)>`）→ `HubConnHandler`。
///
/// `ServerConn` 的 box 字段非 `Sync`，不满足 `Connection: Sync` 约束，故沿用
/// duplex bridge 模式：`tokio::io::duplex` 一端交 registry handler（`DuplexConn`），
/// 另一端与 `ServerConn` 的 reader/writer 双向 copy。
struct ConnHandlerAdapter(ConnHandler);

impl HubConnHandler for ConnHandlerAdapter {
    fn add_conn(&self, conn: ServerConn) {
        let (client, server) = tokio::io::duplex(DUPLEX_BUF);
        let remote = conn.remote_addr;
        let local = conn.local_addr;
        (self.0)(Box::new(DuplexConn {
            inner: client,
            remote: Some(remote),
            local: Some(local),
        }));
        tokio::spawn(async move {
            let ServerConn {
                reader: mut up,
                writer: mut down,
                ..
            } = conn;
            let (mut rd, mut wr) = tokio::io::split(server);
            // 上行（客户端上传 → dispatcher 读）/ 下行（dispatcher 写 → HTTP 响应）
            let a = tokio::io::copy(&mut up, &mut wr);
            let b = tokio::io::copy(&mut rd, &mut down);
            let _ = tokio::join!(a, b);
        });
    }
}

/// duplex 半部，满足 `Connection: AsyncRead + AsyncWrite + Send + Sync + Unpin`。
struct DuplexConn {
    inner: tokio::io::DuplexStream,
    remote: Option<SocketAddr>,
    local: Option<SocketAddr>,
}

impl AsyncRead for DuplexConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for DuplexConn {
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

impl Connection for DuplexConn {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.remote)
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.local)
    }
}

/// listener 句柄。对应 Go `Listener`（h3listener/listener 二选一）。
// ponytail: close 目前仅日志——TCP/QUIC accept 任务持有 listener 所有权，
// registry 层 close 语义需 AbortHandle/CancellationToken 改造（全仓通用课题）。
struct SplithttpListener {
    local: SocketAddr,
}

impl TransportListener for SplithttpListener {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
    fn close(&self) -> io::Result<()> {
        tracing::info!("splithttp listener close addr={}", self.local);
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpStream;
    fn ensure_provider() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// echo 型 ConnHandler：每收到 ServerConn 即写一条下行消息后放弃（触发响应 body EOF）。
    fn greeting_handler() -> (ConnHandler, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&count);
        let h: ConnHandler = Arc::new(move |conn: Box<dyn Connection>| {
            c.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut conn = conn;
                let _ = conn.write_all(b"hello-from-server").await;
                let _ = conn.flush().await;
                // drop → 下行 EOF → 响应 body 结束
            });
        });
        (h, count)
    }

    fn plain_settings() -> StreamSettings {
        StreamSettings {
            protocol: "splithttp".into(),
            ..Default::default()
        }
    }

    /// h1 客户端接入（stream-one）：明文 HTTP/1.1 GET → 200 + 下行数据。
    /// 验证 hyper auto 的 h1 兼容（Go hub.go:566 SetHTTP1(true)）。
    #[tokio::test]
    async fn h1_client_stream_one_roundtrip() {
        let (handler, count) = greeting_handler();
        let listener = listen_splithttp(
            "127.0.0.1:0".parse().unwrap(),
            &plain_settings(),
            &SocketOptions::default(),
            handler,
        )
        .await
        .expect("listen");
        let addr = listener.local_addr().unwrap();

        let mut tcp = TcpStream::connect(addr).await.expect("connect");
        tcp.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        tcp.read_to_end(&mut resp).await.unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(text.contains("200"), "h1 status line missing: {text}");
        assert!(
            text.contains("hello-from-server"),
            "h1 stream-one download missing: {text}"
        );
        assert_eq!(count.load(Ordering::SeqCst), 1, "handler should see 1 conn");
    }

    /// H3 server 接收：alpn=["h3"] → QUIC listener；quinn+h3 客户端 GET stream-one。
    #[tokio::test]
    async fn h3_server_receives_stream_one() {
        ensure_provider();
        let (handler, count) = greeting_handler();
        let mut settings = plain_settings();
        settings.security = "tls".into();
        settings.security_json = Some(serde_json::json!({ "alpn": ["h3"] }));
        let listener = listen_splithttp(
            "127.0.0.1:0".parse().unwrap(),
            &settings,
            &SocketOptions::default(),
            handler,
        )
        .await
        .expect("listen h3");
        let addr = listener.local_addr().unwrap();

        // quinn + h3 客户端（自签证书 → allowInsecure）
        let client_tls = xray_tls::client_config::build_client_config(
            "tls",
            Some(&serde_json::json!({"allowInsecure": true, "alpn": ["h3"]})),
            "127.0.0.1",
        )
        .unwrap()
        .expect("client tls config");
        let quic_cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
        ));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quic_cfg);
        let conn = endpoint
            .connect(addr, "127.0.0.1")
            .unwrap()
            .await
            .expect("quic connect");
        let (mut driver, mut send_req) =
            h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let req = http::Request::builder()
            .method("GET")
            .uri("/")
            .header("host", format!("127.0.0.1:{}", addr.port()))
            .body(())
            .unwrap();
        let mut stream = send_req.send_request(req).await.unwrap();
        stream.finish().await.unwrap();

        let resp = stream.recv_response().await.expect("h3 response");
        assert_eq!(resp.status(), 200);
        let mut got = Vec::new();
        loop {
            match stream.recv_data().await {
                Ok(Some(mut chunk)) => {
                    let n = chunk.remaining();
                    got.extend_from_slice(&chunk.copy_to_bytes(n));
                }
                Ok(None) => break,
                Err(e) => panic!("h3 recv_data: {e}"),
            }
        }
        assert_eq!(got, b"hello-from-server");
        assert_eq!(count.load(Ordering::SeqCst), 1, "handler should see 1 conn");
        drop(send_req);
        drop(endpoint);
    }

    /// REALITY listener 创建 + 非 REALITY 流量 fallback：
    /// 垃圾字节 ClientHello → Invalid → 透明转发 dest（goreality.NewListener 语义）。
    #[tokio::test]
    async fn reality_listener_creation_and_fallback() {
        ensure_provider();
        // fallback dest listener
        let fb = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fb_addr = fb.local_addr().unwrap();
        let (fb_tx, fb_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut s, _) = fb.accept().await.expect("fallback accept");
            let mut buf = vec![0u8; 128];
            let n = s.read(&mut buf).await.unwrap_or(0);
            buf.truncate(n);
            let _ = fb_tx.send(buf);
        });

        let (handler, count) = greeting_handler();
        let mut settings = plain_settings();
        settings.security = "reality".into();
        settings.security_json = Some(serde_json::json!({
            "privateKey": base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode([7u8; 32]),
            "dest": format!("127.0.0.1:{}", fb_addr.port()),
            "xver": 0,
        }));
        let listener = listen_splithttp(
            "127.0.0.1:0".parse().unwrap(),
            &settings,
            &SocketOptions::default(),
            handler,
        )
        .await
        .expect("reality listener created");
        let addr = listener.local_addr().unwrap();

        // 非 REALITY 客户端：垃圾字节 → 验证失败 → fallback 转发原文
        let mut tcp = TcpStream::connect(addr).await.expect("connect");
        // 构造可完整读取但解析必失败的 ClientHello record（content_type=0x16, len=5）：
        // read_tls_record Ok → parse_client_hello Err → Invalid → fallback 转发 record 原文。
        // （纯随机垃圾若 length 字段 >16384 会让 read_tls_record 直接 Err，走 handshake
        // error 分支不 fallback——与 Go goreality 读错误即断连一致。）
        let garbage: &[u8] = &[0x16, 0x03, 0x01, 0x00, 0x05, b'G', b'A', b'R', b'B', b'A'];
        tcp.write_all(garbage).await.unwrap();
        let _ = tcp.shutdown().await;
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), fb_rx)
            .await
            .expect("fallback within 5s")
            .expect("fallback channel open");
        assert!(
            got.starts_with(garbage),
            "fallback should receive original record, got {got:?}"
        );
        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "fallback conn must not reach dispatcher"
        );
    }

    /// unix socket listen（Go hub.go:472-480 port==0 分支）。仅 unix 目标编译。
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_listen_serves_h1() {
        let path = std::env::temp_dir()
            .join(format!("xh-unix-{}.sock", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .into_owned();
        let (handler, count) = greeting_handler();
        let listener = listen_splithttp_unix(&path, &plain_settings(), &SocketOptions::default(), handler)
            .await
            .expect("unix listen");

        let mut s = tokio::net::UnixStream::connect(&path).await.expect("unix connect");
        s.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).await.unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(text.contains("200"), "unix h1 status missing: {text}");
        assert!(text.contains("hello-from-server"), "unix h1 body missing: {text}");
        assert_eq!(count.load(Ordering::SeqCst), 1);
        let _ = std::fs::remove_file(&path);
        drop(listener);
    }
}
