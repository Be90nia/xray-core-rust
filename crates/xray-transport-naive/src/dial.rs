//! naive 出站拨号：TCP → btls Chrome 指纹 TLS → h2 CONNECT → padding 流。
//!
//! 对应 naiveproxy 客户端（Cronet HTTP/2 CONNECT 隧道）：
//! 1. TCP 连接服务器
//! 2. btls uTLS 握手（证书不验证——鉴权全在 `Proxy-Authorization`）
//! 3. hyper h2 客户端握手（ALPN h2 由 Chrome 指纹协商）
//! 4. CONNECT authority-form 请求 + `padding`/`padding-type-request`/ `Proxy-Authorization: Basic`
//!    头
//! 5. 200 响应含 `padding` 头 → 双向首 8 帧帧化，否则直通
//!
//! 隧道上下行经 hyper 的 CONNECT-upgrade（`OnUpgrade`）交付：h2 层收到 200
//! 后把 h2 流的收发两端打包成 `Upgraded`（hyper 不支持 CONNECT 请求体——
//! 请求 body 会被直接丢弃，上行数据必须写 `Upgraded`）。

use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use bytes::Bytes;
use http::{Method, StatusCode, header::HeaderValue};
use hyper::{
    client::conn::http2,
    upgrade::{OnUpgrade, Upgraded},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use xray_common::net::{address::Address, destination::Destination, network::Network, port::Port};
use xray_tls::btls_client::BtlsConn;
use xray_transport::{connection::Connection, sockopt::SocketOptions, system_dialer::dial_system};

use crate::{
    padding::{
        FIRST_PADDINGS, PaddingDecoder, encode_frame, random_padding_header, random_padding_size,
    },
    uri::NaiveConfig,
};

/// Chrome 桌面 UA（对齐 naiveproxy 默认 extra headers 场景）。
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36";

/// 建立 naive 隧道（CONNECT authority-form 指向 `target_host:target_port`）。
///
/// # Errors
/// TCP/TLS/h2 握手失败或 CONNECT 非 200 时返回 `Err(String)`。
pub async fn dial_naive(
    config: &NaiveConfig,
    target_host: &str,
    target_port: u16,
) -> Result<Box<dyn Connection>, String> {
    let server_dest = Destination::new(
        Address::Domain(config.host.clone()),
        Port::new(config.port),
        Network::TCP,
    );
    let tcp = dial_system(&server_dest, &SocketOptions::default())
        .await
        .map_err(|e| format!("naive tcp dial {}: {e}", config.host))?;
    // 回接证书验证（Xray-core-rust-pz6c）：naive 连接真实公网站点，默认完整
    // 链+主机名验证（webpki-roots，对应 naiveproxy/Go 标准行为）；naive 的
    // 鉴权在 Proxy-Authorization，不构成跳过 TLS 验证的理由。
    // pinnedPeerCertSha256 配置时走 PinnedServerCertVerifier（自签互操作场景）。
    let security_json = config
        .pinned_peer_cert_sha256
        .as_deref()
        .map(|pin| serde_json::json!({ "pinnedPeerCertSha256": pin }));
    let tls = BtlsConn::connect(
        tcp,
        &config.sni,
        config.fingerprint,
        None, // ECH（naive 不用）
        Some(
            xray_tls::client_config::build_server_cert_verifier(security_json.as_ref())
                .map_err(|e| format!("build verifier: {e}"))?
                .expect("non-insecure config yields a verifier"),
        ),
    )
    .await
    .map_err(|e| format!("naive tls handshake (sni={}): {e}", config.sni))?;
    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
        .await
        .map_err(|e| format!("naive h2 handshake: {e}"))?;

    // h2 连接驱动：hyper 的 conn future 必须被持续 poll（后台任务 1）。
    let driver = tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(target: "naive", error = %e, "h2 connection driver ended");
        }
    });

    let authority = format!("{target_host}:{target_port}");
    let req = build_connect_request(&authority, config)?;
    let resp =
        sender.send_request(req).await.map_err(|e| format!("naive CONNECT {authority}: {e}"))?;
    if resp.status() != StatusCode::OK {
        return Err(format!("naive CONNECT {authority}: HTTP {}", resp.status().as_u16()));
    }
    // 响应含 padding 头 → 服务端支持 kVariant1，双向首 8 帧帧化
    let padded = resp.headers().contains_key("padding");

    // hyper 对 CONNECT 200：双向流经 OnUpgrade 交付（响应 body 恒为空）。
    let on_upgrade = resp
        .extensions()
        .get::<OnUpgrade>()
        .cloned()
        .ok_or_else(|| format!("naive CONNECT {authority}: no upgrade extension"))?;
    drop(resp);

    // SendRequest 保活到 driver 结束（后台任务 2）：drop 它即通知 hyper
    // 优雅关闭整条 h2 连接（graceful GOAWAY 会终止活跃 CONNECT 流）。
    tokio::spawn(async move {
        let _keep_alive = sender;
        let _ = driver.await;
    });

    let upgraded =
        on_upgrade.await.map_err(|e| format!("naive CONNECT {authority}: upgrade failed: {e}"))?;
    let (rd, wr) = tokio::io::split(UpgradeConn(Arc::new(Mutex::new(TokioIo::new(upgraded)))));
    let tunnel = NaiveConn {
        reader: PaddingReader::new(rd, padded),
        writer: PaddingWriter::new(wr, padded),
    };
    tracing::debug!(target: "naive", %authority, padded, "naive tunnel established");
    Ok(Box::new(tunnel))
}

/// 永不出数据也不结束的 CONNECT 请求 body。
///
/// h2 CONNECT 隧道流在隧道关闭前不得 END_STREAM（RFC 9113 §8.5）——
/// `Empty` body 会让 hyper 在 HEADERS 上置 END_STREAM，服务端 request body
/// 立即 EOF、上行断链。上行数据走 `Upgraded`（`dial_naive` 注释所述）。
struct NeverEndingBody;

impl hyper::body::Body for NeverEndingBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        Poll::Pending
    }
}

fn build_connect_request(
    authority: &str,
    config: &NaiveConfig,
) -> Result<http::Request<NeverEndingBody>, String> {
    let auth: http::uri::Authority =
        authority.parse().map_err(|e| format!("naive authority {authority}: {e}"))?;
    let uri = http::Uri::builder()
        .authority(auth)
        .build()
        .map_err(|e| format!("naive uri {authority}: {e}"))?;
    let padding = HeaderValue::from_str(&random_padding_header())
        .map_err(|e| format!("naive padding header: {e}"))?;
    let credentials = B64.encode(format!("{}:{}", config.username, config.password));
    let proxy_auth = HeaderValue::from_str(&format!("Basic {credentials}"))
        .map_err(|e| format!("naive auth header: {e}"))?;
    http::Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .header("padding", padding)
        .header("padding-type-request", HeaderValue::from_static("1"))
        .header(http::header::PROXY_AUTHORIZATION, proxy_auth)
        .header(http::header::USER_AGENT, HeaderValue::from_static(USER_AGENT))
        .body(NeverEndingBody)
        .map_err(|e| format!("naive build request: {e}"))
}

/// `Upgraded` 的 `Sync` 包装（hyper `Upgraded` 仅 `Send`，而
/// [`Connection`] 要求 `Sync`；锁只在 poll 同步段内短暂持有，不跨 await）。
struct UpgradeConn(Arc<Mutex<TokioIo<Upgraded>>>);

impl AsyncRead for UpgradeConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        Pin::new(&mut *g).poll_read(cx, out)
    }
}

impl AsyncWrite for UpgradeConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        Pin::new(&mut *g).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        Pin::new(&mut *g).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        Pin::new(&mut *g).poll_shutdown(cx)
    }
}

// ============================================================
// 读端：首 8 帧解码，之后直通
// ============================================================

/// 响应流 padding 解码器。
pub struct PaddingReader<R> {
    inner: R,
    decoder: PaddingDecoder,
    /// 原始输入缓冲（未解码字节；`done` 后为直通残余）。
    buf: Vec<u8>,
    rdbuf: Vec<u8>,
    /// 已解码待交付 payload。
    pending: Vec<u8>,
    pending_pos: usize,
    /// 解满 [`FIRST_PADDINGS`] 帧 → 直通。
    done: bool,
    eof: bool,
}

impl<R> PaddingReader<R> {
    pub fn new(inner: R, enabled: bool) -> Self {
        Self {
            inner,
            decoder: PaddingDecoder::default(),
            buf: Vec::new(),
            rdbuf: vec![0u8; 16 * 1024],
            pending: Vec::new(),
            pending_pos: 0,
            done: !enabled,
            eof: false,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for PaddingReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            // 1. 已解码 payload
            if this.pending_pos < this.pending.len() {
                let n = (this.pending.len() - this.pending_pos).min(out.remaining());
                out.put_slice(&this.pending[this.pending_pos..this.pending_pos + n]);
                this.pending_pos += n;
                if this.pending_pos == this.pending.len() {
                    this.pending.clear();
                    this.pending_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            // 2. 直通残余 / 直读
            if this.done || this.eof {
                if !this.buf.is_empty() {
                    let n = this.buf.len().min(out.remaining());
                    out.put_slice(&this.buf[..n]);
                    this.buf.drain(..n);
                    return Poll::Ready(Ok(()));
                }
                if this.done {
                    return Pin::new(&mut this.inner).poll_read(cx, out);
                }
                // EOF 且缓冲耗尽
                return Poll::Ready(Ok(()));
            }
            // 3. 帧化阶段：读 inner → 解码
            let mut rb = ReadBuf::new(&mut this.rdbuf);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rb)? {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => {
                    if rb.filled().is_empty() {
                        this.eof = true;
                    } else {
                        this.buf.extend_from_slice(rb.filled());
                        if this.decoder.decode(&mut this.buf, &mut this.pending) {
                            this.done = true;
                        }
                    }
                },
            }
        }
    }
}

// ============================================================
// 写端：首 8 次写入各成一帧，之后直通
// ============================================================

/// 请求流 padding 编码器。
///
/// ponytail: naiveproxy 对 200<payload<1024 的帧再做 100-200 字节随机
/// 分段写（仅影响本地 TCP 分段，线上字节流一致），不移植。
pub struct PaddingWriter<W> {
    inner: W,
    frames_written: u32,
    /// 当前待排空帧。
    frame: Vec<u8>,
    frame_pos: usize,
    user_len: usize,
    /// 当前帧尚未排空完成（`poll_write` Pending 重入时不得重新编码）。
    frame_pending: bool,
}

impl<W: AsyncWrite + Unpin> PaddingWriter<W> {
    pub fn new(inner: W, enabled: bool) -> Self {
        Self {
            inner,
            frames_written: if enabled { 0 } else { FIRST_PADDINGS },
            frame: Vec::new(),
            frame_pos: 0,
            user_len: 0,
            frame_pending: false,
        }
    }

    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.frame_pos < self.frame.len() {
            let n =
                ready!(Pin::new(&mut self.inner).poll_write(cx, &self.frame[self.frame_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.frame_pos += n;
        }
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for PaddingWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.frames_written >= FIRST_PADDINGS {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        if this.frame_pending {
            // tokio 重入契约：上次 Pending 时本 buf 的帧还没写完——继续排空，
            // 排完即本次 write 成功。重新 encode 会把 payload 发两遍。
            ready!(this.drain(cx))?;
            this.frame_pending = false;
            return Poll::Ready(Ok(this.user_len));
        }
        let padding = random_padding_size(buf.len());
        let (frame, consumed) = encode_frame(buf, padding);
        this.frame = frame;
        this.frame_pos = 0;
        this.user_len = consumed;
        this.frames_written += 1;
        this.frame_pending = true;
        ready!(this.drain(cx))?;
        this.frame_pending = false;
        Poll::Ready(Ok(this.user_len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().inner).poll_shutdown(cx)
    }
}

// ============================================================
// NaiveConn：reader + writer 组合
// ============================================================

/// naive 隧道连接（`Box<dyn Connection>` 上抛）。
pub struct NaiveConn<R, W> {
    reader: PaddingReader<R>,
    writer: PaddingWriter<W>,
}
impl<R, W> NaiveConn<R, W> {
    /// 从 padding reader/writer 组合（入站 mock 直连路径复用）。
    pub fn new(reader: PaddingReader<R>, writer: PaddingWriter<W>) -> Self {
        Self { reader, writer }
    }
}
impl<R: AsyncRead + Unpin, W: Unpin> AsyncRead for NaiveConn<R, W> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().reader).poll_read(cx, out)
    }
}
impl<R: Unpin, W: AsyncWrite + Unpin> AsyncWrite for NaiveConn<R, W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.as_mut().writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().writer).poll_shutdown(cx)
    }
}
impl<R, W> Connection for NaiveConn<R, W>
where
    R: AsyncRead + Unpin + Send + Sync,
    W: AsyncWrite + Unpin + Send + Sync,
{
    fn remote_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        Ok(None)
    }

    fn local_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;

    use super::*;

    /// 双工回环：PaddingWriter 写 12 块（8 帧 + 4 直通）→ PaddingReader 读回逐字节一致。
    #[tokio::test]
    async fn padding_roundtrip_over_duplex() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client, server) = duplex(64 * 1024);
        let chunks: Vec<Vec<u8>> =
            (0..12).map(|i| vec![b'a' + i; 700 + (i as usize) * 13]).collect();
        let expected: Vec<u8> = chunks.concat();

        let writer_task = tokio::spawn(async move {
            let mut w = PaddingWriter::new(client, true);
            for c in &chunks {
                w.write_all(c).await.unwrap();
            }
            w.shutdown().await.unwrap();
        });
        let mut r = PaddingReader::new(server, true);
        let mut got = Vec::new();
        r.read_to_end(&mut got).await.unwrap();
        writer_task.await.unwrap();
        assert_eq!(got, expected);
    }
}
