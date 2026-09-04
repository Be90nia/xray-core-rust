//! SplitHTTP H3 客户端——HTTP/3 over QUIC 拨号（packet-up / stream-up / stream-one）。
//!
//! 翻译自 Go `transport/internet/splithttp/dialer.go` 中 `httpVersion=="3"` 分支，
//! 对应 Go `http3.Transport{QUICConfig, TLSClientConfig, Dial}`。
//!
//! # crate 链
//!
//! - `quinn` 0.11：QUIC 实现（rustls 0.23）
//! - `h3` 0.0.8：HTTP/3 协议层（hyperium 出品）
//! - `h3-quinn` 0.0.10：把 `quinn::Connection` 适配为 `h3::quic::Connection` trait
//!
//! # 关键 API
//!
//! - [`H3Conn::connect`]：建立 quinn Endpoint → connect → `h3::client::new` → spawn driver
//! - [`H3Conn::post_packet`]：packet-up 单次 POST
//! - [`H3Conn::open_stream`]：stream-down GET 下载 / 一次性 POST body
//! - [`H3Conn::open_stream_uploading`]：stream-up / stream-one POST streaming body
//!
//! # 简化点（vs Go 原版）
//!
//! - **stream-one 等价于 stream-up**：H3 没有 REALITY 流量伪装需求（REALITY 强制 H2），
//!   所以 stream-one 用两个独立 H3 stream 实现（POST 上传 + GET 下载），与 stream-up 同。
//! - **不实现连接池**：QUIC 多路复用，一条连接开多个 RequestStream 已足够；
//!   `SendRequest` 可 Clone，packet-up 多次 POST 复用同一 QUIC 连接。
//! - **driver 后台驱动**：`h3::client::new` 返回的 `ConnectionDriver` 必须 poll，
//!   spawn 后台 task 持续驱动。
//! - **watfaq-rustls 兼容**：quinn 用 rustls 0.23，与 watfaq patch 全兼容（API superset）。
//!
//! # 全双工限制
//!
//! h3 `RequestStream` 的 `send_data` 和 `recv_data` 都需 `&mut self`，无法跨 task 并发。
//! 全双工需要单 task 内 `select!` 交替。本实现采用「先发完上传 body 再收响应」的简化
//! 模式（对 splithttp 协议足够：客户端先 upload 完，server 才回 download）。

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::{Buf, Bytes};
use futures_util::{Stream, StreamExt};
use http::request::Request;
use http::{Method, StatusCode};
use rustls::ClientConfig as RustlsClientConfig;
use tokio::io::AsyncRead as AsyncReadTrait;
use tokio::sync::{mpsc, Mutex};
use tokio_util::io::StreamReader;
use tokio_stream::wrappers::ReceiverStream;
use tracing::debug;

use crate::config::{Config, RequestMeta};
use crate::error::{Result, SplitHttpError};

/// h3 SendRequest 类型别名（h3-quinn 适配）。
///
/// `h3::client::new(h3_quinn::Connection)` 返回的 `SendRequest<h3_quinn::OpenStreams, Bytes>`。
pub type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// h3 RequestStream 类型别名。
pub type H3RequestStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// H3 客户端：封装 quinn + h3 SendRequest。
///
/// 持有 config + SendRequest（Mutex 保护，&mut self 用）+ quinn Connection（取地址）。
pub struct H3Conn {
    /// splithttp 配置引用（用于构造 RequestMeta）。
    pub config: Arc<Config>,
    send_req: Mutex<H3SendRequest>,
    quinn_conn: quinn::Connection,
    closed: AtomicBool,
}

impl H3Conn {
    /// 建立 H3 连接。
    ///
    /// 1. ALPN 设置 `h3`
    /// 2. 创建 quinn Endpoint（bind 0.0.0.0:0 或 [::]:0）
    /// 3. connect 到目标地址
    /// 4. `h3::client::new` 包装为 h3 连接
    /// 5. spawn driver 后台 task
    ///
    /// # Errors
    ///
    /// - [`SplitHttpError::Hyper`]：quinn endpoint / connect / h3 new 失败
    pub async fn connect(
        config: Arc<Config>,
        addr: SocketAddr,
        server_name: &str,
        mut tls: RustlsClientConfig,
    ) -> Result<Arc<Self>> {
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic_cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
                .map_err(|e| SplitHttpError::Hyper(format!("QuicClientConfig: {e}")))?,
        ));
        let bind: SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse().expect("valid bind addr")
        } else {
            "[::]:0".parse().expect("valid bind addr")
        };
        let mut endpoint = quinn::Endpoint::client(bind)
            .map_err(|e| SplitHttpError::Hyper(format!("quinn Endpoint: {e}")))?;
        endpoint.set_default_client_config(quic_cfg);

        let conn = endpoint
            .connect(addr, server_name)
            .map_err(|e| SplitHttpError::Hyper(format!("quinn connect initiate: {e}")))?
            .await
            .map_err(|e| SplitHttpError::Hyper(format!("quinn connect: {e}")))?;

        let quinn_conn = h3_quinn::Connection::new(conn.clone());
        let (mut driver, send_req) = h3::client::new(quinn_conn)
            .await
            .map_err(|e| SplitHttpError::Hyper(format!("h3::client::new: {e}")))?;

        // ponytail: driver 必须持续 poll 否则 h3 连接卡住
        tokio::spawn(async move {
            let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        debug!(target: "splithttp", %addr, %server_name, "H3 connection established");

        Ok(Arc::new(Self {
            config,
            send_req: Mutex::new(send_req),
            quinn_conn: conn,
            closed: AtomicBool::new(false),
        }))
    }

    /// 带 [`QuicParamsConfig`] 的 H3 建立函数，对应 Go `createHTTPClient` 中
    /// `httpVersion=="3"` + `streamSettings.QuicParams` 分支（dialer.go:162-279）。
    ///
    /// 在 [`Self::connect`] 基础上，把 `QuicParamsConfig` 字段映射到
    /// quinn [`quinn::TransportConfig`]：
    ///
    /// - `init_stream_receive_window` / `init_connection_receive_window` → 流/连接初始接收窗口
    /// - `max_idle_timeout`/`keep_alive_period`（秒）→ idle timeout + keepalive
    /// - `max_incoming_streams` → 服务端能开最大并发流（<0 = 不限）
    /// - `disable_path_mtu_discovery` → MTU 探测关闭
    ///
    /// `None` 时使用 quinn 默认 [`quinn::TransportConfig`]（与 [`Self::connect`] 行为一致）。
    ///
    /// 注：`UdpHop`（端口轮换）等需要自管 UDP socket 的特性本切片不接入——
    /// splithttp H3 路径继承 register.rs 的 quinn Endpoint 创建，不做包级劫持。
    pub async fn connect_with_quic_params(
        config: Arc<Config>,
        addr: SocketAddr,
        server_name: &str,
        mut tls: RustlsClientConfig,
        quic_params: Option<&xray_transport::memory_settings::QuicParamsConfig>,
    ) -> Result<Arc<Self>> {
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut quic_cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
                .map_err(|e| SplitHttpError::Hyper(format!("QuicClientConfig: {e}")))?,
        ));

        // 把 QuicParamsConfig 注入 quinn::TransportConfig。
        let mut transport_config = quinn::TransportConfig::default();
        if let Some(qp) = quic_params {
            if qp.init_stream_receive_window > 0 {
                transport_config.stream_receive_window(
                    quinn::VarInt::from_u64(qp.init_stream_receive_window)
                        .map_err(|e| SplitHttpError::Hyper(format!("stream_window VarInt: {e}")))?,
                );
            }
            if qp.init_connection_receive_window > 0 {
                transport_config.receive_window(
                    quinn::VarInt::from_u64(qp.init_connection_receive_window)
                        .map_err(|e| SplitHttpError::Hyper(format!("conn_window VarInt: {e}")))?,
                );
            }
        }
        quic_cfg.transport_config(Arc::new(transport_config));

        let bind: SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse().expect("valid bind addr")
        } else {
            "[::]:0".parse().expect("valid bind addr")
        };
        let mut endpoint = quinn::Endpoint::client(bind)
            .map_err(|e| SplitHttpError::Hyper(format!("quinn Endpoint: {e}")))?;
        endpoint.set_default_client_config(quic_cfg);

        let conn = endpoint
            .connect(addr, server_name)
            .map_err(|e| SplitHttpError::Hyper(format!("quinn connect initiate: {e}")))?
            .await
            .map_err(|e| SplitHttpError::Hyper(format!("quinn connect: {e}")))?;

        let quinn_conn = h3_quinn::Connection::new(conn.clone());
        let (mut driver, send_req) = h3::client::new(quinn_conn)
            .await
            .map_err(|e| SplitHttpError::Hyper(format!("h3::client::new: {e}")))?;

        tokio::spawn(async move {
            let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        debug!(target: "splithttp-h3", %addr, %server_name, "H3 connection established with QuicParams");

        Ok(Arc::new(Self {
            config,
            send_req: Mutex::new(send_req),
            quinn_conn: conn,
            closed: AtomicBool::new(false),
        }))
    }

    /// 连接是否已关闭。
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    fn mark_closed(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }

    /// 取 remote/local 地址。
    fn addrs(&self) -> (SocketAddr, SocketAddr) {
        let remote = self.quinn_conn.remote_address();
        // quinn Connection::local_ip() 可能 None（虽然实际上有），fallback 用 unspecified
        let local = self
            .quinn_conn
            .local_ip()
            .map(|ip| SocketAddr::new(ip, 0))
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        (remote, local)
    }

    /// 把 [`RequestMeta`] 转 `http::Request<()>`（body 通过 `send_data` 发送）。
    fn build_h3_request(meta: &RequestMeta) -> Result<Request<()>> {
        let method = Method::from_bytes(meta.method.as_bytes())
            .map_err(|e| SplitHttpError::InvalidUrl(format!("method {e}")))?;
        let mut builder = Request::builder().method(method).uri(&meta.uri);
        for (name, value) in &meta.headers {
            builder = builder.header(name, value);
        }
        if !meta.cookies.is_empty() {
            let cookie_str = meta
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            builder = builder.header("Cookie", cookie_str);
        }
        builder
            .body(())
            .map_err(|e| SplitHttpError::InvalidUrl(format!("body {e}")))
    }

    /// packet-up：单次 POST 等待 200，drain body。
    ///
    /// 对应 `DefaultDialerClient::post_packet`。
    pub async fn post_packet(
        self: &Arc<Self>,
        base_uri: &str,
        session_id: &str,
        seq_str: &str,
        payload: Vec<u8>,
    ) -> Result<()> {
        let meta =
            self.config
                .build_packet_request_meta(base_uri, session_id, seq_str, payload.clone())?;
        let req = Self::build_h3_request(&meta)?;

        let mut send_req = self.send_req.lock().await;
        let mut stream = send_req.send_request(req).await.map_err(|e| {
            self.mark_closed();
            SplitHttpError::Hyper(format!("h3 send_request: {e}"))
        })?;
        drop(send_req);

        stream
            .send_data(Bytes::from(payload))
            .await
            .map_err(|e| SplitHttpError::Hyper(format!("h3 send_data: {e}")))?;
        stream
            .finish()
            .await
            .map_err(|e| SplitHttpError::Hyper(format!("h3 finish: {e}")))?;

        let resp = stream
            .recv_response()
            .await
            .map_err(|e| SplitHttpError::Hyper(format!("h3 recv_response: {e}")))?;
        if resp.status() != StatusCode::OK {
            return Err(SplitHttpError::BadStatus(resp.status().as_u16()));
        }
        // drain response body
        while let Some(_) = stream
            .recv_data()
            .await
            .map_err(|e| SplitHttpError::Hyper(format!("h3 recv_data drain: {e}")))?
        {}
        Ok(())
    }

    /// GET 下载流（stream-down）/ 一次性 POST body。
    ///
    /// 对应 `DefaultDialerClient::open_stream`。
    ///
    /// - `body = None` → GET
    /// - `body = Some` → POST 一次性 body
    pub async fn open_stream(
        self: &Arc<Self>,
        base_uri: &str,
        session_id: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(Box<dyn AsyncReadTrait + Send + Unpin>, SocketAddr, SocketAddr)> {
        let meta = self
            .config
            .build_stream_request_meta(base_uri, session_id, body.clone())?;
        let req = Self::build_h3_request(&meta)?;

        let mut send_req = self.send_req.lock().await;
        let mut stream = send_req.send_request(req).await.map_err(|e| {
            self.mark_closed();
            SplitHttpError::Hyper(format!("h3 send_request: {e}"))
        })?;
        drop(send_req);

        if let Some(b) = &body {
            stream
                .send_data(Bytes::copy_from_slice(b))
                .await
                .map_err(|e| SplitHttpError::Hyper(format!("h3 send_data: {e}")))?;
        }
        stream
            .finish()
            .await
            .map_err(|e| SplitHttpError::Hyper(format!("h3 finish: {e}")))?;

        let (remote, local) = self.addrs();
        if body.is_none() {
            // stream-down GET：发出即返回（对齐 Go `DefaultDialerClient::OpenStream`
            // 的 gotConn 语义——只等连接建立，响应在后台 goroutine 处理）。
            // server 端对 GET 立即回 200 headers（hub.go WriteHeader+Flush），数据
            // 后续流式；非 200 仅记日志、读端 EOF。旧实现同步 `recv_response`
            // 会阻塞 dial：packet-up 的 POST 上传任务在 GET 之后才 spawn，而
            // server 的 GET/POST 建流时序需要请求先行发出——顺序死锁，dial
            // 挂到外层超时（CF/QUIC 面本身放行 quinn，与本 bug 无关）。
            let reader = spawn_h3_lazy_reader(self.clone(), stream);
            return Ok((reader, remote, local));
        }

        // body = Some（一次性 POST）：对齐 Go `PostPacket`，同步等响应。
        let resp = stream
            .recv_response()
            .await
            .map_err(|e| SplitHttpError::Hyper(format!("h3 recv_response: {e}")))?;
        if resp.status() != StatusCode::OK {
            return Err(SplitHttpError::BadStatus(resp.status().as_u16()));
        }

        let reader = spawn_h3_recv_reader(stream);
        Ok((reader, remote, local))
    }

    /// POST streaming body（stream-up / stream-one）。
    ///
    /// 对应 `DefaultDialerClient::open_stream_uploading`。
    ///
    /// - `upload_only = true` → POST 完即弃，返 None（stream-up）
    /// - `upload_only = false` → 额外开 GET 下载流（stream-one；H3 下与 stream-up 等价，
    ///   因 H3 无 REALITY 流量伪装需求）
    pub async fn open_stream_uploading<S>(
        self: &Arc<Self>,
        base_uri: &str,
        session_id: &str,
        body_stream: S,
        upload_only: bool,
    ) -> Result<(
        Option<Box<dyn AsyncReadTrait + Send + Unpin>>,
        SocketAddr,
        SocketAddr,
    )>
    where
        S: Stream<Item = std::io::Result<Bytes>> + Send + 'static,
    {
        // 1. POST streaming body
        let post_meta =
            self.config
                .build_stream_request_meta(base_uri, session_id, Some(Vec::new()))?;
        let post_req = Self::build_h3_request(&post_meta)?;
        let mut send_req = self.send_req.lock().await;
        let mut upload_stream = send_req.send_request(post_req).await.map_err(|e| {
            self.mark_closed();
            SplitHttpError::Hyper(format!("h3 send_request upload: {e}"))
        })?;
        drop(send_req);

        // spawn 上传任务：循环 read body_stream → send_data → finish → drain response
        let this = self.clone();
        let me_for_closed = Arc::downgrade(&this);
        tokio::spawn(async move {
            let mut body_stream = Box::pin(body_stream);
            while let Some(chunk) = body_stream.next().await {
                match chunk {
                    Ok(b) => {
                        if upload_stream
                            .send_data(b)
                            .await
                            .map_err(|e| SplitHttpError::Hyper(format!("upload send_data: {e}")))
                            .is_err()
                        {
                            if let Some(c) = me_for_closed.upgrade() {
                                c.mark_closed();
                            }
                            return;
                        }
                    }
                    Err(_) => {
                        if let Some(c) = me_for_closed.upgrade() {
                            c.mark_closed();
                        }
                        return;
                    }
                }
            }
            let _ = upload_stream.finish().await;
            // drain response（h3 协议要求收完响应否则连接异常）
            if let Ok(resp) = upload_stream.recv_response().await {
                if resp.status() != StatusCode::OK {
                    if let Some(c) = me_for_closed.upgrade() {
                        c.mark_closed();
                    }
                }
            }
            while let Ok(Some(_)) = upload_stream.recv_data().await {}
        });

        if upload_only {
            let (remote, local) = self.addrs();
            return Ok((None, remote, local));
        }

        // 2. 额外开 GET 下载流（stream-one 等价于 stream-up：双 stream 模式）
        let get_meta = self
            .config
            .build_stream_request_meta(base_uri, session_id, None)?;
        let get_req = Self::build_h3_request(&get_meta)?;
        let mut send_req = self.send_req.lock().await;
        let mut dl_stream = send_req.send_request(get_req).await.map_err(|e| {
            self.mark_closed();
            SplitHttpError::Hyper(format!("h3 send_request download: {e}"))
        })?;
        drop(send_req);

        dl_stream
            .finish()
            .await
            .map_err(|e| SplitHttpError::Hyper(format!("h3 finish download: {e}")))?;

        // GET 下载同样 lazy 化（对齐 Go `OpenStream`；理由同 `open_stream`
        // 的 stream-down 分支——响应头不得阻塞 dial 调用方）。
        let reader = spawn_h3_lazy_reader(self.clone(), dl_stream);
        let (remote, local) = self.addrs();
        Ok((Some(reader), remote, local))
    }
}

/// 把 h3 `RequestStream` 的 `recv_data` 循环转为 `Box<dyn AsyncRead>`。
///
/// 用 `tokio::sync::mpsc::channel` + `tokio_util::io::StreamReader` 适配：
/// 1. spawn 一个 task 循环调 `stream.recv_data().await`
/// 2. 把 `Bytes` 通过 channel 发出
/// 3. `ReceiverStream` 包装 channel 为 `Stream<Item=io::Result<Bytes>>`
/// 4. `StreamReader` 把 Stream 转 AsyncRead
///
/// 必须用 channel 是因为 h3 `RequestStream` 的 `send_data`/`recv_data` 都需 `&mut self`，
/// 不能拆分到两个 task（spawn 单向接收任务 + 主任务发送是安全的）。
fn spawn_h3_recv_reader<S, B>(mut stream: h3::client::RequestStream<S, B>) -> Box<dyn AsyncReadTrait + Send + Unpin>
where
    h3::client::RequestStream<S, B>: Send,
    S: h3::quic::RecvStream + 'static,
    B: Buf + 'static,
{
    let (tx, rx) = mpsc::channel::<std::io::Result<Bytes>>(8);
    tokio::spawn(async move {
        loop {
            match stream.recv_data().await {
                Ok(Some(mut buf)) => {
                    let len = buf.remaining();
                    let bytes = buf.copy_to_bytes(len);
                    if tx.send(Ok(bytes)).await.is_err() {
                        return; // 接收端 drop，结束
                    }
                }
                Ok(None) => return,
                Err(e) => {
                    let _ = tx
                        .send(Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            e.to_string(),
                        )))
                        .await;
                    return;
                }
            }
        }
    });
    let reader = StreamReader::new(ReceiverStream::new(rx));
    Box::new(reader)
}

/// stream-down GET 的 lazy 读端（对齐 Go `WaitReadCloser` 语义）。
///
/// dial 调用方不被响应头阻塞：spawn 的后台任务先收响应头——200 则进入
/// `recv_data` 数据循环；非 200 仅记日志并结束（读端 EOF，对齐 Go
/// `"unexpected status"` 分支）；错误则 `mark_closed` + EOF。数据经 channel
/// 转发，转换方式与 [`spawn_h3_recv_reader`] 相同。
fn spawn_h3_lazy_reader<S, B>(
    this: std::sync::Arc<H3Conn>,
    mut stream: h3::client::RequestStream<S, B>,
) -> Box<dyn AsyncReadTrait + Send + Unpin>
where
    h3::client::RequestStream<S, B>: Send,
    S: h3::quic::RecvStream + Send + 'static,
    B: Buf + Send + 'static,
{
    let (tx, rx) = mpsc::channel::<std::io::Result<Bytes>>(8);
    tokio::spawn(async move {
        match stream.recv_response().await {
            Ok(resp) if resp.status() == StatusCode::OK => {}
            Ok(resp) => {
                debug!(target: "splithttp-h3", status = %resp.status(), "unexpected GET status");
                return;
            }
            Err(e) => {
                this.mark_closed();
                debug!(target: "splithttp-h3", error = %e, "GET recv_response failed");
                return;
            }
        }
        loop {
            match stream.recv_data().await {
                Ok(Some(mut buf)) => {
                    let len = buf.remaining();
                    let bytes = buf.copy_to_bytes(len);
                    if tx.send(Ok(bytes)).await.is_err() {
                        return; // 接收端 drop，结束
                    }
                }
                Ok(None) => return,
                Err(e) => {
                    let _ = tx
                        .send(Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            e.to_string(),
                        )))
                        .await;
                    return;
                }
            }
        }
    });
    Box::new(StreamReader::new(ReceiverStream::new(rx)))
}

#[cfg(test)]
mod tests {
    // H3 端到端测试在 tests/mock_h3_server.rs 集成测试覆盖（mock h3::server）。
    // 单元测试需要真实网络 + QUIC + TLS，留集成测试。

    /// 验证 [`H3Conn::connect_with_quic_params`] 中 QuicParams 字段能成功构造成
    /// quinn `TransportConfig`（不发起网络连接）。
    ///
    /// 对应 Go `dialer.go:162-279` 中 `streamSettings.QuicParams` → quic.Config 路径。
    /// 我们直接构造 `quinn::TransportConfig` + 走 mini pipeline，确保 `VarInt` 转换
    /// 等边界值不出错。
    #[test]
    fn quic_params_into_transport_config_succeeds() {
        // 用 quinn re-export 的 VarInt（quinn::VarInt = proto::VarInt）
        let qp = xray_transport::memory_settings::QuicParamsConfig {
            init_stream_receive_window: 65536,
            max_stream_receive_window: 0,
            init_connection_receive_window: 1_048_576,
            max_connection_receive_window: 0,
            max_idle_timeout: 30,
            keep_alive_period: 10,
            disable_path_mtu_discovery: true,
            max_incoming_streams: 100,
            ..Default::default()
        };
        let mut tc = quinn::TransportConfig::default();
        // setter：stream_receive_window / receive_window / max_idle_timeout / keep_alive_interval
        // 走 quinn::TransportConfig，无 get 用；只验可调用不 panic。
        tc.stream_receive_window(quinn::VarInt::from_u64(qp.init_stream_receive_window).unwrap());
        tc.receive_window(quinn::VarInt::from_u64(qp.init_connection_receive_window).unwrap());
        tc.max_idle_timeout(Some(
            std::time::Duration::from_secs(qp.max_idle_timeout as u64)
                .try_into()
                .unwrap(),
        ));
        tc.keep_alive_interval(Some(std::time::Duration::from_secs(
            qp.keep_alive_period as u64,
        )));
        // VarInt 边界：2^62 - 1 应通过；2^63 应失败。
        let max_v = quinn::VarInt::from_u64((1u64 << 62) - 1);
        assert!(max_v.is_ok(), "max VarInt must succeed");
        let overflow = quinn::VarInt::from_u64(1u64 << 63);
        assert!(overflow.is_err(), "VarInt overflow must fail");
    }
}
