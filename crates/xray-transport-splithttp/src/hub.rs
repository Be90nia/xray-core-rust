//! SplitHTTP 服务端 hub（inbound listener）。
//!
//! 对应 Go `transport/internet/splithttp/hub.go` 的 `Listen` + `requestHandler`。
//!
//! ## 架构
//!
//! ```text
//! HTTP client ──POST──→ [hub handler] ──push──→ UploadQueue (per session)
//!                                               ↓
//!                          [forwarder task] ←───┘
//!                               ↓
//!                    ServerConn.reader ──→ dispatcher
//!                    ServerConn.writer ←── dispatcher
//!                               ↓
//!                    [response task] ──→ HTTP GET response ──→ client download
//! ```
//!
//! 三种模式：
//! - **packet-up**：POST `{path}/{session}/{seq}`，body = 单包 payload → push 到 UploadQueue
//! - **stream-up**：POST `{path}/{session}` (无 seq)，body = 流式上传 → push 流式 Reader
//! - **stream-down**：GET `{path}/{session}` → 创建 ServerConn 交给 dispatcher，
//!   reader=UploadQueue（上行数据），writer=HTTP response body（下行数据）
//! - **stream-one**：GET `{path}` (无 session) → 类似 stream-down 但无 session

pub mod handler;
pub mod meta;
pub mod session;

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

pub use meta::RequestMetaInfo;
pub use session::{HttpSession, SessionMap};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener as TokioTcpListener,
};

use crate::{
    config::Config,
    error::{Result, SplitHttpError},
};

/// 服务端连接：reader（上行数据）+ writer（下行数据）+ 地址元数据。
///
/// 对应 Go `splitConn`。dispatcher 通过 reader 读客户端上传数据（来自 UploadQueue），
/// 通过 writer 写下行数据（转发到 HTTP GET response body）。
///
/// `close_signal`：服务端 GET 断开（会话终结）时置位，ServerConn 的 poll_read
/// 随即注入 EOF——对齐 Go hub.go:399 GET handler 退出时的 `conn.Close()`：
/// 客户端断开后整个 splitConn 必须立即终结，而非滞留至 dispatcher 的
/// ConnectionIdle（默认 300s）超时。
#[derive(Clone)]
pub struct ServerConnCloseSignal {
    flag: Arc<std::sync::atomic::AtomicBool>,
    notify: Arc<tokio::sync::Notify>,
}

impl ServerConnCloseSignal {
    /// 创建配对的关闭信号（一个给 ServerConn，一个给守护方）。
    #[must_use]
    pub fn new() -> (Self, Self) {
        let a = Self {
            flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            notify: Arc::new(tokio::sync::Notify::new()),
        };
        let b = a.clone();
        (a, b)
    }

    /// 触发关闭（幂等）：唤醒所有等待中的 poll_read。
    pub fn close(&self) {
        self.flag.store(true, std::sync::atomic::Ordering::Release);
        self.notify.notify_waiters();
    }

    fn poll_closed(&mut self, cx: &mut Context<'_>) -> bool {
        if self.flag.load(std::sync::atomic::Ordering::Acquire) {
            return true;
        }
        // 注册 waiter：close() 的 notify_waiters 会唤醒本 poll_read。
        let notified = self.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().poll(cx).is_ready()
    }
}

pub struct ServerConn {
    /// 上行数据 reader（UploadQueue → dispatcher）。
    pub reader: Box<dyn AsyncRead + Unpin + Send>,
    /// 下行数据 writer（dispatcher → HTTP response body）。
    pub writer: Box<dyn AsyncWrite + Unpin + Send>,
    /// 远端地址。
    pub remote_addr: SocketAddr,
    /// 本地地址。
    pub local_addr: SocketAddr,
    /// 会话终结信号（server GET 断开 → 上行读注入 EOF）。
    pub close_signal: ServerConnCloseSignal,
}

impl AsyncRead for ServerConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.close_signal.poll_closed(cx) {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut *self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for ServerConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.writer).poll_shutdown(cx)
    }
}

/// 新连接回调（对应 Go `internet.ConnHandler`）。
///
/// 每次 GET（stream-down / stream-one）请求到达时调用，把 ServerConn 交给上层 dispatcher。
pub trait HubConnHandler: Send + Sync {
    /// 接收新连接。dispatcher 在此方法返回后开始读写 ServerConn。
    fn add_conn(&self, conn: ServerConn);
}

/// SplitHTTP 服务端 listener。对应 Go `Listener struct`。
pub struct HubListener {
    config: Arc<Config>,
    tcp_listener: TokioTcpListener,
    local_addr: SocketAddr,
    sessions: Arc<SessionMap>,
    conn_handler: Arc<dyn HubConnHandler>,
}

impl HubListener {
    /// 绑定 TCP 地址并构造 listener。对应 Go `ListenXH` 的 TCP 分支。
    ///
    /// # Errors
    /// - [`SplitHttpError::ListenFailed`]：TCP bind 失败
    pub async fn bind(
        addr: SocketAddr,
        config: Arc<Config>,
        conn_handler: Arc<dyn HubConnHandler>,
    ) -> Result<Self> {
        let tcp_listener = TokioTcpListener::bind(addr)
            .await
            .map_err(|e| SplitHttpError::ListenFailed(e.to_string()))?;
        let local_addr =
            tcp_listener.local_addr().map_err(|e| SplitHttpError::ListenFailed(e.to_string()))?;
        Ok(Self {
            config,
            tcp_listener,
            local_addr,
            sessions: Arc::new(SessionMap::new()),
            conn_handler,
        })
    }

    /// 监听器本地地址。
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// 运行 accept 循环（消费 self）。每个 TCP 连接 spawn 一个 hyper http1 服务。
    ///
    /// 返回条件：listener 被关闭（IO 错误）。
    pub async fn serve(self) -> Result<()> {
        let ctx = Arc::new(handler::HandlerContext {
            config: Arc::clone(&self.config),
            host: self.config.host.clone(),
            base_path: self.config.normalized_path(),
            local_addr: self.local_addr,
            sessions: Arc::clone(&self.sessions),
            conn_handler: Arc::clone(&self.conn_handler),
            max_buffered_posts: self.config.normalized_sc_max_buffered_posts() as usize,
            sc_max_each_post_bytes: self.config.normalized_sc_max_each_post_bytes().to as usize,
        });
        loop {
            let (stream, peer_addr) = match self.tcp_listener.accept().await {
                Ok(conn) => conn,
                Err(e) => return Err(SplitHttpError::ListenFailed(e.to_string())),
            };
            let io = hyper_util::rt::TokioIo::new(stream);
            let ctx = Arc::clone(&ctx);
            tokio::spawn(async move {
                use hyper::service::service_fn;
                let svc = service_fn(move |req| {
                    let ctx = Arc::clone(&ctx);
                    async move {
                        Ok::<_, std::convert::Infallible>(
                            handler::handle_request(req, peer_addr, &ctx).await,
                        )
                    }
                });
                // 自动协商 H1/H2：H2 preface 检测，回退到 H1
                let builder = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                );
                let _ = builder.serve_connection(io, svc).await;
            });
        }
    }
}
