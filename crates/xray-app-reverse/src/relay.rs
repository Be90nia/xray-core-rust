//! 反向代理数据流（yamux 多路复用模式）。
//!
//! Bridge（客户端）：单条 TCP 连接到 portal，上面承载多个并发子流。
//! Portal（服务端）：接受 bridge 连接 → yamux → 路由每个子流到 outbound。
//!
//! ## 数据流
//!
//! ```text
//! [用户连接] → [Bridge] ──TCP(yamux)──▶ [Portal] → [Outbound] → [目标]
//!                            │ 子流1 ────────────────▶
//!                            │ 子流2 ────────────────▶
//!                            │ 子流N ────────────────▶
//! ```
//!
//! 使用 paritytech/yamux crate，线格式与 Go hashicorp/yamux 完全互通。
//!
//! ## yamux 0.14 驱动模型
//!
//! yamux `Connection` 使用手动 poll API（`poll_next_inbound` / `poll_new_outbound`），
//! 必须持续调用 `poll_next_inbound` 来驱动连接（处理入站帧、窗口更新、ping/pong）。
//! 我们在后台 task 中用 `std::future::poll_fn` 轮询驱动。
//!
//! Bridge/Portal 两侧的 TCP 均为 tokio 类型，yamux 使用 futures trait，
//! 通过 `tokio_util::compat` 适配层桥接。

use std::io;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

/// yamux 子流（tokio `AsyncRead` + `AsyncWrite`）。
///
/// 由 [`YamuxBridge::open_stream`] 返回 / 传递给 [`serve_portal`] 回调。
/// 底层是 yamux `Stream` 经 compat 适配后的 tokio I/O 对象。
pub type MuxStream = Compat<yamux::Stream>;

/// tokio TcpStream 经 compat 后的类型（yamux `Connection` 的底层 I/O）。
type CompatTcp = Compat<TcpStream>;

// ---------------------------------------------------------------------------
// Bridge（客户端）
// ---------------------------------------------------------------------------

/// Bridge 客户端：通过单条 TCP（yamux 会话）连接 portal，提供并发子流开启能力。
///
/// 对应 Go `app/reverse/bridge.go` 的 `BridgeWorker`——在单条 yamux 会话上
/// 承载所有入站连接的子流。
pub struct YamuxBridge {
    /// 向驱动 task 发送 open-stream 请求。
    open_tx: mpsc::Sender<oneshot::Sender<io::Result<MuxStream>>>,
}

impl YamuxBridge {
    /// 连接 portal，建立 yamux 会话，启动后台驱动 task。
    pub async fn connect(portal_addr: String) -> io::Result<Self> {
        let tcp = TcpStream::connect(&portal_addr).await?;
        tcp.set_nodelay(true).ok();
        Self::connect_on(tcp).await
    }

    /// 在已有 TCP 连接上建立 yamux 客户端会话（测试 / 已有连接复用）。
    pub async fn connect_on(tcp: TcpStream) -> io::Result<Self> {
        let conn = yamux::Connection::new(tcp.compat(), yamux::Config::default(), yamux::Mode::Client);
        let (open_tx, open_rx) = mpsc::channel(64);
        tokio::spawn(drive_bridge(conn, open_rx));
        Ok(Self { open_tx })
    }

    /// 在 yamux 会话上打开一个新子流。
    ///
    /// 多次调用复用同一 TCP 连接——这是与 Go 版一致的多路复用行为。
    pub async fn open_stream(&self) -> io::Result<MuxStream> {
        let (tx, rx) = oneshot::channel();
        self.open_tx
            .send(tx)
            .await
            .map_err(|_| io::Error::other("bridge driver stopped"))?;
        rx.await
            .map_err(|_| io::Error::other("bridge driver dropped reply"))?
    }
}

/// Bridge 驱动 task：轮询 yamux 连接（驱动帧处理），同时响应 open-stream 请求。
///
/// `poll_next_inbound` 即使在 Bridge 端（不期望入站子流）也必须持续调用——
/// 它是连接状态机的唯一驱动力（刷新写缓冲、处理窗口更新、ping/pong）。
async fn drive_bridge(
    mut conn: yamux::Connection<CompatTcp>,
    mut open_rx: mpsc::Receiver<oneshot::Sender<io::Result<MuxStream>>>,
) {
    enum Action {
        Done,
        Open(oneshot::Sender<io::Result<MuxStream>>),
    }

    loop {
        // 单次 poll 同时驱动连接 + 检查 open 请求，避免双重 &mut conn 借用。
        let action = std::future::poll_fn(|cx: &mut Context<'_>| -> Poll<Action> {
            // 先排空入站子流（Bridge 端不应有，但安全丢弃）。
            loop {
                match conn.poll_next_inbound(cx) {
                    Poll::Ready(None) | Poll::Ready(Some(Err(_))) => return Poll::Ready(Action::Done),
                    Poll::Ready(Some(Ok(_))) => continue, // 丢弃意外的入站子流
                    Poll::Pending => break,
                }
            }
            // 检查 open-stream 请求。
            match open_rx.poll_recv(cx) {
                Poll::Ready(None) => Poll::Ready(Action::Done),
                Poll::Ready(Some(req)) => Poll::Ready(Action::Open(req)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await;

        match action {
            Action::Done => break,
            Action::Open(req) => {
                // poll_new_outbound 仅创建 stream handle（无 socket I/O），立即返回。
                let result = std::future::poll_fn(|cx| conn.poll_new_outbound(cx))
                    .await
                    .map(|s| s.compat())
                    .map_err(map_yamux_err);
                let _ = req.send(result);
            }
        }
    }
    tracing::debug!("bridge yamux driver exited");
}

// ---------------------------------------------------------------------------
// Portal（服务端）
// ---------------------------------------------------------------------------

/// Portal 服务端：接受 bridge 连接，为每个 yamux 子流调用 `on_stream` 路由。
///
/// 每个 bridge TCP 连接建立一个 yamux 会话，其上所有子流共享该 TCP。
/// 对应 Go `app/reverse/portal.go` 的 `Portal` + `PortalWorker`。
pub async fn serve_portal<F, Fut>(listener: TcpListener, on_stream: F) -> io::Result<()>
where
    F: Fn(MuxStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let on_stream = Arc::new(on_stream);
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "portal accept error");
                continue;
            }
        };
        tcp.set_nodelay(true).ok();

        let cb = Arc::clone(&on_stream);
        tokio::spawn(async move {
            tracing::debug!(peer = %peer, "portal bridge connected");
            let conn =
                yamux::Connection::new(tcp.compat(), yamux::Config::default(), yamux::Mode::Server);
            drive_portal(conn, cb).await;
            tracing::debug!(peer = %peer, "portal bridge session done");
        });
    }
}

/// Portal 驱动：在单个 yamux 会话上接受子流，每个子流交给 `on_stream`。
async fn drive_portal<F, Fut>(mut conn: yamux::Connection<CompatTcp>, on_stream: Arc<F>)
where
    F: Fn(MuxStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    loop {
        match std::future::poll_fn(|cx| conn.poll_next_inbound(cx)).await {
            None => break,
            Some(Err(e)) => {
                tracing::debug!(error = ?e, "portal yamux session error");
                break;
            }
            Some(Ok(stream)) => {
                let cb = Arc::clone(&on_stream);
                tokio::spawn(async move {
                    cb(stream.compat()).await;
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 错误映射
// ---------------------------------------------------------------------------

/// yamux `ConnectionError` → `io::Error`。
fn map_yamux_err(e: yamux::ConnectionError) -> io::Error {
    io::Error::other(e)
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn bridge_type_exists() {
        fn _assert_bridge(_b: YamuxBridge) {}
    }

    #[tokio::test]
    async fn portal_echo_single_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            serve_portal(listener, |sock| async move {
                let (mut rd, mut wr) = tokio::io::split(sock);
                tokio::io::copy(&mut rd, &mut wr).await.ok();
            })
            .await
            .ok();
        });

        let bridge = YamuxBridge::connect(addr.to_string()).await.unwrap();
        let mut sock = bridge.open_stream().await.unwrap();
        sock.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        sock.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    /// 单 TCP 多流验证：3 个并发子流在同一个 bridge 连接上独立 echo。
    #[tokio::test]
    async fn portal_multiplex_multiple_streams() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            serve_portal(listener, |sock| async move {
                let (mut rd, mut wr) = tokio::io::split(sock);
                tokio::io::copy(&mut rd, &mut wr).await.ok();
            })
            .await
            .ok();
        });

        let bridge = Arc::new(YamuxBridge::connect(addr.to_string()).await.unwrap());

        // 3 个并发子流，各自写不同 payload 并验证 echo 回环。
        let mut handles = Vec::new();
        for i in 0u8..3 {
            let b = Arc::clone(&bridge);
            handles.push(tokio::spawn(async move {
                let mut sock = b.open_stream().await.expect("open_stream");
                let payload = vec![i + 1; 128];
                sock.write_all(&payload).await.expect("write");
                let mut buf = vec![0u8; 128];
                sock.read_exact(&mut buf).await.expect("read");
                assert_eq!(buf, payload, "stream {i} echo mismatch");
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    }

    /// 验证多个 open_stream 复用同一 TCP：在 accept 层面计数，
    /// 3 个子流应只产生 1 次 TCP accept。
    #[tokio::test]
    async fn portal_streams_share_one_tcp() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let tcp_count = Arc::new(AtomicU32::new(0));
        let tc = Arc::clone(&tcp_count);

        // 手动 accept 循环：计数 TCP 连接，每条建立 yamux server 会话。
        tokio::spawn(async move {
            loop {
                let (tcp, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                tc.fetch_add(1, Ordering::SeqCst);
                let conn = yamux::Connection::new(
                    tcp.compat(),
                    yamux::Config::default(),
                    yamux::Mode::Server,
                );
                tokio::spawn(drive_portal(conn, Arc::new(echo_fn)));
            }
        });

        // bridge 只连接 1 次（= 1 TCP），然后开 3 个子流。
        let bridge = Arc::new(YamuxBridge::connect(addr.to_string()).await.unwrap());
        for i in 0u8..3 {
            let mut sock = bridge.open_stream().await.unwrap();
            sock.write_all(&[i]).await.unwrap();
            let mut buf = [0u8; 1];
            sock.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, [i]);
        }


        // 等待可能的额外 accept 注册（不应有）。
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        assert_eq!(tcp_count.load(Ordering::SeqCst), 1, "single TCP for all substreams");
    }

    async fn echo_fn(sock: MuxStream) {
        let (mut rd, mut wr) = tokio::io::split(sock);
        tokio::io::copy(&mut rd, &mut wr).await.ok();
    }
}
