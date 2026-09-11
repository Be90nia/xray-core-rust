//! WebSocket 帧流 ↔ 字节流桥接。
//!
//! `tokio-tungstenite::WebSocketStream` 是消息语义（`Stream<Item=Message>` +
//! `Sink<Message>`），而代理协议期望字节语义（`AsyncRead + AsyncWrite`）。
//! [`WsConnection`] 把 split 后的 sink/stream 桥接到字节流，对应 Go
//! `transport/internet/websocket/connection.go` 的 `connection` 包装。
//!
//! ## 桥接语义（对齐 Go gorilla/websocket）
//!
//! - **写**：每次 `poll_write` 发一条 `Binary` 消息（与 Go `WriteMessage(BinaryMessage, b)`
//!   一致）。调用方若需合并小包应在调用前 buffer。
//! - **读**：从下一条 `Binary` 消息的字节流读取。一条消息可能跨多次 `poll_read`，
//!   多条消息的字节流也不可跨越（每条消息独立消费完才取下一条）。
//! - 控制帧（`Ping`/`Pong`/`Close`）由 tungstenite 自动处理；`Close` 后返回 EOF。
//! - `Text` 帧不接受（仅二进制代理流量）。
//!
//! # Security
//!
//! 切片2 不做消息大小限制（依赖 tungstenite `max_message_size`）；调用方应通过
//! `WebSocketConfig::max_message_size` 配置上限，避免恶意大帧 OOM。

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::sync::Mutex;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use xray_transport::connection::Connection;

/// 桥接 WebSocket 帧流为字节流。
///
/// 包装已 split 的 `WebSocketStream` 两半，实现 `AsyncRead + AsyncWrite + Connection`。
/// `S` 是底层 IO 流（TCP / TLS）；一般通过 `tokio_tungstenite::connect_async*` 或
/// `accept_async` 得到 `WebSocketStream<S>`，调用 `.split()` 后传入。
pub struct WsConnection<S> {
    /// 读半部：从 WS 拿消息。
    pub(crate) read: SplitStreamOwned<S>,
    /// 写半部：发消息到 WS。`Arc<Mutex<..>>` 包装让心跳任务共享写权限
    /// （对应 Go `conn.WriteControl(PingMessage,...)` 共享底层 `*websocket.Conn`）。
    pub(crate) write: Arc<Mutex<SplitSinkOwned<S>>>,
    /// 当前未消费完的消息字节（一条 Binary 消息可能跨多次 poll_read）。
    pub(crate) read_buf: VecDeque<u8>,
    /// 对端地址（可由 PROXY protocol / X-Forwarded-For 覆盖，对应 Go `remoteAddr`）。
    pub(crate) remote: Option<SocketAddr>,
    /// 本端地址。
    pub(crate) local: Option<SocketAddr>,
    /// 心跳 ping 任务句柄；`Drop` 时 abort 防泄漏（对应 Go heartbeat goroutine 生命周期）。
    pub(crate) heartbeat_handle: Option<JoinHandle<()>>,
}

// 类型别名：让签名可读。tokio-tungstenite::WebSocketStream::split 返回：
//   SplitStream<WebSocketStream<S>>  -- Stream<Item=Result<Message, Error>>
//   SplitSink<WebSocketStream<S>, Message> -- Sink<Message>
// 使用 `futures_util::stream::SplitStream` / `sink::SplitSink` 类型。
// 为保持本 crate 不暴露内部类型，用泛型参数让 WsConnection 兼容任何 split 后的形态。
pub(crate) type SplitStreamOwned<S> =
    futures_util::stream::SplitStream<WebSocketStream<S>>;
pub(crate) type SplitSinkOwned<S> =
    futures_util::stream::SplitSink<WebSocketStream<S>, Message>;

impl<S> WsConnection<S> {
    /// 用 split 后的两半 + 地址构造。
    ///
    /// 一般通过 [`Self::from_stream`] 自动 split，本构造方法暴露给需要手动
    /// 控制 split 的场景（如自定义 WebSocketStream 子类）。
    pub fn new(
        read: SplitStreamOwned<S>,
        write: SplitSinkOwned<S>,
        remote: Option<SocketAddr>,
        local: Option<SocketAddr>,
    ) -> Self {
        Self {
            read,
            write: Arc::new(Mutex::new(write)),
            read_buf: VecDeque::new(),
            remote,
            local,
            heartbeat_handle: None,
        }
    }

    /// 从 `WebSocketStream` split 并构造（最常用路径）。
    pub fn from_stream(
        ws: WebSocketStream<S>,
        remote: Option<SocketAddr>,
        local: Option<SocketAddr>,
    ) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (write, read) = ws.split(); // (sink, stream)
        Self::new(read, write, remote, local)
    }

    /// 设置对端地址（用于 PROXY protocol / X-Forwarded-For 覆盖）。
    pub fn set_remote_addr(&mut self, addr: Option<SocketAddr>) {
        self.remote = addr;
    }
}

impl<S> AsyncRead for WsConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // 1. 先吐 read_buf（上一条消息的剩余字节）。
            if !self.read_buf.is_empty() {
                let n = std::cmp::min(self.read_buf.len(), buf.remaining());
                // VecDeque::drain 收集到 Vec 太重，直接逐字节拷贝（n 通常很小）。
                // ponytail: 用 chunk + put_slice 避免 VecDeque::drain 收集。
                // n 通常 ≤ buf.remaining()，一次 put_slice 即可。
                let chunk: Vec<u8> = self.read_buf.drain(..n).collect();
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            // 2. 拉下一条消息。
            match self.read.poll_next_unpin(cx) {
                Poll::Ready(Some(msg)) => match msg {
                    Ok(Message::Binary(data)) => {
                        if data.is_empty() {
                            continue; // 空消息：跳过拿下一条
                        }
                        // 数据大时可一次填满 buf，剩余留 read_buf。
                        let data: Vec<u8> = data.into(); // Bytes/Vec 统一
                        let n = std::cmp::min(data.len(), buf.remaining());
                        buf.put_slice(&data[..n]);
                        if n < data.len() {
                            self.read_buf.extend(&data[n..]);
                        }
                        return Poll::Ready(Ok(()));
                    }
                    Ok(Message::Ping(_) | Message::Pong(_)) => {
                        // tungstenite 自动回 Pong；控制帧对字节流透明。
                        continue;
                    }
                    Ok(Message::Close(_)) => {
                        // 对端关闭：返回 EOF（Ok + 0 bytes）。
                        return Poll::Ready(Ok(()));
                    }
                    Ok(Message::Text(_)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "websocket text frame not supported (binary only)",
                        )));
                    }
                    Ok(Message::Frame(_)) => {
                        // 不该出现：tungstenite 已解码为高层 Message。
                        continue;
                    }
                    Err(e) => {
                        return Poll::Ready(Err(io::Error::other(e)));
                    }
                },
                Poll::Ready(None) => {
                    // 流结束 = EOF
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for WsConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // 1. 获取写锁（心跳任务可能短暂持有）。try_lock 失败则 reschedule 重试。
        // ponytail: 心跳仅持有写锁一次 send（微秒级），wake_by_ref 重试开销极低。
        let mut guard = match this.write.try_lock() {
            Ok(g) => g,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };
        // 2. poll_ready → start_send → poll_flush（SinkExt _unpin 方法通过 DerefMut 调用到 SplitKit）。
        match guard.poll_ready_unpin(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
            Poll::Pending => return Poll::Pending,
        }
        // 票 lwwz：`buf.to_vec()` 的全量拷贝是 tungstenite 0.26 Sink API 的结构性
        // 成本，本 crate 侧无法消除（已核实 tungstenite-0.26.2 源码）：
        // ① `start_send` 持有 `Message::Binary(Bytes)` 直到 flush 完成，`&[u8]`
        //    必须转 owned——`Vec`→`Bytes` 接管分配、`BytesMut::freeze` 让出分配，
        //    缓冲复用均不可行；
        // ② tungstenite `format_into_buf`（frame/frame.rs）随后把 payload 再拷入
        //    自身 out_buffer 并就地掩码——第 2 次拷贝在其内部，无从旁路。
        // Go gorilla `WriteMessage` 仅 1 次拷入写缓冲+掩码，少的正是 ②；消除它
        // 需要 fork tungstenite 暴露写缓冲直写 API（收益 µs 级，不做）。
        if let Err(e) = guard.start_send_unpin(Message::binary(buf.to_vec())) {
            return Poll::Ready(Err(io::Error::other(e)));
        }
        // ponytail: 立即 poll_flush 让数据发到 TCP，避免调用方必须显式 flush。
        // WS 代理语义：每条消息对应独立帧，应即时发送（对齐 Go WriteMessage）。
        match guard.poll_flush_unpin(cx) {
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut guard = match this.write.try_lock() {
            Ok(g) => g,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };
        guard.poll_flush_unpin(cx).map_err(io::Error::other)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut guard = match this.write.try_lock() {
            Ok(g) => g,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };
        // 发 Close 帧再关 sink（对齐 Go connection.Close 行为）。
        // ponytail: tungstenite Sink::close 自动发 Close frame。
        guard.poll_close_unpin(cx).map_err(io::Error::other)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync> Connection for WsConnection<S> {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.remote)
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.local)
    }
}

impl<S> WsConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// 启动心跳 ping 任务（对应 Go `NewConnection` 的 `heartbeatPeriod` goroutine）。
    ///
    /// `period` 为 0 不启动；重复调用先 abort 旧任务再启新的。
    /// 对应 Go `conn.WriteControl(websocket.PingMessage, []byte{}, time.Time{})` 循环。
    pub fn start_heartbeat(&mut self, period: std::time::Duration) {
        if period.is_zero() {
            return;
        }
        let write = Arc::clone(&self.write);
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(period);
            // 跳过首次立即 tick（对齐 Go time.Sleep 先睡后 ping）。
            interval.tick().await;
            loop {
                interval.tick().await;
                let mut guard = write.lock().await;
                // 发空 Ping 并 flush（对齐 Go WriteControl(PingMessage, []byte{})）。
                // send 失败（连接关闭/出错）即停止心跳（对齐 Go break）。
                if guard.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
            }
        });
        if let Some(old) = self.heartbeat_handle.take() {
            old.abort();
        }
        self.heartbeat_handle = Some(handle);
    }
}

impl<S> Drop for WsConnection<S> {
    fn drop(&mut self) {
        if let Some(h) = self.heartbeat_handle.take() {
            h.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    //! 编译期 trait bound 验证 + 心跳 ping 运行时验证。
    use super::*;

    #[test]
    fn ws_connection_implements_connection_trait_bound() {
        // 编译期断言：WsConnection<TcpStream> 满足 Connection supertrait。
        fn _assert_connection<T: Connection>() {}
        _assert_connection::<WsConnection<tokio::net::TcpStream>>();
    }

    #[tokio::test]
    async fn start_heartbeat_sends_ping_frames_to_peer() {
        use std::time::Duration;
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;

        // 1. TCP pair。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let mut conn: WsConnection<tokio::net::TcpStream> =
                WsConnection::from_stream(ws, None, None);
            conn.start_heartbeat(Duration::from_millis(20));
            // 保活 200ms 让心跳发出几个 Ping。
            tokio::time::sleep(Duration::from_millis(200)).await;
            // conn drop → Drop::drop abort heartbeat task。
        });

        // 2. Client: 连接并读 Ping 帧。
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = "ws://localhost/".into_client_request().unwrap();
        let (ws_stream, _resp) = tokio_tungstenite::client_async(req, tcp).await.unwrap();
        let (_write, mut read) = ws_stream.split();

        let mut pings = 0u32;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(150);
        while tokio::time::Instant::now() < deadline {
            if let Ok(Some(Ok(msg))) =
                tokio::time::timeout(Duration::from_millis(50), read.next()).await
            {
                if matches!(msg, Message::Ping(_)) {
                    pings += 1;
                }
            }
        }

        server.await.unwrap();
        assert!(pings >= 1, "expected at least one ping frame, got {pings}");
    }
}
