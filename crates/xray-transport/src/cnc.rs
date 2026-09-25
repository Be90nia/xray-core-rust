//! ContentNetworkConnection：把 dispatcher 的 [`Reader`]/[`Writer`] 对包装为
//! [`Connection`]（Go `net.Conn` 等价物）。
//!
//! 对应 Go `common/net/cnc/connection.go`。Go 消费方：commander/metrics gRPC
//! (`app/commander/outbound.go:85`)、DNS over proxy (`app/dns/nameserver_*.go`)、
//! proxyman outbound 叠 TLS (`app/proxyman/outbound/handler.go:290`)、
//! internet dialer 代理链 (`transport/internet/dialer.go:130`)、grpc transport
//! (`transport/internet/grpc/encoding/{hunkconn,multiconn}.go`)。
//! Rust 现有消费方用 `tokio::io::duplex` + `DuplexConnection` + spawn bridge
//! 间接替代（多一对 pipe + copy 任务）；本类型提供零中间层的直接包装。
//!
//! 与 Go 版差异：
//! - functional options 拆为 builder 方法；`io.Reader`/`io.Writer` 原始流包装 由
//!   `xray_buf::io::{new_reader, new_writer}` 工厂承担，不重复。
//! - `ConnectionOutputMultiUDP` 的 SplitFirstBytes 包边界语义 →
//!   [`ContentNetworkConnection::with_packet_mode`]。
//! - 默认地址：Go 返回 0.0.0.0:0；Rust 按现有 `Connection` 约定返回 `Ok(None)`。
//! - `onClose` 回调无错误返回值（Go 消费方均为无错误语义的 closeSignal/cancel）。
//! - Drop 自动触发 close（RAII，防泄漏 onClose）。

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use xray_buf::{
    io::{Reader, Writer},
    multi::MultiBuffer,
};

use crate::connection::Connection;

/// 读侧状态机。
///
/// reader 在 Pending 期间被 move 进 future（避免自引用结构），
/// future 就绪后归还到 `Inner.reader`。
enum ReadState {
    /// 无缓冲数据、无在途读取。
    Idle,
    /// 在途 `read_multi_buffer` future（持有 reader）。
    Pending(
        Pin<Box<dyn Future<Output = (Box<dyn Reader>, xray_buf::io::Result<MultiBuffer>)> + Send>>,
    ),
    /// 已读回但未消费完的数据（对应 Go `buf.BufferedReader` 内部缓冲）。
    Buffered(MultiBuffer),
}

/// 写侧状态机。
enum WriteState {
    Idle,
    /// 在途 `write_multi_buffer` future（持有 writer）+ 本批字节数。
    /// Go `Write` 全量语义：一次写完整个 buffer 并返回 `len(b)`。
    Pending(
        (Pin<Box<dyn Future<Output = (Box<dyn Writer>, xray_buf::io::Result<()>)> + Send>>, usize),
    ),
}

struct Inner {
    reader: Option<Box<dyn Reader>>,
    writer: Option<Box<dyn Writer>>,
    read_state: ReadState,
    write_state: WriteState,
    /// Go `done.Instance` 等价：置位后 Write 返回 BrokenPipe（`io.ErrClosedPipe`）。
    closed: bool,
    /// Go `ConnectionOutputMultiUDP` 的 SplitFirstBytes 包边界语义。
    packet_mode: bool,
}

/// 把一对 dispatcher [`Reader`]/[`Writer`] 包装为 [`Connection`]。
///
/// 方向约定（与 Go 消费方一致）：
/// - `conn.read` ← `reader`（dispatcher 写出的响应流）；
/// - `conn.write` → `writer`（发往 dispatcher 的请求流）。
pub struct ContentNetworkConnection {
    inner: Mutex<Inner>,
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
    on_close: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl ContentNetworkConnection {
    /// 从一对 reader/writer 构造。
    ///
    /// 对应 Go `NewConnection(ConnectionOutputMulti(r), ConnectionInputMulti(w))`。
    #[must_use]
    pub fn new(reader: Box<dyn Reader>, writer: Box<dyn Writer>) -> Self {
        Self {
            inner: Mutex::new(Inner {
                reader: Some(reader),
                writer: Some(writer),
                read_state: ReadState::Idle,
                write_state: WriteState::Idle,
                closed: false,
                packet_mode: false,
            }),
            local: None,
            remote: None,
            on_close: Mutex::new(None),
        }
    }

    /// 对应 Go `ConnectionLocalAddr`。
    #[must_use]
    pub fn with_local_addr(mut self, addr: SocketAddr) -> Self {
        self.local = Some(addr);
        self
    }

    /// 对应 Go `ConnectionRemoteAddr`。
    #[must_use]
    pub fn with_remote_addr(mut self, addr: SocketAddr) -> Self {
        self.remote = Some(addr);
        self
    }

    /// 对应 Go `ConnectionOnClose`：close 时回调（commander closeSignal、
    /// grpc cancel 等场景）。
    #[must_use]
    pub fn with_on_close(self, f: impl FnOnce() + Send + 'static) -> Self {
        *self.on_close.lock() = Some(Box::new(f));
        self
    }

    /// 对应 Go `ConnectionOutputMultiUDP`（SplitFirstBytes）：
    /// 每次 read 只暴露一个内部 buffer 的数据，保留包边界。
    #[must_use]
    pub fn with_packet_mode(self) -> Self {
        self.inner.lock().packet_mode = true;
        self
    }

    /// 关闭连接（Go `Close`：done + Interrupt(reader) + Close(writer) + onClose）。
    ///
    /// - 后续 write 返回 `BrokenPipe`（Go `io.ErrClosedPipe`）；
    /// - 后续 read 返回 EOF；
    /// - writer 半关闭：dispatcher 侧读端收到 EOF。
    /// 幂等：重复调用无副作用。Drop 时自动调用。
    pub fn close(&self) -> io::Result<()> {
        let mut inner = self.inner.lock();
        if inner.closed {
            return Ok(());
        }
        inner.closed = true;
        // Go Close：done.Close + common.Interrupt(reader) + common.Close(writer)。
        // Rust 等价：drop 读端（中断在途读取），writer.shutdown() 通知
        // dispatcher 读端 EOF。
        inner.reader = None;
        if let Some(w) = inner.writer.take() {
            w.shutdown();
        }
        inner.read_state = ReadState::Idle;
        inner.write_state = WriteState::Idle;
        drop(inner);
        if let Some(cb) = self.on_close.lock().take() {
            cb();
        }
        Ok(())
    }
}

impl AsyncRead for ContentNetworkConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut inner = self.inner.lock();
        if inner.closed {
            // Go：Close 后 reader 已被 Interrupt。Rust 归一化为 EOF。
            return Poll::Ready(Ok(()));
        }
        loop {
            // (a) 已缓冲数据：直接填充（对应 Go BufferedReader 缓存回放）。
            let buffered_nonempty =
                matches!(&inner.read_state, ReadState::Buffered(mb) if !mb.is_empty());
            if buffered_nonempty {
                let packet_mode = inner.packet_mode;
                let ReadState::Buffered(mb) = &mut inner.read_state else {
                    unreachable!();
                };
                let dst = buf.initialize_unfilled();
                // packet 模式：只暴露第一个 buffer（Go SplitFirstBytes 包边界）。
                let limit = if packet_mode {
                    mb.iter().next().map_or(0, |b| b.len()).min(dst.len())
                } else {
                    dst.len()
                };
                let n = mb.read_to(&mut dst[..limit]);
                buf.advance(n);
                if mb.is_empty() {
                    inner.read_state = ReadState::Idle;
                }
                return Poll::Ready(Ok(()));
            }
            // (b) Idle：发起读取（reader move 进 future，避免自引用）。
            if matches!(inner.read_state, ReadState::Idle) {
                let Some(mut reader) = inner.reader.take() else {
                    return Poll::Ready(Err(io::Error::other("cnc: reader unavailable")));
                };
                inner.read_state = ReadState::Pending(Box::pin(async move {
                    let res = reader.read_multi_buffer().await;
                    (reader, res)
                }));
            }
            // (c) 轮询在途 future。
            let ReadState::Pending(fut) = &mut inner.read_state else {
                unreachable!();
            };
            match fut.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready((reader, Ok(mb))) => {
                    inner.reader = Some(reader);
                    if mb.is_empty() {
                        // 空 MultiBuffer = EOF（xray-buf 约定，见 SingleReader）。
                        inner.read_state = ReadState::Idle;
                        return Poll::Ready(Ok(()));
                    }
                    inner.read_state = ReadState::Buffered(mb);
                },
                Poll::Ready((reader, Err(e))) => {
                    inner.reader = Some(reader);
                    inner.read_state = ReadState::Idle;
                    return match e {
                        xray_buf::io::Error::Eof | xray_buf::io::Error::Interrupted => {
                            Poll::Ready(Ok(()))
                        },
                        other => Poll::Ready(Err(io::Error::other(other.to_string()))),
                    };
                },
            }
        }
    }
}

impl AsyncWrite for ContentNetworkConnection {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        if b.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut inner = self.inner.lock();
        if inner.closed {
            // Go Write：done.Done() → io.ErrClosedPipe。
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "cnc: connection closed",
            )));
        }
        let inner = &mut *inner; // reborrow：允许 write_state / writer 字段级 disjoint 借用
        if matches!(inner.write_state, WriteState::Idle) {
            let Some(mut writer) = inner.writer.take() else {
                return Poll::Ready(Err(io::Error::other("cnc: writer unavailable")));
            };
            let mut mb = MultiBuffer::new();
            mb.merge_bytes(b);
            let len = b.len();
            // Go Write 全量语义：一次写完整个 b 并返回 len(b)。
            inner.write_state = WriteState::Pending((
                Box::pin(async move {
                    let res = writer.write_multi_buffer(mb).await;
                    (writer, res)
                }),
                len,
            ));
        }
        let WriteState::Pending((fut, len)) = &mut inner.write_state else {
            unreachable!();
        };
        let len = *len; // 拷出，解除 write_state 借用对后续赋值的约束
        match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready((writer, res)) => {
                inner.writer = Some(writer);
                inner.write_state = WriteState::Idle;
                match res {
                    Ok(()) => Poll::Ready(Ok(len)),
                    Err(e) => Poll::Ready(Err(io::Error::other(e.to_string()))),
                }
            },
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.inner.lock();
        if inner.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "cnc: connection closed",
            )));
        }
        // write_multi_buffer 全量写语义：future 完成即已写出。
        let idle = matches!(inner.write_state, WriteState::Idle);
        if idle {
            return Poll::Ready(Ok(()));
        }
        let inner = &mut *inner; // reborrow（同 poll_write）
        let WriteState::Pending((fut, _)) = &mut inner.write_state else {
            unreachable!();
        };
        match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready((writer, res)) => {
                inner.writer = Some(writer);
                inner.write_state = WriteState::Idle;
                Poll::Ready(res.map_err(|e| io::Error::other(e.to_string())))
            },
        }
    }

    /// 半关闭写方向：通知 dispatcher 读端 EOF（Go pipe.Writer close）。
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.inner.lock();
        if inner.closed {
            return Poll::Ready(Ok(()));
        }
        if let Some(w) = inner.writer.take() {
            w.shutdown();
        }
        inner.write_state = WriteState::Idle;
        Poll::Ready(Ok(()))
    }
}

impl Connection for ContentNetworkConnection {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.remote)
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.local)
    }
}

impl Drop for ContentNetworkConnection {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use xray_buf::{buffer::Buffer, multi::MultiBuffer};

    use super::*;

    /// dispatcher（对端）持有 resp_writer + req_reader；cnc 持有 resp_reader + req_writer。
    fn make_cnc()
    -> (ContentNetworkConnection, Box<dyn xray_buf::io::Writer>, Box<dyn xray_buf::io::Reader>)
    {
        let (resp_reader, resp_writer) = xray_buf::pipe::new();
        let (req_reader, req_writer) = xray_buf::pipe::new();
        let conn = ContentNetworkConnection::new(Box::new(resp_reader), Box::new(req_writer));
        (conn, Box::new(resp_writer), Box::new(req_reader))
    }

    async fn pipe_write(w: &mut Box<dyn xray_buf::io::Writer>, data: &[u8]) {
        use xray_buf::io::Writer as _;
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(data);
        w.write_multi_buffer(mb).await.unwrap();
    }

    async fn pipe_read_all(r: &mut Box<dyn xray_buf::io::Reader>) -> Vec<u8> {
        use xray_buf::io::Reader as _;
        let mut out = Vec::new();
        loop {
            match r.read_multi_buffer().await {
                Ok(mb) => {
                    if mb.is_empty() {
                        return out;
                    }
                    out.extend_from_slice(&mb.to_vec());
                },
                // pipe EOF 表示：Err(Error::Eof)（pipe.rs State::Closed 路径）
                Err(xray_buf::io::Error::Eof) | Err(xray_buf::io::Error::Interrupted) => {
                    return out;
                },
                Err(e) => panic!("pipe_read_all: {e}"),
            }
        }
    }

    #[tokio::test]
    async fn read_write_roundtrip() {
        let (mut conn, mut peer_w, mut peer_r) = make_cnc();

        // 对端写响应 → conn.read 读到
        pipe_write(&mut peer_w, b"hello response").await;
        let mut buf = [0u8; 64];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello response");

        // conn.write → 对端 req_reader 读到
        conn.write_all(b"client request").await.unwrap();
        conn.shutdown().await.unwrap(); // 半关闭：pipe_read_all 需要 EOF 退出
        let got = pipe_read_all(&mut peer_r).await;
        assert_eq!(got, b"client request");
    }

    #[tokio::test]
    async fn write_returns_full_length() {
        // Go Write 全量语义：返回 len(b)
        let (mut conn, _peer_w, mut peer_r) = make_cnc();
        let data = vec![7u8; 100];
        let n = conn.write(&data).await.unwrap();
        assert_eq!(n, 100);
        conn.shutdown().await.unwrap();
        let got = pipe_read_all(&mut peer_r).await;
        assert_eq!(got.len(), 100);
    }

    #[tokio::test]
    async fn read_returns_eof_when_peer_closes() {
        let (mut conn, peer_w, _peer_r) = make_cnc();
        // pipe.Writer 无 Drop 自动关闭；显式 close（Go 显式 Close 语义）
        peer_w.shutdown();
        let mut buf = [0u8; 8];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "peer closed → EOF");
    }

    #[tokio::test]
    async fn write_after_close_returns_broken_pipe() {
        // Go: done.Done() → io.ErrClosedPipe
        let (conn, _peer_w, _peer_r) = make_cnc();
        conn.close().unwrap();
        let mut conn = conn;
        let err = conn.write(b"x").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn read_after_close_returns_eof() {
        let (conn, _peer_w, _peer_r) = make_cnc();
        conn.close().unwrap();
        let mut conn = conn;
        let mut buf = [0u8; 8];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn close_triggers_on_close_callback() {
        let fired = Arc::new(AtomicBool::new(false));
        let (conn, _peer_w, _peer_r) = make_cnc();
        let conn = conn.with_on_close({
            let fired = Arc::clone(&fired);
            move || fired.store(true, Ordering::SeqCst)
        });
        assert!(!fired.load(Ordering::SeqCst));
        conn.close().unwrap();
        assert!(fired.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn drop_triggers_close_semantics() {
        // RAII：drop 即 close（onClose 不泄漏）
        let fired = Arc::new(AtomicBool::new(false));
        let (conn, _peer_w, mut peer_r) = make_cnc();
        let conn = conn.with_on_close({
            let fired = Arc::clone(&fired);
            move || fired.store(true, Ordering::SeqCst)
        });
        drop(conn);
        assert!(fired.load(Ordering::SeqCst));
        // writer 被关闭 → dispatcher 读端收到 EOF（pipe 的 EOF 表示 = Err(Eof)）
        let res = peer_r.read_multi_buffer().await;
        assert!(
            matches!(res, Err(xray_buf::io::Error::Eof)),
            "req pipe should be closed (Err Eof)"
        );
    }

    #[tokio::test]
    async fn shutdown_half_closes_write_direction() {
        let (mut conn, mut peer_w, mut peer_r) = make_cnc();
        conn.write_all(b"before shutdown").await.unwrap();
        conn.shutdown().await.unwrap();
        // 对端仍能读回 shutdown 前的数据
        let got = pipe_read_all(&mut peer_r).await;
        assert_eq!(got, b"before shutdown");
        // 读方向不受影响
        pipe_write(&mut peer_w, b"still readable").await;
        let mut buf = [0u8; 32];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"still readable");
    }

    #[tokio::test]
    async fn packet_mode_preserves_buffer_boundary() {
        // Go ConnectionOutputMultiUDP / SplitFirstBytes：一次 read 只暴露第一个 buffer
        let (resp_reader, mut resp_writer) = xray_buf::pipe::new();
        let (_req_reader, req_writer) = xray_buf::pipe::new();
        let mut conn = ContentNetworkConnection::new(Box::new(resp_reader), Box::new(req_writer))
            .with_packet_mode();

        // 对端一次写入含两个 buffer 的 MultiBuffer（模拟两个 UDP 包）
        let mut mb = MultiBuffer::new();
        mb.push(Buffer::from_vec(b"packet-one".to_vec()));
        mb.push(Buffer::from_vec(b"packet-two".to_vec()));
        resp_writer.write_multi_buffer(mb).await.unwrap();

        // packet 模式：每次 read 只返回一个包，不跨包填充
        let mut buf = [0u8; 64];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"packet-one");
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"packet-two");
    }

    #[tokio::test]
    async fn stream_mode_fills_across_buffers() {
        // 对照：stream（默认）模式一次 read 跨 buffer 填满
        let (resp_reader, mut resp_writer) = xray_buf::pipe::new();
        let (_req_reader, req_writer) = xray_buf::pipe::new();
        let mut conn = ContentNetworkConnection::new(Box::new(resp_reader), Box::new(req_writer));

        let mut mb = MultiBuffer::new();
        mb.push(Buffer::from_vec(b"packet-one".to_vec()));
        mb.push(Buffer::from_vec(b"packet-two".to_vec()));
        resp_writer.write_multi_buffer(mb).await.unwrap();

        let mut buf = [0u8; 64];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"packet-onepacket-two");
    }

    #[tokio::test]
    async fn addr_options_exposed() {
        let (conn, _w, _r) = make_cnc();
        let local: SocketAddr = "127.0.0.1:1111".parse().unwrap();
        let remote: SocketAddr = "10.0.0.1:2222".parse().unwrap();
        let conn = conn.with_local_addr(local).with_remote_addr(remote);
        assert_eq!(conn.local_addr().unwrap(), Some(local));
        assert_eq!(conn.remote_addr().unwrap(), Some(remote));
    }

    #[tokio::test]
    async fn default_addr_is_none() {
        let (conn, _w, _r) = make_cnc();
        assert_eq!(conn.local_addr().unwrap(), None);
        assert_eq!(conn.remote_addr().unwrap(), None);
    }
}
