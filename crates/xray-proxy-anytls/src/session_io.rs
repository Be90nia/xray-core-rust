//! `anytls::Session` → `AsyncRead` / `AsyncWrite` 适配（ADR P-6 服务端面）。
//!
//! `anytls::Session` 只暴露 `async fn read/write(&self, ...)`（非 tokio trait），
//! 其 future 借用 caller 的 buf，不能在 `poll_*` 里现起现熄（借用无法存进 self）。
//! 本适配器把在途 future 缓存在自身字段（`HysteriaConn` 同款手法），future 自持
//! 一块 scratch、完成时连缓冲一起归还 → `Pending` 后重入同一 future，稳态零分配。
//!
//! 服务端原先用 `tokio::io::duplex(64KiB) + pump 任务` 桥接：那条路每方向多一次
//! 中转拷贝（duplex 环形缓冲）加一次 task 唤醒，且每 session 常驻 64 KiB 环。
//! 此处直连省掉两者；`poll_shutdown` 不发帧——FIN 与 socket 收尾仍由
//! [`crate::server::finish_session`] 统一执行（与桥接期语义一致）。

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anytls::proxy::session::Session;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 单次搬运上界：与旧 duplex 泵的 8 KiB 块一致（保 wire 上 PSH 帧长分布不变）。
const CHUNK: usize = 8 * 1024;

/// 在途 read future：完成时交出 `(结果, scratch)`——scratch 归还槽内复用。
type ReadFut = Pin<Box<dyn Future<Output = (io::Result<usize>, Vec<u8>)> + Send>>;

/// 在途 write future：完成时交出 `(结果, 缓冲, 已接受字节数)`。
type WriteFut = Pin<Box<dyn Future<Output = (io::Result<usize>, Vec<u8>, usize)> + Send>>;

/// `Session` → `AsyncRead`。
///
/// `Session::read` 只接受 `&mut [u8]`，落不进 `ReadBuf` 的未填充区，故每次读入
/// 常驻 scratch 再拷给 caller（每块 1 次 memcpy，是这条路的下限）。
pub(crate) struct SessionReader {
    session: Arc<Session>,
    reading: Option<ReadFut>,
    scratch: Vec<u8>,
    /// 已读出但尚未交付的字节区间 `scratch[pos..pos + len]`。
    ///
    /// 在途读的尺寸按发起时的 `ReadBuf::remaining()` 定；父 future 被取消后若以更小
    /// 的 `ReadBuf` 重入，多读的部分留在这里下一次交付（否则 `put_slice` 越界 panic）。
    pos: usize,
    len: usize,
}

impl SessionReader {
    pub(crate) fn new(session: Arc<Session>) -> Self {
        Self { session, reading: None, scratch: Vec::new(), pos: 0, len: 0 }
    }
}

impl AsyncRead for SessionReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let remaining = buf.remaining();
        if remaining == 0 {
            return Poll::Ready(Ok(()));
        }
        // 先交付上一轮遗留字节（父 future 取消后以小 ReadBuf 重入的场景）。
        if this.len > 0 {
            let take = this.len.min(remaining);
            buf.put_slice(&this.scratch[this.pos..this.pos + take]);
            this.pos += take;
            this.len -= take;
            if this.len == 0 {
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        if this.reading.is_none() {
            let n = remaining.min(CHUNK);
            let mut scratch = std::mem::take(&mut this.scratch);
            if scratch.len() < n {
                scratch.resize(n, 0);
            }
            let session = Arc::clone(&this.session);
            this.reading = Some(Box::pin(async move {
                let read = session.read(&mut scratch[..n]).await;
                (read, scratch)
            }));
        }
        let polled = this.reading.as_mut().expect("reading set above when None").as_mut().poll(cx);
        match polled {
            Poll::Pending => Poll::Pending,
            Poll::Ready((read, scratch)) => {
                this.reading = None;
                this.scratch = scratch;
                this.pos = 0;
                this.len = 0;
                match read {
                    // 0 字节 = session 已 FIN/关闭 → EOF（不填 buf）
                    Ok(0) => Poll::Ready(Ok(())),
                    Ok(n) => {
                        let take = n.min(buf.remaining());
                        buf.put_slice(&this.scratch[..take]);
                        this.pos = take;
                        this.len = n - take;
                        if this.len == 0 {
                            this.pos = 0;
                        }
                        Poll::Ready(Ok(()))
                    },
                    Err(e) => Poll::Ready(Err(e)),
                }
            },
        }
    }
}

/// `Session` → `AsyncWrite`。
///
/// `Session::write` 一次调用 = 一个 PSH 帧，故每次只接受至多 [`CHUNK`] 字节
/// （与桥接期 8 KiB 搬运块同尺寸）；调用方拿到短写后自行续写。
pub(crate) struct SessionWriter {
    session: Arc<Session>,
    writing: Option<WriteFut>,
    scratch: Vec<u8>,
}

impl SessionWriter {
    pub(crate) fn new(session: Arc<Session>) -> Self {
        Self { session, writing: None, scratch: Vec::new() }
    }
}

impl AsyncWrite for SessionWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // 在途写在飞：先驱动它。调用方按短写续传，返回的字节数属于在途那次。
        if this.writing.is_some() {
            let polled = this.writing.as_mut().expect("checked is_some").as_mut().poll(cx);
            return match polled {
                Poll::Pending => Poll::Pending,
                Poll::Ready((res, scratch, n)) => {
                    this.writing = None;
                    this.scratch = scratch;
                    // 在途帧按上一轮 buf 尺寸收下；调用方换更小的 buf 重入 = 违反
                    // 「同一 buffer 续写」契约 → 显式失败，禁静默少报造成数据错位。
                    if res.is_ok() && n > buf.len() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "anytls session write: sticky write retried with a shorter buffer",
                        )));
                    }
                    Poll::Ready(res.map(|_| n))
                },
            };
        }
        let n = buf.len().min(CHUNK);
        if n == 0 {
            return Poll::Ready(Ok(0));
        }
        let mut scratch = std::mem::take(&mut this.scratch);
        scratch.clear();
        scratch.extend_from_slice(&buf[..n]);
        let session = Arc::clone(&this.session);
        this.writing = Some(Box::pin(async move {
            let res = session.write(&scratch).await;
            (res, scratch, n)
        }));
        // 首次 poll 立刻驱动一次：帧入队通常即刻完成，省一次额外唤醒。
        let polled = this.writing.as_mut().expect("writing set above").as_mut().poll(cx);
        match polled {
            Poll::Pending => Poll::Pending,
            Poll::Ready((res, scratch, n)) => {
                this.writing = None;
                this.scratch = scratch;
                Poll::Ready(res.map(|_| n))
            },
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // `Session::write` 返回即帧已入 session 发送队列，无本地缓冲可 flush。
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // FIN / 本地半关 / socket 收尾由 `finish_session` 统一执行（单次、有序）。
        Poll::Ready(Ok(()))
    }
}
