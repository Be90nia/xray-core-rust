//! Pipe：双向 in-memory 通信管道。
//!
//! 翻译自 Go xray-core transport/pipe（pipe.go + impl.go + reader.go + writer.go）。
//! [`new`] 返回一对 ([`Reader`], [`Writer`])，写入 Writer 的 MultiBuffer 从 Reader 读出。
//! 支持：close 传播（EOF）、Error 注入（ReturnAnError/Recover）、容量限制（limit）、
//! overflow 处理（丢弃/阻塞）、interrupt（中断并丢弃所有 buffered 数据）。
//!
//! 对应 Go `transport/pipe.New()`。Rust 用 `tokio::sync::Notify` 翻译 signal.Notifier，
//! `tokio::sync::watch` 翻译 done.Instance，std `Mutex<Option<Error>>` 翻译 errChan。

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use crate::{
    io::{Error, Reader as BufReader, Result, Writer as BufWriter},
    multi::MultiBuffer,
};

/// 计数信号量：signal 累积 permit，wait 消费 permit。
/// 对应 Go common/signal/notifier.go：多次写产生多个 signal，读端逐次消费
/// （Go `Notifier.Wait` 的 `Swap(0)>0 return nil chan` 语义）。
///
/// **waker 槽（bd 34nk）**：poll-based 等待（读/写端直驱
/// `poll_read_multi_buffer` / `poll_write_multi_buffer`）下，等待 future 若
/// 每次 poll 重建，其内部 waiter 注册随 future drop 销毁——后到的 signal 只
/// 剩计数、不再有任何 waker → 读端永久失唤醒（只能等调用方自己的超时轮询）。
/// waker 存槽跨 poll 存活，注册持续有效；signal 时取走唤醒。
struct CountingNotify {
    count: AtomicU64,
    /// poll 等待的 waker 槽（跨 poll 存活）。
    /// 用**列表**而非单槽：pipe 允许多写者/多读者（Go pipe 语义），单槽会让
    /// 其余等待者永不被唤醒（close 时全体挂起 = 死锁）。
    wakers: parking_lot::Mutex<Vec<std::task::Waker>>,
}

impl CountingNotify {
    fn new() -> Self {
        Self { count: AtomicU64::new(0), wakers: parking_lot::Mutex::new(Vec::new()) }
    }

    /// 发一个 signal，计数 +1。多次 signal 会累积；首个 signal 唤醒等待者。
    fn signal(&self) {
        if self.count.fetch_add(1, Ordering::SeqCst) == 0 {
            self.wake_all();
        }
    }

    /// 唤醒全部等待者（signal 与 close 路径共用）。
    fn wake_all(&self) {
        let wakers = std::mem::take(&mut *self.wakers.lock());
        for w in wakers {
            w.wake();
        }
    }

    /// 注册 waker（跨 poll 存活）：同一任务重复 poll 覆盖旧条目，不堆积。
    fn register(&self, waker: &std::task::Waker) {
        let mut wakers = self.wakers.lock();
        match wakers.iter_mut().find(|w| w.will_wake(waker)) {
            Some(slot) => *slot = waker.clone(),
            None => wakers.push(waker.clone()),
        }
    }

    /// 等待 signal：swap 全部 count，如果 >0 立即返回；否则挂起等唤醒。
    /// 对应 Go Notifier.Wait 的 `Swap(0)>0 return nil chan` 语义。
    /// waker 存槽跨 poll 保活（读/写端 poll 直驱的性命攸关语义，见结构注释）。
    /// 返回 true = 有 signal 待消费。
    fn poll_wait(&self, cx: &mut Context<'_>) -> bool {
        if self.count.swap(0, Ordering::SeqCst) > 0 {
            return true;
        }
        self.register(cx.waker());
        // 双检：注册窗口内到达的 signal 直接消费（防丢唤醒）
        if self.count.swap(0, Ordering::SeqCst) > 0 {
            return true;
        }
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Open,
    Closed,
    Errord,
}

// ========== 选项 ==========

/// Pipe 选项。对应 Go `pipeOption`。
#[derive(Clone, Copy, Debug)]
pub struct PipeOption {
    /// 缓冲区上限（字节）。`-1` = 无限制。`0` 不算满，`>limit` 才算满。
    pub limit: i64,
    /// 缓冲满时是否丢弃新数据（`true` = 丢弃并返回 Ok，`false` = 阻塞等待读端腾出空间）。
    pub discard_overflow: bool,
    /// 读端空闲超时。如果 reader 超过此时间没读到数据，返回 EOF。
    /// 对应 Go `pipe.Option.Timeout`。
    pub idle_timeout: Option<std::time::Duration>,
}
impl Default for PipeOption {
    fn default() -> Self {
        Self { limit: -1, discard_overflow: false, idle_timeout: None }
    }
}

impl PipeOption {
    #[inline]
    fn is_full(&self, cur_size: usize) -> bool {
        self.limit >= 0 && cur_size as i64 > self.limit
    }
}

// ========== 内部共享状态 ==========

struct PipeInner {
    data: MultiBuffer,
    option: PipeOption,
    state: State,
}

struct PipeShared {
    inner: parking_lot::Mutex<PipeInner>,
    /// 写端通知读端：有新数据可读。
    read_signal: CountingNotify,
    /// 读端通知写端：缓冲有空间可写。
    write_signal: CountingNotify,
    /// close 信号。false = open，true = closed/errord。
    closed: AtomicBool,
    /// 错误注入槽（ReturnAnError/Recover）。
    /// ponytail: Go 用 buffered channel（阻塞 send），这里用 slot 非阻塞覆盖。
    /// 行为差异：重复 return_an_error 会覆盖（Go 阻塞）。实际使用成对调用，覆盖语义不影响。
    err_slot: parking_lot::Mutex<Option<Error>>,
}

impl PipeShared {
    #[inline]
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// 标记 close 并通知所有等待者。幂等。
    fn mark_closed(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            // 唤醒 poll-based 等待者：close 不是数据 signal，但等待中的读/写端
            // 必须醒来才能看到状态变化（否则 close 后仍挂到外部超时；多写者
            // 全挂 = 死锁）。
            self.read_signal.wake_all();
            self.write_signal.wake_all();
        }
    }
}

// ========== 构造函数 ==========

/// 创建一对 (Reader, Writer) pipe，使用默认选项（无缓冲限制）。
pub fn new() -> (Reader, Writer) {
    new_with_option(PipeOption::default())
}

/// 创建一对 (Reader, Writer) pipe，使用指定选项。
pub fn new_with_option(option: PipeOption) -> (Reader, Writer) {
    let shared = Arc::new(PipeShared {
        inner: parking_lot::Mutex::new(PipeInner {
            data: MultiBuffer::new(),
            option,
            state: State::Open,
        }),
        read_signal: CountingNotify::new(),
        write_signal: CountingNotify::new(),
        closed: AtomicBool::new(false),
        err_slot: parking_lot::Mutex::new(None),
    });
    (Reader { shared: shared.clone(), idle: None }, Writer(shared))
}

// ========== Reader ==========

/// Pipe 读端。对应 Go `transport/pipe.Reader`。
pub struct Reader {
    shared: Arc<PipeShared>,
    /// idle timeout 定时器（跨 poll 存活；读成功即重置）。
    /// 必须跨 poll 存活：每次 poll 重建的 sleep 永远等不到超时（poll 不再回来）。
    idle: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl Clone for Reader {
    fn clone(&self) -> Self {
        // 克隆体各自持有独立 idle deadline（读端本就单消费者语义）。
        Self { shared: self.shared.clone(), idle: None }
    }
}

impl Reader {
    /// poll 形态读：waker 注册持久于共享槽（跨 poll 存活）——数据/close 到达
    /// 即真实唤醒读端，而不是等调用方自己的超时轮询（bd 34nk）。
    fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<Result<MultiBuffer>> {
        loop {
            // 取 buffered 数据
            let (data, idle_timeout) = {
                let mut inner = self.shared.inner.lock();
                let data = if !inner.data.is_empty() {
                    std::mem::take(&mut inner.data)
                } else {
                    MultiBuffer::new()
                };
                (data, inner.option.idle_timeout)
            };

            if !data.is_empty() {
                // 读端腾出空间 → 唤醒等待中的写端
                self.shared.write_signal.signal();
                // 读成功 → 重置 idle deadline
                self.idle = None;
                return Poll::Ready(Ok(data));
            }

            // 空，检查状态
            {
                let inner = self.shared.inner.lock();
                match inner.state {
                    State::Open => {},
                    State::Closed => return Poll::Ready(Err(Error::Eof)),
                    State::Errord => {
                        return Poll::Ready(Err(Error::WriteError("pipe interrupted".into())));
                    },
                }
            }

            // 检查错误槽
            {
                let mut slot = self.shared.err_slot.lock();
                if let Some(err) = slot.take() {
                    return Poll::Ready(Err(err));
                }
            }

            // 等待：注册 waker（持久槽）+ 双检；close 与数据 signal 同源唤醒
            let sig_fired = self.shared.read_signal.poll_wait(cx);
            let closed_now = self.shared.is_closed();

            // idle timeout：定时器跨 poll 存活（否则永远等不到超时）
            if let Some(timeout) = idle_timeout {
                if self.idle.is_none() {
                    self.idle = Some(Box::pin(tokio::time::sleep(timeout)));
                }
                let fired = match self.idle.as_mut() {
                    Some(sleep) => sleep.as_mut().poll(cx).is_ready(),
                    None => false,
                };
                if fired {
                    self.idle = None;
                    return Poll::Ready(Err(Error::Eof));
                }
            }

            if sig_fired || closed_now {
                continue;
            }
            return Poll::Pending;
        }
    }

    /// 异步读 MultiBuffer。空且未关闭时阻塞；close 后 buffered 读完返回 EOF；
    /// interrupt 后 buffered 已被丢弃，立即返回错误。
    pub async fn read_multi_buffer(&mut self) -> Result<MultiBuffer> {
        std::future::poll_fn(|cx| self.poll_read(cx)).await
    }

    /// 带超时的读。超时返回 [`Error::TimeoutError`]。
    pub async fn read_multi_buffer_timeout(&mut self, timeout: Duration) -> Result<MultiBuffer> {
        match tokio::time::timeout(timeout, self.read_multi_buffer()).await {
            Ok(result) => result,
            Err(_) => Err(Error::TimeoutError),
        }
    }

    /// 中断 pipe，丢弃所有 buffered data。状态转为 `Errord`。
    /// 后续读返回 `WriteError`，写也返回 `WriteError`。
    pub fn interrupt(&self) {
        Self::interrupt_shared(&self.shared);
    }

    fn interrupt_shared(shared: &Arc<PipeShared>) {
        let mut inner = shared.inner.lock();
        if !inner.data.is_empty() {
            inner.data.release();
            inner.data = MultiBuffer::new();
            if inner.state == State::Closed {
                inner.state = State::Errord;
            }
        }
        if inner.state == State::Open {
            inner.state = State::Errord;
        }
        drop(inner);
        shared.mark_closed();
    }

    /// 注入一个错误，使下一次 read 返回该错误。
    pub fn return_an_error(&self, err: Error) {
        let mut slot = self.shared.err_slot.lock();
        *slot = Some(err);
    }

    /// 取出注入的错误（如果有）。
    pub fn recover(&self) -> Option<Error> {
        self.shared.err_slot.lock().take()
    }

    /// 当前 buffered 字节数。
    pub fn len(&self) -> usize {
        self.shared.inner.lock().data.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 是否已关闭（close 或 interrupt）。
    pub fn is_closed(&self) -> bool {
        self.shared.is_closed()
    }
}

impl BufReader for Reader {
    fn read_multi_buffer(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<MultiBuffer>> + Send + '_>> {
        Box::pin(async move { Reader::read_multi_buffer(self).await })
    }

    /// poll 覆写：waker 持久注册于共享槽（丢唤醒修复的落点）。
    fn poll_read_multi_buffer(&mut self, cx: &mut Context<'_>) -> Poll<Result<MultiBuffer>> {
        Reader::poll_read(self, cx)
    }
}

// ========== Writer ==========

/// Pipe 写端。对应 Go `transport/pipe.Writer`。
#[derive(Clone)]
pub struct Writer(Arc<PipeShared>);

/// 写入路径决策（持锁期间计算）。
enum WriteAction {
    /// 已写入，通知读端即可。
    Done,
    /// 缓冲满，等待读端腾空间。
    Wait,
    /// 缓冲满且 discard_overflow：丢弃数据。
    Discard,
    /// pipe 已关闭/中断，丢弃 mb 返回错误。
    Err,
}

impl Writer {
    /// poll 形态写：管道满时挂起并把 waker 持久注册于共享槽——读端腾出空间
    /// 即真实唤醒写端（bd 34nk）。数据留在 `mb` 里（Pending 不丢数据）。
    fn poll_write(&mut self, cx: &mut Context<'_>, mb: &mut MultiBuffer) -> Poll<Result<()>> {
        if mb.is_empty() {
            return Poll::Ready(Ok(()));
        }
        loop {
            let action = {
                let mut inner = self.0.inner.lock();
                match inner.state {
                    State::Open => {
                        if inner.option.is_full(inner.data.len()) {
                            if inner.option.discard_overflow {
                                WriteAction::Discard
                            } else {
                                WriteAction::Wait
                            }
                        } else {
                            let m = std::mem::take(mb);
                            inner.data.merge(m);
                            WriteAction::Done
                        }
                    },
                    State::Closed | State::Errord => WriteAction::Err,
                }
            };

            match action {
                WriteAction::Done => {
                    self.0.read_signal.signal();
                    return Poll::Ready(Ok(()));
                },
                WriteAction::Discard => {
                    mb.release();
                    return Poll::Ready(Ok(()));
                },
                WriteAction::Err => {
                    mb.release();
                    return Poll::Ready(Err(Error::WriteError("closed pipe".into())));
                },
                WriteAction::Wait => {
                    // 注册写端 waker（持久槽）+ 双检；读端取走数据即 signal
                    let sig_fired = self.0.write_signal.poll_wait(cx);
                    let closed_now = self.0.is_closed();
                    if sig_fired || closed_now {
                        continue;
                    }
                    return Poll::Pending;
                },
            }
        }
    }

    /// 写 MultiBuffer 到 pipe。缓冲满时阻塞，除非 `discard_overflow=true`。
    /// 关闭后写返回 `WriteError`。
    pub async fn write_multi_buffer(&mut self, mb: MultiBuffer) -> Result<()> {
        let mut mb = mb;
        std::future::poll_fn(|cx| self.poll_write(cx, &mut mb)).await
    }

    /// 关闭 pipe。读端读完 buffered 后返回 EOF。多次调用幂等。
    pub fn close(&self) -> Result<()> {
        let was_open = {
            let mut inner = self.0.inner.lock();
            let was_open = inner.state == State::Open;
            if was_open {
                inner.state = State::Closed;
            }
            was_open
        };
        if was_open {
            self.0.mark_closed();
        }
        Ok(())
    }

    /// 中断 pipe（同 [`Reader::interrupt`]）。
    pub fn interrupt(&self) {
        Reader::interrupt_shared(&self.0);
    }

    /// 当前 buffered 字节数。
    pub fn len(&self) -> usize {
        self.0.inner.lock().data.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 是否已关闭。
    pub fn is_closed(&self) -> bool {
        self.0.is_closed()
    }
}

impl BufWriter for Writer {
    fn write_multi_buffer(
        &mut self,
        mb: MultiBuffer,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move { Writer::write_multi_buffer(self, mb).await })
    }

    /// poll 覆写：管道满时 waker 持久注册于共享槽（丢唤醒修复的落点）。
    fn poll_write_multi_buffer(
        &mut self,
        cx: &mut Context<'_>,
        mb: &mut MultiBuffer,
    ) -> Poll<Result<()>> {
        Writer::poll_write(self, cx, mb)
    }

    fn shutdown(&self) {
        // 调用 pipe.Writer 的 inherent close 方法
        let _ = Writer::close(self);
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;
    use crate::buffer::Buffer;

    fn mb(data: &[u8]) -> MultiBuffer {
        MultiBuffer::from_buffer(Buffer::from_bytes(BytesMut::from(data)))
    }

    // ========== 基础读写 ==========

    #[tokio::test]
    async fn test_basic_write_then_read() {
        let (mut r, mut w) = new();
        w.write_multi_buffer(mb(b"hello")).await.unwrap();
        let out = r.read_multi_buffer().await.unwrap();
        assert_eq!(out.to_vec(), b"hello");
    }

    #[tokio::test]
    async fn test_multiple_writes_then_read_concatenated() {
        // Go pipe 语义：多次 write 后 read 一次返回所有 buffered 数据拼接。
        let (mut r, mut w) = new();
        w.write_multi_buffer(mb(b"aaa")).await.unwrap();
        w.write_multi_buffer(mb(b"bbb")).await.unwrap();
        let out = r.read_multi_buffer().await.unwrap();
        assert_eq!(out.to_vec(), b"aaabbb");
    }

    #[tokio::test]
    async fn test_write_empty_is_noop() {
        let (_, mut w) = new();
        w.write_multi_buffer(MultiBuffer::new()).await.unwrap();
        // 验证 len 没增加
        assert_eq!(w.len(), 0);
    }

    // ========== close 传播 ==========

    #[tokio::test]
    async fn test_close_propagates_eof_after_drained() {
        let (mut r, mut w) = new();
        w.write_multi_buffer(mb(b"data")).await.unwrap();
        w.close().unwrap();
        // 先读出 buffered
        let out = r.read_multi_buffer().await.unwrap();
        assert_eq!(out.to_vec(), b"data");
        // 再读 EOF
        let err = r.read_multi_buffer().await.unwrap_err();
        assert!(matches!(err, Error::Eof));
    }

    #[tokio::test]
    async fn test_close_empty_pipe_returns_eof() {
        let (mut r, w) = new();
        w.close().unwrap();
        let err = r.read_multi_buffer().await.unwrap_err();
        assert!(matches!(err, Error::Eof));
    }

    #[tokio::test]
    async fn test_close_idempotent() {
        let (_r, w) = new();
        w.close().unwrap();
        w.close().unwrap();
    }

    #[tokio::test]
    async fn test_write_after_close_returns_error() {
        let (_r, mut w) = new();
        w.close().unwrap();
        let result = w.write_multi_buffer(mb(b"x")).await;
        assert!(result.is_err());
    }

    // ========== 并发读写 ==========

    #[tokio::test]
    async fn test_concurrent_writer_reader() {
        let (mut r, mut w) = new();
        let writer = tokio::spawn(async move {
            for i in 0..10u8 {
                w.write_multi_buffer(mb(&[i; 100])).await.unwrap();
            }
            w.close().unwrap();
        });
        let mut all = Vec::new();
        loop {
            match r.read_multi_buffer().await {
                Ok(data) => all.extend_from_slice(&data.to_vec()),
                Err(Error::Eof) => break,
                Err(e) => panic!("unexpected: {e:?}"),
            }
        }
        writer.await.unwrap();
        assert_eq!(all.len(), 10 * 100);
        // 验证顺序与内容
        for (i, chunk) in all.chunks(100).enumerate() {
            assert!(chunk.iter().all(|&b| b == i as u8), "chunk {i}");
        }
    }

    #[tokio::test]
    async fn test_empty_pipe_blocks_until_close() {
        let (mut r, w) = new();
        let reader = tokio::spawn(async move { r.read_multi_buffer().await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        w.close().unwrap();
        let result = reader.await.unwrap();
        assert!(matches!(result, Err(Error::Eof)));
    }

    // ========== interrupt ==========

    #[tokio::test]
    async fn test_interrupt_closes_pipe() {
        let (mut r, w) = new();
        let reader = tokio::spawn(async move { r.read_multi_buffer().await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        w.interrupt();
        let result = reader.await.unwrap();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_interrupt_discards_buffered_data() {
        let (r, mut w) = new();
        w.write_multi_buffer(mb(b"buffered")).await.unwrap();
        assert_eq!(w.len(), 8);
        w.interrupt();
        // buffered 应被丢弃
        assert_eq!(w.len(), 0);
        // 读应立即返回错误（已 interrupt）
        let mut r = r;
        let err = r.read_multi_buffer().await.unwrap_err();
        assert!(matches!(err, Error::WriteError(_)));
    }

    #[tokio::test]
    async fn test_interrupt_via_reader() {
        let (r, mut w) = new();
        w.write_multi_buffer(mb(b"data")).await.unwrap();
        r.interrupt();
        // 之后 write 应失败
        let result = w.write_multi_buffer(mb(b"more")).await;
        assert!(result.is_err());
    }

    // ========== limit + overflow ==========

    #[tokio::test]
    async fn test_limit_allows_under_capacity() {
        let opt = PipeOption { limit: 100, ..PipeOption::default() };
        let (mut r, mut w) = new_with_option(opt);
        // 50 字节 < 100，可写
        w.write_multi_buffer(mb(&[0u8; 50])).await.unwrap();
        let data = r.read_multi_buffer().await.unwrap();
        assert_eq!(data.len(), 50);
    }

    #[tokio::test]
    async fn test_limit_blocks_when_full() {
        let opt = PipeOption { limit: 10, ..PipeOption::default() };
        let (mut r, mut w) = new_with_option(opt);
        // 首次写 11 字节：初始 size=0，0 > 10 false，merge 后 size=11
        w.write_multi_buffer(mb(&[0u8; 11])).await.unwrap();
        // 第二次写应阻塞：11 > 10 true
        let writer = tokio::spawn(async move { w.write_multi_buffer(mb(&[0u8; 5])).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        // 读取应解除 writer 阻塞
        let data = r.read_multi_buffer().await.unwrap();
        assert_eq!(data.len(), 11);
        writer.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_discard_overflow_drops_excess() {
        let opt = PipeOption { limit: 10, discard_overflow: true, ..PipeOption::default() };
        let (_r, mut w) = new_with_option(opt);
        // 首次 11 字节：merge 成功，buffer=11
        w.write_multi_buffer(mb(&[0u8; 11])).await.unwrap();
        assert_eq!(w.len(), 11);
        // 第二次 5 字节：is_full(11)=true + discard_overflow，立即丢弃返回 Ok
        w.write_multi_buffer(mb(&[0u8; 5])).await.unwrap();
        // buffered 仍为 11
        assert_eq!(w.len(), 11);
    }

    // ========== Error 注入 ==========

    #[tokio::test]
    async fn test_return_an_error_propagates_to_reader() {
        let (mut r, _) = new();
        r.return_an_error(Error::ReadError("injected".into()));
        r.return_an_error(Error::ReadError("injected".into()));
        let err = r.read_multi_buffer().await.unwrap_err();
        assert!(matches!(err, Error::ReadError(ref s) if s == "injected"));
    }

    #[tokio::test]
    async fn test_recover_clears_error() {
        let (r, _) = new();
        r.return_an_error(Error::ReadError("injected".into()));
        r.return_an_error(Error::ReadError("injected".into()));
        let recovered = r.recover();
        assert!(matches!(recovered, Some(Error::ReadError(_))));
        // 已清，再 recover 返回 None
        assert!(r.recover().is_none());
    }

    #[tokio::test]
    async fn test_recover_when_empty_returns_none() {
        let (r, _w) = new();
        assert!(r.recover().is_none());
    }

    // ========== 超时 ==========

    #[tokio::test]
    async fn test_read_timeout() {
        let (mut r, _w) = new();
        let result = r.read_multi_buffer_timeout(Duration::from_millis(50)).await;
        assert!(matches!(result, Err(Error::TimeoutError)));
    }

    #[tokio::test]
    async fn test_read_timeout_succeeds_with_data() {
        let (mut r, mut w) = new();
        w.write_multi_buffer(mb(b"hello")).await.unwrap();
        let out = r.read_multi_buffer_timeout(Duration::from_secs(1)).await.unwrap();
        assert_eq!(out.to_vec(), b"hello");
    }

    // ========== idle_timeout ==========

    #[tokio::test]
    async fn test_idle_timeout_returns_eof() {
        let opt =
            PipeOption { idle_timeout: Some(Duration::from_millis(50)), ..PipeOption::default() };
        let (mut r, _w) = new_with_option(opt);
        // 不写任何数据，reader 应在 idle_timeout 后返回 EOF
        let result = r.read_multi_buffer().await;
        assert!(matches!(result, Err(Error::Eof)));
    }

    #[tokio::test]
    async fn test_idle_timeout_resets_on_data() {
        let opt =
            PipeOption { idle_timeout: Some(Duration::from_millis(100)), ..PipeOption::default() };
        let (mut r, mut w) = new_with_option(opt);
        // 写入数据，reader 应立即返回数据（不触发 idle timeout）
        w.write_multi_buffer(mb(b"hello")).await.unwrap();
        let out = r.read_multi_buffer().await.unwrap();
        assert_eq!(out.to_vec(), b"hello");
        // 数据读完后再读，应触发 idle timeout 返回 EOF
        let result = r.read_multi_buffer().await;
        assert!(matches!(result, Err(Error::Eof)));
    }

    // ========== len / is_empty ==========

    #[tokio::test]
    async fn test_len_tracks_buffered() {
        let (r, mut w) = new();
        assert_eq!(w.len(), 0);
        assert!(w.is_empty());
        w.write_multi_buffer(mb(b"hello")).await.unwrap();
        assert_eq!(w.len(), 5);
        assert_eq!(r.len(), 5);
        assert!(!r.is_empty());
    }

    // ========== Reader/Writer trait ==========

    #[tokio::test]
    async fn test_reader_trait_impl() {
        let (mut r, mut w) = new();
        w.write_multi_buffer(mb(b"trait")).await.unwrap();
        let r_trait: &mut dyn BufReader = &mut r;
        let out = r_trait.read_multi_buffer().await.unwrap();
        assert_eq!(out.to_vec(), b"trait");
    }

    #[tokio::test]
    async fn test_writer_trait_impl() {
        let (mut r, mut w) = new();
        let w_trait: &mut dyn BufWriter = &mut w;
        w_trait.write_multi_buffer(mb(b"trait")).await.unwrap();
        let out = r.read_multi_buffer().await.unwrap();
        assert_eq!(out.to_vec(), b"trait");
    }

    #[tokio::test]
    async fn test_boxed_trait_objects() {
        let (r, w) = new();
        let mut r: Box<dyn BufReader> = Box::new(r);
        let mut w: Box<dyn BufWriter> = Box::new(w);
        w.write_multi_buffer(mb(b"boxed")).await.unwrap();
        let out = r.read_multi_buffer().await.unwrap();
        assert_eq!(out.to_vec(), b"boxed");
    }

    // ========== is_closed ==========

    #[tokio::test]
    async fn test_is_closed_state() {
        let (r, w) = new();
        assert!(!r.is_closed());
        assert!(!w.is_closed());
        w.close().unwrap();
        // watch::send(true) 是同步的，state 立即可见
        assert!(r.is_closed());
        assert!(w.is_closed());
    }

    #[tokio::test]
    async fn test_is_closed_after_interrupt() {
        let (r, w) = new();
        w.interrupt();
        assert!(r.is_closed());
        assert!(w.is_closed());
    }

    // ========== Go TestPipeWriteMultiThread / Interrupt-after-close ==========

    /// Go pipe_test.go TestPipeWriteMultiThread：limit=0 + 10 并发 writer + close。
    /// 语义：恰好一条写入 merge（isFull(cur)>0 阻塞其余），close 唤醒阻塞 writer
    /// 各自释放 mb 不污染 buffered，reader 读到一条完整 "abcd"。
    #[tokio::test]
    async fn test_multi_writer_close_keeps_one_whole_write() {
        let opt = PipeOption { limit: 0, ..PipeOption::default() };
        let (mut r, w) = new_with_option(opt);

        let mut handles = Vec::new();
        for _ in 0..10 {
            let mut w = w.clone();
            handles.push(tokio::spawn(async move { w.write_multi_buffer(mb(b"abcd")).await }));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        w.close().unwrap();
        // Go 原版 errg.Wait() 裸调用忽略错误：恰一个 Ok，其余 Err
        for h in handles {
            let _ = h.await.unwrap();
        }

        // buffered 恰好一条完整写入（多条 merge 会是 "abcdabcd..."）
        let out = r.read_multi_buffer().await.unwrap();
        assert_eq!(out.to_vec(), b"abcd");
        // 读完 EOF
        let err = r.read_multi_buffer().await.unwrap_err();
        assert!(matches!(err, Error::Eof));
    }

    /// Go impl.go Interrupt:194-199：closed 状态且有 buffered data 时 interrupt
    /// → 状态转 Errord、data 被丢弃，reader 得错误而非 drain。
    #[tokio::test]
    async fn test_interrupt_after_close_discards_buffered_data() {
        let (mut r, mut w) = new();
        w.write_multi_buffer(mb(b"data")).await.unwrap();
        w.close().unwrap();
        // close 后 buffered 本可 drain（EOF 语义），interrupt 优先：丢弃并转 errord
        w.interrupt();
        assert_eq!(w.len(), 0);
        let err = r.read_multi_buffer().await.unwrap_err();
        assert!(matches!(err, Error::WriteError(_)), "got {err:?}");
    }

    // ========== Clone ==========

    #[tokio::test]
    async fn test_reader_writer_clone_share_state() {
        let (r, mut w) = new();
        let r2 = r.clone();
        w.write_multi_buffer(mb(b"shared")).await.unwrap();
        // 从 clone 读
        let mut r2 = r2;
        let out = r2.read_multi_buffer().await.unwrap();
        assert_eq!(out.to_vec(), b"shared");
    }

    // ========== poll-once 丢唤醒回归（bd 34nk） ==========

    /// 唤醒计数器：验证「数据到达后读端确实被唤醒」，而不是只靠外部超时轮询。
    #[derive(Default)]
    struct WakeCounter {
        count: AtomicU64,
    }

    impl std::task::Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// 回归（bd 34nk）：「poll 一次即丢 future」的读法（`LinkStream::poll_read`
    /// 形态）下，写端写入后读端必须被唤醒。
    ///
    /// 修复前：pipe 读端在 `select!` 里 await `Notify::notified()`，注册随
    /// future 丢弃销毁 → 写端 `signal()` 只剩计数、无 waker 可唤醒 → 读端
    /// 永久失唤醒（只能等调用方自己的超时轮询）。
    #[tokio::test]
    async fn test_poll_once_reader_woken_by_write() {
        let (mut r, mut w) = new();
        let counter = Arc::new(WakeCounter::default());
        let waker = std::task::Waker::from(counter.clone());
        let mut cx = Context::from_waker(&waker);

        // 第一次 poll：空管道 → Pending（future 立即丢弃）
        let got = {
            let mut fut = BufReader::read_multi_buffer(&mut r);
            fut.as_mut().poll(&mut cx)
        };
        assert!(got.is_pending(), "空管道读端应 Pending");

        // 写端写入 → 读端必须被唤醒
        w.write_multi_buffer(mb(b"hello")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            counter.count.load(Ordering::SeqCst) > 0,
            "写端写入后读端未被唤醒（丢唤醒）：数据只能等外部超时轮询才被取走"
        );

        // 再 poll 一次应拿到数据
        let got = {
            let mut fut = BufReader::read_multi_buffer(&mut r);
            fut.as_mut().poll(&mut cx)
        };
        match got {
            Poll::Ready(Ok(data)) => assert_eq!(data.to_vec(), b"hello"),
            Poll::Ready(Err(e)) => panic!("期望读到数据，实际错误：{e}"),
            Poll::Pending => panic!("期望读到数据，实际 Pending"),
        }
    }

    /// 回归（bd 34nk）：对称场景——管道满时写端 Pending（future 丢弃），
    /// 读端取走数据腾出空间后写端必须被唤醒。
    #[tokio::test]
    async fn test_poll_once_writer_woken_when_reader_drains() {
        let opt = PipeOption { limit: 10, ..PipeOption::default() };
        let (mut r, mut w) = new_with_option(opt);
        // 填满管道（11 > limit=10）
        w.write_multi_buffer(mb(&[0u8; 11])).await.unwrap();

        let counter = Arc::new(WakeCounter::default());
        let waker = std::task::Waker::from(counter.clone());
        let mut cx = Context::from_waker(&waker);

        // 写端 poll：管道满 → Pending（future 立即丢弃；本次只验证唤醒语义）
        let got = {
            let mut fut = BufWriter::write_multi_buffer(&mut w, mb(b"more"));
            fut.as_mut().poll(&mut cx)
        };
        assert!(got.is_pending(), "满管道写端应 Pending");

        // 读端取走数据 → 写端必须被唤醒
        let data = r.read_multi_buffer().await.unwrap();
        assert_eq!(data.len(), 11);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            counter.count.load(Ordering::SeqCst) > 0,
            "读端腾出空间后写端未被唤醒（丢唤醒）：写入只能等外部超时轮询才推进"
        );
    }
}
