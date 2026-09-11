//! Connection 核心（对应 Go `connection.go`）。
//!
//! 编排 [`SendingWorker`] + [`ReceivingWorker`] + [`RoundTripInfo`] + State 状态机，
//! 处理 segment 输入、周期 flush、Ping 维持、优雅关闭。
//!
//! # IO 边界
//!
//! - [`ConnectionCloser`]：关闭底层连接（Go `io.Closer`），生产由 dialer/listener 注入。
//! - [`SegmentWriter`]：输出 segment（已在 [`output`] 模块定义）。
//! - `TokioUpdater`：生产模式 spawn 周期任务；测试模式用 `None`（核心逻辑不依赖 updater）。
//!
//! Read/Write 提供**同步**简化版（不等待窗口/数据，短写或返回 0），上层 adapter
//! 包装成 AsyncRead/AsyncWrite。

use std::pin::Pin;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::Notify;

use crate::config::Config;
use crate::error::{KcpError, Result};
use crate::output::SegmentWriter;
use crate::receiving::ReceivingWorker;
use crate::round_trip::RoundTripInfo;
use crate::segment::{
    CmdOnlySegment, Command, Segment, SegmentKind, SegmentOption,
    DATA_SEGMENT_OVERHEAD, SEGMENT_OPTION_CLOSE,
};
use crate::sending::SendingWorker;
use crate::state::State;
use crate::updater::{TokioUpdater, Updater};

/// IO 边界 trait：关闭底层连接（对应 Go `io.Closer`）。
pub trait ConnectionCloser: Send + Sync {
    /// 关闭底层 socket。
    fn close(&self);
}

/// 空实现的 closer（测试用 / dialer 未接入时）。
#[derive(Debug, Default)]
pub struct NoopCloser;

impl ConnectionCloser for NoopCloser {
    fn close(&self) {}
}

/// 连接元数据（对应 Go `ConnMetadata`）。
#[derive(Debug, Clone, Default)]
pub struct ConnMetadata {
    /// 会话 ID。
    pub conv: u16,
    /// 本地地址。
    pub local_addr: Option<std::net::SocketAddr>,
    /// 远端地址。
    pub remote_addr: Option<std::net::SocketAddr>,
}

impl ConnMetadata {
    #[must_use]
    pub fn new(conv: u16) -> Self {
        Self {
            conv,
            local_addr: None,
            remote_addr: None,
        }
    }
}

/// 30 秒无 incoming 则关闭（对应 Go `30000ms`）。
const STALE_TIMEOUT_MS: u32 = 30_000;
/// Ping 间隔（对应 Go `3000ms`）。
const PING_INTERVAL_MS: u32 = 3_000;
/// Terminating 状态最长持续（对应 Go `8000ms`）。
const TERMINATING_TIMEOUT_MS: u32 = 8_000;
/// PeerTerminating 等待（对应 Go `4000ms`）。
const PEER_TERMINATING_TIMEOUT_MS: u32 = 4_000;
/// ReadyToClose 超时（对应 Go `15000ms`）。
const READY_TO_CLOSE_TIMEOUT_MS: u32 = 15_000;
/// PingUpdater 默认间隔（对应 Go `5000ms`）。
const PING_UPDATER_INTERVAL: Duration = Duration::from_millis(5_000);

/// KCP 连接（对应 Go `Connection`）。
///
/// 内部状态通过 `Arc<ConnectionInner>` 共享，workers + closer + output 均在内。
/// `data_updater` / `ping_updater` 可选（测试时 `None`，生产时 `Some(TokioUpdater)`）。
pub struct Connection {
    inner: Arc<ConnectionInner>,
    data_updater: Option<Arc<TokioUpdater>>,
    ping_updater: Option<Arc<TokioUpdater>>,
}

struct ConnectionInner {
    meta: ConnMetadata,
    state: AtomicI32,
    state_begin_time: AtomicU32,
    last_incoming_time: AtomicU32,
    last_ping_time: AtomicU32,
    since: Instant,
    mss: u32,
    round_trip: Arc<RoundTripInfo>,
    #[allow(dead_code)]
    config: Arc<Config>,
    sending_worker: SendingWorker,
    receiving_worker: ReceivingWorker,
    output: Arc<dyn SegmentWriter>,
    closer: Arc<dyn ConnectionCloser>,
    data_input: Notify,
    data_output: Notify,
    read_deadline: Mutex<Option<Instant>>,
    write_deadline: Mutex<Option<Instant>>,
}

impl Drop for ConnectionInner {
    fn drop(&mut self) {
        // 置位底层 socket 关闭标志，唤醒阻塞的 fetch_input/接收循环——否则
        // Runtime::drop 等 blocking task 永不返回。
        self.closer.close();
    }
}

impl Connection {
    /// 生产构造（对应 Go `NewConnection`）。
    ///
    /// 创建后立即 `ping_updater.wake_up_arc()`（Go 源码同样）。需要 tokio runtime。
    #[must_use]
    pub fn new(
        meta: ConnMetadata,
        writer: Arc<dyn SegmentWriter>,
        closer: Arc<dyn ConnectionCloser>,
        config: Arc<Config>,
    ) -> Self {
        Self::build(meta, writer, closer, config, true)
    }

    /// 测试构造：不创建 updater（避免依赖 tokio runtime）。
    #[must_use]
    pub fn new_without_updater(
        meta: ConnMetadata,
        writer: Arc<dyn SegmentWriter>,
        closer: Arc<dyn ConnectionCloser>,
        config: Arc<Config>,
    ) -> Self {
        Self::build(meta, writer, closer, config, false)
    }

    fn build(
        meta: ConnMetadata,
        writer: Arc<dyn SegmentWriter>,
        closer: Arc<dyn ConnectionCloser>,
        config: Arc<Config>,
        with_updaters: bool,
    ) -> Self {
        let conv = meta.conv;
        let tti = config.tti;
        let mss = config.mtu.saturating_sub(DATA_SEGMENT_OVERHEAD as u32);
        let rtt = Arc::new(RoundTripInfo::new(tti));

        let sending_worker = SendingWorker::new(conv, rtt.clone(), config.clone());
        let receiving_worker =
            ReceivingWorker::new(rtt.clone(), config.clone(), conv, mss as usize + DATA_SEGMENT_OVERHEAD);

        let inner = Arc::new(ConnectionInner {
            meta,
            state: AtomicI32::new(State::Active as i32),
            state_begin_time: AtomicU32::new(0),
            last_incoming_time: AtomicU32::new(0),
            last_ping_time: AtomicU32::new(0),
            since: Instant::now(),
            mss,
            round_trip: rtt,
            config,
            sending_worker,
            receiving_worker,
            output: writer,
            closer,
            data_input: Notify::new(),
            data_output: Notify::new(),
            read_deadline: Mutex::new(None),
            write_deadline: Mutex::new(None),
        });

        let (data_updater, ping_updater) = if with_updaters {
            let data = TokioUpdater::new(
                Duration::from_millis(tti as u64),
                {
                    let w = Arc::downgrade(&inner);
                    move || {
                        let Some(i) = w.upgrade() else {
                            return false;
                        };
                        let state = State::from_i32(i.state.load(Ordering::SeqCst)).unwrap_or(State::Terminated);
                        !state.is(&[State::Terminating, State::Terminated])
                            && (i.sending_worker.update_necessary() || i.receiving_worker.update_necessary())
                    }
                },
                {
                    let w = Arc::downgrade(&inner);
                    move || {
                        let Some(i) = w.upgrade() else {
                            return true;
                        };
                        let state = State::from_i32(i.state.load(Ordering::SeqCst)).unwrap_or(State::Terminated);
                        state.is(&[State::Terminating, State::Terminated])
                    }
                },
                {
                    let w = Arc::downgrade(&inner);
                    move || {
                        let Some(i) = w.upgrade() else {
                            return;
                        };
                        Connection::flush_inner(&i);
                    }
                },
            );
            let ping = TokioUpdater::new(
                PING_UPDATER_INTERVAL,
                {
                    let w = Arc::downgrade(&inner);
                    move || {
                        let Some(i) = w.upgrade() else {
                            return false;
                        };
                        let state = State::from_i32(i.state.load(Ordering::SeqCst)).unwrap_or(State::Terminated);
                        state != State::Terminated
                    }
                },
                {
                    let w = Arc::downgrade(&inner);
                    move || w.upgrade().is_none()
                },
                {
                    let w = Arc::downgrade(&inner);
                    move || {
                        let Some(i) = w.upgrade() else {
                            return;
                        };
                        Connection::flush_inner(&i);
                    }
                },
            );
            ping.wake_up_arc();
            (Some(data), Some(ping))
        } else {
            (None, None)
        };

        Self {
            inner,
            data_updater,
            ping_updater,
        }
    }

    /// 当前状态（对应 Go `Connection.State`）。
    #[must_use]
    pub fn state(&self) -> State {
        State::from_i32(self.inner.state.load(Ordering::SeqCst)).unwrap_or(State::Terminated)
    }

    /// 自连接创建以来的毫秒数（对应 Go `Connection.Elapsed`，u32 会 wrap）。
    fn elapsed(&self) -> u32 {
        self.inner.since.elapsed().as_millis() as u32
    }

    /// 设置状态 + 副作用（对应 Go `Connection.SetState`）。
    pub fn set_state(&self, state: State) {
        let current = self.elapsed();
        self.inner.state.store(state as i32, Ordering::SeqCst);
        self.inner.state_begin_time.store(current, Ordering::SeqCst);

        match state {
            State::ReadyToClose => self.inner.receiving_worker.close_read(),
            State::PeerClosed => self.inner.sending_worker.close_write(),
            State::Terminating => {
                self.inner.receiving_worker.close_read();
                self.inner.sending_worker.close_write();
                self.set_ping_interval(Duration::from_secs(1));
            }
            State::PeerTerminating => {
                self.inner.sending_worker.close_write();
                self.set_ping_interval(Duration::from_secs(1));
            }
            State::Terminated => {
                self.inner.receiving_worker.close_read();
                self.inner.sending_worker.close_write();
                self.set_ping_interval(Duration::from_secs(1));
                self.wake_data_updater();
                self.wake_ping_updater();
                self.terminate();
            }
            State::Active => {}
        }
    }

    /// 关闭连接（对应 Go `Connection.Close`）。
    pub fn close(&self) -> Result<()> {
        // permit 语义（票 eapf）：notify_waiters 只唤醒已注册 waiter 且不留
        // permit——close 落在 poll_read 空读与 notified 注册之间时唤醒丢失，
        // 挂起读要等 updater 下次 transition（数秒）才醒。notify_one 留存
        // permit，此后注册的 waiter 立即通过。
        self.inner.data_input.notify_one();
        self.inner.data_output.notify_one();

        match self.state() {
            State::ReadyToClose | State::Terminating | State::Terminated => {
                Err(KcpError::ClosedConnection)
            }
            State::Active => {
                self.set_state(State::ReadyToClose);
                Ok(())
            }
            State::PeerClosed => {
                self.set_state(State::Terminating);
                Ok(())
            }
            State::PeerTerminating => {
                self.set_state(State::Terminated);
                Ok(())
            }
        }
    }

    /// 终止连接：关闭底层 socket + 释放 workers（对应 Go `Connection.Terminate`）。
    pub fn terminate(&self) {
        // 同 close()：permit 语义防唤醒丢失（票 eapf）
        self.inner.data_input.notify_one();
        self.inner.data_output.notify_one();
        self.inner.closer.close();
        self.inner.sending_worker.release();
        self.inner.receiving_worker.release();
    }

    /// 处理对端 CLOSE 选项位（对应 Go `Connection.HandleOption`）。
    pub fn handle_option(&self, opt: SegmentOption) {
        if (opt & SEGMENT_OPTION_CLOSE) == SEGMENT_OPTION_CLOSE {
            self.on_peer_closed();
        }
    }

    /// 对端关闭（对应 Go `Connection.OnPeerClosed`）。
    pub fn on_peer_closed(&self) {
        match self.state() {
            State::ReadyToClose => self.set_state(State::Terminating),
            State::Active => self.set_state(State::PeerClosed),
            _ => {}
        }
    }

    /// 处理收到的 segments（对应 Go `Connection.Input`）。
    pub fn input(&self, segments: Vec<SegmentKind>) {
        let current = self.elapsed();
        self.inner.last_incoming_time.store(current, Ordering::SeqCst);

        for seg in segments {
            if seg.conversation() != self.inner.meta.conv {
                break;
            }
            match seg {
                SegmentKind::Data(data) => {
                    let opt = data.option;
                    self.handle_option(opt);
                    self.inner.receiving_worker.process_segment(data);
                    let avail = self.inner.receiving_worker.is_data_available();
                    if avail {
                        self.inner.data_input.notify_one();
                    }
                    self.wake_data_updater();
                }
                SegmentKind::Ack(ack) => {
                    let opt = ack.option;
                    let rto = self.inner.round_trip.timeout();
                    self.handle_option(opt);
                    self.inner
                        .sending_worker
                        .process_ack_segment(current, ack, rto);
                    self.inner.data_output.notify_one();
                    self.wake_data_updater();
                }
                SegmentKind::Cmd(cmd) => {
                    let opt = cmd.option;
                    let cmd_command = cmd.command();
                    let receiving_next = cmd.receiving_next;
                    let sending_next = cmd.sending_next;
                    let peer_rto = cmd.peer_rto;
                    self.handle_option(opt);
                    if cmd_command == Command::Terminate {
                        match self.state() {
                            State::Active | State::PeerClosed => {
                                self.set_state(State::PeerTerminating);
                            }
                            State::ReadyToClose => self.set_state(State::Terminating),
                            State::Terminating => self.set_state(State::Terminated),
                            _ => {}
                        }
                    }
                    if opt == SEGMENT_OPTION_CLOSE || cmd_command == Command::Terminate {
                        self.inner.data_input.notify_one();
                        self.inner.data_output.notify_one();
                    }
                    self.inner.sending_worker.process_receiving_next(receiving_next);
                    self.inner
                        .receiving_worker
                        .process_sending_next(sending_next);
                    self.inner.round_trip.update_peer_rto(peer_rto, current);
                }
            }
        }
    }

    /// 周期 flush（对应 Go `Connection.flush` + `updateTask`）。
    pub fn flush(&self) {
        Self::flush_inner(&self.inner);
    }

    fn flush_inner(inner: &ConnectionInner) {
        let current = inner.since.elapsed().as_millis() as u32;
        let state =
            State::from_i32(inner.state.load(Ordering::SeqCst)).unwrap_or(State::Terminated);

        if state == State::Terminated {
            return;
        }
        if state == State::Active
            && current.wrapping_sub(inner.last_incoming_time.load(Ordering::SeqCst)) >= STALE_TIMEOUT_MS
        {
            // 模拟 Go `c.Close()`：仅推进状态机（不调 close() 避免重复 notify）
            inner.data_input.notify_one();
            inner.data_output.notify_one();
            inner.state.store(State::ReadyToClose as i32, Ordering::SeqCst);
            inner.state_begin_time.store(current, Ordering::SeqCst);
            inner.receiving_worker.close_read();
        }

        let state =
            State::from_i32(inner.state.load(Ordering::SeqCst)).unwrap_or(State::Terminated);
        if state == State::ReadyToClose && inner.sending_worker.is_empty() {
            inner.state.store(State::Terminating as i32, Ordering::SeqCst);
            inner.state_begin_time.store(current, Ordering::SeqCst);
            inner.receiving_worker.close_read();
            inner.sending_worker.close_write();
            return Self::flush_inner(inner);
        }

        let state =
            State::from_i32(inner.state.load(Ordering::SeqCst)).unwrap_or(State::Terminated);
        if state == State::Terminating {
            Self::ping_inner(inner, current, Command::Terminate);
            if current.wrapping_sub(inner.state_begin_time.load(Ordering::SeqCst))
                > TERMINATING_TIMEOUT_MS
            {
                inner.state.store(State::Terminated as i32, Ordering::SeqCst);
                inner.state_begin_time.store(current, Ordering::SeqCst);
                inner.receiving_worker.close_read();
                inner.sending_worker.close_write();
                inner.data_input.notify_one();
                inner.data_output.notify_one();
                inner.closer.close();
                inner.sending_worker.release();
                inner.receiving_worker.release();
            }
            return;
        }

        if state == State::PeerTerminating
            && current.wrapping_sub(inner.state_begin_time.load(Ordering::SeqCst))
                > PEER_TERMINATING_TIMEOUT_MS
        {
            inner.state.store(State::Terminating as i32, Ordering::SeqCst);
            inner.state_begin_time.store(current, Ordering::SeqCst);
            inner.receiving_worker.close_read();
            inner.sending_worker.close_write();
            return Self::flush_inner(inner);
        }

        let state =
            State::from_i32(inner.state.load(Ordering::SeqCst)).unwrap_or(State::Terminated);
        if state == State::ReadyToClose
            && current.wrapping_sub(inner.state_begin_time.load(Ordering::SeqCst))
                > READY_TO_CLOSE_TIMEOUT_MS
        {
            inner.state.store(State::Terminating as i32, Ordering::SeqCst);
            inner.state_begin_time.store(current, Ordering::SeqCst);
            inner.receiving_worker.close_read();
            inner.sending_worker.close_write();
            return Self::flush_inner(inner);
        }

        // flush workers
        let acks = inner.receiving_worker.flush(current, state);
        for ack in acks {
            let _ = inner.output.write_segment(&ack);
        }
        let _ = inner
            .sending_worker
            .flush_with_writer(current, &*inner.output, state);

        if current.wrapping_sub(inner.last_ping_time.load(Ordering::SeqCst)) >= PING_INTERVAL_MS {
            Self::ping_inner(inner, current, Command::Ping);
        }
    }

    /// 发送 Ping / Terminate（对应 Go `Connection.Ping`）。
    pub fn ping(&self, current: u32, cmd: Command) {
        Self::ping_inner(&self.inner, current, cmd);
    }

    fn ping_inner(inner: &ConnectionInner, current: u32, cmd: Command) {
        let mut seg = CmdOnlySegment::new();
        seg.conv = inner.meta.conv;
        seg.cmd = cmd;
        seg.receiving_next = inner.receiving_worker.next_number();
        seg.sending_next = inner.sending_worker.first_unacknowledged();
        seg.peer_rto = inner.round_trip.timeout();
        let state =
            State::from_i32(inner.state.load(Ordering::SeqCst)).unwrap_or(State::Terminated);
        if state == State::ReadyToClose {
            seg.option = SEGMENT_OPTION_CLOSE;
        }
        let _ = inner.output.write_segment(&seg);
        inner.last_ping_time.store(current, Ordering::SeqCst);
    }

    /// 同步简化 Read（对应 Go `Connection.Read` 的非阻塞部分）。
    ///
    /// 返回读取字节数（0 表示暂无数据）。状态终态返回 `Err(ClosedConnection)`。
    pub fn read(&self, b: &mut [u8]) -> Result<usize> {
        if self
            .state()
            .is(&[State::ReadyToClose, State::Terminating, State::Terminated])
        {
            return Err(KcpError::ClosedConnection);
        }
        let n = self.inner.receiving_worker.read(b);
        if n > 0 {
            self.wake_data_updater();
        }
        Ok(n)
    }

    /// 同步简化 Write（对应 Go `Connection.Write` 的非阻塞部分）。
    pub fn write(&self, b: &[u8]) -> Result<usize> {
        if self.state() != State::Active {
            return Err(KcpError::ClosedConnection);
        }
        let mss = self.inner.mss as usize;
        let mut written = 0;
        while written < b.len() {
            let end = (written + mss).min(b.len());
            let chunk = &b[written..end];
            let mut buf = xray_buf::buffer::Buffer::new();
            buf.write_from(chunk);
            let state = self.state();
            if !self.inner.sending_worker.push(buf, state) {
                break;
            }
            written = end;
        }
        if written > 0 {
            self.wake_data_updater();
        }
        Ok(written)
    }

    fn wake_data_updater(&self) {
        if let Some(u) = &self.data_updater {
            u.wake_up_arc();
        }
    }

    fn wake_ping_updater(&self) {
        if let Some(u) = &self.ping_updater {
            u.wake_up_arc();
        }
    }

    fn set_ping_interval(&self, interval: Duration) {
        if let Some(u) = &self.ping_updater {
            u.set_interval(interval);
        }
    }

    /// 会话 ID。
    #[must_use]
    pub fn conv(&self) -> u16 {
        self.inner.meta.conv
    }

    /// 本地地址。
    #[must_use]
    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.meta.local_addr
    }

    /// 远端地址。
    #[must_use]
    pub fn remote_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.meta.remote_addr
    }

    /// 通知 data_input（上层 async read 可以 await 这个 Notify）。
    pub fn notify_data_input(&self) {
        self.inner.data_input.notify_one();
    }

    /// 通知 data_output（上层 async write 可以 await 这个 Notify）。
    pub fn notify_data_output(&self) {
        self.inner.data_output.notify_one();
    }

    /// 设置读截止时间。
    pub fn set_read_deadline(&self, t: Option<Instant>) -> Result<()> {
        if self.state() != State::Active {
            return Err(KcpError::ClosedConnection);
        }
        *self.inner.read_deadline.lock() = t;
        Ok(())
    }

    /// 设置写截止时间。
    pub fn set_write_deadline(&self, t: Option<Instant>) -> Result<()> {
        if self.state() != State::Active {
            return Err(KcpError::ClosedConnection);
        }
        *self.inner.write_deadline.lock() = t;
        Ok(())
    }
}

/// KCP `Connection` → `xray_transport::connection::Connection` 异步适配器。
///
/// KCP `Connection` 的 read/write 是同步非阻塞（返回 0 表示暂无数据），
/// 通过 `Notify`（`data_input`/`data_output`）通知数据就绪。
/// 本适配器用 `notified().await` 等待 + 同步 read/write 实现异步 IO。
///
/// 缓存的等待 future 不捕获任何 poll 调用参数（buf 大小/数据副本）——对齐 Go
/// `waitForDataInput`/`waitForDataOutput`（connection.go）：唤醒后用当次 poll
/// 的 buf 重新同步读/写，否则换 buf 复用未完成 future 会写出旧参数
/// （put_slice 溢出 panic / 写出旧数据，bd Xray-core-rust-0mp）。
pub struct KcpConn {
    inner: Arc<Connection>,
    read_state: parking_lot::Mutex<Option<Pin<Box<dyn Future<Output = ()> + Send>>>>,
    write_state: parking_lot::Mutex<Option<Pin<Box<dyn Future<Output = ()> + Send>>>>,
}

impl KcpConn {
    /// 构造。
    #[must_use]
    pub fn new(inner: Arc<Connection>) -> Self {
        Self { inner, read_state: parking_lot::Mutex::new(None), write_state: parking_lot::Mutex::new(None) }
    }

    /// 内部引用。
    #[must_use]
    pub fn inner(&self) -> &Arc<Connection> {
        &self.inner
    }
}

impl std::fmt::Debug for KcpConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KcpConn").finish_non_exhaustive()
    }
}

impl tokio::io::AsyncRead for KcpConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return std::task::Poll::Ready(Ok(()));
        }

        // 对齐 Go Connection.Read（connection.go:316）：循环「用当前 buf 同步读 →
        // 无数据等通知」。缓存 future 只等 data_input（Go waitForDataInput 不携带
        // 调用参数），唤醒后用本次 poll 的 buf 重读。
        let mut tmp = vec![0u8; buf.remaining()];
        loop {
            match self.inner.read(&mut tmp) {
                Ok(0) => {}
                Ok(n) => {
                    buf.put_slice(&tmp[..n]);
                    return std::task::Poll::Ready(Ok(()));
                }
                Err(e) => {
                    return std::task::Poll::Ready(Err(std::io::Error::other(e.to_string())))
                }
            }

            let mut state = self.read_state.lock();
            if state.is_none() {
                let inner = Arc::clone(&self.inner);
                *state = Some(Box::pin(async move {
                    inner.inner.data_input.notified().await;
                }));
            }
            if state.as_mut().unwrap().as_mut().poll(cx).is_pending() {
                return std::task::Poll::Pending;
            }
            // 通知已到达：消费掉缓存的 future（防重 poll 已完成 future），重读
            *state = None;
        }
    }
}

impl tokio::io::AsyncWrite for KcpConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        // 对齐 Go Connection.Write（connection.go:370 + waitForDataOutput）：
        // 循环「用当前 buf 同步写 → 窗口满等通知」。缓存 future 只等
        // data_output、不持有 buf 副本，唤醒后用本次 poll 的 buf 重写。
        loop {
            match self.inner.write(buf) {
                Ok(0) => {}
                Ok(n) => return std::task::Poll::Ready(Ok(n)),
                Err(e) => {
                    return std::task::Poll::Ready(Err(std::io::Error::other(e.to_string())))
                }
            }

            let mut state = self.write_state.lock();
            if state.is_none() {
                let inner = Arc::clone(&self.inner);
                *state = Some(Box::pin(async move {
                    inner.inner.data_output.notified().await;
                }));
            }
            if state.as_mut().unwrap().as_mut().poll(cx).is_pending() {
                return std::task::Poll::Pending;
            }
            *state = None;
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.inner.flush();
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // ponytail: bridge 半关闭时关闭底层 UDP socket——close() 仅置 ReadyToClose，
        // client 端无 listener 触发 Terminated，fetch_input 阻塞 recv 永不返回
        // （Runtime::drop 等 spawn_blocking 测试挂死根因）。Go dialer 由 listener
        // Terminate 兜底；Rust dialer 必经此处。
        self.inner.terminate();
        std::task::Poll::Ready(Ok(()))
    }
}

impl xray_transport::connection::Connection for KcpConn {
    fn remote_addr(&self) -> std::io::Result<Option<std::net::SocketAddr>> {
        Ok(self.inner.remote_addr())
    }

    fn local_addr(&self) -> std::io::Result<Option<std::net::SocketAddr>> {
        Ok(self.inner.local_addr())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::default_config;
    use crate::segment::{AckSegment, DataSegment, Segment};
    use parking_lot::Mutex as PMutex;
    use tokio::io::AsyncRead as _;
    use std::sync::atomic::AtomicUsize;

    /// 收集所有写入的 segment（测试用 SegmentWriter）。
    struct CollectWriter {
        segments: PMutex<Vec<SegmentKind>>,
    }

    impl CollectWriter {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                segments: PMutex::new(Vec::new()),
            })
        }
        fn take(&self) -> Vec<SegmentKind> {
            self.segments.lock().drain(..).collect()
        }
        fn count(&self) -> usize {
            self.segments.lock().len()
        }
    }

    impl SegmentWriter for CollectWriter {
        fn write_segment(&self, seg: &dyn Segment) -> std::io::Result<()> {
            let size = seg.byte_size();
            let mut buf = vec![0u8; size];
            seg.serialize(&mut buf);
            if let Some((kind, _)) = crate::segment::read_segment(&buf) {
                self.segments.lock().push(kind);
            }
            Ok(())
        }
    }

    fn make_connection(conv: u16) -> (Connection, Arc<CollectWriter>) {
        let writer = CollectWriter::new();
        let config = Arc::new(default_config());
        let conn = Connection::new_without_updater(
            ConnMetadata::new(conv),
            writer.clone(),
            Arc::new(NoopCloser),
            config,
        );
        (conn, writer)
    }

    fn make_data(conv: u16, number: u32, payload: &[u8]) -> DataSegment {
        let mut seg = DataSegment::new();
        seg.conv = conv;
        seg.number = number;
        seg.timestamp = 100;
        seg.data().write_from(payload);
        seg
    }

    fn make_ack(conv: u16, number: u32) -> AckSegment {
        let mut seg = AckSegment::new(128);
        seg.conv = conv;
        seg.receiving_next = 0;
        seg.receiving_window = 32;
        seg.timestamp = 100;
        seg.put_number(number);
        seg
    }

    fn make_cmd(conv: u16, cmd: Command) -> crate::segment::CmdOnlySegment {
        let mut seg = crate::segment::CmdOnlySegment::new();
        seg.conv = conv;
        seg.cmd = cmd;
        seg
    }

    #[test]
    fn new_connection_starts_active() {
        let (conn, _) = make_connection(42);
        assert_eq!(conn.state(), State::Active);
        assert_eq!(conn.conv(), 42);
    }

    #[test]
    fn set_state_transitions_and_side_effects() {
        let (conn, _) = make_connection(1);
        conn.set_state(State::ReadyToClose);
        assert_eq!(conn.state(), State::ReadyToClose);
        conn.set_state(State::PeerClosed);
        assert_eq!(conn.state(), State::PeerClosed);
    }

    #[test]
    fn close_from_active_to_ready_to_close() {
        let (conn, _) = make_connection(1);
        assert!(conn.close().is_ok());
        assert_eq!(conn.state(), State::ReadyToClose);
    }

    #[test]
    fn close_from_ready_to_close_returns_error() {
        let (conn, _) = make_connection(1);
        conn.set_state(State::ReadyToClose);
        assert!(matches!(conn.close(), Err(KcpError::ClosedConnection)));
    }

    #[test]
    fn close_from_peer_closed_to_terminating() {
        let (conn, _) = make_connection(1);
        conn.set_state(State::PeerClosed);
        assert!(conn.close().is_ok());
        assert_eq!(conn.state(), State::Terminating);
    }

    #[test]
    fn close_from_peer_terminating_to_terminated() {
        let (conn, _) = make_connection(1);
        conn.set_state(State::PeerTerminating);
        assert!(conn.close().is_ok());
        assert_eq!(conn.state(), State::Terminated);
    }

    #[test]
    fn input_data_segment_notifies_data_input() {
        let (conn, _) = make_connection(1);
        let seg = make_data(1, 0, b"hello");
        conn.input(vec![SegmentKind::Data(seg)]);
        assert!(conn.read(&mut [0u8; 32]).unwrap() > 0);
    }

    #[test]
    fn input_ignores_wrong_conv() {
        let (conn, _) = make_connection(1);
        let seg = make_data(99, 0, b"hello");
        conn.input(vec![SegmentKind::Data(seg)]);
        let mut buf = [0u8; 32];
        assert_eq!(conn.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn input_ack_segment_processes_sending() {
        let (conn, _) = make_connection(1);
        conn.write(b"test").unwrap();
        let ack = make_ack(1, 0);
        conn.input(vec![SegmentKind::Ack(ack)]);
    }

    #[test]
    fn input_cmd_terminate_transitions_state() {
        let (conn, _) = make_connection(1);
        let cmd = make_cmd(1, Command::Terminate);
        conn.input(vec![SegmentKind::Cmd(cmd)]);
        assert_eq!(conn.state(), State::PeerTerminating);
    }

    #[test]
    fn input_cmd_with_close_option_triggers_on_peer_closed() {
        let (conn, _) = make_connection(1);
        let mut cmd = make_cmd(1, Command::Ping);
        cmd.option = SEGMENT_OPTION_CLOSE;
        conn.input(vec![SegmentKind::Cmd(cmd)]);
        assert_eq!(conn.state(), State::PeerClosed);
    }

    #[test]
    fn ping_writes_cmd_only_segment() {
        let (conn, writer) = make_connection(7);
        conn.ping(1000, Command::Ping);
        assert_eq!(writer.count(), 1);
        let segs = writer.take();
        match &segs[0] {
            SegmentKind::Cmd(c) => {
                assert_eq!(c.conv, 7);
                assert_eq!(c.cmd, Command::Ping);
            }
            other => panic!("expected Cmd, got {other:?}"),
        }
    }

    #[test]
    fn ping_with_terminate_command() {
        let (conn, writer) = make_connection(1);
        conn.ping(1000, Command::Terminate);
        let segs = writer.take();
        match &segs[0] {
            SegmentKind::Cmd(c) => assert_eq!(c.cmd, Command::Terminate),
            other => panic!("expected Cmd, got {other:?}"),
        }
    }

    #[test]
    fn write_returns_error_when_not_active() {
        let (conn, _) = make_connection(1);
        conn.set_state(State::ReadyToClose);
        assert!(matches!(conn.write(b"x"), Err(KcpError::ClosedConnection)));
    }

    #[test]
    fn read_returns_error_when_terminating() {
        let (conn, _) = make_connection(1);
        conn.set_state(State::Terminating);
        assert!(matches!(
            conn.read(&mut [0u8; 10]),
            Err(KcpError::ClosedConnection)
        ));
    }

    #[test]
    fn write_then_input_ack_round_trip() {
        let (conn, _) = make_connection(1);
        let n = conn.write(b"hello world").unwrap();
        assert_eq!(n, 11);
        let ack = make_ack(1, 0);
        conn.input(vec![SegmentKind::Ack(ack)]);
    }

    #[test]
    fn flush_active_sends_nothing_when_no_data() {
        let (conn, writer) = make_connection(1);
        conn.flush();
        assert_eq!(writer.count(), 0);
    }

    #[test]
    fn flush_after_write_sends_data_segment() {
        let (conn, writer) = make_connection(1);
        conn.write(b"hello").unwrap();
        writer.take();
        conn.flush();
        let segs = writer.take();
        assert!(
            segs.iter().any(|s| matches!(s, SegmentKind::Data(_))),
            "should send at least one DataSegment"
        );
    }

    #[test]
    fn flush_terminating_sends_terminate_cmd() {
        let (conn, writer) = make_connection(1);
        conn.set_state(State::Terminating);
        writer.take();
        conn.flush();
        let segs = writer.take();
        assert!(
            segs.iter().any(|s| match s {
                SegmentKind::Cmd(c) => c.cmd == Command::Terminate,
                _ => false,
            }),
            "Terminating flush should send Terminate cmd"
        );
    }

    #[test]
    fn flush_writes_ack_for_received_data() {
        let (conn, writer) = make_connection(1);
        let data = make_data(1, 0, b"x");
        conn.input(vec![SegmentKind::Data(data)]);
        writer.take();
        conn.flush();
        let segs = writer.take();
        assert!(
            segs.iter().any(|s| matches!(s, SegmentKind::Ack(_))),
            "flush should send AckSegment for received data"
        );
    }

    #[test]
    fn terminate_releases_resources() {
        let closer_calls = Arc::new(AtomicUsize::new(0));
        struct CountingCloser(Arc<AtomicUsize>);
        impl ConnectionCloser for CountingCloser {
            fn close(&self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let closer = Arc::new(CountingCloser(closer_calls.clone()));
        let writer = CollectWriter::new();
        let config = Arc::new(default_config());
        let conn = Connection::new_without_updater(
            ConnMetadata::new(1),
            writer,
            closer,
            config,
        );
        conn.terminate();
        assert_eq!(closer_calls.load(Ordering::SeqCst), 1);
        conn.terminate();
    }

    #[test]
    fn set_state_terminated_calls_terminate() {
        let closer_calls = Arc::new(AtomicUsize::new(0));
        struct CountingCloser(Arc<AtomicUsize>);
        impl ConnectionCloser for CountingCloser {
            fn close(&self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let closer = Arc::new(CountingCloser(closer_calls.clone()));
        let writer = CollectWriter::new();
        let config = Arc::new(default_config());
        let conn = Connection::new_without_updater(
            ConnMetadata::new(1),
            writer,
            closer,
            config,
        );
        conn.set_state(State::Terminated);
        assert_eq!(conn.state(), State::Terminated);
        assert_eq!(
            closer_calls.load(Ordering::SeqCst),
            1,
            "terminate should close closer"
        );
    }

    // ===== cached future 参数捕获 bug（bd Xray-core-rust-0mp）=====

    fn noop_waker() -> std::task::Waker {
        fn clone(_: *const ()) -> std::task::RawWaker {
            std::task::RawWaker::new(std::ptr::null(), &VTABLE)
        }
        fn noop(_: *const ()) {}
        static VTABLE: std::task::RawWakerVTable =
            std::task::RawWakerVTable::new(clone, noop, noop, noop);
        // SAFETY: vtable 函数均为 no-op
        unsafe { std::task::Waker::from_raw(std::task::RawWaker::new(std::ptr::null(), &VTABLE)) }
    }

    /// 复现（对应 issue 描述）：read_state 缓存的 future 捕获首次 poll 的 buf
    /// 大小。注入线程在「poll_read 同步读返回 0」与「缓存 future 内 read」之间
    /// 的窗口注入数据时，旧实现把 future 读出的 n 字节 put_slice 进更小的当前
    /// buf → tokio `ReadBuf::put_slice` assert panic。
    ///
    /// 修复（对齐 Go `waitForDataInput`：等待不携带调用参数）：缓存 future 只等
    /// 通知，唤醒后用当前 buf 重新同步读。
    #[test]
    fn poll_read_pending_future_does_not_capture_first_buf_size() {
        const CONV: u16 = 7;
        const ROUNDS: usize = 3000;
        const PAYLOAD: usize = 500;
        let (conn, _writer) = make_connection(CONV);
        let conn = Arc::new(conn);
        let mut kcp = Box::pin(KcpConn::new(conn.clone()));
        let waker = noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);

        let injector = std::thread::spawn(move || {
            let payload = vec![0xABu8; PAYLOAD];
            for number in 0..ROUNDS as u32 {
                let seg = make_data(CONV, number, &payload);
                conn.input(vec![SegmentKind::Data(seg)]);
            }
        });

        let total = ROUNDS * PAYLOAD;
        let mut received = 0usize;
        let mut big = [0u8; 1024];
        let mut small = [0u8; 8];
        let mut use_big = true;
        let mut rounds = 0usize;
        while received < total && rounds < 20_000_000 {
            rounds += 1;
            let filled = if use_big {
                let mut rb = tokio::io::ReadBuf::new(&mut big);
                match kcp.as_mut().poll_read(&mut cx, &mut rb) {
                    std::task::Poll::Ready(Ok(())) => rb.filled().len(),
                    std::task::Poll::Pending => {
                        use_big = !use_big;
                        continue;
                    }
                    std::task::Poll::Ready(Err(_)) => break,
                }
            } else {
                let mut rb = tokio::io::ReadBuf::new(&mut small);
                match kcp.as_mut().poll_read(&mut cx, &mut rb) {
                    std::task::Poll::Ready(Ok(())) => rb.filled().len(),
                    std::task::Poll::Pending => {
                        use_big = !use_big;
                        continue;
                    }
                    std::task::Poll::Ready(Err(_)) => break,
                }
            };
            assert!(filled > 0);
            assert!(
                received + filled <= total,
                "read more bytes than injected: {received} + {filled} > {total}"
            );
            received += filled;
            use_big = !use_big;
        }
        injector.join().unwrap();
        assert_eq!(received, total, "should drain all injected bytes losslessly");
    }

    /// write 侧回归保护：发送窗口满挂起 → ACK 开窗唤醒 → 用当次 poll 的 buf
    /// 写出（read 侧参数捕获 panic 由上方并发测试锁定根因，write 侧为同构
    /// 修复，本测试保护挂起/唤醒路径不回归）。
    #[test]
    fn poll_write_pends_on_full_window_and_resumes_with_current_buf() {
        use tokio::io::AsyncWrite as _;
        const CONV: u16 = 9;
        let (conn, _writer) = make_connection(CONV);
        let conn = Arc::new(conn);
        let mut kcp = Box::pin(KcpConn::new(conn.clone()));
        let waker = noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);

        // 填满发送窗口（每轮 1 段，直到 push 失败返回 0）
        let filler = vec![0x11u8; 64];
        while conn.write(&filler).unwrap() > 0 {}

        // 窗口满：写挂起
        let a = vec![0xAAu8; 64];
        assert!(kcp.as_mut().poll_write(&mut cx, &a).is_pending());

        // ACK 释放窗口（input 的 Ack 分支会 notify_one 唤醒写端）
        conn.input(vec![SegmentKind::Ack(make_ack(CONV, 0))]);

        // 唤醒后：换 buf 写出当前 buf 的数据（旧实现写出的是挂起时捕获的 a 副本）
        let b = vec![0xBBu8; 64];
        match kcp.as_mut().poll_write(&mut cx, &b) {
            std::task::Poll::Ready(Ok(n)) => assert!(n > 0),
            other => panic!("expected ready after window reopened, got {other:?}"),
        }
        assert!(!conn.inner.sending_worker.is_empty());
    }

    /// 票 eapf：close/terminate 的唤醒必须留 permit（notify_one）。
    /// notify_waiters 不存 permit——无 waiter 时唤醒直接丢失，之后才挂起的
    /// 读/写等不到 EOF 通知，只能等 updater 定时 transition（数秒延迟）。
    #[tokio::test]
    async fn close_wakeup_leaves_permit_for_late_waiter() {
        let (conn, _) = make_connection(1);
        conn.close().unwrap();
        // 修复前：notify_waiters 在无 waiter 时执行 → permit 不存在 → 永久挂起
        tokio::time::timeout(std::time::Duration::from_millis(500), conn.inner.data_input.notified())
            .await
            .expect("close must leave a wakeup permit on data_input (notify_one)");
        tokio::time::timeout(std::time::Duration::from_millis(500), conn.inner.data_output.notified())
            .await
            .expect("close must leave a wakeup permit on data_output");
    }

    /// 票 eapf 验收：并发 close 竞态下挂起读必须及时醒来返回 ClosedConnection，
    /// 而非等 flush_inner 定时 transition。
    #[tokio::test]
    async fn close_wakes_pending_reader_promptly() {
        let (conn, _) = make_connection(1);
        let conn = Arc::new(conn);
        let mut kcp = KcpConn::new(conn.clone());
        let reader = tokio::spawn(async move {
            use tokio::io::AsyncReadExt as _;
            let mut buf = [0u8; 16];
            kcp.read(&mut buf).await
        });
        // 先让 reader 挂起（waiter 注册完毕），close 再到
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        conn.close().unwrap();
        let res = tokio::time::timeout(std::time::Duration::from_millis(300), reader)
            .await
            .expect("pending reader must wake promptly after close, not hang until next transition");
        assert!(
            res.expect("join").is_err(),
            "read must fail with closed connection after close"
        );
    }
}
