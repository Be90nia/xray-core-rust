//! Mux 客户端
//!
//! 对应 Go 版本 `common/mux/client.go`，实现 Mux 客户端的多路复用调度。
//!
//! # 核心组件
//!
//! - [`Link`]: 传输链路（读写两端）
//! - [`ClientManager`]: 顶层调度入口
//! - [`WorkerPicker`]: Worker 选择器 trait
//! - [`IncrementalWorkerPicker`]: 增量式选择器（LRU + 30s 清理）
//! - [`ClientWorker`]: 核心工作单元
//! - [`ClientWorkerFactory`]: Worker 工厂 trait
//! - [`DialingWorkerFactory`]: 拨号式 Worker 工厂

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::{watch, Mutex};
use tokio::time::Duration;
use tracing::debug;
use xray_buf::buffer::Buffer;
use xray_buf::io::{Reader, Writer};
use xray_buf::multi::MultiBuffer;
use xray_buf::reader::BufferedReader;
use xray_buf::writer::BufferedWriter;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;

use crate::frame::{FrameMetadata, SessionStatus, MAX_METADATA_LEN};
use crate::session::{ClientStrategy, Session, SessionManager, TransferType};
use crate::writer::{MuxWriter, SharedWriter};

// ========== 常量 ==========

/// Mux 协议识别地址
pub const MUX_COOL_ADDRESS: &str = "v1.mux.cool";

/// Mux 协议识别端口
pub const MUX_COOL_PORT: u16 = 9527;

/// 客户端心跳间隔
pub const CLIENT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(16);

/// 首包超时时间
pub const FIRST_PAYLOAD_TIMEOUT: Duration = Duration::from_millis(100);

/// 最大调度重试次数
pub const MAX_DISPATCH_RETRY: usize = 16;

/// Worker 选择器清理间隔
pub const PICKER_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

// ========== Link 结构 ==========

/// 传输链路，包含读取端和写入端。
///
/// 对应 Go 版本 `transport.Link`。
pub struct Link {
    /// 读取端
    pub reader: Box<dyn Reader>,
    /// 写入端
    pub writer: Box<dyn Writer>,
}

// ========== WorkerPicker trait ==========

/// Worker 选择器 trait。
///
/// 对应 Go 版本 `WorkerPicker` 接口。
pub trait WorkerPicker: Send + Sync {
    /// 选择一个可用的 ClientWorker。
    fn pick_available(&self) -> Option<Arc<ClientWorker>>;
}

// ========== ClientWorkerFactory trait ==========

/// Worker 工厂 trait。
///
/// 对应 Go 版本 `ClientWorkerFactory` 接口。
#[async_trait::async_trait]
pub trait ClientWorkerFactory: Send + Sync {
    /// 创建一个新的 ClientWorker。
    async fn create(&self) -> Arc<ClientWorker>;
}

// ========== ClientManager ==========

/// 客户端管理器，顶层调度入口。
///
/// 对应 Go 版本 `ClientManager`。
pub struct ClientManager {
    /// 是否启用 mux
    pub enabled: bool,
    /// Worker 选择器
    picker: Box<dyn WorkerPicker>,
}

impl ClientManager {
    /// 创建新的客户端管理器。
    pub fn new(enabled: bool, picker: Box<dyn WorkerPicker>) -> Self {
        Self { enabled, picker }
    }

    /// 调度连接到 mux worker。
    ///
    /// 对应 Go 版本 `ClientManager.Dispatch`。
    /// 最多重试 `MAX_DISPATCH_RETRY` 次寻找可用 Worker。
    pub fn dispatch(&self) -> Result<Arc<ClientWorker>, ClientError> {
        if !self.enabled {
            return Err(ClientError::MuxDisabled);
        }

        for _ in 0..MAX_DISPATCH_RETRY {
            if let Some(worker) = self.picker.pick_available() {
                if !worker.is_full() {
                    return Ok(worker);
                }
            }
        }

        Err(ClientError::NoAvailableWorker)
    }
}

// ========== IncrementalWorkerPicker ==========

/// 增量式 Worker 选择器。
///
/// 对应 Go 版本 `IncrementalWorkerPicker`。
/// 维护 Worker 列表，优先使用已有可用 Worker，
/// 不可用时通过 Factory 创建新 Worker。
pub struct IncrementalWorkerPicker {
    factory: Arc<dyn ClientWorkerFactory>,
    workers: Mutex<Vec<Arc<ClientWorker>>>,
    cleanup_started: AtomicBool,
}

impl IncrementalWorkerPicker {
    /// 创建新的增量式 Worker 选择器。
    pub fn new(factory: Arc<dyn ClientWorkerFactory>) -> Self {
        Self {
            factory,
            workers: Mutex::new(Vec::new()),
            cleanup_started: AtomicBool::new(false),
        }
    }

    /// 内部选择逻辑：查找可用 Worker 或创建新 Worker。
    ///
    /// 对应 Go 版本 `pickInternal`。
    ///
    /// 防止 `drop(workers) → factory.create() → re-acquire` 期间的并发穿透：
    /// 重新加锁后必须二次检查 find_available，否则 N 个并发任务会
    /// 创建 N 个 Worker 而非共享 1 个（Go 源码也是同一约束，靠 mutex 串行化）。
    pub async fn pick_internal(&self) -> Option<Arc<ClientWorker>> {
        // 第一次加锁：找可用 Worker；找不到时 drop 锁再创建（避免长 factory.create 持锁）。
        {
            let mut workers = self.workers.lock().await;
            if let Some(idx) = Self::find_available(&workers) {
                let len = workers.len();
                if idx != len - 1 {
                    workers.swap(idx, len - 1);
                }
                return Some(workers[len - 1].clone());
            }
            // 清理已关闭的 Worker
            workers.retain(|w| !w.is_closed());
        } // 锁在这里 drop

        // 锁外创建（factory.create 可能耗时：DNS / TCP 拨号）。
        let worker = self.factory.create().await;
        let mut workers = self.workers.lock().await;
        // 二次检查：并发穿透保护——其他任务可能在我们创建期间也
        // 创建了 worker 并 push 进列表；此刻优先复用现有可用 worker。
        if let Some(idx) = Self::find_available(&workers) {
            let len = workers.len();
            if idx != len - 1 {
                workers.swap(idx, len - 1);
            }
            return Some(workers[len - 1].clone());
        }
        // 真的没有可用 worker → push 本次创建的结果
        workers.push(worker.clone());

        // 首次创建 Worker 时标记清理已启动
        // 完整实现应使用 tokio::spawn 启动周期清理任务
        self.cleanup_started.store(true, Ordering::Relaxed);

        Some(worker)
    }

    /// 查找可用的 Worker 索引。
    fn find_available(workers: &[Arc<ClientWorker>]) -> Option<usize> {
        workers.iter().position(|w| !w.is_full() && !w.is_closed())
    }

    /// 清理已关闭的 Worker。
    pub async fn cleanup(&self) {
        let mut workers = self.workers.lock().await;
        let before = workers.len();
        workers.retain(|w| !w.is_closed());
        let removed = before - workers.len();
        if removed > 0 {
            debug!("cleaned up {} closed workers", removed);
        }
    }

    /// 获取 Worker 数量。
    pub async fn worker_count(&self) -> usize {
        self.workers.lock().await.len()
    }
}

impl WorkerPicker for IncrementalWorkerPicker {
    fn pick_available(&self) -> Option<Arc<ClientWorker>> {
        match self.workers.try_lock() {
            Ok(workers) => {
                if let Some(idx) = Self::find_available(&workers) {
                    return Some(workers[idx].clone());
                }
                None
            }
            Err(_) => None,
        }
    }
}

// ========== ClientWorker ==========

/// 客户端工作单元。
///
/// 对应 Go 版本 `ClientWorker`：持有一条 carrier 链路，在其上复用多个子会话。
/// 构造时启动两个数据循环：
/// - `fetch_output`：carrier 读循环（Go `fetchOutput`，client.go:382-419）
/// - `monitor`：16s 定时器，空闲时关闭 worker（Go `monitor`，client.go:226-244）
pub struct ClientWorker {
    session_manager: Arc<SessionManager>,
    closed: AtomicBool,
    done_tx: watch::Sender<bool>,
    done_rx: watch::Receiver<bool>,
    strategy: ClientStrategy,
    /// carrier 写端共享槽：全部 session 的 [`MuxWriter`] 经 [`SharedWriter`] 共写。
    link_writer: Arc<Mutex<Option<Box<dyn Writer>>>>,
}

impl ClientWorker {
    /// 创建新的 ClientWorker 并启动数据循环。
    ///
    /// 对应 Go `NewClientWorker`（`go c.fetchOutput()` / `go c.monitor()`）。
    /// `link` 为 carrier 链路：reader 收服务端下发帧，writer 发客户端上行帧。
    pub fn new(link: Link, strategy: ClientStrategy) -> Arc<Self> {
        let (done_tx, done_rx) = watch::channel(false);
        let worker = Arc::new(Self {
            session_manager: Arc::new(SessionManager::new()),
            closed: AtomicBool::new(false),
            done_tx,
            done_rx,
            strategy,
            link_writer: Arc::new(Mutex::new(Some(link.writer))),
        });

        let w = Arc::clone(&worker);
        tokio::spawn(async move { w.fetch_output(BufferedReader::new(link.reader)).await });

        let w = Arc::clone(&worker);
        tokio::spawn(async move { w.monitor().await });

        worker
    }

    /// 检查是否即将关闭（达到最大连接数）。
    #[must_use]
    pub fn is_closing(&self) -> bool {
        let max_conn = self.strategy.max_connection;
        max_conn > 0 && self.session_manager.count() >= max_conn as u16
    }

    /// 检查是否已满（达到并发或连接上限）。
    #[must_use]
    pub fn is_full(&self) -> bool {
        if self.is_closing() || self.is_closed() {
            return true;
        }
        let max_conc = self.strategy.max_concurrency;
        max_conc > 0 && self.session_manager.count() >= max_conc as u16
    }

    /// 检查是否已关闭。
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// 关闭 Worker。
    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        let _ = self.done_tx.send(true);
    }

    /// 分配新会话到此 Worker。
    pub async fn allocate_session(&self) -> Option<Arc<Session>> {
        if self.is_full() {
            return None;
        }
        self.session_manager.allocate(&self.strategy).await
    }

    /// 获取会话管理器引用。
    #[must_use]
    pub fn session_manager(&self) -> &Arc<SessionManager> {
        &self.session_manager
    }

    /// 获取策略引用。
    #[must_use]
    pub fn strategy(&self) -> &ClientStrategy {
        &self.strategy
    }

    /// 获取关闭信号接收端。
    pub fn done_rx(&self) -> watch::Receiver<bool> {
        self.done_rx.clone()
    }

    /// 获取会话管理器计数。
    #[must_use]
    pub fn session_count(&self) -> u16 {
        self.session_manager.count()
    }

    /// 创建 mux 目标地址（v1.mux.cool:9527）。
    #[must_use]
    pub fn mux_destination() -> Destination {
        use xray_common::net::address::Address;
        use xray_common::net::port::Port;
        Destination::new(
            Address::new_domain(MUX_COOL_ADDRESS),
            Port::new(MUX_COOL_PORT),
            Network::TCP,
        )
    }

    /// 调度一条子连接到本 worker 的 carrier 上（无源信息变体）。
    ///
    /// `dest` 为子会话真实目标（New 帧携带），`link` 为调用方链路。
    /// New 帧不带 GlobalID——服务端按普通 packet 路径处理（Go ctx 无
    /// inbound/cone 时 `xudp.GetGlobalID` 返回零值的等价）。
    pub async fn dispatch(&self, dest: &Destination, link: Link) -> bool {
        self.dispatch_with_source(dest, link, None).await
    }

    /// 带入站源信息的调度（Go client.go:271 `xudp.GetGlobalID(ctx)`）。
    ///
    /// `dest` 为 UDP 且 `input.cone` 时经 `xray_xudp::global_id` 计算源追踪
    /// GlobalID 随 New 帧下发，服务端按 GlobalID 复用 XUDP 会话（cone NAT 下
    /// 同源多目标共享单条 UDP 通道）。计算为零值（非 UDP 源等）或 `input`
    /// 为 None 时不带 GlobalID（兼容）。
    pub async fn dispatch_with_source(
        &self,
        dest: &Destination,
        link: Link,
        input: Option<&xray_xudp::GlobalIdInput>,
    ) -> bool {
        if self.is_full() {
            return false;
        }
        let Some(session) = self.session_manager.allocate(&self.strategy).await else {
            return false;
        };
        session.set_input(BufferedReader::new(link.reader)).await;
        session.set_output(BufferedWriter::new(link.writer)).await;

        let global_id = if dest.network() == Network::UDP {
            input.map(xray_xudp::global_id).filter(|g| *g != [0u8; 8])
        } else {
            None
        };

        let s = Arc::clone(&session);
        let writer_slot = Arc::clone(&self.link_writer);
        let target = dest.clone();
        tokio::spawn(async move { Self::fetch_input(s, target, writer_slot, global_id).await });

        wait_done(session.done_receiver()).await;
        true
    }

    /// session 上行循环：session.input → [`MuxWriter`] → carrier。
    ///
    /// 对应 Go `fetchInput`（client.go:259-287）。首包试探即 Go
    /// `writeFirstPayload`（client.go:246-257，fetchInput :276 调用）：
    /// [`FIRST_PAYLOAD_TIMEOUT`] 内无首包则发送仅含元数据的空 New 帧——
    /// 服务端收到即 dispatch 目标，服务端先说协议（SSH/FTP/SMTP）不再挂死；
    /// 有首包则随 New 帧同批写出。
    async fn fetch_input(
        session: Arc<Session>,
        dest: Destination,
        link_writer: Arc<Mutex<Option<Box<dyn Writer>>>>,
        global_id: Option<[u8; 8]>,
    ) {
        let transfer_type = if dest.network() == Network::UDP {
            TransferType::Packet
        } else {
            TransferType::Stream
        };
        let mut writer = MuxWriter::new(
            session.id(),
            dest,
            Box::new(SharedWriter::new(link_writer)),
            transfer_type,
            global_id,
        );

        let done = session.done_receiver();
        // Go writeFirstPayload：CopyOnceTimeout(100ms)。超时 → 写空
        // MultiBuffer（write_meta_only：仅元数据 New 帧）；EOF/读错误 →
        // Go 返回 err 走 hasError 收尾（不发首帧）。
        enum First {
            Payload(MultiBuffer),
            Probe,
            Abort,
        }
        let first = {
            let mut input = session.input().await;
            match input.as_mut() {
                None => First::Abort,
                Some(reader) => tokio::select! {
                    r = tokio::time::timeout(FIRST_PAYLOAD_TIMEOUT, reader.read_multi_buffer()) => match r {
                        Ok(Ok(mb)) => First::Payload(mb),
                        Ok(Err(_)) => First::Abort,
                        Err(_elapsed) => First::Probe,
                    },
                    _ = wait_done(done.clone()) => First::Abort,
                },
            }
        };
        let mut errored = matches!(first, First::Abort);
        match first {
            First::Payload(mb) => {
                if !mb.is_empty() {
                    session.add_uplink_bytes(mb.len() as u64);
                    session.touch_active().await;
                }
                errored = writer.write(mb).await.is_err();
            }
            First::Probe => {
                errored = writer.write(MultiBuffer::new()).await.is_err();
            }
            First::Abort => {}
        }

        if !errored {
            loop {
                let mut input = session.input().await;
                let Some(reader) = input.as_mut() else { break };
                // select session done：Session::close 需先拿 input 锁才能中断，
                // 持锁阻塞读期间必须可被 done 打断，否则与 close 互相等待死锁
                let read = tokio::select! {
                    r = reader.read_multi_buffer() => Some(r),
                    _ = wait_done(done.clone()) => None,
                };
                let mb = match read {
                    Some(Ok(mb)) => mb,
                    Some(Err(e)) => {
                        if !matches!(e, xray_buf::io::Error::Eof) {
                            writer.set_error();
                        }
                        break;
                    }
                    None => break,
                };
                if mb.is_empty() {
                    break;
                }
                session.add_uplink_bytes(mb.len() as u64);
                session.touch_active().await;
                if writer.write(mb).await.is_err() {
                    writer.set_error();
                    break;
                }
            }
        }
        // Go defer 顺序（client.go:272-273 LIFO）：End 帧先发，session 后关
        let _ = writer.close().await;
        session.close().await;
    }

    /// carrier 读循环。
    ///
    /// 对应 Go `fetchOutput`（client.go:382-419）：读帧 → 按 status 分发；
    /// 任何读错/EOF 退出并关闭 worker。
    async fn fetch_output(self: Arc<Self>, mut reader: BufferedReader) {
        let done = self.done_rx();
        loop {
            let (meta, data) = tokio::select! {
                _ = wait_done(done.clone()) => break,
                frame = read_frame(&mut reader) => match frame {
                    Ok(f) => f,
                    Err(e) => {
                        if !e.is_empty() {
                            debug!("mux client fetch_output stopped: {}", e);
                        }
                        break;
                    }
                },
            };

            match meta.session_status() {
                // 数据已随帧读出，丢弃即可（Go: Copy(NewStreamReader, Discard)）
                SessionStatus::KeepAlive | SessionStatus::New => {}
                SessionStatus::End => {
                    if let Some(session) = self.session_manager.get(meta.session_id()).await {
                        session.close().await;
                    }
                }
                SessionStatus::Keep => {
                    if self.handle_status_keep(&meta, data).await {
                        break;
                    }
                }
            }
        }
        // Go fetchOutput defer: done.Close()
        self.close();
    }

    /// 处理 Keep 帧：数据写入对应 session 的 output（app 方向）。
    ///
    /// 对应 Go `handleStatusKeep`（client.go:347-370）。
    /// 未知 session：ResponseWriter 发 End 帧通知对端 + 丢弃数据。
    /// 返回 `true` 表示致命错误（fetch_output 应退出）。
    async fn handle_status_keep(&self, meta: &FrameMetadata, data: Vec<u8>) -> bool {
        let Some(session) = self.session_manager.get(meta.session_id()).await else {
            let mut closing = MuxWriter::new_response_writer(
                meta.session_id(),
                Box::new(SharedWriter::new(Arc::clone(&self.link_writer))),
                TransferType::Stream,
            );
            return closing.close().await.is_err();
        };
        if data.is_empty() {
            return false;
        }
        session.add_downlink_bytes(data.len() as u64);
        session.touch_active().await;
        let mb = MultiBuffer::from_buffer(Buffer::from_vec(data));
        let write_failed = {
            let mut output = session.output().await;
            match output.as_mut() {
                Some(w) => w.write_multi_buffer_impl(mb).await.is_err(),
                None => false,
            }
        };
        if write_failed {
            // 写下游失败：关闭 session，剩余数据丢弃（Go :363-367）
            session.close().await;
        }
        false
    }

    /// 16s 定时监控。
    ///
    /// 对应 Go `monitor`（client.go:226-244）：
    /// - done → 关闭全部 session（carrier 管道由 factory 任务中断）
    /// - tick → 无会话且空闲 → 关闭 worker
    async fn monitor(self: Arc<Self>) {
        let done = self.done_rx();
        // Go time.Ticker 首 tick 在 16s 后；tokio interval 首次立即触发，需偏移
        let mut ticker = tokio::time::interval_at(
            tokio::time::Instant::now() + CLIENT_KEEPALIVE_INTERVAL,
            CLIENT_KEEPALIVE_INTERVAL,
        );
        loop {
            // tick 前快照（Go :230-231，容忍 tick 间隙分配-释放的竞态语义）
            let check_size = self.session_manager.size().await;
            let check_count = self.session_manager.count();
            tokio::select! {
                _ = wait_done(done.clone()) => {
                    self.session_manager.close().await;
                    return;
                }
                _ = ticker.tick() => {
                    if self.session_manager
                        .close_if_no_session_and_idle(check_size, check_count)
                        .await
                    {
                        debug!("mux client worker idle, closing");
                        self.close();
                    }
                }
            }
        }
    }
}

// ========== 辅助函数 ==========

/// 等待 watch 信号变为 true。
///
/// 先查当前值再订阅变更，容忍「订阅前已关闭」竞态
/// （直接 `changed()` 会错过订阅前的发送）。
pub(crate) async fn wait_done(mut rx: watch::Receiver<bool>) {
    loop {
        if *rx.borrow() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// 从 carrier 读取一个完整帧（metadata + 可选 data）。
///
/// 返回 `Err("")` 表示干净 EOF（对端正常关闭），其余为错误描述。
async fn read_frame(reader: &mut BufferedReader) -> Result<(FrameMetadata, Vec<u8>), String> {
    let mut len_buf = [0u8; 2];
    read_exact(reader, &mut len_buf).await?;
    let meta_len = u16::from_be_bytes(len_buf) as usize;
    if meta_len > MAX_METADATA_LEN {
        return Err(format!("meta_len too large: {meta_len}"));
    }
    let mut body = vec![0u8; meta_len];
    read_exact(reader, &mut body).await?;
    let mut full = Vec::with_capacity(2 + meta_len);
    full.extend_from_slice(&len_buf);
    full.extend_from_slice(&body);
    let (meta, _) =
        FrameMetadata::read_from_bytes(&full).map_err(|e| format!("parse meta: {e:?}"))?;

    let data = if meta.has_data() {
        let mut size_buf = [0u8; 2];
        read_exact(reader, &mut size_buf).await?;
        let size = u16::from_be_bytes(size_buf) as usize;
        let mut data = vec![0u8; size];
        read_exact(reader, &mut data).await?;
        data
    } else {
        Vec::new()
    };
    Ok((meta, data))
}

/// 精确读满 `buf`。读到 0 字节（EOF）返回 `Err("")`，部分读后 EOF 带偏移描述。
async fn read_exact(reader: &mut BufferedReader, buf: &mut [u8]) -> Result<(), String> {
    let mut off = 0;
    while off < buf.len() {
        let n = reader.read(&mut buf[off..]).await;
        if n == 0 {
            return Err(if off == 0 {
                String::new()
            } else {
                format!("EOF at offset {off}/{}", buf.len())
            });
        }
        off += n;
    }
    Ok(())
}

// ========== DialingWorkerFactory ==========

/// 底层 outbound handler 槽。
///
/// 注册流程（xray-core outbound.rs）Phase 1 先建 MuxBridge，
/// Phase 2 才能解析 `via` tag / default handler，故底层 handler 经共享槽延迟注入。
pub type UnderlyingSlot =
    Arc<parking_lot::RwLock<Option<Arc<dyn xray_app_dispatcher::DispatchHandler>>>>;

/// 拨号式 Worker 工厂。
///
/// 对应 Go 版本 `DialingWorkerFactory`（client.go:138-169）：
/// `create` 建立两条 64KB 管道，worker 持内侧，`underlying` 持外侧
/// 作为 carrier 连接发往 `v1.mux.cool:9527`；
/// underlying 返回（carrier 断开）→ 关 worker + 中断管道；
/// worker 关闭（空闲/外部）→ 中断管道终结 underlying。
pub struct DialingWorkerFactory {
    /// 策略
    pub strategy: ClientStrategy,
    /// 底层 outbound（carrier 建立者）
    underlying: UnderlyingSlot,
}

impl DialingWorkerFactory {
    /// 创建新的拨号式工厂，直接持有底层 handler。
    pub fn new(
        underlying: Arc<dyn xray_app_dispatcher::DispatchHandler>,
        strategy: ClientStrategy,
    ) -> Self {
        Self {
            strategy,
            underlying: Arc::new(parking_lot::RwLock::new(Some(underlying))),
        }
    }

    /// 以共享槽创建（延迟注入底层 handler，注册流程 Phase 2 用）。
    #[must_use]
    pub fn with_slot(underlying: UnderlyingSlot, strategy: ClientStrategy) -> Self {
        Self { strategy, underlying }
    }
}

#[async_trait::async_trait]
impl ClientWorkerFactory for DialingWorkerFactory {
    async fn create(&self) -> Arc<ClientWorker> {
        // Go client.go:139 pipe.WithSizeLimit(64 * 1024) × 2
        let option = xray_buf::pipe::PipeOption {
            limit: 64 * 1024,
            ..Default::default()
        };
        let (uplink_reader, uplink_writer) = xray_buf::pipe::new_with_option(option);
        let (downlink_reader, downlink_writer) = xray_buf::pipe::new_with_option(option);

        // Go client.go:143-146 NewClientWorker(Link{downlinkReader, upLinkWriter})
        let worker = ClientWorker::new(
            Link {
                reader: Box::new(downlink_reader),
                writer: Box::new(uplink_writer.clone()),
            },
            self.strategy.clone(),
        );

        let Some(underlying) = self.underlying.read().clone() else {
            // 未注入底层 handler：carrier 立即终结
            worker.close();
            uplink_writer.interrupt();
            downlink_writer.interrupt();
            return worker;
        };

        let carrier = xray_transport::link::Link::new(
            Box::new(uplink_reader),
            Box::new(downlink_writer.clone()),
        );
        let dest = ClientWorker::mux_destination();
        let w = Arc::clone(&worker);
        tokio::spawn(async move {
            let done = w.done_rx();
            tokio::select! {
                // carrier 结束（underlying.dispatch 返回）→ Go client.go:164 c.Close()
                _ = underlying.dispatch(&dest, carrier) => {}
                // worker 关闭（空闲/外部 close）→ 中断管道，终结 underlying
                _ = wait_done(done.clone()) => {}
            }
            w.close();
            uplink_writer.interrupt();
            downlink_writer.interrupt();
        });

        worker
    }
}

// ========== 错误类型 ==========

/// 客户端错误。
#[derive(thiserror::Error, Debug)]
pub enum ClientError {
    /// Mux 未启用
    #[error("mux is not enabled")]
    MuxDisabled,
    /// 无可用 Worker
    #[error("no available worker")]
    NoAvailableWorker,
    /// Worker 已满
    #[error("worker is full")]
    WorkerFull,
    /// 达到最大会话数
    #[error("max session reached")]
    MaxSessionReached,
}

// ========== 测试 ==========

#[cfg(test)]
mod tests {
    use super::*;
    use xray_buf::pipe;

    /// 回环 carrier 的测试 worker（carrier 管道两端都在 worker 内闭合）。
    fn loop_worker(strategy: ClientStrategy) -> Arc<ClientWorker> {
        let (r, w) = pipe::new();
        ClientWorker::new(
            Link {
                reader: Box::new(r),
                writer: Box::new(w),
            },
            strategy,
        )
    }

    /// 空底层 handler（dispatch 立即返回 = carrier 立即断开）。
    #[derive(Debug)]
    struct NopUnderlying;
    impl xray_app_dispatcher::DispatchHandler for NopUnderlying {
        fn tag(&self) -> &str {
            "nop"
        }
        fn dispatch(
            &self,
            _dest: &Destination,
            _link: xray_transport::link::Link,
        ) -> xray_app_dispatcher::default::PinFuture<()> {
            Box::pin(async {})
        }
    }

    #[tokio::test]
    async fn test_client_worker_new() {
        let worker = loop_worker(ClientStrategy::default());
        assert!(!worker.is_closed());
        assert!(!worker.is_full());
        assert!(!worker.is_closing());
    }

    #[tokio::test]
    async fn test_client_worker_close() {
        let worker = loop_worker(ClientStrategy::default());
        worker.close();
        assert!(worker.is_closed());
    }

    #[tokio::test]
    async fn test_client_worker_is_full_when_closed() {
        let worker = loop_worker(ClientStrategy::default());
        worker.close();
        assert!(worker.is_full());
    }

    #[tokio::test]
    async fn test_client_worker_is_closing_with_max_connection() {
        let strategy = ClientStrategy {
            max_concurrency: 0,
            max_connection: 1,
        };
        let worker = loop_worker(strategy);
        assert!(!worker.is_closing()); // count=0 < max_connection=1
    }

    #[test]
    fn test_mux_cool_constants() {
        assert_eq!(MUX_COOL_ADDRESS, "v1.mux.cool");
        assert_eq!(MUX_COOL_PORT, 9527);
    }

    #[test]
    fn test_mux_destination() {
        let dest = ClientWorker::mux_destination();
        assert_eq!(dest.network(), Network::TCP);
    }

    #[test]
    fn test_client_manager_disabled() {
        struct NoopPicker;
        impl WorkerPicker for NoopPicker {
            fn pick_available(&self) -> Option<Arc<ClientWorker>> {
                None
            }
        }
        let mgr = ClientManager::new(false, Box::new(NoopPicker));
        assert!(mgr.dispatch().is_err());
    }

    #[test]
    fn test_dialing_worker_factory() {
        let strategy = ClientStrategy {
            max_concurrency: 10,
            max_connection: 5,
        };
        let factory = DialingWorkerFactory::new(Arc::new(NopUnderlying), strategy);
        assert_eq!(factory.strategy.max_concurrency, 10);
    }

    #[tokio::test]
    async fn test_incremental_picker_cleanup() {
        let strategy = ClientStrategy::default();
        let factory = Arc::new(DialingWorkerFactory::new(Arc::new(NopUnderlying), strategy));
        let picker = IncrementalWorkerPicker::new(factory);
        assert_eq!(picker.worker_count().await, 0);
        picker.cleanup().await;
    }

    #[tokio::test]
    async fn test_incremental_picker_pick_internal() {
        let strategy = ClientStrategy::default();
        let factory = Arc::new(DialingWorkerFactory::new(Arc::new(NopUnderlying), strategy));
        let picker = IncrementalWorkerPicker::new(factory);
        let worker = picker.pick_internal().await;
        assert!(worker.is_some());
        assert_eq!(picker.worker_count().await, 1);
    }

    /// 慢 factory：create 期间人为通知+等待——让并发 pick_internal 有窗口期
    /// 进入 race 区域，验证二次检查生效。Notify 不可 clone，外层用 Arc 包装。
    struct SlowFactory {
        strategy: ClientStrategy,
        create_started: Arc<tokio::sync::Notify>,
        create_can_finish: Arc<tokio::sync::Notify>,
    }
    #[async_trait::async_trait]
    impl ClientWorkerFactory for SlowFactory {
        async fn create(&self) -> Arc<ClientWorker> {
            self.create_started.notify_waiters();
            self.create_can_finish.notified().await;
            DialingWorkerFactory::new(Arc::new(NopUnderlying), self.strategy.clone())
                .create()
                .await
        }
    }

    /// 并发 pick_internal：N 个 task 同时调，期望 worker_count 远小于 N
    /// （无二次检查 = N 个 worker，无 race 防护 = N；二次检查生效 = 1-2）。
    #[tokio::test]
    async fn test_incremental_picker_concurrent_pick_does_not_penetrate() {
        let strategy = ClientStrategy::default();
        let started = Arc::new(tokio::sync::Notify::new());
        let can_finish = Arc::new(tokio::sync::Notify::new());
        let factory: Arc<dyn ClientWorkerFactory> = Arc::new(SlowFactory {
            strategy,
            create_started: Arc::clone(&started),
            create_can_finish: Arc::clone(&can_finish),
        });
        let picker = Arc::new(IncrementalWorkerPicker::new(factory));

        const N: usize = 4;
        let mut handles = Vec::new();
        for _ in 0..N {
            let picker = Arc::clone(&picker);
            handles.push(tokio::spawn(async move {
                let _ = picker.pick_internal().await;
            }));
        }

        // 等一小段时间让 N 个 task 全部阻塞在 SlowFactory::create 内。
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        can_finish.notify_waiters();
        for h in handles {
            let _ = h.await;
        }
        let count = picker.worker_count().await;
        assert!(
            count <= 2,
            "concurrent pick_internal must not create > 2 workers (N={N}, got {count})"
        );
        assert!(count >= 1, "must have created at least 1 worker");
    }

    #[test]
    fn test_client_error_display() {
        assert_eq!(format!("{}", ClientError::MuxDisabled), "mux is not enabled");
        assert_eq!(
            format!("{}", ClientError::NoAvailableWorker),
            "no available worker"
        );
    }

    #[test]
    fn test_link_struct() {
        // Link 结构体的字段类型编译验证
        fn _assert_link_send(reader: Box<dyn Reader>, writer: Box<dyn Writer>) -> Link {
            Link { reader, writer }
        }
    }

    // ========== E2E：双并发会话 × 单 carrier ==========

    /// 单条 echo 会话：写 payload → 读回显 → 半关闭 → 等 dispatch 返回。
    async fn run_echo_session(
        worker: &Arc<ClientWorker>,
        dest: &Destination,
        payload: &[u8],
    ) -> Vec<u8> {
        let (req_rd, req_wr) = pipe::new();
        let (resp_rd, resp_wr) = pipe::new();
        let link = Link {
            reader: Box::new(req_rd),
            writer: Box::new(resp_wr),
        };
        let w = Arc::clone(worker);
        let dest = dest.clone();
        let handle = tokio::spawn(async move { w.dispatch(&dest, link).await });

        let mut req_wr = req_wr;
        let mut resp_rd = resp_rd;
        req_wr
            .write_multi_buffer(MultiBuffer::from_buffer(Buffer::from_vec(
                payload.to_vec(),
            )))
            .await
            .expect("write request");

        // 会话存活期间收响应（全双工时序），读完再半关闭
        let mut got = Vec::with_capacity(payload.len());
        while got.len() < payload.len() {
            let mb = resp_rd.read_multi_buffer().await.expect("read echo");
            assert!(!mb.is_empty(), "unexpected EOF before echo complete");
            got.extend_from_slice(&mb.to_vec());
        }

        // 客户端半关闭 → fetch_input 发 End 帧 → session 关闭 → dispatch 返回
        let _ = req_wr.close();
        assert!(
            handle.await.expect("dispatch task join"),
            "worker.dispatch should accept the session"
        );
        got
    }

    /// E2E：mux client 双并发 TCP 会话 ↔ ServerWorker echo。
    ///
    /// 拓扑：DialingWorkerFactory(underlying=CarrierHandler) 建单条 carrier
    /// （内存管道）→ ServerWorker.process_frame 解帧 → EchoDispatcher 回显。
    /// 断言：两会话独立 roundtrip + 单 carrier 承载双会话
    /// （server session_manager.count == 2）。
    #[tokio::test]
    async fn e2e_two_concurrent_sessions_over_single_carrier() {
        use crate::worker::{DispatchError, Dispatcher, ServerWorker};

        // ---- 服务端子会话目标：echo ----
        struct EchoDispatcher;
        #[async_trait::async_trait]
        impl Dispatcher for EchoDispatcher {
            async fn dispatch(&self, _dest: Destination) -> Result<Link, DispatchError> {
                let (r_up, w_up) = pipe::new();
                let (r_down, w_down) = pipe::new();
                tokio::spawn(async move {
                    let mut r = r_up;
                    let mut w = w_down;
                    loop {
                        match r.read_multi_buffer().await {
                            Ok(mb) => {
                                if mb.is_empty() {
                                    break;
                                }
                                if w.write_multi_buffer(mb).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    let _ = w.close();
                });
                Ok(Link {
                    reader: Box::new(r_down),
                    writer: Box::new(w_up),
                })
            }
        }

        // ---- carrier：把底层 dispatch 的 carrier link 喂给 ServerWorker ----
        struct CarrierHandler {
            server: Arc<ServerWorker>,
        }
        impl std::fmt::Debug for CarrierHandler {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("CarrierHandler").finish()
            }
        }
        impl xray_app_dispatcher::DispatchHandler for CarrierHandler {
            fn tag(&self) -> &str {
                "e2e-carrier"
            }
            fn dispatch(
                &self,
                _dest: &Destination,
                link: xray_transport::link::Link,
            ) -> xray_app_dispatcher::default::PinFuture<()> {
                let server = Arc::clone(&self.server);
                Box::pin(async move {
                    let mut reader = BufferedReader::new(link.reader);
                    let writer: Arc<Mutex<Option<Box<dyn Writer>>>> =
                        Arc::new(Mutex::new(Some(link.writer)));
                    let (ka, idle) = server.spawn_keepalive_and_idle_timeout(Arc::clone(&writer));
                    while matches!(server.process_frame(&mut reader, &writer).await, Ok(true)) {}
                    server.close();
                    ka.abort();
                    idle.abort();
                })
            }
        }

        let server = Arc::new(ServerWorker::new(Arc::new(EchoDispatcher)));
        let underlying: Arc<dyn xray_app_dispatcher::DispatchHandler> =
            Arc::new(CarrierHandler {
                server: Arc::clone(&server),
            });

        // ---- 客户端：factory → picker → worker（单 carrier）----
        let factory = Arc::new(DialingWorkerFactory::new(
            underlying,
            ClientStrategy::default(),
        ));
        let picker = IncrementalWorkerPicker::new(factory);
        let worker = picker.pick_internal().await.expect("worker created");

        let dest = Destination::new(
            xray_common::net::address::Address::new_domain("echo.internal"),
            xray_common::net::port::Port::new(80),
            Network::TCP,
        );

        let (echo1, echo2) = tokio::join!(
            run_echo_session(&worker, &dest, b"ping-one"),
            run_echo_session(&worker, &dest, b"ping-two"),
        );
        assert_eq!(echo1, b"ping-one".to_vec());
        assert_eq!(echo2, b"ping-two".to_vec());

        assert_eq!(
            server.session_manager().count(),
            2,
            "two sessions multiplexed over one carrier"
        );
    }

    /// E2E：服务端先说协议（SSH/FTP/SMTP）。客户端无首包时 fetch_input
    /// 100ms 超时发空 New 帧触发服务端 dispatch（Go `writeFirstPayload`，
    /// client.go:246-257）；服务端 banner 经 pump 回流到客户端。
    /// 旧实现省略首包试探：无首包 session 永不注册到对端 → 双向挂死。
    #[tokio::test]
    async fn e2e_empty_new_probe_dispatches_server_speaks_first() {
        use crate::worker::{DispatchError as SrvDispatchError, Dispatcher, ServerWorker};

        // 捕获 dispatch 的服务端：立即向"上游→客户端"方向写 banner
        struct BannerDispatcher {
            tx: tokio::sync::mpsc::UnboundedSender<Destination>,
        }
        #[async_trait::async_trait]
        impl Dispatcher for BannerDispatcher {
            async fn dispatch(&self, dest: Destination) -> Result<Link, SrvDispatchError> {
                let _ = self.tx.send(dest.clone());
                let (r_down, w_down) = pipe::new();
                let (_up_r, up_w) = pipe::new();
                let mut w = w_down;
                w.write_multi_buffer(MultiBuffer::from_buffer(Buffer::from_vec(
                    b"SSH-2.0-XRAY\r\n".to_vec(),
                )))
                .await
                .expect("write banner");
                let _ = w.close();
                Ok(Link {
                    reader: Box::new(r_down),
                    writer: Box::new(up_w),
                })
            }
        }

        let (c_read, s_write) = pipe::new(); // server → client
        let (s_read, c_write) = pipe::new(); // client → server
        let client = ClientWorker::new(
            Link {
                reader: Box::new(c_read),
                writer: Box::new(c_write),
            },
            ClientStrategy::default(),
        );

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let server = Arc::new(ServerWorker::new(Arc::new(BannerDispatcher { tx })));
        let mut reader = BufferedReader::new(Box::new(s_read));
        let link_writer: Arc<Mutex<Option<Box<dyn Writer>>>> =
            Arc::new(Mutex::new(Some(Box::new(s_write))));
        let (ka, idle) = server.spawn_keepalive_and_idle_timeout(Arc::clone(&link_writer));
        let frame_server = Arc::clone(&server);
        tokio::spawn(async move {
            loop {
                match frame_server.process_frame(&mut reader, &link_writer).await {
                    Ok(true) => continue,
                    _ => break,
                }
            }
            frame_server.close();
            ka.abort();
            idle.abort();
        });

        // 客户端 dispatch：reader 有写端但永不写数据 → 首包试探超时发空 New
        let (req_rd, req_wr) = pipe::new();
        let (resp_rd, resp_wr) = pipe::new();
        let dest = Destination::new(
            xray_common::net::address::Address::new_domain("ssh.internal"),
            xray_common::net::port::Port::new(22),
            Network::TCP,
        );
        let w = Arc::clone(&client);
        let d = dest.clone();
        let dispatch_task = tokio::spawn(async move {
            w.dispatch(
                &d,
                Link {
                    reader: Box::new(req_rd),
                    writer: Box::new(resp_wr),
                },
            )
            .await
        });

        // 核心断言：客户端零 payload，服务端仍收到 New 并 dispatch
        let captured = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("server must dispatch on empty New probe")
            .expect("channel open");
        assert_eq!(captured.address().as_domain(), Some("ssh.internal"));

        // 服务端先说的 banner 回流到客户端 resp 读端
        let mut resp = resp_rd;
        let mb = tokio::time::timeout(std::time::Duration::from_secs(2), resp.read_multi_buffer())
            .await
            .expect("banner within timeout")
            .expect("read ok");
        assert_eq!(mb.to_vec(), b"SSH-2.0-XRAY\r\n");

        // 收尾：关写端 → End → dispatch 返回
        let _ = req_wr.close();
        assert!(dispatch_task.await.expect("join"), "dispatch accepted");
    }
}
