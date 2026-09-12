//! Mux 服务端
//!
//! 对应 Go 版本 `common/mux/server.go`，实现 Mux 服务端帧处理与空闲 monitor。

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::watch;
use tokio::time::Duration;
use tracing::{debug, warn};
use xray_buf::io::{Reader, Writer};
use xray_buf::reader::BufferedReader;
use xray_buf::writer::BufferedWriter;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;

use crate::client::{Link, MUX_COOL_ADDRESS};
use crate::frame::{FrameMetadata, SessionStatus, MAX_METADATA_LEN};
use crate::session::{Session, SessionManager, TransferType, XUDP, XUDPManager, XudpStatus};
use crate::writer::MuxWriter;
use xray_buf::buffer::Buffer;
use xray_buf::multi::MultiBuffer;

/// 服务端 monitor 间隔（60 秒，Go server.go:101 `time.NewTicker(60s)`）。
pub const SERVER_MONITOR_INTERVAL: Duration = Duration::from_secs(60);

#[async_trait::async_trait]
pub trait Dispatcher: Send + Sync {
    async fn dispatch(&self, dest: Destination) -> Result<Link, DispatchError>;
}

#[derive(thiserror::Error, Debug)]
pub enum DispatchError {
    #[error("no route to destination: {0}")]
    NoRoute(String),
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("dispatch timeout: {0}")]
    Timeout(String),
}

/// 将 `DispatchHandler`（消费 link）适配为 `Dispatcher`（返回 link）。
///
/// 实现：创建 pipe pair → 一端包装为 transport::Link 传给 DispatchHandler →
/// 另一端包装为 mux::Link 返回。
/// 对应 Go `mux.Server.Dispatch` 内部调用 `proxy.Dispatch` 的桥接逻辑。
pub struct DispatchHandlerAdapter {
    handler: Arc<dyn xray_app_dispatcher::DispatchHandler>,
}

impl DispatchHandlerAdapter {
    pub fn new(handler: Arc<dyn xray_app_dispatcher::DispatchHandler>) -> Self {
        Self { handler }
    }
}

#[async_trait::async_trait]
impl Dispatcher for DispatchHandlerAdapter {
    async fn dispatch(&self, dest: Destination) -> Result<Link, DispatchError> {
        // 两个 pipe：pipe_a + pipe_b
        // DispatchHandler 写到 write_a → 我们从 read_a 读
        // 我们写到 write_b → DispatchHandler 从 read_b 读
        let (read_a, write_a) = xray_buf::pipe::new();
        let (read_b, write_b) = xray_buf::pipe::new();

        // DispatchHandler 接收 transport::Link
        let dispatch_link = xray_transport::link::Link::new(
            Box::new(read_b),
            Box::new(write_a),
        );
        // 返回 mux::Link
        let return_link = Link {
            reader: Box::new(read_a),
            writer: Box::new(write_b),
        };

        let handler = Arc::clone(&self.handler);
        let dest_clone = dest.clone();
        tokio::spawn(async move {
            handler.dispatch(&dest_clone, dispatch_link).await;
        });

        Ok(return_link)
    }
}

pub struct Server {
    dispatcher: Arc<dyn Dispatcher>,
}

impl Server {
    pub fn new(dispatcher: Arc<dyn Dispatcher>) -> Self {
        Self { dispatcher }
    }

    pub async fn dispatch(&self, dest: &Destination) -> Result<Link, DispatchError> {
        if !Self::is_mux_destination(dest) {
            return self.dispatcher.dispatch(dest.clone()).await;
        }
        Err(DispatchError::NoRoute("mux server not fully initialized".to_string()))
    }

    pub fn is_mux_destination(dest: &Destination) -> bool {
        match dest.address() {
            xray_common::net::address::Address::Domain(domain) => domain == MUX_COOL_ADDRESS,
            _ => false,
        }
    }
}

pub struct ServerWorker {
    dispatcher: Arc<dyn Dispatcher>,
    session_manager: Arc<SessionManager>,
    xudp_manager: Arc<XUDPManager>,
    closed: Arc<AtomicBool>,
    done_tx: watch::Sender<bool>,
    done_rx: watch::Receiver<bool>,
    /// Reverse-mux：解析 New 帧的 source/local（Go `handleStatusNew` 的
    /// `IsReverseMuxFromContext` 分支）。
    read_source_and_local: bool,
    /// 允许的网络类型（Go `session.AllowedNetworkFromContext` 消费，
    /// common/mux/server.go:189-192）：Some(net) 时 New 帧目标网络不匹配 →
    /// 错误 → run 退出拆整条 carrier。
    allowed_network: Option<xray_common::net::network::Network>,
}

impl ServerWorker {
    pub fn new(dispatcher: Arc<dyn Dispatcher>) -> Self {
        let (done_tx, done_rx) = watch::channel(false);
        // bd lahx：接线常驻清理（Go common/mux/session.go:235-252 init goroutine
        // 每分钟清 Expiring 条目并 Interrupt）。task 句柄由 XUDPManager 持有，
        // Drop（worker 释放）时 abort——不泄漏。
        let mut xudp_manager = XUDPManager::new();
        xudp_manager.start_cleanup();
        Self {
            dispatcher,
            session_manager: Arc::new(SessionManager::new()),
            xudp_manager: Arc::new(xudp_manager),
            closed: Arc::new(AtomicBool::new(false)),
            done_tx,
            done_rx,
            read_source_and_local: false,
            allowed_network: None,
        }
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        let _ = self.done_tx.send(true);
    }

    /// 启用 Reverse-mux New 帧的 source/local 解析（reverse BridgeWorker 用）。
    #[must_use]
    pub fn with_read_source_and_local(mut self) -> Self {
        self.read_source_and_local = true;
        self
    }

    /// 设置允许的网络类型（Go `ContextWithAllowedNetwork` + server 消费）。
    #[must_use]
    pub fn with_allowed_network(mut self, network: xray_common::net::network::Network) -> Self {
        self.allowed_network = Some(network);
        self
    }

    #[must_use]
    pub fn session_manager(&self) -> &Arc<SessionManager> {
        &self.session_manager
    }

    pub async fn active_connections(&self) -> u32 {
        self.session_manager.size().await as u32
    }

    pub fn done_rx(&self) -> watch::Receiver<bool> {
        self.done_rx.clone()
    }

    /// 启动 Go `ServerWorker.monitor`（server.go:122-140）等价任务。
    ///
    /// Go 双端从不发送 KeepAlive 帧；monitor 每 60s 快照 size/count，tick 时
    /// 「当前无会话 && 快照 size==0 && count 未变」→ 关闭整条 carrier
    /// （done → 清理会话 + 丢弃 carrier 写端，Go :129-133）。返回 JoinHandle
    /// 供调用方 abort。
    pub fn spawn_monitor(
        &self,
        link_writer: Arc<tokio::sync::Mutex<Option<Box<dyn Writer>>>>,
    ) -> tokio::task::JoinHandle<()> {
        let session_manager = Arc::clone(&self.session_manager);
        let done_rx = self.done_rx.clone();
        let done_tx = self.done_tx.clone();
        let closed = Arc::clone(&self.closed);
        tokio::spawn(async move {
            // Go time.Ticker 首 tick 在 60s 后；interval_at 对齐
            let mut ticker = tokio::time::interval_at(
                tokio::time::Instant::now() + SERVER_MONITOR_INTERVAL,
                SERVER_MONITOR_INTERVAL,
            );
            loop {
                // tick 前快照（Go :126-127，容忍 tick 间隙分配-释放竞态）
                let check_size = session_manager.size().await;
                let check_count = session_manager.count();
                tokio::select! {
                    _ = crate::client::wait_done(done_rx.clone()) => {
                        session_manager.close().await;
                        link_writer.lock().await.take();
                        return;
                    }
                    _ = ticker.tick() => {
                        if session_manager
                            .close_if_no_session_and_idle(check_size, check_count)
                            .await
                        {
                            // Go done.Close()：置 closed + 广播 done（等价
                            // ServerWorker::close；is_closed 观察原子标志）
                            closed.store(true, Ordering::Relaxed);
                            let _ = done_tx.send(true);
                        }
                    }
                }
            }
        })
    }

    /// Handle normal New frame (non-XUDP).
    pub async fn handle_normal_new(
        &self, meta: &FrameMetadata,
        data: Vec<u8>,
        link_writer: &Arc<tokio::sync::Mutex<Option<Box<dyn Writer>>>>,
    ) -> Result<(), ServerError> {
        let target = meta.target().cloned().ok_or_else(|| {
            ServerError::InvalidFrame("new session without target".to_string())
        })?;
        let link = self.dispatcher.dispatch(target.clone()).await.map_err(|e| {
            ServerError::DispatchFailed(format!("dispatch to {}: {}", target, e))
        })?;
        let tt = if target.network() == Network::UDP { TransferType::Packet } else { TransferType::Stream };
        let session = Session::new(meta.session_id(), tt);
        session.set_input(BufferedReader::new(link.reader)).await;
        // Packet 会话禁用 BufferedWriter 缓冲（直写）：包边界保持 + 小包即时
        // 送达（Go server.go:271-277 直接使用 link.Writer，无缓冲包装）。
        let mut output = BufferedWriter::new(link.writer);
        if tt == TransferType::Packet {
            output.set_buffered(false);
        }
        // 写入 New frame 的 data 到 session.output（在 spawn 反向 task 前同步完成，
        // 对齐 Go handleStatusNew 中 `buf.Copy(rr, s.output)` 的语义）
        if !data.is_empty() {
            output
                .write_multi_buffer_impl(MultiBuffer::from_buffer(Buffer::from_vec(data)))
                .await
                .map_err(|e| ServerError::DispatchFailed(format!("initial data: {e}")))?;
            output.flush().await.ok();
        }
        session.set_output(output).await;
        let Some(session) = self.session_manager.add(session).await else {
            return Err(ServerError::SessionAddFailed(meta.session_id()));
        };
        let os = session.clone();
        let ow = link_writer.clone();
        tokio::spawn(async move { Self::handle_session_output(os, ow).await; });
        Ok(())
    }
    /// Handle XUDP New frame.
    ///
    /// `data` 为 New 帧内联数据——Go `handleStatusNew`（server.go:196-240）先经
    /// `NewPacketReader` 读出，dispatch 后 `link.Writer.WriteMultiBuffer(mb)` 转发，
    /// **不得丢弃**（bd 6z8 回归）。
    ///
    /// 会话装配对齐 Go server.go:247-260：`x.Mux` 即加入 sessionManager 的那个
    /// 会话——input=link.Reader（真实上游 I/O）、output=link.Writer（Keep 帧
    /// 下行转发目标），`handle()` 泵任务读真 I/O 回写 carrier。旧实现的孤儿
    /// ms 使泵任务读空 input 立即退出，上游数据永远回不来。
    pub async fn handle_xudp_new(
        &self, meta: &FrameMetadata,
        data: Vec<u8>,
        link_writer: &Arc<tokio::sync::Mutex<Option<Box<dyn Writer>>>>,
        global_id: [u8; 8],
    ) -> Result<(), ServerError> {
        let target = meta.target().cloned().ok_or_else(|| {
            ServerError::InvalidFrame("XUDP session without target".to_string())
        })?;
        let xmgr = &self.xudp_manager;
        let mut xudp = match xmgr.get(&global_id).await {
            None => {
                // miss：首次见该 GlobalID，建新条目 → Active
                let x = XUDP::new(global_id);
                xmgr.register(x.clone()).await;
                x
            }
            Some(mut ex) => {
                if ex.status == XudpStatus::Initializing {
                    warn!("XUDP conflict {:?}", global_id);
                    return Ok(());
                }
                if ex.status == XudpStatus::Active {
                    // zv9l：hit Active → 对齐 Go server.go:216-260——旧会话
                    // detach 后以新 sessionID 重绑旧上游 I/O 注册并重泵。旧实现
                    // 仅写旧 output 就 return：新 sessionID 从未注册，其后所有
                    // Keep 帧查无此 ID 被静默丢（连 End 回帧都没有）。
                    // upgrade 失败 = 旧 session 已 Close/Expiring → 重建。
                    if let Some(old_session) = ex.mux().and_then(|w| w.upgrade()) {
                        if self
                            .xudp_hit_rebind(&old_session, meta, &data, &mut ex, link_writer)
                            .await
                        {
                            return Ok(());
                        }
                    }
                    // 旧 mux 已不可用或重绑失败 → 落回 miss 重建路径
                }
                // Expiring 或 hit-but-mux-stale：重置为 Initializing 后走新建路径
                ex.status = XudpStatus::Initializing;
                xmgr.register(ex.clone()).await;
                ex
            }
        };
        let link = match self.dispatcher.dispatch(target.clone()).await {
            Ok(l) => l,
            Err(e) => {
                xmgr.unregister(&global_id).await;
                return Err(ServerError::DispatchFailed(format!("XUDP dispatch: {}", e)));
            }
        };
        // XUDP 恒为 Packet：直写（禁缓冲），New 帧内联 data 转发到 dispatch 目标
        // ponytail: miss 路径建新上游；hit 路径复用旧上游（zv9l 已对齐 Go
        // server.go:216-260），两条路径在此汇合收尾。
        let mut output = BufferedWriter::new(link.writer);
        output.set_buffered(false);
        if !data.is_empty() {
            output
                .write_multi_buffer_impl(MultiBuffer::from_buffer(Buffer::from_vec(data)))
                .await
                .map_err(|e| ServerError::DispatchFailed(format!("XUDP initial data: {e}")))?;
        }
        let session = Session::new(meta.session_id(), TransferType::Packet);
        session.set_input(BufferedReader::new(link.reader)).await;
        session.set_output(output).await;
        let Some(session) = self.session_manager.add(session).await else {
            return Err(ServerError::SessionAddFailed(meta.session_id()));
        };
        xudp.set_mux(&session);
        xudp.status = XudpStatus::Active;
        // 注册表条目与 session 内快照都取 Active+mux（注册表存 clone，需重注册
        // 写回）：close 时 Active→Expiring，后续同 GlobalID New 可命中复用。
        session.set_xudp(xudp.clone()).await;
        xmgr.register(xudp).await;
        let os = session.clone();
        let ow = link_writer.clone();
        tokio::spawn(async move { Self::handle_session_output(os, ow).await; });
        Ok(())
    }


    /// XUDP hit 复用路径（bd zv9l，对齐 Go server.go:216-260）。
    ///
    /// 旧会话 detach → 首包写旧上游 output → 旧 input/output 转移到新
    /// sessionID 装配注册（manager.add + set_xudp + register）并重泵。
    /// 返回 `false` = 旧链路不可复用（I/O 已空 / 首包写失败 / manager 已关），
    /// 调用方落回 miss 重建路径（Go :221 写失败 → x.Interrupt 的等价分流）。
    async fn xudp_hit_rebind(
        &self,
        old_session: &Arc<Session>,
        meta: &FrameMetadata,
        data: &[u8],
        xudp: &mut XUDP,
        link_writer: &Arc<tokio::sync::Mutex<Option<Box<dyn Writer>>>>,
    ) -> bool {
        // Go :216 x.Mux.Close(false)：detach 旧会话——旧 ID 从 manager 摘除、
        // 旧泵任务退出（对客户端发旧 ID End 帧，Go handle 收尾同型）
        old_session.close().await;
        // Go :217-226 首包写旧上游 output（cone NAT 下同源多目标共享上游通道）
        if !data.is_empty() {
            let mut guard = old_session.output().await;
            let Some(writer) = guard.as_mut() else {
                return false;
            };
            if writer
                .write_multi_buffer_impl(MultiBuffer::from_buffer(Buffer::from_vec(
                    data.to_vec(),
                )))
                .await
                .is_err()
            {
                return false;
            }
        }
        // Go :247-254 重绑：旧 input/output 转移到新 sessionID
        let input = old_session.input().await.take();
        let output = old_session.output().await.take();
        let (Some(input), Some(output)) = (input, output) else {
            return false;
        };
        let session = Session::new(meta.session_id(), TransferType::Packet);
        session.set_input(input).await;
        session.set_output(output).await;
        let Some(session) = self.session_manager.add(session).await else {
            return false;
        };
        xudp.set_mux(&session);
        xudp.status = XudpStatus::Active;
        session.set_xudp(xudp.clone()).await;
        self.xudp_manager.register(xudp.clone()).await;
        let os = session.clone();
        let ow = link_writer.clone();
        tokio::spawn(async move { Self::handle_session_output(os, ow).await; });
        true
    }

    /// Handle session output (upstream data back to mux).
    ///
    /// 多 session 经 [`SharedWriter`] 共写 carrier 写端（旧实现 `take()`
    /// 独占写端，第二个 session 会拿到 None 直接关闭，无法多路复用）。
    async fn handle_session_output(
        session: Arc<Session>,
        link_writer: Arc<tokio::sync::Mutex<Option<Box<dyn Writer>>>>,
    ) {
        let mut rw = MuxWriter::new_response_writer(
            session.id(),
            Box::new(crate::writer::SharedWriter::new(Arc::clone(&link_writer))),
            session.transfer_type(),
        );
        let done = session.done_receiver();
        loop {
            let mut input = session.input().await;
            let Some(reader) = input.as_mut() else { break };
            // select session done：Session::close 需先拿 input 锁才能中断，
            // 持锁阻塞读期间必须可被 done 打断，否则与 close 互相等待死锁
            let read = tokio::select! {
                r = reader.read_multi_buffer() => Some(r),
                _ = crate::client::wait_done(done.clone()) => None,
            };
            let mb = match read {
                Some(Ok(mb)) => mb,
                Some(Err(_)) => {
                    rw.set_error();
                    break;
                }
                None => break,
            };
            if mb.is_empty() {
                break;
            }
            let byte_count = mb.len() as u64;
            session.add_downlink_bytes(byte_count);
            if rw.write(mb).await.is_err() {
                rw.set_error();
                break;
            }
        }
        let _ = rw.close().await;
        session.close().await;
    }

    /// 处理主连接的下一帧（frame dispatcher 主循环单步）。
    ///
    /// 从 `reader` 读取一个完整的 Mux 帧（metadata + optional data），
    /// 按 session_status 分发到对应 handler。
    /// 返回 `Ok(true)` 表示成功处理可继续，`Ok(false)` 表示干净 EOF。
    ///
    /// 对应 Go 版本 `ServerWorker.handleFrame`，单次调用不 spawn 长任务，
    /// 适合测试与可控制并发的场景。
    pub async fn process_frame(
        &self,
        reader: &mut BufferedReader,
        link_writer: &Arc<tokio::sync::Mutex<Option<Box<dyn Writer>>>>,
    ) -> Result<bool, ServerError> {
        // 1. 读 2B length（EOF 返 Ok(false) 表示干净关闭）。select done：
        // monitor 空闲关闭 carrier 后读循环立即退出（Go run() 帧间检查
        // done 的等价），不挂在底层 I/O 上
        let first_read = tokio::select! {
            _ = crate::client::wait_done(self.done_rx.clone()) => return Ok(false),
            r = Self::read_exact_async(reader, 2) => r,
        };
        let len_buf = match first_read {
            Ok(b) => b,
            Err(ServerError::InvalidFrame(msg)) if msg.starts_with("EOF") => return Ok(false),
            Err(e) => return Err(e),
        };
        let meta_len = u16::from_be_bytes([len_buf[0], len_buf[1]]) as usize;
        if meta_len > MAX_METADATA_LEN {
            return Err(ServerError::InvalidFrame(format!("meta_len too large: {}", meta_len)));
        }
        // 2. 读 body
        let body = Self::read_exact_async(reader, meta_len).await?;
        // 3. 解析 metadata（拼回完整 bytes 调 read_from_bytes，因为它需 length 前缀）
        let mut full = Vec::with_capacity(2 + meta_len);
        full.extend_from_slice(&len_buf);
        full.extend_from_slice(&body);
        let parse = if self.read_source_and_local {
            FrameMetadata::read_from_bytes_with_source(&full)
        } else {
            FrameMetadata::read_from_bytes(&full)
        };
        let (meta, _) =
            parse.map_err(|e| ServerError::InvalidFrame(format!("parse meta: {:?}", e)))?;
        // 4. 如有 data，读 data（2B size + payload）
        let data = if meta.has_data() {
            let size_buf = Self::read_exact_async(reader, 2).await?;
            let size = u16::from_be_bytes([size_buf[0], size_buf[1]]) as usize;
            Self::read_exact_async(reader, size).await?
        } else {
            Vec::new()
        };
        // 5. 按 status 分发
        match meta.session_status() {
            SessionStatus::New => {
                // Reverse-mux：Go handleStatusNew（:166-174）据 source/local
                // 覆写 inbound ctx 供日志；Rust dispatcher 无 ctx 管道，先落日志
                if let (Some(source), Some(local)) = (meta.source(), meta.local()) {
                    debug!(
                        session = meta.session_id(),
                        source = %source,
                        local = %local,
                        "reverse mux inbound"
                    );
                }
                // Go server.go:189-192：AllowedNetwork 非未知时 New 帧目标
                // 网络不匹配 → 错误 → handleFrame/run 错误传播拆整条 carrier。
                if let Some(allowed) = self.allowed_network {
                    if let Some(target) = meta.target() {
                        if target.network() != allowed {
                            return Err(ServerError::InvalidFrame(format!(
                                "unexpected network {} (allowed {allowed:?})",
                                target.network()
                            )));
                        }
                    }
                }
                if meta.is_udp_target() && meta.global_id().is_some() {
                    let gid = *meta.global_id().unwrap();
                    self.handle_xudp_new(&meta, data, link_writer, gid).await?;
                } else {
                    self.handle_normal_new(&meta, data, link_writer).await?;
                }
            }
            SessionStatus::Keep => self.handle_status_keep(&meta, data).await?,
            SessionStatus::End => self.handle_status_end(&meta).await?,
            SessionStatus::KeepAlive => {}, // data 已读出丢弃
        }
        Ok(true)
    }

    /// 处理 Keep 帧：把 data 写到对应 session.output（转发到上游 dispatcher 目标）。
    ///
    /// 未知 session_id 静默丢弃（对端可能已 End）。
    pub async fn handle_status_keep(
        &self,
        meta: &FrameMetadata,
        data: Vec<u8>,
    ) -> Result<(), ServerError> {
        if data.is_empty() {
            return Ok(());
        }
        let data_len = data.len() as u64;
        let session = match self.session_manager.get(meta.session_id()).await {
            Some(s) => s,
            None => return Ok(()),
        };
        // 更新流量统计
        session.add_uplink_bytes(data_len);
        let mut guard = session.output().await;
        if let Some(ref mut writer) = *guard {
            let mb = MultiBuffer::from_buffer(Buffer::from_vec(data));
            let _ = writer.write_multi_buffer_impl(mb).await;
        }
        Ok(())
    }

    /// 处理 End 帧：关闭并移除对应 session。
    pub async fn handle_status_end(&self, meta: &FrameMetadata) -> Result<(), ServerError> {
        if let Some(session) = self.session_manager.get(meta.session_id()).await {
            session.close().await;
        }
        Ok(())
    }

    /// 异步精确读取 n 字节，EOF 时返回带 "EOF" 前缀的 InvalidFrame 错误。
    async fn read_exact_async(reader: &mut BufferedReader, n: usize) -> Result<Vec<u8>, ServerError> {
        let mut buf = vec![0u8; n];
        let mut read = 0;
        while read < n {
            let r = reader.read(&mut buf[read..]).await;
            if r == 0 {
                return Err(ServerError::InvalidFrame(format!(
                    "EOF reading {} bytes at offset {}",
                    n, read
                )));
            }
            read += r;
        }
        Ok(buf)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ServerError {
    #[error("invalid frame: {0}")]
    InvalidFrame(String),
    #[error("dispatch failed: {0}")]
    DispatchFailed(String),
    #[error("failed to add session {0}")]
    SessionAddFailed(u16),
    #[error("XUDP conflict: {0}")]
    XudpConflict(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_common::net::address::Address;
    use xray_common::net::port::Port;

    struct MockDispatcher;
    #[async_trait::async_trait]
    impl Dispatcher for MockDispatcher {
        async fn dispatch(&self, _dest: Destination) -> Result<Link, DispatchError> {
            Err(DispatchError::NoRoute("mock".to_string()))
        }
    }

    #[test]
    fn test_server_monitor_interval() {
        assert_eq!(SERVER_MONITOR_INTERVAL, Duration::from_secs(60));
    }

    /// 验收：空载 carrier 60s 关闭（Go monitor，server.go:122-140）。
    /// 双端不发 KeepAlive；「无会话且 count 不变」→ 关整条 carrier。
    #[tokio::test(start_paused = true)]
    async fn monitor_closes_idle_empty_carrier_after_60s() {
        let worker = Arc::new(ServerWorker::new(Arc::new(MockDispatcher)));
        let (_r, w) = xray_buf::pipe::new();
        let link_writer: Arc<tokio::sync::Mutex<Option<Box<dyn Writer>>>> =
            Arc::new(tokio::sync::Mutex::new(Some(Box::new(w))));
        let monitor = worker.spawn_monitor(Arc::clone(&link_writer));
        // 先让 monitor 任务跑一轮注册 60s 定时器（此刻虚拟时间为 0），
        // 否则 advance 之后注册的定时器落在未来，tick 永不触发
        tokio::task::yield_now().await;

        tokio::time::advance(SERVER_MONITOR_INTERVAL + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert!(worker.is_closed(), "空载 60s 后 monitor 关闭整条 carrier");
        assert!(worker.session_manager().is_closed());
        assert!(
            link_writer.lock().await.is_none(),
            "carrier 写端被丢弃（Go Interrupt(link.Writer) 等价）"
        );
        monitor.abort();
    }

    /// 验收：长轮询 300s 不断 + count 变化窗口语义。活跃会话不被空闲杀
    /// （Rust 旧 300s 会话杀已删）；会话结束后第一个周期因快照 count 失效
    /// 不关闭，count 稳定后的周期才关（Go CloseIfNoSessionAndIdle）。
    #[tokio::test(start_paused = true)]
    async fn monitor_keeps_active_session_beyond_300s() {
        let worker = Arc::new(ServerWorker::new(Arc::new(MockDispatcher)));
        let (_r, w) = xray_buf::pipe::new();
        let link_writer: Arc<tokio::sync::Mutex<Option<Box<dyn Writer>>>> =
            Arc::new(tokio::sync::Mutex::new(Some(Box::new(w))));
        let monitor = worker.spawn_monitor(Arc::clone(&link_writer));
        // 先注册定时器再推进虚拟时间（同上）
        tokio::task::yield_now().await;

        let strategy = crate::session::ClientStrategy::default();
        let session = worker
            .session_manager()
            .allocate(&strategy)
            .await
            .expect("allocate");

        tokio::time::advance(Duration::from_secs(301)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert!(!session.is_closed(), "长轮询会话不得被空闲杀");
        assert!(!worker.is_closed(), "有会话时 carrier 不得关闭");

        session.close().await;
        tokio::time::advance(SERVER_MONITOR_INTERVAL + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert!(
            !worker.is_closed(),
            "count 变化后的第一个周期不关闭（快照失效）"
        );

        tokio::time::advance(SERVER_MONITOR_INTERVAL + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert!(worker.is_closed(), "空载且 count 稳定后关闭整条 carrier");
        monitor.abort();
    }

    #[test]
    fn test_dispatch_error_display() {
        assert_eq!(format!("{}", DispatchError::NoRoute("1.2.3.4".to_string())), "no route to destination: 1.2.3.4");
    }

    #[test]
    fn test_server_error_display() {
        assert_eq!(format!("{}", ServerError::InvalidFrame("bad".to_string())), "invalid frame: bad");
    }

    #[tokio::test]
    async fn test_server_worker_new() {
        let worker = ServerWorker::new(Arc::new(MockDispatcher));
        assert!(!worker.is_closed());
        assert_eq!(worker.active_connections().await, 0);
    }

    /// bd lahx：ServerWorker 构造即接线 XUDP 常驻清理任务（Go init goroutine
    /// 语义），Expiring 过期条目被周期回收。
    #[tokio::test(start_paused = true)]
    async fn server_worker_wires_xudp_periodic_cleanup() {
        let worker = Arc::new(ServerWorker::new(Arc::new(MockDispatcher)));
        let mut xudp = crate::session::XUDP::new([9u8; 8]);
        xudp.status = crate::session::XudpStatus::Expiring;
        xudp.expire = std::time::Instant::now() - Duration::from_secs(1);
        worker.xudp_manager.register(xudp).await;

        tokio::time::advance(Duration::from_secs(61)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert_eq!(
            worker.xudp_manager.len().await,
            0,
            "worker-owned cleanup task must reclaim expired entries"
        );
    }
    #[tokio::test]
    async fn test_server_worker_close() {
        let worker = ServerWorker::new(Arc::new(MockDispatcher));
        worker.close();
        assert!(worker.is_closed());
    }

    #[test]
    fn test_server_is_mux_destination() {
        let d = Destination::new(Address::new_domain(MUX_COOL_ADDRESS), Port::new(9527), Network::TCP);
        assert!(Server::is_mux_destination(&d));
    }

    #[tokio::test]
    async fn test_server_dispatch_non_mux() {
        let server = Server::new(Arc::new(MockDispatcher));
        let d = Destination::new(Address::new_domain("example.com".to_string()), Port::new(443), Network::TCP);
        assert!(server.dispatch(&d).await.is_err());
    }

    #[test]
    fn test_dispatch_error_is_std_error() {
        let err = DispatchError::NoRoute("test".to_string());
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn test_server_error_is_std_error() {
        let err = ServerError::InvalidFrame("test".to_string());
        let _: &dyn std::error::Error = &err;
    }


    #[tokio::test]
    async fn test_dispatch_handler_adapter_creates_link() {
        use xray_app_dispatcher::default::DispatchHandler;
        use xray_common::net::address::Address;
        use xray_common::net::port::Port;

        #[derive(Debug)]
        struct NopHandler;
        impl DispatchHandler for NopHandler {
            fn tag(&self) -> &str { "nop" }
            fn dispatch(
                &self,
                _dest: &xray_common::net::destination::Destination,
                _link: xray_transport::link::Link,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>> {
                Box::pin(async {})
            }
        }

        let adapter = DispatchHandlerAdapter::new(Arc::new(NopHandler));
        let dest = Destination::new(Address::new_domain("example.com".to_string()), Port::new(443), Network::TCP);
        let result = adapter.dispatch(dest).await;
        assert!(result.is_ok(), "adapter should return a link");
    }

    // ===== bd 6z8：XUDP gate 触发 + New 帧内联 data 转发 + 首帧即时送达 =====

    mod gate_tests {
        use super::*;
        use std::sync::Arc;
        use tokio::sync::Mutex as AsyncMutex;
        use xray_buf::io::{Reader as _, Writer as _};
        use xray_buf::pipe;
        use xray_buf::reader::BufferedReader;
        use xray_common::net::address::Address;
        use xray_common::net::port::Port;
        use xray_common::serial;

        /// 捕获 dispatcher：记录 dispatch dest，交出 payload 读端
        /// （ret writer 保活，防 session input 立即 EOF）。
        #[derive(Clone)]
        struct CaptureDispatcher {
            tx: tokio::sync::mpsc::UnboundedSender<(Destination, pipe::Reader)>,
            keepers: Arc<parking_lot::Mutex<Vec<pipe::Writer>>>,
        }

        #[async_trait::async_trait]
        impl Dispatcher for CaptureDispatcher {
            async fn dispatch(&self, dest: Destination) -> Result<Link, DispatchError> {
                let (ret_r, ret_w) = pipe::new();
                let (pay_r, pay_w) = pipe::new();
                self.keepers.lock().push(ret_w);
                let _ = self.tx.send((dest.clone(), pay_r));
                Ok(Link {
                    reader: Box::new(ret_r),
                    writer: Box::new(pay_w),
                })
            }
        }

        fn udp_dest() -> Destination {
            Destination::new(
                Address::ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
                Port::new(53),
                Network::UDP,
            )
        }

        fn tcp_dest() -> Destination {
            Destination::new(
                Address::new_domain("example.com".to_string()),
                Port::new(443),
                Network::TCP,
            )
        }

        /// New 帧 + 内联 data 的线格式（meta + 2B size + payload）。
        fn new_frame_with_data(meta: FrameMetadata, payload: &[u8]) -> Vec<u8> {
            let mut buf = meta.to_bytes();
            buf.extend_from_slice(&serial::write_uint16(payload.len() as u16));
            buf.extend_from_slice(payload);
            buf
        }

        /// 喂一帧到 ServerWorker，返回 dispatch 结果 (dest, payload reader)。
        async fn process_one_frame(
            frame: Vec<u8>,
        ) -> (Destination, pipe::Reader, Arc<ServerWorker>) {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let dispatcher = CaptureDispatcher {
                tx,
                keepers: Arc::new(parking_lot::Mutex::new(Vec::new())),
            };
            let server = Arc::new(ServerWorker::new(Arc::new(dispatcher)));
            let (_lw_r, lw_w) = pipe::new();
            let link_writer: Arc<AsyncMutex<Option<Box<dyn Writer>>>> =
                Arc::new(AsyncMutex::new(Some(Box::new(lw_w))));
            let mut reader = BufferedReader::new(xray_buf::io::new_reader(
                std::io::Cursor::new(frame),
            ));
            let ok = server
                .process_frame(&mut reader, &link_writer)
                .await
                .expect("frame processed");
            assert!(ok, "frame should be processed");
            let (dest, pay) = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
                .await
                .expect("dispatch captured")
                .expect("channel open");
            (dest, pay, server)
        }

        /// 从 payload 读端读出全部字节（短超时：验证即时送达，非缓冲滞留）。
        async fn read_payload(pay: &mut pipe::Reader) -> Vec<u8> {
            let mb = tokio::time::timeout(std::time::Duration::from_millis(1500), pay.read_multi_buffer())
                .await
                .expect("payload must arrive without further writes (no buffer stall)")
                .expect("read ok");
            let mut out = Vec::new();
            for b in mb.iter() {
                out.extend_from_slice(b.bytes());
            }
            out
        }

        /// XUDP gate：New + UDP + global_id → handle_xudp_new 路径，
        /// 内联 data 必须转发到 dispatch 目标（Go server.go:240）。bd 6z8。
        #[tokio::test]
        async fn xudp_new_frame_forwards_inline_data() {
            let gid = [9u8; 8];
            let mut meta = FrameMetadata::new_session(7, udp_dest());
            meta.set_global_id(gid);
            let frame = new_frame_with_data(meta, b"first-udp-packet");

            let (dest, mut pay, _server) = process_one_frame(frame).await;

            assert_eq!(dest.network(), Network::UDP);
            let got = read_payload(&mut pay).await;
            assert_eq!(got, b"first-udp-packet");
        }

        /// 普通路径：New + UDP（无 global_id）→ handle_normal_new Packet 会话，
        /// 小包首帧即时送达（不得滞留 BufferedWriter 缓冲）。bd 6z8。
        #[tokio::test]
        async fn udp_new_small_first_frame_immediate() {
            let meta = FrameMetadata::new_session(8, udp_dest());
            let frame = new_frame_with_data(meta, b"tiny");

            let (_dest, mut pay, _server) = process_one_frame(frame).await;

            let got = read_payload(&mut pay).await;
            assert_eq!(got, b"tiny");
        }

        /// 普通路径：New + TCP Stream 会话小首帧也即时送达。bd 6z8。
        #[tokio::test]
        async fn tcp_new_small_first_frame_immediate() {
            let meta = FrameMetadata::new_session(9, tcp_dest());
            let frame = new_frame_with_data(meta, b"GET /");

            let (_dest, mut pay, _server) = process_one_frame(frame).await;

            let got = read_payload(&mut pay).await;
            assert_eq!(got, b"GET /");
        }

        /// AllowedNetwork 校验（Go common/mux/server.go:189-192）：allowed=UDP
        /// 时收到 TCP 目标 New 帧 → process_frame 返回 Err（调用方 run 循环
        /// 等价物 break → 整条 carrier 连接拆除）。vless XRV+mux / splithttp
        /// 入站注入 UDP 允许网络后，子会话恒应为 UDP。
        #[tokio::test]
        async fn allowed_network_rejects_mismatched_new_frame() {
            let meta = FrameMetadata::new_session(10, tcp_dest());
            let frame = new_frame_with_data(meta, b"unexpected-tcp");

            let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
            let dispatcher = CaptureDispatcher {
                tx,
                keepers: Arc::new(parking_lot::Mutex::new(Vec::new())),
            };
            let server = Arc::new(
                ServerWorker::new(Arc::new(dispatcher))
                    .with_allowed_network(Network::UDP),
            );
            let (_lw_r, lw_w) = pipe::new();
            let link_writer: Arc<AsyncMutex<Option<Box<dyn Writer>>>> =
                Arc::new(AsyncMutex::new(Some(Box::new(lw_w))));
            let mut reader = BufferedReader::new(xray_buf::io::new_reader(
                std::io::Cursor::new(frame),
            ));

            let res = server.process_frame(&mut reader, &link_writer).await;
            assert!(res.is_err(), "TCP New frame must be rejected under allowed=UDP");
        }

        /// 对照：allowed=UDP 时 UDP 目标 New 帧正常放行。
        #[tokio::test]
        async fn allowed_network_udp_accepts_udp_new_frame() {
            let meta = FrameMetadata::new_session(11, udp_dest());
            let frame = new_frame_with_data(meta, b"udp-ok");

            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let dispatcher = CaptureDispatcher {
                tx,
                keepers: Arc::new(parking_lot::Mutex::new(Vec::new())),
            };
            let server = Arc::new(
                ServerWorker::new(Arc::new(dispatcher))
                    .with_allowed_network(Network::UDP),
            );
            let (_lw_r, lw_w) = pipe::new();
            let link_writer: Arc<AsyncMutex<Option<Box<dyn Writer>>>> =
                Arc::new(AsyncMutex::new(Some(Box::new(lw_w))));
            let mut reader = BufferedReader::new(xray_buf::io::new_reader(
                std::io::Cursor::new(frame),
            ));

            let ok = server
                .process_frame(&mut reader, &link_writer)
                .await
                .expect("UDP frame must pass allowed=UDP gate");
            assert!(ok);
            let (dest, _pay) = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
                .await
                .expect("dispatch captured")
                .expect("channel open");
            assert_eq!(dest.network(), Network::UDP);
        }
    }

    /// XUDP e2e：client GlobalID 接线 + server 装配 + 双向收发。
    mod xudp_e2e_tests {
        use super::*;
        use crate::client::{ClientWorker, Link as ClientLink};
        use crate::session::ClientStrategy;
        use tokio::sync::Mutex as AsyncMutex;
        use xray_buf::pipe;

        /// UDP 捕获 dispatcher：交出"注入上游响应"的写端与"观察客户端
        /// 上行"的读端（Go 等价：真 UDP socket 两方向）。
        struct UdpCaptureDispatcher {
            tx: tokio::sync::mpsc::UnboundedSender<(Destination, pipe::Writer, pipe::Reader)>,
        }

        #[async_trait::async_trait]
        impl Dispatcher for UdpCaptureDispatcher {
            async fn dispatch(&self, dest: Destination) -> Result<Link, DispatchError> {
                let (r_down, w_down) = pipe::new(); // 上游→客户端：测试持 w_down 注入
                let (up_r, up_w) = pipe::new(); // 客户端→上游：测试持 up_r 观察
                let _ = self.tx.send((dest, w_down, up_r));
                Ok(Link {
                    reader: Box::new(r_down),
                    writer: Box::new(up_w),
                })
            }
        }

        fn udp_target() -> Destination {
            Destination::new(
                Address::ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
                Port::new(53),
                Network::UDP,
            )
        }

        /// ClientWorker ↔ ServerWorker 直连管道拓扑 + UDP 捕获 dispatcher。
        async fn spawn_topology()
        -> (Arc<ClientWorker>, Arc<ServerWorker>, tokio::sync::mpsc::UnboundedReceiver<(Destination, pipe::Writer, pipe::Reader)>) {
            let (c_read, s_write) = pipe::new(); // server → client
            let (s_read, c_write) = pipe::new(); // client → server
            let client = ClientWorker::new(
                ClientLink {
                    reader: Box::new(c_read),
                    writer: Box::new(c_write),
                },
                ClientStrategy::default(),
            );
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            let server = Arc::new(ServerWorker::new(Arc::new(UdpCaptureDispatcher { tx })));
            let mut reader = BufferedReader::new(Box::new(s_read));
            let link_writer: Arc<AsyncMutex<Option<Box<dyn Writer>>>> =
                Arc::new(AsyncMutex::new(Some(Box::new(s_write))));
            let monitor_h = server.spawn_monitor(Arc::clone(&link_writer));
            let frame_server = Arc::clone(&server);
            tokio::spawn(async move {
                loop {
                    match frame_server.process_frame(&mut reader, &link_writer).await {
                        Ok(true) => continue,
                        _ => break,
                    }
                }
                frame_server.close();
                monitor_h.abort();
            });
            (client, server, rx)
        }

        async fn read_all(r: &mut pipe::Reader) -> Vec<u8> {
            let mb = tokio::time::timeout(std::time::Duration::from_secs(3), r.read_multi_buffer())
                .await
                .expect("payload within timeout")
                .expect("read ok");
            let mut out = Vec::new();
            for b in mb.iter() {
                out.extend_from_slice(b.bytes());
            }
            out
        }

        /// 验收：XUDP New 后能收发。客户端 dispatch_with_source 按 cone 入站源
        /// 计算 GlobalID（Go client.go:271），服务端装配 XUDP 会话（Go
        /// server.go:247-260：manager session 直绑 dispatch I/O，泵任务读真
        /// I/O 回写 carrier——旧实现孤儿 ms 使上游响应永远回不来）。
        #[tokio::test]
        async fn xudp_new_bidirectional_send_receive() {
            use xray_xudp::GlobalIdInput;

            let (client, server, mut rx) = spawn_topology().await;

            // 客户端：UDP dest + cone 入站源 → GlobalID 随 New 帧下发
            let input = GlobalIdInput {
                source: "udp:10.0.0.1:5400".to_string(),
                source_network: Network::UDP,
                cone: true,
            };
            let gid = xray_xudp::global_id(&input);
            assert_ne!(gid, [0u8; 8], "cone UDP source must yield nonzero GlobalID");

            let (req_rd, req_wr) = pipe::new();
            let (resp_rd, resp_wr) = pipe::new();
            // 先写上行 payload（探针窗口内就绪）→ fetch_input 首读即得数据，
            // New 帧携带内联 data + GlobalID 同批下发（Go XUDP 线形态；空 New
            // 按 Go frame.go:216 语义不带 GlobalID，服务端按普通 packet 路径）。
            let mut req = req_wr;
            req.write_multi_buffer(MultiBuffer::from_buffer(Buffer::from_vec(
                b"dns-query".to_vec(),
            )))
            .await
            .expect("write uplink");

            let w = Arc::clone(&client);
            let d = udp_target();
            let task = tokio::spawn(async move {
                w.dispatch_with_source(&d, ClientLink {
                    reader: Box::new(req_rd),
                    writer: Box::new(resp_wr),
                }, Some(&input))
                .await
            });

            // 服务端 dispatch UDP 目标 + XUDP 装配完成（Active + mux 接线）
            let (dest, w_down, mut up_r) =
                tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
                    .await
                    .expect("dispatch within timeout")
                    .expect("channel open");
            assert_eq!(dest.network(), Network::UDP);
            assert_eq!(server.active_connections().await, 1, "XUDP session registered");
            let entry = server
                .xudp_manager
                .get(&gid)
                .await
                .expect("XUDP entry keyed by client GlobalID");
            assert_eq!(entry.status, XudpStatus::Active, "entry must be Active after assembly");

            // 上行：New 内联 data → 到达"上游"读端
            let got = read_all(&mut up_r).await;
            assert_eq!(got, b"dns-query", "uplink must reach dispatch target");

            // 下行：上游响应 → 泵任务读真 I/O → Keep 帧 → 客户端 resp 读端
            let mut resp = resp_rd;
            let mut pong = w_down;
            pong.write_multi_buffer(MultiBuffer::from_buffer(Buffer::from_vec(
                b"dns-answer".to_vec(),
            )))
            .await
            .expect("write downlink");
            let _ = pong.close();
            let back = tokio::time::timeout(std::time::Duration::from_secs(3), resp.read_multi_buffer())
                .await
                .expect("downlink within timeout")
                .expect("read ok");
            assert_eq!(back.to_vec(), b"dns-answer", "upstream response must flow back via pump");

            // 收尾：客户端半关闭 → End → server session 摘除
            let _ = req.close();
            let _ = task.await;
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), resp.read_multi_buffer()).await;
        }

        /// kgjo：同 GlobalID 重复 New 命中复用——不再调 dispatcher、不建新 session，
        /// 新包数据写旧 session output 沿用同一上行流。
        #[tokio::test]
        async fn xudp_new_same_global_id_reuses_existing_session() {
            use xray_xudp::GlobalIdInput;

            let (_client, server, mut rx) = spawn_topology().await;

            let input = GlobalIdInput {
                source: "udp:10.0.0.99:6500".to_string(),
                source_network: Network::UDP,
                cone: true,
            };
            let gid = xray_xudp::global_id(&input);
            assert_ne!(gid, [0u8; 8]);
            // 手动驱动两次 XUDP New（同 gid）：模拟 Go 端同一 UDP 流被 mux 化
            // 后 client 多个内层请求共享 GlobalID 的语义（XUDP 协议层）。
            for (i, payload) in [b"req-1".as_slice(), b"req-2".as_slice()].iter().enumerate() {
                let mut meta = FrameMetadata::new_session(100 + i as u16, udp_target());
                meta.set_global_id(gid);
                server
                    .handle_xudp_new(&meta, payload.to_vec(), &Arc::new(AsyncMutex::new(None)), gid)
                    .await
                    .expect("handle_xudp_new");
            }

            // dispatcher 只该被调用一次（首次 New），第二次 hit 复用旧 mux
            let (_dest, _w_down, mut up_r) =
                tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
                    .await
                    .expect("dispatch within timeout")
                    .expect("channel open");
            // 第二次不应再触发 dispatcher.recv（unbounded 单元素已消费）
            assert!(
                rx.try_recv().is_err(),
                "second New must reuse, not re-dispatch"
            );
            // 旧上行读端：两条 payload 通过同一管道到达，pipe 在 read_multi_buffer
            // 上一次性返回所有可读字节，故一次 read 就能拿到两个 payload 拼接。
            // 验证关键：复用路径下 dispatcher 不被第二次调用（try_recv 已断言）。
            let combined = read_all(&mut up_r).await;
            assert_eq!(
                combined,
                b"req-1req-2",
                "both packets arrive at the single upstream via reuse"
            );

            // XUDP entry 仍 Active（hit 路径不重置 status）
            let entry = server
                .xudp_manager
                .get(&gid)
                .await
                .expect("XUDP entry persists");
            assert_eq!(entry.status, XudpStatus::Active);

            // zv9l 验收：hit 重绑后新 sessionID 必须注册进 manager，
            // Keep（新 ID）数据必须到达复用的上游通道
            assert!(
                server.session_manager().get(101).await.is_some(),
                "rebound session must be registered under new ID (bd zv9l)"
            );
            let keep_meta = FrameMetadata::new_session(101, udp_target());
            server
                .handle_status_keep(&keep_meta, b"keep-data".to_vec())
                .await
                .expect("keep frame processed");
            let tail = read_all(&mut up_r).await;
            assert_eq!(
                tail, b"keep-data",
                "Keep with new sessionID must reach the reused upstream (bd zv9l)"
            );
        }
    }
}