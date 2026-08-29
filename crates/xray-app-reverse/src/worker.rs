//! Portal/Bridge worker 纯决策逻辑。
//!
//! 对应 Go `portal.go` 的 `PortalWorker.heartbeat` 决策部分 +
//! `bridge.go` 的 `BridgeWorker.IsActive` 状态判断。
//! 实际 IO（pipe 读写、timer、mux client）由后续 Phase 接入。

use crate::config::ControlState;
use crate::error::ReverseError;

/// Portal worker 进入 drain 状态的总连接数阈值。
/// 对应 Go `portal.go` 的 `w.client.TotalConnections() > 256`。
pub const DRAIN_THRESHOLD: u32 = 256;

/// Heartbeat counter 模数。
/// 对应 Go `portal.go` 的 `w.counter = (w.counter + 1) % 5`。
pub const HEARTBEAT_COUNTER_MOD: u8 = 5;

/// Portal worker heartbeat 决策结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatDecision {
    /// 本次 heartbeat 是否应进入 drain（total_connections 超阈值）。
    pub should_drain: bool,
    /// 是否应发送 Control 消息（draining 或 counter == 1）。
    pub should_send: bool,
    /// 更新后的 counter 值。
    pub new_counter: u8,
    /// Control 消息的 state 字段。
    pub control_state: ControlState,
}

/// Portal worker 状态快照（heartbeat 决策输入）。
///
/// 对应 Go `PortalWorker` 在 heartbeat 时刻读取的字段集合。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortalWorkerState {
    /// worker 是否已关闭。
    pub closed: bool,
    /// 是否已进入 drain 状态。
    pub already_draining: bool,
    /// writer 是否存在（Go 中 `w.writer != nil`）。
    pub writer_present: bool,
    /// 当前总连接数。
    pub total_connections: u32,
    /// 当前 heartbeat counter。
    pub counter: u8,
}

/// Portal worker heartbeat 决策（对应 Go `PortalWorker.heartbeat` 的纯逻辑部分）。
///
/// 预检查（与 Go 一致）：
/// - `closed` → `Err(WorkerStopped)`
/// - `already_draining || !writer_present` → `Err(AlreadyDisposed)`
///
/// 决策：
/// - `total_connections > DRAIN_THRESHOLD` → 本次进入 drain
/// - `counter = (counter + 1) % HEARTBEAT_COUNTER_MOD`
/// - `should_drain || counter == 1` → 发送 Control
pub fn portal_heartbeat_decision(
    state: &PortalWorkerState,
) -> Result<HeartbeatDecision, ReverseError> {
    if state.closed {
        return Err(ReverseError::WorkerStopped);
    }
    if state.already_draining || !state.writer_present {
        return Err(ReverseError::AlreadyDisposed);
    }

    let should_drain = state.total_connections > DRAIN_THRESHOLD;
    let new_counter = (state.counter + 1) % HEARTBEAT_COUNTER_MOD;
    let should_send = should_drain || new_counter == 1;
    let control_state = if should_drain {
        ControlState::Drain
    } else {
        ControlState::Active
    };

    Ok(HeartbeatDecision {
        should_drain,
        should_send,
        new_counter,
        control_state,
    })
}

/// Bridge worker 是否活跃（对应 Go `BridgeWorker.IsActive`）。
///
/// `state == Active && !worker_closed`
#[must_use]
pub fn bridge_worker_is_active(state: ControlState, worker_closed: bool) -> bool {
    matches!(state, ControlState::Active) && !worker_closed
}

// ===========================================================================
// IO 实体（PortalWorker / BridgeWorker）
//
// 对应 Go `app/reverse/portal.go:224-308`（PortalWorker）与
// `app/reverse/bridge.go:101-235`（BridgeWorker）。
// 上方纯决策函数保留为实体的决策核。
// ===========================================================================

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use prost::Message as _;
use xray_buf::io::{Reader as IoReader, Writer as IoWriter};
use xray_buf::multi::MultiBuffer;
use xray_buf::pipe::{self, PipeOption};
use xray_buf::reader::BufferedReader;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_mux::client::{ClientWorker, Link as MuxLink};
use xray_mux::worker::ServerWorker;
use xray_proto::xray::app::reverse::Control as ProtoControl;
use xray_transport::link::Link as TransportLink;

use crate::bridge::LinkDispatch;
use crate::config::{Control, INTERNAL_DOMAIN};
use crate::timer::InactivityTimer;

/// Portal worker 心跳间隔（Go `portal.go:262` Interval: 2s）。
pub const PORTAL_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);

/// Portal worker 不活动终止窗口（Go `portal.go:258` 24h，防泄漏）。
pub const PORTAL_IDLE_TIMEOUT: Duration = Duration::from_secs(24 * 3600);

/// Bridge worker 不活动终止窗口（Go `bridge.go:137` 60s）。
pub const BRIDGE_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Bridge worker 控制流 EOF 后的存活窗口（Go `bridge.go:174` SetTimeout(24h)）。
pub const BRIDGE_DRAIN_WINDOW: Duration = Duration::from_secs(24 * 3600);

/// 控制/数据 pipe 缓冲上限（Go `WithSizeLimit(16 * 1024)`）。
const PIPE_LIMIT: i64 = 16 * 1024;

fn control_pipe_option() -> PipeOption {
    PipeOption {
        limit: PIPE_LIMIT,
        ..PipeOption::default()
    }
}

/// 内部控制连接目标（Go `portal.go:241`：`UDPDestination(DomainAddress("reverse"), 0)`）。
///
/// ponytail: Rust mux client 恒写 global_id `[0;8]`，server 端 UDP dest 强制走
/// XUDP 路径（`handle_xudp_new`），New 帧内联 data 被丢弃（Go `xudp.GetGlobalID`
/// 无全局 ID 时返回 nil → 普通 packet 路径，data 正常转发）。控制流改用 TCP dest
/// 绕开 XUDP 状态机——域名 `reverse` + port 0 的识别语义不变，仅帧 transfer
/// type 不同。mux crate Go 对齐缺口补齐（global_id 可空）后可回归 UDP。
pub fn internal_control_destination() -> Destination {
    Destination::new(
        Address::new_domain(INTERNAL_DOMAIN.to_string()),
        Port::new(0),
        Network::TCP,
    )
}

/// 对应 Go `PortalWorker`（portal.go:224-308）：
/// - 构造：两对 16KiB pipe + 控制连接 dispatch（内部 UDP dest）+ 24h 不活动 timer
/// - 心跳：`Periodic{Interval: 2s}`，`proto.Marshal` + `MergeBytes` 写 Control
/// - drain（total connections > [`DRAIN_THRESHOLD`]）：发 `Control_DRAIN` 后
///   close writer / interrupt reader / 置空 writer
pub struct PortalWorker {
    client: Arc<ClientWorker>,
    /// 控制流上行写端（portal → bridge）。drain 后置 None（Go `w.writer = nil`）。
    writer: Mutex<Option<pipe::Writer>>,
    /// 控制流下行读端（drain 时 interrupt，Go `w.reader`）。
    reader: pipe::Reader,
    draining: AtomicBool,
    counter: AtomicU8,
    timer: Arc<InactivityTimer>,
}

impl PortalWorker {
    /// 创建 PortalWorker 并启动心跳任务。
    ///
    /// 对应 Go `NewPortalWorker`（portal.go:234-266）。控制连接 dispatch 经
    /// `tokio::spawn`：Go 仅在 reader 非 pipe 时等待；Rust `ClientWorker::dispatch`
    /// 统一等待 session 结束，pipe reader 场景 Go 立即返回——spawn 等价。
    pub fn new(client: Arc<ClientWorker>) -> Result<Arc<Self>, ReverseError> {
        if client.is_full() {
            return Err(ReverseError::DispatchControlFailed);
        }
        let (up_r, up_w) = pipe::new_with_option(control_pipe_option());
        let (dn_r, dn_w) = pipe::new_with_option(control_pipe_option());

        let dest = internal_control_destination();
        let c = Arc::clone(&client);
        tokio::spawn(async move {
            c.dispatch(
                &dest,
                MuxLink {
                    reader: Box::new(up_r),
                    writer: Box::new(dn_w),
                },
            )
            .await;
        });

        let timer_client = Arc::clone(&client);
        let timer = InactivityTimer::new(PORTAL_IDLE_TIMEOUT, move || {
            timer_client.close(); // Go terminate: client.Close()
        });

        let worker = Arc::new(Self {
            client,
            writer: Mutex::new(Some(up_w)),
            reader: dn_r,
            draining: AtomicBool::new(false),
            counter: AtomicU8::new(0),
            timer,
        });

        let hb_worker = Arc::clone(&worker);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(PORTAL_HEARTBEAT_INTERVAL).await;
                if hb_worker.heartbeat().await.is_err() {
                    break; // Go task.Periodic：Execute 出错即停
                }
            }
        });

        Ok(worker)
    }

    pub fn client(&self) -> &Arc<ClientWorker> {
        &self.client
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    pub fn is_closed(&self) -> bool {
        self.client.is_closed()
    }

    /// 心跳一次（对应 Go `PortalWorker.heartbeat`，portal.go:268-300）。
    async fn heartbeat(&self) -> Result<(), ReverseError> {
        let state = PortalWorkerState {
            closed: self.client.is_closed(),
            already_draining: self.draining.load(Ordering::Acquire),
            writer_present: self.writer.lock().is_some(),
            total_connections: u32::from(self.client.session_count()),
            counter: self.counter.load(Ordering::Acquire),
        };
        let decision = portal_heartbeat_decision(&state)?;

        let mut msg = Control::default();
        msg.fill_in_random();
        if decision.should_drain {
            self.draining.store(true, Ordering::Release);
            msg.state = decision.control_state;
        }
        self.counter.store(decision.new_counter, Ordering::Release);

        if decision.should_send {
            let Some(mut writer) = self.writer.lock().take() else {
                return Err(ReverseError::AlreadyDisposed);
            };
            let bytes = msg.to_proto().encode_to_vec();
            // ponytail: from_vec（capacity==len）而非 merge_bytes（池 Buffer 8KB 容量）——
            // mux MuxWriter 内部 BufferedWriter 对 capacity>>len 的 buffer 滞留不
            // flush，小 Control 帧会卡在缓冲；from_vec buffer 走直写路径
            // （Go buf.MergeBytes 语义等价：单 buffer 承载整条消息）。
            let mb = MultiBuffer::from_buffer(xray_buf::buffer::Buffer::from_vec(bytes));
            self.timer.update();
            let result = writer.write_multi_buffer(mb).await;
            if decision.should_drain {
                // Go defer（portal.go:284-288）：Close(writer) → Interrupt(reader) → writer=nil
                let _ = writer.close();
                self.reader.interrupt();
            } else {
                *self.writer.lock() = Some(writer);
            }
            result.map_err(|e| ReverseError::PortalDispatchFailed(e.to_string()))?;
        }
        Ok(())
    }
}

impl crate::picker::PickerWorker for PortalWorker {
    fn is_full(&self) -> bool {
        self.client.is_full()
    }

    fn is_closed(&self) -> bool {
        PortalWorker::is_closed(self)
    }

    fn is_draining(&self) -> bool {
        PortalWorker::is_draining(self)
    }

    /// ponytail: Go 用 `client.ActiveConnections()`（SessionManager::size，async）；
    /// Rust picker 为同步 trait，用 `session_count()`（累计值）近似。稳态下
    /// 等价；会话关闭后不回收，偏向较新 worker。需要精确活跃数时给
    /// SessionManager 加同步 active 计数。
    fn active_connections(&self) -> u32 {
        u32::from(self.client.session_count())
    }
}

// ---------------------------------------------------------------------------
// BridgeWorker
// ---------------------------------------------------------------------------

/// Bridge 侧 worker：一条反向 carrier 上的 mux 服务端 + 控制流状态机。
///
/// 对应 Go `BridgeWorker`（bridge.go:101-235）：
/// - 构造：真实 dispatcher dispatch `domain:0/TCP`（注入 inbound tag）得 carrier
///   → `mux.NewServerWorker(self, carrier)` → 60s 不活动 timer（terminate = worker.Close）
/// - `handleInternalConn`：读 Control proto → state 转换
/// - `dispatch`（mux Dispatcher）：内部域走控制 pipe，其余转真实 dispatcher（注入 tag）
pub struct BridgeWorker {
    tag: String,
    worker: RwLock<Option<Arc<ServerWorker>>>,
    dispatcher: Arc<dyn LinkDispatch>,
    /// `ControlState` as u8（Go `w.State`）。
    state: AtomicU8,
    timer: RwLock<Option<Arc<InactivityTimer>>>,
    self_ref: RwLock<Option<std::sync::Weak<Self>>>,
}

impl BridgeWorker {
    /// 创建 BridgeWorker：dispatch carrier + 起 mux ServerWorker + 60s timer。
    ///
    /// 对应 Go `NewBridgeWorker`（bridge.go:109-139）。
    pub async fn new(
        domain: &str,
        tag: &str,
        dispatcher: Arc<dyn LinkDispatch>,
    ) -> Result<Arc<Self>, ReverseError> {
        let dest = Destination::new(
            Address::new_domain(domain.to_string()),
            Port::new(0),
            Network::TCP,
        );
        let carrier = dispatcher.dispatch(&dest, Some(tag)).await?;

        let me = Arc::new(Self {
            tag: tag.to_string(),
            worker: RwLock::new(None),
            dispatcher,
            state: AtomicU8::new(ControlState::Active as u8),
            timer: RwLock::new(None),
            self_ref: RwLock::new(None),
        });
        *me.self_ref.write() = Some(Arc::downgrade(&me));

        let server = Arc::new(ServerWorker::new(me.clone()));
        *me.worker.write() = Some(Arc::clone(&server));

        let timer_server = Arc::clone(&server);
        *me.timer.write() = Some(InactivityTimer::new(BRIDGE_IDLE_TIMEOUT, move || {
            timer_server.close(); // Go terminate: worker.Close()
        }));

        // carrier 帧循环（对应 Go NewServerWorker 内部读循环；模板 = xray-core
        // inbound.rs handle_mux_inbound_link）
        let mut reader = BufferedReader::new(carrier.reader);
        let link_writer: Arc<tokio::sync::Mutex<Option<Box<dyn IoWriter>>>> =
            Arc::new(tokio::sync::Mutex::new(Some(carrier.writer)));
        let (keepalive_h, idle_h) =
            server.spawn_keepalive_and_idle_timeout(Arc::clone(&link_writer));
        let frame_server = Arc::clone(&server);
        tokio::spawn(async move {
            loop {
                match frame_server.process_frame(&mut reader, &link_writer).await {
                    Ok(true) => continue,
                    _ => break,
                }
            }
            frame_server.close();
            keepalive_h.abort();
            idle_h.abort();
        });

        Ok(me)
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn state(&self) -> ControlState {
        match self.state.load(Ordering::Acquire) {
            1 => ControlState::Drain,
            _ => ControlState::Active,
        }
    }

    pub fn server_worker(&self) -> Option<Arc<ServerWorker>> {
        self.worker.read().clone()
    }

    /// mux ServerWorker 是否已关闭（Go `BridgeWorker.Closed`）。
    pub fn is_closed(&self) -> bool {
        self.worker.read().as_ref().is_none_or(|w| w.is_closed())
    }

    /// 是否活跃（Go `BridgeWorker.IsActive`：state == Active && !Closed）。
    pub fn is_active(&self) -> bool {
        bridge_worker_is_active(self.state(), self.is_closed())
    }

    /// 活跃连接数（Go `BridgeWorker.Connections`）。
    pub async fn connections(&self) -> u32 {
        // let 绑定先释放 guard（match scrutinee 的临时 guard 会活到 match 结束，
        // 含 await 臂，导致 non-Send）
        let server = self.worker.read().clone();
        match server {
            Some(w) => w.active_connections().await,
            None => 0,
        }
    }

    fn arc(&self) -> Option<Arc<Self>> {
        self.self_ref.read().as_ref().and_then(|w| w.upgrade())
    }

    /// 控制流读取循环：Control proto → state 转换。
    ///
    /// 对应 Go `BridgeWorker.handleInternalConn`（bridge.go:165-196）：
    /// - 读错（EOF/interrupt）：Closed → `SetTimeout(0)`（立即终止）；
    ///   否则 `SetTimeout(24h)`（drain 存活窗口）
    /// - proto 解析失败：log + `SetTimeout(0)` + return
    /// - 每次成功读：`Timer.Update()`；state 变化即覆写
    pub(crate) async fn handle_internal_conn(me: Arc<Self>, mut reader: Box<dyn IoReader>) {
        loop {
            let mb = match reader.read_multi_buffer().await {
                Err(_) => {
                    if let Some(t) = me.timer.read().clone() {
                        if me.is_closed() {
                            t.set_timeout(Duration::ZERO);
                        } else {
                            t.set_timeout(BRIDGE_DRAIN_WINDOW);
                        }
                    }
                    return;
                }
                Ok(mb) => mb,
            };
            if let Some(t) = me.timer.read().clone() {
                t.update();
            }
            // 每个 Buffer 一条 Control 消息（Go `for _, b := range mb`）
            for b in mb.iter() {
                let parse_result = ProtoControl::decode(b.bytes())
                    .map_err(ReverseError::from)
                    .and_then(|c| Control::from_proto(&c));
                match parse_result {
                    Ok(c) => me.state.store(c.state as u8, Ordering::Release),
                    Err(e) => {
                        // Go bridge.go:184-190：解析失败 → log + SetTimeout(0)
                        tracing::info!(
                            target: "xray_app_reverse",
                            error = %e,
                            "failed to parse proto message"
                        );
                        if let Some(t) = me.timer.read().clone() {
                            t.set_timeout(Duration::ZERO);
                        }
                        return;
                    }
                }
            }
        }
    }

    /// 消费式 dispatch（Go `BridgeWorker.DispatchLink`，bridge.go:223-235）。
    ///
    /// 内部域：同步消费控制流；其余：注入 inbound tag 后转真实 dispatcher。
    pub async fn dispatch_link(
        &self,
        dest: &Destination,
        link: TransportLink,
    ) -> Result<(), ReverseError> {
        if !crate::bridge::is_internal_domain(dest.address().as_domain()) {
            let tag = self.tag.clone();
            return self
                .dispatcher
                .dispatch_link(dest, link, Some(tag.as_str()))
                .await;
        }
        let Some(me) = self.arc() else {
            return Err(ReverseError::CreateBridgeWorker(
                "bridge worker not initialized".into(),
            ));
        };
        Self::handle_internal_conn(me, link.reader).await;
        Ok(())
    }
}

#[async_trait::async_trait]
impl xray_mux::worker::Dispatcher for BridgeWorker {
    /// 返回式 dispatch（Go `BridgeWorker.Dispatch`，bridge.go:198-221）。
    ///
    /// 内部域：两对 16KiB pipe，spawn `handle_internal_conn` 读下行；
    /// 返回上行 link 给 mux session。其余：注入 inbound tag 转真实 dispatcher。
    async fn dispatch(
        &self,
        dest: Destination,
    ) -> Result<MuxLink, xray_mux::worker::DispatchError> {
        if !crate::bridge::is_internal_domain(dest.address().as_domain()) {
            let tag = self.tag.clone();
            return self
                .dispatcher
                .dispatch(&dest, Some(tag.as_str()))
                .await
                .map(|l| MuxLink {
                    reader: l.reader,
                    writer: l.writer,
                })
                .map_err(|e| {
                    xray_mux::worker::DispatchError::ConnectionFailed(e.to_string())
                });
        }

        let Some(me) = self.arc() else {
            return Err(xray_mux::worker::DispatchError::ConnectionFailed(
                "bridge worker not initialized".into(),
            ));
        };
        let (up_r, up_w) = pipe::new_with_option(control_pipe_option());
        let (dn_r, dn_w) = pipe::new_with_option(control_pipe_option());
        // up_w 随控制流任务存活（Go Link{Writer: uplinkWriter} 被 goroutine 持有），
        // 任务结束 drop → up_r EOF → mux session 收尾。
        tokio::spawn(async move {
            Self::handle_internal_conn(me, Box::new(dn_r)).await;
            drop(up_w);
        });
        Ok(MuxLink {
            reader: Box::new(up_r),
            writer: Box::new(dn_w),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(closed: bool, draining: bool, writer: bool, conn: u32, counter: u8) -> PortalWorkerState {
        PortalWorkerState {
            closed,
            already_draining: draining,
            writer_present: writer,
            total_connections: conn,
            counter,
        }
    }

    // --- portal_heartbeat_decision ---

    #[test]
    fn heartbeat_closed_returns_worker_stopped() {
        let err = portal_heartbeat_decision(&state(true, false, true, 0, 0)).unwrap_err();
        assert!(matches!(err, ReverseError::WorkerStopped));
    }

    #[test]
    fn heartbeat_already_draining_returns_disposed() {
        let err = portal_heartbeat_decision(&state(false, true, true, 0, 0)).unwrap_err();
        assert!(matches!(err, ReverseError::AlreadyDisposed));
    }

    #[test]
    fn heartbeat_no_writer_returns_disposed() {
        let err = portal_heartbeat_decision(&state(false, false, false, 0, 0)).unwrap_err();
        assert!(matches!(err, ReverseError::AlreadyDisposed));
    }

    #[test]
    fn heartbeat_below_threshold_no_drain() {
        let d = portal_heartbeat_decision(&state(false, false, true, 100, 0)).unwrap();
        assert!(!d.should_drain);
        assert_eq!(d.control_state, ControlState::Active);
    }

    #[test]
    fn heartbeat_at_threshold_no_drain() {
        // 256 is NOT > 256, so no drain
        let d = portal_heartbeat_decision(&state(false, false, true, DRAIN_THRESHOLD, 0)).unwrap();
        assert!(!d.should_drain);
        assert_eq!(d.control_state, ControlState::Active);
    }

    #[test]
    fn heartbeat_above_threshold_drains() {
        let d = portal_heartbeat_decision(&state(false, false, true, DRAIN_THRESHOLD + 1, 0)).unwrap();
        assert!(d.should_drain);
        assert_eq!(d.control_state, ControlState::Drain);
    }

    #[test]
    fn heartbeat_counter_wraps_mod5() {
        // counter 4 → (4+1)%5 = 0
        let d = portal_heartbeat_decision(&state(false, false, true, 0, 4)).unwrap();
        assert_eq!(d.new_counter, 0);
        // counter 0 → (0+1)%5 = 1
        let d = portal_heartbeat_decision(&state(false, false, true, 0, 0)).unwrap();
        assert_eq!(d.new_counter, 1);
        // counter 3 → (3+1)%5 = 4
        let d = portal_heartbeat_decision(&state(false, false, true, 0, 3)).unwrap();
        assert_eq!(d.new_counter, 4);
    }

    #[test]
    fn heartbeat_sends_when_counter_is_1() {
        // counter 0 → new_counter 1 → should_send = true (even without drain)
        let d = portal_heartbeat_decision(&state(false, false, true, 0, 0)).unwrap();
        assert!(d.should_send);
    }

    #[test]
    fn heartbeat_does_not_send_when_counter_not_1_and_no_drain() {
        // counter 1 → new_counter 2, no drain → should_send = false
        let d = portal_heartbeat_decision(&state(false, false, true, 0, 1)).unwrap();
        assert!(!d.should_send);
    }

    #[test]
    fn heartbeat_drain_always_sends() {
        // Even if counter is not 1, drain forces send
        let d = portal_heartbeat_decision(&state(false, false, true, DRAIN_THRESHOLD + 1, 1)).unwrap();
        assert!(d.should_drain);
        assert!(d.should_send);
    }

    #[test]
    fn heartbeat_full_cycle() {
        // Simulate 5 heartbeats: only counter==1 and drain should send
        let mut counter = 0u8;
        let mut send_count = 0;
        for _ in 0..5 {
            let st = state(false, false, true, 10, counter);
            let d = portal_heartbeat_decision(&st).unwrap();
            if d.should_send {
                send_count += 1;
            }
            counter = d.new_counter;
        }
        // In 5 iterations, counter cycles 1,2,3,4,0 — only counter==1 sends once
        assert_eq!(send_count, 1);
    }

    // --- bridge_worker_is_active ---

    #[test]
    fn bridge_active_when_active_state_and_not_closed() {
        assert!(bridge_worker_is_active(ControlState::Active, false));
    }

    #[test]
    fn bridge_inactive_when_drain_state() {
        assert!(!bridge_worker_is_active(ControlState::Drain, false));
    }

    #[test]
    fn bridge_inactive_when_closed() {
        assert!(!bridge_worker_is_active(ControlState::Active, true));
    }

    #[test]
    fn bridge_inactive_when_drain_and_closed() {
        assert!(!bridge_worker_is_active(ControlState::Drain, true));
    }

    #[test]
    fn drain_threshold_constant() {
        assert_eq!(DRAIN_THRESHOLD, 256);
    }

    #[test]
    fn heartbeat_counter_mod_constant() {
        assert_eq!(HEARTBEAT_COUNTER_MOD, 5);
    }
}

// ===========================================================================
// IO 实体测试
// ===========================================================================

#[cfg(test)]
mod entity_tests {
    use super::*;
    use crate::bridge::LinkDispatch;
    use crate::config::ControlState;
    use parking_lot::Mutex;
    use xray_buf::io::Writer as _;
    use xray_buf::pipe;
    use xray_common::net::address::Address;
    use xray_common::net::port::Port;
    use xray_mux::client::ClientWorker;
    use xray_mux::worker::Dispatcher as _;
    use xray_mux::session::ClientStrategy;

    /// 记录 (dest, inbound_tag) 的 mock 真实 dispatcher。
    #[derive(Default)]
    struct MockLinkDispatch {
        calls: Mutex<Vec<(Destination, Option<String>)>>,
    }

    #[async_trait::async_trait]
    impl LinkDispatch for MockLinkDispatch {
        async fn dispatch(
            &self,
            dest: &Destination,
            inbound_tag: Option<&str>,
        ) -> Result<xray_transport::link::Link, ReverseError> {
            self.calls
                .lock()
                .push((dest.clone(), inbound_tag.map(str::to_string)));
            let (r, w) = pipe::new();
            Ok(xray_transport::link::Link::new(Box::new(r), Box::new(w)))
        }

        async fn dispatch_link(
            &self,
            dest: &Destination,
            _link: xray_transport::link::Link,
            inbound_tag: Option<&str>,
        ) -> Result<(), ReverseError> {
            self.calls
                .lock()
                .push((dest.clone(), inbound_tag.map(str::to_string)));
            Ok(())
        }
    }

    /// 服务端捕获 dispatcher：记录 dispatch dest，送出控制流读端。
    /// 返回流量 writer 保活（drop 会立即使 session reader EOF）。
    #[derive(Clone)]
    struct CaptureDispatcher {
        tx: tokio::sync::mpsc::UnboundedSender<(Destination, pipe::Reader)>,
        keepers: std::sync::Arc<Mutex<Vec<pipe::Writer>>>,
    }

    #[async_trait::async_trait]
    impl xray_mux::worker::Dispatcher for CaptureDispatcher {
        async fn dispatch(
            &self,
            dest: Destination,
        ) -> Result<MuxLink, xray_mux::worker::DispatchError> {
            let (ret_r, ret_w) = pipe::new();
            let (pay_r, pay_w) = pipe::new();
            self.keepers.lock().push(ret_w);
            let _ = self.tx.send((dest.clone(), pay_r));
            Ok(MuxLink {
                reader: Box::new(ret_r),
                writer: Box::new(pay_w),
            })
        }
    }

    /// 读一条 Control 消息（8s 超时）。
    async fn read_control(pay: &mut pipe::Reader) -> ProtoControl {
        let mb = tokio::time::timeout(std::time::Duration::from_secs(8), pay.read_multi_buffer())
            .await
            .expect("control payload within timeout")
            .expect("read ok");
        let mut buf = Vec::new();
        for b in mb.iter() {
            buf.extend_from_slice(b.bytes());
        }
        ProtoControl::decode(buf.as_slice()).expect("control proto decodable")
    }

    /// 搭 portal 侧 e2e 拓扑：ClientWorker ↔ ServerWorker（经两对 pipe）。
    async fn spawn_portal_topology(
        tx: tokio::sync::mpsc::UnboundedSender<(Destination, pipe::Reader)>,
    ) -> Arc<PortalWorker> {
        let (c_read, s_write) = pipe::new(); // server → client
        let (s_read, c_write) = pipe::new(); // client → server
        let client = ClientWorker::new(
            MuxLink {
                reader: Box::new(c_read),
                writer: Box::new(c_write),
            },
            ClientStrategy::default(),
        );
        let worker = PortalWorker::new(client).expect("portal worker");

        let server = std::sync::Arc::new(ServerWorker::new(std::sync::Arc::new(
            CaptureDispatcher {
                tx,
                keepers: std::sync::Arc::new(Mutex::new(Vec::new())),
            },
        )));
        let mut reader = xray_buf::reader::BufferedReader::new(Box::new(s_read));
        let link_writer: std::sync::Arc<tokio::sync::Mutex<Option<Box<dyn IoWriter>>>> =
            std::sync::Arc::new(tokio::sync::Mutex::new(Some(Box::new(s_write))));
        let (ka, idle) = server.spawn_keepalive_and_idle_timeout(link_writer.clone());
        tokio::spawn(async move {
            loop {
                match server.process_frame(&mut reader, &link_writer).await {
                    Ok(true) => continue,
                    _ => break,
                }
            }
            server.close();
            ka.abort();
            idle.abort();
        });
        worker
    }
    #[tokio::test]
    async fn portal_worker_heartbeat_sends_control_on_internal_dest() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let worker = spawn_portal_topology(tx).await;

        // 第一个心跳（≤2s 触发 + 帧传播）：dispatch 内部域 dest + Control(ACTIVE)
        // （Go 为 UDP dest；TCP 规避 mux XUDP 丢内联 data，见 internal_control_destination）
        let (dest, mut pay_r) =
            tokio::time::timeout(std::time::Duration::from_secs(8), rx.recv())
                .await
                .expect("control conn dispatched")
                .expect("channel open");
        assert_eq!(dest.address().as_domain(), Some("reverse"));
        assert_eq!(dest.port().value(), 0);
        assert_eq!(dest.network(), Network::TCP);

        let mb = tokio::time::timeout(std::time::Duration::from_secs(3), pay_r.read_multi_buffer())
            .await
            .expect("control payload within timeout")
            .expect("read ok");
        let mut buf = Vec::new();
        for b in mb.iter() {
            buf.extend_from_slice(b.bytes());
        }
        let ctl = ProtoControl::decode(buf.as_slice()).expect("control proto decodable");
        assert_eq!(ctl.state, ControlState::Active.as_i32());
        assert!((1..=64).contains(&ctl.random.len()));
        assert!(!worker.is_draining());
    }

    #[tokio::test]
    async fn portal_worker_drains_over_threshold_and_disposes() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let worker = spawn_portal_topology(tx).await;

        // 第一个心跳：New 帧（内联 ACTIVE Control）+ 持有 control session 下行读端
        let (_dest, mut pay) =
            tokio::time::timeout(std::time::Duration::from_secs(8), rx.recv())
                .await
                .expect("first control")
                .expect("channel open");
        let first = read_control(&mut pay).await;
        assert_eq!(first.state, ControlState::Active.as_i32());

        // 灌 257 个 user session → total connections > 256
        let user_dest = Destination::new(
            Address::new_domain("internal.target".to_string()),
            Port::new(80),
            Network::TCP,
        );
        for _ in 0..(DRAIN_THRESHOLD + 1) {
            let c = Arc::clone(worker.client());
            let d = user_dest.clone();
            let (r, w) = pipe::new();
            tokio::spawn(async move {
                c.dispatch(&d, MuxLink { reader: Box::new(r), writer: Box::new(w) }).await;
            });
        }

        // 下一心跳（≤4s）：DRAIN Control 经既有 control session 的 Keep 帧送达
        let ctl = read_control(&mut pay).await;
        assert_eq!(ctl.state, ControlState::Drain.as_i32());
        assert!(worker.is_draining(), "worker marked draining");
    }

    #[tokio::test]
    async fn bridge_worker_dispatches_carrier_with_inbound_tag() {
        let mock = std::sync::Arc::new(MockLinkDispatch::default());
        let w = BridgeWorker::new("t.example.com", "bridge-tag", mock.clone())
            .await
            .expect("bridge worker");

        // carrier：domain:0/TCP + inbound tag 注入（Go bridge.go:111-118）
        let calls = mock.calls.lock();
        assert_eq!(calls.len(), 1);
        let (dest, tag) = &calls[0];
        assert_eq!(dest.address().as_domain(), Some("t.example.com"));
        assert_eq!(dest.port().value(), 0);
        assert_eq!(dest.network(), Network::TCP);
        assert_eq!(tag.as_deref(), Some("bridge-tag"));
        drop(calls);

        assert!(w.is_active(), "fresh worker active");
        assert_eq!(w.state(), ControlState::Active);
        assert_eq!(w.connections().await, 0);
    }

    #[tokio::test]
    async fn bridge_worker_internal_conn_state_transitions_and_parse_fail_terminates() {
        let mock = std::sync::Arc::new(MockLinkDispatch::default());
        let w = BridgeWorker::new("t.example.com", "bridge-tag", mock.clone())
            .await
            .expect("bridge worker");

        // 内部域 dispatch → 控制流 pipe（Go bridge.go:208-220）
        let internal = internal_control_destination();
        let mut link = xray_mux::worker::Dispatcher::dispatch(w.as_ref(), internal)
            .await
            .expect("internal dispatch");

        // 写 DRAIN Control 到控制流（portal → bridge 方向 = 返回 link 的 writer）
        let mut ctl = ProtoControl::default();
        ctl.state = ControlState::Drain.as_i32();
        ctl.random = vec![7u8; 8];
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&ctl.encode_to_vec());
        link.writer.write_multi_buffer(mb).await.expect("write control");

        // 状态转换（Go bridge.go:191-193）
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(w.state(), ControlState::Drain);
        assert!(!w.is_active(), "drain state inactive");

        // 写垃圾字节 → proto 解析失败 → SetTimeout(0) → 立即 terminate（worker.Close）
        let mut bad = MultiBuffer::new();
        bad.merge_bytes(&[0xFF, 0xFF, 0xFF, 0xFF]);
        link.writer.write_multi_buffer(bad).await.expect("write garbage");
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(w.is_closed(), "parse failure terminates worker");
    }

    #[tokio::test]
    async fn bridge_worker_non_internal_dispatch_injects_tag() {
        let mock = std::sync::Arc::new(MockLinkDispatch::default());
        let w = BridgeWorker::new("t.example.com", "bridge-tag", mock.clone())
            .await
            .expect("bridge worker");
        mock.calls.lock().clear(); // 清 carrier 记录

        // 非内部域：转真实 dispatcher + tag 注入（Go bridge.go:199-206）
        let ext = Destination::new(
            Address::new_domain("service.local".to_string()),
            Port::new(8080),
            Network::TCP,
        );
        let _ = xray_mux::worker::Dispatcher::dispatch(w.as_ref(), ext)
            .await
            .expect("external dispatch");

        let calls = mock.calls.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0.address().as_domain(), Some("service.local"));
        assert_eq!(calls[0].1.as_deref(), Some("bridge-tag"));
    }
}
