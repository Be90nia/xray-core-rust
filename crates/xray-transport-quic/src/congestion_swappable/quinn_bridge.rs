//! quinn Controller ↔ hysteria CongestionControl 桥接（m9j）。
//!
//! Go（quic-go）允许 `conn.SetCongestionControl` 在握手后热切换算法；quinn 只能在
//! `TransportConfig::congestion_controller_factory` 预装。本模块用一个「可热切换的
//! Controller 包装」弥合：
//!
//! - `QuinnCCFactory` 预装进 TransportConfig，每连接 build 出 `QuinnCCAdapter`；
//! - 初始委托 quinn 内建 CUBIC（对应 Go 未切换前的 quic-go 默认）；
//! - auth 握手后调 [`apply_negotiated`]（对应 Go dialer.go:229-243 / hub.go:75-86 的 congestion
//!   switch），把 BrutalSender / **quinn 内建 BBR** 装上，`QuinnCCAdapter` 即刻切到真实算法（bd
//!   hfb94：BBR 不再用本仓桩版实现）。
//!
//! ## 与 Go 的差异
//!
//! - quinn 无 pacer 集成（Go quic-go 有 SendMode pacing）：Brutal 的速率控制仅通过
//!   `window()`（≈2×bps×rtt）生效，sender 内部 Pacer 不被 quinn 驱动。
//! - quinn 的 `on_ack`/`on_congestion_event` 是聚合事件（批量 acked bytes），而 Go 的
//!   `OnCongestionEventEx` 携带逐包列表：BrutalSender 的 ack/loss 计数按「批」计，
//!   样本积累（MIN_SAMPLE_COUNT=50）略慢，方向正确。

use std::{collections::VecDeque, sync::Arc, time::Instant};

use parking_lot::Mutex;
use quinn_proto::congestion::Controller;

use super::{
    bbr::{Clock as _, DefaultClock, Profile},
    brutal::BrutalSender,
    error::{CongestionError, Result},
    types::{
        AckedPacketInfo, ByteCount, CongestionControl, LostPacketInfo, MonoTime, PacketNumber,
        RttStatsProvider,
    },
    utils::CongestionSetter,
};

/// 把 quinn 事件时间映射到 hysteria MonoTime 域（DefaultClock 的全局基准）。
///
/// `DefaultClock::now()` 返回「此刻」的纳秒；事件时间 `then` 早于此刻，回退
/// `now - then` 的差值。所有时间戳共用 DefaultClock 全局 base，与 sender 内部
/// `clock.now()` 自洽。
fn mono_of(then: Instant) -> MonoTime {
    let clock_now = DefaultClock::new().now();
    #[allow(
        clippy::disallowed_methods,
        reason = "quinn 桥时间戳换算 lag；时钟统一上浮 skeleton::clock 待 bd 39hko"
    )]
    let lag = Instant::now().saturating_duration_since(then);
    clock_now.saturating_sub(lag.as_nanos() as u64)
}

/// 由 quinn `RttEstimator` 快照喂养的 RTT 提供方（对应 Go 侧 quic-go 注入 conn 的
/// rttStats；Go quic-go 在 SetCongestionControl 后由连接内部接线，此处由 adapter
/// 每次 on_ack 时更新共享状态）。
#[derive(Debug, Default)]
struct SharedRtt {
    smoothed_ns: Mutex<u64>,
    min_ns: Mutex<u64>,
}

impl SharedRtt {
    fn update(&self, smoothed: std::time::Duration, min: std::time::Duration) {
        *self.smoothed_ns.lock() = smoothed.as_nanos() as u64;
        *self.min_ns.lock() = min.as_nanos() as u64;
    }
}

impl RttStatsProvider for SharedRtt {
    fn smoothed_rtt(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(*self.smoothed_ns.lock())
    }

    fn min_rtt(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(*self.min_ns.lock())
    }
    // latest：quinn RttEstimator 不暴露 latest（仅 get/min），用 smoothed 近似。
    // ponytail: 若 BBR 需要更精细的 latest 样本，改 quinn fork 暴露字段。
}

/// 未确认包簿：按发送序记录 (pn, bytes)，把 quinn 的聚合 ack/loss 字节冲销成真实
/// pn 列表（pv70：修复前合成 pn=0，BBR sampler 键位错位致 sent_packets 无界增长）。
/// 放在 CCState（共享 slot）而非 adapter 本地——clone_box（path migration）后冲销不错位。
struct SentBook {
    queue: VecDeque<(PacketNumber, ByteCount)>,
    total_bytes: ByteCount,
}

/// 簿字节上限：正常路径簿 ≈ in-flight（BDP 有界）；超限说明冲销失效，丢最老防 OOM。
const MAX_BOOK_BYTES: ByteCount = 64 * 1024 * 1024;

impl SentBook {
    fn new() -> Self {
        Self { queue: VecDeque::new(), total_bytes: 0 }
    }

    fn push(&mut self, pn: PacketNumber, bytes: ByteCount) {
        if bytes == 0 {
            return; // 0 字节条目会让 drain 的整包粒度判断打转
        }
        self.queue.push_back((pn, bytes));
        self.total_bytes += bytes;
        while self.total_bytes > MAX_BOOK_BYTES {
            match self.queue.pop_front() {
                Some((_, sz)) => self.total_bytes -= sz,
                None => {
                    self.total_bytes = 0;
                    break;
                },
            }
        }
    }

    /// 从队首冲销 ≤`bytes` 的条目 → 真实 acked 列表（各条 bytes_acked 之和守恒于
    /// 聚合值）。簿空（migration 交叉等异常）时退化为合成 pn=0 保字节记账。
    fn drain_ack(
        &mut self,
        mut bytes: ByteCount,
        receive_time_ns: MonoTime,
    ) -> Vec<AckedPacketInfo> {
        let mut acked = Vec::new();
        while bytes > 0 {
            match self.queue.pop_front() {
                Some((pn, sz)) => {
                    self.total_bytes -= sz;
                    let take = sz.min(bytes);
                    acked.push(AckedPacketInfo {
                        packet_number: pn,
                        bytes_acked: take,
                        receive_time_ns,
                    });
                    if take < sz {
                        // 整包粒度外的残量留队首（罕见：双 path 事件交叉）。
                        self.queue.push_front((pn, sz - take));
                        self.total_bytes += sz - take;
                        bytes = 0;
                    } else {
                        bytes -= sz;
                    }
                },
                None => {
                    acked.push(AckedPacketInfo {
                        packet_number: 0,
                        bytes_acked: bytes,
                        receive_time_ns,
                    });
                    bytes = 0;
                },
            }
        }
        acked
    }

    /// 从队尾冲销 ≤`bytes` 的条目 → 真实 lost 列表。与 [`SentBook::drain_ack`]
    /// 分吃两端、不重叠；sampler 端 sent_packets 依总字节守恒全清（聚合近似语义）。
    fn drain_lost(&mut self, mut bytes: ByteCount) -> Vec<LostPacketInfo> {
        let mut lost = Vec::new();
        while bytes > 0 {
            match self.queue.pop_back() {
                Some((pn, sz)) => {
                    self.total_bytes -= sz;
                    let take = sz.min(bytes);
                    lost.push(LostPacketInfo { packet_number: pn, bytes_lost: take });
                    if take < sz {
                        self.queue.push_back((pn, sz - take));
                        self.total_bytes += sz - take;
                        bytes = 0;
                    } else {
                        bytes -= sz;
                    }
                },
                None => {
                    lost.push(LostPacketInfo { packet_number: 0, bytes_lost: bytes });
                    bytes = 0;
                },
            }
        }
        lost
    }

    #[allow(dead_code)] // 队列空检查为对称 API，测试面保留
    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

/// fallback 通道要装的算法（bd hfb94：`apply_bbr` 在 factory build **之前**
/// （splithttp H3）或**之后**（hysteria auth 协商）都可能被调用，故须记住请求，
/// build 时按此构造而不是无条件装 CUBIC）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FallbackKind {
    /// factory 尚未 build（fallback 仍是占位 Controller）。
    Unbuilt,
    /// quinn 内建 CUBIC（quinn 缺省 = 未切换前的算法）。
    Cubic,
    /// quinn 内建 BBR（真实 cwnd/pacing 更新）。
    Bbr,
}

/// 每连接 CC 状态：auth 前 fallback（quinn CUBIC/BBR），auth 后 active（hysteria 算法）。
struct CCState {
    active: Option<Box<dyn CongestionControl>>,
    fallback: Box<dyn Controller>,
    /// fallback 通道当前/待装的算法（见 [`FallbackKind`]）。
    fallback_kind: FallbackKind,
    /// 最近已知 MTU（factory build / `on_mtu_update` 更新；`apply_bbr` 就地重建用）。
    mtu: u16,
    /// 已确认的最大包号（供 fallback 的 `on_end_acks` 判定轮次边界）。
    max_acked_pn: Option<u64>,
    /// 近似 in-flight 字节（on_sent 累加 / ack·loss 扣减），供 hysteria 事件用。
    in_flight: ByteCount,
    /// 未确认包簿（pv70）：真实 pn 冲销聚合 ack/loss 字节。
    book: SentBook,
}

/// CC 槽位：跨 `QuinnCCAdapter` clone 共享（quinn clone_box 走 path migration 时保持
/// 已协商算法）。同时是 [`CongestionSetter`] 的第一个生产实现。
pub struct HysteriaCCSlot {
    state: Mutex<CCState>,
    rtt: Arc<SharedRtt>,
}

impl HysteriaCCSlot {
    /// 构造（fallback 初始化延迟到 factory build，见 [`install_swappable_cc`]）。
    #[must_use]
    pub fn new() -> Self {
        Self { state: Mutex::new(CCState::empty()), rtt: Arc::new(SharedRtt::default()) }
    }

    /// 当前窗口（active 优先；测试/调试观察用）。
    #[must_use]
    pub fn current_window(&self) -> u64 {
        let st = self.state.lock();
        match &st.active {
            Some(cc) => cc.congestion_window().max(0) as u64,
            None => st.fallback.window(),
        }
    }

    /// 是否已装载 active 算法（auth 协商/预载后为 true；跨 crate 消费方探针）。
    #[must_use]
    pub fn has_active(&self) -> bool {
        self.state.lock().active.is_some()
    }

    /// 是否已请求 quinn 内建 BBR（bd hfb94：BBR 走 fallback 通道以拿全保真 quinn
    /// 事件，故 [`HysteriaCCSlot::has_active`] 为 false——消费方探针用本方法）。
    #[must_use]
    pub fn is_bbr(&self) -> bool {
        self.state.lock().fallback_kind == FallbackKind::Bbr
    }
}

impl Default for HysteriaCCSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for HysteriaCCSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HysteriaCCSlot")
            .field("has_active", &self.state.lock().active.is_some())
            .finish_non_exhaustive()
    }
}

impl CCState {
    fn empty() -> Self {
        Self {
            active: None,
            // build 前占位；factory build 时替换为真 CUBIC/BBR。empty 期间 window() 给
            // 固定值，真实连接必然先经 factory build，不会出现在数据路径上。
            fallback: Box::new(PlaceholderController),
            fallback_kind: FallbackKind::Unbuilt,
            // 1200 = quinn BASE_DATAGRAM_SIZE（未暴露为 pub const，与
            // `types::INITIAL_PACKET_SIZE` 同值）。
            mtu: 1200,
            max_acked_pn: None,
            in_flight: 0,
            book: SentBook::new(),
        }
    }
}

/// 占位 Controller（factory build 前的空槽）。
struct PlaceholderController;
impl Controller for PlaceholderController {
    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent: bool,
        _lost: u64,
    ) {
    }

    fn on_mtu_update(&mut self, _new_mtu: u16) {}

    fn window(&self) -> u64 {
        1452
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(PlaceholderController)
    }

    fn initial_window(&self) -> u64 {
        1452
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

impl CongestionSetter for HysteriaCCSlot {
    fn set_congestion_control(&self, cc: Box<dyn CongestionControl>) {
        self.state.lock().active = Some(cc);
    }
}

/// quinn ControllerFactory：为每条连接构造 [`QuinnCCAdapter`]，fallback 换成真正的
/// quinn 控制器（按 [`FallbackKind`]：CUBIC 缺省 / 预装 BBR）。
struct QuinnCCFactory {
    slot: Arc<HysteriaCCSlot>,
}

/// 构造 quinn 内建 BBR（bd hfb94：真实 cwnd/min_rtt/pacing 更新）。
fn make_bbr(mtu: u16) -> Box<dyn Controller> {
    Box::new(quinn_proto::congestion::Bbr::new(
        Arc::new(quinn_proto::congestion::BbrConfig::default()),
        mtu,
    ))
}

impl quinn_proto::congestion::ControllerFactory for QuinnCCFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        let mut st = self.slot.state.lock();
        st.mtu = current_mtu;
        st.fallback = match st.fallback_kind {
            FallbackKind::Bbr => make_bbr(current_mtu),
            FallbackKind::Unbuilt | FallbackKind::Cubic => {
                st.fallback_kind = FallbackKind::Cubic;
                Box::new(quinn_proto::congestion::Cubic::new(
                    Arc::new(quinn_proto::congestion::CubicConfig::default()),
                    now,
                    current_mtu,
                ))
            },
        };
        drop(st);
        Box::new(QuinnCCAdapter { slot: Arc::clone(&self.slot) })
    }
}

/// quinn Controller 实现：事件委托给 active（hysteria）或 fallback（quinn 内建）。
struct QuinnCCAdapter {
    slot: Arc<HysteriaCCSlot>,
}

impl Controller for QuinnCCAdapter {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        let mut st = self.slot.state.lock();
        st.in_flight += bytes as ByteCount;
        st.book.push(last_packet_number as i64, bytes as ByteCount);
        let in_flight = st.in_flight;
        match &mut st.active {
            Some(cc) => {
                cc.on_packet_sent(
                    mono_of(now),
                    in_flight,
                    last_packet_number as i64,
                    bytes as i64,
                    true,
                );
            },
            None => st.fallback.on_sent(now, bytes, last_packet_number),
        }
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &quinn_proto::RttEstimator,
    ) {
        // 喂 RTT（Brutal 窗口 = 2×bps×rtt 依赖它）。
        self.slot.rtt.update(rtt.get(), rtt.min());
        let mut st = self.slot.state.lock();
        let prior = st.in_flight;
        st.in_flight = (st.in_flight - bytes as ByteCount).max(0);
        let t = mono_of(now);
        // 聚合 ack 字节 → 真实 pn 列表（pv70）；fallback 期也冲销，保持簿对齐。
        let acked = st.book.drain_ack(bytes as ByteCount, t);
        // fallback 的 `on_end_acks` 需要「本批最大已确认包号」（quinn BBR 据此判轮次）。
        for p in &acked {
            let pn = u64::try_from(p.packet_number).unwrap_or(0);
            let newer = match st.max_acked_pn {
                Some(prev) => pn > prev,
                None => true,
            };
            if newer {
                st.max_acked_pn = Some(pn);
            }
        }
        match &mut st.active {
            Some(cc) => cc.on_congestion_event_ex(prior, t, &acked, &[]),
            None => st.fallback.on_ack(now, sent, bytes, app_limited, rtt),
        }
    }

    /// bd hfb94：quinn BBR 的 cwnd / pacing_rate 只在 `on_end_acks` 里推进
    /// （`calculate_cwnd`），而 active（hysteria 算法）没有对应钩子 ⇒ 缺这条转发时
    /// 即使装的是真 BBR，窗口也会钉在初始值（与装桩版无区别）。
    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        let mut st = self.slot.state.lock();
        let largest = match (st.max_acked_pn, largest_packet_num_acked) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        if st.active.is_none() {
            st.fallback.on_end_acks(now, in_flight, app_limited, largest);
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        let mut st = self.slot.state.lock();
        st.in_flight = (st.in_flight - lost_bytes as ByteCount).max(0);
        let in_flight = st.in_flight;
        let t = mono_of(now);
        // 聚合 lost 字节 → 真实 pn 列表（pv70）。
        let lost = st.book.drain_lost(lost_bytes as ByteCount);
        match &mut st.active {
            Some(cc) => cc.on_congestion_event_ex(in_flight, t, &[], &lost),
            None => {
                st.fallback.on_congestion_event(now, sent, is_persistent_congestion, lost_bytes)
            },
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        let mut st = self.slot.state.lock();
        // bd 9wipb：MTU 可能**变小**（PMTU 黑洞探测后的正常回调，下限 1200）——
        // 记下当前值供 apply_bbr 就地重建；两侧算法都必须接受缩小（不得 panic）。
        st.mtu = new_mtu;
        match &mut st.active {
            Some(cc) => cc.set_max_datagram_size(i64::from(new_mtu)),
            None => st.fallback.on_mtu_update(new_mtu),
        }
    }

    fn window(&self) -> u64 {
        let st = self.slot.state.lock();
        match &st.active {
            Some(cc) => cc.congestion_window().max(0) as u64,
            None => st.fallback.window(),
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        // 共享同一 slot：path migration 后仍保持已协商的 CC（Brutal 语义不丢）。
        Box::new(QuinnCCAdapter { slot: Arc::clone(&self.slot) })
    }

    fn initial_window(&self) -> u64 {
        let st = self.slot.state.lock();
        match &st.active {
            Some(cc) => cc.congestion_window().max(0) as u64,
            None => st.fallback.initial_window(),
        }
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

/// RttStatsProvider 的共享句柄（供 Arc 化前的 sender 注入；Go 侧由 quic-go 在
/// SetCongestionControl 内部接线，quinn 无此钩子故构造期注入）。
struct SharedRttHandle(Arc<SharedRtt>);
impl RttStatsProvider for SharedRttHandle {
    fn smoothed_rtt(&self) -> std::time::Duration {
        self.0.smoothed_rtt()
    }

    fn min_rtt(&self) -> std::time::Duration {
        self.0.min_rtt()
    }
}

/// 应用 BBR（对应 Go `UseBBR`）。
///
/// bd hfb94：装 **quinn 内建 BBR**，不再装本仓 hysteria 侧 `BbrSender` 桩——后者
/// `on_congestion_event_ex` 只更新 bytes_in_flight/sampler，从不更新 cwnd/min_rtt/
/// pacing_rate，`congestion_window()` 恒为 32×MTU（169ms RTT 下 ≈1.8Mbps，比 Go 差
/// 一个数量级）。走 fallback 通道是为了拿 quinn 的**全保真**事件
/// （`on_sent` / `on_ack(rtt, app_limited)` / `on_end_acks` / `on_congestion_event` /
/// `on_mtu_update`）；hysteria 的 `CongestionControl` trait 只有聚合后的 ack/loss 列表，
/// 无法喂养真 BBR。
///
/// 与 Go 的差异：quinn BBR 无 `bbrProfile` 三档 gain（conservative/standard/
/// aggressive），`profile` 仅由调用方做配置合法性校验（`Profile::parse`），算法语义
/// 统一为 standard——与 `xray-transport::finalmask::xdns::doh3` 同口径。
pub fn apply_bbr(slot: &HysteriaCCSlot, _profile: Profile) {
    let mut st = slot.state.lock();
    // 真 BBR 走 fallback：清掉可能存在的 hysteria active（否则 active 优先，仍走桩）。
    st.active = None;
    let built = st.fallback_kind != FallbackKind::Unbuilt;
    st.fallback_kind = FallbackKind::Bbr;
    // factory build 之后调用（hysteria auth 后协商）需就地重建；build 之前只登记。
    if built {
        st.fallback = make_bbr(st.mtu);
    }
}

/// 应用 Brutal（对应 Go `UseBrutal(conn, tx, disableLossCompensation)`）。
pub fn apply_brutal(slot: &HysteriaCCSlot, tx_bps: u64, disable_loss_compensation: bool) {
    let mut sender = BrutalSender::new(tx_bps, disable_loss_compensation);
    sender.set_rtt_stats_provider(Box::new(SharedRttHandle(Arc::clone(&slot.rtt))));
    slot.set_congestion_control(Box::new(sender));
}

/// 按协商结果应用 CC（对应 Go dialer.go:229-243 / hub.go:75-86 的 switch）。
///
/// - `"reno"`：不动（保持 quinn 默认 CUBIC）；
/// - `"bbr"`：BBR；
/// - `""`/`"brutal"`：双边带宽非 0 才 Brutal（`min(brutal_up, down)`），否则 BBR；
/// - `"force-brutal"`：无条件 Brutal（`brutal_up`）。
///
/// `down` 是对端 `Hysteria-CC-RX` 头（client 取响应头，server 取请求头）。
/// 未知值返回 Err（Go panic；Rust 生产路径降级为 warn 更安全）。
pub fn apply_negotiated(
    slot: &HysteriaCCSlot,
    congestion: &str,
    bbr_profile: &str,
    brutal_up: u64,
    down: u64,
    disable_loss_compensation: bool,
) -> Result<()> {
    match congestion.to_ascii_lowercase().as_str() {
        "reno" => Ok(()),
        "bbr" => {
            apply_bbr(slot, Profile::parse(bbr_profile)?);
            Ok(())
        },
        "" | "brutal" => {
            if brutal_up == 0 || down == 0 {
                apply_bbr(slot, Profile::parse(bbr_profile)?);
            } else {
                apply_brutal(slot, brutal_up.min(down), disable_loss_compensation);
            }
            Ok(())
        },
        "force-brutal" => {
            apply_brutal(slot, brutal_up, disable_loss_compensation);
            Ok(())
        },
        other => Err(CongestionError::UnsupportedCongestionType(other.to_string())),
    }
}

/// 给 TransportConfig 装可热切换 CC 工厂；返回槽位句柄供 auth 后协商用。
pub fn install_swappable_cc(t: &mut quinn::TransportConfig) -> Arc<HysteriaCCSlot> {
    let slot = Arc::new(HysteriaCCSlot::new());
    let factory: Arc<QuinnCCFactory> = Arc::new(QuinnCCFactory { slot: Arc::clone(&slot) });
    t.congestion_controller_factory(factory);
    slot
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_swaps_window_to_brutal_semantics() {
        use quinn_proto::congestion::Controller as _;

        let slot = HysteriaCCSlot::new();
        // 未 build factory、未切换：占位窗口。
        let adapter = QuinnCCAdapter { slot: Arc::new(slot) };
        assert_eq!(adapter.window(), 1452);

        // 切到 Brutal(1 MB/s)：无 RTT 样本时窗口回落 10240（brutal.rs 语义）。
        apply_brutal(&adapter.slot, 1_000_000, false);
        assert_eq!(adapter.window(), 10_240);

        // RTT 喂样后窗口 = 2×bps×rtt（100ms RTT，ack_rate=1 → 200_000 字节）。
        adapter
            .slot
            .rtt
            .update(std::time::Duration::from_millis(100), std::time::Duration::from_millis(100));
        assert_eq!(adapter.window(), 200_000);
    }

    /// s8ti 契约：亚毫秒 RTT 钳窗口语义——回环/床测必须 MB/s 级带宽。
    ///
    /// Brutal 窗口 = 2×bps×rtt（Go quic-go 同数学）：10 MB/s × 1ms 回环 RTT
    /// → 20_000 B ≫ 1 MTU（1200B），数据面正常；若带宽过小（KB/s 级）×亚毫秒
    /// RTT，窗口数学值低于 1 MTU 被钳底 → quinn 发送停滞。TUIC 经共享槽接入
    /// Brutal 时配置带宽必须遵守此量级（同 hysteria_transport.rs 床测注释）。
    #[test]
    fn brutal_window_with_mbps_bandwidth_at_submillisecond_rtt_exceeds_mtu() {
        let slot = HysteriaCCSlot::new();
        assert!(!slot.has_active(), "fresh slot must be fallback-only");
        apply_brutal(&slot, 10_000_000, false); // 10 MB/s
        assert!(slot.has_active());
        slot.rtt.update(std::time::Duration::from_millis(1), std::time::Duration::from_millis(1));
        // 数学：2 × 10_000_000 bps × 0.001 s = 20_000 字节 ≫ 1 MTU。
        assert_eq!(slot.current_window(), 20_000);
    }

    /// 模拟 quinn 建连：factory build 一次（fallback 由占位换成真控制器）。
    fn build_factory(slot: &Arc<HysteriaCCSlot>) -> Box<dyn Controller> {
        let factory: Arc<QuinnCCFactory> = Arc::new(QuinnCCFactory { slot: Arc::clone(slot) });
        #[allow(clippy::disallowed_methods, reason = "测试：CC factory build 时刻入参")]
        quinn_proto::congestion::ControllerFactory::build(factory, Instant::now(), 1200)
    }

    #[test]
    fn apply_negotiated_matches_go_switch() {
        // bbr：装 quinn 内建 BBR（走 fallback 通道，bd hfb94）。
        let slot = HysteriaCCSlot::new();
        apply_negotiated(&slot, "bbr", "standard", 0, 0, false).unwrap();
        assert!(slot.is_bbr());
        assert!(!slot.has_active(), "BBR 不再走 hysteria active 通道");

        // reno：不切换。
        let slot = HysteriaCCSlot::new();
        apply_negotiated(&slot, "reno", "", 999, 999, false).unwrap();
        assert!(slot.state.lock().active.is_none());

        // 行为断言（Box<dyn CongestionControl> 不可 downcast）：
        // - Brutal 无 RTT → 窗口 floor 10240；喂 RTT 后 = 2×bps×rtt（可反推 bps）。
        // - BBR 初始 → 窗口 32×1200 = 38400。
        const RTT10S: std::time::Duration = std::time::Duration::from_secs(10);

        // ""+双边非 0 → Brutal(min(500,800)=500)：10s RTT → 2×500×10 = 10000。
        let slot = HysteriaCCSlot::new();
        apply_negotiated(&slot, "", "standard", 500, 800, false).unwrap();
        slot.rtt.update(RTT10S, RTT10S);
        assert_eq!(slot.current_window(), 10_000, "min(up=500, down=800) = 500");

        // up=0 → BBR（quinn 内建；build 后初始窗口 = BbrConfig 缺省 200×1200B）。
        let slot = Arc::new(HysteriaCCSlot::new());
        apply_negotiated(&slot, "brutal", "standard", 0, 800, false).unwrap();
        assert!(slot.is_bbr(), "up=0 must fall back to BBR");
        build_factory(&slot);
        assert_eq!(slot.current_window(), 240_000, "quinn BBR 缺省初始窗口");

        // force-brutal：直接 up=1234，不看 down：10s RTT → 2×1234×10 = 24680。
        let slot = HysteriaCCSlot::new();
        apply_negotiated(&slot, "force-brutal", "", 1234, 0, false).unwrap();
        slot.rtt.update(RTT10S, RTT10S);
        assert_eq!(slot.current_window(), 24_680);

        // 未知值 → Err（Go panic 的安全化）。
        assert!(apply_negotiated(&HysteriaCCSlot::new(), "vegas", "", 1, 1, false).is_err());
        // 非法 profile → Err。
        assert!(apply_negotiated(&HysteriaCCSlot::new(), "bbr", "turbo", 1, 1, false).is_err());
    }

    #[test]
    fn adapter_delegates_to_fallback_until_swap() {
        use quinn_proto::congestion::Controller as _;

        let slot = Arc::new(HysteriaCCSlot::new());
        // 模拟 factory build：fallback 变为真 CUBIC。
        let factory: Arc<QuinnCCFactory> = Arc::new(QuinnCCFactory { slot: Arc::clone(&slot) });
        #[allow(clippy::disallowed_methods, reason = "测试：CC factory build 时刻入参")]
        quinn_proto::congestion::ControllerFactory::build(factory, Instant::now(), 1200);
        let adapter = QuinnCCAdapter { slot };
        // CUBIC 初始窗口 = 14720.clamp(2*1200, 10*1200) = 12000（quinn 语义）。
        assert_eq!(adapter.window(), 12_000);

        // 切 Brutal 后窗口立即变为 Brutal 语义。
        apply_brutal(&adapter.slot, 100_000, false);
        assert_eq!(adapter.window(), 10_240);
    }

    #[test]
    fn adapter_events_reach_active_sender() {
        use quinn_proto::congestion::Controller as _;

        let slot = Arc::new(HysteriaCCSlot::new());
        let factory: Arc<QuinnCCFactory> = Arc::new(QuinnCCFactory { slot: Arc::clone(&slot) });
        #[allow(clippy::disallowed_methods, reason = "测试：CC factory build 时刻入参")]
        quinn_proto::congestion::ControllerFactory::build(factory, Instant::now(), 1200);
        let mut adapter = QuinnCCAdapter { slot: Arc::clone(&slot) };
        apply_brutal(&slot, 1_000_000, false);

        // 事件不 panic、swap 后窗口仍为 Brutal 语义。
        #[allow(clippy::disallowed_methods, reason = "测试：CC 事件时间戳构造")]
        let now = Instant::now();
        adapter.on_sent(now, 1200, 1);
        adapter.on_congestion_event(now, now, false, 600);
        // 簿随事件冲销：1200 入簿，600 partial-loss 后残量留队尾。
        {
            let st = slot.state.lock();
            assert_eq!(st.book.queue.len(), 1);
            assert_eq!(st.book.total_bytes, 600);
        }
        adapter.on_mtu_update(1400);
        assert_eq!(adapter.window(), 10_240);

        // clone_box 共享 slot：切换对 clone 生效（path migration 语义）。
        let cloned = adapter.clone_box();
        apply_brutal(&slot, 2_000_000, false);
        // 2MB/s 无 RTT → 仍是 10240 floor；喂 RTT 后 = 2×2MB/s×50ms。
        slot.rtt.update(std::time::Duration::from_millis(50), std::time::Duration::from_millis(50));
        assert_eq!(cloned.window(), 200_000);
    }

    #[test]
    fn bbr_loss_events_drain_sent_book() {
        use quinn_proto::congestion::Controller as _;

        // pv70 回归：修复前合成 pn=0 永不命中 sampler 键，sent_packets 恒增长；
        // 修复后聚合 lost 字节按真实 pn 冲销，全丢后簿必须清空。
        let slot = Arc::new(HysteriaCCSlot::new());
        apply_bbr(&slot, Profile::Standard);
        let mut adapter = QuinnCCAdapter { slot: Arc::clone(&slot) };
        #[allow(clippy::disallowed_methods, reason = "测试：CC 事件时间戳构造")]
        let now = Instant::now();

        adapter.on_sent(now, 1200, 1);
        adapter.on_sent(now, 1200, 2);
        adapter.on_sent(now, 1200, 3);
        assert_eq!(slot.state.lock().book.queue.len(), 3);

        // 丢 1 包（1200B）→ 簿剩 2 条；其余 2 包（2400B）也丢 → 簿空。
        adapter.on_congestion_event(now, now, false, 1200);
        assert_eq!(slot.state.lock().book.queue.len(), 2);
        adapter.on_congestion_event(now, now, false, 2400);

        let st = slot.state.lock();
        assert!(st.book.is_empty(), "sent book must drain to empty (was unbounded)");
        assert_eq!(st.in_flight, 0);
    }

    #[test]
    fn sent_book_shared_across_clone_box() {
        use quinn_proto::congestion::Controller as _;

        // 簿在 CCState（共享 slot）：migration clone 后另一 adapter 事件照常冲销。
        let slot = Arc::new(HysteriaCCSlot::new());
        apply_bbr(&slot, Profile::Standard);
        let mut a = QuinnCCAdapter { slot: Arc::clone(&slot) };
        let mut b = QuinnCCAdapter { slot: Arc::clone(&slot) };
        #[allow(clippy::disallowed_methods, reason = "测试：CC 事件时间戳构造")]
        let now = Instant::now();

        a.on_sent(now, 1200, 7);
        b.on_congestion_event(now, now, false, 1200);
        assert!(slot.state.lock().book.is_empty(), "clone must see the same book");
    }

    #[test]
    fn sent_book_synthesizes_pn0_when_empty_and_caps_bytes() {
        let mut book = SentBook::new();
        // 簿空：退化为合成 pn=0 单条，字节守恒（旧行为兜底）。
        let acked = book.drain_ack(2400, 42);
        assert_eq!(acked.len(), 1);
        assert_eq!(acked[0].packet_number, 0);
        assert_eq!(acked[0].bytes_acked, 2400);

        // 超上限丢最老：total_bytes 封顶，防 OOM。
        for pn in 0..100_000u64 {
            book.push(pn as i64, 1200);
        }
        assert!(book.total_bytes <= MAX_BOOK_BYTES);
        assert!(book.queue.len() < 100_000);
    }

    #[test]
    fn sent_book_ack_bytes_conserved_in_pn_list() {
        let mut book = SentBook::new();
        book.push(1, 1200);
        book.push(2, 800);
        // 聚合 2000B → 两条真实 pn，各带自身字节，总和守恒。
        let acked = book.drain_ack(2000, 7);
        assert_eq!(acked.len(), 2);
        assert_eq!(acked[0].packet_number, 1);
        assert_eq!(acked[0].bytes_acked, 1200);
        assert_eq!(acked[1].packet_number, 2);
        assert_eq!(acked[1].bytes_acked, 800);
        assert!(book.is_empty());

        // loss 同理：从队尾冲销，与 ack 分吃两端不重叠。
        book.push(3, 1200);
        book.push(4, 1200);
        let lost = book.drain_lost(1200);
        assert_eq!(lost.len(), 1);
        assert_eq!(lost[0].packet_number, 4);
        assert_eq!(book.total_bytes, 1200);
    }

    #[test]
    fn install_swappable_cc_returns_live_slot() {
        let mut t = quinn::TransportConfig::default();
        let slot = install_swappable_cc(&mut t);
        apply_brutal(&slot, 42, false);
        assert!(slot.state.lock().active.is_some());
    }

    /// bd hfb94 契约 1：缺省装配（`install_swappable_cc` + `apply_bbr`）装的是
    /// **quinn 内建 BBR**，不是桩版——桩版窗口恒 32×MTU=38400、quinn CUBIC 12000，
    /// quinn BBR 缺省 200×1200=240000，三者可区分。
    #[test]
    fn default_assembly_installs_real_quinn_bbr() {
        // 装配顺序与 splithttp/h3_client.rs 一致：先装槽位，再 apply_bbr（build 之前）。
        let mut t = quinn::TransportConfig::default();
        let slot = install_swappable_cc(&mut t);
        apply_bbr(&slot, Profile::Standard);
        let adapter = build_factory(&slot);

        assert!(slot.is_bbr());
        assert_eq!(adapter.window(), 240_000, "quinn BBR 初始窗口（桩版会是 38400）");
        assert_eq!(adapter.initial_window(), 240_000);
    }

    /// bd hfb94 契约 2：cwnd 随 ACK 增长。
    ///
    /// 桩版 `on_congestion_event_ex` 只更新 bytes_in_flight/sampler，从不更新 cwnd，
    /// `congestion_window()` 恒为 32×MTU ⇒ 169ms RTT 下吞吐钉死 ~1.8Mbps。本测试经
    /// `QuinnCCAdapter` 喂 sent/ack/end_acks 并断言窗口**严格增长**，同时钉住
    /// `on_end_acks` 转发（quinn BBR 只在那个钩子里算 cwnd/pacing_rate）。
    #[test]
    fn bbr_cwnd_grows_with_acked_bytes() {
        let mut t = quinn::TransportConfig::default();
        let slot = install_swappable_cc(&mut t);
        apply_bbr(&slot, Profile::Standard);
        let mut adapter = build_factory(&slot);
        let initial = adapter.window();

        // SAFETY: quinn 未提供 `RttEstimator` 的公开构造器。该类型的全部字段是
        // Duration / Option<Duration>（整数字段），全零位型合法：latest=0s、
        // smoothed=None（tag 0）、min=0s。本测试只用它跑 cwnd 增长数学。
        let rtt: quinn_proto::RttEstimator = unsafe { std::mem::zeroed() };
        #[allow(clippy::disallowed_methods, reason = "测试：CC 事件时间戳构造")]
        let sent_at = Instant::now();

        // 第 1 轮：BBR 首轮必进 ProbeRtt（尚无 min_rtt 样本；该模式下不涨窗口），
        // 200ms 后的一次 round start 会回 Startup——用可控事件时间直接跳过。
        adapter.on_end_acks(sent_at, 0, false, None);
        let later = sent_at + std::time::Duration::from_millis(300);
        let acked_at = later + std::time::Duration::from_millis(10);

        for pn in 1..=64u64 {
            adapter.on_sent(later, 1200, pn);
        }
        for _ in 1..=64u64 {
            adapter.on_ack(acked_at, later, 1200, false, &rtt);
        }
        adapter.on_end_acks(acked_at, 0, false, Some(64));

        let grown = adapter.window();
        assert!(grown > initial, "cwnd 必须随 ACK 增长：initial={initial} grown={grown}");
    }

    /// bd hfb94 契约 3：factory 已 build 后才 `apply_bbr`（hysteria auth 后协商路径）
    /// 必须就地换成真 BBR，而不是留在 quinn 缺省 CUBIC。
    #[test]
    fn apply_bbr_after_build_replaces_cubic() {
        let mut t = quinn::TransportConfig::default();
        let slot = install_swappable_cc(&mut t);
        let adapter = build_factory(&slot);
        assert_eq!(adapter.window(), 12_000, "quinn CUBIC 初始窗口");

        apply_bbr(&slot, Profile::Standard);
        assert!(slot.is_bbr());
        assert_eq!(adapter.window(), 240_000, "auth 后协商 BBR 必须换成真 BBR");
    }

    /// bd 9wipb 契约：PMTU 黑洞探测成功后 quinn 会用**更小** MTU 回调（正常事件）。
    /// adapter 两条通道（fallback=BBR / active=Brutal）都必须接受缩小且不 panic——
    /// 旧桩版在这里 `assert!(size >= max_datagram_size)` panic，落在 quinn 连接驱动
    /// task 内 ⇒ 该 endpoint 全部连接静默失效。
    #[test]
    fn mtu_decrease_never_panics() {
        let mut t = quinn::TransportConfig::default();
        let slot = install_swappable_cc(&mut t);
        apply_bbr(&slot, Profile::Standard);
        let mut adapter = build_factory(&slot);
        adapter.on_mtu_update(1500);
        adapter.on_mtu_update(1200); // PMTU 黑洞下限
        assert!(adapter.window() >= 4 * 1200, "缩 MTU 后窗口不得低于新 min");

        // active 通道（Brutal）同样必须接受缩小。
        let slot2 = Arc::new(HysteriaCCSlot::new());
        apply_brutal(&slot2, 1_000_000, false);
        let mut adapter2 = QuinnCCAdapter { slot: Arc::clone(&slot2) };
        adapter2.on_mtu_update(1500);
        adapter2.on_mtu_update(1200);
        assert_eq!(slot2.state.lock().mtu, 1200);
    }
}
