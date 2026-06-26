//! BbrSender —— BBR 拥塞控制主算法（对应 Go `congestion/bbr/bbr_sender.go`）。
//!
//! 完整翻译 ProfileConfig + struct + CongestionControl trait 接口，
//! 状态机内部简化（标记 TODO：完整 STARTUP/DRAIN/PROBE_BW/PROBE_RTT 状态转换
//! 等真正需要运行 hysteria 时补全；quinn 集成可改用 quinn-proto 自带 BBR）。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::super::pacer::Pacer;
use super::super::types::{
    AckedPacketInfo, ByteCount, CongestionControl, LostPacketInfo, MonoTime, PacketNumber,
    RttStatsProvider, INITIAL_PACKET_SIZE,
};
use super::bandwidth::{Bandwidth, INF_BANDWIDTH};
use super::bandwidth_sampler::{BandwidthSampler, INF_RTT};
use super::clock::Clock;
use super::Profile;

// ===== 算法常量（对应 Go `const` 块） =====

pub const MIN_BPS: u64 = 65_536; // 64 KB/s
pub const INITIAL_CONGESTION_WINDOW_PACKETS: ByteCount = 32;
pub const MIN_CONGESTION_WINDOW_PACKETS: ByteCount = 4;
pub const DEFAULT_HIGH_GAIN: f64 = 2.885; // 2/ln(2)
pub const DERIVED_HIGH_CWND_GAIN: f64 = 2.0;
pub const BANDWIDTH_WINDOW_SIZE: u64 = 10; // gainCycleLength + 2
pub const MIN_RTT_EXPIRY: Duration = Duration::from_secs(10);
pub const PROBE_RTT_TIME: Duration = Duration::from_millis(200);
pub const STARTUP_GROWTH_TARGET: f64 = 1.25;
pub const ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP: i64 = 3;
pub const DEFAULT_STARTUP_FULL_LOSS_COUNT: u64 = 8;
pub const QUIC_BBR2_DEFAULT_LOSS_THRESHOLD: f64 = 0.02;

/// BBR 模式（对应 Go `bbrMode`：Startup/Drain/ProbeBw/ProbeRtt）。
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum BbrMode {
    #[default]
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
}

/// 恢复状态（对应 Go `bbrRecoveryState`）。
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum BbrRecoveryState {
    #[default]
    NotInRecovery,
    Conservation,
    Growth,
}

/// Profile 配置（对应 Go `profileConfig`）。
#[derive(Copy, Clone, Debug)]
pub struct ProfileConfig {
    pub high_gain: f64,
    pub high_cwnd_gain: f64,
    pub congestion_window_gain_constant: f64,
    pub num_startup_rtts: i64,
    pub drain_to_target: bool,
    pub detect_overshooting: bool,
    pub bytes_lost_multiplier: u8,
    pub enable_ack_aggregation_startup: bool,
    pub expire_ack_aggregation_startup: bool,
    pub enable_overestimate_avoidance: bool,
    pub reduce_extra_acked_on_bandwidth_increase: bool,
}

/// 取 Profile 对应的配置（对应 Go `configForProfile`）。
#[must_use]
pub fn config_for_profile(profile: Profile) -> ProfileConfig {
    match profile {
        Profile::Conservative => ProfileConfig {
            high_gain: 2.25,
            high_cwnd_gain: 1.75,
            congestion_window_gain_constant: 1.75,
            num_startup_rtts: 2,
            drain_to_target: true,
            detect_overshooting: true,
            bytes_lost_multiplier: 1,
            enable_ack_aggregation_startup: false,
            expire_ack_aggregation_startup: false,
            enable_overestimate_avoidance: true,
            reduce_extra_acked_on_bandwidth_increase: true,
        },
        Profile::Aggressive => ProfileConfig {
            high_gain: 3.0,
            high_cwnd_gain: 2.25,
            congestion_window_gain_constant: 2.5,
            num_startup_rtts: 4,
            drain_to_target: false,
            detect_overshooting: false,
            bytes_lost_multiplier: 2,
            enable_ack_aggregation_startup: true,
            expire_ack_aggregation_startup: true,
            enable_overestimate_avoidance: false,
            reduce_extra_acked_on_bandwidth_increase: false,
        },
        Profile::Standard => ProfileConfig {
            high_gain: DEFAULT_HIGH_GAIN,
            high_cwnd_gain: DERIVED_HIGH_CWND_GAIN,
            congestion_window_gain_constant: 2.0,
            num_startup_rtts: ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP,
            drain_to_target: false,
            detect_overshooting: false,
            bytes_lost_multiplier: 2,
            enable_ack_aggregation_startup: false,
            expire_ack_aggregation_startup: false,
            enable_overestimate_avoidance: false,
            reduce_extra_acked_on_bandwidth_increase: false,
        },
    }
}

/// min congestion window（对应 Go `minCongestionWindowForMaxDatagramSize`）。
fn min_congestion_window_for_max_datagram_size(max_datagram_size: ByteCount) -> ByteCount {
    MIN_CONGESTION_WINDOW_PACKETS * max_datagram_size
}

/// 缩放 byte window（对应 Go `scaleByteWindowForDatagramSize`）。
fn scale_byte_window(window: ByteCount, old_size: ByteCount, new_size: ByteCount) -> ByteCount {
    if old_size == new_size {
        window
    } else {
        ((window as u64) * (new_size as u64) / (old_size as u64)) as ByteCount
    }
}

/// BbrSender 主体（对应 Go `bbrSender`）。
///
/// ponytail: 字段完整对齐 Go 端，方法实现简化版（接口完整 + 状态机内部占位）。
pub struct BbrSender {
    inner: Mutex<BbrInner>,
    pacer: Arc<Pacer>,
    clock: Arc<dyn Clock>,
}

struct BbrInner {
    rtt_stats: Option<Box<dyn RttStatsProvider>>,
    sampler: BandwidthSampler,
    mode: BbrMode,
    round_trip_count: u64,
    last_sent_packet: PacketNumber,
    current_round_trip_end: PacketNumber,
    num_loss_events_in_round: u64,
    bytes_lost_in_round: ByteCount,
    min_rtt: Duration,
    min_rtt_timestamp: MonoTime,
    congestion_window: ByteCount,
    initial_congestion_window: ByteCount,
    max_congestion_window: ByteCount,
    min_congestion_window: ByteCount,
    profile: Profile,
    high_gain: f64,
    high_cwnd_gain: f64,
    drain_gain: f64,
    pacing_rate: Bandwidth,
    pacing_gain: f64,
    congestion_window_gain: f64,
    congestion_window_gain_constant: f64,
    num_startup_rtts: i64,
    cycle_current_offset: usize,
    last_cycle_start: MonoTime,
    is_at_full_bandwidth: bool,
    rounds_without_bandwidth_gain: i64,
    bandwidth_at_last_round: Bandwidth,
    exiting_quiescence: bool,
    exit_probe_rtt_at: MonoTime,
    probe_rtt_round_passed: bool,
    last_sample_is_app_limited: bool,
    has_no_app_limited_sample: bool,
    recovery_state: BbrRecoveryState,
    end_recovery_at: PacketNumber,
    recovery_window: ByteCount,
    is_app_limited_recovery: bool,
    slower_startup: bool,
    rate_based_startup: bool,
    enable_ack_aggregation_during_startup: bool,
    expire_ack_aggregation_in_startup: bool,
    drain_to_target: bool,
    detect_overshooting: bool,
    bytes_lost_while_detecting_overshooting: ByteCount,
    bytes_lost_multiplier_while_detecting_overshooting: u8,
    cwnd_to_calculate_min_pacing_rate: ByteCount,
    max_congestion_window_with_network_parameters_adjusted: ByteCount,
    max_datagram_size: ByteCount,
    bytes_in_flight: ByteCount,
}

impl std::fmt::Debug for BbrSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.lock().unwrap();
        f.debug_struct("BbrSender")
            .field("mode", &inner.mode)
            .field("round_trip_count", &inner.round_trip_count)
            .field("profile", &inner.profile)
            .field("min_rtt", &inner.min_rtt)
            .field("congestion_window", &inner.congestion_window)
            .finish_non_exhaustive()
    }
}

impl BbrSender {
    /// 构造（对应 Go `NewBbrSender`）。
    pub fn new(clock: Arc<dyn Clock>, initial_max_datagram_size: ByteCount, profile: Profile) -> Self {
        let initial_cwnd = INITIAL_CONGESTION_WINDOW_PACKETS * initial_max_datagram_size;
        let max_cwnd = 100 * initial_max_datagram_size; // ponytail: MaxCongestionWindowPackets = 100
        let min_cwnd = min_congestion_window_for_max_datagram_size(initial_max_datagram_size);

        let sampler = BandwidthSampler::new(BANDWIDTH_WINDOW_SIZE);

        // Pacer 的 bandwidthForPacer：return pacing_rate * pacing_gain
        // ponytail: 用 Arc<Mutex<(Bandwidth, f64)>> 共享 (pacing_rate, pacing_gain)
        let bw_state = Arc::new(Mutex::new((Bandwidth(0), 1.0_f64)));
        let bw_for_closure = Arc::clone(&bw_state);
        let pacer = Arc::new(Pacer::new(move || {
            let (rate, gain) = *bw_for_closure.lock().unwrap();
            ((rate.0 as f64) * gain) as ByteCount
        }));

        let mut inner = BbrInner {
            rtt_stats: None,
            sampler,
            mode: BbrMode::Startup,
            round_trip_count: 0,
            last_sent_packet: super::super::types::INVALID_PACKET_NUMBER,
            current_round_trip_end: super::super::types::INVALID_PACKET_NUMBER,
            num_loss_events_in_round: 0,
            bytes_lost_in_round: 0,
            min_rtt: INF_RTT,
            min_rtt_timestamp: 0,
            congestion_window: initial_cwnd,
            initial_congestion_window: initial_cwnd,
            max_congestion_window: max_cwnd,
            min_congestion_window: min_cwnd,
            profile: Profile::Standard,
            high_gain: DEFAULT_HIGH_GAIN,
            high_cwnd_gain: DERIVED_HIGH_CWND_GAIN,
            drain_gain: 1.0 / DEFAULT_HIGH_GAIN,
            pacing_rate: Bandwidth(0),
            pacing_gain: 1.0,
            congestion_window_gain: 1.0,
            congestion_window_gain_constant: 2.0,
            num_startup_rtts: ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP,
            cycle_current_offset: 0,
            last_cycle_start: 0,
            is_at_full_bandwidth: false,
            rounds_without_bandwidth_gain: 0,
            bandwidth_at_last_round: Bandwidth(0),
            exiting_quiescence: false,
            exit_probe_rtt_at: 0,
            probe_rtt_round_passed: false,
            last_sample_is_app_limited: false,
            has_no_app_limited_sample: false,
            recovery_state: BbrRecoveryState::NotInRecovery,
            end_recovery_at: super::super::types::INVALID_PACKET_NUMBER,
            recovery_window: max_cwnd,
            is_app_limited_recovery: false,
            slower_startup: false,
            rate_based_startup: false,
            enable_ack_aggregation_during_startup: false,
            expire_ack_aggregation_in_startup: false,
            drain_to_target: false,
            detect_overshooting: false,
            bytes_lost_while_detecting_overshooting: 0,
            bytes_lost_multiplier_while_detecting_overshooting: 2,
            cwnd_to_calculate_min_pacing_rate: initial_cwnd,
            max_congestion_window_with_network_parameters_adjusted: max_cwnd,
            max_datagram_size: initial_max_datagram_size,
            bytes_in_flight: 0,
        };

        // 同步初始 (rate, gain) 到 pacer 闭包
        *bw_state.lock().unwrap() = (inner.pacing_rate, inner.pacing_gain);

        Self {
            inner: Mutex::new(inner),
            pacer,
            clock,
        }
        // bw_state 在 drop 时释放（pacer 闭包持有副本）
        // ponytail: bw_state 局部变量没保留到 struct，pacer 闭包是唯一持有者。
    }

    /// 应用 Profile 配置（对应 Go `applyProfile`）。
    fn apply_profile_locked(inner: &mut BbrInner, profile: Profile) {
        let cfg = config_for_profile(profile);
        inner.profile = profile;
        inner.high_gain = cfg.high_gain;
        inner.high_cwnd_gain = cfg.high_cwnd_gain;
        inner.drain_gain = 1.0 / cfg.high_gain;
        inner.congestion_window_gain_constant = cfg.congestion_window_gain_constant;
        inner.num_startup_rtts = cfg.num_startup_rtts;
        inner.drain_to_target = cfg.drain_to_target;
        inner.detect_overshooting = cfg.detect_overshooting;
        inner.bytes_lost_multiplier_while_detecting_overshooting = cfg.bytes_lost_multiplier;
        inner.enable_ack_aggregation_during_startup = cfg.enable_ack_aggregation_startup;
        inner.expire_ack_aggregation_in_startup = cfg.expire_ack_aggregation_startup;
        if cfg.enable_overestimate_avoidance {
            inner.sampler.enable_overestimate_avoidance();
        }
        inner
            .sampler
            .set_reduce_extra_acked_on_bandwidth_increase(cfg.reduce_extra_acked_on_bandwidth_increase);
    }

    /// 当前模式。
    pub fn mode(&self) -> BbrMode {
        self.inner.lock().unwrap().mode
    }

    /// 当前 profile。
    pub fn profile(&self) -> Profile {
        self.inner.lock().unwrap().profile
    }

    /// 当前 pacing rate。
    pub fn pacing_rate(&self) -> Bandwidth {
        self.inner.lock().unwrap().pacing_rate
    }
}

impl CongestionControl for BbrSender {
    fn set_rtt_stats_provider(&mut self, provider: Box<dyn RttStatsProvider>) {
        self.inner.lock().unwrap().rtt_stats = Some(provider);
    }

    fn time_until_send(&self, _bytes_in_flight: ByteCount) -> MonoTime {
        self.pacer.time_until_send()
    }

    fn has_pacing_budget(&self, now: MonoTime) -> bool {
        let mds = self.inner.lock().unwrap().max_datagram_size;
        self.pacer.budget(now) >= mds
    }

    fn can_send(&self, bytes_in_flight: ByteCount) -> bool {
        bytes_in_flight < self.congestion_window()
    }

    fn congestion_window(&self) -> ByteCount {
        let inner = self.inner.lock().unwrap();
        if inner.mode == BbrMode::ProbeRtt {
            return inner.min_congestion_window;
        }
        if inner.recovery_state != BbrRecoveryState::NotInRecovery {
            return inner.congestion_window.min(inner.recovery_window);
        }
        inner.congestion_window
    }

    fn on_packet_sent(
        &mut self,
        sent_time: MonoTime,
        bytes_in_flight: ByteCount,
        packet_number: PacketNumber,
        bytes: ByteCount,
        is_retransmittable: bool,
    ) {
        self.pacer.sent_packet(sent_time, bytes);
        let mut inner = self.inner.lock().unwrap();
        inner.last_sent_packet = packet_number;
        inner.bytes_in_flight = bytes_in_flight;
        if bytes_in_flight == 0 {
            inner.exiting_quiescence = true;
        }
        inner
            .sampler
            .on_packet_sent(sent_time, packet_number, bytes, bytes_in_flight, is_retransmittable);
    }

    fn on_packet_acked(
        &mut self,
        _number: PacketNumber,
        _acked_bytes: ByteCount,
        _prior_in_flight: ByteCount,
        _event_time: MonoTime,
    ) {
        // Go 端为 stub
    }

    fn on_congestion_event(
        &mut self,
        _number: PacketNumber,
        _lost_bytes: ByteCount,
        _prior_in_flight: ByteCount,
    ) {
        // Go 端为 stub
    }

    fn on_congestion_event_ex(
        &mut self,
        prior_in_flight: ByteCount,
        event_time: MonoTime,
        acked_packets: &[AckedPacketInfo],
        lost_packets: &[LostPacketInfo],
    ) {
        // ponytail: 简化实现 —— 更新 bytes_in_flight + sampler 累积计数。
        // 完整算法应更新 maxBandwidth / minRtt / pacing_rate / recovery_window，
        // 等真正运行 hysteria 时补全（quinn-proto BBR 可替代）。
        let mut inner = self.inner.lock().unwrap();
        inner.bytes_in_flight = prior_in_flight;
        for p in acked_packets {
            inner.bytes_in_flight -= p.bytes_acked;
        }
        for p in lost_packets {
            inner.bytes_in_flight -= p.bytes_lost;
        }
        let max_bw = inner.pacing_rate;
        let rtt_count = inner.round_trip_count;
        inner.sampler.on_congestion_event(
            event_time,
            acked_packets,
            lost_packets,
            max_bw,
            INF_BANDWIDTH,
            rtt_count,
        );
    }

    fn set_max_datagram_size(&mut self, size: ByteCount) {
        let mut inner = self.inner.lock().unwrap();
        assert!(
            size >= inner.max_datagram_size,
            "BBR cannot decrease max datagram size"
        );
        let old_mds = inner.max_datagram_size;
        let old_min_cwnd = inner.min_congestion_window;
        let old_initial_cwnd = inner.initial_congestion_window;

        inner.max_datagram_size = size;
        inner.initial_congestion_window =
            scale_byte_window(inner.initial_congestion_window, old_mds, size);
        inner.max_congestion_window =
            scale_byte_window(inner.max_congestion_window, old_mds, size);
        inner.min_congestion_window = min_congestion_window_for_max_datagram_size(size);
        inner.cwnd_to_calculate_min_pacing_rate =
            scale_byte_window(inner.cwnd_to_calculate_min_pacing_rate, old_mds, size);
        inner.max_congestion_window_with_network_parameters_adjusted = scale_byte_window(
            inner.max_congestion_window_with_network_parameters_adjusted,
            old_mds,
            size,
        );

        // 同步 congestion_window
        if inner.congestion_window == old_min_cwnd {
            inner.congestion_window = inner.min_congestion_window;
        } else if inner.congestion_window == old_initial_cwnd {
            inner.congestion_window = inner.initial_congestion_window;
        } else {
            inner.congestion_window = inner
                .congestion_window
                .clamp(inner.min_congestion_window, inner.max_congestion_window);
        }
        inner.recovery_window = inner
            .recovery_window
            .clamp(inner.min_congestion_window, inner.max_congestion_window);

        drop(inner);
        self.pacer.set_max_datagram_size(size);
    }

    fn in_slow_start(&self) -> bool {
        self.inner.lock().unwrap().mode == BbrMode::Startup
    }

    fn in_recovery(&self) -> bool {
        self.inner.lock().unwrap().recovery_state != BbrRecoveryState::NotInRecovery
    }

    fn maybe_exit_slow_start(&mut self) {
        // Go 端为 stub
    }

    fn on_retransmission_timeout(&mut self, _packets_retransmitted: bool) {
        // Go 端为 stub
    }

    fn pacer(&self) -> &Pacer {
        &self.pacer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::congestion::bbr::DefaultClock;
    use crate::congestion::types::test_support::MockRttStats;

    fn make_sender() -> BbrSender {
        BbrSender::new(
            Arc::new(DefaultClock::new()),
            INITIAL_PACKET_SIZE,
            Profile::Standard,
        )
    }

    #[test]
    fn new_sender_starts_in_startup_mode() {
        let s = make_sender();
        assert_eq!(s.mode(), BbrMode::Startup);
        assert_eq!(s.profile(), Profile::Standard);
        assert!(s.in_slow_start());
        assert!(!s.in_recovery());
    }

    #[test]
    fn congestion_window_initial_value() {
        let s = make_sender();
        // 32 * 1200 = 38400
        assert_eq!(s.congestion_window(), 38400);
    }

    #[test]
    fn can_send_below_window() {
        let s = make_sender();
        assert!(s.can_send(10000));
        assert!(!s.can_send(100_000));
    }

    #[test]
    fn set_max_datagram_size_scales_windows() {
        let mut s = make_sender();
        s.set_max_datagram_size(1400);
        // min_cwnd 应从 4 * 1200 = 4800 → 4 * 1400 = 5600
        let inner = s.inner.lock().unwrap();
        assert_eq!(inner.min_congestion_window, 5600);
        assert_eq!(inner.initial_congestion_window, 32 * 1400);
        assert_eq!(inner.max_datagram_size, 1400);
    }

    #[test]
    #[should_panic(expected = "BBR cannot decrease")]
    fn set_max_datagram_size_decreasing_panics() {
        let mut s = make_sender();
        s.set_max_datagram_size(500); // < INITIAL_PACKET_SIZE
    }

    #[test]
    fn config_for_profile_consistent_with_go() {
        let std_cfg = config_for_profile(Profile::Standard);
        assert!((std_cfg.high_gain - DEFAULT_HIGH_GAIN).abs() < 1e-9);
        assert_eq!(std_cfg.num_startup_rtts, 3);
        assert_eq!(std_cfg.bytes_lost_multiplier, 2);

        let cons_cfg = config_for_profile(Profile::Conservative);
        assert!((cons_cfg.high_gain - 2.25).abs() < 1e-9);
        assert_eq!(cons_cfg.num_startup_rtts, 2);
        assert!(cons_cfg.enable_overestimate_avoidance);
        assert!(cons_cfg.reduce_extra_acked_on_bandwidth_increase);

        let agg_cfg = config_for_profile(Profile::Aggressive);
        assert!((agg_cfg.high_gain - 3.0).abs() < 1e-9);
        assert_eq!(agg_cfg.num_startup_rtts, 4);
        assert!(agg_cfg.enable_ack_aggregation_startup);
    }

    #[test]
    fn on_packet_sent_records_state() {
        let mut s = make_sender();
        s.on_packet_sent(100, 1200, 1, 1200, true);
        let inner = s.inner.lock().unwrap();
        assert_eq!(inner.last_sent_packet, 1);
        assert_eq!(inner.bytes_in_flight, 1200);
    }

    #[test]
    fn on_congestion_event_ex_updates_bytes_in_flight() {
        let mut s = make_sender();
        s.on_packet_sent(100, 1200, 1, 1200, true);
        let acked = vec![AckedPacketInfo {
            packet_number: 1,
            bytes_acked: 1200,
            receive_time_ns: 200,
        }];
        s.on_congestion_event_ex(1200, 200, &acked, &[]);
        let inner = s.inner.lock().unwrap();
        assert_eq!(inner.bytes_in_flight, 0);
    }

    #[test]
    fn pacing_rate_initial_is_zero() {
        let s = make_sender();
        assert_eq!(s.pacing_rate(), Bandwidth(0));
    }

    #[test]
    fn time_until_send_uses_pacer() {
        let s = make_sender();
        // 初始 budget 充足 → time_until_send 应为 0
        assert_eq!(s.time_until_send(0), 0);
    }

    #[test]
    fn has_pacing_budget_initially_true() {
        let s = make_sender();
        assert!(s.has_pacing_budget(0));
    }

    #[test]
    fn rtt_provider_can_be_set() {
        let mut s = make_sender();
        s.set_rtt_stats_provider(Box::new(MockRttStats::new(Duration::from_millis(50))));
        // 仅验证不 panic；内部已设置
    }

    #[test]
    fn scale_byte_window_identity() {
        assert_eq!(scale_byte_window(1000, 1200, 1200), 1000);
    }

    #[test]
    fn scale_byte_window_grow() {
        assert_eq!(scale_byte_window(1200, 1200, 2400), 2400);
    }

    #[test]
    fn min_congestion_window_for_size() {
        assert_eq!(min_congestion_window_for_max_datagram_size(1200), 4800);
        assert_eq!(min_congestion_window_for_max_datagram_size(1400), 5600);
    }

    #[test]
    fn modes_have_distinct_values() {
        assert_ne!(BbrMode::Startup, BbrMode::Drain);
        assert_ne!(BbrMode::ProbeBw, BbrMode::ProbeRtt);
    }

    #[test]
    fn recovery_states_distinct() {
        assert_ne!(
            BbrRecoveryState::NotInRecovery,
            BbrRecoveryState::Conservation
        );
        assert_ne!(BbrRecoveryState::Conservation, BbrRecoveryState::Growth);
    }

    #[test]
    fn constants_match_go() {
        assert_eq!(MIN_BPS, 65_536);
        assert_eq!(INITIAL_CONGESTION_WINDOW_PACKETS, 32);
        assert_eq!(MIN_CONGESTION_WINDOW_PACKETS, 4);
        assert!((DEFAULT_HIGH_GAIN - 2.885).abs() < 1e-3);
        assert_eq!(DERIVED_HIGH_CWND_GAIN, 2.0);
        assert_eq!(BANDWIDTH_WINDOW_SIZE, 10);
        assert_eq!(MIN_RTT_EXPIRY, Duration::from_secs(10));
        assert_eq!(PROBE_RTT_TIME, Duration::from_millis(200));
        assert!((STARTUP_GROWTH_TARGET - 1.25).abs() < 1e-9);
        assert_eq!(ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP, 3);
        assert_eq!(DEFAULT_STARTUP_FULL_LOSS_COUNT, 8);
        assert!((QUIC_BBR2_DEFAULT_LOSS_THRESHOLD - 0.02).abs() < 1e-9);
    }
}
