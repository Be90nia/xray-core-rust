//! BandwidthSampler —— 带宽采样器（对应 Go `congestion/bbr/bandwidth_sampler.go`）。
//!
//! 完整翻译核心类型 + 接口，内部采样算法做简化（标记 TODO：完整 BBR 行为
//! 等真正需要运行 hysteria 时补全；quinn 集成可改用 quinn-proto 自带 BBR）。

use std::time::Duration;

use super::super::types::{AckedPacketInfo, ByteCount, LostPacketInfo, MonoTime, PacketNumber};
use super::bandwidth::{Bandwidth, INF_BANDWIDTH};

/// 发送时刻状态（对应 Go `sendTimeState`）。
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SendTimeState {
    pub is_valid: bool,
    pub is_app_limited: bool,
    pub total_bytes_sent: ByteCount,
    pub total_bytes_acked: ByteCount,
    pub total_bytes_lost: ByteCount,
    pub bytes_in_flight: ByteCount,
}

impl SendTimeState {
    /// 构造有效状态（对应 Go `newSendTimeState`）。
    #[must_use]
    pub fn new(
        is_app_limited: bool,
        total_bytes_sent: ByteCount,
        total_bytes_acked: ByteCount,
        total_bytes_lost: ByteCount,
        bytes_in_flight: ByteCount,
    ) -> Self {
        Self {
            is_valid: true,
            is_app_limited,
            total_bytes_sent,
            total_bytes_acked,
            total_bytes_lost,
            bytes_in_flight,
        }
    }
}

/// 一次带宽采样结果（对应 Go `bandwidthSample`）。
#[derive(Copy, Clone, Debug, Default)]
pub struct BandwidthSample {
    pub bandwidth: Bandwidth,
    pub rtt: Duration,
    pub send_rate: Bandwidth,
    pub state_at_send: SendTimeState,
}

impl BandwidthSample {
    /// 默认值（send_rate = INF，对应 Go `newBandwidthSample`）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            send_rate: INF_BANDWIDTH,
            ..Self::default()
        }
    }
}

/// Extra ACK 事件（对应 Go `extraAckedEvent`）。
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ExtraAckedEvent {
    pub extra_acked: ByteCount,
    pub bytes_acked: ByteCount,
    pub time_delta: Duration,
    pub round: u64,
}

/// 拥塞事件整体采样结果（对应 Go `BandwidthSampler.OnCongestionEvent` 返回）。
#[derive(Copy, Clone, Debug, Default)]
pub struct CongestionEventSample {
    pub sample_max_bandwidth: Bandwidth,
    pub sample_rtt: Duration,
    pub extra_acked: ByteCount,
    pub sample_is_app_limited: bool,
    pub last_packet_send_state: SendTimeState,
}

/// "无穷大" RTT（对应 Go `infRTT = time.Duration(math.MaxInt64)`）。
pub const INF_RTT: Duration = Duration::MAX;

/// BandwidthSampler（对应 Go `bandwidthSampler`）。
///
/// ponytail: 完整接口 + 简化内部状态。Go 端用 packetNumberIndexedQueue +
/// maxAckHeightTracker 跟踪每包状态，Rust 端用 HashMap + 累积计数器简化。
pub struct BandwidthSampler {
    round_trip_count: u64,
    app_limited_packets: std::collections::HashMap<PacketNumber, ()>,
    sent_packets: std::collections::HashMap<PacketNumber, SendTimeState>,
    total_bytes_sent: ByteCount,
    total_bytes_acked: ByteCount,
    total_bytes_lost: ByteCount,
    is_app_limited: bool,
    overestimate_avoidance_enabled: bool,
    reduce_extra_acked_on_bandwidth_increase: bool,
}

impl std::fmt::Debug for BandwidthSampler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BandwidthSampler")
            .field("round_trip_count", &self.round_trip_count)
            .field("total_bytes_sent", &self.total_bytes_sent)
            .field("total_bytes_acked", &self.total_bytes_acked)
            .field("total_bytes_lost", &self.total_bytes_lost)
            .field("is_app_limited", &self.is_app_limited)
            .finish_non_exhaustive()
    }
}

impl BandwidthSampler {
    /// 构造（对应 Go `newBandwidthSampler(window_size)`）。
    #[must_use]
    pub fn new(_window_size: u64) -> Self {
        Self {
            round_trip_count: 0,
            app_limited_packets: std::collections::HashMap::new(),
            sent_packets: std::collections::HashMap::new(),
            total_bytes_sent: 0,
            total_bytes_acked: 0,
            total_bytes_lost: 0,
            is_app_limited: false,
            overestimate_avoidance_enabled: false,
            reduce_extra_acked_on_bandwidth_increase: false,
        }
    }

    pub fn enable_overestimate_avoidance(&mut self) {
        self.overestimate_avoidance_enabled = true;
    }

    pub fn set_reduce_extra_acked_on_bandwidth_increase(&mut self, v: bool) {
        self.reduce_extra_acked_on_bandwidth_increase = v;
    }

    #[must_use]
    pub fn round_trip_count(&self) -> u64 {
        self.round_trip_count
    }

    #[must_use]
    pub fn total_bytes_sent(&self) -> ByteCount {
        self.total_bytes_sent
    }

    #[must_use]
    pub fn total_bytes_acked(&self) -> ByteCount {
        self.total_bytes_acked
    }

    #[must_use]
    pub fn total_bytes_lost(&self) -> ByteCount {
        self.total_bytes_lost
    }

    pub fn on_packet_sent(
        &mut self,
        _sent_time: MonoTime,
        packet_number: PacketNumber,
        bytes: ByteCount,
        bytes_in_flight: ByteCount,
        is_retransmittable: bool,
    ) {
        self.total_bytes_sent += bytes;
        if is_retransmittable {
            let state = SendTimeState::new(
                self.is_app_limited,
                self.total_bytes_sent,
                self.total_bytes_acked,
                self.total_bytes_lost,
                bytes_in_flight,
            );
            self.sent_packets.insert(packet_number, state);
        }
    }

    pub fn on_congestion_event(
        &mut self,
        _event_time: MonoTime,
        acked_packets: &[AckedPacketInfo],
        lost_packets: &[LostPacketInfo],
        _max_bandwidth_estimate: Bandwidth,
        _estimate_filter_lower_bound: Bandwidth,
        _round_trip_count: u64,
    ) -> CongestionEventSample {
        let mut last_acked_state = SendTimeState::default();

        for acked in acked_packets {
            if let Some(state) = self.sent_packets.remove(&acked.packet_number) {
                self.total_bytes_acked += acked.bytes_acked;
                last_acked_state = state;
            }
        }
        for lost in lost_packets {
            if self.sent_packets.remove(&lost.packet_number).is_some() {
                self.total_bytes_lost += lost.bytes_lost;
            }
        }

        CongestionEventSample {
            sample_max_bandwidth: Bandwidth(0),
            sample_rtt: INF_RTT,
            extra_acked: 0,
            sample_is_app_limited: false,
            last_packet_send_state: last_acked_state,
        }
    }

    pub fn on_app_limited(&mut self, packet_number: PacketNumber) {
        self.is_app_limited = true;
        self.app_limited_packets.insert(packet_number, ());
    }

    pub fn remove_obsolete_packets(&mut self, _less_than: PacketNumber) {}

    pub fn advance_round(&mut self) {
        self.round_trip_count += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sampler_initial_state() {
        let s = BandwidthSampler::new(10);
        assert_eq!(s.round_trip_count(), 0);
        assert_eq!(s.total_bytes_sent(), 0);
        assert_eq!(s.total_bytes_acked(), 0);
        assert_eq!(s.total_bytes_lost(), 0);
    }

    #[test]
    fn on_packet_sent_increments_bytes_sent() {
        let mut s = BandwidthSampler::new(10);
        s.on_packet_sent(100, 1, 500, 500, true);
        assert_eq!(s.total_bytes_sent(), 500);
        s.on_packet_sent(200, 2, 300, 800, false);
        assert_eq!(s.total_bytes_sent(), 800);
    }

    #[test]
    fn on_congestion_event_accumulates_acked_and_lost() {
        let mut s = BandwidthSampler::new(10);
        s.on_packet_sent(100, 1, 1000, 1000, true);
        s.on_packet_sent(200, 2, 2000, 3000, true);

        let acked = vec![AckedPacketInfo {
            packet_number: 1,
            bytes_acked: 1000,
            receive_time_ns: 500,
        }];
        let lost = vec![LostPacketInfo {
            packet_number: 2,
            bytes_lost: 2000,
        }];

        let sample = s.on_congestion_event(500, &acked, &lost, Bandwidth(0), INF_BANDWIDTH, 0);
        assert_eq!(s.total_bytes_acked(), 1000);
        assert_eq!(s.total_bytes_lost(), 2000);
        assert_eq!(sample.sample_rtt, INF_RTT);
    }

    #[test]
    fn on_app_limited_sets_flag_for_subsequent_packets() {
        let mut s = BandwidthSampler::new(10);
        s.on_app_limited(42);
        s.on_packet_sent(100, 50, 500, 500, true);
        let state = s.sent_packets.get(&50).expect("packet 50 should be tracked");
        assert!(state.is_app_limited);
    }

    #[test]
    fn advance_round_increments_counter() {
        let mut s = BandwidthSampler::new(10);
        s.advance_round();
        s.advance_round();
        assert_eq!(s.round_trip_count(), 2);
    }

    #[test]
    fn enable_overestimate_avoidance_sets_flag() {
        let mut s = BandwidthSampler::new(10);
        s.enable_overestimate_avoidance();
        assert!(s.overestimate_avoidance_enabled);
    }

    #[test]
    fn set_reduce_extra_acked_sets_flag() {
        let mut s = BandwidthSampler::new(10);
        s.set_reduce_extra_acked_on_bandwidth_increase(true);
        assert!(s.reduce_extra_acked_on_bandwidth_increase);
    }

    #[test]
    fn send_time_state_new_marks_valid() {
        let st = SendTimeState::new(false, 100, 50, 5, 45);
        assert!(st.is_valid);
        assert!(!st.is_app_limited);
        assert_eq!(st.total_bytes_sent, 100);
    }

    #[test]
    fn real_packet_numbers_drain_sent_packets_but_synthetic_pn0_never_matches() {
        // pv70 根因对照：quinn 适配层修复前合成 pn=0（键位错位），sampler 状态
        // 恒增长；喂真实 pn 列表（SentBook 冲销产出）必须逐条删除。
        let mut s = BandwidthSampler::new(10);
        s.on_packet_sent(100, 1, 1200, 1200, true);
        s.on_packet_sent(110, 2, 1200, 2400, true);
        s.on_packet_sent(120, 3, 1200, 3600, true);
        assert_eq!(s.sent_packets.len(), 3);

        // 修复前 adapter 行为：聚合事件合成 pn=0 → 永不命中，sent_packets 恒增长。
        let synthetic = [AckedPacketInfo {
            packet_number: 0,
            bytes_acked: 2400,
            receive_time_ns: 200,
        }];
        s.on_congestion_event(200, &synthetic, &[], Bandwidth(0), INF_BANDWIDTH, 0);
        assert_eq!(s.sent_packets.len(), 3, "synthetic pn=0 never matches: unbounded growth");

        // 修复后：真实 pn 列表（ack 队首 2 包）+ loss（队尾 1 包）→ 全清。
        let acked = [
            AckedPacketInfo { packet_number: 1, bytes_acked: 1200, receive_time_ns: 300 },
            AckedPacketInfo { packet_number: 2, bytes_acked: 1200, receive_time_ns: 300 },
        ];
        let lost = [LostPacketInfo { packet_number: 3, bytes_lost: 1200 }];
        s.on_congestion_event(300, &acked, &lost, Bandwidth(0), INF_BANDWIDTH, 0);
        assert!(s.sent_packets.is_empty(), "real pns must drain sampler state");
        assert_eq!(s.total_bytes_acked(), 2400);
        assert_eq!(s.total_bytes_lost(), 1200);
    }
}
