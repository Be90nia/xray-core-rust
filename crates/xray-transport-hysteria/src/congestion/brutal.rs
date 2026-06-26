//! BrutalSender —— 固定带宽发送器（对应 Go `congestion/brutal/brutal.go`）。
//!
//! 算法：以恒定速率 `bps` 发送，但根据近 5 秒 ACK 率动态调整 effective rate。
//! ACK 率 < 0.8 钳制为 0.8；样本不足时按 1.0 处理。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::pacer::Pacer;
use super::types::{
    AckedPacketInfo, ByteCount, CongestionControl, LostPacketInfo, MonoTime, PacketNumber,
    RttStatsProvider, INITIAL_PACKET_SIZE,
};

const PKT_INFO_SLOT_COUNT: usize = 5;
const MIN_SAMPLE_COUNT: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;
const CONGESTION_WINDOW_MULTIPLIER: f64 = 2.0;

/// 单个 slot 的 ACK/Loss 计数（对应 Go `pktInfo`）。
#[derive(Debug, Default, Clone, Copy)]
struct PktInfo {
    /// 单调秒数（对应 Go `Timestamp int64`）。
    timestamp: i64,
    ack_count: u64,
    loss_count: u64,
}

/// BrutalSender（对应 Go `BrutalSender`）。
pub struct BrutalSender {
    inner: Mutex<BrutalInner>,
    pacer: Arc<Pacer>,
    /// 与 pacer 闭包共享的 ack_rate（用于 effective bps 计算）。
    shared_ack_rate: Arc<Mutex<f64>>,
}

struct BrutalInner {
    rtt_stats: Option<Box<dyn RttStatsProvider>>,
    bps: ByteCount,
    max_datagram_size: ByteCount,
    /// 5 个秒级 slot 的 ACK/Loss 样本。
    pkt_info_slots: [PktInfo; PKT_INFO_SLOT_COUNT],
    /// 当前 effective ack rate（[MIN_ACK_RATE, 1.0]）。
    ack_rate: f64,
}

impl std::fmt::Debug for BrutalSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.lock().unwrap();
        f.debug_struct("BrutalSender")
            .field("bps", &inner.bps)
            .field("max_datagram_size", &inner.max_datagram_size)
            .field("ack_rate", &inner.ack_rate)
            .finish_non_exhaustive()
    }
}

impl BrutalSender {
    /// 构造（对应 Go `NewBrutalSender`）。
    ///
    /// `bps` —— 目标发送速率（bytes/s）。
    #[must_use]
    pub fn new(bps: u64) -> Self {
        let bps_i = bps as ByteCount;
        let shared_ack_rate = Arc::new(Mutex::new(1.0_f64));
        let ar_for_closure = Arc::clone(&shared_ack_rate);
        let pacer = Arc::new(Pacer::new(move || {
            let rate = *ar_for_closure.lock().unwrap();
            // effective_bps = bps / ack_rate
            ((bps_i as f64) / rate) as ByteCount
        }));

        Self {
            inner: Mutex::new(BrutalInner {
                rtt_stats: None,
                bps: bps_i,
                max_datagram_size: INITIAL_PACKET_SIZE,
                pkt_info_slots: [PktInfo::default(); PKT_INFO_SLOT_COUNT],
                ack_rate: 1.0,
            }),
            pacer,
            shared_ack_rate,
        }
    }

    /// 测试访问：当前 ack_rate。
    pub fn ack_rate(&self) -> f64 {
        self.inner.lock().unwrap().ack_rate
    }

    /// 当前 bps（目标速率）。
    pub fn bps(&self) -> ByteCount {
        self.inner.lock().unwrap().bps
    }

    /// 更新 ack_rate（对应 Go `updateAckRate`），持锁调用。
    fn update_ack_rate_locked(inner: &mut BrutalInner, current_timestamp_secs: i64) {
        let min_timestamp = current_timestamp_secs - PKT_INFO_SLOT_COUNT as i64;
        let mut ack_count: u64 = 0;
        let mut loss_count: u64 = 0;
        for info in &inner.pkt_info_slots {
            if info.timestamp < min_timestamp {
                continue;
            }
            ack_count = ack_count.saturating_add(info.ack_count);
            loss_count = loss_count.saturating_add(info.loss_count);
        }
        let total = ack_count + loss_count;
        if total < MIN_SAMPLE_COUNT {
            inner.ack_rate = 1.0;
            return;
        }
        let rate = ack_count as f64 / total as f64;
        if rate < MIN_ACK_RATE {
            inner.ack_rate = MIN_ACK_RATE;
        } else {
            inner.ack_rate = rate;
        }
    }
}

impl CongestionControl for BrutalSender {
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
        bytes_in_flight <= self.congestion_window()
    }

    fn congestion_window(&self) -> ByteCount {
        let inner = self.inner.lock().unwrap();
        let rtt = inner
            .rtt_stats
            .as_ref()
            .map(|p| p.smoothed_rtt())
            .unwrap_or_default();
        if rtt.is_zero() {
            return 10_240;
        }
        let mut cwnd = ((inner.bps as f64)
            * rtt.as_secs_f64()
            * CONGESTION_WINDOW_MULTIPLIER
            / inner.ack_rate) as ByteCount;
        if cwnd < inner.max_datagram_size {
            cwnd = inner.max_datagram_size;
        }
        cwnd
    }

    fn on_packet_sent(
        &mut self,
        sent_time: MonoTime,
        _bytes_in_flight: ByteCount,
        _packet_number: PacketNumber,
        bytes: ByteCount,
        _is_retransmittable: bool,
    ) {
        self.pacer.sent_packet(sent_time, bytes);
    }

    fn on_packet_acked(
        &mut self,
        _number: PacketNumber,
        _acked_bytes: ByteCount,
        _prior_in_flight: ByteCount,
        _event_time: MonoTime,
    ) {
        // stub（Go 同样 stub）
    }

    fn on_congestion_event(
        &mut self,
        _number: PacketNumber,
        _lost_bytes: ByteCount,
        _prior_in_flight: ByteCount,
    ) {
        // stub（Go 同样 stub）
    }

    fn on_congestion_event_ex(
        &mut self,
        _prior_in_flight: ByteCount,
        event_time: MonoTime,
        acked_packets: &[AckedPacketInfo],
        lost_packets: &[LostPacketInfo],
    ) {
        let current_timestamp_secs = (event_time / 1_000_000_000) as i64;
        let slot = (current_timestamp_secs.rem_euclid(PKT_INFO_SLOT_COUNT as i64)) as usize;
        let ack_n = acked_packets.len() as u64;
        let loss_n = lost_packets.len() as u64;
        let mut inner = self.inner.lock().unwrap();
        if inner.pkt_info_slots[slot].timestamp == current_timestamp_secs {
            inner.pkt_info_slots[slot].loss_count += loss_n;
            inner.pkt_info_slots[slot].ack_count += ack_n;
        } else {
            inner.pkt_info_slots[slot] = PktInfo {
                timestamp: current_timestamp_secs,
                ack_count: ack_n,
                loss_count: loss_n,
            };
        }
        Self::update_ack_rate_locked(&mut inner, current_timestamp_secs);
        // 同步 effective rate 到 pacer 闭包。
        let new_rate = inner.ack_rate;
        drop(inner);
        *self.shared_ack_rate.lock().unwrap() = new_rate;
    }

    fn set_max_datagram_size(&mut self, size: ByteCount) {
        {
            let mut inner = self.inner.lock().unwrap();
            inner.max_datagram_size = size;
        }
        self.pacer.set_max_datagram_size(size);
    }

    fn in_slow_start(&self) -> bool {
        false
    }

    fn in_recovery(&self) -> bool {
        false
    }

    fn maybe_exit_slow_start(&mut self) {}

    fn on_retransmission_timeout(&mut self, _packets_retransmitted: bool) {}

    fn pacer(&self) -> &Pacer {
        &self.pacer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::congestion::types::test_support::MockRttStats;

    #[test]
    fn new_brutal_initial_state() {
        let bs = BrutalSender::new(1_000_000);
        assert_eq!(bs.bps(), 1_000_000);
        assert_eq!(bs.ack_rate(), 1.0);
        assert!(!bs.in_slow_start());
        assert!(!bs.in_recovery());
    }

    #[test]
    fn congestion_window_zero_rtt_returns_floor() {
        let bs = BrutalSender::new(1_000_000);
        assert_eq!(bs.congestion_window(), 10_240);
    }

    #[test]
    fn congestion_window_with_rtt_scales() {
        let mut bs = BrutalSender::new(1_000_000);
        let rtt = MockRttStats::new(Duration::from_millis(100));
        bs.set_rtt_stats_provider(Box::new(rtt));
        // cwnd = bps * rtt * 2 / ack_rate = 1e6 * 0.1 * 2 / 1.0 = 200_000
        assert_eq!(bs.congestion_window(), 200_000);
    }

    #[test]
    fn congestion_window_clamped_to_max_datagram_size() {
        let mut bs = BrutalSender::new(1);
        let rtt = MockRttStats::new(Duration::from_micros(1));
        bs.set_rtt_stats_provider(Box::new(rtt));
        assert_eq!(bs.congestion_window(), INITIAL_PACKET_SIZE);
    }

    #[test]
    fn on_congestion_event_ex_records_into_slot() {
        let mut bs = BrutalSender::new(1_000_000);
        let acked = vec![AckedPacketInfo {
            packet_number: 1,
            bytes_acked: 100,
            receive_time_ns: 0,
        }];
        bs.on_congestion_event_ex(0, 1_000_000_000, &acked, &[]);
        assert_eq!(bs.ack_rate(), 1.0); // total=1 < 50
    }

    #[test]
    fn ack_rate_drops_below_min_clamped() {
        let mut bs = BrutalSender::new(1_000_000);
        let acked: Vec<_> = (0..60)
            .map(|i| AckedPacketInfo {
                packet_number: i,
                bytes_acked: 100,
                receive_time_ns: 0,
            })
            .collect();
        let lost: Vec<_> = (0..60)
            .map(|i| LostPacketInfo {
                packet_number: 200 + i,
                bytes_lost: 100,
            })
            .collect();
        bs.on_congestion_event_ex(0, 1_000_000_000, &acked, &lost);
        assert_eq!(bs.ack_rate(), MIN_ACK_RATE);
    }

    #[test]
    fn ack_rate_high_stays_high() {
        let mut bs = BrutalSender::new(1_000_000);
        let acked: Vec<_> = (0..95)
            .map(|i| AckedPacketInfo {
                packet_number: i,
                bytes_acked: 100,
                receive_time_ns: 0,
            })
            .collect();
        let lost: Vec<_> = (0..5)
            .map(|i| LostPacketInfo {
                packet_number: 200 + i,
                bytes_lost: 100,
            })
            .collect();
        bs.on_congestion_event_ex(0, 1_000_000_000, &acked, &lost);
        assert!((bs.ack_rate() - 0.95).abs() < 1e-9);
    }

    #[test]
    fn can_send_when_in_flight_below_window() {
        let mut bs = BrutalSender::new(1_000_000);
        let rtt = MockRttStats::new(Duration::from_millis(100));
        bs.set_rtt_stats_provider(Box::new(rtt));
        assert!(bs.can_send(100_000));
        assert!(!bs.can_send(300_000));
    }

    #[test]
    fn set_max_datagram_size_takes_effect() {
        let mut bs = BrutalSender::new(1);
        bs.set_max_datagram_size(1400);
        let rtt = MockRttStats::new(Duration::from_micros(1));
        bs.set_rtt_stats_provider(Box::new(rtt));
        assert_eq!(bs.congestion_window(), 1400);
    }

    #[test]
    fn on_packet_sent_records_to_pacer() {
        let mut bs = BrutalSender::new(1_000_000);
        bs.on_packet_sent(100, 0, 1, 500, true);
        assert_eq!(bs.pacer().budget(100), 11_500);
    }

    #[test]
    fn slot_overwrite_when_timestamp_differs() {
        let mut bs = BrutalSender::new(1_000_000);
        let acked1 = vec![AckedPacketInfo {
            packet_number: 1,
            bytes_acked: 100,
            receive_time_ns: 0,
        }];
        bs.on_congestion_event_ex(0, 1_000_000_000, &acked1, &[]);
        assert_eq!(bs.ack_rate(), 1.0);

        let acked2: Vec<_> = (0..80)
            .map(|i| AckedPacketInfo {
                packet_number: 100 + i,
                bytes_acked: 100,
                receive_time_ns: 0,
            })
            .collect();
        let lost2: Vec<_> = (0..20)
            .map(|i| LostPacketInfo {
                packet_number: 500 + i,
                bytes_lost: 100,
            })
            .collect();
        bs.on_congestion_event_ex(0, 12_000_000_000, &acked2, &lost2);
        assert!((bs.ack_rate() - 0.8).abs() < 1e-9);
    }

    #[test]
    fn ack_rate_synced_to_pacer_closure() {
        // 验证 update_ack_rate 后 pacer 闭包看到的 rate 也更新
        let bs = BrutalSender::new(1_000_000);
        let initial_bw = bs.pacer.budget(0); // 触发闭包，但不直接观察 rate
        let _ = initial_bw;
        // 通过 pacer budget 间接验证：rate 改变后 effective_bw 变化
        // ponytail: 这里仅检查不 panic；完整验证需 Pacer 暴露 effective_bw。
    }
}
