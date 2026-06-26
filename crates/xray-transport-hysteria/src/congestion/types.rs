//! 共享类型 + congestion 接口 trait（脱离 quic-go 依赖）。
//!
//! Go 端用 `quic-go/congestion` 包的 `ByteCount` / `PacketNumber` /
//! `RTTStatsProvider` / `CongestionControl`。Rust 端用本地类型别名 +
//! 本地 trait 抽象，便于纯算法测试 + 上层（quinn）适配。
//!
//! ponytail: 翻译为 `i64` / `u64` 等原生类型，避免引入 quinn-proto 依赖。

use std::time::Duration;

use super::pacer::Pacer;

/// 字节计数（对应 Go `congestion.ByteCount = int64`）。
pub type ByteCount = i64;

/// 包序号（对应 Go `congestion.PacketNumber = int64`）。
pub type PacketNumber = i64;

/// 单调时钟（对应 Go `monotime.Time = uint64`，单位纳秒）。
pub type MonoTime = u64;

/// 初始数据包大小（对应 Go `congestion.InitialPacketSize = 1200`）。
pub const INITIAL_PACKET_SIZE: ByteCount = 1200;

/// 最小 pacing 间隔（对应 Go `congestion.MinPacingDelay = 1 * time.Millisecond`）。
pub const MIN_PACING_DELAY_NS: u64 = 1_000_000;

/// 无效包序号（对应 Go BBR 中 `invalidPacketNumber = -1`）。
pub const INVALID_PACKET_NUMBER: PacketNumber = -1;

/// ACK 包信息（对应 Go `congestion.AckedPacketInfo`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckedPacketInfo {
    /// 被确认的包序号。
    pub packet_number: PacketNumber,
    /// 被确认的字节数。
    pub bytes_acked: ByteCount,
    /// 接收时刻（单调时钟，纳秒）。
    pub receive_time_ns: MonoTime,
}

/// 丢包信息（对应 Go `congestion.LostPacketInfo`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LostPacketInfo {
    /// 丢失的包序号。
    pub packet_number: PacketNumber,
    /// 丢失的字节数。
    pub bytes_lost: ByteCount,
}

/// RTT 统计提供方（对应 Go `congestion.RTTStatsProvider`）。
///
/// BrutalSender / BbrSender 都需要查询当前 RTT 估算。上层（quinn）注入实现，
/// 测试时用 `MockRttStats`。
pub trait RttStatsProvider: Send + Sync {
    /// 平滑 RTT（对应 Go `SmoothedRTT()`）。
    fn smoothed_rtt(&self) -> Duration;

    /// 最小 RTT（对应 Go `MinRTT()`，BBR 用）。
    fn min_rtt(&self) -> Duration {
        self.smoothed_rtt()
    }

    /// 最新 RTT 样本（对应 Go `LatestRTT()`，BBR 用）。
    fn latest_rtt(&self) -> Duration {
        self.smoothed_rtt()
    }
}

/// 拥塞控制接口（对应 Go `congestion.CongestionControl`）。
///
/// quinn 通过 `quinn_proto::congestion::Controller` 注入；本 trait 是 hysteria
/// 算法（BrutalSender / BbrSender）实现的统一抽象，便于纯算法测试。
/// 上层 quinn adapter 将本 trait 适配为 `quinn_proto::congestion::Controller`。
pub trait CongestionControl: Send + Sync {
    /// 设置 RTT 统计提供方（对应 Go `SetRTTStatsProvider`）。
    fn set_rtt_stats_provider(&mut self, provider: Box<dyn RttStatsProvider>);

    /// 返回下次允许发包的时刻（对应 Go `TimeUntilSend`）。
    /// 返回 0 表示立即可发。
    fn time_until_send(&self, bytes_in_flight: ByteCount) -> MonoTime;

    /// 是否有 pacing budget 可发一个包（对应 Go `HasPacingBudget`）。
    fn has_pacing_budget(&self, now: MonoTime) -> bool;

    /// 是否允许发送（对应 Go `CanSend`）。
    fn can_send(&self, bytes_in_flight: ByteCount) -> bool;

    /// 拥塞窗口（bytes，对应 Go `GetCongestionWindow`）。
    fn congestion_window(&self) -> ByteCount;

    /// 包发送事件（对应 Go `OnPacketSent`）。
    #[allow(clippy::too_many_arguments)]
    fn on_packet_sent(
        &mut self,
        sent_time: MonoTime,
        bytes_in_flight: ByteCount,
        packet_number: PacketNumber,
        bytes: ByteCount,
        is_retransmittable: bool,
    );

    /// 包 ACK 事件（对应 Go `OnPacketAcked`）。
    fn on_packet_acked(
        &mut self,
        number: PacketNumber,
        acked_bytes: ByteCount,
        prior_in_flight: ByteCount,
        event_time: MonoTime,
    );

    /// 拥塞事件（旧 API，对应 Go `OnCongestionEvent`）。
    fn on_congestion_event(
        &mut self,
        number: PacketNumber,
        lost_bytes: ByteCount,
        prior_in_flight: ByteCount,
    );

    /// 拥塞事件批量（对应 Go `OnCongestionEventEx`）。
    fn on_congestion_event_ex(
        &mut self,
        prior_in_flight: ByteCount,
        event_time: MonoTime,
        acked_packets: &[AckedPacketInfo],
        lost_packets: &[LostPacketInfo],
    );

    /// 设置最大数据包大小（对应 Go `SetMaxDatagramSize`）。
    fn set_max_datagram_size(&mut self, size: ByteCount);

    /// 是否在慢启动（对应 Go `InSlowStart`）。
    fn in_slow_start(&self) -> bool;

    /// 是否在恢复期（对应 Go `InRecovery`）。
    fn in_recovery(&self) -> bool;

    /// 慢启动退出检查（对应 Go `MaybeExitSlowStart`）。
    fn maybe_exit_slow_start(&mut self);

    /// RTO 超时事件（对应 Go `OnRetransmissionTimeout`）。
    fn on_retransmission_timeout(&mut self, packets_retransmitted: bool);

    /// 取共享 Pacer 引用（hysteria 内部 pacing 辅助）。
    fn pacer(&self) -> &Pacer;
}

#[cfg(test)]
pub(crate) mod test_support {
    //! 测试辅助：mock RTT 提供方。

    use super::*;
    use std::sync::Mutex;

    /// Mock RTT 提供方，可设置固定的 smoothed_rtt。
    pub struct MockRttStats {
        rtt: Mutex<Duration>,
    }

    impl MockRttStats {
        pub fn new(rtt: Duration) -> Self {
            Self {
                rtt: Mutex::new(rtt),
            }
        }

        pub fn set(&self, rtt: Duration) {
            *self.rtt.lock().unwrap() = rtt;
        }
    }

    impl RttStatsProvider for MockRttStats {
        fn smoothed_rtt(&self) -> Duration {
            *self.rtt.lock().unwrap()
        }
    }
}
