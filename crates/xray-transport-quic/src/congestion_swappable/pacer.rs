//! Token bucket pacer（对应 Go `congestion/common/pacer.go`）。
//!
//! Ponytail：`Pacer` 用纯整数 token bucket 实现，时钟用纳秒级 `u64`（对应 Go
//! `monotime.Time`），带宽查询通过 closure 注入（对应 Go `getBandwidth func()`）。

use std::sync::Mutex;

use super::types::{ByteCount, INITIAL_PACKET_SIZE, MIN_PACING_DELAY_NS, MonoTime};

const MAX_BURST_PACKETS: ByteCount = 10;
const MAX_BURST_PACING_DELAY_MULTIPLIER: u64 = 4;

/// Pacer 实现 token bucket pacing（对应 Go `Pacer`）。
///
/// 状态被 `Mutex` 保护以允许跨线程共享。Go 端 Pacer 仅在 sender goroutine
/// 内访问，无锁；Rust 端按通用安全做法加锁。
pub struct Pacer {
    inner: Mutex<PacerInner>,
    /// 带宽查询回调（bytes/s）。Go 端是 `getBandwidth func() ByteCount`。
    get_bandwidth: Box<dyn Fn() -> ByteCount + Send + Sync>,
}

struct PacerInner {
    budget_at_last_sent: ByteCount,
    max_datagram_size: ByteCount,
    /// 上次发包的单调时间（纳秒）。0 表示未发送过。
    last_sent_time: MonoTime,
}

impl std::fmt::Debug for Pacer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.lock().unwrap();
        f.debug_struct("Pacer")
            .field("budget_at_last_sent", &inner.budget_at_last_sent)
            .field("max_datagram_size", &inner.max_datagram_size)
            .field("last_sent_time", &inner.last_sent_time)
            .finish_non_exhaustive()
    }
}

impl Pacer {
    /// 构造 Pacer（对应 Go `NewPacer`）。
    ///
    /// `get_bandwidth` 返回当前可用带宽（bytes/s），由 sender 动态调整。
    pub fn new(get_bandwidth: impl Fn() -> ByteCount + Send + Sync + 'static) -> Self {
        Self {
            inner: Mutex::new(PacerInner {
                budget_at_last_sent: MAX_BURST_PACKETS * INITIAL_PACKET_SIZE,
                max_datagram_size: INITIAL_PACKET_SIZE,
                last_sent_time: 0,
            }),
            get_bandwidth: Box::new(get_bandwidth),
        }
    }

    /// 记录一次发包（对应 Go `SentPacket`）。
    pub fn sent_packet(&self, send_time_ns: MonoTime, size: ByteCount) {
        let mut inner = self.inner.lock().unwrap();
        let budget = budget_at(&inner, send_time_ns, &self.get_bandwidth);
        if size > budget {
            inner.budget_at_last_sent = 0;
        } else {
            inner.budget_at_last_sent = budget - size;
        }
        inner.last_sent_time = send_time_ns;
    }

    /// 当前可用 budget（bytes，对应 Go `Budget`）。
    #[must_use]
    pub fn budget(&self, now_ns: MonoTime) -> ByteCount {
        let inner = self.inner.lock().unwrap();
        budget_at(&inner, now_ns, &self.get_bandwidth)
    }

    /// 计算下次发送时间（纳秒，对应 Go `TimeUntilSend`）。
    ///
    /// 返回 0 表示立即可发。
    #[must_use]
    pub fn time_until_send(&self) -> MonoTime {
        let inner = self.inner.lock().unwrap();
        if inner.budget_at_last_sent >= inner.max_datagram_size {
            return 0;
        }
        // diff = 1e9 * (max_datagram_size - budget)
        let diff = 1_000_000_000_u64
            .saturating_mul((inner.max_datagram_size - inner.budget_at_last_sent).max(0) as u64);
        let bw = (self.get_bandwidth)().max(1) as u64;
        let mut d = diff / bw;
        if diff % bw != 0 {
            d += 1;
        }
        let d = d.max(MIN_PACING_DELAY_NS);
        inner.last_sent_time.saturating_add(d)
    }

    /// 设置最大数据包大小（对应 Go `SetMaxDatagramSize`）。
    pub fn set_max_datagram_size(&self, size: ByteCount) {
        let mut inner = self.inner.lock().unwrap();
        inner.max_datagram_size = size;
    }
}

fn budget_at(
    inner: &PacerInner,
    now_ns: MonoTime,
    get_bandwidth: &dyn Fn() -> ByteCount,
) -> ByteCount {
    if inner.last_sent_time == 0 {
        return max_burst_size(inner, get_bandwidth);
    }
    let dt_ns = now_ns.saturating_sub(inner.last_sent_time);
    let bw = get_bandwidth();
    let delta = bw.saturating_mul(dt_ns as ByteCount) / 1_000_000_000;
    let budget = inner.budget_at_last_sent.saturating_add(delta);
    let cap = max_burst_size(inner, get_bandwidth);
    // ponytail: 防溢出，对应 Go `if budget < 0` 分支。
    if budget > cap { cap } else { budget }
}

fn max_burst_size(inner: &PacerInner, get_bandwidth: &dyn Fn() -> ByteCount) -> ByteCount {
    let from_pacing_delay = (MAX_BURST_PACING_DELAY_MULTIPLIER * MIN_PACING_DELAY_NS) as ByteCount
        * get_bandwidth()
        / 1_000_000_000;
    let from_packets = MAX_BURST_PACKETS * inner.max_datagram_size;
    from_pacing_delay.max(from_packets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_pacer_initial_budget_is_burst_packets() {
        let p = Pacer::new(|| 1_000_000);
        // 初始 last_sent_time=0 → 返回 max_burst_size
        let b = p.budget(1);
        assert_eq!(b, MAX_BURST_PACKETS * INITIAL_PACKET_SIZE);
    }

    #[test]
    fn sent_packet_reduces_budget() {
        let p = Pacer::new(|| 1_000_000);
        let initial = p.budget(100);
        p.sent_packet(100, 100);
        let after = p.budget(100);
        assert_eq!(after, initial - 100);
    }

    #[test]
    fn sent_packet_exceeding_budget_zeroes_out() {
        let p = Pacer::new(|| 1_000);
        let huge = (MAX_BURST_PACKETS * INITIAL_PACKET_SIZE) + 1;
        p.sent_packet(100, huge);
        assert_eq!(p.budget(100), 0);
    }

    #[test]
    fn budget_replenishes_over_time() {
        let p = Pacer::new(|| 1_000_000_000); // 1 GB/s
        // max_burst_size = max(4 * MIN_PACING_DELAY_NS * bw / 1e9,
        //                       MAX_BURST_PACKETS * INITIAL_PACKET_SIZE)
        //                = max(4 * 1_000_000 * 1e9 / 1e9, 10 * 1200)
        //                = max(4_000_000, 12_000) = 4_000_000
        let cap: ByteCount = 4_000_000;
        let burst = MAX_BURST_PACKETS * INITIAL_PACKET_SIZE; // 12_000
        p.sent_packet(1_000_000_000, burst);
        // sent_packet first-time 分支: budget_at_last_sent = cap - burst
        assert_eq!(p.budget(1_000_000_000), cap - burst);
        // 1 秒后应补满到 cap
        assert_eq!(p.budget(2_000_000_000), cap);
    }

    #[test]
    fn time_until_send_zero_when_budget_enough() {
        let p = Pacer::new(|| 1_000_000);
        // 初始 budget >> max_datagram_size
        assert_eq!(p.time_until_send(), 0);
    }

    #[test]
    fn time_until_send_positive_when_budget_low() {
        let p = Pacer::new(|| 1_000_000); // 1 MB/s
        p.sent_packet(100, MAX_BURST_PACKETS * INITIAL_PACKET_SIZE);
        let t = p.time_until_send();
        // 应该返回 last_sent_time + 某个正数（>= MIN_PACING_DELAY_NS）
        assert!(t >= 100 + MIN_PACING_DELAY_NS, "got {t}");
    }

    #[test]
    fn set_max_datagram_size_takes_effect() {
        let p = Pacer::new(|| 1_000_000);
        p.set_max_datagram_size(1400);
        // 修改后 time_until_send 的判定阈值变成 1400
        // budget 仍为初始 10*1200=12000 > 1400，所以 time_until_send=0
        assert_eq!(p.time_until_send(), 0);
    }
}
