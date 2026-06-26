//! SendingWindow + SendingWorker（对应 Go `sending.go`）。

use std::collections::VecDeque;
use std::sync::Arc;

use parking_lot::Mutex;
use xray_buf::buffer::Buffer;

use crate::config::{Config, ConfigExt};
use crate::output::SegmentWriter;
use crate::round_trip::RoundTripInfo;
use crate::segment::{DataSegment, Segment, SEGMENT_OPTION_CLOSE};
use crate::state::State;

/// 发送窗口（对应 Go `SendingWindow struct`）。
pub struct SendingWindow {
    cache: VecDeque<DataSegment>,
    total_in_flight_size: u32,
}

impl SendingWindow {
    pub fn new() -> Self {
        Self {
            cache: VecDeque::new(),
            total_in_flight_size: 0,
        }
    }

    pub fn release(&mut self) {
        while let Some(mut seg) = self.cache.pop_front() {
            seg.release();
        }
    }

    #[must_use]
    pub fn len(&self) -> u32 {
        self.cache.len() as u32
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    pub fn push(&mut self, number: u32, payload: Buffer) {
        let mut seg = DataSegment::new();
        seg.number = number;
        seg.payload = Some(payload);
        self.cache.push_back(seg);
    }

    #[must_use]
    pub fn first_number(&self) -> Option<u32> {
        self.cache.front().map(|s| s.number)
    }

    pub fn clear_before(&mut self, una: u32) {
        while let Some(front) = self.cache.front() {
            if front.number >= una {
                break;
            }
            let mut seg = self.cache.pop_front().unwrap();
            seg.release();
        }
    }

    pub fn handle_fast_ack(&mut self, number: u32, rto: u32) {
        if self.is_empty() {
            return;
        }
        for seg in &mut self.cache {
            if number == seg.number || number.wrapping_sub(seg.number) > 0x7FFF_FFFF {
                break;
            }
            if seg.transmit > 0 && seg.timeout > rto / 3 {
                seg.timeout -= rto / 3;
            }
        }
    }

    pub fn remove(&mut self, number: u32) -> bool {
        let pos = self.cache.iter().position(|s| s.number == number);
        if let Some(idx) = pos {
            if self.total_in_flight_size > 0 {
                self.total_in_flight_size -= 1;
            }
            let mut seg = self.cache.remove(idx).unwrap();
            seg.release();
            true
        } else {
            false
        }
    }

    /// 准备 flush：返回需重发的 segment 克隆 + 统计数据。
    pub(crate) fn prepare_flush(
        &mut self,
        current: u32,
        rto: u32,
        max_in_flight: u32,
        conv: u16,
        state: State,
        first_unacknowledged: u32,
    ) -> FlushPreparation {
        let mut lost = 0u32;
        let mut in_flight = 0u32;
        let mut to_send: Vec<DataSegment> = Vec::new();

        for seg in self.cache.iter_mut() {
            if current.wrapping_sub(seg.timeout) >= 0x7FFF_FFFF {
                continue;
            }
            if seg.transmit == 0 {
                self.total_in_flight_size += 1;
            } else {
                lost += 1;
            }
            seg.timeout = current + rto;
            seg.timestamp = current;
            seg.transmit += 1;
            seg.conv = conv;
            seg.option = if state == State::ReadyToClose {
                SEGMENT_OPTION_CLOSE
            } else {
                0
            };
            seg.sending_next = first_unacknowledged;
            to_send.push(clone_for_send(seg));

            in_flight += 1;
            if in_flight >= max_in_flight {
                break;
            }
        }

        FlushPreparation {
            to_send,
            lost,
            in_flight,
            total_in_flight_size: self.total_in_flight_size,
        }
    }
}

impl Default for SendingWindow {
    fn default() -> Self {
        Self::new()
    }
}

/// flush 预备返回数据。
pub(crate) struct FlushPreparation {
    pub to_send: Vec<DataSegment>,
    pub lost: u32,
    pub in_flight: u32,
    pub total_in_flight_size: u32,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct FlushOutcome {
    pub needs_ping: bool,
}

pub struct SendingWorker {
    inner: Mutex<Inner>,
    conv: u16,
    rtt: Arc<RoundTripInfo>,
    config: Arc<Config>,
}

struct Inner {
    window: SendingWindow,
    first_unacknowledged: u32,
    next_number: u32,
    remote_next_number: u32,
    control_window: u32,
    window_size: u32,
    first_unacknowledged_updated: bool,
    closed: bool,
}

impl SendingWorker {
    pub fn new(conv: u16, rtt: Arc<RoundTripInfo>, config: Arc<Config>) -> Self {
        let control_window = config.get_sending_in_flight_size();
        let window_size = config.get_sending_buffer_size();
        Self {
            inner: Mutex::new(Inner {
                window: SendingWindow::new(),
                first_unacknowledged: 0,
                next_number: 0,
                remote_next_number: 32,
                control_window,
                window_size,
                first_unacknowledged_updated: false,
                closed: false,
            }),
            conv,
            rtt,
            config,
        }
    }

    pub fn conv(&self) -> u16 {
        self.conv
    }

    pub fn rtt(&self) -> &Arc<RoundTripInfo> {
        &self.rtt
    }

    pub fn release(&self) {
        let mut inner = self.inner.lock();
        inner.window.release();
        inner.closed = true;
    }

    pub fn process_receiving_next(&self, next_number: u32) {
        let mut inner = self.inner.lock();
        inner.window.clear_before(next_number);
        Self::find_first_unacknowledged(&mut inner);
    }

    fn find_first_unacknowledged(inner: &mut Inner) {
        let first = inner.first_unacknowledged;
        inner.first_unacknowledged = inner.window.first_number().unwrap_or(inner.next_number);
        if first != inner.first_unacknowledged {
            inner.first_unacknowledged_updated = true;
        }
    }

    fn process_ack(inner: &mut Inner, number: u32) -> bool {
        let too_low = number.wrapping_sub(inner.first_unacknowledged) > 0x7FFF_FFFF;
        let too_high = number.wrapping_sub(inner.next_number) < 0x7FFF_FFFF;
        if too_low || too_high {
            return false;
        }
        let removed = inner.window.remove(number);
        if removed {
            Self::find_first_unacknowledged(inner);
        }
        removed
    }

    pub fn process_ack_segment(
        &self,
        current: u32,
        mut ack: crate::segment::AckSegment,
        rto: u32,
    ) {
        let ack_timestamp = ack.timestamp;
        let maxack_data = {
            let mut inner = self.inner.lock();
            if inner.closed {
                ack.release();
                return;
            }

            if inner.remote_next_number < ack.receiving_window {
                inner.remote_next_number = ack.receiving_window;
            }
            inner.window.clear_before(ack.receiving_next);
            Self::find_first_unacknowledged(&mut inner);

            if ack.is_empty() {
                ack.release();
                return;
            }

            let mut maxack = 0u32;
            let mut maxack_removed = false;
            for &number in &ack.number_list {
                let removed = Self::process_ack(&mut inner, number);
                if maxack < number {
                    maxack = number;
                    maxack_removed = removed;
                }
            }

            if maxack_removed {
                inner.window.handle_fast_ack(maxack, rto);
            }
            ack.release();

            maxack_removed
        };

        if maxack_data {
            let diff = current.wrapping_sub(ack_timestamp);
            if diff < 10000 {
                self.rtt.update(diff, current);
            }
        }
    }

    pub fn push(&self, payload: Buffer, _state: State) -> bool {
        let mut inner = self.inner.lock();
        if inner.closed {
            return false;
        }
        if inner.window.len() > inner.window_size {
            return false;
        }
        let next = inner.next_number;
        inner.window.push(next, payload);
        inner.next_number += 1;
        true
    }

    pub fn flush_with_writer(
        &self,
        current: u32,
        writer: &dyn SegmentWriter,
        state: State,
    ) -> FlushOutcome {
        let mut inner = self.inner.lock();
        if inner.closed {
            return FlushOutcome::default();
        }

        let mut cwnd = self.config.get_sending_in_flight_size();
        let una_diff = inner
            .remote_next_number
            .wrapping_sub(inner.first_unacknowledged);
        if cwnd > una_diff {
            cwnd = una_diff;
        }
        if cwnd > inner.control_window {
            cwnd = inner.control_window;
        }
        cwnd = cwnd.saturating_mul(self.config.cwnd_multiplier.max(1));

        let rto = self.rtt.timeout();
        let first_unacknowledged = inner.first_unacknowledged;

        let prep = inner.window.prepare_flush(
            current,
            rto,
            cwnd,
            self.conv,
            state,
            first_unacknowledged,
        );

        if prep.in_flight > 0 && prep.total_in_flight_size > 0 {
            let rate = prep.lost * 100 / prep.total_in_flight_size;
            inner.control_window = adjust_control_window(inner.control_window, rate, &self.config);
        }

        inner.first_unacknowledged_updated = false;
        let updated = std::mem::replace(&mut inner.first_unacknowledged_updated, false);
        drop(inner);

        for seg in prep.to_send {
            let _ = writer.write_segment(&seg);
        }

        FlushOutcome { needs_ping: updated }
    }

    pub fn close_write(&self) {
        let mut inner = self.inner.lock();
        inner.window.clear_before(0xFFFF_FFFF);
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().window.is_empty()
    }

    #[must_use]
    pub fn update_necessary(&self) -> bool {
        !self.is_empty()
    }

    #[must_use]
    pub fn first_unacknowledged(&self) -> u32 {
        self.inner.lock().first_unacknowledged
    }
}

fn clone_for_send(seg: &DataSegment) -> DataSegment {
    DataSegment {
        conv: seg.conv,
        option: seg.option,
        timestamp: seg.timestamp,
        number: seg.number,
        sending_next: seg.sending_next,
        payload: seg.payload.as_ref().map(|b| {
            let mut new_b = Buffer::new();
            new_b.write_from(b.bytes());
            new_b
        }),
        timeout: seg.timeout,
        transmit: seg.transmit,
    }
}

pub fn adjust_control_window(current: u32, loss_rate: u32, config: &Config) -> u32 {
    let mut new_cwnd = current;
    if loss_rate >= 15 {
        new_cwnd = 3 * new_cwnd / 4;
    }
    if loss_rate <= 5 {
        new_cwnd += new_cwnd / 4;
    }
    if new_cwnd < 16 {
        new_cwnd = 16;
    }
    let max_cwnd = config.get_sending_in_flight_size();
    if new_cwnd > max_cwnd {
        new_cwnd = max_cwnd;
    }
    new_cwnd
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::default_config;
    use crate::output::SimpleSegmentWriter;
    use crate::round_trip::RoundTripInfo;

    fn make_buf(data: &[u8]) -> Buffer {
        let mut b = Buffer::new();
        b.write_from(data);
        b
    }

    #[test]
    fn window_starts_empty() {
        let w = SendingWindow::new();
        assert!(w.is_empty());
        assert_eq!(w.len(), 0);
        assert!(w.first_number().is_none());
    }

    #[test]
    fn window_push_increments_len() {
        let mut w = SendingWindow::new();
        w.push(1, make_buf(b"hello"));
        w.push(2, make_buf(b"world"));
        assert_eq!(w.len(), 2);
        assert_eq!(w.first_number(), Some(1));
    }

    #[test]
    fn window_clear_before_removes_strict_less_than() {
        let mut w = SendingWindow::new();
        w.push(1, make_buf(b"a"));
        w.push(2, make_buf(b"b"));
        w.push(3, make_buf(b"c"));
        w.clear_before(2);
        assert_eq!(w.len(), 2);
        assert_eq!(w.first_number(), Some(2));
    }

    #[test]
    fn window_clear_before_max_clears_all() {
        let mut w = SendingWindow::new();
        w.push(1, make_buf(b"a"));
        w.push(2, make_buf(b"b"));
        w.clear_before(0xFFFF_FFFF);
        assert!(w.is_empty());
    }

    #[test]
    fn window_remove_finds_target() {
        let mut w = SendingWindow::new();
        w.push(10, make_buf(b"a"));
        w.push(20, make_buf(b"b"));
        assert!(w.remove(10));
        assert_eq!(w.len(), 1);
        assert_eq!(w.first_number(), Some(20));
    }

    #[test]
    fn window_remove_missing_returns_false() {
        let mut w = SendingWindow::new();
        w.push(10, make_buf(b"a"));
        assert!(!w.remove(99));
    }

    #[test]
    fn window_release_drops_all() {
        let mut w = SendingWindow::new();
        w.push(1, make_buf(b"a"));
        w.push(2, make_buf(b"b"));
        w.release();
        assert!(w.is_empty());
    }

    #[test]
    fn adjust_window_grows_on_low_loss() {
        let cfg = default_config();
        assert_eq!(adjust_control_window(100, 5, &cfg), 125);
    }

    #[test]
    fn adjust_window_shrinks_on_high_loss() {
        let cfg = default_config();
        assert_eq!(adjust_control_window(100, 15, &cfg), 75);
    }

    #[test]
    fn adjust_window_clamped_to_16() {
        let cfg = default_config();
        assert_eq!(adjust_control_window(4, 15, &cfg), 16);
    }

    #[test]
    fn adjust_window_capped_at_max() {
        let cfg = default_config();
        let max_cwnd = cfg.get_sending_in_flight_size();
        assert_eq!(adjust_control_window(max_cwnd * 2, 5, &cfg), max_cwnd);
    }

    fn make_worker() -> SendingWorker {
        let cfg = Arc::new(default_config());
        let rtt = Arc::new(RoundTripInfo::new(50));
        SendingWorker::new(1, rtt, cfg)
    }

    #[test]
    fn worker_starts_empty() {
        let w = make_worker();
        assert!(w.is_empty());
        assert!(!w.update_necessary());
        assert_eq!(w.first_unacknowledged(), 0);
        assert_eq!(w.conv(), 1);
    }

    #[test]
    fn worker_push_increments_next_number() {
        let w = make_worker();
        assert!(w.push(make_buf(b"a"), State::Active));
        assert!(w.push(make_buf(b"b"), State::Active));
        assert!(!w.is_empty());
        assert!(w.update_necessary());
    }

    #[test]
    fn worker_push_after_release_fails() {
        let w = make_worker();
        w.release();
        assert!(!w.push(make_buf(b"x"), State::Active));
    }

    #[test]
    fn worker_process_receiving_next_clears() {
        let w = make_worker();
        w.push(make_buf(b"a"), State::Active);
        w.push(make_buf(b"b"), State::Active);
        w.process_receiving_next(2);
        assert!(w.is_empty());
    }

    #[test]
    fn worker_close_write_clears() {
        let w = make_worker();
        w.push(make_buf(b"a"), State::Active);
        w.push(make_buf(b"b"), State::Active);
        w.close_write();
        assert!(w.is_empty());
    }

    #[test]
    fn worker_flush_empty_returns_default() {
        struct NoopW;
        impl crate::output::UnderlyingWriter for NoopW {
            fn write_all(&self, _: &[u8]) -> std::io::Result<()> {
                Ok(())
            }
        }
        let w = make_worker();
        let writer = SimpleSegmentWriter::new(NoopW);
        let outcome = w.flush_with_writer(1000, &writer, State::Active);
        assert!(!outcome.needs_ping);
    }

    #[test]
    fn worker_flush_with_data_calls_writer() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Mutex as StdMutex;

        struct CountingWriter {
            count: Arc<AtomicU32>,
            chunks: Arc<StdMutex<Vec<Vec<u8>>>>,
        }
        impl crate::output::UnderlyingWriter for CountingWriter {
            fn write_all(&self, buf: &[u8]) -> std::io::Result<()> {
                self.count.fetch_add(1, Ordering::SeqCst);
                self.chunks.lock().unwrap().push(buf.to_vec());
                Ok(())
            }
        }

        let count = Arc::new(AtomicU32::new(0));
        let chunks = Arc::new(StdMutex::new(Vec::new()));
        let writer = SimpleSegmentWriter::new(CountingWriter {
            count: count.clone(),
            chunks: chunks.clone(),
        });

        let w = make_worker();
        w.push(make_buf(b"hello"), State::Active);
        w.push(make_buf(b"world"), State::Active);

        w.flush_with_writer(1000, &writer, State::Active);

        assert!(count.load(Ordering::SeqCst) >= 1, "writer 应被调用");
    }
}
