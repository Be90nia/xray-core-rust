//! ReceivingWindow + AckList + ReceivingWorker（对应 Go `receiving.go`）。
//!
//! 接收侧负责：缓存乱序到达的 DataSegment，按 `next_number` 顺序读出；
//! 收集待确认的 (number, timestamp) 对，flush 时批量打包成 AckSegment。

use std::{collections::HashMap, sync::Arc};

use parking_lot::Mutex;
use xray_buf::multi::MultiBuffer;

use crate::{
    config::{Config, ConfigExt},
    round_trip::RoundTripInfo,
    segment::{AckSegment, DataSegment, SEGMENT_OPTION_CLOSE, Segment},
    state::State,
};

// ============== ReceivingWindow ==============

/// 接收窗口（对应 Go `ReceivingWindow struct`）。
///
/// 用 HashMap 缓存乱序到达的 DataSegment，等待 `next_number` 推进时按序取出。
pub struct ReceivingWindow {
    cache: HashMap<u32, DataSegment>,
}

impl ReceivingWindow {
    pub fn new() -> Self {
        Self { cache: HashMap::new() }
    }

    /// 尝试插入 `id -> value`。
    ///
    /// 对应 Go `ReceivingWindow.Set`，返回是否新插入。
    /// 如果 `id` 已存在，原 `value` 被归还给调用方（调用方负责 `release`）。
    pub fn set(&mut self, id: u32, value: DataSegment) -> Option<DataSegment> {
        if self.cache.contains_key(&id) {
            return Some(value);
        }
        self.cache.insert(id, value);
        None
    }

    /// 是否存在 `id` 的 segment（对应 Go `Has`）。
    #[must_use]
    pub fn has(&self, id: u32) -> bool {
        self.cache.contains_key(&id)
    }

    /// 移除并返回 `id` 的 segment（对应 Go `Remove`）。
    pub fn remove(&mut self, id: u32) -> Option<DataSegment> {
        self.cache.remove(&id)
    }
}

impl Default for ReceivingWindow {
    fn default() -> Self {
        Self::new()
    }
}

// ============== AckList ==============

/// ACK 列表（对应 Go `AckList struct`）。
///
/// 收集待确认的 (number, timestamp) 对，flush 时按 `next_flush[i]` 节流批量打包成
/// `AckSegment`。每个 AckSegment 最多容纳 `(mss - 17) / 4` 个 number。
pub struct AckList {
    timestamps: Vec<u32>,
    numbers: Vec<u32>,
    next_flush: Vec<u32>,
    flush_candidates: Vec<u32>,
    dirty: bool,
    mss: usize,
}

impl AckList {
    /// 构造。`mss` = max segment size（含 segment 头），用于计算每个 AckSegment 的
    /// number 容量（对应 Go `NewAckList` 第二参数 `kcp.mss + DataSegmentOverhead`）。
    #[must_use]
    pub fn new(mss: usize) -> Self {
        Self {
            timestamps: Vec::new(),
            numbers: Vec::new(),
            next_flush: Vec::new(),
            // 对齐 Go `NewAckList` 的 `make([]uint32, 0, 128)`：cap 恒 0 会让
            // flush 中的 `len < cap` 条件永远成立但 push 反复 realloc，性能差。
            flush_candidates: Vec::with_capacity(128),
            dirty: false,
            mss,
        }
    }

    /// 追加一个待确认 (number, timestamp)（对应 Go `AckList.Add`）。
    pub fn add(&mut self, number: u32, timestamp: u32) {
        self.timestamps.push(timestamp);
        self.numbers.push(number);
        self.next_flush.push(0);
        self.dirty = true;
    }

    /// 清除所有 `number < una` 的项（对应 Go `AckList.Clear`）。
    ///
    /// `una` = receiving worker 的 `next_number`，所有小于它的 number 已被对端确认，
    /// 可以清除。保留 `number >= una` 的项。
    pub fn clear(&mut self, una: u32) {
        let mut count = 0;
        let len = self.numbers.len();
        for i in 0..len {
            if self.numbers[i] < una {
                continue;
            }
            if i != count {
                self.numbers[count] = self.numbers[i];
                self.timestamps[count] = self.timestamps[i];
                self.next_flush[count] = self.next_flush[i];
            }
            count += 1;
        }
        if count < len {
            self.numbers.truncate(count);
            self.timestamps.truncate(count);
            self.next_flush.truncate(count);
            self.dirty = true;
        }
    }

    /// 刷新：返回需要发送的 AckSegment 列表（对应 Go `AckList.Flush`）。
    ///
    /// **注意**：返回的 AckSegment 仅填充了 `number_list` 和 `timestamp`，
    /// 调用方（`ReceivingWorker::flush`）需补充 `conv` / `option` /
    /// `receiving_next` / `receiving_window` 后再发送。
    ///
    /// 节流逻辑：每个 number 的 `next_flush[i]` 控制下次最早 flush 时间；
    /// 未到时间的 number 进入 `flush_candidates`，用于补足当前 seg 的剩余容量。
    pub fn flush(&mut self, current: u32, rto: u32) -> Vec<AckSegment> {
        self.flush_candidates.clear();

        let limit = self.mss.saturating_sub(17) / 4;
        let mut out: Vec<AckSegment> = Vec::new();
        let mut seg = AckSegment::new(limit);

        for i in 0..self.numbers.len() {
            if self.next_flush[i] > current {
                // 未到 flush 时间，收集到 candidates（受 cap 限制）
                if self.flush_candidates.len() < self.flush_candidates.capacity() {
                    self.flush_candidates.push(self.numbers[i]);
                }
                continue;
            }
            seg.put_number(self.numbers[i]);
            seg.put_timestamp(self.timestamps[i]);
            let mut timeout = rto / 2;
            if timeout < 20 {
                timeout = 20;
            }
            self.next_flush[i] = current.wrapping_add(timeout);

            if seg.is_full() {
                out.push(seg);
                seg = AckSegment::new(limit);
                self.dirty = false;
            }
        }

        if self.dirty || !seg.is_empty() {
            // 用 candidates 补足当前 seg 剩余容量（不更新 timestamp）
            for &number in &self.flush_candidates {
                if seg.is_full() {
                    break;
                }
                seg.put_number(number);
            }
            out.push(seg);
            self.dirty = false;
        }

        out
    }

    /// 待确认数量（对应 Go `len(l.numbers)`）。
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.numbers.len()
    }

    /// flush_candidates 容量（对应 Go `cap(l.flushCandidates) = 128`）。
    #[must_use]
    pub fn flush_candidates_capacity(&self) -> usize {
        self.flush_candidates.capacity()
    }
}

// ============== ReceivingWorker ==============

/// 接收 worker（对应 Go `ReceivingWorker struct`）。
///
/// 与 sending 模块一致：共享状态 `Arc<RoundTripInfo>` + `Arc<Config>` + `conv`，
/// `Mutex<Inner>` 保护窗口与 acklist。`left_over` 独立锁，假设读端单线程访问。
pub struct ReceivingWorker {
    inner: Mutex<Inner>,
    /// Read 时未消费完的剩余数据（对应 Go `leftOver buf.MultiBuffer`）。
    left_over: Mutex<Option<MultiBuffer>>,
    conv: u16,
    rtt: Arc<RoundTripInfo>,
    #[allow(dead_code)]
    config: Arc<Config>,
}

struct Inner {
    window: ReceivingWindow,
    acklist: AckList,
    next_number: u32,
    window_size: u32,
}

impl ReceivingWorker {
    /// 构造（对应 Go `NewReceivingWorker`）。
    ///
    /// `mss` = max segment size（Go 中为 `kcp.mss + DataSegmentOverhead`），
    /// 用于 AckList 计算每个 AckSegment 的容量。
    #[must_use]
    pub fn new(rtt: Arc<RoundTripInfo>, config: Arc<Config>, conv: u16, mss: usize) -> Self {
        let window_size = config.get_receiving_in_flight_size();
        Self {
            inner: Mutex::new(Inner {
                window: ReceivingWindow::new(),
                acklist: AckList::new(mss),
                next_number: 0,
                window_size,
            }),
            left_over: Mutex::new(None),
            conv,
            rtt,
            config,
        }
    }

    /// 释放资源（对应 Go `ReceivingWorker.Release`）。
    pub fn release(&self) {
        let mut left = self.left_over.lock();
        if let Some(mb) = left.as_mut() {
            mb.release();
        }
        *left = None;
    }

    /// 处理对端"已发送到 number"的通知（对应 Go `ProcessSendingNext`）。
    ///
    /// 清除所有已确认的 ACK 项。
    pub fn process_sending_next(&self, number: u32) {
        let mut inner = self.inner.lock();
        inner.acklist.clear(number);
    }

    /// 处理收到的 DataSegment（对应 Go `ProcessSegment`）。
    ///
    /// 落在接收窗口外的 segment 直接丢弃；窗口内的加入 HashMap 并登记 ACK。
    pub fn process_segment(&self, mut seg: DataSegment) {
        let mut inner = self.inner.lock();
        let number = seg.number;
        let idx = number.wrapping_sub(inner.next_number);
        if idx >= inner.window_size {
            seg.release();
            return;
        }
        inner.acklist.clear(seg.sending_next);
        inner.acklist.add(number, seg.timestamp);
        if let Some(dup) = inner.window.set(seg.number, seg) {
            // 已存在重复 segment，释放
            let mut d = dup;
            d.release();
        }
    }

    /// 读取所有按序连续的数据，返回 MultiBuffer（对应 Go `ReadMultiBuffer`）。
    ///
    /// 如果 `left_over` 有剩余，优先返回。
    pub fn read_multi_buffer(&self) -> MultiBuffer {
        // 先检查 left_over
        {
            let mut left = self.left_over.lock();
            if let Some(mb) = left.take() {
                return mb;
            }
        }

        let mut inner = self.inner.lock();
        let mut mb = MultiBuffer::new();
        loop {
            let next = inner.next_number;
            let mut seg = match inner.window.remove(next) {
                Some(s) => s,
                None => break,
            };
            inner.next_number = inner.next_number.wrapping_add(1);
            if let Some(buf) = seg.detach() {
                mb.push(buf);
            }
            seg.release();
        }
        mb
    }

    /// 读取数据到 `b`，返回读取字节数（对应 Go `Read`）。
    ///
    /// 如果 MultiBuffer 不够填满 `b`，剩余 MultiBuffer 存入 `left_over` 供下次读取。
    pub fn read(&self, b: &mut [u8]) -> usize {
        let mut mb = self.read_multi_buffer();
        if mb.is_empty() {
            return 0;
        }
        let want = b.len();
        let split = mb.split_bytes(want);
        let mut written = 0;
        for buf in split.iter() {
            let src = buf.bytes();
            let n = src.len();
            b[written..written + n].copy_from_slice(src);
            written += n;
        }
        if !mb.is_empty() {
            let mut left = self.left_over.lock();
            *left = Some(mb);
        }
        written
    }

    /// 是否有可读数据（对应 Go `IsDataAvailable`）。
    #[must_use]
    pub fn is_data_available(&self) -> bool {
        let inner = self.inner.lock();
        inner.window.has(inner.next_number)
    }

    /// 下一个期望序号（对应 Go `NextNumber`）。
    #[must_use]
    pub fn next_number(&self) -> u32 {
        let inner = self.inner.lock();
        inner.next_number
    }

    /// 是否需要 flush（对应 Go `UpdateNecessary`）。
    ///
    /// acklist 中有待确认 number 时返回 true。
    #[must_use]
    pub fn update_necessary(&self) -> bool {
        let inner = self.inner.lock();
        inner.acklist.pending_len() > 0
    }

    /// flush：返回需要发送的 AckSegment 列表（对应 Go `ReceivingWorker.Flush`）。
    ///
    /// AckList.Flush 产出 AckSegment 后，本方法补充 `conv` / `option` /
    /// `receiving_next` / `receiving_window` 字段。`state` 决定是否设置 CLOSE 选项。
    pub fn flush(&self, current: u32, state: State) -> Vec<AckSegment> {
        let rto = self.rtt.timeout();
        let mut inner = self.inner.lock();
        let next_number = inner.next_number;
        let window_size = inner.window_size;
        let mut segments = inner.acklist.flush(current, rto);

        let option = if state == State::ReadyToClose { SEGMENT_OPTION_CLOSE } else { 0 };
        for seg in &mut segments {
            seg.conv = self.conv;
            seg.option = option;
            seg.receiving_next = next_number;
            seg.receiving_window = next_number.wrapping_add(window_size);
        }
        segments
    }

    /// CloseRead 空操作（对应 Go `ReceivingWorker.CloseRead`）。
    ///
    /// Go 源码即空函数，保留接口对齐。
    pub fn close_read(&self) {}

    /// 接收窗口大小（对应 Go `ReceivingWorker.windowSize`）。
    #[must_use]
    pub fn window_size(&self) -> u32 {
        let inner = self.inner.lock();
        inner.window_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::default_config, round_trip::RoundTripInfo};

    fn make_worker(next_number: u32, window_size: u32) -> ReceivingWorker {
        let config = Arc::new(default_config());
        let rtt = Arc::new(RoundTripInfo::new(50));
        let worker = ReceivingWorker::new(rtt, config, 1, 1400);
        {
            let mut inner = worker.inner.lock();
            inner.next_number = next_number;
            inner.window_size = window_size;
        }
        worker
    }

    fn make_data_segment(number: u32, payload: &[u8]) -> DataSegment {
        let mut seg = DataSegment::new();
        seg.number = number;
        seg.timestamp = 100;
        seg.sending_next = 0;
        seg.data().write_from(payload);
        seg
    }

    // ============== ReceivingWindow ==============

    #[test]
    fn window_set_new_returns_none() {
        let mut w = ReceivingWindow::new();
        let seg = make_data_segment(1, b"abc");
        assert!(w.set(1, seg).is_none());
        assert!(w.has(1));
    }

    #[test]
    fn window_set_duplicate_returns_new_value() {
        let mut w = ReceivingWindow::new();
        let seg1 = make_data_segment(1, b"abc");
        assert!(w.set(1, seg1).is_none());
        let seg2 = make_data_segment(1, b"xyz");
        // set 返回新值（让 caller 释放），map 保留旧值
        let returned = w.set(1, seg2).expect("should return new value");
        assert_eq!(returned.payload.as_ref().unwrap().bytes(), b"xyz");
        let mut d = returned;
        d.release();
    }

    #[test]
    fn window_has_remove() {
        let mut w = ReceivingWindow::new();
        assert!(!w.has(5));
        let seg = make_data_segment(5, b"x");
        assert!(w.set(5, seg).is_none());
        assert!(w.has(5));
        let removed = w.remove(5).expect("should remove");
        assert_eq!(removed.number, 5);
        assert!(!w.has(5));
        assert!(w.remove(5).is_none());
    }

    // ============== AckList ==============

    #[test]
    fn acklist_add_increments() {
        let mut a = AckList::new(1400);
        assert_eq!(a.pending_len(), 0);
        assert!(!a.dirty);
        a.add(1, 100);
        a.add(2, 200);
        assert_eq!(a.pending_len(), 2);
        assert!(a.dirty);
    }

    #[test]
    fn acklist_clear_removes_below_una() {
        let mut a = AckList::new(1400);
        a.add(1, 100);
        a.add(5, 200);
        a.add(10, 300);
        a.clear(5); // 保留 >= 5
        assert_eq!(a.pending_len(), 2);
        assert_eq!(a.numbers, vec![5, 10]);
        assert_eq!(a.timestamps, vec![200, 300]);
    }

    #[test]
    fn acklist_clear_all_below_una() {
        let mut a = AckList::new(1400);
        a.add(1, 100);
        a.add(2, 200);
        a.clear(10);
        assert_eq!(a.pending_len(), 0);
    }

    #[test]
    fn acklist_clear_noop_when_all_above_una() {
        let mut a = AckList::new(1400);
        a.add(10, 100);
        a.add(20, 200);
        a.dirty = false; // 重置 dirty 测试 clear 无清除时不应设 dirty
        a.clear(5);
        assert_eq!(a.pending_len(), 2);
        assert!(!a.dirty);
    }

    #[test]
    fn acklist_flush_returns_empty_when_no_pending() {
        let mut a = AckList::new(1400);
        let out = a.flush(1000, 200);
        assert!(out.is_empty());
    }

    #[test]
    fn acklist_flush_returns_segment_for_pending() {
        let mut a = AckList::new(1400);
        a.add(1, 100);
        a.add(2, 200);
        // current=1000，next_flush 初始 0，0 > 1000 false → 全部 flush
        let out = a.flush(1000, 200);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].number_list, vec![1, 2]);
        assert_eq!(out[0].timestamp, 200); // PutTimestamp wrap-safe 取最大
    }

    #[test]
    fn acklist_flush_respects_next_flush_throttle() {
        let mut a = AckList::new(1400);
        a.add(1, 100);
        // 第一次 flush 在 current=1000，设置 next_flush[0] = 1000 + max(100, 20) = 1100
        let out1 = a.flush(1000, 200);
        assert_eq!(out1.len(), 1);

        // current=1050 < next_flush[0]=1100 → 不 flush，进入 candidates
        // 但 dirty 已 false 且 seg 为空 → 不发送 candidates
        let out2 = a.flush(1050, 200);
        assert_eq!(out2.len(), 0);

        // current=1100 >= next_flush[0]=1100 → flush
        let out3 = a.flush(1100, 200);
        assert_eq!(out3.len(), 1);
        assert_eq!(out3[0].number_list, vec![1]);
    }

    #[test]
    fn acklist_flush_splits_multiple_segments_when_full() {
        // limit = (100 - 17) / 4 = 20
        let mut a = AckList::new(100);
        for i in 0..45 {
            a.add(i, 100 + i);
        }
        let out = a.flush(1000, 200);
        // 45 numbers / limit 20 → 2 满 + 1 部分 = 3
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].number_list.len(), 20);
        assert_eq!(out[1].number_list.len(), 20);
        assert_eq!(out[2].number_list.len(), 5);
    }
    // ============== ReceivingWorker ==============

    #[test]
    fn acklist_flush_candidates_collected_for_throttled_numbers() {
        // 1eeu-kcp: 验证 flush_candidates 行为：throttle-only 数字进 candidates，
        // candidates 在 dirty 末尾补足当前 seg 剩余容量（不更新 timestamp）。
        // mss=1400 → limit clamp 到 ACK_NUMBER_LIMIT=128。
        let mut a = AckList::new(1400);
        a.add(1, 100);
        let out1 = a.flush(1000, 200);
        // 1 个立即 flush,seg 未满(1<128),末尾 dirty push 1 次
        assert_eq!(out1.len(), 1);
        assert_eq!(out1[0].number_list, vec![1]);

        // 第二次 flush:1 仍 throttle,加 200 个新数字（next_flush=0 < current 全部立即 flush）
        for i in 2..=201u32 {
            a.add(i, 100);
        }
        let out2 = a.flush(1050, 200);
        // 200 立即 flush:128 满→push seg1,剩 72;candidates 补 1→seg2=73;push
        assert_eq!(out2.len(), 2);
        assert_eq!(out2[0].number_list.len(), 128);
        // seg2:72 立即 + 1 候选 = 73
        assert_eq!(out2[1].number_list.len(), 73);
        // 1 号在 seg2（candidates 补）
        assert!(out2[1].number_list.contains(&1));
    }

    #[test]
    fn acklist_flush_candidates_has_capacity_128() {
        // 1eeu-kcp: 验证 Vec::with_capacity(128) 对齐 Go `make([]uint32, 0, 128)`。
        // 直接断言 cap 而非行为,避开 throttle-only 路径的 dirty 边角条件。
        let a = AckList::new(1400);
        assert_eq!(a.flush_candidates_capacity(), 128);
    }

    #[test]
    fn worker_process_segment_in_window() {
        let worker = make_worker(0, 32);
        let seg = make_data_segment(0, b"hello");
        worker.process_segment(seg);
        assert!(worker.is_data_available());
        assert_eq!(worker.next_number(), 0);
    }

    #[test]
    fn worker_process_segment_out_of_window_dropped() {
        let worker = make_worker(0, 4);
        let seg = make_data_segment(100, b"far");
        worker.process_segment(seg);
        assert!(!worker.is_data_available());
        assert_eq!(worker.next_number(), 0);
    }

    #[test]
    fn worker_process_segment_duplicate_released() {
        let worker = make_worker(0, 32);
        worker.process_segment(make_data_segment(0, b"first"));
        worker.process_segment(make_data_segment(0, b"dup"));
        // 只有第一个生效
        let mb = worker.read_multi_buffer();
        assert_eq!(mb.buffer_count(), 1);
        // next_number 推进到 1
        assert_eq!(worker.next_number(), 1);
    }

    #[test]
    fn worker_read_multi_buffer_sequential() {
        let worker = make_worker(0, 32);
        // 乱序到达
        worker.process_segment(make_data_segment(2, b"cc"));
        worker.process_segment(make_data_segment(0, b"aa"));
        worker.process_segment(make_data_segment(1, b"bb"));

        // next_number=0，但 0 和 1 连续，2 也在窗口内
        // read_multi_buffer 只取连续的：0, 1, 2 都有
        let mb = worker.read_multi_buffer();
        assert_eq!(mb.buffer_count(), 3);
        assert_eq!(worker.next_number(), 3);
    }

    #[test]
    fn worker_read_multi_buffer_stops_at_gap() {
        let worker = make_worker(0, 32);
        worker.process_segment(make_data_segment(0, b"aa"));
        worker.process_segment(make_data_segment(2, b"cc"));
        // 缺少 1，只能读 0
        let mb = worker.read_multi_buffer();
        assert_eq!(mb.buffer_count(), 1);
        assert_eq!(worker.next_number(), 1);
        // 补上 1 后可以继续读
        drop(mb);
        worker.process_segment(make_data_segment(1, b"bb"));
        let mb2 = worker.read_multi_buffer();
        assert_eq!(mb2.buffer_count(), 2);
    }

    #[test]
    fn worker_read_into_slice() {
        let worker = make_worker(0, 32);
        worker.process_segment(make_data_segment(0, b"hello"));
        worker.process_segment(make_data_segment(1, b"world"));

        let mut buf = [0u8; 32];
        let n = worker.read(&mut buf);
        assert_eq!(n, 10);
        assert_eq!(&buf[..10], b"helloworld");
    }

    #[test]
    fn worker_read_partial_keeps_leftover() {
        let worker = make_worker(0, 32);
        worker.process_segment(make_data_segment(0, b"hello"));
        worker.process_segment(make_data_segment(1, b"world"));

        let mut buf = [0u8; 7];
        let n = worker.read(&mut buf);
        assert_eq!(n, 7);
        assert_eq!(&buf, b"hellowo");

        // 剩余 "rld" 存入 left_over，下次 read 取出
        let mut buf2 = [0u8; 10];
        let n2 = worker.read(&mut buf2);
        assert_eq!(n2, 3);
        assert_eq!(&buf2[..3], b"rld");
    }

    #[test]
    fn worker_read_returns_zero_when_empty() {
        let worker = make_worker(0, 32);
        let mut buf = [0u8; 10];
        assert_eq!(worker.read(&mut buf), 0);
    }

    #[test]
    fn worker_process_sending_next_clears_acklist() {
        let worker = make_worker(0, 32);
        worker.process_segment(make_data_segment(0, b"x"));
        assert!(worker.update_necessary());
        worker.process_sending_next(1); // una=1，number 0 < 1 → 清除
        assert!(!worker.update_necessary());
    }

    #[test]
    fn worker_flush_returns_empty_when_no_pending() {
        let worker = make_worker(0, 32);
        let out = worker.flush(1000, State::Active);
        assert!(out.is_empty());
    }

    #[test]
    fn worker_flush_returns_filled_ack_segments() {
        let worker = make_worker(5, 32);
        worker.process_segment(make_data_segment(5, b"x"));
        worker.process_segment(make_data_segment(6, b"y"));

        let out = worker.flush(1000, State::Active);
        assert_eq!(out.len(), 1);
        let seg = &out[0];
        assert_eq!(seg.conv, 1); // make_worker 设 conv=1
        assert_eq!(seg.option, 0);
        assert_eq!(seg.receiving_next, 5);
        assert_eq!(seg.receiving_window, 5 + 32);
        assert!(seg.number_list.contains(&5));
        assert!(seg.number_list.contains(&6));
    }

    #[test]
    fn worker_flush_sets_close_option_when_ready_to_close() {
        let worker = make_worker(0, 32);
        worker.process_segment(make_data_segment(0, b"x"));
        let out = worker.flush(1000, State::ReadyToClose);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].option, SEGMENT_OPTION_CLOSE);
    }

    #[test]
    fn worker_window_size_reflects_config() {
        let worker = make_worker(0, 42);
        assert_eq!(worker.window_size(), 42);
    }

    #[test]
    fn worker_release_clears_left_over() {
        let worker = make_worker(0, 32);
        // 制造 left_over
        worker.process_segment(make_data_segment(0, b"hello"));
        worker.process_segment(make_data_segment(1, b"world"));
        let mut small = [0u8; 3];
        let _ = worker.read(&mut small);
        // left_over 应有剩余
        {
            let left = worker.left_over.lock();
            assert!(left.is_some());
        }
        worker.release();
        {
            let left = worker.left_over.lock();
            assert!(left.is_none());
        }
    }

    #[test]
    fn worker_close_read_is_noop() {
        let worker = make_worker(0, 32);
        worker.close_read(); // 不 panic 即可
    }

    #[test]
    fn worker_default_config_window_size_nonzero() {
        let config = Arc::new(default_config());
        let rtt = Arc::new(RoundTripInfo::new(50));
        let worker = ReceivingWorker::new(rtt, config, 0, 1400);
        assert!(worker.window_size() > 0);
    }
}
