//! PacketNumberIndexedQueue —— 按包序号索引的队列（对应 Go
//! `congestion/bbr/packet_number_indexed_queue.go`）。
//!
//! 支持：
//! - 末尾追加（含填补缺失中间项）
//! - 任意位置删除（标记 not present + 清理前缀）
//! - 按序号检索
//!
//! 内部用 RingBuffer<entryWrapper<T>>。

use super::{
    super::types::{INVALID_PACKET_NUMBER, PacketNumber},
    ringbuffer::RingBuffer,
};

/// 单条目包装（对应 Go `entryWrapper[T]`）。
#[derive(Copy, Clone, Debug, Default)]
struct EntryWrapper<T> {
    present: bool,
    entry: T,
}

/// 按包序号索引的队列（对应 Go `packetNumberIndexedQueue[T]`）。
pub struct PacketNumberIndexedQueue<T: Copy + Default> {
    entries: RingBuffer<EntryWrapper<T>>,
    number_of_present_entries: usize,
    first_packet: PacketNumber,
}

impl<T: Copy + Default> PacketNumberIndexedQueue<T> {
    /// 构造（对应 Go `newPacketNumberIndexedQueue[T](size)`）。
    pub fn new(size: usize) -> Self {
        Self {
            entries: RingBuffer::with_capacity(size),
            number_of_present_entries: 0,
            first_packet: INVALID_PACKET_NUMBER,
        }
    }

    /// 是否为空（对应 Go `IsEmpty`）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.number_of_present_entries == 0
    }

    /// 当前条目数（对应 Go `NumberOfPresentEntries`）。
    #[must_use]
    pub fn number_of_present_entries(&self) -> usize {
        self.number_of_present_entries
    }

    /// 底层 deque 槽位数（对应 Go `EntrySlotsUsed`）。
    #[must_use]
    pub fn entry_slots_used(&self) -> usize {
        self.entries.len()
    }

    /// 第一个包序号（对应 Go `FirstPacket`）。空时返回 INVALID_PACKET_NUMBER。
    #[must_use]
    pub fn first_packet(&self) -> PacketNumber {
        self.first_packet
    }

    /// 最后插入的包序号（对应 Go `LastPacket`）。空时返回 INVALID_PACKET_NUMBER。
    #[must_use]
    pub fn last_packet(&self) -> PacketNumber {
        if self.is_empty() {
            INVALID_PACKET_NUMBER
        } else {
            self.first_packet + (self.entries.len() as PacketNumber - 1)
        }
    }

    /// 插入条目（对应 Go `Emplace`）。
    ///
    /// 返回 true 表示成功插入；false 表示重复或乱序。
    pub fn emplace(&mut self, packet_number: PacketNumber, entry: T) -> bool {
        if packet_number == INVALID_PACKET_NUMBER {
            return false;
        }

        if self.is_empty() {
            self.entries.push_back(EntryWrapper { present: true, entry });
            self.number_of_present_entries = 1;
            self.first_packet = packet_number;
            return true;
        }

        // 不允许乱序：packet_number 必须 > last
        if packet_number <= self.last_packet() {
            return false;
        }

        // 填补中间空缺
        let offset = packet_number - self.first_packet;
        let gap = offset as usize - self.entries.len();
        for _ in 0..gap {
            self.entries.push_back(EntryWrapper::default());
        }

        self.entries.push_back(EntryWrapper { present: true, entry });
        self.number_of_present_entries += 1;
        true
    }

    /// 取条目引用（对应 Go `GetEntry`）。
    #[must_use]
    pub fn get_entry(&self, packet_number: PacketNumber) -> Option<&T> {
        let ew = self.get_entry_wrapper(packet_number)?;
        if ew.present { Some(&ew.entry) } else { None }
    }

    /// 取条目可变引用。
    #[must_use]
    pub fn get_entry_mut(&mut self, packet_number: PacketNumber) -> Option<&mut T> {
        // ponytail: 用 offset_mut 需要先验证 present。
        let ew = self.get_entry_wrapper(packet_number)?;
        if !ew.present {
            return None;
        }
        // 安全路径：再次通过 offset_mut 拿可变引用
        let offset = (packet_number - self.first_packet) as usize;
        let ew_mut = self.entries.offset_mut(offset);
        if ew_mut.present { Some(&mut ew_mut.entry) } else { None }
    }

    /// 删除条目（对应 Go `Remove`）。可选回调 f。
    pub fn remove(&mut self, packet_number: PacketNumber, f: Option<&dyn Fn(&T)>) -> bool {
        let present = match self.get_entry_wrapper(packet_number) {
            Some(ew) if ew.present => ew.present,
            _ => return false,
        };
        let _ = present;

        // 先回调
        if let Some(callback) = f {
            let offset = (packet_number - self.first_packet) as usize;
            let ew_ref = self.entries.offset(offset);
            if ew_ref.present {
                callback(&ew_ref.entry);
            }
        }

        // 标记 not present
        let offset = (packet_number - self.first_packet) as usize;
        let ew_mut = self.entries.offset_mut(offset);
        ew_mut.present = false;
        self.number_of_present_entries -= 1;

        // 若删的是 first，清理前缀
        if packet_number == self.first_packet {
            self.cleanup();
        }
        true
    }

    /// 删除到（不含）packet_number（对应 Go `RemoveUpTo`）。
    pub fn remove_up_to(&mut self, packet_number: PacketNumber) {
        while !self.entries.is_empty()
            && self.first_packet != INVALID_PACKET_NUMBER
            && self.first_packet < packet_number
        {
            if self.entries.front().present {
                self.number_of_present_entries -= 1;
            }
            self.entries.pop_front();
            self.first_packet += 1;
        }
        self.cleanup();
    }

    fn cleanup(&mut self) {
        while !self.entries.is_empty() && !self.entries.front().present {
            self.entries.pop_front();
            self.first_packet += 1;
        }
        if self.entries.is_empty() {
            self.first_packet = INVALID_PACKET_NUMBER;
        }
    }

    fn get_entry_wrapper(&self, packet_number: PacketNumber) -> Option<&EntryWrapper<T>> {
        if packet_number == INVALID_PACKET_NUMBER
            || self.is_empty()
            || packet_number < self.first_packet
        {
            return None;
        }
        let offset = (packet_number - self.first_packet) as usize;
        if offset >= self.entries.len() {
            return None;
        }
        Some(self.entries.offset(offset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_queue_is_empty() {
        let q: PacketNumberIndexedQueue<i32> = PacketNumberIndexedQueue::new(16);
        assert!(q.is_empty());
        assert_eq!(q.first_packet(), INVALID_PACKET_NUMBER);
        assert_eq!(q.last_packet(), INVALID_PACKET_NUMBER);
    }

    #[test]
    fn emplace_first_sets_first_packet() {
        let mut q: PacketNumberIndexedQueue<i32> = PacketNumberIndexedQueue::new(16);
        assert!(q.emplace(100, 42));
        assert_eq!(q.first_packet(), 100);
        assert_eq!(q.last_packet(), 100);
        assert_eq!(q.get_entry(100), Some(&42));
    }

    #[test]
    fn emplace_invalid_returns_false() {
        let mut q: PacketNumberIndexedQueue<i32> = PacketNumberIndexedQueue::new(16);
        assert!(!q.emplace(INVALID_PACKET_NUMBER, 1));
    }

    #[test]
    fn emplace_out_of_order_returns_false() {
        let mut q: PacketNumberIndexedQueue<i32> = PacketNumberIndexedQueue::new(16);
        assert!(q.emplace(10, 1));
        assert!(!q.emplace(10, 2)); // 同序号
        assert!(!q.emplace(5, 3)); // 更小序号
    }

    #[test]
    fn emplace_with_gap_fills() {
        let mut q: PacketNumberIndexedQueue<i32> = PacketNumberIndexedQueue::new(16);
        assert!(q.emplace(10, 100));
        assert!(q.emplace(15, 200));
        // 11..14 应被填补为 not present
        assert_eq!(q.entry_slots_used(), 6);
        assert_eq!(q.number_of_present_entries(), 2);
        assert_eq!(q.get_entry(11), None);
        assert_eq!(q.get_entry(15), Some(&200));
    }

    #[test]
    fn remove_first_triggers_cleanup() {
        let mut q: PacketNumberIndexedQueue<i32> = PacketNumberIndexedQueue::new(16);
        q.emplace(10, 100);
        q.emplace(11, 200);
        q.emplace(12, 300);
        assert!(q.remove(10, None));
        assert_eq!(q.first_packet(), 11);
    }

    #[test]
    fn remove_non_existent_returns_false() {
        let mut q: PacketNumberIndexedQueue<i32> = PacketNumberIndexedQueue::new(16);
        q.emplace(10, 100);
        assert!(!q.remove(99, None));
        assert!(!q.remove(5, None));
    }

    #[test]
    fn remove_with_callback() {
        let mut q: PacketNumberIndexedQueue<i32> = PacketNumberIndexedQueue::new(16);
        q.emplace(10, 42);
        let seen_cell = std::cell::Cell::new(0i32);
        let f: &dyn Fn(&i32) = &|v| seen_cell.set(*v);
        q.remove(10, Some(f));
        assert_eq!(seen_cell.get(), 42);
    }

    #[test]
    fn remove_up_to_clears_prefix() {
        let mut q: PacketNumberIndexedQueue<i32> = PacketNumberIndexedQueue::new(16);
        for i in 10..20 {
            q.emplace(i, i as i32 * 10);
        }
        q.remove_up_to(15);
        assert_eq!(q.first_packet(), 15);
        assert_eq!(q.number_of_present_entries(), 5);
    }

    #[test]
    fn get_entry_mut_allows_modification() {
        let mut q: PacketNumberIndexedQueue<i32> = PacketNumberIndexedQueue::new(16);
        q.emplace(10, 100);
        if let Some(v) = q.get_entry_mut(10) {
            *v = 999;
        }
        assert_eq!(q.get_entry(10), Some(&999));
    }

    #[test]
    fn last_packet_after_gap() {
        let mut q: PacketNumberIndexedQueue<i32> = PacketNumberIndexedQueue::new(16);
        q.emplace(10, 1);
        q.emplace(20, 2);
        assert_eq!(q.last_packet(), 20);
    }

    #[test]
    fn remove_middle_keeps_first() {
        let mut q: PacketNumberIndexedQueue<i32> = PacketNumberIndexedQueue::new(16);
        q.emplace(10, 100);
        q.emplace(11, 200);
        q.emplace(12, 300);
        // 删中间 11，first_packet 应保持 10
        assert!(q.remove(11, None));
        assert_eq!(q.first_packet(), 10);
        assert_eq!(q.number_of_present_entries(), 2);
    }

    #[test]
    fn remove_all_resets_to_invalid_first() {
        let mut q: PacketNumberIndexedQueue<i32> = PacketNumberIndexedQueue::new(16);
        q.emplace(10, 100);
        q.remove(10, None);
        assert_eq!(q.first_packet(), INVALID_PACKET_NUMBER);
        assert!(q.is_empty());
    }
}
