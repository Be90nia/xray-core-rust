//! RingBuffer —— 环形队列（对应 Go `congestion/bbr/ringbuffer.go`）。
//!
//! ponytail: Rust 端用 `VecDeque` 实现等价语义，避免手写环形索引。
//! 保留 grow/empty/len/front/back/offset/clear 接口语义对齐 Go。

use std::collections::VecDeque;

/// RingBuffer（对应 Go `RingBuffer[T]`）。
pub struct RingBuffer<T> {
    inner: VecDeque<T>,
}

impl<T> Default for RingBuffer<T> {
    fn default() -> Self {
        Self { inner: VecDeque::new() }
    }
}

impl<T> RingBuffer<T> {
    /// 构造（对应 Go `(r *RingBuffer[T]) Init(size int)`）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 预分配容量（对应 Go `Init`）。
    pub fn with_capacity(size: usize) -> Self {
        Self {
            inner: VecDeque::with_capacity(size),
        }
    }

    /// 长度（对应 Go `Len`）。
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// 是否为空（对应 Go `Empty`）。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// 追加（对应 Go `PushBack`，满时自动扩容）。
    pub fn push_back(&mut self, value: T) {
        self.inner.push_back(value);
    }

    /// 弹出头部（对应 Go `PopFront`）。空时 panic（与 Go 一致）。
    ///
    /// 调用前应检查 `is_empty()`。
    pub fn pop_front(&mut self) -> T {
        self.inner
            .pop_front()
            .expect("RingBuffer::pop_front on empty queue")
    }

    /// 头部引用（对应 Go `Front`）。空时 panic。
    pub fn front(&self) -> &T {
        self.inner
            .front()
            .expect("RingBuffer::front on empty queue")
    }

    /// 头部可变引用。
    pub fn front_mut(&mut self) -> &mut T {
        self.inner
            .front_mut()
            .expect("RingBuffer::front_mut on empty queue")
    }

    /// 尾部引用（对应 Go `Back`）。空时 panic。
    pub fn back(&self) -> &T {
        self.inner.back().expect("RingBuffer::back on empty queue")
    }

    /// 偏移引用（对应 Go `Offset`）。越界 panic。
    pub fn offset(&self, index: usize) -> &T {
        self.inner
            .get(index)
            .expect("RingBuffer::offset index out of range")
    }

    /// 偏移可变引用。
    pub fn offset_mut(&mut self, index: usize) -> &mut T {
        self.inner
            .get_mut(index)
            .expect("RingBuffer::offset_mut index out of range")
    }

    /// 清空（对应 Go `Clear`）。
    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty() {
        let rb: RingBuffer<i32> = RingBuffer::new();
        assert!(rb.is_empty());
        assert_eq!(rb.len(), 0);
    }

    #[test]
    fn push_pop_fifo_order() {
        let mut rb: RingBuffer<i32> = RingBuffer::new();
        rb.push_back(1);
        rb.push_back(2);
        rb.push_back(3);
        assert_eq!(rb.len(), 3);
        assert_eq!(rb.pop_front(), 1);
        assert_eq!(rb.pop_front(), 2);
        assert_eq!(rb.pop_front(), 3);
        assert!(rb.is_empty());
    }

    #[test]
    fn front_and_back() {
        let mut rb = RingBuffer::new();
        rb.push_back(10);
        rb.push_back(20);
        rb.push_back(30);
        assert_eq!(*rb.front(), 10);
        assert_eq!(*rb.back(), 30);
    }

    #[test]
    fn offset_access() {
        let mut rb = RingBuffer::new();
        rb.push_back(100);
        rb.push_back(200);
        rb.push_back(300);
        assert_eq!(*rb.offset(0), 100);
        assert_eq!(*rb.offset(1), 200);
        assert_eq!(*rb.offset(2), 300);
    }

    #[test]
    fn offset_mut_modifies() {
        let mut rb = RingBuffer::new();
        rb.push_back(1);
        rb.push_back(2);
        *rb.offset_mut(1) = 999;
        assert_eq!(*rb.offset(1), 999);
    }

    #[test]
    #[should_panic(expected = "pop_front on empty")]
    fn pop_front_empty_panics() {
        let mut rb: RingBuffer<i32> = RingBuffer::new();
        let _ = rb.pop_front();
    }

    #[test]
    #[should_panic(expected = "front on empty")]
    fn front_empty_panics() {
        let rb: RingBuffer<i32> = RingBuffer::new();
        let _ = rb.front();
    }

    #[test]
    #[should_panic(expected = "back on empty")]
    fn back_empty_panics() {
        let rb: RingBuffer<i32> = RingBuffer::new();
        let _ = rb.back();
    }

    #[test]
    #[should_panic(expected = "offset index out of range")]
    fn offset_oob_panics() {
        let mut rb = RingBuffer::new();
        rb.push_back(1);
        let _ = rb.offset(5);
    }

    #[test]
    fn clear_empties() {
        let mut rb = RingBuffer::new();
        rb.push_back(1);
        rb.push_back(2);
        rb.clear();
        assert!(rb.is_empty());
    }

    #[test]
    fn front_mut_modifies_head() {
        let mut rb = RingBuffer::new();
        rb.push_back(5);
        rb.push_back(6);
        *rb.front_mut() = 100;
        assert_eq!(*rb.front(), 100);
    }

    #[test]
    fn with_capacity_does_not_allocate_more_than_needed() {
        let rb: RingBuffer<i32> = RingBuffer::with_capacity(100);
        // 仅验证不 panic 且为空
        assert!(rb.is_empty());
    }

    #[test]
    fn many_pushes_pop_correctly() {
        let mut rb = RingBuffer::new();
        for i in 0..1000 {
            rb.push_back(i);
        }
        for i in 0..500 {
            assert_eq!(rb.pop_front(), i);
        }
        assert_eq!(rb.len(), 500);
        assert_eq!(*rb.front(), 500);
        assert_eq!(*rb.back(), 999);
    }
}
