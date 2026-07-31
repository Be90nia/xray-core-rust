//! 核心 Buffer 结构
//!
//! 对应 Go 版本 `common/buf.Buffer`，封装 `BytesMut` 并维护读写游标。
//! Buffer 是单所有权的（Rust 所有权系统天然保证），不需要 Go 中的 ownership enum。

use bytes::{Bytes, BytesMut};

use crate::alloc;

/// 核心缓冲区，封装 `BytesMut` 并维护读写游标。
///
/// - `start`: 读游标（已读数据起始位置）
/// - `end`: 写游标（已写数据结束位置）
///
/// 有效数据范围: `inner[start..end]`
///
/// 对应 Go 版本的 `buf.Buffer`，但利用 Rust 所有权系统消除了 Go 的 ownership 枚举。
#[must_use = "Buffer 持有池化内存，丢弃前应调用 release() 或让 Drop 自动回收"]
pub struct Buffer {
    inner: BytesMut,
    start: usize,
    end: usize,
    /// UDP 目的地覆盖，对应 Go `buf.Buffer.UDP`。
    /// 当 Buffer 承载 UDP 数据时，此字段记录目标地址，
    /// 用于 UDP NAT 和 endpoint override 场景。
    udp: Option<std::net::SocketAddr>,
}

impl Buffer {
    // ========== 构造函数 ==========

    /// 从池中分配默认大小 (8KB) 的缓冲区。
    ///
    /// 对应 Go 的 `New()` 构造函数。
    pub fn new() -> Self {
        let inner = alloc::alloc(alloc::DEFAULT_SIZE);
        Self {
            inner,
            start: 0,
            end: 0,
            udp: None,
        }
    }

    /// 分配指定大小的缓冲区（直接分配，不经过池）。
    ///
    /// 对应 Go 的 `NewWithSize(size)`，创建精确大小的非池化缓冲区。
    /// 如需池化分配，使用 [`Buffer::new()`]。
    pub fn with_capacity(size: usize) -> Self {
        let inner = BytesMut::with_capacity(size);
        Self {
            inner,
            start: 0,
            end: 0,
            udp: None,
        }
    }

    /// 从外部数据构造缓冲区（非池化管理）。
    ///
    /// 写游标设置为数据末尾，即所有数据都可读。
    /// 释放时容量不匹配池分层会直接丢弃。
    pub fn from_bytes(data: impl Into<BytesMut>) -> Self {
        let inner = data.into();
        let end = inner.len();
        Self {
            inner,
            start: 0,
            end,
            udp: None,
        }
    }

    /// 从 Vec 构造缓冲区。
    pub fn from_vec(data: Vec<u8>) -> Self {
        let len = data.len();
        let mut inner = BytesMut::with_capacity(len);
        inner.extend_from_slice(&data);
        Self {
            inner,
            start: 0,
            end: len,
            udp: None,
        }
    }

    // ========== 读操作 ==========

    /// 返回缓冲区中未读数据的字节数。
    ///
    /// 对应 Go 的 `Buffer.Len()`。
    #[inline]
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// 缓冲区是否为空（无未读数据）。
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// 返回未读数据的字节切片引用。
    ///
    /// 对应 Go 的 `Buffer.Bytes()`。
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        &self.inner[self.start..self.end]
    }

    /// 将读游标前进 n 字节（跳过 n 字节数据）。
    ///
    /// 对应 Go 的 `Buffer.Advance()`。
    ///
    /// # Panics
    /// 如果 n 超过未读数据长度会 panic。
    pub fn advance(&mut self, n: usize) {
        assert!(
            n <= self.len(),
            "advance {n} 超过未读数据长度 {}",
            self.len()
        );
        self.start += n;
    }

    /// 从缓冲区读取数据到 `dst`，返回实际读取的字节数。
    ///
    /// 对应 Go 的 `Buffer.Read()`。
    pub fn read_to(&mut self, dst: &mut [u8]) -> usize {
        let n = self.len().min(dst.len());
        dst[..n].copy_from_slice(&self.inner[self.start..self.start + n]);
        self.start += n;
        n
    }

    /// 读取单个字节。
    pub fn read_byte(&mut self) -> Option<u8> {
        if self.is_empty() {
            return None;
        }
        let b = self.inner[self.start];
        self.start += 1;
        Some(b)
    }

    // ========== 写操作 ==========

    /// 返回缓冲区总容量。
    #[inline]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// 返回剩余可写空间。
    ///
    /// 对应 Go 的 `Buffer.Free()`。
    #[inline]
    pub fn free(&self) -> usize {
        self.inner.capacity() - self.end
    }

    /// 返回可写区域的可变引用（end 之后的空间）。
    ///
    /// 用于直接写入操作（如系统调用 read）。
    /// 注意：返回的切片长度为 BytesMut 的剩余容量，不是 free()。
    pub fn writable_bytes(&mut self) -> &mut [u8] {
        let end = self.end;
        let cap = self.inner.capacity();
        // SAFETY: 扩展 len 到 capacity 以暴露可写区域
        if cap > self.inner.len() {
            unsafe {
                self.inner.set_len(cap);
            }
        }
        &mut self.inner[end..]
    }

    /// 将写游标前进 n 字节（确认写入了 n 字节）。
    ///
    /// # Panics
    /// 如果 n 超过剩余可写空间会 panic。
    pub fn advance_write(&mut self, n: usize) {
        let new_end = self.end + n;
        assert!(
            new_end <= self.inner.capacity(),
            "advance_write {n} 超过可写空间 (end={}, cap={})",
            self.end,
            self.inner.capacity()
        );
        // 确保 BytesMut 知道数据已写入
        if new_end > self.inner.len() {
            // SAFETY: 我们只在已分配的 capacity 范围内扩展 length，
            // 调用方负责确保通过 writable_bytes() 写入了有效数据。
            unsafe {
                self.inner.set_len(new_end);
            }
        }
        self.end = new_end;
    }

    /// 从 `src` 写入数据到缓冲区，返回实际写入的字节数。
    ///
    /// 对应 Go 的 `Buffer.Write()`。只写入可用空间允许的量。
    pub fn write_from(&mut self, src: &[u8]) -> usize {
        let available = self.free();
        let n = src.len().min(available);
        if n == 0 {
            return 0;
        }
        let end = self.end;
        let new_end = end + n;
        // SAFETY: BytesMut::with_capacity 创建 len=0 但 capacity>0 的缓冲区。
        // 我们需要先扩展 len 到目标位置，然后写入数据。
        // 这是安全的因为 capacity 足够（available 已检查）且我们会立即填充数据。
        if new_end > self.inner.len() {
            unsafe {
                self.inner.set_len(new_end);
            }
        }
        self.inner[end..new_end].copy_from_slice(&src[..n]);
        self.end = new_end;
        n
    }

    /// 写入单个字节，成功返回 `true`，缓冲区满返回 `false`。
    pub fn write_byte(&mut self, b: u8) -> bool {
        if self.free() == 0 {
            return false;
        }
        let end = self.end;
        let new_end = end + 1;
        // SAFETY: 同 write_from，先扩展 len 再写入
        if new_end > self.inner.len() {
            unsafe {
                self.inner.set_len(new_end);
            }
        }
        self.inner[end] = b;
        self.end = new_end;
        true
    }

    /// 将 `Bytes` 数据写入缓冲区末尾。
    ///
    /// 如果剩余空间不足，会扩展内部存储（非池化行为）。
    /// 对应 Go 的 `Buffer.Write()`。
    pub fn put(&mut self, b: impl Into<Bytes>) {
        let data = b.into();
        let data_len = data.len();
        if data_len == 0 {
            return;
        }
        let new_end = self.end + data_len;
        // 确保有足够的 capacity
        if new_end > self.inner.capacity() {
            self.inner.resize(new_end, 0);
        }
        // SAFETY: 扩展 len 以覆盖写入区域
        if new_end > self.inner.len() {
            unsafe {
                self.inner.set_len(new_end);
            }
        }
        self.inner[self.end..new_end].copy_from_slice(&data);
        self.end = new_end;
    }

    // ========== 工具方法 ==========

    /// 重置缓冲区（丢弃所有未读数据，游标归零）。
    ///
    /// 对应 Go 的 `Buffer.Clear()`。
    pub fn clear(&mut self) {
        self.start = 0;
        self.end = 0;
        self.udp = None;
    }

    /// 截断缓冲区，仅保留前 n 字节未读数据。
    ///
    /// 如果 n 大于当前长度则不做任何操作。
    pub fn truncate(&mut self, n: usize) {
        if n < self.len() {
            self.end = self.start + n;
        }
    }

    /// 获取 UDP 目的地覆盖。
    ///
    /// 对应 Go 的 `buf.Buffer.UDP`。
    /// 当 Buffer 承载 UDP 数据时，此字段记录目标地址。
    #[inline]
    pub fn udp(&self) -> Option<std::net::SocketAddr> {
        self.udp
    }

    /// 设置 UDP 目的地覆盖。
    ///
    /// 对应 Go 的 `buf.Buffer.UDP = dest`。
    /// 用于 UDP NAT 和 endpoint override 场景。
    #[inline]
    pub fn set_udp(&mut self, dest: Option<std::net::SocketAddr>) {
        self.udp = dest;
    }

    /// 从缓冲区前端分割出 n 字节，返回新的 Buffer。
    ///
    /// 对应 Go 的 `Buffer.Slice()` 和分割操作。
    /// 原缓冲区的读游标前进 n 字节。
    ///
    /// # Panics
    /// 如果 n 超过未读数据长度会 panic。
    pub fn split_to(&mut self, n: usize) -> Buffer {
        assert!(
            n <= self.len(),
            "split_to {n} 超过未读数据长度 {}",
            self.len()
        );
        let split_end = self.start + n;
        let mut new_inner = BytesMut::with_capacity(n);
        new_inner.extend_from_slice(&self.inner[self.start..split_end]);
        self.start = split_end;
        Buffer {
            inner: new_inner,
            start: 0,
            end: n,
            udp: None,
        }
    }

    /// 在 n 字节处分割，保留后段，返回前段。
    ///
    /// 原缓冲区保留第 n 字节之后的数据。
    pub fn split_off(&mut self, n: usize) -> Buffer {
        assert!(
            n <= self.len(),
            "split_off {n} 超过未读数据长度 {}",
            self.len()
        );
        let split_end = self.start + n;
        let mut new_inner = BytesMut::with_capacity(n);
        new_inner.extend_from_slice(&self.inner[self.start..split_end]);
        self.start = split_end;
        Buffer {
            inner: new_inner,
            start: 0,
            end: n,
            udp: None,
        }
    }

    /// 消费缓冲区，返回 `Bytes`（零拷贝冻结）。
    ///
    /// 对应 Go 的将 Buffer 内容转为字节切片的场景。
    pub fn into_bytes(mut self) -> Bytes {
        let data = self.inner.split_off(self.start);
        self.start = 0;
        self.end = 0;
        data.freeze()
    }

    /// 调整缓冲区大小。
    ///
    /// - 如果 new_len < 当前长度，截断
    /// - 如果 new_len > 当前长度，用零填充
    pub fn resize(&mut self, new_len: usize) {
        let current = self.len();
        if new_len <= current {
            self.end = self.start + new_len;
            return;
        }
        let extra = new_len - current;
        let needed = self.end + extra;
        // 使用 resize 扩展并填充零
        if needed > self.inner.len() {
            self.inner.resize(needed, 0);
        } else {
            // 已有足够 len，只需填充零
            for i in self.end..needed {
                self.inner[i] = 0;
            }
        }
        self.end = needed;
    }

    // ========== 释放/回收 ==========

    /// 释放缓冲区回池中。
    ///
    /// 对应 Go 的 `Buffer.Release()`。重置游标并归还 `BytesMut` 到分配池。
    pub fn release(&mut self) {
        self.start = 0;
        self.end = 0;
        self.udp = None;
        // 将 inner 替换为空，把旧的归还池中
        let old = std::mem::replace(&mut self.inner, BytesMut::new());
        alloc::release(old);
    }

    /// 检查缓冲区是否已释放（inner 为空）。
    #[inline]
    pub fn is_released(&self) -> bool {
        self.inner.capacity() == 0
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        if self.inner.capacity() > 0 {
            self.start = 0;
            self.end = 0;
            let old = std::mem::replace(&mut self.inner, BytesMut::new());
            alloc::release(old);
        }
    }
}

// ========== Trait 实现 ==========

impl std::fmt::Debug for Buffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Buffer")
            .field("len", &self.len())
            .field("capacity", &self.capacity())
            .field("start", &self.start)
            .field("end", &self.end)
            .field("udp", &self.udp)
            .finish()
    }
}

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        self.bytes()
    }
}

impl AsMut<[u8]> for Buffer {
    fn as_mut(&mut self) -> &mut [u8] {
        let start = self.start;
        let end = self.end;
        &mut self.inner[start..end]
    }
}

impl Default for Buffer {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for Buffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = String::from_utf8_lossy(self.bytes());
        write!(f, "{s}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        alloc::clear();
    }

    #[test]
    fn test_new_buffer() {
        init();
        let buf = Buffer::new();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert!(buf.capacity() >= alloc::DEFAULT_SIZE);
    }

    #[test]
    fn test_with_capacity() {
        init();
        let buf = Buffer::with_capacity(1024);
        assert!(buf.is_empty());
        assert!(buf.capacity() >= 1024);
    }

    #[test]
    fn test_from_bytes() {
        let buf = Buffer::from_bytes(BytesMut::from("hello"));
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.bytes(), b"hello");
    }

    #[test]
    fn test_from_vec() {
        let buf = Buffer::from_vec(vec![1, 2, 3, 4, 5]);
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.bytes(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_write_read() {
        init();
        let mut buf = Buffer::new();
        let written = buf.write_from(b"hello world");
        assert_eq!(written, 11);
        assert_eq!(buf.len(), 11);

        let mut dst = [0u8; 5];
        let read = buf.read_to(&mut dst);
        assert_eq!(read, 5);
        assert_eq!(&dst, b"hello");
        assert_eq!(buf.len(), 6);
        assert_eq!(buf.bytes(), b" world");
    }

    #[test]
    fn test_write_byte() {
        init();
        let mut buf = Buffer::new();
        assert!(buf.write_byte(0x41));
        assert!(buf.write_byte(0x42));
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.bytes(), b"AB");
    }

    #[test]
    fn test_read_byte() {
        let buf = Buffer::from_bytes(BytesMut::from("ABC"));
        let mut buf = buf;
        assert_eq!(buf.read_byte(), Some(b'A'));
        assert_eq!(buf.read_byte(), Some(b'B'));
        assert_eq!(buf.read_byte(), Some(b'C'));
        assert_eq!(buf.read_byte(), None);
    }

    #[test]
    fn test_advance() {
        let mut buf = Buffer::from_bytes(BytesMut::from("hello"));
        buf.advance(2);
        assert_eq!(buf.bytes(), b"llo");
        assert_eq!(buf.len(), 3);
    }

    #[test]
    #[should_panic]
    fn test_advance_overflow() {
        let mut buf = Buffer::from_bytes(BytesMut::from("hi"));
        buf.advance(10);
    }

    #[test]
    fn test_free_space() {
        init();
        let buf = Buffer::new();
        let cap = buf.capacity();
        assert_eq!(buf.free(), cap);
        drop(buf);
    }

    #[test]
    fn test_writable_bytes_and_advance_write() {
        init();
        let mut buf = Buffer::new();
        let writable = buf.writable_bytes();
        assert!(writable.len() >= alloc::DEFAULT_SIZE);

        // 模拟直接写入
        let data = b"direct";
        buf.writable_bytes()[..data.len()].copy_from_slice(data);
        buf.advance_write(data.len());
        assert_eq!(buf.len(), 6);
        assert_eq!(buf.bytes(), b"direct");
    }

    #[test]
    fn test_put() {
        init();
        let mut buf = Buffer::new();
        buf.put(Bytes::from("hello"));
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.bytes(), b"hello");
    }

    #[test]
    fn test_clear() {
        let mut buf = Buffer::from_bytes(BytesMut::from("hello"));
        assert_eq!(buf.len(), 5);
        buf.clear();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_truncate() {
        let mut buf = Buffer::from_bytes(BytesMut::from("hello world"));
        buf.truncate(5);
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.bytes(), b"hello");
    }

    #[test]
    fn test_truncate_larger() {
        let mut buf = Buffer::from_bytes(BytesMut::from("hi"));
        buf.truncate(100);
        assert_eq!(buf.len(), 2); // 不变
    }

    #[test]
    fn test_split_to() {
        let mut buf = Buffer::from_bytes(BytesMut::from("hello world"));
        let front = buf.split_to(5);
        assert_eq!(front.bytes(), b"hello");
        assert_eq!(buf.bytes(), b" world");
    }

    #[test]
    fn test_split_off() {
        let mut buf = Buffer::from_bytes(BytesMut::from("hello world"));
        let front = buf.split_off(5);
        assert_eq!(front.bytes(), b"hello");
        assert_eq!(buf.bytes(), b" world");
    }

    #[test]
    fn test_into_bytes() {
        let buf = Buffer::from_bytes(BytesMut::from("hello"));
        let bytes = buf.into_bytes();
        assert_eq!(&bytes[..], b"hello");
    }

    #[test]
    fn test_resize_shrink() {
        let mut buf = Buffer::from_bytes(BytesMut::from("hello world"));
        buf.resize(5);
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.bytes(), b"hello");
    }

    #[test]
    fn test_resize_grow() {
        init();
        let mut buf = Buffer::with_capacity(64);
        buf.write_from(b"hi");
        buf.resize(10);
        assert_eq!(buf.len(), 10);
        assert_eq!(&buf.bytes()[..2], b"hi");
        // 扩展部分应为零
        assert_eq!(&buf.bytes()[2..], &[0u8; 8]);
    }

    #[test]
    fn test_release() {
        init();
        let mut buf = Buffer::new();
        buf.write_from(b"data");
        buf.release();
        assert!(buf.is_released());
        assert!(buf.is_empty());
    }

    #[test]
    fn test_drop_auto_release() {
        init();
        {
            let mut buf = Buffer::new();
            buf.write_from(b"temporary");
        }
        // Drop 应该已将缓冲区归还池中
    }

    #[test]
    fn test_debug_format() {
        let buf = Buffer::from_bytes(BytesMut::from("test"));
        let debug = format!("{buf:?}");
        assert!(debug.contains("len: 4"));
        assert!(debug.contains("capacity"));
    }

    #[test]
    fn test_as_ref() {
        let buf = Buffer::from_bytes(BytesMut::from("hello"));
        assert_eq!(buf.as_ref(), b"hello");
    }

    #[test]
    fn test_as_mut() {
        let mut buf = Buffer::from_bytes(BytesMut::from("hello"));
        buf.as_mut()[0] = b'H';
        assert_eq!(buf.bytes(), b"Hello");
    }

    #[test]
    fn test_display() {
        let buf = Buffer::from_bytes(BytesMut::from("hello"));
        assert_eq!(format!("{buf}"), "hello");
    }

    #[test]
    fn test_default() {
        init();
        let buf = Buffer::default();
        assert!(buf.is_empty());
    }

    #[test]
    fn test_large_write() {
        init();
        let mut buf = Buffer::new();
        let data = vec![0xABu8; 7000];
        let written = buf.write_from(&data);
        assert_eq!(written, 7000);
        assert_eq!(buf.len(), 7000);
    }

    #[test]
    fn test_write_full_buffer() {
        init();
        let mut buf = Buffer::with_capacity(8);
        let written = buf.write_from(b"12345678");
        assert_eq!(written, 8);
        // 再写应该失败（0 字节）
        let written2 = buf.write_from(b"9");
        assert_eq!(written2, 0);
    }

    #[test]
    fn test_write_byte_full() {
        init();
        let mut buf = Buffer::with_capacity(2);
        assert!(buf.write_byte(1));
        assert!(buf.write_byte(2));
        assert!(!buf.write_byte(3)); // 满了
    }

    #[test]
    fn test_read_to_partial() {
        let mut buf = Buffer::from_bytes(BytesMut::from("hello"));
        let mut dst = [0u8; 3];
        let n = buf.read_to(&mut dst);
        assert_eq!(n, 3);
        assert_eq!(&dst, b"hel");
        assert_eq!(buf.bytes(), b"lo");
    }

    #[test]
    fn test_read_to_dst_larger() {
        let mut buf = Buffer::from_bytes(BytesMut::from("hi"));
        let mut dst = [0u8; 10];
        let n = buf.read_to(&mut dst);
        assert_eq!(n, 2);
        assert_eq!(&dst[..2], b"hi");
    }

    #[test]
    fn test_udp_field_default_none() {
        let buf = Buffer::new();
        assert!(buf.udp().is_none());
    }

    #[test]
    fn test_udp_set_and_get() {
        let mut buf = Buffer::new();
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8080));
        buf.set_udp(Some(addr));
        assert_eq!(buf.udp(), Some(addr));
    }

    #[test]
    fn test_udp_cleared_on_clear() {
        let mut buf = Buffer::new();
        buf.set_udp(Some(std::net::SocketAddr::from(([127, 0, 0, 1], 9090))));
        buf.clear();
        assert!(buf.udp().is_none());
    }

    #[test]
    fn test_udp_cleared_on_release() {
        init();
        let mut buf = Buffer::new();
        buf.set_udp(Some(std::net::SocketAddr::from(([127, 0, 0, 1], 9090))));
        buf.release();
        assert!(buf.udp().is_none());
    }

    #[test]
    fn test_udp_not_carried_to_split() {
        let mut buf = Buffer::from_bytes(BytesMut::from("hello world"));
        buf.set_udp(Some(std::net::SocketAddr::from(([192, 168, 1, 1], 53))));
        let front = buf.split_to(5);
        // Split buffer 不继承 udp（新 Buffer 从 split 产生，语义上属于不同的数据包）
        assert!(front.udp().is_none());
    }
}
