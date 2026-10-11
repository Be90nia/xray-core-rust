//! 核心 Buffer 结构
//!
//! 对应 Go 版本 `common/buf.Buffer`，封装 `BytesMut` 并维护读写游标。
//! Buffer 是单所有权的（Rust 所有权系统天然保证）；
//! [`Buffer::from_bytes_frozen`] 补回 Go ownership enum 的只读形态
//! （oracle v1 §2.2-3）：外部 `Bytes` 零拷贝进入 relay，Drop 不回池。

use bytes::{Buf, Bytes, BytesMut};

use crate::alloc;

/// Buffer 内部存储双态。
enum Inner {
    /// 池化管理：Drop / release 归还分配池。
    Pooled(BytesMut),
    /// 外部所有权冻结只读（hyper/h2 chunk 经 [`Buffer::from_bytes_frozen`] 进入）。
    /// 非池来源：Drop 直接释放。首次可变访问写时复制（引用计数唯一则零拷贝转正）。
    Frozen(Bytes),
}

/// 核心缓冲区，封装 `BytesMut`（或冻结 `Bytes`）并维护读写游标。
///
/// - `start`: 读游标（已读数据起始位置）
/// - `end`: 写游标（已写数据结束位置）
///
/// 有效数据范围: `inner[start..end]`
#[must_use = "Buffer 持有池化内存，丢弃前应调用 release() 或让 Drop 自动回收"]
pub struct Buffer {
    inner: Inner,
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
        Self { inner: Inner::Pooled(inner), start: 0, end: 0, udp: None }
    }

    /// 分配指定大小的缓冲区（直接分配，不经过池）。
    ///
    /// 对应 Go 的 `NewWithSize(size)`，创建精确大小的非池化缓冲区。
    /// 如需池化分配，使用 [`Buffer::new()`]。
    pub fn with_capacity(size: usize) -> Self {
        let inner = BytesMut::with_capacity(size);
        Self { inner: Inner::Pooled(inner), start: 0, end: 0, udp: None }
    }

    /// 从外部数据构造缓冲区（非池化管理）。
    ///
    /// 写游标设置为数据末尾，即所有数据都可读。
    /// 释放时容量不匹配池分层会直接丢弃。
    pub fn from_bytes(data: impl Into<BytesMut>) -> Self {
        let inner = data.into();
        let end = inner.len();
        Self { inner: Inner::Pooled(inner), start: 0, end, udp: None }
    }

    /// 持有外部 `Bytes`（零拷贝只读入口，所有权转移 freeze）。
    ///
    /// 对应 Go ownership enum 的只读形态（oracle v1 §2.2-3）：hyper/h2 产出的
    /// `Bytes` 无拷贝进入 Buffer/MultiBuffer relay。语义要点：
    /// - **所有权转移**：`Bytes` move 进 Buffer，全程零拷贝；
    /// - **Drop 不回池**：frozen 来源非池，Drop 直接释放（与池化路径的关口）；
    /// - 需要可变访问（`as_mut`/写路径）时写时复制：引用计数唯一则 零拷贝转正，共享（如
    ///   `BytesMut::split_to().freeze()` 的姊妹份 仍存活）才真实拷贝。
    pub fn from_bytes_frozen(data: Bytes) -> Self {
        let end = data.len();
        Self { inner: Inner::Frozen(data), start: 0, end, udp: None }
    }

    /// 从 Vec 构造缓冲区。
    pub fn from_vec(data: Vec<u8>) -> Self {
        let len = data.len();
        let mut inner = BytesMut::with_capacity(len);
        inner.extend_from_slice(&data);
        Self { inner: Inner::Pooled(inner), start: 0, end: len, udp: None }
    }

    /// 写路径统一入口：`Frozen` → `Pooled` 写时复制（COW）。
    ///
    /// frozen 是非池只读所有权，首次可变访问转正为普通 `BytesMut`；
    /// 引用计数唯一走 `try_into_mut` 零拷贝，共享才真实拷贝——永不 panic，
    /// 只读 relay 热路径（`bytes()`/`advance`/`split_to`）完全不经过这里。
    fn pooled_mut(&mut self) -> &mut BytesMut {
        if let Inner::Frozen(data) = &mut self.inner {
            let owned = std::mem::take(data);
            let converted = match owned.try_into_mut() {
                Ok(vec) => vec,
                Err(shared) => {
                    let mut m = BytesMut::with_capacity(shared.len());
                    m.extend_from_slice(&shared);
                    m
                },
            };
            self.inner = Inner::Pooled(converted);
        }
        match &mut self.inner {
            Inner::Pooled(m) => m,
            Inner::Frozen(_) => unreachable!("上一分支已转正"),
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
        match &self.inner {
            Inner::Pooled(m) => &m[self.start..self.end],
            Inner::Frozen(b) => &b[self.start..self.end],
        }
    }

    /// 返回索引 `index` 处的字节（相对于未读数据起始位置）。
    ///
    /// 对应 Go 的 `Buffer.Byte(index)`。`index=0` 表示第一个未读字节。
    ///
    /// # Panics
    /// 如果 `index >= len()` 会 panic。
    #[inline]
    pub fn byte(&self, index: usize) -> u8 {
        assert!(index < self.len(), "byte index {index} 超过未读数据长度 {}", self.len());
        self.bytes()[index]
    }

    /// 设置索引 `index` 处的字节为 `value`（相对于未读数据起始位置）。
    ///
    /// 对应 Go 的 `Buffer.SetByte(index, value)`。`index=0` 表示第一个未读字节。
    ///
    /// # Panics
    /// 如果 `index >= len()` 会 panic。
    #[inline]
    pub fn set_byte(&mut self, index: usize, value: u8) {
        assert!(index < self.len(), "set_byte index {index} 超过未读数据长度 {}", self.len());
        let idx = self.start + index;
        self.pooled_mut()[idx] = value;
    }

    /// 将读游标前进 n 字节（跳过 n 字节数据）。
    /// 对应 Go 的 `Buffer.Advance()`。
    ///
    /// # Panics
    /// 如果 n 超过未读数据长度会 panic。
    pub fn advance(&mut self, n: usize) {
        assert!(n <= self.len(), "advance {n} 超过未读数据长度 {}", self.len());
        self.start += n;
    }

    /// 从缓冲区读取数据到 `dst`，返回实际读取的字节数。
    ///
    /// 对应 Go 的 `Buffer.Read()`。
    pub fn read_to(&mut self, dst: &mut [u8]) -> usize {
        let n = self.len().min(dst.len());
        dst[..n].copy_from_slice(&self.bytes()[..n]);
        self.start += n;
        n
    }

    /// 读取单个字节。
    pub fn read_byte(&mut self) -> Option<u8> {
        if self.is_empty() {
            return None;
        }
        let b = self.byte(0);
        self.start += 1;
        Some(b)
    }

    // ========== 写操作 ==========

    /// 返回缓冲区总容量。
    ///
    /// Frozen 变体无可写容量（返回数据长度，`free()` 恒为 0）。
    #[inline]
    pub fn capacity(&self) -> usize {
        match &self.inner {
            Inner::Pooled(m) => m.capacity(),
            Inner::Frozen(b) => b.len(),
        }
    }

    /// 返回剩余可写空间。
    ///
    /// 对应 Go 的 `Buffer.Free()`。
    #[inline]
    pub fn free(&self) -> usize {
        self.capacity() - self.end
    }

    /// 返回可写区域的可变引用（end 之后的空间）。
    ///
    /// 用于直接写入操作（如系统调用 read）。
    /// 注意：返回的切片长度为 BytesMut 的剩余容量，不是 free()。
    pub fn writable_bytes(&mut self) -> &mut [u8] {
        let end = self.end;
        let m = self.pooled_mut();
        let cap = m.capacity();
        // SAFETY: 扩展 len 到 capacity 以暴露可写区域
        if cap > m.len() {
            unsafe {
                m.set_len(cap);
            }
        }
        &mut m[end..]
    }

    /// 将写游标前进 n 字节（确认写入了 n 字节）。
    ///
    /// # Panics
    /// 如果 n 超过剩余可写空间会 panic。
    pub fn advance_write(&mut self, n: usize) {
        let new_end = self.end + n;
        assert!(
            new_end <= self.capacity(),
            "advance_write {n} 超过可写空间 (end={}, cap={})",
            self.end,
            self.capacity()
        );
        let m = self.pooled_mut();
        // 确保 BytesMut 知道数据已写入
        if new_end > m.len() {
            // SAFETY: 我们只在已分配的 capacity 范围内扩展 length，
            // 调用方负责确保通过 writable_bytes() 写入了有效数据。
            unsafe {
                m.set_len(new_end);
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
        {
            let m = self.pooled_mut();
            // SAFETY: free() 已确认容量充足（Pooled 变体 capacity>=end+n），
            // 先扩展 len 到目标位置再填充数据。
            if new_end > m.len() {
                unsafe {
                    m.set_len(new_end);
                }
            }
            m[end..new_end].copy_from_slice(&src[..n]);
        }
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
        {
            let m = self.pooled_mut();
            // SAFETY: 同 write_from，free() 已确认容量充足
            if new_end > m.len() {
                unsafe {
                    m.set_len(new_end);
                }
            }
            m[end] = b;
        }
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
        let end = self.end;
        {
            let m = self.pooled_mut();
            // 确保有足够的 capacity
            if new_end > m.capacity() {
                m.resize(new_end, 0);
            }
            // SAFETY: 扩展 len 以覆盖写入区域
            if new_end > m.len() {
                unsafe {
                    m.set_len(new_end);
                }
            }
            m[end..new_end].copy_from_slice(&data);
        }
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
        // Frozen 非池来源没有「可清后复用」语义：丢弃 Bytes 并转出一份
        // 池化空缓冲，保证 clear 后的写路径仍走池化（与 Pooled 行为一致）。
        if let Inner::Frozen(b) = &mut self.inner {
            *b = Bytes::new();
            self.inner = Inner::Pooled(alloc::alloc(alloc::DEFAULT_SIZE));
        }
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
    /// 双态均零拷贝：Pooled 走 `BytesMut` 引用计数分割（O(1)），Frozen 走
    /// `Bytes::slice`（姊妹份共享底层分配，与 `BytesMut::split_to().freeze()`
    /// 的零拷贝语义同源）。
    ///
    /// # Panics
    /// 如果 n 超过未读数据长度会 panic。
    pub fn split_to(&mut self, n: usize) -> Buffer {
        assert!(n <= self.len(), "split_to {n} 超过未读数据长度 {}", self.len());
        let split_end = self.start + n;
        let remaining = self.len() - n;
        let new_inner = match &mut self.inner {
            Inner::Pooled(m) => {
                // O(1) 引用计数分割：先摘走已读前缀，再摘出前 n 字节；
                // 原缓冲余量随之从 0 起（end 之后不可见区保持不可见）
                if self.start > 0 {
                    m.advance(self.start);
                }
                let front = m.split_to(n);
                self.start = 0;
                self.end = remaining;
                Inner::Pooled(front)
            },
            Inner::Frozen(b) => {
                // 底层不动：返回切片，原缓冲纯游标推进
                let front = b.slice(self.start..split_end);
                self.start = split_end;
                Inner::Frozen(front)
            },
        };
        Buffer { inner: new_inner, start: 0, end: n, udp: None }
    }

    /// 在 n 字节处分割，保留后段，返回前段。
    ///
    /// 原缓冲区保留第 n 字节之后的数据。零拷贝语义同 [`Buffer::split_to`]。
    pub fn split_off(&mut self, n: usize) -> Buffer {
        assert!(n <= self.len(), "split_off {n} 超过未读数据长度 {}", self.len());
        let split_end = self.start + n;
        let remaining = self.len() - n;
        let new_inner = match &mut self.inner {
            Inner::Pooled(m) => {
                if self.start > 0 {
                    m.advance(self.start);
                }
                let front = m.split_to(n);
                self.start = 0;
                self.end = remaining;
                Inner::Pooled(front)
            },
            Inner::Frozen(b) => {
                let front = b.slice(self.start..split_end);
                self.start = split_end;
                Inner::Frozen(front)
            },
        };
        Buffer { inner: new_inner, start: 0, end: n, udp: None }
    }

    /// 消费缓冲区，返回 `Bytes`（零拷贝冻结）。
    ///
    /// 对应 Go 的将 Buffer 内容转为字节切片的场景。
    pub fn into_bytes(mut self) -> Bytes {
        match &mut self.inner {
            Inner::Pooled(m) => {
                if self.start > 0 {
                    m.advance(self.start);
                }
                m.split().freeze()
            },
            Inner::Frozen(b) => b.slice(self.start..self.end),
        }
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
        let end = self.end;
        {
            let m = self.pooled_mut();
            // 使用 resize 扩展并填充零
            if needed > m.len() {
                m.resize(needed, 0);
            } else {
                // 已有足够 len，只需填充零
                for i in end..needed {
                    m[i] = 0;
                }
            }
        }
        self.end = needed;
    }

    // ========== 释放/回收 ==========

    /// 释放缓冲区回池中。
    ///
    /// 对应 Go 的 `Buffer.Release()`。重置游标并归还 `BytesMut` 到分配池。
    /// Frozen 变体（[`Buffer::from_bytes_frozen`] 非池来源）直接释放，**不回池**。
    pub fn release(&mut self) {
        self.start = 0;
        self.end = 0;
        self.udp = None;
        match &mut self.inner {
            Inner::Pooled(m) => {
                // 将 inner 替换为空，把旧的归还池中
                let old = std::mem::replace(m, BytesMut::new());
                alloc::release(old);
            },
            Inner::Frozen(b) => *b = Bytes::new(),
        }
    }

    /// 检查缓冲区是否已释放（inner 为空）。
    #[inline]
    pub fn is_released(&self) -> bool {
        match &self.inner {
            Inner::Pooled(m) => m.capacity() == 0,
            Inner::Frozen(b) => b.is_empty(),
        }
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        // 只有池化分支回池；Frozen 非池来源随 Bytes 引用计数自然释放。
        if let Inner::Pooled(m) = &mut self.inner {
            if m.capacity() > 0 {
                self.start = 0;
                self.end = 0;
                let old = std::mem::replace(m, BytesMut::new());
                alloc::release(old);
            }
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
        &mut self.pooled_mut()[start..end]
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

    #[test]
    fn test_set_byte_basic() {
        let mut buf = Buffer::from_bytes(BytesMut::from("hello"));
        buf.set_byte(0, b'H');
        buf.set_byte(4, b'X');
        assert_eq!(buf.bytes(), b"HellX");
    }

    #[test]
    fn test_byte_basic() {
        let buf = Buffer::from_bytes(BytesMut::from("hello"));
        assert_eq!(buf.byte(0), b'h');
        assert_eq!(buf.byte(1), b'e');
        assert_eq!(buf.byte(4), b'o');
    }

    #[test]
    fn test_byte_after_advance() {
        // Byte 索引是相对于未读数据起始位置的全局 index。
        let mut buf = Buffer::from_bytes(BytesMut::from("hello"));
        buf.advance(2);
        assert_eq!(buf.byte(0), b'l');
        assert_eq!(buf.byte(2), b'o');
    }

    #[test]
    fn test_set_byte_after_advance() {
        // advance(2) 后未读数据为 "llo"（len=3），set_byte(0,'L') → "Llo"。
        let mut buf = Buffer::from_bytes(BytesMut::from("hello"));
        buf.advance(2);
        buf.set_byte(0, b'L');
        assert_eq!(buf.bytes(), b"Llo");
        assert_eq!(buf.byte(2), b'o');
    }

    // ========== from_bytes_frozen（P1 零拷贝入口） ==========

    #[test]
    fn test_frozen_basics() {
        let data = Bytes::from_static(b"hello frozen");
        let len = data.len();
        let buf = Buffer::from_bytes_frozen(data);
        assert_eq!(buf.len(), len);
        assert_eq!(buf.bytes(), b"hello frozen");
        assert_eq!(buf.as_ref(), b"hello frozen");
        assert!(buf.capacity() >= len);
        // Frozen 无可写空间：free 恒 0，写不进去（与池化满缓冲行为一致）
        assert_eq!(buf.free(), 0);
    }

    #[test]
    fn test_frozen_advance_and_read() {
        let mut buf = Buffer::from_bytes_frozen(Bytes::from_static(b"abcdef"));
        buf.advance(2);
        assert_eq!(buf.bytes(), b"cdef");
        let mut dst = [0u8; 2];
        assert_eq!(buf.read_to(&mut dst), 2);
        assert_eq!(&dst, b"cd");
        assert_eq!(buf.bytes(), b"ef");
    }

    #[test]
    fn test_frozen_release_not_pooled() {
        init();
        let mut buf = Buffer::from_bytes_frozen(Bytes::from_static(b"temp"));
        assert!(!buf.is_released());
        buf.release();
        assert!(buf.is_released());
        // release 后写入仍安全（转出池化空缓冲语义由 clear 同款路径承接）
    }

    #[test]
    fn test_frozen_cow_write_unique_is_cheap() {
        // 唯一引用：try_into_mut 零拷贝转正
        let mut buf = Buffer::from_bytes_frozen(Bytes::from(b"hello".to_vec()));
        buf.put(Bytes::from_static(b"!"));
        assert_eq!(buf.bytes(), b"hello!");
    }

    #[test]
    fn test_frozen_cow_write_shared() {
        // 共享引用（姊妹份存活）：COW 真实拷贝，内容正确、互不可见
        let shared = Bytes::from(b"hello".to_vec());
        let sister = shared.clone();
        let mut buf = Buffer::from_bytes_frozen(shared);
        buf.set_byte(0, b'H');
        assert_eq!(buf.bytes(), b"Hello");
        assert_eq!(&sister[..], b"hello");
    }

    #[test]
    fn test_frozen_split_to() {
        let buf = Buffer::from_bytes_frozen(Bytes::from_static(b"hello world"));
        let mut it = buf;
        let front = it.split_to(5);
        assert_eq!(front.bytes(), b"hello");
        assert_eq!(it.bytes(), b" world");
        let tail = it.split_to(1);
        assert_eq!(tail.bytes(), b" ");
        assert_eq!(it.bytes(), b"world");
    }

    #[test]
    fn test_frozen_into_bytes_zero_copy() {
        let mut buf = Buffer::from_bytes_frozen(Bytes::from(b"abcdef".to_vec()));
        buf.advance(2);
        let bytes = buf.into_bytes();
        assert_eq!(&bytes[..], b"cdef");
    }

    #[test]
    fn test_pooled_split_to_after_partial_read() {
        // 回归守卫：已读前缀（start>0）存在时 split_to 的余量游标必须正确。
        let mut buf = Buffer::from_bytes(BytesMut::from(&b"0123456789"[..]));
        buf.advance(2); // 未读 "23456789"
        let front = buf.split_to(2); // front = "23"
        assert_eq!(front.bytes(), b"23");
        assert_eq!(buf.bytes(), b"456789");
        let rest = buf.split_off(buf.len()); // 余量整体摘出
        assert_eq!(rest.bytes(), b"456789");
        assert!(buf.is_empty());
    }

    #[test]
    fn test_frozen_clear_transitions_to_pooled() {
        init();
        let mut buf = Buffer::from_bytes_frozen(Bytes::from_static(b"gone"));
        buf.clear();
        assert!(buf.is_empty());
        // clear 后转池化：可继续写
        assert_eq!(buf.write_from(b"new"), 3);
        assert_eq!(buf.bytes(), b"new");
    }
}
