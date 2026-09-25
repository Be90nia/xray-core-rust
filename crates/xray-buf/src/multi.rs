//! MultiBuffer 多缓冲区操作
//!
//! 对应 Go 版本 `common/buf.MultiBuffer`，管理一组 `Buffer` 的集合。
//! 用于高效处理分散/聚集 I/O，避免频繁的内存拷贝。

use std::mem::ManuallyDrop;

use crate::buffer::Buffer;

/// 多缓冲区容器，管理一组 `Buffer`。
///
/// 对应 Go 的 `MultiBuffer []*Buffer`。
/// 适用于需要同时操作多个缓冲区的场景，如分散读取、聚集写入。
///
/// 内部使用 `ManuallyDrop<Vec<Buffer>>` 以支持消费型方法（`into_buffers`、`into_vec`、
/// `IntoIterator`）在移动 `Vec` 内容的同时正确禁用 `Drop` 的重复释放。
#[must_use = "MultiBuffer 持有池化内存，丢弃前应调用 release() 或让 Drop 自动回收"]
pub struct MultiBuffer {
    buffers: ManuallyDrop<Vec<Buffer>>,
}

impl MultiBuffer {
    // ========== 构造函数 ==========

    /// 创建空的 MultiBuffer。
    pub fn new() -> Self {
        Self { buffers: ManuallyDrop::new(Vec::new()) }
    }

    /// 预分配指定数量的缓冲区槽位。
    pub fn with_capacity(n: usize) -> Self {
        Self { buffers: ManuallyDrop::new(Vec::with_capacity(n)) }
    }

    /// 从单个 Buffer 构造。
    pub fn from_buffer(buf: Buffer) -> Self {
        Self { buffers: ManuallyDrop::new(vec![buf]) }
    }

    /// 从 `Vec<Buffer>` 构造。
    pub fn from_buffers(buffers: Vec<Buffer>) -> Self {
        Self { buffers: ManuallyDrop::new(buffers) }
    }

    // ========== 基本操作 ==========

    /// 追加一个 Buffer。
    pub fn push(&mut self, buf: Buffer) {
        self.buffers.push(buf);
    }

    /// 所有缓冲区中的总字节数。
    pub fn len(&self) -> usize {
        self.buffers.iter().map(|b| b.len()).sum()
    }

    /// 是否为空（无数据或无缓冲区）。
    pub fn is_empty(&self) -> bool {
        self.buffers.is_empty() || self.len() == 0
    }

    /// 缓冲区数量。
    pub fn buffer_count(&self) -> usize {
        self.buffers.len()
    }

    /// 消费为 `Vec<Buffer>`。
    ///
    /// 调用方将负责释放这些 Buffer（它们的 Drop 会自动释放）。
    pub fn into_buffers(mut self) -> Vec<Buffer> {
        // SAFETY: 取出内部 Vec，并通过 forget 阻止 Drop 再次释放。
        // Buffer 的 Drop 会在各自被丢弃时释放回池中。
        let buffers = unsafe { ManuallyDrop::take(&mut self.buffers) };
        std::mem::forget(self);
        buffers
    }

    // ========== 分割操作 ==========

    /// 从 MultiBuffer 中分割出前 n 字节，返回新的 MultiBuffer。
    ///
    /// 对应 Go 的 `SplitBytes`。
    /// 按需从各 Buffer 中提取数据，可能跨越多个 Buffer。
    pub fn split_bytes(&mut self, n: usize) -> MultiBuffer {
        if n == 0 {
            return MultiBuffer::new();
        }

        let mut result = MultiBuffer::new();
        let mut remaining = n;

        // 第一遍：数清楚有多少个完整 buffer 可以被一次性 drain 走
        // （O(k) 而非 O(n) 总成本，Vec::drain 一次性 memmove 余下元素）。
        let mut full_take: usize = 0;
        for buf in self.buffers.iter() {
            if remaining <= buf.len() {
                break;
            }
            remaining -= buf.len();
            full_take += 1;
        }
        if full_take > 0 {
            let drained: Vec<Buffer> = self.buffers.drain(..full_take).collect();
            for buf in drained {
                result.push(buf);
            }
        }

        // 第二遍：剩余部分（跨最后一个 buffer 的 partial）一次性 split_to。
        if remaining > 0 && !self.buffers.is_empty() {
            let front = &mut self.buffers[0];
            let partial = front.split_to(remaining);
            result.push(partial);
        }

        result
    }

    /// 取出第一个 Buffer 并将其内容复制到 `dst`。
    ///
    /// 对应 Go 的 `SplitFirstBytes(mb, p)`：split 出 first buffer 后将
    /// 其内容 copy 到 `p`（最多 `min(first.len, p.len)` 字节），first buffer
    /// 被消费掉（返回后已释放回池中）。
    ///
    /// 返回实际复制的字节数。空 MultiBuffer 时返回 0。
    pub fn split_first_bytes(&mut self, dst: &mut [u8]) -> usize {
        let first = match self.buffers.first_mut() {
            Some(b) => b,
            None => return 0,
        };
        let n = first.bytes().len().min(dst.len());
        dst[..n].copy_from_slice(&first.bytes()[..n]);
        // 释放 first buffer 后移除（drain(..1) 单次 memmove，替代 remove(0)）。
        for mut removed in self.buffers.drain(..1) {
            removed.release();
        }
        n
    }

    /// 对应 Go 的 `SplitFirst`。
    pub fn split_first(&mut self) -> Option<Buffer> {
        // drain 的 end 超 len 会 panic，空 Vec 须先 guard。
        if self.buffers.is_empty() {
            return None;
        }
        self.buffers.drain(..1).next()
    }

    /// 分割出总计约 `size` 字节的 MultiBuffer。
    pub fn split_size(&mut self, size: usize) -> MultiBuffer {
        if size == 0 {
            return MultiBuffer::new();
        }

        let mut result = MultiBuffer::new();
        let mut accumulated = 0usize;

        // 第一遍：数清楚要完整取走的 buffer 数（Vec::drain 一次性 memmove 余下元素，
        // 单次操作完成「前缀搬迁」而非 remove(0) 每次 O(n) 累计 O(n²)）。
        let mut full_take: usize = 0;
        for buf in self.buffers.iter() {
            let buf_len = buf.len();
            if accumulated + buf_len > size {
                break;
            }
            accumulated += buf_len;
            full_take += 1;
        }
        if full_take > 0 {
            let drained: Vec<Buffer> = self.buffers.drain(..full_take).collect();
            for buf in drained {
                result.push(buf);
            }
        }

        // 第二遍：累积未达 size 时跨最后一个 buffer 的 partial 切分。
        if accumulated < size && !self.buffers.is_empty() {
            let front = &mut self.buffers[0];
            let needed = size - accumulated;
            let partial = front.split_to(needed);
            result.push(partial);
        }
        result
    }

    // ========== 合并操作 ==========

    /// 将另一个 MultiBuffer 的所有缓冲区合并到当前。
    ///
    /// 对应 Go 的 `MergeMulti`。
    pub fn merge(&mut self, mut other: MultiBuffer) {
        // SAFETY: 从 other 取出 buffers 后 forget other，阻止其 Drop 释放。
        let buffers = unsafe { ManuallyDrop::take(&mut other.buffers) };
        std::mem::forget(other);
        self.buffers.extend(buffers);
    }

    /// 将字节数据写入 MultiBuffer。
    ///
    /// 对应 Go 的 `MergeBytes`。
    /// 尝试追加到现有缓冲区，空间不足则创建新缓冲区。
    pub fn merge_bytes(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        let mut remaining = data;

        // 尝试填充最后一个缓冲区
        if let Some(last) = self.buffers.last_mut() {
            let written = last.write_from(remaining);
            remaining = &remaining[written..];
        }

        // 剩余数据写入新缓冲区
        while !remaining.is_empty() {
            let mut buf = Buffer::new();
            let written = buf.write_from(remaining);
            remaining = &remaining[written..];
            self.buffers.push(buf);
        }
    }

    /// 合并小缓冲区为更少的大缓冲区。
    ///
    /// 对应 Go 的 `Compact`。
    /// 将多个小缓冲区合并为一个或几个满缓冲区，减少系统调用次数。
    pub fn compact(&mut self) {
        if self.buffers.len() <= 1 {
            return;
        }

        let total_len: usize = self.buffers.iter().map(|b| b.len()).sum();
        if total_len == 0 {
            self.release();
            return;
        }

        let mut compacted = Vec::new();
        let mut current = Buffer::new();

        for buf in self.buffers.drain(..) {
            let data = buf.bytes();
            if data.is_empty() {
                continue;
            }

            let mut src_offset = 0;
            while src_offset < data.len() {
                let written = current.write_from(&data[src_offset..]);
                src_offset += written;

                if current.free() == 0 && src_offset < data.len() {
                    compacted.push(current);
                    current = Buffer::new();
                }
            }
        }

        if !current.is_empty() {
            compacted.push(current);
        }

        // 先释放旧的已 drain 的 Vec（drain 后已空），再替换
        // SAFETY: drain 已清空 buffers，可以安全 drop
        unsafe {
            ManuallyDrop::drop(&mut self.buffers);
        }
        self.buffers = ManuallyDrop::new(compacted);
    }

    // ========== 释放 ==========

    /// 释放所有缓冲区回池中。
    ///
    /// 对应 Go 的 `ReleaseMulti`。
    pub fn release(&mut self) {
        for mut buf in self.buffers.drain(..) {
            buf.release();
        }
    }

    // ========== 读写接口 ==========

    /// 从 MultiBuffer 读取数据到 dst。
    ///
    /// 按顺序从各 Buffer 读取，读完后自动移除空 Buffer。
    pub fn read_to(&mut self, dst: &mut [u8]) -> usize {
        let mut total_read = 0;
        let mut dst_offset = 0;

        // 已读空的前缀数量：循环内只推进索引，结束后一次 drain 单次 memmove，
        // 消除逐个 remove(0) 的 O(k·n) 前缀搬迁。
        let mut emptied = 0usize;
        while dst_offset < dst.len() && self.buffers.len() > emptied {
            let front = &mut self.buffers[emptied];
            let n = front.read_to(&mut dst[dst_offset..]);
            dst_offset += n;
            total_read += n;

            if front.is_empty() {
                emptied += 1;
            }
        }
        self.buffers.drain(..emptied);

        total_read
    }

    /// 将 src 数据写入 MultiBuffer。
    ///
    /// 追加到现有缓冲区或创建新缓冲区。
    pub fn write_from(&mut self, src: &[u8]) -> usize {
        let original_len = src.len();
        self.merge_bytes(src);
        original_len
    }

    /// 随机访问读取：从指定偏移量复制数据到 dst。
    ///
    /// 跨越多个 Buffer 进行读取，offset 是相对于 MultiBuffer 起始位置的全局偏移。
    pub fn copy_to_slice(&self, mut offset: usize, dst: &mut [u8]) {
        let mut dst_offset = 0;

        for buf in self.buffers.iter() {
            let buf_len = buf.len();
            if offset >= buf_len {
                offset -= buf_len;
                continue;
            }

            let available = buf_len - offset;
            let to_copy = available.min(dst.len() - dst_offset);
            let buf_bytes = buf.bytes();
            dst[dst_offset..dst_offset + to_copy]
                .copy_from_slice(&buf_bytes[offset..offset + to_copy]);
            dst_offset += to_copy;
            offset = 0;

            if dst_offset >= dst.len() {
                break;
            }
        }
    }

    // ========== 迭代 ==========

    /// 不可变迭代器。
    pub fn iter(&self) -> impl Iterator<Item = &Buffer> {
        self.buffers.iter()
    }

    /// 可变迭代器。
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Buffer> {
        self.buffers.iter_mut()
    }

    // ========== 转换 ==========

    /// 将所有缓冲区数据扁平化为 `Vec<u8>`。
    pub fn to_vec(&self) -> Vec<u8> {
        let total: usize = self.buffers.iter().map(|b| b.len()).sum();
        let mut result = Vec::with_capacity(total);
        for buf in self.buffers.iter() {
            result.extend_from_slice(buf.bytes());
        }
        result
    }

    /// 消费 MultiBuffer 并扁平化为 `Vec<u8>`。
    pub fn into_vec(self) -> Vec<u8> {
        let buffers = self.into_buffers();
        let total: usize = buffers.iter().map(|b| b.len()).sum();
        let mut result = Vec::with_capacity(total);
        for buf in buffers {
            result.extend_from_slice(buf.bytes());
        }
        result
    }
}

impl Drop for MultiBuffer {
    fn drop(&mut self) {
        self.release();
        // SAFETY: release 已将所有 Buffer 归还池中，drain 清空了 Vec，
        // 可以安全丢弃 ManuallyDrop 包装的空 Vec。
        unsafe {
            ManuallyDrop::drop(&mut self.buffers);
        }
    }
}

impl Default for MultiBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for MultiBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiBuffer")
            .field("buffer_count", &self.buffer_count())
            .field("total_len", &self.len())
            .finish()
    }
}

impl IntoIterator for MultiBuffer {
    type IntoIter = std::vec::IntoIter<Buffer>;
    type Item = Buffer;

    fn into_iter(self) -> Self::IntoIter {
        self.into_buffers().into_iter()
    }
}

impl<'a> IntoIterator for &'a MultiBuffer {
    type IntoIter = std::slice::Iter<'a, Buffer>;
    type Item = &'a Buffer;

    fn into_iter(self) -> Self::IntoIter {
        self.buffers.iter()
    }
}

impl<'a> IntoIterator for &'a mut MultiBuffer {
    type IntoIter = std::slice::IterMut<'a, Buffer>;
    type Item = &'a mut Buffer;

    fn into_iter(self) -> Self::IntoIter {
        self.buffers.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;

    fn make_buffer(data: &[u8]) -> Buffer {
        Buffer::from_bytes(BytesMut::from(data))
    }

    #[test]
    fn test_new() {
        let mb = MultiBuffer::new();
        assert!(mb.is_empty());
        assert_eq!(mb.buffer_count(), 0);
        assert_eq!(mb.len(), 0);
    }

    #[test]
    fn test_with_capacity() {
        let mb = MultiBuffer::with_capacity(4);
        assert_eq!(mb.buffer_count(), 0);
    }

    #[test]
    fn test_from_buffer() {
        let buf = make_buffer(b"hello");
        let mb = MultiBuffer::from_buffer(buf);
        assert_eq!(mb.len(), 5);
        assert_eq!(mb.buffer_count(), 1);
    }

    #[test]
    fn test_from_buffers() {
        let bufs = vec![make_buffer(b"ab"), make_buffer(b"cd")];
        let mb = MultiBuffer::from_buffers(bufs);
        assert_eq!(mb.len(), 4);
        assert_eq!(mb.buffer_count(), 2);
    }

    #[test]
    fn test_push() {
        let mut mb = MultiBuffer::new();
        mb.push(make_buffer(b"hello"));
        mb.push(make_buffer(b" world"));
        assert_eq!(mb.len(), 11);
        assert_eq!(mb.buffer_count(), 2);
    }

    #[test]
    fn test_is_empty_no_buffers() {
        let mb = MultiBuffer::new();
        assert!(mb.is_empty());
    }

    #[test]
    fn test_is_empty_with_empty_buffers() {
        let mut mb = MultiBuffer::new();
        mb.push(Buffer::new());
        assert!(mb.is_empty());
    }

    #[test]
    fn test_split_bytes_full() {
        let mut mb = MultiBuffer::from_buffers(vec![make_buffer(b"hello"), make_buffer(b" world")]);
        let split = mb.split_bytes(5);
        assert_eq!(split.len(), 5);
        assert_eq!(split.to_vec(), b"hello");
        assert_eq!(mb.len(), 6);
        assert_eq!(mb.to_vec(), b" world");
    }

    #[test]
    fn test_split_bytes_partial() {
        let mut mb = MultiBuffer::from_buffer(make_buffer(b"hello world"));
        let split = mb.split_bytes(5);
        assert_eq!(split.to_vec(), b"hello");
        assert_eq!(mb.to_vec(), b" world");
    }

    #[test]
    fn test_split_bytes_cross_buffer() {
        let mut mb = MultiBuffer::from_buffers(vec![
            make_buffer(b"hel"),
            make_buffer(b"lo wo"),
            make_buffer(b"rld"),
        ]);
        let split = mb.split_bytes(7);
        assert_eq!(split.to_vec(), b"hello w");
        assert_eq!(mb.to_vec(), b"orld");
    }

    #[test]
    fn test_split_bytes_zero() {
        let mut mb = MultiBuffer::from_buffer(make_buffer(b"hello"));
        let split = mb.split_bytes(0);
        assert_eq!(split.len(), 0);
        assert_eq!(mb.len(), 5);
    }

    #[test]
    fn test_split_first() {
        let mut mb = MultiBuffer::from_buffers(vec![make_buffer(b"first"), make_buffer(b"second")]);
        let first = mb.split_first();
        assert!(first.is_some());
        assert_eq!(first.expect("checked").bytes(), b"first");
        assert_eq!(mb.buffer_count(), 1);
    }

    #[test]
    fn test_split_first_empty() {
        let mut mb = MultiBuffer::new();
        assert!(mb.split_first().is_none());
    }

    #[test]
    fn test_split_size() {
        let mut mb = MultiBuffer::from_buffers(vec![
            make_buffer(b"aaa"),
            make_buffer(b"bbb"),
            make_buffer(b"ccc"),
        ]);
        let split = mb.split_size(5);
        assert_eq!(split.to_vec(), b"aaabb");
        assert_eq!(mb.to_vec(), b"bccc");
    }

    #[test]
    fn test_split_size_exact() {
        let mut mb = MultiBuffer::from_buffers(vec![make_buffer(b"aaa"), make_buffer(b"bbb")]);
        let split = mb.split_size(6);
        assert_eq!(split.to_vec(), b"aaabbb");
        assert_eq!(mb.len(), 0);
    }

    #[test]
    fn test_merge() {
        let mut mb1 = MultiBuffer::from_buffer(make_buffer(b"hello"));
        let mb2 = MultiBuffer::from_buffer(make_buffer(b" world"));
        mb1.merge(mb2);
        assert_eq!(mb1.len(), 11);
        assert_eq!(mb1.buffer_count(), 2);
    }

    #[test]
    fn test_merge_bytes() {
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(b"hello world");
        assert_eq!(mb.len(), 11);
        assert_eq!(mb.to_vec(), b"hello world");
    }

    #[test]
    fn test_merge_bytes_existing() {
        let mut mb = MultiBuffer::from_buffer(make_buffer(b"hi"));
        mb.merge_bytes(b" there");
        assert_eq!(mb.len(), 8);
        assert_eq!(mb.to_vec(), b"hi there");
    }

    #[test]
    fn test_merge_bytes_empty() {
        let mut mb = MultiBuffer::from_buffer(make_buffer(b"hello"));
        mb.merge_bytes(b"");
        assert_eq!(mb.len(), 5);
    }

    #[test]
    fn test_compact() {
        let mut mb = MultiBuffer::from_buffers(vec![
            make_buffer(b"ab"),
            make_buffer(b"cd"),
            make_buffer(b"ef"),
        ]);
        mb.compact();
        assert_eq!(mb.len(), 6);
        assert_eq!(mb.buffer_count(), 1);
        assert_eq!(mb.to_vec(), b"abcdef");
    }

    #[test]
    fn test_compact_single_buffer() {
        let mut mb = MultiBuffer::from_buffer(make_buffer(b"hello"));
        mb.compact();
        assert_eq!(mb.buffer_count(), 1);
        assert_eq!(mb.len(), 5);
    }

    #[test]
    fn test_compact_empty() {
        let mut mb = MultiBuffer::new();
        mb.compact();
        assert_eq!(mb.buffer_count(), 0);
    }

    #[test]
    fn test_release() {
        let mut mb = MultiBuffer::from_buffers(vec![make_buffer(b"a"), make_buffer(b"b")]);
        mb.release();
        assert_eq!(mb.buffer_count(), 0);
        assert!(mb.is_empty());
    }

    #[test]
    fn test_read_to() {
        let mut mb = MultiBuffer::from_buffers(vec![make_buffer(b"hel"), make_buffer(b"lo")]);
        let mut dst = [0u8; 5];
        let n = mb.read_to(&mut dst);
        assert_eq!(n, 5);
        assert_eq!(&dst, b"hello");
        assert!(mb.is_empty());
    }

    #[test]
    fn test_read_to_partial() {
        let mut mb = MultiBuffer::from_buffer(make_buffer(b"hello"));
        let mut dst = [0u8; 3];
        let n = mb.read_to(&mut dst);
        assert_eq!(n, 3);
        assert_eq!(&dst, b"hel");
        assert_eq!(mb.len(), 2);
    }

    #[test]
    fn test_write_from() {
        let mut mb = MultiBuffer::new();
        let n = mb.write_from(b"hello");
        assert_eq!(n, 5);
        assert_eq!(mb.len(), 5);
        assert_eq!(mb.to_vec(), b"hello");
    }

    #[test]
    fn test_copy_to_slice() {
        let mb = MultiBuffer::from_buffers(vec![make_buffer(b"hello"), make_buffer(b" world")]);
        let mut dst = [0u8; 5];
        mb.copy_to_slice(3, &mut dst);
        assert_eq!(&dst, b"lo wo");
    }

    #[test]
    fn test_copy_to_slice_first_buffer() {
        let mb = MultiBuffer::from_buffer(make_buffer(b"hello world"));
        let mut dst = [0u8; 5];
        mb.copy_to_slice(0, &mut dst);
        assert_eq!(&dst, b"hello");
    }

    #[test]
    fn test_copy_to_slice_cross_buffer() {
        let mb = MultiBuffer::from_buffers(vec![
            make_buffer(b"ab"),
            make_buffer(b"cdef"),
            make_buffer(b"gh"),
        ]);
        let mut dst = [0u8; 4];
        mb.copy_to_slice(1, &mut dst);
        assert_eq!(&dst, b"bcde");
    }

    #[test]
    fn test_iter() {
        let mb = MultiBuffer::from_buffers(vec![make_buffer(b"ab"), make_buffer(b"cd")]);
        let lens: Vec<usize> = mb.iter().map(|b| b.len()).collect();
        assert_eq!(lens, vec![2, 2]);
    }

    #[test]
    fn test_iter_mut() {
        let mut mb = MultiBuffer::from_buffers(vec![make_buffer(b"ab"), make_buffer(b"cd")]);
        for buf in mb.iter_mut() {
            buf.as_mut()[0] = b'x';
        }
        assert_eq!(mb.to_vec(), b"xbxd");
    }

    #[test]
    fn test_into_iter() {
        let mb = MultiBuffer::from_buffers(vec![make_buffer(b"ab"), make_buffer(b"cd")]);
        let bufs: Vec<Buffer> = mb.into_iter().collect();
        assert_eq!(bufs.len(), 2);
    }

    #[test]
    fn test_to_vec() {
        let mb = MultiBuffer::from_buffers(vec![make_buffer(b"hel"), make_buffer(b"lo")]);
        assert_eq!(mb.to_vec(), b"hello");
    }

    #[test]
    fn test_into_vec() {
        let mb = MultiBuffer::from_buffers(vec![make_buffer(b"hel"), make_buffer(b"lo")]);
        assert_eq!(mb.into_vec(), b"hello");
    }

    #[test]
    fn test_debug() {
        let mb = MultiBuffer::from_buffers(vec![make_buffer(b"ab"), make_buffer(b"cd")]);
        let debug = format!("{mb:?}");
        assert!(debug.contains("buffer_count: 2"));
        assert!(debug.contains("total_len: 4"));
    }

    #[test]
    fn test_default() {
        let mb = MultiBuffer::default();
        assert!(mb.is_empty());
    }

    #[test]
    fn test_drop_releases() {
        {
            let mut mb = MultiBuffer::new();
            mb.push(Buffer::new());
            mb.push(Buffer::new());
        }
    }

    #[test]
    fn test_large_data() {
        let mut mb = MultiBuffer::new();
        let data = vec![0xABu8; 20000];
        mb.merge_bytes(&data);
        assert_eq!(mb.len(), 20000);
        assert_eq!(mb.to_vec(), data);
    }

    #[test]
    fn test_split_bytes_more_than_available() {
        let mut mb = MultiBuffer::from_buffer(make_buffer(b"hello"));
        let split = mb.split_bytes(100);
        assert_eq!(split.to_vec(), b"hello");
        assert_eq!(mb.len(), 0);
    }

    #[test]
    fn test_into_buffers() {
        let mb = MultiBuffer::from_buffers(vec![make_buffer(b"a"), make_buffer(b"b")]);
        let bufs = mb.into_buffers();
        assert_eq!(bufs.len(), 2);
    }

    #[test]
    fn test_compact_large_data() {
        let mut mb = MultiBuffer::new();
        for i in 0..10u8 {
            mb.push(make_buffer(&[i]));
        }
        assert_eq!(mb.buffer_count(), 10);
        mb.compact();
        assert_eq!(mb.buffer_count(), 1);
        assert_eq!(mb.len(), 10);
        let vec = mb.to_vec();
        assert_eq!(vec, (0..10u8).collect::<Vec<_>>());
    }

    #[test]
    fn test_split_first_bytes_basic() {
        // 对应 Go TestSplitFirstBytes：mb 只有一个 buffer "ab" + "cd" 两个 buffer。
        // 第一个 buffer ("ab") 被完全消费并 copy 到 dst，mb 保留剩余 buffer。
        let mut mb = MultiBuffer::from_buffers(vec![make_buffer(b"ab"), make_buffer(b"cd")]);
        let mut dst = [0u8; 2];
        let n = mb.split_first_bytes(&mut dst);
        assert_eq!(n, 2);
        assert_eq!(&dst, b"ab");
        // 第一个 buffer 被消费（释放），第二个保留
        assert_eq!(mb.buffer_count(), 1);
        assert_eq!(mb.to_vec(), b"cd");
    }

    #[test]
    fn test_split_first_bytes_short_dst() {
        // dst 比 first buffer 短：只 copy min(dst.len, first.len) 字节。
        // first buffer 仍然被消费。
        let mut mb = MultiBuffer::from_buffer(make_buffer(b"hello"));
        let mut dst = [0u8; 3];
        let n = mb.split_first_bytes(&mut dst);
        assert_eq!(n, 3);
        assert_eq!(&dst, b"hel");
        assert_eq!(mb.len(), 0); // first buffer 被 release
    }

    #[test]
    fn test_split_first_bytes_empty_multibuf() {
        let mut mb = MultiBuffer::new();
        let mut dst = [0u8; 4];
        let n = mb.split_first_bytes(&mut dst);
        assert_eq!(n, 0);
    }

    #[test]
    fn test_split_first_bytes_only_consumes_first() {
        // 关键语义：SplitFirstBytes 只 split 第一个 Buffer，
        // 后续 Buffer 保留在 mb 中。
        let mut mb = MultiBuffer::from_buffers(vec![make_buffer(b"hello"), make_buffer(b"world")]);
        let mut dst = [0u8; 5];
        let n = mb.split_first_bytes(&mut dst);
        assert_eq!(n, 5);
        assert_eq!(&dst, b"hello");
        // 第一个 Buffer 消费，但第二个保留
        assert_eq!(mb.buffer_count(), 1);
        assert_eq!(mb.to_vec(), b"world");
    }
}
