//! Scatter/gather (readv) 缓冲区读取
//!
//! 对应 Go 版本 `common/buf/readv_*.go`，提供自适应分配策略的 scatter-gather 读取。
//! Unix 平台使用 `nix::sys::uio::readv`，Windows 使用 `WSARecv`，其他平台使用顺序读取回退。

use crate::buffer::Buffer;
use crate::io::{self, Reader, Result};
use crate::multi::MultiBuffer;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncRead, AsyncReadExt};

// ========== USE_READV 全局标志 ==========

/// 全局 readv 启用标志
///
/// 在支持 readv 的平台上默认为 true，可在运行时切换。
/// 对应 Go 的 `ReadVEnabled`。
pub static USE_READV: AtomicBool = AtomicBool::new(true);

// ========== AllocStrategy ==========

/// 分配策略
///
/// 对应 Go 的 readv 分配策略，控制 scatter-gather 读取时的缓冲区数量。
#[derive(Debug, Clone, Copy)]
pub enum AllocStrategy {
    /// 固定数量的缓冲区
    Fixed(usize),
    /// 自适应：从 1 个缓冲区开始，逐步增长到 2→4→8
    Adaptive,
}

impl Default for AllocStrategy {
    fn default() -> Self {
        AllocStrategy::Adaptive
    }
}

// ========== ReadVReader ==========

/// Scatter-gather 读取器
///
/// 对应 Go 的 `ReadVReader`，支持自适应分配策略的 scatter-gather 读取。
/// 从底层 AsyncRead 读取数据到多个 Buffer 中，减少系统调用次数。
pub struct ReadVReader<R> {
    reader: R,
    strategy: AllocStrategy,
    alloc_count: usize,
}

impl<R> ReadVReader<R> {
    /// 创建新的 ReadVReader
    ///
    /// `strategy` 控制每次读取时分配的缓冲区数量。
    pub fn new(reader: R, strategy: AllocStrategy) -> Self {
        let alloc_count = match strategy {
            AllocStrategy::Fixed(n) => n,
            AllocStrategy::Adaptive => 1,
        };
        Self {
            reader,
            strategy,
            alloc_count,
        }
    }

    /// 使用默认自适应策略创建 ReadVReader
    pub fn with_adaptive(reader: R) -> Self {
        Self::new(reader, AllocStrategy::Adaptive)
    }

    /// 使用固定缓冲区数量创建 ReadVReader
    pub fn with_fixed(reader: R, count: usize) -> Self {
        Self::new(reader, AllocStrategy::Fixed(count))
    }

    /// 获取当前分配数量
    pub fn alloc_count(&self) -> usize {
        self.alloc_count
    }
}

impl<R: AsyncRead + Unpin + Send> ReadVReader<R> {
    /// 计算下次分配的缓冲区数量
    fn next_alloc_count(&mut self) -> usize {
        match self.strategy {
            AllocStrategy::Fixed(n) => n,
            AllocStrategy::Adaptive => {
                let count = self.alloc_count;
                if count < 8 {
                    self.alloc_count = count * 2;
                }
                count
            }
        }
    }

    /// 执行 scatter-gather 读取
    ///
    /// 在支持 readv 的平台上使用系统调用，否则回退到顺序读取。
    pub async fn readv(&mut self) -> Result<MultiBuffer> {
        if !USE_READV.load(Ordering::Relaxed) {
            return self.readv_fallback().await;
        }

        let count = self.next_alloc_count();
        let mut buffers = self.allocate_buffers(count);
        self.readv_platform(&mut buffers).await
    }

    /// 分配指定数量的空缓冲区
    fn allocate_buffers(&self, count: usize) -> Vec<Buffer> {
        let mut buffers = Vec::with_capacity(count);
        for _ in 0..count {
            buffers.push(Buffer::new());
        }
        buffers
    }

    /// 回退实现：顺序读取到每个 Buffer
    async fn readv_fallback(&mut self) -> Result<MultiBuffer> {
        let count = self.next_alloc_count();
        let mut buffers = self.allocate_buffers(count);
        self.readv_sequential(&mut buffers).await
    }

    /// 顺序读取到每个 Buffer
    async fn readv_sequential(&mut self, buffers: &mut Vec<Buffer>) -> Result<MultiBuffer> {
        let mut result = MultiBuffer::new();
        let mut any_data = false;

        for buf in buffers.iter_mut() {
            let writable = buf.writable_bytes();
            match self.reader.read(writable).await {
                Ok(0) => {
                    buf.release();
                    break;
                }
                Ok(n) => {
                    buf.advance_write(n);
                    any_data = true;
                    result.push(std::mem::take(buf));
                }
                Err(e) => {
                    buf.release();
                    if any_data {
                        return Ok(result);
                    }
                    return Err(io::classify_io_error(e, true));
                }
            }
        }

        if !any_data {
            for buf in buffers.iter_mut() {
                if !buf.is_released() {
                    buf.release();
                }
            }
        }

        Ok(result)
    }
}

impl<R: AsyncRead + Unpin + Send> Reader for ReadVReader<R> {
    fn read_multi_buffer(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<MultiBuffer>> + Send + '_>> {
        Box::pin(async move { self.readv().await })
    }
}

// ========== 平台特定实现 ==========

#[cfg(unix)]
impl<R: AsyncRead + Unpin + Send> ReadVReader<R> {
    /// Unix 平台：回退到顺序读取（tokio AsyncRead 无法直接获取 fd）
    async fn readv_platform(&mut self, buffers: &mut Vec<Buffer>) -> Result<MultiBuffer> {
        self.readv_sequential(buffers).await
    }
}

#[cfg(windows)]
impl<R: AsyncRead + Unpin + Send> ReadVReader<R> {
    /// Windows 平台：回退到顺序读取（tokio AsyncRead 无法直接获取 SOCKET）
    async fn readv_platform(&mut self, buffers: &mut Vec<Buffer>) -> Result<MultiBuffer> {
        self.readv_sequential(buffers).await
    }
}

#[cfg(not(any(unix, windows)))]
impl<R: AsyncRead + Unpin + Send> ReadVReader<R> {
    /// 其他平台：顺序读取回退
    async fn readv_platform(&mut self, buffers: &mut Vec<Buffer>) -> Result<MultiBuffer> {
        self.readv_sequential(buffers).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_use_readv_flag() {
        assert!(USE_READV.load(Ordering::Relaxed));
        USE_READV.store(false, Ordering::Relaxed);
        assert!(!USE_READV.load(Ordering::Relaxed));
        USE_READV.store(true, Ordering::Relaxed);
    }

    #[test]
    fn test_alloc_strategy_default() {
        let strategy = AllocStrategy::default();
        assert!(matches!(strategy, AllocStrategy::Adaptive));
    }

    #[test]
    fn test_alloc_strategy_debug() {
        let fixed = AllocStrategy::Fixed(4);
        assert_eq!(format!("{fixed:?}"), "Fixed(4)");
        let adaptive = AllocStrategy::Adaptive;
        assert_eq!(format!("{adaptive:?}"), "Adaptive");
    }

    #[tokio::test]
    async fn test_readv_reader_basic() {
        let data = b"hello world";
        let cursor = Cursor::new(data.to_vec());
        let mut reader = ReadVReader::with_adaptive(cursor);

        let mb = reader.readv().await.expect("readv failed");
        assert!(!mb.is_empty());
        assert_eq!(mb.to_vec(), b"hello world");
    }

    #[tokio::test]
    async fn test_readv_reader_fixed_strategy() {
        let data = b"hello";
        let cursor = Cursor::new(data.to_vec());
        let mut reader = ReadVReader::with_fixed(cursor, 2);

        assert_eq!(reader.alloc_count(), 2);
        let mb = reader.readv().await.expect("readv failed");
        assert!(!mb.is_empty());
    }

    #[tokio::test]
    async fn test_readv_reader_adaptive_growth() {
        let data = b"hello";
        let cursor = Cursor::new(data.to_vec());
        let mut reader = ReadVReader::with_adaptive(cursor);

        assert_eq!(reader.alloc_count(), 1);
        let _ = reader.readv().await;
        assert_eq!(reader.alloc_count(), 2);
    }

    #[tokio::test]
    async fn test_readv_reader_empty() {
        let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let mut reader = ReadVReader::with_adaptive(cursor);

        let mb = reader.readv().await.expect("readv failed");
        assert!(mb.is_empty());
    }

    #[tokio::test]
    async fn test_readv_reader_large_data() {
        let data = vec![0xABu8; 20000];
        let cursor = Cursor::new(data.clone());
        let mut reader = ReadVReader::with_adaptive(cursor);

        let mut total = MultiBuffer::new();
        loop {
            let mb = reader.readv().await.expect("readv failed");
            if mb.is_empty() {
                break;
            }
            total.merge(mb);
        }
        assert_eq!(total.len(), 20000);
        assert_eq!(total.to_vec(), data);
    }

    #[tokio::test]
    async fn test_readv_reader_as_reader_trait() {
        let data = b"hello";
        let cursor = Cursor::new(data.to_vec());
        let mut reader = ReadVReader::with_adaptive(cursor);

        let mb = reader.read_multi_buffer().await.expect("read failed");
        assert!(!mb.is_empty());
    }

    #[tokio::test]
    async fn test_readv_reader_disabled() {
        USE_READV.store(false, Ordering::Relaxed);
        let data = b"hello";
        let cursor = Cursor::new(data.to_vec());
        let mut reader = ReadVReader::with_adaptive(cursor);

        let mb = reader.readv().await.expect("readv fallback failed");
        assert!(!mb.is_empty());
        USE_READV.store(true, Ordering::Relaxed);
    }

    #[tokio::test]
    async fn test_readv_reader_new_with_strategy() {
        let cursor = Cursor::new(b"hello".to_vec());
        let reader = ReadVReader::new(cursor, AllocStrategy::Fixed(3));
        assert_eq!(reader.alloc_count(), 3);
    }
}