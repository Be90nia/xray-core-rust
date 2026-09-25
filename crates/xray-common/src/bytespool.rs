//! 字节池分配器重导出
//!
//! 对应 Go 版本 `common/bytespool` 包，直接重导出 `xray_buf::alloc` 模块
//! 提供的分层缓冲池分配功能。

pub use xray_buf::alloc::{DEFAULT_SIZE, alloc, clear, release};
