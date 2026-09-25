//! Copy 管道实现
//!
//! 对应 Go 版本 `common/buf/copy.go`，提供 Reader→Writer 的数据拷贝管道，
//! 支持超时、活动回调、大小计数等选项。

use std::{sync::Arc, time::Duration};

use crate::io::{self, Reader, Result, Writer};

// ========== CopyOptions ==========

/// Copy 操作的配置选项
///
/// 对应 Go 的 `CopyOption` 函数选项模式。
pub struct CopyOptions {
    /// 活动回调：每次读写成功后调用
    pub on_update_activity: Option<Arc<dyn Fn() + Send + Sync>>,

    /// 大小计数回调：每次读取后调用，传入读取字节数
    pub on_count_size: Option<Arc<dyn Fn(usize) + Send + Sync>>,
}

impl Default for CopyOptions {
    fn default() -> Self {
        Self { on_update_activity: None, on_count_size: None }
    }
}

impl std::fmt::Debug for CopyOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CopyOptions")
            .field("has_activity_cb", &self.on_update_activity.is_some())
            .field("has_size_cb", &self.on_count_size.is_some())
            .finish()
    }
}

/// 创建"更新活动"选项
///
/// 对应 Go 的 `UpdateActivity` 选项。
pub fn update_activity(f: impl Fn() + Send + Sync + 'static) -> impl Fn(&mut CopyOptions) {
    let f = Arc::new(f);
    move |opts| {
        opts.on_update_activity = Some(f.clone());
    }
}

/// 创建"计数大小"选项
///
/// 对应 Go 的 `CountSize` 选项。
pub fn count_size(f: impl Fn(usize) + Send + Sync + 'static) -> impl Fn(&mut CopyOptions) {
    let f = Arc::new(f);
    move |opts| {
        opts.on_count_size = Some(f.clone());
    }
}

// ========== Copy 函数 ==========

/// 从 Reader 拷贝数据到 Writer，直到遇到错误
///
/// 对应 Go 的 `Copy(Reader, Writer, ...CopyOption)`。
/// 循环执行：读取 → 写入 → 回调，直到读取返回空或错误。
pub async fn copy<R, W>(reader: &mut R, writer: &mut W) -> Result<()>
where
    R: Reader + ?Sized,
    W: Writer + ?Sized,
{
    copy_with_options(reader, writer, CopyOptions::default()).await
}

/// 带选项的 Copy
///
/// 对应 Go 的 `Copy` 带可选参数版本。
pub async fn copy_with_options<R, W>(
    reader: &mut R,
    writer: &mut W,
    options: CopyOptions,
) -> Result<()>
where
    R: Reader + ?Sized,
    W: Writer + ?Sized,
{
    loop {
        let mb = reader.read_multi_buffer().await?;

        if mb.is_empty() {
            tracing::trace!("copy: 读取到空 MultiBuffer，结束");
            return Ok(());
        }

        let size = mb.len();

        if let Some(ref cb) = options.on_count_size {
            cb(size);
        }

        writer.write_multi_buffer(mb).await?;

        if let Some(ref cb) = options.on_update_activity {
            cb();
        }
    }
}

/// 单次带超时的 Copy
///
/// 对应 Go 的 `CopyOnceTimeout`。
/// 执行一次读取（带超时），然后写入。如果读取超时，返回 TimeoutError。
pub async fn copy_once_timeout<R, W>(
    reader: &mut R,
    writer: &mut W,
    timeout: Duration,
) -> Result<()>
where
    R: Reader + ?Sized,
    W: Writer + ?Sized,
{
    let mb = tokio::select! {
        result = reader.read_multi_buffer() => result?,
        _ = tokio::time::sleep(timeout) => {
            return Err(io::Error::TimeoutError);
        }
    };

    if mb.is_empty() {
        return Ok(());
    }

    writer.write_multi_buffer(mb).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        io::Cursor,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::*;
    use crate::io::{new_reader, new_writer};

    #[tokio::test]
    async fn test_copy_basic() {
        let cursor = Cursor::new(b"hello world".to_vec());
        let mut reader = new_reader(cursor);

        let buffer: Vec<u8> = Vec::new();
        let mut writer = new_writer(buffer);

        copy(&mut reader, &mut writer).await.expect("copy failed");
    }

    #[tokio::test]
    async fn test_copy_empty() {
        let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let mut reader = new_reader(cursor);

        let buffer: Vec<u8> = Vec::new();
        let mut writer = new_writer(buffer);

        copy(&mut reader, &mut writer).await.expect("copy failed");
    }

    #[tokio::test]
    async fn test_copy_with_options_activity() {
        let cursor = Cursor::new(b"hello".to_vec());
        let mut reader = new_reader(cursor);

        let buffer: Vec<u8> = Vec::new();
        let mut writer = new_writer(buffer);

        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = count.clone();
        let update_fn = update_activity(move || {
            count_clone.fetch_add(1, Ordering::Relaxed);
        });

        let mut opts = CopyOptions::default();
        update_fn(&mut opts);

        copy_with_options(&mut reader, &mut writer, opts).await.expect("copy failed");

        assert!(count.load(Ordering::Relaxed) > 0);
    }

    #[tokio::test]
    async fn test_copy_with_options_size() {
        let cursor = Cursor::new(b"hello".to_vec());
        let mut reader = new_reader(cursor);

        let buffer: Vec<u8> = Vec::new();
        let mut writer = new_writer(buffer);

        let total_size = Arc::new(AtomicUsize::new(0));
        let total_clone = total_size.clone();
        let size_fn = count_size(move |n| {
            total_clone.fetch_add(n, Ordering::Relaxed);
        });

        let mut opts = CopyOptions::default();
        size_fn(&mut opts);

        copy_with_options(&mut reader, &mut writer, opts).await.expect("copy failed");

        assert!(total_size.load(Ordering::Relaxed) > 0);
    }

    #[tokio::test]
    async fn test_copy_once_timeout_success() {
        let cursor = Cursor::new(b"hello".to_vec());
        let mut reader = new_reader(cursor);

        let buffer: Vec<u8> = Vec::new();
        let mut writer = new_writer(buffer);

        let result = copy_once_timeout(&mut reader, &mut writer, Duration::from_secs(5)).await;
        result.expect("copy_once_timeout failed");
    }

    #[tokio::test]
    async fn test_copy_once_timeout_empty() {
        let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let mut reader = new_reader(cursor);

        let buffer: Vec<u8> = Vec::new();
        let mut writer = new_writer(buffer);

        let result = copy_once_timeout(&mut reader, &mut writer, Duration::from_secs(5)).await;
        result.expect("copy_once_timeout should succeed on empty");
    }

    #[test]
    fn test_copy_options_default() {
        let opts = CopyOptions::default();
        assert!(opts.on_update_activity.is_none());
        assert!(opts.on_count_size.is_none());
    }

    #[test]
    fn test_copy_options_debug() {
        let opts = CopyOptions::default();
        let debug = format!("{opts:?}");
        assert!(debug.contains("has_activity_cb: false"));
        assert!(debug.contains("has_size_cb: false"));
    }
}
