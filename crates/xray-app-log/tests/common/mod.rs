//! 共享测试台：tracing 捕获 + 串行锁。
//!
//! global `CHANNELS` 与 tracing 订阅者都是进程级单例：跨测试二进制不共享，
//! 但同一二进制内的测试会互相覆盖，故串行。
#![allow(dead_code)] // 各测试二进制只用到其中一部分

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

/// 串行锁：global General 槽的激活期会整体换/清出口集。
static SERIAL: Mutex<()> = Mutex::new(());

pub fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// 捕获账本（共享字节缓冲）。
#[derive(Default)]
pub struct CaptureBuf(Mutex<Vec<u8>>);

impl CaptureBuf {
    pub fn text(&self) -> String {
        let buf = self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        String::from_utf8_lossy(&buf).into_owned()
    }

    pub fn clear(&self) {
        self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clear();
    }
}

#[derive(Clone)]
struct CaptureWriter(Arc<CaptureBuf>);

impl std::io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// 一次性装 capture 订阅者（进程级全局默认）。必须在任何 tracing 事件之前装好：
/// callsite interest 有进程级缓存，先无订阅者评估会被缓存成 Never → 后续恒捕 0 条。
pub fn capture() -> &'static Arc<CaptureBuf> {
    static CAPTURE: OnceLock<Arc<CaptureBuf>> = OnceLock::new();
    CAPTURE.get_or_init(|| {
        let buf = Arc::new(CaptureBuf::default());
        let _ = tracing_subscriber::fmt()
            .with_writer(CaptureWriter(Arc::clone(&buf)))
            .with_max_level(tracing::Level::TRACE)
            .try_init();
        buf
    })
}
