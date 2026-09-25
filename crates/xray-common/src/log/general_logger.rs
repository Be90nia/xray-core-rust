//! 通用日志处理器，对应 Go `common/log/logger.go::generalLogger`。
//!
//! Go 端语义（`logger.go:23-115`）：
//! - 128 条 `chan Message` 缓冲；
//! - `Handle` 写入满时丢弃（`select { default }`）；
//! - 单 token `semaphore.Instance(1)` 确保任意时刻仅 1 个后台 task；
//! - 后台 task 每 60s tick 若自上次写后无新数据则退出（`dataWritten` flag）；
//! - `Close` 唤醒后台 task 走清理路径。
//!
//! Rust 端口用 `tokio::sync::mpsc::channel(128)` + 单一后台 `tokio::spawn` task
//! + `tokio::time::interval(60s)` + `parking_lot::Mutex<bool>` 充当 Go semaphore 单 token。

use std::{io, sync::Arc, time::Duration};

use parking_lot::Mutex;
use tokio::{sync::mpsc, task::JoinHandle};

use super::{Handler, Message};

/// 通用日志写入器 trait，对应 Go `common/log.Writer` 接口。
pub trait Writer: Send + Sync {
    /// 写入完整一行（不含换行；内部按需加 `\n`）。
    fn write(&self, line: &str) -> io::Result<()>;
    /// 默认 no-op flush；文件 writer 可覆写。
    fn flush(&self) -> io::Result<()> {
        Ok(())
    }
}

/// Logger 工厂 trait，对应 Go `WriterCreator`。
pub trait WriterCreator: Send + Sync {
    /// 每次后台 task 启动时调用一次。返回 `None` → task 立即退出。
    fn create(&self) -> Option<Box<dyn Writer>>;
}

/// Stdout writer creator（对应 Go `CreateStdoutLogWriter`）。
#[derive(Debug, Clone, Copy, Default)]
pub struct StdoutWriterCreator;

impl WriterCreator for StdoutWriterCreator {
    fn create(&self) -> Option<Box<dyn Writer>> {
        Some(Box::new(StdoutWriter))
    }
}

/// Stderr writer creator（对齐 Go `CreateStderrLogWriter`）。
#[derive(Debug, Clone, Copy, Default)]
pub struct StderrWriterCreator;

impl WriterCreator for StderrWriterCreator {
    fn create(&self) -> Option<Box<dyn Writer>> {
        Some(Box::new(StderrWriter))
    }
}

struct StdoutWriter;
struct StderrWriter;

impl Writer for StdoutWriter {
    fn write(&self, line: &str) -> io::Result<()> {
        use std::io::Write;
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        out.write_all(line.as_bytes())?;
        out.write_all(b"\n")
    }
}

impl Writer for StderrWriter {
    fn write(&self, line: &str) -> io::Result<()> {
        use std::io::Write;
        let stderr = std::io::stderr();
        let mut out = stderr.lock();
        out.write_all(line.as_bytes())?;
        out.write_all(b"\n")
    }
}

/// 1 min idle ticker，对应 Go `time.NewTicker(time.Minute)`。
pub const IDLE_FLUSH_INTERVAL: Duration = Duration::from_secs(60);

/// 通道缓冲长度，对应 Go `make(chan Message, 128)`。
const CHANNEL_BUFFER: usize = 128;

/// 共享后台 task 状态。
///
/// `running` 等价于 Go `semaphore.Instance(1)` 的 token：未持 token 时可 CAS 持，
/// task 退出时释放。
struct Inner {
    tx: Option<mpsc::Sender<Message>>,
    handle: Option<JoinHandle<()>>,
    running: bool,
}

/// 通用 Logger，对应 Go `generalLogger`。
pub struct GeneralLogger {
    inner: Arc<Mutex<Inner>>,
    creator: Arc<dyn WriterCreator>,
}

impl GeneralLogger {
    /// 创建 Logger；不立即启动后台 task（与 Go 一致：Handle 触发启动）。
    #[must_use]
    pub fn new(creator: Arc<dyn WriterCreator>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner { tx: None, handle: None, running: false })),
            creator,
        }
    }

    /// 显式启动后台 task（通常无需：handle_message 会自动启动）。
    pub fn run_once(&self) {
        self.ensure_running();
    }

    /// 首次写入或显式启动时启动后台 task；重复调用是 no-op。
    fn ensure_running(&self) {
        let mut g = self.inner.lock();
        if g.running {
            return;
        }
        let (tx, rx) = mpsc::channel::<Message>(CHANNEL_BUFFER);
        g.tx = Some(tx);
        g.running = true;

        let creator = Arc::clone(&self.creator);
        let inner = Arc::clone(&self.inner);
        let handle = tokio::spawn(async move {
            run_loop(creator, inner.clone(), rx).await;
        });
        g.handle = Some(handle);
    }

    /// 写入一条消息；满则丢。对应 Go `Handle` 的 `select { default }`。
    pub fn handle_message(&self, message: &Message) {
        self.ensure_running();
        let tx = self.inner.lock().tx.clone();
        if let Some(tx) = tx {
            let _ = tx.try_send(message.clone());
        }
    }

    /// 主动关闭（对应 Go `Close`）：drop tx → task 退出 → join。
    pub async fn close(&self) {
        let handle = {
            let mut g = self.inner.lock();
            // drop sender 触发 rx.recv() 返回 None。
            g.tx.take();
            g.handle.take()
        };
        if let Some(h) = handle {
            let _ = h.await;
        }
    }
}

/// 后台 task 主循环。与 Go `generalLogger.run` 等价：
/// - `dataWritten` flag；
/// - ticker 每 60s 触发：若 flag 为 `false` 则退出；
/// - rx 关闭则退出。
async fn run_loop(
    creator: Arc<dyn WriterCreator>,
    inner: Arc<Mutex<Inner>>,
    mut rx: mpsc::Receiver<Message>,
) {
    let writer = match creator.create() {
        Some(w) => w,
        None => {
            inner.lock().running = false;
            return;
        },
    };

    let mut ticker = tokio::time::interval(IDLE_FLUSH_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // 跳过 `interval` 第一次立即触发——否则第一次 await 立即 tick 1 退出。
    ticker.tick().await;

    let mut data_written = false;
    loop {
        tokio::select! {
            biased;
            maybe = rx.recv() => {
                match maybe {
                    Some(msg) => {
                        let line = format_message(&msg);
                        let _ = writer.write(&line);
                        let _ = writer.flush();
                        data_written = true;
                    }
                    None => break,
                }
            }
            _ = ticker.tick() => {
                if !data_written {
                    break;
                }
                data_written = false;
            }
        }
    }

    let _ = writer.flush();
    inner.lock().running = false;
}

impl Handler for GeneralLogger {
    fn handle(&self, message: &Message) {
        self.handle_message(message);
    }
}

/// 格式化单行：`[severity] content`。Go `msg.String()` 等价。
fn format_message(msg: &Message) -> String {
    format!("[{}] {}", msg.severity.as_str(), msg.content)
}

// ── 测试 ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use parking_lot::Mutex;

    use super::*;
    use crate::log::Severity;

    /// 测试用 writer，把每行累计到共享 buffer。
    struct CollectingWriter {
        lines: Arc<Mutex<Vec<String>>>,
    }

    impl Writer for CollectingWriter {
        fn write(&self, line: &str) -> io::Result<()> {
            self.lines.lock().push(line.to_string());
            Ok(())
        }
    }

    struct CollectingCreator {
        lines: Arc<Mutex<Vec<String>>>,
    }

    impl WriterCreator for CollectingCreator {
        fn create(&self) -> Option<Box<dyn Writer>> {
            Some(Box::new(CollectingWriter { lines: Arc::clone(&self.lines) }))
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_buffers_and_writer_receives() {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let creator = Arc::new(CollectingCreator { lines: Arc::clone(&lines) });
        let logger = GeneralLogger::new(creator);

        logger.handle_message(&Message::new(Severity::Info, "hello"));
        logger.handle_message(&Message::new(Severity::Error, "world"));

        tokio::time::sleep(Duration::from_millis(50)).await;
        logger.close().await;

        let captured = lines.lock().clone();
        assert_eq!(captured.len(), 2, "expected 2 lines, got {:?}", captured);
        assert_eq!(captured[0], "[info] hello");
        assert_eq!(captured[1], "[error] world");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_drops_when_channel_full() {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let creator = Arc::new(CollectingCreator { lines: Arc::clone(&lines) });
        let logger = GeneralLogger::new(creator);

        for i in 0..200 {
            logger.handle_message(&Message::new(Severity::Info, format!("m{i}")));
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
        logger.close().await;

        let captured = lines.lock();
        assert!(captured.len() <= 128, "chan cap=128 but got {}", captured.len());
        assert!(!captured.is_empty());
    }

    /// 并发 handle_message 不应启动多个 task：`running` flag 防并发。
    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_handle_only_one_backend_task() {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let creator = Arc::new(CollectingCreator { lines: Arc::clone(&lines) });
        let logger = Arc::new(GeneralLogger::new(creator));

        let mut joins = Vec::new();
        for _ in 0..8 {
            let l = Arc::clone(&logger);
            joins.push(tokio::spawn(async move {
                for i in 0..10 {
                    l.handle_message(&Message::new(Severity::Info, format!("m{i}")));
                }
            }));
        }
        for j in joins {
            j.await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        logger.close().await;

        let captured = lines.lock();
        // 8 threads × 10 msgs = 80 条上限。
        assert!(captured.len() <= 80, "got {} > 80", captured.len());
        assert!(!captured.is_empty());
    }

    #[test]
    fn format_message_includes_severity_and_content() {
        let m = Message::new(Severity::Warning, "x");
        assert_eq!(format_message(&m), "[warning] x");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn close_then_handle_does_not_deadlock() {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let creator = Arc::new(CollectingCreator { lines: Arc::clone(&lines) });
        let logger = GeneralLogger::new(creator);

        logger.handle_message(&Message::new(Severity::Info, "first"));
        logger.close().await;
        logger.handle_message(&Message::new(Severity::Info, "second"));
        tokio::time::sleep(Duration::from_millis(50)).await;
        logger.close().await;

        let captured = lines.lock();
        assert!(
            captured.iter().any(|l| l == "[info] first"),
            "first message must be flushed before close returns; got {:?}",
            captured
        );
    }

    /// Creator 返回 None 时 task 立即退出；handle 不阻塞、不 panic。
    #[tokio::test(flavor = "current_thread")]
    async fn none_creator_task_exits_cleanly() {
        struct NoneCreator;
        impl WriterCreator for NoneCreator {
            fn create(&self) -> Option<Box<dyn Writer>> {
                None
            }
        }

        let logger = GeneralLogger::new(Arc::new(NoneCreator));
        logger.handle_message(&Message::new(Severity::Info, "drop me"));
        tokio::time::sleep(Duration::from_millis(50)).await;
        // 即使后台 task 已退出，close 仍应正常返回（take handle 为 None）。
        logger.close().await;
        // 状态可观察：running 已被释放。
        assert!(!logger.inner.lock().running);
    }
}
