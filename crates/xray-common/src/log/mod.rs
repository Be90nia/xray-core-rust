//! 日志基础设施
//!
//! 对应 Go 版本 `common/log` 包，提供日志级别、消息类型与全局通道注册表。
//!
//! 分发机制（P1-10-b）：旧 `HANDLERS` 无差别扇出 + `tracing` 双写已收敛为
//! udf `logx::ChannelRegistry` **单入口**——general/access/dns 三固定通道，
//! 每通道独立 sink 与 level（`channels()`/`register_channel` 装配期注册，
//! 未注册通道 emit 首次告警一行后静默，写失败计数可观测）。便捷入口（[`debug`]/[`info`]/
//! [`warning`]/[`error`]）只走 general 通道一路，不再直发 tracing。
//! Go 级别别名（[`Severity::as_str`]）与消息语义留仓不动。
//! 带通道缓冲的通用 Logger 见 [`general_logger`]。

use std::{fmt, sync::Arc};

// udf 通道类型的宿主侧可见性：实现 `ChannelSink` 需命名 trait 与 `Channel`/
// `log::Level`/`LevelFilter`（udf trait 签名用到），不 re-export 则宿主只能
// 依赖 udf 仓直连（第二套依赖面）。此处只做**转发**，不新增机制。
pub use ::log::{Level, LevelFilter};
pub use skeleton_infra::logx::{Channel, ChannelSink};
use skeleton_infra::logx::{ChannelError, ChannelRegistry};

/// general 通道落样 target（埋点规范 `xray_frame::<域>`，域 = `log`）。
const GENERAL_TARGET: &str = "xray_frame::log";

/// 日志严重级别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Debug,
    Info,
    Warning,
    Error,
}

impl Severity {
    /// 返回级别的字符串表示。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    /// 通道扇出的级别轴（`log::Level`）；Go 级别别名 [`Self::as_str`] 不受影响。
    fn to_log_level(self) -> log::Level {
        match self {
            Self::Debug => log::Level::Debug,
            Self::Info => log::Level::Info,
            // log 门面无 "warning"，Go 别名文案由 sink 侧还原（见 general_logger）。
            Self::Warning => log::Level::Warn,
            Self::Error => log::Level::Error,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 日志消息。
#[derive(Debug, Clone)]
pub struct Message {
    /// 消息严重级别
    pub severity: Severity,
    /// 消息内容
    pub content: String,
}

impl Message {
    /// 创建新的日志消息。
    pub fn new(severity: Severity, content: impl Into<String>) -> Self {
        Self { severity, content: content.into() }
    }
}

/// 带时间戳的日志记录。
#[derive(Debug, Clone)]
pub struct Record {
    /// 日志消息
    pub message: Message,
    /// 记录时间戳
    pub timestamp: std::time::SystemTime,
}

impl Record {
    /// 从消息创建新记录，时间戳为当前时间。
    pub fn new(message: Message) -> Self {
        Self { message, timestamp: std::time::SystemTime::now() }
    }
}

/// 全局通道注册表：general/access/dns 三固定通道的单入口分发（替代旧
/// `HANDLERS` 无差别扇出）。未注册通道 emit 首次告警一行后静默（bd 8zs12：
/// 「日志写了没人看见」必须留痕；告警走 tracing，不递归走本通道）；
/// 同通道重复注册 fail-visible；装配期注册一次，进程生命期使用。
static CHANNELS: std::sync::LazyLock<ChannelRegistry> =
    std::sync::LazyLock::new(ChannelRegistry::new);

/// General 槽已注册标记（[`register_channel`] 落笔；未注册告警的判定面）。
static GENERAL_REGISTERED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
/// 未注册告警已发标记（进程级只告警一次）。
static UNREGISTERED_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// 全局通道注册表（装配期注册 sink / 配置密钥掩码 `set_secrets` / 观测丢弃
/// 计数 `dropped_total`）。
pub fn channels() -> &'static ChannelRegistry {
    &CHANNELS
}

/// 注册全局通道 sink（同通道二次注册 = Err，fail-visible，原 sink 不动）。
pub fn register_channel(sink: Arc<dyn ChannelSink>) -> Result<(), ChannelError> {
    let is_general = sink.channel() == Channel::General;
    let result = CHANNELS.register(sink);
    if result.is_ok() && is_general {
        GENERAL_REGISTERED.store(true, std::sync::atomic::Ordering::Release);
    }
    result
}

/// 通过 general 通道记录消息（单入口；无双写）。General 槽未注册时首次
/// 告警一行（fail-visible），消息本身仍静默丢弃（udf 装配期纪律不变）。
pub fn log(message: Message) {
    warn_once_if_general_unregistered();
    CHANNELS.emit(
        Channel::General,
        message.severity.to_log_level(),
        GENERAL_TARGET,
        &message.content,
    );
}

/// 未注册 General 槽的 emit 首次告警一行后静默（bd 8zs12：日志基础设施自身
/// 缺装配时，「写了没人看见」必须留痕；生产 xray-cli 启动即装 tracing 订阅者，
/// 告警可见）。告警走 tracing 直发，不经本通道——递归无意义且槽正是缺的那路。
fn warn_once_if_general_unregistered() {
    if GENERAL_REGISTERED.load(std::sync::atomic::Ordering::Acquire) {
        return;
    }
    if UNREGISTERED_WARNED.swap(true, std::sync::atomic::Ordering::AcqRel) {
        return;
    }
    tracing::warn!(
        target: GENERAL_TARGET,
        "general log channel has no sink registered; messages are dropped \
         (warn once; register via xray_common::log::register_channel)"
    );
}

/// 记录 Debug 级别日志。
pub fn debug(content: impl Into<String>) {
    log(Message::new(Severity::Debug, content));
}

/// 记录 Info 级别日志。
pub fn info(content: impl Into<String>) {
    log(Message::new(Severity::Info, content));
}

/// 记录 Warning 级别日志。
pub fn warning(content: impl Into<String>) {
    log(Message::new(Severity::Warning, content));
}

/// 记录 Error 级别日志。
pub fn error(content: impl Into<String>) {
    log(Message::new(Severity::Error, content));
}

/// 带通道缓冲的通用 Logger，对应 Go `common/log/logger.go::generalLogger`。
pub mod general_logger;

#[cfg(test)]
mod tests {
    use parking_lot::Mutex;

    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Debug < Severity::Info);
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
    }

    #[test]
    fn test_severity_as_str() {
        assert_eq!(Severity::Debug.as_str(), "debug");
        assert_eq!(Severity::Info.as_str(), "info");
        assert_eq!(Severity::Warning.as_str(), "warning");
        assert_eq!(Severity::Error.as_str(), "error");
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", Severity::Debug), "debug");
        assert_eq!(format!("{}", Severity::Error), "error");
    }

    #[test]
    fn test_message_new() {
        let msg = Message::new(Severity::Info, "test message");
        assert_eq!(msg.severity, Severity::Info);
        assert_eq!(msg.content, "test message");
    }

    #[test]
    fn test_record_new() {
        let msg = Message::new(Severity::Warning, "record test");
        let record = Record::new(msg);
        assert_eq!(record.message.severity, Severity::Warning);
        assert_eq!(record.message.content, "record test");
        // 时间戳应该接近当前时间
        assert!(record.timestamp.elapsed().is_ok());
    }

    /// 测试用通道 sink，捕获 (级别, target, 内容) 到共享向量。
    struct TestSink {
        channel: Channel,
        records: Mutex<Vec<(log::Level, String, String)>>,
    }

    impl TestSink {
        fn new(channel: Channel) -> Arc<Self> {
            Arc::new(Self { channel, records: Mutex::new(Vec::new()) })
        }

        fn records(&self) -> Vec<(log::Level, String, String)> {
            self.records.lock().clone()
        }
    }

    impl ChannelSink for TestSink {
        fn channel(&self) -> Channel {
            self.channel
        }

        fn level(&self) -> log::LevelFilter {
            log::LevelFilter::Trace
        }

        fn write(&self, level: log::Level, target: &str, message: &str) {
            self.records.lock().push((level, target.to_string(), message.to_string()));
        }

        fn dropped_lines(&self) -> u64 {
            0
        }
    }

    /// 全局 `CHANNELS` 在测试间共享且无注销面（udf 装配期一次性纪律），
    /// 用 mutex 串行化触碰全局注册表的测试。
    static CHANNEL_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    #[test]
    fn test_convenience_functions_route_to_general_channel() {
        let _guard = CHANNEL_TEST_LOCK.lock();

        let sink = TestSink::new(Channel::General);
        register_channel(sink.clone()).expect("首注恒 Ok（单测试二进制内仅此一处注册 General）");

        debug("debug msg");
        info("info msg");
        warning("warn msg");
        error("error msg");

        let records = sink.records();
        assert_eq!(records.len(), 4);
        assert_eq!(records[0].0, log::Level::Debug);
        assert_eq!(records[1].0, log::Level::Info);
        assert_eq!(records[2].0, log::Level::Warn);
        assert_eq!(records[3].0, log::Level::Error);
        for (_, target, _) in &records {
            assert_eq!(target, "xray_frame::log", "埋点 target 规范 xray_frame::<域>");
        }
    }
}
