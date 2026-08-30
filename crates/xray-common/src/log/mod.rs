//! 日志基础设施
//!
//! 对应 Go 版本 `common/log` 包，提供日志级别、消息类型、处理器接口和全局注册表。
//! 带通道缓冲的通用 Logger 见 [`general_logger`]。
//!



use std::fmt;
use std::sync::Arc;
use std::sync::RwLock;

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
        Self {
            severity,
            content: content.into(),
        }
    }
}

/// 日志处理器 trait。
pub trait Handler: Send + Sync {
    /// 处理一条日志消息。
    fn handle(&self, message: &Message);
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
        Self {
            message,
            timestamp: std::time::SystemTime::now(),
        }
    }
}

/// 全局处理器列表。
static HANDLERS: std::sync::LazyLock<RwLock<Vec<Arc<dyn Handler>>>> =
    std::sync::LazyLock::new(|| RwLock::new(Vec::new()));

/// 注册全局日志处理器。
pub fn register_handler(handler: Arc<dyn Handler>) {
    if let Ok(mut handlers) = HANDLERS.write() {
        handlers.push(handler);
    }
}

/// 通过所有已注册的处理器记录消息。
pub fn log(message: Message) {
    if let Ok(handlers) = HANDLERS.read() {
        for handler in handlers.iter() {
            handler.handle(&message);
        }
    }
}

/// 记录 Debug 级别日志。
pub fn debug(content: impl Into<String>) {
    let msg = content.into();
    tracing::debug!("{}", msg);
    log(Message::new(Severity::Debug, msg));
}

/// 记录 Info 级别日志。
pub fn info(content: impl Into<String>) {
    let msg = content.into();
    tracing::info!("{}", msg);
    log(Message::new(Severity::Info, msg));
}

/// 记录 Warning 级别日志。
pub fn warning(content: impl Into<String>) {
    let msg = content.into();
    tracing::warn!("{}", msg);
    log(Message::new(Severity::Warning, msg));
}

/// 记录 Error 级别日志。
pub fn error(content: impl Into<String>) {
    let msg = content.into();
    tracing::error!("{}", msg);
    log(Message::new(Severity::Error, msg));
}

/// 清除所有已注册的处理器（仅用于测试）。
#[cfg(test)]
fn clear_handlers() {
    if let Ok(mut handlers) = HANDLERS.write() {
        handlers.clear();
    }
}


/// 带通道缓冲的通用 Logger，对应 Go `common/log/logger.go::generalLogger`。
pub mod general_logger;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

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

    /// 测试用处理器，收集消息到共享向量中。
    struct TestHandler {
        messages: Mutex<Vec<Message>>,
    }

    impl TestHandler {
        fn new() -> Self {
            Self {
                messages: Mutex::new(Vec::new()),
            }
        }

        fn messages(&self) -> Vec<Message> {
            self.messages.lock().map(|m| m.clone()).unwrap_or_default()
        }
    }

    impl Handler for TestHandler {
        fn handle(&self, message: &Message) {
            if let Ok(mut msgs) = self.messages.lock() {
                msgs.push(message.clone());
            }
        }
    }

    #[test]
    fn test_register_and_log() {
        clear_handlers();

        let handler = Arc::new(TestHandler::new());
        let messages_ptr = {
            let h = Arc::downgrade(&handler);
            register_handler(handler);
            // 重新获取引用以检查消息
            h.upgrade().expect("handler should exist")
        };

        log(Message::new(Severity::Info, "hello"));
        log(Message::new(Severity::Error, "world"));

        let msgs = messages_ptr.messages();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].content, "hello");
        assert_eq!(msgs[0].severity, Severity::Info);
        assert_eq!(msgs[1].content, "world");
        assert_eq!(msgs[1].severity, Severity::Error);

        clear_handlers();
    }

    #[test]
    fn test_convenience_functions() {
        clear_handlers();

        let handler = Arc::new(TestHandler::new());
        let messages_ptr = {
            let h = Arc::downgrade(&handler);
            register_handler(handler);
            h.upgrade().expect("handler should exist")
        };

        debug("debug msg");
        info("info msg");
        warning("warn msg");
        error("error msg");

        let msgs = messages_ptr.messages();
        assert_eq!(msgs.len(), 4);
        assert_eq!(msgs[0].severity, Severity::Debug);
        assert_eq!(msgs[1].severity, Severity::Info);
        assert_eq!(msgs[2].severity, Severity::Warning);
        assert_eq!(msgs[3].severity, Severity::Error);

        clear_handlers();
    }
}
