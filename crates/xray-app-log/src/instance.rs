//! 日志消息类型 + LogHandler trait + HandlerCreator 注册机制 + Instance 编排。
//!
//! 对应 Go `app/log/log.go` 的 `Instance` + `Handle` 分发，
//! 与 `app/log/log_creator.go` 的全局 `handlerCreatorMap`。

use std::sync::Arc;

use parking_lot::RwLock;
use std::collections::HashMap;

use crate::config::{LogConfig, LogType, SeverityLevel};
use crate::error::{at_error, at_warning, LogError};
use crate::mask::mask_addresses;

/// Access 日志状态：accepted / rejected。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessStatus {
    Accepted,
    Rejected,
}

impl AccessStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }
}

/// Access 日志消息（对应 Go `log.AccessMessage`）。
#[derive(Debug, Clone, Default)]
pub struct AccessMessage {
    pub from: String,
    pub to: String,
    pub email: String,
    pub tag: String,
    pub status: Option<AccessStatus>,
    pub reason: String,
}

impl AccessMessage {
    /// 序列化为单行字符串（与 Go 版 `String()` 类似格式）。
    pub fn format(&self) -> String {
        let st = self
            .status
            .map(|s| s.as_str())
            .unwrap_or("unknown");
        format!(
            "from {} to {} email={} tag={} status={} reason={}",
            self.from, self.to, self.email, self.tag, st, self.reason,
        )
    }
}

/// DNS 日志消息（对应 Go `log.DNSLog`）。
#[derive(Debug, Clone, Default)]
pub struct DnsLog {
    pub query: String,
    pub domain: String,
    pub result: String,
}

impl DnsLog {
    pub fn format(&self) -> String {
        format!("dns query={} domain={} result={}", self.query, self.domain, self.result)
    }
}

/// 通用日志消息（对应 Go `log.GeneralMessage`）。
#[derive(Debug, Clone)]
pub struct GeneralMessage {
    pub severity: SeverityLevel,
    pub content: String,
}

impl GeneralMessage {
    pub fn format(&self) -> String {
        format!("[{}] {}", self.severity.as_i32(), self.content)
    }
}

/// Log 消息枚举：按类型路由到 access/dns/error logger。
#[derive(Debug, Clone)]
pub enum LogEntry {
    Access(AccessMessage),
    Dns(DnsLog),
    General(GeneralMessage),
}

impl LogEntry {
    /// 序列化为字符串表示（用于日志 handler 输出）。
    pub fn format(&self) -> String {
        match self {
            Self::Access(m) => m.format(),
            Self::Dns(m) => m.format(),
            Self::General(m) => m.format(),
        }
    }
}

/// LogHandler trait：实际写日志的处理器（file/console/none）。
///
/// 对应 Go `log.Handler` interface。
pub trait LogHandler: Send + Sync {
    fn handle(&self, entry: &LogEntry);
}

/// HandlerCreator options（对应 Go `HandlerCreatorOptions`）。
#[derive(Debug, Clone, Default)]
pub struct HandlerCreatorOptions {
    pub path: String,
}

/// Handler 工厂函数 trait。
pub trait HandlerCreator: Send + Sync {
    fn create(&self, log_type: LogType, options: &HandlerCreatorOptions)
        -> Result<Option<Arc<dyn LogHandler>>, LogError>;
}

/// 全局 handler creator 注册表。
///
/// 对应 Go `handlerCreatorMap` + `handlerCreatorMapLock`。
pub struct HandlerCreatorRegistry {
    inner: RwLock<HashMap<LogType, Arc<dyn HandlerCreator>>>,
}

impl HandlerCreatorRegistry {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// 注册 creator；若已存在则返回 DuplicateHandlerCreator。
    pub fn register(
        &self,
        log_type: LogType,
        creator: Arc<dyn HandlerCreator>,
    ) -> Result<(), LogError> {
        let mut g = self.inner.write();
        if g.contains_key(&log_type) {
            return Err(LogError::DuplicateHandlerCreator(log_type));
        }
        g.insert(log_type, creator);
        Ok(())
    }

    /// 创建 handler；未注册则返回 NoHandlerCreator。
    pub fn create(
        &self,
        log_type: LogType,
        options: &HandlerCreatorOptions,
    ) -> Result<Option<Arc<dyn LogHandler>>, LogError> {
        let g = self.inner.read();
        let Some(creator) = g.get(&log_type) else {
            return Err(LogError::NoHandlerCreator(log_type));
        };
        let creator = creator.clone();
        drop(g);
        creator.create(log_type, options)
    }
}

impl Default for HandlerCreatorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// None 类型 handler creator：永远返回 None（与 Go 注册的 None creator 一致）。
pub struct NoneHandlerCreator;
impl HandlerCreator for NoneHandlerCreator {
    fn create(
        &self,
        _log_type: LogType,
        _options: &HandlerCreatorOptions,
    ) -> Result<Option<Arc<dyn LogHandler>>, LogError> {
        Ok(None)
    }
}

/// 把 handler 包装一层，对 entry 内容做 mask 处理后再转发。
///
/// 对应 Go `MaskedMsgWrapper`：当 mask != (32, 128) 时，对 LogEntry 的所有
/// String 字段执行 IP 掩码替换。
pub struct MaskingHandler {
    inner: Arc<dyn LogHandler>,
    mask4: i32,
    mask6: i32,
}

impl MaskingHandler {
    pub fn new(inner: Arc<dyn LogHandler>, mask4: i32, mask6: i32) -> Self {
        Self { inner, mask4, mask6 }
    }

    fn apply(&self, entry: &LogEntry) -> LogEntry {
        if self.mask4 == 32 && self.mask6 == 128 {
            return entry.clone();
        }
        match entry {
            LogEntry::Access(m) => LogEntry::Access(AccessMessage {
                from: mask_addresses(&m.from, self.mask4, self.mask6),
                to: mask_addresses(&m.to, self.mask4, self.mask6),
                email: m.email.clone(),
                tag: m.tag.clone(),
                status: m.status,
                reason: mask_addresses(&m.reason, self.mask4, self.mask6),
            }),
            LogEntry::Dns(m) => LogEntry::Dns(DnsLog {
                query: mask_addresses(&m.query, self.mask4, self.mask6),
                domain: mask_addresses(&m.domain, self.mask4, self.mask6),
                result: mask_addresses(&m.result, self.mask4, self.mask6),
            }),
            LogEntry::General(m) => LogEntry::General(GeneralMessage {
                severity: m.severity,
                content: mask_addresses(&m.content, self.mask4, self.mask6),
            }),
        }
    }
}

impl LogHandler for MaskingHandler {
    fn handle(&self, entry: &LogEntry) {
        let masked = self.apply(entry);
        self.inner.handle(&masked);
    }
}

/// LogInstance：主编排类，对应 Go `app/log.Instance`。
///
/// 持有 config + access_logger + error_logger + 状态字段，编排：
///   - `start()`：用注册表创建 access/error handler
///   - `handle(entry)`：按消息类型路由（access / dns / error）
///   - `close()`：丢弃 handler
pub struct LogInstance {
    config: LogConfig,
    mask4: i32,
    mask6: i32,
    inner: RwLock<InstanceInner>,
}

struct InstanceInner {
    active: bool,
    access_logger: Option<Arc<dyn LogHandler>>,
    error_logger: Option<Arc<dyn LogHandler>>,
}

impl LogInstance {
    /// 用配置 + mask 解析结果构造（已外部解析过 mask）。
    pub fn new_with_mask(config: LogConfig, mask4: i32, mask6: i32) -> Self {
        Self {
            config,
            mask4,
            mask6,
            inner: RwLock::new(InstanceInner {
                active: false,
                access_logger: None,
                error_logger: None,
            }),
        }
    }

    /// 用配置构造，自动解析 mask_address。
    pub fn new(config: LogConfig) -> Result<Self, LogError> {
        let (m4, m6) = crate::mask::parse_mask_address(&config.mask_address)?;
        Ok(Self::new_with_mask(config, m4, m6))
    }

    pub fn config(&self) -> &LogConfig {
        &self.config
    }

    pub fn mask4(&self) -> i32 {
        self.mask4
    }

    pub fn mask6(&self) -> i32 {
        self.mask6
    }

    /// Start：用 registry 创建 handler 并标记 active。
    pub fn start(&self, registry: &HandlerCreatorRegistry) -> Result<(), LogError> {
        let mut g = self.inner.write();
        if g.active {
            return Ok(());
        }

        let access_opts = HandlerCreatorOptions {
            path: self.config.access_log_path.clone(),
        };
        match registry.create(self.config.access_log_type, &access_opts) {
            Ok(h) => g.access_logger = h.map(|h| self.wrap_with_mask(h)),
            Err(e) => {
                at_warning(&LogError::HandlerCreate(format!(
                    "access logger init failed: {e}"
                )));
            }
        }

        let error_opts = HandlerCreatorOptions {
            path: self.config.error_log_path.clone(),
        };
        match registry.create(self.config.error_log_type, &error_opts) {
            Ok(h) => g.error_logger = h.map(|h| self.wrap_with_mask(h)),
            Err(e) => {
                at_warning(&LogError::HandlerCreate(format!(
                    "error logger init failed: {e}"
                )));
            }
        }

        g.active = true;
        Ok(())
    }

    fn wrap_with_mask(&self, handler: Arc<dyn LogHandler>) -> Arc<dyn LogHandler> {
        if self.mask4 == 32 && self.mask6 == 128 {
            handler
        } else {
            Arc::new(MaskingHandler::new(handler, self.mask4, self.mask6))
        }
    }

    /// Close：标记 inactive + 清空 handler。
    pub fn close(&self) {
        let mut g = self.inner.write();
        if !g.active {
            return;
        }
        g.active = false;
        g.access_logger = None;
        g.error_logger = None;
    }

    /// 是否已启动。
    pub fn is_active(&self) -> bool {
        self.inner.read().active
    }

    /// 处理一条日志：按类型分发。
    ///
    /// - Access → access_logger（若注册）
    /// - Dns → 仅当 enable_dns_log && access_logger（若注册）
    /// - General → error_logger（若注册 且 severity <= error_log_level）
    pub fn handle(&self, entry: &LogEntry) {
        let g = self.inner.read();
        if !g.active {
            return;
        }
        match entry {
            LogEntry::Access(_) => {
                if let Some(h) = &g.access_logger {
                    h.handle(entry);
                }
            }
            LogEntry::Dns(_) => {
                if self.config.enable_dns_log {
                    if let Some(h) = &g.access_logger {
                        h.handle(entry);
                    }
                }
            }
            LogEntry::General(m) => {
                if m.severity <= self.config.error_log_level {
                    if let Some(h) = &g.error_logger {
                        h.handle(entry);
                    }
                }
            }
        }
    }

    /// 重启：close + start。
    pub fn restart(&self, registry: &HandlerCreatorRegistry) -> Result<(), LogError> {
        self.close();
        self.start(registry).map_err(|e| {
            at_error(&e);
            e
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// 测试用 LogHandler：把 entry format 后追加到共享 Vec。
    struct CapturingHandler {
        recorded: Mutex<Vec<String>>,
    }

    impl CapturingHandler {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                recorded: Mutex::new(Vec::new()),
            })
        }
        fn snapshot(&self) -> Vec<String> {
            self.recorded.lock().unwrap().clone()
        }
    }

    impl LogHandler for CapturingHandler {
        fn handle(&self, entry: &LogEntry) {
            self.recorded.lock().unwrap().push(entry.format());
        }
    }

    struct FixedCreator {
        handler: Arc<dyn LogHandler>,
    }
    impl HandlerCreator for FixedCreator {
        fn create(
            &self,
            _t: LogType,
            _o: &HandlerCreatorOptions,
        ) -> Result<Option<Arc<dyn LogHandler>>, LogError> {
            Ok(Some(self.handler.clone()))
        }
    }

    fn registry_with_console(handler: Arc<dyn LogHandler>) -> HandlerCreatorRegistry {
        let r = HandlerCreatorRegistry::new();
        r.register(
            LogType::Console,
            Arc::new(FixedCreator {
                handler: handler.clone(),
            }),
        )
        .unwrap();
        r.register(LogType::File, Arc::new(FixedCreator { handler }))
            .unwrap();
        r
    }

    #[test]
    fn access_status_str() {
        assert_eq!(AccessStatus::Accepted.as_str(), "accepted");
        assert_eq!(AccessStatus::Rejected.as_str(), "rejected");
    }

    #[test]
    fn access_format_contains_key_fields() {
        let m = AccessMessage {
            from: "1.1.1.1".into(),
            to: "2.2.2.2".into(),
            email: "u@e".into(),
            tag: "t".into(),
            status: Some(AccessStatus::Accepted),
            reason: "ok".into(),
        };
        let s = m.format();
        assert!(s.contains("1.1.1.1"));
        assert!(s.contains("2.2.2.2"));
        assert!(s.contains("u@e"));
        assert!(s.contains("accepted"));
    }

    #[test]
    fn dns_format_contains_fields() {
        let m = DnsLog {
            query: "A example.com".into(),
            domain: "example.com".into(),
            result: "ok".into(),
        };
        let s = m.format();
        assert!(s.contains("example.com"));
        assert!(s.contains("A example.com"));
    }

    #[test]
    fn general_format_contains_severity_and_content() {
        let m = GeneralMessage {
            severity: SeverityLevel::Warning,
            content: "watch out".into(),
        };
        let s = m.format();
        assert!(s.contains("watch out"));
    }

    #[test]
    fn entry_format_dispatches() {
        let a = LogEntry::Access(AccessMessage::default());
        let d = LogEntry::Dns(DnsLog::default());
        let g = LogEntry::General(GeneralMessage {
            severity: SeverityLevel::Info,
            content: "x".into(),
        });
        assert!(!a.format().is_empty());
        assert!(!d.format().is_empty());
        assert!(g.format().contains("x"));
    }

    #[test]
    fn registry_register_then_create() {
        let h = CapturingHandler::new();
        let r = registry_with_console(h);
        let created = r
            .create(LogType::Console, &HandlerCreatorOptions::default())
            .unwrap();
        assert!(created.is_some());
    }

    #[test]
    fn registry_duplicate_register_rejected() {
        let r = HandlerCreatorRegistry::new();
        r.register(
            LogType::Console,
            Arc::new(NoneHandlerCreator),
        )
        .unwrap();
        let err = r
            .register(LogType::Console, Arc::new(NoneHandlerCreator))
            .unwrap_err();
        assert!(matches!(err, LogError::DuplicateHandlerCreator(LogType::Console)));
    }

    #[test]
    fn registry_create_unknown_returns_err() {
        let r = HandlerCreatorRegistry::new();
        let err = match r.create(LogType::Event, &HandlerCreatorOptions::default()) {
            Err(e) => e,
            Ok(_) => panic!("expected Err"),
        };
        assert!(matches!(err, LogError::NoHandlerCreator(LogType::Event)));
    }

    #[test]
    fn none_creator_returns_none_handler() {
        let r = HandlerCreatorRegistry::new();
        r.register(LogType::None, Arc::new(NoneHandlerCreator))
            .unwrap();
        let h = r
            .create(LogType::None, &HandlerCreatorOptions::default())
            .unwrap();
        assert!(h.is_none());
    }

    #[test]
    fn instance_start_marks_active() {
        let cfg = LogConfig::default();
        let inst = LogInstance::new(cfg).unwrap();
        let r = HandlerCreatorRegistry::new();
        r.register(LogType::Console, Arc::new(NoneHandlerCreator))
            .unwrap();
        r.register(LogType::None, Arc::new(NoneHandlerCreator))
            .unwrap();
        assert!(!inst.is_active());
        inst.start(&r).unwrap();
        assert!(inst.is_active());
    }

    #[test]
    fn instance_start_twice_is_noop() {
        let cfg = LogConfig::default();
        let inst = LogInstance::new(cfg).unwrap();
        let r = HandlerCreatorRegistry::new();
        r.register(LogType::Console, Arc::new(NoneHandlerCreator))
            .unwrap();
        r.register(LogType::None, Arc::new(NoneHandlerCreator))
            .unwrap();
        inst.start(&r).unwrap();
        inst.start(&r).unwrap();
        assert!(inst.is_active());
    }

    #[test]
    fn instance_close_clears_active() {
        let cfg = LogConfig::default();
        let inst = LogInstance::new(cfg).unwrap();
        let r = HandlerCreatorRegistry::new();
        r.register(LogType::Console, Arc::new(NoneHandlerCreator))
            .unwrap();
        r.register(LogType::None, Arc::new(NoneHandlerCreator))
            .unwrap();
        inst.start(&r).unwrap();
        inst.close();
        assert!(!inst.is_active());
    }

    #[test]
    fn instance_close_twice_is_noop() {
        let cfg = LogConfig::default();
        let inst = LogInstance::new(cfg).unwrap();
        inst.close();
        inst.close();
        assert!(!inst.is_active());
    }

    #[test]
    fn instance_handle_when_inactive_is_dropped() {
        let cfg = LogConfig::default();
        let inst = LogInstance::new(cfg).unwrap();
        let entry = LogEntry::General(GeneralMessage {
            severity: SeverityLevel::Error,
            content: "x".into(),
        });
        inst.handle(&entry); // not active → dropped
    }

    #[test]
    fn instance_handle_access_routes_to_handler() {
        let h = CapturingHandler::new();
        let snap = h.clone();

        // 自定义 registry 直接返回 capturing handler
        let r = HandlerCreatorRegistry::new();
        r.register(LogType::Console, Arc::new(FixedCreator { handler: h }))
            .unwrap();

        let mut cfg = LogConfig::default();
        cfg.access_log_type = LogType::Console;
        let inst = LogInstance::new(cfg).unwrap();
        inst.start(&r).unwrap();

        let entry = LogEntry::Access(AccessMessage {
            from: "1.1.1.1".into(),
            ..Default::default()
        });
        inst.handle(&entry);
        let s = snap.snapshot();
        assert_eq!(s.len(), 1);
        assert!(s[0].contains("1.1.1.1"));
    }

    #[test]
    fn instance_handle_dns_disabled_drops() {
        let h = CapturingHandler::new();
        let snap = h.clone();
        let r = HandlerCreatorRegistry::new();
        r.register(LogType::Console, Arc::new(FixedCreator { handler: h }))
            .unwrap();

        let mut cfg = LogConfig::default();
        cfg.access_log_type = LogType::Console;
        cfg.enable_dns_log = false;
        let inst = LogInstance::new(cfg).unwrap();
        inst.start(&r).unwrap();
        inst.handle(&LogEntry::Dns(DnsLog {
            query: "q".into(),
            ..Default::default()
        }));
        assert!(snap.snapshot().is_empty());
    }

    #[test]
    fn instance_handle_dns_enabled_routes() {
        let h = CapturingHandler::new();
        let snap = h.clone();
        let r = HandlerCreatorRegistry::new();
        r.register(LogType::Console, Arc::new(FixedCreator { handler: h }))
            .unwrap();

        let mut cfg = LogConfig::default();
        cfg.access_log_type = LogType::Console;
        cfg.enable_dns_log = true;
        let inst = LogInstance::new(cfg).unwrap();
        inst.start(&r).unwrap();
        inst.handle(&LogEntry::Dns(DnsLog {
            query: "Q".into(),
            ..Default::default()
        }));
        assert_eq!(snap.snapshot().len(), 1);
    }

    #[test]
    fn instance_handle_general_below_level_drops() {
        let h = CapturingHandler::new();
        let snap = h.clone();
        let r = HandlerCreatorRegistry::new();
        r.register(LogType::Console, Arc::new(FixedCreator { handler: h }))
            .unwrap();

        let mut cfg = LogConfig::default();
        cfg.error_log_type = LogType::Console;
        cfg.error_log_level = SeverityLevel::Error; // 只记 Error
        let inst = LogInstance::new(cfg).unwrap();
        inst.start(&r).unwrap();

        inst.handle(&LogEntry::General(GeneralMessage {
            severity: SeverityLevel::Debug, // Debug > Error，被丢弃
            content: "ignored".into(),
        }));
        assert!(snap.snapshot().is_empty());
    }

    #[test]
    fn instance_handle_general_at_level_routes() {
        let h = CapturingHandler::new();
        let snap = h.clone();
        let r = HandlerCreatorRegistry::new();
        r.register(LogType::Console, Arc::new(FixedCreator { handler: h }))
            .unwrap();

        let mut cfg = LogConfig::default();
        cfg.error_log_type = LogType::Console;
        cfg.error_log_level = SeverityLevel::Warning;
        let inst = LogInstance::new(cfg).unwrap();
        inst.start(&r).unwrap();

        inst.handle(&LogEntry::General(GeneralMessage {
            severity: SeverityLevel::Warning,
            content: "kept".into(),
        }));
        assert_eq!(snap.snapshot().len(), 1);
    }

    #[test]
    fn masking_handler_applies_mask() {
        let h = CapturingHandler::new();
        let snap = h.clone();
        let masked: Arc<dyn LogHandler> = Arc::new(MaskingHandler::new(h, 0, 128));
        masked.handle(&LogEntry::General(GeneralMessage {
            severity: SeverityLevel::Info,
            content: "from 192.168.1.1".into(),
        }));
        let s = snap.snapshot();
        assert!(s[0].contains("[Masked IPv4]"));
        assert!(!s[0].contains("192.168.1.1"));
    }

    #[test]
    fn masking_handler_no_mask_passthrough() {
        let h = CapturingHandler::new();
        let snap = h.clone();
        let masked: Arc<dyn LogHandler> = Arc::new(MaskingHandler::new(h, 32, 128));
        masked.handle(&LogEntry::General(GeneralMessage {
            severity: SeverityLevel::Info,
            content: "from 192.168.1.1".into(),
        }));
        let s = snap.snapshot();
        assert!(s[0].contains("192.168.1.1"));
    }

    #[test]
    fn restart_close_then_start() {
        let h = CapturingHandler::new();
        let r = HandlerCreatorRegistry::new();
        r.register(LogType::Console, Arc::new(FixedCreator { handler: h }))
            .unwrap();
        r.register(LogType::None, Arc::new(NoneHandlerCreator))
            .unwrap();
        let cfg = LogConfig::default();
        let inst = LogInstance::new(cfg).unwrap();
        inst.start(&r).unwrap();
        assert!(inst.is_active());
        inst.restart(&r).unwrap();
        assert!(inst.is_active());
    }

    #[test]
    fn instance_new_invalid_mask_returns_err() {
        let mut cfg = LogConfig::default();
        cfg.mask_address = "7+64".into(); // ipv4 mask 不整除 8
        let r = LogInstance::new(cfg);
        assert!(r.is_err());
    }

    #[test]
    fn instance_mask_getters_expose_parsed() {
        let mut cfg = LogConfig::default();
        cfg.mask_address = "half".into();
        let inst = LogInstance::new(cfg).unwrap();
        assert_eq!(inst.mask4(), 16);
        assert_eq!(inst.mask6(), 32);
    }

    // 确保关键类型 Send + Sync
    fn _assert<T: Send + Sync>() {}

    #[test]
    fn types_are_send_sync() {
        _assert::<HandlerCreatorRegistry>();
        _assert::<LogInstance>();
        _assert::<Arc<dyn LogHandler>>();
        _assert::<Arc<dyn HandlerCreator>>();
        _assert::<MaskingHandler>();
    }
}
