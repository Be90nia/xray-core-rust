//! xray-app-log 配置 + LogType/SeverityLevel 枚举。

use xray_proto::xray::{
    app::log::{Config as ProtoConfig, LogType as ProtoLogType},
    common::log::Severity as ProtoSeverity,
};

use crate::error::LogError;

/// Log 输出类型，对应 proto `LogType`。
///
/// 数值按 proto 顺序，便于 `from_proto_i32` 转换与持久化。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogType {
    None = 0,
    Console = 1,
    File = 2,
    Event = 3,
}

impl LogType {
    /// 从 prost 生成的 proto enum 构造。
    pub fn from_proto(p: ProtoLogType) -> Self {
        match p {
            ProtoLogType::None => Self::None,
            ProtoLogType::Console => Self::Console,
            ProtoLogType::File => Self::File,
            ProtoLogType::Event => Self::Event,
        }
    }

    /// 转回 prost enum。
    pub fn to_proto(self) -> ProtoLogType {
        match self {
            Self::None => ProtoLogType::None,
            Self::Console => ProtoLogType::Console,
            Self::File => ProtoLogType::File,
            Self::Event => ProtoLogType::Event,
        }
    }

    /// 从原始 i32 值构造（prost enum 是 i32 常量）。
    pub fn from_proto_i32(v: i32) -> Result<Self, LogError> {
        match v {
            0 => Ok(Self::None),
            1 => Ok(Self::Console),
            2 => Ok(Self::File),
            3 => Ok(Self::Event),
            other => Err(LogError::InvalidLogType(other)),
        }
    }

    /// i32 数值（对应 proto enum 值）。
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

/// 日志严重级别。
///
/// 对应 proto `xray.common.log.Severity`：数值越大越详细
/// （与 `xray_common::log::Severity` 顺序相反，后者数值越大越严重）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SeverityLevel {
    Unknown = 0,
    Error = 1,
    Warning = 2,
    Info = 3,
    Debug = 4,
}

impl SeverityLevel {
    pub fn from_proto(p: ProtoSeverity) -> Self {
        match p {
            ProtoSeverity::Unknown => Self::Unknown,
            ProtoSeverity::Error => Self::Error,
            ProtoSeverity::Warning => Self::Warning,
            ProtoSeverity::Info => Self::Info,
            ProtoSeverity::Debug => Self::Debug,
        }
    }

    pub fn to_proto(self) -> ProtoSeverity {
        match self {
            Self::Unknown => ProtoSeverity::Unknown,
            Self::Error => ProtoSeverity::Error,
            Self::Warning => ProtoSeverity::Warning,
            Self::Info => ProtoSeverity::Info,
            Self::Debug => ProtoSeverity::Debug,
        }
    }

    pub fn from_proto_i32(v: i32) -> Result<Self, LogError> {
        match v {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::Error),
            2 => Ok(Self::Warning),
            3 => Ok(Self::Info),
            4 => Ok(Self::Debug),
            other => Err(LogError::InvalidSeverity(other)),
        }
    }

    pub fn as_i32(self) -> i32 {
        self as i32
    }

    /// 小写名称（对齐 Go proto `Severity_String`：unknown/error/warning/info/debug）。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }
}

/// 日志输出格式。
///
/// Go v26.6.1 基线无 format 配置（console 单行 `Message.String()`），
/// `json` 为 Rust 侧扩展（对齐 assignment 需求），字段名沿用 Go
/// `log.AccessMessage` 结构体字段小写形式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    #[default]
    Console,
    Json,
}

impl LogFormat {
    /// 从配置字符串解析：`"json"` → Json，其余（含空）→ Console。
    pub fn parse(s: &str) -> Self {
        if s.eq_ignore_ascii_case("json") { Self::Json } else { Self::Console }
    }
}

/// Log 配置，对应 proto `xray.app.log.Config`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogConfig {
    pub error_log_type: LogType,
    pub error_log_level: SeverityLevel,
    pub error_log_path: String,
    pub access_log_type: LogType,
    pub access_log_path: String,
    pub enable_dns_log: bool,
    pub mask_address: String,
    /// 输出格式（console 单行 / json）。proto 无对应字段，from_proto 恒为 Console。
    pub format: LogFormat,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            error_log_type: LogType::Console,
            error_log_level: SeverityLevel::Warning,
            error_log_path: String::new(),
            access_log_type: LogType::None,
            access_log_path: String::new(),
            enable_dns_log: false,
            mask_address: String::new(),
            format: LogFormat::Console,
        }
    }
}

impl LogConfig {
    pub fn from_proto(p: &ProtoConfig) -> Self {
        Self {
            error_log_type: LogType::from_proto_i32(p.error_log_type).unwrap_or(LogType::Console),
            error_log_level: SeverityLevel::from_proto_i32(p.error_log_level)
                .unwrap_or(SeverityLevel::Warning),
            error_log_path: p.error_log_path.clone(),
            access_log_type: LogType::from_proto_i32(p.access_log_type).unwrap_or(LogType::None),
            access_log_path: p.access_log_path.clone(),
            enable_dns_log: p.enable_dns_log,
            mask_address: p.mask_address.clone(),
            format: LogFormat::Console,
        }
    }

    pub fn to_proto(&self) -> ProtoConfig {
        let mut out = ProtoConfig::default();
        out.error_log_type = self.error_log_type.as_i32();
        out.error_log_level = self.error_log_level.as_i32();
        out.error_log_path = self.error_log_path.clone();
        out.access_log_type = self.access_log_type.as_i32();
        out.access_log_path = self.access_log_path.clone();
        out.enable_dns_log = self.enable_dns_log;
        out.mask_address = self.mask_address.clone();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_type_roundtrip() {
        for t in [LogType::None, LogType::Console, LogType::File, LogType::Event] {
            assert_eq!(LogType::from_proto(t.to_proto()), t);
        }
    }

    #[test]
    fn log_type_from_i32_invalid() {
        assert!(LogType::from_proto_i32(99).is_err());
    }

    #[test]
    fn log_type_as_i32() {
        assert_eq!(LogType::None.as_i32(), 0);
        assert_eq!(LogType::Console.as_i32(), 1);
        assert_eq!(LogType::File.as_i32(), 2);
        assert_eq!(LogType::Event.as_i32(), 3);
    }

    #[test]
    fn severity_ordering() {
        // 数值越大越详细
        assert!(SeverityLevel::Debug > SeverityLevel::Info);
        assert!(SeverityLevel::Info > SeverityLevel::Warning);
        assert!(SeverityLevel::Warning > SeverityLevel::Error);
        assert!(SeverityLevel::Error > SeverityLevel::Unknown);
    }

    #[test]
    fn severity_from_proto_i32() {
        assert_eq!(SeverityLevel::from_proto_i32(0).unwrap(), SeverityLevel::Unknown);
        assert_eq!(SeverityLevel::from_proto_i32(4).unwrap(), SeverityLevel::Debug);
        assert!(SeverityLevel::from_proto_i32(7).is_err());
    }

    #[test]
    fn config_default_is_sensible() {
        let c = LogConfig::default();
        assert_eq!(c.error_log_type, LogType::Console);
        assert_eq!(c.error_log_level, SeverityLevel::Warning);
        assert_eq!(c.access_log_type, LogType::None);
        assert!(!c.enable_dns_log);
        assert!(c.mask_address.is_empty());
    }

    #[test]
    fn config_from_proto_invalid_falls_back_to_default() {
        let mut p = ProtoConfig::default();
        p.error_log_type = 99; // invalid
        p.error_log_level = 99; // invalid
        p.access_log_type = 99; // invalid
        let c = LogConfig::from_proto(&p);
        // 应回退到 default 值
        assert_eq!(c.error_log_type, LogType::Console);
        assert_eq!(c.error_log_level, SeverityLevel::Warning);
        assert_eq!(c.access_log_type, LogType::None);
    }

    #[test]
    fn config_to_proto_roundtrip() {
        let c = LogConfig {
            error_log_type: LogType::File,
            error_log_level: SeverityLevel::Debug,
            error_log_path: "/var/log/err.log".into(),
            access_log_type: LogType::File,
            access_log_path: "/var/log/access.log".into(),
            enable_dns_log: true,
            mask_address: "half".into(),
            format: LogFormat::Console,
        };
        let p = c.to_proto();
        let c2 = LogConfig::from_proto(&p);
        assert_eq!(c, c2);
    }

    #[test]
    fn log_format_parse() {
        assert_eq!(LogFormat::parse("json"), LogFormat::Json);
        assert_eq!(LogFormat::parse("JSON"), LogFormat::Json);
        assert_eq!(LogFormat::parse("console"), LogFormat::Console);
        assert_eq!(LogFormat::parse(""), LogFormat::Console);
        assert_eq!(LogFormat::default(), LogFormat::Console);
    }

    #[test]
    fn config_from_proto_dns_flag() {
        let mut p = ProtoConfig::default();
        p.enable_dns_log = true;
        let c = LogConfig::from_proto(&p);
        assert!(c.enable_dns_log);
    }

    #[test]
    fn severity_as_i32() {
        assert_eq!(SeverityLevel::Unknown.as_i32(), 0);
        assert_eq!(SeverityLevel::Debug.as_i32(), 4);
    }
}
