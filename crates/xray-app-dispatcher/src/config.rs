//! 配置类型
//!
//! 对应 Go `app/dispatcher/config.proto`。当前 proto schema 为空
//! （`SessionConfig` 仅保留字段，`Config` 仅含 settings），保留类型骨架
//! 以便后续接入。

use xray_proto::xray::app::dispatcher::{Config as ProtoConfig, SessionConfig as ProtoSessionConfig};

/// 分发器会话配置（保留字段，当前空）。
///
/// 对应 Go `app/dispatcher.SessionConfig`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionConfig {
    // 当前 proto 仅有 `reserved 1`，无字段
}

impl SessionConfig {
    /// 从 proto 转换（当前无字段，仅类型检查）。
    pub fn from_proto(_p: &ProtoSessionConfig) -> Self {
        Self {}
    }

    /// 转回 proto。
    pub fn to_proto(&self) -> ProtoSessionConfig {
        ProtoSessionConfig {}
    }
}

/// 分发器顶层配置。
///
/// 对应 Go `app/dispatcher.Config`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    /// 会话级设置
    pub settings: SessionConfig,
}

impl Config {
    /// 从 proto 转换。
    pub fn from_proto(p: &ProtoConfig) -> Self {
        Self {
            settings: p
                .settings
                .as_ref()
                .map(SessionConfig::from_proto)
                .unwrap_or_default(),
        }
    }

    /// 转回 proto。
    pub fn to_proto(&self) -> ProtoConfig {
        ProtoConfig {
            settings: Some(self.settings.to_proto()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_config_default_roundtrip() {
        let cfg = SessionConfig::default();
        let proto = cfg.to_proto();
        let back = SessionConfig::from_proto(&proto);
        assert_eq!(cfg, back);
    }

    #[test]
    fn config_default_roundtrip() {
        let cfg = Config::default();
        let proto = cfg.to_proto();
        let back = Config::from_proto(&proto);
        assert_eq!(cfg, back);
    }

    #[test]
    fn config_from_proto_none_settings() {
        let mut proto = ProtoConfig::default();
        proto.settings = None;
        let cfg = Config::from_proto(&proto);
        assert_eq!(cfg.settings, SessionConfig::default());
    }
}
