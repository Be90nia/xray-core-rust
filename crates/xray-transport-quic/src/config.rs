//! QUIC 传输配置（最小子集）。
//!
//! 对应 Go `transport/internet/quic/config.go::Config`。当前仅解析安全层
//! （TLS）所需的字段；`header` / `key`（obfuscation）与 `congestion` 留 follow-up。

use std::io;

/// QUIC 配置（最小子集）。
///
/// Go 端字段对照：
/// - `header`：obfuscation header（未实现）
/// - `key`：obfuscation key（未实现）
/// - `security` / `tlsSettings`：通过 `StreamSettings.security_json` 承载，本结构不重复存储
/// - `congestion`：拥塞控制算法（未实现）
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicConfig {
    /// 是否启用 keep-alive（对应 Go `keep_alive`，默认 false）。
    pub keep_alive: bool,
}

impl QuicConfig {
    /// 从 `quicSettings` JSON 解析。
    ///
    /// `None` 或非 object 返回 [`QuicConfig::default`]。
    pub fn from_json(json: Option<&serde_json::Value>) -> io::Result<Self> {
        let Some(v) = json else { return Ok(Self::default()); };
        let Some(obj) = v.as_object() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "quicSettings must be a JSON object",
            ));
        };
        let keep_alive = obj
            .get("keepAlive")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);
        Ok(Self { keep_alive })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_returns_default() {
        let cfg = QuicConfig::from_json(None).unwrap();
        assert_eq!(cfg, QuicConfig::default());
        assert!(!cfg.keep_alive);
    }

    #[test]
    fn keep_alive_parsed() {
        let v: serde_json::Value = serde_json::from_str(r#"{"keepAlive":true}"#).unwrap();
        let cfg = QuicConfig::from_json(Some(&v)).unwrap();
        assert!(cfg.keep_alive);
    }

    #[test]
    fn non_object_returns_err() {
        let v: serde_json::Value = serde_json::from_str(r#""not-an-object""#).unwrap();
        let r = QuicConfig::from_json(Some(&v));
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn empty_object_uses_defaults() {
        let v: serde_json::Value = serde_json::from_str(r#"{}"#).unwrap();
        let cfg = QuicConfig::from_json(Some(&v)).unwrap();
        assert!(!cfg.keep_alive);
    }
}
