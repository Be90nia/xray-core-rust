//! QUIC 传输配置。
//!
//! 对应 Go `transport/internet/quic/config.go::Config`。
//! 解析安全层（TLS）所需的字段 + 拥塞控制（`congestion`）。

use std::io;
use std::sync::Arc;

/// QUIC 配置。
///
/// Go 端字段对照：
/// - `header` / `key`：obfuscation（未实现，quinn 不支持 header obfuscation）
/// - `security` / `tlsSettings`：通过 `StreamSettings.security_json` 承载，本结构不重复存储
/// - `congestion`：拥塞控制算法（`"bbr"` / `"cubic"` / `"new_reno"`，默认 CUBIC）
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicConfig {
    /// 是否启用 keep-alive（对应 Go `keep_alive`，默认 false）。
    pub keep_alive: bool,
    /// 拥塞控制算法（对应 Go `CongestionControl`）。
    ///
    /// `"bbr"` → quinn-proto BBR；其他（`""`、`"cubic"`、`"new_reno"`）→ 默认 CUBIC。
    pub congestion: String,
}

impl QuicConfig {
    /// 从 `quicSettings` JSON 解析。
    ///
    /// `None` 或非 object 返回 [`QuicConfig::default`]（非 object 返回 Err）。
    ///
    /// # Errors
    /// JSON 非 object → [`InvalidData`](io::ErrorKind::InvalidData)。
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
        let congestion = obj
            .get("congestion")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        Ok(Self {
            keep_alive,
            congestion,
        })
    }

    /// 构建 quinn [`TransportConfig`]（拥塞控制选择）。
    ///
    /// `congestion == "bbr"` → quinn-proto BBR；
    /// 其他（`""`、`"cubic"`、`"new_reno"`、未知值）→ CUBIC（quinn 默认）。
    #[must_use]
    pub fn build_transport_config(&self) -> quinn::TransportConfig {
        let mut t = quinn::TransportConfig::default();
        match self.congestion.to_ascii_lowercase().as_str() {
            "bbr" => {
                t.congestion_controller_factory(Arc::new(
                    quinn_proto::congestion::BbrConfig::default(),
                ));
            }
            // cubic / new_reno / "" / 未知 → CUBIC（quinn 默认，与 Go quic-go 一致）
            _ => {
                t.congestion_controller_factory(Arc::new(
                    quinn_proto::congestion::CubicConfig::default(),
                ));
            }
        }
        t
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
        assert!(cfg.congestion.is_empty());
    }

    #[test]
    fn keep_alive_parsed() {
        let v: serde_json::Value = serde_json::from_str(r#"{"keepAlive":true}"#).unwrap();
        let cfg = QuicConfig::from_json(Some(&v)).unwrap();
        assert!(cfg.keep_alive);
    }

    #[test]
    fn congestion_parsed() {
        let v: serde_json::Value = serde_json::from_str(r#"{"congestion":"bbr"}"#).unwrap();
        let cfg = QuicConfig::from_json(Some(&v)).unwrap();
        assert_eq!(cfg.congestion, "bbr");
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
        assert!(cfg.congestion.is_empty());
    }

    #[test]
    fn build_transport_config_bbr() {
        let cfg = QuicConfig {
            congestion: "bbr".into(),
            ..Default::default()
        };
        // 不 panic 即可——quinn TransportConfig 内部不暴露已设的 congestion 类型
        let _t = cfg.build_transport_config();
    }

    #[test]
    fn build_transport_config_default_is_cubic() {
        let cfg = QuicConfig::default();
        let _t = cfg.build_transport_config();
    }

    #[test]
    fn build_transport_config_case_insensitive() {
        let cfg = QuicConfig {
            congestion: "BBR".into(),
            ..Default::default()
        };
        let _t = cfg.build_transport_config();
    }
}
