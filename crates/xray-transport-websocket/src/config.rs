//! WebSocket 传输配置。
//!
//! 对应 Go `transport/internet/websocket/config.go` + `config.proto`。
//!
//! ## 字段
//!
//! | 字段 | 用途 |
//! |------|------|
//! | `host` | HTTP `Host` header（缺省用 dest 地址） |
//! | `path` | URL 路径（自动补 `/` 前缀） |
//! | `header` | 自定义额外 header |
//! | `accept_proxy_protocol` | 服务端是否接受 PROXY protocol |
//! | `ed` | Early Data 长度（0-RTT） |
//! | `heartbeat_period` | 心跳 ping 周期（秒），0=不启用 |

use std::collections::HashMap;

use crate::error::Result;

/// WebSocket 配置。对应 proto `xray.transport.internet.websocket.Config`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    /// HTTP `Host` header 值。
    pub host: String,
    /// URL 路径。空时默认 `/`；不以 `/` 开头自动补 `/`。
    pub path: String,
    /// 额外自定义 header。
    pub header: HashMap<String, String>,
    /// 服务端是否接受 PROXY protocol v1/v2。切片2 接入。
    pub accept_proxy_protocol: bool,
    /// Early Data 长度（用于 0-RTT 优化）。
    pub ed: u32,
    /// 心跳 ping 周期（秒）。0 表示不发送 ping。对应 Go `heartbeatPeriod`。
    pub heartbeat_period: u32,
}

impl Config {
    /// 构造时确保 `path` 以 `/` 开头。对应 Go `GetNormalizedPath`。
    #[must_use]
    pub fn normalized_path(&self) -> String {
        if self.path.is_empty() {
            return "/".to_string();
        }
        if self.path.starts_with('/') {
            return self.path.clone();
        }
        format!("/{}", self.path)
    }

    /// 从 prost 生成的 proto Config 构造。
    pub fn from_proto(p: xray_proto::xray::transport::internet::websocket::Config) -> Result<Self> {
        Ok(Self {
            host: p.host,
            path: p.path,
            header: p.header.into_iter().collect(),
            accept_proxy_protocol: p.accept_proxy_protocol,
            ed: p.ed,
            heartbeat_period: p.heartbeat_period,
        })
    }

    /// 转换为 prost Config（用于序列化）。
    #[must_use]
    pub fn to_proto(&self) -> xray_proto::xray::transport::internet::websocket::Config {
        xray_proto::xray::transport::internet::websocket::Config {
            host: self.host.clone(),
            path: self.path.clone(),
            header: self.header.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            accept_proxy_protocol: self.accept_proxy_protocol,
            ed: self.ed,
            heartbeat_period: self.heartbeat_period,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_path_empty_returns_slash() {
        let cfg = Config::default();
        assert_eq!(cfg.normalized_path(), "/");
    }

    #[test]
    fn normalized_path_no_leading_slash_prepended() {
        let cfg = Config { path: "ws".into(), ..Default::default() };
        assert_eq!(cfg.normalized_path(), "/ws");
    }

    #[test]
    fn normalized_path_already_valid_passthrough() {
        let cfg = Config { path: "/api/ws".into(), ..Default::default() };
        assert_eq!(cfg.normalized_path(), "/api/ws");
    }

    #[test]
    fn proto_roundtrip() {
        let mut cfg = Config {
            host: "example.com".into(),
            path: "/ws".into(),
            accept_proxy_protocol: true,
            ed: 2048,
            heartbeat_period: 30,
            ..Default::default()
        };
        cfg.header.insert("X-Custom".into(), "v".into());
        let proto = cfg.to_proto();
        let cfg2 = Config::from_proto(proto).unwrap();
        assert_eq!(cfg, cfg2);
    }

    #[test]
    fn default_config_is_empty() {
        let cfg = Config::default();
        assert!(cfg.host.is_empty());
        assert!(cfg.path.is_empty());
        assert!(cfg.header.is_empty());
        assert!(!cfg.accept_proxy_protocol);
        assert_eq!(cfg.ed, 0);
        assert_eq!(cfg.heartbeat_period, 0);
    }
}
