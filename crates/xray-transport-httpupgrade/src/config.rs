//! HTTPUpgrade 配置。
//!
//! 对应 Go `transport/internet/httpupgrade/config.go` 与 `config.proto`。
//!
//! ## 字段
//!
//! | 字段 | 用途 |
//!|------|------|
//!| `host` | HTTP `Host` header 值（缺省用 dest 地址） |
//!| `path` | URL 路径（自动补 `/` 前缀） |
//!| `header` | 自定义额外 header（key→value） |
//!| `accept_proxy_protocol` | 服务端是否接受 PROXY protocol（切片2） |
//!| `ed` | Early Data 长度（0=立即读取响应，非 0=延迟读，用于 0-RTT） |
//!
//! ## 与 Go 差异
//!
//! Go proto 是 `map<string,string>` header，Rust 用 `std::collections::HashMap`。

use std::collections::HashMap;

use crate::error::Result;

/// HTTPUpgrade 配置。对应 proto `xray.transport.internet.httpupgrade.Config`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    /// HTTP `Host` header 值。空时客户端用 dest 地址，服务端不校验。
    pub host: String,
    /// URL 路径。空时默认 `/`；不以 `/` 开头自动补 `/`。
    pub path: String,
    /// 额外自定义 header。客户端写入请求，服务端不解析（仅按 host/path 校验）。
    pub header: HashMap<String, String>,
    /// 服务端是否接受 PROXY protocol v1/v2。切片2 接入。
    pub accept_proxy_protocol: bool,
    /// Early Data 长度（用于 0-RTT 优化）。0 = 客户端立即读取 101 响应；
    /// 非 0 = 延迟到首字节写入后读，避免 0-RTT 与协议握手冲突。
    pub ed: u32,
}

impl Config {
    /// 用 `path` 字段构造时确保以 `/` 开头。对应 Go `GetNormalizedPath`。
    ///
    /// - 空路径返回 `/`。
    /// - 不以 `/` 开头的路径补 `/` 前缀。
    /// - 其他原样返回。
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

    /// 从 prost 生成的 proto Config 构造。对应 Go 反序列化路径。
    pub fn from_proto(p: xray_proto::xray::transport::internet::httpupgrade::Config) -> Result<Self> {
        Ok(Self {
            host: p.host,
            path: p.path,
            header: p.header.into_iter().collect(),
            accept_proxy_protocol: p.accept_proxy_protocol,
            ed: p.ed,
        })
    }

    /// 转换为 prost Config（用于序列化）。
    #[must_use]
    pub fn to_proto(&self) -> xray_proto::xray::transport::internet::httpupgrade::Config {
        xray_proto::xray::transport::internet::httpupgrade::Config {
            host: self.host.clone(),
            path: self.path.clone(),
            header: self.header.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            accept_proxy_protocol: self.accept_proxy_protocol,
            ed: self.ed,
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
        let cfg = Config {
            path: "ws".into(),
            ..Default::default()
        };
        assert_eq!(cfg.normalized_path(), "/ws");
    }

    #[test]
    fn normalized_path_already_valid_passthrough() {
        let cfg = Config {
            path: "/api/ws".into(),
            ..Default::default()
        };
        assert_eq!(cfg.normalized_path(), "/api/ws");
    }

    #[test]
    fn proto_roundtrip() {
        let mut cfg = Config {
            host: "example.com".into(),
            path: "/ws".into(),
            accept_proxy_protocol: true,
            ed: 2048,
            ..Default::default()
        };
        cfg.header.insert("X-Custom".into(), "value".into());
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
    }
}
