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
//! | `pool_size` | 客户端 outbound 预连接池空闲上限（0=关池）；**默认 12 = 开池**（省后续会话 1 RTT 握手；显式 0 关池） |

use std::collections::HashMap;

use crate::error::Result;

/// WebSocket 配置。对应 proto `xray.transport.internet.websocket.Config`。
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// 客户端 outbound 预连接池空闲上限（Rust 独有能力，Go 无对应机制）。
    ///
    /// `>0`（默认 12）= 每 (host, port, path, sni, fingerprint) 最多保留
    /// `pool_size` 条「握手完成、零内层字节」的预连接（首拨后由后台补拨填池，
    /// 省后续会话 1 RTT 握手）。`0` = 每次 Dial 现拨一条，服务端只看到真实
    /// 会话连接。
    ///
    /// 为何默认 12（bd s8eio 复议，2026-11-02）：s8eio 曾把缺省改成 0，理由是
    /// 「Go 无池」——但那是**服务端连接数**维度，不是 wire 语义维度；预连接池
    /// 不改数据面 wire，只影响客户端少付一个握手 RTT。实测（v2rayN →
    /// Cloudflare Argo → 176，shadowsocks+ws+tls）缺省 0 关池 TTFB median
    /// 4489ms vs 显式 12 的 3001ms（慢 33%），且开池后与旧内核（默认 12）
    /// 持平 → 判定为真倒退，恢复缺省 12。服务端连接数 ×(1+池深) 的代价是
    /// 真实存在的，需要严格对齐 Go 时显式配 `wsSettings.poolSize: 0`。
    pub pool_size: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: String::new(),
            path: String::new(),
            header: HashMap::new(),
            accept_proxy_protocol: false,
            ed: 0,
            // Bug-B（bd cqyj）：心跳缺省 30s 对齐 Go dialer NewConnection——
            // 缺位时 NAT/CDN 静默切断（60-180s 窗口）→ 半开死链 → 全协议假死 000。
            // JSON 显式 heartbeatPeriod:0 仍可关闭（register.rs parse 路径）。
            heartbeat_period: 30,
            // bd s8eio 复议（2026-11-02）：默认 12 = 开池。实测缺省 0 关池时，
            // 经 Cloudflare 的 ws 节点 TTFB 慢 33%（4489ms vs 3001ms），且一批
            // 节点测速直接超时 → 判定真倒退，恢复开池。需严格对齐 Go（服务端
            // 连接数敏感）时显式配 `wsSettings.poolSize: 0`。
            pool_size: 12,
        }
    }
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
    #[allow(clippy::result_large_err)] // WsError 携带协议上下文，Box 化徒增间接
    pub fn from_proto(p: xray_proto::xray::transport::internet::websocket::Config) -> Result<Self> {
        Ok(Self {
            host: p.host,
            path: p.path,
            header: p.header.into_iter().collect(),
            accept_proxy_protocol: p.accept_proxy_protocol,
            ed: p.ed,
            // Bug-B：proto3 u32 无显式 0 表达——0 视为未配置 → 默认 30s。
            heartbeat_period: if p.heartbeat_period == 0 { 30 } else { p.heartbeat_period },
            // proto 无 poolSize 字段（Go config.proto 只有 host/path/headers/
            // accept_proxy_protocol/ed/heartbeatPeriod）→ proto 路径按缺省 12
            // 开池（与 `Config::default()` 一致）；JSON 侧 `poolSize: 0` 可关。
            pool_size: 12,
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
        // Bug-B：心跳缺省 30s（显式 0 才关闭）。
        assert_eq!(cfg.heartbeat_period, 30);
    }
}
