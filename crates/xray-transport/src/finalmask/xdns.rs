//! # D9: xDNS 伪装传输
//!
//! 对应 Go `transport/internet/finalmask/xdns/`。
//!
//! 把代理流量伪装成 DNS 查询/响应——客户端发 DNS query，服务端返回 DNS response，
//! 实际 payload 编码在 DNS 记录中。
//!
//! ## TODO rpn-future
//!
//! - 实现 DNS query 包装（payload → base32 → TXT/A 记录）
//! - 实现 DNS response 解包（response 记录 → payload）
//! - 实现 DNS-over-HTTPS/TLS 传输

/// xDNS 配置。
#[derive(Debug, Clone, Default)]
pub struct XdnsConfig {
    /// 伪装的 DNS 服务器域名。
    pub dns_server: String,
    /// 查询域名后缀（如 ".example.com"）。
    pub query_suffix: String,
    /// 每个查询最大 payload（字节，受 DNS 协议限制通常 ≤ 253 字节域名）。
    pub max_payload_per_query: usize,
}

/// xDNS session（stub）。
pub struct XdnsSession {
    config: XdnsConfig,
}

impl XdnsSession {
    #[must_use]
    pub fn new(config: XdnsConfig) -> Self {
        Self { config }
    }

    /// 把 payload 编码为 DNS 查询域名（stub）。
    ///
    /// TODO rpn-future: base32 编码 + 分片 + 后缀拼接。
    pub fn encode_to_query(&self, payload: &[u8]) -> String {
        format!("{}.{}", hex::encode_simple(payload), self.config.query_suffix)
    }

    /// 从 DNS 响应解码 payload（stub）。
    pub fn decode_from_response(&self, response: &str) -> Vec<u8> {
        response
            .trim_end_matches(&self.config.query_suffix)
            .split('.')
            .next()
            .unwrap_or("")
            .as_bytes()
            .to_vec()
    }
}

// hex 编码 stub（避免引入 hex crate）
mod hex {
    pub fn encode_simple(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }
}
