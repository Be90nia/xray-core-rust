//! # D3: Custom header 自定义头
//!
//! 对应 Go `transport/internet/finalmask/header/custom/`。
//!
//! 允许用户自定义流量头部格式（如模拟特定 HTTP/TLS client Hello）。
//!
//! ## TODO rpn-future
//!
//! - 实现 header 模板解析（JSON 格式描述）
//! - 实现 encoder/decoder（按模板注入/提取头部）

use std::collections::HashMap;

/// 自定义头配置。
#[derive(Debug, Clone, Default)]
pub struct CustomHeaderConfig {
    /// 头部模板（name → value pattern）。
    pub headers: HashMap<String, String>,
    /// 是否启用随机填充。
    pub random_padding: bool,
}

/// 自定义头编码器（stub）。
pub struct CustomHeaderEncoder {
    config: CustomHeaderConfig,
}

impl CustomHeaderEncoder {
    #[must_use]
    pub fn new(config: CustomHeaderConfig) -> Self {
        Self { config }
    }

    /// 编码头部（stub：返回 headers 的简单拼接）。
    ///
    /// TODO rpn-future: 实现模板化编码 + 随机填充。
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (k, v) in &self.config.headers {
            out.extend_from_slice(k.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(v.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_single_header() {
        let mut headers = HashMap::new();
        headers.insert("X-Custom".to_string(), "value".to_string());
        let enc = CustomHeaderEncoder::new(CustomHeaderConfig {
            headers,
            random_padding: false,
        });
        let out = enc.encode();
        assert!(out.windows(2).any(|w| w == b": "));
    }
}
