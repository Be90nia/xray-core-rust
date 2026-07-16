//! # D7: Salamander 编码
//!
//! 对应 Go `transport/internet/finalmask/salamander/`。
//!
//! Salamander 是一种流量混淆编码——通过字节替换 + 位置置换让流量看起来随机。
//!
//! ## TODO rpn-future
//!
//! - 实现 salamander encode（字节替换表 + 位置置换）
//! - 实现 salamander decode（逆操作）

/// Salamander 配置。
#[derive(Debug, Clone)]
pub struct SalamanderConfig {
    /// 编码密钥（seed）。
    pub key: Vec<u8>,
}

impl Default for SalamanderConfig {
    fn default() -> Self {
        Self { key: vec![0; 32] }
    }
}

/// Salamander 编码器（stub）。
pub struct SalamanderEncoder {
    config: SalamanderConfig,
}

impl SalamanderEncoder {
    #[must_use]
    pub fn new(config: SalamanderConfig) -> Self {
        Self { config }
    }

    /// 编码（stub：XOR key 循环）。
    ///
    /// TODO rpn-future: 实现完整的字节替换 + 位置置换。
    pub fn encode(&self, data: &[u8]) -> Vec<u8> {
        data.iter()
            .enumerate()
            .map(|(i, b)| b ^ self.config.key[i % self.config.key.len()])
            .collect()
    }

    /// 解码（stub：同 encode，XOR 对称）。
    pub fn decode(&self, data: &[u8]) -> Vec<u8> {
        self.encode(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let enc = SalamanderEncoder::new(SalamanderConfig::default());
        let original = b"hello world";
        let encoded = enc.encode(original);
        let decoded = enc.decode(&encoded);
        assert_eq!(&decoded, original);
    }
}
