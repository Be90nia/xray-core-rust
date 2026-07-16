//! # DTLS header disguise
//!
//! 对应 Go `transport/internet/headers/dtls/`。
//!
//! TODO tgg-future: 实现 DTLS 1.0 record 层 encode/decode。

#[derive(Debug, Clone, Default)]
pub struct DtlsConfig {
    pub version: u16,
}

pub struct DtlsHeader {
    config: DtlsConfig,
}

impl DtlsHeader {
    #[must_use]
    pub fn new(config: DtlsConfig) -> Self {
        Self { config }
    }

    pub fn encode(&self, _payload_len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; 13];
        buf[0] = 0x17;
        buf[1..3].copy_from_slice(&self.config.version.to_be_bytes());
        buf
    }
}
