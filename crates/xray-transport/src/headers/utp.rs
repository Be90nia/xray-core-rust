//! # uTP header disguise
//!
//! 对应 Go `transport/internet/headers/utp/`。

#[derive(Debug, Clone, Default)]
pub struct UtpConfig {
    pub version: u8,
}

pub struct UtpHeader {
    config: UtpConfig,
}

impl UtpHeader {
    #[must_use]
    pub fn new(config: UtpConfig) -> Self {
        Self { config }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 20];
        buf[0] = 0x41;
        buf
    }
}
