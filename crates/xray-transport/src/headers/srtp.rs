//! # SRTP header disguise
//!
//! 对应 Go `transport/internet/headers/srtp/`。

#[derive(Debug, Clone, Default)]
pub struct SrtpConfig {
    pub payload_type: u8,
}

pub struct SrtpHeader {
    config: SrtpConfig,
}

impl SrtpHeader {
    #[must_use]
    pub fn new(config: SrtpConfig) -> Self {
        Self { config }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 12];
        buf[0] = 0x80;
        buf[1] = self.config.payload_type;
        buf
    }
}
