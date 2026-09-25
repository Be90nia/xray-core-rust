//! # uTP header disguise
//!
//! 对应 Go `transport/internet/headers/utp/`。

#[derive(Debug, Clone, Default)]
pub struct UtpConfig {
    pub version: u8,
}

pub struct UtpHeader {
    // 与 Go headers/utp 一致：config 仅为构造形态保留，encode 写死伪装字节。
    #[allow(dead_code)]
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
