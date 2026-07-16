//! # WireGuard header disguise
//!
//! 对应 Go `transport/internet/headers/wireguard/`。

#[derive(Debug, Clone, Default)]
pub struct WireguardConfig {
    pub receiver_index: u32,
}

pub struct WireguardHeader {
    config: WireguardConfig,
}

impl WireguardHeader {
    #[must_use]
    pub fn new(config: WireguardConfig) -> Self {
        Self { config }
    }

    pub fn encode(&self, counter: u64) -> Vec<u8> {
        let mut buf = vec![0u8; 16];
        buf[0] = 0x04;
        buf[4..8].copy_from_slice(&self.config.receiver_index.to_le_bytes());
        buf[8..16].copy_from_slice(&counter.to_le_bytes());
        buf
    }
}
