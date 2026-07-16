//! # WeChat header disguise
//!
//! 对应 Go `transport/internet/headers/wechat/`。

#[derive(Debug, Clone, Default)]
pub struct WechatConfig {
    pub padding: usize,
}

pub struct WechatHeader {
    config: WechatConfig,
}

impl WechatHeader {
    #[must_use]
    pub fn new(config: WechatConfig) -> Self {
        Self { config }
    }

    pub fn encode(&self) -> Vec<u8> {
        vec![0xa1u8, 0x08]
    }
}
