//! # D4: mkcp 伪装
//!
//! 对应 Go `transport/internet/finalmask/mkcp/`。
//!
//! 把 mkcp（modified KCP）流量伪装成其他协议（如 wechat video）。
//!
//! ## TODO rpn-future
//!
//! - 实现 mkcp frame → disguise frame 转换
//! - 实现 disguise frame → mkcp frame 还原

/// mkcp 伪装配置。
#[derive(Debug, Clone, Default)]
pub struct MkcpDisguiseConfig {
    /// 伪装目标协议（wechat/srtp/utp/wireguard/dtls）。
    pub target: String,
    /// 伪装参数。
    pub params: std::collections::HashMap<String, String>,
}

/// mkcp 伪装器（stub）。
pub struct MkcpDisguiser {
    config: MkcpDisguiseConfig,
}

impl MkcpDisguiser {
    #[must_use]
    pub fn new(config: MkcpDisguiseConfig) -> Self {
        Self { config }
    }

    /// 伪装目标协议名。
    #[must_use]
    pub fn target(&self) -> &str {
        &self.config.target
    }

    /// 编码 mkcp frame 为伪装 frame（stub：透传）。
    ///
    /// TODO rpn-future: 按目标协议编码。
    pub fn encode(&self, mkcp_frame: &[u8]) -> Vec<u8> {
        mkcp_frame.to_vec()
    }

    /// 解码伪装 frame 为 mkcp frame（stub：透传）。
    pub fn decode(&self, disguised: &[u8]) -> Vec<u8> {
        disguised.to_vec()
    }
}
