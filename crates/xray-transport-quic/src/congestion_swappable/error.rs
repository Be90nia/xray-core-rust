//! 拥塞控制模块错误类型。
//!
//! s8ti 自 hysteria `HysteriaError` 解耦——本模块自 quinn_bridge 起为跨协议共享
//! （hysteria / tuic 消费），错误类型随模块走，不再依赖 hysteria crate。

use thiserror::Error;

/// 拥塞控制配置错误。
#[derive(Debug, Error)]
pub enum CongestionError {
    /// 不支持的拥塞控制类型。
    #[error("unsupported congestion type: {0}")]
    UnsupportedCongestionType(String),

    /// 不支持的 BBR profile。
    #[error("unsupported BBR profile: {0}")]
    UnsupportedBbrProfile(String),
}

/// 模块内统一 Result 别名。
pub type Result<T, E = CongestionError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_unchanged() {
        assert_eq!(
            CongestionError::UnsupportedCongestionType("cubic".into()).to_string(),
            "unsupported congestion type: cubic"
        );
        assert_eq!(
            CongestionError::UnsupportedBbrProfile("weird".into()).to_string(),
            "unsupported BBR profile: weird"
        );
    }
}
