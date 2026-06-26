//! 代理管理器错误类型
//!
//! 对应 Go `app/proxyman/` 包内散落的 `errors.New(...)` 调用，以及 `common.ErrNoClue`。

use thiserror::Error;

/// 代理管理器错误
#[derive(Debug, Error)]
pub enum ProxymanError {
    /// tag 已存在（对应 Go `"existing tag found: " + tag`）
    #[error("existing tag found: {0}")]
    ExistingTag(String),

    /// 未找到 handler（对应 Go `"handler not found: " + tag`）
    #[error("handler not found: {0}")]
    HandlerNotFound(String),

    /// 不是 ReceiverConfig
    #[error("not a ReceiverConfig")]
    NotReceiverConfig,

    /// 不是 SenderConfig
    #[error("not a SenderConfig")]
    NotSenderConfig,

    /// 不是 SenderConfig（settings 类型断言失败）
    #[error("settings is not SenderConfig")]
    SettingsNotSenderConfig,

    /// 不是 inbound proxy
    #[error("not an inbound proxy")]
    NotInboundProxy,

    /// 不是 outbound proxy
    #[error("not an outbound handler")]
    NotOutboundProxy,

    /// 代理不是 UserManager
    #[error("proxy is not a UserManager")]
    NotUserManager,

    /// 无法从 handler 取出 inbound proxy
    #[error("can't get inbound proxy from handler")]
    GetInboundProxyFailed,

    /// 无法从 handler 取出 outbound proxy
    #[error("can't get outbound proxy from handler")]
    GetOutboundProxyFailed,

    /// 解析 stream config 失败
    #[error("failed to parse stream config: {0}")]
    StreamConfigParse(String),

    /// 未知操作（TypedMessage 无法反序列化）
    #[error("unknown operation")]
    UnknownOperation,

    /// 不是 inbound 操作
    #[error("not an inbound operation")]
    NotInboundOperation,

    /// 不是 outbound 操作
    #[error("not an outbound operation")]
    NotOutboundOperation,

    /// 解析 user 失败
    #[error("failed to parse user: {0}")]
    UserParse(String),

    /// 目的地地址为空
    #[error("nil destination address")]
    NilDestination,

    /// 检测到回环连接
    #[error("loopback connection detected")]
    LoopbackDetected,

    /// 取得出站 handler 失败
    #[error("failed to get outbound handler with tag: {0}")]
    OutboundHandlerNotFound(String),

    /// XUDP 拒绝 UDP/443 流量
    #[error("XUDP rejected UDP/443 traffic")]
    XudpRejectUdp443,

    /// 处理 mux outbound 流量失败
    #[error("failed to process mux outbound traffic: {0}")]
    MuxOutboundFailed(String),

    /// 处理 outbound 流量失败
    #[error("failed to process outbound traffic: {0}")]
    OutboundProcessFailed(String),

    /// ErrNoClue（Go `common.ErrNoClue`，表示语义模糊的"未找到"）
    #[error("no clue")]
    NoClue,

    /// 关闭资源失败汇总
    #[error("failed to close all resources: {0}")]
    CloseAllFailed(String),

    /// 无法监听 socket
    #[error("unable to listen socket: {0}")]
    ListenSocketFailed(String),

    /// 其他错误（用于 trait/IO 边界占位）
    #[error("other: {0}")]
    Other(String),
}

impl ProxymanError {
    /// 警告级别工厂（对应 Go `errors.New(...).AtWarning()`）
    #[must_use]
    pub fn at_warning(self) -> Self {
        self
    }

    /// 错误级别工厂（对应 Go `errors.New(...).AtError()`）
    #[must_use]
    pub fn at_error(self) -> Self {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_existing_tag() {
        assert_eq!(
            ProxymanError::ExistingTag("inbound1".to_string()).to_string(),
            "existing tag found: inbound1"
        );
    }

    #[test]
    fn display_handler_not_found() {
        assert_eq!(
            ProxymanError::HandlerNotFound("proxy".to_string()).to_string(),
            "handler not found: proxy"
        );
    }

    #[test]
    fn display_not_receiver_config() {
        assert_eq!(ProxymanError::NotReceiverConfig.to_string(), "not a ReceiverConfig");
    }

    #[test]
    fn display_stream_config_parse() {
        let e = ProxymanError::StreamConfigParse("bad field".to_string());
        assert_eq!(e.to_string(), "failed to parse stream config: bad field");
    }

    #[test]
    fn display_unknown_operation() {
        assert_eq!(ProxymanError::UnknownOperation.to_string(), "unknown operation");
    }

    #[test]
    fn display_nil_destination() {
        assert_eq!(ProxymanError::NilDestination.to_string(), "nil destination address");
    }

    #[test]
    fn display_loopback_detected() {
        assert_eq!(ProxymanError::LoopbackDetected.to_string(), "loopback connection detected");
    }

    #[test]
    fn display_no_clue() {
        assert_eq!(ProxymanError::NoClue.to_string(), "no clue");
    }

    #[test]
    fn display_xudp_reject() {
        assert_eq!(
            ProxymanError::XudpRejectUdp443.to_string(),
            "XUDP rejected UDP/443 traffic"
        );
    }

    #[test]
    fn display_close_all_failed() {
        let e = ProxymanError::CloseAllFailed("2 errors".to_string());
        assert_eq!(e.to_string(), "failed to close all resources: 2 errors");
    }

    #[test]
    fn at_warning_returns_self() {
        let e = ProxymanError::NotReceiverConfig.at_warning();
        assert!(matches!(e, ProxymanError::NotReceiverConfig));
    }

    #[test]
    fn at_error_returns_self() {
        let e = ProxymanError::NotSenderConfig.at_error();
        assert!(matches!(e, ProxymanError::NotSenderConfig));
    }
}
