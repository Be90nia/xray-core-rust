//! commander 错误类型。
//!
//! 对应 Go `app/commander/` 各 `errors.New("...")` 与 grpc 启动错误的具体化。

use thiserror::Error;

/// Commander 错误。
#[derive(Debug, Error)]
pub enum CommanderError {
    /// Service 注册失败。对应 Go `errors.New("not a Service.")`。
    #[error("not a Service (type_url={type_url})")]
    NotAService { type_url: String },

    /// 服务配置解码失败。对应 Go `rawConfig.GetInstance()` 错误。
    #[error("service config decode failed for `{type_url}`: {reason}")]
    ServiceDecodeFailed { type_url: String, reason: String },

    /// 监听地址解析失败。对应 Go `net.ResolveTCPAddr` 错误。
    #[error("invalid listen address `{addr}`: {reason}")]
    InvalidListenAddr { addr: String, reason: String },

    /// gRPC server 启动失败。对应 Go `c.server.Serve` 错误。
    #[error("grpc server failed: {0}")]
    GrpcServerFailed(String),

    /// Outbound handler 注册失败。对应 Go `c.ohm.AddHandler` 错误。
    #[error("outbound handler register failed for tag `{0}`")]
    OutboundRegisterFailed(String),

    /// Commander 已关闭，操作不允许。
    #[error("commander closed")]
    Closed,

    /// 注册器（registrar）操作错误。来自 [`GrpcServerRegistrar`](crate::GrpcServerRegistrar) 实现。
    #[error("registrar error: {0}")]
    Registrar(String),
}

/// 警告日志辅助。
pub fn log_warning(msg: impl AsRef<str>) {
    tracing::warn!("{}", msg.as_ref());
}

/// 错误日志辅助。
pub fn log_error(msg: impl AsRef<str>) {
    tracing::error!("{}", msg.as_ref());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_not_a_service() {
        let e = CommanderError::NotAService {
            type_url: "xray.app.stats.command.Config".into(),
        };
        assert_eq!(
            e.to_string(),
            "not a Service (type_url=xray.app.stats.command.Config)"
        );
    }

    #[test]
    fn error_display_service_decode_failed() {
        let e = CommanderError::ServiceDecodeFailed {
            type_url: "type.googleapis.com/xray.Foo".into(),
            reason: "invalid proto".into(),
        };
        assert_eq!(
            e.to_string(),
            "service config decode failed for `type.googleapis.com/xray.Foo`: invalid proto"
        );
    }

    #[test]
    fn error_display_invalid_listen_addr() {
        let e = CommanderError::InvalidListenAddr {
            addr: ":-1".into(),
            reason: "invalid port".into(),
        };
        assert_eq!(e.to_string(), "invalid listen address `:-1`: invalid port");
    }

    #[test]
    fn error_display_grpc_server_failed() {
        let e = CommanderError::GrpcServerFailed("bind refused".into());
        assert_eq!(e.to_string(), "grpc server failed: bind refused");
    }

    #[test]
    fn error_display_outbound_register_failed() {
        let e = CommanderError::OutboundRegisterFailed("api_out".into());
        assert_eq!(
            e.to_string(),
            "outbound handler register failed for tag `api_out`"
        );
    }

    #[test]
    fn error_display_closed() {
        let e = CommanderError::Closed;
        assert_eq!(e.to_string(), "commander closed");
    }

    #[test]
    fn error_display_registrar() {
        let e = CommanderError::Registrar("tonic build error".into());
        assert_eq!(e.to_string(), "registrar error: tonic build error");
    }

    #[test]
    fn log_helpers_no_panic() {
        log_warning("test");
        log_error("test");
    }
}
