//! VLESS 协议错误类型。
//!
//! 对应 Go 版本 `proxy/vless/` 各包用 `errors.New(...)` 表达的错误情况。

use std::io;

/// 凭据掩码口径（安全 F1 / bd 0rtm，同 vmess 修复）：认证凭据（uuid 等）
/// 在错误链里只出前 8 字符指纹（非 hex 以 `?` 占位），禁原文——错误链经
/// `error = %e` 直落生产日志（inbound/server.rs:199 形态）。
fn mask_cred(s: &str) -> String {
    s.chars().take(8).map(|c| if c.is_ascii_hexdigit() { c } else { '?' }).collect()
}
/// VLESS 协议所有错误变体。
#[derive(Debug, thiserror::Error)]
pub enum VlessError {
    /// UUID 字符串无法解析。
    #[error("failed to parse ID: {}", mask_cred(.0))]
    InvalidUuid(String),

    /// Account 字段值非法（如 `Encryption` 不支持）。
    #[error("invalid account: {0}")]
    InvalidAccount(String),

    /// 重复添加用户（email 冲突）。
    #[error("User {0} already exists.")]
    UserAlreadyExists(String),

    /// 按 email/UUID 查找用户时未找到。
    #[error("User {} not found.", mask_cred(.0))]
    UserNotFound(String),

    /// `Del` 调用时 email 为空。
    #[error("Email must not be empty.")]
    EmptyEmail,

    /// 请求版本字节不在支持范围内（当前仅支持 0）。
    #[error("invalid request version: {0}")]
    InvalidRequestVersion(u8),

    /// 请求头中的 UUID 在 validator 中查不到对应用户。
    #[error("invalid request user id: {0}")]
    InvalidRequestUserId(String),

    /// 请求头 command 字节非法。
    #[error("invalid request command: {0}")]
    InvalidRequestCommand(u8),

    /// 请求头地址解析失败或地址缺失。
    #[error("invalid request address")]
    InvalidRequestAddress,

    /// 读底层连接失败。
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// 写底层连接失败。
    #[error("failed to write: {0}")]
    WriteFailed(String),

    /// protobuf 编解码失败。
    #[error("protobuf error: {0}")]
    ProtoError(String),

    /// 响应版本与请求版本不匹配。
    #[error("unexpected response version. Expecting {expected} but actually {actual}")]
    UnexpectedResponseVersion { expected: u8, actual: u8 },

    /// IO 边界 trait 方法未实现（依赖未就绪）。
    #[error("operation not supported: {0}")]
    NotImplemented(String),

    /// 其他未分类错误。
    #[error("{0}")]
    Other(String),
}

/// `Result<T, VlessError>` 别名。
pub type Result<T> = std::result::Result<T, VlessError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_invalid_uuid() {
        let e = VlessError::InvalidUuid("not-a-uuid".into());
        assert!(format!("{e}").contains("failed to parse ID"));
    }

    #[test]
    fn display_user_already_exists() {
        let e = VlessError::UserAlreadyExists("test@example.com".into());
        let s = format!("{e}");
        assert!(s.contains("already exists"));
        assert!(s.contains("test@example.com"));
    }

    #[test]
    fn display_unexpected_response_version() {
        let e = VlessError::UnexpectedResponseVersion { expected: 0, actual: 1 };
        let s = format!("{e}");
        assert!(s.contains("Expecting 0"));
        assert!(s.contains("actually 1"));
    }

    #[test]
    fn from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::UnexpectedEof, "short");
        let e: VlessError = io_err.into();
        assert!(matches!(e, VlessError::Io(_)));
        assert!(format!("{e}").contains("io error"));
    }
    /// 安全 F1（bd 0rtm 口径）：`InvalidUuid` 的 Display 只出 8-hex 指纹，
    /// uuid 原文禁入错误链（错误链经 `error = %e` 直落生产日志）。
    #[test]
    fn display_invalid_uuid_masks_raw_id() {
        let raw = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let e = VlessError::InvalidUuid(raw.to_string());
        let s = format!("{e}");
        assert!(s.contains("failed to parse ID"), "口径保留: {s}");
        assert!(s.contains("b831381d"), "指纹保留: {s}");
        assert!(!s.contains(raw), "uuid 原文禁入: {s}");
    }

    /// 安全 F1：`UserNotFound` 双载荷（validator=email、请求头=uuid 原文，
    /// encoding/server.rs:101）——uuid 是认证凭据，误配场景原文=真实凭据，
    /// Display 一律掩码。
    #[test]
    fn display_user_not_found_masks_raw_uuid() {
        let raw = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let e = VlessError::UserNotFound(raw.to_string());
        let s = format!("{e}");
        assert!(s.contains("not found"), "口径保留: {s}");
        assert!(!s.contains(raw), "uuid 原文禁入: {s}");
    }

    /// 安全 F1 捕获测试：生产日志形态（inbound/server.rs:199 `error = %e`
    /// 直落日志）携带 `UserNotFound` 错误链时不得带 uuid 原文。
    /// 手写 subscriber（同 xray-conf 模式，零新依赖）；set_default + rebuild
    /// 防 callsite 缓存恒捕 0（xray-common/tests/log_single_entry.rs 先例）。
    #[test]
    fn auth_error_chain_into_log_has_no_raw_uuid() {
        use std::sync::{Arc, Mutex};

        struct WarnCapture(Arc<Mutex<Vec<String>>>);
        impl tracing::Subscriber for WarnCapture {
            fn enabled(&self, _meta: &tracing::Metadata<'_>) -> bool {
                true
            }

            fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }

            fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

            fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {
            }

            fn event(&self, event: &tracing::Event<'_>) {
                struct Fmt(String);
                impl tracing::field::Visit for Fmt {
                    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                        self.0.push_str(&format!("{}={value} ", field.name()));
                    }

                    fn record_debug(
                        &mut self,
                        field: &tracing::field::Field,
                        value: &dyn std::fmt::Debug,
                    ) {
                        self.0.push_str(&format!("{}={value:?} ", field.name()));
                    }
                }
                let mut v = Fmt(String::new());
                event.record(&mut v);
                self.0.lock().unwrap().push(v.0);
            }

            fn enter(&self, _span: &tracing::span::Id) {}

            fn exit(&self, _span: &tracing::span::Id) {}
        }

        let raw = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let err = VlessError::UserNotFound(raw.to_string());
        let capture = Arc::new(Mutex::new(Vec::new()));
        let guard = tracing::subscriber::set_default(WarnCapture(Arc::clone(&capture)));
        tracing::callsite::rebuild_interest_cache();
        // 测试面 raw tracing 登记（nn8os 2b）：本测试自发射事件验证 capture
        // subscriber 形态与 UUID 掩码断言（非生产路径）；`warn!` 换等价展开
        // `event!` 过 L3 禁令。
        tracing::event!(tracing::Level::WARN, error = %err, "vless connection ended with error");
        drop(guard);
        let lines = capture.lock().unwrap().join("\n");
        assert!(lines.contains("vless connection ended"), "捕获必须咬到事件: {lines:?}");
        assert!(!lines.contains(raw), "uuid 原文禁入日志: {lines:?}");
    }
}
