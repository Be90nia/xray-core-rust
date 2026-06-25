//! uTLS 连接接口与占位。
//!
//! 翻译自 Go `transport/internet/tls/tls.go` 中的 `Interface interface`
//! 与 `Conn`/`UConn` 包装类型。
//!
//! # 现状（重要）
//! **实际 uTLS 握手未实现**。Rust 生态目前没有 uTLS 等价品。本模块只翻译
//! 接口定义（`ConnInterface` trait），让上层能基于该 trait 类型工作。
//!
//! 翻译时与 xray-transport 的 [`Connection`](xray_transport::connection::Connection)
//! trait 对齐：本 trait 不重复 `AsyncRead`/`AsyncWrite` 约束，只表达 TLS 附加
//! 能力（握手、SNI 验证、ALPN 协商）。实际包装类型（`Conn`/`UConn`）等接入
//! rustls + uTLS 等价品后再加。

use std::future::Future;
use std::io;
use std::pin::Pin;

/// TLS 连接接口。
///
/// 对应 Go `Interface interface { net.Conn; HandshakeContext; VerifyHostname; ... }`。
///
/// 由于 [`xray_transport::connection::Connection`] 已表达 `AsyncRead + AsyncWrite + addr`，
/// 本 trait 只加 TLS 特有方法。实现者可同时实现两个 trait。
pub trait ConnInterface: xray_transport::connection::Connection {
    /// 执行 TLS 握手。超时与取消由调用方通过 ctx 等价机制（tokio::time::timeout 等）控制。
    ///
    /// 对应 Go `HandshakeContext(ctx context.Context) error`。
    fn handshake<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;

    /// 验证 peer 证书是否匹配给定 hostname。
    ///
    /// 对应 Go `VerifyHostname(host string) error`。
    fn verify_hostname<'a>(&'a self, host: &'a str) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;

    /// 握手并返回 ServerName（SNI）。握手失败返回空字符串。
    ///
    /// 对应 Go `HandshakeContextServerName(ctx context.Context) string`。
    fn handshake_server_name<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = String> + Send + 'a>>;

    /// 返回 ALPN 协商出的协议名（如 `"h2"`/`"http/1.1"`）。未协商返回空字符串。
    ///
    /// 对应 Go `NegotiatedProtocol() string`。
    fn negotiated_protocol<'a>(&'a self) -> Pin<Box<dyn Future<Output = String> + Send + 'a>>;
}

// 为了让 trait dyn-compatible，手写 Pin<Box<dyn Future>> 风格。
// 这与 xray-buf::io 的 Writer trait 风格一致（见 docs/translation-conventions.md §3.3）。

// ============================================================
// 工厂函数占位
// ============================================================

/// 创建标准库 TLS 客户端连接。
///
/// 对应 Go `Client(c net.Conn, config *tls.Config) net.Conn`。
/// **未实现**——等接入 rustls 后补充。
pub fn client<I>(_inner: I) -> Result<(), crate::error::TlsError> {
    // 占位：签名保留与 Go 对齐，让上层可以写 `client(...)?`;
    // 实际 rustls 包装等接入后实现。
    Err(crate::error::TlsError::UtlsNotImplemented)
}

/// 创建标准库 TLS 服务端连接。
///
/// 对应 Go `Server(c net.Conn, config *tls.Config) net.Conn`。
/// **未实现**——等接入 rustls 后补充。
pub fn server<I>(_inner: I) -> Result<(), crate::error::TlsError> {
    Err(crate::error::TlsError::UtlsNotImplemented)
}

/// 创建 uTLS 指纹伪装客户端连接。
///
/// 对应 Go `UClient(c net.Conn, config *tls.Config, fingerprint *utls.ClientHelloID) net.Conn`。
/// **未实现**——Rust 生态无 uTLS 等价品。等生态成熟或自研后再接。
pub fn u_client<I>(_inner: I, _fp: crate::fingerprint::Fingerprint) -> Result<(), crate::error::TlsError> {
    Err(crate::error::TlsError::UtlsNotImplemented)
}

// ============================================================
// 测试（仅 trait 可编译性 + 占位错误）
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_stubs_return_not_implemented() {
        // 当前仅占位，上层应检查返回错误为 UtlsNotImplemented
        assert!(matches!(
            client::<()>(()),
            Err(crate::error::TlsError::UtlsNotImplemented)
        ));
    }
}
