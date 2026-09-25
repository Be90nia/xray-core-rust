//! gRPC over TLS（uTLS 指纹伪装版本）占位。
//!
//! 翻译自 Go `transport/internet/tls/grpc.go`。
//!
//! # 现状
//! gRPC 集成依赖 Rust 端 gRPC crate（如 `tonic`）+ uTLS 实现，**均未就绪**。
//! 本模块只翻译类型定义与 trait，待 Phase 5 (transport-grpc) + uTLS 接入后实现。

use std::{future::Future, pin::Pin};

use crate::{error::TlsError, fingerprint::Fingerprint};

/// gRPC TLS 认证信息。
///
/// 对应 Go `grpcUtlsInfo struct { State utls.ConnectionState; CommonAuthInfo; SPIFFEID }`。
/// Rust 端简化为枚举字段——实际 `ConnectionState` 字段等接入 rustls 后填。
#[derive(Debug, Clone, Default)]
pub struct GrpcUtlsInfo {
    /// 协商出的密码套件名称（对应 Go 的 `StandardName`，格式 `"0x{hex}"`）。
    pub cipher_suite_standard_name: String,
    /// peer 证书链原始 DER（取 PeerCertificates[0]）。
    pub remote_certificate: Vec<u8>,
    /// SPIFFE ID（可选）。Go 端标注 experimental。
    pub spiffe_id: Option<String>,
}

impl GrpcUtlsInfo {
    /// 对应 Go `AuthType() string`。固定返回 `"utls"`。
    pub fn auth_type(&self) -> &'static str {
        "utls"
    }
}

/// gRPC TransportCredentials（uTLS 指纹伪装版）。
///
/// 对应 Go `grpcUtls struct` + `credentials.TransportCredentials` 接口。
/// Rust 端 tonic 的 `Channel` 体系与 Go grpc credentials 不直接对应，
/// 这里留 trait 作为上层抽象点。
pub trait GrpcUtlsCredentials: Send + Sync {
    /// 客户端握手。
    ///
    /// 对应 Go `ClientHandshake(ctx, authority, rawConn)`。
    fn client_handshake<'a>(
        &'a mut self,
        authority: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<GrpcUtlsInfo, TlsError>> + Send + 'a>>;

    /// 服务端握手。**uTLS 作为服务端不支持**，调用永远返回错误。
    ///
    /// 对应 Go `ServerHandshake` —— Go 端是 panic("not available!")，
    /// Rust 改为 `Result` 返回错误（避免 panic 破坏进程稳定性）。
    fn server_handshake(&self) -> Result<(), TlsError> {
        Err(TlsError::UtlsNotImplemented)
    }
    /// 克隆凭证。
    fn clone_box(&self) -> Box<dyn GrpcUtlsCredentials>;

    /// 覆盖 ServerName。
    fn override_server_name<'a>(
        &'a mut self,
        server_name: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), TlsError>> + Send + 'a>>;
}

/// 构造 gRPC uTLS credentials。
///
/// 对应 Go `NewGrpcUtls(c *gotls.Config, fingerprint *utls.ClientHelloID)`。
/// **未实现**——待 grpc + uTLS crate 接入。
pub fn new_grpc_utls(_fp: Fingerprint) -> Result<Box<dyn GrpcUtlsCredentials>, TlsError> {
    Err(TlsError::UtlsNotImplemented)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_type_constant() {
        let info = GrpcUtlsInfo::default();
        assert_eq!(info.auth_type(), "utls");
    }

    #[test]
    fn server_handshake_always_errors() {
        // Go 是 panic，Rust 返回 Err 避免崩进程
        struct DummyCreds;
        impl GrpcUtlsCredentials for DummyCreds {
            fn client_handshake<'a>(
                &'a mut self,
                _authority: &'a str,
            ) -> Pin<Box<dyn Future<Output = Result<GrpcUtlsInfo, TlsError>> + Send + 'a>>
            {
                Box::pin(async { Err(TlsError::UtlsNotImplemented) })
            }

            fn clone_box(&self) -> Box<dyn GrpcUtlsCredentials> {
                Box::new(DummyCreds)
            }

            fn override_server_name<'a>(
                &'a mut self,
                _name: &'a str,
            ) -> Pin<Box<dyn Future<Output = Result<(), TlsError>> + Send + 'a>> {
                Box::pin(async { Ok(()) })
            }
        }
        let c = DummyCreds;
        assert!(matches!(c.server_handshake(), Err(TlsError::UtlsNotImplemented)));
    }

    #[test]
    fn factory_returns_not_implemented() {
        assert!(matches!(new_grpc_utls(Fingerprint::Chrome), Err(TlsError::UtlsNotImplemented)));
    }
}
