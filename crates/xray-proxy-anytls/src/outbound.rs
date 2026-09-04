//! AnyTLS 出站处理器。
//!
//! 包装 [`AnytlsClient`]，实现 [`OutboundHandler`] trait。
//!
//! ## 流程
//!
//! 1. `OutboundHandler::dial(destination)` 被调度器调用
//! 2. 把 [`Destination`] 转 [`SocksAddr`]
//! 3. 调 `AnytlsClient::dial` 建立 TLS 连接 + 写 SOCKS5 目标
//! 4. 返回 `Ok(())`（与 hysteria 一致，连接对象由 dispatcher 通过 DialBridge 获取）

use std::sync::Arc;

use async_trait::async_trait;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::session::Session;
use xray_features::outbound::{OutboundError, OutboundHandler};

use crate::client::{AnytlsClient, ClientConfig};
use crate::error::Result;
use crate::socks::SocksAddr;

/// AnyTLS 出站 Handler。
///
/// 持有配置 + `AnytlsClient`（内部复用 TLS 会话池），实现 [`OutboundHandler`]。
pub struct AnytlsOutboundHandler {
    tag: String,
    config: ClientConfig,
    client: AnytlsClient,
}

impl AnytlsOutboundHandler {
    /// 构造出站 Handler。
    ///
    /// # 参数
    /// - `tag`：handler 标签（路由匹配用）
    /// - `config`：AnyTLS 客户端配置（server_addr / sni / tls_config 等）
    pub fn new(tag: impl Into<String>, config: ClientConfig) -> Self {
        let client = AnytlsClient::new(config.clone());
        Self {
            tag: tag.into(),
            config,
            client,
        }
    }

    /// 配置引用。
    #[must_use]
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }
}

#[async_trait]
impl OutboundHandler for AnytlsOutboundHandler {
    fn tag(&self) -> &str {
        &self.tag
    }

    /// 通过 AnyTLS 拨号到目标地址。
    ///
    /// `destination` 是最终目标（经 AnyTLS server 中继），AnyTLS server 地址
    /// 来自 [`ClientConfig::server_addr`]。
    async fn dial(
        &self,
        destination: &Destination,
        _session: &Session,
    ) -> std::result::Result<(), OutboundError> {
        let socks = dest_to_socks(destination)
            .map_err(|e| OutboundError::ConnectionFailed(format!("anytls dest parse: {e}")))?;

        self.client
            .dial(&socks)
            .await
            .map_err(|e| OutboundError::ConnectionFailed(format!("anytls dial: {e}")))?;

        tracing::debug!(
            tag = %self.tag,
            dest = %destination,
            "anytls outbound stream established"
        );
        Ok(())
    }

    /// AnyTLS 仅支持 TCP 中继（基于 TLS stream）。
    fn can_handle(&self, destination: &Destination) -> bool {
        destination.network() == Network::TCP
    }
}

/// Destination → SocksAddr 转换。
fn dest_to_socks(dest: &Destination) -> Result<SocksAddr> {
    let port = dest.port().value();
    match dest.address() {
        xray_common::net::address::Address::IPv4(ip) => Ok(SocksAddr::ipv4(*ip, port)),
        xray_common::net::address::Address::IPv6(ip) => {
            Ok(SocksAddr::Ipv6(std::net::SocketAddrV6::new(*ip, port, 0, 0)))
        }
        xray_common::net::address::Address::Domain(d) => Ok(SocksAddr::domain(d.clone(), port)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use xray_common::net::address::Address;
    use xray_common::net::port::Port;

    fn make_dest(network: Network) -> Destination {
        Destination::new(
            Address::Domain("example.com".to_string()),
            Port::new(443),
            network,
        )
    }

    use std::sync::Once;

    static INIT_CRYPTO: Once = Once::new();

    fn init_crypto() {
        INIT_CRYPTO.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn make_handler() -> AnytlsOutboundHandler {
        init_crypto();
        // 构造一个最小 tls config（不验证证书，仅用于构造测试）
        // 构造一个最小 tls config（不验证证书，仅用于构造测试）
        let tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(dangerous::NoVerifier))
                .with_no_client_auth(),
        );
        let config = ClientConfig::new("127.0.0.1:443", "example.com", "test-password", tls_config);
        AnytlsOutboundHandler::new("test", config)
    }

    #[tokio::test]
    async fn handler_tag() {
        let h = make_handler();
        assert_eq!(h.tag(), "test");
    }

    #[tokio::test]
    async fn can_handle_tcp_only() {
        let h = make_handler();
        assert!(h.can_handle(&make_dest(Network::TCP)));
        assert!(!h.can_handle(&make_dest(Network::UDP)));
        assert!(!h.can_handle(&make_dest(Network::Unix)));
    }

    #[test]
    fn dest_to_socks_roundtrip() {
        let d = Destination::new(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(8080),
            Network::TCP,
        );
        let s = dest_to_socks(&d).unwrap();
        match s {
            SocksAddr::Ipv4(a) => {
                assert_eq!(a.ip().octets(), [127, 0, 0, 1]);
                assert_eq!(a.port(), 8080);
            }
            _ => panic!("expected Ipv4"),
        }
    }

    #[test]
    fn dest_to_socks_domain() {
        let d = Destination::new(
            Address::new_domain("example.com"),
            Port::new(443),
            Network::TCP,
        );
        let s = dest_to_socks(&d).unwrap();
        match s {
            SocksAddr::Domain(h, p) => {
                assert_eq!(h, "example.com");
                assert_eq!(p, 443);
            }
            _ => panic!("expected Domain"),
        }
    }

    /// 危险：不验证证书，仅用于测试构造。
    mod dangerous {
        use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::fmt;

        pub struct NoVerifier;

        impl fmt::Debug for NoVerifier {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct("NoVerifier").finish()
            }
        }

        impl ServerCertVerifier for NoVerifier {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp: &[u8],
                _now: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                vec![
                    rustls::SignatureScheme::RSA_PKCS1_SHA256,
                    rustls::SignatureScheme::RSA_PKCS1_SHA384,
                    rustls::SignatureScheme::RSA_PKCS1_SHA512,
                    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                    rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                    rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
                    rustls::SignatureScheme::RSA_PSS_SHA256,
                    rustls::SignatureScheme::RSA_PSS_SHA384,
                    rustls::SignatureScheme::RSA_PSS_SHA512,
                    rustls::SignatureScheme::ED25519,
                ]
            }
        }
    }
}
