//! OCSP stapling 集成模块。
//!
//! 对应 Go `transport/internet/tls/config.go` 中 `setupOcspTicker` 逻辑：
//! TLS 服务器在握手时附带 OCSP 响应（status_request extension），
//! 客户端无需单独查询 OCSP responder，减少握手延迟。
//!
//! # 实现
//!
//! 基于 `ocsp-stapler` crate 的 [`Stapler`]，它实现
//! [`rustls::server::ResolvesServerCert`] trait，包装内层 resolver，
//! 后台自动获取 OCSP 响应并 staple 到证书。
//!
//! # 用法
//!
//! ```rust,ignore
//! let config = OcspStaplerConfig::enabled();
//! let server_config = build_server_config_with_stapling(
//!     "example.com", certs_pem, key_pem, &config,
//! )?;
//! ```

use std::sync::Arc;

use ocsp_stapler::Stapler;
use rustls::server::ResolvesServerCertUsingSni;
use rustls::sign::CertifiedKey;
use rustls_pemfile;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tracing::info;

use crate::error::TlsError;

/// OCSP stapling 配置。
///
/// 对应 Go proto `Certificate.ocsp_stapling` 字段：
/// - 0 或 `Disabled`：不启用 OCSP stapling
/// - >0 或 `Enabled`：启用（后台定期刷新 OCSP 响应）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspStaplerConfig {
    /// 禁用 OCSP stapling。
    Disabled,
    /// 启用 OCSP stapling。
    Enabled,
}

impl OcspStaplerConfig {
    /// 从 proto 的 `ocsp_stapling` uint64 值创建配置。
    ///
    /// 0 → Disabled，>0 → Enabled。
    #[must_use]
    pub fn from_proto_value(value: u64) -> Self {
        if value == 0 { Self::Disabled } else { Self::Enabled }
    }

    /// 是否启用。
    #[must_use]
    pub fn is_enabled(self) -> bool {
        self == Self::Enabled
    }

    /// 创建启用配置。
    #[must_use]
    pub fn enabled() -> Self {
        Self::Enabled
    }

    /// 创建禁用配置。
    #[must_use]
    pub fn disabled() -> Self {
        Self::Disabled
    }
}

impl Default for OcspStaplerConfig {
    fn default() -> Self {
        Self::Disabled
    }
}

/// 从 PEM 编码的字节加载证书链和私钥为 [`CertifiedKey`]。
///
/// `certs_pem` 应包含终端实体证书 + issuer 证书（OCSP stapling 需要 issuer）。
/// `key_pem` 应包含匹配的私钥。
fn load_certified_key(certs_pem: &[u8], key_pem: &[u8]) -> Result<CertifiedKey, TlsError> {
    // 解析 PEM 证书链
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut certs_pem.as_ref())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::PemLoad(format!("failed to parse certificates: {e}")))?;

    if certs.is_empty() {
        return Err(TlsError::PemLoad("no certificates found in PEM input".into()));
    }

    // 解析 PEM 私钥
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_ref())
        .map_err(|e| TlsError::PemLoad(format!("failed to parse private key: {e}")))?
        .ok_or_else(|| TlsError::PemLoad("no private key found in PEM input".into()))?;

    // 转换为 rustls 签名密钥
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| TlsError::PemLoad(format!("private key type not supported by ring: {e}")))?;

    Ok(CertifiedKey::new(certs, signing_key))
}

/// 构建带 OCSP stapling 的 TLS 服务端配置。
///
/// 当 `config` 为 [`OcspStaplerConfig::Enabled`] 时：
/// 1. 加载 PEM 证书链 + 私钥到 [`CertifiedKey`]
/// 2. 注册到 SNI resolver
/// 3. 用 [`Stapler`] 包装 resolver（后台获取 OCSP 响应并 staple）
/// 4. 构建 `ServerConfig` 使用 stapler 作为 cert resolver
///
/// 当 `config` 为 [`OcspStaplerConfig::Disabled`] 时：
/// 构建不启用 OCSP stapling 的标准 `ServerConfig`。
///
/// # 错误
///
/// - [`TlsError::PemLoad`]：PEM 解析或密钥转换失败
/// - [`TlsError::OcspStaplingInit`]：证书链不足（OCSP stapling 需要 issuer 证书）
pub fn build_server_config_with_stapling(
    server_name: &str,
    certs_pem: &[u8],
    key_pem: &[u8],
    config: &OcspStaplerConfig,
) -> Result<ServerConfigAndStapler, TlsError> {
    let ckey = load_certified_key(certs_pem, key_pem)?;
    let ckey = Arc::new(ckey);

    if config.is_enabled() {
        // OCSP stapling 需要至少 2 个证书（end-entity + issuer）
        if ckey.cert.len() < 2 {
            return Err(TlsError::OcspStaplingInit(
                "OCSP stapling requires at least 2 certificates (end-entity + issuer)".into(),
            ));
        }

        // 注册到 SNI resolver
        let mut sni_resolver = ResolvesServerCertUsingSni::new();
        sni_resolver.add(server_name, ckey.as_ref().clone()).map_err(|e| {
            TlsError::OcspStaplingInit(format!("failed to add cert to SNI resolver: {e}"))
        })?;

        // 用 Stapler 包装，后台自动获取 OCSP 响应并 staple
        let stapler = Arc::new(Stapler::new(Arc::new(sni_resolver)));

        // 预加载证书，Must-Staple 证书首次请求时已有 OCSP 响应
        stapler.preload(ckey);

        info!(
            target: "xray_tls::ocsp_stapling",
            server_name,
            "OCSP stapling enabled for server"
        );

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(stapler.clone());

        Ok(ServerConfigAndStapler {
            server_config: Arc::new(server_config),
            stapler: Some(stapler),
        })
    } else {
        // 不启用 OCSP stapling，用 SNI resolver + with_cert_resolver
        let mut sni_resolver = ResolvesServerCertUsingSni::new();
        sni_resolver.add(server_name, ckey.as_ref().clone()).map_err(|e| {
            TlsError::OcspStaplingInit(format!("failed to add cert to SNI resolver: {e}"))
        })?;

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(sni_resolver));

        Ok(ServerConfigAndStapler { server_config: Arc::new(server_config), stapler: None })
    }
}

/// TLS 服务端配置 + 可选的 OCSP stapler 句柄。
///
/// `stapler` 为 `Some` 时，调用方应在 shutdown 时调用 `stapler.stop().await`
/// 以清理后台 OCSP 刷新 worker。
pub struct ServerConfigAndStapler {
    /// rustls 服务端配置（可直接用于 `TlsAcceptor`）。
    pub server_config: Arc<rustls::ServerConfig>,
    /// OCSP stapler 句柄。`None` 表示未启用 stapling。
    pub stapler: Option<Arc<Stapler>>,
}

impl ServerConfigAndStapler {
    /// 停止 OCSP stapler 后台 worker。
    ///
    /// 启用了 stapling 时必须调用以清理资源。
    /// 未启用时为 no-op。
    pub async fn stop(&self) {
        if let Some(stapler) = &self.stapler {
            stapler.stop().await;
        }
    }
}

// ============================================================
// 测试
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    // 安装 ring crypto provider，否则 Stapler 会 panic
    fn install_ring_provider() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .unwrap_or_default();
    }
    #[test]
    fn ocsp_stapler_config_from_proto() {
        assert_eq!(OcspStaplerConfig::from_proto_value(0), OcspStaplerConfig::Disabled);
        assert_eq!(OcspStaplerConfig::from_proto_value(1), OcspStaplerConfig::Enabled);
        assert_eq!(OcspStaplerConfig::from_proto_value(3600), OcspStaplerConfig::Enabled);
    }

    #[test]
    fn ocsp_stapler_config_is_enabled() {
        assert!(!OcspStaplerConfig::Disabled.is_enabled());
        assert!(OcspStaplerConfig::Enabled.is_enabled());
    }

    #[test]
    fn ocsp_stapler_config_default() {
        assert_eq!(OcspStaplerConfig::default(), OcspStaplerConfig::Disabled);
    }

    #[test]
    fn load_certified_key_rejects_empty_certs() {
        let result = load_certified_key(b"", b"");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, TlsError::PemLoad(_)));
        assert!(err.to_string().contains("no certificates"));
    }

    #[test]
    fn load_certified_key_rejects_empty_key() {
        // 有效的证书 PEM 但无私钥
        let certs_pem = b"-----BEGIN CERTIFICATE-----\nMIIBjTCCAWOgAwIBAgIUfZxZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYwDQYJKoZIhvcNAQELBQAwETEPMA0GA1UEAwwGVGVzdENBMCAXDTI0MDEwMTAwMDAwMFoYDzIwNTQwMTAxMDAwMDAwWjARMQ8wDQYDVQQDDAY8VGVzdD4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYxo4HCMIG/MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUZzYxZzYxZzYxZzYxZzYxZzYxZzYwHwYDVR0jBBgwFoAUZzYxZzYxZzYxZzYxZzYxZzYxZzYwDAYDVR0TBAUwAwEB/zAJBgcqhkjOPQ4BAgNHADBEAiAZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYIGC2BQCMQCIQDZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYxZzYw==\n-----END CERTIFICATE-----\n";
        let result = load_certified_key(certs_pem, b"");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, TlsError::PemLoad(_)));
        assert!(err.to_string().contains("no private key"));
    }

    /// 使用 rcgen 生成自签证书测试 OCSP stapling 集成。
    #[test]
    fn build_server_config_disabled_uses_single_cert() {
        let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();

        let certs_pem = cert.pem().into_bytes();
        let key_pem = key_pair.serialize_pem().into_bytes();

        let result = build_server_config_with_stapling(
            "localhost",
            &certs_pem,
            &key_pem,
            &OcspStaplerConfig::Disabled,
        );
        assert!(result.is_ok(), "Disabled config should succeed");
        let sc = result.unwrap();
        assert!(sc.stapler.is_none(), "Stapler should be None when disabled");
    }

    /// OCSP stapling 启用但只有 1 个证书时应返回错误。
    #[test]
    fn build_server_config_enabled_rejects_single_cert() {
        let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();

        let certs_pem = cert.pem().into_bytes();
        let key_pem = key_pair.serialize_pem().into_bytes();

        let result = build_server_config_with_stapling(
            "localhost",
            &certs_pem,
            &key_pem,
            &OcspStaplerConfig::Enabled,
        );
        assert!(result.is_err(), "Should fail with only 1 cert");
        let err = result.unwrap_err();
        assert!(matches!(err, TlsError::OcspStaplingInit(_)));
        assert!(err.to_string().contains("at least 2 certificates"));
    }

    /// 测试 OCSP stapling 启用且有完整证书链时成功构建。
    #[test]
    fn build_server_config_enabled_with_chain() {
        // 生成 CA + end-entity 证书链
        let ca_params = rcgen::CertificateParams::new(vec!["Test CA".to_string()]).unwrap();
        let ca_key_pair = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key_pair).unwrap();

        let mut ee_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        ee_params.is_ca = rcgen::IsCa::NoCa;
        let ee_key_pair = rcgen::KeyPair::generate().unwrap();
        let ee_cert = ee_params.signed_by(&ee_key_pair, &ca_cert, &ca_key_pair).unwrap();

        // PEM: end-entity + issuer
        let mut certs_pem = ee_cert.pem().into_bytes();
        certs_pem.extend_from_slice(ca_cert.pem().as_bytes());
        let key_pem = ee_key_pair.serialize_pem().into_bytes();

        let result = build_server_config_with_stapling(
            "localhost",
            &certs_pem,
            &key_pem,
            &OcspStaplerConfig::Enabled,
        );
        assert!(result.is_ok(), "Enabled with chain should succeed");
        let sc = result.unwrap();
        assert!(sc.stapler.is_some(), "Stapler should be Some when enabled");
    }

    /// 测试 ServerConfigAndStapler::stop 在未启用时为 no-op。
    #[tokio::test]
    async fn stop_is_noop_when_disabled() {
        let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();

        let certs_pem = cert.pem().into_bytes();
        let key_pem = key_pair.serialize_pem().into_bytes();

        let sc = build_server_config_with_stapling(
            "localhost",
            &certs_pem,
            &key_pem,
            &OcspStaplerConfig::Disabled,
        )
        .unwrap();

        // 不应 panic 或 hang
        sc.stop().await;
    }

    /// 测试 ServerConfigAndStapler::stop 在启用时能正常关闭。
    #[tokio::test]
    async fn stop_cleans_up_when_enabled() {
        let ca_params = rcgen::CertificateParams::new(vec!["Test CA".to_string()]).unwrap();
        let ca_key_pair = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key_pair).unwrap();

        let mut ee_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        ee_params.is_ca = rcgen::IsCa::NoCa;
        let ee_key_pair = rcgen::KeyPair::generate().unwrap();
        let ee_cert = ee_params.signed_by(&ee_key_pair, &ca_cert, &ca_key_pair).unwrap();

        let mut certs_pem = ee_cert.pem().into_bytes();
        certs_pem.extend_from_slice(ca_cert.pem().as_bytes());
        let key_pem = ee_key_pair.serialize_pem().into_bytes();

        let sc = build_server_config_with_stapling(
            "localhost",
            &certs_pem,
            &key_pem,
            &OcspStaplerConfig::Enabled,
        )
        .unwrap();

        // 不应 panic 或 hang
        sc.stop().await;
    }
}
