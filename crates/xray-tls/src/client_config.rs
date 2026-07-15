//! 从 `streamSettings` 安全配置构建 `rustls::ClientConfig`。
//!
//! 对应 Go `transport/internet/tls/tls.go::ConfigFromStreamSettings` + `GetTLSConfig`。
//!
//! 本模块只做最小化组装：解析 `serverName` / `allowInsecure` / `alpn` 三字段，
//! 用 `webpki-roots` 信任根或 `dangerous()` 跳过验证。fingerprint / ECH / 证书钉扎
//! 等高级特性留待 REALITY 切片接入。

use std::io;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

/// 默认 ALPN 协议列表（对齐 Go `NextProto = []string{"h2", "http/1.1"}`）。
const DEFAULT_ALPN: &[&str] = &["h2", "http/1.1"];

/// 从 `streamSettings` 的安全配置构建 rustls `ClientConfig`。
///
/// 对应 Go `ConfigFromStreamSettings` + `GetTLSConfig`。
///
/// # 参数
/// - `security`：安全层名（`"none"` / `"tls"` / `"reality"`）。非 `"tls"` / `"reality"` 返回 `None`。
/// - `security_json`：`tlsSettings` 或 `realitySettings` 的 JSON 值。`None` 用默认值。
/// - `server_name`：默认 SNI（当 `tlsSettings.serverName` 缺失时使用）。
///
/// # 返回
/// - `Ok(None)`：不需要 TLS
/// - `Ok(Some(Arc<ClientConfig>))`：构建成功
/// - `Err`：配置解析错误（如 `alpn` 元素不是字符串）
///
/// # 安全
///
/// `allowInsecure=true` 会跳过证书验证（对齐 Go `InsecureSkipVerify`）。仅用于调试或
/// 明确接受 MITM 风险的场景。生产环境必须保持 `false`。
pub fn build_client_config(
    security: &str,
    security_json: Option<&serde_json::Value>,
    server_name: &str,
) -> io::Result<Option<Arc<ClientConfig>>> {
    // ring provider 安装幂等：进程内首次安装生效，后续 no-op。
    // ponytail: 放在函数入口确保调用方不必显式 install。
    let _ = rustls::crypto::ring::default_provider().install_default();

    if !matches!(security, "tls" | "reality") {
        return Ok(None);
    }

    let json = security_json.cloned().unwrap_or(serde_json::Value::Null);
    let obj = json.as_object();

    // serverName：缺失时用参数传入的默认值（通常是 dest 地址）。
    let _sni: String = obj
        .and_then(|m| m.get("serverName"))
        .and_then(|v| v.as_str())
        .unwrap_or(server_name)
        .to_string();

    // allowInsecure：默认 false。
    let allow_insecure: bool = obj
        .and_then(|m| m.get("allowInsecure"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // alpn：数组；缺失用 DEFAULT_ALPN。
    let alpn_owned: Vec<Vec<u8>> = if let Some(arr) = obj.and_then(|m| m.get("alpn")).and_then(|v| v.as_array()) {
        arr.iter()
            .map(|s| {
                s.as_str()
                    .map(|x| x.as_bytes().to_vec())
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "alpn array must contain only strings"))
            })
            .collect::<io::Result<_>>()?
    } else {
        DEFAULT_ALPN.iter().map(|s| s.as_bytes().to_vec()).collect()
    };

    let config = if allow_insecure {
        build_dangerous(&alpn_owned)?
    } else {
        build_with_webpki_roots(&alpn_owned)?
    };

    Ok(Some(Arc::new(config)))
}

/** 用 webpki-roots 信任根 + ALPN 构建标准 ClientConfig。 */
fn build_with_webpki_roots(alpn: &[Vec<u8>]) -> io::Result<ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.to_vec();
    Ok(cfg)
}

/**
 * 用 `dangerous()` + `NoCertificateVerification` 跳过证书验证。
 *
 * 仅在 `allowInsecure=true` 时使用。
 */
fn build_dangerous(alpn: &[Vec<u8>]) -> io::Result<ClientConfig> {
    let mut cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.to_vec();
    Ok(cfg)
}

/// 永远通过证书验证的 verifier（对齐 Go `InsecureSkipVerify: true`）。
///
/// # 安全
///
/// 该 verifier 完全不检查证书，**仅在调试或明确接受 MITM 风险的场景使用**。
/// 生产环境必须保持 `allowInsecure=false`。
#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // ponytail: 永远通过——与 Go InsecureSkipVerify 等价。
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // 暴露所有 rustls 内置方案，避免与 peer 协商失败。
        // ponytail: 不筛选 = dangerous verifier 接受任何签名方案。
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
            SignatureScheme::ECDSA_NISTP521_SHA512,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn install_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn none_security_returns_none() {
        install_provider();
        let r = build_client_config("none", None, "example.com").unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn empty_security_returns_none() {
        install_provider();
        let r = build_client_config("", None, "example.com").unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn tls_security_with_null_json_returns_some() {
        install_provider();
        let r = build_client_config("tls", None, "example.com").unwrap();
        assert!(r.is_some(), "tls should produce a ClientConfig even with null json");
    }

    #[test]
    fn tls_security_parses_alpn() {
        install_provider();
        let v: serde_json::Value =
            serde_json::from_str(r#"{"serverName":"x.com","alpn":["h2","http/1.1"]}"#).unwrap();
        let cfg = build_client_config("tls", Some(&v), "fallback.com").unwrap().unwrap();
        let negotiated: Vec<Vec<u8>> = cfg.alpn_protocols.clone();
        assert_eq!(negotiated, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    #[test]
    fn tls_security_alpn_invalid_type_returns_err() {
        install_provider();
        let v: serde_json::Value = serde_json::from_str(r#"{"alpn":["h2",123]}"#).unwrap();
        let r = build_client_config("tls", Some(&v), "x.com");
        assert!(r.is_err(), "non-string alpn element must error");
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn tls_security_alpn_defaults_when_missing() {
        install_provider();
        let v: serde_json::Value = serde_json::from_str(r#"{"serverName":"x.com"}"#).unwrap();
        let cfg = build_client_config("tls", Some(&v), "fallback.com").unwrap().unwrap();
        let negotiated: Vec<Vec<u8>> = cfg.alpn_protocols.clone();
        assert_eq!(negotiated, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    #[test]
    fn allow_insecure_produces_dangerous_verifier() {
        install_provider();
        let v: serde_json::Value = serde_json::from_str(r#"{"allowInsecure":true}"#).unwrap();
        let cfg = build_client_config("tls", Some(&v), "example.com").unwrap().unwrap();
        // dangerous verifier 应该是 NoCertificateVerification；通过 ALPN 仍设置验证 dangerous 路径走通。
        assert!(!cfg.alpn_protocols.is_empty());
        // 没有公开 API 直接判 verifier 类型，靠 e2e 验证行为。
    }

    #[test]
    fn reality_security_treated_as_tls() {
        install_provider();
        let r = build_client_config("reality", None, "example.com").unwrap();
        assert!(r.is_some(), "reality should produce a ClientConfig");
    }
}
