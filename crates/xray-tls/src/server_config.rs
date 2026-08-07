//! 从 `streamSettings` 安全配置构建 `rustls::ServerConfig`。
//!
//! 对应 Go `transport/internet/tls/tls.go::ConfigFromStreamSettings` (server side)。

use std::io;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;

/// 从 `streamSettings` 的安全配置构建 rustls `ServerConfig`。
///
/// # 参数
/// - `security`：安全层名（`"none"` / `"tls"` / `"reality"`）。非 `"tls"` / `"reality"` 返回 `None`。
/// - `security_json`：`tlsSettings` 的 JSON 值。
///
/// # 返回
/// - `Ok(None)`：不需要 TLS
/// - `Ok(Some(Arc<ServerConfig>))`：构建成功
/// - `Err`：配置解析错误
pub fn build_server_config(
    security: &str,
    security_json: Option<&serde_json::Value>,
) -> io::Result<Option<Arc<ServerConfig>>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    if !matches!(security, "tls" | "reality") {
        return Ok(None);
    }

    let json = security_json.cloned().unwrap_or(serde_json::Value::Null);

    // 从 JSON 解析证书
    let (certs, key) = if let Some(certs_json) = json.get("certificates").and_then(|v| v.as_array()) {
        // Go 格式：certificates[].certificateFile + keyFile
        parse_certificates_from_files(certs_json)?
    } else if let (Some(cert_str), Some(key_str)) = (
        json.get("cert").and_then(|x| x.as_str()),
        json.get("key").and_then(|x| x.as_str()),
    ) {
        // inline PEM 格式（anytls 等用）
        parse_inline_pem(cert_str, key_str)?
    } else {
        return Err(io::Error::other(
            "TLS server config: no certificates found (need certificates[].certificateFile+keyFile or cert+key)",
        ));
    };

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::other(format!("build TLS server config: {e}")))?;

    Ok(Some(Arc::new(config)))
}

/// 从 Go 格式 certificates 数组解析（certificateFile + keyFile）。
fn parse_certificates_from_files(
    certs_json: &[serde_json::Value],
) -> io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let first = certs_json
        .first()
        .ok_or_else(|| io::Error::other("TLS config 'certificates' array is empty"))?;

    let cert_file = first
        .get("certificateFile")
        .and_then(|v| v.as_str())
        .ok_or_else(|| io::Error::other("TLS certificate missing 'certificateFile'"))?;
    let key_file = first
        .get("keyFile")
        .and_then(|v| v.as_str())
        .ok_or_else(|| io::Error::other("TLS certificate missing 'keyFile'"))?;

    let cert_pem = std::fs::read(cert_file)
        .map_err(|e| io::Error::other(format!("read cert file {cert_file}: {e}")))?;
    let key_pem = std::fs::read(key_file)
        .map_err(|e| io::Error::other(format!("read key file {key_file}: {e}")))?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io::Error::other(format!("parse cert PEM: {e}")))?;

    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .map_err(|e| io::Error::other(format!("parse key PEM: {e}")))?
        .ok_or_else(|| io::Error::other("no private key found in key file"))?;

    Ok((certs, key))
}

/// 从 inline PEM 字符串解析。
fn parse_inline_pem(
    cert_str: &str,
    key_str: &str,
) -> io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_str.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io::Error::other(format!("parse inline cert PEM: {e}")))?;

    let key = rustls_pemfile::private_key(&mut key_str.as_bytes())
        .map_err(|e| io::Error::other(format!("parse inline key PEM: {e}")))?
        .ok_or_else(|| io::Error::other("no private key in inline PEM"))?;

    Ok((certs, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_security_returns_none() {
        assert!(build_server_config("none", None).unwrap().is_none());
    }

    #[test]
    fn empty_security_returns_none() {
        assert!(build_server_config("", None).unwrap().is_none());
    }

    #[test]
    fn tls_without_certificates_errors() {
        let result = build_server_config("tls", Some(&serde_json::json!({})));
        assert!(result.is_err());
    }

    #[test]
    fn tls_with_inline_pem_works() {
        // ponytail: 无证书配置时用自签名证书
        let _ = rustls::crypto::ring::default_provider().install_default();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        let json = serde_json::json!({
            "cert": cert_pem,
            "key": key_pem,
        });

        let config = build_server_config("tls", Some(&json)).unwrap();
        assert!(config.is_some());
    }
}
