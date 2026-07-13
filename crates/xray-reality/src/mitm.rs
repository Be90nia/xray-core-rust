//! REALITY 服务端 MITM 证书生成。
//!
//! 翻译自 Go `xtls/reality` 库的服务端证书伪造逻辑。Go 端连 dest 拿真实证书
//! 后用 mldsa65 重新签名；Rust 端先用 rcgen 自签证书（SAN 从 SNI 提取），
//! REALITY 客户端 InsecureSkipVerify=true + 自定义 REALITY 握手验证，不影响安全性。
//!
//! # 工作流
//!
//! 1. [`generate_self_signed_cert`]：rcgen 为指定 SNI 生成自签证书
//! 2. [`build_server_config`]：用证书构建 rustls `ServerConfig`
//! 3. [`server_tls`]（[`crate::server`]）：peek ClientHello → verify → TLS 握手 / fallback

use crate::error::{RealityError, Result};

use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// 为指定 SNI 生成自签证书。
///
/// 返回 `(cert_der, key_der)`，用于 [`build_server_config`]。
///
/// # Errors
/// - rcgen 参数构造 / 密钥生成 / 签名失败 → [`RealityError::CertGenerate`]
pub fn generate_self_signed_cert(sni: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let params = rcgen::CertificateParams::new(vec![sni.to_string()])
        .map_err(|e| RealityError::CertGenerate(format!("rcgen params: {e}")))?;
    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| RealityError::CertGenerate(format!("rcgen keypair: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| RealityError::CertGenerate(format!("rcgen self_signed: {e}")))?;
    Ok((cert.der().to_vec(), key_pair.serialize_der()))
}

/// 用证书 + 私钥构建 rustls `ServerConfig`（无客户端认证）。
///
/// # Errors
/// - 私钥 DER 解析失败 / ServerConfig 构建失败 → [`RealityError::CertGenerate`]
pub fn build_server_config(cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<ServerConfig> {
    let key = PrivateKeyDer::try_from(key_der)
        .map_err(|e| RealityError::CertGenerate(format!("private key der: {e}")))?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert_der)], key)
        .map_err(|e| RealityError::CertGenerate(format!("server config: {e}")))?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_self_signed_cert_returns_nonempty_ders() {
        let (cert_der, key_der) = generate_self_signed_cert("www.mozilla.org").unwrap();
        assert!(!cert_der.is_empty(), "cert_der must not be empty");
        assert!(!key_der.is_empty(), "key_der must not be empty");
        // X.509 DER 应以 SEQUENCE tag 0x30 开头
        assert_eq!(cert_der[0], 0x30, "cert_der should start with SEQUENCE tag");
    }

    #[test]
    fn build_server_config_from_generated_cert() {
        let (cert_der, key_der) = generate_self_signed_cert("localhost").unwrap();
        let config = build_server_config(cert_der, key_der);
        assert!(config.is_ok(), "ServerConfig build should succeed");
    }

    #[test]
    fn different_snis_produce_different_certs() {
        let (cert1, _) = generate_self_signed_cert("a.test").unwrap();
        let (cert2, _) = generate_self_signed_cert("b.test").unwrap();
        assert_ne!(cert1, cert2, "different SANs should produce different certs");
    }
}
