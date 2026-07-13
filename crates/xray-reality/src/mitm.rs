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

/// 生成 REALITY Ed25519 证书（cert 末尾 64 字节 HMAC 签名）。
///
/// 翻译自 Go XTLS/REALITY `tls.go` 的 cert 生成逻辑：
///
/// 1. rcgen 生成 Ed25519 self-signed cert
/// 2. 取 Ed25519 公钥（32 字节）
/// 3. 计算 HMAC-SHA512(auth_key, pub_key) → 64 字节签名
///    （[`crate::crypto::sign_reality_certificate`]）
/// 4. 覆盖 cert_der 末尾 64 字节为 HMAC 签名
///
/// rustls 不校验 cert 自身签名（trust anchor 在客户端），只验证
/// CertificateVerify（标准 TLS 1.3 Ed25519 签名）。REALITY 客户端额外
/// 校验 cert 末尾 64 字节为 HMAC。
///
/// 双签名机制：cert.signatureValue = HMAC（REALITY 校验）；
/// CertificateVerify = 真 Ed25519 签名（标准 TLS 1.3）。
///
/// # 参数
///
/// - `auth_key`：HKDF-SHA256 派生的认证密钥（来自 [`verify_reality_client_hello`]）
///
/// # 返回
///
/// `(cert_der, key_der)`：HMAC 签名的 cert + PKCS#8 私钥。
///
/// # Errors
///
/// - rcgen Ed25519 keypair 生成失败 → [`RealityError::CertGenerate`]
/// - HMAC 计算失败 → [`RealityError::EmptySharedKey`]
/// - cert_der 过短（< 64 字节） → [`RealityError::CertGenerate`]
pub fn generate_reality_ed25519_cert(auth_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};

    // ponytail: rcgen 不能模拟 Go 极简 params (SerialNumber=0, 无 issuer/subject/validity),
    // 用 SAN=reality.local 占位 (不影响 REALITY 校验, 只用于 X.509 解析)
    let params = CertificateParams::new(vec!["reality.local".to_string()])
        .map_err(|e| RealityError::CertGenerate(format!("rcgen params: {e}")))?;

    let key_pair = KeyPair::generate_for(&PKCS_ED25519)
        .map_err(|e| RealityError::CertGenerate(format!("rcgen Ed25519 keypair: {e}")))?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| RealityError::CertGenerate(format!("rcgen self_signed: {e}")))?;

    let mut cert_der = cert.der().to_vec();
    let key_der = key_pair.serialize_der();

    // 取 Ed25519 公钥原始字节 (32 bytes)
    let pub_key = key_pair.public_key_raw();

    // HMAC-SHA512 签名
    let hmac_sig = crate::crypto::sign_reality_certificate(auth_key, pub_key)?;

    // 覆盖 cert_der 末尾 64 字节为 HMAC 签名
    // rcgen Ed25519 cert DER 末尾结构: ... BIT STRING (03) | len (42) | unused_bits (00) | signature (64 bytes)
    let len = cert_der.len();
    if len < 64 {
        return Err(RealityError::CertGenerate(format!(
            "cert_der too short: {len} bytes, need >= 64"
        )));
    }
    cert_der[len - 64..].copy_from_slice(&hmac_sig);

    Ok((cert_der, key_der))
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

    #[test]
    fn generate_reality_ed25519_cert_returns_valid_structure() {
        let auth_key = [0x42u8; 32];
        let (cert_der, key_der) = generate_reality_ed25519_cert(&auth_key).unwrap();
        assert!(cert_der.len() > 100, "cert_der should be reasonable size");
        assert!(!key_der.is_empty());
        assert_eq!(cert_der[0], 0x30, "cert_der should start with SEQUENCE tag");
    }

    #[test]
    fn generate_reality_ed25519_cert_hmac_roundtrip() {
        // 验证 sign→verify roundtrip
        let auth_key = [0x42u8; 32];
        let pub_key = [0xabu8; 32]; // 测试用固定公钥
        let sig = crate::crypto::sign_reality_certificate(&auth_key, &pub_key).unwrap();
        let valid = crate::crypto::verify_reality_certificate(&auth_key, &pub_key, &sig).unwrap();
        assert!(valid, "HMAC signature should verify");

        // 错误 auth_key 应失败
        let wrong_key = [0x99u8; 32];
        let invalid = crate::crypto::verify_reality_certificate(&wrong_key, &pub_key, &sig).unwrap();
        assert!(!invalid, "HMAC with wrong key should fail");
    }
}
