//! REALITY 服务端证书生成（Go 语义：进程级固定空证书模板 + 每连接 HMAC 原位覆盖）。
//!
//! 翻译自 XTLS/REALITY `handshake_server_tls13.go` 的 `init()` 与 `handshake()`
//! pickCertificate 块（xray-core v26.6.1 依赖 v0.0.0-20260322-9234c772ba8f）：
//!
//! - `init()`：进程启动生成一次 ed25519 密钥 + 极简空证书 `signedCert`
//!   （`SerialNumber=0`，无 subject/SAN/扩展）；
//! - 每连接（auth 成功后）：`cert = bytes.Clone(signedCert)`，把
//!   `HMAC-SHA512(AuthKey, ed25519Pub)` 的 64 字节写入 cert 末尾 64 字节
//!   （原位覆盖 ed25519 signatureValue）；客户端（reality.go
//!   `VerifyPeerCertificate`：`h.Write(pub)` 后比对 `certs[0].Signature`）
//!   重算 HMAC 比对，通过即 Verified；
//! - 配置 `Mldsa65Key` 时 Go 换用带 3309 字节保留扩展（OID 0.0）的变体模板，
//!   并把 `HMAC-SHA512(AuthKey, pub‖ClientHello‖ServerHello)` 的 ML-DSA-65
//!   签名写入 `cert[126:]` 固定偏移——Rust 端签名路径 stub（见
//!   [`generate_reality_ed25519_cert_mldsa65`]）。
//!
//! 注意：Go REALITY 服务端**不会**从 dest 获取或重签证书——dest 仅在 auth
//! 失败后作 fallback 透明转发（客户端与真实 dest 直接完成 TLS，DPI 在该路径
//! 看到的是 dest 的真证书）。本模块的空证书只呈现给持有私钥的 REALITY 客户端。
//!
//! # 工作流
//!
//! 1. [`DUMMY_CERT`]：进程级固定模板（Go `init()` 等价）
//! 2. [`generate_reality_ed25519_cert`]：克隆模板 + HMAC 覆盖末尾 64 字节
//! 3. [`build_server_config`]：用证书构建 rustls `ServerConfig`
//! 4. [`server_tls`]（[`crate::server`]）：peek ClientHello → verify → TLS 握手 / fallback

use std::sync::LazyLock;

use crate::error::{RealityError, Result};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// ML-DSA-65 签名长度（FIPS 204；Go 预留扩展 `empty[:3309]`）。
pub const MLDSA65_SIGNATURE_LEN: usize = 3309;

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
    // rustls 双 CryptoProvider feature unification 时裸 builder() 会 panic；
    // install_default 幂等（已装返回 Err，忽略）。参考 xray-proxy-tuic server.rs 样板。
    let _ = rustls::crypto::ring::default_provider().install_default();
    let key = PrivateKeyDer::try_from(key_der)
        .map_err(|e| RealityError::CertGenerate(format!("private key der: {e}")))?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert_der)], key)
        .map_err(|e| RealityError::CertGenerate(format!("server config: {e}")))?;
    Ok(config)
}

/// 进程级固定 REALITY 证书模板（对应 Go `init()` 的 `ed25519Priv` + `signedCert`）。
struct DummyCert {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    public_key_raw: [u8; 32],
}

static DUMMY_CERT: LazyLock<DummyCert> =
    LazyLock::new(|| build_dummy_cert().expect("REALITY dummy cert template"));

/// Go `init()` 等价：极简空证书（SerialNumber=0、空 subject、无 SAN、无扩展）。
///
/// validity 用 rcgen 默认固定区间（1975-01-01..4096-01-01）：REALITY 客户端
/// 走自定义 HMAC 验证、不校验时间窗，固定区间保证模板确定性。
///
/// # Errors
/// - rcgen Ed25519 keypair 生成 / 签名失败 → [`RealityError::CertGenerate`]
fn build_dummy_cert() -> Result<DummyCert> {
    use rcgen::{CertificateParams, DistinguishedName, KeyPair, PKCS_ED25519, SerialNumber};

    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new(); // 清空默认 CN（Go: 空 pkix.Name）
    // Go serial=0 经 yasna 编码为 `02 00`（INTEGER 内容 0 字节）＝非法定长 DER，
    // BoringSSL 客户端解析 Certificate 直接 DECODE_ERROR（Go 自家 x509 容忍空
    // INTEGER 故无此问题）。固定 serial=1 保持模板确定性且 DER 合法。
    params.serial_number = Some(SerialNumber::from_slice(&[1]));
    let key_pair = KeyPair::generate_for(&PKCS_ED25519)
        .map_err(|e| RealityError::CertGenerate(format!("rcgen Ed25519 keypair: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| RealityError::CertGenerate(format!("rcgen self_signed: {e}")))?;
    let public_key_raw: [u8; 32] = key_pair
        .public_key_raw()
        .try_into()
        .map_err(|_| RealityError::CertGenerate("ed25519 public key != 32 bytes".into()))?;

    Ok(DummyCert {
        cert_der: cert.der().to_vec(),
        key_der: key_pair.serialize_der(),
        public_key_raw,
    })
}

/// 生成 REALITY Ed25519 证书（Go `handshake()` pickCertificate 块的 Rust 等价）。
///
/// 1. 克隆进程级固定模板 [`DUMMY_CERT`]（Go `bytes.Clone(signedCert)`）
/// 2. 计算 HMAC-SHA512(auth_key, 模板 ed25519 公钥)
///    （[`crate::crypto::sign_reality_certificate`]）
/// 3. 覆盖 cert_der 末尾 64 字节（Go `h.Sum(cert[:len(cert)-64])`——rcgen
///    Ed25519 cert DER 末尾为 BIT STRING signature，内容恰 64 字节）
///
/// rustls 不校验叶子证书自签（trust anchor 在客户端），只验证
/// CertificateVerify（标准 TLS 1.3 Ed25519 签名，用模板私钥）。REALITY 客户端
/// 额外校验 cert 末尾 64 字节为 HMAC。
///
/// # 参数
///
/// - `auth_key`：HKDF-SHA256 派生的认证密钥（来自 [`verify_reality_client_hello`]）
///
/// # 返回
///
/// `(cert_der, key_der)`：HMAC 覆盖后的 cert + PKCS#8 私钥。
///
/// # Errors
///
/// - HMAC 计算失败 → [`RealityError::EmptySharedKey`]
pub fn generate_reality_ed25519_cert(auth_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {

    let dummy = &*DUMMY_CERT;

    // Go: h := hmac.New(sha512.New, c.AuthKey); h.Write(ed25519Priv[32:])
    let hmac_sig = crate::crypto::sign_reality_certificate(auth_key, &dummy.public_key_raw)?;

    // Go: h.Sum(cert[:len(cert)-64])
    let mut cert_der = dummy.cert_der.clone();
    let len = cert_der.len();
    cert_der[len - 64..].copy_from_slice(&hmac_sig);

    Ok((cert_der, dummy.key_der.clone()))
}

/// ML-DSA-65 变体证书 + 签名路径 stub（未实现）。
///
/// Go（handshake_server_tls13.go）：配置 `Mldsa65Key` 时换用带 3309 字节保留
/// 扩展（OID 0.0）的模板证书；HMAC 覆盖后继续
/// `h.Write(clientHello.original); h.Write(hello.original)`，把
/// `HMAC-SHA512(AuthKey, pub‖CH‖SH)` 的 ML-DSA-65 签名写入 `cert[126:]`。
///
/// Rust 端阻塞点：rustls `ResolvesServerCert::resolve()` 只暴露 ClientHello，
/// 证书选定前拿不到 ServerHello 原始字节（Go 在自家 TLS 栈握手函数内生成证书，
/// 无此约束）。签名原语本身已可用（`ml_dsa` crate，见 xray-cli `gen_mldsa65`）。
///
/// # Errors
///
/// - 恒返回 [`RealityError::Mldsa65NotImplemented`]
pub fn generate_reality_ed25519_cert_mldsa65(
    _auth_key: &[u8],
    _client_hello_raw: &[u8],
    _server_hello_raw: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    Err(RealityError::Mldsa65NotImplemented)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 确保 rustls CryptoProvider 在并行测试中只初始化一次
    fn ensure_crypto_provider() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| { let _ = rustls::crypto::ring::default_provider().install_default(); });
    }

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
        ensure_crypto_provider();
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

    /// Go init()：进程级固定模板（signedCert + ed25519Priv），连接间仅末尾
    /// 64 字节 HMAC 不同（Go handshake_server_tls13.go pickCertificate 块）。
    #[test]
    fn reality_cert_uses_static_template_across_calls() {
        let (cert1, key1) = generate_reality_ed25519_cert(&[0x42u8; 32]).unwrap();
        let (cert2, key2) = generate_reality_ed25519_cert(&[0x99u8; 32]).unwrap();

        assert_eq!(key1, key2, "dummy cert key must be process-static (Go init)");
        let n = cert1.len();
        assert_eq!(n, cert2.len());
        assert_eq!(
            cert1[..n - 64],
            cert2[..n - 64],
            "cert template must be static"
        );
        assert_ne!(
            cert1[n - 64..],
            cert2[n - 64..],
            "per-connection HMAC tail must differ"
        );

        // 相同 auth_key → 逐字节一致（HMAC 确定性）
        let (cert3, _) = generate_reality_ed25519_cert(&[0x42u8; 32]).unwrap();
        assert_eq!(cert1, cert3);
    }

    /// Go 空证书语义：无 SAN、无 subject CN——DPI 无法从证书匹配 SNI/身份。
    /// （旧实现 SAN=reality.local + 默认 CN 是可检测伪迹。）
    #[test]
    fn reality_cert_has_no_identifiable_artifacts() {
        let (cert_der, _) = generate_reality_ed25519_cert(&[0x42u8; 32]).unwrap();
        assert!(
            !cert_der.windows(13).any(|w| w == b"reality.local"),
            "SAN reality.local artifact must be gone"
        );
        assert!(
            !cert_der.windows(22).any(|w| w == b"rcgen self signed cert"),
            "default rcgen CN must be cleared (Go: empty pkix.Name)"
        );
        // SAN 扩展 OID 2.5.29.17（DER: 06 03 55 1D 11）必须缺席
        let san_oid: [u8; 5] = [0x06, 0x03, 0x55, 0x1d, 0x11];
        assert!(
            !cert_der.windows(san_oid.len()).any(|w| w == san_oid),
            "Go dummy cert carries no SAN extension"
        );
    }

    /// 从 cert DER 提取 ed25519 原始公钥（SPKI OID + BIT STRING 头后 32 字节）。
    fn cert_ed25519_pubkey(cert_der: &[u8]) -> [u8; 32] {
        const PAT: [u8; 8] = [0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
        let pos = cert_der
            .windows(PAT.len())
            .position(|w| w == PAT)
            .expect("ed25519 SPKI present");
        cert_der[pos + PAT.len()..pos + PAT.len() + 32]
            .try_into()
            .unwrap()
    }

    /// 端到端重签验证（对应 Go 客户端 reality.go VerifyPeerCertificate 快速路径）：
    /// 从生成证书提取 ed25519 公钥 → 重算 HMAC → 与末尾 64 字节比对。
    #[test]
    fn generate_reality_ed25519_cert_end_to_end_verify() {
        let auth_key = [0x42u8; 32];
        let (cert_der, _) = generate_reality_ed25519_cert(&auth_key).unwrap();

        let pub_key = cert_ed25519_pubkey(&cert_der);
        let tail: Vec<u8> = cert_der[cert_der.len() - 64..].to_vec();
        assert!(
            crate::crypto::verify_reality_certificate(&auth_key, &pub_key, &tail).unwrap(),
            "client-side HMAC check must verify (Go VerifyPeerCertificate)"
        );

        // 错误 auth_key（MITM / 非 REALITY 场景）必须失败
        assert!(
            !crate::crypto::verify_reality_certificate(&[0x99u8; 32], &pub_key, &tail)
                .unwrap(),
            "wrong auth_key must not verify"
        );
    }

    /// mldsa65 签名路径 stub：rustls 证书选定前拿不到 ServerHello 字节 → NotImplemented。
    #[test]
    fn mldsa65_cert_signing_stub_not_implemented() {
        let err = generate_reality_ed25519_cert_mldsa65(&[0x42u8; 32], &[1, 2, 3], &[4, 5, 6])
            .unwrap_err();
        assert!(matches!(err, RealityError::Mldsa65NotImplemented));
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
