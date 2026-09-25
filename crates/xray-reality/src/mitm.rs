//! REALITY 服务端证书生成（Go 语义：进程级固定空证书模板 + 每连接 HMAC 原位覆盖）。
//!
//! 翻译自 XTLS/REALITY `handshake_server_tls13.go` 的 `init()` 与 `handshake()`
//! pickCertificate 块（xray-core v26.6.1 依赖 v0.0.0-20260322-9234c772ba8f）：
//!
//! - `init()`：进程启动生成一次 ed25519 密钥 + 极简空证书 `signedCert` （`SerialNumber=0`，无
//!   subject/SAN/扩展）；
//! - 每连接（auth 成功后）：`cert = bytes.Clone(signedCert)`，把 `HMAC-SHA512(AuthKey, ed25519Pub)`
//!   的 64 字节写入 cert 末尾 64 字节 （原位覆盖 ed25519 signatureValue）；客户端（reality.go
//!   `VerifyPeerCertificate`：`h.Write(pub)` 后比对 `certs[0].Signature`） 重算 HMAC 比对，通过即
//!   Verified；
//! - 配置 `Mldsa65Key` 时 Go 换用带 3309 字节保留扩展（OID 0.0）的变体模板， 并把
//!   `HMAC-SHA512(AuthKey, pub‖ClientHello‖ServerHello)` 的 ML-DSA-65 签名写入 `cert[126:]`
//!   固定偏移——Rust 端已实现 （[`generate_reality_ed25519_cert_mldsa65`]，偏移动态定位）；生产接线
//!   受 rustls 证书选定时机限制，见该函数文档。
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

use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::error::{RealityError, Result};

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

/// Go reality fork 服务端语义复刻（xtls/reality handshake_server_tls13.go:142-161）：
/// REALITY 握手的 CertificateVerify **硬编码 `hs.sigAlg = Ed25519`**，不走
/// `selectSignatureScheme` 协商——Go utls Chrome 模板的 signature_algorithms
/// 不含 ed25519（只有 ECDSA-P256/P384 + RSA-PSS/PKCS1），标准 TLS 服务端会因
/// 交集为空拒握（rustls `PeerIncompatible::NoSignatureSchemesInCommon`，CI #32
/// Go cli→Rust srv 跨栈失败根因）；而 Go/utls 客户端验证 CertificateVerify 时
/// 只按 scheme 字段分派签名算法、不检查其是否在自己声明过的列表里，故 Go↔Go
/// 天然互通。REALITY 证书锁死 Ed25519（客户端 HMAC 验证要求
/// `certs[0].PublicKey` 为 ed25519），无法换证书迁就客户端列表。
#[derive(Debug)]
struct ForceEd25519SigningKey {
    inner: std::sync::Arc<dyn rustls::sign::SigningKey>,
}

impl rustls::sign::SigningKey for ForceEd25519SigningKey {
    fn choose_scheme(
        &self,
        _offered: &[rustls::SignatureScheme],
    ) -> Option<std::boxed::Box<dyn rustls::sign::Signer>> {
        // 忽略客户端 offered 列表（Go fork 同语义），仅当底层密钥确实支持
        // Ed25519 时返回 Some——REALITY 证书恒为 Ed25519，否则维持标准行为。
        self.inner.choose_scheme(&[rustls::SignatureScheme::ED25519])
    }

    fn public_key(&self) -> Option<rustls_pki_types::SubjectPublicKeyInfoDer<'_>> {
        self.inner.public_key()
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.inner.algorithm()
    }
}

/// [`ForceEd25519SigningKey`] 的 KeyProvider 包装（REALITY 服务端专用）。
///
/// 无状态：key 装载直接委托 `ring::sign::any_supported_type`（watfaq-rustls
/// fork `Ring::load_private_key` 的同一入口），外包强推层。watfaq-rustls
/// fork 的 `CryptoProvider::key_provider` 是 `&'static dyn KeyProvider`（非
/// 标准 rustls 的 `Arc`），故以 static 实例提供（[`FORCE_ED25519_PROVIDER`]）。
#[derive(Debug)]
struct ForceEd25519KeyProvider;

impl rustls::crypto::KeyProvider for ForceEd25519KeyProvider {
    fn load_private_key(
        &self,
        key_der: rustls_pki_types::PrivateKeyDer<'static>,
    ) -> std::result::Result<std::sync::Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        let inner = rustls::crypto::ring::sign::any_supported_type(&key_der)?;
        Ok(std::sync::Arc::new(ForceEd25519SigningKey { inner }))
    }

    fn fips(&self) -> bool {
        false
    }
}

/// [`ForceEd25519KeyProvider`] 静态实例（fork 要求 `&'static`，见上）。
static FORCE_ED25519_PROVIDER: &dyn rustls::crypto::KeyProvider = &ForceEd25519KeyProvider;

/// 用证书 + 私钥构建 rustls `ServerConfig`（无客户端认证）。
///
/// 强推 Ed25519 语义见 [`ForceEd25519SigningKey`]（Go fork `hs.sigAlg = Ed25519`
/// 复刻；rustls 默认协商会在 Go utls 客户端上触发 NoSignatureSchemesInCommon）。
///
/// # Errors
/// - 私钥 DER 解析失败 / ServerConfig 构建失败 → [`RealityError::CertGenerate`]
pub fn build_server_config(cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<ServerConfig> {
    // rustls 双 CryptoProvider feature unification 时裸 builder() 会 panic；
    // 经 xray-common 集中入口幂等安装（bd jrh7）。
    xray_common::ensure_default_crypto_provider();
    let key = PrivateKeyDer::try_from(key_der)
        .map_err(|e| RealityError::CertGenerate(format!("private key der: {e}")))?;
    let mut provider = rustls::crypto::ring::default_provider();
    provider.key_provider = FORCE_ED25519_PROVIDER;
    let config = ServerConfig::builder_with_provider(std::sync::Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| RealityError::CertGenerate(format!("protocol versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert_der)], key)
        .map_err(|e| RealityError::CertGenerate(format!("server config: {e}")))?;
    Ok(config)
}

/// 进程级固定 REALITY 证书模板（对应 Go `init()` 的 `ed25519Priv` + `signedCert`）。
struct DummyCert {
    cert_der: Vec<u8>,
    /// mldsa65 变体模板（Go `signedCertMldsa65`：同密钥自签 + OID 0.0 的
    /// 3309B 保留扩展）。cm97：签名路径的宿主证书。
    cert_der_mldsa65: Vec<u8>,
    /// 变体模板中扩展 value 区起始偏移（Go 硬编码 `cert[126:]` 的等价物；
    /// rcgen 与 Go x509 的 DER 布局不同，必须动态定位）。
    mldsa65_ext_value_off: usize,
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

    let make_params = || {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new(); // 清空默认 CN（Go: 空 pkix.Name）
        // Go serial=0 经 yasna 编码为 `02 00`（INTEGER 内容 0 字节）＝非法定长 DER，
        // BoringSSL 客户端解析 Certificate 直接 DECODE_ERROR（Go 自家 x509 容忍空
        // INTEGER 故无此问题）。固定 serial=1 保持模板确定性且 DER 合法。
        params.serial_number = Some(SerialNumber::from_slice(&[1]));
        params
    };
    let key_pair = KeyPair::generate_for(&PKCS_ED25519)
        .map_err(|e| RealityError::CertGenerate(format!("rcgen Ed25519 keypair: {e}")))?;
    let cert = make_params()
        .self_signed(&key_pair)
        .map_err(|e| RealityError::CertGenerate(format!("rcgen self_signed: {e}")))?;

    // mldsa65 变体模板（Go signedCertMldsa65 等价）：同密钥自签 + 单个
    // OID 0.0 扩展，value 预留 3309B 全零（握手时原位覆盖为 ML-DSA-65 签名）。
    let mut params_mldsa65 = make_params();
    params_mldsa65.custom_extensions =
        vec![rcgen::CustomExtension::from_oid_content(&[0, 0], vec![0u8; MLDSA65_SIGNATURE_LEN])];
    let cert_mldsa65 = params_mldsa65
        .self_signed(&key_pair)
        .map_err(|e| RealityError::CertGenerate(format!("rcgen self_signed mldsa65: {e}")))?;
    let cert_der_mldsa65 = cert_mldsa65.der().to_vec();
    let mldsa65_ext_value_off = crate::util::find_oid_0_0_extension(&cert_der_mldsa65)
        .map(|(off, len)| {
            assert_eq!(len, MLDSA65_SIGNATURE_LEN, "mldsa65 extension value length");
            off
        })
        .ok_or_else(|| {
            RealityError::CertGenerate("mldsa65 extension not found in template".into())
        })?;

    let public_key_raw: [u8; 32] = key_pair
        .public_key_raw()
        .try_into()
        .map_err(|_| RealityError::CertGenerate("ed25519 public key != 32 bytes".into()))?;

    Ok(DummyCert {
        cert_der: cert.der().to_vec(),
        cert_der_mldsa65,
        mldsa65_ext_value_off,
        key_der: key_pair.serialize_der(),
        public_key_raw,
    })
}

/// 生成 REALITY Ed25519 证书（Go `handshake()` pickCertificate 块的 Rust 等价）。
///
/// 1. 克隆进程级固定模板 [`DUMMY_CERT`]（Go `bytes.Clone(signedCert)`）
/// 2. 计算 HMAC-SHA512(auth_key, 模板 ed25519 公钥) （[`crate::crypto::sign_reality_certificate`]）
/// 3. 覆盖 cert_der 末尾 64 字节（Go `h.Sum(cert[:len(cert)-64])`——rcgen Ed25519 cert DER 末尾为
///    BIT STRING signature，内容恰 64 字节）
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

/// ML-DSA-65 变体证书 + 签名（Go `handshake()` pickCertificate 块 mldsa65
/// 分支的 Rust 等价，cm97）。
///
/// Go（handshake_server_tls13.go）：配置 `Mldsa65Key` 时换用带 3309 字节保留
/// 扩展（OID 0.0）的模板证书；HMAC 覆盖后继续
/// `h.Write(clientHello.original); h.Write(hello.original)`，把
/// `HMAC-SHA512(AuthKey, pub‖CH‖SH)` 的 ML-DSA-65 签名写入 `cert[126:]`。
/// Rust 侧差异仅在偏移获取方式：rcgen 与 Go x509 的 DER 布局不同，签名写入
/// 点由模板构建期动态定位（[`DummyCert::mldsa65_ext_value_off`]），语义一致。
///
/// # 参数
///
/// - `auth_key`：HKDF-SHA256 派生的认证密钥
/// - `client_hello_raw`：客户端 ClientHello 完整 handshake message （type(1)+len(3)+body，对齐 Go
///   `hs.clientHello.original`）
/// - `server_hello_raw`：服务端 ServerHello 完整 handshake message（对齐 Go `hs.hello.original`）
/// - `mldsa65_seed`：ML-DSA-65 种子（Go `mldsa65Seed`，32 字节）
///
/// # Errors
///
/// - HMAC 计算失败 → [`RealityError::EmptySharedKey`]
/// - seed 长度 ≠ 32 → [`RealityError::InvalidMldsa65SeedLen`]
///
/// # 生产接线边界
///
/// rustls `ResolvesServerCert::resolve()` 只暴露 ClientHello，证书选定前
/// 拿不到 ServerHello 原始字节（Go 在自家 TLS 栈握手函数内生成证书，无此
/// 约束；btls 无 server acceptor）。本函数可签可验（契约测试覆盖），但
/// `server_tls` 生产路径暂无调用点；客户端侧的完整链路（btls ServerHello
/// 捕获 + 验签）已落地（[`crate::client`]）。
pub fn generate_reality_ed25519_cert_mldsa65(
    auth_key: &[u8],
    client_hello_raw: &[u8],
    server_hello_raw: &[u8],
    mldsa65_seed: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let dummy = &*DUMMY_CERT;

    let mut cert_der = dummy.cert_der_mldsa65.clone();
    // Go: h := hmac.New(sha512.New, c.AuthKey); h.Write(ed25519Priv[32:]);
    //     h.Sum(cert[:len(cert)-64])
    let hmac_sig = crate::crypto::sign_reality_certificate(auth_key, &dummy.public_key_raw)?;
    let len = cert_der.len();
    cert_der[len - 64..].copy_from_slice(&hmac_sig);

    // Go: h.Write(clientHello.original); h.Write(hello.original);
    //     mldsa65.SignTo(key, h.Sum(nil), nil, false, cert[126:])
    let msg = crate::crypto::hmac_reality_message(
        auth_key,
        &dummy.public_key_raw,
        client_hello_raw,
        server_hello_raw,
    )?;
    let sig = crate::crypto::sign_mldsa65_signature(mldsa65_seed, &msg)?;
    let off = dummy.mldsa65_ext_value_off;
    cert_der[off..off + sig.len()].copy_from_slice(&sig);

    Ok((cert_der, dummy.key_der.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 确保 rustls CryptoProvider 在并行测试中只初始化一次
    fn ensure_crypto_provider() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
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
        assert_eq!(cert1[..n - 64], cert2[..n - 64], "cert template must be static");
        assert_ne!(cert1[n - 64..], cert2[n - 64..], "per-connection HMAC tail must differ");

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
        let pos = cert_der.windows(PAT.len()).position(|w| w == PAT).expect("ed25519 SPKI present");
        cert_der[pos + PAT.len()..pos + PAT.len() + 32].try_into().unwrap()
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
            !crate::crypto::verify_reality_certificate(&[0x99u8; 32], &pub_key, &tail).unwrap(),
            "wrong auth_key must not verify"
        );
    }

    /// cm97 契约：mldsa65 变体证书签名/验签全链 roundtrip（对齐 Go
    /// handshake_server_tls13.go 签名端 + reality.go VerifyPeerCertificate
    /// 验证端）。篡改任一输入必须验签失败。
    #[test]
    fn mldsa65_cert_sign_verify_roundtrip() {
        let auth_key = [0x42u8; 32];
        let seed = [0x07u8; 32];
        let ch = [0x11u8; 256];
        let sh = [0x22u8; 90];

        let (cert_der, key_der) =
            generate_reality_ed25519_cert_mldsa65(&auth_key, &ch, &sh, &seed).unwrap();
        assert!(!key_der.is_empty());
        assert_eq!(cert_der[0], 0x30, "cert_der should start with SEQUENCE tag");

        // 标准 REALITY HMAC 尾仍在（两种模板都必须写，Go 同）
        let pub_key = DUMMY_CERT.public_key_raw;
        let hmac_sig = crate::crypto::sign_reality_certificate(&auth_key, &pub_key).unwrap();
        let n = cert_der.len();
        assert_eq!(&cert_der[n - 64..], &hmac_sig, "HMAC tail must be present");

        // 客户端视角：定位扩展 → 重算滚动 HMAC → mldsa65 验签
        let (off, sig_len) =
            crate::util::find_oid_0_0_extension(&cert_der).expect("OID 0.0 extension present");
        assert_eq!(sig_len, crate::crypto::MLDSA65_SIG_LEN);
        let sig = &cert_der[off..off + sig_len];
        let msg = crate::crypto::hmac_reality_message(&auth_key, &pub_key, &ch, &sh).unwrap();
        let pubkey_1952 = crate::crypto::derive_mldsa65_pubkey(&seed).unwrap();
        let ok = crate::crypto::verify_mldsa65_signature(&pubkey_1952, &msg, sig).unwrap();
        assert!(ok, "roundtrip sign→verify must hold");

        // 篡改 ServerHello → 验签失败（签名覆盖 CH‖SH 上下文）
        let sh_bad = [0x23u8; 90];
        let msg_bad =
            crate::crypto::hmac_reality_message(&auth_key, &pub_key, &ch, &sh_bad).unwrap();
        let bad = crate::crypto::verify_mldsa65_signature(&pubkey_1952, &msg_bad, sig).unwrap();
        assert!(!bad, "tampered ServerHello must fail verification");
    }

    /// 变体模板与标准模板同密钥同布局（除扩展外逐字节一致不可期——rcgen
    /// 布局由扩展插入改变——但公钥/HMAC 尾语义必须一致）。
    #[test]
    fn mldsa65_template_shares_key_with_standard() {
        let auth_key = [0x42u8; 32];
        let (std_cert, _) = generate_reality_ed25519_cert(&auth_key).unwrap();
        let (var_cert, var_key) =
            generate_reality_ed25519_cert_mldsa65(&auth_key, &[1u8; 8], &[2u8; 8], &[0x07u8; 32])
                .unwrap();
        let (_, std_key2) = generate_reality_ed25519_cert(&auth_key).unwrap();
        assert_eq!(var_key, std_key2, "both templates use the process-static key");
        assert!(var_cert.len() > std_cert.len(), "variant carries the 3309B extension");
        assert!(
            crate::util::find_oid_0_0_extension(&std_cert).is_none(),
            "standard template must not carry OID 0.0 extension"
        );
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
        let invalid =
            crate::crypto::verify_reality_certificate(&wrong_key, &pub_key, &sig).unwrap();
        assert!(!invalid, "HMAC with wrong key should fail");
    }
}
