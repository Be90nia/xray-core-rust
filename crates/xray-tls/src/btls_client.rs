//! BoringSSL (btls) 后端 uTLS 指纹伪装。
//!
//! 使用 [`btls`]（BoringSSL Rust 绑定）构造真实浏览器 ClientHello 指纹，
//! 替代标准 rustls 的默认指纹（易被 DPI 识别）。
//!
//! - Chrome 131（无 ApplicationSettingsNew，有 ECH）
//! - Chrome 120（类似 Chrome 131，有 ECH）
//! - Chrome 133（含 ALPS / delegated_credentials / record_size_limit）
//! - Firefox 120（双 key share: X25519 + P-256）
//! - Firefox 148
//! - Safari 26.3 (macOS)
//! - iOS 13（Safari-like，单 key share）
//! - iOS 14 / 18.4（Safari-like，双 key share）
//! - Edge 106（Chrome 106 时代 cipher/sigalgs）
//! - Edge 133（复用 Chrome 133 配置）
//! - 360 11.0（Chrome-like，无 ALPS/ECH/delegated_credentials）
//! - QQ 11.1（Chrome-like，有 ALPS，无 ECH/delegated_credentials）
//! 其他指纹将 fallback 到标准 rustls。

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use btls::ssl::{KeyShare, SslConnector, SslMethod};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_btls::SslStream as TokioSslStream;
use tracing::debug;
use xray_transport::connection::Connection;

use crate::fingerprint::Fingerprint;

// ============================================================
// 指纹配置输出：connector + per-connection 参数
// ============================================================

/// 指纹配置：SslConnector + 握手时 per-connection 参数。
///
/// `connector_for_fingerprint()` 返回此结构体，`connect()` 据此配置
/// key shares 和 ALPS 等只能在 `Ssl`（per-connection）上设置的选项。
pub(crate) struct FingerprintConfig {
    pub(crate) connector: SslConnector,
    /// 握手时发送的 key shares。
    pub(crate) key_shares: &'static [KeyShare],
    /// ALPS (Application-Layer Protocol Settings, 0xfe0d) 数据。
    /// Chrome 使用，Firefox/Safari 不使用（传空切片跳过）。
    pub(crate) alps: &'static [u8],
}

// ============================================================
// Chrome 133 指纹配置
// ============================================================

/// Chrome 133 cipher suites（TLS 1.3 + TLS 1.2）。
const CHROME_133_CIPHER_LIST: &str = concat!(
    "TLS_AES_128_GCM_SHA256:",
    "TLS_AES_256_GCM_SHA384:",
    "TLS_CHACHA20_POLY1305_SHA256:",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:",
    "TLS_RSA_WITH_AES_128_GCM_SHA256:",
    "TLS_RSA_WITH_AES_256_GCM_SHA384:",
    "TLS_RSA_WITH_AES_128_CBC_SHA:",
    "TLS_RSA_WITH_AES_256_CBC_SHA:",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
);

/// Chrome 133 signature algorithms。
const CHROME_133_SIGALGS: &str = concat!(
    "ecdsa_secp256r1_sha256:",
    "rsa_pss_rsae_sha256:",
    "rsa_pkcs1_sha256:",
    "ecdsa_secp384r1_sha384:",
    "rsa_pss_rsae_sha384:",
    "rsa_pkcs1_sha384:",
    "rsa_pss_rsae_sha512:",
    "rsa_pkcs1_sha512:",
    "rsa_pkcs1_sha1"
);

/// Chrome 133 supported groups。
/// 诊断：暂时移除 PQ X25519MLKEM768，只用经典曲线。
const CHROME_133_CURVES: &str = "X25519:P-256:P-384";

/// Chrome 133 ALPN。
const CHROME_133_ALPN: &[u8] = b"\x02h2\x08http/1.1";

/// Chrome 133 key shares（仅 X25519，诊断：移除 PQ）。
const CHROME_133_KEY_SHARES: &[KeyShare] = &[
    KeyShare::X25519,
];

/// Chrome 133 ALPS 数据（h2）。
const CHROME_133_ALPS: &[u8] = b"\x02h2";

/// Chrome 133 extension permutation 顺序。
/// 参考 Go uTLS HelloChrome_120 + BoringSSL extension IDs。
fn chrome_133_ext_perm() -> Vec<btls::ssl::ExtensionType> {
    vec![
        btls::ssl::ExtensionType::from(0x0000), // SSL_EXT_tls_supported_versions
        btls::ssl::ExtensionType::from(0x0033), // SSL_EXT_tls_key_share
        btls::ssl::ExtensionType::from(0x0010), // SSL_EXT_tls_alpn
        btls::ssl::ExtensionType::from(0x000d), // SSL_EXT_tls_signature_algorithms
        btls::ssl::ExtensionType::from(0x0038), // SSL_EXT_tls_supported_groups
        btls::ssl::ExtensionType::from(0x0005), // SSL_EXT_tls_status_request
        btls::ssl::ExtensionType::from(0x0012), // SSL_EXT_tls_signed_cert_timestamp
        btls::ssl::ExtensionType::from(0x002b), // SSL_EXT_tls_compress_certificate
        btls::ssl::ExtensionType::from(0x0039), // SSL_EXT_tls_pre_shared_key
        btls::ssl::ExtensionType::from(0x002d), // SSL_EXT_tls_psk_key_exchange_modes
        btls::ssl::ExtensionType::from(0x0017), // SSL_EXT_tls_extended_master_secret
        btls::ssl::ExtensionType::from(0x0023), // SSL_EXT_tls_session_ticket
        btls::ssl::ExtensionType::from(0x000b), // SSL_EXT_tls_ec_point_formats
        btls::ssl::ExtensionType::from(0xff01), // SSL_EXT_tls_renegotiation_info
        btls::ssl::ExtensionType::from(0x001b), // SSL_EXT_tls_record_size_limit
        btls::ssl::ExtensionType::from(0x0015), // SSL_EXT_tls_padding
        btls::ssl::ExtensionType::from(0xfe0d), // SSL_EXT_tls_application_settings
        btls::ssl::ExtensionType::from(0x0044), // SSL_EXT_tls_delegated_credentials
        btls::ssl::ExtensionType::from(0x003a), // SSL_EXT_tls_encrypted_client_hello
    ]
}

/// 构建带 Chrome 133 指纹的 SslConnector。
fn chrome_133_connector() -> io::Result<SslConnector> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| io::Error::other(e.to_string()))?;

    builder
        .set_cipher_list(CHROME_133_CIPHER_LIST)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder
        .set_sigalgs_list(CHROME_133_SIGALGS)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder
        .set_curves_list(CHROME_133_CURVES)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder
        .set_alpn_protos(CHROME_133_ALPN)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder.set_extension_permutation(&chrome_133_ext_perm())
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_record_size_limit(0x4001);
    builder
        .set_delegated_credentials(CHROME_133_SIGALGS)
        .map_err(|e| io::Error::other(e.to_string()))?;
    // PQ key share (X25519MLKEM768) 暂时禁用——BoringSSL 在 server 不支持
    // MLKEM768 时报 'unknown BoringSSL error' 而非 graceful fallback
    // TODO: 等 BoringSSL/CF 上游修复 PQ key share fallback 后再启用

    // 禁用内置 root 验证（xray 自行管理证书验证）
    builder.set_verify(btls::ssl::SslVerifyMode::NONE);

    Ok(builder.build())
}

// ============================================================
// Chrome 131 指纹配置
// ============================================================

/// Chrome 131 cipher suites（与 Chrome 133 相同）。
const CHROME_131_CIPHER_LIST: &str = CHROME_133_CIPHER_LIST;

/// Chrome 131 signature algorithms（与 Chrome 133 相同）。
const CHROME_131_SIGALGS: &str = CHROME_133_SIGALGS;

/// Chrome 131 supported groups（与 Chrome 133 相同，无 PQ）。
const CHROME_131_CURVES: &str = CHROME_133_CURVES;

/// Chrome 131 ALPN（与 Chrome 133 相同）。
const CHROME_131_ALPN: &[u8] = CHROME_133_ALPN;

/// Chrome 131 key shares（仅 X25519，无 PQ）。
const CHROME_131_KEY_SHARES: &[KeyShare] = &[KeyShare::X25519];

/// Chrome 131 ALPS 数据（h2，与 Chrome 133 相同）。
const CHROME_131_ALPS: &[u8] = CHROME_133_ALPS;

/// Chrome 131 extension permutation 顺序。
/// 与 Chrome 133 的差异：无 delegated_credentials (0x0044)，无 record_size_limit (0x001b)。
/// Chrome 131 有 ECH (0x003a) 和 ApplicationSettings (0xfe0d)。
fn chrome_131_ext_perm() -> Vec<btls::ssl::ExtensionType> {
    vec![
        btls::ssl::ExtensionType::from(0x0000), // supported_versions
        btls::ssl::ExtensionType::from(0x0033), // key_share
        btls::ssl::ExtensionType::from(0x0010), // alpn
        btls::ssl::ExtensionType::from(0x000d), // signature_algorithms
        btls::ssl::ExtensionType::from(0x0038), // supported_groups
        btls::ssl::ExtensionType::from(0x0005), // status_request
        btls::ssl::ExtensionType::from(0x0012), // signed_cert_timestamp
        btls::ssl::ExtensionType::from(0x002b), // compress_certificate
        btls::ssl::ExtensionType::from(0x0039), // pre_shared_key
        btls::ssl::ExtensionType::from(0x002d), // psk_key_exchange_modes
        btls::ssl::ExtensionType::from(0x0017), // extended_master_secret
        btls::ssl::ExtensionType::from(0x0023), // session_ticket
        btls::ssl::ExtensionType::from(0x000b), // ec_point_formats
        btls::ssl::ExtensionType::from(0xff01), // renegotiation_info
        btls::ssl::ExtensionType::from(0x0015), // padding
        btls::ssl::ExtensionType::from(0xfe0d), // application_settings
        btls::ssl::ExtensionType::from(0x003a), // encrypted_client_hello
    ]
}

/// 构建带 Chrome 131 指纹的 SslConnector。
/// 与 Chrome 133 的差异：无 record_size_limit，无 delegated_credentials。
fn chrome_131_connector() -> io::Result<SslConnector> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| io::Error::other(e.to_string()))?;

    builder
        .set_cipher_list(CHROME_131_CIPHER_LIST)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder
        .set_sigalgs_list(CHROME_131_SIGALGS)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder
        .set_curves_list(CHROME_131_CURVES)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder
        .set_alpn_protos(CHROME_131_ALPN)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder.set_extension_permutation(&chrome_131_ext_perm())
        .map_err(|e| io::Error::other(e.to_string()))?;
    // Chrome 131 无 record_size_limit / delegated_credentials

    // 禁用内置 root 验证（xray 自行管理证书验证）
    builder.set_verify(btls::ssl::SslVerifyMode::NONE);

    Ok(builder.build())
}

// ============================================================
// Chrome 120 指纹配置
// ============================================================

/// Chrome 120 cipher suites（与 Chrome 133 相同）。
const CHROME_120_CIPHER_LIST: &str = CHROME_133_CIPHER_LIST;

/// Chrome 120 signature algorithms（与 Chrome 133 相同）。
const CHROME_120_SIGALGS: &str = CHROME_133_SIGALGS;

/// Chrome 120 supported groups（与 Chrome 133 相同，无 PQ）。
const CHROME_120_CURVES: &str = CHROME_133_CURVES;

/// Chrome 120 ALPN（与 Chrome 133 相同）。
const CHROME_120_ALPN: &[u8] = CHROME_133_ALPN;

/// Chrome 120 key shares（仅 X25519，无 PQ）。
const CHROME_120_KEY_SHARES: &[KeyShare] = &[KeyShare::X25519];

/// Chrome 120 ALPS 数据（h2，与 Chrome 133 相同）。
const CHROME_120_ALPS: &[u8] = CHROME_133_ALPS;

/// Chrome 120 extension permutation 顺序。
/// 与 Chrome 131 相同：无 record_size_limit，无 delegated_credentials。
/// 有 ECH (0x003a) 和 ApplicationSettings (0xfe0d)。
fn chrome_120_ext_perm() -> Vec<btls::ssl::ExtensionType> {
    chrome_131_ext_perm()
}

/// 构建带 Chrome 120 指纹的 SslConnector。
/// 与 Chrome 131 相同（cipher/sigalgs/ext_perm 一致）。
fn chrome_120_connector() -> io::Result<SslConnector> {
    chrome_131_connector()
}

// ============================================================
// Firefox 148 指纹配置
// ============================================================

/// Firefox 148 cipher suites（仅 BoringSSL 支持的，按原始顺序）。
/// 原始 u16 列表含 Camellia/SEED 等旧 cipher，BoringSSL 不支持，已剔除。
const FIREFOX_148_CIPHER_LIST: &str = concat!(
    "TLS_AES_128_GCM_SHA256:",
    "TLS_AES_256_GCM_SHA384:",
    "TLS_CHACHA20_POLY1305_SHA256:",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:",
    "TLS_RSA_WITH_AES_256_GCM_SHA384:",
    "TLS_RSA_WITH_AES_128_GCM_SHA256:",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA:",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA:",
    "TLS_RSA_WITH_AES_256_CBC_SHA:",
    "TLS_RSA_WITH_AES_128_CBC_SHA:",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
);

/// Firefox 148 signature algorithms。
const FIREFOX_148_SIGALGS: &str = concat!(
    "ecdsa_secp256r1_sha256:",
    "rsa_pss_rsae_sha256:",
    "rsa_pkcs1_sha256:",
    "rsa_pss_rsae_sha384:",
    "rsa_pss_rsae_sha512:",
    "ecdsa_secp384r1_sha384:",
    "rsa_pkcs1_sha384:",
    "ecdsa_secp521r1_sha512:",
    "rsa_pkcs1_sha512:",
    "rsa_pkcs1_sha1:",
    "ecdsa_sha1"
);

/// Firefox 148 supported groups：X25519, P-256, P-384, P-521。
const FIREFOX_148_CURVES: &str = "X25519:P-256:P-384:P-521";

/// Firefox 148 ALPN。
const FIREFOX_148_ALPN: &[u8] = b"\x02h2\x08http/1.1";

/// Firefox 148 key shares（仅 X25519，无 PQ）。
const FIREFOX_148_KEY_SHARES: &[KeyShare] = &[KeyShare::X25519];

/// Firefox 148 不使用 ALPS。
const FIREFOX_148_ALPS: &[u8] = &[];

/// Firefox 148 extension permutation 顺序。
fn firefox_148_ext_perm() -> Vec<btls::ssl::ExtensionType> {
    vec![
        btls::ssl::ExtensionType::from(0x0000), // supported_versions
        btls::ssl::ExtensionType::from(0x001b), // record_size_limit
        btls::ssl::ExtensionType::from(0x0033), // key_share
        btls::ssl::ExtensionType::from(0x002b), // compress_certificate
        btls::ssl::ExtensionType::from(0x000d), // signature_algorithms
        btls::ssl::ExtensionType::from(0x0012), // signed_cert_timestamp
        btls::ssl::ExtensionType::from(0x000b), // ec_point_formats
        btls::ssl::ExtensionType::from(0x0015), // padding
        btls::ssl::ExtensionType::from(0x0017), // extended_master_secret
        btls::ssl::ExtensionType::from(0x0023), // session_ticket
        btls::ssl::ExtensionType::from(0x002d), // psk_key_exchange_modes
        btls::ssl::ExtensionType::from(0x001c), // ALPS (Firefox 也发)
        btls::ssl::ExtensionType::from(0x001d), // ? (0x001d)
        btls::ssl::ExtensionType::from(0x0029), // ? (0x0029)
        btls::ssl::ExtensionType::from(0x002a), // ? (0x002a)
        btls::ssl::ExtensionType::from(0xfe0d), // application_settings
    ]
}

/// 构建带 Firefox 148 指纹的 SslConnector。
fn firefox_148_connector() -> io::Result<SslConnector> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| io::Error::other(e.to_string()))?;

    builder
        .set_cipher_list(FIREFOX_148_CIPHER_LIST)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder
        .set_sigalgs_list(FIREFOX_148_SIGALGS)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder
        .set_curves_list(FIREFOX_148_CURVES)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder
        .set_alpn_protos(FIREFOX_148_ALPN)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder.set_extension_permutation(&firefox_148_ext_perm())
        .map_err(|e| io::Error::other(e.to_string()))?;
    // Firefox 不使用 record_size_limit / delegated_credentials

    // 禁用内置 root 验证（xray 自行管理证书验证）
    builder.set_verify(btls::ssl::SslVerifyMode::NONE);

    Ok(builder.build())
}

// ============================================================
// Firefox 120 指纹配置
// ============================================================

/// Firefox 120 cipher suites（与 Firefox 148 相同）。
const FIREFOX_120_CIPHER_LIST: &str = FIREFOX_148_CIPHER_LIST;

/// Firefox 120 signature algorithms（与 Firefox 148 相同）。
const FIREFOX_120_SIGALGS: &str = FIREFOX_148_SIGALGS;

/// Firefox 120 supported groups（与 Firefox 148 相同）。
const FIREFOX_120_CURVES: &str = FIREFOX_148_CURVES;

/// Firefox 120 ALPN（与 Firefox 148 相同）。
const FIREFOX_120_ALPN: &[u8] = FIREFOX_148_ALPN;

/// Firefox 120 key shares（X25519 + P-256 双 key share，Firefox 120+ 特性）。
const FIREFOX_120_KEY_SHARES: &[KeyShare] = &[KeyShare::X25519, KeyShare::P256];

/// Firefox 120 不使用 ALPS。
const FIREFOX_120_ALPS: &[u8] = &[];

/// Firefox 120 extension permutation 顺序（与 Firefox 148 相同）。
fn firefox_120_ext_perm() -> Vec<btls::ssl::ExtensionType> {
    firefox_148_ext_perm()
}

/// 构建带 Firefox 120 指纹的 SslConnector。
/// 与 Firefox 148 的差异：双 key share (X25519 + P-256)。
/// cipher/sigalgs/curves/ext_perm 相同。
fn firefox_120_connector() -> io::Result<SslConnector> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| io::Error::other(e.to_string()))?;

    builder
        .set_cipher_list(FIREFOX_120_CIPHER_LIST)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder
        .set_sigalgs_list(FIREFOX_120_SIGALGS)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder
        .set_curves_list(FIREFOX_120_CURVES)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder
        .set_alpn_protos(FIREFOX_120_ALPN)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder.set_extension_permutation(&firefox_120_ext_perm())
        .map_err(|e| io::Error::other(e.to_string()))?;
    // Firefox 不使用 record_size_limit / delegated_credentials

    // 禁用内置 root 验证（xray 自行管理证书验证）
    builder.set_verify(btls::ssl::SslVerifyMode::NONE);

    Ok(builder.build())
}

// ============================================================
// Safari 26.3 指纹配置
// ============================================================

/// Safari 26.3 cipher suites（仅 BoringSSL 支持的，按原始顺序）。
const SAFARI_26_3_CIPHER_LIST: &str = concat!(
    "TLS_AES_128_GCM_SHA256:",
    "TLS_AES_256_GCM_SHA384:",
    "TLS_CHACHA20_POLY1305_SHA256:",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:",
    "TLS_RSA_WITH_AES_256_GCM_SHA384:",
    "TLS_RSA_WITH_AES_128_GCM_SHA256:",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA:",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA:",
    "TLS_RSA_WITH_AES_256_CBC_SHA:",
    "TLS_RSA_WITH_AES_128_CBC_SHA:",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
);

/// Safari 26.3 signature algorithms。
/// 与 Firefox 148 相同，额外包含 ed25519/ed448 系列。
const SAFARI_26_3_SIGALGS: &str = concat!(
    "ecdsa_secp256r1_sha256:",
    "rsa_pss_rsae_sha256:",
    "rsa_pkcs1_sha256:",
    "rsa_pss_rsae_sha384:",
    "rsa_pss_rsae_sha512:",
    "ecdsa_secp384r1_sha384:",
    "rsa_pkcs1_sha384:",
    "ecdsa_secp521r1_sha512:",
    "rsa_pkcs1_sha512:",
    "rsa_pkcs1_sha1:",
    "ecdsa_sha1:",
    "ed25519:",
    "rsa_pss_pss_sha256:",
    "rsa_pss_pss_sha384:",
    "rsa_pss_pss_sha512:",
    "ed448"
);

/// Safari 26.3 supported groups：X25519, P-256, P-384, P-521。
const SAFARI_26_3_CURVES: &str = "X25519:P-256:P-384:P-521";

/// Safari 26.3 ALPN。
const SAFARI_26_3_ALPN: &[u8] = b"\x02h2\x08http/1.1";

/// Safari 26.3 key shares（仅 X25519）。
const SAFARI_26_3_KEY_SHARES: &[KeyShare] = &[KeyShare::X25519];

/// Safari 26.3 不使用 ALPS。
const SAFARI_26_3_ALPS: &[u8] = &[];

/// Safari 26.3 extension permutation 顺序（与 Firefox 148 相同）。
fn safari_26_3_ext_perm() -> Vec<btls::ssl::ExtensionType> {
    firefox_148_ext_perm()
}

/// 构建带 Safari 26.3 指纹的 SslConnector。
fn safari_26_3_connector() -> io::Result<SslConnector> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| io::Error::other(e.to_string()))?;

    builder
        .set_cipher_list(SAFARI_26_3_CIPHER_LIST)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder
        .set_sigalgs_list(SAFARI_26_3_SIGALGS)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder
        .set_curves_list(SAFARI_26_3_CURVES)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder
        .set_alpn_protos(SAFARI_26_3_ALPN)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder.set_extension_permutation(&safari_26_3_ext_perm())
        .map_err(|e| io::Error::other(e.to_string()))?;
    // Safari 不使用 record_size_limit / delegated_credentials

    // 禁用内置 root 验证（xray 自行管理证书验证）
    builder.set_verify(btls::ssl::SslVerifyMode::NONE);

    Ok(builder.build())
}

// ============================================================
// iOS 18.4 指纹配置
// ============================================================

/// iOS 18.4 key shares（X25519 + P-256，与 Safari 不同）。
const IOS_18_4_KEY_SHARES: &[KeyShare] = &[KeyShare::X25519, KeyShare::P256];

/// iOS 18.4 不使用 ALPS。
const IOS_18_4_ALPS: &[u8] = &[];

// iOS 18.4 复用 Safari 26.3 的 connector（cipher/sigalgs/curves/ALPN/ext_perm 相同），
// 仅 key shares 不同（双 key share: X25519 + P-256）。

// ============================================================
// iOS 13 指纹配置
// ============================================================

/// iOS 13 key shares（仅 X25519，与 Safari 相同）。
const IOS_13_KEY_SHARES: &[KeyShare] = &[KeyShare::X25519];

/// iOS 13 不使用 ALPS。
const IOS_13_ALPS: &[u8] = &[];

// iOS 13 复用 Safari 26.3 的 connector（cipher/sigalgs/curves/ALPN/ext_perm 相同），
// 仅 key shares 不同（单 key share: X25519）。

// ============================================================
// iOS 14 指纹配置
// ============================================================

/// iOS 14 key shares（X25519 + P-256，与 iOS 18.4 相同）。
const IOS_14_KEY_SHARES: &[KeyShare] = &[KeyShare::X25519, KeyShare::P256];

/// iOS 14 不使用 ALPS。
const IOS_14_ALPS: &[u8] = &[];

// iOS 14 复用 Safari 26.3 的 connector（与 iOS 18.4 相同），
// 双 key share: X25519 + P-256。

// ============================================================
// Edge 106 指纹配置
// ============================================================

/// Edge 106 cipher suites（Chrome 106 时代，与 Chrome 133 相同）。
const EDGE_106_CIPHER_LIST: &str = CHROME_133_CIPHER_LIST;

/// Edge 106 signature algorithms（Chrome 106 时代，与 Chrome 133 相同）。
const EDGE_106_SIGALGS: &str = CHROME_133_SIGALGS;

/// Edge 106 supported groups（与 Chrome 133 相同，无 PQ）。
const EDGE_106_CURVES: &str = CHROME_133_CURVES;

/// Edge 106 ALPN（与 Chrome 133 相同）。
const EDGE_106_ALPN: &[u8] = CHROME_133_ALPN;

/// Edge 106 key shares（仅 X25519，无 PQ）。
const EDGE_106_KEY_SHARES: &[KeyShare] = &[KeyShare::X25519];

/// Edge 106 ALPS 数据（h2，与 Chrome 133 相同）。
const EDGE_106_ALPS: &[u8] = CHROME_133_ALPS;

/// Edge 106 extension permutation 顺序。
/// Chrome 106 时代：无 record_size_limit，无 delegated_credentials，无 ECH。
/// 有 ApplicationSettings (0xfe0d)。
fn edge_106_ext_perm() -> Vec<btls::ssl::ExtensionType> {
    vec![
        btls::ssl::ExtensionType::from(0x0000), // supported_versions
        btls::ssl::ExtensionType::from(0x0033), // key_share
        btls::ssl::ExtensionType::from(0x0010), // alpn
        btls::ssl::ExtensionType::from(0x000d), // signature_algorithms
        btls::ssl::ExtensionType::from(0x0038), // supported_groups
        btls::ssl::ExtensionType::from(0x0005), // status_request
        btls::ssl::ExtensionType::from(0x0012), // signed_cert_timestamp
        btls::ssl::ExtensionType::from(0x002b), // compress_certificate
        btls::ssl::ExtensionType::from(0x0039), // pre_shared_key
        btls::ssl::ExtensionType::from(0x002d), // psk_key_exchange_modes
        btls::ssl::ExtensionType::from(0x0017), // extended_master_secret
        btls::ssl::ExtensionType::from(0x0023), // session_ticket
        btls::ssl::ExtensionType::from(0x000b), // ec_point_formats
        btls::ssl::ExtensionType::from(0xff01), // renegotiation_info
        btls::ssl::ExtensionType::from(0x0015), // padding
        btls::ssl::ExtensionType::from(0xfe0d), // application_settings
    ]
}

/// 构建带 Edge 106 指纹的 SslConnector。
/// Chrome 106 时代：无 record_size_limit，无 delegated_credentials，无 ECH。
fn edge_106_connector() -> io::Result<SslConnector> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| io::Error::other(e.to_string()))?;

    builder
        .set_cipher_list(EDGE_106_CIPHER_LIST)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder
        .set_sigalgs_list(EDGE_106_SIGALGS)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder
        .set_curves_list(EDGE_106_CURVES)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder
        .set_alpn_protos(EDGE_106_ALPN)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder.set_extension_permutation(&edge_106_ext_perm())
        .map_err(|e| io::Error::other(e.to_string()))?;
    // Edge 106 无 record_size_limit / delegated_credentials / ECH

    // 禁用内置 root 验证（xray 自行管理证书验证）
    builder.set_verify(btls::ssl::SslVerifyMode::NONE);

    Ok(builder.build())
}

// ============================================================
// 360 11.0 指纹配置
// ============================================================

/// 360 11.0 cipher suites（与 Chrome 133 相同，含 3DES）。
const QIHOO_360_11_0_CIPHER_LIST: &str = CHROME_133_CIPHER_LIST;

/// 360 11.0 signature algorithms（与 Chrome 133 相同，含 SHA1）。
const QIHOO_360_11_0_SIGALGS: &str = CHROME_133_SIGALGS;

/// 360 11.0 supported groups（X25519, P-256, P-384，无 PQ）。
const QIHOO_360_11_0_CURVES: &str = "X25519:P-256:P-384";

/// 360 11.0 ALPN（h2, http/1.1）。
const QIHOO_360_11_0_ALPN: &[u8] = b"\x02h2\x08http/1.1";

/// 360 11.0 key shares（仅 X25519）。
const QIHOO_360_11_0_KEY_SHARES: &[KeyShare] = &[KeyShare::X25519];

/// 360 11.0 不使用 ALPS。
const QIHOO_360_11_0_ALPS: &[u8] = &[];

/// 360 11.0 extension permutation 顺序。
/// Chrome-like 但无 ALPS/ECH/delegated_credentials/record_size_limit。
/// 有 ChannelID (0x754f) 和 CompressCert (Brotli only)。
fn qihoo_360_11_0_ext_perm() -> Vec<btls::ssl::ExtensionType> {
    vec![
        btls::ssl::ExtensionType::from(0x0000), // supported_versions
        btls::ssl::ExtensionType::from(0x0033), // key_share
        btls::ssl::ExtensionType::from(0x0010), // alpn
        btls::ssl::ExtensionType::from(0x000d), // signature_algorithms
        btls::ssl::ExtensionType::from(0x0038), // supported_groups
        btls::ssl::ExtensionType::from(0x0005), // status_request
        btls::ssl::ExtensionType::from(0x0012), // signed_cert_timestamp
        btls::ssl::ExtensionType::from(0x002b), // compress_certificate
        btls::ssl::ExtensionType::from(0x0039), // pre_shared_key
        btls::ssl::ExtensionType::from(0x002d), // psk_key_exchange_modes
        btls::ssl::ExtensionType::from(0x0017), // extended_master_secret
        btls::ssl::ExtensionType::from(0x0023), // session_ticket
        btls::ssl::ExtensionType::from(0x000b), // ec_point_formats
        btls::ssl::ExtensionType::from(0xff01), // renegotiation_info
        btls::ssl::ExtensionType::from(0x0015), // padding
    ]
}

/// 构建带 360 11.0 指纹的 SslConnector。
/// Chrome-like 但无 ALPS/ECH/delegated_credentials/record_size_limit。
fn qihoo_360_11_0_connector() -> io::Result<SslConnector> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| io::Error::other(e.to_string()))?;

    builder
        .set_cipher_list(QIHOO_360_11_0_CIPHER_LIST)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder
        .set_sigalgs_list(QIHOO_360_11_0_SIGALGS)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder
        .set_curves_list(QIHOO_360_11_0_CURVES)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder
        .set_alpn_protos(QIHOO_360_11_0_ALPN)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder.set_extension_permutation(&qihoo_360_11_0_ext_perm())
        .map_err(|e| io::Error::other(e.to_string()))?;
    // 360 无 record_size_limit / delegated_credentials / ECH / ALPS

    // 禁用内置 root 验证（xray 自行管理证书验证）
    builder.set_verify(btls::ssl::SslVerifyMode::NONE);

    Ok(builder.build())
}

// ============================================================
// QQ 11.1 指纹配置
// ============================================================

/// QQ 11.1 cipher suites（与 Chrome 133 相同但无 3DES）。
const QQ_11_1_CIPHER_LIST: &str = concat!(
    "TLS_AES_128_GCM_SHA256:",
    "TLS_AES_256_GCM_SHA384:",
    "TLS_CHACHA20_POLY1305_SHA256:",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:",
    "TLS_RSA_WITH_AES_128_GCM_SHA256:",
    "TLS_RSA_WITH_AES_256_GCM_SHA384:",
    "TLS_RSA_WITH_AES_128_CBC_SHA:",
    "TLS_RSA_WITH_AES_256_CBC_SHA"
);

/// QQ 11.1 signature algorithms（与 Chrome 133 相同但无 SHA1）。
const QQ_11_1_SIGALGS: &str = concat!(
    "ecdsa_secp256r1_sha256:",
    "rsa_pss_rsae_sha256:",
    "rsa_pkcs1_sha256:",
    "ecdsa_secp384r1_sha384:",
    "rsa_pss_rsae_sha384:",
    "rsa_pkcs1_sha384:",
    "rsa_pss_rsae_sha512:",
    "rsa_pkcs1_sha512"
);

/// QQ 11.1 supported groups（X25519, P-256, P-384）。
const QQ_11_1_CURVES: &str = "X25519:P-256:P-384";

/// QQ 11.1 ALPN（h2, http/1.1）。
const QQ_11_1_ALPN: &[u8] = b"\x02h2\x08http/1.1";

/// QQ 11.1 key shares（仅 X25519）。
const QQ_11_1_KEY_SHARES: &[KeyShare] = &[KeyShare::X25519];

/// QQ 11.1 ALPS 数据（h2）。
const QQ_11_1_ALPS: &[u8] = b"\x02h2";

/// QQ 11.1 extension permutation 顺序。
/// Chrome-like，有 ApplicationSettings (0xfe0d)，无 ECH/delegated_credentials/record_size_limit。
fn qq_11_1_ext_perm() -> Vec<btls::ssl::ExtensionType> {
    vec![
        btls::ssl::ExtensionType::from(0x0000), // supported_versions
        btls::ssl::ExtensionType::from(0x0033), // key_share
        btls::ssl::ExtensionType::from(0x0010), // alpn
        btls::ssl::ExtensionType::from(0x000d), // signature_algorithms
        btls::ssl::ExtensionType::from(0x0038), // supported_groups
        btls::ssl::ExtensionType::from(0x0005), // status_request
        btls::ssl::ExtensionType::from(0x0012), // signed_cert_timestamp
        btls::ssl::ExtensionType::from(0x002b), // compress_certificate
        btls::ssl::ExtensionType::from(0x0039), // pre_shared_key
        btls::ssl::ExtensionType::from(0x002d), // psk_key_exchange_modes
        btls::ssl::ExtensionType::from(0x0017), // extended_master_secret
        btls::ssl::ExtensionType::from(0x0023), // session_ticket
        btls::ssl::ExtensionType::from(0x000b), // ec_point_formats
        btls::ssl::ExtensionType::from(0xff01), // renegotiation_info
        btls::ssl::ExtensionType::from(0x0015), // padding
        btls::ssl::ExtensionType::from(0xfe0d), // application_settings
    ]
}

/// 构建带 QQ 11.1 指纹的 SslConnector。
/// Chrome-like，有 ALPS，无 ECH/delegated_credentials/record_size_limit。
fn qq_11_1_connector() -> io::Result<SslConnector> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|e| io::Error::other(e.to_string()))?;

    builder
        .set_cipher_list(QQ_11_1_CIPHER_LIST)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder
        .set_sigalgs_list(QQ_11_1_SIGALGS)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder
        .set_curves_list(QQ_11_1_CURVES)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder
        .set_alpn_protos(QQ_11_1_ALPN)
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder.set_extension_permutation(&qq_11_1_ext_perm())
        .map_err(|e| io::Error::other(e.to_string()))?;
    // QQ 无 record_size_limit / delegated_credentials / ECH

    // 禁用内置 root 验证（xray 自行管理证书验证）
    builder.set_verify(btls::ssl::SslVerifyMode::NONE);

    Ok(builder.build())
}
/// 根据指纹选择 btls 连接器。返回 `None` 表示该指纹不支持 btls（fallback rustls）。
pub(crate) fn connector_for_fingerprint(fp: &Fingerprint) -> Option<io::Result<FingerprintConfig>> {
    match fp {
        Fingerprint::Chrome | Fingerprint::HelloChrome133 => {
            Some(chrome_133_connector().map(|c| FingerprintConfig {
                connector: c,
                key_shares: CHROME_133_KEY_SHARES,
                alps: CHROME_133_ALPS,
            }))
        }
        Fingerprint::HelloChrome131 => {
            Some(chrome_131_connector().map(|c| FingerprintConfig {
                connector: c,
                key_shares: CHROME_131_KEY_SHARES,
                alps: CHROME_131_ALPS,
            }))
        }
        Fingerprint::HelloChrome120 => {
            Some(chrome_120_connector().map(|c| FingerprintConfig {
                connector: c,
                key_shares: CHROME_120_KEY_SHARES,
                alps: CHROME_120_ALPS,
            }))
        }
        Fingerprint::Firefox | Fingerprint::HelloFirefox148 => {
            Some(firefox_148_connector().map(|c| FingerprintConfig {
                connector: c,
                key_shares: FIREFOX_148_KEY_SHARES,
                alps: FIREFOX_148_ALPS,
            }))
        }
        Fingerprint::HelloFirefox120 => {
            Some(firefox_120_connector().map(|c| FingerprintConfig {
                connector: c,
                key_shares: FIREFOX_120_KEY_SHARES,
                alps: FIREFOX_120_ALPS,
            }))
        }
        Fingerprint::Safari | Fingerprint::HelloSafari26_3 => {
            Some(safari_26_3_connector().map(|c| FingerprintConfig {
                connector: c,
                key_shares: SAFARI_26_3_KEY_SHARES,
                alps: SAFARI_26_3_ALPS,
            }))
        }
        Fingerprint::HelloIos13 => {
            Some(safari_26_3_connector().map(|c| FingerprintConfig {
                connector: c,
                key_shares: IOS_13_KEY_SHARES,
                alps: IOS_13_ALPS,
            }))
        }
        Fingerprint::Ios | Fingerprint::HelloIos14 => {
            Some(safari_26_3_connector().map(|c| FingerprintConfig {
                connector: c,
                key_shares: IOS_14_KEY_SHARES,
                alps: IOS_14_ALPS,
            }))
        }
        Fingerprint::Edge | Fingerprint::HelloEdge106 => {
            Some(edge_106_connector().map(|c| FingerprintConfig {
                connector: c,
                key_shares: EDGE_106_KEY_SHARES,
                alps: EDGE_106_ALPS,
            }))
        }
        Fingerprint::Hello360_11_0 => {
            Some(qihoo_360_11_0_connector().map(|c| FingerprintConfig {
                connector: c,
                key_shares: QIHOO_360_11_0_KEY_SHARES,
                alps: QIHOO_360_11_0_ALPS,
            }))
        }
        Fingerprint::HelloQq_11_1 => {
            Some(qq_11_1_connector().map(|c| FingerprintConfig {
                connector: c,
                key_shares: QQ_11_1_KEY_SHARES,
                alps: QQ_11_1_ALPS,
            }))
        }
        _ => None,
    }
}

// ============================================================
// BtlsConn 包装
// ============================================================

/// btls (BoringSSL) 后端 uTLS 连接。
///
/// 包装 `tokio_btls::SslStream<S>`，实现 xray-tls 的 ConnInterface。
pub struct BtlsConn<S> {
    stream: Pin<Box<TokioSslStream<S>>>,
    /// 用户期望的指纹。
    pub fingerprint: Fingerprint,
    /// 握手时指定的 server_name。
    server_name: String,
}

impl<S: Connection + Unpin> BtlsConn<S> {
    /// 创建 btls uTLS 连接（完成握手）。
    ///
    /// 步骤：构建 connector → 配置指纹 → 创建 SslStream → 异步握手。
    pub async fn connect(
        stream: S,
        server_name: &str,
        fingerprint: Fingerprint,
    ) -> io::Result<Self> {
        let fp_config = connector_for_fingerprint(&fingerprint)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "fingerprint not supported by btls"))?
            .map_err(|e| io::Error::other(e.to_string()))?;

        let mut cfg = fp_config.connector
            .configure()
            .map_err(|e| io::Error::other(e.to_string()))?;
        cfg.set_verify_hostname(false);

        let mut ssl = cfg
            .into_ssl(server_name)
            .map_err(|e| io::Error::other(e.to_string()))?;

        // per-connection 配置：key shares 和 ALPS 按指纹不同
        ssl.set_client_key_shares(fp_config.key_shares)
            .map_err(|e| io::Error::other(e.to_string()))?;
        if !fp_config.alps.is_empty() {
            ssl.add_application_settings(fp_config.alps)
                .map_err(|e| io::Error::other(e.to_string()))?;
        }
        debug!(
            target: "xray_tls::btls",
            fingerprint = ?fingerprint,
            server_name,
            "btls uTLS 握手开始"
        );

        let tls_stream = TokioSslStream::new(ssl, stream)
            .map_err(|e| io::Error::other(e.to_string()))?;

        // 异步握手（tokio_btls SslStream::connect 需要 Pin<&mut Self>）
        let mut pinned = Box::pin(tls_stream);
        pinned.as_mut().connect().await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, e.to_string()))?;

        debug!(
            target: "xray_tls::btls",
            fingerprint = ?fingerprint,
            server_name,
            "btls uTLS 握手完成"
        );

        Ok(Self {
            stream: pinned,
            fingerprint,
            server_name: server_name.to_string(),
        })
    }
}

impl<S: Connection + Unpin> AsyncRead for BtlsConn<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.stream.as_mut().poll_read(cx, buf)
    }
}

impl<S: Connection + Unpin> AsyncWrite for BtlsConn<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.stream.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream.as_mut().poll_shutdown(cx)
    }
}

impl<S: Connection + Unpin> Connection for BtlsConn<S> {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        // btls SslStream 不暴露底层流，需通过 SslRef 获取
        // 暂时返回 None（不影响核心功能，Connection trait 允许）
        Ok(None)
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
}

use crate::ConnInterface;

impl<S: Connection + Unpin> ConnInterface for BtlsConn<S> {
    fn handshake<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        // btls 握手在 connect() 中已完成
        Box::pin(async { Ok(()) })
    }

    fn verify_hostname<'a>(
        &'a self,
        _host: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        // btls 已在 cert verifier 中处理（或禁用验证时跳过）
        Box::pin(async { Ok(()) })
    }

    fn handshake_server_name<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = String> + Send + 'a>> {
        let name = self.server_name.clone();
        Box::pin(async move { name })
    }

    fn negotiated_protocol<'a>(&'a self) -> Pin<Box<dyn Future<Output = String> + Send + 'a>> {
        let proto = self
            .stream
            .ssl()
            .selected_alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).to_string())
            .unwrap_or_default();
        Box::pin(async move { proto })
    }
}
