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
//!
//! 清单外指纹返回 `InvalidData` 硬错（不再静默回退标准 rustls）：配置了
//! 指纹说明用户在意 ClientHello 伪装，静默降级等于伪装失效。

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
    // ponytail (REALITY): Go REALITY 服务端证书/CertificateVerify 用 Ed25519
    // (0x0807),真实 Chrome 不发送该算法但 Go utls Chrome 指纹接受 —— 必须加。
    "ed25519:",
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

/// Chrome 133 supported groups（PQ X25519MLKEM768 优先）。
/// Chrome 133+ 默认发送 PQ key share，组顺序：PQ → classic。
const CHROME_133_CURVES: &str = "X25519MLKEM768:X25519:P-256:P-384";

/// Chrome 133 ALPN。
const CHROME_133_ALPN: &[u8] = b"\x02h2\x08http/1.1";

/// Chrome 133 key shares（PQ X25519MLKEM768 + X25519）。
/// 对应 Chrome 133 ClientHello 的 key_share 扩展。
/// ponytail: 加回 X25519_MLKEM768 key_share entry（之前只发 X25519 导致服务端选
/// MLKEM768 时 key_share 为空 → 断连；Go uTLS Chrome 133 双发 GREASE + MLKEM768 + X25519，
/// 与之对齐。REALITY 兼容问题此前测试时 VPS 端未严格选 MLKEM768 所以未暴露，
/// 现在补回真 MLKEM768 key share 后 server 选 X25519 仍工作（xtls/reality 容忍）。
const CHROME_133_KEY_SHARES: &[KeyShare] = &[KeyShare::X25519_MLKEM768, KeyShare::X25519];

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
    chrome_133_connector_alpn(CHROME_133_ALPN)
}

/// Chrome 133 无 ALPN 变体：uTLS `HelloRandomizedNoALPN` 的就近映射底座
/// （ALPS 依赖 ALPN 协商，无 ALPN 时由调用方一并置空）。
fn chrome_133_connector_no_alpn() -> io::Result<SslConnector> {
    chrome_133_connector_alpn(b"")
}

fn chrome_133_connector_alpn(alpn: &'static [u8]) -> io::Result<SslConnector> {
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
    if !alpn.is_empty() {
        builder
            .set_alpn_protos(alpn)
            .map_err(|e| io::Error::other(e.to_string()))?;
    }
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder.set_extension_permutation(&chrome_133_ext_perm())
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_record_size_limit(0x4001);
    builder
        .set_delegated_credentials(CHROME_133_SIGALGS)
        .map_err(|e| io::Error::other(e.to_string()))?;
    // PQ key share (X25519MLKEM768) 通过 set_curves_list 中的组顺序自动生成。
    // Chrome 133+ 将 PQ 组排在首位以启用 post-quantum TLS.

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

/// Chrome 131 key shares（PQ X25519MLKEM768 + X25519，与 Chrome 133 一致）。
const CHROME_131_KEY_SHARES: &[KeyShare] = &[KeyShare::X25519_MLKEM768, KeyShare::X25519];

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
#[cfg(test)]
const CHROME_120_CIPHER_LIST: &str = CHROME_133_CIPHER_LIST;

/// Chrome 120 signature algorithms（与 Chrome 133 相同）。
#[cfg(test)]
const CHROME_120_SIGALGS: &str = CHROME_133_SIGALGS;

/// Chrome 120 supported groups（无 PQ，MLKEM768 是 Chrome 131+ 特性）。
#[cfg(test)]
const CHROME_120_CURVES: &str = "X25519:P-256:P-384";

/// Chrome 120 ALPN（与 Chrome 133 相同）。
#[cfg(test)]
const CHROME_120_ALPN: &[u8] = CHROME_133_ALPN;

/// Chrome 120 key shares（仅 X25519，无 PQ）。
const CHROME_120_KEY_SHARES: &[KeyShare] = &[KeyShare::X25519];

/// Chrome 120 ALPS 数据（h2，与 Chrome 133 相同）。
const CHROME_120_ALPS: &[u8] = CHROME_133_ALPS;

/// Chrome 120 extension permutation 顺序。
/// 与 Chrome 131 相同：无 record_size_limit，无 delegated_credentials。
/// 有 ECH (0x003a) 和 ApplicationSettings (0xfe0d)。
#[cfg(test)]
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
    "ed25519"
    // BoringSSL 不支持: rsa_pkcs1_sha1, ecdsa_sha1, ed448, rsa_pss_pss_*
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
#[cfg(test)]
const IOS_18_4_KEY_SHARES: &[KeyShare] = &[KeyShare::X25519, KeyShare::P256];

/// iOS 18.4 不使用 ALPS。
#[cfg(test)]
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
/// 根据指纹选择 btls 连接器。
///
/// 返回 `Some(Ok(config))` = btls 支持；`Some(Err(_))` = 清单外指纹（硬错
/// `InvalidData`，不再静默回退标准 rustls）；函数不再返回 `None`。
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
        Fingerprint::Qihoo360 | Fingerprint::Hello360_11_0 => {
            Some(qihoo_360_11_0_connector().map(|c| FingerprintConfig {
                connector: c,
                key_shares: QIHOO_360_11_0_KEY_SHARES,
                alps: QIHOO_360_11_0_ALPS,
            }))
        }
        Fingerprint::Qq | Fingerprint::HelloQq_11_1 => {
            Some(qq_11_1_connector().map(|c| FingerprintConfig {
                connector: c,
                key_shares: QQ_11_1_KEY_SHARES,
                alps: QQ_11_1_ALPS,
            }))
        }
        // Old Chrome variants → Chrome 120 (oldest implemented)
        Fingerprint::HelloChromeAuto | Fingerprint::HelloChrome58 | Fingerprint::HelloChrome62
        | Fingerprint::HelloChrome70 | Fingerprint::HelloChrome72 | Fingerprint::HelloChrome83
        | Fingerprint::HelloChrome87 | Fingerprint::HelloChrome96 | Fingerprint::HelloChrome100
        | Fingerprint::HelloChrome102 | Fingerprint::HelloChrome106Shuffle
        | Fingerprint::HelloChrome100Psk | Fingerprint::HelloChrome112PskShuf
        | Fingerprint::HelloChrome114PaddingPskShuf | Fingerprint::HelloChrome115Pq
        | Fingerprint::HelloChrome115PqPsk | Fingerprint::HelloChrome120Pq => {
            tracing::warn!(target: "xray_tls::fingerprint", "old Chrome fingerprint {:?} falling back to Chrome 120", fp);
            Some(chrome_120_connector().map(|c| FingerprintConfig {
                connector: c, key_shares: CHROME_120_KEY_SHARES, alps: CHROME_120_ALPS,
            }))
        }
        // Old Firefox variants → Firefox 120
        Fingerprint::HelloFirefoxAuto | Fingerprint::HelloFirefox55 | Fingerprint::HelloFirefox56
        | Fingerprint::HelloFirefox63 | Fingerprint::HelloFirefox65 | Fingerprint::HelloFirefox99
        | Fingerprint::HelloFirefox102 | Fingerprint::HelloFirefox105 => {
            tracing::warn!(target: "xray_tls::fingerprint", "old Firefox fingerprint {:?} falling back to Firefox 120", fp);
            Some(firefox_120_connector().map(|c| FingerprintConfig {
                connector: c, key_shares: FIREFOX_120_KEY_SHARES, alps: FIREFOX_120_ALPS,
            }))
        }
        // Old iOS/Safari variants → iOS 13
        Fingerprint::HelloIosAuto | Fingerprint::HelloIos11_1 | Fingerprint::HelloIos12_1
        | Fingerprint::HelloSafari16_0 | Fingerprint::HelloSafariAuto => {
            tracing::warn!(target: "xray_tls::fingerprint", "old iOS/Safari fingerprint {:?} falling back to Safari 26.3", fp);
            Some(safari_26_3_connector().map(|c| FingerprintConfig {
                connector: c, key_shares: IOS_13_KEY_SHARES, alps: IOS_13_ALPS,
            }))
        }
        // Old Edge variants → Edge 106
        Fingerprint::HelloEdge85 | Fingerprint::HelloEdgeAuto => {
            tracing::warn!(target: "xray_tls::fingerprint", "old Edge fingerprint {:?} falling back to Edge 106", fp);
            Some(edge_106_connector().map(|c| FingerprintConfig {
                connector: c, key_shares: EDGE_106_KEY_SHARES, alps: EDGE_106_ALPS,
            }))
        }
        // Old 360/QQ variants → existing
        Fingerprint::Hello360Auto | Fingerprint::Hello360_7_5 => {
            tracing::warn!(target: "xray_tls::fingerprint", "old 360 fingerprint {:?} falling back to 360 11.0", fp);
            Some(qihoo_360_11_0_connector().map(|c| FingerprintConfig {
                connector: c, key_shares: QIHOO_360_11_0_KEY_SHARES, alps: QIHOO_360_11_0_ALPS,
            }))
        }
        Fingerprint::HelloQqAuto => {
            tracing::warn!(target: "xray_tls::fingerprint", "old QQ fingerprint {:?} falling back to QQ 11.1", fp);
            Some(qq_11_1_connector().map(|c| FingerprintConfig {
                connector: c, key_shares: QQ_11_1_KEY_SHARES, alps: QQ_11_1_ALPS,
            }))
        }
        // Android → Chrome (Android WebView ≈ Chrome)
        Fingerprint::Android | Fingerprint::HelloAndroid11OkHttp => {
            tracing::warn!(target: "xray_tls::fingerprint", "Android fingerprint {:?} falling back to Chrome 133", fp);
            Some(chrome_133_connector().map(|c| FingerprintConfig {
                connector: c, key_shares: CHROME_133_KEY_SHARES, alps: CHROME_133_ALPS,
            }))
        }
        // Golang → Chrome 120 (Go stdlib has no uTLS fingerprint)
        Fingerprint::HelloGolang => {
            tracing::warn!(target: "xray_tls::fingerprint", "Golang fingerprint falling back to Chrome 120");
            Some(chrome_120_connector().map(|c| FingerprintConfig {
                connector: c, key_shares: CHROME_120_KEY_SHARES, alps: CHROME_120_ALPS,
            }))
        }
        // Random → Chrome 133 (most common modern browser)
        Fingerprint::Random | Fingerprint::Randomized | Fingerprint::HelloRandomized
        | Fingerprint::HelloRandomizedAlpn => {
            tracing::debug!(target: "xray_tls::fingerprint", "Random fingerprint → Chrome 133");
            Some(chrome_133_connector().map(|c| FingerprintConfig {
                connector: c, key_shares: CHROME_133_KEY_SHARES, alps: CHROME_133_ALPS,
            }))
        }
        // RandomizedNoALPN：uTLS 随机化指纹的无 ALPN 变体。btls 无法复刻
        // uTLS 的 cipher/扩展顺序随机化，就近映射到无 ALPN 的 Chrome 133
        // 配置（ALPS 依赖 ALPN 协商，随之一并置空）。
        Fingerprint::RandomizedNoAlpn | Fingerprint::HelloRandomizedNoAlpn => {
            Some(chrome_133_connector_no_alpn().map(|c| FingerprintConfig {
                connector: c,
                key_shares: CHROME_133_KEY_SHARES,
                alps: b"",
            }))
        }
        // UniformRandom：uTLS 均匀权重随机化（Go xray 未收录该预设名，Rust
        // 端按 uTLS 库补全）。btls 无逐字段均匀随机化能力，就近映射 Chrome 133。
        Fingerprint::UniformRandom => {
            Some(chrome_133_connector().map(|c| FingerprintConfig {
                connector: c, key_shares: CHROME_133_KEY_SHARES, alps: CHROME_133_ALPS,
            }))
        }
        // 清单外指纹：硬错 InvalidData。配置了指纹说明用户在意 ClientHello
        // 伪装，静默回退标准 rustls 等于伪装失效（批3 裁决：显式失败）。
        _ => Some(Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "fingerprint {fp:?} not supported by btls; pick a supported fingerprint (silent rustls fallback removed)"
            ),
        ))),
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
    /// 步骤：构建 connector → 配置指纹 + ECH → 创建 SslStream → 异步握手。
    ///
    /// `ech_config_list`（`tlsSettings.echConfigList` 原文）非空时在握手前
    /// `SSL_set1_ech_config_list`（对应 Go `ApplyECH` client 分支；resolve
    /// 失败自动降级 invalid config 使握手失败，不静默明文）。
    pub async fn connect(
        stream: S,
        server_name: &str,
        fingerprint: Fingerprint,
        ech_config_list: Option<&str>,
    ) -> io::Result<Self> {
        use crate::ech::ApplyEch;

        let fp_config = match connector_for_fingerprint(&fingerprint) {
            Some(Ok(c)) => c,
            // 清单外指纹：透传 InvalidData 硬错（不静默降级）
            Some(Err(e)) => return Err(e),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "fingerprint not supported by btls",
                ))
            }
        };

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
        // ECH（加密 ClientHello）：握手前设置 config list
        if let Some(list) = ech_config_list {
            ssl.apply_ech(&[], list)
                .map_err(|e| io::Error::other(e.to_string()))?;
        }
        debug!(
            target: "xray_tls::btls",
            fingerprint = ?fingerprint,
            server_name,
            ech = ech_config_list.is_some(),
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

    /// 从已握手 stream 组装（[`crate::btls_reality::connect_reality`] 用）。
    pub(crate) fn from_parts(
        stream: Pin<Box<TokioSslStream<S>>>,
        fingerprint: Fingerprint,
        server_name: &str,
    ) -> Self {
        Self { stream, fingerprint, server_name: server_name.to_string() }
    }
}

/// 指纹是否被 btls 支持（REALITY u_client 路径选择的预检）。
///
/// 清单外指纹为 `false`（`Some(Err)` 不算支持）；调用方（如 REALITY）据此
/// 走各自的平台降级路径，u_client 主路径则直接硬错。
#[must_use]
pub fn fingerprint_supported(fp: &Fingerprint) -> bool {
    matches!(connector_for_fingerprint(fp), Some(Ok(_)))
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
        Ok(None)
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }

    fn raw_tcp_clone(&self) -> Option<tokio::net::TcpStream> {
        // 穿透 BoringSSL 层克隆内层流的裸 TCP（共享 socket，vision splice 用）。
        // 内层继续沿 Connection 链穿透（TcpConnection / HelloRewriteStream / Box）。
        let stream: &TokioSslStream<S> = self.stream.as_ref().get_ref();
        stream.get_ref().raw_tcp_clone()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::get_fingerprint;

    /// ModernFingerprints 全池 + 补齐清单（android/randomized 家族/
    /// uniformrandom）必须 btls 可用（Some(Ok)），且 fingerprint_supported 同步。
    #[test]
    fn fingerprint_list_fully_supported_by_btls() {
        let mut names = vec![
            "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
            "random", "randomized", "randomizednoalpn", "uniformrandom",
            "hellofirefox_120", "hellofirefox_148", "hellochrome_120",
            "hellochrome_131", "hellochrome_133", "helloios_13", "helloios_14",
            "helloedge_106", "hellosafari_26_3", "hello360_11_0", "helloqq_11_1",
        ];
        for name in names.drain(..) {
            let fp = get_fingerprint(name).unwrap_or_else(|e| panic!("{name}: {e}"));
            let r = connector_for_fingerprint(&fp)
                .unwrap_or_else(|| panic!("{name}: no connector"));
            assert!(r.is_ok(), "{name} ({fp:?}) must build a connector: {:?}", r.err());
            assert!(super::fingerprint_supported(&fp), "{name} must be supported");
        }
    }

    /// 清单外指纹（unsafe/hellochrome_58 等旧变体之外的占位）——这里以
    /// `Unsafe` 为样本——必须 Some(Err) 且错误类别为 InvalidData（硬错，
    /// 不再静默回退标准 rustls）。
    #[test]
    fn unsupported_fingerprint_fails_hard_with_invalid_data() {
        let fp = get_fingerprint("unsafe").expect("unsafe must resolve");
        let r = connector_for_fingerprint(&fp).expect("returns Some(Err), never None");
        let err = match r {
            Ok(_) => panic!("out-of-list fingerprint must fail"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "got: {err}");
        assert!(!super::fingerprint_supported(&fp));
    }

    /// 无 ALPN 变体产出的 connector 不带 ALPN 扩展底座（alps 置空跳过）。
    #[test]
    fn randomized_no_alpn_skips_alps() {
        let fp = Fingerprint::RandomizedNoAlpn;
        let cfg = connector_for_fingerprint(&fp)
            .expect("Some")
            .expect("Ok");
        assert!(cfg.alps.is_empty());
        // 有 ALPN 变体对照：Chrome 133 携带 h2 ALPS
        let with = connector_for_fingerprint(&Fingerprint::Chrome)
            .expect("Some")
            .expect("Ok");
        assert!(!with.alps.is_empty());
    }
}
