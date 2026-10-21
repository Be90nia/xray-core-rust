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

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use btls::ssl::{KeyShare, SslConnector, SslContextBuilder, SslMethod, SslRef};
use foreign_types::ForeignTypeRef as _;
use rustls::client::danger::ServerCertVerifier;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_btls::SslStream as TokioSslStream;
use tracing::debug;
use xray_transport::connection::Connection;

use crate::fingerprint::Fingerprint;

// ============================================================
// 指纹配置输出：connector + per-connection 参数
// ============================================================

/// connector builder 挂 NST 回调：NewSessionTicket 到达即把带票 session 存入
/// 进程内 cache（[`crate::tls_session_cache`]）。
///
/// 根因（bd 0kqj B2 二次修复）：握手完成点 `SSL_get_session()` 拿到的是无
/// ticket 的 handshake session，`ssl_session_get_type` 判 `kNotResumable`、
/// `should_offer_psk` 拒绝 → ClientHello 永不发 PSK → 复用恒失败。带票
/// session 只在 NST 到达时经 `SSL_CTX_sess_set_new_cb` 交付（BoringSSL
/// `tls13_client.cc::ssl_process_new_session_ticket`）。
///
/// `SSL_SESS_CACHE_CLIENT` 是回调触发前提（tls13_client.cc:1151 位测试）；
/// BoringSSL 客户端内部缓存为 no-op，该位无其他副作用。回调在 CTX 级、拿不到
/// per-connection `enableSessionResumption`，写入不做门控——读取侧
/// `lookup_for_resume` 按 flag 门控，false 时只存不读、行为正确。
fn install_session_cache_hook(builder: &mut SslContextBuilder) {
    builder.set_session_cache_mode(btls::ssl::SslSessionCacheMode::CLIENT);
    builder.set_new_session_callback(|ssl, session| {
        if let Some(name) = ssl.servername(btls::ssl::NameType::HOST_NAME) {
            crate::tls_session_cache::store_session(name, session);
        }
    });
}

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

    builder.set_cipher_list(CHROME_133_CIPHER_LIST).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_sigalgs_list(CHROME_133_SIGALGS).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_curves_list(CHROME_133_CURVES).map_err(|e| io::Error::other(e.to_string()))?;
    if !alpn.is_empty() {
        builder.set_alpn_protos(alpn).map_err(|e| io::Error::other(e.to_string()))?;
    }
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder
        .set_extension_permutation(&chrome_133_ext_perm())
        .map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_record_size_limit(0x4001);
    builder
        .set_delegated_credentials(CHROME_133_SIGALGS)
        .map_err(|e| io::Error::other(e.to_string()))?;
    // PQ key share (X25519MLKEM768) 通过 set_curves_list 中的组顺序自动生成。
    // Chrome 133+ 将 PQ 组排在首位以启用 post-quantum TLS.

    // 禁用内置 root 验证（xray 自行管理证书验证）
    builder.set_verify(btls::ssl::SslVerifyMode::NONE);
    install_session_cache_hook(&mut builder);

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

    builder.set_cipher_list(CHROME_131_CIPHER_LIST).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_sigalgs_list(CHROME_131_SIGALGS).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_curves_list(CHROME_131_CURVES).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_alpn_protos(CHROME_131_ALPN).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder
        .set_extension_permutation(&chrome_131_ext_perm())
        .map_err(|e| io::Error::other(e.to_string()))?;
    // Chrome 131 无 record_size_limit / delegated_credentials

    // 禁用内置 root 验证（xray 自行管理证书验证）
    builder.set_verify(btls::ssl::SslVerifyMode::NONE);
    install_session_cache_hook(&mut builder);

    Ok(builder.build())
}

// ============================================================
// Chrome 120 指纹配置
// ============================================================

/// Chrome 120 key shares（仅 X25519，无 PQ）。
const CHROME_120_KEY_SHARES: &[KeyShare] = &[KeyShare::X25519];

/// Chrome 120 ALPS 数据（h2，与 Chrome 133 相同）。
const CHROME_120_ALPS: &[u8] = CHROME_133_ALPS;

/// Chrome 120 extension permutation 顺序。
/// 与 Chrome 131 相同：无 record_size_limit，无 delegated_credentials。
/// 有 ECH (0x003a) 和 ApplicationSettings (0xfe0d)。
#[cfg(test)]
#[allow(dead_code)] // Chrome 指纹模板对齐保留
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
/// ponytail (REALITY): Go REALITY 服务端证书/CertificateVerify 用 Ed25519
/// (0x0807)，真实 Firefox 148 不发送该算法（uTLS HelloFirefox_148 同）但
/// btls 客户端按声明列表校验 CertificateVerify——与 chrome 模板同款处理，必须加。
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
    "ed25519:",
    "rsa_pkcs1_sha1:",
    "ecdsa_sha1"
);

/// Firefox 148 supported groups：X25519MLKEM768 优先（Firefox 132+ 默认 PQ），
/// 后接 X25519, P-256, P-384, P-521。key shares 必须是该列表的同序子集
/// （BoringSSL `SSL_set1_client_key_shares` 校验），故 MLKEM768 须列首位。
const FIREFOX_148_CURVES: &str = "X25519MLKEM768:X25519:P-256:P-384:P-521";

/// Firefox 148 ALPN。
const FIREFOX_148_ALPN: &[u8] = b"\x02h2\x08http/1.1";

/// Firefox 148 key shares：`[X25519MLKEM768, X25519, P256]`，
/// 对齐 Go uTLS `HelloFirefox_148`（utls@v1.8.3 u_parrots.go）。REALITY 服务端
/// （Go `xtls/reality` tls.go、本仓 xray-reality server.rs 同门）要求 ClientHello
/// 带 MLKEM768 key share，缺则 reject→forward。
const FIREFOX_148_KEY_SHARES: &[KeyShare] =
    &[KeyShare::X25519_MLKEM768, KeyShare::X25519, KeyShare::P256];

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
    builder.set_sigalgs_list(FIREFOX_148_SIGALGS).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_curves_list(FIREFOX_148_CURVES).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_alpn_protos(FIREFOX_148_ALPN).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder
        .set_extension_permutation(&firefox_148_ext_perm())
        .map_err(|e| io::Error::other(e.to_string()))?;
    // Firefox 不使用 record_size_limit / delegated_credentials

    // 禁用内置 root 验证（xray 自行管理证书验证）
    builder.set_verify(btls::ssl::SslVerifyMode::NONE);
    install_session_cache_hook(&mut builder);

    Ok(builder.build())
}

// ============================================================
// Firefox 120 指纹配置
// ============================================================

/// Firefox 120 cipher suites（与 Firefox 148 相同）。
const FIREFOX_120_CIPHER_LIST: &str = FIREFOX_148_CIPHER_LIST;

/// Firefox 120 signature algorithms（与 Firefox 148 相同）。
const FIREFOX_120_SIGALGS: &str = FIREFOX_148_SIGALGS;

/// Firefox 120 supported groups（无 PQ——ML-KEM 是 Firefox 132 引入，120 不带）。
/// 独立于 `FIREFOX_148_CURVES`（148 已加 MLKEM768）。
const FIREFOX_120_CURVES: &str = "X25519:P-256:P-384:P-521";

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
    builder.set_sigalgs_list(FIREFOX_120_SIGALGS).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_curves_list(FIREFOX_120_CURVES).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_alpn_protos(FIREFOX_120_ALPN).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder
        .set_extension_permutation(&firefox_120_ext_perm())
        .map_err(|e| io::Error::other(e.to_string()))?;
    // Firefox 不使用 record_size_limit / delegated_credentials

    // 禁用内置 root 验证（xray 自行管理证书验证）
    builder.set_verify(btls::ssl::SslVerifyMode::NONE);
    install_session_cache_hook(&mut builder);

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
    "ed25519" // BoringSSL 不支持: rsa_pkcs1_sha1, ecdsa_sha1, ed448, rsa_pss_pss_*
);

/// Safari 26.3 supported groups：X25519MLKEM768 优先（iOS 18/macOS 26 默认 PQ），
/// 后接 X25519, P-256, P-384, P-521。同 Firefox：key shares 须为同序子集。
const SAFARI_26_3_CURVES: &str = "X25519MLKEM768:X25519:P-256:P-384:P-521";

/// Safari 26.3 ALPN。
const SAFARI_26_3_ALPN: &[u8] = b"\x02h2\x08http/1.1";

/// Safari 26.3 key shares：`[X25519MLKEM768, X25519]`。Go uTLS `HelloSafari_26_3`
/// 原形是 `[GREASE, X25519MLKEM768, X25519]`，GREASE key share 无法在此表达——
/// BoringSSL `SSL_set1_client_key_shares` 校验 key shares 必须是真实组的同序子集
/// （GREASE 假组 ID 被拒），降级省略 GREASE 条目，MLKEM768/X25519 保留。
const SAFARI_26_3_KEY_SHARES: &[KeyShare] = &[KeyShare::X25519_MLKEM768, KeyShare::X25519];

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
    builder.set_sigalgs_list(SAFARI_26_3_SIGALGS).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_curves_list(SAFARI_26_3_CURVES).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_alpn_protos(SAFARI_26_3_ALPN).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder
        .set_extension_permutation(&safari_26_3_ext_perm())
        .map_err(|e| io::Error::other(e.to_string()))?;
    // Safari 不使用 record_size_limit / delegated_credentials

    // 禁用内置 root 验证（xray 自行管理证书验证）
    builder.set_verify(btls::ssl::SslVerifyMode::NONE);
    install_session_cache_hook(&mut builder);

    Ok(builder.build())
}

// ============================================================
// iOS 18.4 指纹配置
// ============================================================

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

    builder.set_cipher_list(EDGE_106_CIPHER_LIST).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_sigalgs_list(EDGE_106_SIGALGS).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_curves_list(EDGE_106_CURVES).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_alpn_protos(EDGE_106_ALPN).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder
        .set_extension_permutation(&edge_106_ext_perm())
        .map_err(|e| io::Error::other(e.to_string()))?;
    // Edge 106 无 record_size_limit / delegated_credentials / ECH

    // 禁用内置 root 验证（xray 自行管理证书验证）
    builder.set_verify(btls::ssl::SslVerifyMode::NONE);
    install_session_cache_hook(&mut builder);

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
    builder.set_curves_list(QIHOO_360_11_0_CURVES).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_alpn_protos(QIHOO_360_11_0_ALPN).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder
        .set_extension_permutation(&qihoo_360_11_0_ext_perm())
        .map_err(|e| io::Error::other(e.to_string()))?;
    // 360 无 record_size_limit / delegated_credentials / ECH / ALPS

    // 禁用内置 root 验证（xray 自行管理证书验证）
    builder.set_verify(btls::ssl::SslVerifyMode::NONE);
    install_session_cache_hook(&mut builder);

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

    builder.set_cipher_list(QQ_11_1_CIPHER_LIST).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_sigalgs_list(QQ_11_1_SIGALGS).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_curves_list(QQ_11_1_CURVES).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_alpn_protos(QQ_11_1_ALPN).map_err(|e| io::Error::other(e.to_string()))?;
    builder.set_grease_enabled(true);
    builder.set_permute_extensions(true);
    builder
        .set_extension_permutation(&qq_11_1_ext_perm())
        .map_err(|e| io::Error::other(e.to_string()))?;
    // QQ 无 record_size_limit / delegated_credentials / ECH

    // 禁用内置 root 验证（xray 自行管理证书验证）
    builder.set_verify(btls::ssl::SslVerifyMode::NONE);
    install_session_cache_hook(&mut builder);

    Ok(builder.build())
}
/// btls 实际生效指纹裁决（票 daqq G8b：消灭「配 A 发 B」静默降级）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintResolution {
    /// btls 有该指纹的专属 ClientHello 模板（connector + key shares + ALPS）。
    Native,
    /// btls 无该指纹的模板：显式降级，实际发送 `effective` 模板的
    /// ClientHello。连接建立时 warn（含 configured/effective/支持清单），
    /// 本枚举即编程查询的诊断入口。
    Degraded {
        /// 实际生效（被降级到）的模板指纹。
        effective: Fingerprint,
    },
    /// btls 无模板且无降级映射：dial 硬错 `InvalidData`。
    Unsupported,
}

/// 查询配置指纹在 btls 侧实际生效的模板（诊断入口）。
///
/// **显式映射表**（票 daqq）：`Fingerprint` 每个变体必须在此处声明裁决
/// （Native / Degraded / Unsupported），并由 `fingerprint.rs` 的
/// `fingerprint_resolution_explicit_table` 测试以 exhaustive match 锁死；
/// 新增枚举变体时该测试编译失败，强制补表——禁止未声明的「配 A 发 B」分支。
///
/// btls 能力边界（依 `btls` rev ab7f522 公开 API 调研）：无内置指纹模板
/// （无 uTLS ClientHelloSpec 等价物），仅有逐字段定制原语（`set_cipher_list`/
/// `set_curves_list`/`set_sigalgs_list`/`set_extension_permutation`/
/// `set_grease_enabled`/ALPN/ALPS/key shares）。历史模板须逐字段参数表复刻，
/// 未复刻的一律显式降级或硬错，不再静默回落。
#[must_use]
pub fn effective_fingerprint(fp: &Fingerprint) -> FingerprintResolution {
    use Fingerprint::*;
    match fp {
        // 原生模板（9 组专属 ClientHello 配置，见本文件各 *_connector()）。
        Chrome | HelloChrome133
        | HelloChrome131
        | HelloChrome120
        | Firefox | HelloFirefox148
        | HelloFirefox120
        | Safari | HelloSafari26_3
        | HelloIos13 // Safari connector + iOS 13 专属 key shares/ALPS
        | Ios | HelloIos14
        | Edge | HelloEdge106
        | Qihoo360 | Hello360_11_0
        | Qq | HelloQq_11_1 => FingerprintResolution::Native,
        // 旧 Chrome 族 → Chrome 120（btls 最老 Chrome 实现）
        HelloChromeAuto
        | HelloChrome58
        | HelloChrome62
        | HelloChrome70
        | HelloChrome72
        | HelloChrome83
        | HelloChrome87
        | HelloChrome96
        | HelloChrome100
        | HelloChrome102
        | HelloChrome106Shuffle
        | HelloChrome100Psk
        | HelloChrome112PskShuf
        | HelloChrome114PaddingPskShuf
        | HelloChrome115Pq
        | HelloChrome115PqPsk
        | HelloChrome120Pq => FingerprintResolution::Degraded { effective: HelloChrome120 },
        // 旧 Firefox 族 → Firefox 120
        HelloFirefoxAuto
        | HelloFirefox55
        | HelloFirefox56
        | HelloFirefox63
        | HelloFirefox65
        | HelloFirefox99
        | HelloFirefox102
        | HelloFirefox105 => FingerprintResolution::Degraded { effective: HelloFirefox120 },
        // 旧 iOS/Safari 族 → iOS 13 配置
        HelloIosAuto
        | HelloIos11_1
        | HelloIos12_1
        | HelloSafari16_0
        | HelloSafariAuto => FingerprintResolution::Degraded { effective: HelloIos13 },
        // 旧 Edge 族 → Edge 106
        HelloEdge85 | HelloEdgeAuto => {
            FingerprintResolution::Degraded { effective: HelloEdge106 }
        },
        // 旧 360/QQ 族 → 现存实现
        Hello360Auto | Hello360_7_5 => {
            FingerprintResolution::Degraded { effective: Hello360_11_0 }
        },
        HelloQqAuto => FingerprintResolution::Degraded { effective: HelloQq_11_1 },
        // Android WebView ≈ Chrome
        Android | HelloAndroid11OkHttp => FingerprintResolution::Degraded { effective: Chrome },
        // Go stdlib 无 uTLS 指纹 → Chrome 120
        HelloGolang => FingerprintResolution::Degraded { effective: HelloChrome120 },
        // 随机化族：btls 无逐字段随机化能力（uTLS 的 cipher/扩展顺序洗牌无
        // 对应 API），诚实退化为静态 Chrome 133 并告警——不假装随机。
        Random
        | Randomized
        | HelloRandomized
        | HelloRandomizedAlpn
        | UniformRandom => FingerprintResolution::Degraded { effective: Chrome },
        // 无 ALPN 变体：同为 Chrome 133 静态降级；build 侧按配置名走
        // no-ALPN connector（ALPS 依赖 ALPN 协商，随之一并置空）。
        RandomizedNoAlpn | HelloRandomizedNoAlpn => {
            FingerprintResolution::Degraded { effective: Chrome }
        },
        // Go 端 `unsafe` 是 InsecureSkipVerify 占位，不是指纹。
        Unsafe => FingerprintResolution::Unsupported,
    }
}

/// 原生支持清单（降级 warn 文本与测试共用引用）。
const NATIVE_TEMPLATE_LIST: &str = "chrome firefox safari ios edge 360 qq \
     hellochrome_120/131/133 hellofirefox_120/148 helloios_13/14 \
     helloedge_106 hellosafari_26_3 hello360_11_0 helloqq_11_1";

/// 根据指纹选择 btls 连接器。
///
/// 返回 `Some(Ok(config))` = btls 支持（Native 或已告警的显式降级）；
/// `Some(Err(_))` = 清单外指纹（硬错 `InvalidData`，不再静默回退标准
/// rustls）；函数不再返回 `None`。
pub(crate) fn connector_for_fingerprint(fp: &Fingerprint) -> Option<io::Result<FingerprintConfig>> {
    let effective = match effective_fingerprint(fp) {
        FingerprintResolution::Native => *fp,
        FingerprintResolution::Degraded { effective } => {
            // 大声降级（票 daqq）：「配 A 发 B」必须可观测——每连接 warn
            // 带配置指纹、实际生效模板与原生支持清单。
            tracing::warn!(
                target: "xray_tls::fingerprint",
                configured = ?fp,
                effective = ?effective,
                "fingerprint not implemented by btls: degraded ClientHello in use; native templates: {NATIVE_TEMPLATE_LIST}; see effective_fingerprint()"
            );
            effective
        },
        FingerprintResolution::Unsupported => {
            // 清单外指纹：硬错 InvalidData。配置了指纹说明用户在意 ClientHello
            // 伪装，静默回退标准 rustls 等于伪装失效（批3 裁决：显式失败）。
            return Some(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "fingerprint {fp:?} not supported by btls; pick a supported fingerprint (silent rustls fallback removed)"
                ),
            )));
        },
    };
    Some(build_fingerprint_config(fp, &effective))
}

/// 按实际生效模板构建 connector 配置（分支与 [`effective_fingerprint`] 的
/// Native/Degraded 目标一一对应）。
fn build_fingerprint_config(
    configured: &Fingerprint,
    effective: &Fingerprint,
) -> io::Result<FingerprintConfig> {
    // random 族无 ALPN 变体：映射表统一到 Chrome，此处按配置名分流。
    let no_alpn =
        matches!(configured, Fingerprint::RandomizedNoAlpn | Fingerprint::HelloRandomizedNoAlpn);
    match effective {
        Fingerprint::Chrome | Fingerprint::HelloChrome133 => {
            let connector =
                if no_alpn { chrome_133_connector_no_alpn() } else { chrome_133_connector() };
            connector.map(|c| FingerprintConfig {
                connector: c,
                key_shares: CHROME_133_KEY_SHARES,
                alps: if no_alpn { b"" } else { CHROME_133_ALPS },
            })
        },
        Fingerprint::HelloChrome131 => chrome_131_connector().map(|c| FingerprintConfig {
            connector: c,
            key_shares: CHROME_131_KEY_SHARES,
            alps: CHROME_131_ALPS,
        }),
        Fingerprint::HelloChrome120 => chrome_120_connector().map(|c| FingerprintConfig {
            connector: c,
            key_shares: CHROME_120_KEY_SHARES,
            alps: CHROME_120_ALPS,
        }),
        Fingerprint::Firefox | Fingerprint::HelloFirefox148 => {
            firefox_148_connector().map(|c| FingerprintConfig {
                connector: c,
                key_shares: FIREFOX_148_KEY_SHARES,
                alps: FIREFOX_148_ALPS,
            })
        },
        Fingerprint::HelloFirefox120 => firefox_120_connector().map(|c| FingerprintConfig {
            connector: c,
            key_shares: FIREFOX_120_KEY_SHARES,
            alps: FIREFOX_120_ALPS,
        }),
        Fingerprint::Safari | Fingerprint::HelloSafari26_3 => {
            safari_26_3_connector().map(|c| FingerprintConfig {
                connector: c,
                key_shares: SAFARI_26_3_KEY_SHARES,
                alps: SAFARI_26_3_ALPS,
            })
        },
        Fingerprint::HelloIos13 => safari_26_3_connector().map(|c| FingerprintConfig {
            connector: c,
            key_shares: IOS_13_KEY_SHARES,
            alps: IOS_13_ALPS,
        }),
        Fingerprint::Ios | Fingerprint::HelloIos14 => safari_26_3_connector().map(|c| {
            FingerprintConfig { connector: c, key_shares: IOS_14_KEY_SHARES, alps: IOS_14_ALPS }
        }),
        Fingerprint::Edge | Fingerprint::HelloEdge106 => edge_106_connector().map(|c| {
            FingerprintConfig { connector: c, key_shares: EDGE_106_KEY_SHARES, alps: EDGE_106_ALPS }
        }),
        Fingerprint::Qihoo360 | Fingerprint::Hello360_11_0 => {
            qihoo_360_11_0_connector().map(|c| FingerprintConfig {
                connector: c,
                key_shares: QIHOO_360_11_0_KEY_SHARES,
                alps: QIHOO_360_11_0_ALPS,
            })
        },
        Fingerprint::Qq | Fingerprint::HelloQq_11_1 => qq_11_1_connector().map(|c| {
            FingerprintConfig { connector: c, key_shares: QQ_11_1_KEY_SHARES, alps: QQ_11_1_ALPS }
        }),
        // 穷尽性由 effective_fingerprint 保证（测试锁死），此处不可达；
        // 显式失败优于悄悄吞。
        other => unreachable!("unmapped effective fingerprint {other:?}"),
    }
}

// ============================================================
// TLS 1.3 0-RTT (early data)：FFI + 客户端状态机
// ============================================================

// btls-sys bindings 未生成 early-data 符号（bindgen 清单缺），手动 extern "C"
// 声明——符号在 BoringSSL ssl.lib 内真实存在（ssl.h:4194-4230），链接期由
// btls-sys 的静态库解析（同 btls_reality.rs 的 REALITY patch 函数先例）。
unsafe extern "C" {
    fn SSL_set_early_data_enabled(ssl: *mut btls_sys::SSL, enabled: i32);
    fn SSL_in_early_data(ssl: *const btls_sys::SSL) -> i32;
    fn SSL_early_data_accepted(ssl: *const btls_sys::SSL) -> i32;
    fn SSL_reset_early_data_reject(ssl: *mut btls_sys::SSL);
}

/// `SSL_ERROR_EARLY_DATA_REJECTED`（ssl.h:458）——服务端拒绝 0-RTT 时
/// `SSL_get_error` 的返回值。
const SSL_ERROR_EARLY_DATA_REJECTED: i32 = 15;

/// 客户端 0-RTT 状态。per-connection 状态，无跨连接共享、无全局锁。
/// `Default`（=Off）供 `mem::take` 原子换出使用。
#[derive(Default)]
enum EarlyData {
    /// 无 0-RTT：未启用 / 无缓存 session / 已 accept / 已重发完成。
    #[default]
    Off,
    /// 握手停在 0-RTT 写窗（ClientHello 已发出，服务端 flight 未到）：
    /// 后续应用写走 early data，须缓存已写字节备拒收重发。
    Offering { written: Vec<u8> },
    /// 服务端拒绝（`SSL_ERROR_EARLY_DATA_REJECTED`，且已
    /// `SSL_reset_early_data_reject`）：补完握手后用普通 SSL_write 重发
    /// `pending[sent..]`，保证应用层数据零丢失、零重复。
    Replay { pending: Vec<u8>, sent: usize },
}

impl<S: Connection + Unpin> BtlsConn<S> {
    /// 取 BoringSSL `SSL*`（`stream` 持有，生命周期覆盖全部调用点）。
    fn ssl_ptr(&self) -> *mut btls_sys::SSL {
        self.stream.ssl().as_ptr()
    }

    /// SSL 是否仍在 0-RTT 写窗（握手停在 ClientHello 后）。
    fn in_early_data(&self) -> bool {
        // SAFETY: ssl 指针由 self.stream 持有且握手窗口内有效。
        unsafe { SSL_in_early_data(self.ssl_ptr()) == 1 }
    }

    /// 最近一次读/写报错是否 = 服务端拒绝 0-RTT（rwstate 保持该值直至 reset）。
    fn early_data_rejected(&self) -> bool {
        // SAFETY: ssl 指针由 self.stream 持有；ret_code 传 -1 读 rwstate。
        unsafe { btls_sys::SSL_get_error(self.ssl_ptr(), -1) == SSL_ERROR_EARLY_DATA_REJECTED }
    }

    /// 0-RTT 终态查询（验收/测试用）。`None` = 未提供 0-RTT（未启用/无缓存/
    /// session 不支持）；`Some(false)` = 提供了但被服务端拒绝；`Some(true)` =
    /// 被接受。
    #[must_use]
    pub fn early_data_accepted(&self) -> Option<bool> {
        match self.early {
            EarlyData::Off if self.offered_early_data => {
                // SAFETY: ssl 指针由 self.stream 持有。
                Some(unsafe { SSL_early_data_accepted(self.ssl_ptr()) == 1 })
            },
            EarlyData::Offering { .. } | EarlyData::Replay { .. } => None,
            EarlyData::Off => None,
        }
    }

    /// 进入拒绝重发路径：reset SSL 0-RTT 状态，把已写 early 字节转入待重发队列。
    fn begin_replay(&mut self) {
        let EarlyData::Offering { written } = std::mem::take(&mut self.early) else {
            return;
        };
        // SAFETY: 仅在 rwstate == SSL_ERROR_EARLY_DATA_REJECTED 时调用（ssl.h 契约）。
        unsafe { SSL_reset_early_data_reject(self.ssl_ptr()) };
        debug!(
            target: "xray_tls::btls",
            server_name = %self.server_name,
            bytes = written.len(),
            "early_data_status=REJECTED (0-RTT); replaying buffered request after handshake"
        );
        self.early = EarlyData::Replay { pending: written, sent: 0 };
    }

    /// 0-RTT 写窗自然关闭（读/写驱动握手完成）：报告 accept 结果并落终态。
    /// accept 时已写字节随 0-RTT 送达，无需重发；reject 不会走到这里
    /// （reject 以 error 形态报出，走 [`Self::begin_replay`]）。
    fn finish_offer(&mut self) {
        let EarlyData::Offering { written } = std::mem::take(&mut self.early) else {
            return;
        };
        // SAFETY: ssl 指针由 self.stream 持有且握手已完成。
        let accepted = unsafe { SSL_early_data_accepted(self.ssl_ptr()) == 1 };
        debug!(
            target: "xray_tls::btls",
            server_name = %self.server_name,
            bytes = written.len(),
            "early_data_status={}", if accepted { "ACCEPTED (0-RTT)" } else { "NOT_USED" }
        );
        self.early = EarlyData::Off;
    }

    /// Replay 阶段驱动：①补完被拒后的握手 ②普通写重发 pending 剩余字节。
    /// 任一步 Pending 即整体 Pending，状态自持、跨 poll 续跑。
    fn poll_drive_replay(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.stream.as_mut().poll_do_handshake(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(io::Error::other(e.to_string())));
                },
                Poll::Ready(Ok(())) => {},
            }
            let EarlyData::Replay { pending, sent } = &mut self.early else {
                return Poll::Ready(Ok(()));
            };
            match self.stream.as_mut().poll_write(cx, &pending[*sent..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(n)) => {
                    *sent += n;
                    if *sent == pending.len() {
                        debug!(
                            target: "xray_tls::btls",
                            server_name = %self.server_name,
                            bytes = pending.len(),
                            "early_data replay complete (1-RTT fallback)"
                        );
                        // 拒绝后握手以真实证书链完成：回接验证必须重跑
                        //（connect 时验证的是 session 预测链）。
                        if let Some(v) = self.verifier.as_deref() {
                            if let Err(e) =
                                verify_peer_certs(self.stream.ssl(), &self.server_name, v)
                            {
                                return Poll::Ready(Err(e));
                            }
                        }
                        self.early = EarlyData::Off;
                        return Poll::Ready(Ok(()));
                    }
                },
            }
        }
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
    /// 0-RTT (early data) 状态机（见 [`EarlyData`]）。
    early: EarlyData,
    /// connect 是否提供过 0-RTT（区分「未提供」与「提供后被拒」的终态查询）。
    offered_early_data: bool,
    /// 回接证书验证器：拒绝重发路径握手重跑后须对真实链重验。
    verifier: Option<Arc<dyn ServerCertVerifier>>,
}

impl<S: Connection + Unpin> BtlsConn<S> {
    /// 创建 btls uTLS 连接（完成握手）。
    ///
    /// # 参数
    /// - `verifier`：rustls 服务端证书验证器。`Some(v)` 时握手成功后对 btls 拿到的 peer
    ///   证书链做**回接验证**（链 + 主机名，对齐 Go uTLS 非 `InsecureSkipVerify`
    ///   时的完整验证，tls.go `copyConfig`）；`None` = 跳过（`allowInsecure=true`
    ///   等价）。`allowInsecure`/pinned/vcn 语义由 调用方传入的 verifier
    ///   编码（`build_client_config` 产物直接取 `ClientConfig.verifier`）。REALITY
    ///   路径（`from_parts`）自管 HMAC， 不经此参数。
    pub async fn connect(
        stream: S,
        server_name: &str,
        fingerprint: Fingerprint,
        ech_config_list: Option<&str>,
        verifier: Option<Arc<dyn ServerCertVerifier>>,
    ) -> io::Result<Self> {
        Self::connect_with_alpn(
            stream,
            server_name,
            fingerprint,
            ech_config_list,
            verifier,
            None,
            false,
        )
        .await
    }

    /// `connect` 的 ALPN 覆盖版（ws/httpupgrade 出站接线用，md5i）。
    ///
    /// 对应 Go `UConn.WebsocketHandshakeContext`（tls.go:98-133）：保持指纹模板
    /// 其余 ClientHello 形态，仅把 ALPN 扩展重写为 `alpn_wire`（openssl wire
    /// 格式，如 `b"\x08http/1.1"`）；`None` = 保持模板 ALPN（原行为）。
    ///
    /// `early_data`：TLS 1.3 0-RTT 总闸（幂等首写协议才开，如 ws upgrade GET）。
    /// 仅当此前 `SSL_set_session` 命中带 `max_early_data_size` 宣告的缓存
    /// session 时实际生效（BoringSSL 自门控：无缓存/不支持时该 flag 无效果，
    /// 行为与 0-RTT 关闭完全一致）。握手停在 0-RTT 写窗时返回的连接处于
    /// `EarlyData::Offering` 态——应用首写以 early data 发出，若服务端拒绝
    /// 则由 AsyncWrite/AsyncRead 内的重发路径兜底（数据零丢失）。
    pub async fn connect_with_alpn(
        stream: S,
        server_name: &str,
        fingerprint: Fingerprint,
        ech_config_list: Option<&str>,
        verifier: Option<Arc<dyn ServerCertVerifier>>,
        alpn_wire: Option<&[u8]>,
        early_data: bool,
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
                ));
            },
        };

        let mut cfg =
            fp_config.connector.configure().map_err(|e| io::Error::other(e.to_string()))?;
        cfg.set_verify_hostname(false);

        // 客户端 TLS session cache（B2，2026-10-19，bd 0kqj 修复）：connector 自身
        // 不同进程间共享——每个 dial 重新构建 `FpConfig.connector` = 新 SSL_CTX；
        // 本模块 cache 直接持有 BoringSSL ref-counted `SslSession` 跨 CTX 投递
        // （早前 to_der/from_der 序列化路径被 `not_resumable=true` 陷阱废——
        // BoringSSL `SSL_SESSION_to_bytes` 在 TLS 1.3 path 写「NOT RESUMABLE」
        // 占位符，无法还原 ticket）。`enableSessionResumption=false` 走 lookup
        // 早返（与 rustls 路径的 `Resumption::disabled()` 对齐）。
        let enable_session_resumption =
            crate::tls_session_cache::parse_enable_session_resumption(None);
        let mut ssl = cfg.into_ssl(server_name).map_err(|e| io::Error::other(e.to_string()))?;
        let mut session_set = false;
        if let Some(session) =
            crate::tls_session_cache::lookup_for_resume(server_name, enable_session_resumption)
        {
            // SAFETY: SslSession ref-counted，`session` 绑定到 if-let scope，离开前
            // BoringSSL 已 up-ref session，drop 在 scope 末尾释放。
            if unsafe { ssl.set_session(&session) }.is_ok() {
                session_set = true;
            } else {
                debug!(
                    target: "xray_tls::btls",
                    fingerprint = ?fingerprint,
                    server_name,
                    "btls uTLS: SSL_set_session 失败，将走 full handshake"
                );
            }
        }
        // 0-RTT 总闸：仅在缓存 session 命中时启用（无缓存时开 flag 也无 wire
        // 效果，但闸门语义保持「未命中=完全不提供 0-RTT」）。BoringSSL 仍会按
        // session 是否携带 max_early_data_size 宣告自门控：不支持的 session
        // 直接完整握手，与关闭 0-RTT 行为一致。
        let early_data_armed = early_data && session_set;
        let offered_early_data = early_data_armed;

        // per-connection 配置：key shares 和 ALPS 按指纹不同
        ssl.set_client_key_shares(fp_config.key_shares)
            .map_err(|e| io::Error::other(e.to_string()))?;
        if !fp_config.alps.is_empty() {
            ssl.add_application_settings(fp_config.alps)
                .map_err(|e| io::Error::other(e.to_string()))?;
        }
        // ALPN 覆盖（md5i ws/httpupgrade）：SSL_set_alpn_protos 覆盖连接器
        // 模板的 ALPN（BoringSSL per-SSL 优先于 per-CTX）。指纹其余形态不变。
        if let Some(alpn) = alpn_wire {
            ssl.set_alpn_protos(alpn).map_err(|e| io::Error::other(e.to_string()))?;
        }
        // ECH（加密 ClientHello）：握手前设置 config list
        if let Some(list) = ech_config_list {
            ssl.apply_ech(&[], list).map_err(|e| io::Error::other(e.to_string()))?;
        }
        debug!(
            target: "xray_tls::btls",
            fingerprint = ?fingerprint,
            server_name,
            ech = ech_config_list.is_some(),
            "btls uTLS 握手开始"
        );
        let tls_stream =
            TokioSslStream::new(ssl, stream).map_err(|e| io::Error::other(e.to_string()))?;

        // 异步握手（tokio_btls SslStream::connect 需要 Pin<&mut Self>）
        let mut pinned = Box::pin(tls_stream);
        if early_data_armed {
            // SAFETY: SSL 指针由 pinned 流持有；握手未开始（connect 未调用），
            // 0-RTT flag 必须在首个握手字节前设置（ssl.h 契约）。
            unsafe { SSL_set_early_data_enabled(pinned.ssl().as_ptr(), 1) };
        }
        pinned
            .as_mut()
            .connect()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, e.to_string()))?;

        // 0-RTT 写窗检测：缓存 session 带 max_early_data_size 宣告时，握手停在
        // ClientHello 后（handshake.cc:642 early_return），应用首写将以 early
        // data 发出。未停窗 = 完整握手已在 connect 内完成（原行为，零变化）。
        let mut early = EarlyData::Off;
        if unsafe { SSL_in_early_data(pinned.ssl().as_ptr()) == 1 } {
            debug!(
                target: "xray_tls::btls",
                fingerprint = ?fingerprint,
                server_name,
                "early_data offered (handshake paused in 0-RTT window)"
            );
            early = EarlyData::Offering { written: Vec::new() };
        }

        // 会话复用证据埋点（B2 验收 7）：握手成功后从 ssl 读 `session_reused`
        // （BoringSSL 内部 = `SSL_session_reused(ssl)`）。True = 本次握手走了
        // 1-RTT/0-RTT resumption；False = 1-RTT 完整握手（新 server / ticket 过期）。
        let reused = pinned.ssl().session_reused();
        debug!(
            target: "xray_tls::btls",
            fingerprint = ?fingerprint,
            server_name,
            session_reused = reused,
            "btls uTLS 握手完成"
        );

        // 回接验证：btls 全程 set_verify(NONE)（保 ClientHello 指纹不被
        // 验证回调影响），握手成功后用 rustls verifier 验 peer 链。
        if let Some(v) = verifier.as_deref() {
            verify_peer_certs(pinned.ssl(), server_name, v)?;
        }

        // session 回写不在此处：握手完成点 `SSL_get_session()` 是无 ticket 的
        // handshake session（`kNotResumable`，永不发 PSK）——写入已移至 connector
        // 的 `set_new_session_callback`（NST 到达时交付带票 session，见
        // [`install_session_cache_hook`]）。

        Ok(Self {
            stream: pinned,
            fingerprint,
            server_name: server_name.to_string(),
            early,
            offered_early_data,
            verifier,
        })
    }

    /// 从已握手 stream 组装（[`crate::btls_reality::connect_reality`] 用）。
    pub(crate) fn from_parts(
        stream: Pin<Box<TokioSslStream<S>>>,
        fingerprint: Fingerprint,
        server_name: &str,
    ) -> Self {
        Self {
            stream,
            fingerprint,
            server_name: server_name.to_string(),
            early: EarlyData::Off,
            offered_early_data: false,
            verifier: None,
        }
    }
}

/// btls 握手后证书回接验证：peer 链转 DER 喂给 rustls `ServerCertVerifier`。
///
/// 客户端侧 `peer_cert_chain()` 含叶子（btls 文档注），布局与 rustls
/// `verify_server_cert(end_entity, intermediates)` 一致。
fn verify_peer_certs(
    ssl: &SslRef,
    server_name: &str,
    verifier: &dyn ServerCertVerifier,
) -> io::Result<()> {
    let chain = ssl.peer_cert_chain().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "btls: server sent no certificate")
    })?;
    let mut ders: Vec<CertificateDer<'static>> = Vec::with_capacity(chain.len());
    for cert in chain.iter() {
        let der = cert.to_der().map_err(|e| io::Error::other(e.to_string()))?;
        ders.push(CertificateDer::from(der));
    }
    let Some((end_entity, intermediates)) = ders.split_first() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "btls: empty peer certificate chain",
        ));
    };
    let name: ServerName<'static> = ServerName::try_from(server_name.to_string()).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("invalid server name: {e}"))
    })?;
    verifier
        .verify_server_cert(end_entity, intermediates, &name, &[], UnixTime::now())
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("btls certificate verification failed for {server_name}: {e}"),
            )
        })
        .map(|_| ())
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
        let this = &mut *self;
        loop {
            // Replay 义务优先：先补握手 + 重发被拒字节，再谈读。
            if matches!(this.early, EarlyData::Replay { .. }) {
                std::task::ready!(this.poll_drive_replay(cx))?;
            }
            let EarlyData::Offering { .. } = this.early else {
                return this.stream.as_mut().poll_read(cx, buf);
            };
            // 0-RTT 写窗中的读 = 驱动握手完成（BoringSSL 语义，ssl.h:4204）。
            match this.stream.as_mut().poll_read(cx, buf) {
                Poll::Ready(Ok(())) => {
                    if !this.in_early_data() {
                        this.finish_offer();
                    }
                    return Poll::Ready(Ok(()));
                },
                Poll::Ready(Err(e)) => {
                    if this.early_data_rejected() {
                        this.begin_replay();
                        continue;
                    }
                    return Poll::Ready(Err(e));
                },
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: Connection + Unpin> AsyncWrite for BtlsConn<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        loop {
            // Replay 义务优先：先补握手 + 重发被拒字节，再写本次数据。
            if matches!(this.early, EarlyData::Replay { .. }) {
                std::task::ready!(this.poll_drive_replay(cx))?;
            }
            let EarlyData::Offering { .. } = this.early else {
                return this.stream.as_mut().poll_write(cx, buf);
            };
            // 0-RTT 写窗中的写 = early data；缓存字节备拒收重发。
            match this.stream.as_mut().poll_write(cx, buf) {
                Poll::Ready(Ok(n)) => {
                    if let EarlyData::Offering { written } = &mut this.early {
                        written.extend_from_slice(&buf[..n]);
                    }
                    // 写超 early data 上限时 BoringSSL 先完成握手再写
                    //（ssl.h:4166），此处顺带捕捉写窗关闭。
                    if !this.in_early_data() {
                        this.finish_offer();
                    }
                    return Poll::Ready(Ok(n));
                },
                Poll::Ready(Err(e)) => {
                    if this.early_data_rejected() {
                        this.begin_replay();
                        continue;
                    }
                    return Poll::Ready(Err(e));
                },
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Replay 中的 flush 先清重发义务（flush = 排空缓冲语义）。
        if matches!(self.early, EarlyData::Replay { .. }) {
            std::task::ready!(self.poll_drive_replay(cx))?;
        }
        self.stream.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // 关闭前不清重发义务 = 丢数据；先补发再关。
        if matches!(self.early, EarlyData::Replay { .. }) {
            std::task::ready!(self.poll_drive_replay(cx))?;
        }
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

    fn handshake_server_name<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = String> + Send + 'a>> {
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

    use std::sync::{Arc, Mutex};

    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Subscriber};

    /// 极简 warn 捕获 subscriber（票 daqq）：断言降级告警真实发出且携带
    /// configured/effective 字段（真实 tracing 事件，非 mock）。
    #[derive(Clone, Default)]
    struct WarnCapture(Arc<Mutex<Vec<String>>>);

    impl Subscriber for WarnCapture {
        fn enabled(&self, meta: &tracing::Metadata<'_>) -> bool {
            meta.level() <= &tracing::Level::WARN
        }
        fn new_span(&self, _attrs: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _span: &Id, _values: &Record<'_>) {}
        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
        fn event(&self, event: &Event<'_>) {
            struct Fmt(String);
            impl tracing::field::Visit for Fmt {
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    self.0.push_str(&format!("{}={value} ", field.name()));
                }
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    self.0.push_str(&format!("{}={value:?} ", field.name()));
                }
            }
            let mut v = Fmt(String::new());
            event.record(&mut v);
            self.0.lock().unwrap().push(v.0);
        }
        fn enter(&self, _span: &Id) {}
        fn exit(&self, _span: &Id) {}
    }

    /// 已知不支持的历史指纹（hellochrome_58）→ 显式降级 Chrome 120：
    /// warn 必须真实发出且含 configured/effective 两个字段。
    #[test]
    fn degraded_fingerprint_warns_with_configured_and_effective() {
        let capture = WarnCapture::default();
        tracing::subscriber::with_default(capture.clone(), || {
            let cfg = connector_for_fingerprint(&Fingerprint::HelloChrome58)
                .expect("Some")
                .expect("degraded config builds");
            let _ = cfg;
        });
        let warns = capture.0.lock().unwrap();
        for w in warns.iter() {
            // e2e 取证（--nocapture）：真实 warn 文本。
            println!("[e2e] warn: {w}");
        }
        assert!(
            warns.iter().any(|w| {
                w.contains("configured=HelloChrome58")
                    && w.contains("effective=HelloChrome120")
                    && w.contains("not implemented by btls")
            }),
            "expected degradation warn, got: {warns:?}"
        );
    }

    /// random/randomized 族：btls 无真随机化能力 → 静态 Chrome 133 必须
    /// **明确告警**（修复前只有 debug!，RUST_LOG=warn 下完全不可见）。
    #[test]
    fn random_fingerprint_warns_fixed_degradation() {
        let capture = WarnCapture::default();
        tracing::subscriber::with_default(capture.clone(), || {
            let cfg = connector_for_fingerprint(&Fingerprint::Random)
                .expect("Some")
                .expect("random degraded config builds");
            let _ = cfg;
        });
        let warns = capture.0.lock().unwrap();
        assert!(
            warns
                .iter()
                .any(|w| { w.contains("configured=Random") && w.contains("effective=Chrome") }),
            "expected random degradation warn, got: {warns:?}"
        );
    }

    /// randomizednoalpn：降级 Chrome 但走 no-ALPN connector（ALPS 置空），
    /// 且同样必须告警。
    #[test]
    fn randomized_no_alpn_degrades_with_warning() {
        let capture = WarnCapture::default();
        tracing::subscriber::with_default(capture.clone(), || {
            let cfg = connector_for_fingerprint(&Fingerprint::RandomizedNoAlpn)
                .expect("Some")
                .expect("no-alpn degraded config builds");
            assert!(cfg.alps.is_empty(), "no-ALPN variant must have empty ALPS");
        });
        let warns = capture.0.lock().unwrap();
        assert!(
            warns.iter().any(|w| {
                w.contains("configured=RandomizedNoAlpn") && w.contains("effective=Chrome")
            }),
            "expected no-alpn degradation warn, got: {warns:?}"
        );
    }

    /// 原生指纹不得触发降级告警（告警只属于「配 A 发 B」）。
    #[test]
    fn native_fingerprint_emits_no_warning() {
        let capture = WarnCapture::default();
        tracing::subscriber::with_default(capture.clone(), || {
            let _ = connector_for_fingerprint(&Fingerprint::Chrome).expect("Some").expect("ok");
            let _ = connector_for_fingerprint(&Fingerprint::HelloIos13).expect("Some").expect("ok");
        });
        assert!(capture.0.lock().unwrap().is_empty(), "native fingerprints must not warn");
    }

    /// 清单外指纹（unsafe）：硬错 InvalidData，文本含支持提示（原文保留）。
    #[test]
    fn unsupported_fingerprint_hard_errors() {
        // FingerprintConfig 无 Debug（SslConnector 无 derive），用 match 解构。
        let err = match connector_for_fingerprint(&Fingerprint::Unsafe) {
            Some(Ok(_)) => panic!("out-of-list fingerprint must hard-error"),
            Some(Err(e)) => e,
            None => panic!("connector_for_fingerprint never returns None"),
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("not supported by btls"), "got: {err}");
    }

    /// ModernFingerprints 全池 + 补齐清单（android/randomized 家族/
    /// uniformrandom）必须 btls 可用（Some(Ok)），且 fingerprint_supported 同步。
    #[test]
    fn fingerprint_list_fully_supported_by_btls() {
        let mut names = vec![
            "chrome",
            "firefox",
            "safari",
            "ios",
            "android",
            "edge",
            "360",
            "qq",
            "random",
            "randomized",
            "randomizednoalpn",
            "uniformrandom",
            "hellofirefox_120",
            "hellofirefox_148",
            "hellochrome_120",
            "hellochrome_131",
            "hellochrome_133",
            "helloios_13",
            "helloios_14",
            "helloedge_106",
            "hellosafari_26_3",
            "hello360_11_0",
            "helloqq_11_1",
        ];
        for name in names.drain(..) {
            let fp = get_fingerprint(name).unwrap_or_else(|e| panic!("{name}: {e}"));
            let r =
                connector_for_fingerprint(&fp).unwrap_or_else(|| panic!("{name}: no connector"));
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
        let cfg = connector_for_fingerprint(&fp).expect("Some").expect("Ok");
        assert!(cfg.alps.is_empty());
        // 有 ALPN 变体对照：Chrome 133 携带 h2 ALPS
        let with = connector_for_fingerprint(&Fingerprint::Chrome).expect("Some").expect("Ok");
        assert!(!with.alps.is_empty());
    }

    /// TLS 1.3 0-RTT 三相回环：①首连 full handshake（无 0-RTT）②warm cache
    /// 重连 → early data 被接受且服务端收到的字节与客户端写出一致 ③对无 0-RTT
    /// 服务端重连（同 SNI，PSK 解不开）→ REJECTED → reset+重发 → 数据完整。
    /// 覆盖 AsyncWrite/AsyncRead 状态机的 offer/accept/reject/replay 全路径。
    #[tokio::test]
    async fn early_data_accept_reject_replay_roundtrip() {
        use std::sync::Arc as StdArc;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use xray_transport::connection::TcpConnection;

        let timeout = tokio::time::Duration::from_secs(60);
        tokio::time::timeout(timeout, async {
            // 服务端 A：0-RTT 开（stateful + 64K）；服务端 B：缺省（无状态 ticketer）。
            let cfg_ed = crate::server_config::build_server_config(
                "tls",
                Some(&serde_json::json!({"allowEarlyData": true})),
            )
            .unwrap()
            .unwrap();
            let cfg_plain =
                crate::server_config::build_server_config("tls", Some(&serde_json::json!({})))
                    .unwrap()
                    .unwrap();
            let acceptor_ed = StdArc::new(tokio_rustls::TlsAcceptor::from(cfg_ed));
            let acceptor_plain = StdArc::new(tokio_rustls::TlsAcceptor::from(cfg_plain));

            let lsn = StdArc::new(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap());
            let addr = lsn.local_addr().unwrap();

            // 服务端任务：accept 一条连接 → 排空 early data → 回写 HELLO → 读一段。
            type Acceptor = StdArc<tokio_rustls::TlsAcceptor>;
            async fn serve(
                lsn: StdArc<tokio::net::TcpListener>,
                acc: Acceptor,
            ) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
                let (tcp, _) = lsn.accept().await?;
                let mut tls = acc.accept(tcp).await?;
                let mut early = Vec::new();
                if let Some(mut ed) = tls.get_mut().1.early_data() {
                    use std::io::Read as _;
                    let _ = ed.read_to_end(&mut early);
                }
                let mut tls = tls;
                tls.write_all(b"HELLO").await?;
                let mut buf = [0u8; 64];
                let n = tls.read(&mut buf).await.unwrap_or(0);
                Ok((early, buf[..n].to_vec()))
            }

            // ① 首连（无缓存）→ full handshake，不得提供 0-RTT。
            let s1 = tokio::spawn(serve(lsn.clone(), acceptor_ed.clone()));
            let tcp1 = TcpConnection::new(tokio::net::TcpStream::connect(addr).await.unwrap());
            let mut c1 = BtlsConn::connect_with_alpn(
                tcp1,
                "localhost",
                Fingerprint::Chrome,
                None,
                None,
                None,
                true,
            )
            .await
            .unwrap();
            assert_eq!(c1.early_data_accepted(), None, "首连无缓存：不应有 0-RTT 终态");
            c1.write_all(b"PING1").await.unwrap();
            let mut buf = [0u8; 5];
            c1.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"HELLO");
            drop(c1);
            let (early1, got1) = s1.await.unwrap().unwrap();
            assert!(early1.is_empty(), "首连不应有 early data: {early1:?}");
            assert_eq!(&got1, b"PING1");

            // ② warm cache 重连（0-RTT 服务端）→ 停窗 → 首写 early data → ACCEPTED。
            let s2 = tokio::spawn(serve(lsn.clone(), acceptor_ed.clone()));
            let tcp2 = TcpConnection::new(tokio::net::TcpStream::connect(addr).await.unwrap());
            let mut c2 = BtlsConn::connect_with_alpn(
                tcp2,
                "localhost",
                Fingerprint::Chrome,
                None,
                None,
                None,
                true,
            )
            .await
            .unwrap();
            c2.write_all(b"PING2").await.unwrap();
            let mut buf = [0u8; 5];
            c2.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"HELLO");
            assert_eq!(c2.early_data_accepted(), Some(true), "warm cache + 0-RTT 服务端必须接受");
            drop(c2);
            let (early2, got2) = s2.await.unwrap().unwrap();
            assert_eq!(early2, b"PING2", "服务端收到的 early 字节须与客户端首写一致");
            assert!(got2.is_empty(), "accept 场景无重发：后续流不应再有数据");

            // ③ 同 SNI 拨无 0-RTT 服务端 → PSK 解不开 → REJECTED → 重发保数据。
            let s3 = tokio::spawn(serve(lsn, acceptor_plain));
            let tcp3 = TcpConnection::new(tokio::net::TcpStream::connect(addr).await.unwrap());
            let mut c3 = BtlsConn::connect_with_alpn(
                tcp3,
                "localhost",
                Fingerprint::Chrome,
                None,
                None,
                None,
                true,
            )
            .await
            .unwrap();
            c3.write_all(b"PING3").await.unwrap();
            let mut buf = [0u8; 5];
            c3.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"HELLO");
            assert_eq!(c3.early_data_accepted(), Some(false), "被拒后终态必须是 Some(false)");
            drop(c3);
            let (early3, got3) = s3.await.unwrap().unwrap();
            assert!(early3.is_empty(), "拒绝方不应收到 early data: {early3:?}");
            assert_eq!(&got3, b"PING3", "重发后数据必须完整送达（禁止丢数据）");
        })
        .await
        .expect("early-data roundtrip timed out");
    }
}
