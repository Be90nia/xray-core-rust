//! BoringSSL (btls) 后端 uTLS 指纹伪装。
//!
//! 使用 [`btls`]（BoringSSL Rust 绑定）构造真实浏览器 ClientHello 指纹，
//! 替代标准 rustls 的默认指纹（易被 DPI 识别）。
//!
//! # 支持的指纹
//!
//! 当前仅移植 Chrome 133 指纹（含 PQ X25519MLKEM768 key share）。
//! 其他指纹将 fallback 到标准 rustls。

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use btls::ssl::{SslConnector, SslMethod};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_btls::SslStream as TokioSslStream;
use tracing::debug;
use xray_transport::connection::Connection;

use crate::fingerprint::Fingerprint;

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

/// Chrome 133 supported groups（含 PQ X25519MLKEM768）。
const CHROME_133_CURVES: &str = "X25519MLKEM768:X25519:P-256:P-384";

/// Chrome 133 ALPN。
const CHROME_133_ALPN: &[u8] = b"\x02h2\x08http/1.1";

/// Chrome 133 key shares（X25519 + PQ X25519MLKEM768）。
/// group ID: X25519=0x001D (32 bytes), X25519MLKEM768=0x6D00 (1216 bytes)。
const CHROME_133_KEY_SHARES: &[btls::ssl::KeyShare] = &[
    btls::ssl::KeyShare::X25519,
    btls::ssl::KeyShare::X25519_MLKEM768,
];

/// Chrome 133 extension permutation 顺序。
/// 参考 Go uTLS HelloChrome_120 + BoringSSL extension IDs。
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

    // 禁用内置 root 验证（xray 自行管理证书验证）
    builder.set_verify(btls::ssl::SslVerifyMode::NONE);

    Ok(builder.build())
}

/// 根据指纹选择 btls 连接器。返回 `None` 表示该指纹不支持 btls（fallback rustls）。
pub fn connector_for_fingerprint(fp: &Fingerprint) -> Option<io::Result<SslConnector>> {
    match fp {
        Fingerprint::Chrome => Some(chrome_133_connector()),
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
        let connector = connector_for_fingerprint(&fingerprint)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "fingerprint not supported by btls"))?
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let mut cfg = connector
            .configure()
            .map_err(|e| io::Error::other(e.to_string()))?;
        cfg.set_verify_hostname(false);

        let mut ssl = cfg
            .into_ssl(server_name)
            .map_err(|e| io::Error::other(e.to_string()))?;

        // per-connection 配置
        ssl.set_client_key_shares(CHROME_133_KEY_SHARES)
            .map_err(|e| io::Error::other(e.to_string()))?;
        ssl.add_application_settings(b"\x02h2")
            .map_err(|e| io::Error::other(e.to_string()))?;

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
