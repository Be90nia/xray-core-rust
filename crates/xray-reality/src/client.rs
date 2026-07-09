//! REALITY 客户端。
//!
//! 翻译自 Go `transport/internet/reality/reality.go` 的 `UClient`/`UConn` 部分。
//!
//! # 实现（watfaq-rustls）
//!
//! REALITY 握手通过 [watfaq-rustls](https://github.com/Watfaq/rustls)（Watfaq
//! fork，branch `watfaq/0.23.40`）的 `ClientConfig::builder().with_reality()`
//! API 实现：watfaq rustls 在 TLS 1.3 握手内部自动完成 REALITY session_id
//! 编码（ECDH + HKDF + AES-256-GCM）与 `RealityServerCertVerifier`（HMAC-SHA512
//! cert 校验）。auth_key/session_id 算法逐字节对齐 Go 原版 `reality.go`。
//!
//! 纯密码学算法仍保留在 [`crate::crypto`] 模块（session_id 编码、auth_key
//! 派生、证书验证），独立可测；客户端握手路径直接复用 watfaq 内部实现。
//!
//! # XTLS-Vision splice
//!
//! `u_client` 返回裸 `TlsStream<S>`；上层可包装为 `SplicableTlsStream`（待实现）
//! 以支持 XTLS-Vision 的 splice 模式（clash-rs PR#1057 方案）。

use std::sync::Arc;

use rustls::client::RealityConfig as WatfaqRealityConfig;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;
use webpki_roots::TLS_SERVER_ROOTS;

use crate::config::RealityConfig;
use crate::error::RealityError;

/// REALITY 客户端连接状态（握手前/握手后统一形态）。
///
/// 对应 Go `UConn struct { *utls.UConn; Config; ServerName; AuthKey; Verified }`。
/// 字段保留与 Go 端一致；实际 TLS 连接包装（utls.UConn 等价）等接入后补。
#[derive(Debug)]
pub struct UConnState {
    /// 配置引用（含客户端字段：fingerprint/server_name/public_key/...）。
    pub config: RealityConfig,
    /// 实际使用的 SNI（如配置为空则取自 destination，由 [`u_client`] 注入）。
    pub server_name: String,
    /// ECDH 派生的 auth key（握手成功后填充；32 字节，HKDF 收紧后）。
    ///
    /// 对应 Go `uConn.AuthKey []byte`，握手前为空 `Vec::new()`。
    pub auth_key: Vec<u8>,
    /// 证书是否通过 REALITY 校验（ed25519 + HMAC-SHA512）。
    pub verified: bool,
}

impl UConnState {
    /// 构造初始状态（未握手）。
    ///
    /// 会调用 [`RealityConfig::validate_client`] 预检客户端必备字段。
    pub fn new(config: RealityConfig) -> Result<Self, RealityError> {
        config.validate_client()?;
        Ok(Self {
            server_name: config.server_name.clone(),
            config,
            auth_key: Vec::new(),
            verified: false,
        })
    }
}

/// 创建 REALITY 客户端连接（watfaq-rustls `with_reality` 握手）。
///
/// 对应 Go `UClient(c net.Conn, config *Config, ctx, dest) (net.Conn, error)`。
///
/// 使用 watfaq-rustls 的 REALITY 扩展：`ClientConfig::builder().with_reality()`
/// 注入 REALITY session_id 计算（ECDH + HKDF-SHA256 + AES-256-GCM，auth_key
/// 内部派生）+ `RealityServerCertVerifier`（HMAC-SHA512 证书校验）。
///
/// 返回已握手的 `TlsStream<S>`；上层可包装为 `SplicableTlsStream`（XTLS-Vision）。
///
/// # Errors
///
/// - [`RealityError::WatfaqConfig`]：`public_key`/`short_id` 构建失败
/// - [`RealityError::InvalidServerName`]：SNI 非法 DNS 名
/// - [`RealityError::TlsHandshake`]：TLS 握手 IO 错误
pub async fn u_client<S>(
    inner: S,
    state: UConnState,
) -> Result<tokio_rustls::client::TlsStream<S>, RealityError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let cfg = &state.config;
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&cfg.public_key);
    let reality = WatfaqRealityConfig::new(pk, cfg.short_id.clone())
        .map_err(|e| RealityError::WatfaqConfig(e.to_string()))?;
    let roots = RootCertStore::from_iter(TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_reality(reality)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = ServerName::try_from(state.server_name.clone())
        .map_err(|e| RealityError::InvalidServerName(e.to_string()))?;
    connector
        .connect(server_name, inner)
        .await
        .map_err(|e| RealityError::TlsHandshake(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_proto::transport::internet::reality::Config as ProtoConfig;

    fn make_valid_config() -> RealityConfig {
        let proto = ProtoConfig {
            fingerprint: "chrome".into(),
            public_key: vec![1u8; 32],
            server_name: "example.com".into(),
            ..Default::default()
        };
        RealityConfig::from_proto(&proto).unwrap()
    }

    #[test]
    fn uconn_state_new_validates_config() {
        let state = UConnState::new(make_valid_config());
        assert!(state.is_ok());
        let s = state.unwrap();
        assert_eq!(s.server_name, "example.com");
        assert!(s.auth_key.is_empty());
        assert!(!s.verified);
    }

    #[test]
    fn uconn_state_rejects_bad_public_key() {
        let mut cfg = make_valid_config();
        cfg.public_key = vec![0u8; 16];
        let err = UConnState::new(cfg).unwrap_err();
        assert!(matches!(
            err,
            RealityError::InvalidPublicKeyLen { actual: 16 }
        ));
    }

    #[test]
    fn uconn_state_rejects_empty_fingerprint() {
        let mut cfg = make_valid_config();
        cfg.fingerprint = String::new();
        let err = UConnState::new(cfg).unwrap_err();
        assert!(matches!(err, RealityError::FingerprintNotFound));
    }

    /// watfaq RealityConfig 能从 UConnState 字段构建（public_key [u8;32] + short_id Vec<u8>）。
    /// auth_key/session_id 由 watfaq 内部派生，此处仅验证配置构造不 panic。
    #[test]
    fn watfaq_reality_config_builds_from_uconn_state() {
        let state = UConnState::new(make_valid_config()).unwrap();
        let cfg = &state.config;
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&cfg.public_key);
        let reality = WatfaqRealityConfig::new(pk, cfg.short_id.clone());
        assert!(reality.is_ok(), "watfaq RealityConfig 构建应成功");
    }

    /// short_id 超过 8 字节时 watfaq RealityConfig::new 返回错误。
    #[test]
    fn watfaq_reality_config_rejects_oversized_short_id() {
        let mut cfg = make_valid_config();
        cfg.short_id = vec![0u8; 9]; // 超过 8 字节上限
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&cfg.public_key);
        let err = WatfaqRealityConfig::new(pk, cfg.short_id.clone());
        assert!(err.is_err(), "short_id 9 字节应被拒绝");
    }
}
