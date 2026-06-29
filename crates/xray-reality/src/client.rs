//! REALITY 客户端。
//!
//! 翻译自 Go `transport/internet/reality/reality.go` 的 `UClient`/`UConn` 部分。
//!
//! # 现状（重要）
//! **实际 uTLS 握手未实现**。Rust 生态目前没有
//! `github.com/refraction-networking/utls` 的成熟等价品（需要字节级
//! ClientHello 控制：SessionId 注入、key_share ECDH、AEAD 加密 sessionId[:16]
//! 等）。本模块只翻译**配置数据结构与签名**，让上层能基于 [`UConnState`] 类型工作。
//!
//! 切片2 留待：
//! - 接入 `rustls` + 自研 uTLS 等价品（或上游 fork）
//! - `VerifyPeerCertificate` 回调（Go 端通过 reflect+unsafe hack 读 utls 内部字段，
//!   Rust 端需要 TLS 库暴露同等 API）
//! - http2 spider crawler（fallback 模式：路径收集 + RandBetween delays）

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

/// 创建 REALITY 客户端连接。
///
/// 对应 Go `UClient(c net.Conn, config *Config, ctx, dest) (net.Conn, error)`。
///
/// **未实现**——等接入 uTLS 等价品后实现。当前返回 [`RealityError::UtlsRequired`]。
///
/// # 切片2 待办
/// 1. 字节级 ClientHello 构造：
///    - SessionId[0..3] = core version（Version_x/y/z）
///    - SessionId[4..8] = unix timestamp（big-endian u32）
///    - SessionId[8..]  = config.short_id（最多 24 字节）
/// 2. ECDH(X25519) 派生 auth_key：`ecdhe.ECDH(publicKey)`
/// 3. HKDF-SHA256 收紧 auth_key 到 32 字节：
///    `hkdf.New(sha256, authKey, hello.Random[:20], "REALITY")`
/// 4. AES-GCM 加密 SessionId[:16]：
///    `aead.Seal(sessionId[:0], hello.Random[20:], sessionId[:16], hello.Raw)`
/// 5. 调用底层 uTLS 等价品完成握手
/// 6. 失败 fallback：spider crawler（http2 + RandBetween delays，见 [`crate::util::get_path_locked`]）
pub fn u_client<C>(_inner: C, _state: UConnState) -> Result<(), RealityError> {
    Err(RealityError::UtlsRequired)
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

    #[test]
    fn u_client_stub_returns_utls_required() {
        let state = UConnState::new(make_valid_config()).unwrap();
        let err = u_client::<()>((), state).unwrap_err();
        assert!(matches!(err, RealityError::UtlsRequired));
    }
}
