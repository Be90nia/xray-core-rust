//! REALITY 错误类型。
//!
//! 翻译自 Go `transport/internet/reality/reality.go` 与 `config.go` 中
//! 所有 `errors.New(...)` / `errors.LogError(...)` 调用点。

use thiserror::Error;

/// `xray-reality` 所有公共 API 的统一错误类型。
#[derive(Debug, Error)]
pub enum RealityError {
    /// uTLS 指纹名解析失败（对应 Go `"REALITY: failed to get fingerprint"`）。
    #[error("REALITY: failed to get fingerprint")]
    FingerprintNotFound,

    /// 服务端公钥缺失或长度错误（对应 Go `"REALITY: publicKey == nil"`）。
    #[error("REALITY: publicKey is empty or invalid")]
    EmptyPublicKey,

    /// ECDH 共享密钥派生失败（对应 Go `"REALITY: SharedKey == nil"`）。
    #[error("REALITY: SharedKey (ECDH) is nil")]
    EmptySharedKey,

    /// ECDH 或 HKDF-SHA256 派生 auth_key 失败（密钥长度错或 HKDF expand 失败）。
    #[error("REALITY: auth_key derivation failed (ECDH or HKDF)")]
    AuthKeyDeriveFailed,

    /// AES-256-GCM 加密 session_id[:16] 失败（auth_key 长度非 32 字节）。
    #[error("REALITY: session_id AES-GCM encryption failed")]
    SessionIdEncryptFailed,

    /// 当前 uTLS 指纹不支持 TLS 1.3，无法完成 REALITY 握手。
    #[error("REALITY: current fingerprint does not support TLS 1.3, handshake cannot establish")]
    FingerprintNoTls13,

    /// peer 返回了真实证书（疑似 MITM 或重定向；对应 Go 仅记日志）。
    #[error("REALITY: received real certificate (potential MITM or redirection)")]
    RealCertificateReceived,

    /// 处理了无效连接后回退失败（对应 Go `"processed invalid connection"` AtWarning）。
    #[error("REALITY: processed invalid connection")]
    InvalidConnection,

    /// short_id 长度不为 8（Go 端 `*[8]byte` 强制约束）。
    #[error("REALITY: short_id length is {actual}, expected 8")]
    InvalidShortIdLen { actual: usize },

    /// X25519 private_key 长度不为 32。
    #[error("REALITY: private_key length is {actual}, expected 32")]
    InvalidPrivateKeyLen { actual: usize },

    /// X25519 public_key 长度不为 32。
    #[error("REALITY: public_key length is {actual}, expected 32")]
    InvalidPublicKeyLen { actual: usize },

    /// master key log 文件打开失败（对应 Go 仅记 inner 日志，本实现保留原因以便排查）。
    #[error("failed to open master key log at {path}: {reason}")]
    OpenKeyLog { path: String, reason: String },

    /// uTLS Rust 端未实现——预留变体。
    ///
    /// 当前 `xray-reality` 不引入真实 uTLS 握手（Rust 生态无 uTLS 等价品，
    /// 见 [`crate`] 顶部文档说明）。实际握手等生态成熟或自研后再接。
    #[error("uTLS-based REALITY handshake not yet implemented in Rust")]
    UtlsRequired,

    /// watfaq-rustls `RealityConfig` 构建失败（short_id 过长或内部加密错误）。
    #[error("REALITY: watfaq RealityConfig build failed: {0}")]
    WatfaqConfig(String),

    /// SNI（ServerName）解析失败（非法 DNS 名）。
    #[error("REALITY: invalid server name: {0}")]
    InvalidServerName(String),

    /// TLS 握手 IO 错误（连接拒绝、超时、TLS 协议错误等）。
    #[error("REALITY: TLS handshake IO error: {0}")]
    TlsHandshake(String),

    /// AES-256-GCM 解密 session_id 失败（auth_key 错误、AAD 不匹配、或密文被篡改）。
    #[error("REALITY: session_id AES-GCM decryption failed")]
    SessionIdDecryptFailed,

    /// session_id 内 timestamp 超出允许窗口（对应 Go `time.Since/Until` 校验）。
    #[error("REALITY: timestamp {actual} out of window (now {expected}, max_diff {max_diff}s)")]
    TimestampOutOfWindow { actual: u32, expected: u32, max_diff: u32 },

    /// session_id 内 short_id 不在服务端白名单。
    #[error("REALITY: short_id not in whitelist")]
    ShortIdNotAllowed,

    /// key_share extension 缺失或不含 X25519 (group 0x001d) 条目——无法完成 REALITY 验证。
    #[error("REALITY: key_share extension missing or no X25519 entry")]
    NoKeyShareX25519,

    /// rcgen 证书生成或 rustls ServerConfig 构建失败。
    #[error("REALITY: certificate generation failed: {0}")]
    CertGenerate(String),
}

/// REALITY crate 统一 Result 别名。
pub type Result<T> = std::result::Result<T, RealityError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_messages_match_go() {
        // 关键错误消息保持英文 + 与 Go 版本一致，方便日志对照。
        assert_eq!(
            RealityError::FingerprintNotFound.to_string(),
            "REALITY: failed to get fingerprint"
        );
        assert_eq!(
            RealityError::EmptySharedKey.to_string(),
            "REALITY: SharedKey (ECDH) is nil"
        );
        assert_eq!(
            RealityError::InvalidConnection.to_string(),
            "REALITY: processed invalid connection"
        );
    }

    #[test]
    fn invalid_short_id_len_carries_actual() {
        let e = RealityError::InvalidShortIdLen { actual: 4 };
        assert!(e.to_string().contains("4"));
        assert!(e.to_string().contains("expected 8"));
    }

    #[test]
    fn open_key_log_carries_path_and_reason() {
        let e = RealityError::OpenKeyLog {
            path: "/tmp/x.keylog".into(),
            reason: "permission denied".into(),
        };
        let s = e.to_string();
        assert!(s.contains("/tmp/x.keylog"));
        assert!(s.contains("permission denied"));
    }

    #[test]
    fn utls_required_has_explanatory_message() {
        let s = RealityError::UtlsRequired.to_string();
        assert!(s.contains("not yet implemented"));
    }
}
