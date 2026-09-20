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

    /// key_share extension 缺失或不含合格 X25519MLKEM768 组合（sb6g 对齐 Go
    /// tls.go:233-235：纯 X25519 单 share、MLKEM 顺序颠倒、重复 MLKEM entry
    /// 均视为 outdated/strange ClientHello reject→forward）。
    #[error("REALITY: key_share extension missing or no X25519 entry")]
    NoKeyShareX25519,

    /// rcgen 证书生成或 rustls ServerConfig 构建失败。
    #[error("REALITY: certificate generation failed: {0}")]
    CertGenerate(String),

    /// mldsa65_seed 长度不为 32（Go 端 `(*[32]byte)` 转换直接 panic）。
    #[error("REALITY: mldsa65_seed length is {actual}, expected 32")]
    InvalidMldsa65SeedLen { actual: usize },

    /// bd frxi：max_useless_records 超出 u32（proto uint64 下溢保护）。
    #[error("REALITY: max_useless_records {value} exceeds u32")]
    InvalidMaxUselessRecords { value: u64 },

    /// ML-DSA-65 验签失败（公钥/签名解码失败，多为脏数据或长度错）。
    /// tvky：验签原语对接 RustCrypto ml-dsa（与 xray-cli 同 crate）。
    /// cm97：签名生成端（[`crate::mitm`]）与客户端 btls ServerHello 捕获
    /// 验签链路已落地；客户端配 `mldsa65Verify` 而服务端未带 mldsa65 扩展时，
    /// Go 端回退标准 x509 验证（必败断连），Rust 端以
    /// [`RealityError::RealCertificateReceived`] 等价断连。
    #[error("REALITY: mldsa65 signature decode failed")]
    Mldsa65VerifyFailed,

    /// fs0o/ft0g: 解密 payload 的 ClientVer 低于配置的 `min_client_ver`（Go
    /// `MinClientVer=[26,3,27]` 即 Xray-core v26.3.27 版本门控，
    /// xtls/reality tls.go:259-267）。
    #[error("REALITY: client version too old")]
    ClientVersionTooOld,

    /// fs0o/ft0g: 解密 payload 的 ClientVer 高于配置的 `max_client_ver`。
    #[error("REALITY: client version too new")]
    ClientVersionTooNew,

    /// 49i9：客户端配了 `mldsa65Verify` 但所选指纹走 watfaq-rustls fallback——
    /// 该栈没有 mldsa65 证书扩展验签钩子，静默跳过 = fail-open。配置期已拒
    /// （register.rs），此变体兜底 `UConnState` 字面构造等绕过路径，防降级为明文验证。
    #[error("REALITY: mldsa65Verify requires a btls-supported fingerprint (watfaq-rustls fallback path cannot verify mldsa65)")]
    Mldsa65VerifyNeedsBtlsFingerprint,
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
}
