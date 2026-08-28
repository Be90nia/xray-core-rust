//! TLS 错误类型。

use thiserror::Error;

/// `xray-tls` 所有公共 API 的统一错误类型。
///
/// 翻译自 Go 版 `transport/internet/tls/` 各处 `errors.New(...)` 与
/// `crypto/tls.errNoCertificates`（经 `unsafe.go` 的 go:linkname 暴露）。
#[derive(Debug, Error)]
pub enum TlsError {
    /// 证书链中无可用证书（对应 Go 的 `errNoCertificates`）。
    #[error("no certificates configured")]
    NoCertificates,

    /// 自签根证书池加载/追加失败。
    #[error("failed to load self-signed cert pool: {0}")]
    LoadSelfCertPool(String),

    /// 系统 root 证书池加载失败。
    #[error("failed to load system root: {0}")]
    LoadSystemRoot(String),

    /// 追加 PEM 证书到根池失败。
    #[error("failed to append cert to root pool")]
    AppendCertToRoot,

    /// 证书路径读取失败（OCSP hot-reload 或路径模式加载）。
    #[error("failed to read certificate at path {path}: {reason}")]
    ReadCertificate { path: String, reason: String },

    /// 解析 ECH key set 二进制失败（对应 Go 的 `ErrInvalidLen`）。
    #[error("invalid ECH key length")]
    InvalidEchKeyLength,

    /// ECH DNS 查询返回的 HTTPS RR 中没有可用 ECH config。
    #[error("no valid ECH config found in DNS response")]
    NoEchConfig,

    /// ECH DNS 服务器格式错误。
    #[error("invalid ECH DNS server format: {0}")]
    InvalidEchDnsServerFormat(String),

    /// ECH 配置应用到 btls (BoringSSL) 失败（key 长度非法、TLV 结构错等）。
    #[error("failed to apply ECH config: {0}")]
    EchApply(String),

    /// pinned 证书哈希校验：peer 证书未被识别。
    #[error("peer cert is unrecognized (against pinnedPeerCertSha256)")]
    PinnedCertNotFound,

    /// pinned 证书或 root CA 校验：peer 证书无效。
    #[error("peer cert is invalid ({against})")]
    PeerCertInvalid { against: &'static str },

    /// uTLS 指纹不支持（任务描述中提到的指纹名不在 `PresetFingerprints`/
    /// `ModernFingerprints`/`OtherFingerprints` 三张表里）。
    #[error("unknown uTLS fingerprint: {0}")]
    UnknownFingerprint(String),

    /// uTLS 指纹伪装未接真实库——预留变体。
    ///
    /// `u_client` 工厂当前 fallback 到标准 rustls 握手，
    /// 不会返回本错误。真实 uTLS 待 REALITY 任务再接 watfaq-rustls。
    #[error("uTLS handshake not yet implemented in Rust")]
    UtlsNotImplemented,

    /// OCSP stapling 初始化失败（证书链不足、解析错误等）。
    #[error("OCSP stapling init failed: {0}")]
    OcspStaplingInit(String),

    /// OCSP 响应获取失败（网络/解析错误等）。
    #[error("OCSP response fetch failed: {0}")]
    OcspResponseFetch(String),

    /// PEM 证书/密钥加载失败。
    #[error("failed to load PEM: {0}")]
    PemLoad(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_messages_match_go() {
        // 关键错误消息保持英文 + 与 Go 版本一致，方便日志对照。
        assert_eq!(
            TlsError::NoCertificates.to_string(),
            "no certificates configured"
        );
        assert_eq!(
            TlsError::InvalidEchKeyLength.to_string(),
            "invalid ECH key length"
        );
        assert_eq!(
            TlsError::PinnedCertNotFound.to_string(),
            "peer cert is unrecognized (against pinnedPeerCertSha256)"
        );
        assert!(TlsError::UnknownFingerprint("foo".into())
            .to_string()
            .contains("foo"));
    }

    #[test]
    fn peer_cert_invalid_carries_context() {
        let e = TlsError::PeerCertInvalid {
            against: "root CAs and verifyPeerCertByName",
        };
        assert!(e.to_string().contains("root CAs"));
    }
}
