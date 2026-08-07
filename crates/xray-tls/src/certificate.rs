//! TLS 证书使用方式与辅助函数。
//!
//! 翻译自 Go `transport/internet/tls/config.go` 中与 `Certificate` 相关的纯逻辑。
//!
//! # 范围
//! 本模块提供**类型安全**的 `CertificateUsage` enum（包装 prost 生成的 i32 常量），
//! 以及纯函数 helper：`is_encipherment`、`is_authority_issue`、
//! `from_proto_i32`/`to_proto_i32`。
//!
//! **不翻译**：`ParseCertificate`（依赖 `cert.Certificate`，Rust 端无此类型）、
//! `BuildCertificates`（依赖 `tls.X509KeyPair` + `x509.ParseCertificate`）、
//! `setupOcspTicker`（异步后台任务 + 文件 IO）等。等 x509 + tokio 接入后添加。

use xray_proto::xray::transport::internet::tls::Certificate;

/// TLS 证书用途。
///
/// 对应 proto `transport/internet/tls/config.proto` 中 `Certificate.Usage` enum。
/// prost 生成的是 `i32` 常量，这里提供类型安全的 wrapper。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CertificateUsage {
    /// `ENCIPHERMENT = 0`——用作服务端加密证书（TLS 握手中送出的实际证书）。
    Encipherment,
    /// `AUTHORITY_VERIFY = 1`——用作验证客户端证书的 CA。
    AuthorityVerify,
    /// `AUTHORITY_ISSUE = 2`——用作可签发新证书的中间 CA（配合 `getGetCertificateFunc` 动态签发）。
    AuthorityIssue,
}

// prost 生成的常量路径。路径很长，留在这里以备查证。
use xray_proto::xray::transport::internet::tls::certificate::Usage as ProtoUsage;

impl CertificateUsage {
    /// 从 prost 生成的 i32 转换。未知值返回 `None`（与 Go proto 默认值 0 = ENCIPHERMENT 兼容）。
    ///
    /// # 示例
    /// ```
    /// use xray_tls::certificate::CertificateUsage;
    /// assert_eq!(CertificateUsage::from_proto_i32(0), Some(CertificateUsage::Encipherment));
    /// assert_eq!(CertificateUsage::from_proto_i32(2), Some(CertificateUsage::AuthorityIssue));
    /// assert_eq!(CertificateUsage::from_proto_i32(99), None);
    /// ```
    pub fn from_proto_i32(v: i32) -> Option<Self> {
        match v {
            x if x == ProtoUsage::Encipherment as i32 => Some(Self::Encipherment),
            x if x == ProtoUsage::AuthorityVerify as i32 => Some(Self::AuthorityVerify),
            x if x == ProtoUsage::AuthorityIssue as i32 => Some(Self::AuthorityIssue),
            _ => None,
        }
    }

    /// 反向转换回 proto i32 常量。
    pub fn to_proto_i32(self) -> i32 {
        match self {
            Self::Encipherment => ProtoUsage::Encipherment as i32,
            Self::AuthorityVerify => ProtoUsage::AuthorityVerify as i32,
            Self::AuthorityIssue => ProtoUsage::AuthorityIssue as i32,
        }
    }
}

use std::io;

// ============================================================
// 证书生成（对应 Go Generate + GenerateCertFunc）
// ============================================================

/// 生成自签名证书（用于测试或无外部证书配置时）。
///
/// 对应 Go `transport/internet/tls/tls.go::Generate`。
///
/// 返回 `(cert_pem, key_pem)`。
///
/// # 示例
/// ```
/// use xray_tls::certificate::generate_self_signed_cert;
/// let (cert, key) = generate_self_signed_cert(&["localhost", "127.0.0.1"]).unwrap();
/// assert!(cert.contains("BEGIN CERTIFICATE"));
/// assert!(key.contains("BEGIN PRIVATE KEY"));
/// ```
pub fn generate_self_signed_cert(common_names: &[&str]) -> io::Result<(String, String)> {
    let params = rcgen::CertificateParams::new(
        common_names.iter().map(|s| s.to_string()).collect::<Vec<String>>(),
    ).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let cert = params.self_signed(&key_pair)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}
/// `Certificate.usage == ENCIPHERMENT`？
///
/// 对应 Go `BuildCertificates` 中 `if entry.Usage != Certificate_ENCIPHERMENT { continue }`。
///
/// # 示例
/// ```
/// use xray_tls::certificate::is_encipherment;
/// use xray_proto::xray::transport::internet::tls::Certificate;
/// let mut c = Certificate::default();
/// c.usage = 0; // ENCIPHERMENT
/// assert!(is_encipherment(&c));
/// c.usage = 2; // AUTHORITY_ISSUE
/// assert!(!is_encipherment(&c));
/// ```
pub fn is_encipherment(c: &Certificate) -> bool {
    matches!(
        CertificateUsage::from_proto_i32(c.usage),
        Some(CertificateUsage::Encipherment)
    )
}

/// `Certificate.usage == AUTHORITY_ISSUE`？
///
/// 对应 Go `getCustomCA` 中 `if certificate.Usage == Certificate_AUTHORITY_ISSUE`。
pub fn is_authority_issue(c: &Certificate) -> bool {
    matches!(
        CertificateUsage::from_proto_i32(c.usage),
        Some(CertificateUsage::AuthorityIssue)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proto_constants_are_sequential() {
        // proto3 enum 从 0 开始
        assert_eq!(ProtoUsage::Encipherment as i32, 0);
        assert_eq!(ProtoUsage::AuthorityVerify as i32, 1);
        assert_eq!(ProtoUsage::AuthorityIssue as i32, 2);
    }

    #[test]
    fn usage_round_trip() {
        for u in [
            CertificateUsage::Encipherment,
            CertificateUsage::AuthorityVerify,
            CertificateUsage::AuthorityIssue,
        ] {
            let i = u.to_proto_i32();
            assert_eq!(CertificateUsage::from_proto_i32(i), Some(u));
        }
    }

    #[test]
    fn usage_unknown_value_returns_none() {
        assert_eq!(CertificateUsage::from_proto_i32(-1), None);
        assert_eq!(CertificateUsage::from_proto_i32(99), None);
    }

    #[test]
    fn is_encipherment_checks_proto_field() {
        let mut c = Certificate::default();
        c.usage = 0;
        assert!(is_encipherment(&c));
        assert!(!is_authority_issue(&c));

        c.usage = 2;
        assert!(!is_encipherment(&c));
        assert!(is_authority_issue(&c));
    }

    #[test]
    fn is_encipherment_unknown_usage_treated_as_not() {
        // 未知 usage（proto 默认值未初始化时可能）视为非 ENCIPHERMENT，与 Go 一致
        let mut c = Certificate::default();
        c.usage = 99;
        assert!(!is_encipherment(&c));
        assert!(!is_authority_issue(&c));
    }
}
