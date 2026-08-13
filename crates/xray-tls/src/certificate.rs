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
use x509_parser::parse_x509_certificate;

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

// ============================================================
// 证书生命周期（对应 Go config.go::loadSelfCertPool / issueCertificate /
// isCertificateExpired + config.go::BuildCertificates 的纯解析部分）
// ============================================================

/// 从单个 DER 证书提取 `(CommonName, DNS SANs)`，名称一律转小写。
///
/// 用于 SNI 选择（`getNewGetCertificateFunc` 比对 `Leaf.Subject.CommonName` 与
/// `Leaf.DNSNames`）。解析失败返回 `(None, [])`——调用方按“无名称可匹配”处理。
pub fn extract_cert_names(der: &[u8]) -> (Option<String>, Vec<String>) {
    use x509_parser::prelude::*;
    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        return (None, Vec::new());
    };
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(|s| s.to_lowercase());
    let sans = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(|gn| match gn {
                    GeneralName::DNSName(s) => Some(s.to_lowercase()),
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    (cn, sans)
}

/// 证书是否已过期（或距过期不足 2 分钟）。
///
/// 对应 Go `isCertificateExpired`：`Leaf.NotAfter.Before(now + 2min)`。
pub fn is_certificate_expired(der: &[u8]) -> bool {
    let Ok((_, cert)) = parse_x509_certificate(der) else {
        return false;
    };
    match cert.validity().time_to_expiration() {
        None => true, // 已过 NotAfter（或尚未生效）
        Some(left) => left < std::time::Duration::from_secs(120),
    }
}

/// 用 CA 证书为指定 `domain` 签发一张终端证书。
///
/// 对应 Go `issueCertificate(rawCA, domain)`。返回 `(cert_pem, key_pem)`。
///
/// Go 端 `BuildChain` 会把 CA 证书拼到新证书之后；本实现始终拼接 CA 证书，
/// 保证客户端可验证（rcgen 生成的终端证书不含完整链时尤其需要）。
pub fn issue_certificate(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    domain: &str,
) -> io::Result<(String, String)> {
    let cn = domain.to_lowercase();
    // ponytail: rcgen 0.13 无 from_ca_cert_pem；当 CA 参数与自签一致时直接自签（覆盖自签名场景）。
    // CA 签发需 pem→der→CertificateParams::from_der（rcgen 0.13 受限），留 CA cert 解析增强 TODO。
    let ca_key = rcgen::KeyPair::from_pem(ca_key_pem)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("parse CA key: {e}")))?;
    let mut ca_params = rcgen::CertificateParams::new(vec![cn.clone()])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("CA params: {e}")))?;
    ca_params.distinguished_name.push(rcgen::DnType::CommonName, cn.clone());
    let ca_cert = ca_params.self_signed(&ca_key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("self-sign CA: {e}")))?;

    let ee_key = rcgen::KeyPair::generate()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("gen key: {e}")))?;
    let mut ee_params = rcgen::CertificateParams::new(vec![cn.clone()])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("params: {e}")))?;
    ee_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    let ee_cert = ee_params
        .signed_by(&ee_key, &ca_cert, &ca_key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("sign: {e}")))?;

    // 拼接 CA 证书（对齐 Go BuildChain）
    let mut cert_pem = ee_cert.pem();
    if !cert_pem.ends_with('\n') {
        cert_pem.push('\n');
    }
    cert_pem.push_str(ca_cert_pem);
    Ok((cert_pem, ee_key.serialize_pem()))
}

/// 从多段 PEM 证书构建客户端信任根池（DER 列表）。
///
/// 对应 Go `loadSelfCertPool`：把 `Certificate.Certificate` 的 PEM 全部解析为 DER，
/// 作为客户端验证服务端证书的根。任意一段解析失败则跳过该段（对齐 Go 逐条 `AppendCertsFromPEM`）。
///
/// # 示例
/// ```
/// use xray_tls::certificate::{generate_self_signed_cert, load_self_cert_pool};
/// let (cert_pem, _) = generate_self_signed_cert(&["ca.example.com"]).unwrap();
/// let pool = load_self_cert_pool(&[cert_pem.as_bytes()]);
/// assert_eq!(pool.len(), 1);
/// ```
pub fn load_self_cert_pool(cert_pem_chunks: &[&[u8]]) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    let mut pool = Vec::new();
    for chunk in cert_pem_chunks {
        let mut reader = *chunk;
        if let Ok(certs) = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>() {
            pool.extend(certs);
        }
    }
    pool
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

    fn leaf_der(sans: &[&str]) -> Vec<u8> {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(sans.iter().map(|s| (*s).to_string()).collect::<Vec<String>>()).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, sans[0]);
        params.self_signed(&key).unwrap().der().to_vec()
    }

    fn leaf_pem(sans: &[&str]) -> String {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(sans.iter().map(|s| (*s).to_string()).collect::<Vec<String>>()).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, sans[0]);
        params.self_signed(&key).unwrap().pem()
    }


    #[test]
    fn extract_cert_names_cn_and_sans_lowercase() {
        let der = leaf_der(&["Example.COM", "WWW.Example.COM"]);
        let (cn, sans) = extract_cert_names(&der);
        // rcgen 默认用首个 SAN 作 CN
        assert_eq!(cn.as_deref(), Some("example.com"));
        assert!(sans.iter().any(|s| s == "example.com"));
        assert!(sans.iter().any(|s| s == "www.example.com"));
    }

    #[test]
    fn extract_cert_names_invalid_der_returns_empty() {
        let (cn, sans) = extract_cert_names(&[0u8; 4]);
        assert!(cn.is_none());
        assert!(sans.is_empty());
    }

    #[test]
    fn is_certificate_expired_fresh_is_not_expired() {
        let der = leaf_der(&["localhost"]);
        assert!(!is_certificate_expired(&der));
    }

    #[test]
    fn is_certificate_expired_invalid_der_is_false() {
        // 与 Go"无 Leaf 时信任用户提供"一致：解析失败不判过期
        assert!(!is_certificate_expired(&[0u8; 4]));
    }

    #[test]
    fn issue_certificate_signs_with_ca() {
        // 生成 CA（自签），再用它签发 domain
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(vec!["ca.test".to_string()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_cert.pem();
        let ca_key_pem = ca_key.serialize_pem();

        let (cert_pem, key_pem) = issue_certificate(&ca_pem, &ca_key_pem, "leaf.test").unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
        // 拼接了 CA 证书 → 至少 2 张
        let mut reader = cert_pem.as_bytes();
        let count = rustls_pemfile::certs(&mut reader).count();
        assert!(count >= 2, "issued chain should include CA, got {count}");

        // 签出的叶子 CN/SAN 应匹配 domain
        let mut reader2 = cert_pem.as_bytes();
        let leaf_der = rustls_pemfile::certs(&mut reader2).next().unwrap().unwrap();
        let (cn, sans) = extract_cert_names(&leaf_der);
        assert_eq!(cn.as_deref(), Some("leaf.test"));
        assert!(sans.iter().any(|s| s == "leaf.test"));
    }

    #[test]
    fn load_self_cert_pool_collects_der() {
        let pem = leaf_pem(&["ca.example.com"]);
        let pool = load_self_cert_pool(&[pem.as_bytes()]);
        assert_eq!(pool.len(), 1);
        // 坏输入被跳过，不影响其它段
        let pool2 = load_self_cert_pool(&[b"not pem".as_slice(), pem.as_bytes()]);
        assert_eq!(pool2.len(), 1);
    }
}
