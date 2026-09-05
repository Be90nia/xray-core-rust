//! TLS 证书使用方式与辅助函数。
//!
//! 翻译自 Go `transport/internet/tls/config.go` + `infra/conf/transport_internet.go`
//! 中与证书相关的部分：
//! - `generate_self_signed_cert`：rcgen 自签（Go `tls.go::Generate`）
//! - `generate_self_signed_cert_with_options`：支持 is_ca/org/CN/expire 的变体，
//!   对应 Go `main/commands/all/tls/cert.go::executeCert` 的 flag 选项
//! - `extract_cert_names`：CN + DNS SAN 提取（SNI 选择用）
//! - `EntryUsage` + `entry_usage` + `entry_certs_and_key`：`certificates[]` 条目
//!   的 usage 分类与 file-or-inline 读取（Go `TLSCertConfig.Build` + `readFileOrString`）
//!
//! **已删除**（bd yuz 死代码清理，全仓零调用方）：`CertificateUsage` proto wrapper、
//! `is_encipherment`/`is_authority_issue`、`issue_certificate`（AUTHORITY_ISSUE 动态
//! 签发路径 `getGetCertificateFunc` 为非目标）、`is_certificate_expired`（热重载 ticker
//! 专用，热重载为已知技术债）、`load_self_cert_pool`（被 DER 直加 `RootCertStore` 取代）。
//! 钉扎校验 [`crate::config::verify_chain`] 由 `client_config` 的钉扎 verifier 接入。
//!
//! # 副作用
//!
//! `generate_self_signed_cert*` 是**确定性 + 无 I/O 副作用**的纯计算：rcgen 在内存
//! 里构造 `CertificateParams` + 生成临时 `KeyPair` + 私钥签名 → 输出 PEM 文本。
//! 调用方若要落盘需自行 `fs::write`。
use std::io;
use std::time::Duration as StdDuration;

use rcgen::{BasicConstraints, IsCa, KeyUsagePurpose};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

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
/// `generate_self_signed_cert_with_options` 的可选参数。
///
/// 对应 Go `main/commands/all/tls/cert.go::executeCert` 的 flag：
/// - `common_name` ↔ `--name`（CN；默认 "Xray Inc"）
/// - `organization` ↔ `--org`（O；默认 "Xray Inc"）
/// - `is_ca` ↔ `--ca`（CA 证书，签发能力 + key usages CertSign/KeyEncipherment/DigitalSignature）
/// - `not_after` ↔ `--expire`（自此刻起的有效期，std 库 Duration）
#[derive(Debug, Clone)]
pub struct CertOptions {
    pub common_name: String,
    pub organization: String,
    pub is_ca: bool,
    pub not_after: StdDuration,
}

impl Default for CertOptions {
    fn default() -> Self {
        Self {
            common_name: "Xray Inc".to_string(),
            organization: "Xray Inc".to_string(),
            is_ca: false,
            not_after: StdDuration::from_secs(90 * 24 * 60 * 60),
        }
    }
}

/// 生成自签名证书（带 options）。
///
/// 对应 Go `main/commands/all/tls/cert.go::executeCert`。
/// 返回 `(cert_pem, key_pem)`。
pub fn generate_self_signed_cert_with_options(
    domains: &[String],
    opts: &CertOptions,
) -> io::Result<(String, String)> {
    let mut params = rcgen::CertificateParams::new(domains.to_vec())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        opts.common_name.clone(),
    );
    params.distinguished_name.push(
        rcgen::DnType::OrganizationName,
        opts.organization.clone(),
    );
    let not_after = time::OffsetDateTime::now_utc()
        + time::Duration::try_from(opts.not_after).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("not_after: {e}"))
        })?;
    params.not_after = not_after;
    if opts.is_ca {
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::KeyEncipherment,
            KeyUsagePurpose::DigitalSignature,
        ];
    }
    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}


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

// ============================================================
// certificates[] 条目解析（对应 Go TLSCertConfig.Build / readFileOrString）
// ============================================================

/// `certificates[]` 条目的 `usage` 分类。
///
/// 对应 Go `TLSCertConfig.Build` 的字符串映射：
/// - `"encipherment"`（默认，未知值也回落到此）：服务端加密证书。
/// - `"verify"`：**Rust 扩展**——Go 的 `AUTHORITY_VERIFY` 在 v26 无任何消费方；
///   Rust 用作 mTLS 客户端 CA（`server_config` 以此 opt-in 要求客户端证书）。
/// - `"issue"`：Go `AUTHORITY_ISSUE` 动态签发 CA；Rust 未实现动态签发，
///   目前仅用于把条目从服务端证书集合中排除（对齐 Go `BuildCertificates` 过滤）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryUsage {
    /// 用作服务端加密证书（TLS 握手中送出的实际证书）。
    Encipherment,
    /// 用作验证客户端证书的 CA（mTLS）。
    Verify,
    /// 动态签发 CA（未实现动态签发，仅参与过滤）。
    Issue,
}

/// 解析条目 `usage`（大小写不敏感）。
///
/// 未知值回落 [`EntryUsage::Encipherment`]——对齐 Go `Build` 的 `default` 分支。
pub fn entry_usage(entry: &serde_json::Value) -> EntryUsage {
    match entry
        .get("usage")
        .and_then(|v| v.as_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("verify") => EntryUsage::Verify,
        Some("issue") => EntryUsage::Issue,
        _ => EntryUsage::Encipherment,
    }
}

/// 读取 file-or-inline 字段：`xxxFile`（磁盘路径）优先，否则内联 `xxx`。
///
/// 内联值支持 string 或 string 数组（数组按 Go `readFileOrString` 用 `\n` 连接，
/// 即 PEM 按行拆成数组元素的写法）。字段缺失或显式 `null` 返回 `Ok(None)`。
///
/// 内联类型非法（非 string、非字符串数组，如数字数组）→ `Err`。对齐 Go
/// `TLSCertConfig.CertStr []string`（infra/conf/transport_security.go:250）：
/// JSON 反序列化类型不匹配在配置加载期即报错，不存在"静默跳过、回退自签"路径。
fn file_or_inline(
    file: Option<&str>,
    inline: Option<&serde_json::Value>,
    what: &str,
) -> io::Result<Option<Vec<u8>>> {
    if let Some(f) = file {
        return std::fs::read(f)
            .map(Some)
            .map_err(|e| io::Error::other(format!("read {what} file {f}: {e}")));
    }
    match inline {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) => {
            if s.is_empty() {
                // Go: "" 无法反序列化为 []string → 配置错误
                return Err(io::Error::other(format!("{what}: empty inline value")));
            }
            Ok(Some(s.clone().into_bytes()))
        }
        Some(serde_json::Value::Array(items)) => {
            let mut lines = Vec::with_capacity(items.len());
            for v in items {
                let Some(s) = v.as_str() else {
                    return Err(io::Error::other(format!(
                        "{what}: expected string or array of PEM lines, got {v}"
                    )));
                };
                lines.push(s);
            }
            Ok(Some(lines.join("\n").into_bytes()))
        }
        Some(other) => Err(io::Error::other(format!(
            "{what}: expected string or array of PEM lines, got {other}"
        ))),
    }
}

/// 从 PEM 解析私钥，对齐 Go `tls.X509KeyPair`：PEM 标签仅作提示，按 DER 内容
/// 识别实际格式。
///
/// rustls-pemfile 纯按 PEM 标签分发（`RSA PRIVATE KEY` → Pkcs1），而 Go `tls cert`
/// 生成的 PEM 是错标的（RSA 标签 + SEC1 EC 内容，Go `X509KeyPair` 逐格式尝试所以
/// 自家能用）。错标交 rustls-pemfile 后被错误定形为 Pkcs1，签名密钥解析按 RSA 走
/// 必败（"failed to parse private key as RSA, ECDSA, or EdDSA"）。此处用
/// [`PrivateKeyDer::try_from`]（官方 DER 内容嗅探：跳过外层 SEQUENCE 头后按
/// version 模式识别 Pkcs8/Pkcs1/Sec1）重新定形；内容无法识别时保留原标签结果，
/// 正确标签路径行为不变。
pub(crate) fn pem_private_key(pem: &[u8]) -> io::Result<Option<PrivateKeyDer<'static>>> {
    let key = rustls_pemfile::private_key(&mut pem.as_ref())
        .map_err(|e| io::Error::other(format!("parse key PEM: {e}")))?;
    Ok(key.map(|k| PrivateKeyDer::try_from(k.secret_der().to_vec()).unwrap_or(k)))
}

/// 解析单个 `certificates[]` 条目 → `(证书链, 可选私钥)`。
///
/// 对应 Go `TLSCertConfig.Build`（infra/conf/transport_security.go:260-298）：
/// `certificateFile`+`keyFile`（磁盘）或 `certificate`+`key`（内联）。
///
/// - 证书内容缺失（无 file 且无内联/内联为空）→ `Err`——对齐 Go
///   `readFileOrString` 的 "both file and bytes are empty." → Build error；
///   Go 中无内容条目不存在跳过语义，配置直接加载失败。
/// - PEM 解析出 0 张证书 → `Err`（Go 侧空内容透传后在 X509KeyPair 层报错；
///   宁可启动报错也不静默回退自签证书）。
/// - key 缺失 → key 为 `None`——`usage:"verify"` 的 CA 条目合法地不带私钥
///   （Go 仅在 `len(KeyFile)>0 || len(KeyStr)>0` 时才读取 key）。
///
/// # Errors
/// - 证书/私钥文件读取失败、内联类型非法或 PEM 解析失败/无证书块。
pub fn entry_certs_and_key(
    entry: &serde_json::Value,
) -> io::Result<(Vec<CertificateDer<'static>>, Option<PrivateKeyDer<'static>>)> {
    let cert_bytes = file_or_inline(
        entry.get("certificateFile").and_then(|v| v.as_str()),
        entry.get("certificate"),
        "certificate",
    )?;
    let Some(cert_bytes) = cert_bytes else {
        return Err(io::Error::other(
            "certificate: both file and inline content are empty",
        ));
    };
    let certs = rustls_pemfile::certs(&mut cert_bytes.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io::Error::other(format!("parse cert PEM: {e}")))?;
    if certs.is_empty() {
        return Err(io::Error::other(
            "certificate: no PEM certificate block found",
        ));
    }

    let key_bytes = file_or_inline(
        entry.get("keyFile").and_then(|v| v.as_str()),
        entry.get("key"),
        "key",
    )?;
    let key = match key_bytes {
        Some(b) => pem_private_key(&b)?,
        None => None,
    };
    Ok((certs, key))
}


#[cfg(test)]
mod tests {
    use super::*;

    fn leaf_der(sans: &[&str]) -> Vec<u8> {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(sans.iter().map(|s| (*s).to_string()).collect::<Vec<String>>()).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, sans[0]);
        params.self_signed(&key).unwrap().der().to_vec()
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

    // ---- certificates[] 条目非法内联格式 → Err（对齐 Go TLSCertConfig.Build）----

    fn cert_entry(inline: serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "certificate": inline })
    }

    #[test]
    fn entry_rejects_numeric_array_inline() {
        // ServerMatrix 实测场景：PEM 写成数字数组 → Go 侧 unmarshal error，
        // Rust 侧必须报错而非静默回退自签证书。
        let e = cert_entry(serde_json::json!([1, 2, 3]));
        assert!(entry_certs_and_key(&e).is_err());
    }

    #[test]
    fn entry_rejects_scalar_inline() {
        for e in [
            cert_entry(serde_json::json!(12345)),
            cert_entry(serde_json::json!(true)),
            cert_entry(serde_json::json!({"pem": "x"})),
        ] {
            assert!(entry_certs_and_key(&e).is_err(), "scalar inline must error");
        }
    }

    // ---- 私钥解析：错标 PEM 按 DER 内容重定形（对齐 Go X509KeyPair）----

    /// Go `tls cert` v26.7.28 的实际产出（D:/tmp/interop_key.pem）：RSA PEM 标签
    /// + PKCS#8 包装的 EC P-256 内容（DER 以 30 81 87 02 01 00 30 开头——Go 侧
    /// X509KeyPair 不看标签照样能用）。
    const MISLABELED_EC_KEY_PEM: &str = "\
-----BEGIN RSA PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg6sUhV38mcGUNG/uc
aZ9A3Sng12a1YFnJcLOELh+loNChRANCAATG2iorYlDeMjaVlb7XdvtKt1Og/t5H
45rFCy1LsSXiGo2MktbCiNQHg972FJTwSy5QLYLcuKBbveAMQyiwAs3C
-----END RSA PRIVATE KEY-----
";

    /// 纯 SEC1（ECPrivateKey，DER 以 30 6b 02 01 01 04 开头），内容取自上一
    /// fixture 内嵌的 EC 私钥（EC PRIVATE KEY 正确标签）。
    const SEC1_EC_KEY_PEM: &str = "\
-----BEGIN EC PRIVATE KEY-----
MGsCAQEEIOrFIVd/JnBlDRv7nGmfQN0p4NdmtWBZyXCzhC4fpaDQoUQDQgAExtoq
K2JQ3jI2lZW+13b7SrdToP7eR+OaxQstS7El4hqNjJLWwojUB4Pe9hSU8EsuUC2C
3LigW73gDEMosALNwg==
-----END EC PRIVATE KEY-----
";

    #[test]
    fn mislabeled_rsa_tag_ec_content_resolved_as_pkcs8() {
        let key = pem_private_key(MISLABELED_EC_KEY_PEM.as_bytes()).unwrap().unwrap();
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
    }

    #[test]
    fn correctly_labeled_ec_key_resolved_as_sec1() {
        let key = pem_private_key(SEC1_EC_KEY_PEM.as_bytes()).unwrap().unwrap();
        assert!(matches!(key, PrivateKeyDer::Sec1(_)));
    }

    #[test]
    fn correctly_labeled_pkcs8_key_resolved_as_pkcs8() {
        let (_, key_pem) = generate_self_signed_cert(&["localhost"]).unwrap();
        let key = pem_private_key(key_pem.as_bytes()).unwrap().unwrap();
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
    }

    #[test]
    fn entry_rejects_mixed_type_array_inline() {
        let e = cert_entry(serde_json::json!(["-----BEGIN CERTIFICATE-----", 1]));
        assert!(entry_certs_and_key(&e).is_err());
    }

    #[test]
    fn entry_rejects_missing_or_empty_content() {
        // 无 file 且无内联 → Go readFileOrString "both file and bytes are empty"
        assert!(entry_certs_and_key(&serde_json::json!({})).is_err());
        assert!(entry_certs_and_key(&cert_entry(serde_json::json!([]))).is_err());
        assert!(entry_certs_and_key(&cert_entry(serde_json::json!(""))).is_err());
        // 非 PEM 字符串 → 解析出 0 张证书
        assert!(entry_certs_and_key(&cert_entry(serde_json::json!("not a pem"))).is_err());
    }

    #[test]
    fn entry_rejects_bad_key_type_but_allows_missing_key() {
        let (pem, key) = generate_self_signed_cert(&["k.test"]).unwrap();
        let bad_key = serde_json::json!({ "certificate": pem, "key": 42 });
        assert!(entry_certs_and_key(&bad_key).is_err());
        // key 缺失合法（verify CA 条目）
        let no_key = serde_json::json!({ "certificate": pem });
        let (certs, k) = entry_certs_and_key(&no_key).unwrap();
        assert_eq!(certs.len(), 1);
        assert!(k.is_none());
        let _ = key;
    }

    #[test]
    fn entry_accepts_string_and_pem_line_array() {
        let (pem, _) = generate_self_signed_cert(&["ok.test"]).unwrap();
        // 整段字符串
        let (certs, _) = entry_certs_and_key(&cert_entry(serde_json::json!(pem.clone()))).unwrap();
        assert_eq!(certs.len(), 1);
        // PEM 行数组（Go readFileOrString join "\n"）
        let lines: Vec<&str> = pem.lines().collect();
        let (certs2, _) =
            entry_certs_and_key(&cert_entry(serde_json::json!(lines))).unwrap();
        assert_eq!(certs2, certs);
    }


    #[test]
    fn options_default_matches_go_ninety_days() {
        // Go `cmdCert.Flag.Duration("expire", 90d)` 默认 90 天
        assert_eq!(
            CertOptions::default().not_after,
            StdDuration::from_secs(90 * 24 * 60 * 60)
        );
        assert!(!CertOptions::default().is_ca);
        assert_eq!(CertOptions::default().common_name, "Xray Inc");
        assert_eq!(CertOptions::default().organization, "Xray Inc");
    }

    #[test]
    fn with_options_ca_sets_basic_constraints() {
        let (cert_pem, key_pem) = generate_self_signed_cert_with_options(
            &["ca.test".to_string()],
            &CertOptions {
                is_ca: true,
                ..CertOptions::default()
            },
        )
        .unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
        use x509_parser::prelude::FromDer;
        let der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        let (_, cert) =
            x509_parser::certificate::X509Certificate::from_der(&der).unwrap();
        let bc = cert.basic_constraints().unwrap();
        assert!(bc.map(|b| b.value.ca).unwrap_or(false));
    }

    #[test]
    fn with_options_org_and_cn_baked_into_subject() {
        let (cert_pem, _) = generate_self_signed_cert_with_options(
            &["test.example".to_string()],
            &CertOptions {
                common_name: "My CN".to_string(),
                organization: "My Org".to_string(),
                ..CertOptions::default()
            },
        )
        .unwrap();
        use x509_parser::prelude::FromDer;
        let der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        let (_, cert) =
            x509_parser::certificate::X509Certificate::from_der(&der).unwrap();
        let subject = cert.subject().to_string();
        assert!(subject.contains("My Org"), "subject should contain O=My Org: {subject}");
        assert!(subject.contains("My CN"), "subject should contain CN=My CN: {subject}");
    }

    #[test]
    fn with_options_multiple_domains_appear_as_sans() {
        let domains = vec!["a.test".to_string(), "b.test".to_string(), "c.test".to_string()];
        let (cert_pem, _) = generate_self_signed_cert_with_options(
            &domains,
            &CertOptions::default(),
        )
        .unwrap();
        use x509_parser::prelude::FromDer;
        let der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        let (_, cert) =
            x509_parser::certificate::X509Certificate::from_der(&der).unwrap();
        let sans: Vec<String> = cert
            .subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names
            .iter()
            .filter_map(|gn| match gn {
                x509_parser::prelude::GeneralName::DNSName(s) => Some(s.to_string()),
                _ => None,
            })
            .collect();
        assert!(sans.contains(&"a.test".to_string()));
        assert!(sans.contains(&"b.test".to_string()));
        assert!(sans.contains(&"c.test".to_string()));
    }

    #[test]
    fn with_options_zero_duration_succeeds() {
        // not_after=0s 不应 panic；rcgen 接受 not_after = now
        let result = generate_self_signed_cert_with_options(
            &["x".to_string()],
            &CertOptions {
                not_after: StdDuration::from_secs(0),
                ..CertOptions::default()
            },
        );
        assert!(result.is_ok());
    }


    #[test]
    fn entry_usage_mapping() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"usage":"VERIFY"}"#).unwrap();
        assert_eq!(entry_usage(&v), EntryUsage::Verify);
        let v: serde_json::Value = serde_json::from_str(r#"{"usage":"issue"}"#).unwrap();
        assert_eq!(entry_usage(&v), EntryUsage::Issue);
        // 缺失 / 未知 → Encipherment（Go default 分支）
        let v: serde_json::Value = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(entry_usage(&v), EntryUsage::Encipherment);
        let v: serde_json::Value =
            serde_json::from_str(r#"{"usage":"bogus"}"#).unwrap();
        assert_eq!(entry_usage(&v), EntryUsage::Encipherment);
    }

    #[test]
    fn entry_certs_and_key_inline() {
        let (cert_pem, key_pem) = generate_self_signed_cert(&["localhost"]).unwrap();
        let v = serde_json::json!({ "certificate": cert_pem, "key": key_pem });
        let (certs, key) = entry_certs_and_key(&v).unwrap();
        assert_eq!(certs.len(), 1);
        assert!(key.is_some());
    }

    #[test]
    fn entry_certs_and_key_verify_entry_without_key() {
        // usage:"verify" 的 CA 条目只有证书 → key 为 None，不报错
        let (cert_pem, _) = generate_self_signed_cert(&["ca.test"]).unwrap();
        let v = serde_json::json!({ "certificate": cert_pem, "usage": "verify" });
        let (certs, key) = entry_certs_and_key(&v).unwrap();
        assert_eq!(certs.len(), 1);
        assert!(key.is_none());
    }

    #[test]
    fn entry_certs_and_key_missing_cert_errors() {
        // 对齐 Go：无 file 且无内联 → Build error，不再跳过
        let v = serde_json::json!({ "key": "-----BEGIN PRIVATE KEY-----\n" });
        assert!(entry_certs_and_key(&v).is_err());
    }

    #[test]
    fn entry_certs_and_key_inline_array_lines() {
        // Go 写法：certificate 为 string 数组（PEM 按行拆分）
        let (cert_pem, _) = generate_self_signed_cert(&["localhost"]).unwrap();
        let lines: Vec<&str> = cert_pem.lines().collect();
        let v = serde_json::json!({ "certificate": lines });
        let (certs, _) = entry_certs_and_key(&v).unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn entry_certs_and_key_bad_pem_errors() {
        // 对齐 Go：PEM 无证书块 → Err（宁启动报错不静默回退自签）
        let v = serde_json::json!({ "certificate": "not a pem", "key": "also not" });
        assert!(entry_certs_and_key(&v).is_err());
    }
}
