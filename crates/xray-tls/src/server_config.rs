//! 从 `streamSettings` 安全配置构建 `rustls::ServerConfig`。
//!
//! 对应 Go `transport/internet/tls/config.go::ConfigFromStreamSettings` (server side) +
//! `getNewGetCertificateFunc`（SNI 多证书选择）。

use std::io;
use std::sync::Arc;

use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::certificate::{
    entry_certs_and_key, entry_usage, generate_self_signed_cert, EntryUsage,
    extract_cert_names,
};
use crate::config::security_params;

// ============================================================
// NamedCertKey：rustls CertifiedKey + 预提取的 SNI 名称
// ============================================================

/// 一张服务端证书及其可用于 SNI 匹配的名称集合（CN + DNS SAN，全小写）。
///
/// 对应 Go `BuildCertificates` 产出的 `[]*tls.Certificate`（每张带 `Leaf`）。
#[derive(Debug, Clone)]
pub struct NamedCertKey {
    /// rustls 签名证书链 + 私钥。
    pub key: Arc<CertifiedKey>,
    /// `Leaf.Subject.CommonName` 与 `Leaf.DNSNames` 的并集，全小写。
    pub names: Vec<String>,
}

impl NamedCertKey {
    /// 从 PEM 解析出的证书链 + 私钥构造。
    fn from_cert_der(
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> io::Result<Self> {
        let signing = rustls::crypto::ring::sign::any_supported_type(&key)
            .map_err(|e| io::Error::other(format!("unsupported private key: {e}")))?;
        let names = cert_names(&certs);
        Ok(Self {
            key: Arc::new(CertifiedKey::new(certs, signing)),
            names,
        })
    }
}

/// 取叶子证书（链首）的 CN + DNS SAN，全小写。无名称返回空。
fn cert_names(certs: &[CertificateDer<'static>]) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(leaf) = certs.first() {
        let (cn, sans) = extract_cert_names(leaf);
        // CN 与 SAN 可重复（rcgen 把首个 SAN 也设为 CN），去重避免匹配混淆。
        for name in cn.into_iter().chain(sans) {
            if !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out
}

// ============================================================
// SNI 证书选择（对应 Go getNewGetCertificateFunc）
// ============================================================

/// rustls [`ResolvesServerCert`]：按 SNI 从多张证书中选择，支持通配符。
///
/// 对应 Go `getNewGetCertificateFunc`（无 CA 动态签发的静态多证书路径）。
/// 匹配规则与 Go 一致：
/// 1. 无证书 → `None`
/// 2. 非 `reject_unknown` 且（仅一张证书 **或** 客户端未发 SNI）→ 首张
/// 3. 精确匹配 SNI（CN/SAN）→ 命中
/// 4. 通配符匹配（`sub.example.com` → `*.example.com`）→ 命中
/// 5. `reject_unknown` → `None`，否则回退首张
#[derive(Debug)]
pub struct SniCertResolver {
    entries: Vec<NamedCertKey>,
    reject_unknown: bool,
}

impl SniCertResolver {
    /// 从命名证书列表构造。`reject_unknown` 对应 Go `Config.RejectUnknownSni`。
    #[must_use]
    pub fn new(entries: Vec<NamedCertKey>, reject_unknown: bool) -> Self {
        Self {
            entries,
            reject_unknown,
        }
    }

    /// 条目数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 纯 SNI 选择：按 `sni`（已小写或原样）选出命中条目。便于单测。
    fn select(&self, sni: Option<&str>) -> Option<&NamedCertKey> {
        if self.entries.is_empty() {
            return None;
        }
        let lower = sni.map(str::to_lowercase);
        // Go: !rejectUnknownSni && (len==1 || sni=="") → certs[0]
        if !self.reject_unknown
            && (self.entries.len() == 1 || lower.as_deref().map_or(true, str::is_empty))
        {
            return Some(&self.entries[0]);
        }
        let lower = lower?;
        // 通配符："sub.example.com" → "*.example.com"（首个点之后）
        let wildcard = match lower.find('.') {
            Some(idx) => format!("*{}", &lower[idx..]),
            None => String::from("*"),
        };
        for entry in &self.entries {
            if entry.names.iter().any(|n| n == &lower || n == &wildcard) {
                return Some(entry);
            }
        }
        if self.reject_unknown {
            None
        } else {
            Some(&self.entries[0])
        }
    }
}

impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        // 仅取 DNS 类型的 SNI，统一小写
        let sni: Option<String> = client_hello.server_name().map(|sn| sn.to_lowercase());
        self.select(sni.as_deref()).map(|e| Arc::clone(&e.key))
    }
}

// ============================================================
// build_server_config
// ============================================================

/// 从 `streamSettings` 的安全配置构建 rustls `ServerConfig`。
///
/// # 参数
/// - `security`：安全层名（`"none"` / `"tls"` / `"reality"`）。非 `"tls"` / `"reality"` 返回 `None`。
/// - `security_json`：`tlsSettings` 的 JSON 值。
///
/// # 返回
/// - `Ok(None)`：不需要 TLS
/// - `Ok(Some(Arc<ServerConfig>))`：构建成功
/// - `Err`：配置解析错误
///
/// # 证书来源
/// - `certificates[].certificateFile + keyFile`：可配置多张（启用 SNI 选择）
/// - 顶层 `cert` + `key`：单张内联 PEM（anytls 等用）
/// - 均缺失：回退自签名证书（`localhost` / `127.0.0.1`），便于本地与测试。
///
/// # 热重载 / OCSP ticker
/// 对应 Go `setupOcspTicker` 的后台热重载 + OCSP 刷新当前留作 TODO：
/// 需把 resolver 包进 `arc_swap::ArcSwap` 并 spawn tokio 定时任务重新读取
/// `certificatePath`/`keyPath` 后原子替换。OCSP 装订已由 `ocsp-stapler`（`ocsp-stapling`
/// feature）在握手层实现，参见 [`crate::ocsp_stapling`]。
pub fn build_server_config(
    security: &str,
    security_json: Option<&serde_json::Value>,
) -> io::Result<Option<Arc<ServerConfig>>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    if !matches!(security, "tls" | "reality") {
        return Ok(None);
    }

    let json = security_json.cloned().unwrap_or(serde_json::Value::Null);
    let reject_unknown = json
        .get("rejectUnknownSni")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let mut entries = build_named_cert_keys(&json)?;

    // 无证书配置：回退自签名（保证 TLS 服务端总能启动，对齐 REALITY 的可用性）
    if entries.is_empty() {
        let (cert_pem, key_pem) = generate_self_signed_cert(&["localhost", "127.0.0.1"])?;
        entries.push(NamedCertKey::from_cert_der(
            pem_certs(cert_pem.as_bytes())?,
            pem_key(key_pem.as_bytes())?,
        )?);
    }

    // minVersion/maxVersion/cipherSuites/curvePreferences → 自定义 provider + 版本列表
    let (provider, versions) = security_params(&json);

    let resolver = Arc::new(SniCertResolver::new(entries, reject_unknown));
    let builder = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .map_err(|e| io::Error::other(format!("protocol versions: {e}")))?;

    // mTLS：`usage:"verify"` 条目构成客户端 CA 池时要求并验证客户端证书。
    // Go v26 无服务端 mTLS（全仓无 ClientAuth），此处为 Rust 扩展——显式 opt-in，
    // 未配置 verify 条目时保持 with_no_client_auth，既有配置行为不变。
    let client_ca = client_ca_root_store(&json)?;
    let builder = if client_ca.is_empty() {
        builder.with_no_client_auth()
    } else {
        let verifier = WebPkiClientVerifier::builder(Arc::new(client_ca))
            .build()
            .map_err(|e| io::Error::other(format!("client CA verifier: {e}")))?;
        builder.with_client_cert_verifier(verifier)
    };
    let mut config = builder.with_cert_resolver(resolver);

    // alpn：对齐 Go GetTLSConfig——NextProtos 取 tlsSettings.alpn，
    // 为空时默认 ["h2", "http/1.1"]（WS/httpupgrade 依赖 http/1.1，gRPC 依赖 h2）。
    config.alpn_protocols = parse_alpn(&json)?;

    Ok(Some(Arc::new(config)))
}

/// 解析 `tlsSettings.alpn` 数组；缺失或非数组时用默认 `["h2", "http/1.1"]`。
///
/// 对应 Go `GetTLSConfig`：`config.NextProtos = c.NextProtocol`（JSON `alpn`），
/// 仍为空则 fallback `[]string{"h2", "http/1.1"}`。与 client_config.rs 行为对称。
fn parse_alpn(json: &serde_json::Value) -> io::Result<Vec<Vec<u8>>> {
    if let Some(arr) = json.get("alpn").and_then(|v| v.as_array()) {
        arr.iter()
            .map(|s| {
                s.as_str()
                    .map(|x| x.as_bytes().to_vec())
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "alpn array must contain only strings",
                        )
                    })
            })
            .collect()
    } else {
        Ok(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
    }
}

/// 从 `tlsSettings` JSON 解析全部命名证书。
///
/// 优先 `certificates[]`（file 或内联，支持多张，仅 `usage:"encipherment"`）；
/// 若该数组为空且顶层存在内联 `cert`+`key`，则解析单张。
fn build_named_cert_keys(json: &serde_json::Value) -> io::Result<Vec<NamedCertKey>> {
    let mut out = Vec::new();
    if let Some(arr) = json.get("certificates").and_then(|v| v.as_array()) {
        for entry in arr {
            // Go BuildCertificates：仅 ENCIPHERMENT 条目用作服务端证书，
            // "verify"（mTLS 客户端 CA）/"issue" 条目不参与。
            if entry_usage(entry) != EntryUsage::Encipherment {
                continue;
            }
            let (certs, key) = entry_certs_and_key(entry)?;
            match key {
                Some(key) => out.push(NamedCertKey::from_cert_der(certs, key)?),
                None => tracing::warn!(
                    "certificates[] encipherment entry has certificate but no key; skipped"
                ),
            }
        }
    }
    if out.is_empty() {
        if let (Some(cert_str), Some(key_str)) = (
            json.get("cert").and_then(|x| x.as_str()),
            json.get("key").and_then(|x| x.as_str()),
        ) {
            out.push(NamedCertKey::from_cert_der(
                pem_certs(cert_str.as_bytes())?,
                pem_key(key_str.as_bytes())?,
            )?);
        }
    }
    Ok(out)
}

/// `certificates[]` 中 `usage:"verify"` 条目 → 客户端 CA 信任池（mTLS，Rust 扩展）。
///
/// 条目非法（内联类型错误/内容缺失/PEM 无证书块）→ `Err` 传播——对齐 Go：
/// `TLSCertConfig.Build` 在配置加载期报错，不在池构建层静默吞掉；条目内
/// 单张 DER 不被信任仅跳过（对齐 Go 逐条 `AppendCertsFromPEM` 容错）。
///
/// # Errors
/// 条目解析失败时传播。
fn client_ca_root_store(json: &serde_json::Value) -> io::Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    if let Some(arr) = json.get("certificates").and_then(|v| v.as_array()) {
        for entry in arr {
            if entry_usage(entry) != EntryUsage::Verify {
                continue;
            }
            let (certs, _) = entry_certs_and_key(entry)?;
            for der in certs {
                let _ = store.add(der);
            }
        }
    }
    Ok(store)
}

/// 从 PEM 字节解析全部证书。
fn pem_certs(pem: &[u8]) -> io::Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut pem.as_ref())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io::Error::other(format!("parse cert PEM: {e}")))
}

/// 从 PEM 字节解析单个私钥。
fn pem_key(pem: &[u8]) -> io::Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut pem.as_ref())
        .map_err(|e| io::Error::other(format!("parse key PEM: {e}")))?
        .ok_or_else(|| io::Error::other("no private key found in PEM"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn install_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    /// 用 rcgen 生成一张叶子证书（SAN 列表），返回 (cert_pem, key_pem)。
    fn leaf_cert(sans: &[&str]) -> (String, String) {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(
            sans.iter().map(|s| s.to_string()).collect::<Vec<String>>(),
        )
        .unwrap();
        // 设 CN = 首个 SAN，避免 rcgen 默认 CN "rcgen self signed cert" 污染 names。
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, sans[0]);
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }

    /// 从 PEM 构造 NamedCertKey。
    fn named(cert_pem: &str, key_pem: &str) -> NamedCertKey {
        NamedCertKey::from_cert_der(
            pem_certs(cert_pem.as_bytes()).unwrap(),
            pem_key(key_pem.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn none_security_returns_none() {
        assert!(build_server_config("none", None).unwrap().is_none());
    }

    #[test]
    fn empty_security_returns_none() {
        assert!(build_server_config("", None).unwrap().is_none());
    }

    #[test]
    fn server_config_defaults_alpn() {
        let config =
            build_server_config("tls", Some(&serde_json::json!({}))).unwrap().unwrap();
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn server_config_parses_alpn() {
        let json = serde_json::json!({ "alpn": ["h2"] });
        let config = build_server_config("tls", Some(&json)).unwrap().unwrap();
        assert_eq!(config.alpn_protocols, vec![b"h2".to_vec()]);
    }

    #[test]
    fn server_config_alpn_invalid_type_returns_err() {
        let json = serde_json::json!({ "alpn": ["h2", 123] });
        assert!(build_server_config("tls", Some(&json)).is_err());
    }

    #[test]
    fn tls_without_certificates_falls_back_to_self_signed() {
        // 无证书配置 → 回退自签名（不再报错），保证服务端可启动
        let config = build_server_config("tls", Some(&serde_json::json!({}))).unwrap();
        assert!(config.is_some());
    }

    #[test]
    fn tls_invalid_inline_cert_errors_instead_of_silent_fallback() {
        // Go：certificates 条目类型非法 = JSON 反序列化到 []string 失败 = 配置加载 error。
        // 对齐：非法内联必须报错，不得静默回退自签证书。
        let config = build_server_config(
            "tls",
            Some(&serde_json::json!({ "certificates": [{ "certificate": [1, 2, 3] }] })),
        );
        assert!(config.is_err(), "非法内联数字数组必须报错");
    }

    #[test]
    fn tls_with_inline_pem_works() {
        let (cert_pem, key_pem) = leaf_cert(&["localhost"]);
        let json = serde_json::json!({ "cert": cert_pem, "key": key_pem });
        let config = build_server_config("tls", Some(&json)).unwrap();
        assert!(config.is_some());
    }

    #[test]
    fn named_cert_key_extracts_leaf_names() {
        // 验证 CN + SAN 被提取为小写
        let (cert_pem, key_pem) = leaf_cert(&["Example.COM", "www.Example.COM"]);
        let n = named(&cert_pem, &key_pem);
        // rcgen 把 SAN 放进证书；CN 默认取第一个 SAN
        assert!(n.names.iter().any(|x| x == "example.com"));
        assert!(n.names.iter().any(|x| x == "www.example.com"));
    }

    // ----- SNI 多证书选择测试（验收项） -----

    #[test]
    fn sni_single_cert_no_sni_returns_first() {
        install_provider();
        let e = named(&leaf_cert(&["a.com"]).0, &leaf_cert(&["a.com"]).1);
        let r = SniCertResolver::new(vec![e], false);
        // 单证书：无论 SNI 与否都返回首张
        assert!(r.select(None).is_some());
        assert!(r.select(Some("anything.com")).is_some());
    }

    #[test]
    fn sni_exact_match_selects_right_cert() {
        install_provider();
        let (c1, k1) = leaf_cert(&["a.example.com"]);
        let (c2, k2) = leaf_cert(&["b.example.com"]);
        let e1 = named(&c1, &k1);
        let e2 = named(&c2, &k2);
        let r = SniCertResolver::new(vec![e1, e2], false);

        let got = r.select(Some("b.example.com")).unwrap();
        assert_eq!(got.names, vec!["b.example.com".to_string()]);
    }

    #[test]
    fn sni_wildcard_match_selects_right_cert() {
        install_provider();
        // 证书 1：*.example.com 通配
        let (cw, kw) = leaf_cert(&["*.example.com"]);
        // 证书 2：精确 other.org
        let (ce, ke) = leaf_cert(&["exact.other.org"]);
        let ew = named(&cw, &kw);
        let ee = named(&ce, &ke);
        let r = SniCertResolver::new(vec![ew, ee], false);

        // sub.example.com → 匹配 *.example.com（ew）
        let got = r.select(Some("sub.example.com")).unwrap();
        assert_eq!(got.names, vec!["*.example.com".to_string()]);

        // exact.other.org → 精确匹配（ee），非 wildcard
        let got2 = r.select(Some("exact.other.org")).unwrap();
        assert_eq!(got2.names, vec!["exact.other.org".to_string()]);
    }

    #[test]
    fn sni_case_insensitive_match() {
        install_provider();
        let (c, k) = leaf_cert(&["example.com"]);
        let e = named(&c, &k);
        let r = SniCertResolver::new(vec![e.clone(), named(&leaf_cert(&["other.com"]).0, &leaf_cert(&["other.com"]).1)], false);

        // 大写 SNI 应回落小写后匹配
        let got = r.select(Some("EXAMPLE.COM")).unwrap();
        assert_eq!(got.names, e.names);
    }

    #[test]
    fn sni_unknown_falls_back_to_first_when_not_reject() {
        install_provider();
        let e1 = named(&leaf_cert(&["a.com"]).0, &leaf_cert(&["a.com"]).1);
        let e2 = named(&leaf_cert(&["b.com"]).0, &leaf_cert(&["b.com"]).1);
        let r = SniCertResolver::new(vec![e1, e2], false);

        let got = r.select(Some("nomatch.com")).unwrap();
        assert_eq!(got.names, vec!["a.com".to_string()]);
    }

    #[test]
    fn sni_unknown_rejected_when_reject_unknown() {
        install_provider();
        let e1 = named(&leaf_cert(&["a.com"]).0, &leaf_cert(&["a.com"]).1);
        let e2 = named(&leaf_cert(&["b.com"]).0, &leaf_cert(&["b.com"]).1);
        let r = SniCertResolver::new(vec![e1, e2], true);

        assert!(r.select(Some("nomatch.com")).is_none());
        // 精确匹配仍应命中
        assert!(r.select(Some("a.com")).is_some());
    }

    #[test]
    fn sni_empty_entries_resolves_none() {
        install_provider();
        let r = SniCertResolver::new(vec![], false);
        assert!(r.select(Some("a.com")).is_none());
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }
}
