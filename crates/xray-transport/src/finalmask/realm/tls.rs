//! # realm 信令 TLS 配置（对应 Go `realm.Config.TlsConfig`）
//!
//! Go 侧链路：`infra/conf/transport_finalmask.go:1064-1072`（`TlsConfig.Build()` →
//! proto `xray.transport.internet.tls.Config`）→ `realm/http.go:84-90`
//! （`tr.TLSClientConfig = tlsConfig.GetTLSConfig()`，信令 HTTP 客户端唯一消费点）。
//!
//! 字段对齐以 **Go `GetTLSConfig`（transport/internet/tls/config.go:368-486）在
//! realm 路径实际读取的字段**为准：
//!
//! | Go 字段 | 处理 |
//! |---|---|
//! | `serverName` | 非空且 ≠ url host → 硬错（reqwest 无法把 SNI 与连接主机解耦） |
//! | `allowInsecure` | true → 硬错（Go transport_security.go:362-364 已移除该字段） |
//! | `verifyPeerCertByName` | 非空 → 硬错（reqwest 无自定义验证钩子） |
//! | `alpn` | 应用到 rustls `alpn_protocols`；空回落 `["h2","http/1.1"]`（Go :426-428） |
//! | `pinnedPeerCertSha256` | 叶子证书 SHA-256 钉扎（Go `RandCarrier` + `InsecureSkipVerify` 语义）；CA 钉扎模式（Go `verifyChain` FoundCa）不支持 |
//! | `certificates[].certificate` | PEM → DER 自定义 CA 信任根（Go `getCertPool`） |
//! | `disableSystemRoot` | true = 仅信自定义 CA（Go `loadSelfCertPool`，空池一切验证失败同 Go） |
//! | `minVersion` | 1.2/1.3 收紧 rustls 协议版本；1.0/1.1 rustls 下限 1.2，warn 后按默认 |
//! | `fingerprint` / `maxVersion` / `cipherSuites` / `curvePreferences` / `enableSessionResumption` / `masterKeyLog` / `ech*` / `rejectUnknownSni` / `certificates[].key` | warn 后忽略（Go 读但 reqwest/rustls 预配置无对应能力） |
//!
//! 缺省/null 的 `tlsConfig` → `None` → reqwest 默认 rustls 路径（旧 `use_tls:true`
//! 行为，向后兼容）。

use std::{io, sync::Arc};

use base64::Engine;
use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
    version::{TLS12, TLS13},
};

/// Go `GetTLSConfig` 在无显式 ALPN 时的默认 NextProtos（config.go:426-428）。
const DEFAULT_ALPN: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// realm 信令 TLS 配置结构。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsConfig {
    /// Go `NextProtocol` → ALPN。
    pub alpn: Vec<String>,
    /// Go `PinnedPeerCertSha256` 展开（32 字节/项；叶子证书 SHA-256）。
    pub pinned_peer_cert_sha256: Vec<Vec<u8>>,
    /// `certificates[].certificate` PEM 解出的 DER（自定义 CA 信任根）。
    pub ca_certificates: Vec<Vec<u8>>,
    /// Go `DisableSystemRoot`：true = 仅信自定义 CA。
    pub disable_system_root: bool,
    /// Go `MinVersion` 收紧后的 rustls 协议版本下限。
    pub min_version: Option<MinTlsVersion>,
}

/// `minVersion` 能在 rustls 上生效的取值。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinTlsVersion {
    Tls12,
    Tls13,
}

/// 解析 realm settings 的 `tlsConfig` JSON（标准 xray TLS settings 形状）。
///
/// `json` 为 `None` / `Value::Null` → `Ok(None)`（缺省，Go 侧同为 nil）。
/// `host` 为信令 URL 的 host，用于判定 `serverName` 覆盖是否可安全跳过。
pub fn parse_tls_config(
    json: Option<&serde_json::Value>,
    host: &str,
) -> io::Result<Option<TlsConfig>> {
    let Some(obj) = json.and_then(|v| v.as_object()) else {
        // None / Null / 缺省 → 无 TLS 配置。非对象的 tlsConfig 是配置错误。
        if let Some(v) = json.filter(|v| !v.is_null()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("realm tlsConfig: expected object, got {v}"),
            ));
        }
        return Ok(None);
    };

    // allowInsecure：Go transport_security.go:362-364 已移除（硬错），realm 路径同。
    if obj.get("allowInsecure").and_then(|v| v.as_bool()).unwrap_or(false) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "realm tlsConfig: \"allowInsecure\" is removed, use \
             \"pinnedPeerCertSha256\"(pcs) and \"verifyPeerCertByName\"(vcn) instead",
        ));
    }

    // serverName：SNI 覆盖。reqwest 的 SNI/校验名都来自 URL host，无法解耦；
    // 与 host 相同 = 无操作放行，不同 = 显式拒绝（静默忽略会让 SNI 感知的服务端
    // 握手以难排查的方式失败）。
    if let Some(sn) = obj.get("serverName").and_then(|v| v.as_str()) {
        if !sn.is_empty() && sn != host {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "realm tlsConfig: serverName override {sn:?} is not supported by this \
                     build; keep serverName equal to the url host ({host:?}) or remove it"
                ),
            ));
        }
    }

    if let Some(vcn) = obj.get("verifyPeerCertByName").and_then(|v| v.as_str()) {
        if !vcn.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "realm tlsConfig: \"verifyPeerCertByName\" is not supported by this build; \
                 use pinnedPeerCertSha256 or remove the key",
            ));
        }
    }

    let alpn = match obj.get("alpn").and_then(|v| v.as_array()) {
        Some(arr) => arr
            .iter()
            .map(|s| {
                s.as_str().map(str::to_string).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "realm tlsConfig: alpn array must contain only strings",
                    )
                })
            })
            .collect::<io::Result<Vec<_>>>()?,
        None => Vec::new(),
    };

    let pinned_peer_cert_sha256 = parse_pinned_hashes(obj)?;

    let mut ca_certificates = Vec::new();
    if let Some(arr) = obj.get("certificates").and_then(|v| v.as_array()) {
        for entry in arr {
            let pem = entry.get("certificate").and_then(|v| v.as_str()).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "realm tlsConfig: certificates entry must be an object with a PEM \
                         \"certificate\" string",
                )
            })?;
            ca_certificates.extend(pem_certificates_to_der(pem)?);
        }
    }

    let disable_system_root =
        obj.get("disableSystemRoot").and_then(|v| v.as_bool()).unwrap_or(false);

    // minVersion：1.2/1.3 生效；1.0/1.1 rustls 下限即 1.2（warn 后按默认，Go 侧
    // min 是下限、正常协商都会 ≥1.2）；未知值 Go switch 静默忽略，同。
    let min_version = match obj.get("minVersion").and_then(|v| v.as_str()) {
        Some("1.2") => Some(MinTlsVersion::Tls12),
        Some("1.3") => Some(MinTlsVersion::Tls13),
        Some(v @ ("1.0" | "1.1")) => {
            tracing::warn!(
                target: "xray_transport::realm::tls",
                "realm tlsConfig: minVersion {v:?} is below the rustls floor (TLS 1.2); ignored"
            );
            None
        },
        _ => None,
    };

    // Go GetTLSConfig 读到但本构建无对应能力的字段：一次性 warn，不静默丢。
    const IGNORED: [&str; 10] = [
        "fingerprint",
        "maxVersion",
        "cipherSuites",
        "curvePreferences",
        "enableSessionResumption",
        "masterKeyLog",
        "echConfigList",
        "echServerKeys",
        "echSockopt",
        "rejectUnknownSni",
    ];
    let ignored: Vec<&str> =
        IGNORED.iter().copied().filter(|k| obj.get(*k).is_some_and(|v| !v.is_null())).collect();
    if !ignored.is_empty() {
        tracing::warn!(
            target: "xray_transport::realm::tls",
            "realm tlsConfig: fields {ignored:?} are read by Go GetTLSConfig but not applied \
             by this build; ignored"
        );
    }

    Ok(Some(TlsConfig {
        alpn,
        pinned_peer_cert_sha256,
        ca_certificates,
        disable_system_root,
        min_version,
    }))
}

/// 预配置 rustls `ClientConfig`；无可应用字段返回 `None`（reqwest 默认路径）。
///
/// 有任一可应用字段时必须显式带信任根（预配置会整体替换 reqwest 默认 TLS），
/// 与 Go `getCertPool` 对齐：非 `disableSystemRoot` 时叠加 webpki-roots（本仓
/// "Go nil RootCAs 用系统根" 的既有 webpki-roots 等价决策）。
pub fn build_rustls_client_config(tls: &TlsConfig) -> io::Result<Option<ClientConfig>> {
    let applicable = !tls.alpn.is_empty()
        || !tls.pinned_peer_cert_sha256.is_empty()
        || !tls.ca_certificates.is_empty()
        || tls.disable_system_root
        || tls.min_version.is_some();
    if !applicable {
        return Ok(None);
    }

    // ring provider 经 xray-common 集中入口幂等安装（bd jrh7，与 xray-tls 同惯例）。
    xray_common::ensure_default_crypto_provider();

    let versions: &[&'static rustls::SupportedProtocolVersion] =
        if tls.min_version == Some(MinTlsVersion::Tls13) { &[&TLS13] } else { &[&TLS12, &TLS13] };
    let builder = ClientConfig::builder_with_protocol_versions(versions);

    let builder = if tls.pinned_peer_cert_sha256.is_empty() {
        let mut roots = RootCertStore::empty();
        if !tls.disable_system_root {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        for der in &tls.ca_certificates {
            roots
                .add(CertificateDer::from(der.clone()))
                .map_err(|e| io::Error::other(format!("failed to append cert: {e}")))?;
        }
        builder.with_root_certificates(roots)
    } else {
        let provider = CryptoProvider::get_default()
            .cloned()
            .ok_or_else(|| io::Error::other("no default crypto provider"))?;
        builder.dangerous().with_custom_certificate_verifier(Arc::new(PinnedLeafVerifier {
            pins: tls.pinned_peer_cert_sha256.clone(),
            provider,
        }))
    };

    let mut cfg = builder.with_no_client_auth();
    cfg.alpn_protocols = if tls.alpn.is_empty() {
        DEFAULT_ALPN.iter().map(|s| s.to_vec()).collect()
    } else {
        tls.alpn.iter().map(|s| s.as_bytes().to_vec()).collect()
    };
    Ok(Some(cfg))
}

/// 解析 `pinnedPeerCertSha256`：逗号分隔 hex（容忍 OpenSSL 冒号），32 字节/项。
///
/// 错误文案对齐 xray-tls `parse_pinned_hashes`（同源 Go transport_security.go:365-380）。
fn parse_pinned_hashes(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> io::Result<Vec<Vec<u8>>> {
    let Some(pin) = obj.get("pinnedPeerCertSha256").filter(|v| !v.is_null()) else {
        return Ok(Vec::new());
    };
    let Some(spec) = pin.as_str() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("pinnedPeerCertSha256: expected string (comma-separated hex), got {pin}"),
        ));
    };
    if spec.is_empty() {
        return Ok(Vec::new());
    }
    let mut pins = Vec::new();
    for v in spec.split(',') {
        if v.is_empty() {
            continue;
        }
        let cleaned = v.replace(':', "");
        let bytes = hex::decode(&cleaned).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("pinnedPeerCertSha256: invalid hex: {e}"),
            )
        })?;
        if bytes.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("incorrect pinnedPeerCertSha256 length: {v}"),
            ));
        }
        pins.push(bytes);
    }
    Ok(pins)
}

/// PEM 字符串 → 全部 CERTIFICATE 块的 DER。
fn pem_certificates_to_der(pem: &str) -> io::Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut body = String::new();
    let mut in_block = false;
    for line in pem.lines() {
        let t = line.trim();
        if t.starts_with("-----BEGIN CERTIFICATE-----") {
            in_block = true;
            body.clear();
        } else if t.starts_with("-----END CERTIFICATE-----") {
            let der =
                base64::engine::general_purpose::STANDARD.decode(body.as_bytes()).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("failed to append cert: invalid PEM base64: {e}"),
                    )
                })?;
            out.push(der);
            in_block = false;
        } else if in_block {
            body.push_str(t);
        }
    }
    if out.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "failed to append cert: no CERTIFICATE PEM block found",
        ));
    }
    Ok(out)
}

/// 叶子证书 SHA-256 是否命中钉扎列表。
fn pin_matches(pins: &[Vec<u8>], cert_der: &[u8]) -> bool {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(cert_der);
    pins.iter().any(|p| p.as_slice() == digest.as_slice())
}

/// 叶子证书钉扎验证器。对应 Go `InsecureSkipVerify=true + VerifyPeerCertificate=
/// verifyPeerCert`：链/名验证被钉扎取代，握手签名仍由 provider 验（Go crypto/tls
/// 同样不因 InsecureSkipVerify 免除握手签名校验）。CA 钉扎模式不支持（见模块头）。
#[derive(Debug)]
struct PinnedLeafVerifier {
    pins: Vec<Vec<u8>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedLeafVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if pin_matches(&self.pins, end_entity.as_ref()) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "peer cert is unrecognized (against pinnedPeerCertSha256)".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_and_null_yield_none() {
        assert!(parse_tls_config(None, "h.example.com").unwrap().is_none());
        assert!(
            parse_tls_config(Some(&serde_json::Value::Null), "h.example.com").unwrap().is_none()
        );
    }

    #[test]
    fn non_object_rejects() {
        let e = parse_tls_config(Some(&serde_json::json!(7)), "h.example.com").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn full_fields_parse_into_struct() {
        let pem = "-----BEGIN CERTIFICATE-----\nQUJDREVG\n-----END CERTIFICATE-----\n";
        let cfg = parse_tls_config(
            Some(&serde_json::json!({
                "alpn": ["h2", "http/1.1"],
                "pinnedPeerCertSha256": "ab".repeat(32),
                "certificates": [{ "certificate": pem }],
                "disableSystemRoot": true,
                "minVersion": "1.3"
            })),
            "h.example.com",
        )
        .unwrap()
        .expect("tlsConfig present");
        assert_eq!(cfg.alpn, vec!["h2", "http/1.1"]);
        assert_eq!(cfg.pinned_peer_cert_sha256.len(), 1);
        assert_eq!(cfg.ca_certificates.len(), 1);
        assert_eq!(cfg.ca_certificates[0], b"ABCDEF");
        assert!(cfg.disable_system_root);
        assert_eq!(cfg.min_version, Some(MinTlsVersion::Tls13));
    }

    #[test]
    fn allow_insecure_rejects_like_go_removed_feature() {
        let e =
            parse_tls_config(Some(&serde_json::json!({"allowInsecure": true})), "h.example.com")
                .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(e.to_string().contains("allowInsecure"));
    }

    #[test]
    fn server_name_override_rejects_but_equal_host_passes() {
        let e = parse_tls_config(
            Some(&serde_json::json!({"serverName": "other.example.com"})),
            "h.example.com",
        )
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        // 与 host 相同 = 无操作，放行
        assert!(
            parse_tls_config(
                Some(&serde_json::json!({"serverName": "h.example.com"})),
                "h.example.com"
            )
            .is_ok()
        );
    }

    #[test]
    fn verify_peer_cert_by_name_rejects() {
        let e = parse_tls_config(
            Some(&serde_json::json!({"verifyPeerCertByName": "svc.internal"})),
            "h.example.com",
        )
        .unwrap_err();
        assert!(e.to_string().contains("verifyPeerCertByName"));
    }

    #[test]
    fn invalid_pin_rejects() {
        let bad_len = parse_tls_config(
            Some(&serde_json::json!({"pinnedPeerCertSha256": "ab".repeat(31)})),
            "h.example.com",
        )
        .unwrap_err();
        assert!(bad_len.to_string().contains("incorrect pinnedPeerCertSha256 length"));
        let bad_hex = parse_tls_config(
            Some(&serde_json::json!({"pinnedPeerCertSha256": "zz".repeat(32)})),
            "h.example.com",
        )
        .unwrap_err();
        assert!(bad_hex.to_string().contains("invalid hex"));
        // OpenSSL 冒号格式 + 空串
        let ok = parse_tls_config(
            Some(&serde_json::json!({
                "pinnedPeerCertSha256": format!("{}:{}", "ab".repeat(16), "cd".repeat(16))
            })),
            "h.example.com",
        )
        .unwrap();
        assert_eq!(ok.expect("pins").pinned_peer_cert_sha256.len(), 1);
        assert!(
            parse_tls_config(
                Some(&serde_json::json!({"pinnedPeerCertSha256": ""})),
                "h.example.com",
            )
            .unwrap()
            .expect("cfg")
            .pinned_peer_cert_sha256
            .is_empty()
        );
    }

    #[test]
    fn alpn_non_string_rejects() {
        let e = parse_tls_config(Some(&serde_json::json!({"alpn": ["h2", 3]})), "h.example.com")
            .unwrap_err();
        assert!(e.to_string().contains("alpn"));
    }

    #[test]
    fn go_only_fields_warn_and_ignore() {
        let cfg = parse_tls_config(
            Some(&serde_json::json!({
                "fingerprint": "chrome",
                "maxVersion": "1.3",
                "cipherSuites": "TLS_AES_128_GCM_SHA256",
                "minVersion": "1.1"
            })),
            "h.example.com",
        )
        .unwrap()
        .expect("cfg");
        // 只有 minVersion 字段（1.1 降级 None）→ 与默认等价
        assert_eq!(cfg, TlsConfig::default());
    }

    #[test]
    fn build_returns_none_when_nothing_applicable() {
        assert!(build_rustls_client_config(&TlsConfig::default()).unwrap().is_none());
    }

    #[test]
    fn build_applies_alpn_with_default_fallback() {
        // 仅有 pin：预配置生效，ALPN 回落 Go 默认
        let tls =
            TlsConfig { pinned_peer_cert_sha256: vec![vec![0u8; 32]], ..TlsConfig::default() };
        let cfg = build_rustls_client_config(&tls).unwrap().expect("preconfig");
        assert_eq!(cfg.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);

        // 自定义 ALPN 原样生效
        let tls = TlsConfig { alpn: vec!["myproto".into()], ..TlsConfig::default() };
        let cfg = build_rustls_client_config(&tls).unwrap().expect("preconfig");
        assert_eq!(cfg.alpn_protocols, vec![b"myproto".to_vec()]);
    }

    #[test]
    fn pin_matches_leaf_hash() {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(b"leaf-cert-der").to_vec();
        assert!(pin_matches(&[hash], b"leaf-cert-der"));
        assert!(!pin_matches(&[vec![0u8; 32]], b"leaf-cert-der"));
    }
}
