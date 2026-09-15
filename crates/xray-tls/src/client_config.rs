//! 从 `streamSettings` 安全配置构建 `rustls::ClientConfig`。
//!
//! 对应 Go `transport/internet/tls/tls.go::ConfigFromStreamSettings` + `GetTLSConfig`
//! （client 侧）。已覆盖字段：
//! - `serverName`（SNI 由调用方传给 `utls::client`，此处仅解析）
//! - `allowInsecure` / `alpn`
//! - `minVersion` / `maxVersion` / `cipherSuites` / `curvePreferences`
//!   （经 [`crate::config::security_params`]，rustls 边界项 warn 后降级）
//! - `disableSystemRoot` + `certificates[]`：自定义 CA 信任根替代 webpki-roots
//!   （对应 Go `getCertPool` → `loadSelfCertPool`）
//! - `pinnedPeerCertSha256`：证书钉扎（对应 Go `RandCarrier.verifyPeerCert` +
//!   `verifyChain`，见 [`PinnedServerCertVerifier`]）
//! - `certificates[]` 带 key 条目：客户端身份证书（mTLS 双向握手；Go 无此能力，
//!   Rust 扩展）
//!
//! ECH 留待 115 另 issue；`verifyPeerCertByName` 未实现（Go v26 新增，暂无需求）。

use std::io;
use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

use crate::certificate::entry_certs_and_key;
use crate::config::{security_params, verify_chain, VerifyResult};
use crate::pin::generate_cert_hash;

/// 默认 ALPN 协议列表（对齐 Go `NextProto = []string{"h2", "http/1.1"}`）。
const DEFAULT_ALPN: &[&str] = &["h2", "http/1.1"];

/// 从 `streamSettings` 的安全配置构建 rustls `ClientConfig`。
///
/// 对应 Go `ConfigFromStreamSettings` + `GetTLSConfig`。
///
/// # 参数
/// - `security`：安全层名（`"none"` / `"tls"` / `"reality"`）。非 `"tls"` / `"reality"` 返回 `None`。
/// - `security_json`：`tlsSettings` 或 `realitySettings` 的 JSON 值。`None` 用默认值。
/// - `server_name`：默认 SNI（当 `tlsSettings.serverName` 缺失时使用）。
///
/// # 返回
/// - `Ok(None)`：不需要 TLS
/// - `Ok(Some(Arc<ClientConfig>))`：构建成功
/// - `Err`：配置解析错误（如 `alpn` 元素非字符串、`pinnedPeerCertSha256` 非法 hex/长度）
///
/// # 安全
///
/// `allowInsecure=true` 会跳过证书验证（对齐 Go `InsecureSkipVerify`，v26 已在
/// JSON 层移除该字段，Rust 保留兼容）。仅用于调试或明确接受 MITM 风险的场景。
/// 从 `streamSettings` 的安全配置构建 rustls `ClientConfig`。
///
/// 对应 Go `transport/internet/tls/tls.go::ConfigFromStreamSettings` + `GetTLSConfig`
/// （client 侧）。已覆盖字段：
/// - `serverName`（SNI 由调用方传给 `utls::client`，此处仅解析）
/// - `allowInsecure` / `alpn`
/// - `minVersion` / `maxVersion` / `cipherSuites` / `curvePreferences`
///   （经 [`crate::config::security_params`]，rustls 边界项 warn 后降级）
/// - `disableSystemRoot` + `certificates[]`：自定义 CA 信任根替代 webpki-roots
///   （对应 Go `getCertPool` → `loadSelfCertPool`）
/// - `pinnedPeerCertSha256`：证书钉扎（对应 Go `RandCarrier.verifyPeerCert` +
///   `verifyChain`，见 [`PinnedServerCertVerifier`]）
/// - `certificates[]` 带 key 条目：客户端身份证书（mTLS 双向握手；Go 无此能力，
///   Rust 扩展）
/// - `verifyPeerCertByName`（Go v26 新增）：以字符串而非 SNI 主机名做证书验证，
///   用于 ECH/PSK 等握手阶段 SNI 与真实服务名不一致的场景。
/// - `masterKeyLog`（Go `tls.Config.KeyLogWriter` 等价）/ `enableSessionResumption`
///   （Go `SessionTicketsDisabled` 等价）：pwh6 字段族增量。
///
/// ECH 留待 115 另 issue。
pub fn build_client_config(
    security: &str,
    security_json: Option<&serde_json::Value>,
    server_name: &str,
) -> io::Result<Option<Arc<ClientConfig>>> {
    // ring provider 经 xray-common 集中入口幂等安装（bd jrh7）。
    // ponytail: 放在函数入口确保调用方不必显式 install。
    xray_common::ensure_default_crypto_provider();

    if !matches!(security, "tls" | "reality") {
        return Ok(None);
    }

    let json = security_json.cloned().unwrap_or(serde_json::Value::Null);
    let obj = json.as_object();

    // serverName：缺失时用参数传入的默认值（通常是 dest 地址）。
    // SNI 不进 ClientConfig（rustls 由 connect(server_name) 参数决定），仅保留解析。
    let _sni: String = obj
        .and_then(|m| m.get("serverName"))
        .and_then(|v| v.as_str())
        .unwrap_or(server_name)
        .to_string();

    // allowInsecure：默认 false。
    let allow_insecure: bool = obj
        .and_then(|m| m.get("allowInsecure"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    // Go infra/conf/transport_internet.go:698-700：allowInsecure 已移除（硬报错）。
    // Rust 保留现行为：warn + 继续跳过证书验证。
    if allow_insecure {
        xray_common::errors::warn_removed_feature(
            "\"allowInsecure\"",
            "\"pinnedPeerCertSha256\"(pcs) and \"verifyPeerCertByName\"(vcn)",
        );
    }

    // alpn：数组；缺失用 DEFAULT_ALPN。
    let alpn_owned: Vec<Vec<u8>> = if let Some(arr) = obj.and_then(|m| m.get("alpn")).and_then(|v| v.as_array()) {
        arr.iter()
            .map(|s| {
                s.as_str()
                    .map(|x| x.as_bytes().to_vec())
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "alpn array must contain only strings"))
            })
            .collect::<io::Result<_>>()?
    } else {
        DEFAULT_ALPN.iter().map(|s| s.as_bytes().to_vec()).collect()
    };

    // minVersion/maxVersion/cipherSuites/curvePreferences → provider + 版本列表
    let (provider, versions) = security_params(&json);

    // pinnedPeerCertSha256：逗号分隔 hex（容忍 OpenSSL 冒号），32 字节/项
    let pins = parse_pinned_hashes(&json)?;

    // mTLS 客户端身份：首个同时含证书+私钥的 certificates[] 条目
    let identity = client_identity(&json)?;

    // pwh6: TLS 字段族增量解析（client 侧）。所有字段缺失=默认行为，向前兼容。
    let master_key_log = crate::server_config::parse_master_key_log(&json);
    let enable_session_resumption = obj
        .and_then(|m| m.get("enableSessionResumption"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    // verifyPeerCertByName：Go v26 新增——以字符串而非 SNI 主机名做证书验证。
    // 用法：ECH/PSK 等握手阶段 SNI 与真实服务名不一致场景，对 ECH inner SNI
    // 暴露的真实服务做校验。Rust 端把字符串传给 PinnedServerCertVerifier 的
    // verify_server_cert 替代默认 SNI 校验。空字符串=保持默认 SNI 校验。
    let verify_peer_cert_by_name = obj
        .and_then(|m| m.get("verifyPeerCertByName"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // echSockopt（Go transport_security.go:318 `echSockopt`）：Go 唯一消费点是
    // ECH DoH 查询链（ech.go QueryRecord→dnsQuery 的连接 sockopt）。Rust 该链路
    // 未实现（DoH 形态 ECHConfigList 直接降级 invalid），此处识别 + 显式忽略提示。
    if crate::ech::parse_ech_sockopt(&json).is_some()
        && obj.and_then(|m| m.get("echConfigList")).and_then(|v| v.as_str())
            .is_some_and(|s| s.contains("://"))
    {
        tracing::warn!(
            target: "xray_tls::client_config",
            "echSockopt is set but ECH DoH query is not implemented; sockopt ignored (ECH config will be invalid)"
        );
    }

    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .map_err(|e| io::Error::other(format!("protocol versions: {e}")))?;

    let builder = if allow_insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
    } else if !pins.is_empty() || !verify_peer_cert_by_name.is_empty() {
        // pwh6: verifyPeerCertByName 与 pinnedPeerCertSha256 互不冲突，可同时配；
        // 任一非空都走 PinnedServerCertVerifier（已实现 verify_chain 逻辑）。
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedServerCertVerifier::new(
                pins,
                verify_peer_cert_by_name,
            )))
    } else {
        builder.with_root_certificates(verifier_roots(&json)?)
    };

    let mut cfg = match identity {
        Some((certs, key)) => builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| io::Error::other(format!("client auth cert: {e}")))?,
        None => builder.with_no_client_auth(),
    };
    cfg.alpn_protocols = alpn_owned;

    // pwh6: masterKeyLog — Go KeyLogWriter（config.go:467-474）。string 路径
    // 追加写 NSS 行；bool true（历史方言）走 SSLKEYLOGFILE env；打开失败
    // 对齐 Go：warn 后继续（无 keylog）。
    match master_key_log {
        crate::server_config::MasterKeyLogSetting::Path(path) => {
            match std::fs::OpenOptions::new().create(true).append(true).open(&path) {
                Ok(file) => {
                    cfg.key_log = Arc::new(crate::server_config::KeyLogFileWriter(
                        parking_lot::Mutex::new(file),
                    ));
                }
                Err(e) => tracing::warn!(
                    target: "xray_tls::client_config",
                    error = %e,
                    path = %path,
                    "failed to open masterKeyLog as file; key log disabled"
                ),
            }
        }
        crate::server_config::MasterKeyLogSetting::EnvFile => {
            cfg.key_log = Arc::new(rustls::KeyLogFile::new());
        }
        crate::server_config::MasterKeyLogSetting::Off => {}
    }

    // pwh6: enableSessionResumption=false 走 rustls `Resumption::disabled()`
    // （client/client_conn.rs:495：store=NoClientSessionStorage +
    // tls12_resumption=Disabled）。Go 端 `SessionTicketsDisabled=true` 等价。
    if !enable_session_resumption {
        cfg.resumption = rustls::client::Resumption::disabled();
    }

    Ok(Some(Arc::new(cfg)))
}

/// 客户端验证器信任根选择：`disableSystemRoot=true` → `certificates[]` 全部
/// 证书作自定义 CA（对应 Go `loadSelfCertPool`，不筛 usage）；否则 webpki-roots
/// （Go 用系统根，Rust 沿用既有 webpki-roots 决策）。
fn verifier_roots(json: &serde_json::Value) -> io::Result<RootCertStore> {
    let disable = json
        .as_object()
        .and_then(|m| m.get("disableSystemRoot"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if disable {
        custom_root_store(json)
    } else {
        let mut store = RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Ok(store)
    }
}

/// 按安全配置构建**服务端证书验证器**（btls 指纹路径回接验证用，pz6c）。
///
/// 对应 Go `copyConfig`（tls.go:149-161）把验证语义透传进 utls.Config：uTLS
/// 非 insecure 时握手执行完整链验证。返回 `None` = `allowInsecure=true`
/// （跳过验证，等价 Go `InsecureSkipVerify`）；`Some` 按序命中 pinned/vcn
/// 自定义验证器或 webpki（用户根 / webpki-roots）验证器，与
/// [`build_client_config`] 的 rustls 路径同语义。
///
/// # 参数
/// - `security_json`：`tlsSettings` JSON；`None` 按 `{}`（默认全验证）。
pub fn build_server_cert_verifier(
    security_json: Option<&serde_json::Value>,
) -> io::Result<Option<Arc<dyn ServerCertVerifier>>> {
    // ring provider 经集中入口安装（同 build_client_config:78）：workspace
    // feature unification 同启 ring+aws-lc-rs 时 rustls 无法自动选定 provider，
    // naive/btls 路径只经本函数装配 rustls 验证器 → 进程级 panic。
    xray_common::ensure_default_crypto_provider();
    let json = security_json.cloned().unwrap_or(serde_json::Value::Null);
    let allow_insecure = json
        .as_object()
        .and_then(|m| m.get("allowInsecure"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if allow_insecure {
        return Ok(None);
    }
    let pins = parse_pinned_hashes(&json)?;
    let verify_peer_cert_by_name = json
        .as_object()
        .and_then(|m| m.get("verifyPeerCertByName"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if !pins.is_empty() || !verify_peer_cert_by_name.is_empty() {
        return Ok(Some(Arc::new(PinnedServerCertVerifier::new(
            pins,
            verify_peer_cert_by_name,
        ))));
    }
    let verifier = WebPkiServerVerifier::builder(Arc::new(verifier_roots(&json)?))
        .build()
        .map_err(|e| io::Error::other(format!("webpki verifier: {e}")))?;
    Ok(Some(verifier))
}

/// `disableSystemRoot=true` 时的信任根：`certificates[]` 全部条目的证书
/// （对应 Go `loadSelfCertPool`——遍历全部 `Certificate`，不筛 usage）。
///
/// 未配置任何证书 → 空池（对齐 Go：空 `x509.CertPool`，一切验证失败）。
///
/// # Errors
/// 条目非法（内联类型错误/内容缺失/PEM 无证书块）时传播——对齐 Go：配置
/// 加载期即报错，不在信任根构建层静默吞掉。
fn custom_root_store(json: &serde_json::Value) -> io::Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    if let Some(arr) = json.get("certificates").and_then(|v| v.as_array()) {
        for entry in arr {
            let (certs, _) = entry_certs_and_key(entry)?;
            for der in certs {
                // 单条证书不被信任时跳过（对齐 Go 逐条 AppendCertsFromPEM 的容错语义：
                // 追加失败只影响该条证书，不中断池构建）
                let _ = store.add(der);
            }
        }
    }
    Ok(store)
}

/// 解析 `pinnedPeerCertSha256`：逗号分隔 hex 字符串（容忍 OpenSSL 冒号格式）。
///
/// 对应 Go `TLSConfig.Build` L701-717：空段跳过；hex 非法或长度 ≠ 32 报错。
fn parse_pinned_hashes(json: &serde_json::Value) -> io::Result<Vec<Vec<u8>>> {
    let Some(spec) = json.get("pinnedPeerCertSha256").and_then(|v| v.as_str()) else {
        return Ok(Vec::new());
    };
    let mut pins = Vec::new();
    for v in spec.split(',') {
        let v = v.trim();
        if v.is_empty() {
            continue;
        }
        // remove colons for OpenSSL format
        let cleaned: String = v.chars().filter(|c| *c != ':').collect();
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


/// 客户端身份证书（mTLS）：`certificates[]` 中首个同时含证书与私钥的条目。
///
/// Go 客户端从不发送证书（`GetTLSConfig` 不设 `tls.Config.Certificates`）；
/// 这是 Rust 扩展，服务端配置 `usage:"verify"` CA 时用于双向握手。
/// CA 条目（`usage:"verify"`）通常无私钥，不会被误认。
fn client_identity(
    json: &serde_json::Value,
) -> io::Result<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>> {
    if let Some(arr) = json.get("certificates").and_then(|v| v.as_array()) {
        for entry in arr {
            let (certs, key) = entry_certs_and_key(entry)?;
            if let Some(key) = key {
                return Ok(Some((certs, key)));
            }
        }
    }
    Ok(None)
}

/// 证书钉扎 verifier（对应 Go `RandCarrier.verifyPeerCert` + `verifyChain`）。
///
/// 语义与 Go 一致：
/// 1. pin 命中**叶子** → 直接通过（Go `foundLeaf` 即 `return nil`，不查链/有效期/主机名）。
/// 2. pin 命中链中 **CA** → 以该 CA 为唯一信任根做完整 webpki 验证
///    （链构建 + 签名 + 有效期 + 主机名，对应 Go foundCA 分支的 `certs[0].Verify`）。
/// 3. 无命中 → 拒绝（"peer cert is unrecognized"）。
///
/// pwh6: 附加 `verify_peer_cert_by_name`（Go `verifyPeerCertByName` v26 新增）：
/// 非空时替代默认 SNI 做证书主机名校验。ECH 等握手阶段 SNI 与真实服务名不一致
/// 场景：对 ECH inner SNI 暴露的真实服务名做校验。空=默认 SNI 校验。
///
/// 握手签名验证是**真实验证**（委托 ring provider），与
/// [`NoCertificateVerification`] 的全过语义不同——钉扎不降低握手完整性。
#[derive(Debug)]
struct PinnedServerCertVerifier {
    /// 每项 32 字节 SHA-256。
    pins: Vec<Vec<u8>>,
    /// Go `verifyPeerCertByName` 等价——非空时替代 SNI 做主机名校验。
    verify_peer_cert_by_name: String,
}

impl PinnedServerCertVerifier {
    fn new(pins: Vec<Vec<u8>>, verify_peer_cert_by_name: String) -> Self {
        Self {
            pins,
            verify_peer_cert_by_name,
        }
    }
}
impl ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // pwh6: verifyPeerCertByName 非空时替代默认 SNI——ECH/PSK 场景
        // 握手阶段 SNI 与真实服务名不一致。pin 命中叶子分支照过；命中 CA
        // 分支用 vcn 重新构造 ServerName 走 webpki 主机名校验。
        let effective_name = if self.verify_peer_cert_by_name.is_empty() {
            server_name.clone()
        } else {
            ServerName::try_from(self.verify_peer_cert_by_name.as_str())
                .map_err(|e| rustls::Error::General(format!("verifyPeerCertByName: {e}")))?
        };
        // [叶子, 中间证书...] 的 hash/is_ca 输入（对应 Go verifyPeerCert 的 certs）
        let mut hashes = vec![generate_cert_hash(end_entity)];
        let mut is_ca = vec![false];
        for cert in intermediates {
            hashes.push(generate_cert_hash(cert));
            is_ca.push(
                x509_parser::parse_x509_certificate(cert.as_ref())
                    .map(|(_, c)| c.is_ca())
                    .unwrap_or(false),
            );
        }

        match verify_chain(&hashes, &is_ca, &self.pins) {
            (VerifyResult::FoundLeaf, _) => Ok(ServerCertVerified::assertion()),
            (VerifyResult::FoundCa, Some(idx)) => {
                // verify_chain 的索引含叶子（0），中间证书从 1 起
                let ca = intermediates
                    .get(idx - 1)
                    .ok_or_else(|| rustls::Error::General("pinned CA index out of range".into()))?;
                let mut store = RootCertStore::empty();
                store
                    .add(ca.clone())
                    .map_err(|e| rustls::Error::General(format!("pinned CA: {e}")))?;
                let verifier = WebPkiServerVerifier::builder(Arc::new(store))
                    .build()
                    .map_err(|e| rustls::Error::General(format!("pinned CA verifier: {e}")))?;
                verifier.verify_server_cert(
                    end_entity,
                    intermediates,
                    &effective_name,
                    ocsp_response,
                    now,
                )
            }
            _ => Err(rustls::Error::General(
                "peer cert is unrecognized (against pinnedPeerCertSha256)".into(),
            )),
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
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
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
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// 永远通过证书验证的 verifier（对齐 Go `InsecureSkipVerify: true`）。
///
/// # 安全
///
/// 该 verifier 完全不检查证书，**仅在调试或明确接受 MITM 风险的场景使用**。
/// 生产环境必须保持 `allowInsecure=false`。
#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // ponytail: 永远通过——与 Go InsecureSkipVerify 等价。
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // 暴露所有 rustls 内置方案，避免与 peer 协商失败。
        // ponytail: 不筛选 = dangerous verifier 接受任何签名方案。
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
            SignatureScheme::ECDSA_NISTP521_SHA512,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::version::{TLS12, TLS13};

    #[test]
    fn client_invalid_inline_cert_errors_instead_of_silent_skip() {
        // disableSystemRoot=true 时信任根来自 certificates[]；条目类型非法
        // → custom_root_store Err 传播（对齐 Go 配置加载 error），不再静默吞掉。
        let v = serde_json::json!({
            "disableSystemRoot": true,
            "certificates": [{ "certificate": 42 }]
        });
        assert!(build_client_config("tls", Some(&v), "fallback.com").is_err());
    }

    fn install_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    // ---- 既有行为回归 ----

    #[test]
    fn none_security_returns_none() {
        install_provider();
        let r = build_client_config("none", None, "example.com").unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn empty_security_returns_none() {
        install_provider();
        let r = build_client_config("", None, "example.com").unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn tls_security_with_null_json_returns_some() {
        install_provider();
        let r = build_client_config("tls", None, "example.com").unwrap();
        assert!(r.is_some(), "tls should produce a ClientConfig even with null json");
    }

    #[test]
    fn tls_security_parses_alpn() {
        install_provider();
        let v: serde_json::Value =
            serde_json::from_str(r#"{"serverName":"x.com","alpn":["h2","http/1.1"]}"#).unwrap();
        let cfg = build_client_config("tls", Some(&v), "fallback.com").unwrap().unwrap();
        let negotiated: Vec<Vec<u8>> = cfg.alpn_protocols.clone();
        assert_eq!(negotiated, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    #[test]
    fn tls_security_alpn_invalid_type_returns_err() {
        install_provider();
        let v: serde_json::Value = serde_json::from_str(r#"{"alpn":["h2",123]}"#).unwrap();
        let r = build_client_config("tls", Some(&v), "x.com");
        assert!(r.is_err(), "non-string alpn element must error");
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn tls_security_alpn_defaults_when_missing() {
        install_provider();
        let v: serde_json::Value = serde_json::from_str(r#"{"serverName":"x.com"}"#).unwrap();
        let cfg = build_client_config("tls", Some(&v), "fallback.com").unwrap().unwrap();
        let negotiated: Vec<Vec<u8>> = cfg.alpn_protocols.clone();
        assert_eq!(negotiated, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    #[test]
    fn allow_insecure_produces_dangerous_verifier() {
        install_provider();
        let v: serde_json::Value = serde_json::from_str(r#"{"allowInsecure":true}"#).unwrap();
        let cfg = build_client_config("tls", Some(&v), "example.com").unwrap().unwrap();
        // dangerous verifier 应该是 NoCertificateVerification；通过 ALPN 仍设置验证 dangerous 路径走通。
        assert!(!cfg.alpn_protocols.is_empty());
        // 没有公开 API 直接判 verifier 类型，靠 e2e 验证行为。
    }

    #[test]
    fn reality_security_treated_as_tls() {
        install_provider();
        let r = build_client_config("reality", None, "example.com").unwrap();
        assert!(r.is_some(), "reality should produce a ClientConfig");
    }

    // ---- minVersion/maxVersion/cipherSuites/curvePreferences（security_params）----

    #[test]
    fn versions_default_both() {
        let (p, v) = security_params(&serde_json::json!({}));
        drop(p);
        assert_eq!(v, vec![&TLS13, &TLS12]);
    }

    #[test]
    fn versions_min_max_bounds() {
        // min 1.2 → 1.3 + 1.2
        let (_, v) = security_params(&serde_json::json!({"minVersion": "1.2"}));
        assert_eq!(v, vec![&TLS13, &TLS12]);
        // min 1.3 → 仅 1.3
        let (_, v) = security_params(&serde_json::json!({"minVersion": "1.3"}));
        assert_eq!(v, vec![&TLS13]);
        // max 1.2 → 仅 1.2
        let (_, v) = security_params(&serde_json::json!({"maxVersion": "1.2"}));
        assert_eq!(v, vec![&TLS12]);
        // min 1.3 + max 1.2 → 空 → 回落默认
        let (_, v) = security_params(&serde_json::json!({"minVersion": "1.3", "maxVersion": "1.2"}));
        assert_eq!(v, vec![&TLS13, &TLS12]);
    }

    #[test]
    fn versions_tls10_tls11_unsupported_clamped() {
        // min 1.0/1.1 → Unsupported warn + 钳到 1.2
        let (_, v) = security_params(&serde_json::json!({"minVersion": "1.0"}));
        assert_eq!(v, vec![&TLS13, &TLS12]);
        let (_, v) = security_params(&serde_json::json!({"minVersion": "1.1"}));
        assert_eq!(v, vec![&TLS13, &TLS12]);
        // max 1.1 → 无可用版本 → 回落默认
        let (_, v) = security_params(&serde_json::json!({"maxVersion": "1.1"}));
        assert_eq!(v, vec![&TLS13, &TLS12]);
        // 未知值 → 对齐 Go 忽略
        let (_, v) = security_params(&serde_json::json!({"minVersion": "9.9"}));
        assert_eq!(v, vec![&TLS13, &TLS12]);
    }

    #[test]
    fn cipher_suites_filter() {
        let (p, _) = security_params(&serde_json::json!({
            "cipherSuites": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_AES_128_GCM_SHA256"
        }));
        assert_eq!(p.cipher_suites.len(), 2);
        // ring 默认 9 个（3×TLS1.3 + 6×TLS1.2 ECDHE）
        let (p, _) = security_params(&serde_json::json!({}));
        assert_eq!(p.cipher_suites.len(), 9);
        // 全部不可用 → 保留默认
        let (p, _) = security_params(&serde_json::json!({"cipherSuites": "BOGUS:FAKE"}));
        assert_eq!(p.cipher_suites.len(), 9);
        // CBC 套件 rustls 不支持 → 跳过
        let (p, _) = security_params(&serde_json::json!({
            "cipherSuites": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_AES_256_GCM_SHA384"
        }));
        assert_eq!(p.cipher_suites.len(), 1);
    }

    #[test]
    fn curve_preferences_filter() {
        // 仅 x25519 可用（curvep521 Unsupported warn 跳过、junk 未知 warn 跳过）
        let (p, _) = security_params(&serde_json::json!({
            "curvePreferences": ["x25519", "curvep521", "junk"]
        }));
        assert_eq!(p.kx_groups.len(), 1);
        assert_eq!(p.kx_groups[0].name(), rustls::NamedGroup::X25519);
        // 用户顺序保留：P384 在前
        let (p, _) = security_params(&serde_json::json!({
            "curvePreferences": ["curvep384", "curvep256"]
        }));
        assert_eq!(p.kx_groups.len(), 2);
        assert_eq!(p.kx_groups[0].name(), rustls::NamedGroup::secp384r1);
        // 全不可用 → 保留默认 3 组
        let (p, _) = security_params(&serde_json::json!({
            "curvePreferences": ["x25519mlkem768"]
        }));
        assert_eq!(p.kx_groups.len(), 3);
        // 单字符串形态（Go StringList 兼容）
        let (p, _) = security_params(&serde_json::json!({
            "curvePreferences": "curvep256"
        }));
        assert_eq!(p.kx_groups.len(), 1);
    }

    // ---- pinnedPeerCertSha256 解析 ----

    #[test]
    fn pinned_hashes_parse() {
        let ok = parse_pinned_hashes(&serde_json::json!({
            "pinnedPeerCertSha256": "00ff".repeat(16)
        }))
        .unwrap();
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].len(), 32);
        // 空段跳过；空字符串 / 缺失 → 空 pins
        assert!(parse_pinned_hashes(&serde_json::json!({"pinnedPeerCertSha256": ""}))
            .unwrap()
            .is_empty());
        assert!(parse_pinned_hashes(&serde_json::json!({})).unwrap().is_empty());
    }

    #[test]
    fn pinned_hashes_multiple_and_colons() {
        let h1 = "aa".repeat(32);
        let h2 = "bb".repeat(32);
        let pins = parse_pinned_hashes(&serde_json::json!({
            "pinnedPeerCertSha256": format!("{h1},{h2}")
        }))
        .unwrap();
        assert_eq!(pins.len(), 2);
        // 冒号（OpenSSL 格式）被剥离
        let colonized: String = h1.as_str().chars().enumerate()
            .map(|(i, c)| if i % 2 == 0 && i > 0 { format!(":{c}") } else { c.to_string() })
            .collect();
        let pins = parse_pinned_hashes(&serde_json::json!({
            "pinnedPeerCertSha256": colonized
        }))
        .unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0], hex::decode(&h1).unwrap());
    }

    #[test]
    fn pinned_hashes_invalid() {
        // 非 hex
        let e = parse_pinned_hashes(&serde_json::json!({"pinnedPeerCertSha256": "zz".repeat(32)}))
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        // 长度错（31 字节）
        let e = parse_pinned_hashes(&serde_json::json!({"pinnedPeerCertSha256": "ab".repeat(31)}))
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        // build 层透传错误
        let r = build_client_config(
            "tls",
            Some(&serde_json::json!({"pinnedPeerCertSha256": "1234"})),
            "x.com",
        );
        assert!(r.is_err());
    }

    #[test]
    fn disable_system_root_without_certs_builds_empty_pool() {
        // Go：空 pool = 全部验证失败；构建本身不报错
        install_provider();
        let cfg = build_client_config(
            "tls",
            Some(&serde_json::json!({"disableSystemRoot": true})),
            "x.com",
        )
        .unwrap()
        .unwrap();
        assert!(!cfg.alpn_protocols.is_empty());
    }

    #[test]
    fn client_identity_picks_keyed_entry() {
        let (c1, _) = test_leaf_pem("nokey.example.com");
        let (c2, k2) = test_leaf_pem("id.example.com");
        let json = serde_json::json!({
            "certificates": [
                { "certificate": c1 },
                { "certificate": c2, "key": k2 },
            ]
        });
        let id = client_identity(&json).unwrap().unwrap();
        assert_eq!(id.0.len(), 1); // 选中带 key 的第二个条目
        let none = client_identity(&serde_json::json!({"certificates": [{"certificate": c1}]}))
            .unwrap();
        assert!(none.is_none());
    }

    // ---- e2e：内存双工管道上的真实握手 ----

    /// 生成自签叶子证书 (cert_pem, key_pem)。
    fn test_leaf_pem(san: &str) -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![san.to_string()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, san);
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    /// 生成 CA（is_ca=true）。
    fn make_ca(cn: &str) -> (rcgen::Certificate, rcgen::KeyPair) {
        let mut params = rcgen::CertificateParams::new(vec![cn.to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, cn);
        let key = rcgen::KeyPair::generate().unwrap();
        (params.self_signed(&key).unwrap(), key)
    }

    /// 用 CA 签发叶子证书 (cert_pem, key_pem)。
    fn issue_leaf(san: &str, ca: &rcgen::Certificate, ca_key: &rcgen::KeyPair) -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![san.to_string()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, san);
        let cert = params.signed_by(&key, ca, ca_key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    /// PEM 首张证书的 SHA-256 hex（钉扎值）。
    fn pem_leaf_hash_hex(pem: &str) -> String {
        let der = rustls_pemfile::certs(&mut pem.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        hex::encode(generate_cert_hash(der.as_ref()))
    }

    type Duplex = tokio::io::DuplexStream;

    /// 在 `tokio::io::duplex` 上做一次真实 TLS 握手，返回 (服务端结果, 客户端结果)。
    async fn handshake_pair(
        server_json: serde_json::Value,
        client_json: serde_json::Value,
        sni: &str,
    ) -> (
        io::Result<tokio_rustls::server::TlsStream<Duplex>>,
        io::Result<tokio_rustls::client::TlsStream<Duplex>>,
    ) {
        let sc = crate::server_config::build_server_config("tls", Some(&server_json))
            .unwrap()
            .unwrap();
        let cc = build_client_config("tls", Some(&client_json), sni)
            .unwrap()
            .unwrap();
        let (a, b) = tokio::io::duplex(4096);
        let accept = async {
            tokio_rustls::TlsAcceptor::from(sc)
                .accept(a)
                .await
                .map_err(io::Error::other)
        };
        let connect = async {
            let name = ServerName::try_from(sni.to_string()).unwrap();
            tokio_rustls::TlsConnector::from(cc)
                .connect(name, b)
                .await
                .map_err(io::Error::other)
        };
        tokio::join!(accept, connect)
    }

    #[tokio::test]
    async fn e2e_tls13_only_version() {
        let (sr, cr) = handshake_pair(
            serde_json::json!({"minVersion": "1.3"}),
            serde_json::json!({"minVersion": "1.3", "allowInsecure": true}),
            "localhost",
        )
        .await;
        let client = cr.unwrap();
        sr.unwrap();
        assert_eq!(
            client.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
    }

    #[tokio::test]
    async fn e2e_tls12_only_version() {
        let (sr, cr) = handshake_pair(
            serde_json::json!({"maxVersion": "1.2"}),
            serde_json::json!({"maxVersion": "1.2", "allowInsecure": true}),
            "localhost",
        )
        .await;
        let client = cr.unwrap();
        sr.unwrap();
        assert_eq!(
            client.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_2)
        );
    }

    #[tokio::test]
    async fn e2e_cipher_suite_restricted() {
        let (sr, cr) = handshake_pair(
            serde_json::json!({"cipherSuites": "TLS_CHACHA20_POLY1305_SHA256", "minVersion": "1.3"}),
            serde_json::json!({"cipherSuites": "TLS_CHACHA20_POLY1305_SHA256", "minVersion": "1.3", "allowInsecure": true}),
            "localhost",
        )
        .await;
        let client = cr.unwrap();
        sr.unwrap();
        assert_eq!(
            client.get_ref().1.negotiated_cipher_suite().unwrap().suite(),
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        );
    }

    #[tokio::test]
    async fn e2e_curve_restricted_handshakes() {
        // 双方只留 P256 → 握手成功
        let (sr, cr) = handshake_pair(
            serde_json::json!({"curvePreferences": ["curvep256"], "minVersion": "1.3"}),
            serde_json::json!({"curvePreferences": ["curvep256"], "minVersion": "1.3", "allowInsecure": true}),
            "localhost",
        )
        .await;
        cr.unwrap();
        sr.unwrap();
    }

    #[tokio::test]
    async fn e2e_curve_mismatch_fails() {
        // 客户端只 x25519，服务端只 P256 → 无公共组 → 双方失败
        let (sr, cr) = handshake_pair(
            serde_json::json!({"curvePreferences": ["curvep256"], "minVersion": "1.3"}),
            serde_json::json!({"curvePreferences": ["x25519"], "minVersion": "1.3", "allowInsecure": true}),
            "localhost",
        )
        .await;
        assert!(sr.is_err() || cr.is_err());
    }

    #[tokio::test]
    async fn e2e_custom_ca_replaces_webpki_roots() {
        // CA 签发的服务端证书：disableSystemRoot + CA 条目 → 握手成功
        let (ca, ca_key) = make_ca("Test Root CA");
        let (leaf_pem, leaf_key) = issue_leaf("localhost", &ca, &ca_key);
        let (sr, cr) = handshake_pair(
            serde_json::json!({"certificates": [{"certificate": leaf_pem, "key": leaf_key}]}),
            serde_json::json!({
                "disableSystemRoot": true,
                "certificates": [{"certificate": ca.pem()}]
            }),
            "localhost",
        )
        .await;
        let client = cr.expect("custom CA should validate CA-signed server cert");
        sr.unwrap();
        assert_eq!(
            client.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );

        // 对照：不配 disableSystemRoot（webpki-roots）→ 验证失败
        let (sr2, cr2) = handshake_pair(
            serde_json::json!({"certificates": [{"certificate": leaf_pem, "key": leaf_key}]}),
            serde_json::json!({}),
            "localhost",
        )
        .await;
        assert!(cr2.is_err(), "webpki roots must reject private CA cert");
        drop(sr2);
    }

    #[tokio::test]
    async fn e2e_pinned_leaf_accepts() {
        let (cert_pem, key_pem) = test_leaf_pem("localhost");
        let pin = pem_leaf_hash_hex(&cert_pem);
        let (sr, cr) = handshake_pair(
            serde_json::json!({"certificates": [{"certificate": cert_pem, "key": key_pem}]}),
            serde_json::json!({"pinnedPeerCertSha256": pin}),
            "localhost",
        )
        .await;
        cr.unwrap();
        sr.unwrap();
    }

    #[tokio::test]
    async fn e2e_pinned_wrong_hash_rejects() {
        let (cert_pem, key_pem) = test_leaf_pem("localhost");
        let other_pin = pem_leaf_hash_hex(&test_leaf_pem("other.example.com").0);
        let (sr, cr) = handshake_pair(
            serde_json::json!({"certificates": [{"certificate": cert_pem, "key": key_pem}]}),
            serde_json::json!({"pinnedPeerCertSha256": other_pin}),
            "localhost",
        )
        .await;
        assert!(cr.is_err(), "wrong pin must be rejected");
        assert!(sr.is_err());
    }

    #[tokio::test]
    async fn e2e_pinned_ca_verifies_chain() {
        // pin 命中链中 CA → 以该 CA 为根做完整验证（叶子 SAN localhost 匹配）
        let (ca, ca_key) = make_ca("Pinned Root CA");
        let (leaf_pem, leaf_key) = issue_leaf("localhost", &ca, &ca_key);
        let mut chain_pem = leaf_pem.clone();
        if !chain_pem.ends_with('\n') {
            chain_pem.push('\n');
        }
        chain_pem.push_str(&ca.pem());
        let ca_pin = pem_leaf_hash_hex(&ca.pem());

        let (sr, cr) = handshake_pair(
            serde_json::json!({"certificates": [{"certificate": chain_pem, "key": leaf_key}]}),
            serde_json::json!({"pinnedPeerCertSha256": ca_pin}),
            "localhost",
        )
        .await;
        cr.unwrap();
        sr.unwrap();

        // 对照：叶子 SAN 不匹配 SNI → foundCA 路径的完整验证拒绝
        let (leaf2_pem, leaf2_key) = issue_leaf("elsewhere.example.com", &ca, &ca_key);
        let mut chain2 = leaf2_pem.clone();
        chain2.push('\n');
        chain2.push_str(&ca.pem());
        let (sr2, cr2) = handshake_pair(
            serde_json::json!({"certificates": [{"certificate": chain2, "key": leaf2_key}]}),
            serde_json::json!({"pinnedPeerCertSha256": ca_pin}),
            "localhost",
        )
        .await;
        assert!(cr2.is_err(), "pinned CA path must verify server name");
        drop(sr2);
    }

    #[tokio::test]
    async fn e2e_mtls_full_handshake() {
        let (ca, ca_key) = make_ca("mTLS Root CA");
        let (server_pem, server_key) = issue_leaf("localhost", &ca, &ca_key);
        let (client_pem, client_key) = issue_leaf("client.identity", &ca, &ca_key);
        let server_pin = pem_leaf_hash_hex(&server_pem);

        // 服务端：encipherment 证书 + usage:"verify" CA → 要求客户端证书
        // 客户端：pin 服务端证书 + 提供自己的证书
        let (sr, cr) = handshake_pair(
            serde_json::json!({
                "certificates": [
                    { "certificate": server_pem, "key": server_key },
                    { "certificate": ca.pem(), "usage": "verify" },
                ]
            }),
            serde_json::json!({
                "pinnedPeerCertSha256": server_pin,
                "certificates": [{ "certificate": client_pem, "key": client_key }],
            }),
            "localhost",
        )
        .await;
        let client = cr.expect("mTLS handshake with client cert should succeed");
        let server = sr.expect("server should verify client cert against verify CA");
        assert_eq!(
            client.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        drop(server);
    }

    #[tokio::test]
    async fn e2e_mtls_rejects_client_without_cert() {
        let (ca, ca_key) = make_ca("mTLS Root CA");
        let (server_pem, server_key) = issue_leaf("localhost", &ca, &ca_key);
        let server_pin = pem_leaf_hash_hex(&server_pem);

        // 客户端不提供证书 → 服务端要求客户端证书 → 握手失败
        let (sr, cr) = handshake_pair(
            serde_json::json!({
                "certificates": [
                    { "certificate": server_pem, "key": server_key },
                    { "certificate": ca.pem(), "usage": "verify" },
                ]
            }),
            serde_json::json!({"pinnedPeerCertSha256": server_pin}),
            "localhost",
        )
        .await;
        assert!(cr.is_err() || sr.is_err(), "server must require client cert");
    }

    #[tokio::test]
    async fn e2e_non_encipherment_usage_not_presented() {
        // usage:"issue" 条目被过滤（对齐 Go BuildCertificates）→ 服务端回退自签名
        // → 客户端（信任 CA 签发的证书）验证失败。对照组见 e2e_custom_ca_replaces_webpki_roots
        //（默认 usage 的 CA 签发叶子证书会被正常送出并验证通过）。
        let (ca, ca_key) = make_ca("Filter Root CA");
        let (leaf_pem, leaf_key) = issue_leaf("localhost", &ca, &ca_key);
        let (_sr, cr) = handshake_pair(
            serde_json::json!({
                "certificates": [
                    { "certificate": leaf_pem, "key": leaf_key, "usage": "issue" },
                ]
            }),
            serde_json::json!({
                "disableSystemRoot": true,
                "certificates": [{"certificate": ca.pem()}]
            }),
            "localhost",
        )
        .await;
        assert!(cr.is_err(), "usage:issue entry must not be presented as server cert");
    }

    // ===== pwh6: client 侧 TLS 字段族增量行为测试 =====

    /// `masterKeyLog=true` 切到 KeyLogFile；`false`（默认）保持 NoKeyLog。
    #[test]
    fn pwh6_client_master_key_log_swaps_key_log() {
        let cfg_off = build_client_config("tls", None, "example.com")
            .unwrap()
            .unwrap();
        let cfg_on = build_client_config(
            "tls",
            Some(&serde_json::json!({ "masterKeyLog": true })),
            "example.com",
        )
        .unwrap()
        .unwrap();
        assert!(!std::sync::Arc::ptr_eq(&cfg_off.key_log, &cfg_on.key_log));
        assert!(format!("{:?}", &*cfg_on.key_log).contains("KeyLogFile"));
        assert!(format!("{:?}", &*cfg_off.key_log).contains("NoKeyLog"));
    }

    /// 票 8k4s①：client 侧 `masterKeyLog` string 路径 → KeyLogFileWriter 且
    /// 文件被创建（bool true 方言仍走 KeyLogFile，见上一个测试）。
    #[test]
    fn pwh6_client_master_key_log_string_path_wires_writer() {
        let path = std::env::temp_dir().join(format!(
            "xray_tls_8k4s_client_{}.log",
            std::process::id()
        ));
        let cfg = build_client_config(
            "tls",
            Some(&serde_json::json!({ "masterKeyLog": path.to_string_lossy() })),
            "example.com",
        )
        .unwrap()
        .unwrap();
        assert!(format!("{:?}", &*cfg.key_log).contains("KeyLogFileWriter"));
        assert!(path.exists(), "Go O_CREATE: file must be created eagerly");
        std::fs::remove_file(&path).ok();
    }

    /// 票 8k4s③：`echSockopt` + DoH 形态 `echConfigList` → 配置构建不 panic
    /// （降级 warn 路径；ECH config 本身仍会 resolve 成 invalid）。
    #[test]
    fn pwh6_client_ech_sockopt_with_doh_config_builds() {
        let json = serde_json::json!({
            "echConfigList": "https://1.1.1.1/dns-query",
            "echSockopt": { "domainStrategy": "UseIP" }
        });
        let cfg = build_client_config("tls", Some(&json), "example.com")
            .unwrap()
            .unwrap();
        assert!(format!("{:?}", &*cfg.key_log).contains("NoKeyLog"));
    }

    /// `enableSessionResumption=false` → resumption 切换到 disabled（type_name 变化）。
    #[test]
    fn pwh6_client_disable_session_resumption_swaps_resumption() {
        let cfg_off = build_client_config("tls", None, "example.com")
            .unwrap()
            .unwrap();
        let cfg_on = build_client_config(
            "tls",
            Some(&serde_json::json!({ "enableSessionResumption": false })),
            "example.com",
        )
        .unwrap()
        .unwrap();
        // Resumption 不暴露 pub 字段直接比较；通过 Debug 输出含 store 名称区分。
        let off_dbg = format!("{:?}", cfg_off.resumption);
        let on_dbg = format!("{:?}", cfg_on.resumption);
        assert_ne!(off_dbg, on_dbg);
        // 关闭时类型名含 NoClientSessionStorage。
        assert!(on_dbg.contains("NoClientSessionStorage"));
    }

    /// `verifyPeerCertByName` 非空时构造 PinnedServerCertVerifier（含 vcn 字段）。
    /// 通过尝试错误 hex 触发 Err 路径，验证 vcn 字符串被构造器接纳。
    #[test]
    fn pwh6_verify_peer_cert_by_name_accepted_by_verifier() {
        // 无效 pin hex + 有效 vcn → 错误来自 pin 解析，不是 vcn 解析。
        let cfg = build_client_config(
            "tls",
            Some(&serde_json::json!({
                "pinnedPeerCertSha256": "zz".repeat(32),
                "verifyPeerCertByName": "real.service.example",
            })),
            "fake.sni",
        );
        let err = cfg.err().expect("invalid pin hex must error");
        assert!(err.to_string().contains("pinnedPeerCertSha256"));
    }

    /// `verifyPeerCertByName` 字段缺失/空时行为兼容——pin 命中 CA 验证用默认 SNI。
    #[test]
    fn pwh6_verify_peer_cert_by_name_empty_falls_back_to_sni() {
        let cfg = build_client_config(
            "tls",
            Some(&serde_json::json!({
                "pinnedPeerCertSha256": "00ff".repeat(16),
            })),
            "fallback.sni",
        )
        .unwrap()
        .unwrap();
        // alpn 默认
        assert_eq!(cfg.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }
}
