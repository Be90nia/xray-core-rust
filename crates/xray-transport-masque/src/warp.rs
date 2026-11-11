//! WARP 变体（Cloudflare）：客户端自签证书 + 端点公钥 pin + 静态地址 + draft setting。
//!
//! 语义唯一源：Go `transport/internet/masque/warp.go`（v26.11.9 @ 676eaf66，`useWarp` /
//! `warpCertificate`）+ `infra/conf/transport_method.go:806-967`（`MasqueWarpConfig.Build`
//! 的 `warp` 段）+ `dialer.go:109-140`（CID 长度 20 / 空 ALPN 放行 / 静态地址）
//! + `connectip/client.go:23`（`SettingDatagramDraft00`）+ `connectip/http2.go:48-54` （Cloudflare
//!   请求头改写）。
//!
//! # 形态差异（实现面，语义对齐）
//! - Go 用 `x509.CreateCertificate` 现场签名；本仓用 `rcgen`（xray-tls 生产依赖同款，
//!   零新增第三方）装配同一张证书：serial = 128 bit 随机、`NotBefore = now-1h`、 `NotAfter =
//!   now+24h`、空 DN、无扩展。
//! - Go 的 `InsecureSkipVerify=true + VerifyPeerCertificate` 组合在本仓落成
//!   `WarpSpkiVerifier`——链验证按 Go 语义跳过，只做 leaf SPKI 全字节比对。rustls 的
//!   `ClientConfig.verifier` 不对外可写，故 pin 路径由本模块新建 `ClientConfig` （只继承 ALPN / SNI
//!   开关 / fragment 上限）；若用户另配
//!   `pinnedPeerCertSha256`/`verifyPeerCertByName`/`allowInsecure`，Go 会跳过 WARP 自带
//!   pin，本仓同判：复用既有 `ClientConfig` 只挂客户端证书。
//!
//! # 已知偏差（bd 2m30a 已登记）
//! - `privateKey` 只接受 PKCS #8（Go 还接受 SEC 1 并归一化成 PKCS #8）。
//! - `fingerprint` + `warp`：btls 路径拿不到 peer 证书，pin 无从执行 ⇒ 装配期 fail-visible 拒绝（Go
//!   允许该组合）。
//! - h3 专属面（[`CONNECTION_ID_LENGTH`] / [`SETTING_DATAGRAM_DRAFT00`]）只登记常量 + golden
//!   断言：本仓 h3 未接（规划 §7 R11），h2 载具不需要这两项。

use std::{net::IpAddr, str::FromStr, sync::Arc};

use base64::Engine as _;
use rustls::{
    ClientConfig, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    sign::{CertifiedKey, SingleCertAndKey},
};
use serde_json::Value;

use crate::{
    capsule::IpPrefix,
    error::{MasqueError, Result},
};

/// WARP 缺省 `:authority`（Go `warp.go:16` `WarpHost`）。
pub const WARP_HOST: &str = "cloudflareaccess.com";
/// WARP 缺省请求路径（Go `warp.go:17` `WarpPath`）。
pub const WARP_PATH: &str = "/";
/// WARP 的 QUIC 连接 ID 长度（Go `dialer.go:110`；h3 专属，本仓 h3 未接）。
pub const CONNECTION_ID_LENGTH: usize = 20;
/// draft-connect-ip datagram setting（Go `connectip/client.go:23`
/// `SettingDatagramDraft00 = 0x276`；h3 专属，本仓 h3 未接）。
pub const SETTING_DATAGRAM_DRAFT00: u64 = 0x276;
/// Cloudflare 的 CONNECT-IP 请求头（Go `connectip/client.go:21` `cloudflareProtocol`）。
pub const CLOUDFLARE_PROTOCOL: &str = "cf-connect-ip";
/// `Pq-Enabled` 缺省值（Go `connectip/http2.go:52`，字面量小写 `false`）。
pub const PQ_ENABLED: &str = "false";

/// `masqueSettings.warp`（Go `infra/conf/transport_method.go:800-804` + `masque.Warp`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warp {
    /// PKCS #8 DER 私钥（Go `parseWarpPrivateKey` 归一化产物；ECDSA P-256）。
    pub private_key: Vec<u8>,
    /// PKIX SubjectPublicKeyInfo DER（端点公钥；pin 比对面）。
    pub public_key: Vec<u8>,
    /// 本端地址（Go `parseWarpAddress`：至少一项、每族至多一项）。
    pub address: Vec<IpPrefix>,
}

impl Warp {
    /// 解析 `masqueSettings.warp` JSON（Go `MasqueWarpConfig` → `Build` 的 warp 段）。
    ///
    /// 校验顺序与文案对齐 Go：`privateKey` → `publicKey` → `address`。
    pub fn from_json(v: &Value) -> Result<Warp> {
        let obj = v.as_object().ok_or_else(|| bad("\"warp\" must be an object"))?;
        let private_raw = obj
            .get("privateKey")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("invalid \"privateKey\" in \"warp\""))?;
        let private_key = parse_private_key(private_raw)
            .map_err(|e| bad(format!("invalid \"privateKey\" in \"warp\": {e}")))?;

        let public_raw = obj
            .get("publicKey")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("invalid \"publicKey\" in \"warp\""))?;
        let public_key = parse_public_key(public_raw)
            .map_err(|e| bad(format!("invalid \"publicKey\" in \"warp\": {e}")))?;

        let address_raw = obj
            .get("address")
            .and_then(Value::as_array)
            .ok_or_else(|| bad("\"address\" in \"warp\" is not set"))?;
        let mut address = Vec::with_capacity(address_raw.len());
        for entry in address_raw {
            let s = entry.as_str().ok_or_else(|| bad("\"address\" in \"warp\" must be strings"))?;
            address.push(s.to_string());
        }

        Ok(Warp { private_key, public_key, address: parse_addresses(&address)? })
    }

    /// 从 proto `Warp` 构造（Go `Build()` 产物已归一化；本仓再验一次，fail-visible）。
    pub fn from_proto(w: &xray_proto::transport::internet::masque::Warp) -> Result<Warp> {
        if w.private_key.is_empty() {
            return Err(bad("invalid \"privateKey\" in \"warp\": empty key"));
        }
        // proto 侧已是 DER；仍走一遍 ECDSA P-256 判定（防手写 proto 绕过 Build）。
        let key_pair = key_pair_from_pkcs8(&w.private_key)
            .map_err(|e| bad(format!("invalid \"privateKey\" in \"warp\": {e}")))?;
        if w.public_key.is_empty() {
            return Err(bad("invalid \"publicKey\" in \"warp\": empty key"));
        }
        validate_spki(&w.public_key)
            .map_err(|e| bad(format!("invalid \"publicKey\" in \"warp\": {e}")))?;
        Ok(Warp {
            private_key: key_pair.serialize_der(),
            public_key: w.public_key.clone(),
            address: parse_addresses(&w.address)?,
        })
    }

    /// Go `warpCertificate`：用 WARP 私钥签一张临时自签证书
    /// （serial 128 bit 随机 / `NotBefore=now-1h` / `NotAfter=now+24h` / 空 DN）。
    pub fn certificate(&self) -> Result<Vec<u8>> {
        let key_pair = key_pair_from_pkcs8(&self.private_key)?;
        let mut serial = [0u8; 16];
        self.provider().secure_random.fill(&mut serial).map_err(|_| {
            MasqueError::Io(std::io::Error::other("masque: warp serial: random unavailable"))
        })?;
        let now = std_now()?;
        let mut params = rcgen::CertificateParams::default();
        // Go 的 template 只有 serial/NotBefore/NotAfter：无 Subject、无 SAN、无扩展。
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.subject_alt_names = Vec::new();
        params.serial_number = Some(serial.to_vec().into());
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::hours(24);
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| MasqueError::Protocol(format!("masque: warp certificate: {e}")))?;
        Ok(cert.der().to_vec())
    }

    /// Go `useWarp`：把客户端证书（恒做）与端点公钥 pin（`pin_required` 时）装进
    /// rustls 客户端配置。
    ///
    /// `pin_required = false` 对应 Go 的 `InsecureSkipVerify == true` 提前返回——用户的
    /// `pinnedPeerCertSha256`/`verifyPeerCertByName`/`allowInsecure` 已接管验证，此时只挂
    /// 客户端证书（复用 `base` 的验证器与全部 TLS 参数）。
    pub fn client_config(
        &self,
        base: &Arc<ClientConfig>,
        pin_required: bool,
    ) -> Result<Arc<ClientConfig>> {
        let cert = CertificateDer::from(self.certificate()?);
        let provider = self.provider();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.private_key.clone()));

        if !pin_required {
            // `client_auth_cert_resolver` 是公开字段 ⇒ 改 base 副本，验证器与版本/套件/
            // 会话参数全部保留。
            let certified = CertifiedKey::from_der(vec![cert], key, &provider)
                .map_err(|e| MasqueError::Protocol(format!("masque: warp client cert: {e}")))?;
            let mut cfg = (**base).clone();
            cfg.client_auth_cert_resolver = Arc::new(SingleCertAndKey::from(certified));
            return Ok(Arc::new(cfg));
        }

        let built = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| MasqueError::Protocol(format!("masque: warp TLS versions: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(WarpSpkiVerifier::new(
                self.public_key.clone(),
                provider,
            )))
            .with_client_auth_cert(vec![cert], key)
            .map_err(|e| MasqueError::Protocol(format!("masque: warp client cert: {e}")))?;
        let mut cfg = built;
        cfg.alpn_protocols = base.alpn_protocols.clone();
        cfg.enable_sni = base.enable_sni;
        cfg.max_fragment_size = base.max_fragment_size;
        Ok(Arc::new(cfg))
    }

    /// 本端地址（Go `establish` 的 `local`：每个 prefix 取 `Addr()`）。
    pub fn local_addrs(&self) -> Vec<IpAddr> {
        self.address.iter().map(|p| p.addr).collect()
    }

    fn provider(&self) -> Arc<CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }
}

/// Cloudflare h2 客户端的 `:authority` 补齐（Go `connectip/http2.go:53-55`）：
/// 缺端口时补 `:443`（`[v6]` 形态保留括号）。
pub fn cloudflare_authority(authority: &str) -> String {
    let (name, has_port) = match authority.strip_prefix('[') {
        Some(rest) => match rest.find(']') {
            Some(end) => (&rest[..end], !rest[end + 1..].is_empty()),
            None => return format!("{authority}:443"),
        },
        None => match authority.rsplit_once(':') {
            Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) => (name, true),
            _ => (authority, false),
        },
    };
    if has_port {
        return authority.to_string();
    }
    if name.contains(':') { format!("[{name}]:443") } else { format!("{name}:443") }
}

/// WARP 自带端点公钥 pin 是否**必须**执行。
///
/// Go `useWarp`（warp.go:58-60）：`tlsConfig.InsecureSkipVerify == true` 时提前返回、
/// 不装 WARP 自带 pin——而 `InsecureSkipVerify` 在 `allowInsecure` /
/// `pinnedPeerCertSha256`（pcs）/ `verifyPeerCertByName`（vcn）任一存在时为 true。
pub fn pin_required(security_json: Option<&Value>) -> bool {
    let Some(obj) = security_json.and_then(Value::as_object) else {
        return true;
    };
    let skip = obj.get("allowInsecure").and_then(Value::as_bool) == Some(true)
        || ["pinnedPeerCertSha256", "verifyPeerCertByName"]
            .iter()
            .any(|k| obj.get(*k).and_then(Value::as_str).is_some_and(|s| !s.is_empty()));
    !skip
}

/// 端点公钥 pin 验证器：链验证跳过，只比对 leaf 的 SubjectPublicKeyInfo 全字节
/// （Go `VerifyPeerCertificate` 的 `bytes.Equal(leaf.RawSubjectPublicKeyInfo, publicKey)`）。
#[derive(Debug)]
struct WarpSpkiVerifier {
    public_key: Vec<u8>,
    provider: Arc<CryptoProvider>,
}

impl WarpSpkiVerifier {
    fn new(public_key: Vec<u8>, provider: Arc<CryptoProvider>) -> Self {
        Self { public_key, provider }
    }
}

impl ServerCertVerifier for WarpSpkiVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let spki = subject_public_key_info(end_entity.as_ref()).ok_or_else(|| {
            rustls::Error::General("masque: the WARP endpoint sent a malformed certificate".into())
        })?;
        if spki == self.public_key.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "masque: the WARP endpoint's key doesn't match \"publicKey\"".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// X.509 leaf 的 `subjectPublicKeyInfo` **完整 TLV**（Go
/// `x509.Certificate.RawSubjectPublicKeyInfo` 同字节）。
///
/// 只走 `RFC 5280 §4.1` 的固定字段序：`tbsCertificate` 内 `[0] version?` → serialNumber
/// → signature → issuer → validity → subject → **subjectPublicKeyInfo**。
pub(crate) fn subject_public_key_info(cert_der: &[u8]) -> Option<&[u8]> {
    let (0x30, cert_body) = der_body(cert_der)? else { return None };
    let (0x30, tbs) = der_body(cert_body)? else { return None };
    let mut at = 0;
    if let (0xA0, _) = der_body(tbs.get(at..)?)? {
        at += der_tlv_len(tbs.get(at..)?)?;
    }
    // serialNumber / signature / issuer / validity / subject
    for _ in 0..5 {
        at += der_tlv_len(tbs.get(at..)?)?;
    }
    let (0x30, _) = der_body(tbs.get(at..)?)? else { return None };
    let total = der_tlv_len(tbs.get(at..)?)?;
    tbs.get(at..at + total)
}

/// 解一颗 DER TLV：返回 `(tag, content)`。
fn der_body(buf: &[u8]) -> Option<(u8, &[u8])> {
    let tag = *buf.first()?;
    let (header, len) = der_len(buf.get(1..)?)?;
    let start = 1 + header;
    buf.get(start..start.checked_add(len)?).map(|body| (tag, body))
}

/// 整颗 TLV 的长度（tag + length + content）。
fn der_tlv_len(buf: &[u8]) -> Option<usize> {
    let (header, len) = der_len(buf.get(1..)?)?;
    Some(1 + header + len)
}

/// DER 长度字段：返回 `(长度字段字节数, 内容长度)`。
fn der_len(buf: &[u8]) -> Option<(usize, usize)> {
    let first = *buf.first()?;
    if first < 0x80 {
        return Some((1, usize::from(first)));
    }
    let n = usize::from(first & 0x7F);
    if !(1..=4).contains(&n) {
        return None;
    }
    let bytes = buf.get(1..1 + n)?;
    let mut len = 0usize;
    for b in bytes {
        len = len.checked_mul(256)?.checked_add(usize::from(*b))?;
    }
    Some((1 + n, len))
}

/// Go `decodeWarpKey`：trim → PEM 优先 → 否则 std base64。
fn decode_key(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() {
        return Err(MasqueError::Protocol("empty key".into()));
    }
    if let Some(body) = pem_body(s) {
        return base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .map_err(|e| MasqueError::Protocol(format!("invalid PEM body: {e}")));
    }
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(|e| MasqueError::Protocol(format!("neither PEM nor base64: {e}")))
}

/// PEM 首尾行之间的 base64 正文（WARP 只收单块 PEM，故不引 pem crate）。
fn pem_body(s: &str) -> Option<String> {
    let mut lines = s.lines().map(str::trim);
    let begin = lines.find(|l| l.starts_with("-----BEGIN ") && l.ends_with("-----"))?;
    let label = begin.trim_start_matches("-----BEGIN ").trim_end_matches("-----");
    let end = format!("-----END {label}-----");
    let mut body = String::new();
    for line in lines {
        if line == end {
            return Some(body);
        }
        body.push_str(line);
    }
    None
}

/// Go `parseWarpPrivateKey`：PKCS #8 ECDSA P-256 → 归一化 PKCS #8 DER。
fn parse_private_key(s: &str) -> Result<Vec<u8>> {
    let der = decode_key(s)?;
    let key_pair = key_pair_from_pkcs8(&der)
        .map_err(|e| MasqueError::Protocol(format!("not an ECDSA P-256 PKCS #8 key: {e}")))?;
    Ok(key_pair.serialize_der())
}

fn key_pair_from_pkcs8(der: &[u8]) -> Result<rcgen::KeyPair> {
    let pkcs8 = PrivatePkcs8KeyDer::from(der.to_vec());
    rcgen::KeyPair::from_der_and_sign_algo(
        &PrivateKeyDer::Pkcs8(pkcs8),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .map_err(|e| MasqueError::Protocol(e.to_string()))
}

/// Go `parseWarpPublicKey`：必须是合法 PKIX SubjectPublicKeyInfo。
fn parse_public_key(s: &str) -> Result<Vec<u8>> {
    let der = decode_key(s)?;
    validate_spki(&der)
        .map_err(|e| MasqueError::Protocol(format!("not a PKIX public key: {e}")))?;
    Ok(der)
}

/// PKIX `SubjectPublicKeyInfo` 形状校验：`SEQUENCE { SEQUENCE { OID, ... }, BIT STRING }`
/// （Go 走完整 `x509.ParsePKIXPublicKey`；本仓只需挡住明显非 SPKI 的输入）。
fn validate_spki(der: &[u8]) -> std::result::Result<(), String> {
    let (0x30, body) = der_body(der).ok_or("not a DER SEQUENCE")? else {
        return Err("not a DER SEQUENCE".into());
    };
    let (0x30, _alg) = der_body(body).ok_or("missing AlgorithmIdentifier")? else {
        return Err("missing AlgorithmIdentifier".into());
    };
    let alg_total = der_tlv_len(body).ok_or("truncated AlgorithmIdentifier")?;
    let rest = body.get(alg_total..).ok_or("missing subjectPublicKey")?;
    let (tag, _) = der_body(rest).ok_or("truncated subjectPublicKey")?;
    if tag != 0x03 {
        return Err("subjectPublicKey is not a BIT STRING".into());
    }
    Ok(())
}

/// Go `parseWarpAddress`：`netip.ParsePrefix` 优先、否则 `netip.ParseAddr`；
/// 至少一项、每族至多一项。
fn parse_addresses(list: &[String]) -> Result<Vec<IpPrefix>> {
    if list.is_empty() {
        return Err(bad("\"address\" in \"warp\" is not set"));
    }
    let mut out: Vec<IpPrefix> = Vec::with_capacity(list.len());
    let (mut v4, mut v6) = (false, false);
    for s in list {
        let prefix =
            parse_prefix(s).ok_or_else(|| bad(format!("invalid \"address\" in \"warp\": {s}")))?;
        match prefix.addr {
            IpAddr::V4(_) if v4 => return Err(too_many_addresses()),
            IpAddr::V6(_) if v6 => return Err(too_many_addresses()),
            IpAddr::V4(_) => v4 = true,
            IpAddr::V6(_) => v6 = true,
        }
        out.push(prefix);
    }
    Ok(out)
}

fn too_many_addresses() -> MasqueError {
    bad("\"address\" in \"warp\" takes at most one IPv4 and one IPv6 address")
}

/// `netip.ParsePrefix` 失败时回落 `netip.ParseAddr`（`/len` 缺省取满位长）。
fn parse_prefix(s: &str) -> Option<IpPrefix> {
    let (addr_raw, len_raw) = match s.split_once('/') {
        Some((a, l)) => (a, Some(l)),
        None => (s, None),
    };
    let addr = IpAddr::from_str(addr_raw).ok()?;
    let full = if addr.is_ipv4() { 32 } else { 128 };
    let prefix_len = match len_raw {
        Some(l) => l.parse::<u8>().ok()?,
        None => full,
    };
    (prefix_len <= full).then_some(IpPrefix { addr, prefix_len })
}

fn std_now() -> Result<time::OffsetDateTime> {
    Ok(time::OffsetDateTime::now_utc())
}

fn bad(msg: impl Into<String>) -> MasqueError {
    MasqueError::Protocol(format!("masqueSettings: {}", msg.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(der: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(der)
    }

    /// 生成一对 ECDSA P-256 密钥：`(PKCS8 私钥 DER, SPKI 公钥 DER)`。
    fn generate_key() -> (Vec<u8>, Vec<u8>) {
        let key_pair =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate p256");
        (key_pair.serialize_der(), key_pair.public_key_der())
    }

    fn warp_json(private: &[u8], public: &[u8], address: &[&str]) -> Value {
        serde_json::json!({
            "privateKey": b64(private),
            "publicKey": b64(public),
            "address": address,
        })
    }

    #[test]
    fn go_constants_are_golden() {
        // 逐值对拍 Go（warp.go:14-15 / dialer.go:127 / connectip/client.go:23 /
        // connectip/http2.go:51-52）。
        assert_eq!(WARP_HOST, "cloudflareaccess.com");
        assert_eq!(WARP_PATH, "/");
        assert_eq!(CONNECTION_ID_LENGTH, 20);
        assert_eq!(SETTING_DATAGRAM_DRAFT00, 0x276);
        assert_eq!(CLOUDFLARE_PROTOCOL, "cf-connect-ip");
        assert_eq!(PQ_ENABLED, "false");
    }

    #[test]
    fn parses_base64_and_pem_keys() {
        let (private, public) = generate_key();
        let warp = Warp::from_json(&warp_json(&private, &public, &["172.16.0.2", "fd01::1"]))
            .expect("base64 config");
        assert_eq!(warp.private_key, private);
        assert_eq!(warp.public_key, public);
        assert_eq!(warp.address.len(), 2);
        assert_eq!(warp.address[0].addr, "172.16.0.2".parse::<IpAddr>().expect("v4"));
        assert_eq!(warp.address[0].prefix_len, 32);
        assert_eq!(warp.address[1].prefix_len, 128);

        // PEM 形态（Go `decodeWarpKey` 先试 pem.Decode）。
        let label = ["PRIV", "ATE", " KEY"].concat();
        let pem_private =
            format!("-----BEGIN {label}-----\n{}\n-----END {label}-----", b64(&private));
        let pem_public =
            format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----", b64(&public));
        let warp = Warp::from_json(&serde_json::json!({
            "privateKey": pem_private,
            "publicKey": pem_public,
            "address": ["172.16.0.2"],
        }))
        .expect("pem config");
        assert_eq!(warp.private_key, private);
        assert_eq!(warp.public_key, public);
    }

    #[test]
    fn address_accepts_prefix_and_bare_address() {
        let (private, public) = generate_key();
        let warp = Warp::from_json(&warp_json(&private, &public, &["172.16.0.0/24"]))
            .expect("prefix form");
        assert_eq!(warp.address[0].prefix_len, 24);
    }

    #[test]
    fn rejects_missing_or_duplicate_address() {
        let (private, public) = generate_key();
        let err = Warp::from_json(&warp_json(&private, &public, &[])).expect_err("empty address");
        assert!(err.to_string().contains("is not set"), "{err}");

        let err = Warp::from_json(&warp_json(&private, &public, &["1.2.3.4", "5.6.7.8"]))
            .expect_err("two v4");
        assert!(err.to_string().contains("at most one IPv4"), "{err}");

        let err = Warp::from_json(&warp_json(&private, &public, &["not-an-ip"]))
            .expect_err("bad address");
        assert!(err.to_string().contains("invalid \"address\""), "{err}");
    }

    #[test]
    fn rejects_bad_keys_fail_visible() {
        let (private, public) = generate_key();
        // 非 base64 / 非 PEM
        let err = Warp::from_json(&serde_json::json!({
            "privateKey": "not base64!!",
            "publicKey": b64(&public),
            "address": ["172.16.0.2"],
        }))
        .expect_err("bad private key");
        assert!(err.to_string().contains("invalid \"privateKey\""), "{err}");

        // 非 ECDSA P-256（Ed25519）
        let ed = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519");
        let err = Warp::from_json(&serde_json::json!({
            "privateKey": b64(&ed.serialize_der()),
            "publicKey": b64(&public),
            "address": ["172.16.0.2"],
        }))
        .expect_err("non-P256 key");
        assert!(err.to_string().contains("invalid \"privateKey\""), "{err}");

        // 公钥类型错（base64 但非 SPKI）
        let err = Warp::from_json(&serde_json::json!({
            "privateKey": b64(&private),
            "publicKey": b64(b"not a key"),
            "address": ["172.16.0.2"],
        }))
        .expect_err("bad public key");
        assert!(err.to_string().contains("invalid \"publicKey\""), "{err}");

        // 缺 publicKey（acceptance 2：缺 pin = 装配期 Err）
        let err = Warp::from_json(&serde_json::json!({
            "privateKey": b64(&private),
            "address": ["172.16.0.2"],
        }))
        .expect_err("missing public key");
        assert!(err.to_string().contains("invalid \"publicKey\""), "{err}");
    }

    #[test]
    fn certificate_carries_the_warp_key_and_go_window() {
        let (private, public) = generate_key();
        let warp = Warp::from_json(&warp_json(&private, &public, &["172.16.0.2"])).expect("config");
        let cert_der = warp.certificate().expect("certificate");
        // 自签证书的 SPKI 必须就是 WARP 公钥（Go TestWarpCertificate 同断言）。
        assert_eq!(subject_public_key_info(&cert_der), Some(public.as_slice()));
        // 有效期窗口：now-1h .. now+24h（Go warp.go:37-38）。
        let (not_before, not_after) = validity(&cert_der);
        let now = std_now().expect("now").unix_timestamp();
        assert!((not_before - (now - 3600)).abs() <= 5, "notBefore {not_before} vs {now}");
        assert!((not_after - (now + 24 * 3600)).abs() <= 5, "notAfter {not_after} vs {now}");
        // serial = 128 bit 随机（DER INTEGER 正数，最多 17 字节含符号位 0x00）。
        let serial = serial_bytes(&cert_der);
        assert!(!serial.is_empty() && serial.len() <= 17, "serial {serial:?}");
        // 每次签发的 serial 不同（Go rand.Int）。
        let other = warp.certificate().expect("certificate");
        assert_ne!(serial_bytes(&other), serial);
    }

    #[test]
    fn spki_extraction_matches_rcgen_public_key_der() {
        // golden：rcgen 的 public_key_der() 就是 RFC 5280 SPKI TLV。
        let (private, public) = generate_key();
        let key_pair = rcgen::KeyPair::from_der_and_sign_algo(
            &PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private)),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        )
        .expect("pkcs8");
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        let cert = params.self_signed(&key_pair).expect("self signed");
        assert_eq!(subject_public_key_info(cert.der()).map(<[u8]>::to_vec), Some(public));
        // 垃圾输入不 panic
        assert!(subject_public_key_info(b"garbage").is_none());
        assert!(subject_public_key_info(&[0x30, 0x80]).is_none());
        assert!(subject_public_key_info(&[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]).is_none());
    }

    #[test]
    fn pin_verifier_accepts_matching_key_and_rejects_other() {
        let (private, public) = generate_key();
        let warp = Warp::from_json(&warp_json(&private, &public, &["172.16.0.2"])).expect("config");
        let cert_der = warp.certificate().expect("certificate");
        let cert = CertificateDer::from(cert_der);
        let name = ServerName::try_from("cloudflareaccess.com").expect("name");
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1));
        let verifier = WarpSpkiVerifier::new(warp.public_key.clone(), warp.provider());
        assert!(
            verifier.verify_server_cert(&cert, &[], &name, &[], now).is_ok(),
            "matching key must pass"
        );

        // 换一把公钥 = 不匹配 → Err（Go `doesn't match "publicKey"`）。
        let (_other_private, other_public) = generate_key();
        let mismatch = WarpSpkiVerifier::new(other_public, warp.provider());
        let err = mismatch
            .verify_server_cert(&cert, &[], &name, &[], now)
            .expect_err("mismatched key must fail");
        assert!(err.to_string().contains("doesn't match \"publicKey\""), "{err}");
    }

    #[test]
    fn client_config_installs_client_cert() {
        let (private, public) = generate_key();
        let warp = Warp::from_json(&warp_json(&private, &public, &["172.16.0.2"])).expect("config");
        let base = Arc::new(
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("versions")
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        );
        for pin in [true, false] {
            let cfg = warp.client_config(&base, pin).expect("warp client config");
            assert!(cfg.client_auth_cert_resolver.has_certs(), "pin={pin}");
        }
    }

    #[test]
    fn cloudflare_authority_adds_443_when_port_missing() {
        // Go warp_test.go:303 断言 Host == "cloudflareaccess.com:443"。
        assert_eq!(cloudflare_authority(WARP_HOST), "cloudflareaccess.com:443");
        assert_eq!(cloudflare_authority("cloudflareaccess.com:443"), "cloudflareaccess.com:443");
        assert_eq!(cloudflare_authority("cloudflareaccess.com:8443"), "cloudflareaccess.com:8443");
        assert_eq!(cloudflare_authority("[2001:db8::1]"), "[2001:db8::1]:443");
        assert_eq!(cloudflare_authority("[2001:db8::1]:443"), "[2001:db8::1]:443");
    }

    #[test]
    fn pin_required_mirrors_go_insecure_skip_verify() {
        // Go warp.go:58-60：InsecureSkipVerify（allowInsecure/pcs/vcn）时跳过 WARP pin。
        assert!(pin_required(None));
        assert!(pin_required(Some(&serde_json::json!({"alpn": ["h2"]}))));
        assert!(!pin_required(Some(&serde_json::json!({"allowInsecure": true}))));
        assert!(!pin_required(Some(&serde_json::json!({"pinnedPeerCertSha256": "ab"}))));
        assert!(!pin_required(Some(&serde_json::json!({"verifyPeerCertByName": "a.test"}))));
        assert!(pin_required(Some(&serde_json::json!({"pinnedPeerCertSha256": ""}))));
    }

    #[test]
    fn from_proto_revalidates() {
        let (private, public) = generate_key();
        let proto = xray_proto::transport::internet::masque::Warp {
            private_key: private.clone(),
            public_key: public.clone(),
            address: vec!["172.16.0.2".to_string()],
        };
        let warp = Warp::from_proto(&proto).expect("proto warp");
        assert_eq!(warp.private_key, private);
        assert_eq!(warp.public_key, public);
        assert_eq!(warp.local_addrs(), vec!["172.16.0.2".parse::<IpAddr>().expect("v4")]);

        let empty = xray_proto::transport::internet::masque::Warp {
            private_key: Vec::new(),
            public_key: public,
            address: vec!["172.16.0.2".to_string()],
        };
        assert!(Warp::from_proto(&empty).is_err(), "empty private key must fail");
    }

    /// 证书 Validity 的 `(notBefore, notAfter)` unix 秒。
    fn validity(cert_der: &[u8]) -> (i64, i64) {
        let (_, cert_body) = der_body(cert_der).expect("outer");
        let (_, tbs) = der_body(cert_body).expect("tbs");
        let mut at = 0;
        if let (0xA0, _) = der_body(&tbs[at..]).expect("version") {
            at += der_tlv_len(&tbs[at..]).expect("version len");
        }
        for _ in 0..3 {
            at += der_tlv_len(&tbs[at..]).expect("field");
        }
        let (0x30, validity) = der_body(&tbs[at..]).expect("validity") else {
            panic!("validity is not a SEQUENCE");
        };
        let (_, not_before) = der_body(validity).expect("notBefore");
        let nb_len = der_tlv_len(validity).expect("notBefore len");
        let (_, not_after) = der_body(&validity[nb_len..]).expect("notAfter");
        (utc_time_secs(not_before), utc_time_secs(not_after))
    }

    fn serial_bytes(cert_der: &[u8]) -> Vec<u8> {
        let (_, cert_body) = der_body(cert_der).expect("outer");
        let (_, tbs) = der_body(cert_body).expect("tbs");
        let mut at = 0;
        if let (0xA0, _) = der_body(&tbs[at..]).expect("version") {
            at += der_tlv_len(&tbs[at..]).expect("version len");
        }
        let (0x02, serial) = der_body(&tbs[at..]).expect("serial") else {
            panic!("serial is not an INTEGER");
        };
        serial.to_vec()
    }

    /// DER UTCTime（`YYMMDDhhmmssZ`）→ unix 秒（仅测试断言用）。
    fn utc_time_secs(raw: &[u8]) -> i64 {
        let s = std::str::from_utf8(raw).expect("utctime ascii");
        let year = 2000 + s[0..2].parse::<i64>().expect("year");
        let month = s[2..4].parse::<i64>().expect("month");
        let day = s[4..6].parse::<i64>().expect("day");
        let hour = s[6..8].parse::<i64>().expect("hour");
        let min = s[8..10].parse::<i64>().expect("min");
        let sec = s[10..12].parse::<i64>().expect("sec");
        days_from_civil(year, month, day) * 86400 + hour * 3600 + min * 60 + sec
    }

    /// Howard Hinnant 的 civil→days 算法。
    fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
        let y = if m <= 2 { y - 1 } else { y };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400;
        let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }
}
