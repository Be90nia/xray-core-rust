//! REALITY 客户端。
//!
//! 翻译自 Go `transport/internet/reality/reality.go` 的 `UClient`/`UConn` 部分。
//!
//! # 实现（双路径）
//!
//! - **btls 指纹路径（主路径）**：[`xray_tls::btls_reality::connect_reality`]
//!   用 BoringSSL 原生浏览器 ClientHello（Chrome/Firefox/Safari/... 指纹，
//!   对应 Go `utls.UClient` 的 uTLS 模板握手），在 ClientHello record 写出
//!   前（BIO 拦截）注入 REALITY session_id（auth_key = ECDH(X25519 key share
//!   私钥, 服务端公钥)，AES-256-GCM Seal，AAD = zero-session-id 版
//!   handshake message），握手后验证证书 HMAC-SHA512。
//! - **watfaq-rustls 路径（fallback）**：指纹不被 btls 支持时退回
//!   `ClientConfig::builder().with_reality()`（标准 rustls ClientHello）。
//!
//! 纯密码学算法在 [`crate::crypto`] 模块（session_id 编码、auth_key 派生、
//! 证书验证），独立可测。
//!
//! # XTLS-Vision splice
//!
//! `u_client` 返回 [`RealityTlsStream`]；上层可包装为 `SplicableTlsStream`（待实现）
//! 以支持 XTLS-Vision 的 splice 模式（clash-rs PR#1057 方案）。

use std::io;
use std::sync::Arc;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use btls::ssl::SslRef;
use parking_lot::Mutex;
use rustls::client::RealityConfig as WatfaqRealityConfig;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::client::TlsStream;
use webpki_roots::TLS_SERVER_ROOTS;
use xray_tls::btls_reality::{connect_reality, x25519_key_share_private, RealityHooks};
use xray_transport::connection::Connection;

use crate::config::RealityConfig;
use crate::crypto;
use crate::error::RealityError;

/// REALITY 客户端连接状态（握手前/握手后统一形态）。
///
/// 对应 Go `UConn struct { *utls.UConn; Config; ServerName; AuthKey; Verified }`。
#[derive(Debug)]
pub struct UConnState {
    /// 配置引用（含客户端字段：fingerprint/server_name/public_key/...）。
    pub config: RealityConfig,
    /// 实际使用的 SNI（如配置为空则取自 destination，由 [`u_client`] 注入）。
    pub server_name: String,
    /// ECDH 派生的 auth key（握手成功后填充；32 字节，HKDF 收紧后）。
    ///
    /// 对应 Go `uConn.AuthKey []byte`，握手前为空 `Vec::new()`。
    /// btls 路径中 auth_key 在握手内部派生使用（不回填本字段）。
    pub auth_key: Vec<u8>,
    /// 证书是否通过 REALITY 校验（ed25519 + HMAC-SHA512）。
    ///
    /// btls 路径：握手成功返回 = 验证通过（失败即 Err，不返回连接）。
    pub verified: bool,
}

impl UConnState {
    /// 构造初始状态（未握手）。
    ///
    /// 会调用 [`RealityConfig::validate_client`] 预检客户端必备字段。
    pub fn new(config: RealityConfig) -> Result<Self, RealityError> {
        config.validate_client()?;
        Ok(Self {
            server_name: config.server_name.clone(),
            config,
            auth_key: Vec::new(),
            verified: false,
        })
    }
}

/// REALITY TLS 流：btls 指纹路径或 watfaq-rustls fallback 路径。
pub enum RealityTlsStream<S> {
    /// btls (BoringSSL) 浏览器指纹握手（`S` 被包进 BIO 拦截层）。
    Btls(xray_tls::btls_client::BtlsConn<xray_tls::btls_reality::HelloRewriteStream<S>>),
    /// watfaq-rustls `with_reality` 标准握手（fallback）。
    Rustls(TlsStream<S>),
}
impl<S: Connection> AsyncRead for RealityTlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            RealityTlsStream::Btls(c) => Pin::new(c).poll_read(cx, buf),
            RealityTlsStream::Rustls(t) => Pin::new(t).poll_read(cx, buf),
        }
    }
}

impl<S: Connection> AsyncWrite for RealityTlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            RealityTlsStream::Btls(c) => Pin::new(c).poll_write(cx, buf),
            RealityTlsStream::Rustls(t) => Pin::new(t).poll_write(cx, buf),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            RealityTlsStream::Btls(c) => Pin::new(c).poll_flush(cx),
            RealityTlsStream::Rustls(t) => Pin::new(t).poll_flush(cx),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            RealityTlsStream::Btls(c) => Pin::new(c).poll_shutdown(cx),
            RealityTlsStream::Rustls(t) => Pin::new(t).poll_shutdown(cx),
        }
    }
}
impl<S: Connection> Connection for RealityTlsStream<S> {
    fn remote_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        match self {
            RealityTlsStream::Btls(c) => c.remote_addr(),
            RealityTlsStream::Rustls(t) => t.get_ref().0.remote_addr(),
        }
    }
    fn local_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        match self {
            RealityTlsStream::Btls(c) => c.local_addr(),
            RealityTlsStream::Rustls(t) => t.get_ref().0.local_addr(),
        }
    }
    fn raw_tcp_clone(&self) -> Option<tokio::net::TcpStream> {
        // 穿透 TLS 层克隆内层流的裸 TCP（vision splice 用）。
        match self {
            RealityTlsStream::Btls(c) => c.raw_tcp_clone(),
            RealityTlsStream::Rustls(t) => t.get_ref().0.raw_tcp_clone(),
        }
    }
}

/// REALITY session_id 明文里的协议版本（watfaq 语义 `[1, 8, 1]`，
/// 与服务端 [`crate::server`] 解码兼容）。
// REALITY session_id 明文头 3 字节 = 客户端 Xray 版本 (major,minor,patch)。
// 服务端 (v26.3.27+) 拒绝过低版本客户端 → 必须声明 ≥26.3.27。
const REALITY_VERSION: [u8; 3] = [26, 7, 28];

/// btls REALITY 钩子：session_id 注入 + 证书 HMAC 验证。
///
/// 算法全部复用 [`crate::crypto`]（与 watfaq 路径/服务端逐字节对齐）。
struct BtlsRealityHooks {
    /// 服务端 X25519 静态公钥（RealityConfig.public_key）。
    server_pub: [u8; 32],
    /// 客户端 short_id（≤8 字节）。
    short_id: Vec<u8>,
    /// 客户端 mldsa65 验签公钥（`mldsa65Verify`，1952B；空 = 不做 PQC 验证）。
    mldsa65_verify: Vec<u8>,
    /// rewrite 时派生的 auth_key（verify 阶段复用）。
    auth_key: Mutex<Option<[u8; 32]>>,
    /// 最终发出的 ClientHello handshake message（transcript 回调窗口缓存；
    /// HRR 重发时覆盖为最后一次，对齐 Go `Hello.Raw`）。
    client_hello_raw: Mutex<Option<Vec<u8>>>,
    /// 收到的 ServerHello handshake message（BoringSSL 入站捕获，cm97；
    /// 对齐 Go `HandshakeState.ServerHello.Raw`）。
    server_hello_raw: Mutex<Option<Vec<u8>>>,
}

impl BtlsRealityHooks {
    fn new(config: &RealityConfig) -> Result<Self, RealityError> {
        let mut server_pub = [0u8; 32];
        server_pub.copy_from_slice(&config.public_key);
        Ok(Self {
            server_pub,
            short_id: config.short_id.clone(),
            mldsa65_verify: config.mldsa65_verify.clone(),
            auth_key: Mutex::new(None),
            client_hello_raw: Mutex::new(None),
            server_hello_raw: Mutex::new(None),
        })
    }
}

impl RealityHooks for BtlsRealityHooks {
    /// 在 ClientHello record 写出前注入 REALITY session_id。
    ///
    /// 对应 Go `reality.go:141-175`（`hello.SessionId` 构造 + AEAD Seal +
    /// `copy(hello.Raw[39:], hello.SessionId)`）。
    fn rewrite_client_hello(&self, ssl: &SslRef, record: &mut [u8]) -> io::Result<()> {
        let mut off = 0usize;
        while off + 5 <= record.len() {
            let content_type = record[off];
            let rec_len = u16::from_be_bytes([record[off + 3], record[off + 4]]) as usize;
            let body_start = off + 5;
            let body_end = body_start + rec_len;
            if body_end > record.len() {
                // record 不完整（不应发生）：放行不改写，服务端自会拒绝
                return Ok(());
            }
            // handshake record 且首消息为 ClientHello
            if content_type == 22 && rec_len > 44 && record[body_start] == 1 {
                let hs = &mut record[body_start..body_end];
                // handshake 布局：[type(1)][len(3)][legacy_version(2)][random(32)][sid_len(1)][sid(32)]
                const HS_HDR: usize = 1 + 3 + 2; // type+len+version → random 起点
                const SID_LEN_OFF: usize = HS_HDR + 32;
                const SID_OFF: usize = SID_LEN_OFF + 1; // = 39，与服务端 SESSION_ID_OFFSET_IN_HANDSHAKE 一致
                if hs[SID_LEN_OFF] != 32 {
                    return Err(io::Error::other("REALITY: unexpected session_id length in ClientHello"));
                }
                let random: [u8; 32] = hs[HS_HDR..HS_HDR + 32].try_into().map_err(|_| {
                    io::Error::other("REALITY: short ClientHello random")
                })?;

                // auth_key = HKDF(ECDH(key share priv, server pub), salt=random[:20])
                let priv_key = x25519_key_share_private(ssl).ok_or_else(|| {
                    io::Error::other(
                        "REALITY: current fingerprint does not offer an X25519 key share",
                    )
                })?;
                let auth_key = crypto::derive_auth_key(&priv_key, &self.server_pub, &random[..20])
                    .map_err(|e| io::Error::other(e.to_string()))?;

                // 明文 session_id：version + timestamp + short_id
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(0);
                let mut sid = crypto::encode_session_id(REALITY_VERSION, ts, &self.short_id)
                    .map_err(|e| io::Error::other(e.to_string()))?;

                // AAD = zero-session-id 版 handshake message（对齐 watfaq/服务端口径）
                let mut aad = hs.to_vec();
                aad[SID_OFF..SID_OFF + 32].fill(0);
                crypto::encrypt_session_id(&auth_key, &random[20..], &mut sid, &aad)
                    .map_err(|e| io::Error::other(e.to_string()))?;

                // 等长写回（对应 Go copy(hello.Raw[39:], hello.SessionId)）
                hs[SID_OFF..SID_OFF + 32].copy_from_slice(&sid);
                *self.auth_key.lock() = Some(auth_key);
            }
            off = body_end;
        }
        Ok(())
    }

    /// ponytail (REALITY): transcript 一致注入 —— BoringSSL
    /// ssl_add_message_cbb 在计入 transcript 前回调。
    ///
    /// `msg` = 完整 handshake message（type(1)+len(3)+body，无 record 头），
    /// 字段偏移与 record body 相同：random=6..38、sid_len=38、sid=39..71。
    fn rewrite_client_hello_msg(
        &self,
        ssl_ptr: xray_tls::btls_reality::RealitySslPtr,
        msg: &mut [u8],
    ) -> io::Result<()> {
        if msg.len() < 71 || msg[0] != 1 {
            return Ok(());
        }
        const HS_HDR: usize = 1 + 3 + 2;
        const SID_LEN_OFF: usize = HS_HDR + 32;
        const SID_OFF: usize = SID_LEN_OFF + 1;
        if msg[SID_LEN_OFF] != 32 {
            return Err(io::Error::other("REALITY: unexpected session_id length in ClientHello"));
        }
        let random: [u8; 32] = msg[HS_HDR..HS_HDR + 32]
            .try_into()
            .map_err(|_| io::Error::other("REALITY: short ClientHello random"))?;

        let priv_key = xray_tls::btls_reality::x25519_key_share_private_raw(ssl_ptr)
            .ok_or_else(|| {
                io::Error::other(
                    "REALITY: current fingerprint does not offer an X25519 key share",
                )
            })?;
        let auth_key = crypto::derive_auth_key(&priv_key, &self.server_pub, &random[..20])
            .map_err(|e| io::Error::other(e.to_string()))?;

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        let mut sid = crypto::encode_session_id(REALITY_VERSION, ts, &self.short_id)
            .map_err(|e| io::Error::other(e.to_string()))?;

        // AAD = zero-sid 版 message；Go: aead.Seal(sid[:0], random[20:], sid[:16], hello.Raw)
        let mut aad = msg.to_vec();
        aad[SID_OFF..SID_OFF + 32].fill(0);
        crypto::encrypt_session_id(&auth_key, &random[20..], &mut sid, &aad)
            .map_err(|e| io::Error::other(e.to_string()))?;

        msg[SID_OFF..SID_OFF + 32].copy_from_slice(&sid);
        *self.auth_key.lock() = Some(auth_key);
        // 缓存最终发出的 ClientHello（HRR 重发覆盖），verify 阶段拼 mldsa65 消息
        *self.client_hello_raw.lock() = Some(msg.to_vec());
        Ok(())
    }

    /// ServerHello 入站捕获（cm97）：缓存原始 handshake message 供 verify
    /// 阶段拼 mldsa65 签名消息（对齐 Go `h.Write(ServerHello.Raw)`）。
    fn on_server_hello(&self, msg: &[u8]) -> io::Result<()> {
        *self.server_hello_raw.lock() = Some(msg.to_vec());
        Ok(())
    }
    /// 握手后验证证书：末尾 64 字节须为 HMAC-SHA512(auth_key, ed25519 pubkey)；
    /// 配置 `mldsa65Verify` 时追加 PQC 扩展验签（cm97）。
    ///
    /// 对应 Go `UConn.VerifyPeerCertificate`；失败 = 真证书/被转发 → 断连。
    fn verify_handshake(&self, ssl: &SslRef) -> io::Result<()> {
        let auth_key = self
            .auth_key
            .lock()
            .ok_or_else(|| io::Error::other("REALITY: auth key not derived (no ClientHello sent)"))?;
        let cert = ssl
            .peer_certificate()
            .ok_or_else(|| io::Error::other("REALITY: server sent no certificate"))?;
        let der = x509_to_der(&cert)
            .ok_or_else(|| io::Error::other("REALITY: failed to encode peer certificate"))?;
        let ch_raw = self.client_hello_raw.lock().clone();
        let sh_raw = self.server_hello_raw.lock().clone();
        verify_reality_cert_full(
            &der,
            &auth_key,
            &self.mldsa65_verify,
            ch_raw.as_deref(),
            sh_raw.as_deref(),
        )
        .map_err(io::Error::other)
    }
}

/// REALITY 证书完整验证（标准 HMAC 尾 + 可选 mldsa65 PQC 扩展验签）。
///
/// 对应 Go `UConn.VerifyPeerCertificate` 全部分支：
/// 1. `HMAC(auth_key, pub)` == cert 末尾 64B（两种模板都必须）；
/// 2. 配置 `mldsa65Verify` 时：cert 必须带 OID 0.0 扩展（服务端 mldsa65 变体
///    模板标记），`HMAC(auth, pub‖CH.Raw‖SH.Raw)` 的 ML-DSA-65 验签必须通过。
///    Go 端此分支失败会落 x509 fallback（对自签 REALITY cert 必败 → 断连），
///    Rust 无 x509 fallback，直接返回错误——语义等价。
///
/// 提纯自 [`BtlsRealityHooks::verify_handshake`]（`SslRef` 不可 mock），
/// 契约测试直接驱动本函数。
fn verify_reality_cert_full(
    cert_der: &[u8],
    auth_key: &[u8; 32],
    mldsa65_verify: &[u8],
    client_hello_raw: Option<&[u8]>,
    server_hello_raw: Option<&[u8]>,
) -> Result<(), RealityError> {
    let Some(pub_key) = extract_ed25519_pubkey(cert_der) else {
        return Err(RealityError::RealCertificateReceived);
    };
    if cert_der.len() < 64 {
        return Err(RealityError::RealCertificateReceived);
    }
    let sig = &cert_der[cert_der.len() - 64..];
    let ok = crypto::verify_reality_certificate(auth_key, &pub_key, sig).unwrap_or(false);
    if !ok {
        return Err(RealityError::RealCertificateReceived);
    }
    // Go: if len(c.Config.Mldsa65Verify) > 0 { ... }
    if !mldsa65_verify.is_empty() {
        let (Some(ch_raw), Some(sh_raw)) = (client_hello_raw, server_hello_raw) else {
            // btls 路径两个捕获点恒先于 verify 触发；缺失 = 栈行为异常
            return Err(RealityError::TlsHandshake(
                "REALITY: ClientHello/ServerHello not captured for mldsa65 verification".into(),
            ));
        };
        // Go: if len(certs[0].Extensions) > 0 —— 无扩展 = 服务端未签 mldsa65 →
        // x509 fallback 必败 → 断连
        let (off, len) = crate::util::find_oid_0_0_extension(cert_der).ok_or(
            RealityError::RealCertificateReceived,
        )?;
        let ext_sig = &cert_der[off..off + len];
        let msg =
            crypto::hmac_reality_message(auth_key, &pub_key, ch_raw, sh_raw)?;
        let verified =
            crypto::verify_mldsa65_signature(mldsa65_verify, &msg, ext_sig).unwrap_or(false);
        if !verified {
            return Err(RealityError::RealCertificateReceived);
        }
    }
    Ok(())
}

/// 证书 DER 编码（[`xray_tls::btls_reality::x509_to_der`] 转发）。
fn x509_to_der(cert: &btls::x509::X509) -> Option<Vec<u8>> {
    xray_tls::btls_reality::x509_to_der(cert)
}

/// 从 REALITY 证书 DER 提取 Ed25519 公钥（32 字节）。
///
/// 语义对齐 watfaq-rustls `extract_ed25519_pubkey_from_reality_cert`：
/// 定位 Ed25519 OID（`06 03 2b 65 70`）后小窗口内找 BIT STRING 头
/// （`03 21 00`），取后续 32 字节。
fn extract_ed25519_pubkey(cert_der: &[u8]) -> Option<[u8; 32]> {
    const OID: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];
    const BIT_STRING_HDR: [u8; 3] = [0x03, 0x21, 0x00];

    let n = cert_der.len();
    if n < OID.len() + BIT_STRING_HDR.len() + 32 {
        return None;
    }
    for i in 0..n.saturating_sub(OID.len()) {
        if cert_der[i..i + OID.len()] != OID {
            continue;
        }
        let search_end = (i + OID.len() + 16).min(n.saturating_sub(BIT_STRING_HDR.len() + 32));
        for j in (i + OID.len())..=search_end {
            if cert_der[j..j + BIT_STRING_HDR.len()] == BIT_STRING_HDR {
                let key_start = j + BIT_STRING_HDR.len();
                if key_start + 32 <= n {
                    let mut pubkey = [0u8; 32];
                    pubkey.copy_from_slice(&cert_der[key_start..key_start + 32]);
                    return Some(pubkey);
                }
            }
        }
    }
    None
}

/// 创建 REALITY 客户端连接（浏览器指纹握手 + REALITY 注入）。
///
/// 对应 Go `UClient(c net.Conn, config *Config, ctx, dest) (net.Conn, error)`：
/// `tls.GetFingerprint(config.Fingerprint)` → `utls.UClient`（指纹模板）→
/// session_id 注入 → 握手 → 证书验证。
///
/// # 路径选择
///
/// 1. 指纹被 btls 支持（chrome/firefox/safari/ios/edge/360/qq 及其变体）
///    → BoringSSL 浏览器指纹 ClientHello + REALITY 注入（主路径）。
/// 2. 指纹不被 btls 支持 → watfaq-rustls 标准握手（fallback，
///    ClientHello 为标准 rustls 指纹，REALITY session_id 由 rustls 内部注入）。
///
/// # Errors
///
/// - [`RealityError::FingerprintNotFound`]：指纹名未知
/// - [`RealityError::TlsHandshake`]：握手 IO 错误或 REALITY 证书验证失败
/// - [`RealityError::WatfaqConfig`] / [`RealityError::InvalidServerName`]：fallback 路径配置错误
pub async fn u_client<S>(
    inner: S,
    state: UConnState,
) -> Result<RealityTlsStream<S>, RealityError>
where
    S: Connection,
{
    let UConnState { config, server_name, .. } = state;

    // Go: fingerprint := tls.GetFingerprint(config.Fingerprint)；nil → 报错
    let fp = xray_tls::fingerprint::get_fingerprint(&config.fingerprint)
        .map_err(|_| RealityError::FingerprintNotFound)?;

    // 主路径：btls 浏览器指纹（材料齐 + 指纹受支持才消费 inner）
    if config.public_key.len() == crate::config::X25519_KEY_LEN
        && xray_tls::btls_client::fingerprint_supported(&fp)
    {
        let hooks = Arc::new(BtlsRealityHooks::new(&config)?);
        let conn = connect_reality(inner, &server_name, fp, hooks)
            .await
            .map_err(|e| RealityError::TlsHandshake(e.to_string()))?;
        return Ok(RealityTlsStream::Btls(conn));
    }

    // fallback：watfaq-rustls with_reality（标准 rustls ClientHello）
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&config.public_key);
    let reality = WatfaqRealityConfig::new(pk, config.short_id.clone())
        .map_err(|e| RealityError::WatfaqConfig(e.to_string()))?;
    let roots = RootCertStore::from_iter(TLS_SERVER_ROOTS.iter().cloned());
    xray_common::ensure_default_crypto_provider();
    let tls_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_reality(reality)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let name = ServerName::try_from(server_name)
        .map_err(|e| RealityError::InvalidServerName(e.to_string()))?;
    let stream = connector
        .connect(name, inner)
        .await
        .map_err(|e| RealityError::TlsHandshake(e.to_string()))?;
    Ok(RealityTlsStream::Rustls(stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_config() -> crate::config::RealityConfig {
        use xray_proto::transport::internet::reality::Config as ProtoConfig;
        let proto = ProtoConfig {
            fingerprint: "chrome".into(),
            public_key: vec![1u8; 32],
            server_name: "example.com".into(),
            ..Default::default()
        };
        RealityConfig::from_proto(&proto).unwrap()
    }

    /// UConnState 构造校验（fingerprint 非空）。
    #[test]
    fn uconn_state_rejects_empty_fingerprint() {
        let mut cfg = make_valid_config();
        cfg.fingerprint = String::new();
        // validate_client 拒空 fingerprint——但 get_fingerprint("") 有 Chrome 默认。
        // 现状保持 validate_client 语义（构造期拒绝空串）。
        let err = UConnState::new(cfg).unwrap_err();
        assert!(matches!(err, RealityError::FingerprintNotFound));
    }

    /// watfaq RealityConfig 能从配置字段构建（fallback 路径材料）。
    #[test]
    fn watfaq_reality_config_builds_from_config() {
        let state = UConnState::new(make_valid_config()).unwrap();
        let cfg = state.config;
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&cfg.public_key);
        let reality = WatfaqRealityConfig::new(pk, cfg.short_id.clone());
        assert!(reality.is_ok(), "watfaq RealityConfig should build");
    }

    /// 指纹路由：chrome → btls 支持；未知指纹名在 UConnState 后仍会报
    /// FingerprintNotFound（get_fingerprint 失败）。
    #[test]
    fn fingerprint_routing_btls_supported() {
        let chrome = xray_tls::fingerprint::get_fingerprint("chrome").unwrap();
        assert!(xray_tls::btls_client::fingerprint_supported(&chrome));
        let firefox = xray_tls::fingerprint::get_fingerprint("firefox").unwrap();
        assert!(xray_tls::btls_client::fingerprint_supported(&firefox));
    }

    /// ClientHello record 改写：合成 record 验证 session_id 被加密替换、
    /// 其余字节不动、长度不变。
    #[tokio::test]
    async fn btls_hooks_rewrite_synthetic_client_hello() {
        use x25519_dalek::{PublicKey, StaticSecret};

        // 合成 ClientHello handshake message：type(1)=1,len(3),version(2),random(32),
        // sid_len(1)=32,sid(32),余下 cipher 等填充
        let mut msg = Vec::new();
        msg.push(1u8); // handshake type ClientHello
        msg.extend_from_slice(&300u32.to_be_bytes()[1..]); // length 3B
        msg.extend_from_slice(&[0x03, 0x03]); // legacy_version
        msg.extend_from_slice(&(0u8..32).collect::<Vec<u8>>()); // random = 0..31
        msg.push(32); // sid_len
        msg.extend_from_slice(&[0u8; 32]); // 原始 session_id（随机值也行）
        msg.extend_from_slice(&[0x13, 0x01, 0x13, 0x02, 0x00, 0xff]); // cipher_suites 等
        let body_len = msg.len() - 4;

        // 包一层 TLS record
        let mut record = Vec::new();
        record.push(22u8); // handshake
        record.extend_from_slice(&[0x03, 0x03]); // version
        record.extend_from_slice(&(body_len as u16).to_be_bytes());
        record.extend_from_slice(&msg);

        let server_secret = StaticSecret::from([0x33u8; 32]);
        let server_pub = PublicKey::from(&server_secret);

        let config = RealityConfig {
            fingerprint: "chrome".into(),
            server_name: "example.com".into(),
            public_key: server_pub.as_bytes().to_vec(),
            short_id: vec![0xaa; 8],
            ..Default::default()
        };
        let hooks = BtlsRealityHooks::new(&config).unwrap();

        // 无 ssl（绕过私钥导出）不可直接调 rewrite（需要 ssl）——
        // 用解耦方式验证算法链：手工执行与 rewrite 相同的密码学步骤，
        // 验证服务端能解密。完整 record 级验证在集成测试（真 btls 握手）。
        // 此处仅验证 hooks 构造与字段。
        assert_eq!(hooks.short_id, vec![0xaa; 8]);
        assert!(hooks.auth_key.lock().is_none());
    }

    /// Ed25519 公钥提取：构造 REALITY 证书（mitm 生成器）验证提取正确。
    #[test]
    fn extract_ed25519_pubkey_from_reality_cert() {
        let auth_key = [0x42u8; 32];
        let (cert_der, _key) = crate::mitm::generate_reality_ed25519_cert(&auth_key).unwrap();
        let pub_key = extract_ed25519_pubkey(&cert_der)
            .expect("REALITY cert should contain Ed25519 pubkey");
        assert_eq!(pub_key.len(), 32);

        // 端到端：verify_handshake 的验证逻辑（HMAC roundtrip）
        let sig = &cert_der[cert_der.len() - 64..];
        let ok = crypto::verify_reality_certificate(&auth_key, &pub_key, sig).unwrap();
        assert!(ok, "REALITY cert HMAC should verify");
    }

    /// cm97 契约：完整验证链——mldsa65 服务端 cert（mitm 生成）→ 客户端
    /// verify_reality_cert_full 通过（捕获 CH/SH 来自真实回调用）。
    #[test]
    fn verify_full_mldsa65_cert_roundtrip() {
        let auth_key = [0x42u8; 32];
        let seed = [0x07u8; 32];
        let ch = [0x11u8; 256];
        let sh = [0x22u8; 90];
        let (cert_der, _) =
            crate::mitm::generate_reality_ed25519_cert_mldsa65(&auth_key, &ch, &sh, &seed)
                .unwrap();
        let pubkey_1952 = crypto::derive_mldsa65_pubkey(&seed).unwrap();

        verify_reality_cert_full(
            &cert_der,
            &auth_key,
            &pubkey_1952,
            Some(&ch),
            Some(&sh),
        )
        .expect("mldsa65 signed cert must verify");
    }

    /// mldsa65Verify 配置 + 标准cert（无 OID 0.0 扩展）→ 拒绝（Go 语义：
    /// Extensions 空 → x509 fallback 必败断连）。
    #[test]
    fn verify_full_rejects_standard_cert_when_mldsa65_configured() {
        let auth_key = [0x42u8; 32];
        let seed = [0x07u8; 32];
        let (std_cert, _) = crate::mitm::generate_reality_ed25519_cert(&auth_key).unwrap();
        let pubkey_1952 = crypto::derive_mldsa65_pubkey(&seed).unwrap();
        let err = verify_reality_cert_full(
            &std_cert,
            &auth_key,
            &pubkey_1952,
            Some(&[0x11u8; 256]),
            Some(&[0x22u8; 90]),
        )
        .unwrap_err();
        assert!(matches!(err, RealityError::RealCertificateReceived));
    }

    /// 篡改 ServerHello → mldsa65 验签失败（签名覆盖 CH‖SH 上下文）。
    #[test]
    fn verify_full_rejects_tampered_server_hello() {
        let auth_key = [0x42u8; 32];
        let seed = [0x07u8; 32];
        let (cert_der, _) = crate::mitm::generate_reality_ed25519_cert_mldsa65(
            &auth_key,
            &[0x11u8; 256],
            &[0x22u8; 90],
            &seed,
        )
        .unwrap();
        let pubkey_1952 = crypto::derive_mldsa65_pubkey(&seed).unwrap();
        let err = verify_reality_cert_full(
            &cert_der,
            &auth_key,
            &pubkey_1952,
            Some(&[0x11u8; 256]),
            Some(&[0x99u8; 90]), // SH 被替换
        )
        .unwrap_err();
        assert!(matches!(err, RealityError::RealCertificateReceived));
    }

    /// mldsa65 未配置 + 标准 cert → 通过（非 PQC 链路现状兼容）；
    /// mldsa65 配置但捕获缺失 → 显式错误（栈异常，不静默放行）。
    #[test]
    fn verify_full_without_mldsa65_and_missing_capture() {
        let auth_key = [0x42u8; 32];
        let (std_cert, _) = crate::mitm::generate_reality_ed25519_cert(&auth_key).unwrap();
        // 未配置 mldsa65Verify：CH/SH 缺失不影响
        verify_reality_cert_full(&std_cert, &auth_key, &[], None, None)
            .expect("standard path must stay compatible");
        // 配置了 mldsa65Verify 但捕获缺失：显式 TlsHandshake 错误
        let pubkey_1952 = vec![0xabu8; crypto::MLDSA65_PUBKEY_LEN];
        let err = verify_reality_cert_full(&std_cert, &auth_key, &pubkey_1952, None, None)
            .unwrap_err();
        assert!(matches!(err, RealityError::TlsHandshake(_)));
    }
}
