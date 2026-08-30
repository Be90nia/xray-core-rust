//! REALITY transport dialer 注册（完整）。
//!
//! 把 [`crate::client::u_client`] 接入全局 `TRANSPORT_DIALER_CACHE`。
//! 对应 Go `transport/internet/reality/reality.go::Dial` +
//! `internet.RegisterTransportDialer("reality", ...)`.
//!
//! ## 流程
//!
//! 1. 从 `streamSettings.security_json` 解析 `realitySettings`（`serverName`/`publicKey`/
//!    `shortId`/`fingerprint`）→ [`RealityConfig`]
//! 2. TCP 连接到 `dest`（reality 跑在 TLS 上，TLS 跑在 TCP 上）
//! 3. 调 [`u_client`] 做 REALITY TLS handshake（watfaq-rustls 内部派生 session_id/auth_key）
//! 4. 包装返回的 `TlsStream` 为 [`RealityConnection`]（impl [`Connection`])

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use crate::client::RealityTlsStream;

use xray_common::net::destination::Destination;
use xray_transport::connection::Connection;
use xray_transport::dialer::{StreamSettings, TransportDialFn, register_transport_dialer};

use crate::client::{u_client, UConnState};
use crate::config::RealityConfig;

/// 注册 REALITY transport dialer。幂等。
pub fn register_dialer() -> io::Result<()> {
    let dialer: TransportDialFn = Arc::new(move |dest, _sockopt, settings| {
        let dest = dest.clone();
        let settings = settings.clone();
        Box::pin(async move { dial_reality(&dest, &settings).await })
    });
    let _ = register_transport_dialer("reality", dialer);
    Ok(())
}

async fn dial_reality(dest: &Destination, settings: &StreamSettings) -> io::Result<Box<dyn Connection>> {
    let config = parse_reality_config(settings.security_json.as_ref())?;
    let state = UConnState::new(config).map_err(|e| io::Error::other(e.to_string()))?;

    // TCP 连接到 dest（reality 跑在 TLS 上，TLS 跑在 TCP 上）
    let host = dest.address().to_string();
    let port = dest.port().value();
    let addr = format!("{host}:{port}");
    let tcp = tokio::net::TcpStream::connect(&addr)
        .await
        .map_err(|e| io::Error::other(format!("reality tcp connect to {addr}: {e}")))?;

    let tcp = xray_transport::connection::TcpConnection::new(tcp);

    let remote_addr = tcp.remote_addr().ok().flatten();
    let local_addr = tcp.local_addr().ok().flatten();

    let tls_stream = u_client(tcp, state)
        .await
        .map_err(|e| io::Error::other(format!("reality handshake: {e}")))?;

    let mut conn = RealityConnection::new(tls_stream);
    conn.remote_addr = remote_addr;
    conn.local_addr = local_addr;
    Ok(Box::new(conn))
}

/// 对已建立的底层连接做 REALITY 握手，返回包装后的 Connection。
///
/// 供 tcp dialer（`xray-transport-tcp`）在 `security=reality` 时调用：
/// tcp dialer 先 `dial_system` 建 TCP，再委托本函数完成 REALITY TLS 握手。
/// 对应 Go `reality.UClient(conn, config, ctx, dest)`。
///
/// `conn` 通常是 `dial_system` 返回的底层 TCP 连接。
pub async fn handshake_over(
    conn: Box<dyn Connection>,
    settings: &StreamSettings,
) -> io::Result<Box<dyn Connection>> {
    let config = parse_reality_config(settings.security_json.as_ref())?;
    let state = UConnState::new(config).map_err(|e| io::Error::other(e.to_string()))?;
    let remote_addr = conn.remote_addr()?;
    let local_addr = conn.local_addr()?;
    let tls_stream = u_client(conn, state)
        .await
        .map_err(|e| io::Error::other(format!("reality handshake: {e}")))?;
    let mut rc = RealityConnection::new(tls_stream);
    rc.remote_addr = remote_addr;
    rc.local_addr = local_addr;
    Ok(Box::new(rc))
}

/// 从 `realitySettings` JSON 构造 [`RealityConfig`]。
///
/// 接受字段（Go `infra/conf/transport_internet.go::RealityConfig` JSON tag）：
/// - `serverName` (string, required)
/// - `publicKey` (base64 string, required)
/// - `shortId` (hex string, optional)
/// - `fingerprint` (string, optional, 默认 "chrome")
fn parse_reality_config(json: Option<&serde_json::Value>) -> io::Result<RealityConfig> {
    let json = json.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "reality requires security_json settings")
    })?;
    let obj = json.as_object().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "reality settings must be a JSON object")
    })?;

    let server_name = obj
        .get("serverName")
        .and_then(|v| v.as_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "reality: missing serverName"))?;
    let public_key_b64 = obj
        .get("publicKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "reality: missing publicKey"))?;
    let fingerprint = obj
        .get("fingerprint")
        .and_then(|v| v.as_str())
        .unwrap_or("chrome");
    let short_id_str = obj.get("shortId").and_then(|v| v.as_str()).unwrap_or("");

    let public_key = base64_url_decode(public_key_b64).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("reality: invalid publicKey base64: {public_key_b64}"),
        )
    })?;
    let short_id = if short_id_str.is_empty() {
        Vec::new()
    } else {
        hex::decode(short_id_str).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("reality: invalid shortId hex: {e}"),
            )
        })?
    };

    Ok(RealityConfig {
        fingerprint: fingerprint.to_string(),
        server_name: server_name.to_string(),
        public_key,
        short_id,
        ..Default::default()
    })
}

/// base64 RawURL 解码（无 padding，兼容 std 变体）。对应 Go `base64.RawURLEncoding.DecodeString`。
fn base64_url_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let normalized = s.replace('+', "-").replace('/', "_");
    let normalized = normalized.trim_end_matches('=');
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(normalized)
        .ok()
        .or_else(|| base64::engine::general_purpose::STANDARD.decode(s).ok())
}

/// REALITY TLS 连接 wrapper（impl [`Connection`] trait）。
///
/// 包装 `tokio_rustls::client::TlsStream<S>`，提供 `remote_addr`/`local_addr`
/// （从底层 TcpStream 拿，TLS handshake 之前快照保存）。
pub struct RealityConnection<S> {
    inner: RealityTlsStream<S>,
    remote_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
}

impl<S> RealityConnection<S> {
    #[must_use]
    pub fn new(inner: RealityTlsStream<S>) -> Self {
        Self { inner, remote_addr: None, local_addr: None }
    }
}

impl<S: Connection> AsyncRead for RealityConnection<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: Connection> AsyncWrite for RealityConnection<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S: Connection> Connection for RealityConnection<S> {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.remote_addr)
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.local_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    #[test]
    fn register_dialer_is_idempotent() {
        register_dialer().expect("first register ok");
        register_dialer().expect("second register ok (idempotent)");
    }

    #[test]
    fn parse_reality_config_missing_json_returns_err() {
        let r = parse_reality_config(None);
        assert!(r.is_err());
    }

    #[test]
    fn parse_reality_config_missing_server_name_returns_err() {
        let v: serde_json::Value = serde_json::from_str(r#"{"publicKey":"AAA"}"#).unwrap();
        let r = parse_reality_config(Some(&v));
        assert!(r.is_err());
    }

    #[test]
    fn parse_reality_config_invalid_public_key_returns_err() {
        // 非 base64 字符串
        let v: serde_json::Value = serde_json::from_str(
            r#"{"serverName":"example.com","publicKey":"!!!not-base64!!!"}"#,
        )
        .unwrap();
        let r = parse_reality_config(Some(&v));
        assert!(r.is_err());
    }

    #[test]
    fn parse_reality_config_accepts_url_safe_no_pad_public_key() {
        // Go base64.RawURLEncoding(X25519 pubkey) — 测试集成套件也走 URL_SAFE_NO_PAD。
        use base64::Engine as _;
        let raw = [0x42u8; 32];
        let url_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let json: serde_json::Value = serde_json::json!({
            "serverName": "reality.local",
            "publicKey": url_b64,
        });
        let cfg = parse_reality_config(Some(&json)).expect("URL_SAFE_NO_PAD accepted");
        assert_eq!(cfg.public_key, raw);
    }

    #[test]
    fn parse_reality_config_accepts_standard_public_key() {
        // 双兼容：标准 base64（含 + / =）也吃，回退路径。
        use base64::Engine as _;
        let raw = [0x37u8; 32];
        let std_b64 = base64::engine::general_purpose::STANDARD.encode(raw);
        let json: serde_json::Value = serde_json::json!({
            "serverName": "reality.local",
            "publicKey": std_b64,
        });
        let cfg = parse_reality_config(Some(&json)).expect("STANDARD accepted");
        assert_eq!(cfg.public_key, raw);
    }

    #[test]
    fn base64_url_decode_variants() {
        // URL-safe (X25519 公钥 32 字节)
        let url = "j0DFrbaPJWJK5bIU6nZ6bslNgp09e14a0bpvPiE4KF8";
        assert_eq!(base64_url_decode(url).unwrap().len(), 32);
        // 标准 base64 也能解码（双兼容）
        let std_enc = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        assert_eq!(base64_url_decode(&std_enc).unwrap().len(), 32);
        // 非法 → None
        assert!(base64_url_decode("!!!not-base64!!!").is_none());
    }
}
