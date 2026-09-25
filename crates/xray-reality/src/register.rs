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

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use xray_common::net::destination::Destination;
use xray_transport::{
    connection::Connection,
    dialer::{StreamSettings, TransportDialFn, register_transport_dialer},
};

use crate::{
    client::{RealityTlsStream, UConnState, u_client},
    config::RealityConfig,
};

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

async fn dial_reality(
    dest: &Destination,
    settings: &StreamSettings,
) -> io::Result<Box<dyn Connection>> {
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
    // 257w：password 代 publicKey 别名（Go transport_security.go:190-192，
    // password 非空时覆盖 publicKey）；缺省报错文案对齐 Go 用 "password" 字样。
    let public_key_b64 = match obj.get("password").and_then(|v| v.as_str()) {
        Some(p) if !p.is_empty() => p,
        _ => obj
            .get("publicKey")
            .and_then(|v| v.as_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "reality: empty password"))?,
    };
    let fingerprint = obj.get("fingerprint").and_then(|v| v.as_str()).unwrap_or("chrome");
    let short_id_str = obj.get("shortId").and_then(|v| v.as_str()).unwrap_or("");

    let public_key = base64_url_decode(public_key_b64).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("reality: invalid publicKey base64: {public_key_b64}"),
        )
    })?;
    // 49i9：X25519 publicKey 必须 32B——非 32B 会话 fallback 路径 panic / btls
    // 主路径永不匹配。Go 端 UClient 握手期硬错（reality.go：ecdh.X25519()
    // .NewPublicKey(config.PublicKey) err → "REALITY: publicKey == nil"），
    // 此处前置到配置期拒启（fail-fast，语义同向）。
    if public_key.len() != crate::config::X25519_KEY_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("reality: invalid publicKey: need 32B X25519 key, got {}B", public_key.len()),
        ));
    }
    let short_id = if short_id_str.is_empty() {
        Vec::new()
    } else {
        hex::decode(short_id_str).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("reality: invalid shortId hex: {e}"))
        })?
    };
    // 257w：mldsa65Verify 配置期校验（Go transport_security.go:209-213，
    // base64 RawURL 解码 + 1952B 公钥），配错即拒启而非静默忽略。
    let mldsa65_verify = match obj.get("mldsa65Verify").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => {
            let der = base64_url_decode(s).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("reality: invalid mldsa65Verify: {s}"),
                )
            })?;
            if der.len() != 1952 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "reality: invalid mldsa65Verify: need 1952B public key, got {}B",
                        der.len()
                    ),
                ));
            }
            der
        },
        _ => Vec::new(),
    };
    // 49i9：mldsa65Verify 只有 btls 主路径能验签（BtlsRealityHooks 捕获
    // CH/SH 拼 mldsa65 消息）；watfaq-rustls fallback 无验签钩子，该组合
    // 静默跳过验签 = fail-open。Go 端全指纹走 utls 均验签（fail-closed），
    // 故配置期直接拒绝组合——比运行时静默降级影响小（取舍：改 watfaq fork
    // 补验签钩子成本远超配置期拒绝，且该组合本就不可用）。
    if !mldsa65_verify.is_empty() {
        let fp = xray_tls::fingerprint::get_fingerprint(fingerprint).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("reality: unknown fingerprint: {fingerprint}"),
            )
        })?;
        if !xray_tls::btls_client::fingerprint_supported(&fp) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "reality: mldsa65Verify requires a btls-supported fingerprint, got \"{fingerprint}\" (watfaq-rustls fallback path cannot verify mldsa65)"
                ),
            ));
        }
    }
    // 257w：spiderX → SpiderY 行为参数（Go transport_security.go:214-242）。
    // 默认 "/"；必须以 '/' 开头；query 参数 p/c/t/i/r（单值或 a-b 区间）写入
    // spider_y[10] 对应槽位（解析失败取 0 对齐 Go `_, _ :=`），消费后从 query 剔除。
    // Go transport_security.go:214-242：空串同缺失归一 "/"（uriclient.py 产物 spiderX=""）。
    let spider_x_raw =
        obj.get("spiderX").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("/");
    if !spider_x_raw.starts_with('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("reality: invalid spiderX: {spider_x_raw}"),
        ));
    }
    let (spider_x, spider_y) = parse_spider_x(spider_x_raw);

    Ok(RealityConfig {
        fingerprint: fingerprint.to_string(),
        server_name: server_name.to_string(),
        public_key,
        short_id,
        mldsa65_verify,
        spider_x,
        spider_y,
        ..Default::default()
    })
}

/// spiderX 路径+query 拆解：p/c/t/i/r → spider_y 槽位（0-1/2-3/4-5/6-7/8-9），
/// 剩余 query 按原顺序保留在返回的 spider_x 中（Go 端经 url.Encode 重排序，
/// 该字段目前仅 spider 爬行消费，Rust 端未实现爬行，保留原序足够）。
fn parse_spider_x(raw: &str) -> (String, Vec<i64>) {
    let mut spider_y = vec![0i64; 10];
    let (path, query) = match raw.split_once('?') {
        Some((p, q)) => (p, q),
        None => return (raw.to_string(), spider_y),
    };
    let param_slot = |k: &str| match k {
        "p" => Some(0),
        "c" => Some(2),
        "t" => Some(4),
        "i" => Some(6),
        "r" => Some(8),
        _ => None,
    };
    let mut kept = Vec::new();
    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let Some((k, v)) = pair.split_once('=') else {
            kept.push(pair);
            continue;
        };
        match param_slot(k) {
            Some(slot) if !v.is_empty() => {
                let mut parts = v.splitn(2, '-');
                let lo = parts.next().unwrap_or("").parse::<i64>().unwrap_or(0);
                let hi = parts.next().map(|s| s.parse::<i64>().unwrap_or(0)).unwrap_or(lo);
                spider_y[slot] = lo;
                spider_y[slot + 1] = hi;
            },
            _ => kept.push(pair),
        }
    }
    let spider_x =
        if kept.is_empty() { path.to_string() } else { format!("{path}?{}", kept.join("&")) };
    (spider_x, spider_y)
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

    fn raw_tcp_clone(&self) -> Option<TcpStream> {
        // 穿透到 REALITY TLS 流继续克隆裸 TCP（vision splice 用）。
        self.inner.raw_tcp_clone()
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::*;

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
        let v: serde_json::Value =
            serde_json::from_str(r#"{"serverName":"example.com","publicKey":"!!!not-base64!!!"}"#)
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
    /// 257w：password 代 publicKey（Go transport_security.go:190-192）。
    #[test]
    fn parse_reality_config_password_alias() {
        let raw = [0x11u8; 32];
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        // 仅 password
        let json = serde_json::json!({"serverName": "a.com", "password": b64});
        let cfg = parse_reality_config(Some(&json)).expect("password alias accepted");
        assert_eq!(cfg.public_key, raw);
        // password 在场时覆盖 publicKey（Go 语义：非空 password 直接赋给 PublicKey）
        let raw2 = [0x22u8; 32];
        let b64_2 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw2);
        let json = serde_json::json!({
            "serverName": "a.com",
            "publicKey": b64,
            "password": b64_2
        });
        let cfg = parse_reality_config(Some(&json)).expect("password overrides publicKey");
        assert_eq!(cfg.public_key, raw2);
        // 两者都缺 → 报 "password" 字样（Go :194 empty "password"）
        let json = serde_json::json!({"serverName": "a.com"});
        let err = parse_reality_config(Some(&json)).unwrap_err();
        assert!(err.to_string().contains("password"), "got: {err}");
    }

    /// 257w：mldsa65Verify base64 + 1952B 校验（Go transport_security.go:209-213）。
    #[test]
    fn parse_reality_config_mldsa65_verify() {
        // 合法 1952B
        let der = vec![0x5Au8; 1952];
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&der);
        let json = serde_json::json!({
            "serverName": "a.com",
            "publicKey": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]),
            "mldsa65Verify": b64
        });
        let cfg = parse_reality_config(Some(&json)).expect("valid mldsa65Verify accepted");
        assert_eq!(cfg.mldsa65_verify, der);
        // 长度错（≠1952）→ 拒
        let b64_short = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x5Au8; 32]);
        let json = serde_json::json!({
            "serverName": "a.com",
            "publicKey": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]),
            "mldsa65Verify": b64_short
        });
        let err = parse_reality_config(Some(&json)).unwrap_err();
        assert!(err.to_string().contains("mldsa65Verify"), "got: {err}");
        // 非 base64 → 拒
        let json = serde_json::json!({
            "serverName": "a.com",
            "publicKey": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]),
            "mldsa65Verify": "!!!not-base64!!!"
        });
        let err = parse_reality_config(Some(&json)).unwrap_err();
        assert!(err.to_string().contains("mldsa65Verify"), "got: {err}");
    }

    /// 49i9：非 32B publicKey 配置期拒启（Go UClient 握手期硬错
    /// "REALITY: publicKey == nil" 的 fail-fast 前置）。
    #[test]
    fn parse_reality_config_rejects_non_32b_public_key() {
        // 31B → 拒
        let json = serde_json::json!({
            "serverName": "a.com",
            "publicKey": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 31]),
        });
        let err = parse_reality_config(Some(&json)).unwrap_err();
        assert!(err.to_string().contains("need 32B X25519 key, got 31B"), "got: {err}");
        // 33B → 拒
        let json = serde_json::json!({
            "serverName": "a.com",
            "publicKey": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 33]),
        });
        let err = parse_reality_config(Some(&json)).unwrap_err();
        assert!(err.to_string().contains("got 33B"), "got: {err}");
        // password 别名路径同样校验
        let json = serde_json::json!({
            "serverName": "a.com",
            "password": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 16]),
        });
        let err = parse_reality_config(Some(&json)).unwrap_err();
        assert!(err.to_string().contains("got 16B"), "got: {err}");
    }

    /// 49i9：mldsa65Verify + 非 btls 指纹（watfaq-rustls fallback，无验签钩子）
    /// 组合配置期拒启——堵 fail-open（Go 全指纹走 utls 均验签）。
    ///
    /// 注：`unsafe` 是唯一 get_fingerprint 认识但 btls 清单外的预设
    /// （connector_for_fingerprint → Some(Err) → fingerprint_supported=false，
    /// u_client 走 watfaq fallback）；randomizednoalpn 等现已被 btls 就近映射覆盖。
    #[test]
    fn parse_reality_config_rejects_mldsa65_with_fallback_fingerprint() {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x5Au8; 1952]);
        let json = serde_json::json!({
            "serverName": "a.com",
            "publicKey": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]),
            "fingerprint": "unsafe", // btls 清单外 → fallback 路径
            "mldsa65Verify": b64
        });
        let err = parse_reality_config(Some(&json)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("mldsa65Verify"), "got: {msg}");
        assert!(msg.contains("unsafe"), "got: {msg}");
        // 未知指纹名同样拒（无法保证验签能力）
        let json = serde_json::json!({
            "serverName": "a.com",
            "publicKey": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]),
            "fingerprint": "!!!unknown!!!",
            "mldsa65Verify": b64
        });
        let err = parse_reality_config(Some(&json)).unwrap_err();
        assert!(err.to_string().contains("unknown fingerprint"), "got: {err}");
        // 对照：chrome（btls 支持）+ mldsa65Verify → 接受（既有测试覆盖，这里直证）
        let json = serde_json::json!({
            "serverName": "a.com",
            "publicKey": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]),
            "fingerprint": "chrome",
            "mldsa65Verify": b64
        });
        parse_reality_config(Some(&json)).expect("chrome + mldsa65Verify accepted");
    }

    /// 257w：spiderX 默认 "/"、'/' 前缀硬错、p/c/t/i/r → spider_y 槽位
    /// （Go transport_security.go:214-242）。
    #[test]
    fn parse_reality_config_spider_x() {
        let pub_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        let mk = |spider: &str| {
            serde_json::json!({
                "serverName": "a.com",
                "publicKey": pub_b64,
                "spiderX": spider
            })
        };
        // 缺省 → "/" 且 spider_y 全零
        let cfg = parse_reality_config(Some(&serde_json::json!({
            "serverName": "a.com", "publicKey": pub_b64
        })))
        .unwrap();
        assert_eq!(cfg.spider_x, "/");
        assert_eq!(cfg.spider_y, vec![0i64; 10]);
        // 非 '/' 开头 → 拒
        let err = parse_reality_config(Some(&mk("http://evil.com"))).unwrap_err();
        assert!(err.to_string().contains("spiderX"), "got: {err}");
        // 单值 → 区间两端同值；区间 → 两端；消费后 query 剔除
        let cfg = parse_reality_config(Some(&mk("/x?g=1&p=5&t=10-20&r=3"))).unwrap();
        assert_eq!(cfg.spider_y[0], 5);
        assert_eq!(cfg.spider_y[1], 5); // 单值双槽同值
        assert_eq!(cfg.spider_y[4], 10);
        assert_eq!(cfg.spider_y[5], 20); // 区间
        assert_eq!(cfg.spider_y[8], 3);
        assert_eq!(cfg.spider_y[9], 3);
        assert_eq!(cfg.spider_y[2], 0); // c 未配
        assert_eq!(cfg.spider_x, "/x?g=1"); // p/t/r 已消费，未知参数 g 保留
        // 非数值 → 0（Go `_, _ :=` 宽松语义）
        let cfg = parse_reality_config(Some(&mk("/?p=abc"))).unwrap();
        assert_eq!(cfg.spider_y[0], 0);
        assert_eq!(cfg.spider_y[1], 0);
        assert_eq!(cfg.spider_x, "/");
    }
}
