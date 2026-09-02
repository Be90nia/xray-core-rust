//! WebSocket 客户端：拨号 + 握手 + early data。
//!
//! 对应 Go `transport/internet/websocket/dialer.go` 的 `dialWebSocket` +
//! `Dial`。Rust 端复用 `tokio-tungstenite` 处理 HTTP Upgrade 握手 + TLS，
//! Xray 自身只负责构造 URI、自定义 header、`Sec-WebSocket-Protocol` (early data)
//! 与 [`WsConnection`] 字节流包装。
//!
//! # Early Data (0-RTT)
//!
//! Go 约定：early data 用 base64.RawURLEncoding 编码后放入
//! `Sec-WebSocket-Protocol` header（不是 URL `?ed=` 参数）。
//! 服务端若识别到，先把这些字节当作「连接首批数据」喂给上层，再进入 WS 帧循环。
//!
//! # TLS
//!
//! `tls_config: Some(_)` 走 rustls + wss://；`None` 走明文 ws://。
//! 拨 TCP 由 `tokio-tungstenite` 内部完成（用 URI 的 host:port）。

use std::sync::Arc;

use base64::Engine;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::Request as WsRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{client_async_tls_with_config, Connector, MaybeTlsStream};

use xray_common::net::destination::Destination;

use crate::config::Config;
use crate::error::{Result, WsError};
use crate::ws_bridge::WsConnection;

/// 拨号参数（与 Go `dialWebSocket` 入参对齐）。
pub struct DialOptions<'a> {
    /// WS 配置（host/path/header/heartbeat）。
    pub config: &'a Config,
    /// 目标地址（端口用于 URI authority；地址若与 `config.host` 不一致则用 host）。
    pub destination: &'a Destination,
    /// 可选 early data（0-RTT 第一批字节）。`None` 或空切片表示无 early data。
    pub early_data: Option<&'a [u8]>,
    /// 可选 rustls `ClientConfig`（`Some` → `wss://`，`None` → `ws://`）。
    pub tls_config: Option<Arc<rustls::ClientConfig>>,
    /// TLS SNI（`tlsSettings.serverName`）。None 用 destination 地址。
    /// Go：拨号目标（dest）与 SNI 解耦（CDN/argo 场景 SNI/Host 是配置域名）。
    pub tls_server_name: Option<String>,
}

/// 完成 WS 握手并返回字节流包装。
///
/// 返回 `WsConnection<MaybeTlsStream<TcpStream>>`，可直接作为
/// `AsyncRead + AsyncWrite + Connection` 使用。
pub async fn dial(
    opts: DialOptions<'_>,
) -> Result<WsConnection<MaybeTlsStream<Box<dyn xray_transport::connection::Connection>>>> {
    // TLS 自管时 URI 也必须用 ws://：tungstenite 的 uri_mode 按 scheme 判断，
    // wss + Connector::Plain 会报 "TLS support not compiled in"。
    let uri = build_request_uri(opts.config, opts.destination, false);
    let request = build_request(&uri, opts.config, opts.early_data)?;

    // ponytail: WebSocketConfig 默认 64 MiB max_message_size 足够代理流量。
    let ws_cfg = WebSocketConfig::default();

    // 自管 TCP + TLS：tokio-tungstenite 的 connect_async_tls_with_config 用
    // URI authority 做 SNI，而 CDN/argo 场景 URI authority（拨号目标）与
    // SNI/Host（配置域名）必须解耦（Go NetDial(dest) + ServerName(tlsSettings)）。
    // connector=None 时 tungstenite 把传入流当 TLS-ready（Plain 包装）。
    let host = opts.destination.address().to_string();
    let port = opts.destination.port().value();
    let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
    tcp.set_nodelay(true).ok();

    let stream: Box<dyn xray_transport::connection::Connection> = match opts.tls_config {
        Some(cfg) => {
            let sni = opts.tls_server_name.as_deref().unwrap_or(host.as_str());
            let tls_stream =
                xray_tls::utls::client(Box::new(xray_transport::connection::TcpConnection::new(tcp)) as Box<dyn xray_transport::connection::Connection>, sni, cfg)
                    .await?;
            Box::new(tls_stream)
        }
        None => Box::new(xray_transport::connection::TcpConnection::new(tcp)),
    };

    // connector=None 时 tungstenite(native-tls feature)会对流再叠一层 TLS;
    // 我们的 TLS 分支已自管 TLS,必须显式 Plain(仅明文分支也是 Plain 包装)。
    let (stream, _resp) =
        client_async_tls_with_config(request, stream, Some(ws_cfg), Some(Connector::Plain)).await?;

    // remote/local addr：地址不暴露；调用方需要时通过 dispatcher 注入。
    Ok(WsConnection::from_stream(stream, None, None))
}

/// 构造 URI（`ws://` 或 `wss://` + authority + path）。
///
/// 对应 Go `dialer.go` 中 `uri := protocol + "://" + host + path`。
fn build_request_uri(cfg: &Config, dest: &Destination, use_tls: bool) -> String {
    let protocol = if use_tls { "wss" } else { "ws" };
    let host = dest.address().to_string();
    // ponytail: URI authority 用 dest 地址（真实拨号目标）。
    // Host header 用 cfg.host（在 build_request 中设置，CDN/SNI 场景使用）。
    let port = dest.port().value();
    let needs_explicit_port = !(port == 80 && !use_tls) && !(port == 443 && use_tls);
    let authority = if needs_explicit_port {
        format!("{host}:{port}")
    } else {
        host
    };
    let path = cfg.normalized_path();
    format!("{protocol}://{authority}{path}")
}

/// 构造自定义 WS Upgrade request：附加 user header + Host + early-data。
fn build_request(uri: &str, cfg: &Config, ed: Option<&[u8]>) -> Result<WsRequest> {
    let mut req = uri
        .into_client_request()
        .map_err(|e| WsError::HandshakeFailed(format!("invalid URI: {e}")))?;

    // 1. Host header：Go 用 wsSettings.Host 覆盖（如果配置）。
    if !cfg.host.is_empty() {
        req.headers_mut().insert(
            http::header::HOST,
            HeaderValue::from_str(&cfg.host)
                .map_err(|e| WsError::HandshakeFailed(format!("invalid host header: {e}")))?,
        );
    }

    // 2. 用户自定义 header。
    for (k, v) in &cfg.header {
        // 头名解析：用 http::HeaderName 验证。
        let name = k
            .parse::<http::header::HeaderName>()
            .map_err(|e| WsError::HandshakeFailed(format!("invalid header name {k:?}: {e}")))?;
        let value = HeaderValue::from_str(v)
            .map_err(|e| WsError::HandshakeFailed(format!("invalid header value for {k}: {e}")))?;
        req.headers_mut().insert(name, value);
    }

    // 3. Early data → Sec-WebSocket-Protocol header (base64 RawURL no padding)。
    //    对齐 Go：header.Set("Sec-WebSocket-Protocol", base64.RawURLEncoding.EncodeToString(ed))
    if let Some(data) = ed {
        if !data.is_empty() {
            // ponytail: 用 RawURLEncoding（无 padding）匹配 v2ray/xray 协议约定。
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data);
            // tungstenite::http::header 常量名：SEC_WEBSOCKET_PROTOCOL
            req.headers_mut().insert(
                "Sec-WebSocket-Protocol",
                HeaderValue::from_str(&encoded)
                    .map_err(|e| WsError::HandshakeFailed(format!("early data encode: {e}")))?,
            );
        }
    }
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_common::net::address::Address;
    use xray_common::net::destination::Destination;
    use xray_common::net::network::Network;
    use xray_common::net::port::Port;

    fn dest(host: &str, port: u16) -> Destination {
        Destination::new(Address::new_domain(host), Port::new(port), Network::TCP)
    }

    #[test]
    fn uri_uses_destination_address_not_config_host() {
        // URI authority 用 dest 地址（cfg.host 仅作为 Host header）。
        let cfg = Config {
            host: "cdn.example.com".into(),
            path: "/ws".into(),
            ..Default::default()
        };
        let d = dest("1.2.3.4", 443);
        assert_eq!(build_request_uri(&cfg, &d, true), "wss://1.2.3.4/ws");
    }

    #[test]
    fn uri_falls_back_to_destination_address() {
        let cfg = Config::default(); // host 空
        let d = dest("example.com", 80);
        assert_eq!(build_request_uri(&cfg, &d, false), "ws://example.com/");
    }

    #[test]
    fn uri_explicit_nonstandard_port() {
        let cfg = Config::default();
        let d = dest("example.com", 8080);
        assert_eq!(build_request_uri(&cfg, &d, false), "ws://example.com:8080/");
    }

    #[test]
    fn uri_standard_port_wss_omits_port() {
        let cfg = Config::default();
        let d = dest("example.com", 443);
        assert_eq!(build_request_uri(&cfg, &d, true), "wss://example.com/");
    }

    #[test]
    fn uri_path_normalized_prepends_slash() {
        let cfg = Config {
            path: "api".into(),
            ..Default::default()
        };
        let d = dest("example.com", 80);
        assert_eq!(build_request_uri(&cfg, &d, false), "ws://example.com/api");
    }

    #[test]
    fn build_request_sets_host_header() {
        let cfg = Config {
            host: "front.example.com".into(),
            ..Default::default()
        };
        let req = build_request("ws://1.2.3.4/", &cfg, None).unwrap();
        assert_eq!(req.headers().get("host").unwrap(), "front.example.com");
    }

    #[test]
    fn build_request_attaches_early_data_as_sec_websocket_protocol() {
        let cfg = Config::default();
        let ed = b"hello-ed";
        let req = build_request("ws://example.com/", &cfg, Some(ed.as_slice())).unwrap();
        let v = req
            .headers()
            .get("Sec-WebSocket-Protocol")
            .expect("header should be set");
        // base64 URL_SAFE_NO_PAD("hello-ed") = "aGVsbG8tZWQ"
        assert_eq!(v.to_str().unwrap(), "aGVsbG8tZWQ");
    }

    #[test]
    fn build_request_empty_early_data_omits_header() {
        let cfg = Config::default();
        let req = build_request("ws://example.com/", &cfg, Some(&[])).unwrap();
        assert!(req.headers().get("Sec-WebSocket-Protocol").is_none());
    }

    #[test]
    fn build_request_attaches_custom_headers() {
        let mut cfg = Config::default();
        cfg.header.insert("X-Forwarded-For".into(), "10.0.0.1".into());
        cfg.header.insert("X-Custom".into(), "v".into());
        let req = build_request("ws://example.com/", &cfg, None).unwrap();
        assert_eq!(req.headers().get("x-forwarded-for").unwrap(), "10.0.0.1");
        assert_eq!(req.headers().get("x-custom").unwrap(), "v");
    }
}
