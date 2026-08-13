//! SplitHTTP transport dialer + listener 注册。
//!
//! dialer: 已集成——通过 [`MutexReader`] 包装 `!Sync` reader 使 `SplitConn` 满足
//! [`Connection`](xray_transport::connection::Connection) 的 `Sync` bound。
//! listener: HTTP/2 server 监听待集成，当前返回 `Unsupported`。
//!
//! 协议名同时注册 `"splithttp"`（Go 标准）和 `"xhttp"`（用户配置简写）。

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use xray_common::net::destination::Destination;
use xray_transport::connection::Connection;
use xray_transport::dialer::{StreamSettings, TransportDialFn, register_transport_dialer};
use xray_transport::listener_registry::{TransportListenFn, register_transport_listener};
use xray_transport::sockopt::SocketOptions;

use crate::client::DefaultDialerClient;
use crate::config::Config;
use crate::dialer;
use crate::h3_client::H3Conn;
use crate::transport::listen_splithttp;

/// 注册 SplitHTTP transport dialer。幂等。
pub fn register_dialer() -> io::Result<()> {
    let dial_fn: TransportDialFn = Arc::new(move |dest, sockopt, settings| {
        let dest = dest.clone();
        let sockopt = sockopt.clone();
        let settings = settings.clone();
        Box::pin(async move { dial_splithttp(&dest, &sockopt, &settings).await })
    });
    let _ = register_transport_dialer("splithttp", dial_fn.clone());
    let _ = register_transport_dialer("xhttp", dial_fn);
    Ok(())
}

/// 注册 SplitHTTP transport listener。幂等。
pub fn register_listener() -> io::Result<()> {
    let listen_fn: TransportListenFn = Arc::new(move |addr, settings, sockopt, handler| {
        let settings = settings.clone();
        let sockopt = sockopt.clone();
        let handler = handler.clone();
        Box::pin(async move { listen_splithttp(addr, &settings, &sockopt, handler).await })
    });
    let _ = register_transport_listener("splithttp", listen_fn.clone());
    let _ = register_transport_listener("xhttp", listen_fn);
    Ok(())
}

/// 实际拨号：解析配置 → 构建 TLS client → 调用 [`dialer::dial`] → 包装为 `Box<dyn Connection>`。
async fn dial_splithttp(
    dest: &Destination,
    _sockopt: &SocketOptions,
    settings: &StreamSettings,
) -> io::Result<Box<dyn Connection>> {
    let config = parse_splithttp_config(settings.transport_json.as_ref())?;
    let config = Arc::new(config);

    // Host: 配置优先，缺失用 dest 地址。
    let default_sni = dest.address().to_string();
    let host = if config.host.is_empty() {
        format!("{}:{}", dest.address(), dest.port())
    } else {
        format!("{}:{}", config.host, dest.port())
    };

    // Scheme: TLS/REALITY → https，否则 http。
    let has_tls = matches!(settings.security.as_str(), "tls" | "reality");
    let has_reality = settings.security == "reality";
    let scheme = if has_tls { "https" } else { "http" };

    // Build rustls ClientConfig.
    let tls_config = xray_tls::client_config::build_client_config(
        &settings.security,
        settings.security_json.as_ref(),
        &default_sni,
    )?;

    // DefaultDialerClient needs a rustls ClientConfig. If no TLS, use a default.
    let rustls_config = match tls_config {
        Some(arc_cfg) => (*arc_cfg).clone(),
        None => {
            // No TLS → build a minimal rustls config (won't be used for actual TLS,
            // but DefaultDialerClient::new requires one).
            let _ = rustls::crypto::ring::default_provider().install_default();
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth()
        }
    };

    // Determine HTTP version from ALPN (对应 Go `decideHTTPVersion`)。
    // ALPN 来自 rustls_config.alpn_protocols（`build_client_config` 从 tlsSettings 解析）。
    let next_protocol: Vec<String> = rustls_config
        .alpn_protocols
        .iter()
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .collect();
    let http_version = dialer::decide_http_version(has_tls, has_reality, &next_protocol);

    let packet_conn = if http_version == "3" {
        // HTTP/3 over QUIC path（对应 Go `createHTTPClient` 中 `httpVersion=="3"` 分支）。
        // quinn 需要 `SocketAddr`（不做 DNS），域名走 `tokio::net::lookup_host` 解析。
        let socket_addr = resolve_dest_socket_addr(dest)
            .await
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("H3 dial: DNS resolve failed for {}", dest.address()),
                )
            })?;
        // SNI: config.host 优先，缺失用 dest 地址（对齐 Go `requestURL.Host` fallback）。
        let server_name = if !config.host.is_empty() {
            config.host.as_str()
        } else {
            &default_sni
        };
        let h3_conn = H3Conn::connect(config.clone(), socket_addr, server_name, rustls_config)
            .await
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("splithttp H3 connect failed: {e}"),
                )
            })?;
        dialer::dial_h3(h3_conn, config, scheme, &host, has_reality)
            .await
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("splithttp H3 dial failed: {e}"),
                )
            })?
    } else {
        // HTTP/1.1 / HTTP/2 path（hyper + hyper-rustls）。
        let client = Arc::new(DefaultDialerClient::new(config.clone(), rustls_config));
        dialer::dial(client, config, scheme, &host, has_tls)
            .await
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("splithttp dial failed: {e}"),
                )
            })?
    };

    // Wrap !Sync reader in MutexReader → SplitConn that impl Connection.
    let sync_conn = packet_conn.into_sync_reader();
    Ok(Box::new(sync_conn) as Box<dyn Connection>)
}

/// 将 [`Destination`] 解析为 [`SocketAddr`]（quinn/H3 需要；域名走系统 DNS）。
///
/// 对应 Go `internet.DialSystem` 中 `dest.Network == UDP` 的域名解析。
/// IP 地址直接转换；Domain 通过 `tokio::net::lookup_host`。
async fn resolve_dest_socket_addr(dest: &Destination) -> Option<SocketAddr> {
    let port = dest.port().value();
    match dest.address() {
        xray_common::net::address::Address::IPv4(v4) => Some(SocketAddr::new((*v4).into(), port)),
        xray_common::net::address::Address::IPv6(v6) => Some(SocketAddr::new((*v6).into(), port)),
        xray_common::net::address::Address::Domain(d) => {
            tokio::net::lookup_host((d.as_str(), port)).await.ok()?.next()
        }
    }
}

/// 从 `splithttpSettings` JSON 解析为强类型 [`Config`]。
///
/// `None` 或非 object 返回 [`Config::default`]。
fn parse_splithttp_config(json: Option<&serde_json::Value>) -> io::Result<Config> {
    let Some(v) = json else { return Ok(Config::default()); };
    let Some(obj) = v.as_object() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "splithttpSettings must be a JSON object",
        ));
    };

    let host = obj.get("host").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let path = obj.get("path").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let mode = obj.get("mode").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let no_grpc_header = obj.get("noGRPCHeader").or_else(|| obj.get("no_grpc_header")).and_then(|x| x.as_bool()).unwrap_or(false);
    let no_sse_header = obj.get("noSSEHeader").or_else(|| obj.get("no_sse_header")).and_then(|x| x.as_bool()).unwrap_or(false);
    let sc_max_each_post_bytes = obj.get("scMaxEachPostBytes").or_else(|| obj.get("sc_max_each_post_bytes")).and_then(parse_range);
    let sc_min_posts_interval_ms = obj.get("scMinPostsIntervalMs").or_else(|| obj.get("sc_min_posts_interval_ms")).and_then(parse_range);
    let sc_max_buffered_posts = obj.get("scMaxBufferedPosts").or_else(|| obj.get("sc_max_buffered_posts")).and_then(|x| x.as_i64()).unwrap_or(0);
    let x_padding_bytes = obj.get("xPaddingBytes").or_else(|| obj.get("x_padding_bytes")).and_then(parse_range);
    let uplink_http_method = obj.get("uplinkHTTPMethod").or_else(|| obj.get("uplink_http_method")).and_then(|x| x.as_str()).unwrap_or("").to_string();

    let headers = parse_headers(obj.get("header"))
        .or_else(|| parse_headers(obj.get("headers")))
        .unwrap_or_default();

    Ok(Config {
        host,
        path,
        mode,
        headers,
        x_padding_bytes,
        no_grpc_header,
        no_sse_header,
        sc_max_each_post_bytes,
        sc_min_posts_interval_ms,
        sc_max_buffered_posts,
        uplink_http_method,
        ..Config::default()
    })
}

/// Parse a RangeConfig from JSON: either `{"from":N,"to":N}` or a single integer.
fn parse_range(v: &serde_json::Value) -> Option<crate::config::RangeConfig> {
    if let Some(obj) = v.as_object() {
        let from = obj.get("from").and_then(|x| x.as_i64()).unwrap_or(0) as i32;
        let to = obj.get("to").and_then(|x| x.as_i64()).unwrap_or(0) as i32;
        Some(crate::config::RangeConfig::new(from, to))
    } else if let Some(n) = v.as_i64() {
        let n = n as i32;
        Some(crate::config::RangeConfig::new(n, n))
    } else {
        None
    }
}

/// 把 JSON 子对象解析为 `HashMap<String, String>`。非 object 或缺失返回 `None`。
fn parse_headers(v: Option<&serde_json::Value>) -> Option<std::collections::HashMap<String, String>> {
    let obj = v?.as_object()?;
    let mut map = std::collections::HashMap::with_capacity(obj.len());
    for (k, val) in obj {
        if let Some(s) = val.as_str() {
            map.insert(k.clone(), s.to_string());
        }
    }
    Some(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_dialer_is_idempotent() {
        register_dialer().expect("first register ok");
        register_dialer().expect("second register ok (idempotent)");
    }

    #[test]
    fn parse_splithttp_config_none_returns_default() {
        let cfg = parse_splithttp_config(None).unwrap();
        assert!(cfg.host.is_empty());
        assert!(cfg.path.is_empty());
        assert!(cfg.mode.is_empty());
    }

    #[test]
    fn parse_splithttp_config_basic_fields() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"host":"h.example.com","path":"/ws","mode":"packet-up","noGRPCHeader":true}"#,
        )
        .unwrap();
        let cfg = parse_splithttp_config(Some(&v)).unwrap();
        assert_eq!(cfg.host, "h.example.com");
        assert_eq!(cfg.path, "/ws");
        assert_eq!(cfg.mode, "packet-up");
        assert!(cfg.no_grpc_header);
    }

    #[test]
    fn parse_splithttp_config_accepts_headers_plural() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"headers":{"X-Forwarded-For":"10.0.0.1"}}"#).unwrap();
        let cfg = parse_splithttp_config(Some(&v)).unwrap();
        assert_eq!(cfg.headers.get("X-Forwarded-For").unwrap(), "10.0.0.1");
    }

    #[test]
    fn parse_splithttp_config_non_object_returns_err() {
        let v: serde_json::Value = serde_json::from_str(r#""not-an-object""#).unwrap();
        let r = parse_splithttp_config(Some(&v));
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn parse_range_from_object() {
        let v: serde_json::Value = serde_json::from_str(r#"{"from":100,"to":200}"#).unwrap();
        let r = parse_range(&v).unwrap();
        assert_eq!((r.from, r.to), (100, 200));
    }

    #[test]
    fn parse_range_from_integer() {
        let v: serde_json::Value = serde_json::from_str(r#"500"#).unwrap();
        let r = parse_range(&v).unwrap();
        assert_eq!((r.from, r.to), (500, 500));
    }
}
