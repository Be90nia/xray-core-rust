//! WebSocket transport dialer + listener 注册：
//!
//! 对应 Go `transport/internet/websocket/dialer.go::init()` 中的
//! `internet.RegisterTransportDialer(protocolName, Dial(...))` 和
//! `transport/internet/websocket/hub.go::init()` 中的
//! `internet.RegisterTransportListener(protocolName, ListenWS)`。
//!
//! ## 调用
//!
//! 进程启动时调用一次 [`register_dialer`] 和 [`register_listener`]；
//!
//! 对应 Go `transport/internet/websocket/dialer.go::init()` 中的
//! `internet.RegisterTransportDialer(protocolName, Dial(...))`。
//!
//! ## 调用
//!
//! 进程启动时调用一次 [`register_dialer`]；幂等——重复注册的 `AlreadyExists` 被忽略。

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use xray_common::net::destination::Destination;
use xray_transport::connection::Connection;
use xray_transport::dialer::{
    StreamSettings, TransportDialFn, register_transport_dialer,
};
use xray_transport::listener_registry::{
    ConnHandler, TransportListenFn, TransportListener,
    register_transport_listener,
};
use xray_transport::sockopt::SocketOptions;
use crate::client::{DialOptions, dial};
use crate::config::Config;

/// 注册 WebSocket transport dialer。
///
/// 协议名同时注册 `"ws"` 和 `"websocket"`——Go 端用 `"websocket"`，JSON `network`
/// 字段在客户端配置里常写 `"ws"`，两者都映射到本 dialer。
///
/// 幂等：重复调用忽略 `AlreadyExists`（对齐 Go `init()` 在测试中多次执行的容错）。
pub fn register_dialer() -> io::Result<()> {
    let dialer: TransportDialFn = Arc::new(move |dest, _sockopt, settings| {
        // TransportDialFn 返回 'static future，必须在进入 async block 前拥有数据。
        let dest = dest.clone();
        let settings = settings.clone();
        Box::pin(async move { dial_ws(&dest, &settings).await })
    });
    // ponytail: 重复注册忽略——主代理与测试可能并发触发注册。
    let _ = register_transport_dialer("ws", dialer.clone());
    let _ = register_transport_dialer("websocket", dialer);
    Ok(())
}

/// 注册 WebSocket transport listener。
///
/// 协议名同时注册 `"ws"` 和 `"websocket"`，与 [`register_dialer`] 一致。
///
/// 当前实现：绑定 TCP + spawn accept loop（每个新连接做 WS 握手后调用 ConnHandler）。
/// TLS 包装由 stream settings 的 security 字段决定——`"tls"` 时自动包装 TLS accept。
///
/// 幂等：重复调用忽略 `AlreadyExists`。
pub fn register_listener() -> io::Result<()> {
    let listen_fn: TransportListenFn = Arc::new(move |addr, settings, _sockopt, handler| {
        let settings = settings.clone();
        let handler = handler.clone();
        Box::pin(async move { listen_ws(addr, &settings, &handler).await })
    });
    // ponytail: 重复注册忽略——主代理与测试可能并发触发注册。
    let _ = register_transport_listener("ws", listen_fn.clone());
    let _ = register_transport_listener("websocket", listen_fn);
    Ok(())
}

/// 实际监听：解析 wsSettings → bind WsListener → spawn accept loop。
async fn listen_ws(
    addr: SocketAddr,
    settings: &StreamSettings,
    handler: &ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    let config = parse_ws_config(settings.transport_json.as_ref())?;
    let ws_config = Arc::new(config);

    let mut ws_listener = crate::server::WsListener::bind(addr, ws_config.clone())
        .await
        .map_err(|e| io::Error::other(e))?;

    let local_addr = ws_listener.local_addr()
        .map_err(|e| io::Error::other(e))?;

    let close_notify = Arc::new(tokio::sync::Notify::new());
    let close_notify_clone = close_notify.clone();

    // 根据 security 决定是否包装 TLS。
    let use_tls = settings.security != "none" && !settings.security.is_empty();

    // spawn accept loop。
    let handler = handler.clone();
    let tls_config = if use_tls {
        xray_tls::server_config::build_server_config(&settings.security, settings.security_json.as_ref())?
    } else {
        None
    };
    tokio::spawn(async move {
        loop {
            tokio::select! {
                result = async {
                    if let Some(ref tls_cfg) = tls_config {
                        ws_listener.accept_tls(tls_cfg.clone()).await
                    } else {
                        ws_listener.accept().await
                    }
                } => {
                    match result {
                        Ok(accepted) => {
                            handler(accepted.conn);
                        }
                        Err(e) => {
                            let msg = e.to_string();
                            if msg.contains("closed") { break; }
                            // ponytail: too many open files 时 sleep 重试，其他错误继续
                            if msg.contains("too many") {
                                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                            }
                            continue;
                        }
                    }
                }
                _ = close_notify_clone.notified() => break,
            }
        }
    });

    Ok(Box::new(WsTransportListener { local_addr, close_notify }))
}

/// WebSocket `TransportListener` wrapper。只持有 local_addr + close 通知。
struct WsTransportListener {
    local_addr: SocketAddr,
    close_notify: Arc<tokio::sync::Notify>,
}

impl TransportListener for WsTransportListener {
    fn close(&self) -> io::Result<()> {
        // 通知 accept loop 退出。底层 TcpListener 在 WsListener drop 时关闭。
        self.close_notify.notify_waiters();
        Ok(())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

/// 实际拨号：解析 wsSettings → tls config → 调用 client::dial → 包装为 Connection。
async fn dial_ws(dest: &Destination, settings: &StreamSettings) -> io::Result<Box<dyn Connection>> {
    let config = parse_ws_config(settings.transport_json.as_ref())?;

    // 默认 SNI 用 dest 地址（与 Go `serverName = dest address` 一致）。
    let default_sni = dest.address().to_string();
    let tls_config = xray_tls::client_config::build_client_config(
        &settings.security,
        settings.security_json.as_ref(),
        &default_sni,
    )?;

    let conn = dial(DialOptions {
        config: &config,
        destination: dest,
        early_data: None,
        tls_config,
    })
    .await
    .map_err(|e| io::Error::other(e))?;

    Ok(Box::new(conn))
}

/// 从 `wsSettings` JSON 解析为强类型 [`Config`]。
///
/// 接受的 JSON 字段（对齐 Go proto JSON + 用户配置两种写法）：
/// - `host` / `path`：字符串
/// - `header` 或 `headers`：`map<string,string>`（同时支持两种 key 兼容客户端配置）
/// - `ed`：u32（Early Data 长度）
/// - `heartbeatPeriod`：u32（秒，camelCase 对齐 proto JSON）
///
/// `None` 或非 object 返回 [`Config::default`]。
fn parse_ws_config(json: Option<&serde_json::Value>) -> io::Result<Config> {
    let Some(v) = json else { return Ok(Config::default()); };
    let Some(obj) = v.as_object() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "wsSettings must be a JSON object",
        ));
    };

    let mut host = obj.get("host").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let mut path = obj.get("path").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let mut ed = obj.get("ed").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    let heartbeat_period = obj
        .get("heartbeatPeriod")
        .and_then(|x| x.as_u64())
        .unwrap_or(0) as u32;

    // Go `infra/conf/transport_internet.go::WebSocketConfig.Build`：
    // path 中 `?ed=N` 提取为 Ed 字段并从 path 删除（其余 query 参数保留）。
    if let Some((base, query)) = path.split_once('?') {
        let mut kept = Vec::new();
        for kv in query.split('&') {
            if let Some(v) = kv.strip_prefix("ed=") {
                if let Ok(n) = v.parse::<u32>() {
                    ed = n;
                    continue;
                }
            }
            kept.push(kv);
        }
        path = if kept.is_empty() {
            base.to_string()
        } else {
            format!("{base}?{}", kept.join("&"))
        };
    }

    // Go：headers 里的 host（大小写不敏感）提升为 Host 字段并从 headers 删除。
    let mut header = parse_headers(obj.get("header"))
        .or_else(|| parse_headers(obj.get("headers")))
        .unwrap_or_default();

    if let Some(host_key) = header
        .keys()
        .find(|k| k.eq_ignore_ascii_case("host"))
        .cloned()
    {
        let v = header.remove(&host_key).unwrap_or_default();
        if host.is_empty() {
            host = v;
        }
    }
    let accept_proxy_protocol = obj
        .get("acceptProxyProtocol")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);

    Ok(Config {
        host,
        path,
        header,
        accept_proxy_protocol,
        ed,
        heartbeat_period,
    })
}

/// 把 JSON 子对象解析为 `HashMap<String, String>`。非 object 或缺失返回 `None`。
fn parse_headers(v: Option<&serde_json::Value>) -> Option<std::collections::HashMap<String, String>> {
    let obj = v?.as_object()?;
    let mut map = std::collections::HashMap::with_capacity(obj.len());
    for (k, val) in obj {
        if let Some(s) = val.as_str() {
            map.insert(k.clone(), s.to_string());
        }
        // 非 string 值跳过（与 Go proto JSON 解析对未知字段的容忍一致）。
    }
    Some(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ws_config_none_returns_default() {
        let cfg = parse_ws_config(None).unwrap();
        assert!(cfg.host.is_empty());
        assert!(cfg.path.is_empty());
        assert_eq!(cfg.ed, 0);
    }

    #[test]
    fn parse_ws_config_basic_fields() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"host":"h.example.com","path":"/ws","ed":2048,"heartbeatPeriod":30}"#,
        )
        .unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.host, "h.example.com");
        assert_eq!(cfg.path, "/ws");
        assert_eq!(cfg.ed, 2048);
        assert_eq!(cfg.heartbeat_period, 30);
    }

    #[test]
    fn parse_ws_config_accepts_headers_plural() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"headers":{"X-Forwarded-For":"10.0.0.1"}}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.header.get("X-Forwarded-For").unwrap(), "10.0.0.1");
    }

    #[test]
    fn parse_ws_config_accepts_header_singular() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"header":{"X-Custom":"v"}}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.header.get("X-Custom").unwrap(), "v");
    }

    #[test]
    fn parse_ws_config_header_preferred_over_headers() {
        // 同时给两种 key：header（proto）优先于 headers（用户）。
        let v: serde_json::Value = serde_json::from_str(
            r#"{"header":{"K":"from-proto"},"headers":{"K":"from-user"}}"#,
        )
        .unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.header.get("K").unwrap(), "from-proto");
    }

    #[test]
    fn parse_ws_config_non_object_returns_err() {
        let v: serde_json::Value = serde_json::from_str(r#""not-an-object""#).unwrap();
        let r = parse_ws_config(Some(&v));
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn parse_ws_config_skips_non_string_header_values() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"headers":{"good":"v","bad":123}}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.header.len(), 1);
        assert_eq!(cfg.header.get("good").unwrap(), "v");
    }

    /// 对齐 Go `WebSocketConfig.Build`：`path:"/ws?ed=2048"` → ed=2048, path="/ws"。
    #[test]
    fn parse_ws_config_path_ed_extraction() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"path":"/ws?ed=2048","acceptProxyProtocol":true}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.path, "/ws");
        assert_eq!(cfg.ed, 2048);
        assert!(cfg.accept_proxy_protocol);
    }

    /// 其余 query 参数保留，仅剥离 ed。
    #[test]
    fn parse_ws_config_path_ed_keeps_other_params() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"path":"/ws?x=1&ed=1024&y=2"}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.path, "/ws?x=1&y=2");
        assert_eq!(cfg.ed, 1024);
    }

    /// Go 兼容：headers 里的 host 提升为 Host 字段并从 headers 删除。
    #[test]
    fn parse_ws_config_headers_host_promotion() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"headers":{"Host":"h.example.com","X-Foo":"1"}}"#,
        )
        .unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.host, "h.example.com");
        assert!(!cfg.header.contains_key("Host"));
        assert_eq!(cfg.header.get("X-Foo").map(String::as_str), Some("1"));
    }
}
