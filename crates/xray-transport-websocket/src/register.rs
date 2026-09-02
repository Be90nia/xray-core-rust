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

    // Tcpmask（Go websocket/hub.go:132-134：`TcpmaskManager.WrapListener` →
    // 每条 accept conn 过 `WrapConnServer` 再进 handler；空 manager = 恒等）。
    let tcpmask = Arc::new(
        xray_transport::finalmask::build_tcpmask_manager_from_json(
            settings.finalmask_json.as_ref(),
        )?,
    );

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
                            // Tcpmask wrap 失败 → 丢弃该 conn 继续 accept
                            // （Go finalmask.go tcpListener.Accept：wrap err →
                            // conn.Close + 返回 err，accept 循环继续）。
                            match xray_transport::finalmask::wrap_conn_server_into_connection(
                                &tcpmask,
                                accepted.conn,
                            ) {
                                Ok(conn) => handler(conn),
                                Err(e) => {
                                    tracing::warn!(error = %e, "ws tcpmask wrap failed, dropping conn");
                                }
                            }
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
    let mut tls_config = xray_tls::client_config::build_client_config(
        &settings.security,
        settings.security_json.as_ref(),
        &default_sni,
    )?;
    // Go websocket/dialer.go：`tls.WithNextProto("http/1.1")`——WS upgrade 是
    // HTTP/1.1 语义；默认 ALPN 含 "h2" 时 CDN（Cloudflare）会协商 h2，随后
    // tungstenite 发 HTTP/1.1 upgrade 被 h2 帧流打断（httparse: invalid HTTP version）。
    if let Some(cfg) = tls_config.as_mut() {
        if let Some(c) = std::sync::Arc::get_mut(cfg) {
            c.alpn_protocols = vec![b"http/1.1".to_vec()];
        }
    }

    let conn = dial(DialOptions {
        config: &config,
        destination: dest,
        early_data: None,
        tls_config,
        tls_server_name: settings
            .security_json
            .as_ref()
            .and_then(|v| v.get("serverName"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    })
    .await
    .map_err(|e| io::Error::other(e))?;

    // Tcpmask（Go websocket/dialer.go:56-63：`TcpmaskManager.WrapConnClient`，
    // security 包装之后链式应用 finalmask_json.tcp[]）。
    xray_transport::finalmask::wrap_conn_client_from_settings(settings, Box::new(conn))
}

/// 从 path 提取 `?ed=N` 早期数据参数。
///
/// 对应 Go `infra/conf/transport_internet.go::WebSocketConfig.Build`：
///
/// ```go
/// if u, err := url.Parse(path); err == nil {
///     if q := u.Query(); q.Get("ed") != "" {
///         Ed, _ := strconv.Atoi(q.Get("ed"))
///         ed = uint32(Ed)
///         q.Del("ed")
///         u.RawQuery = q.Encode()
///         path = u.String()
///     }
/// }
/// ```
///
/// 语义逐条对齐 httpupgrade 的 [`xray_transport_httpupgrade::config::extract_ed_from_path`]：
/// - **提取门**：首个 `ed` query 值为非空字符串才提取（`?ed=`、`?ed` 或首值空 → 整体不动）。
/// - **数值**：`strconv.Atoi` 语法错误 → 0（溢出时 Go 返回钳制值且错误被忽略）；
///   `uint32(Ed)` 截断低 32 位，负数回绕。
/// - **删除**：提取触发时删除**全部** `ed` 参数（即使 Atoi 失败）。
/// - **重编码**：剩余参数按 Go `Values.Encode()`——键稳定排序、`QueryEscape`。
/// - **fragment**：`#` 后内容不参与解析，结果原样回接。
/// - **解析失败**：path 部分含非法 `%` 转义时 Go `url.Parse` 报错 → 整体跳过提取。
///
/// 返回 `(清理后 path, 提取的 ed)`；未触发提取时 ed 为 `None`（path 原样返回）。
fn extract_ed_from_path(path: &str) -> (String, Option<u32>) {
    let (before_frag, frag) = match path.split_once('#') {
        Some((b, f)) => (b, Some(f)),
        None => (path, None),
    };
    let Some((base, query)) = before_frag.split_once('?') else {
        return (path.to_string(), None);
    };
    // Go `url.Parse`：path 部分非法 % 转义 → err → 整体不提取。
    if has_invalid_escape(base) {
        return (path.to_string(), None);
    }
    // Go `parseQuery`：`&` 分割、首个 `=` 分 k/v、非法转义跳过该 pair、空 kv 跳过。
    let mut pairs: Vec<(String, String)> = Vec::new();
    for kv in query.split('&') {
        if kv.is_empty() {
            continue;
        }
        let (k, v) = match kv.split_once('=') {
            Some((k, v)) => (k, v),
            None => (kv, ""),
        };
        if let (Some(k), Some(v)) = (query_unescape(k), query_unescape(v)) {
            pairs.push((k, v));
        }
    }
    // Go `Values.Get`：取首个 ed 值；非空字符串才触发提取。
    let Some(ed_value) = pairs.iter().find(|(k, _)| k == "ed").map(|(_, v)| v.clone()) else {
        return (path.to_string(), None);
    };
    if ed_value.is_empty() {
        return (path.to_string(), None);
    }
    let ed = Some(go_atoi_u32(&ed_value));
    // Go `Values.Del("ed")` + `Values.Encode()`：删全部 ed，剩余按键排序 + QueryEscape。
    pairs.retain(|(k, _)| k != "ed");
    let mut out = base.to_string();
    if !pairs.is_empty() {
        pairs.sort_by(|a, b| a.0.cmp(&b.0)); // 稳定排序：同键多值保持插入序
        let encoded: Vec<String> = pairs
            .iter()
            .map(|(k, v)| format!("{}={}", query_escape(k), query_escape(v)))
            .collect();
        out.push('?');
        out.push_str(&encoded.join("&"));
    }
    if let Some(f) = frag {
        out.push('#');
        out.push_str(f);
    }
    (out, ed)
}

/// Go `strconv.Atoi` + `uint32(...)` 转换语义（错误时返回值仍被采用）。
fn go_atoi_u32(s: &str) -> u32 {
    let (neg, digits) = match s.as_bytes().first() {
        Some(b'+') => (false, &s[1..]),
        Some(b'-') => (true, &s[1..]),
        _ => (false, s),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return 0; // 语法错误 → Go Atoi 返回 0 + err（err 被忽略）
    }
    // 溢出：Go ParseInt ErrRange 返回钳制值（正 → MaxInt64，负 → MinInt64=−2^63）。
    let limit: i128 = if neg { 1i128 << 63 } else { i64::MAX as i128 };
    let mut v: i128 = 0;
    for b in digits.bytes() {
        v = (v * 10 + i128::from(b - b'0')).min(limit);
    }
    (if neg { -v } else { v }) as u32 // 截断低 32 位，负数回绕（同 Go uint32(int)）
}

/// Go `url.QueryUnescape`：`+`→空格、`%XX`（大小写十六进制）解码；非法转义返回 `None`。
fn query_unescape(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                if i + 2 >= b.len() {
                    return None;
                }
                let hi = hex_val(b[i + 1])?;
                let lo = hex_val(b[i + 2])?;
                out.push(hi << 4 | lo);
                i += 3;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

/// Go `url.QueryEscape`：`[A-Za-z0-9-_.~]` 保留，空格→`+`，其余 `%XX` 大写。
fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &c in s.as_bytes() {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(c as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{c:02X}")),
        }
    }
    out
}

/// path 部分是否含非法 `%` 转义（Go `unescape(path, encodePath)` 报错场景）。
fn has_invalid_escape(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() || hex_val(b[i + 1]).is_none() || hex_val(b[i + 2]).is_none() {
                return true;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    false
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
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
    let (cleaned, path_ed) = extract_ed_from_path(&path);
    path = cleaned;
    if let Some(e) = path_ed {
        ed = e;
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

    // ---------------------------------------------------------------------
    // `extract_ed_from_path` Go 语义边界（与 httpupgrade 完整版对齐）
    // ---------------------------------------------------------------------

    /// 键排序：剩余参数按字母序拼成 early data，ed=2048 提取后 path="/ws?x=1&y=2"。
    #[test]
    fn extract_ed_key_sort() {
        let v: serde_json::Value = serde_json::from_str(r#"{"path":"/ws?y=2&ed=2048&x=1"}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.path, "/ws?x=1&y=2");
        assert_eq!(cfg.ed, 2048);
    }

    /// Atoi 边界 — 超过 u32 上限 (> 65535 区段展示)：截断低 32 位（Go uint32(int) 语义）。
    #[test]
    fn extract_ed_atoi_clamps_overflow() {
        // 4294967297 = 2^32 + 1 → 截断后为 1
        let v: serde_json::Value =
            serde_json::from_str(r#"{"path":"/ws?ed=4294967297"}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.ed, 1);
        assert_eq!(cfg.path, "/ws");
        // 99999999999999999999 → Go ParseInt ErrRange 钳到 MaxInt64 → uint32 截断 = 0xFFFFFFFF
        let v: serde_json::Value =
            serde_json::from_str(r#"{"path":"/ws?ed=99999999999999999999"}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.ed, u32::MAX);
        assert_eq!(cfg.path, "/ws");
        // -99999999999999999999 → Go ErrRange 钳到 MinInt64 → uint32 截断 = 0
        let v: serde_json::Value =
            serde_json::from_str(r#"{"path":"/ws?ed=-99999999999999999999"}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.ed, 0);
        assert_eq!(cfg.path, "/ws");
    }

    /// Atoi 边界 — 负数回绕（Go `uint32(int)` 截断低 32 位）。
    #[test]
    fn extract_ed_atoi_negative_wraps() {
        let v: serde_json::Value = serde_json::from_str(r#"{"path":"/ws?ed=-1"}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.ed, u32::MAX);
        assert_eq!(cfg.path, "/ws");
    }

    /// Atoi 边界 — 非数字字符串：Go Atoi 返回 err，ed=0，参数仍删除。
    #[test]
    fn extract_ed_atoi_non_numeric_zero() {
        let v: serde_json::Value = serde_json::from_str(r#"{"path":"/ws?ed=abc"}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.ed, 0);
        assert_eq!(cfg.path, "/ws");
    }

    /// 空值门：ed 值缺失 / 空字符串 / 仅 `ed` 无 `=` → 整体不动，cfg.ed 默认 0。
    #[test]
    fn extract_ed_empty_gate_keeps_path() {
        // "?ed=" → 首值空 → 整体不动
        let v: serde_json::Value = serde_json::from_str(r#"{"path":"/ws?ed="}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.path, "/ws?ed=");
        assert_eq!(cfg.ed, 0);
        // "?ed" 无 = → 整体不动
        let v: serde_json::Value = serde_json::from_str(r#"{"path":"/ws?ed"}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.path, "/ws?ed");
        assert_eq!(cfg.ed, 0);
        // "?ed=&ed=2048" → 首值空 → 整体不动（Go Get 取首个，非空才触发）
        let v: serde_json::Value = serde_json::from_str(r#"{"path":"/ws?ed=&ed=2048"}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.path, "/ws?ed=&ed=2048");
        assert_eq!(cfg.ed, 0);
    }

    /// 多 ed 键：Get 取首个，Del 删全部（即使首值空 → 不触发）。
    #[test]
    fn extract_ed_multiple_ed_first_non_empty() {
        let v: serde_json::Value = serde_json::from_str(r#"{"path":"/ws?ed=1&ed=2"}"#).unwrap();
        let cfg = parse_ws_config(Some(&v)).unwrap();
        assert_eq!(cfg.ed, 1);
        assert_eq!(cfg.path, "/ws");
    }

    /// 单元测直接测 `extract_ed_from_path` 助手（Go 语义全矩阵）。
    #[test]
    fn extract_ed_from_path_go_semantics() {
        let f = |p: &str| extract_ed_from_path(p);
        // 基本提取 + 删除
        assert_eq!(f("/ws?ed=2048"), ("/ws".to_string(), Some(2048)));
        // 无 query / 无 ed：原样
        assert_eq!(f("/ws"), ("/ws".to_string(), None));
        assert_eq!(f("/ws?x=1"), ("/ws?x=1".to_string(), None));
        // 提取门
        assert_eq!(f("/ws?ed="), ("/ws?ed=".to_string(), None));
        assert_eq!(f("/ws?ed"), ("/ws?ed".to_string(), None));
        // 多 ed 取首
        assert_eq!(f("/ws?ed=1&ed=2"), ("/ws".to_string(), Some(1)));
        // ed=0 仍触发（值非空）+ 删除
        assert_eq!(f("/ws?ed=0"), ("/ws".to_string(), Some(0)));
        // 非法数值 → 0 + 删除
        assert_eq!(f("/ws?ed=abc"), ("/ws".to_string(), Some(0)));
        // 负数 → uint32 回绕
        assert_eq!(f("/ws?ed=-1"), ("/ws".to_string(), Some(u32::MAX)));
        // 溢出钳制
        assert_eq!(
            f("/ws?ed=99999999999999999999"),
            ("/ws".to_string(), Some(u32::MAX))
        );
        assert_eq!(
            f("/ws?ed=-99999999999999999999"),
            ("/ws".to_string(), Some(0))
        );
        // u32 范围内截断低 32 位
        assert_eq!(f("/ws?ed=4294967297"), ("/ws".to_string(), Some(1)));
        // 剩余按键排序 + QueryEscape
        assert_eq!(f("/ws?y=2&ed=1024&x=1"), ("/ws?x=1&y=2".to_string(), Some(1024)));
        // fragment 保留
        assert_eq!(f("/ws?ed=2048#frag"), ("/ws#frag".to_string(), Some(2048)));
        // path 部分非法 % 转义 → 整体不动
        assert_eq!(f("/w%zz?ed=2048"), ("/w%zz?ed=2048".to_string(), None));
    }

    /// Tcpmask round-trip（o54c，Go websocket/dialer.go:56-63 + hub.go:132-134）：
    /// dial 与 hub 双端配置 fragment mask 后 e2e echo 收发。
    #[tokio::test]
    async fn ws_dial_hub_tcpmask_roundtrip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use xray_common::net::address::Address;
        use xray_common::net::network::Network;
        use xray_common::net::port::Port;

        let finalmask = serde_json::json!({
            "tcp": [{"type": "fragment", "settings": {
                "packets_from": 1, "packets_to": 2,
                "length": {"from": 8, "to": 16}, "interval": {"from": 0, "to": 0}
            }}]
        });
        let mut settings = StreamSettings::default();
        settings.protocol = "websocket".to_string();
        settings.transport_json = Some(serde_json::json!({"path": "/ws"}));
        settings.finalmask_json = Some(finalmask);

        // echo handler：读到什么写回什么。
        let handler: ConnHandler = Arc::new(|conn| {
            tokio::spawn(async move {
                let mut conn = conn;
                let mut buf = [0u8; 1024];
                loop {
                    match conn.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if conn.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        });
        let listener = listen_ws("127.0.0.1:0".parse().unwrap(), &settings, &handler)
            .await
            .expect("listen_ws");
        let addr = listener.local_addr().expect("local_addr");

        let dest = Destination::new(
            Address::new_domain("127.0.0.1"),
            Port::new(addr.port()),
            Network::TCP,
        );
        let mut conn = dial_ws(&dest, &settings).await.expect("dial_ws");

        conn.write_all(b"hello-ws-tcpmask").await.expect("write");
        let mut buf = vec![0u8; 64];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            conn.read(&mut buf),
        )
        .await
        .expect("echo timeout")
        .expect("read ok");
        assert_eq!(&buf[..n], b"hello-ws-tcpmask");
    }
}
