//! HTTPUpgrade transport dialer + listener 注册。
//!
//! 对应 Go `transport/internet/httpupgrade/dialer.go::init()` 中的
//! `internet.RegisterTransportDialer(protocolName, Dial(...))` 和
//! `transport/internet/httpupgrade/hub.go::init()` 中的
//! `internet.RegisterTransportListener(protocolName, Listen(...))`。
//!
//! ## 调用
//!
//! 进程启动时调用一次 [`register_dialer`] 和 [`register_listener`]；幂等——重复注册的 `AlreadyExists` 被忽略。
//!
//! ## 已集成
//!
//! 拨号器已完整集成：TCP 拨号 + TLS 包装 + HTTP/1.1 upgrade 握手。
//! 监听器已集成：TCP bind + PROXY protocol + TLS + HTTP/1.1 握手 + accept loop。

use std::io;
use std::net::SocketAddr;
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

use crate::client::HttpUpgradeClient;
use crate::config::Config;
use crate::connection::HttpUpgradeConnection;
use crate::server::HttpUpgradeServer;
/// 注册 HTTPUpgrade transport dialer。
///
/// 协议名注册 `"httpupgrade"`——Go JSON `network` 字段此值映射到 `httpupgradeSettings`。
///
/// 幂等：重复调用忽略 `AlreadyExists`（对齐 Go `init()` 在测试中多次执行的容错）。
pub fn register_dialer() -> io::Result<()> {
    let dialer: TransportDialFn = Arc::new(move |dest, sockopt, settings| {
        let dest = dest.clone();
        let sockopt = sockopt.clone();
        let settings = settings.clone();
        Box::pin(async move { dial_httpupgrade(&dest, &sockopt, &settings).await })
    });
    // ponytail: 重复注册忽略——主代理与测试可能并发触发注册。
    let _ = register_transport_dialer("httpupgrade", dialer);
    Ok(())
}

/// 注册 HTTPUpgrade transport listener。
///
/// 协议名注册 `"httpupgrade"`，与 [`register_dialer`] 一致。
///
/// 幂等：重复调用忽略 `AlreadyExists`。
pub fn register_listener() -> io::Result<()> {
    let listen_fn: TransportListenFn = Arc::new(move |addr, settings, sockopt, handler| {
        let settings = settings.clone();
        let sockopt = sockopt.clone();
        Box::pin(async move { listen_httpupgrade(addr, &settings, &sockopt, handler).await })
    });
    let _ = register_transport_listener("httpupgrade", listen_fn);
    Ok(())
}

/// 实际监听：TCP bind → PROXY protocol（可选）→ TLS（可选）→ HTTP upgrade 握手 → accept loop。
///
/// 对应 Go `hub.go::ListenHTTPUpgrade`：
/// 1. 解析 httpupgrade 配置
/// 2. TCP bind (`internet.ListenSystem`)
/// 3. accept loop：每条连接 → PROXY protocol → TLS → HTTP upgrade 握手 → ConnHandler
async fn listen_httpupgrade(
    addr: SocketAddr,
    settings: &StreamSettings,
    sockopt: &SocketOptions,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    let config = parse_httpupgrade_config(settings.transport_json.as_ref())?;
    let accept_proxy = config.accept_proxy_protocol;

    // 1. TCP bind
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;

    // 2. TLS 配置（可选）
    let tls_config = build_tls_server_config(settings)?;

    // Tcpmask（Go httpupgrade/hub.go:145-147：`TcpmaskManager.WrapListener` →
    // 每条 accept conn 过 `WrapConnServer` 再进 handler；空 manager = 恒等）。
    let tcpmask = Arc::new(
        xray_transport::finalmask::build_tcpmask_manager_from_json(
            settings.finalmask_json.as_ref(),
        )?,
    );

    // 3. spawn accept loop（XFF 信任名单来自 sockopt.trustedXForwardedFor，
    // Go hub.go:117-121 + 90-94）。
    let mut server = HttpUpgradeServer::new(config);
    server.trusted_x_forwarded_for = sockopt.trusted_x_forwarded_for.clone();
    // accept task 的 abort 句柄：close() 直接取消 task，parked 在 accept() 上的
    // 循环被确定性解除，TcpListener drop 即释放端口（对齐 Go hub.go Close()）。
    let accept_task = tokio::spawn(async move {
        loop {
            let (mut tcp, mut remote) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::debug!("HTTPUpgrade accept error: {e}");
                    continue;
                }
            };

            // PROXY protocol（可选）
            if accept_proxy {
                match xray_transport::read_proxy_protocol(&mut tcp).await {
                    Ok(Some(real_addr)) => remote = real_addr,
                    Ok(None) => {},
                    Err(e) => {
                        tracing::debug!("HTTPUpgrade PROXY protocol parse error: {e}");
                        continue;
                    }
                }
            }

            match do_handshake(tcp, &server, tls_config.clone(), remote).await {
                Ok(conn) => {
                    // Tcpmask wrap 失败 → 丢弃该 conn 继续（Go tcpListener.Accept 语义）。
                    match xray_transport::finalmask::wrap_conn_server_into_connection(
                        &tcpmask,
                        conn,
                    ) {
                        Ok(masked) => handler(masked),
                        Err(e) => {
                            tracing::debug!("HTTPUpgrade tcpmask wrap error: {e}");
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("HTTPUpgrade handshake error: {e}");
                }
            }
        }
    });

    Ok(Box::new(HttpUpgradeListener { local, abort: accept_task.abort_handle() })
        as Box<dyn TransportListener>)
}

async fn do_handshake(
    tcp: tokio::net::TcpStream,
    server: &HttpUpgradeServer,
    tls_config: Option<Arc<tokio_rustls::rustls::ServerConfig>>,
    remote: SocketAddr,
) -> io::Result<Box<dyn Connection>> {
    // security=tls：先完成 TLS accept，再在其上做 HTTP upgrade 握手
    // （Go hub.go：tls.Server(conn) 后进 upgrade handler）；非 TLS 直连。
    let wrapped: Box<dyn Connection> = match tls_config {
        Some(cfg) => {
            let tls = xray_tls::utls::server(
                xray_transport::connection::TcpConnection::new(tcp),
                cfg,
            )
            .await?;
            Box::new(tls)
        }
        None => Box::new(xray_transport::connection::TcpConnection::new(tcp)),
    };
    let (conn, _leftover) = server
        .handshake_io(wrapped)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, format!("HTTPUpgrade handshake: {e}")))?;
    let final_conn = if conn.remote_addr_override.is_some() { conn }
        else { HttpUpgradeConnection::with_remote_addr(conn.into_inner(), remote) };
    Ok(Box::new(final_conn) as Box<dyn Connection>)
}

/// 构建 TLS server config（如果 security == "tls"），非 TLS 返回 None。
///
/// 对应 Go `hub.go` 的 `tlsConfig := tls.ConfigFromStreamSettings(...)`。
fn build_tls_server_config(
    settings: &StreamSettings,
) -> io::Result<Option<Arc<tokio_rustls::rustls::ServerConfig>>> {
    xray_tls::server_config::build_server_config(
        &settings.security,
        settings.security_json.as_ref(),
    )
}

/// HTTPUpgrade transport listener 句柄。
struct HttpUpgradeListener {
    local: SocketAddr,
    abort: tokio::task::AbortHandle,
}

impl TransportListener for HttpUpgradeListener {
    fn close(&self) -> io::Result<()> {
        // 取消 accept task：正在 accept()/握手 await 中的循环被打断，端口释放。
        self.abort.abort();
        Ok(())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

/// HTTP `Host` 三级回退（Go dialer.go:83-89）：
/// `config.host` → `tlsSettings.serverName`（仅 TLS 配置时参与）→ 拨号地址。
///
/// CDN 按 IP 拨号且对端校验 Host 时（hub.go:57-59），缺 serverName 级会
/// 404 unrecognized（票 gbgr）。
#[must_use]
fn resolve_upgrade_host(
    config_host: &str,
    tls_active: bool,
    server_name: Option<&str>,
    dest_address: &str,
) -> String {
    if !config_host.is_empty() {
        config_host.to_string()
    } else if tls_active {
        server_name
            .filter(|s| !s.is_empty())
            .unwrap_or(dest_address)
            .to_string()
    } else {
        dest_address.to_string()
    }
}

/// 实际拨号：解析配置 → TCP 拨号 → TLS 包装（可选）→ HTTP upgrade 握手。
///
/// 对应 Go `dialer.go::dialhttpUpgrade` 完整流程：
/// 1. 解析 httpupgrade 配置
/// 2. TCP 拨号 (`internet.DialSystem`)
/// 3. TLS 包装（`security == "tls"` 或 `"reality"` 时）
/// 4. HTTP/1.1 upgrade 握手 (`HttpUpgradeClient::dial_over_io`)
async fn dial_httpupgrade(
    dest: &Destination,
    sockopt: &SocketOptions,
    settings: &StreamSettings,
) -> io::Result<Box<dyn Connection>> {
    let config = parse_httpupgrade_config(settings.transport_json.as_ref())?;

    // Host 三级回退（Go dialer.go:83-89）：config.host → tlsSettings.serverName
    // （仅 TLS 配置时参与）→ 拨号地址。CDN 按 IP 拨号 + 对端校验 Host 场景，
    // 缺 serverName 级会导致 404 unrecognized（票 gbgr）。
    let default_sni = dest.address().to_string();

    // 1. 可选 TLS 配置（先于 Host 回退：Go `tConfig != nil` 门槛需要它）。
    let mut tls_config = xray_tls::client_config::build_client_config(
        &settings.security,
        settings.security_json.as_ref(),
        &default_sni,
    )?;
    // tlsSettings.serverName（可空：Go `tConfig.ServerName` 空则落第三级）。
    let server_name = settings
        .security_json
        .as_ref()
        .and_then(|v| v.get("serverName"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let host = resolve_upgrade_host(
        &config.host,
        tls_config.is_some(),
        server_name.as_deref(),
        &default_sni,
    );

    // 2. TCP 拨号
    let tcp_conn = xray_transport::system_dialer::dial_system(dest, sockopt).await?;

    // Go httpupgrade/dialer.go：`tls.WithNextProto("http/1.1")`——upgrade 是
    // HTTP/1.1 语义，ALPN 含 "h2" 时 CDN 协商 h2 导致 upgrade 帧解析失败。
    if let Some(cfg) = tls_config.as_mut() {
        if let Some(c) = std::sync::Arc::get_mut(cfg) {
            c.alpn_protocols = vec![b"http/1.1".to_vec()];
        }
    }

    // Go：SNI = tlsSettings.serverName（缺失用 dest）——与拨号目标解耦（CDN 场景）。
    let sni = server_name.unwrap_or_else(|| default_sni.clone());

    let upgraded_conn: Box<dyn Connection> = if let Some(cfg) = tls_config {
        // Go httpupgrade/dialer.go:68-77：fingerprint 解析成功（缺省 → chrome
        // 默认）即 UClient + WebsocketHandshakeContext（btls 真实指纹 + ALPN
        // http/1.1 重写）；非法指纹名 → GetFingerprint nil → 标准 TLS。
        // md5i 接线（2026-09-06 回归根因 = chrome 模板 ALPN h2 被 CDN 协商，
        // h1 upgrade 帧解析失败；ALPN 重写见 connect_with_alpn）。
        match xray_tls::fingerprint::get_fingerprint(fingerprint_name(settings)) {
            Ok(fp) => {
                let alpn =
                    xray_tls::utls::websocket_handshake_alpn(settings.security_json.as_ref());
                let tls_conn = xray_tls::utls::u_client_with_alpn(
                    tcp_conn,
                    &sni,
                    cfg,
                    fp,
                    None,
                    settings.security_json.as_ref(),
                    Some(&alpn),
                )
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, format!("TLS handshake failed: {e}")))?;
                Box::new(tls_conn) as Box<dyn Connection>
            }
            Err(_) => {
                let tls_conn = xray_tls::utls::client(tcp_conn, &sni, cfg)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, format!("TLS handshake failed: {e}")))?;
                Box::new(tls_conn) as Box<dyn Connection>
            }
        }
    } else {
        tcp_conn
    };

    // 3. HTTP upgrade 握手
    let client = HttpUpgradeClient::new(host, config.clone());
    let ed = config.ed;

    let conn: Box<dyn Connection> = if ed > 0 {
        // 0-RTT：延迟读 101 响应，让上层先写 early data
        let httpupgrade_conn = client
            .dial_over_io_deferred(upgraded_conn)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, format!("HTTPUpgrade handshake failed: {e}")))?;
        Box::new(httpupgrade_conn) as Box<dyn Connection>
    } else {
        let (httpupgrade_conn, _leftover) = client
            .dial_over_io(upgraded_conn)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, format!("HTTPUpgrade handshake failed: {e}")))?;
        Box::new(httpupgrade_conn) as Box<dyn Connection>
    };
    // Tcpmask（Go httpupgrade/dialer.go:55-60：`TcpmaskManager.WrapConnClient`）。
    xray_transport::finalmask::wrap_conn_client_from_settings(settings, conn)
}

/// 从 `httpupgradeSettings` JSON 解析为强类型 [`Config`]。
///
/// 接受的 JSON 字段（对齐 Go proto JSON + 用户配置两种写法）：
/// - `host`：字符串（HTTP Host header）
/// - `path`：字符串（URL 路径）
/// - `header` 或 `headers`：`map<string,string>`（同时支持两种 key 兼容客户端配置）
/// - `ed`：u32（Early Data 长度）
/// - `acceptProxyProtocol`：bool（服务端用，客户端忽略）
///
/// `None` 或非 object 返回 [`Config::default`]。
fn parse_httpupgrade_config(json: Option<&serde_json::Value>) -> io::Result<Config> {
    let Some(v) = json else { return Ok(Config::default()); };
    let Some(obj) = v.as_object() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "httpupgradeSettings must be a JSON object",
        ));
    };

    let host = obj
        .get("host")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let mut path = obj
        .get("path")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let mut ed = obj.get("ed").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    // Go `HttpUpgradeConfig.Build`：path 中 `?ed=N` 提取为 ed 并从 path 删除
    // （Go 用户配置层唯一来源；此处优先于直接 ed 字段）。
    let (cleaned, path_ed) = crate::config::extract_ed_from_path(&path);
    path = cleaned;
    if let Some(e) = path_ed {
        ed = e;
    }
    let accept_proxy_protocol = obj
        .get("acceptProxyProtocol")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);

    // header / headers 二选一（proto JSON 用 "header"，用户配置常写 "headers"）。
    let header = parse_headers(obj.get("header"))
        .or_else(|| parse_headers(obj.get("headers")))
        .unwrap_or_default();

    Ok(Config {
        host,
        path,
        header,
        accept_proxy_protocol,
        ed,
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


/// 读 `tlsSettings.fingerprint`（空 = 未配置）。Go `tls.GetFingerprint` 的
/// 前置解析；四个传输出站共用同款语义，与 tcp register 内联实现一致。
fn fingerprint_name(settings: &StreamSettings) -> &str {
    settings
        .security_json
        .as_ref()
        .and_then(|v| v.as_object())
        .and_then(|m| m.get("fingerprint"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
}
#[cfg(test)]
mod tests {
    use super::*;
    use xray_transport::dialer::get_transport_dialer;

    #[test]
    fn tls_server_config_none_when_security_empty() {
        let settings = StreamSettings::tcp();
        assert!(build_tls_server_config(&settings).unwrap().is_none());
    }

    #[test]
    fn fingerprint_name_reads_tls_settings() {
        let mut s = StreamSettings::tcp();
        s.security_json = Some(serde_json::json!({"fingerprint": "chrome"}));
        assert_eq!(fingerprint_name(&s), "chrome");
        // 未配置 → 空串（走标准 rustls 分支）。
        assert_eq!(fingerprint_name(&StreamSettings::tcp()), "");
    }

    #[test]
    fn parse_httpupgrade_config_none_returns_default() {
        let cfg = parse_httpupgrade_config(None).unwrap();
        assert!(cfg.host.is_empty());
        assert!(cfg.path.is_empty());
        assert_eq!(cfg.ed, 0);
        assert!(cfg.header.is_empty());
    }

    #[test]
    fn parse_httpupgrade_config_basic_fields() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"host":"h.example.com","path":"/upgrade","ed":2048}"#,
        )
        .unwrap();
        let cfg = parse_httpupgrade_config(Some(&v)).unwrap();
        assert_eq!(cfg.host, "h.example.com");
        assert_eq!(cfg.path, "/upgrade");
        assert_eq!(cfg.ed, 2048);
    }

    /// 对齐 Go `HttpUpgradeConfig.Build`（infra/conf/transport_internet.go:186-210）：
    /// `path:"/ws?ed=2048"` → ed=2048、path 剥离 query。
    #[test]
    fn parse_httpupgrade_config_path_ed_extraction() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"path":"/ws?ed=2048"}"#).unwrap();
        let cfg = parse_httpupgrade_config(Some(&v)).unwrap();
        assert_eq!(cfg.path, "/ws");
        assert_eq!(cfg.ed, 2048);
    }

    /// 多参数：`ed` 提取后其余参数保留（Go `q.Del("ed")` + `q.Encode()`，按键排序）。
    #[test]
    fn parse_httpupgrade_config_path_ed_keeps_other_params() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"path":"/ws?x=1&ed=1024&y=2"}"#).unwrap();
        let cfg = parse_httpupgrade_config(Some(&v)).unwrap();
        assert_eq!(cfg.path, "/ws?x=1&y=2");
        assert_eq!(cfg.ed, 1024);
    }

    /// 非法数值：Go `Ed, _ := strconv.Atoi(...)` 忽略错误 → ed=0，但 `ed` 参数仍被删除。
    #[test]
    fn parse_httpupgrade_config_path_ed_invalid_value_zero() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"path":"/ws?ed=abc"}"#).unwrap();
        let cfg = parse_httpupgrade_config(Some(&v)).unwrap();
        assert_eq!(cfg.path, "/ws");
        assert_eq!(cfg.ed, 0);
    }

    /// 空值：Go `q.Get("ed") != ""` 不成立 → 整体不提取，path 原样保留。
    #[test]
    fn parse_httpupgrade_config_path_empty_ed_value_no_extraction() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"path":"/ws?ed="}"#).unwrap();
        let cfg = parse_httpupgrade_config(Some(&v)).unwrap();
        assert_eq!(cfg.path, "/ws?ed=");
        assert_eq!(cfg.ed, 0);
    }

    /// path 中 `?ed=` 优先于直接 `ed` 字段（Go JSON 配置层只有 path 提取一条来源）。
    #[test]
    fn parse_httpupgrade_config_path_ed_overrides_direct_field() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"path":"/ws?ed=2048","ed":4096}"#).unwrap();
        let cfg = parse_httpupgrade_config(Some(&v)).unwrap();
        assert_eq!(cfg.path, "/ws");
        assert_eq!(cfg.ed, 2048);
    }

    #[test]
    fn parse_httpupgrade_config_accepts_headers_plural() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"headers":{"X-Forwarded-For":"10.0.0.1"}}"#).unwrap();
        let cfg = parse_httpupgrade_config(Some(&v)).unwrap();
        assert_eq!(cfg.header.get("X-Forwarded-For").unwrap(), "10.0.0.1");
    }

    #[test]
    fn parse_httpupgrade_config_accepts_header_singular() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"header":{"X-Custom":"v"}}"#).unwrap();
        let cfg = parse_httpupgrade_config(Some(&v)).unwrap();
        assert_eq!(cfg.header.get("X-Custom").unwrap(), "v");
    }

    #[test]
    fn parse_httpupgrade_config_header_preferred_over_headers() {
        // 同时给两种 key：header（proto）优先于 headers（用户）。
        let v: serde_json::Value = serde_json::from_str(
            r#"{"header":{"K":"from-proto"},"headers":{"K":"from-user"}}"#,
        )
        .unwrap();
        let cfg = parse_httpupgrade_config(Some(&v)).unwrap();
        assert_eq!(cfg.header.get("K").unwrap(), "from-proto");
    }

    #[test]
    fn parse_httpupgrade_config_non_object_returns_err() {
        let v: serde_json::Value = serde_json::from_str(r#""not-an-object""#).unwrap();
        let r = parse_httpupgrade_config(Some(&v));
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn parse_httpupgrade_config_skips_non_string_header_values() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"headers":{"good":"v","bad":123}}"#).unwrap();
        let cfg = parse_httpupgrade_config(Some(&v)).unwrap();
        assert_eq!(cfg.header.len(), 1);
        assert_eq!(cfg.header.get("good").unwrap(), "v");
    }

    #[test]
    fn parse_httpupgrade_config_accept_proxy_protocol() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"acceptProxyProtocol":true}"#).unwrap();
        let cfg = parse_httpupgrade_config(Some(&v)).unwrap();
        assert!(cfg.accept_proxy_protocol);
    }

    #[test]
    fn register_dialer_registers_protocol_name() {
        register_dialer().unwrap();
        assert!(get_transport_dialer("httpupgrade").is_some());
    }

    #[tokio::test]
    async fn dial_httpupgrade_connects_to_local_server() {
        use xray_common::net::address::Address;
        use xray_common::net::network::Network;
        use xray_common::net::port::Port;
        use std::net::Ipv4Addr;

        // 启动本地 TCP listener 模拟 HTTPUpgrade 服务端。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            // 读客户端请求
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            let req = std::str::from_utf8(&buf[..n]).unwrap();
            assert!(req.starts_with("GET /ws HTTP/1.1"));
            // 回 101 响应
            let resp = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
            stream.write_all(resp).await.unwrap();
            stream.flush().await.unwrap();
        });

        let dest = Destination::new(
            Address::IPv4(Ipv4Addr::LOCALHOST),
            Port::new(addr.port()),
            Network::TCP,
        );
        let settings = StreamSettings {
            protocol: "httpupgrade".to_string(),
            transport_json: Some(serde_json::json!({"path":"/ws"})),
            ..StreamSettings::tcp()
        };
        let sockopt = SocketOptions::default();
        let result = dial_httpupgrade(&dest, &sockopt, &settings).await;
        assert!(result.is_ok(), "dial should succeed: {:?}", result.err());
        let conn = result.unwrap();
        // 验证 Connection 可用
        assert!(conn.remote_addr().is_ok());
        server.await.unwrap();
    }

    /// md5i 验收：httpupgrade 出站 fingerprint=chrome → btls 真实 chrome
    /// ClientHello（多 cipher + GREASE，rustls 从不发送），ALPN 仅 http/1.1
    /// （Go `WebsocketHandshakeContext` 语义）。
    #[tokio::test]
    async fn dial_tls_fingerprint_chrome_sends_btls_hello_with_h1_alpn() {
        use xray_common::net::address::Address;
        use xray_common::net::network::Network;
        use xray_common::net::port::Port;
        use std::net::Ipv4Addr;
        use tokio::io::AsyncReadExt;
        use std::time::Duration;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
                    .await
                    .expect("hello read timeout")
                    .unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 5 && buf[0] == 0x16 {
                    let want = 5 + (usize::from(buf[3]) << 8) + usize::from(buf[4]);
                    if buf.len() >= want {
                        break;
                    }
                }
            }
            buf
        });

        let dest = Destination::new(
            Address::IPv4(Ipv4Addr::LOCALHOST),
            Port::new(addr.port()),
            Network::TCP,
        );
        let settings = StreamSettings {
            protocol: "httpupgrade".to_string(),
            transport_json: Some(serde_json::json!({"path":"/hu"})),
            security: "tls".to_string(),
            security_json: Some(serde_json::json!({"fingerprint": "chrome"})),
            ..StreamSettings::tcp()
        };
        let result = dial_httpupgrade(&dest, &SocketOptions::default(), &settings).await;
        assert!(result.is_err(), "capture server drops conn → dial must fail");

        let hello = server.await.unwrap();
        assert_eq!(hello[0], 0x16, "TLS handshake record");
        let mut c = 43usize;
        c += 1 + usize::from(hello[c]); // session_id
        let len = (usize::from(hello[c]) << 8) + usize::from(hello[c + 1]);
        let suites = &hello[c + 2..c + 2 + len];
        assert!(len / 2 >= 12, "chrome hello must carry many ciphers");
        assert!(
            suites
                .chunks_exact(2)
                .any(|s| s[0] == s[1] && (s[0] & 0x0f) == 0x0a),
            "GREASE cipher absent → not a btls chrome hello"
        );
        let mut h1_wire = vec![0x00, 0x09, 0x08];
        h1_wire.extend_from_slice(b"http/1.1");
        assert!(
            hello.windows(h1_wire.len()).any(|w| w == h1_wire.as_slice()),
            "ALPN must be http/1.1-only"
        );
    }

    /// `?ed=` 端到端往返：path 提取 ed → 客户端 0-RTT（101 前先写 early data）→
    /// 延迟读解析 101 → 读到服务端 payload。对齐 Go `dialer.go:114-118`（Ed!=0 时不预读响应）。
    #[tokio::test]
    async fn dial_httpupgrade_path_ed_early_data_roundtrip() {
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use xray_common::net::address::Address;
        use xray_common::net::network::Network;
        use xray_common::net::port::Port;
        use std::net::Ipv4Addr;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            // 1. 读完整请求头；path 应已剥离 ?ed=2048。
            //    early data 可能与请求头同段到达（TCP 合并）——保留 \r\n\r\n 之后的余留，
            //    与生产端 hub.rs handshake_io 返回 leftover 的做法一致。
            let mut req = Vec::new();
            let hdr_end = loop {
                let n = stream.read(&mut buf).await.unwrap();
                assert!(n > 0);
                req.extend_from_slice(&buf[..n]);
                if let Some(pos) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
            };
            let req_str = String::from_utf8_lossy(&req[..hdr_end]);
            assert!(
                req_str.starts_with("GET /ws HTTP/1.1"),
                "path 应剥离 ?ed=2048，实际: {req_str}"
            );
            // 2. 收 early data（ed=0 时客户端会阻塞等 101 → 此处 5s 超时失败而非挂死）
            let mut early = req[hdr_end..].to_vec();
            while early.len() < 5 {
                let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
                    .await
                    .expect("early data 应在 101 响应之前到达")
                    .expect("stream read");
                assert!(n > 0);
                early.extend_from_slice(&buf[..n]);
            }
            assert_eq!(&early[..5], b"early");
            // 3. 回 101 + 服务端首包
            stream
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\npong")
                .await
                .unwrap();
            stream.flush().await.unwrap();
        });

        let dest = Destination::new(
            Address::IPv4(Ipv4Addr::LOCALHOST),
            Port::new(addr.port()),
            Network::TCP,
        );
        let settings = StreamSettings {
            protocol: "httpupgrade".to_string(),
            transport_json: Some(serde_json::json!({"path":"/ws?ed=2048"})),
            ..StreamSettings::tcp()
        };
        let mut conn = dial_httpupgrade(&dest, &SocketOptions::default(), &settings)
            .await
            .expect("dial should succeed");

        // dial 返回即可写 early data（0-RTT，无需先等 101）
        conn.write_all(b"early").await.unwrap();
        conn.flush().await.unwrap();

        // 首次 read：DeferredResponseReader 解析 101 后透传 payload
        let mut out = vec![0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(5), conn.read(&mut out))
            .await
            .expect("read 应在 101 后返回")
            .expect("read should succeed");
        assert_eq!(&out[..n], b"pong");
        server.await.unwrap();
    }

    /// Tcpmask round-trip（o54c，Go httpupgrade/dialer.go:55-60 + hub.go:145-147）：
    /// dial 与 hub 双端配置 fragment mask 后 e2e echo 收发。
    #[tokio::test]
    async fn httpupgrade_dial_hub_tcpmask_roundtrip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use xray_common::net::address::Address;
        use xray_common::net::network::Network;
        use xray_common::net::port::Port;
        use std::net::Ipv4Addr;
        use std::time::Duration;

        let finalmask = serde_json::json!({
            "tcp": [{"type": "fragment", "settings": {
                "packets_from": 1, "packets_to": 2,
                "length": {"from": 8, "to": 16}, "interval": {"from": 0, "to": 0}
            }}]
        });
        let settings = StreamSettings {
            protocol: "httpupgrade".to_string(),
            transport_json: Some(serde_json::json!({"path":"/hu"})),
            finalmask_json: Some(finalmask),
            ..StreamSettings::tcp()
        };

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
        let listener = listen_httpupgrade(
            "127.0.0.1:0".parse().unwrap(),
            &settings,
            &SocketOptions::default(),
            handler,
        )
        .await
        .expect("listen_httpupgrade");
        let addr = listener.local_addr().expect("local_addr");

        let dest = Destination::new(
            Address::IPv4(Ipv4Addr::LOCALHOST),
            Port::new(addr.port()),
            Network::TCP,
        );
        let mut conn = dial_httpupgrade(&dest, &SocketOptions::default(), &settings)
            .await
            .expect("dial_httpupgrade");

        conn.write_all(b"hello-hu-tcpmask").await.expect("write");
        // tcpmask 分片 + echo 按 chunk 回写：单次 read 可能只拿到一个分片
        // （8-16B），TCP 拆段即红（CI ubuntu 首跑实证）。循环读满 17 字节，
        // 总预算 5s；产品无问题（分片本来就不保证整段一次到达）。
        let payload = b"hello-hu-tcpmask";
        let mut got = Vec::with_capacity(payload.len());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while got.len() < payload.len() {
            let mut buf = [0u8; 64];
            let budget = deadline.saturating_duration_since(tokio::time::Instant::now());
            let n = tokio::time::timeout(budget, conn.read(&mut buf))
                .await
                .expect("echo timeout")
                .expect("read ok");
            assert!(
                n > 0,
                "echo closed early at {}/{} bytes",
                got.len(),
                payload.len()
            );
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(&got, payload);
    }

    #[test]
    fn host_fallback_config_host_wins() {
        assert_eq!(
            resolve_upgrade_host("cdn.example.com", true, Some("sni.example.com"), "1.2.3.4"),
            "cdn.example.com"
        );
    }

    #[test]
    fn host_fallback_server_name_only_with_tls() {
        // 票 gbgr：host 未配 + TLS 时 serverName 参与回退（Go dialer.go:84-86）。
        assert_eq!(
            resolve_upgrade_host("", true, Some("sni.example.com"), "1.2.3.4"),
            "sni.example.com"
        );
        // 无 TLS 配置：Go `tConfig != nil` 不成立，serverName 不参与。
        assert_eq!(
            resolve_upgrade_host("", false, Some("sni.example.com"), "1.2.3.4"),
            "1.2.3.4"
        );
    }

    #[test]
    fn host_fallback_dest_address_is_last_resort() {
        // serverName 缺失/空串：Go `tConfig.ServerName` 空则落 dest（dialer.go:87-89）。
        assert_eq!(resolve_upgrade_host("", true, None, "1.2.3.4"), "1.2.3.4");
        assert_eq!(resolve_upgrade_host("", true, Some(""), "1.2.3.4"), "1.2.3.4");
        assert_eq!(resolve_upgrade_host("", false, None, "1.2.3.4"), "1.2.3.4");
    }
    /// close() 后 accept task 被 abort，端口释放、新连接被拒（票 x6sp 行为面：
    /// 修复前 AtomicBool 无唤醒，parked 在 accept() 的循环永久挂起）。
    #[tokio::test]
    async fn close_rejects_new_connections() {
        use std::time::Duration;
        let settings = StreamSettings {
            protocol: "httpupgrade".to_string(),
            ..StreamSettings::tcp()
        };
        let handler: ConnHandler = Arc::new(|_| {});
        let listener = listen_httpupgrade(
            "127.0.0.1:0".parse().unwrap(),
            &settings,
            &SocketOptions::default(),
            handler,
        )
        .await
        .expect("listen_httpupgrade");
        let addr = listener.local_addr().expect("local_addr");

        listener.close().expect("close");

        // abort → TcpListener drop 是异步的：轮询直至 connect 被拒。
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match tokio::net::TcpStream::connect(addr).await {
                Err(_) => break,
                Ok(_) => {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "close 后端口仍接受连接（僵尸 listener 未解除）"
                    );
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }
}
