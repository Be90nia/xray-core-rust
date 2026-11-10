//! SplitHTTP transport dialer + listener 注册。
//!
//! dialer: 已集成——通过 `MutexReader` 包装 `!Sync` reader 使 `SplitConn` 满足
//! ``Connection` 的 `Sync` bound。
//! listener: HTTP/2 server 监听待集成，当前返回 `Unsupported`。
//!
//! 协议名同时注册 `"splithttp"`（Go 标准）和 `"xhttp"`（用户配置简写）。

use std::{io, net::SocketAddr, sync::Arc};

use xray_common::net::destination::Destination;
use xray_transport::{
    connection::Connection,
    dialer::{StreamSettings, TransportDialFn, register_transport_dialer},
    ignore_already_exists,
    listener_registry::{TransportListenFn, register_transport_listener},
    sockopt::SocketOptions,
    system_dialer::dial_system,
};

use crate::{
    client::{DefaultDialerClient, DialTarget},
    config::Config,
    dialer,
    h3_client::{H3Conn, LazyH3Conn},
    transport::listen_splithttp,
};

/// 注册 SplitHTTP transport dialer。幂等。
pub fn register_dialer() -> io::Result<()> {
    let dial_fn: TransportDialFn = Arc::new(move |dest, sockopt, settings| {
        let dest = dest.clone();
        let sockopt = sockopt.clone();
        let settings = settings.clone();
        Box::pin(async move { dial_splithttp(&dest, &sockopt, &settings).await })
    });
    ignore_already_exists(register_transport_dialer("splithttp", dial_fn.clone()))?;
    ignore_already_exists(register_transport_dialer("xhttp", dial_fn))?;
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
    ignore_already_exists(register_transport_listener("splithttp", listen_fn.clone()))?;
    ignore_already_exists(register_transport_listener("xhttp", listen_fn))?;
    Ok(())
}

/// 注册 SplitHTTP transport 的 unix 监听（对应 Go splithttp/hub.go:526-531
/// `port==0` → `net.UnixAddr` 分支）。
///
/// 协议名同时注册 `"splithttp"` 和 `"xhttp"`，与 [`register_listener`] 一致。
/// 必须在使用 `listener_registry::listen_unix("splithttp", ...)` 之前调用。
/// 幂等：重复调用忽略 `AlreadyExists`。
#[cfg(unix)]
pub fn register_unix_listener() -> io::Result<()> {
    use xray_transport::listener_registry::{
        UnixTransportListenFn, register_transport_unix_listener,
    };
    let listen_fn: UnixTransportListenFn = Arc::new(move |path, settings, sockopt, handler| {
        Box::pin(async move {
            crate::transport::listen_unix_splithttp(path, settings, sockopt, handler).await
        })
    });
    ignore_already_exists(register_transport_unix_listener("splithttp", listen_fn.clone()))?;
    ignore_already_exists(register_transport_unix_listener("xhttp", listen_fn))?;
    Ok(())
}

/// 实际拨号：解析配置 → 构建 TLS client → 调用 [`dialer::dial`] → 包装为 `Box<dyn Connection>`。
async fn dial_splithttp(
    dest: &Destination,
    sockopt: &SocketOptions,
    settings: &StreamSettings,
) -> io::Result<Box<dyn Connection>> {
    let config = parse_splithttp_config(settings.transport_json.as_ref())?;
    let config = Arc::new(config);
    let default_sni = dest.address().to_string();
    // H10：Go dialer.go:311-321 requestURL.Host 恒为裸 host——config.Host →
    // tls/reality ServerName → dest.Address 三级回退，**从不追加 :port**
    // （端口仅在 Go browser_dialer 分支追加，Rust 无此分支）。此前恒拼
    // `:{dest.port}` 造成 Host/:authority 指纹差异。
    // ponytail: 之前「:authority 拼端口」是基于 CF 实测可接受形态，但与
    // Go wire 不同——对齐 Go 回裸 host。
    let sni_from_settings = settings
        .security_json
        .as_ref()
        .and_then(|v| v.get("serverName"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let host = if !config.host.is_empty() {
        config.host.clone()
    } else if !sni_from_settings.is_empty() {
        sni_from_settings.to_string()
    } else {
        default_sni.clone()
    };

    let has_tls = matches!(settings.security.as_str(), "tls" | "reality");
    let has_reality = settings.security == "reality";
    let scheme = if has_tls { "https" } else { "http" };

    // tlsSettings.fingerprint：h1/h2 路径出站走自定义 hyper connector
    // （DefaultDialerClient::new），TCP 后用 btls u_client 完成真实浏览器指纹
    // 握手（对齐 Go splithttp dialContext 的 tls.UClient）。h3（quinn）只吃
    // rustls ClientConfig，指纹仍降级（h3 分支内 warn）。REALITY 的指纹由
    // REALITY 握手自管（u_client + session_id 重写），不在此注入。
    let fp_name = settings
        .security_json
        .as_ref()
        .and_then(|v| v.as_object())
        .and_then(|m| m.get("fingerprint"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let fingerprint = if has_tls && !has_reality && !fp_name.is_empty() {
        Some(xray_tls::fingerprint::get_fingerprint(fp_name).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("invalid fingerprint: {e}"))
        })?)
    } else {
        None
    };

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
            xray_common::ensure_default_crypto_provider();
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth()
        },
    };

    // Determine HTTP version from ALPN (对应 Go `decideHTTPVersion`)。
    // ALPN 来自 rustls_config.alpn_protocols（`build_client_config` 从 tlsSettings 解析）。
    let next_protocol: Vec<String> = rustls_config
        .alpn_protocols
        .iter()
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .collect();
    let http_version = dialer::decide_http_version(has_tls, has_reality, &next_protocol);

    // finalmask（bd dppv）：Go splithttp/dialer.go:127-134——h1/h2 路径在
    // dialContext 内 TCP 后、TLS 前 WrapConnClient（首字节 = mask 头）；h3/QUIC
    // 无 Tcpmask（Go hub.go:546-549 同款排除）。空 manager = 恒等。
    // 按配置内容复用（bd nzli6）：xmc 派生 67ms 只在首次构建付一次。
    let tcpmask = xray_transport::finalmask::shared_tcpmask_manager_from_json(
        settings.finalmask_json.as_ref(),
    )?;
    // 下载侧通道（Go `dialer.go:355-404`）：配了 `downloadSettings` 就**另建**一个下载侧
    // HTTP 客户端（独立 dest/tls/host/path/ALPN）——上行仍走主客户端。
    //
    // Go 侧该分支在 `dialer.go:355`（`if transportConfiguration.DownloadSettings != nil`），
    // 构造 `memory2`（完整 StreamConfig）→ dest2/tlsConfig2/config2 → `httpClient2`。
    let download_side = match config.download_settings.as_ref() {
        None => None,
        Some(ds) => Some(build_download_side(ds, sockopt).await?),
    };

    // 池 key 的配置内容片段（Go 用 MemoryStreamConfig 指针身份；Rust 用内容）。
    let security_json_key =
        settings.security_json.as_ref().map(|v| v.to_string()).unwrap_or_default();
    let transport_json_key =
        settings.transport_json.as_ref().map(|v| v.to_string()).unwrap_or_default();
    let sockopt_json_key =
        settings.sockopt_json.as_ref().map(|v| v.to_string()).unwrap_or_default();
    let finalmask_json_key =
        settings.finalmask_json.as_ref().map(|v| v.to_string()).unwrap_or_default();

    let packet_conn = if http_version == "3" {
        if !fp_name.is_empty() {
            crate::LOG.warn(format!(
                "tlsSettings.fingerprint={fp_name} not supported on quinn (HTTP/3) stack; using default rustls ClientHello"
            ));
        }
        // HTTP/3 over QUIC path（对应 Go `createHTTPClient` 中 `httpVersion=="3"` 分支）。
        // quinn 需要 `SocketAddr`（不做 DNS），域名走 `tokio::net::lookup_host` 解析。
        let socket_addr = resolve_dest_socket_addr(dest).await.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("H3 dial: DNS resolve failed for {}", dest.address()),
            )
        })?;
        // SNI: config.host 优先，缺失用 dest 地址（对齐 Go `requestURL.Host` fallback）。
        // owned String：xmux 池单元的工厂是 'static 闭包（借用不能进 'static）。
        let server_name: String =
            if !config.host.is_empty() { config.host.clone() } else { default_sni.clone() };
        // finalmask.quicParams（对应 Go streamSettings.QuicParams；CC + 窗口字段。
        // 缺省时 connect_with_quic_params 仍默认 BBR——对齐 dialer.go:161-164 PR #5711）。
        let quic_params = xray_transport::memory_settings::parse_quic_params_config(
            settings.finalmask_json.as_ref().and_then(|f| f.get("quicParams")),
        )?;
        let h3_conn = {
            // xmux 接线（bd s42cg）：Go 的 h3 也经 `getHTTPClient` 的 xmux manager
            // 复用（`dialer.go:63-79`）——Rust 侧此前每拨新建一条 QUIC 连接。
            // 池单元是 [`LazyH3Conn`]（握手推迟到首次使用，对齐 Go 的 lazy transport）。
            let xmux_config = config.xmux.clone().unwrap_or_default();
            let key = crate::mux::xmux_manager_key(
                dest,
                &[
                    &settings.security,
                    &security_json_key,
                    &transport_json_key,
                    &sockopt_json_key,
                    &finalmask_json_key,
                ],
            );
            let pool_config = config.clone();
            let pool_sockopt = sockopt.clone();
            let manager = crate::mux::H3_MANAGERS.get_or(&key, || {
                Arc::new(crate::mux::XmuxManager::new(xmux_config, move || {
                    LazyH3Conn::new(
                        pool_config.clone(),
                        socket_addr,
                        server_name.clone(),
                        rustls_config.clone(),
                        quic_params.clone(),
                        pool_sockopt.clone(),
                    )
                }))
            });
            manager.get_xmux_client()
        };
        dialer::dial_h3(h3_conn, download_side.as_ref(), config, scheme, &host, has_reality)
            .await
            .map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("splithttp H3 dial failed: {e}"),
            )
        })?
    } else {
        // REALITY xhttp: TCP → REALITY TLS handshake (u_client + session_id/auth_key
        // 重写 + cert HMAC) → h2 直握手 stream-one。hyper-rustls 不知道 REALITY,
        // 必须自己做完 TLS 握手再传 TLS 流给 `dial_reality_stream_one`。
        // 对应 Go `splithttp/dialer.go::Dial` 在 `reality.UClient(conn, ...)` 闭包里
        // 包 TCP 触发的同一行为，Rust 端拆分到 splithttp 路径专用。
        if has_reality {
            let tcp_conn = dial_system(dest, sockopt).await.map_err(|e| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("splithttp reality dial_system: {e}"),
                )
            })?;
            let remote_addr = tcp_conn.remote_addr().ok().flatten();
            let local_addr = tcp_conn.local_addr().ok().flatten();
            // finalmask（bd dppv）：TCP 后、REALITY TLS 前（Go dialContext 层序）。
            let tcp_conn =
                xray_transport::finalmask::wrap_conn_client_into_connection(&tcpmask, tcp_conn)?;
            let tls_stream =
                xray_reality::register::handshake_over(tcp_conn, settings).await.map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("splithttp reality handshake: {e}"),
                    )
                })?;
            let remote =
                remote_addr.unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
            let local = local_addr.unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
            // base_uri 必须拼 config.path — 否则 splithttp request URL 是 host/ 而不是 host/path,
            // 服务端 REALITY handler 找不到 path 返回 404（fix-reality-xhttp-11 子代理 25min
            // 调研结论）。 用 normalized_path() 自动补前导 / + 加末尾 /，与 dial() 函数
            // (line 314-318) 对齐。
            let base_uri = format!("{scheme}://{host}{path}", path = config.normalized_path());
            let session_id = String::new();
            dialer::dial_reality_stream_one(tls_stream, remote, local, base_uri, session_id, config)
                .await
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("splithttp reality stream-one: {e}"),
                    )
                })?
        } else {
            // HTTP/1.1 / HTTP/2 path（hyper + hyper-rustls）。
            // Bug A: TCP 必须恒拨 `dest`，URL authority（config.host）仅作 Host 头；
            // 否则域名前置（home.begonia92.top→CF→sg-argo.yzswgroup.top）会连接
            // 到错误边缘（实测 CF argo 直连 h2 GET 不回包→挂死）。
            // Bug B: 第 5 个参数是 `has_reality`，不是 `has_tls`——否则无显式 mode 的
            // TLS 节点（vmess+xhttp）被错判 stream-one → 服务器 400 拒绝。
            let dial_target = DialTarget {
                host: dest.address().to_string(),
                port: dest.port().value(),
                sni: settings
                    .security_json
                    .as_ref()
                    .and_then(|j| j.get("serverName").and_then(|v| v.as_str()))
                    .unwrap_or("")
                    .to_string(),
                sockopt: sockopt.clone(),
            };
            // bd vkirx①（lf51l 已清）：此前的握手前 RTT 探针（`resolve_rtt` 一次性
            // TCP）就是抓包看到的「stream-one 每会话多 1 条零字节 TCP」（Rust 2 条 vs
            // Go 1 条）的唯一来源；阶梯撤掉后它零消费者，已整体删除（Go 本无此机制）。
            // xmux 接线（bd s42cg）：Go `getHTTPClient`（dialer.go:47-79）经
            // `globalDialerMap` + `XmuxManager.GetXmuxClient` **复用** HTTP 客户端；
            // Rust 侧此前每拨现建（dialer.rs 对 mux:: 零引用）⇒ 每条代理连接一条新
            // TCP。接线后：客户端按 xmux 五维判定从池里取（新建 ≤ maxConnections，
            // 之后按 maxConcurrency 随机选），复用即**复用底层 TCP 连接**。
            let client = {
                let xmux_config = config.xmux.clone().unwrap_or_default();
                let key = crate::mux::xmux_manager_key(
                    dest,
                    &[
                        &settings.security,
                        &security_json_key,
                        &transport_json_key,
                        &sockopt_json_key,
                        &finalmask_json_key,
                    ],
                );
                let pool_config = config.clone();
                let pool_tcpmask = Arc::clone(&tcpmask);
                let pool_security_json = settings.security_json.clone();
                let manager = crate::mux::H2_MANAGERS.get_or(&key, || {
                    Arc::new(crate::mux::XmuxManager::new(xmux_config, move || {
                        Arc::new(DefaultDialerClient::new(
                            pool_config.clone(),
                            rustls_config.clone(),
                            dial_target.clone(),
                            fingerprint,
                            pool_security_json.clone(),
                            Some(Arc::clone(&pool_tcpmask)),
                        ))
                    }))
                });
                manager.get_xmux_client()
            };
            dialer::dial(client, download_side.as_ref(), config, scheme, &host, has_reality)
                .await
                .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("splithttp dial failed: {e}"),
                )
            })?
        }
    };

    // finalmask 已在各拨号分支内（TCP 后、TLS 前）套上（bd dppv）；h3/QUIC 无
    // Tcpmask（Go hub.go:546-549 同款排除）。
    Ok(Box::new(packet_conn.into_sync_reader()))
}
/// 构建下载侧通道（Go `dialer.go:355-404` 的 `httpClient2` / `requestURL2`）。
///
/// Go 用 `downloadSettings` 的**完整 StreamConfig** 另建下载侧 HTTP 客户端：
/// - `dest2` = 下载侧 address/port（自己的拨号目标）
/// - `tlsConfig2` / `realityConfig2` = 下载侧自己的 security
/// - `httpVersion2` = 下载侧自己的 ALPN 推出的 HTTP 版本（可与主通道不同）
/// - `config2` = 下载侧 `splithttpSettings`（自己的 host/path/query）
///
/// Rust 侧承载见 [`crate::config::DownloadSettings`]（协议段 + 原始 StreamConfig JSON
/// + 拨号目标），本函数把它转成「下载侧客户端 + 下载侧 base_uri」。
async fn build_download_side(
    ds: &crate::config::DownloadSettings,
    sockopt: &SocketOptions,
) -> io::Result<dialer::DownloadSide> {
    let dl_config = Arc::new((*ds.config).clone());
    let stream = xray_transport::dialer::StreamSettings::from_json(Some(&ds.stream_json));
    let has_tls = matches!(stream.security.as_str(), "tls" | "reality");
    let has_reality = stream.security == "reality";
    let scheme = if has_tls { "https" } else { "http" };
    // host 三级回落（Go dialer.go:377-390）：下载侧 splithttpSettings.host →
    // TLS serverName → 下载侧目标地址。
    let sni = stream
        .security_json
        .as_ref()
        .and_then(|j| j.get("serverName"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let dl_host = if !dl_config.host.is_empty() {
        dl_config.host.clone()
    } else if !sni.is_empty() {
        sni.clone()
    } else {
        ds.destination.address().to_string()
    };
    let base_uri = dialer::build_request_url(
        scheme,
        &dl_host,
        &dl_config.normalized_path(),
        &dl_config.normalized_query(),
    );

    // 下载侧 TLS（自己的 tlsSettings/realitySettings）+ 自己的 ALPN → HTTP 版本。
    let tls_config = xray_tls::client_config::build_client_config(
        &stream.security,
        stream.security_json.as_ref(),
        &dl_host,
    )?;
    let rustls_config = match tls_config {
        Some(cfg) => (*cfg).clone(),
        None => {
            xray_common::ensure_default_crypto_provider();
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth()
        },
    };
    let next_protocol: Vec<String> = rustls_config
        .alpn_protocols
        .iter()
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .collect();
    let http_version = dialer::decide_http_version(has_tls, has_reality, &next_protocol);

    let client = if http_version == "3" {
        // h3 下载侧：独立 QUIC 连接（Go `dest2.Network = UDP` + 独立 tlsConfig2）。
        let socket_addr = resolve_dest_socket_addr(&ds.destination).await.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "splithttp downloadSettings H3 dial: DNS resolve failed for {}",
                    ds.destination.address()
                ),
            )
        })?;
        let quic_params = xray_transport::memory_settings::parse_quic_params_config(
            stream.finalmask_json.as_ref().and_then(|f| f.get("quicParams")),
        )?;
        let h3 = H3Conn::connect_with_quic_params(
            dl_config.clone(),
            socket_addr,
            &dl_host,
            rustls_config,
            quic_params.as_ref(),
            sockopt,
        )
        .await
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("splithttp downloadSettings H3 connect failed: {e}"),
            )
        })?;
        dialer::DownloadClient::H3(h3)
    } else {
        let fp_name = stream
            .security_json
            .as_ref()
            .and_then(|v| v.as_object())
            .and_then(|m| m.get("fingerprint"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let fingerprint = if has_tls && !has_reality && !fp_name.is_empty() {
            Some(xray_tls::fingerprint::get_fingerprint(fp_name).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid downloadSettings fingerprint: {e}"),
                )
            })?)
        } else {
            None
        };
        // 按配置内容复用（bd nzli6）：下载侧配置同样可能含 xmc（67ms/次）。
        let dl_tcpmask = xray_transport::finalmask::shared_tcpmask_manager_from_json(
            stream.finalmask_json.as_ref(),
        )?;
        let dial_target = DialTarget {
            host: ds.destination.address().to_string(),
            port: ds.destination.port().value(),
            sni: sni.clone(),
            sockopt: sockopt.clone(),
        };
        dialer::DownloadClient::H2(Arc::new(DefaultDialerClient::new(
            dl_config.clone(),
            rustls_config,
            dial_target,
            fingerprint,
            stream.security_json.clone(),
            Some(Arc::clone(&dl_tcpmask)),
        )))
    };

    crate::hot_log!(
        DEBUG,
        "downloadSettings wired: base_uri={base_uri} dest={} http_version={http_version}",
        ds.destination
    );
    Ok(dialer::DownloadSide { client, base_uri })
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
        },
    }
}

/// 解析 `downloadSettings` 的拨号目标（address + port）。
///
/// Go `infra/conf/transport_internet.go:50-52`：`StreamConfig{Address *Address; Port uint16}`；
/// `Address` 的 JSON 是**字符串**（`common.go:53-67`：`env:` 前缀读环境变量，其余按
/// `net.ParseAddress` 解析）。
///
/// 缺 address 或 port 时 Go 在 `dialer.go:369 dest2 := *memory2.Destination` 处
/// **空指针 panic**——Rust 侧改为配置期硬错（fail-visible，不 panic）。
fn parse_download_destination(
    ds: &serde_json::Map<String, serde_json::Value>,
) -> io::Result<Destination> {
    let raw = ds.get("address").and_then(|v| v.as_str()).unwrap_or("").trim();
    let address = match raw.strip_prefix("env:") {
        Some(key) => std::env::var(key).unwrap_or_default(),
        None => raw.to_string(),
    };
    let port = ds.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
    if address.is_empty() || port == 0 || port > u16::MAX as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "downloadSettings must carry \"address\" and \"port\" (Go: nil Destination panics)",
        ));
    }
    let addr: xray_common::net::address::Address = address.parse().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("downloadSettings.address is invalid: {e}"),
        )
    })?;
    Ok(Destination::tcp(addr, xray_common::net::port::Port::new(port as u16)))
}

/// 从 `splithttpSettings` JSON 解析为强类型 [`Config`]。
///
/// `None` 或非 object 返回 [`Config::default`]。xHTTP 默认 xmux 预设
/// （Go v26.7.28 transport_method.go:452）即使在 `None` 时也套用，
/// 让 `parse_splithttp_config(None)` 与 `parse_splithttp_config(Some({"xmux":{}}))`
/// 行为一致：maxConnections = 3（anti-TSPU）。
pub(crate) fn parse_splithttp_config(json: Option<&serde_json::Value>) -> io::Result<Config> {
    let obj = match json {
        None => return Ok(default_xhttp_config()),
        Some(v) => match v.as_object() {
            Some(o) => o,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "splithttpSettings must be a JSON object",
                ));
            },
        },
    };

    // extra（Go transport_method.go:317-326）：整体覆盖配置——以 extra 对象为
    // 基底重解析，host/path/mode 恒取外层；`extra: null` 视同未设置（Go 侧
    // RawMessage("null") Unmarshal 后等于零值覆盖，属病态写法，Rust 取宽容
    // 语义）；嵌套 extra 不递归（Go Build 只解一层）。
    if let Some(extra) = obj.get("extra") {
        match extra {
            serde_json::Value::Null => {},
            serde_json::Value::Object(extra_obj) => {
                let mut merged = extra_obj.clone();
                for key in ["host", "path", "mode"] {
                    let outer =
                        obj.get(key).cloned().unwrap_or(serde_json::Value::String(String::new()));
                    merged.insert(key.to_string(), outer);
                }
                merged.remove("extra");
                return parse_splithttp_config(Some(&serde_json::Value::Object(merged)));
            },
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "splithttpSettings.extra must be a JSON object matching the \
                     splithttpSettings schema",
                ));
            },
        }
    }

    parse_splithttp_fields(obj)
}

/// splithttp 字段解析（无 extra 合并；入口见 [`parse_splithttp_config`]）。
fn parse_splithttp_fields(obj: &serde_json::Map<String, serde_json::Value>) -> io::Result<Config> {
    let get_str = |k: &str| obj.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    // 新键优先、旧键兜底（Go v26.7.28 transport_method.go:269-270 用
    // sessionIDPlacement/sessionIDKey；Rust 早期键 sessionPlacement/sessionKey
    // 继续兼容，取第一个非空字符串值）。
    let get_str2 = |k_new: &str, k_old: &str| {
        obj.get(k_new)
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .or_else(|| obj.get(k_old).and_then(|x| x.as_str()))
            .unwrap_or("")
            .to_string()
    };
    let get_bool = |k: &str| obj.get(k).and_then(|x| x.as_bool()).unwrap_or(false);
    let get_i64 = |k: &str| obj.get(k).and_then(|x| x.as_i64()).unwrap_or(0);
    let get_range = |k: &str| obj.get(k).and_then(parse_range);

    let headers = parse_headers(obj.get("header"))
        .or_else(|| parse_headers(obj.get("headers")))
        .unwrap_or_default();

    // xmux 子对象 → XmuxConfig
    // ponytail: 与 Go v26.7.28 infra/conf/transport_method.go:452 对齐——
    // 用户未提供 xmux（或提供空对象）时套默认预设：
    // maxConnections {3,3}, hMaxRequestTimes {600,900}, hMaxReusableSecs {1800,3000}。
    // 上一版 anti-TSPU 前默认 6；本次同步对齐 3（commit 18e28390）。
    let xmux = match obj.get("xmux").and_then(|x| x.as_object()) {
        Some(m) if !m.is_empty() => crate::config::XmuxConfig {
            max_concurrency: m.get("maxConcurrency").and_then(parse_range),
            max_connections: m.get("maxConnections").and_then(parse_range),
            c_max_reuse_times: m.get("cMaxReuseTimes").and_then(parse_range),
            h_max_request_times: m.get("hMaxRequestTimes").and_then(parse_range),
            h_max_reusable_secs: m.get("hMaxReusableSecs").and_then(parse_range),
            h_keep_alive_period: m.get("hKeepAlivePeriod").and_then(|x| x.as_i64()).unwrap_or(0),
        },
        _ => crate::config::XmuxConfig {
            max_connections: Some(crate::config::RangeConfig::new(3, 3)),
            h_max_request_times: Some(crate::config::RangeConfig::new(600, 900)),
            h_max_reusable_secs: Some(crate::config::RangeConfig::new(1800, 3000)),
            ..Default::default()
        },
    };

    // Go `infra/conf/transport_method.go:458-460`：`maxConnections` 与
    // `maxConcurrency` **互斥**（同时配 → 配置期硬错）——两者语义相冲（前者限池
    // 容量、后者限单池并发）。Go 缺省预设只给 maxConnections，故缺省不触发 ✓。
    if xmux.max_connections.as_ref().is_some_and(|r| r.to > 0)
        && xmux.max_concurrency.as_ref().is_some_and(|r| r.to > 0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "maxConnections cannot be specified together with maxConcurrency",
        ));
    }

    // downloadSettings 是嵌套 StreamConfig（Go `infra/conf/transport_method.go:295`
    // `DownloadSettings *StreamConfig`）：**完整** StreamConfig——address/port/method/
    // security/tls/reality + `splithttpSettings` 协议段。
    //
    // Go `dialer.go:355-404` 用它另建下载侧 HTTP 客户端（独立 dest/tls/host/path）；
    // Rust 侧同款接线（bd x0f0r 收口）：协议段解析为嵌套 [`Config`]，传输层段保留
    // 原始 JSON（拨号时经 `StreamSettings::from_json` 转既有承载类型），拨号目标解析为
    // [`Destination`]。
    //
    // Go `transport_method.go:508-511`：**stream-one 模式禁止配 downloadSettings**
    // （配置期硬错）——下行在 stream-one 下是主通道 POST 的响应，下载侧客户端用不上。
    let download_settings = match obj.get("downloadSettings") {
        None => None,
        Some(ds) => {
            if get_str("mode") == "stream-one" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Can not use \"downloadSettings\" in \"stream-one\" mode.",
                ));
            }
            let ds_obj = ds.as_object().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "downloadSettings must be a StreamConfig object carrying splithttpSettings",
                )
            })?;
            let inner = ds.get("splithttpSettings").ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "downloadSettings must be a StreamConfig object carrying splithttpSettings",
                )
            })?;
            let config = parse_splithttp_config(Some(inner))?;
            let destination = parse_download_destination(ds_obj)?;
            Some(Box::new(crate::config::DownloadSettings {
                config: Box::new(config),
                stream_json: ds.clone(),
                destination,
            }))
        },
    };

    let config = Config {
        host: get_str("host"),
        path: get_str("path"),
        mode: get_str("mode"),
        headers,
        x_padding_bytes: get_range("xPaddingBytes"),
        x_padding_obfs_mode: get_bool("xPaddingObfsMode"),
        x_padding_key: get_str("xPaddingKey"),
        x_padding_header: get_str("xPaddingHeader"),
        x_padding_placement: get_str("xPaddingPlacement"),
        x_padding_method: get_str("xPaddingMethod"),
        uplink_http_method: get_str("uplinkHTTPMethod"),
        // proto `bytes h2Params = 30`：Go conf 层是 `json.RawMessage`
        // （infra/conf/transport_method.go:296 `H2Params json.RawMessage` → :499
        // 原样赋给 proto bytes）——JSON 面是**裸 JSON**（如
        // `"h2Params": {"maxConcurrentStreams": 100}`），不是 base64。
        // 此处只做「值 → 字节」；是否为对象/是否可解析由 listener 启动期定夺
        // （Go 同层：conf 层不拒，hub.go:559-565 unmarshal 才失败 ⇒ 启动失败）。
        // `null` ⇒ 空（Go `json.Unmarshal("null", &cfg)` 是 no-op ⇒ 等同未配置）。
        h2_params: match obj.get("h2Params") {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(v) => serde_json::to_vec(v).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("h2Params encode failed: {e}"))
            })?,
        },
        session_placement: get_str2("sessionIDPlacement", "sessionPlacement"),
        session_key: get_str2("sessionIDKey", "sessionKey"),
        seq_placement: get_str("seqPlacement"),
        seq_key: get_str("seqKey"),
        uplink_data_placement: get_str("uplinkDataPlacement"),
        uplink_data_key: get_str("uplinkDataKey"),
        uplink_chunk_size: get_range("uplinkChunkSize"),
        session_id_table: {
            let raw = get_str("sessionIDTable");
            // 命中预定义名（如 "HEX"）时替换为字面值，未命中按字面处理。
            // 对应 Go transport_method.go:409-411 conf 层替换。
            let resolved = match crate::config::lookup_predefined_session_id_table(&raw) {
                Some(s) => s.to_string(),
                None => raw,
            };
            // 281r：roomSize = len(table)^length 必须 < 2^30，否则 token 空间过小致
            // entropy 不足被探测区分。
            //
            // 已知偏离（bd 1a2yy）：Go `transport_method.go:421-424` 的 roomSize 是
            // Σ_{k=from..to} table^k（`roomSize` 定义见 :521-529）且拒「太小」
            // （room < 2<<30），方向与聚合都与此处相反（本节拒「太大」）——现状被
            // bd 281r 测试钉住，按票面契约保持不动；修正需另票并改该测试的期望。
            if let Some(len_range) = obj.get("sessionIDLength").and_then(parse_range) {
                let table_len = resolved.len() as u64;
                if table_len > 1 && len_range.to > 0 {
                    let mut room = 1u64;
                    for _ in 0..len_range.to {
                        room = room.saturating_mul(table_len);
                        if room >= (1u64 << 30) {
                            break;
                        }
                    }
                    if room >= (1u64 << 30) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "splithttpSettings sessionIDTable length {} ^ sessionIDLength.to {} \
                                 must be < 2^30 (roomSize); reduce length or expand table",
                                table_len, len_range.to
                            ),
                        ));
                    }
                }
            }
            resolved
        },
        session_id_length: obj.get("sessionIDLength").and_then(parse_range),
        no_grpc_header: get_bool("noGRPCHeader"),
        no_sse_header: get_bool("noSSEHeader"),
        // scMaxEachPostBytes（Go transport_method.go:289 Int32Range；票 037f 前只从
        // proto 灌、JSON 恒回落默认 1MB）。消费点：client dialer.rs POST 切片阈值 +
        // server hub/handler.rs:291 413 拒收。
        sc_max_each_post_bytes: get_range("scMaxEachPostBytes"),
        sc_min_posts_interval_ms: get_range("scMinPostsIntervalMs"),
        sc_max_buffered_posts: get_i64("scMaxBufferedPosts"),
        sc_stream_up_server_secs: get_range("scStreamUpServerSecs"),
        server_max_header_bytes: get_i64("serverMaxHeaderBytes") as i32,
        xmux: Some(xmux),
        download_settings,
    };
    // sessionIDTable / sessionIDLength 的 ASCII + from>0 校验在构造点统一执行，与
    // proto 入口共用（bd 1a2yy：原内联在此处，`from_proto` 旁路）；roomSize 见上方
    // 内联块（方向待另票修正）。
    crate::config::validate_session_id(&config.session_id_table, config.session_id_length)?;
    Ok(config)
}

/// xHTTP 默认配置（无 splithttpSettings JSON 时套用）。
/// 与 `parse_splithttp_config(Some({"xmux":{}}))` 等价：除 xmux 默认预设外全空。
fn default_xhttp_config() -> Config {
    Config {
        xmux: Some(crate::config::XmuxConfig {
            max_connections: Some(crate::config::RangeConfig::new(3, 3)),
            h_max_request_times: Some(crate::config::RangeConfig::new(600, 900)),
            h_max_reusable_secs: Some(crate::config::RangeConfig::new(1800, 3000)),
            ..Default::default()
        }),
        ..Config::default()
    }
}

/// Parse a RangeConfig from JSON.
///
/// Go `infra/conf/common.go` `Int32Range.UnmarshalJSON` 只认两种形态：**字符串**
/// `"1-2"` / `"7"`，或**裸整数** `7`——`{from,to}` 对象在 Go 侧是硬错
/// （"Invalid integer range, expected either string of form \"1-2\" or plain integer."）。
/// 本函数按 Go 的两种形态解析；另保留对象形态作为 Rust 侧**宽松超集**（既有配置与
/// 内部用例依赖；写反不会静默跨端漂移——Go 会报错）。
fn parse_range(v: &serde_json::Value) -> Option<crate::config::RangeConfig> {
    if let Some(obj) = v.as_object() {
        let from = obj.get("from").and_then(|x| x.as_i64()).unwrap_or(0) as i32;
        let to = obj.get("to").and_then(|x| x.as_i64()).unwrap_or(0) as i32;
        Some(crate::config::RangeConfig::new(from, to))
    } else if let Some(n) = v.as_i64() {
        let n = n as i32;
        Some(crate::config::RangeConfig::new(n, n))
    } else if let Some(s) = v.as_str() {
        // Go `ParseRangeString`："7" → (7,7)；"1-2" → (1,2)。
        // shortcut: 负数为分隔符的形态（Go "-114-514" → (-114,514)）不解析——
        // splithttp 各范围字段无负数语义，需要时按 Go `splitFromSecondDash` 补齐。
        let s = s.trim();
        if let Ok(n) = s.parse::<i64>() {
            let n = n as i32;
            return Some(crate::config::RangeConfig::new(n, n));
        }
        let (left, right) = s.split_once('-')?;
        let from = left.trim().parse::<i64>().ok()? as i32;
        let to = right.trim().parse::<i64>().ok()? as i32;
        Some(crate::config::RangeConfig::new(from, to))
    } else {
        None
    }
}

/// 把 JSON 子对象解析为 `HashMap<String, String>`。非 object 或缺失返回 `None`。
fn parse_headers(
    v: Option<&serde_json::Value>,
) -> Option<std::collections::HashMap<String, String>> {
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

    /// 对齐 Go v26.7.28 infra/conf/transport_method.go:452：
    /// 用户未提供 `xmux` 子对象时套默认预设（anti-TSPU: maxConnections=3）。
    #[test]
    fn parse_xmux_default_preset_when_missing() {
        let cfg = parse_splithttp_config(None).unwrap();
        let xm = cfg.xmux.as_ref().expect("xmux preset applied");
        assert_eq!(xm.max_connections.unwrap().from, 3);
        assert_eq!(xm.max_connections.unwrap().to, 3);
        assert_eq!(xm.h_max_request_times.unwrap().from, 600);
        assert_eq!(xm.h_max_request_times.unwrap().to, 900);
        assert_eq!(xm.h_max_reusable_secs.unwrap().from, 1800);
        assert_eq!(xm.h_max_reusable_secs.unwrap().to, 3000);
        // 其余字段保持零默认
        assert!(xm.max_concurrency.is_none());
        assert!(xm.c_max_reuse_times.is_none());
    }

    /// 对齐 Go v26.7.28：用户提供空 `xmux: {}` 也套默认预设。
    #[test]
    fn parse_xmux_empty_object_applies_preset() {
        let v: serde_json::Value = serde_json::from_str(r#"{"xmux":{}}"#).unwrap();
        let cfg = parse_splithttp_config(Some(&v)).unwrap();
        let xm = cfg.xmux.as_ref().expect("preset");
        assert_eq!(xm.max_connections.unwrap().to, 3);
    }

    /// 用户显式提供 xmux 子字段时不被默认预设覆盖（透传）。
    #[test]
    fn parse_xmux_explicit_value_passes_through() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"xmux":{"maxConnections":{"from":7,"to":9}}}"#).unwrap();
        let cfg = parse_splithttp_config(Some(&v)).unwrap();
        let xm = cfg.xmux.as_ref().expect("xmux present");
        assert_eq!(xm.max_connections.unwrap().from, 7);
        assert_eq!(xm.max_connections.unwrap().to, 9);
        // 用户没填的字段保持 None（不被预设填 3）
        assert!(xm.h_max_request_times.is_none());
    }

    /// Go `infra/conf/transport_method.go:458-460`：`maxConnections` 与 `maxConcurrency`
    /// 同时配 → 配置期硬错（两者语义相冲：前者限池容量、后者限单池并发）。
    #[test]
    fn parse_xmux_rejects_concurrency_with_connections() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"xmux":{"maxConcurrency":{"from":1,"to":4},"maxConnections":{"from":2,"to":8}}}"#,
        )
        .unwrap();
        let err = parse_splithttp_config(Some(&v)).expect_err("must reject");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("cannot be specified together"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn parse_splithttp_config_all_fields() {
        // 对齐 Go SplitHTTPConfig 30 字段全量对拍
        let v: serde_json::Value = serde_json::from_str(
            r#"{"host":"h.com","path":"/p","mode":"stream-up",
               "xPaddingBytes":{"from":100,"to":200},
               "xPaddingObfsMode":true,"xPaddingKey":"k","xPaddingHeader":"X",
               "xPaddingPlacement":"header","xPaddingMethod":"garble",
               "uplinkHTTPMethod":"PUT","sessionPlacement":"query","sessionKey":"sid",
               "seqPlacement":"query","seqKey":"seq","uplinkDataPlacement":"query",
               "uplinkDataKey":"d","uplinkChunkSize":{"from":1000,"to":2000},
               "scStreamUpServerSecs":{"from":1,"to":2},"serverMaxHeaderBytes":8192,
               "h2Params":{"maxConcurrentStreams":128},
               "xmux":{"maxConnections":{"from":2,"to":8},
                       "cMaxReuseTimes":{"from":3,"to":3},"hMaxRequestTimes":{"from":5,"to":6},
                       "hMaxReusableSecs":{"from":7,"to":8},"hKeepAlivePeriod":30},
               "downloadSettings":{"address":"dl.example.com","port":8443,
                   "splithttpSettings":{"host":"dl.example.com","path":"/dl"}}}"#,
        )
        .unwrap();
        let cfg = parse_splithttp_config(Some(&v)).unwrap();
        assert_eq!(cfg.x_padding_bytes.as_ref().unwrap().from, 100);
        assert_eq!(cfg.x_padding_bytes.as_ref().unwrap().to, 200);
        assert!(cfg.x_padding_obfs_mode);
        assert_eq!(cfg.x_padding_key, "k");
        assert_eq!(cfg.x_padding_header, "X");
        assert_eq!(cfg.x_padding_placement, "header");
        assert_eq!(cfg.x_padding_method, "garble");
        assert_eq!(cfg.uplink_http_method, "PUT");
        assert_eq!(cfg.session_placement, "query");
        assert_eq!(cfg.session_key, "sid");
        assert_eq!(cfg.seq_placement, "query");
        assert_eq!(cfg.seq_key, "seq");
        assert_eq!(cfg.uplink_data_placement, "query");
        assert_eq!(cfg.uplink_data_key, "d");
        assert_eq!(cfg.uplink_chunk_size.as_ref().unwrap().from, 1000);
        assert_eq!(cfg.sc_stream_up_server_secs.as_ref().unwrap().to, 2);
        assert_eq!(cfg.server_max_header_bytes, 8192);
        let h2: serde_json::Value =
            serde_json::from_slice(&cfg.h2_params).expect("h2Params 是裸 JSON 字节");
        assert_eq!(h2["maxConcurrentStreams"], 128);
        let xm = cfg.xmux.as_ref().unwrap();
        // maxConcurrency 与 maxConnections 互斥（Go transport_method.go:458-460 硬错），
        // 全字段用例只配后者；互斥本身由 `parse_xmux_rejects_concurrency_with_connections` 覆盖。
        assert_eq!(xm.max_connections.as_ref().unwrap().to, 8);
        assert_eq!(xm.h_keep_alive_period, 30);
        let dl = cfg.download_settings.as_ref().unwrap();
        assert_eq!(dl.config.host, "dl.example.com");
        assert_eq!(dl.config.path, "/dl");
        assert_eq!(dl.destination.port().value(), 8443);
        assert_eq!(dl.destination.address().to_string(), "dl.example.com");
    }

    /// bd zm2m2：`h2Params` JSON 面是**裸 JSON 对象**（Go conf 层 `json.RawMessage`，
    /// `infra/conf/transport_method.go:296`/`:499` 原样进 proto bytes）——不是 base64。
    #[test]
    fn parse_splithttp_h2_params_raw_json_object() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"h2Params":{"maxConcurrentStreams":100,"maxReadFrameSize":1048576}}"#,
        )
        .unwrap();
        let cfg = parse_splithttp_config(Some(&v)).expect("parse ok");
        let params = crate::h2_params::H2Params::parse(&cfg.h2_params)
            .expect("listener 层可解析")
            .expect("已配置");
        assert_eq!(params.max_concurrent_streams, Some(100));
        assert_eq!(params.max_frame_size, Some(1_048_576));
    }

    /// 缺省 / `null` ⇒ 空字节 ⇒ 消费端 `None`（连接级 builder 零 setter）。
    #[test]
    fn parse_splithttp_h2_params_absent_or_null_is_empty() {
        for json in [r#"{}"#, r#"{"h2Params":null}"#] {
            let v: serde_json::Value = serde_json::from_str(json).unwrap();
            let cfg = parse_splithttp_config(Some(&v)).expect("parse ok");
            assert!(cfg.h2_params.is_empty(), "{json}");
            assert!(crate::h2_params::H2Params::parse(&cfg.h2_params).expect("ok").is_none());
        }
    }

    /// conf 层不判形态（Go 同层：`json.RawMessage` 收任何值），非对象值在 listener 启动期
    /// 拒启——base64 字符串形态因此不会被误当配置接受。
    #[test]
    fn parse_splithttp_h2_params_non_object_rejected_at_listener() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"h2Params":"eyJtYXhDb25jdXJyZW50U3RyZWFtcyI6MTAwfQ=="}"#)
                .unwrap();
        let cfg = parse_splithttp_config(Some(&v)).expect("conf 层不拒");
        assert!(crate::h2_params::H2Params::parse(&cfg.h2_params).is_err());
    }

    /// 票 037f：scMaxEachPostBytes JSON 灌入（此前只走 proto，JSON 恒默认 1MB）。
    /// 消费点：client POST 切片阈值 / server 413 拒收。
    #[test]
    fn parse_splithttp_sc_max_each_post_bytes_wires_field() {
        // 对象形态
        let v: serde_json::Value =
            serde_json::from_str(r#"{"scMaxEachPostBytes":{"from":500000,"to":900000}}"#).unwrap();
        let cfg = parse_splithttp_config(Some(&v)).unwrap();
        let r = cfg.sc_max_each_post_bytes.expect("field must be set from JSON");
        assert_eq!((r.from, r.to), (500_000, 900_000));
        // 归一化透传（to != 0 不落默认）
        let n = cfg.normalized_sc_max_each_post_bytes();
        assert_eq!((n.from, n.to), (500_000, 900_000));

        // 整数形态
        let v: serde_json::Value =
            serde_json::from_str(r#"{"scMaxEachPostBytes":250000}"#).unwrap();
        let cfg = parse_splithttp_config(Some(&v)).unwrap();
        let r = cfg.sc_max_each_post_bytes.expect("integer form");
        assert_eq!((r.from, r.to), (250_000, 250_000));

        // 缺省 → None → normalized 默认 1MB（Go 同）
        let cfg = parse_splithttp_config(Some(&serde_json::json!({}))).unwrap();
        assert!(cfg.sc_max_each_post_bytes.is_none());
        let n = cfg.normalized_sc_max_each_post_bytes();
        assert_eq!((n.from, n.to), (1_000_000, 1_000_000));
    }

    /// 票 037f：extra 整体覆盖（Go transport_method.go:317-326）——extra 字段生效、
    /// host/path/mode 恒取外层、未覆盖字段被抹掉（Go c = &extra 语义）。
    #[test]
    fn parse_splithttp_extra_overrides_keeping_outer_host_path_mode() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"host":"outer.example.com","path":"/outer","mode":"stream-up",
                "noGRPCHeader":true,"scMaxBufferedPosts":30,
                "extra":{"noGRPCHeader":false,"scMaxBufferedPosts":99,
                         "scMaxEachPostBytes":{"from":100000,"to":200000},
                         "host":"ignored.example.com"}}"#,
        )
        .unwrap();
        let cfg = parse_splithttp_config(Some(&v)).unwrap();
        // host/path/mode 恒取外层
        assert_eq!(cfg.host, "outer.example.com");
        assert_eq!(cfg.path, "/outer");
        assert_eq!(cfg.mode, "stream-up");
        // extra 内字段覆盖外层
        assert!(!cfg.no_grpc_header, "extra.noGRPCHeader=false must override outer true");
        assert_eq!(cfg.sc_max_buffered_posts, 99);
        let r = cfg.sc_max_each_post_bytes.expect("extra scMaxEachPostBytes");
        assert_eq!((r.from, r.to), (100_000, 200_000));
    }

    /// extra 非对象（Go json.Unmarshal 失败）→ 拒；extra null 视同未设置。
    #[test]
    fn parse_splithttp_extra_type_errors_and_null_passthrough() {
        for bad in [r#""string""#, "42", "[]"] {
            let v: serde_json::Value =
                serde_json::from_str(&format!(r#"{{"extra":{bad}}}"#)).unwrap();
            let err = parse_splithttp_config(Some(&v)).expect_err("non-object extra must reject");
            assert!(err.to_string().contains("extra"), "got: {err}");
        }
        // null：外层字段原样生效
        let v: serde_json::Value =
            serde_json::from_str(r#"{"path":"/keep","noGRPCHeader":true,"extra":null}"#).unwrap();
        let cfg = parse_splithttp_config(Some(&v)).unwrap();
        assert_eq!(cfg.path, "/keep");
        assert!(cfg.no_grpc_header);
    }

    #[test]
    fn parse_splithttp_config_session_id_new_keys() {
        // Go v26.7.28 键名：sessionIDPlacement / sessionIDKey。
        let v: serde_json::Value =
            serde_json::from_str(r#"{"sessionIDPlacement":"header","sessionIDKey":"X-Sid"}"#)
                .unwrap();
        let cfg = parse_splithttp_config(Some(&v)).unwrap();
        assert_eq!(cfg.session_placement, "header");
        assert_eq!(cfg.session_key, "X-Sid");
    }

    #[test]
    fn parse_splithttp_config_session_id_legacy_keys_still_work() {
        // 旧键（Rust 早期实现）：sessionPlacement / sessionKey 兼容双读。
        let v: serde_json::Value =
            serde_json::from_str(r#"{"sessionPlacement":"query","sessionKey":"sid"}"#).unwrap();
        let cfg = parse_splithttp_config(Some(&v)).unwrap();
        assert_eq!(cfg.session_placement, "query");
        assert_eq!(cfg.session_key, "sid");
    }

    #[test]
    fn parse_splithttp_config_session_id_new_keys_win_over_legacy() {
        // 新旧键同时出现：新键优先。
        let v: serde_json::Value = serde_json::from_str(
            r#"{"sessionIDPlacement":"cookie","sessionPlacement":"query",
                "sessionIDKey":"new","sessionKey":"old"}"#,
        )
        .unwrap();
        let cfg = parse_splithttp_config(Some(&v)).unwrap();
        assert_eq!(cfg.session_placement, "cookie");
        assert_eq!(cfg.session_key, "new");
    }

    #[test]
    fn parse_splithttp_config_no_sse_header() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"noSSEHeader":true,"noGRPCHeader":true}"#).unwrap();
        let cfg = parse_splithttp_config(Some(&v)).unwrap();
        assert!(cfg.no_sse_header);
        assert!(cfg.no_grpc_header);
        // 缺省 false。
        let cfg = parse_splithttp_config(Some(&serde_json::json!({}))).unwrap();
        assert!(!cfg.no_sse_header);
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

    /// Go `Int32Range.UnmarshalJSON` 的字符串形态：`"1-2"` → (1,2)、`"7"` → (7,7)。
    /// 修前 Rust 只认对象/裸整数 ⇒ 用户按 Go 文档写的 xmux 范围被**静默忽略**。
    #[test]
    fn parse_range_from_go_string_forms() {
        let two: serde_json::Value = serde_json::from_str(r#""100-200""#).unwrap();
        let r = parse_range(&two).unwrap();
        assert_eq!((r.from, r.to), (100, 200));

        let one: serde_json::Value = serde_json::from_str(r#""600""#).unwrap();
        let r = parse_range(&one).unwrap();
        assert_eq!((r.from, r.to), (600, 600));
    }

    /// Go 字符串形态经 `parse_splithttp_config` 落到 xmux 五维（端到端解析路径）。
    #[test]
    fn parse_xmux_go_string_forms_reach_fields() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"xmux":{"maxConnections":"3","hMaxRequestTimes":"600-900"}}"#)
                .unwrap();
        let cfg = parse_splithttp_config(Some(&v)).unwrap();
        let xm = cfg.xmux.as_ref().expect("xmux present");
        assert_eq!(xm.max_connections.unwrap().to, 3);
        let h = xm.h_max_request_times.unwrap();
        assert_eq!((h.from, h.to), (600, 900));
    }

    #[test]
    fn parse_range_from_integer() {
        let v: serde_json::Value = serde_json::from_str(r#"500"#).unwrap();
        let r = parse_range(&v).unwrap();
        assert_eq!((r.from, r.to), (500, 500));
    }
    /// sessionIDTable 预定义名（"HEX"）解析后替换为字面值。
    #[test]
    fn parse_session_id_table_predefined_resolves_to_alphabet() {
        let v: serde_json::Value = serde_json::from_str(r#"{"sessionIDTable":"HEX"}"#).unwrap();
        let cfg = parse_splithttp_config(Some(&v)).expect("parse ok");
        assert_eq!(cfg.session_id_table, "0123456789ABCDEF");
    }

    /// sessionIDTable 自定义字符串按字面透传。
    #[test]
    fn parse_session_id_table_custom_passes_through() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"sessionIDTable":"abc123!@#"}"#).unwrap();
        let cfg = parse_splithttp_config(Some(&v)).expect("parse ok");
        assert_eq!(cfg.session_id_table, "abc123!@#");
    }

    /// sessionIDTable 缺失 → 空字符串（fallback UUID）。
    #[test]
    fn parse_session_id_table_missing_is_empty() {
        let cfg = parse_splithttp_config(None).expect("parse ok");
        assert_eq!(cfg.session_id_table, "");
        assert!(cfg.session_id_length.is_none());
    }

    /// sessionIDTable 含非 ASCII（>=0x80）拒绝配置。
    #[test]
    fn parse_session_id_table_non_ascii_rejected() {
        // 中文（0xE4 开 UTF-8）混在 table 里应被拒。
        let v: serde_json::Value =
            serde_json::from_str(r#"{"sessionIDTable":"abc\u00FF"}"#).unwrap();
        let r = parse_splithttp_config(Some(&v));
        assert!(r.is_err());
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("sessionIDTable"), "unexpected msg: {msg}");
    }

    /// 281r：len(table)^length >= 2^30 拒绝配置。
    /// 1 字符 table × 31 长度：1^31 = 1（合法）。
    /// 2 字符 table × 31 长度：2^31 = 2G ≥ 2^30（拒绝）。
    #[test]
    fn parse_session_id_table_room_size_too_small_rejected() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"sessionIDTable":"ab","sessionIDLength":{"from":31,"to":31}}"#,
        )
        .unwrap();
        let r = parse_splithttp_config(Some(&v));
        assert!(r.is_err(), "2^31 should be rejected");
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("2^30"), "unexpected msg: {msg}");
    }
    #[test]
    fn parse_session_id_length_valid_range() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"sessionIDLength":{"from":8,"to":16}}"#).unwrap();
        let cfg = parse_splithttp_config(Some(&v)).expect("parse ok");
        let r = cfg.session_id_length.expect("some");
        assert_eq!((r.from, r.to), (8, 16));
    }

    /// sessionIDLength from <= 0 拒绝（镜像 Go transport_method.go:417-419）。
    #[test]
    fn parse_session_id_length_from_zero_rejected() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"sessionIDLength":{"from":0,"to":8}}"#).unwrap();
        let r = parse_splithttp_config(Some(&v));
        assert!(r.is_err());
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("sessionIDLength.from"), "unexpected msg: {msg}");
    }

    /// sessionIDLength 整数简写解析：from==to。
    #[test]
    fn parse_session_id_length_from_integer() {
        let v: serde_json::Value = serde_json::from_str(r#"{"sessionIDLength":12}"#).unwrap();
        let cfg = parse_splithttp_config(Some(&v)).expect("parse ok");
        let r = cfg.session_id_length.expect("some");
        assert_eq!((r.from, r.to), (12, 12));
    }

    /// ③ transport 级 unix 监听 roundtrip（bd lfrg③）：注册 → listen_unix →
    /// UDS 建连 → 真实 HTTP 服务处理（GET 错误 path → 立即 404，host/path
    /// 校验链真实执行）→ close 后 socket 释放新连接被拒。对应 Go
    /// splithttp/hub.go:526-531 `port == net.Port(0)` 分支。unix-only。
    #[cfg(unix)]
    #[tokio::test]
    async fn listen_unix_splithttp_roundtrip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use xray_transport::listener_registry::ConnHandler;

        let _ = register_unix_listener();

        let path = std::env::temp_dir().join(format!(
            "xray-xh-unix-hub-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let path_str = path.to_str().unwrap().to_string();
        let _ = std::fs::remove_file(&path_str);

        let handler: ConnHandler = Arc::new(|_| {});
        let settings = StreamSettings {
            protocol: "splithttp".to_string(),
            transport_json: Some(serde_json::json!({"path": "/xh"})),
            ..StreamSettings::tcp()
        };
        let listener = xray_transport::listener_registry::listen_unix(
            &path_str,
            settings,
            xray_transport::sockopt::SocketOptions::default(),
            handler,
        )
        .await
        .expect("listen_unix(splithttp) 失败");
        // unix listener 无 SocketAddr：全零占位（对齐 tcp/ws/httpupgrade hub unix 契约）。
        assert_eq!(
            listener.local_addr().expect("local_addr 失败"),
            SocketAddr::from(([0, 0, 0, 0], 0))
        );

        // 客户端：UDS 建连 → 真实 HTTP GET（校验过的 path，无 session → 400/404
        // 级错误响应；服务端 HTTP 层真实处理而非裸 socket echo）。
        let mut uds = tokio::net::UnixStream::connect(&path_str).await.expect("UDS connect 失败");
        uds.write_all(b"GET /xh HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
            .await
            .expect("write 失败");
        let mut buf = vec![0u8; 2048];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), uds.read(&mut buf))
            .await
            .expect("HTTP 响应超时")
            .expect("read 失败");
        assert!(n > 0, "服务端无响应");
        let head = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(head.starts_with("HTTP/1.1 "), "expected HTTP/1.1 response, got: {head}");

        listener.close().expect("close 失败");
        // close 后 socket 释放，新连接被拒（close_rejects 同款轮询）。
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match tokio::net::UnixStream::connect(&path_str).await {
                Err(_) => break,
                Ok(_) => {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "close 后 unix socket 仍接受连接（abort 通知丢失/循环未退出）"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                },
            }
        }
        let _ = std::fs::remove_file(&path_str);
    }

    /// unix 监听 finalmask 拒绝路径（对齐 tcp/ws/httpupgrade hub unix 惯例）。
    /// 错误在 bind 前返回——但被测函数本身 cfg(unix)，测试随行。
    #[cfg(unix)]
    #[tokio::test]
    async fn listen_unix_splithttp_rejects_finalmask() {
        use xray_transport::listener_registry::ConnHandler;

        let settings = StreamSettings {
            protocol: "splithttp".to_string(),
            finalmask_json: Some(serde_json::json!({"enabled": true})),
            ..StreamSettings::tcp()
        };
        let handler: ConnHandler = Arc::new(|_| {});
        let result = crate::transport::listen_unix_splithttp(
            "/tmp/xray-xh-unix-finalmask-reject.sock".into(),
            settings,
            xray_transport::sockopt::SocketOptions::default(),
            handler,
        )
        .await;
        let Err(e) = result else { panic!("expected finalmask rejection, got a listener") };
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        assert!(e.to_string().contains("finalmask is not supported on unix listeners"));
    }

    /// Tcpmask round-trip（o54c，Go splithttp/dialer.go:127-134 + hub.go:547-549）：
    /// 明文 HTTP/1.1 packet-up，dial 与 hub 双端配置 fragment mask 后 e2e echo。
    #[tokio::test]
    async fn splithttp_dial_hub_tcpmask_roundtrip() {
        use std::net::Ipv4Addr;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use xray_common::net::{address::Address, network::Network, port::Port};

        let finalmask = serde_json::json!({
            "tcp": [{"type": "fragment", "settings": {
                "packets_from": 1, "packets_to": 2,
                "length": {"from": 8, "to": 16}, "interval": {"from": 0, "to": 0}
            }}]
        });
        let settings = StreamSettings {
            protocol: "splithttp".to_string(),
            transport_json: Some(serde_json::json!({"path":"/xh", "mode":"packet-up"})),
            finalmask_json: Some(finalmask),
            ..StreamSettings::tcp()
        };

        let handler: xray_transport::listener_registry::ConnHandler = Arc::new(|conn| {
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
                        },
                    }
                }
            });
        });
        let listener = listen_splithttp(
            "127.0.0.1:0".parse().unwrap(),
            &settings,
            &SocketOptions::default(),
            handler,
        )
        .await
        .expect("listen_splithttp");
        let addr = listener.local_addr().expect("local_addr");

        let dest = Destination::new(
            Address::IPv4(Ipv4Addr::LOCALHOST),
            Port::new(addr.port()),
            Network::TCP,
        );
        let mut conn = dial_splithttp(&dest, &SocketOptions::default(), &settings)
            .await
            .expect("dial_splithttp");

        conn.write_all(b"hello-xh-tcpmask").await.expect("write");
        let mut buf = vec![0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(10), conn.read(&mut buf))
            .await
            .expect("echo timeout")
            .expect("read ok");
        assert_eq!(&buf[..n], b"hello-xh-tcpmask");
    }
}
