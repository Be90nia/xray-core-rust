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
use xray_transport::system_dialer::dial_system;
use xray_transport::sockopt::SocketOptions;

use crate::client::{DefaultDialerClient, DialTarget};
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
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid fingerprint: {e}"),
            )
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
        if !fp_name.is_empty() {
            tracing::warn!(
                target: "xray_transport_splithttp",
                "tlsSettings.fingerprint={fp_name} not supported on quinn (HTTP/3) stack; using default rustls ClientHello"
            );
        }
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
        // finalmask.quicParams（对应 Go streamSettings.QuicParams；CC + 窗口字段。
        // 缺省时 connect_with_quic_params 仍默认 BBR——对齐 dialer.go:161-164 PR #5711）。
        let quic_params = xray_transport::memory_settings::parse_quic_params_config(
            settings.finalmask_json.as_ref().and_then(|f| f.get("quicParams")),
        )?;
        let h3_conn = H3Conn::connect_with_quic_params(
            config.clone(),
            socket_addr,
            server_name,
            rustls_config,
            quic_params.as_ref(),
            sockopt,
        )
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
            let tls_stream = xray_reality::register::handshake_over(tcp_conn, settings)
                .await
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("splithttp reality handshake: {e}"),
                    )
                })?;
            let remote = remote_addr.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
            let local = local_addr.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
            // base_uri 必须拼 config.path — 否则 splithttp request URL 是 host/ 而不是 host/path,
            // 服务端 REALITY handler 找不到 path 返回 404（fix-reality-xhttp-11 子代理 25min 调研结论）。
            // 用 normalized_path() 自动补前导 / + 加末尾 /，与 dial() 函数 (line 314-318) 对齐。
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
            };
            let client = Arc::new(DefaultDialerClient::new(
                config.clone(),
                rustls_config,
                dial_target,
                fingerprint,
                settings.security_json.clone(),
            ));
            dialer::dial(client, config, scheme, &host, has_reality)
                .await
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("splithttp dial failed: {e}"),
                    )
                })?
        }
    };

    // Tcpmask（Go splithttp/dialer.go:127-134：仅 h1/h2 路径的 dialContext 内
    // WrapConnClient；h3/QUIC 无 Tcpmask）。
    let sync_conn: Box<dyn Connection> = Box::new(packet_conn.into_sync_reader());
    if http_version == "3" {
        Ok(sync_conn)
    } else {
        xray_transport::finalmask::wrap_conn_client_from_settings(settings, sync_conn)
    }
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
            }
        },
    };

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
        Some(m) if !m.is_empty() => Some(crate::config::XmuxConfig {
            max_concurrency: m.get("maxConcurrency").and_then(parse_range),
            max_connections: m.get("maxConnections").and_then(parse_range),
            c_max_reuse_times: m.get("cMaxReuseTimes").and_then(parse_range),
            h_max_request_times: m.get("hMaxRequestTimes").and_then(parse_range),
            h_max_reusable_secs: m.get("hMaxReusableSecs").and_then(parse_range),
            h_keep_alive_period: m.get("hKeepAlivePeriod").and_then(|x| x.as_i64()).unwrap_or(0),
        }),
        _ => Some(crate::config::XmuxConfig {
            max_connections: Some(crate::config::RangeConfig::new(3, 3)),
            h_max_request_times: Some(crate::config::RangeConfig::new(600, 900)),
            h_max_reusable_secs: Some(crate::config::RangeConfig::new(1800, 3000)),
            ..Default::default()
        }),
    };

    // downloadSettings 是嵌套 StreamConfig：取其中 splithttpSettings 递归解析
    // ponytail: 只取 splithttpSettings 子对象；TLS/security 归 stream 层管，这里不碰。
    let download_settings = obj.get("downloadSettings").and_then(|ds| {
        ds.get("splithttpSettings")
            .and_then(|v| parse_splithttp_config(Some(v)).ok())
            .map(Box::new)
    });

    Ok(Config {
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
            // 镜像 Go transport_method.go:420-424 ASCII + roomSize 校验。
            // 281r：roomSize = len(table)^length 必须 < 2^30，否则 token 空间
            // 过小致 entropy 不足被探测区分。len(table) 为 0 单独守——`table^0==1`
            // 永远 < 2^30 但表示常量 ID 仍有问题，留给上层配置警告。
            if resolved.as_bytes().iter().any(|b| *b >= 0x80) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "splithttpSettings.sessionIDTable must contain only ASCII characters",
                ));
            }
            // 281r：len(table)^length < 2^30 校验。Go 用 math.Pow(2,30)
            // 直接乘；此处用 checked_mul 防溢出（O(log n) 累乘即够）。
            if let Some(len_range) = obj.get("sessionIDLength").and_then(parse_range) {
                let table_len = resolved.len() as u64;
                if table_len > 0 && len_range.to > 0 {
                    let mut room = 1u64;
                    let mut overflowed = false;
                    for _ in 0..len_range.to {
                        if let Some(v) = room.checked_mul(table_len) {
                            room = v;
                        } else {
                            overflowed = true;
                            break;
                        }
                        // 早停：已达阈值即拒绝累乘
                        if room >= (1u64 << 30) {
                            overflowed = true;
                            break;
                        }
                    }
                    if overflowed || room >= (1u64 << 30) {
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
        session_id_length: match obj.get("sessionIDLength").and_then(parse_range) {
            Some(r) if r.from > 0 => Some(r),
            // from <= 0 与 Go transport_method.go:417-419 校验一致：直接拒绝配置。
            Some(r) if r.from <= 0 => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "splithttpSettings.sessionIDLength.from must be greater than 0",
                ));
            }
            _ => None,
        },
        no_grpc_header: get_bool("noGRPCHeader"),
        no_sse_header: get_bool("noSSEHeader"),
        sc_min_posts_interval_ms: get_range("scMinPostsIntervalMs"),
        sc_max_buffered_posts: get_i64("scMaxBufferedPosts"),
        sc_stream_up_server_secs: get_range("scStreamUpServerSecs"),
        server_max_header_bytes: get_i64("serverMaxHeaderBytes") as i32,
        xmux,
        download_settings,
        ..Config::default()
    })
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
        let v: serde_json::Value = serde_json::from_str(
            r#"{"xmux":{"maxConnections":{"from":7,"to":9}}}"#,
        )
        .unwrap();
        let cfg = parse_splithttp_config(Some(&v)).unwrap();
        let xm = cfg.xmux.as_ref().expect("xmux present");
        assert_eq!(xm.max_connections.unwrap().from, 7);
        assert_eq!(xm.max_connections.unwrap().to, 9);
        // 用户没填的字段保持 None（不被预设填 3）
        assert!(xm.h_max_request_times.is_none());
    }

    #[test]
    fn parse_splithttp_config_all_fields() {
        // 对齐 Go SplitHTTPConfig 30 字段全量对拍
        let v: serde_json::Value = serde_json::from_str(
            r#"{"host":"h.com","path":"/p","mode":"stream-one",
               "xPaddingBytes":{"from":100,"to":200},
               "xPaddingObfsMode":true,"xPaddingKey":"k","xPaddingHeader":"X",
               "xPaddingPlacement":"header","xPaddingMethod":"garble",
               "uplinkHTTPMethod":"PUT","sessionPlacement":"query","sessionKey":"sid",
               "seqPlacement":"query","seqKey":"seq","uplinkDataPlacement":"query",
               "uplinkDataKey":"d","uplinkChunkSize":{"from":1000,"to":2000},
               "scStreamUpServerSecs":{"from":1,"to":2},"serverMaxHeaderBytes":8192,
               "xmux":{"maxConcurrency":{"from":1,"to":4},"maxConnections":{"from":2,"to":8},
                       "cMaxReuseTimes":{"from":3,"to":3},"hMaxRequestTimes":{"from":5,"to":6},
                       "hMaxReusableSecs":{"from":7,"to":8},"hKeepAlivePeriod":30},
               "downloadSettings":{"splithttpSettings":{"host":"dl.example.com","path":"/dl"}},
               "extra":{}}"#,
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
        let xm = cfg.xmux.as_ref().unwrap();
        assert_eq!(xm.max_concurrency.as_ref().unwrap().to, 4);
        assert_eq!(xm.h_keep_alive_period, 30);
        let dl = cfg.download_settings.as_ref().unwrap();
        assert_eq!(dl.host, "dl.example.com");
        assert_eq!(dl.path, "/dl");
    }

    #[test]
    fn parse_splithttp_config_session_id_new_keys() {
        // Go v26.7.28 键名：sessionIDPlacement / sessionIDKey。
        let v: serde_json::Value = serde_json::from_str(
            r#"{"sessionIDPlacement":"header","sessionIDKey":"X-Sid"}"#,
        )
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

    #[test]
    fn parse_range_from_integer() {
        let v: serde_json::Value = serde_json::from_str(r#"500"#).unwrap();
        let r = parse_range(&v).unwrap();
        assert_eq!((r.from, r.to), (500, 500));
    }
    /// sessionIDTable 预定义名（"HEX"）解析后替换为字面值。
    #[test]
    fn parse_session_id_table_predefined_resolves_to_alphabet() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"sessionIDTable":"HEX"}"#).unwrap();
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
        let v: serde_json::Value =
            serde_json::from_str(r#"{"sessionIDLength":12}"#).unwrap();
        let cfg = parse_splithttp_config(Some(&v)).expect("parse ok");
        let r = cfg.session_id_length.expect("some");
        assert_eq!((r.from, r.to), (12, 12));
    }


    /// Tcpmask round-trip（o54c，Go splithttp/dialer.go:127-134 + hub.go:547-549）：
    /// 明文 HTTP/1.1 packet-up，dial 与 hub 双端配置 fragment mask 后 e2e echo。
    #[tokio::test]
    async fn splithttp_dial_hub_tcpmask_roundtrip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use xray_common::net::address::Address;
        use xray_common::net::network::Network;
        use xray_common::net::port::Port;
        use std::net::Ipv4Addr;

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
                        }
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
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            conn.read(&mut buf),
        )
        .await
        .expect("echo timeout")
        .expect("read ok");
        assert_eq!(&buf[..n], b"hello-xh-tcpmask");
    }
}
