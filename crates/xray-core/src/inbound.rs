//! SOCKS5 inbound listener：接收连接 → SOCKS5 握手 → dispatcher 分发。
//!
//! 对应 Go `app/proxyman/inbound/always.go::handle_connection` + `proxy/socks/server.go`。
//! 这里实现最小端到端切片：TCP accept → socks5 handshake → SocksAddr → Destination →
//! `DispatchHandler::dispatch(dest, link)`。
//!
//! 不含：sniffing（协议嗅探）、UDP associate、多 inbound 注册管理（由 proxyman::InboundManager 负责）。

use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::net::TcpStream;
use xray_app_dispatcher::default::SimpleOhm;
use xray_app_dispatcher::OutboundHandlerManager;
use xray_buf::io::{new_reader, new_writer};
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_proxy_socks::protocol::{Host, SocksAddr};
use xray_proxy_socks::server::{socks5_server_handshake, SocksRequest};
use xray_proxy_socks::ServerConfig;
use xray_transport::link::Link;
use tokio::task::JoinHandle;
use xray_conf::{BuiltConfig, BuiltInbound};
// P1-B: vless/trojan inbound 集成
use std::collections::HashMap;
use xray_proto::xray::proxy::vless::Account as VlessProtoAccount;
use xray_proxy_trojan::{serve_trojan, MemoryAccount as TrojanMemoryAccount, MemoryUser as TrojanMemoryUser, fallback::{Fallback, FallbackPolicy}};
use xray_proxy_vless::{serve_vless, MemoryAccount as VlessMemoryAccount, MemoryUser as VlessMemoryUser, MemoryValidator as VlessMemoryValidator, Validator as VlessValidator};
use xray_proxy_vmess::{serve_vmess, MemoryAccount as VmessMemoryAccount, MemoryUser as VmessMemoryUser, TimedUserValidator as VmessTimedUserValidator, Validator as VmessValidator};
use xray_common::uuid::UUID;
// tdy: http + dokodemo inbound 集成
use xray_proxy_http::ServerConfig as HttpServerConfig;
use xray_proxy_http::server::http_server_handshake;
// zx7: mux inbound 检测
use xray_mux::client::{MUX_COOL_ADDRESS, MUX_COOL_PORT};
// 补全协议 inbound 注册
use xray_proxy_ss::{SsInbound, CipherType as SsCipherType};
use xray_proxy_ss::config::MemoryAccount as SsConfigMemoryAccount;
use xray_proxy_dns::{DnsInbound, DnsOutbound, Handler as DnsHandler, Config as DnsConfig};
use xray_proxy_loopback::LoopbackHandler;
#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
use xray_proxy_tun::{TunInboundHandler, StackOptions, Tun};
use xray_proxy_wireguard::DeviceConfig;
use xray_transport_hysteria::hub::StubListenerFactory;
use xray_features::inbound::InboundHandler;
use tokio::net::UdpSocket;
use xray_proxy_blackhole::{BlackholeInboundHandler, ResponseConfig as BlackholeResponseConfig};
use xray_proxy_freedom::FreedomInboundHandler;

/// SOCKS5 inbound 服务入口。
///
/// 绑定 `addr` 监听，每个连接 spawn 独立 task：
/// 1. SOCKS5 握手得目标 `SocksAddr`
/// 2. 转 `Destination`，构造 `Link`（用 TcpStream 的 read/write half）
/// 3. `ohm` 的 default handler `dispatch(dest, link)` 拨号并桥接
///
/// # 参数
/// - `listener`：已绑定的 TCP listener
/// - `ohm`：出站管理器（至少有 default handler）
/// - `config`：SOCKS5 server 配置（auth method 等）
///
/// # 错误
/// accept 循环自身错误返回；单个连接错误只 log 不中断循环。
pub async fn serve_socks5(
    listener: TcpListener,
    ohm: Arc<SimpleOhm>,
    config: Arc<ServerConfig>,
) -> std::io::Result<()> {
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;

    tracing::info!(
        addr = %listener.local_addr()?,
        "socks5 inbound listening"
    );

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "socks5 accept failed");
                continue;
            }
        };

        let handler = Arc::clone(&handler);
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &config, &handler).await {
                tracing::debug!(error = %e, "socks5 connection ended with error");
            }
        });

        let _ = peer; // 仅 log 级别可用，当前不记
    }
}

/// 处理单个 SOCKS5 连接：handshake → dispatch。
async fn handle_connection(
    mut stream: TcpStream,
    config: &ServerConfig,
    handler: &Arc<dyn xray_app_dispatcher::DispatchHandler>,
) -> std::io::Result<()> {
    // 1. SOCKS5 握手
    let socks_addr = socks5_server_handshake(&mut stream, config)
        .await
        .map_err(|e| std::io::Error::other(format!("socks5 handshake: {e}")))?;

    // 2. SocksAddr → Destination
    let dest = socks_addr_to_destination(&socks_addr)?;

    // 3. 拆 TcpStream → (read, write) → Link
    // ponytail: tokio::io::split 返回的 ReadHalf/WriteHalf 是 'static + Send，
    // new_reader/new_writer 接受 AsyncRead/AsyncWrite + Unpin + Send + 'static。
    let (read_half, write_half) = tokio::io::split(stream);
    let link = Link::new(new_reader(read_half), new_writer(write_half));

    // 4. dispatch（dispatch 内部拨号 + bridge，消耗 link）
    // zx7: mux.cool dest 转给 mux ServerWorker（当前 stub）
    if is_mux_destination(&dest) {
        tracing::info!("socks5: mux.cool destination detected, spawning mux inbound handler");
        tokio::spawn(handle_mux_inbound_link(link, Arc::clone(handler)));
        return Ok(());
    }
    let _ = handler.dispatch(&dest, link).await;

    Ok(())
}

/// 检测 dest 是否为 mux.cool 多路复用信令目的地（zx7）。
///
/// 当客户端配置了 mux，会把目标设为 `v1.mux.cool:9527`，
/// inbound 收到后应转给 mux [`ServerWorker`] 解帧。
pub fn is_mux_destination(dest: &Destination) -> bool {
    matches!(dest.address(), Address::Domain(d) if d == MUX_COOL_ADDRESS)
        && dest.port().value() == MUX_COOL_PORT
}

/// 处理 mux.cool 入站连接：创建 ServerWorker，循环读帧，为每个子 session dispatch。
///
/// 对应 Go `mux.Server.OnTransport(link.Reader, link.Writer)`。
async fn handle_mux_inbound_link(link: Link, handler: Arc<dyn xray_app_dispatcher::DispatchHandler>) {
    use xray_buf::reader::BufferedReader;
    use xray_buf::writer::BufferedWriter;
    use xray_mux::worker::{DispatchHandlerAdapter, ServerWorker};

    let adapter = Arc::new(DispatchHandlerAdapter::new(handler));
    let worker = ServerWorker::new(adapter);

    // 包装 link reader/writer 为 BufferedReader/BufferedWriter
    let mut reader = BufferedReader::new(link.reader);
    let link_writer: Arc<tokio::sync::Mutex<Option<Box<dyn xray_buf::io::Writer>>>> =
        Arc::new(tokio::sync::Mutex::new(Some(link.writer)));

    // 启动 keepalive + idle timeout
    let (keepalive_h, idle_h) = worker.spawn_keepalive_and_idle_timeout(link_writer.clone());

    // 主帧处理循环
    loop {
        match worker.process_frame(&mut reader, &link_writer).await {
            Ok(true) => continue,
            Ok(false) => break, // 干净 EOF
            Err(e) => {
                tracing::warn!(error = %e, "mux frame processing error");
                break;
            }
        }
    }

    worker.close();
    keepalive_h.abort();
    idle_h.abort();
}

/// `SocksRequest` → `Destination`（TCP）。
///
/// `Host::Ipv4` → `Address::IPv4`，`Ipv6` → `Address::IPv6`，`Domain` → `Address::Domain`。
/// UDP ASSOCIATE 请求返回 Unsupported 错误。
fn socks_addr_to_destination(req: &SocksRequest) -> std::io::Result<Destination> {
    let addr = match req {
        SocksRequest::TcpConnect(addr) => addr,
        SocksRequest::UdpAssociate(_, _) => {
            return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "UDP ASSOCIATE not supported"))
        }
    };
    let address = match &addr.host {
        Host::Ipv4(ip) => Address::IPv4(*ip),
        Host::Ipv6(ip) => Address::IPv6(*ip),
        Host::Domain(d) => Address::Domain(d.clone()),
    };
    Ok(Destination::new(address, Port::new(addr.port), Network::TCP))
}

/// HTTP proxy inbound 服务入口（tdy）。
///
/// 接受连接 → http_server_handshake → 拆 stream → dispatch。
/// 当前只 dispatch CONNECT 隧道；普通 HTTP 代理（GET/POST 等）暂不支持，留切片3。
pub async fn serve_http(
    listener: TcpListener,
    ohm: Arc<SimpleOhm>,
    config: Arc<HttpServerConfig>,
) -> std::io::Result<()> {
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;
    tracing::info!(addr = %listener.local_addr()?, "http proxy inbound listening");
    loop {
        let (mut stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "http accept failed");
                continue;
            }
        };
        let handler = Arc::clone(&handler);
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            // 1. handshake → (dest, method)
            let (dest, method) = match http_server_handshake(&mut stream, &config).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(error = %e, "http handshake failed");
                    return;
                }
            };
            // 2. 只 dispatch CONNECT（plain HTTP 留切片3）
            if method != "CONNECT" {
                tracing::debug!(method = %method, "plain HTTP proxy not yet supported, skipping");
                return;
            }
            // 3. 拆 stream → Link → dispatch
            let (read_half, write_half) = tokio::io::split(stream);
            let link = Link::new(new_reader(read_half), new_writer(write_half));
            // zx7: mux.cool dest 转给 mux ServerWorker（stub）
            if is_mux_destination(&dest) {
                tracing::info!("http: mux.cool destination detected, spawning mux inbound handler");
                tokio::spawn(handle_mux_inbound_link(link, handler));
                return;
            }
            let _ = handler.dispatch(&dest, link).await;
        });
    }
}

/// Dokodemo-door inbound 服务入口（tdy）。
///
/// 接受连接 → 直接用预定义 `dest` 拼装 Link → dispatch（dokodemo 无握手协议）。
pub async fn serve_dokodemo(
    listener: TcpListener,
    ohm: Arc<SimpleOhm>,
    dest: Destination,
) -> std::io::Result<()> {
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;
    tracing::info!(addr = %listener.local_addr()?, dest = ?dest, "dokodemo inbound listening");
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "dokodemo accept failed");
                continue;
            }
        };
        let handler = Arc::clone(&handler);
        let dest = dest.clone();
        tokio::spawn(async move {
            let (read_half, write_half) = tokio::io::split(stream);
            let link = Link::new(new_reader(read_half), new_writer(write_half));
            let _ = handler.dispatch(&dest, link).await;
        });
    }
}

/// SS 入站模式（legacy AEAD 或 SS-2022）。
#[derive(Clone)]
pub enum SsInboundMode {
    /// Legacy AEAD 单/多用户。
    Legacy(Arc<SsInbound>),
    /// SS-2022 单用户。
    Ss2022(Arc<xray_proxy_ss::ss2022::Ss2022Inbound>),
    /// SS-2022 多用户。
    Ss2022Multi(Arc<xray_proxy_ss::ss2022::MultiUserInbound>),
    /// SS-2022 中继。
    Ss2022Relay(Arc<xray_proxy_ss::ss2022::RelayInbound>),
}

/// Shadowsocks inbound 服务入口。
///
/// 接受连接 → handle_conn → parse dest → dispatch。
pub async fn serve_ss(
    listener: TcpListener,
    ohm: Arc<SimpleOhm>,
    inbound: SsInboundMode,
) -> std::io::Result<()> {
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;
    tracing::info!(addr = %listener.local_addr()?, "ss inbound listening");
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "ss accept failed");
                continue;
            }
        };
        let handler = Arc::clone(&handler);
        let mode = inbound.clone();
        tokio::spawn(async move {
            let handshake = match &mode {
                SsInboundMode::Legacy(ib) => {
                    ib.handle_conn(stream).await.map(|(header, ss_stream)| {
                        (header.address, header.port, ss_stream)
                    }).map_err(|e| std::io::Error::other(e.to_string()))
                }
                SsInboundMode::Ss2022(ib) => {
                    ib.handle_conn(stream).await
                        .map(|r| (r.address, r.port, r.stream))
                        .map_err(|e| std::io::Error::other(e.to_string()))
                }
                SsInboundMode::Ss2022Multi(ib) => {
                    ib.handle_conn(stream).await
                        .map(|r| (r.address, r.port, r.stream))
                        .map_err(|e| std::io::Error::other(e.to_string()))
                }
                SsInboundMode::Ss2022Relay(ib) => {
                    ib.handle_conn(stream).await
                        .map(|r| (r.address, r.port, r.stream))
                        .map_err(|e| std::io::Error::other(e.to_string()))
                }
            };
            match handshake {
                Ok((address, port, mut ss_stream)) => {
                    let dest = Destination::new(address, Port::new(port), Network::TCP);
                    let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
                    tokio::spawn(async move {
                        loop {
                            match ss_stream.read_chunk().await {
                                Ok(Some(chunk)) => {
                                    if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut server_io, &chunk).await {
                                        tracing::debug!("ss pump up write: {e}"); break;
                                    }
                                    if let Err(e) = tokio::io::AsyncWriteExt::flush(&mut server_io).await {
                                        tracing::debug!("ss pump up flush: {e}"); break;
                                    }
                                }
                                Ok(None) => break,
                                Err(e) => { tracing::debug!("ss pump up read: {e}"); break; }
                            }
                        }
                        let _ = tokio::io::AsyncWriteExt::shutdown(&mut server_io).await;
                    });
                    let (client_rd, client_wr) = tokio::io::split(client_io);
                    let link = Link::new(new_reader(client_rd), new_writer(client_wr));
                    let _ = handler.dispatch(&dest, link).await;
                }
                Err(e) => {
                    tracing::debug!(error = %e, "ss inbound handshake failed");
                }
            }
        });
    }
}

/// DNS inbound 服务入口。
///
/// 同时监听 UDP 和 TCP：
/// - UDP：recv_from → handle_packet → send_to 响应
/// - TCP：accept → handle_conn（2B 长度前缀帧循环）
pub async fn serve_dns(
    udp: UdpSocket,
    tcp: TcpListener,
    inbound: Arc<DnsInbound>,
) -> std::io::Result<()> {
    // UDP task
    let udp_inbound = Arc::clone(&inbound);
    let udp_handle = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            match udp.recv_from(&mut buf).await {
                Ok((len, peer)) => {
                    match udp_inbound.handle_packet(&buf[..len]).await {
                        Ok(Some(resp)) => {
                            if let Err(e) = udp.send_to(&resp, peer).await {
                                tracing::debug!(error = %e, "dns udp send failed");
                            }
                        }
                        Ok(None) => {} // Drop: 不响应
                        Err(e) => {
                            tracing::debug!(error = %e, "dns udp handle_packet failed");
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "dns udp recv failed");
                }
            }
        }
    });
    // TCP accept loop
    let tcp_inbound = Arc::clone(&inbound);
    let tcp_handle = tokio::spawn(async move {
        loop {
            match tcp.accept().await {
                Ok((conn, _peer)) => {
                    let inbound = Arc::clone(&tcp_inbound);
                    tokio::spawn(async move {
                        if let Err(e) = inbound.handle_conn(conn).await {
                            tracing::debug!(error = %e, "dns tcp conn failed");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "dns tcp accept failed");
                }
            }
        }
    });
    // 等待任一 task 结束（正常情况不会结束）
    tokio::select! {
        r = udp_handle => {
            r.map_err(|e| std::io::Error::other(format!("dns udp task: {e}")))
        }
        r = tcp_handle => {
            r.map_err(|e| std::io::Error::other(format!("dns tcp task: {e}")))
        }
    }
}

/// 遍历 BuiltConfig 的 inbounds，按协议 spawn listener tasks。
///
/// 返回每个 inbound 的 JoinHandle（用于优雅关闭）。不支持的协议 warn 跳过。
///
/// # 当前支持
///
/// - `socks`：SOCKS5 inbound（TCP accept → handshake → dispatch）
/// - 其他协议（vless/trojan/vmess/http）：warn 跳过（待后续切片）
pub async fn spawn_inbounds(
    built: &BuiltConfig,
    ohm: Arc<SimpleOhm>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let mut handles = Vec::new();
    for ib in &built.inbounds {
        if let Some(handle) = spawn_one_inbound(ib, Arc::clone(&ohm)).await? {
            handles.push(handle);
        }
    }
    Ok(handles)
}

/// 按协议种类启动单个 inbound listener。
async fn spawn_one_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    // TUN inbound 不需要 port/addr，提前处理
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
    if ib.entry.kind.as_str() == "tun" {
        let options = parse_tun_inbound_config(&ib.entry.data)?;
        let handler = TunInboundHandler::new(&ib.tag, options)
            .await
            .map_err(|e| std::io::Error::other(format!("tun inbound: {e}")))?;
        tracing::info!(tag = %ib.tag, "tun inbound listening");
        let handle = tokio::spawn(async move {
            if let Err(e) = handler.start().await {
                tracing::error!(error = ?e, "tun inbound stopped");
            }
        });
        return Ok(Some(handle));
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd")))]
    if ib.entry.kind.as_str() == "tun" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN inbound is only supported on Linux/Android/FreeBSD",
        ));
    }

    let listen = ib.listen.as_deref().unwrap_or("0.0.0.0");
    let port = match ib.port {
        Some(p) => p,
        None => {
            tracing::warn!(
                tag = %ib.tag,
                protocol = %ib.entry.kind,
                "inbound has no port, skipping"
            );
            return Ok(None);
        }
    };
    let addr = format!("{listen}:{port}");

    match ib.entry.kind.as_str() {
        "socks" => {
            let listener = TcpListener::bind(&addr).await?;
            tracing::info!(tag = %ib.tag, addr = %addr, "socks5 inbound listening");
            let config = Arc::new(ServerConfig::default());
            let handle = tokio::spawn(async move {
                if let Err(e) = serve_socks5(listener, ohm, config).await {
                    tracing::error!(error = %e, "socks5 inbound stopped");
                }
            });
            Ok(Some(handle))
        }
        "vless" => {
            let validator: Arc<dyn VlessValidator> = build_vless_validator(&ib.entry.data)?;
            let listener = TcpListener::bind(&addr).await?;
            tracing::info!(tag = %ib.tag, addr = %addr, users = validator.get_count(), "vless inbound listening");
            let handle = tokio::spawn(async move {
                if let Err(e) = serve_vless(listener, ohm, validator, None).await {
                    tracing::error!(error = %e, "vless inbound stopped");
                }
            });
            Ok(Some(handle))
        }
        "trojan" => {
            let users = build_trojan_users(&ib.entry.data)?;
            // Trojan fallback：解析 JSON fallbacks 数组构建决策树
            let fallbacks = serde_json::from_slice::<serde_json::Value>(&ib.entry.data)
                .ok()
                .and_then(|v| v.get("fallbacks").cloned())
                .and_then(|fbs| serde_json::from_value::<Vec<serde_json::Value>>(fbs).ok())
                .map(|fbs| {
                    let list: Vec<Fallback> = fbs.into_iter().filter_map(|fb| {
                        Some(Fallback {
                            name: fb.get("name").and_then(|v| v.as_str()).unwrap_or("").into(),
                            alpn: fb.get("alpn").and_then(|v| v.as_str()).unwrap_or("").into(),
                            path: fb.get("path").and_then(|v| v.as_str()).unwrap_or("").into(),
                            dest: fb.get("dest").and_then(|v| v.as_str()).unwrap_or("127.0.0.1:80").into(),
                            xver: fb.get("xver").and_then(|v| v.as_u64()).unwrap_or(0),
                        })
                    }).collect();
                    if list.is_empty() { None } else { Some(FallbackPolicy::from_list(&list)) }
                })
                .flatten();
            let listener = TcpListener::bind(&addr).await?;
            tracing::info!(tag = %ib.tag, addr = %addr, users = users.len(), "trojan inbound listening");
            let handle = tokio::spawn(async move {
                if let Err(e) = serve_trojan(listener, ohm, users, fallbacks, None).await {
                    tracing::error!(error = %e, "trojan inbound stopped");
                }
            });
            Ok(Some(handle))
        }
        "vmess" => {
            let validator = build_vmess_validator(&ib.entry.data)?;
            // VMess detour：Go DetourConfig.to 重定向到指定 outbound tag（可选）
            let detour_to = serde_json::from_slice::<serde_json::Value>(&ib.entry.data)
                .ok()
                .and_then(|v| {
                    v.get("detour")
                        .and_then(|d| d.get("to"))
                        .and_then(|t| t.as_str())
                        .map(|s| s.to_string())
                });
            let listener = TcpListener::bind(&addr).await?;
            tracing::info!(tag = %ib.tag, addr = %addr, "vmess inbound listening");
            let handle = tokio::spawn(async move {
                if let Err(e) = serve_vmess(listener, ohm, validator, detour_to, None).await {
                    tracing::error!(error = %e, "vmess inbound stopped");
                }
            });
            Ok(Some(handle))
        }
        "http" => {
            let config = parse_http_config(&ib.entry.data)?;
            let listener = TcpListener::bind(&addr).await?;
            tracing::info!(tag = %ib.tag, addr = %addr, "http inbound listening");
            let handle = tokio::spawn(async move {
                if let Err(e) = serve_http(listener, ohm, Arc::new(config)).await {
                    tracing::error!(error = %e, "http inbound stopped");
                }
            });
            Ok(Some(handle))
        }
        "dokodemo" => {
            let dest = parse_dokodemo_dest(&ib.entry.data)?;
            let listener = TcpListener::bind(&addr).await?;
            tracing::info!(tag = %ib.tag, addr = %addr, dest = ?dest, "dokodemo inbound listening");
            let handle = tokio::spawn(async move {
                if let Err(e) = serve_dokodemo(listener, ohm, dest).await {
                    tracing::error!(error = %e, "dokodemo inbound stopped");
                }
            });
            Ok(Some(handle))
        }
        // shadowsocks inbound：SsInbound + serve_ss accept loop
        "shadowsocks" => {
            let listener = TcpListener::bind(&addr).await?;
            let inbound = parse_ss_inbound_config(&ib.entry.data)?;
            tracing::info!(tag = %ib.tag, addr = %addr, "shadowsocks inbound listening");
            let handle = tokio::spawn(async move {
                if let Err(e) = serve_ss(listener, ohm, inbound).await {
                    tracing::error!(error = %e, "shadowsocks inbound stopped");
                }
            });
            Ok(Some(handle))
        }
        // hysteria inbound：HysteriaInboundHandler impl InboundHandler
        "hysteria" => {
            let bind_addr: std::net::SocketAddr = addr.parse()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("parse addr: {e}")))?;
            let (config, factory) = parse_hysteria_inbound_config(&ib.entry.data, bind_addr)?;
            let handler = xray_proxy_hysteria::HysteriaInboundHandler::new(
                &ib.tag, config, bind_addr, factory,
            )
            .map_err(|e| std::io::Error::other(format!("hysteria inbound: {e}")))?;
            tracing::info!(tag = %ib.tag, addr = %addr, "hysteria inbound listening");
            let handle = tokio::spawn(async move {
                if let Err(e) = handler.start().await {
                    tracing::error!(error = ?e, "hysteria inbound stopped");
                }
            });
            Ok(Some(handle))
        }
        // anytls inbound：AnytlsInboundHandler impl InboundHandler
        "anytls" => {
            let bind_addr: std::net::SocketAddr = addr.parse()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("parse addr: {e}")))?;
            let tls_acceptor = parse_anytls_tls_acceptor(&ib.entry.data)?;
            let handler = xray_proxy_anytls::AnytlsInboundHandler::new(
                &ib.tag, bind_addr, tls_acceptor,
            );
            tracing::info!(tag = %ib.tag, addr = %addr, "anytls inbound listening");
            let handle = tokio::spawn(async move {
                if let Err(e) = handler.start().await {
                    tracing::error!(error = ?e, "anytls inbound stopped");
                }
            });
            Ok(Some(handle))
        }
        // tuic inbound：QUIC listener，当前 no-op（需要 quinn server adapter）
        "tuic" => {
            let handler = parse_tuic_inbound_config(&ib.entry.data, &addr)?;
            tracing::info!(tag = %ib.tag, addr = %addr, "tuic inbound listening");
            let handle = tokio::spawn(async move {
                if let Err(e) = handler.start().await {
                    tracing::error!(error = ?e, "tuic inbound stopped");
                }
            });
            Ok(Some(handle))
        }
        // wireguard inbound：WireguardInboundHandler impl InboundHandler
        "wireguard" => {
            let (config, listen_port) = parse_wireguard_inbound_config(&ib.entry.data)?;
            let handler = xray_proxy_wireguard::WireguardInboundHandler::new(
                &ib.tag, &config, listen_port,
            )
            .await
            .map_err(|e| std::io::Error::other(format!("wireguard inbound: {e}")))?;
            tracing::info!(tag = %ib.tag, port = listen_port, "wireguard inbound listening");
            let handle = tokio::spawn(async move {
                if let Err(e) = handler.start().await {
                    tracing::error!(error = ?e, "wireguard inbound stopped");
                }
            });
            Ok(Some(handle))
        }
        // dns inbound：UDP+TCP listener → handle_packet/handle_conn
        "dns" => {
            let (handler, outbound) = parse_dns_inbound_config(&ib.entry.data, &ib.tag)?;
            let inbound = Arc::new(DnsInbound::new(&ib.tag, handler, outbound));
            let udp = UdpSocket::bind(&addr).await?;
            let tcp = TcpListener::bind(&addr).await?;
            tracing::info!(tag = %ib.tag, addr = %addr, "dns inbound listening (UDP+TCP)");
            let handle = tokio::spawn(async move {
                if let Err(e) = serve_dns(udp, tcp, inbound).await {
                    tracing::error!(error = %e, "dns inbound stopped");
                }
            });
            Ok(Some(handle))
        }
        // loopback inbound：LoopbackHandler 注册（outbound-only，start/close no-op）
        "loopback" => {
            let inbound_tag = parse_loopback_config(&ib.entry.data)?;
            let _handler = LoopbackHandler::new(&ib.tag, xray_proto::xray::proxy::loopback::Config { inbound_tag });
            tracing::info!(tag = %ib.tag, "loopback inbound registered (outbound-only)");
            // LoopbackHandler 的 InboundHandler::start 是 no-op，不 spawn task
            Ok(None)
        }
        // blackhole inbound：accept 连接后静默关闭/写 403 后关闭
        "blackhole" => {
            let response = parse_blackhole_inbound_response(&ib.entry.data);
            let handler = BlackholeInboundHandler::new(&ib.tag, response, &addr);
            handler.start().await
                .map_err(|e| std::io::Error::other(format!("blackhole inbound: {e}")))?;
            let handle = tokio::spawn(async move {
                // accept 循环在 start() 内部 spawn，此 task 保持 handler 存活
                std::future::pending::<()>().await
            });
            Ok(Some(handle))
        }
        // freedom inbound：accept 连接后 dial 预定义目标并双向转发
        "freedom" => {
            let dest = parse_freedom_inbound_dest(&ib.entry.data)?;
            let handler = FreedomInboundHandler::new(&ib.tag, &addr, dest, Arc::clone(&ohm));
            handler.start().await
                .map_err(|e| std::io::Error::other(format!("freedom inbound: {e}")))?;
            let handle = tokio::spawn(async move {
                // accept 循环在 start() 内部 spawn，此 task 保持 handler 存活
                std::future::pending::<()>().await
            });
            Ok(Some(handle))
        }
        other => {
            tracing::warn!(
                tag = %ib.tag,
                protocol = %other,
                "inbound protocol not yet supported, skipping"
            );
            Ok(None)
        }
    }
}

/// 从 inbound entry.data（JSON）解析 vless clients → MemoryValidator。
///
/// JSON 格式：`{"clients":[{"id":"uuid","flow":"","email":""}],"decryption":"none"}`。
/// 对每个 client 构造最小 `ProtoAccount`（id+flow+encryption=none）→ `MemoryAccount::from_proto_account`。
fn build_vless_validator(data: &[u8]) -> std::io::Result<std::sync::Arc<dyn VlessValidator>> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("vless inbound settings JSON: {e}")))?;
    let validator = VlessMemoryValidator::new();
    if let Some(clients) = v.get("clients").and_then(|c| c.as_array()) {
        for c in clients {
            let id = c.get("id").and_then(|x| x.as_str()).unwrap_or("");
            let email = c.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let level = c.get("level").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
            let flow = c.get("flow").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let proto = VlessProtoAccount {
                id: id.to_string(),
                flow,
                encryption: "none".to_string(),
                ..Default::default()
            };
            let account = VlessMemoryAccount::from_proto_account(&proto)
                .map_err(|e| std::io::Error::other(format!("vless account parse: {e}")))?;
            let user = VlessMemoryUser::new(email, level, account);
            if let Err(e) = validator.add(user) {
                tracing::warn!(error = %e, "skip duplicate vless user during validator build");
            }
        }
    }
    Ok(std::sync::Arc::new(validator))
}

/// 从 inbound entry.data（JSON）解析 trojan clients → HashMap<key_hash, MemoryUser>。
///
/// JSON 格式：`{"clients":[{"password":"...","email":""}]}`。
/// 对每个 client：`MemoryAccount::new(password)`（内部计算 hex(sha224)）→ MemoryUser → key_hash 入表。
fn build_trojan_users(data: &[u8]) -> std::io::Result<HashMap<String, TrojanMemoryUser>> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("trojan inbound settings JSON: {e}")))?;
    let mut users = HashMap::new();
    if let Some(clients) = v.get("clients").and_then(|c| c.as_array()) {
        for c in clients {
            let password = c.get("password").and_then(|x| x.as_str()).unwrap_or("");
            let email = c.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let level = c.get("level").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
            let account = TrojanMemoryAccount::new(password);
            let user = TrojanMemoryUser::new(email, level, account);
            users.insert(user.key_hash(), user);
        }
    }
    Ok(users)
}


/// 从 inbound entry.data（JSON）解析 http accounts → HttpServerConfig。
///
/// JSON 格式：`{"accounts":[{"user":"u","pass":"p"}]}`（用户可选）
fn parse_http_config(data: &[u8]) -> std::io::Result<HttpServerConfig> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("http inbound settings JSON: {e}")))?;
    let mut config = HttpServerConfig::default();
    if let Some(accounts) = v.get("accounts").and_then(|c| c.as_array()) {
        for a in accounts {
            let user = a.get("user").and_then(|x| x.as_str()).unwrap_or("");
            let pass = a.get("pass").and_then(|x| x.as_str()).unwrap_or("");
            if !user.is_empty() {
                config.accounts.insert(user.to_string(), pass.to_string());
            }
        }
    }
    Ok(config)
}

/// 从 inbound entry.data（JSON）解析 dokodemo 配置 → Destination（预定义目标）。
///
/// JSON 格式：`{"address":"1.2.3.4","port":80,"network":"tcp"}`（address+port 必填）
fn parse_dokodemo_dest(data: &[u8]) -> std::io::Result<Destination> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("dokodemo inbound settings JSON: {e}")))?;
    let address_str = v.get("address").and_then(|x| x.as_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "dokodemo: missing address"))?;
    let port = v.get("port").and_then(|x| x.as_u64())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "dokodemo: missing port"))?
        as u16;
    // address 是 IPv4/IPv6/Domain 之一
    let address = if let Ok(v4) = address_str.parse::<std::net::Ipv4Addr>() {
        Address::IPv4(v4)
    } else if let Ok(v6) = address_str.parse::<std::net::Ipv6Addr>() {
        Address::IPv6(v6)
    } else {
        Address::Domain(address_str.to_string())
    };
    Ok(Destination::new(address, Port::new(port), Network::TCP))
}

/// 从 inbound entry.data（JSON）解析 vmess clients → TimedUserValidator。
///
/// JSON 格式：`{"clients":[{"id":"uuid","level":0,"alterId":0,"email":""}]}`。
/// 现代 VMess (AEAD) 不用 alterId，忽略该字段。`id` 解析为 `UUID` → `MemoryAccount::new(uuid)`。
fn build_vmess_validator(data: &[u8]) -> std::io::Result<std::sync::Arc<VmessTimedUserValidator>> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("vmess inbound settings JSON: {e}")))?;
    let validator = VmessTimedUserValidator::new();
    if let Some(clients) = v.get("clients").and_then(|c| c.as_array()) {
        for c in clients {
            let id = c.get("id").and_then(|x| x.as_str()).unwrap_or("");
            let email = c.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let level = c.get("level").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
            let uuid = UUID::parse(id)
                .ok_or_else(|| std::io::Error::other(format!("vmess invalid uuid: {id}")))?;
            let account = VmessMemoryAccount::new(uuid);
            let user = VmessMemoryUser::new(email, account).with_level(level);
            if let Err(e) = VmessValidator::add(&validator, user) {
                tracing::warn!(error = %e, "skip vmess user during validator build");
            }
        }
    }
    Ok(std::sync::Arc::new(validator))
}

/// 从 inbound entry.data（JSON）解析 SS 客户端 → SsInbound。
///
/// JSON 格式：`{"method":"aes-128-gcm","password":"..."}` 或
/// `{"clients":[{"method":"aes-128-gcm","password":"...","email":""}]}`。
fn parse_ss_inbound_config(data: &[u8]) -> std::io::Result<SsInboundMode> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("ss inbound settings JSON: {e}")))?;

    // SS-2022 检测：method 以 "2022-blake3-" 开头
    let method = v.get("method").and_then(|x| x.as_str()).unwrap_or("aes-128-gcm");
    if method.starts_with("2022-blake3-") {
        return parse_ss2022_inbound_config(method, &v);
    }

    // Legacy SS AEAD
    use xray_proto::xray::proxy::shadowsocks::Account as ProtoAccount;
    if let Some(clients) = v.get("clients").and_then(|c| c.as_array()) {
        let mut users = Vec::new();
        for c in clients {
            let password = c.get("password").and_then(|x| x.as_str()).unwrap_or("");
            let email = c.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let c_method = c.get("method").and_then(|x| x.as_str()).unwrap_or("aes-128-gcm");
            let cipher = ss_cipher_from_str(c_method)
                .ok_or_else(|| std::io::Error::other(format!("unsupported ss cipher: {c_method}")))?;
            let proto = ProtoAccount { password: password.to_string(), cipher_type: cipher.as_i32(), iv_check: false };
            let account = SsConfigMemoryAccount::from_proto(&proto)
                .map_err(|e| std::io::Error::other(format!("ss account parse: {e}")))?;
            users.push(xray_proxy_ss::validator::MemoryUser::new(email, account));
        }
        if users.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "ss inbound: no users"));
        }
        return Ok(SsInboundMode::Legacy(Arc::new(SsInbound::with_users(users))));
    }

    // Legacy 单用户
    let password = v.get("password").and_then(|x| x.as_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "ss inbound: missing password"))?;
    let cipher = ss_cipher_from_str(method)
        .ok_or_else(|| std::io::Error::other(format!("unsupported ss cipher: {method}")))?;
    let proto = ProtoAccount { password: password.to_string(), cipher_type: cipher.as_i32(), iv_check: false };
    let account = SsConfigMemoryAccount::from_proto(&proto)
        .map_err(|e| std::io::Error::other(format!("ss account parse: {e}")))?;
    Ok(SsInboundMode::Legacy(Arc::new(SsInbound::new(account, "u@ss.local"))))
}

/// SS-2022 入站配置解析。
fn parse_ss2022_inbound_config(method: &str, v: &serde_json::Value) -> std::io::Result<SsInboundMode> {
    use xray_proxy_ss::ss2022::{MultiUserInbound, RelayDestination, RelayInbound, Ss2022Inbound, Ss2022User};
    use xray_proxy_ss::ss2022::key::psk_from_base64;

    let server_psk = v.get("password").and_then(|x| x.as_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "ss2022 inbound: missing server PSK"))?;

    // 中继模式：destinations 数组
    if let Some(dests) = v.get("destinations").and_then(|d| d.as_array()) {
        let mut destinations = Vec::new();
        for d in dests {
            let key_b64 = d.get("password").and_then(|x| x.as_str()).unwrap_or("");
            let email = d.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let level = d.get("level").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
            let addr_str = d.get("server").and_then(|x| x.as_str()).unwrap_or("127.0.0.1");
            let port = d.get("server_port").and_then(|x| x.as_u64()).unwrap_or(0) as u16;
            let psk = psk_from_base64(key_b64)
                .map_err(|e| std::io::Error::other(format!("ss2022 relay PSK: {e}")))?;
            destinations.push(RelayDestination {
                key: psk,
                address: xray_common::net::address::Address::Domain(addr_str.to_string()),
                port,
                email,
                level,
            });
        }
        if destinations.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "ss2022 relay: no destinations"));
        }
        let relay = RelayInbound::new(method, server_psk, destinations)
            .map_err(|e| std::io::Error::other(format!("ss2022 relay: {e}")))?;
        return Ok(SsInboundMode::Ss2022Relay(Arc::new(relay)));
    }

    // 多用户模式：clients 数组
    if let Some(clients) = v.get("clients").and_then(|c| c.as_array()) {
        let mut users = Vec::new();
        for c in clients {
            let psk_b64 = c.get("password").and_then(|x| x.as_str()).unwrap_or("");
            let email = c.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let level = c.get("level").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
            let psk = psk_from_base64(psk_b64)
                .map_err(|e| std::io::Error::other(format!("ss2022 user PSK: {e}")))?;
            users.push(Ss2022User { email, level, psk });
        }
        if users.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "ss2022 multi: no users"));
        }
        let multi = MultiUserInbound::new(method, server_psk, users)
            .map_err(|e| std::io::Error::other(format!("ss2022 multi: {e}")))?;
        return Ok(SsInboundMode::Ss2022Multi(Arc::new(multi)));
    }

    // 单用户模式
    let single = Ss2022Inbound::new(method, server_psk, "u@ss2022.local")
        .map_err(|e| std::io::Error::other(format!("ss2022 single: {e}")))?;
    Ok(SsInboundMode::Ss2022(Arc::new(single)))
}

/// SS cipher 字符串 → CipherType。
fn ss_cipher_from_str(s: &str) -> Option<SsCipherType> {
    match s {
        "aes-128-gcm" => Some(SsCipherType::Aes128Gcm),
        "aes-256-gcm" => Some(SsCipherType::Aes256Gcm),
        "chacha20-ietf-poly1305" => Some(SsCipherType::ChaCha20Poly1305),
        _ => None,
    }
}

/// 从 inbound entry.data（JSON）解析 hysteria inbound 配置。
///
/// 返回 (HysteriaConfig, HysteriaListenerFactory)。
/// JSON 格式：`{"auth":"...","server_name":"..."}`。
fn parse_hysteria_inbound_config(
    data: &[u8],
    bind_addr: std::net::SocketAddr,
) -> std::io::Result<(xray_proxy_hysteria::HysteriaConfig, Arc<dyn xray_transport_hysteria::hub::HysteriaListenerFactory>)> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("hysteria inbound settings JSON: {e}")))?;
    let auth = v.get("auth").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let server_name = v.get("server_name").and_then(|x| x.as_str()).unwrap_or("hysteria").to_string();
    let config = xray_proxy_hysteria::HysteriaConfig::new(bind_addr.to_string(), auth)
        .with_server_name(server_name);
    // ponytail: 真实 QUIC listener factory 需要 quinn server adapter
    // 当前用 StubListenerFactory，quinn server adapter 待后续切片实现
    let factory: Arc<dyn xray_transport_hysteria::hub::HysteriaListenerFactory> = Arc::new(StubListenerFactory);
    Ok((config, factory))
}

/// 从 inbound entry.data（JSON）解析 anytls TLS acceptor。
///
/// JSON 格式：`{"cert":"...","key":"..."}`（PEM 格式）。
/// 缺省时用自签名证书（仅测试场景）。
fn parse_anytls_tls_acceptor(data: &[u8]) -> std::io::Result<tokio_rustls::TlsAcceptor> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("anytls inbound settings JSON: {e}")))?;
    // 尝试从配置读证书
    let (cert_der, key_der) = if let (Some(cert_str), Some(key_str)) = (
        v.get("cert").and_then(|x| x.as_str()),
        v.get("key").and_then(|x| x.as_str()),
    ) {
        let mut cert_reader = std::io::BufReader::new(cert_str.as_bytes());
        let cert_pem = rustls_pemfile::certs(&mut cert_reader)
            .into_iter().next()
            .ok_or_else(|| std::io::Error::other("no cert in PEM"))?
            .map_err(|e| std::io::Error::other(format!("parse cert PEM: {e}")))?;
        let mut key_reader = std::io::BufReader::new(key_str.as_bytes());
        let key_pem = rustls_pemfile::private_key(&mut key_reader)
            .map_err(|e| std::io::Error::other(format!("parse key PEM: {e}")))?
            .ok_or_else(|| std::io::Error::other("no key in PEM"))?;
        (cert_pem, key_pem)
    } else {
        // ponytail: 无证书配置时用自签名证书（仅测试场景）
        let _ = rustls::crypto::ring::default_provider().install_default();
        let key_pair = rcgen::KeyPair::generate()
            .map_err(|e| std::io::Error::other(format!("rcgen keypair: {e}")))?;
        let params = rcgen::CertificateParams::new(vec!["localhost".into()])
            .map_err(|e| std::io::Error::other(format!("rcgen params: {e}")))?;
        let cert = params.self_signed(&key_pair)
            .map_err(|e| std::io::Error::other(format!("rcgen self_signed: {e}")))?;
        (
            CertificateDer::from(cert.der().clone()),
            PrivateKeyDer::try_from(key_pair.serialize_der())
                .map_err(|e| std::io::Error::other(format!("rcgen key der: {e}")))?,
        )
    };
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.into()], key_der)
        .map_err(|e| std::io::Error::other(format!("rustls server config: {e}")))?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// 从 inbound entry.data（JSON）解析 wireguard inbound 配置。
///
/// JSON 格式：`{"secretKey":"...","peers":[{"publicKey":"...","endpoint":"..."}]}`。
fn parse_wireguard_inbound_config(data: &[u8]) -> std::io::Result<(DeviceConfig, u16)> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("wireguard inbound settings JSON: {e}")))?;
    let secret_key = v.get("secretKey").and_then(|x| x.as_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "wireguard: missing secretKey"))?
        .to_string();
    let mut peers = Vec::new();
    if let Some(arr) = v.get("peers").and_then(|x| x.as_array()) {
        for p in arr {
            let public_key = p.get("publicKey").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let endpoint = p.get("endpoint").and_then(|x| x.as_str()).unwrap_or("").to_string();
            peers.push(xray_proxy_wireguard::PeerConfig {
                public_key,
                endpoint,
                ..Default::default()
            });
        }
    }
    let endpoint = v.get("address").and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_else(|| vec!["10.0.0.2/32".to_string()]);
    let port = v.get("port").and_then(|x| x.as_u64()).unwrap_or(51820) as u16;
    let config = DeviceConfig {
        secret_key,
        peers,
        endpoint,
        ..Default::default()
    };
    Ok((config, port))
}

/// 从 inbound entry.data（JSON）解析 dns inbound 配置。
///
/// JSON 格式：`{"servers":["8.8.8.8:53"]}` 或空对象。
/// 返回 (Handler, DnsOutbound)。
fn parse_dns_inbound_config(
    data: &[u8],
    tag: &str,
) -> std::io::Result<(DnsHandler, DnsOutbound)> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("dns inbound settings JSON: {e}")))?;
    let handler = DnsHandler::init(&DnsConfig::default());
    // 解析上游 DNS 服务器列表
    let servers: Vec<(std::net::IpAddr, u16)> = v.get("servers")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter().filter_map(|s| {
                s.as_str().and_then(|addr| {
                    let (ip, port) = addr.rsplit_once(':')?;
                    let ip: std::net::IpAddr = ip.parse().ok()?;
                    let port: u16 = port.parse().ok()?;
                    Some((ip, port))
                })
            }).collect()
        })
        .unwrap_or_default();
    let outbound = if servers.is_empty() {
        DnsOutbound::new_system(tag)
            .map_err(|e| std::io::Error::other(format!("dns outbound init: {e}")))?
    } else {
        DnsOutbound::new_with_servers(tag, &servers)
            .map_err(|e| std::io::Error::other(format!("dns outbound init: {e}")))?
    };
    Ok((handler, outbound))
}

/// 从 inbound entry.data（JSON）解析 loopback 配置 → inbound_tag。
///
/// JSON 格式：`{"inboundTag":"..."}`。
fn parse_loopback_config(data: &[u8]) -> std::io::Result<String> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("loopback inbound settings JSON: {e}")))?;
    let inbound_tag = v.get("inboundTag").and_then(|x| x.as_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "loopback: missing inboundTag"))?
        .to_string();
    Ok(inbound_tag)
}

/// 从 inbound entry.data（JSON）解析 tuic inbound 配置。
///
/// JSON 格式：`{"uuid":"...","password":"...","serverName":"..."}`。
/// uuid 必填，password 必填，serverName 默认 "tuic"。
fn parse_tuic_inbound_config(
    data: &[u8],
    addr: &str,
) -> std::io::Result<xray_proxy_tuic::TuicInboundHandler> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("tuic inbound settings JSON: {e}")))?;
    let uuid_str = v.get("uuid").and_then(|x| x.as_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "tuic: missing uuid"))?;
    let uuid = uuid::Uuid::parse_str(uuid_str)
        .map_err(|e| std::io::Error::other(format!("tuic invalid uuid: {e}")))?;
    let password = v.get("password").and_then(|x| x.as_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "tuic: missing password"))?;
    let server_name = v.get("serverName").and_then(|x| x.as_str()).unwrap_or("tuic").to_string();
    let bind_addr: std::net::SocketAddr = addr.parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("tuic parse addr: {e}")))?;
    let config = xray_proxy_tuic::TuicInboundConfig {
        listen: bind_addr,
        server_name,
        uuid,
        password: password.to_string(),
        cert_der: None,
        key_der: None,
    };
    xray_proxy_tuic::TuicInboundHandler::new("", config)
        .map_err(|e| std::io::Error::other(format!("tuic inbound: {e}")))
}

/// TUN 配置占位设备——满足 StackOptions.tun 存在性校验。
///
/// TunInboundHandler::new 校验 options.tun.is_some()，但 start() 内部
/// 直接 TunDevice::create 硬编码参数，不使用 options.tun 的设备。
/// 因此配置解析阶段只需提供占位。
#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
struct TunPlaceholder;

#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
impl Tun for TunPlaceholder {
    fn start(&self) -> xray_proxy_tun::Result<()> { Ok(()) }
    fn close(&self) -> xray_proxy_tun::Result<()> { Ok(()) }
    fn name(&self) -> xray_proxy_tun::Result<String> { Ok("placeholder".into()) }
    fn index(&self) -> xray_proxy_tun::Result<i32> { Ok(0) }
}

/// 从 inbound entry.data（JSON）解析 TUN inbound 配置 → StackOptions。
///
/// JSON 格式：`{"idleTimeout":"30s"}`（idleTimeout 可选，默认 30s）。
/// 设备参数（name/address/mtu）当前硬编码在 TunInboundHandler::start，
/// 后续切片从 JSON 读取。
#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
fn parse_tun_inbound_config(data: &[u8]) -> std::io::Result<StackOptions> {
    let mut opts = StackOptions::default();
    opts.tun = Some(Box::new(TunPlaceholder));
    if data.is_empty() {
        return Ok(opts);
    }
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("tun config: {e}")))?;
    // idleTimeout：数字（秒）或字符串（如 "30s"/"5m"）
    if let Some(val) = v.get("idleTimeout") {
        opts.idle_timeout = parse_duration_value(val)?;
    }
    Ok(opts)
}

/// 解析 duration 值：数字=秒，字符串="30s"/"5m"/"1h"。
fn parse_duration_value(val: &serde_json::Value) -> std::io::Result<std::time::Duration> {
    match val {
        serde_json::Value::Number(n) => {
            let secs = n.as_u64().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "idleTimeout: not a positive integer")
            })?;
            Ok(std::time::Duration::from_secs(secs))
        }
        serde_json::Value::String(s) => parse_duration_suffix(s),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "idleTimeout: expected number or string",
        )),
    }
}

/// 解析带后缀的 duration 字符串（"30s"/"5m"/"1h"/"2h30m"）。
fn parse_duration_suffix(s: &str) -> std::io::Result<std::time::Duration> {
    let mut total_secs: u64 = 0;
    let mut num_buf = String::new();
    for ch in s.chars() {
        match ch {
            '0'..='9' => num_buf.push(ch),
            's' => {
                let n: u64 = num_buf.parse().map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("idleTimeout: bad number in '{s}'"))
                })?;
                total_secs += n;
                num_buf.clear();
            }
            'm' => {
                let n: u64 = num_buf.parse().map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("idleTimeout: bad number in '{s}'"))
                })?;
                total_secs += n * 60;
                num_buf.clear();
            }
            'h' => {
                let n: u64 = num_buf.parse().map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("idleTimeout: bad number in '{s}'"))
                })?;
                total_secs += n * 3600;
                num_buf.clear();
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("idleTimeout: unknown suffix '{ch}' in '{s}'"),
                ));
            }
        }
    }
    // 无后缀的尾部数字视为秒
    if !num_buf.is_empty() {
        let n: u64 = num_buf.parse().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("idleTimeout: trailing number in '{s}'"))
        })?;
        total_secs += n;
    }
    Ok(std::time::Duration::from_secs(total_secs))
}

/// 从 inbound entry.data（JSON）解析 blackhole inbound 响应配置。
///
/// JSON 格式：`{"response":{"type":"none"}}` 或 `{"response":{"type":"http"}}`。
/// 缺省时默认 None。
fn parse_blackhole_inbound_response(data: &[u8]) -> BlackholeResponseConfig {
    if data.is_empty() {
        return BlackholeResponseConfig::None;
    }
    let v: serde_json::Value = serde_json::from_slice(data).unwrap_or_default();
    let response_type = v.get("response")
        .and_then(|r| r.get("type"))
        .and_then(|t| t.as_str())
        .unwrap_or("none");
    match response_type {
        "http" => BlackholeResponseConfig::Http403,
        _ => BlackholeResponseConfig::None,
    }
}

/// 从 inbound entry.data（JSON）解析 freedom inbound 预定义目标地址。
///
/// JSON 格式：`{"address":"1.2.3.4","port":80}`（address+port 必填）。
/// 类似 dokodemo 的配置格式。
fn parse_freedom_inbound_dest(data: &[u8]) -> std::io::Result<Destination> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("freedom inbound settings JSON: {e}")))?;
    let address_str = v.get("address").and_then(|x| x.as_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "freedom inbound: missing address"))?;
    let port = v.get("port").and_then(|x| x.as_u64())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "freedom inbound: missing port"))?
        as u16;
    let address = if let Ok(v4) = address_str.parse::<std::net::Ipv4Addr>() {
        Address::IPv4(v4)
    } else if let Ok(v6) = address_str.parse::<std::net::Ipv6Addr>() {
        Address::IPv6(v6)
    } else {
        Address::Domain(address_str.to_string())
    };
    Ok(Destination::new(address, Port::new(port), Network::TCP))
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use xray_app_dispatcher::default::SimpleOhm;
    use xray_proxy_freedom::make_freedom_dial_fn;
    use xray_proxy_socks::protocol::{ATYP_DOMAIN, ATYP_IPV4};

    /// 端到端：SOCKS5 client → SOCKS5 inbound → freedom outbound → echo server。
    #[tokio::test]
    async fn socks5_inbound_to_freedom_outbound_e2e() {
        // 1. 起 echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = echo_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        // 2. 配置 dispatcher：freedom outbound → SimpleOhm default
        let ohm = Arc::new(SimpleOhm::new());
        let dial_fn = make_freedom_dial_fn();
        let bridge = std::sync::Arc::new(xray_app_dispatcher::default::DialBridge::new(
            "freedom",
            dial_fn,
        )) as std::sync::Arc<dyn xray_app_dispatcher::DispatchHandler>;
        ohm.set_default(bridge);

        // 3. 起 SOCKS5 inbound
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let config = Arc::new(ServerConfig::default());
        let ohm_clone = Arc::clone(&ohm);
        tokio::spawn(async move {
            let _ = serve_socks5(socks_listener, ohm_clone, config).await;
        });

        // 4. SOCKS5 client：连 socks5 → handshake → 请求 echo server → 写数据 → 读 echo
        let mut client = TcpStream::connect(socks_addr).await.unwrap();
        // 握手：版本 5，1 method，no-auth(0)
        client
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00], "server should select no-auth");

        // 请求 CONNECT echo_addr（IPv4）
        let ip = echo_addr.ip();
        assert!(ip.is_ipv4(), "echo addr should be ipv4");
        let ipv4_bytes = match ip {
            std::net::IpAddr::V4(v4) => v4.octets(),
            _ => unreachable!(),
        };
        let port_bytes = echo_addr.port().to_be_bytes();
        let mut req = vec![0x05, 0x01, 0x00, ATYP_IPV4];
        req.extend_from_slice(&ipv4_bytes);
        req.extend_from_slice(&port_bytes);
        client.write_all(&req).await.unwrap();

        // 读 CONNECT 成功响应（10 字节）
        let mut connect_resp = [0u8; 10];
        client.read_exact(&mut connect_resp).await.unwrap();
        assert_eq!(connect_resp[1], 0x00, "CONNECT should succeed");

        // 5. 发数据 + 读 echo
        let payload = b"hello socks5 proxy!";
        client.write_all(payload).await.unwrap();

        let mut got = vec![0u8; payload.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, payload, "should receive echo through proxy");
    }

    #[test]
    fn socks_addr_to_destination_ipv4() {
        let addr = SocksAddr {
            host: Host::Ipv4(Ipv4Addr::new(1, 2, 3, 4)),
            port: 8080,
        };
        let req = SocksRequest::TcpConnect(addr);
        let dest = socks_addr_to_destination(&req).unwrap();
        assert!(dest.is_tcp());
        assert_eq!(dest.port(), Port::new(8080));
        match dest.address() {
            Address::IPv4(ip) => assert_eq!(ip.octets(), [1, 2, 3, 4]),
            other => panic!("expected IPv4, got {other:?}"),
        }
    }

    #[test]
    fn socks_addr_to_destination_domain() {
        let addr = SocksAddr {
            host: Host::Domain("example.com".to_string()),
            port: 443,
        };
        let req = SocksRequest::TcpConnect(addr);
        let dest = socks_addr_to_destination(&req).unwrap();
        assert_eq!(dest.port(), Port::new(443));
        match dest.address() {
            Address::Domain(d) => assert_eq!(d, "example.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
        let _ = ATYP_DOMAIN; // 确认 import 路径
    }

    #[test]
    fn build_vless_validator_parses_clients_json() {
        let uuid = "66ad4540-b58c-4ad2-9926-ea63445a9b57";
        let settings = serde_json::json!({
            "clients": [{ "id": uuid, "email": "alice@example.com", "level": 0 },
                          { "id": "11111111-2222-3333-4444-555555555555", "email": "bob" }],
            "decryption": "none",
        });
        let data = serde_json::to_vec(&settings).unwrap();
        let validator = super::build_vless_validator(&data).unwrap();
        // get_count from Validator trait
        use xray_proxy_vless::Validator as VlessValidatorTrait;
        assert_eq!(VlessValidatorTrait::get_count(&*validator), 2);
        // 用户可被取出（按 UUID lookup）
        let parsed_uuid = xray_common::uuid::UUID::parse(uuid).expect("uuid");
        let user = VlessValidatorTrait::get(&*validator, &parsed_uuid).expect("user should be registered");
        assert_eq!(user.email, "alice@example.com");
    }

    #[test]
    fn build_vless_validator_empty_clients() {
        let settings = serde_json::json!({ "decryption": "none" });
        let data = serde_json::to_vec(&settings).unwrap();
        let validator = super::build_vless_validator(&data).unwrap();
        use xray_proxy_vless::Validator as VlessValidatorTrait;
        assert_eq!(VlessValidatorTrait::get_count(&*validator), 0);
    }

    #[test]
    fn build_vless_validator_invalid_json() {
        let bad = b"not a json";
        let err = super::build_vless_validator(bad);
        assert!(err.is_err(), "invalid JSON should error");
    }

    #[test]
    fn build_trojan_users_parses_clients_json() {
        let settings = serde_json::json!({
            "clients": [{ "password": "secret", "email": "alice" },
                          { "password": "another", "email": "bob" }],
        });
        let data = serde_json::to_vec(&settings).unwrap();
        let users = super::build_trojan_users(&data).unwrap();
        assert_eq!(users.len(), 2, "should parse 2 trojan users");
        // 手动构造同样的 account 验证 key_hash 一致
        let expected_account = TrojanMemoryAccount::new("secret");
        let expected_user = TrojanMemoryUser::new("alice", 0, expected_account);
        assert!(users.contains_key(&expected_user.key_hash()));
    }

    #[test]
    fn build_trojan_users_empty_clients() {
        let settings = serde_json::json!({});
        let data = serde_json::to_vec(&settings).unwrap();
        let users = super::build_trojan_users(&data).unwrap();
        assert!(users.is_empty());
    }

    #[test]
    fn build_vmess_validator_parses_clients_json() {
        let uuid = "66ad4540-b58c-4ad2-9926-ea63445a9b57";
        let settings = serde_json::json!({
            "clients": [{ "id": uuid, "email": "alice", "level": 0 },
                          { "id": "11111111-2222-3333-4444-555555555555", "email": "bob" }],
        });
        let data = serde_json::to_vec(&settings).unwrap();
        let validator = super::build_vmess_validator(&data).unwrap();
        use xray_proxy_vmess::Validator as VmessValidatorTrait;
        assert_eq!(VmessValidatorTrait::count(&*validator), 2);
    }

    #[test]
    fn build_vmess_validator_invalid_uuid() {
        let settings = serde_json::json!({ "clients": [{ "id": "not-a-uuid" }] });
        let data = serde_json::to_vec(&settings).unwrap();
        assert!(super::build_vmess_validator(&data).is_err());
    }

    #[test]
    fn parse_http_config_extracts_accounts() {
        let settings = serde_json::json!({
            "accounts": [{ "user": "u1", "pass": "p1" }, { "user": "u2", "pass": "p2" }]
        });
        let data = serde_json::to_vec(&settings).unwrap();
        let cfg = super::parse_http_config(&data).unwrap();
        assert_eq!(cfg.accounts.get("u1").unwrap(), "p1");
        assert_eq!(cfg.accounts.get("u2").unwrap(), "p2");
    }

    #[test]
    fn parse_http_config_empty_returns_default() {
        let data = b"{}";
        let cfg = super::parse_http_config(data).unwrap();
        assert!(cfg.accounts.is_empty());
    }

    #[test]
    fn parse_dokodemo_dest_ipv4() {
        let settings = serde_json::json!({ "address": "192.168.1.1", "port": 8080 });
        let data = serde_json::to_vec(&settings).unwrap();
        let dest = super::parse_dokodemo_dest(&data).unwrap();
        assert!(matches!(dest.address(), Address::IPv4(_)));
        assert_eq!(dest.port().value(), 8080);
    }

    #[test]
    fn parse_dokodemo_dest_domain() {
        let settings = serde_json::json!({ "address": "example.com", "port": 443 });
        let data = serde_json::to_vec(&settings).unwrap();
        let dest = super::parse_dokodemo_dest(&data).unwrap();
        assert!(matches!(dest.address(), Address::Domain(_)));
        assert_eq!(dest.port().value(), 443);
    }

    #[test]
    fn parse_dokodemo_dest_missing_address_returns_err() {
        let settings = serde_json::json!({ "port": 80 });
        let data = serde_json::to_vec(&settings).unwrap();
        assert!(super::parse_dokodemo_dest(&data).is_err());
    }

    #[test]
    fn parse_dokodemo_dest_missing_port_returns_err() {
        let settings = serde_json::json!({ "address": "1.2.3.4" });
        let data = serde_json::to_vec(&settings).unwrap();
        assert!(super::parse_dokodemo_dest(&data).is_err());
    }

    #[test]
    fn is_mux_destination_detects_mux_cool() {
        let dest = Destination::new(
            Address::Domain("v1.mux.cool".to_string()),
            Port::new(9527),
            Network::TCP,
        );
        assert!(super::is_mux_destination(&dest));
    }

    #[test]
    fn is_mux_destination_rejects_normal_domain() {
        let dest = Destination::new(
            Address::Domain("example.com".to_string()),
            Port::new(443),
            Network::TCP,
        );
        assert!(!super::is_mux_destination(&dest));
    }

    #[test]
    fn is_mux_destination_rejects_wrong_port() {
        let dest = Destination::new(
            Address::Domain("v1.mux.cool".to_string()),
            Port::new(80),  // 不是 9527
            Network::TCP,
        );
        assert!(!super::is_mux_destination(&dest));
    }

    #[test]
    fn is_mux_destination_rejects_ipv4() {
        let dest = Destination::new(
            Address::IPv4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
            Port::new(9527),
            Network::TCP,
        );
        assert!(!super::is_mux_destination(&dest));
    }

    #[test]
    fn build_vmess_validator_empty_clients() {
        let settings = serde_json::json!({});
        let data = serde_json::to_vec(&settings).unwrap();
        let validator = super::build_vmess_validator(&data).unwrap();
        use xray_proxy_vmess::Validator as VmessValidatorTrait;
        assert_eq!(VmessValidatorTrait::count(&*validator), 0);
    }
}
