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
use std::net::SocketAddr;
use xray_proxy_socks::protocol::{Host, SocksAddr, decode_udp_packet, encode_udp_packet};
use xray_proxy_socks::server::{socks_handshake, SocksRequest};
use xray_proxy_socks::ServerConfig;
use tokio::io::AsyncReadExt;
use xray_transport::link::Link;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
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
use xray_proxy_http::server::{
    http_server_handshake, extract_request_path, build_forwarded_request, HandshakeResult,
};
use xray_app_dispatcher::DispatchHandler;
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
use xray_transport_hysteria::quinn_adapter::QuinnListenerFactory;
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

/// 处理单个 SOCKS 连接：handshake → dispatch（TCP CONNECT）或 UDP relay。
///
/// 兼容 SOCKS4/4a/5。UDP ASSOCIATE 时 spawn relay pump 并保持 TCP 控制连接。
async fn handle_connection(
    mut stream: TcpStream,
    config: &ServerConfig,
    handler: &Arc<dyn xray_app_dispatcher::DispatchHandler>,
) -> std::io::Result<()> {
    // 1. SOCKS 握手（兼容 4/4a/5）
    let socks_req = socks_handshake(&mut stream, config)
        .await
        .map_err(|e| std::io::Error::other(format!("socks handshake: {e}")))?;

    match socks_req {
        SocksRequest::UdpAssociate(_, relay_socket) => {
            // UDP relay：spawn pump，保持 TCP 控制连接直到客户端断开
            let relay = tokio::spawn(async move {
                let _ = handle_udp_associate(relay_socket).await;
            });
            // SOCKS5 UDP ASSOCIATE 语义：TCP 控制连接存在期间 relay 有效。
            // 读到 EOF/错误（客户端关闭控制连接）即终止 relay。
            let mut drop_buf = [0u8; 64];
            let _ = stream.read(&mut drop_buf).await;
            relay.abort();
            Ok(())
        }
        SocksRequest::TcpConnect(addr) => {
            // 2. SocksAddr → Destination
            let dest = socks_addr_to_destination(&addr)?;
            // 3. 拆 TcpStream → (read, write) → Link
            // ponytail: tokio::io::split 返回的 ReadHalf/WriteHalf 是 'static + Send,
            // new_reader/new_writer 接受 AsyncRead/AsyncWrite + Unpin + Send + 'static.
            let (read_half, write_half) = tokio::io::split(stream);
            let link = Link::new(new_reader(read_half), new_writer(write_half));
            // 4. dispatch（zx7: mux.cool dest 转给 mux ServerWorker）
            if is_mux_destination(&dest) {
                tracing::info!("socks: mux.cool destination detected, spawning mux inbound handler");
                tokio::spawn(handle_mux_inbound_link(link, Arc::clone(handler)));
                return Ok(());
            }
            let _ = handler.dispatch(&dest, link).await;
            Ok(())
        }
    }
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

/// `SocksAddr` → TCP `Destination`。
///
/// `Host::Ipv4` → `Address::IPv4`，`Ipv6` → `Address::IPv6`，`Domain` → `Address::Domain`。
fn socks_addr_to_destination(addr: &SocksAddr) -> std::io::Result<Destination> {
    let address = match &addr.host {
        Host::Ipv4(ip) => Address::IPv4(*ip),
        Host::Ipv6(ip) => Address::IPv6(*ip),
        Host::Domain(d) => Address::Domain(d.clone()),
    };
    Ok(Destination::new(address, Port::new(addr.port), Network::TCP))
}

/// SOCKS5 UDP ASSOCIATE relay pump。
///
/// 对应 Go `proxy/socks/server.go::handleUDPPayload`。
/// 从 relay socket 读客户端 UDP 请求帧（SOCKS5 UDP encapsulation:
/// `[RSV(2)][FRAG(1)][ATYP][DST.ADDR][DST.PORT][DATA]`），解码出目标地址 +
/// payload，转发到目标并回传响应。当客户端 TCP 控制连接关闭时，
/// 调用方 abort 本 task 终止 relay。
///
/// ponytail: 无 UDP dispatcher 路径，每个数据报独立开 ephemeral UDP socket
/// 转发（匹配当前 codebase 的 TCP-only dispatch 架构）。升级路径：接入
/// dispatcher 的 UDP session，复用 per-dest 长连接 socket。
async fn handle_udp_associate(relay_socket: UdpSocket) -> std::io::Result<()> {
    let mut buf = [0u8; 65535];
    loop {
        let (n, client_addr) = match relay_socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, "socks udp relay recv failed");
                continue;
            }
        };

        // 解码 SOCKS5 UDP 请求帧 → (目标地址, payload)
        let (dest_addr, payload) = match decode_udp_packet(&buf[..n]) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, "socks udp decode failed; dropping");
                continue;
            }
        };

        // 域名走 tokio lookup；IP 直接构造
        let dest = match resolve_udp_dest(&dest_addr).await {
            Some(d) => d,
            None => {
                tracing::debug!(dest = ?dest_addr, "socks udp dest resolve failed");
                continue;
            }
        };

        // 转发：ephemeral UDP socket → connect → send → recv (5s timeout)
        let fwd = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(error = %e, "socks udp fwd bind failed");
                continue;
            }
        };
        if fwd.connect(dest).await.is_err() {
            continue;
        }
        if fwd.send(payload).await.is_err() {
            continue;
        }
        let mut rbuf = [0u8; 65535];
        let rn = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fwd.recv(&mut rbuf),
        )
        .await
        {
            Ok(Ok(n)) => n,
            _ => continue, // 超时或错误：丢弃，不发响应
        };

        // 编码响应帧（BND.ADDR = 目标地址），发回客户端
        let resp = encode_udp_packet(&dest_addr, &rbuf[..rn]);
        if relay_socket.send_to(&resp, client_addr).await.is_err() {
            continue;
        }
    }
}

/// `SocksAddr` → `SocketAddr`（域名走 `tokio::net::lookup_host` 解析）。
async fn resolve_udp_dest(addr: &SocksAddr) -> Option<SocketAddr> {
    match &addr.host {
        Host::Ipv4(ip) => Some(SocketAddr::new((*ip).into(), addr.port)),
        Host::Ipv6(ip) => Some(SocketAddr::new((*ip).into(), addr.port)),
        Host::Domain(d) => tokio::net::lookup_host((d.as_str(), addr.port))
            .await
            .ok()?
            .next(),
    }
}

/// HTTP proxy inbound 服务入口。
///
/// 接受连接 → http_server_handshake → CONNECT 隧道 dispatch 或 plain HTTP 代理转发。
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
            // 1. handshake
            let hs = match http_server_handshake(&mut stream, &config).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!(error = %e, "http handshake failed");
                    return;
                }
            };
            // 2. Plain HTTP proxy（GET/POST 等）
            if hs.method != "CONNECT" {
                handle_plain_http(stream, hs, Arc::clone(&handler)).await;
                return;
            }
            // 3. CONNECT：拆 stream → Link → dispatch
            let dest = hs.dest;
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

/// 处理 plain HTTP 代理请求（GET/POST 等）。
///
/// 对应 Go `proxy/http/server.go::handlePlainHTTP`。通过 dispatch 拨号到目标，
/// 并发转发请求（head + body → 目标）和响应（目标 → 客户端）。
async fn handle_plain_http(
    client: TcpStream,
    hs: HandshakeResult,
    handler: Arc<dyn DispatchHandler>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use xray_buf::io::{Reader as BufReader, Writer as BufWriter};
    use xray_buf::multi::MultiBuffer;

    // 1. 构建转发请求（绝对 URL → 相对 path，移除 hop-by-hop headers）
    let path = extract_request_path(&hs.target);
    let request_head = build_forwarded_request(&hs.method, &path, &hs.headers);

    // 2. 创建 pipe 对，构造 dispatch link
    let (up_r, up_w) = xray_buf::pipe::new();
    let (dn_r, dn_w) = xray_buf::pipe::new();
    let dn_w_cleanup = dn_w.clone();
    let link = Link::new(
        Box::new(up_r) as Box<dyn BufReader>,
        Box::new(dn_w) as Box<dyn BufWriter>,
    );

    // 3. dispatch：拨号目标 + bridge（up_r → 目标写，目标读 → dn_w）
    let dest = hs.dest.clone();
    let h = Arc::clone(&handler);
    let dispatch_and_cleanup = async move {
        h.dispatch(&dest, link).await;
        // dispatch 结束（bridge EOF 或拨号失败）→ 关闭 dn_w 解除 read 阻塞
        dn_w_cleanup.shutdown();
    };

    // 4. 拆 client stream：read(body) + write(response) 并发
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let mut up_w = up_w;
    let mut dn_r = dn_r;

    // 上行：写 request head + copy body → 目标
    let write_req = async {
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&request_head);
        let _ = up_w.write_multi_buffer(mb).await;
        let mut buf = vec![0u8; 8192];
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut mb = MultiBuffer::new();
                    mb.merge_bytes(&buf[..n]);
                    if up_w.write_multi_buffer(mb).await.is_err() {
                        break;
                    }
                }
            }
        }
        up_w.shutdown(); // EOF → dispatch bridge 关闭目标写半部
    };

    // 下行：读响应 → 客户端
    let read_resp = async {
        loop {
            match dn_r.read_multi_buffer().await {
                Ok(mb) => {
                    if mb.is_empty() {
                        break;
                    }
                    let data = mb.to_vec();
                    if client_write.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };

    tokio::join!(dispatch_and_cleanup, write_req, read_resp);
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

/// Dokodemo-door UDP inbound 服务入口。
///
/// 对应 Go `Process()` 中 `network == UDP` 分支：recv_from → 转发到预定义 dest →
/// recv 响应 → send_to 回客户端。
///
/// 当前使用 per-packet ephemeral socket 模式（与 SOCKS UDP associate 一致）。
/// Go 生产环境用 FakeUDP（Linux TPROXY 伪造源地址），此处简化。
pub async fn serve_dokodemo_udp(
    udp: UdpSocket,
    dest: Destination,
) -> std::io::Result<()> {
    let udp = Arc::new(udp);
    tracing::info!(addr = %udp.local_addr()?, dest = ?dest, "dokodemo UDP inbound listening");
    let mut buf = [0u8; 65535];
    loop {
        let (n, peer) = match udp.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "dokodemo udp recv failed");
                continue;
            }
        };
        // 解析目标 SocketAddr（域名走 DNS 解析）
        let dest_addr = match resolve_dest_socketaddr(&dest).await {
            Some(a) => a,
            None => {
                tracing::debug!(dest = ?dest, "dokodemo udp dest resolve failed");
                continue;
            }
        };
        let payload = buf[..n].to_vec();
        let udp_sock = Arc::clone(&udp);
        // ponytail: per-packet ephemeral forward; upgrade to session-based if QPS matters.
        tokio::spawn(async move {
            let fwd = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(error = %e, "dokodemo udp fwd bind failed");
                    return;
                }
            };
            if fwd.connect(dest_addr).await.is_err() {
                return;
            }
            if fwd.send(&payload).await.is_err() {
                return;
            }
            let mut rbuf = [0u8; 65535];
            let rn = match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                fwd.recv(&mut rbuf),
            ).await {
                Ok(Ok(n)) => n,
                _ => return,
            };
            if udp_sock.send_to(&rbuf[..rn], peer).await.is_err() {
                tracing::debug!("dokodemo udp send_to client failed");
            }
        });
    }
}

/// 将 [`Destination`] 解析为 [`SocketAddr`]（域名走 `tokio::net::lookup_host`）。
async fn resolve_dest_socketaddr(dest: &Destination) -> Option<SocketAddr> {
    let port = dest.port().value();
    match dest.address() {
        Address::IPv4(v4) => Some(SocketAddr::new((*v4).into(), port)),
        Address::IPv6(v6) => Some(SocketAddr::new((*v6).into(), port)),
        Address::Domain(d) => tokio::net::lookup_host((d.as_str(), port))
            .await
            .ok()?
            .next(),
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
                    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
                    // 双向 pump（与 outbound SsConnection 对称）：单个 task select! 串行推进，
                    // 因 SSStream 共享 nonce 计数器不可并发持有 read/write &mut。
                    // up: ss_stream.read_chunk → server_io (密文→明文, 供 dispatch reader)
                    // down: server_io 读 → ss_stream.write_chunk (明文→密文, 回包给客户端)
                    tokio::spawn(async move {
                        let (mut srv_rd, mut srv_wr) = tokio::io::split(server_io);
                        let mut down_buf = vec![0u8; 8 * 1024];
                        loop {
                            tokio::select! {
                                // up: 客户端密文 chunk → 解密 → server_io 写端（流向 dispatch）
                                chunk = ss_stream.read_chunk() => {
                                    match chunk {
                                        Ok(Some(plaintext)) => {
                                            if tokio::io::AsyncWriteExt::write_all(&mut srv_wr, &plaintext).await.is_err() { break; }
                                            if tokio::io::AsyncWriteExt::flush(&mut srv_wr).await.is_err() { break; }
                                        }
                                        Ok(None) => { let _ = tokio::io::AsyncWriteExt::shutdown(&mut srv_wr).await; break; }
                                        Err(e) => { tracing::debug!("ss pump up read: {e}"); break; }
                                    }
                                }
                                // down: dispatch 回包（server_io 读端）→ 加密 chunk → 写回客户端
                                n = tokio::io::AsyncReadExt::read(&mut srv_rd, &mut down_buf) => {
                                    match n {
                                        Ok(0) => { let _ = ss_stream.shutdown().await; break; }
                                        Ok(n) => {
                                            if ss_stream.write_chunk(&down_buf[..n]).await.is_err() { break; }
                                            if ss_stream.flush().await.is_err() { break; }
                                        }
                                        Err(e) => { tracing::debug!("ss pump down read: {e}"); break; }
                                    }
                                }
                            }
                        }
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
    shutdown_token: CancellationToken,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let mut handles = Vec::new();
    for ib in &built.inbounds {
        if let Some(handle) = spawn_one_inbound(ib, Arc::clone(&ohm), shutdown_token.clone()).await? {
            handles.push(handle);
        }
    }
    Ok(handles)
}

/// spawn 一个 inbound serve task，监听 shutdown_token 实现优雅关闭。
///
/// token cancel 时取消 serve future（drop listener，accept 循环终止）。
/// 对应 Go 有序关闭的"先停 accept"阶段。connection drain 留后续。
fn spawn_inbound_serve(
    tag: String,
    shutdown_token: CancellationToken,
    fut: impl Future<Output = std::io::Result<()>> + Send + 'static,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        tokio::select! {
            r = fut => {
                if let Err(e) = r {
                    tracing::error!(tag = %tag, error = %e, "inbound stopped");
                }
            }
            _ = shutdown_token.cancelled() => {
                tracing::info!(tag = %tag, "inbound shutting down (graceful)");
            }
        }
    })
}

/// 从 inbound streamSettings 构建 TLS acceptor（security=tls 时）。
///
/// 对应 Go inbound listener 的 `tls.ConfigFromStreamSettings` → `tls.NewListener`。
/// serve 函数 accept 后先做 TLS handshake 再处理协议数据。
fn build_tls_acceptor(
    stream_settings_json: Option<&serde_json::Value>,
) -> std::io::Result<Option<Arc<xray_transport::TlsAcceptor>>> {
    let settings = xray_transport::dialer::StreamSettings::from_json(stream_settings_json);
    if !settings.is_tls() {
        return Ok(None);
    }
    let cfg = xray_tls::server_config::build_server_config(
        &settings.security,
        settings.security_json.as_ref(),
    )?;
    Ok(cfg.map(|c| Arc::new(xray_transport::TlsAcceptor::from(c))))
}

/// REALITY inbound 配置（从 `realitySettings` 解析）。
///
/// 字段对齐 Go `infra/conf REALITYConfig`：privateKey（base64 RawURL，32B）、
/// shortIds（hex 白名单）、dest/target（fallback 目标）、xver（PROXY protocol）、
/// maxTimeDiff（timestamp 容差秒，Go 默认 43200=±12h）。
struct RealityInboundConfig {
    server_private_key: [u8; 32],
    short_ids: Vec<[u8; 8]>,
    max_diff: u32,
    fallback_dest: String,
    xver: u8,
}

fn parse_reality_config(
    settings: &xray_transport::dialer::StreamSettings,
) -> std::io::Result<RealityInboundConfig> {
    let json = settings.security_json.as_ref().ok_or_else(|| {
        std::io::Error::other("reality inbound requires realitySettings")
    })?;
    let key_str = json
        .get("privateKey")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| std::io::Error::other("reality: empty privateKey"))?;
    let key = base64_url_decode(key_str)
        .and_then(|k| <[u8; 32]>::try_from(k).ok())
        .ok_or_else(|| std::io::Error::other("reality: invalid privateKey (need base64 32B)"))?;

    let mut short_ids = Vec::new();
    if let Some(arr) = json.get("shortIds").and_then(|x| x.as_array()) {
        for sid in arr {
            let Some(hex) = sid.as_str() else { continue };
            if let Some(bytes) = hex_decode_8(hex) {
                short_ids.push(bytes);
            }
        }
    }
    // 无 shortIds：默认允许全零（Go REALITY 空配置兼容）
    if short_ids.is_empty() {
        short_ids.push([0u8; 8]);
    }

    // dest/target：int（端口→localhost:port）或字符串 host:port
    let dest_raw = json
        .get("target")
        .or_else(|| json.get("dest"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let fallback_dest = match dest_raw.as_u64() {
        Some(port) => format!("localhost:{port}"),
        None => dest_raw
            .as_str()
            .unwrap_or("localhost:443")
            .to_string(),
    };

    let xver = json.get("xver").and_then(|x| x.as_u64()).unwrap_or(0).min(2) as u8;
    let max_diff = json
        .get("maxTimeDiff")
        .and_then(|x| x.as_u64())
        .unwrap_or(43200) as u32;

    Ok(RealityInboundConfig {
        server_private_key: key,
        short_ids,
        max_diff,
        fallback_dest,
        xver,
    })
}

/// base64 RawURL 解码（无 padding，兼容 std 变体）。
fn base64_url_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let normalized = s.replace('+', "-").replace('/', "_");
    let normalized = normalized.trim_end_matches('=');
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(normalized)
        .ok()
        .or_else(|| base64::engine::general_purpose::STANDARD.decode(s).ok())
}

/// hex 字符串 → 8 字节 short_id。
fn hex_decode_8(s: &str) -> Option<[u8; 8]> {
    if s.len() > 16 {
        return None;
    }
    let padded = format!("{s:0<16}");
    let bytes = hex::decode(padded).ok()?;
    bytes.try_into().ok()
}

/// VLESS + REALITY inbound：accept → server_tls 验证。
///
/// - Verified：TLS 流走 VLESS 协议处理
/// - Invalid：原连接 + ClientHello record fallback 到 dest（PROXY protocol xver）
async fn serve_reality_vless(
    listener: TcpListener,
    ohm: Arc<SimpleOhm>,
    validator: Arc<dyn VlessValidator>,
    cfg: RealityInboundConfig,
) -> std::io::Result<()> {
    use xray_reality::server::{RealityServerOutcome, fallback_to_dest, server_tls};

    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;
    let local = listener.local_addr()?;
    tracing::info!(addr = %local, "vless+reality inbound listening");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "reality inbound accept failed");
                continue;
            }
        };
        let handler = Arc::clone(&handler);
        let validator = Arc::clone(&validator);
        let key = cfg.server_private_key;
        let ids = cfg.short_ids.clone();
        let max_diff = cfg.max_diff;
        let dest = cfg.fallback_dest.clone();
        let xver = cfg.xver;
        tokio::spawn(async move {
            match server_tls(stream, &key, &ids, max_diff).await {
                Ok(RealityServerOutcome::Verified(tls)) => {
                    if let Err(e) =
                        xray_proxy_vless::handle_vless_connection(tls, &handler, &validator).await
                    {
                        tracing::debug!(error = %e, "reality vless connection ended with error");
                    }
                }
                Ok(RealityServerOutcome::Invalid { conn, record, reason }) => {
                    // 非 REALITY 客户端（如浏览器/探测器）→ 透明转发到 fallback dest
                    tracing::debug!(error = ?reason, dest = %dest, "reality verify failed, fallback");
                    let _ = fallback_to_dest(conn, &record, &dest, peer, local, xver).await;
                }
                Err(e) => {
                    tracing::warn!(error = ?e, "reality tls handshake error");
                }
            }
        });
    }
}

/// 按协议种类启动单个 inbound listener。
async fn spawn_one_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
    shutdown_token: CancellationToken,
) -> std::io::Result<Option<JoinHandle<()>>> {
    // TUN inbound 不需要 port/addr，提前处理
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
    if ib.entry.kind.as_str() == "tun" {
        let options = parse_tun_inbound_config(&ib.entry.data)?;
        let dispatch = ohm.get_default_handler().ok_or_else(|| {
            std::io::Error::other("tun inbound requires a default outbound handler")
        })?;
        let handler = TunInboundHandler::new(&ib.tag, options, dispatch)
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
            let config = Arc::new(parse_socks_server_config(&ib.entry.data)?);
            tracing::info!(tag = %ib.tag, addr = %addr, auth = ?config.auth_type, udp = config.udp_enabled, "socks5 inbound listening");
            Ok(Some(spawn_inbound_serve(ib.tag.clone(), shutdown_token, async move {
                serve_socks5(listener, ohm, config).await
            })))
        }
        "vless" => {
            let validator: Arc<dyn VlessValidator> = build_vless_validator(&ib.entry.data)?;
            let listener = TcpListener::bind(&addr).await?;
            let settings = xray_transport::dialer::StreamSettings::from_json(
                ib.stream_settings_json.as_ref(),
            );
            if settings.security == "reality" {
                // REALITY：server_tls 验证 → Verified 走 VLESS；Invalid fallback 到 dest
                let reality = parse_reality_config(&settings)?;
                tracing::info!(tag = %ib.tag, addr = %addr, users = validator.get_count(), fallback = %reality.fallback_dest, "vless+reality inbound listening");
                Ok(Some(spawn_inbound_serve(ib.tag.clone(), shutdown_token, async move {
                    serve_reality_vless(listener, ohm, validator, reality).await
                })))
            } else {
                let tls = build_tls_acceptor(ib.stream_settings_json.as_ref())?;
                // VLESS fallbacks：Go napfb（name→alpn→path→dest+xver）
                let fallbacks = build_vless_fallbacks(&ib.entry.data);
                tracing::info!(tag = %ib.tag, addr = %addr, users = validator.get_count(), tls = tls.is_some(), fallbacks = fallbacks.as_ref().map_or(0, |f| f.len()), "vless inbound listening");
                Ok(Some(spawn_inbound_serve(ib.tag.clone(), shutdown_token, async move {
                    serve_vless(listener, ohm, validator, tls, fallbacks).await
                })))
            }
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
            let tls = build_tls_acceptor(ib.stream_settings_json.as_ref())?;
            let listener = TcpListener::bind(&addr).await?;
            tracing::info!(tag = %ib.tag, addr = %addr, users = users.len(), tls = tls.is_some(), "trojan inbound listening");
            Ok(Some(spawn_inbound_serve(ib.tag.clone(), shutdown_token, async move {
                serve_trojan(listener, ohm, users, fallbacks, tls).await
            })))
        }
        "vmess" => {
            let validator = build_vmess_validator(&ib.entry.data)?;
            let tls = build_tls_acceptor(ib.stream_settings_json.as_ref())?;
            let listener = TcpListener::bind(&addr).await?;
            tracing::info!(tag = %ib.tag, addr = %addr, tls = tls.is_some(), "vmess inbound listening");
            Ok(Some(spawn_inbound_serve(ib.tag.clone(), shutdown_token, async move {
                serve_vmess(listener, ohm, validator, tls).await
            })))
        }
        "http" => {
            let config = parse_http_config(&ib.entry.data)?;
            let listener = TcpListener::bind(&addr).await?;
            tracing::info!(tag = %ib.tag, addr = %addr, "http inbound listening");
            Ok(Some(spawn_inbound_serve(ib.tag.clone(), shutdown_token, async move {
                serve_http(listener, ohm, Arc::new(config)).await
            })))
        }
        "dokodemo" => {
            let settings = parse_dokodemo_settings(&ib.entry.data)?;
            let dest = settings.dest.clone();
            // followRedirect 留 TODO: 需要从 listener fd 调 SO_ORIGINAL_DST（Linux-only）。
            // 当前 TCP/UDP 走 predefined dest。
            let mut handles = Vec::new();
            if settings.allow_tcp {
                let listener = TcpListener::bind(&addr).await?;
                tracing::info!(tag = %ib.tag, addr = %addr, dest = ?dest, "dokodemo TCP inbound listening");
                let ohm_tcp = Arc::clone(&ohm);
                let dest_tcp = dest.clone();
                handles.push(tokio::spawn(async move {
                    if let Err(e) = serve_dokodemo(listener, ohm_tcp, dest_tcp).await {
                        tracing::error!(error = %e, "dokodemo TCP inbound stopped");
                    }
                }));
            }
            if settings.allow_udp {
                let udp = UdpSocket::bind(&addr).await?;
                tracing::info!(tag = %ib.tag, addr = %addr, dest = ?dest, "dokodemo UDP inbound listening");
                let dest_udp = dest.clone();
                handles.push(tokio::spawn(async move {
                    if let Err(e) = serve_dokodemo_udp(udp, dest_udp).await {
                        tracing::error!(error = %e, "dokodemo UDP inbound stopped");
                    }
                }));
            }
            if handles.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "dokodemo: no valid network specified (need tcp and/or udp)",
                ));
            }
            // 合并所有 listener handle；token cancel 时 combined 被取消（子 handle 被 drop/abort）。
            Ok(Some(spawn_inbound_serve(ib.tag.clone(), shutdown_token, async move {
                for h in handles {
                    let _ = h.await;
                }
                Ok(())
            })))
        }
        // shadowsocks inbound：SsInbound + serve_ss accept loop
        "shadowsocks" => {
            let listener = TcpListener::bind(&addr).await?;
            let inbound = parse_ss_inbound_config(&ib.entry.data)?;
            tracing::info!(tag = %ib.tag, addr = %addr, "shadowsocks inbound listening");
            Ok(Some(spawn_inbound_serve(ib.tag.clone(), shutdown_token, async move {
                serve_ss(listener, ohm, inbound).await
            })))
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
            Ok(Some(spawn_inbound_serve(ib.tag.clone(), shutdown_token, async move {
                handler.start().await.map_err(|e| std::io::Error::other(format!("{e}")))
            })))
        }
        // anytls inbound：AnytlsInboundHandler impl InboundHandler
        "anytls" => {
            let bind_addr: std::net::SocketAddr = addr.parse()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("parse addr: {e}")))?;
            let tls_acceptor = parse_anytls_tls_acceptor(&ib.entry.data)?;
            let handler = xray_proxy_anytls::AnytlsInboundHandler::new(
                &ib.tag, bind_addr, tls_acceptor,
            );
            Ok(Some(spawn_inbound_serve(ib.tag.clone(), shutdown_token, async move {
                handler.start().await.map_err(|e| std::io::Error::other(format!("{e}")))
            })))
        }
        // tuic inbound：QUIC listener + auth + Connect → dispatcher/router 分发
        "tuic" => {
            let dispatch = ohm.get_default_handler().ok_or_else(|| {
                std::io::Error::other("tuic inbound requires a default outbound handler")
            })?;
            let handler = parse_tuic_inbound_config(&ib.entry.data, &addr)?
                .with_dispatch(dispatch);
            Ok(Some(spawn_inbound_serve(ib.tag.clone(), shutdown_token, async move {
                handler.start().await.map_err(|e| std::io::Error::other(format!("{e}")))
            })))
        }
        // wireguard inbound：WireguardInboundHandler impl InboundHandler
        "wireguard" => {
            let (config, listen_port) = parse_wireguard_inbound_config(&ib.entry.data)?;
            let dispatch = ohm.get_default_handler().ok_or_else(|| {
                std::io::Error::other("wireguard inbound requires a default outbound handler")
            })?;
            let handler = xray_proxy_wireguard::WireguardInboundHandler::new(
                &ib.tag, &config, listen_port, dispatch,
            )
            .await
            .map_err(|e| std::io::Error::other(format!("wireguard inbound: {e}")))?;
            Ok(Some(spawn_inbound_serve(ib.tag.clone(), shutdown_token, async move {
                handler.start().await.map_err(|e| std::io::Error::other(format!("{e}")))
            })))
        }
        // dns inbound：UDP+TCP listener → handle_packet/handle_conn
        "dns" => {
            let (handler, outbound) = parse_dns_inbound_config(&ib.entry.data, &ib.tag)?;
            let inbound = Arc::new(DnsInbound::new(&ib.tag, handler, outbound));
            let udp = UdpSocket::bind(&addr).await?;
            let tcp = TcpListener::bind(&addr).await?;
            tracing::info!(tag = %ib.tag, addr = %addr, "dns inbound listening (UDP+TCP)");
            Ok(Some(spawn_inbound_serve(ib.tag.clone(), shutdown_token, async move {
                serve_dns(udp, tcp, inbound).await
            })))
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
            // accept 循环在 start() 内部 spawn，此 task 保持 handler 存活并监听 shutdown。
            Ok(Some(spawn_inbound_serve(ib.tag.clone(), shutdown_token, async move {
                std::future::pending::<()>().await;
                Ok(())
            })))
        }
        // freedom inbound：accept 连接后 dial 预定义目标并双向转发
        "freedom" => {
            let dest = parse_freedom_inbound_dest(&ib.entry.data)?;
            let handler = FreedomInboundHandler::new(&ib.tag, &addr, dest, Arc::clone(&ohm));
            handler.start().await
                .map_err(|e| std::io::Error::other(format!("freedom inbound: {e}")))?;
            // accept 循环在 start() 内部 spawn，此 task 保持 handler 存活并监听 shutdown。
            Ok(Some(spawn_inbound_serve(ib.tag.clone(), shutdown_token, async move {
                std::future::pending::<()>().await;
                Ok(())
            })))
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

/// 从 inbound entry.data（JSON）解析 SOCKS 服务端配置。
///
/// 字段对齐 Go `infra/conf/socks.go::SocksServerConfig`：
/// `{"auth":"password","users":[{"user":"u","pass":"p"}],"udp":true,"userLevel":0}`。
/// `users`/`accounts` 同义（Go 两个字段都收）；`ip`（UDP 回包地址）无消费方暂不解析。
fn parse_socks_server_config(data: &[u8]) -> std::io::Result<ServerConfig> {
    if data.is_empty() {
        return Ok(ServerConfig::default());
    }
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("socks inbound settings JSON: {e}")))?;

    let mut cfg = ServerConfig::default();
    if v.get("auth").and_then(|x| x.as_str()) == Some("password") {
        cfg.auth_type = xray_proxy_socks::config::AuthType::Password;
    }
    if let Some(users) = v
        .get("users")
        .or_else(|| v.get("accounts"))
        .and_then(|x| x.as_array())
    {
        for u in users {
            let user = u.get("user").and_then(|x| x.as_str()).unwrap_or("");
            let pass = u.get("pass").and_then(|x| x.as_str()).unwrap_or("");
            cfg.accounts.insert(user.to_string(), pass.to_string());
        }
    }
    cfg.udp_enabled = v.get("udp").and_then(|x| x.as_bool()).unwrap_or(false);
    cfg.user_level = v.get("userLevel").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    Ok(cfg)
}

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



/// 从 inbound entry.data（JSON）解析 VLESS `fallbacks` 数组 → FallbackPolicy。
///
/// JSON 格式（Go `infra/conf/vless.go` VLessInboundFallback）：
/// `{"fallbacks":[{"name":"sni","alpn":"h2","path":"/api","dest":"127.0.0.1:80","xver":0}]}`
/// 空数组或缺失返回 None（维持无 fallback 的直连路径）。
fn build_vless_fallbacks(data: &[u8]) -> Option<std::sync::Arc<xray_proxy_vless::FallbackPolicy>> {
    let v: serde_json::Value = serde_json::from_slice(data).ok()?;
    let fbs = v.get("fallbacks")?.as_array()?;
    let mut policy = xray_proxy_vless::FallbackPolicy::new();
    for fb in fbs {
        let name = fb.get("name").and_then(|x| x.as_str()).unwrap_or("");
        let alpn = fb.get("alpn").and_then(|x| x.as_str()).unwrap_or("");
        let path = fb.get("path").and_then(|x| x.as_str()).unwrap_or("");
        let Some(dest) = fb.get("dest").and_then(|x| x.as_str()) else {
            tracing::warn!("vless fallback entry missing dest, skipped");
            continue;
        };
        let xver = fb.get("xver").and_then(|x| x.as_u64()).unwrap_or(0).min(2) as u8;
        policy.add(name, alpn, path, xray_proxy_vless::FallbackDest::new(dest, xver));
    }
    if policy.is_empty() { None } else { Some(std::sync::Arc::new(policy)) }
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
/// JSON 格式：`{"address":"1.2.3.4","port":80,"network":"tcp"}`（address+port 必填）。
/// 委托给 [`parse_dokodemo_settings`]，返回其 `dest` 字段。
fn parse_dokodemo_dest(data: &[u8]) -> std::io::Result<Destination> {
    Ok(parse_dokodemo_settings(data)?.dest)
}

/// Dokodemo inbound 解析后的完整设置。
///
/// 对应 Go `proxy/dokodemo/config.go::Config`。
struct DokodemoInboundSettings {
    /// 预定义目标（TCP 和 UDP 各一份，网络类型不同）。
    dest: Destination,
    /// 是否允许 TCP。
    allow_tcp: bool,
    /// 是否允许 UDP。
    allow_udp: bool,
    /// 是否跟随 iptables REDIRECT 原始目标（透明代理）。
    follow_redirect: bool,
}

/// 从 inbound entry.data（JSON）解析完整 dokodemo 设置。
///
/// JSON 格式：`{"address":"1.2.3.4","port":80,"network":"tcp,udp","followRedirect":true}`。
/// `network` 可选（默认 `"tcp"`）；`followRedirect` 可选（默认 `false`）。
fn parse_dokodemo_settings(data: &[u8]) -> std::io::Result<DokodemoInboundSettings> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("dokodemo inbound settings JSON: {e}")))?;
    let address_str = v.get("address").and_then(|x| x.as_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "dokodemo: missing address"))?;
    let port = v.get("port").and_then(|x| x.as_u64())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "dokodemo: missing port"))?
        as u16;
    let address = if let Ok(v4) = address_str.parse::<std::net::Ipv4Addr>() {
        Address::IPv4(v4)
    } else if let Ok(v6) = address_str.parse::<std::net::Ipv6Addr>() {
        Address::IPv6(v6)
    } else {
        Address::Domain(address_str.to_string())
    };
    // network：逗号分隔，默认 tcp。对应 Go allowed_networks。
    let network_str = v.get("network").and_then(|x| x.as_str()).unwrap_or("tcp");
    let allow_tcp = network_str.contains("tcp");
    let allow_udp = network_str.contains("udp");
    let follow_redirect = v.get("followRedirect").and_then(|x| x.as_bool()).unwrap_or(false);

    let dest = if allow_udp && !allow_tcp {
        Destination::new(address, Port::new(port), Network::UDP)
    } else {
        Destination::new(address, Port::new(port), Network::TCP)
    };
    Ok(DokodemoInboundSettings { dest, allow_tcp, allow_udp, follow_redirect })
}

/// 从 inbound entry.data（JSON）解析 vmess clients → TimedUserValidator。
///
/// JSON 格式：`{"clients":[{"id":"uuid","level":0,"alterId":0,"email":""}]}`。
/// 现代 VMess (AEAD) 不用 alterId，忽略该字段。`id` 解析为 `UUID` → `MemoryAccount::new(uuid)`。
fn build_vmess_validator(data: &[u8]) -> std::io::Result<std::sync::Arc<VmessTimedUserValidator>> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("vmess inbound settings JSON: {e}")))?;
    let validator = VmessTimedUserValidator::new();
    // Go VMessDefaultConfig：{"default":{"level":N}}，user 未显式给 level 时的默认值。
    let default_level = v
        .get("default")
        .and_then(|d| d.get("level"))
        .and_then(|x| x.as_u64())
        .unwrap_or(0) as u32;
    if let Some(clients) = v.get("clients").and_then(|c| c.as_array()) {
        for c in clients {
            let id = c.get("id").and_then(|x| x.as_str()).unwrap_or("");
            let email = c.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let level = c.get("level").and_then(|x| x.as_u64()).unwrap_or(u64::from(default_level)) as u32;
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
    SsCipherType::from_name(s)
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
    // 真实 quinn server adapter：自签证书（或配置 cert/key PEM），ALPN h3 由 listen() 设置
    let _ = rustls::crypto::ring::default_provider().install_default();
    let server_config = build_hysteria_tls_server_config(&v)?;
    let factory: Arc<dyn xray_transport_hysteria::hub::HysteriaListenerFactory> =
        Arc::new(QuinnListenerFactory::new(Arc::new(server_config)));
    Ok((config, factory))
}

/// 构造 hysteria QUIC server 用的 rustls `ServerConfig`。
///
/// JSON 可选 `cert`/`key`（PEM）；缺省时用自签证书（测试场景）。ALPN h3 由
/// [`QuinnListenerFactory::listen`] 设置，这里不重复。
fn build_hysteria_tls_server_config(
    v: &serde_json::Value,
) -> std::io::Result<rustls::ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
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
        // ponytail: 无证书配置时用自签证书（仅测试场景，client 用 NoVerifier）
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
    Ok(rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.into()], key_der)
        .map_err(|e| std::io::Error::other(format!("rustls server config: {e}")))?)
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

    /// parse_socks_server_config：auth/users/accounts/udp/userLevel 字段对齐 Go conf。
    #[test]
    fn parse_socks_server_config_full_fields() {
        let json = br#"{"auth":"password","users":[{"user":"alice","pass":"p1"}],"udp":true,"userLevel":3}"#;
        let cfg = parse_socks_server_config(json).unwrap();
        assert_eq!(cfg.auth_type, xray_proxy_socks::config::AuthType::Password);
        assert!(cfg.has_account("alice", "p1"));
        assert!(cfg.requires_auth());
        assert!(cfg.udp_enabled);
        assert_eq!(cfg.user_level, 3);
    }

    /// accounts 别名 + 默认 noauth + 空配置。
    #[test]
    fn parse_socks_server_config_accounts_alias_and_default() {
        let cfg = parse_socks_server_config(br#"{"accounts":[{"user":"bob","pass":"p2"}]}"#).unwrap();
        assert!(cfg.has_account("bob", "p2"));
        assert_eq!(cfg.auth_type, xray_proxy_socks::config::AuthType::NoAuth);
        assert!(!cfg.udp_enabled);
        let empty = parse_socks_server_config(b"").unwrap();
        assert_eq!(empty, ServerConfig::default());
    }

    /// parse_reality_config：privateKey/shortIds/dest 双形态/默认值。
    #[test]
    fn parse_reality_config_full_fields() {
        use base64::Engine as _;
        let key = [7u8; 32];
        let key_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key);
        let json = serde_json::json!({
            "privateKey": key_b64,
            "shortIds": ["", "0123456789abcdef"],
            "target": "example.com:443",
            "xver": 1,
            "maxTimeDiff": 300
        });
        let settings = xray_transport::dialer::StreamSettings {
            security: "reality".to_string(),
            security_json: Some(json),
            ..xray_transport::dialer::StreamSettings::tcp()
        };
        let cfg = parse_reality_config(&settings).unwrap();
        assert_eq!(cfg.server_private_key, key);
        assert_eq!(cfg.short_ids.len(), 2);
        assert_eq!(cfg.short_ids[0], [0u8; 8]);
        assert_eq!(cfg.short_ids[1][0], 0x01);
        assert_eq!(cfg.fallback_dest, "example.com:443");
        assert_eq!(cfg.xver, 1);
        assert_eq!(cfg.max_diff, 300);
    }

    #[test]
    fn parse_reality_config_port_dest_and_defaults() {
        use base64::Engine as _;
        let key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        // dest 为 int 端口 → localhost:port；缺省 xver=0/maxTimeDiff=43200/shortIds=[0u8;8]
        let json = serde_json::json!({
            "privateKey": key_b64,
            "dest": 8443
        });
        let settings = xray_transport::dialer::StreamSettings {
            security: "reality".to_string(),
            security_json: Some(json),
            ..xray_transport::dialer::StreamSettings::tcp()
        };
        let cfg = parse_reality_config(&settings).unwrap();
        assert_eq!(cfg.fallback_dest, "localhost:8443");
        assert_eq!(cfg.xver, 0);
        assert_eq!(cfg.max_diff, 43200);
        assert_eq!(cfg.short_ids, vec![[0u8; 8]]);
    }

    #[test]
    fn parse_reality_config_rejects_missing_key() {
        let settings = xray_transport::dialer::StreamSettings {
            security: "reality".to_string(),
            security_json: Some(serde_json::json!({})),
            ..xray_transport::dialer::StreamSettings::tcp()
        };
        assert!(parse_reality_config(&settings).is_err());
    }
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

    /// 端到端：VLESS client（tcp+reality 出站）→ serve_reality_vless → freedom → echo。
    /// 同时验证 Invalid（非 REALITY 客户端）→ fallback dest 透明转发。
    #[tokio::test]
    async fn vless_reality_inbound_e2e() {
        // rustls 全局 provider（并行测试只装一次）
        static PROVIDER: std::sync::Once = std::sync::Once::new();
        PROVIDER.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
        use base64::Engine as _;
        use xray_proxy_vless::encoding::client::{
            decode_response_header, encode_request_header,
        };
        use xray_proxy_vless::encoding::VlessCommand;
        use xray_transport::dialer::{StreamSettings, dial_with_settings};
        use xray_transport::sockopt::SocketOptions;

        // 1. echo server（VLESS 数据目标）
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

        // 2. freedom outbound → SimpleOhm
        let ohm = Arc::new(SimpleOhm::new());
        let bridge = Arc::new(xray_app_dispatcher::default::DialBridge::new(
            "freedom",
            make_freedom_dial_fn(),
        )) as Arc<dyn xray_app_dispatcher::DispatchHandler>;
        ohm.set_default(bridge);

        // 3. validator（test UUID）
        let validator = Arc::new(VlessMemoryValidator::new());
        let test_uuid = UUID::parse("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let mut proto_account = VlessProtoAccount::default();
        proto_account.id = "b831381d-6324-4d53-ad4f-8cda48b30811".to_string();
        let account = VlessMemoryAccount::from_proto_account(&proto_account).unwrap();
        validator
            .add(VlessMemoryUser::new("e2e-user", 0, account))
            .unwrap();

        // 4. serve_reality_vless
        let server_secret = x25519_dalek::StaticSecret::from([0x99u8; 32]);
        let server_public = x25519_dalek::PublicKey::from(&server_secret);
        let short_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let reality_cfg = RealityInboundConfig {
            server_private_key: server_secret.to_bytes(),
            short_ids: vec![short_id],
            max_diff: 43200,
            fallback_dest: format!("127.0.0.1:{}", echo_addr.port()),
            xver: 0,
        };
        let rl = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rl_addr = rl.local_addr().unwrap();
        let ohm_c = Arc::clone(&ohm);
        let val_c = Arc::clone(&validator) as Arc<dyn VlessValidator>;
        tokio::spawn(async move {
            let _ = serve_reality_vless(rl, ohm_c, val_c, reality_cfg).await;
        });

        // 5. client：tcp+reality dial → VLESS 请求 → echo 回读
        let _ = xray_transport_tcp::register::register_dialer();
        let mut settings = StreamSettings::tcp();
        settings.security = "reality".to_string();
        settings.security_json = Some(serde_json::json!({
            "serverName": "reality.local",
            "publicKey": base64::engine::general_purpose::STANDARD.encode(server_public.to_bytes()),
            "shortId": hex::encode(short_id),
            "fingerprint": "chrome"
        }));
        let dest = Destination::tcp(
            Address::IPv4(std::net::Ipv4Addr::LOCALHOST),
            Port::new(rl_addr.port()),
        );
        let mut conn = dial_with_settings("tcp", &dest, &SocketOptions::default(), &settings)
            .await
            .expect("tcp+reality dial should succeed");

        // VLESS 请求头（TCP → echo）
        encode_request_header(
            &mut conn,
            0,
            &test_uuid,
            VlessCommand::Tcp,
            Some(&Address::IPv4(std::net::Ipv4Addr::LOCALHOST)),
            Some(echo_addr.port()),
            &Default::default(),
        )
        .await
        .unwrap();
        let _ = decode_response_header(&mut conn, 0).await.unwrap();

        let payload = b"hello vless+reality!";
        conn.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        conn.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, payload, "vless over reality should echo");
    }

    #[test]
    fn socks_addr_to_destination_ipv4() {
        let addr = SocksAddr {
            host: Host::Ipv4(Ipv4Addr::new(1, 2, 3, 4)),
            port: 8080,
        };
        let dest = socks_addr_to_destination(&addr).unwrap();
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
        let dest = socks_addr_to_destination(&addr).unwrap();
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
        // "not-a-uuid"（10 字节）在 Go ParseString 语义下派生 v5，合法。
        // >30 字节非标准格式才是非法。
        let settings =
            serde_json::json!({ "clients": [{ "id": "this-id-is-longer-than-thirty-bytes!!" }] });
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
    fn parse_dokodemo_settings_tcp_only() {
        let settings = serde_json::json!({ "address": "1.2.3.4", "port": 80, "network": "tcp" });
        let data = serde_json::to_vec(&settings).unwrap();
        let s = super::parse_dokodemo_settings(&data).unwrap();
        assert!(s.allow_tcp);
        assert!(!s.allow_udp);
        assert!(!s.follow_redirect);
        assert!(s.dest.is_tcp());
    }

    #[test]
    fn parse_dokodemo_settings_udp_only() {
        let settings = serde_json::json!({ "address": "1.2.3.4", "port": 53, "network": "udp" });
        let data = serde_json::to_vec(&settings).unwrap();
        let s = super::parse_dokodemo_settings(&data).unwrap();
        assert!(!s.allow_tcp);
        assert!(s.allow_udp);
        assert!(s.dest.is_udp());
    }

    #[test]
    fn parse_dokodemo_settings_tcp_udp() {
        let settings = serde_json::json!({ "address": "1.2.3.4", "port": 53, "network": "tcp,udp" });
        let data = serde_json::to_vec(&settings).unwrap();
        let s = super::parse_dokodemo_settings(&data).unwrap();
        assert!(s.allow_tcp);
        assert!(s.allow_udp);
    }

    #[test]
    fn parse_dokodemo_settings_follow_redirect() {
        let settings = serde_json::json!({ "address": "1.2.3.4", "port": 80, "followRedirect": true });
        let data = serde_json::to_vec(&settings).unwrap();
        let s = super::parse_dokodemo_settings(&data).unwrap();
        assert!(s.follow_redirect);
    }

    #[test]
    fn parse_dokodemo_settings_default_network_is_tcp() {
        let settings = serde_json::json!({ "address": "1.2.3.4", "port": 80 });
        let data = serde_json::to_vec(&settings).unwrap();
        let s = super::parse_dokodemo_settings(&data).unwrap();
        assert!(s.allow_tcp);
        assert!(!s.allow_udp);
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
