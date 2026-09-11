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
use xray_transport::system_listener::InboundTcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use xray_conf::{BuiltConfig, BuiltInbound};
// P1-B: vless/trojan inbound 集成
use std::collections::HashMap;
use xray_proto::xray::proxy::vless::Account as VlessProtoAccount;
use xray_proxy_trojan::{serve_trojan, MemoryAccount as TrojanMemoryAccount, MemoryUser as TrojanMemoryUser, fallback::{Fallback, FallbackPolicy}};
use xray_proxy_vless::{serve_vless, MemoryAccount as VlessMemoryAccount, MemoryUser as VlessMemoryUser, MemoryValidator as VlessMemoryValidator, Validator as VlessValidator, VlessInboundOptions};
use xray_proxy_vmess::{serve_vmess, MemoryAccount as VmessMemoryAccount, MemoryUser as VmessMemoryUser, TimedUserValidator as VmessTimedUserValidator, Validator as VmessValidator, VmessError};
use xray_common::uuid::UUID;
// tdy: http + dokodemo inbound 集成
use xray_proxy_http::ServerConfig as HttpServerConfig;
use xray_proxy_http::server::{
    http_server_handshake, extract_request_path, build_forwarded_request, HandshakeResult,
};
use xray_app_dispatcher::{DispatchHandler, UdpDispatchSession};
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
    listener: InboundTcpListener,
    ohm: Arc<SimpleOhm>,
    config: Arc<ServerConfig>,
    handshake_timeout: Option<std::time::Duration>,
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
            if let Err(e) =
                handle_connection(stream, peer, &config, &handler, handshake_timeout).await
            {
                // Go proxyman/worker.go:124：连接结束错误统一 LogInfo("connection ends")。
                tracing::info!(peer = %peer, error = %e, "socks5 connection ended with error");
            }
        });

    }
}

/// 处理单个 SOCKS 连接：handshake → dispatch（TCP CONNECT）或 UDP relay。
///
/// 泛型流：TcpStream（TCP 监听）与 UDS `Box<dyn Connection>`（vodx unix
/// inbound）共用；`socks_handshake` 本就是 AsyncRead+AsyncWrite 泛型。
async fn handle_connection<S>(
    mut stream: S,
    peer: std::net::SocketAddr,
    config: &ServerConfig,
    handler: &Arc<dyn xray_app_dispatcher::DispatchHandler>,
    handshake_timeout: Option<std::time::Duration>,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // 1. SOCKS 握手（兼容 4/4a/5）；受握手限时约束（Go proxy/socks/server.go
    // Process: SetReadDeadline(policy().Timeouts.Handshake)，超时断开；仅覆盖
    // 握手阶段，dispatch 数据路径不限时）
    let socks_req = {
        let handshake_fut = socks_handshake(&mut stream, config);
        let res = match handshake_timeout {
            Some(d) => tokio::time::timeout(d, handshake_fut).await,
            None => Ok(handshake_fut.await),
        };
        match res {
            Ok(r) => r.map_err(|e| std::io::Error::other(format!("socks handshake: {e}")))?,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "socks handshake timeout",
                ))
            }
        }
    };

    match socks_req {
        SocksRequest::UdpAssociate(_, relay_socket) => {
            // UDP relay：spawn pump，保持 TCP 控制连接直到客户端断开
            // handler 是 &Arc 引用，spawn 的 future 需 'static —— spawn 前 clone
            let udp_handler = Arc::clone(handler);
            let relay = tokio::spawn(async move {
                let _ = handle_udp_associate(relay_socket, udp_handler).await;
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
            let dest = socks_addr_to_destination(&addr, Network::TCP);
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
            // access log（bd 4uu）：from=客户端源地址（对应 Go socks server ctx
            // ContextWithAccessMessage{From: conn.RemoteAddr()}）；email 留空（无认证），
            // inbound_tag 由 InboundDispatchHandler 补齐。
            let access = xray_app_dispatcher::AccessContext {
                from: peer.to_string(),
                ..Default::default()
            };
            let _ = handler.dispatch_with_access(&dest, link, access).await;
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
/// 对应 Go `mux.Server.OnTransport(link.Reader, link.Writer)`。socks/http 在
/// 协议层内联调用；wiring 的 [`crate::wiring::MuxCarrierHandler`] 装饰器对
/// 其余 inbound（vless/trojan/ss/…）统一按 destination 判定调用。
pub(crate) async fn handle_mux_inbound_link(link: Link, handler: Arc<dyn xray_app_dispatcher::DispatchHandler>) {
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

/// `SocksAddr` → `Destination`（`network` 指定 TCP/UDP）。
///
/// `Host::Ipv4` → `Address::IPv4`，`Ipv6` → `Address::IPv6`，`Domain` → `Address::Domain`。
fn socks_addr_to_destination(addr: &SocksAddr, network: Network) -> Destination {
    let address = match &addr.host {
        Host::Ipv4(ip) => Address::IPv4(*ip),
        Host::Ipv6(ip) => Address::IPv6(*ip),
        Host::Domain(d) => Address::Domain(d.clone()),
    };
    Destination::new(address, Port::new(addr.port), network)
}

/// `Destination` → `SocksAddr`（UDP 回包帧的 BND.ADDR 来源地址）。
fn destination_to_socks_addr(dest: &Destination) -> SocksAddr {
    let host = match dest.address() {
        Address::IPv4(ip) => Host::Ipv4(*ip),
        Address::IPv6(ip) => Host::Ipv6(*ip),
        Address::Domain(d) => Host::Domain(d.clone()),
    };
    SocksAddr {
        host,
        port: dest.port().value(),
    }
}

/// SOCKS5 UDP ASSOCIATE relay pump。
///
/// 对应 Go `proxy/socks/server.go::handleUDPPayload`。所有数据报经
/// [`UdpDispatchSession`] 走 dispatcher（routing 规则选 outbound），域名目标
/// 原样透传由 outbound 解析。当客户端 TCP 控制连接关闭时，调用方 abort 本
/// task 终止 relay。
async fn handle_udp_associate(
    relay_socket: UdpSocket,
    handler: Arc<dyn DispatchHandler>,
) -> std::io::Result<()> {
    let mut session = UdpDispatchSession::new(handler);
    let mut buf = [0u8; 65535];
    // 最近一个客户端地址：响应可能晚于请求到达，跨循环迭代记忆
    let mut last_client: Option<SocketAddr> = None;
    loop {
        tokio::select! {
            v = relay_socket.recv_from(&mut buf) => {
                let (n, client) = match v {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!(error = %e, "socks udp relay recv failed");
                        continue;
                    }
                };
                last_client = Some(client);
                // 解码 SOCKS5 UDP 请求帧 → (目标地址, payload)
                let (dest_addr, payload) = match decode_udp_packet(&buf[..n]) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!(error = %e, "socks udp decode failed; dropping");
                        continue;
                    }
                };
                let dest = socks_addr_to_destination(&dest_addr, Network::UDP);
                if session.send_packet(&dest, payload).await.is_err() {
                    tracing::debug!("socks udp dispatch send failed");
                }
            }
            r = session.recv_packet() => {
                let (source, payload) = match r {
                    Ok(Some(v)) => v,
                    Ok(None) => return Ok(()), // outbound 关闭，会话结束
                    Err(e) => {
                        tracing::debug!(error = %e, "socks udp dispatch recv failed");
                        continue;
                    }
                };
                let Some(client) = last_client else { continue };
                // 编码响应帧（BND.ADDR = 响应来源地址），发回客户端
                let resp = encode_udp_packet(&destination_to_socks_addr(&source), &payload);
                if relay_socket.send_to(&resp, client).await.is_err() {
                    tracing::debug!("socks udp send_to client failed");
                }
            }
        }
    }
}
/// Mixed proxy inbound(V2RayN / Go xray `mixed` 协议 = socks + http 复合 listener)。
///
/// 单 listener 每连接 peek 1 字节嗅探:0x05 → SOCKS5;ASCII 字母开头 → HTTP。
/// 对应 Go `proxy/mixed/mixed.go` 同一 listener 上 mux socks 与 http 两个 handler。
/// 握手限时由 [`handshake_timeout_for`] 提供（policy 或 Go SessionDefault 60s 兜底）。
async fn serve_mixed(
    listener: InboundTcpListener,
    ohm: Arc<SimpleOhm>,
    socks_cfg: Arc<ServerConfig>,
    http_cfg: Arc<HttpServerConfig>,
    handshake_timeout: Option<std::time::Duration>,
) -> std::io::Result<()> {
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;
    tracing::info!(addr = %listener.local_addr()?, "mixed (socks+http) inbound listening");
    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "mixed accept failed");
                continue;
            }
        };
        let handler = Arc::clone(&handler);
        let socks_cfg = Arc::clone(&socks_cfg);
        let http_cfg = Arc::clone(&http_cfg);
        let handshake_timeout = handshake_timeout;
        tokio::spawn(async move {
            // 1 字节 sniff(带超时避免恶意 client 占资源)
            let mut sniff = [0u8; 1];
            let read_res = match handshake_timeout {
                Some(d) => tokio::time::timeout(d, stream.peek(&mut sniff)).await,
                None => Ok(stream.peek(&mut sniff).await),
            };
            let n = match read_res { Ok(Ok(n)) => n, _ => return };
            if n == 0 { return; }
            if sniff[0] == 0x05 {
                // SOCKS5 路径（握手与 sniff/http 段共用同一限时）
                let hs_fut = socks_handshake(&mut stream, &socks_cfg);
                let hs = match handshake_timeout {
                    Some(d) => match tokio::time::timeout(d, hs_fut).await {
                        Ok(r) => r,
                        Err(_) => return,
                    },
                    None => hs_fut.await,
                };
                match hs {
                    Ok(SocksRequest::TcpConnect(addr)) => {
                        let dest = socks_addr_to_destination(&addr, Network::TCP);
                        let (read_half, write_half) = tokio::io::split(stream);
                        let link = Link::new(new_reader(read_half), new_writer(write_half));
                        if is_mux_destination(&dest) {
                            tokio::spawn(handle_mux_inbound_link(link, handler));
                        } else {
                            let _ = handler.dispatch(&dest, link).await;
                        }
                    }
                    Ok(SocksRequest::UdpAssociate(_, _)) => {
                        // UDP associate 简化:暂不支持(mixed UDP 罕见,跟 socks5 UDP 等价)
                        tracing::debug!("mixed: udp associate not supported in mixed mode");
                    }
                    Err(e) => tracing::debug!(error = %e, "mixed socks handshake failed"),
                }
            } else if sniff[0].is_ascii_alphabetic() {
                // HTTP 路径(简化版:仅 CONNECT + plain,无 mux 派生)
                let handshake_fut = http_server_handshake(&mut stream, &http_cfg);
                let hs = match handshake_timeout {
                    Some(d) => match tokio::time::timeout(d, handshake_fut).await {
                        Ok(r) => r,
                        Err(_) => return,
                    },
                    None => handshake_fut.await,
                };
                let hs = match hs { Ok(v) => v, Err(_) => return };
                if hs.method != "CONNECT" {
                    handle_plain_http(stream, hs, Arc::clone(&handler)).await;
                } else {
                    let dest = hs.dest;
                    let (read_half, write_half) = tokio::io::split(stream);
                    let link = Link::new(new_reader(read_half), new_writer(write_half));
                    if is_mux_destination(&dest) {
                        tokio::spawn(handle_mux_inbound_link(link, handler));
                    } else {
                        let _ = handler.dispatch(&dest, link).await;
                    }
                }
            } else {
                tracing::debug!(first_byte = sniff[0], "mixed: unknown first byte, closing");
            }
            let _ = peer; // 仅用于 closure capture
        });
    }
}


/// HTTP proxy inbound 服务入口。
///
/// 接受连接 → http_server_handshake → CONNECT 隧道 dispatch 或 plain HTTP 代理转发。
/// `handshake_timeout` 对应 Go `proxy/http/server.go:112`
/// `conn.SetReadDeadline(policy().Timeouts.Handshake)`（policy 来自
/// `ForLevel(UserLevel)`，见 spawn_one_inbound http 分支）；None 时不限时。
pub async fn serve_http(
    listener: InboundTcpListener,
    ohm: Arc<SimpleOhm>,
    config: Arc<HttpServerConfig>,
    handshake_timeout: Option<std::time::Duration>,
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
        let handshake_timeout = handshake_timeout;
        tokio::spawn(async move {
            // 1. handshake（按 userLevel 对应 policy 的 handshake 超时限制，
            // 超时即断开——对应 Go SetReadDeadline 到期后 ReadRequest 超时错误）
            let handshake_fut = http_server_handshake(&mut stream, &config);
            let hs = match handshake_timeout {
                Some(d) => match tokio::time::timeout(d, handshake_fut).await {
                    Ok(r) => r,
                    Err(_) => {
                        tracing::debug!("http handshake timeout, closing connection");
                        return;
                    }
                },
                None => handshake_fut.await,
            };
            let hs = match hs {
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
        let mut buf = xray_buf::alloc::alloc(xray_buf::alloc::DEFAULT_SIZE);
        buf.resize(xray_buf::alloc::DEFAULT_SIZE, 0);
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
        xray_buf::alloc::release(buf);
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

/// Dokodemo TCP inbound per-connection 目标解析选项。
///
/// 对应 Go `DokodemoDoor` 的 `rewriteAddress`/`rewritePort`/`portMap`/
/// `followRedirect` + streamSettings TLS（`tls.NewListener` 包裹）。
#[derive(Clone)]
pub struct DokodemoTcpOptions {
    /// 预定义目标（settings.address + settings.port，均可缺省 → `None`）。
    pub dest: Option<Destination>,
    /// 端口映射：监听端口字符串 → `"host:port"`（host/port 均可缺省）。
    /// 仅 `follow_redirect=false` 时生效。
    pub port_map: HashMap<String, String>,
    /// 跟随 iptables REDIRECT 原始目标（Linux `SO_ORIGINAL_DST`）+ TLS SNI 覆盖。
    pub follow_redirect: bool,
    /// TLS acceptor（streamSettings `security:tls` 时）。
    pub tls: Option<Arc<xray_transport::TlsAcceptor>>,
}

/// 字符串解析为 [`Address`]：IPv4 → IPv6 → 域名。
fn parse_address_str(s: &str) -> Address {
    if let Ok(v4) = s.parse::<std::net::Ipv4Addr>() {
        Address::IPv4(v4)
    } else if let Ok(v6) = s.parse::<std::net::Ipv6Addr>() {
        Address::IPv6(v6)
    } else {
        Address::Domain(s.to_string())
    }
}

/// [`SocketAddr`] 的 IP 部分转 [`Address`]。
fn socketaddr_to_address(addr: SocketAddr) -> Address {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => Address::IPv4(v4),
        std::net::IpAddr::V6(v6) => Address::IPv6(v6),
    }
}

/// Dokodemo TCP per-connection dest 解析。对应 Go `Process()` L79-136。
///
/// `follow_redirect=true` 优先级：
/// 1. `original_dst`（Linux `SO_ORIGINAL_DST`，iptables REDIRECT 透明代理）
/// 2. TLS 握手 SNI 覆盖 address（port 保持 rewrite 值，缺省 0；Go dokodemo.go:122-132，
///    仅在未被 original_dst 覆盖时）
/// 3. predefined dest；三者皆无 → `None`（Go：dest 无效，dispatch 失败）
///
/// `follow_redirect=false`：predefined dest 回填（address 缺省 → 本机回环、
/// port 缺省 → 本地端口，Go dokodemo.go:86-100）+ `port_map`（:101-109）。
/// 返回 `None` = 无有效目标（仅 follow_redirect 且 original/SNI/rewrite 皆缺时）。
fn resolve_dokodemo_tcp_dest(
    opts: &DokodemoTcpOptions,
    local_ip: Option<std::net::IpAddr>,
    local_port: Option<u16>,
    original_dst: Option<SocketAddr>,
    tls_sni: Option<&str>,
) -> Option<Destination> {
    let mut dest = opts.dest.clone();
    if opts.follow_redirect {
        let mut overridden = false;
        if let Some(orig) = original_dst {
            dest = Some(Destination::tcp(socketaddr_to_address(orig), Port::new(orig.port())));
            overridden = true;
        }
        if !overridden {
            if let Some(sni) = tls_sni.filter(|s| !s.is_empty()) {
                let port = dest.as_ref().map_or(0, |d| d.port().value());
                dest = Some(Destination::tcp(
                    Address::Domain(sni.to_string()),
                    Port::new(port),
                ));
            }
        }
        dest
    } else {
        // rewrite 缺省回填（Go dokodemo.go:86-100）：address → 本机回环
        // （依监听地址族选 v4/v6），port → 本地监听端口。
        let mut d = dest.unwrap_or_else(|| {
            Destination::tcp(loopback_addr(local_ip), Port::new(0))
        });
        if d.port().value() == 0 {
            if let Some(lp) = local_port {
                d = Destination::tcp(d.address().clone(), Port::new(lp));
            }
        }
        // port_map：值 "host:port"，host/port 均可空（Go dokodemo.go:101-109，
        // SplitHostPort 错误已在 parse 阶段校验，此处容错跳过）。
        if let Some(lp) = local_port {
            if let Some(mapping) = opts.port_map.get(&lp.to_string()) {
                if let Some((host, port_str)) = mapping.rsplit_once(':') {
                    if !port_str.is_empty() {
                        if let Ok(p) = port_str.parse::<u16>() {
                            d = Destination::tcp(d.address().clone(), Port::new(p));
                        }
                    }
                    let host = host.trim_start_matches('[').trim_end_matches(']');
                    if !host.is_empty() {
                        d = Destination::tcp(parse_address_str(host), d.port());
                    }
                }
            }
        }
        Some(d)
    }
}

/// rewrite address 缺省时的本机回环地址（Go dokodemo.go:91-96：依监听
/// 地址族选 127.0.0.1 / ::1）。
fn loopback_addr(local_ip: Option<std::net::IpAddr>) -> Address {
    match local_ip {
        Some(std::net::IpAddr::V6(_)) => Address::IPv6(std::net::Ipv6Addr::LOCALHOST),
        _ => Address::IPv4(std::net::Ipv4Addr::LOCALHOST),
    }
}

/// Dokodemo-door inbound 服务入口（tdy / i09）。
///
/// 接受连接 → 按 [`DokodemoTcpOptions`] 解析目标 dest（predefined / port_map /
/// follow_redirect / TLS SNI）→ 拼装 Link → dispatch（dokodemo 无握手协议）。
///
/// 对应 Go `Process()`：TLS 由 listener 层包裹（`tls.NewListener`），SNI 在
/// follow_redirect 未被 SO_ORIGINAL_DST 覆盖时改写 dest.address。
pub async fn serve_dokodemo(
    listener: InboundTcpListener,
    ohm: Arc<SimpleOhm>,
    opts: DokodemoTcpOptions,
) -> std::io::Result<()> {
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;
    tracing::info!(
        addr = %listener.local_addr()?,
        dest = ?opts.dest,
        follow_redirect = opts.follow_redirect,
        tls = opts.tls.is_some(),
        "dokodemo inbound listening"
    );
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "dokodemo accept failed");
                continue;
            }
        };
        let handler = Arc::clone(&handler);
        let opts = opts.clone();
        tokio::spawn(async move {
            let local_ip = stream.local_addr().ok().map(|a| a.ip());
            let local_port = stream.local_addr().ok().map(|a| a.port());

            // follow_redirect：Linux 下从 accept 的 fd 查 SO_ORIGINAL_DST。
            // Go 由 TPROXY listener 在 transport 层写入 session ctx（Go dokodemo.go
            // L113-121），Rust 在此直接 getsockopt；非 REDIRECT 连接返回 Err → 回落。
            #[cfg(target_os = "linux")]
            let original_dst = if opts.follow_redirect {
                use std::os::fd::AsRawFd;
                xray_transport::sockopt::get_original_dst(stream.as_raw_fd()).ok()
            } else {
                None
            };
            #[cfg(not(target_os = "linux"))]
            let original_dst: Option<SocketAddr> = None;

            if let Some(acc) = opts.tls.clone() {
                // TLS 握手首包（ClientHello）读超时：静默连接占位防护
                // （Go SessionDefault Timeouts.Handshake=60s 同源）。
                match tokio::time::timeout(DEFAULT_HANDSHAKE_TIMEOUT, acc.accept(stream)).await {
                    Ok(Ok(tls_stream)) => {
                        // SNI 覆盖：握手完成后的 ClientHello server_name
                        // （rustls ServerConnection::server_name）。
                        let sni = tls_stream.get_ref().1.server_name();
                        match resolve_dokodemo_tcp_dest(&opts, local_ip, local_port, original_dst, sni)
                        {
                            Some(dest) => {
                                let (read_half, write_half) = tokio::io::split(tls_stream);
                                let link = Link::new(new_reader(read_half), new_writer(write_half));
                                let _ = handler.dispatch(&dest, link).await;
                            }
                            None => tracing::warn!(
                                "dokodemo: no valid destination (followRedirect without original dst/SNI/rewrite)"
                            ),
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "dokodemo TLS accept failed");
                    }
                    Err(_) => {
                        tracing::debug!("dokodemo TLS accept timeout");
                    }
                }
            } else {
                match resolve_dokodemo_tcp_dest(&opts, local_ip, local_port, original_dst, None) {
                    Some(dest) => {
                        let (read_half, write_half) = tokio::io::split(stream);
                        let link = Link::new(new_reader(read_half), new_writer(write_half));
                        let _ = handler.dispatch(&dest, link).await;
                    }
                    None => tracing::warn!(
                        "dokodemo: no valid destination (followRedirect without original dst/rewrite)"
                    ),
                }
            }
        });
    }
}

/// Dokodemo-door UDP inbound 服务入口。
///
/// 对应 Go `Process()` 中 `network == UDP` 分支：数据报按 peer 源地址分桶到
/// per-peer [`UdpDispatchSession`]（Go `udp.Dispatcher` 会话模型），响应回发
/// 给产生它的会话的 peer——不再共享 last_peer（多客户端交错时回包串扰）。
///
/// 底层 socket 由 [`xray_transport::udp::hub::UdpHub`] 承载：
/// `follow_redirect=true` 时以 `ReceiveOriginalDestination` 监听（Linux 下
/// IP_TRANSPARENT + IP_RECVORIGDSTADDR，逐包携带原始目标，对应 Go
/// `HubReceiveOriginalDestination`），回包经 fakeudp 伪造源地址
/// （Go dokodemo.go:158-176 PacketWriter + fakeudp_linux.go）；非 Linux/
/// 未命中 TPROXY 时回包直接从监听 socket 发出（已知平台降级，对齐 Go
/// fakeudp_other.go）。
///
/// `dest`：predefined 目标（dokodemo 语义：固定目标；address/port 缺省时
/// 回填本机回环 + 本地端口，Go dokodemo.go:86-100）。
pub async fn serve_dokodemo_udp(
    bind_addr: SocketAddr,
    handler: Arc<dyn DispatchHandler>,
    dest: Option<Destination>,
    follow_redirect: bool,
) -> std::io::Result<()> {
    use xray_transport::udp::hub::ReceiveOriginalDestination;
    let hub = xray_transport::udp::hub::UdpHub::listen(
        bind_addr,
        &[Box::new(ReceiveOriginalDestination(follow_redirect))],
        None,
    )
    .await?;
    serve_dokodemo_udp_on(hub, handler, dest).await
}

/// 已建 [`UdpHub`] 的 dokodemo UDP 服务循环（测试/组合入口）。
pub async fn serve_dokodemo_udp_on(
    hub: xray_transport::udp::hub::UdpHub,
    handler: Arc<dyn DispatchHandler>,
    dest: Option<Destination>,
) -> std::io::Result<()> {
    let local = hub.local_addr().ok();
    let local_port = local.as_ref().map(|a| a.port());
    let mut dest =
        dest.unwrap_or_else(|| Destination::udp(loopback_addr(local.map(|a| a.ip())), Port::new(0)));
    if dest.port().value() == 0 {
        if let Some(lp) = local_port {
            dest = Destination::udp(dest.address().clone(), Port::new(lp));
        }
    }
    tracing::info!(addr = ?local, dest = ?dest, "dokodemo UDP inbound listening");

    let (mut hub_rx, hub) = hub.split();
    // per-peer 会话表：首包建会话 task；空闲清扫复用 retain 模式（同 SS UDP
    // relay 的 sessions.retain，本表按 idle 时间判定，60s 对齐 Go udp
    // Dispatcher 的会话超时）。
    let mut peers: HashMap<SocketAddr, PeerSession> = HashMap::new();
    let mut cleanup_at = tokio::time::Instant::now() + DOKODEMO_UDP_IDLE;
    loop {
        tokio::select! {
            pkt = hub_rx.recv() => {
                let Some(pkt) = pkt else { return Ok(()) }; // hub 关闭
                let peer = pkt.source;
                // 逐包目标：TPROXY 命中原始目标用之，否则 predefined
                // （Go destinationOverridden → ob.Target 覆盖）。
                let dest_override = pkt
                    .target
                    .map(|a| Destination::udp(socketaddr_to_address(a), Port::new(a.port())));
                let entry = match peers.entry(peer) {
                    std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                    std::collections::hash_map::Entry::Vacant(e) => {
                        let (tx, rx) = tokio::sync::mpsc::channel(64);
                        let overridden = dest_override.is_some();
                        let first_dest = dest_override.clone().unwrap_or_else(|| dest.clone());
                        tokio::spawn(dokodemo_peer_relay(
                            peer,
                            rx,
                            Arc::clone(&handler),
                            first_dest,
                            Arc::clone(&hub),
                            overridden,
                        ));
                        e.insert(PeerSession {
                            tx,
                            last_active: tokio::time::Instant::now(),
                        })
                    }
                };
                entry.last_active = tokio::time::Instant::now();
                if entry.tx.send((dest_override, pkt.payload)).await.is_err() {
                    tracing::debug!("dokodemo udp peer session closed; packet dropped");
                }
            }
            _ = tokio::time::sleep_until(cleanup_at) => {
                // 丢弃 idle / 已关会话：tx drop → peer task 退出 → link/fake socket 释放
                peers.retain(|_, p| {
                    !p.tx.is_closed() && p.last_active.elapsed() < DOKODEMO_UDP_IDLE
                });
                cleanup_at = tokio::time::Instant::now() + DOKODEMO_UDP_IDLE;
            }
        }
    }
}

/// dokodemo UDP 会话空闲清理阈值（60s，Go udp Dispatcher 会话超时同值）。
const DOKODEMO_UDP_IDLE: std::time::Duration = std::time::Duration::from_secs(60);

/// per-peer 会话表条目。
struct PeerSession {
    /// 主循环 → peer task 的入站包队列 `(逐包 dest 覆盖, payload)`。
    tx: tokio::sync::mpsc::Sender<(Option<Destination>, Vec<u8>)>,
    last_active: tokio::time::Instant,
}

/// 单 peer UDP 会话任务：入站队列 → [`UdpDispatchSession`] → 响应回发本 peer。
///
/// 响应路径（对齐 Go dokodemo.go:158-176 PacketWriter）：
/// - 非 TPROXY：响应经监听 socket（hub）回发（Go `SequentialWriter{conn}`）。
/// - TPROXY（Linux）：响应源为 IP 时经 fakeudp 伪造源地址回发（per 源缓存，
///   Go `w.conns`）；源伪造不可用时丢弃该响应（Go 同款 LogInfo+continue）。
async fn dokodemo_peer_relay(
    peer: SocketAddr,
    mut rx: tokio::sync::mpsc::Receiver<(Option<Destination>, Vec<u8>)>,
    handler: Arc<dyn DispatchHandler>,
    default_dest: Destination,
    hub: Arc<xray_transport::udp::hub::UdpHub>,
    overridden: bool,
) {
    let mut session = UdpDispatchSession::new(handler);
    #[allow(unused_mut)]
    let mut fake_cache: HashMap<(std::net::IpAddr, u16), Arc<tokio::net::UdpSocket>> =
        HashMap::new();
    loop {
        tokio::select! {
            r = rx.recv() => {
                match r {
                    Some((dest, payload)) => {
                        let d = dest.as_ref().unwrap_or(&default_dest);
                        if session.send_packet(d, &payload).await.is_err() {
                            tracing::debug!("dokodemo udp dispatch send failed");
                        }
                    }
                    None => return, // idle 清扫丢表项（tx 关闭）
                }
            }
            r = session.recv_packet() => {
                match r {
                    Ok(Some((source, payload))) => {
                        // TPROXY（Linux）：按响应源选 fakeudp；None=经 hub 回发
                        #[cfg(target_os = "linux")]
                        let fake = if overridden {
                            fake_responder(&mut fake_cache, &source)
                        } else {
                            None
                        };
                        #[cfg(not(target_os = "linux"))]
                        let fake: Option<Arc<tokio::net::UdpSocket>> = None;
                        #[cfg(not(target_os = "linux"))]
                        let _ = (&overridden, &source, &fake_cache);
                        match fake {
                            Some(s) => {
                                if s.send_to(&payload, peer).await.is_err() {
                                    tracing::debug!("dokodemo udp fakeudp send_to client failed");
                                }
                            }
                            None => {
                                if hub.send_to(&payload, peer).await.is_err() {
                                    tracing::debug!("dokodemo udp send_to client failed");
                                }
                            }
                        }
                    }
                    Ok(None) => return, // outbound 关闭，会话结束
                    Err(e) => {
                        tracing::debug!(error = %e, "dokodemo udp dispatch recv failed");
                        continue;
                    }
                }
            }
        }
    }
}

/// TPROXY 响应回发 socket：按响应源（IP）取/建 fakeudp 透明 socket。
///
/// - 响应源为 IP：`fakeudp` bind 到该源地址（per 源缓存，Go `w.conns` 同键）。
/// - 创建失败（需 CAP_NET_ADMIN）或源为域名（无法 bind）：返回 `None`，调用
///   方丢弃该响应（Go PacketWriter 创建失败 LogInfo+drop 同款降级）。
/// mark 恒 0：Rust dokodemo UDP 路径未接 session sockopt mark（Go 缺省 0 同值）。
#[cfg(target_os = "linux")]
fn fake_responder(
    cache: &mut HashMap<(std::net::IpAddr, u16), Arc<tokio::net::UdpSocket>>,
    source: &Destination,
) -> Option<Arc<tokio::net::UdpSocket>> {
    let ip = match source.address() {
        Address::IPv4(v4) => std::net::IpAddr::V4(*v4),
        Address::IPv6(v6) => std::net::IpAddr::V6(*v6),
        Address::Domain(_) => return None,
    };
    let key = (ip, source.port().value());
    if let Some(s) = cache.get(&key) {
        return Some(Arc::clone(s));
    }
    match xray_proxy_dokodemo::fakeudp::fake_udp(SocketAddr::new(ip, key.1), 0) {
        Ok(s) => {
            let s = Arc::new(s);
            cache.insert(key, Arc::clone(&s));
            Some(s)
        }
        Err(e) => {
            tracing::warn!(error = %e, "dokodemo TPROXY fakeudp create failed; response dropped");
            None
        }
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

/// SS inbound 双向 pump + dispatch（Legacy 握手后共用，泛型以支持 transport 流）。
///
/// up: ss_stream.read_chunk → server_io（密文→明文，供 dispatch reader）；
/// down: server_io 读 → ss_stream.write_chunk（明文→密文，回包给客户端）。
async fn spawn_ss_pump<C>(
    mut ss_stream: xray_proxy_ss::stream::SSStream<C>,
    dest: Destination,
    handler: std::sync::Arc<dyn DispatchHandler>,
) where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    // 单 task select! 串行推进：SSStream 共享 nonce 计数器不可并发持有 read/write &mut。
    tokio::spawn(async move {
        let (mut srv_rd, mut srv_wr) = tokio::io::split(server_io);
        let mut down_buf = vec![0u8; 8 * 1024];
        loop {
            tokio::select! {
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

/// Legacy SS 单条 TCP 连接完整 pipeline：握手 → pump → dispatch。
///
/// serve_ss accept loop 与 transport inbound（grpc/kcp/ws hub）共用；
/// transport 分支的 conn 已被 hub 解包为明文流。
async fn ss_legacy_pipeline<C>(
    ib: std::sync::Arc<xray_proxy_ss::inbound::SsInbound>,
    handler: std::sync::Arc<dyn DispatchHandler>,
    stream: C,
    // sm80④：policy Timeouts.Handshake（Go SessionDefault 60s 同源；装配层注入）
    handshake_timeout: std::time::Duration,
) where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // 首包读超时：静默连接占位防护；transport 分支共用本函数，一并覆盖。
    let handshake =
        match tokio::time::timeout(handshake_timeout, ib.handle_conn(stream)).await {
            Ok(r) => r.map(|(header, ss_stream)| (header.address, header.port, ss_stream)),
            Err(_) => {
                tracing::debug!("ss legacy inbound handshake timeout");
                return;
            }
        };
    match handshake {
        Ok((address, port, ss_stream)) => {
            let dest = Destination::new(address, Port::new(port), Network::TCP);
            spawn_ss_pump(ss_stream, dest, handler).await;
        }
        Err(e) => {
            tracing::debug!(error = %e, "ss inbound handshake failed");
        }
    }
}

/// Shadowsocks inbound 服务入口。
///
/// 接受连接 → handle_conn → parse dest → dispatch。
pub async fn serve_ss(
    listener: InboundTcpListener,
    ohm: Arc<SimpleOhm>,
    inbound: SsInboundMode,
    // sm80④：policy Timeouts.Handshake（legacy 与 ss2022 TCP 握手共用）
    handshake_timeout: std::time::Duration,
) -> std::io::Result<()> {
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;
    // SS UDP relay：同端口 UDP 监听（Go Process(UDP) 分支；legacy 与 2022 均有）
    enum SsUdpFlavor {
        Legacy(Arc<SsInbound>),
        Ss2022 {
            kind: xray_proxy_ss::ss2022::key::CipherKind2022,
            server_psk: Vec<u8>,
            users: Vec<([u8; 16], Vec<u8>)>,
        },
    }
    let udp_flavor = match &inbound {
        SsInboundMode::Legacy(ib) => Some(SsUdpFlavor::Legacy(Arc::clone(ib))),
        SsInboundMode::Ss2022(ib) => Some(SsUdpFlavor::Ss2022 {
            kind: ib.kind(),
            server_psk: ib.psk().to_vec(),
            users: Vec::new(),
        }),
        SsInboundMode::Ss2022Multi(ib) => Some(SsUdpFlavor::Ss2022 {
            kind: ib.kind(),
            server_psk: ib.server_psk().to_vec(),
            users: ib.udp_user_table(),
        }),
        // relay 模式 Go 走 RelayService NewPacketConnection（整 PacketConn 中继），
        // 不在本批
        SsInboundMode::Ss2022Relay(_) => None,
    };
    if let Some(flavor) = udp_flavor {
        let port = listener.local_addr()?.port();
        match tokio::net::UdpSocket::bind(("0.0.0.0", port)).await {
            Ok(sock) => {
                let handler = Arc::clone(&handler);
                tokio::spawn(async move {
                    let _ = match flavor {
                        SsUdpFlavor::Legacy(ib) => {
                            serve_ss_udp(Arc::new(sock), ib, handler).await
                        }
                        SsUdpFlavor::Ss2022 { kind, server_psk, users } => {
                            serve_ss2022_udp(Arc::new(sock), kind, server_psk, users, handler)
                                .await
                        }
                    };
                });
            }
            Err(e) => tracing::warn!(error = %e, port, "ss udp bind failed, udp relay disabled"),
        }
    }
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
            match mode {
                SsInboundMode::Legacy(ib) => {
                    ss_legacy_pipeline(ib, handler, stream, handshake_timeout).await;
                }
                SsInboundMode::Ss2022(ib) => {
                    let handshake = tokio::time::timeout(handshake_timeout, ib.handle_conn(stream)).await;
                    let handshake = match handshake {
                        Ok(r) => r
                            .map(|resp| (resp.address, resp.port, resp.stream))
                            .map_err(|e| std::io::Error::other(e.to_string())),
                        Err(_) => {
                            tracing::debug!("ss2022 inbound handshake timeout");
                            return;
                        }
                    };
                    if let Ok((address, port, ss_stream)) = handshake {
                        let dest = Destination::new(address, Port::new(port), Network::TCP);
                        spawn_ss_pump(ss_stream, dest, handler).await;
                    } else if let Err(e) = handshake {
                        tracing::debug!(error = %e, "ss inbound handshake failed");
                    }
                }
                SsInboundMode::Ss2022Multi(ib) => {
                    let handshake = tokio::time::timeout(DEFAULT_HANDSHAKE_TIMEOUT, ib.handle_conn(stream)).await;
                    let handshake = match handshake {
                        Ok(r) => r
                            .map(|resp| (resp.address, resp.port, resp.stream))
                            .map_err(|e| std::io::Error::other(e.to_string())),
                        Err(_) => {
                            tracing::debug!("ss2022 multi inbound handshake timeout");
                            return;
                        }
                    };
                    if let Ok((address, port, ss_stream)) = handshake {
                        let dest = Destination::new(address, Port::new(port), Network::TCP);
                        spawn_ss_pump(ss_stream, dest, handler).await;
                    } else if let Err(e) = handshake {
                        tracing::debug!(error = %e, "ss inbound handshake failed");
                    }
                }
                SsInboundMode::Ss2022Relay(ib) => {
                    // relay：身份匹配 + 剥 identity header，字节原样桥（无 chunk 解密）
                    let handshake =
                        tokio::time::timeout(DEFAULT_HANDSHAKE_TIMEOUT, ib.handle_conn_relay(stream)).await;
                    let handshake = match handshake {
                        Ok(v) => v,
                        Err(_) => {
                            tracing::debug!("ss2022 relay inbound handshake timeout");
                            return;
                        }
                    };
                    let Ok((_addr, port, prefix, tcp)) = handshake else {
                        tracing::debug!("ss2022 relay inbound handshake failed");
                        return;
                    };
                    let dest = Destination::new(_addr, Port::new(port), Network::TCP);
                    let (r, w) = tokio::io::split(tcp);
                    let link = Link::new(
                        new_reader(SsRelayReader::new(prefix, r)),
                        new_writer(w),
                    );
                    let _ = handler.dispatch(&dest, link).await;
                }
            }
        });
    }
}

/// 前缀字节回灌 reader（relay 模式把 salt 回灌到流头，与 vless/tuic InitialedReader 同模式）。
struct SsRelayReader<R> {
    initial: std::io::Cursor<Vec<u8>>,
    inner: R,
}

impl<R> SsRelayReader<R> {
    fn new(initial: Vec<u8>, inner: R) -> Self {
        Self { initial: std::io::Cursor::new(initial), inner }
    }
}

impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for SsRelayReader<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.initial.position() < self.initial.get_ref().len() as u64 {
            let unfilled = buf.initialize_unfilled();
            let n = std::io::Read::read(&mut self.initial, unfilled)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            buf.advance(n);
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
/// SS UDP per-client relay 的 channel 项：(目标, payload, 发起用户 account)。
type SsUdpItem = (Destination, Vec<u8>, xray_proxy_ss::config::MemoryAccount);

/// SS UDP per-client 会话空闲淘汰时限（Go `CancelAfterInactivity(1min)`）。
const SS_UDP_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// SS-2022 UDP AEAD 会话表存活期（bd 29nk，对齐 sing-shadowsocks
/// `udpSessions: LruCache{WithAge(udpTimeout)}`——Go Xray inbound.go:57
/// `NewServiceWithPassword(..., 500, ...)` 传 udpTimeout=500s）。
const SS2022_UDP_SESSION_LIFETIME: std::time::Duration = std::time::Duration::from_secs(500);

/// 惰性清扫过期的 AEAD 会话条目（对齐 sing LruCache `maybeDeleteOldest`：
/// Store/Load 时从表里删 `expires <= now`；`WithUpdateAgeOnGet` 由调用方
/// 命中时刷新 deadline 表达）。返回清扫后条数。
fn sweep_expired_ss2022_sessions(
    server_sessions: &mut HashMap<u64, (Arc<xray_proxy_ss::ss2022::packet::ServerUdpSession2022>, std::time::Instant)>,
    now: std::time::Instant,
) -> usize {
    server_sessions.retain(|_, (_, deadline)| *deadline > now);
    server_sessions.len()
}

/// SS Legacy UDP relay 入口。
///
/// 对应 Go `proxy/shadowsocks/server.go::handleUDPPayload`：recv_from →
/// decode_udp_packet（匹配用户 + 解出目标/payload）→ 按客户端源地址分发到
/// per-client [`UdpDispatchSession`]（Go `udp.Dispatcher` cone 会话模型）。
/// 回包由 [`ss_udp_client_relay`] 用发起用户的 account `encode_udp_packet`
/// 后 send_to 客户端。
pub async fn serve_ss_udp(
    udp: Arc<tokio::net::UdpSocket>,
    ib: Arc<SsInbound>,
    handler: Arc<dyn DispatchHandler>,
) -> std::io::Result<()> {
    use xray_proxy_ss::protocol::decode_udp_packet;
    tracing::info!(addr = %udp.local_addr()?, "ss udp relay listening");
    let mut buf = vec![0u8; 65_536];
    let mut clients: HashMap<SocketAddr, tokio::sync::mpsc::Sender<SsUdpItem>> = HashMap::new();
    loop {
        let (n, client) = match udp.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "ss udp recv failed");
                continue;
            }
        };
        // ponytail: 收包时顺带清扫已退出（60s 空闲淘汰）会话的残留 sender；
        // O(clients)/包，海量并发 UDP 客户端时换后台定时清扫
        clients.retain(|_, tx| !tx.is_closed());
        let (header, payload) = match decode_udp_packet(ib.validator(), &buf[..n]) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, "ss udp decode failed (unknown user?)");
                continue;
            }
        };
        let dest = Destination::new(header.address.clone(), Port::new(header.port), Network::UDP);
        let item = (dest, payload, header.user.account.clone());
        let tx = clients.entry(client).or_insert_with(|| {
            let (tx, rx) = tokio::sync::mpsc::channel(16);
            tokio::spawn(ss_udp_client_relay(
                Arc::clone(&udp),
                client,
                rx,
                Arc::clone(&handler),
            ));
            tx
        });
        if tx.send(item).await.is_err() {
            // relay task 已退出（空闲淘汰）：丢弃 entry，该 client 下一包重建会话
            clients.remove(&client);
        }
    }
}

/// 单客户端 SS UDP relay（Go 每个 NAT entry 的读写 task）。
///
/// - up：主循环 decode 后的 (dest, payload) → [`UdpDispatchSession::send_packet`]
///   （首包懒建 dispatch link，域名目标原样透传由 outbound 解析）
/// - down：`recv_packet` 回包 → 发起用户 account `encode_udp_packet` →
///   send_to 客户端
///
/// 60s 双向无活动自动退出（Go `CancelAfterInactivity(1min)`）。
async fn ss_udp_client_relay(
    udp: Arc<tokio::net::UdpSocket>,
    client: SocketAddr,
    mut rx: tokio::sync::mpsc::Receiver<SsUdpItem>,
    handler: Arc<dyn DispatchHandler>,
) {
    use xray_proxy_ss::protocol::encode_udp_packet;
    let mut session = UdpDispatchSession::new(handler);
    // 回包加密 account：跟随最近请求的用户（Go 按 client NAT entry 记 user）
    let mut account: Option<xray_proxy_ss::config::MemoryAccount> = None;
    let idle = tokio::time::sleep(SS_UDP_IDLE_TIMEOUT);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            item = rx.recv() => {
                match item {
                    Some((dest, payload, acct)) => {
                        account = Some(acct);
                        if session.send_packet(&dest, &payload).await.is_err() {
                            break;
                        }
                        idle.as_mut().reset(tokio::time::Instant::now() + SS_UDP_IDLE_TIMEOUT);
                    }
                    None => break, // 主循环丢弃本 entry（会话被替换）
                }
            }
            r = session.recv_packet() => {
                match r {
                    Ok(Some((source, payload))) => {
                        if let Some(acct) = &account {
                            if let Ok(enc) = encode_udp_packet(
                                acct,
                                source.address(),
                                source.port().value(),
                                &payload,
                            ) {
                                let _ = udp.send_to(&enc, client).await;
                            }
                        }
                        idle.as_mut().reset(tokio::time::Instant::now() + SS_UDP_IDLE_TIMEOUT);
                    }
                    Ok(None) => break, // outbound 关闭，会话结束
                    Err(e) => {
                        tracing::debug!(error = %e, "ss udp dispatch recv failed");
                        continue; // 坏帧跳过（与 SOCKS relay 一致）
                    }
                }
            }
            _ = &mut idle => break, // 60s 空闲淘汰
        }
    }
}

/// SS-2022 UDP relay 入口（Go `MultiService.newPacket` + `udpNat`）。
///
/// recv_from → [`server_decode_header`]（ECB 头 + EIH 用户识别）→ 按 client
/// sessionId 分发到 per-session NAT entry（[`ServerUdpSession2022`] +
/// [`ss2022_udp_client_relay`]，Go `udpNat` cone 会话模型）。回包由 relay
/// task 用该会话的 server sessionId/cipher `encode` 后 send_to 客户端。
///
/// `users` 空 = 单用户（AEAD key 直接从 server PSK 派生）。
pub async fn serve_ss2022_udp(
    udp: Arc<UdpSocket>,
    kind: xray_proxy_ss::ss2022::key::CipherKind2022,
    server_psk: Vec<u8>,
    users: Vec<([u8; 16], Vec<u8>)>,
    handler: Arc<dyn DispatchHandler>,
) -> std::io::Result<()> {
    use xray_proxy_ss::ss2022::packet::{server_decode_header, ServerUdpSession2022};

    tracing::info!(addr = %udp.local_addr()?, "ss2022 udp relay listening");
    let mut buf = vec![0u8; 65_536];
    type Item = (Destination, Vec<u8>, SocketAddr);
    let mut sessions: HashMap<u64, tokio::sync::mpsc::Sender<Item>> = HashMap::new();
    let mut server_sessions: HashMap<
        u64,
        (Arc<ServerUdpSession2022>, std::time::Instant),
    > = HashMap::new();
    loop {
        let (n, client) = match udp.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "ss2022 udp recv failed");
                continue;
            }
        };
        // ponytail: 收包时顺带清扫已退出（60s 空闲淘汰）会话的残留 sender；
        // O(sessions)/包，海量并发 UDP 客户端时换后台定时清扫
        sessions.retain(|_, tx| !tx.is_closed());
        // bd 29nk：顺带惰性清扫超龄（500s 无活动）AEAD 会话——表此前只增不删，
        // 海量 UDP 客户端下是内存泄漏；对齐 Go sing udpSessions LRU 淘汰。
        let now = std::time::Instant::now();
        sweep_expired_ss2022_sessions(&mut server_sessions, now);
        // 1. ECB 解头 + EIH 用户识别
        let hdr = match server_decode_header(kind, &server_psk, &users, &buf[..n]) {
            Ok(h) => h,
            Err(e) => {
                tracing::debug!(error = %e, "ss2022 udp decode header failed (unknown user?)");
                continue;
            }
        };
        let sid = hdr.session_id;
        // 2. 查/建 per-sessionId NAT entry
        if !server_sessions.contains_key(&sid) {
            match ServerUdpSession2022::new(kind, hdr.aead_psk.to_vec(), sid) {
                Ok(s) => {
                    server_sessions.insert(sid, (Arc::new(s), now + SS2022_UDP_SESSION_LIFETIME));
                }
                Err(e) => {
                    tracing::debug!(error = %e, "ss2022 udp session init failed");
                    continue;
                }
            }
        }
        // 命中即刷新存活期（sing WithUpdateAgeOnGet 语义）。
        let Some((session, deadline)) = server_sessions.get_mut(&sid) else {
            continue;
        };
        *deadline = now + SS2022_UDP_SESSION_LIFETIME;
        let session = Arc::clone(session);
        // 3. AEAD 解 body + 解析目标（重放/时间戳校验在 decode_body 内）
        let (address, port, payload) = match session.decode_body(
            &hdr.hdr,
            hdr.packet_id,
            &buf[16 + hdr.eih_len..n],
        ) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, "ss2022 udp decode body failed");
                continue;
            }
        };
        let dest = Destination::new(address, Port::new(port), Network::UDP);
        // 4. 分发到 relay task（首包懒建）
        let tx = sessions.entry(sid).or_insert_with(|| {
            let (tx, rx) = tokio::sync::mpsc::channel(16);
            tokio::spawn(ss2022_udp_client_relay(
                Arc::clone(&udp),
                client,
                Arc::clone(&session),
                rx,
                Arc::clone(&handler),
            ));
            tx
        });
        if tx.send((dest, payload, client)).await.is_err() {
            // relay task 已退出（空闲淘汰）：丢弃 entry，该 session 下一包重建
            sessions.remove(&sid);
        }
    }
}

/// 单 client session 的 SS-2022 UDP relay（Go 每个 udpNat entry 的读写 task）。
///
/// - up：主循环 decode 后的 (dest, payload) → [`UdpDispatchSession::send_packet`]
/// - down：`recv_packet` 回包 → [`ServerUdpSession2022::encode`] →
///   send_to 客户端（最新源地址，随每包更新）
///
/// 60s 双向无活动自动退出。
async fn ss2022_udp_client_relay(
    udp: Arc<UdpSocket>,
    mut client: SocketAddr,
    session: Arc<xray_proxy_ss::ss2022::packet::ServerUdpSession2022>,
    mut rx: tokio::sync::mpsc::Receiver<(Destination, Vec<u8>, SocketAddr)>,
    handler: Arc<dyn DispatchHandler>,
) {
    let mut dispatch = UdpDispatchSession::new(handler);
    let idle = tokio::time::sleep(SS_UDP_IDLE_TIMEOUT);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            item = rx.recv() => {
                match item {
                    Some((dest, payload, src)) => {
                        client = src;
                        if dispatch.send_packet(&dest, &payload).await.is_err() {
                            break;
                        }
                        idle.as_mut().reset(tokio::time::Instant::now() + SS_UDP_IDLE_TIMEOUT);
                    }
                    None => break, // 主循环丢弃本 entry（会话被替换）
                }
            }
            r = dispatch.recv_packet() => {
                match r {
                    Ok(Some((source, payload))) => {
                        if let Ok(enc) = session.encode(
                            source.address(),
                            source.port().value(),
                            &payload,
                        ) {
                            let _ = udp.send_to(&enc, client).await;
                        }
                        idle.as_mut().reset(tokio::time::Instant::now() + SS_UDP_IDLE_TIMEOUT);
                    }
                    Ok(None) => break, // outbound 关闭，会话结束
                    Err(e) => {
                        tracing::debug!(error = %e, "ss2022 udp dispatch recv failed");
                        continue; // 坏帧跳过（与 SOCKS relay 一致）
                    }
                }
            }
            _ = &mut idle => break, // 60s 空闲淘汰
        }
    }
}

/// hysteria `TcpDispatcher` → xray `DispatchHandler` 适配器（rxw）。
///
/// InterStreamConn 用现成 `HysteriaConn` 包装成 Connection 后按 dispatch Link 桥接。
#[derive(Debug)]
struct HysteriaTcpDispatch(Arc<dyn xray_app_dispatcher::DispatchHandler>);

impl xray_proxy_hysteria::TcpDispatcher for HysteriaTcpDispatch {
    fn dispatch_tcp(
        &self,
        dest_addr: &str,
        stream: std::sync::Arc<xray_transport_hysteria::conn::InterStreamConn>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send + '_>> {
        let handler = Arc::clone(&self.0);
        // 解析 "host:port" → Destination（IPv4/IPv6/域名）
        let Some((host, port_str)) = dest_addr.rsplit_once(':') else {
            return Box::pin(std::future::ready(Err(std::io::Error::other(format!(
                "hysteria dest parse: {dest_addr}"
            )))));
        };
        let Ok(port) = port_str.parse::<u16>() else {
            return Box::pin(std::future::ready(Err(std::io::Error::other(format!(
                "hysteria dest port: {dest_addr}"
            )))));
        };
        let address = if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
            Address::IPv4(v4)
        } else if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
            Address::IPv6(v6)
        } else {
            Address::Domain(host.to_string())
        };
        let dest = Destination::new(address, Port::new(port), Network::TCP);
        Box::pin(async move {
            let conn = xray_transport_hysteria::HysteriaConn::new(stream);
            let (r, w) = tokio::io::split(conn);
            let link = Link::new(new_reader(r), new_writer(w));
            let _ = handler.dispatch(&dest, link).await;
            Ok(())
        })
    }
}

/// DNS inbound 服务入口。
///
/// 同时监听 UDP 和 TCP：
/// - UDP：recv_from → handle_packet → send_to 响应
/// - TCP：accept → handle_conn（2B 长度前缀帧循环）
pub async fn serve_dns(
    udp: UdpSocket,
    tcp: InboundTcpListener,
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
    dispatcher: Option<Arc<xray_app_dispatcher::DefaultDispatcher>>,
    shutdown_token: CancellationToken,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let mut handles = Vec::new();
    for ib in &built.inbounds {
        // 方案 B：生产链经 DefaultDispatcher（sniffing + stats + routing）。
        // 每个 inbound 一份 ohm 快照，default 替换为携带该 inbound sniffing 配置
        // 与 tag 的 wrapper；master ohm 的 default 保持真实出站（避免递归）。
        // wrapper 外再包 MuxCarrierHandler（Go always.go:89 mux.NewServer 装饰器）：
        // v1.mux.cool carrier 由 mux ServerWorker 接管，子会话回 wrapper。
        let per_ohm = dispatcher
            .as_ref()
            .map(|d| {
                let snap = Arc::new(ohm.snapshot());
                let sniff =
                    crate::wiring::sniffing_request_from_json(ib.sniffing_json.as_ref());
                let inbound_handler: Arc<dyn xray_app_dispatcher::DispatchHandler> =
                    Arc::new(crate::wiring::InboundDispatchHandler::new(
                        Arc::clone(d),
                        sniff,
                        &ib.tag,
                    ));
                snap.set_default(Arc::new(crate::wiring::MuxCarrierHandler::new(
                    inbound_handler,
                )));
                snap
            })
            .unwrap_or_else(|| Arc::clone(&ohm));
        // policy manager（dispatcher 装配时注入，见 start_full_dispatched）：
        // 供 http inbound 按 userLevel 查 handshake 超时等 per-level 策略。
        let policy = dispatcher
            .as_ref()
            .and_then(|d| d.policy_manager.clone());
        if let Some(handle) =
            spawn_one_inbound(ib, per_ohm, policy, shutdown_token.clone()).await?
        {
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
/// maxTimeDiff（时间戳容差秒，**0 = 禁用时间窗校验**）。
/// 来源：Go xtls/reality `tls.go:259` `config.MaxTimeDiff == 0 || time.Since(...).Abs() <= MaxTimeDiff`。
#[derive(Debug)]
struct RealityInboundConfig {
    server_private_key: [u8; 32],
    short_ids: Vec<[u8; 8]>,
    max_diff: u32,
    fallback_dest: String,
    xver: u8,
    /// fs0o：客户端版本门（字节序字典序比较；空 = 不限）。
    min_client_ver: Vec<u8>,
    max_client_ver: Vec<u8>,
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
    // mldsa65Seed：后量子签名未实现（cz5x）。配置在场即显式报错，
    // 不静默忽略——避免运营者误以为 PQC 已生效。
    if let Some(seed) = json.get("mldsa65Seed").and_then(|x| x.as_str()) {
        if !seed.is_empty() {
            return Err(std::io::Error::other(
                "reality: mldsa65Seed configured but ML-DSA-65 signing is not implemented \
                 in Rust (remove mldsa65Seed or use a Go server)",
            ));
        }
    }
    // maxTimeDiff：Go 默认 0（禁用），单位毫秒 → 转换为秒传给 verify。
    // 缺省注入 43200（原 Rust 行为）会让 Go 兼容配置（无字段）的客户端被强制±12h 窗。
    let max_diff_ms = json
        .get("maxTimeDiff")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let max_diff = (max_diff_ms / 1000) as u32;
    let parse_ver = |s: &str| -> Vec<u8> {
        s.split('.')
            .filter_map(|p| p.trim().parse::<u8>().ok())
            .collect()
    };
    let min_client_ver = json
        .get("minClientVer")
        .and_then(|x| x.as_str())
        .map(&parse_ver)
        .unwrap_or_default();
    let max_client_ver = json
        .get("maxClientVer")
        .and_then(|x| x.as_str())
        .map(&parse_ver)
        .unwrap_or_default();

    Ok(RealityInboundConfig {
        server_private_key: key,
        short_ids,
        max_diff,
        fallback_dest,
        xver,
        min_client_ver,
        max_client_ver,
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
    listener: InboundTcpListener,
    ohm: Arc<SimpleOhm>,
    validator: Arc<dyn VlessValidator>,
    cfg: RealityInboundConfig,
    options: Option<VlessInboundOptions>,
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
        let options = options.clone();
        let key = cfg.server_private_key;
        let ids = cfg.short_ids.clone();
        let max_diff = cfg.max_diff;
        let dest = cfg.fallback_dest.clone();
        let xver = cfg.xver;
        let min_ver = cfg.min_client_ver.clone();
        let max_ver = cfg.max_client_ver.clone();
        tokio::spawn(async move {
            match server_tls(stream, &key, &ids, max_diff, &min_ver, &max_ver).await {
                Ok(RealityServerOutcome::Verified(tls)) => {
                    if let Err(e) = xray_proxy_vless::handle_vless_connection(
                        tls,
                        &handler,
                        &validator,
                        options.clone(),
                        None,
                    )
                    .await
                    {
                        // Go vless inbound.go:522：拒绝 AtInfo + RemoteAddr。
                        tracing::info!(peer = %peer, error = %e, "reality vless connection ended with error");
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

/// settings.protocol 是否由 transport listener 承载（非裸 TCP）。
///
/// 对应 Go `tcp_hub.go::ListenTCP` 按 protocolName 查注册表；`tcp`/`raw`
/// 走既有 serve_* 直连路径（TLS accept + fallback SNI/ALPN 提取在该层完成）。
/// 别名表与 `xray_transport::dialer::protocol_settings_key` 一致。
fn is_transport_listener_protocol(protocol: &str) -> bool {
    matches!(
        protocol,
        "ws" | "websocket"
            | "grpc" | "h2" | "http"
            | "kcp" | "mkcp"
            | "httpupgrade"
            | "splithttp" | "xhttp"
    )
}

/// 经 listener_registry 启动 transport inbound（ws/grpc/kcp/httpupgrade/splithttp）。
///
/// 对应 Go `proxyman` worker 对 `internet.ListenTCP` 的调用：TLS/security
/// 由 transport hub 内部完成（grpc/ws hub 自带 accept_tls），上层 ConnHandler
/// 收到的已是协议解包后的明文 conn。listener 移入 pending future 保活，
/// shutdown abort 时随 task drop。
async fn spawn_transport_listener_inbound(
    tag: &str,
    bind_addr: SocketAddr,
    settings: xray_transport::dialer::StreamSettings,
    shutdown_token: CancellationToken,
    on_conn: xray_transport::listener_registry::ConnHandler,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let listener = xray_transport::listener_registry::listen_tcp(
        bind_addr,
        settings,
        xray_transport::sockopt::SocketOptions::default(),
        on_conn,
    )
    .await?;
    tracing::info!(tag = %tag, addr = %bind_addr, "transport inbound listening");
    Ok(Some(spawn_inbound_serve(tag.to_string(), shutdown_token, async move {
        let _listener = listener;
        std::future::pending::<()>().await;
        Ok(())
    })))
}

/// `Box<dyn Connection>` 的 peer/local 地址（transport 解包层丢失时用 bind 地址兜底）。
fn transport_conn_addrs(
    conn: &dyn xray_transport::connection::Connection,
    bind_addr: SocketAddr,
) -> (SocketAddr, SocketAddr) {
    let peer = conn.remote_addr().ok().flatten().unwrap_or(bind_addr);
    let local = conn.local_addr().ok().flatten().unwrap_or(bind_addr);
    (peer, local)
}

/// 无 policy manager 时的 inbound 握手/首包读超时兜底。Go `SessionDefault()`
/// `Timeouts.Handshake = 60s`（features/policy/policy.go:125-133，注释：对齐
/// nginx client_header_timeout 以免暴露服务端身份）；ss/dokodemo 路径同样取值。
const DEFAULT_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// 按 userLevel 查 policy 的握手超时；无 policy manager 时回退
/// [`DEFAULT_HANDSHAKE_TIMEOUT`]（Go DefaultPolicyFeature 兜底语义）。
fn handshake_timeout_for(
    policy: &Option<std::sync::Arc<dyn xray_features::policy::PolicyManager>>,
    level: u32,
) -> std::time::Duration {
    policy
        .as_ref()
        .map(|pm| pm.policy_for_level(level).timeout.handshake)
        .unwrap_or(DEFAULT_HANDSHAKE_TIMEOUT)
}

/// 按协议种类启动单个 inbound listener。
async fn spawn_one_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
    policy: Option<Arc<dyn xray_features::policy::PolicyManager>>,
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
    // vodx：unix 路径监听（Go system_listener.go:118 UnixAddr 分支）走 UDS
    // listener；端口语义不适用，须在 port 解析前分派。判别与 xray-conf
    // Address::is_unix_path 一致（'/' 绝对路径 / '@' abstract）。
    if is_unix_listen_path(listen) {
        return spawn_unix_inbound(ib, ohm, policy, shutdown_token, listen).await;
    }
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
    // e7le：入站 sockopt（streamSettings.sockopt JSON；缺省 tcp_nodelay=true）
    // 统一喂给 InboundTcpListener——此前 9 处裸 bind+accept 无 nodelay，
    // 与 Go net 默认（NoDelay=true）相反，流式下行每 chunk 受 Nagle 拖累。
    let inbound_sockopts = xray_transport::dialer::StreamSettings::from_json(
        ib.stream_settings_json.as_ref(),
    )
    .socket_options();

    match ib.entry.kind.as_str() {
        "socks" => {
            let listener = InboundTcpListener::bind(&addr, inbound_sockopts.clone()).await?;
            let config = Arc::new(parse_socks_server_config(&ib.entry.data)?);
            // 握手限时（Go proxy/socks：SetReadDeadline(policy().Timeouts.Handshake)）
            let handshake_timeout = Some(handshake_timeout_for(&policy, config.user_level));
            tracing::info!(tag = %ib.tag, addr = %addr, auth = ?config.auth_type, udp = config.udp_enabled, "socks5 inbound listening");
            Ok(Some(spawn_inbound_serve(ib.tag.clone(), shutdown_token, async move {
                serve_socks5(listener, ohm, config, handshake_timeout).await
            })))
        }
        "mixed" => {
            // V2RayN / Go xray mixed 协议 = socks + http 复合 listener。
            // 单 listener peek 首字节嗅探:0x05 → socks;ASCII 字母开头 → http。
            let socks_cfg = Arc::new(parse_socks_server_config(&ib.entry.data)?);
            let http_cfg = Arc::new(parse_http_config(&ib.entry.data)?);
            // 嗅探/socks/http 三段握手读共用一个限时；对齐 Go mixed mux 的两个
            // handler（socks/http 均按 policy().Timeouts.Handshake 限时）。
            let handshake_timeout = handshake_timeout_for(&policy, http_cfg.user_level);
            let listener = InboundTcpListener::bind(&addr, inbound_sockopts.clone()).await?;
            tracing::info!(tag = %ib.tag, addr = %addr, "mixed (socks+http) inbound listening");
            Ok(Some(spawn_inbound_serve(ib.tag.clone(), shutdown_token, async move {
                serve_mixed(listener, ohm, socks_cfg, http_cfg, Some(handshake_timeout)).await
            })))
        }
        "vless" => {
            let validator: Arc<dyn VlessValidator> = build_vless_validator(&ib.entry.data)?;
            // ENC decryption（Go inbound.go:104-114 handler.decryption）：settings
            // 级 "mlkem768x25519plus.*" 字符串 → handler 级共享 ServerInstance。
            let decryption = build_vless_decryption(&ib.entry.data)?;
            let options = VlessInboundOptions {
                decryption: decryption.clone(),
                // sm80④：policy Timeouts.Handshake 下传（Go inbound.go:281-284）
                handshake_timeout: Some(handshake_timeout_for(&policy, 0)),
                ..Default::default()
            };
            let settings = xray_transport::dialer::StreamSettings::from_json(
                ib.stream_settings_json.as_ref(),
            );
            if is_transport_listener_protocol(&settings.protocol) {
                // transport 分支（ws/grpc/kcp/httpupgrade/splithttp）：listener_registry
                // 承载监听，TLS/security 在 transport hub 内部终结——勿再叠
                // build_tls_acceptor（双重握手）。
                let handler = ohm.get_default_handler().ok_or_else(|| {
                    std::io::Error::other("no default outbound handler registered")
                })?;
                let fallbacks = build_vless_fallbacks(&ib.entry.data);
                let bind_addr: SocketAddr = addr.parse().map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("parse addr: {e}"))
                })?;
                tracing::info!(tag = %ib.tag, addr = %addr, network = %settings.protocol, security = %settings.security, users = validator.get_uuid_count(), "vless transport inbound listening");
                let on_conn: xray_transport::listener_registry::ConnHandler = Arc::new(move |conn| {
                    let handler = Arc::clone(&handler);
                    let validator = Arc::clone(&validator);
                    let fallbacks = fallbacks.clone();
                    let options = options.clone();
                    tokio::spawn(async move {
                        let (peer, local) = transport_conn_addrs(conn.as_ref(), bind_addr);
                        // TLS 已在 transport hub 内终结，name/alpn 不可得
                        if let Err(e) = xray_proxy_vless::handle_connection_with_fallback(
                            conn, &handler, &validator, fallbacks, peer, local,
                            String::new(), String::new(), Some(options), None,
                        ).await {
                            // Go vless inbound.go:522：拒绝 AtInfo + RemoteAddr。
                            tracing::info!(peer = %peer, error = %e, "vless transport connection ended with error");
                        }
                    });
                });
                spawn_transport_listener_inbound(&ib.tag, bind_addr, settings, shutdown_token, on_conn).await
            } else {
                let listener = InboundTcpListener::bind(&addr, inbound_sockopts.clone()).await?;
                if settings.security == "reality" {
                    // REALITY：server_tls 验证 → Verified 走 VLESS；Invalid fallback 到 dest
                    let reality = parse_reality_config(&settings)?;
                    tracing::info!(tag = %ib.tag, addr = %addr, users = validator.get_uuid_count(), fallback = %reality.fallback_dest, "vless+reality inbound listening");
                    Ok(Some(spawn_inbound_serve(ib.tag.clone(), shutdown_token, async move {
                        serve_reality_vless(listener, ohm, validator, reality, Some(options)).await
                    })))
                } else {
                    let tls = build_tls_acceptor(ib.stream_settings_json.as_ref())?;
                    // VLESS fallbacks：Go napfb（name→alpn→path→dest+xver）
                    let fallbacks = build_vless_fallbacks(&ib.entry.data);
                    tracing::info!(tag = %ib.tag, addr = %addr, users = validator.get_uuid_count(), tls = tls.is_some(), fallbacks = fallbacks.as_ref().map_or(0, |f| f.len()), enc = decryption.is_some(), "vless inbound listening");
                    Ok(Some(spawn_inbound_serve(ib.tag.clone(), shutdown_token, async move {
                        serve_vless(listener, ohm, validator, tls, fallbacks, Some(options)).await
                    })))
                }
            }
        }
        "trojan" => {
            let users = build_trojan_users(&ib.entry.data)?;
            // Trojan fallback：解析 JSON fallbacks 数组构建决策树
            // （dest 数字/缺失对齐 Go trojan.go:151-198，解析失败即启动失败）
            let fallbacks = build_trojan_fallbacks(&ib.entry.data)?;
            let settings = xray_transport::dialer::StreamSettings::from_json(
                ib.stream_settings_json.as_ref(),
            );
            if is_transport_listener_protocol(&settings.protocol) {
                // transport 分支：listener_registry 承载，TLS 在 hub 内终结。
                let handler = ohm.get_default_handler().ok_or_else(|| {
                    std::io::Error::other("no default outbound handler registered")
                })?;
                let validator = Arc::new(xray_proxy_trojan::Validator::new());
                for (_, user) in users {
                    if let Err(e) = validator.add(user) {
                        tracing::warn!(error = %e, "skip duplicate user during trojan transport inbound init");
                    }
                }
                let bind_addr: SocketAddr = addr.parse().map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("parse addr: {e}"))
                })?;
                tracing::info!(tag = %ib.tag, addr = %addr, network = %settings.protocol, security = %settings.security, users = validator.get_key_count(), "trojan transport inbound listening");
                let hs_timeout = handshake_timeout_for(&policy, 0);
                let on_conn: xray_transport::listener_registry::ConnHandler = Arc::new(move |conn| {
                    let validator = Arc::clone(&validator);
                    let handler = Arc::clone(&handler);
                    let fb_policy = fallbacks.clone();
                    tokio::spawn(async move {
                        let (peer, local) = transport_conn_addrs(conn.as_ref(), bind_addr);
                        xray_proxy_trojan::serve_trojan_conn(
                            conn, validator, handler, fb_policy, peer, local,
                            String::new(), String::new(),
                            hs_timeout,
                        ).await;
                    });
                });
                spawn_transport_listener_inbound(&ib.tag, bind_addr, settings, shutdown_token, on_conn).await
            } else {
                let tls = build_tls_acceptor(ib.stream_settings_json.as_ref())?;
                let listener = InboundTcpListener::bind(&addr, inbound_sockopts.clone()).await?;
                tracing::info!(tag = %ib.tag, addr = %addr, users = users.len(), tls = tls.is_some(), "trojan inbound listening");
                Ok(Some(spawn_inbound_serve(ib.tag.clone(), shutdown_token, async move {
                    serve_trojan(listener, ohm, users, fallbacks, tls, handshake_timeout_for(&policy, 0)).await
                })))
            }
        }
        "vmess" => {
            let validator = build_vmess_validator(&ib.entry.data)?;
            let settings = xray_transport::dialer::StreamSettings::from_json(
                ib.stream_settings_json.as_ref(),
            );
            if is_transport_listener_protocol(&settings.protocol) {
                // transport 分支：listener_registry 承载，TLS 在 hub 内终结。
                let handler = ohm.get_default_handler().ok_or_else(|| {
                    std::io::Error::other("no default outbound handler registered")
                })?;
                let history = Arc::new(xray_proxy_vmess::SessionHistory::new());
                // transport 层无 TLS 时维持裸 TCP 的 drain 防指纹语义（Go：!isTLS → drain）
                let is_drain = !settings.is_tls();
                let bind_addr: SocketAddr = addr.parse().map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("parse addr: {e}"))
                })?;
                tracing::info!(tag = %ib.tag, addr = %addr, network = %settings.protocol, security = %settings.security, "vmess transport inbound listening");
                let hs_timeout = handshake_timeout_for(&policy, 0);
                let on_conn: xray_transport::listener_registry::ConnHandler = Arc::new(move |conn| {
                    let handler = Arc::clone(&handler);
                    let validator = Arc::clone(&validator);
                    let history = Arc::clone(&history);
                    tokio::spawn(async move {
                        let (peer, _local) = transport_conn_addrs(conn.as_ref(), bind_addr);
                        if let Err(e) = xray_proxy_vmess::handle_vmess_connection(
                            conn, &handler, &validator, &history, is_drain,
                            hs_timeout,
                        ).await {
                            // Go vmess inbound.go:250：拒绝 AtInfo + RemoteAddr。
                            tracing::info!(peer = %peer, error = %e, "vmess transport connection ended with error");
                        }
                    });
                });
                spawn_transport_listener_inbound(&ib.tag, bind_addr, settings, shutdown_token, on_conn).await
            } else {
                let tls = build_tls_acceptor(ib.stream_settings_json.as_ref())?;
                let listener = InboundTcpListener::bind(&addr, inbound_sockopts.clone()).await?;
                tracing::info!(tag = %ib.tag, addr = %addr, tls = tls.is_some(), "vmess inbound listening");
                Ok(Some(spawn_inbound_serve(ib.tag.clone(), shutdown_token, async move {
                    serve_vmess(listener, ohm, validator, tls, handshake_timeout_for(&policy, 0)).await
                })))
            }
        }
        "http" => {
            let config = parse_http_config(&ib.entry.data)?;
            // userLevel 生效：policy_for_level(UserLevel).timeout.handshake →
            // serve_http 读首请求超时。对应 Go proxy/http/server.go:47-51 policy()
            // + :112 SetReadDeadline(Timeouts.Handshake)；无 policy manager（如
            // 无 policy 配置块）时对齐 Go SessionDefault 兜底 60s
            // （features/policy/policy.go:130），不再无限时。
            let handshake_timeout = handshake_timeout_for(&policy, config.user_level);
            let listener = InboundTcpListener::bind(&addr, inbound_sockopts.clone()).await?;
            tracing::info!(tag = %ib.tag, addr = %addr, "http inbound listening");
            Ok(Some(spawn_inbound_serve(ib.tag.clone(), shutdown_token, async move {
                serve_http(listener, ohm, Arc::new(config), Some(handshake_timeout)).await
            })))
        }
        "dokodemo" => {
            let settings = parse_dokodemo_settings(&ib.entry.data)?;
            let dest = settings.dest.clone();
            // TLS（streamSettings security=tls）：对应 Go tls.NewListener 包裹，
            // SNI 在 serve_dokodemo 内用于 follow_redirect 未覆盖时的 dest 改写。
            let tls = build_tls_acceptor(ib.stream_settings_json.as_ref())?;
            // followRedirect 的 SO_ORIGINAL_DST 仅 Linux 可用；非 Linux 回落
            // predefined dest（对齐 Go fakeudp_other.go 的平台差异处理方式）。
            #[cfg(not(target_os = "linux"))]
            if settings.follow_redirect {
                tracing::warn!(
                    tag = %ib.tag,
                    "dokodemo followRedirect requires Linux (SO_ORIGINAL_DST / UDP TPROXY); falling back to predefined dest"
                );
            }
            let mut handles = Vec::new();
            if settings.allow_tcp {
                let listener = InboundTcpListener::bind(&addr, inbound_sockopts.clone()).await?;
                tracing::info!(tag = %ib.tag, addr = %addr, dest = ?dest, tls = tls.is_some(), "dokodemo TCP inbound listening");
                let ohm_tcp = Arc::clone(&ohm);
                let opts = DokodemoTcpOptions {
                    dest: dest.clone(),
                    port_map: settings.port_map,
                    follow_redirect: settings.follow_redirect,
                    tls,
                };
                handles.push(tokio::spawn(async move {
                    if let Err(e) = serve_dokodemo(listener, ohm_tcp, opts).await {
                        tracing::error!(error = %e, "dokodemo TCP inbound stopped");
                    }
                }));
            }
            if settings.allow_udp {
                let bind_addr: SocketAddr = addr.parse().map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("parse addr: {e}"))
                })?;
                let dispatch = ohm.get_default_handler().ok_or_else(|| {
                    std::io::Error::other(
                        "dokodemo UDP inbound requires a default outbound handler",
                    )
                })?;
                tracing::info!(tag = %ib.tag, addr = %addr, dest = ?dest, "dokodemo UDP inbound listening");
                let dest_udp = dest.clone();
                let follow_redirect = settings.follow_redirect;
                handles.push(tokio::spawn(async move {
                    if let Err(e) =
                        serve_dokodemo_udp(bind_addr, dispatch, dest_udp, follow_redirect).await
                    {
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
            let settings = xray_transport::dialer::StreamSettings::from_json(
                ib.stream_settings_json.as_ref(),
            );
            // transport 分支（grpc/kcp/ws hub 承载）：仅 Legacy 模式接线（2022 模式
            // 的 handle_conn 尚为 TcpStream 特化，保持裸 TCP 回落不回归）。
            if is_transport_listener_protocol(&settings.protocol) {
                if let SsInboundMode::Legacy(ss_ib) = parse_ss_inbound_config(&ib.entry.data)? {
                    let handler = ohm.get_default_handler().ok_or_else(|| {
                        std::io::Error::other("no default outbound handler registered")
                    })?;
                    let bind_addr: SocketAddr = addr.parse().map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("parse addr: {e}"))
                    })?;
                    tracing::info!(tag = %ib.tag, addr = %addr, network = %settings.protocol, security = %settings.security, "ss transport inbound listening");
                    let on_conn: xray_transport::listener_registry::ConnHandler = Arc::new(move |conn| {
                        let ib = Arc::clone(&ss_ib);
                        let handler = Arc::clone(&handler);
                        let hs_timeout = handshake_timeout_for(&policy, 0);
                        tokio::spawn(async move {
                            ss_legacy_pipeline(ib, handler, conn, hs_timeout).await;
                        });
                    });
                    return spawn_transport_listener_inbound(&ib.tag, bind_addr, settings, shutdown_token, on_conn).await;
                }
                tracing::warn!(tag = %ib.tag, network = %settings.protocol, "ss transport inbound only supports legacy AEAD mode; falling back to raw TCP");
            }
            let listener = InboundTcpListener::bind(&addr, inbound_sockopts.clone()).await?;
            let inbound = parse_ss_inbound_config(&ib.entry.data)?;
            tracing::info!(tag = %ib.tag, addr = %addr, "shadowsocks inbound listening");
            Ok(Some(spawn_inbound_serve(ib.tag.clone(), shutdown_token, async move {
                serve_ss(listener, ohm, inbound, handshake_timeout_for(&policy, 0)).await
            })))
        }
        // hysteria inbound：HysteriaInboundHandler impl InboundHandler（rxw：接 dispatcher）
        "hysteria" | "hysteria2" => {
            let bind_addr: std::net::SocketAddr = addr.parse()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("parse addr: {e}")))?;
            let (config, factory) = parse_hysteria_inbound_config(&ib.entry.data, bind_addr, ib.stream_settings_json.as_ref())?;
            let dispatch = ohm.get_default_handler().ok_or_else(|| {
                std::io::Error::other("hysteria inbound requires a default outbound handler")
            })?;
            let handler = xray_proxy_hysteria::HysteriaInboundHandler::new(
                &ib.tag, config, bind_addr, factory,
            )
            .map_err(|e| std::io::Error::other(format!("hysteria inbound: {e}")))?
            .with_dispatcher(Some(Arc::new(HysteriaTcpDispatch(Arc::clone(&dispatch)))))
            .with_udp_dispatcher(Some(dispatch));
            tracing::info!(tag = %ib.tag, addr = %addr, "hysteria inbound listening");
            Ok(Some(spawn_inbound_serve(ib.tag.clone(), shutdown_token, async move {
                handler.start().await.map_err(|e| std::io::Error::other(format!("{e}")))
            })))
        }
        // anytls inbound：AnytlsInboundHandler impl InboundHandler
        "anytls" => {
            let bind_addr: std::net::SocketAddr = addr.parse()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("parse addr: {e}")))?;
            let (tls_acceptor, password) = parse_anytls_tls_acceptor(&ib.entry.data)?;
            let handler = xray_proxy_anytls::AnytlsInboundHandler::new(
                &ib.tag, bind_addr, tls_acceptor,
            )
            .with_password(password);
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
            let tcp = InboundTcpListener::bind(&addr, inbound_sockopts.clone()).await?;
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

/// listen 地址是否为 unix domain socket 路径。
///
/// 判别与 `xray_conf` `Address::is_unix_path` 一致：`/` 开头为文件系统路径，
/// `@` 开头为 Linux abstract socket。
fn is_unix_listen_path(listen: &str) -> bool {
    listen.starts_with('/') || listen.starts_with('@')
}

/// UDS accept 循环：每连接调用 `on_conn`（与 transport hub ConnHandler 同形）。
///
/// 单次 accept 失败仅 log 不终止 listener（与各 TCP serve 循环同语义）。
#[cfg(unix)]
async fn serve_unix_listener(
    listener: xray_transport::system_listener::UnixListener,
    on_conn: xray_transport::listener_registry::ConnHandler,
) -> std::io::Result<()> {
    use xray_transport::system_listener::SystemListener;
    loop {
        match listener.accept().await {
            Ok(conn) => on_conn(conn),
            Err(e) => {
                tracing::warn!(error = %e, "unix inbound accept failed");
            }
        }
    }
}

/// unix 路径 inbound：UDS listener + UnixConnection accept（bd vodx）。
///
/// 对应 Go `DefaultListener.Listen` 的 `*net.UnixAddr` 分支
/// （transport/internet/system_listener.go:118）。Go 侧 TCP 类代理经
/// `net.Conn` 抽象天然支持 UDS；Rust 侧 serve 层为 TcpStream 特化，故仅
/// 接线已有泛型/`Connection` 入口的协议（socks/vless/vmess/trojan/ss 的
/// 裸 TCP 路径），其余协议显式报错，不静默错绑。security=tls/reality 与
/// transport 协议（ws/grpc/kcp/…）的终结层不支持 UDS，同样显式报错。
#[cfg(unix)]
async fn spawn_unix_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
    policy: Option<Arc<dyn xray_features::policy::PolicyManager>>,
    shutdown_token: CancellationToken,
    listen: &str,
) -> std::io::Result<Option<JoinHandle<()>>> {
    use xray_transport::system_listener::listen_unix_system;

    let settings =
        xray_transport::dialer::StreamSettings::from_json(ib.stream_settings_json.as_ref());
    if is_transport_listener_protocol(&settings.protocol) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "uds inbound '{}': transport protocol '{}' not supported over unix socket",
                ib.tag, settings.protocol
            ),
        ));
    }
    match settings.security.as_str() {
        "" | "none" => {}
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!(
                    "uds inbound '{}': security='{other}' not supported over unix socket",
                    ib.tag
                ),
            ));
        }
    }
    // 协议支持矩阵前置：不支持 UDS 的协议在 bind 前显式报错（fail-fast，
    // 对齐 Go inbound 创建失败即启动失败的语义）。
    const UDS_SUPPORTED_PROTOCOLS: &[&str] =
        &["socks", "vless", "vmess", "trojan", "shadowsocks"];
    if !UDS_SUPPORTED_PROTOCOLS.contains(&ib.entry.kind.as_str()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "uds inbound '{}': protocol '{}' not supported over unix socket",
                ib.tag, ib.entry.kind
            ),
        ));
    }
    let listener = listen_unix_system(listen, settings.socket_options()).await?;
    let handler = ohm.get_default_handler().ok_or_else(|| {
        std::io::Error::other("no default outbound handler registered")
    })?;
    // UDS 无 SocketAddr；对齐 Go UnixConnWrapper.RemoteAddr 的 0.0.0.0:0。
    let unspecified =
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

    let serve: std::pin::Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>> =
        match ib.entry.kind.as_str() {
            "socks" => {
                let config = Arc::new(parse_socks_server_config(&ib.entry.data)?);
                let handshake_timeout = Some(handshake_timeout_for(&policy, config.user_level));
                Box::pin(serve_unix_listener(listener, {
                    let handler = Arc::clone(&handler);
                    Arc::new(move |conn| {
                        let handler = Arc::clone(&handler);
                        let config = Arc::clone(&config);
                        tokio::spawn(async move {
                            let peer =
                                conn.remote_addr().ok().flatten().unwrap_or(unspecified);
                            if let Err(e) = handle_connection(
                                conn,
                                peer,
                                &config,
                                &handler,
                                handshake_timeout,
                            )
                            .await
                            {
                                tracing::info!(
                                    peer = %peer,
                                    error = %e,
                                    "socks5 (uds) connection ended with error"
                                );
                            }
                        });
                    })
                }))
            }
            "vless" => {
                let validator: Arc<dyn VlessValidator> = build_vless_validator(&ib.entry.data)?;
                let decryption = build_vless_decryption(&ib.entry.data)?;
                let options = VlessInboundOptions {
                    decryption: decryption.clone(),
                    ..Default::default()
                };
                let fallbacks = build_vless_fallbacks(&ib.entry.data);
                tracing::info!(
                    tag = %ib.tag,
                    users = validator.get_uuid_count(),
                    "vless (uds) inbound listening"
                );
                Box::pin(serve_unix_listener(listener, {
                    let handler = Arc::clone(&handler);
                    Arc::new(move |conn| {
                        let handler = Arc::clone(&handler);
                        let validator = Arc::clone(&validator);
                        let fallbacks = fallbacks.clone();
                        let options = options.clone();
                        tokio::spawn(async move {
                            let (peer, local) =
                                transport_conn_addrs(conn.as_ref(), unspecified);
                            if let Err(e) = xray_proxy_vless::handle_connection_with_fallback(
                                conn, &handler, &validator, fallbacks, peer, local,
                                String::new(), String::new(), Some(options), None,
                            )
                            .await
                            {
                                tracing::info!(
                                    peer = %peer,
                                    error = %e,
                                    "vless (uds) connection ended with error"
                                );
                            }
                        });
                    })
                }))
            }
            "vmess" => {
                let validator = build_vmess_validator(&ib.entry.data)?;
                let history = Arc::new(xray_proxy_vmess::SessionHistory::new());
                // security 已 gate 为 none → 与裸 TCP 分支同为 drain 语义。
                let is_drain = !settings.is_tls();
                tracing::info!(tag = %ib.tag, "vmess (uds) inbound listening");
                Box::pin(serve_unix_listener(listener, {
                    let handler = Arc::clone(&handler);
                    Arc::new(move |conn| {
                        let handler = Arc::clone(&handler);
                        let validator = Arc::clone(&validator);
                        let history = Arc::clone(&history);
                        tokio::spawn(async move {
                            let (peer, _local) =
                                transport_conn_addrs(conn.as_ref(), unspecified);
                            if let Err(e) = xray_proxy_vmess::handle_vmess_connection(
                                conn, &handler, &validator, &history, is_drain,
                            )
                            .await
                            {
                                tracing::info!(
                                    peer = %peer,
                                    error = %e,
                                    "vmess (uds) connection ended with error"
                                );
                            }
                        });
                    })
                }))
            }
            "trojan" => {
                let users = build_trojan_users(&ib.entry.data)?;
                let fallbacks = build_trojan_fallbacks(&ib.entry.data)?;
                let validator = Arc::new(xray_proxy_trojan::Validator::new());
                for (_, user) in users {
                    if let Err(e) = validator.add(user) {
                        tracing::warn!(
                            error = %e,
                            "skip duplicate user during trojan uds inbound init"
                        );
                    }
                }
                tracing::info!(tag = %ib.tag, "trojan (uds) inbound listening");
                Box::pin(serve_unix_listener(listener, {
                    let handler = Arc::clone(&handler);
                    Arc::new(move |conn| {
                        let handler = Arc::clone(&handler);
                        let validator = Arc::clone(&validator);
                        let fallbacks = fallbacks.clone();
                        tokio::spawn(async move {
                            let (peer, local) =
                                transport_conn_addrs(conn.as_ref(), unspecified);
                            xray_proxy_trojan::serve_trojan_conn(
                                conn, validator, handler, fallbacks, peer, local,
                                String::new(), String::new(),
                            )
                            .await;
                        });
                    })
                }))
            }
            "shadowsocks" => {
                let inbound = match parse_ss_inbound_config(&ib.entry.data)? {
                    SsInboundMode::Legacy(ss_ib) => Arc::new(ss_ib),
                    _ => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            format!(
                                "uds inbound '{}': ss2022 not supported over unix socket",
                                ib.tag
                            ),
                        ));
                    }
                };
                tracing::info!(tag = %ib.tag, "shadowsocks (uds) inbound listening");
                Box::pin(serve_unix_listener(listener, {
                    let handler = Arc::clone(&handler);
                    Arc::new(move |conn| {
                        let handler = Arc::clone(&handler);
                        let inbound = Arc::clone(&inbound);
                        let hs_timeout = handshake_timeout_for(&policy, 0);
                        tokio::spawn(async move {
                            ss_legacy_pipeline(inbound, handler, conn, hs_timeout).await;
                        });
                    })
                }))
            }
            _ => unreachable!("uds protocol support checked above"),
        };

    Ok(Some(spawn_inbound_serve(
        ib.tag.clone(),
        shutdown_token,
        serve,
    )))
}

/// 非 unix 平台：unix 路径监听显式 Unsupported（vodx 验收：Windows 断言），
/// 不静默回落 TCP bind。
#[cfg(not(unix))]
async fn spawn_unix_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
    policy: Option<Arc<dyn xray_features::policy::PolicyManager>>,
    shutdown_token: CancellationToken,
    listen: &str,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let _ = (ohm, policy, shutdown_token, listen);
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!(
            "unix socket inbound '{}' is only supported on unix platforms",
            ib.tag
        ),
    ))
}

/// 从 inbound entry.data（JSON）解析 SOCKS 服务端配置。
///
/// 字段对齐 Go `infra/conf/socks.go::SocksServerConfig`：
/// `{"auth":"password","users":[{"user":"u","pass":"p"}],"udp":true,"userLevel":0}`。
/// `users`/`accounts` 同义（Go 两个字段都收）；`ip`（Go `Host`，UDP relay 绑定
/// 地址，`xray-proxy-socks` UDP ASSOCIATE 消费）解析为 proto `IPOrDomain`。
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
    // `ip`（Go socks.go:35 `Host *Address json:"ip"`）：UDP relay 绑定 IP；
    // 未配置时 config.address 保持 None，socks 侧回退 127.0.0.1（既有默认行为）。
    if let Some(ip_str) = v.get("ip").and_then(|x| x.as_str()) {
        cfg.address = Some(match parse_address_str(ip_str) {
            Address::IPv4(ip) => xray_proto::xray::common::net::IpOrDomain {
                address: Some(xray_proto::xray::common::net::ip_or_domain::Address::Ip(
                    ip.octets().to_vec(),
                )),
            },
            Address::IPv6(ip) => xray_proto::xray::common::net::IpOrDomain {
                address: Some(xray_proto::xray::common::net::ip_or_domain::Address::Ip(
                    ip.octets().to_vec(),
                )),
            },
            Address::Domain(d) => xray_proto::xray::common::net::IpOrDomain {
                address: Some(xray_proto::xray::common::net::ip_or_domain::Address::Domain(d)),
            },
        });
    }
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

/// 解析 settings.decryption → handler 级共享 ENC 解密实例（Go inbound.go:104-114）。
///
/// `"none"`/缺省 → `None`（无 ENC 层）；`"mlkem768x25519plus.<mode>.<seconds>s.<keys>"` →
/// 初始化 [`xray_proxy_vless::encryption::ServerInstance`]（私钥 32B=X25519 /
/// 64B=ML-KEM-768 seed）。非法非 none 值报错（Go conf 层 Build 同为 error）。
fn build_vless_decryption(
    data: &[u8],
) -> std::io::Result<Option<std::sync::Arc<xray_proxy_vless::encryption::ServerInstance>>> {
    use xray_proxy_vless::encryption::{parse_server_decryption, ServerInstance as EncServerInstance};
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("vless inbound settings JSON: {e}")))?;
    let raw = v
        .get("decryption")
        .and_then(|d| d.as_str())
        .unwrap_or("none");
    let Some(p) = parse_server_decryption(raw) else {
        if raw != "none" && !raw.is_empty() {
            return Err(std::io::Error::other(format!(
                "VLESS settings: unsupported \"decryption\": {raw}"
            )));
        }
        return Ok(None);
    };
    let mut inst = EncServerInstance::new();
    let key_count = p.keys.len();
    inst
        .init(p.keys, p.xor_mode, p.seconds_from, p.seconds_to, &p.padding)
        .map_err(|e| std::io::Error::other(format!("vless decryption init: {e}")))?;
    tracing::info!(seconds_from = p.seconds_from, seconds_to = p.seconds_to, keys = key_count, "vless enc decryption enabled");
    Ok(Some(std::sync::Arc::new(inst)))
}

/// Linux abstract namespace padding（Go infra/conf/trojan.go:182-186）。
///
/// `dest` 以 `@@` 开头时（仅 unix 平台），把 `dest[1..]` 拷贝到 108 字节 NUL-padded
/// buffer（首字节隐式 `'\0'`），返回该 buffer 的字符串表示。haproxy 等下游需要
/// 固定长度的 `syscall.RawSockaddrUnix` 结构。
///
/// 非 unix 平台或 dest 不以 `@@` 开头时直接返回原值（保持 Windows 下无变换）。
fn apply_unix_abstract_padding(dest: &str) -> String {
    #[cfg(unix)]
    {
        // Linux `syscall.RawSockaddrUnix{}.Path` 字节数。
        // ponytail: hardcoded 108 对齐 syscall.RawSockaddrUnix.Path；改需联动内核常量。
        const UNIX_PATH_MAX: usize = 108;
        if let Some(stripped) = dest.strip_prefix("@@") {
            let mut buf = [0u8; UNIX_PATH_MAX];
            let src = stripped.as_bytes();
            let copy_len = src.len().min(UNIX_PATH_MAX);
            buf[..copy_len].copy_from_slice(&src[..copy_len]);
            // NUL 字节在 Rust String 中合法（`\0` 是 valid char），Linux 拨号时按
            // 首个 NUL 截断 abstract namespace path。
            return String::from_utf8_lossy(&buf).into_owned();
        }
    }
    dest.to_string()
}
/// 从 inbound entry.data（JSON）解析 trojan clients → HashMap<key_hash, MemoryUser>。
///
/// JSON 格式：`{"clients":[{"password":"...","email":""}]}` 或 `{"users":[...]}`。
/// 对每个 client：`MemoryAccount::new(password)`（内部计算 hex(sha224)）→ MemoryUser → key_hash 入表。
fn build_trojan_users(data: &[u8]) -> std::io::Result<HashMap<String, TrojanMemoryUser>> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("trojan inbound settings JSON: {e}")))?;
    let mut users = HashMap::new();
    // Go infra/conf/trojan.go:124-126：`if c.Clients != nil { c.Users = c.Clients }`
    // — 若 `clients` 字段存在则覆盖 `users`，否则 fall back 到 `users`。
    let client_list = v
        .get("clients")
        .or_else(|| v.get("users"))
        .and_then(|c| c.as_array());
    if let Some(clients) = client_list {
        for c in clients {
            // Trojan Flow 已移除（Go infra/conf/trojan.go:134-136 服务端逐用户检查）。
            // Rust 保留现行为：warn + 忽略该字段继续建用户。
            if let Some(w) = crate::outbound::trojan_flow_removed_warning(c) {
                xray_common::log::warning(w);
            }
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

/// 从 inbound entry.data（JSON）解析 trojan `fallbacks` 数组 → FallbackPolicy。
///
/// dest 形态对齐 Go `infra/conf/trojan.go:151-198`：
/// - json 数字 N（或纯数字字符串）→ `"localhost:N"`（:154-155 + :188-190）；
/// - `type` 缺省时按 dest 形态推导（:177-194）：`@`/`/` 前缀 → unix
///   （`@@` 抽象套接字做 108 字节 NUL padding），`host:port` → tcp；
/// - dest 缺失/null 且 `type` 也缺省 → 报错（:196-198；不再回退 127.0.0.1:80），
///   与 Go 一致：fallbacks 配置错误 = inbound 启动失败。
fn build_trojan_fallbacks(data: &[u8]) -> std::io::Result<Option<std::sync::Arc<FallbackPolicy>>> {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) else {
        return Ok(None);
    };
    let Some(fbs) = v.get("fallbacks").and_then(|f| f.as_array()) else {
        return Ok(None);
    };
    let mut list = Vec::with_capacity(fbs.len());
    for fb in fbs {
        let name = fb.get("name").and_then(|x| x.as_str()).unwrap_or("").into();
        let alpn = fb.get("alpn").and_then(|x| x.as_str()).unwrap_or("").into();
        let path = fb.get("path").and_then(|x| x.as_str()).unwrap_or("").into();
        let xver = fb.get("xver").and_then(|x| x.as_u64()).unwrap_or(0);
        let mut dest = match fb.get("dest") {
            Some(serde_json::Value::Number(n)) => n.to_string(),
            Some(serde_json::Value::String(s)) => s.clone(),
            _ => String::new(),
        };
        let mut fb_type = fb.get("type").and_then(|x| x.as_str()).unwrap_or("").to_string();
        if fb_type.is_empty() && !dest.is_empty() {
            if dest == "serve-ws-none" {
                // Go trojan.go:178-179：内建 ws 服务标记，透传给 serve 侧。
            } else if dest.starts_with('/') || dest.starts_with('@') {
                fb_type = "unix".into();
                dest = apply_unix_abstract_padding(&dest);
            } else {
                if dest.parse::<i64>().is_ok() {
                    dest = format!("localhost:{dest}");
                }
                if looks_like_host_port(&dest) {
                    fb_type = "tcp".into();
                }
            }
        }
        if fb_type.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                r#"trojan fallbacks: please fill in a valid value for every "dest""#,
            ));
        }
        list.push(Fallback { name, alpn, path, r#type: fb_type, dest, xver });
    }
    if list.is_empty() {
        Ok(None)
    } else {
        Ok(Some(FallbackPolicy::from_list(&list)))
    }
}

/// `host:port` 形态判定（Go `net.SplitHostPort` 的轻量版，仅用于 fallback
/// type=tcp 推导）：host 非空、port 全数字非空；host 含裸冒号视为非法
/// （方括号 IPv6 例外，`]` 结尾即合法）。
fn looks_like_host_port(s: &str) -> bool {
    match s.rsplit_once(':') {
        Some((h, p)) => {
            !h.is_empty()
                && !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && (!h.contains(':') || h.ends_with(']'))
        }
        None => false,
    }
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
/// 从 inbound entry.data（JSON）解析 http inbound 配置 → HttpServerConfig。
///
/// JSON 格式：`{"users":[{"user":"u","pass":"p"}],"allowTransparent":true,"userLevel":3}`。
/// `users`/`accounts` 同义（Go http.go:26-27 两个字段都收），users 优先。
/// 字段名/零值默认对齐 Go infra/conf/http.go:25-30（Transparent→AllowTransparent、UserLevel→UserLevel）。
fn parse_http_config(data: &[u8]) -> std::io::Result<HttpServerConfig> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("http inbound settings JSON: {e}")))?;
    let mut config = HttpServerConfig::default();
    if let Some(accounts) = v
        .get("users")
        .or_else(|| v.get("accounts"))
        .and_then(|c| c.as_array())
    {
        for a in accounts {
            let user = a.get("user").and_then(|x| x.as_str()).unwrap_or("");
            let pass = a.get("pass").and_then(|x| x.as_str()).unwrap_or("");
            if !user.is_empty() {
                config.accounts.insert(user.to_string(), pass.to_string());
            }
        }
    }
    config.allow_transparent = v
        .get("allowTransparent")
        .and_then(|c| c.as_bool())
        .unwrap_or(false);
    config.user_level = v
        .get("userLevel")
        .and_then(|c| c.as_u64())
        .unwrap_or(0) as u32;
    Ok(config)
}

/// 解析后的完整 dokodemo 设置。
#[derive(Debug)]
struct DokodemoInboundSettings {
    /// 预定义目标（TCP 和 UDP 各一份，网络类型不同）。address/port 均可缺省
    /// （Go `RewriteAddress`/`RewritePort` 独立可选）；仅 address 给出时 port=0，
    /// 由 serve 侧回填本地端口（Go dokodemo.go:86-100）。
    dest: Option<Destination>,
    /// 是否允许 TCP。
    allow_tcp: bool,
    /// 是否允许 UDP。
    allow_udp: bool,
    /// 是否跟随 iptables REDIRECT 原始目标（透明代理）。
    follow_redirect: bool,
    /// 端口映射：监听端口字符串 → "host:port"。
    port_map: HashMap<String, String>,
}

/// 从 inbound entry.data（JSON）解析完整 dokodemo 设置。
/// JSON 格式：`{"address":"1.2.3.4","port":80,"network":"tcp,udp","followRedirect":true}`。
/// `network` 可选（默认 `"tcp"`）；`followRedirect` 可选（默认 `false`）；
/// `address`/`port` 可选（Go dokodemo.go:26-31：address→RewriteAddress、
/// port→RewritePort 独立生效；followRedirect 透明代理时目标取 SO_ORIGINAL_DST）。
fn parse_dokodemo_settings(data: &[u8]) -> std::io::Result<DokodemoInboundSettings> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("dokodemo inbound settings JSON: {e}")))?;
    let address = v.get("address").and_then(|x| x.as_str()).map(parse_address_str);
    let port = v.get("port").and_then(|x| x.as_u64()).map(|p| p as u16);
    // network：逗号分隔，默认 tcp。对应 Go allowed_networks。
    let network_str = v.get("network").and_then(|x| x.as_str()).unwrap_or("tcp");
    let allow_tcp = network_str.contains("tcp");
    let allow_udp = network_str.contains("udp");
    let follow_redirect = v.get("followRedirect").and_then(|x| x.as_bool()).unwrap_or(false);

    // portMap：监听端口 → "host:port"（Go infra/conf/dokodemo.go:17，值校验 L39-43
    // SplitHostPort——host 可空、port 可空但必须有冒号且 port 为数字）。
    let mut port_map = HashMap::new();
    if let Some(map) = v.get("portMap").and_then(|x| x.as_object()) {
        for (key, val) in map {
            let val_str = val.as_str().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "dokodemo: portMap value must be a string",
                )
            })?;
            let (_, port_str) = val_str.rsplit_once(':').ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("dokodemo: invalid portMap: {val_str} (missing port)"),
                )
            })?;
            if !port_str.is_empty() && port_str.parse::<u16>().is_err() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("dokodemo: invalid portMap: {val_str} (bad port)"),
                ));
            }
            port_map.insert(key.clone(), val_str.to_string());
        }
    }

    // address/port 独立可选：仅 address 时 port=0（serve 侧回填本地端口）。
    let dest = address.map(|address| {
        let port = port.unwrap_or(0);
        if allow_udp && !allow_tcp {
            Destination::new(address, Port::new(port), Network::UDP)
        } else {
            Destination::new(address, Port::new(port), Network::TCP)
        }
    });
    Ok(DokodemoInboundSettings { dest, allow_tcp, allow_udp, follow_redirect, port_map })
}

/// 从 inbound entry.data（JSON）解析 vmess clients → TimedUserValidator。
///
/// JSON 格式：`{"clients":[{"id":"uuid","level":0,"alterId":0,"email":""}]}`。
/// 现代 VMess (AEAD) 不用 alterId：Go v26 已删除该字段，legacy 请求在服务端死于
/// "invalid user"。本实现保留兼容字段但 alterId≠0 直接拒绝（fail-fast），
/// 不静默忽略。`id` 解析为 `UUID` → `MemoryAccount::new(uuid)`。
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
            // alterId≠0 = legacy VMess 意图，AEAD-only 实现直接拒绝（数字/字符串都认）。
            let alter_id = c
                .get("alterId")
                .and_then(|x| x.as_i64().or_else(|| x.as_str().and_then(|s| s.parse::<i64>().ok())))
                .unwrap_or(0);
            if alter_id != 0 {
                tracing::warn!(alter_id, id, "vmess inbound: legacy VMess is not supported");
                return Err(std::io::Error::other(
                    VmessError::UnsupportedLegacyAlterId(alter_id).to_string(),
                ));
            }
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
/// JSON 格式：`{"method":"aes-128-gcm","password":"..."}`（单用户）或
/// `{"users":[{"method":"aes-128-gcm","password":"...","email":""}]}`。
/// `users`/`clients` 同义（Go shadowsocks.go:46-47 两个字段都收），users 优先。
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
    if let Some(clients) = v
        .get("users")
        .or_else(|| v.get("clients"))
        .and_then(|c| c.as_array())
    {
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
///
/// 形态判定对齐 Go `buildShadowsocks2022`（infra/conf/shadowsocks.go:113-177）：
/// `destinations[]`（Rust 旧形）或 `users[]`/`clients[]` 首元素带 `address`
/// （Go 形 relay，:130）→ 中继；数组无 `address` → 多用户；无数组 → 单用户。
/// `users` 主键，`clients` 旧名回退（:46-47,54-56）。
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

    // users/clients 双读（Go shadowsocks.go:46-47,54-56）
    let users_arr = v
        .get("users")
        .or_else(|| v.get("clients"))
        .and_then(|c| c.as_array());

    // 中继模式（Go 形）：首元素带 address → 按 relay destination 解析
    // （Go shadowsocks.go:130 判定 + :162-175 构建；address/port 主键，
    // server/server_port 为 Rust 旧名回退，不作为判定依据）。
    if let Some(user_list) = users_arr {
        let go_relay = user_list
            .first()
            .is_some_and(|u| u.get("address").and_then(|x| x.as_str()).is_some());
        if go_relay {
            let mut destinations = Vec::new();
            for u in user_list {
                let key_b64 = u.get("password").and_then(|x| x.as_str()).unwrap_or("");
                let email = u.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
                let level = u.get("level").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                let addr_str = u
                    .get("address")
                    .or_else(|| u.get("server"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("127.0.0.1");
                let port = u
                    .get("port")
                    .or_else(|| u.get("server_port"))
                    .and_then(|x| x.as_u64())
                    .unwrap_or(0) as u16;
                let psk = psk_from_base64(key_b64)
                    .map_err(|e| std::io::Error::other(format!("ss2022 relay PSK: {e}")))?;
                destinations.push(RelayDestination {
                    key: psk,
                    address: parse_address_str(addr_str),
                    port,
                    email,
                    level,
                });
            }
            if destinations.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "ss2022 relay: no destinations",
                ));
            }
            let relay = RelayInbound::new(method, server_psk, destinations)
                .map_err(|e| std::io::Error::other(format!("ss2022 relay: {e}")))?;
            return Ok(SsInboundMode::Ss2022Relay(Arc::new(relay)));
        }

        // 多用户模式：数组无 address（Go shadowsocks.go:130 → MultiUserServerConfig）
        let mut users = Vec::new();
        for c in user_list {
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
/// JSON 格式：`{"version":2,"auth":"...","server_name":"..."}`。
///
/// `version` 字段对齐 Go `infra/conf/hysteria.go:39-48`：`version != 2` 直接报错
/// （Go 端 `errors.New("version != 2")`）——Rust 端静默忽略会接受 v1 配置但走 v2
/// 实现（连接握手/UDP 帧结构差异），互操作必坏。读取时强制 v2。
fn parse_hysteria_inbound_config(
    data: &[u8],
    bind_addr: std::net::SocketAddr,
    finalmask_json: Option<&serde_json::Value>,
) -> std::io::Result<(xray_proxy_hysteria::HysteriaConfig, Arc<dyn xray_transport_hysteria::hub::HysteriaListenerFactory>)> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("hysteria inbound settings JSON: {e}")))?;
    // 强制 version == 2（Go 端 hysteria.go:46-48 行为镜像；缺省 = 2）
    if let Some(ver) = v.get("version").and_then(|x| x.as_i64()) {
        if ver != 2 {
            return Err(std::io::Error::other(format!(
                "hysteria version {ver} not supported (only version 2)"
            )));
        }
    }
    let auth = v.get("auth").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let server_name = v.get("server_name").and_then(|x| x.as_str()).unwrap_or("hysteria").to_string();
    // 真实 quinn server adapter：自签证书（或配置 cert/key PEM），ALPN h3 由 listen() 设置
    let _ = rustls::crypto::ring::default_provider().install_default();
    let server_config = build_hysteria_tls_server_config(&v)?;
    // streamSettings.finalmask.quicParams → HysteriaConfig（brutal/CC/windows/keepAlive）
    let quic_params = xray_transport_hysteria::quic_params::parse_quic_params(finalmask_json)?
        .unwrap_or_else(xray_transport_hysteria::quic_params::default_hysteria_quic_params);
    // 构造 inbound HysteriaConfig：server_addr = bind_addr（监听点）；
    // server_name 在 v 缺省时用 hysteria 默认（= server_addr 的 host 段）。
    let mut config = xray_proxy_hysteria::HysteriaConfig::new(bind_addr.to_string(), auth);
    if !server_name.is_empty() && server_name != "hysteria" {
        config = config.with_server_name(server_name);
    }
    let config = config.with_quic_params(quic_params);
    // masquerade 嵌套对象（Go infra/conf transport_internet.go:498-549）：展开到
    // proto 扁平字段再 MasqType::from_config（Go hub.go:210-254 同构）
    let config = if v.get("masquerade").is_some() {
        let mut proto = xray_transport_hysteria::proto_config::Config::default();
        xray_transport_hysteria::proto_config::apply_masquerade_json(
            &mut proto,
            v.get("masquerade").unwrap_or(&serde_json::Value::Null),
        )?;
        config.with_masq(
            xray_transport_hysteria::hub::MasqType::from_config(&proto)
                .map_err(|e| std::io::Error::other(format!("hysteria masquerade: {e}")))?,
        )
    } else {
        config
    };
    // salamander UDP 混淆：streamSettings.finalmask.udp[]（对应 Go UdpmaskManager）
    let salamander = xray_transport_hysteria::salamander_socket::parse_salamander_obfs(finalmask_json)?;
    let factory: Arc<dyn xray_transport_hysteria::hub::HysteriaListenerFactory> =
        Arc::new(QuinnListenerFactory::new(Arc::new(server_config)).with_salamander(salamander));
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

/// 从 inbound entry.data（JSON）解析 anytls TLS acceptor + 认证密码。
///
/// JSON 格式：`{"cert":"...","key":"...","password":"..."}`（cert/key 为 PEM）。
/// cert/key 缺省时用自签名证书（仅测试场景）；password 缺省时不校验客户端认证帧。
fn parse_anytls_tls_acceptor(
    data: &[u8],
) -> std::io::Result<(tokio_rustls::TlsAcceptor, Option<String>)> {
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
    let password = v
        .get("password")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);
    Ok((tokio_rustls::TlsAcceptor::from(Arc::new(config)), password))
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
/// JSON 字段与默认值对齐 Go `infra/conf/tun.go::TunConfig.Build`
/// （name/mtu/gateway/dns/userLevel/autoSystemRoutingTable/autoOutboundsInterface
/// + Rust 扩展 idleTimeout）；解析实现在 `xray_proxy_tun::config`（全平台可测）。
#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
fn parse_tun_inbound_config(data: &[u8]) -> std::io::Result<StackOptions> {
    let mut opts = StackOptions::parse_json(data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}")))?;
    opts.tun = Some(Box::new(TunPlaceholder));
    Ok(opts)
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

    /// bd b8i 对称面：不支持平台（Windows/macOS 等）tun inbound →
    /// `spawn_one_inbound` 返回 Unsupported 硬错误（对齐 Go 不支持平台
    /// NewTun 失败 → inbound 创建失败的 fail-fast 语义）。
    /// 支持平台分支见 outbound.rs `register_tun_outbound`（Linux 侧对称）。
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd")))]
    #[tokio::test]
    async fn tun_inbound_rejected_on_unsupported_platform() {
        let ib = BuiltInbound {
            entry: xray_conf::BuiltEntry {
                kind: "tun".to_string(),
                data: b"{}".to_vec(),
            },
            tag: "tun-in".to_string(),
            port: None,
            listen: None,
            stream_settings_json: None,
            sniffing_json: None,
        };
        let err = spawn_one_inbound(&ib, Arc::new(SimpleOhm::new()), None, CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported, "got: {err}");
    }

    /// bd vodx（Windows 断言面）：unix 路径 listen → `spawn_one_inbound`
    /// 显式 Unsupported，不静默走 TCP bind（行为对齐 Go 端 UDS inbound 为
    /// unix 平台能力；此平台不支持须 fail-fast）。
    /// unix 平台分支见下方 `unix_socket_socks_inbound_e2e`。
    #[cfg(windows)]
    #[tokio::test]
    async fn unix_listen_path_rejected_on_windows() {
        let ib = BuiltInbound {
            entry: xray_conf::BuiltEntry {
                kind: "socks".to_string(),
                data: b"{}".to_vec(),
            },
            tag: "uds-win".to_string(),
            port: None,
            listen: Some("/tmp/xray-uds-win.sock".to_string()),
            stream_settings_json: None,
            sniffing_json: None,
        };
        let err = spawn_one_inbound(&ib, Arc::new(SimpleOhm::new()), None, CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported, "got: {err}");
    }

    /// bd vodx（unix 端到端）：socks inbound 经 `spawn_one_inbound` 的 unix
    /// 路径分派 → `listen_unix_system` UDS listener → 泛型 `handle_connection`
    /// → freedom → TCP echo。证明 UDS 接线被主分派入口真实调用。
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socket_socks_inbound_e2e() {
        // 1. echo server（TCP 目标）
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

        // 2. dispatcher：freedom outbound → SimpleOhm default
        let ohm = Arc::new(SimpleOhm::new());
        let bridge = Arc::new(xray_app_dispatcher::default::DialBridge::new(
            "freedom",
            make_freedom_dial_fn(),
        )) as Arc<dyn xray_app_dispatcher::DispatchHandler>;
        ohm.set_default(bridge);

        // 3. UDS inbound（走 spawn_one_inbound 的 unix 路径分派）
        let sock_path =
            std::env::temp_dir().join(format!("xray-uds-e2e-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock_path);
        let ib = BuiltInbound {
            entry: xray_conf::BuiltEntry {
                kind: "socks".to_string(),
                data: b"{}".to_vec(),
            },
            tag: "uds-e2e".to_string(),
            port: None,
            listen: Some(sock_path.to_string_lossy().into_owned()),
            stream_settings_json: None,
            sniffing_json: None,
        };
        let handle = spawn_one_inbound(&ib, Arc::clone(&ohm), None, CancellationToken::new())
            .await
            .unwrap()
            .expect("uds socks inbound should spawn a serve task");

        // 4. UDS client：握手 → CONNECT echo → 回读
        let mut client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00], "server should select no-auth");

        let ipv4_bytes = match echo_addr.ip() {
            std::net::IpAddr::V4(v4) => v4.octets(),
            _ => unreachable!(),
        };
        let mut req = vec![0x05, 0x01, 0x00, ATYP_IPV4];
        req.extend_from_slice(&ipv4_bytes);
        req.extend_from_slice(&echo_addr.port().to_be_bytes());
        client.write_all(&req).await.unwrap();

        let mut connect_resp = [0u8; 10];
        client.read_exact(&mut connect_resp).await.unwrap();
        assert_eq!(connect_resp[1], 0x00, "CONNECT should succeed");

        let payload = b"hello uds socks!";
        client.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, payload, "should receive echo through uds proxy");

        handle.abort();
        let _ = std::fs::remove_file(&sock_path);
    }

    /// bd 1zko8：anytls settings 解析补 password——`password` 键解析为
    /// Some；缺省/空串为 None（不校验）；cert/key 缺省走自签（测试场景）。
    #[test]
    fn parse_anytls_tls_acceptor_password() {
        let (acceptor, pw) = parse_anytls_tls_acceptor(br#"{"password":"s3cret"}"#).unwrap();
        assert_eq!(pw.as_deref(), Some("s3cret"));
        let _ = acceptor; // 自签构造成功即合法

        let (_, pw) = parse_anytls_tls_acceptor(b"{}").unwrap();
        assert_eq!(pw, None, "missing password must stay None");

        let (_, pw) = parse_anytls_tls_acceptor(br#"{"password":""}"#).unwrap();
        assert_eq!(pw, None, "empty password must stay None");
    }



    /// ect：`hysteriaSettings.masquerade` JSON → proxy HysteriaConfig.masq
    /// （Go infra/conf transport_internet.go:498-549 展开路径）。
    #[test]
    fn parse_hysteria_inbound_masquerade() {
        use xray_transport_hysteria::hub::MasqType;
        let addr: std::net::SocketAddr = "127.0.0.1:8443".parse().unwrap();

        // string 类：content/headers/statusCode 全解析
        let data = br#"{"auth":"t","masquerade":{"type":"string","content":"hi","headers":{"X-A":"1"},"statusCode":418}}"#;
        let (config, _factory) = parse_hysteria_inbound_config(data, addr, None).unwrap();
        match config.masq.as_ref().unwrap() {
            MasqType::String { body, headers, status_code } => {
                assert_eq!(body, "hi");
                assert_eq!(headers.get("X-A").unwrap(), "1");
                assert_eq!(*status_code, 418);
            }
            other => panic!("expected String masq, got {other:?}"),
        }

        // file 类
        let data = br#"{"masquerade":{"type":"file","dir":"/var/www"}}"#;
        let (config, _factory) = parse_hysteria_inbound_config(data, addr, None).unwrap();
        assert_eq!(config.masq.as_ref().unwrap(), &MasqType::File("/var/www".into()));

        // 未知类型 → parse 错误（Go hub.go:252-253 "unknown masq type"）
        let data = br#"{"masquerade":{"type":"bogus"}}"#;
        assert!(parse_hysteria_inbound_config(data, addr, None).is_err());

        // 无 masquerade → None（零行为变化）
        let data = br#"{"auth":"t"}"#;
        let (config, _factory) = parse_hysteria_inbound_config(data, addr, None).unwrap();
        assert!(config.masq.is_none());
    }

    /// rxw：HysteriaTcpDispatch 适配器——mock QUIC stream → dispatch（freedom）→ echo 回环。
    #[tokio::test]
    async fn hysteria_tcp_dispatch_to_freedom_e2e() {
        use xray_proxy_freedom::make_freedom_dial_fn;
        use xray_proxy_hysteria::TcpDispatcher as _;
        use xray_app_dispatcher::default::DialBridge;
        use xray_transport_hysteria::conn::{InterStreamConn, QuicStream};

        // duplex-backed mock QUIC stream（读写 halves 独立锁，避免 dispatch 桥双向互锁）
        #[derive(Debug)]
        struct DuplexQuicStream {
            r: tokio::sync::Mutex<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
            w: tokio::sync::Mutex<tokio::io::WriteHalf<tokio::io::DuplexStream>>,
            local: std::net::SocketAddr,
            remote: std::net::SocketAddr,
        }
        impl QuicStream for DuplexQuicStream {
            fn read<'a>(&'a self, buf: &'a mut [u8])
                -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<usize>> + Send + 'a>> {
                Box::pin(async {
                    use tokio::io::AsyncReadExt as _;
                    self.r.lock().await.read(buf).await
                })
            }
            fn write<'a>(&'a self, buf: &'a [u8])
                -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<usize>> + Send + 'a>> {
                Box::pin(async {
                    use tokio::io::AsyncWriteExt as _;
                    self.w.lock().await.write(buf).await
                })
            }
            fn cancel_read(&self, _code: u64) {}
            fn close(&self) -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>> {
                Box::pin(async { Ok(()) })
            }
            fn local_addr(&self) -> std::net::SocketAddr { self.local }
            fn remote_addr(&self) -> std::net::SocketAddr { self.remote }
        }

        // echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut c, _)) = echo_listener.accept().await else { break };
                tokio::spawn(async move {
                    let (mut r, mut w) = c.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });

        // SimpleOhm + freedom
        let ohm = Arc::new(SimpleOhm::new());
        let bridge = Arc::new(DialBridge::new("freedom", make_freedom_dial_fn()))
            as Arc<dyn xray_app_dispatcher::DispatchHandler>;
        ohm.set_default(bridge);
        let handler = ohm.get_default_handler().unwrap();

        let local: std::net::SocketAddr = "127.0.0.1:443".parse().unwrap();
        let remote: std::net::SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let (client_side, server_side) = tokio::io::duplex(4096);
        let (sr, sw) = tokio::io::split(server_side);
        let stream: Arc<dyn QuicStream> = Arc::new(DuplexQuicStream {
            r: tokio::sync::Mutex::new(sr),
            w: tokio::sync::Mutex::new(sw),
            local,
            remote,
        });
        let conn = Arc::new(InterStreamConn::new(stream, local, remote, false));

        let dispatch = HysteriaTcpDispatch(Arc::clone(&handler));
        let conn2 = Arc::clone(&conn);
        let dest = format!("127.0.0.1:{echo_port}");
        tokio::spawn(async move {
            use xray_proxy_hysteria::TcpDispatcher as _;
            let _ = dispatch.dispatch_tcp(&dest, conn2).await;
        });

        // client：写 payload → dispatch 桥 → echo → 回包
        let payload = b"hysteria-dispatch-e2e";
        let mut client = client_side;
        client.write_all(payload).await.unwrap();
        let mut rbuf = vec![0u8; 128];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut rbuf))
            .await.unwrap().unwrap();
        assert_eq!(&rbuf[..n], payload);
        drop(client);
        // 留时间给桥收尾（read EOF → 关闭）
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    /// agb：SS-2022 UDP inbound → dispatch → 回环 e2e（多用户 EIH，
    /// MarkerUdpDispatch 验证真正经 dispatch link，模式同 ss_udp_dispatch_roundtrip）。
    #[tokio::test]
    async fn ss2022_udp_dispatch_roundtrip() {
        use xray_proxy_ss::ss2022::key::{CipherKind2022, psk_identity};
        use xray_proxy_ss::ss2022::packet::ClientUdpSession2022;

        // 1. PSK（多用户：server iPSK + user uPSK）+ serve_ss2022_udp
        let ipsk: Vec<u8> = (0..32u8).collect();
        let upsk: Vec<u8> = (32..64u8).collect();
        let users = vec![(psk_identity(&upsk), upsk.clone())];
        let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let handler: Arc<dyn xray_app_dispatcher::DispatchHandler> =
            Arc::new(MarkerUdpDispatch { marker: b"ss2022-via-dispatch" });
        tokio::spawn(serve_ss2022_udp(
            Arc::new(relay),
            CipherKind2022::Aes256Gcm,
            ipsk.clone(),
            users,
            handler,
        ));

        // 2. client：2022 UDP 帧 → relay（目标任意，marker handler 不打真实包）
        let client_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client_sock.connect(relay_addr).await.unwrap();
        let client = ClientUdpSession2022::new(
            CipherKind2022::Aes256Gcm,
            vec![ipsk, upsk],
        )
        .unwrap();
        let frame = client
            .encode(&Address::IPv4(Ipv4Addr::LOCALHOST), 53, b"ping")
            .unwrap();
        client_sock.send(&frame).await.unwrap();

        // 3. 收回帧并 decode 出标记 payload
        let mut rbuf = vec![0u8; 2048];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client_sock.recv(&mut rbuf),
        )
        .await
        .expect("response via dispatcher within 5s")
        .expect("recv");
        let (_addr, _port, data) = client.decode(&rbuf[..n]).unwrap();
        assert_eq!(data, b"ss2022-via-dispatch");
    }

    /// bd 29nk：server_sessions 过期清扫——deadline <= now 的条目被清
    /// （sing LruCache `expires <= now` 删语义），存活条目保留，空表 no-op。
    #[test]
    fn sweep_expired_ss2022_sessions_drops_only_expired() {
        use xray_proxy_ss::ss2022::key::CipherKind2022;
        use xray_proxy_ss::ss2022::packet::ServerUdpSession2022;

        let mk = |sid: u64| {
            Arc::new(ServerUdpSession2022::new(CipherKind2022::Aes256Gcm, vec![7u8; 32], sid).unwrap())
        };
        let now = std::time::Instant::now();
        let mut table: HashMap<u64, (Arc<ServerUdpSession2022>, std::time::Instant)> = HashMap::new();
        // expired：deadline 恰等于 now（边界，Go `expires <= now` 删）。
        table.insert(1, (mk(1), now));
        // expired：deadline 已过。
        table.insert(2, (mk(2), now - std::time::Duration::from_secs(1)));
        // alive：还有 300s。
        table.insert(3, (mk(3), now + std::time::Duration::from_secs(300)));

        assert_eq!(sweep_expired_ss2022_sessions(&mut table, now), 1);
        assert!(table.contains_key(&3), "alive session must survive sweep");
        assert!(!table.contains_key(&1), "boundary-dead session must be swept");
        assert!(!table.contains_key(&2), "past-deadline session must be swept");

        assert_eq!(sweep_expired_ss2022_sessions(&mut table, now), 1);
        let mut empty: HashMap<u64, (Arc<ServerUdpSession2022>, std::time::Instant)> = HashMap::new();
        assert_eq!(sweep_expired_ss2022_sessions(&mut empty, now), 0);
    }


    /// agb：SS-2022 UDP inbound → freedom UDP dispatch → 真 echo 回环 e2e
    /// （FreedomDispatchBridge 的 UDP 分支走 udp::relay，DialBridge 仅 TCP）。
    #[tokio::test]
    async fn ss2022_udp_inbound_dispatch_to_freedom_e2e() {
        use xray_proxy_freedom::dispatcher::FreedomDispatchBridge;
        use xray_proxy_freedom::make_freedom_dial_fn;
        use xray_app_dispatcher::default::DialBridge;
        use xray_proxy_ss::ss2022::key::{CipherKind2022, psk_identity};
        use xray_proxy_ss::ss2022::packet::ClientUdpSession2022;

        // 1. UDP echo server
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_v4 = match echo_addr.ip() {
            std::net::IpAddr::V4(v4) => v4,
            _ => panic!("echo should be ipv4"),
        };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            loop {
                let Ok((n, peer)) = echo.recv_from(&mut buf).await else { break };
                let _ = echo.send_to(&buf[..n], peer).await;
            }
        });

        // 2. PSK（多用户）+ serve_ss2022_udp + FreedomDispatchBridge
        let ipsk: Vec<u8> = (0..32u8).collect();
        let upsk: Vec<u8> = (32..64u8).collect();
        let users = vec![(psk_identity(&upsk), upsk.clone())];
        let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let handler: Arc<dyn xray_app_dispatcher::DispatchHandler> = Arc::new(
            FreedomDispatchBridge::from_bridge(Arc::new(DialBridge::new("freedom", make_freedom_dial_fn()))),
        );
        tokio::spawn(serve_ss2022_udp(
            Arc::new(relay),
            CipherKind2022::Aes256Gcm,
            ipsk.clone(),
            users,
            handler,
        ));

        // 3. client：2022 UDP 帧 → serve → freedom dispatch → echo → 回帧
        let client_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client_sock.connect(relay_addr).await.unwrap();
        let client = ClientUdpSession2022::new(
            CipherKind2022::Aes256Gcm,
            vec![ipsk, upsk],
        )
        .unwrap();

        let payload = b"ss2022-udp-dispatch-e2e".to_vec();
        let frame = client
            .encode(&Address::IPv4(echo_v4), echo_addr.port(), &payload)
            .unwrap();
        client_sock.send(&frame).await.unwrap();

        let mut rbuf = vec![0u8; 65_535];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client_sock.recv(&mut rbuf),
        )
        .await
        .expect("recv timeout")
        .expect("recv");
        let (addr, port, echoed) = client.decode(&rbuf[..n]).unwrap();
        assert_eq!(addr, Address::IPv4(echo_v4));
        assert_eq!(port, echo_addr.port());
        assert_eq!(echoed, payload);
    }

    /// agb：SS-2022 UDP outbound（make_ss_dial_fn 2022 分支）→ serve_ss2022_udp
    /// 完整对拉 e2e：duplex XUDP 帧 → SsConnection 2022 pump → UDP → inbound
    /// 解包 → freedom → echo → 回程全链。
    #[tokio::test]
    async fn ss2022_udp_outbound_inbound_roundtrip_e2e() {
        use xray_proxy_freedom::dispatcher::FreedomDispatchBridge;
        use xray_proxy_freedom::make_freedom_dial_fn;
        use xray_app_dispatcher::default::DialBridge;
        use xray_proxy_ss::ss2022::key::{CipherKind2022, psk_identity};
        use base64::Engine as _;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::io::AsyncWriteExt as _;
        use xray_xudp::packet::{PacketReader, PacketWriter};

        // 1. UDP echo server
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_v4 = match echo_addr.ip() {
            std::net::IpAddr::V4(v4) => v4,
            _ => panic!("echo should be ipv4"),
        };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            loop {
                let Ok((n, peer)) = echo.recv_from(&mut buf).await else { break };
                let _ = echo.send_to(&buf[..n], peer).await;
            }
        });

        // 2. SS-2022 server（inbound 侧，多用户）
        let ipsk: Vec<u8> = (0..32u8).collect();
        let upsk: Vec<u8> = (32..64u8).collect();
        let users = vec![(psk_identity(&upsk), upsk.clone())];
        let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_port = relay.local_addr().unwrap().port();
        let echo_handler: Arc<dyn xray_app_dispatcher::DispatchHandler> = Arc::new(
            FreedomDispatchBridge::from_bridge(Arc::new(DialBridge::new("freedom", make_freedom_dial_fn()))),
        );
        tokio::spawn(serve_ss2022_udp(
            Arc::new(relay),
            CipherKind2022::Aes256Gcm,
            ipsk.clone(),
            users,
            echo_handler,
        ));

        // 3. SS-2022 outbound：parse_ss_config（2022 method 分流）+ make_ss_dial_fn
        let b64 = base64::engine::general_purpose::STANDARD;
        let cfg_json = format!(
            r#"{{"servers":[{{"address":"127.0.0.1","port":{relay_port},
            "method":"2022-blake3-aes-256-gcm",
            "password":"{}:{}"}}]}}"#,
            b64.encode(&ipsk),
            b64.encode(&upsk),
        );
        let cfg = std::sync::Arc::new(xray_proxy_ss::parse_ss_config(cfg_json.as_bytes()).unwrap());
        assert!(cfg.ss2022.is_some(), "2022 method should route to ss2022 params");
        let ss_bridge = Arc::new(DialBridge::new("ss2022-out", xray_proxy_ss::make_ss_dial_fn(cfg)));

        // 4. dispatch link：duplex 承载 XUDP 帧流（模拟 inbound 侧）
        let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
        let dest = Destination::new(Address::IPv4(echo_v4), Port::new(echo_addr.port()), Network::UDP);
        let (srv_rd, srv_wr) = tokio::io::split(server_io);
        tokio::spawn(async move {
            ss_bridge.dispatch(&dest, xray_transport::link::Link::new(
                xray_buf::io::new_reader(srv_rd),
                xray_buf::io::new_writer(srv_wr),
            )).await;
        });

        // 5. 写 XUDP 帧 → 2022 outbound → inbound 解包 → freedom → echo → 回帧
        let payload = b"ss2022-outbound-e2e".to_vec();
        let mut frame = Vec::new();
        let mut pw = PacketWriter::new(
            &mut frame,
            Destination::new(Address::IPv4(echo_v4), Port::new(echo_addr.port()), Network::UDP),
            [0u8; 8],
        );
        pw.write_packet(&payload).unwrap();
        drop(pw);
        client_io.write_all(&frame).await.unwrap();

        let mut accum = Vec::new();
        let mut buf = vec![0u8; 8 * 1024];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let n = tokio::time::timeout_at(deadline, client_io.read(&mut buf))
                .await
                .expect("response within 5s")
                .expect("read");
            accum.extend_from_slice(&buf[..n]);
            let mut cursor = std::io::Cursor::new(&accum[..]);
            let mut pr = PacketReader::new(&mut cursor);
            if let Ok(Some(pkt)) = pr.read_packet() {
                let (data, _) = pkt.into_parts();
                assert_eq!(data, payload);
                return;
            }
        }
    }

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

    /// `ip` 字段（Go socks.go:35 `Host`）→ config.address（UDP relay 绑定消费）。
    #[test]
    fn parse_socks_server_config_ip_field() {
        use xray_proto::xray::common::net::ip_or_domain::Address as ProtoAddr;
        let cfg = parse_socks_server_config(br#"{"ip":"127.0.0.9","udp":true}"#).unwrap();
        let addr = cfg.address.expect("ip should populate config.address");
        assert_eq!(
            addr.address,
            Some(ProtoAddr::Ip(vec![127, 0, 0, 9])),
            "ipv4 → 4-byte Ip"
        );
        let cfg6 = parse_socks_server_config(br#"{"ip":"::1"}"#).unwrap();
        let addr6 = cfg6.address.expect("ipv6 should populate too");
        assert!(matches!(
            &addr6.address,
            Some(ProtoAddr::Ip(b)) if b.len() == 16
        ));
        let cfg_none = parse_socks_server_config(br#"{"udp":true}"#).unwrap();
        assert!(cfg_none.address.is_none(), "no ip → None（127.0.0.1 回退在 socks 侧）");
    }

    /// legacy ss：`users` 主键（Go shadowsocks.go:46）与 `clients` 旧名回退。
    #[test]
    fn parse_ss_inbound_config_users_alias_and_clients_fallback() {
        let users_json = br#"{"method":"aes-128-gcm","users":[
            {"method":"aes-128-gcm","password":"pw1","email":"a@x"},
            {"method":"aes-256-gcm","password":"pw2","email":"b@x"}]}"#;
        let mode = super::parse_ss_inbound_config(users_json).unwrap();
        let SsInboundMode::Legacy(ib) = &mode else {
            panic!("users[] should build legacy ss inbound");
        };
        assert_eq!(ib.server().users_count(), 2, "users[] → 2 users");

        let clients_json = br#"{"method":"aes-128-gcm","clients":[
            {"method":"aes-128-gcm","password":"pw1","email":"a@x"}]}"#;
        let mode = super::parse_ss_inbound_config(clients_json).unwrap();
        let SsInboundMode::Legacy(ib) = &mode else {
            panic!("clients[] fallback should still work");
        };
        assert_eq!(ib.server().users_count(), 1, "clients[] → 1 user");
    }

    /// ss2022 多用户：`users[]`（无 address → multi，Go shadowsocks.go:130）。
    #[test]
    fn parse_ss2022_inbound_config_users_alias_multi() {
        // 16 字节 PSK 的标准 base64（aes-128-gcm PSK 长度要求）。
        let psk = "EREREREREREREREREREREA==";
        let json = format!(
            r#"{{"method":"2022-blake3-aes-128-gcm","password":"{psk}",
                "users":[{{"password":"{psk}","email":"a@x"}},
                         {{"password":"{psk}","email":"b@x","level":2}}]}}"#
        );
        let mode = super::parse_ss_inbound_config(json.as_bytes()).unwrap();
        let SsInboundMode::Ss2022Multi(multi) = &mode else {
            panic!("users[] without address should build multi-user inbound");
        };
        assert_eq!(multi.users_count(), 2);
        // clients 旧名回退
        let json = format!(
            r#"{{"method":"2022-blake3-aes-128-gcm","password":"{psk}",
                "clients":[{{"password":"{psk}","email":"a@x"}}]}}"#
        );
        let mode = super::parse_ss_inbound_config(json.as_bytes()).unwrap();
        let SsInboundMode::Ss2022Multi(multi) = &mode else {
            panic!("clients[] fallback should build multi-user inbound");
        };
        assert_eq!(multi.users_count(), 1);
    }

    /// ss2022 中继 Go 形：`users[0].address` 非空 → relay（Go shadowsocks.go:130），
    /// address/port 主键 + server/server_port 旧名回退；`destinations[]` 旧形保持兼容。
    #[test]
    fn parse_ss2022_inbound_config_go_relay_users_address() {
        use xray_common::net::address::Address;
        let psk = "EREREREREREREREREREREA==";
        // Go 形：users[].address/port
        let json = format!(
            r#"{{"method":"2022-blake3-aes-128-gcm","password":"{psk}",
                "users":[{{"password":"{psk}","address":"10.0.0.1","port":8388,"email":"r1"}},
                         {{"password":"{psk}","address":"relay.example.com","port":9}}]}}"#
        );
        let mode = super::parse_ss_inbound_config(json.as_bytes()).unwrap();
        let SsInboundMode::Ss2022Relay(relay) = &mode else {
            panic!("users[0].address should detect relay mode");
        };
        assert_eq!(relay.destinations_count(), 2);

        // 旧名回退：users[] 带 server/server_port 也判 relay（键回退，判定仍看 address）
        let json = format!(
            r#"{{"method":"2022-blake3-aes-128-gcm","password":"{psk}",
                "users":[{{"password":"{psk}","address":"10.0.0.2","server_port":8388}}]}}"#
        );
        let mode = super::parse_ss_inbound_config(json.as_bytes()).unwrap();
        assert!(matches!(mode, SsInboundMode::Ss2022Relay(_)));

        // Rust 旧形：destinations[] → relay（既有行为不回归）
        let json = format!(
            r#"{{"method":"2022-blake3-aes-128-gcm","password":"{psk}",
                "destinations":[{{"password":"{psk}","server":"10.0.0.3","server_port":8388}}]}}"#
        );
        let mode = super::parse_ss_inbound_config(json.as_bytes()).unwrap();
        let SsInboundMode::Ss2022Relay(relay) = &mode else {
            panic!("destinations[] legacy form should stay relay");
        };
        assert_eq!(relay.destinations_count(), 1);
        let _ = Address::Domain(String::new()); // 类型锚定
    }

    /// ss2022：users[] 无 address 时绝不误判 relay（回归防护）。
    #[test]
    fn parse_ss2022_inbound_config_users_without_address_stays_multi() {
        let psk = "EREREREREREREREREREREA==";
        let json = format!(
            r#"{{"method":"2022-blake3-aes-128-gcm","password":"{psk}",
                "users":[{{"password":"{psk}","port":8388}}]}}"#
        );
        let mode = super::parse_ss_inbound_config(json.as_bytes()).unwrap();
        assert!(matches!(mode, SsInboundMode::Ss2022Multi(_)));
    }

    /// b2e：SS Legacy UDP relay 经 dispatcher（UdpDispatchSession）。
    ///
    /// MarkerUdpDispatch 只有经 dispatch link 才能回标记帧，raw 直连路径
    /// 给不出；回包必须能用发起用户 account 解出标记 payload。
    #[tokio::test]
    async fn ss_udp_dispatch_roundtrip() {
        use xray_proxy_ss::config::MemoryAccount as SsAccount;
        use xray_proxy_ss::protocol::{decode_udp_packet, encode_udp_packet};

        // 1. SS inbound（单用户 aes-128-gcm）+ serve_ss_udp（dispatch handler）
        let account = SsAccount::from_proto(&xray_proto::xray::proxy::shadowsocks::Account {
            password: "udp-test-pass".into(),
            cipher_type: SsCipherType::Aes128Gcm.as_i32(),
            iv_check: false,
        })
        .unwrap();
        let ib = Arc::new(SsInbound::new(account.clone(), "u@ss.udp"));
        let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let handler: Arc<dyn xray_app_dispatcher::DispatchHandler> =
            Arc::new(MarkerUdpDispatch { marker: b"ss-via-dispatch" });
        let ib_clone = Arc::clone(&ib);
        tokio::spawn(async move {
            let _ = serve_ss_udp(Arc::new(relay), ib_clone, handler).await;
        });

        // 2. client：encode 一个 UDP 包发给 relay（目标任意，dispatch 标记 handler 不打真实包）
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let packet = encode_udp_packet(
            &account,
            &Address::IPv4(Ipv4Addr::LOCALHOST),
            53,
            b"ping",
        )
        .unwrap();
        client.send_to(&packet, relay_addr).await.unwrap();

        // 3. 收回包并解密（发起用户 account 可解出标记 payload）
        let mut rbuf = vec![0u8; 2048];
        let (n, _from) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.recv_from(&mut rbuf),
        )
        .await
        .unwrap()
        .unwrap();
        let (_header, data) = decode_udp_packet(ib.validator(), &rbuf[..n]).unwrap();
        assert_eq!(data, b"ss-via-dispatch");
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
            // maxTimeDiff 单位毫秒（Go `time.Duration(c.MaxTimeDiff) * time.Millisecond`）。
            // 30000 ms = 30s → 转秒后 30。
            "maxTimeDiff": 30000
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
        assert_eq!(cfg.max_diff, 30);
    }

    #[test]
    fn parse_reality_config_port_dest_and_defaults() {
        use base64::Engine as _;
        let key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        // dest 为 int 端口 → localhost:port；缺省 xver=0/maxTimeDiff=0（Go 兼容：禁用时间窗）/shortIds=[0u8;8]
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
        assert_eq!(cfg.max_diff, 0);
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

    /// mldsa65 后未实现：JSON 端必须显式报错不静默忽略（cz5x）。
    #[test]
    fn parse_reality_config_rejects_mldsa65_seed() {
        use base64::Engine as _;
        let key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        let json = serde_json::json!({
            "privateKey": key_b64,
            "mldsa65Seed": "deadbeef00000000000000000000000000000000000000000000000000000000",
        });
        let settings = xray_transport::dialer::StreamSettings {
            security: "reality".to_string(),
            security_json: Some(json),
            ..xray_transport::dialer::StreamSettings::tcp()
        };
        let err = parse_reality_config(&settings).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mldsa65") && msg.contains("not implemented"),
            "expected mldsa65 not implemented error, got: {msg}"
        );
    }
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
        let socks_listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        ).await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let config = Arc::new(ServerConfig::default());
        let ohm_clone = Arc::clone(&ohm);
        tokio::spawn(async move {
            let _ = serve_socks5(socks_listener, ohm_clone, config, None).await;
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
            min_client_ver: Vec::new(),
            max_client_ver: Vec::new(),
        };
        let rl = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        ).await.unwrap();
        let rl_addr = rl.local_addr().unwrap();
        let ohm_c = Arc::clone(&ohm);
        let val_c = Arc::clone(&validator) as Arc<dyn VlessValidator>;
        tokio::spawn(async move {
            let _ = serve_reality_vless(rl, ohm_c, val_c, reality_cfg, None).await;
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
        let dest = socks_addr_to_destination(&addr, Network::TCP);
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
        let dest = socks_addr_to_destination(&addr, Network::TCP);
        assert_eq!(dest.port(), Port::new(443));
        match dest.address() {
            Address::Domain(d) => assert_eq!(d, "example.com"),
            other => panic!("expected Domain, got {other:?}"),
        }
        let _ = ATYP_DOMAIN; // 确认 import 路径
    }

    /// b2e：dispatch 被以 UDP dest 调用即回一个标记 XUDP 响应帧。
    ///
    /// 用于验证 inbound UDP relay 真正走 dispatcher（而非 raw socket 直连）：
    /// 标记 payload 只有经 dispatch link 回来才可能出现。
    #[derive(Debug)]
    struct MarkerUdpDispatch {
        marker: &'static [u8],
    }

    impl xray_app_dispatcher::DispatchHandler for MarkerUdpDispatch {
        fn tag(&self) -> &str {
            "marker-udp-dispatch"
        }

        fn dispatch(
            &self,
            dest: &Destination,
            link: Link,
        ) -> xray_app_dispatcher::default::PinFuture<()> {
            let source = Destination::udp(dest.address().clone(), dest.port());
            let marker = self.marker;
            Box::pin(async move {
                let Link { mut writer, .. } = link;
                let mut frame = Vec::with_capacity(marker.len() + 64);
                let mut pw = xray_xudp::packet::PacketWriter::new(&mut frame, source, [0u8; 8]);
                let _ = pw.write_packet(marker);
                drop(pw);
                let mut mb = xray_buf::multi::MultiBuffer::new();
                mb.merge_bytes(&frame);
                let _ = writer.write_multi_buffer(mb).await;
            })
        }
    }

    /// b2e：SOCKS UDP ASSOCIATE relay 经 dispatcher（UdpDispatchSession）。
    #[tokio::test]
    async fn socks_udp_dispatch_roundtrip() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let handler: Arc<dyn xray_app_dispatcher::DispatchHandler> =
            Arc::new(MarkerUdpDispatch { marker: b"via-dispatch" });
        tokio::spawn(async move {
            let _ = handle_udp_associate(relay, handler).await;
        });

        // 客户端 → relay socket：SOCKS5 UDP 请求帧（目标仅作路由地址，不打真实包）
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = SocksAddr {
            host: Host::Ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            port: 53,
        };
        client
            .send_to(&encode_udp_packet(&target, b"ping"), relay_addr)
            .await
            .unwrap();

        // 响应必须是 MarkerUdpDispatch 写回的标记帧（raw 直连路径给不出）
        let mut rbuf = [0u8; 1500];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.recv_from(&mut rbuf),
        )
        .await
        .expect("response via dispatcher within 5s")
        .unwrap();
        let (_src, payload) = decode_udp_packet(&rbuf[..n]).unwrap();
        assert_eq!(payload, b"via-dispatch");
    }

    /// b2e：dokodemo UDP inbound 经 dispatcher（固定 dest）。
    #[tokio::test]
    async fn dokodemo_udp_dispatch_roundtrip() {
        let hub = xray_transport::udp::hub::UdpHub::listen("127.0.0.1:0".parse().unwrap(), &[], None)
            .await
            .unwrap();
        let local = hub.local_addr().unwrap();
        let handler: Arc<dyn xray_app_dispatcher::DispatchHandler> =
            Arc::new(MarkerUdpDispatch { marker: b"dokodemo-via-dispatch" });
        let dest = Destination::udp(Address::IPv4(std::net::Ipv4Addr::new(8, 8, 8, 8)), Port::new(53));
        tokio::spawn(async move {
            let _ = serve_dokodemo_udp_on(hub, handler, Some(dest)).await;
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"ping", local).await.unwrap();
        let mut rbuf = [0u8; 1500];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.recv_from(&mut rbuf),
        )
        .await
        .expect("response via dispatcher within 5s")
        .unwrap();
        assert_eq!(&rbuf[..n], b"dokodemo-via-dispatch");
    }

    /// per-peer：每个 peer 的 dispatch 会话各自回发标记帧——两个客户端并发，
    /// 各自只收到自己会话的响应（旧单 session+last_peer 模型下两客户端共享
    /// 一个 dispatch，只会出现同一个标记 / 回包串扰）。
    #[derive(Debug)]
    struct CounterUdpDispatch {
        counter: std::sync::atomic::AtomicU32,
    }

    impl xray_app_dispatcher::DispatchHandler for CounterUdpDispatch {
        fn tag(&self) -> &str {
            "counter-udp-dispatch"
        }

        fn dispatch(
            &self,
            dest: &Destination,
            link: Link,
        ) -> xray_app_dispatcher::default::PinFuture<()> {
            let n = self.counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let marker = format!("peer-{n}");
            let source = Destination::udp(dest.address().clone(), dest.port());
            Box::pin(async move {
                let Link { mut writer, .. } = link;
                let mut frame = Vec::with_capacity(marker.len() + 64);
                let mut pw = xray_xudp::packet::PacketWriter::new(&mut frame, source, [0u8; 8]);
                let _ = pw.write_packet(marker.as_bytes());
                drop(pw);
                let mut mb = xray_buf::multi::MultiBuffer::new();
                mb.merge_bytes(&frame);
                let _ = writer.write_multi_buffer(mb).await;
            })
        }
    }
    #[tokio::test]
    async fn dokodemo_udp_per_peer_sessions_no_cross_delivery() {
        let hub = xray_transport::udp::hub::UdpHub::listen("127.0.0.1:0".parse().unwrap(), &[], None)
            .await
            .unwrap();
        let local = hub.local_addr().unwrap();
        let handler: Arc<dyn xray_app_dispatcher::DispatchHandler> = Arc::new(CounterUdpDispatch {
            counter: std::sync::atomic::AtomicU32::new(0),
        });
        let dest = Destination::udp(Address::IPv4(std::net::Ipv4Addr::new(8, 8, 8, 8)), Port::new(53));
        tokio::spawn(async move {
            let _ = serve_dokodemo_udp_on(hub, handler, Some(dest)).await;
        });

        let client_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client_a.send_to(b"from-a", local).await.unwrap();
        client_b.send_to(b"from-b", local).await.unwrap();

        async fn recv_marker(sock: &UdpSocket) -> String {
            let mut rbuf = [0u8; 1500];
            let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv_from(&mut rbuf))
                .await
                .expect("per-peer response within 5s")
                .unwrap();
            String::from_utf8_lossy(&rbuf[..n]).into_owned()
        }
        let (ma, mb) = tokio::join!(recv_marker(&client_a), recv_marker(&client_b));

        // 恰好两个会话各发各的标记：集合为 {peer-0, peer-1} 且互不相同
        // （共享单 session 模型只会产出同一个标记，且可能串投）。
        let mut markers = vec![ma.as_str(), mb.as_str()];
        markers.sort_unstable();
        assert_eq!(markers, vec!["peer-0", "peer-1"], "each peer must get its own session marker");
    }
    fn tcp_opts() -> super::DokodemoTcpOptions {
        super::DokodemoTcpOptions {
            dest: Some(Destination::tcp(
                Address::IPv4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                Port::new(80),
            )),
            port_map: HashMap::new(),
            follow_redirect: false,
            tls: None,
        }
    }

    #[test]
    fn resolve_dokodemo_port_map_rewrites_host_and_port() {
        let mut opts = tcp_opts();
        opts.port_map
            .insert("80".to_string(), "192.168.99.1:9090".to_string());
        let dest = super::resolve_dokodemo_tcp_dest(&opts, None, Some(80), None, None)
            .unwrap();
        assert_eq!(dest.port().value(), 9090);
        match dest.address() {
            Address::IPv4(v4) => assert_eq!(v4.octets(), [192, 168, 99, 1]),
            other => panic!("expected mapped IPv4, got {other:?}"),
        }
    }

    #[test]
    fn resolve_dokodemo_port_map_port_only_keeps_address() {
        let mut opts = tcp_opts();
        opts.port_map.insert("80".to_string(), ":5353".to_string());
        let dest = super::resolve_dokodemo_tcp_dest(&opts, None, Some(80), None, None)
            .unwrap();
        assert_eq!(dest.port().value(), 5353);
        match dest.address() {
            Address::IPv4(v4) => assert_eq!(v4.octets(), [10, 0, 0, 1]),
            other => panic!("expected predefined IPv4, got {other:?}"),
        }
    }

    #[test]
    fn resolve_dokodemo_port_map_domain_host() {
        let mut opts = tcp_opts();
        opts.port_map
            .insert("80".to_string(), "example.org:".to_string());
        let dest = super::resolve_dokodemo_tcp_dest(&opts, None, Some(80), None, None)
            .unwrap();
        assert_eq!(dest.port().value(), 80);
        match dest.address() {
            Address::Domain(d) => assert_eq!(d, "example.org"),
            other => panic!("expected Domain, got {other:?}"),
        }
    }

    #[test]
    fn resolve_dokodemo_port_map_no_match_uses_predefined() {
        let mut opts = tcp_opts();
        opts.port_map
            .insert("443".to_string(), "192.168.99.1:9090".to_string());
        let dest = super::resolve_dokodemo_tcp_dest(&opts, None, Some(80), None, None)
            .unwrap();
        assert_eq!(dest.port().value(), 80);
        match dest.address() {
            Address::IPv4(v4) => assert_eq!(v4.octets(), [10, 0, 0, 1]),
            other => panic!("expected predefined IPv4, got {other:?}"),
        }
    }

    #[test]
    fn resolve_dokodemo_sni_overrides_address_keeps_port() {
        let mut opts = tcp_opts();
        opts.follow_redirect = true;
        let dest = super::resolve_dokodemo_tcp_dest(
            &opts,
            None,
            Some(80),
            None,
            Some("sni.example.com"),
        )
        .unwrap();
        assert_eq!(dest.port().value(), 80, "SNI 只覆盖 address，port 保持");
        match dest.address() {
            Address::Domain(d) => assert_eq!(d, "sni.example.com"),
            other => panic!("expected SNI domain, got {other:?}"),
        }
    }

    #[test]
    fn resolve_dokodemo_original_dst_wins_over_sni() {
        let mut opts = tcp_opts();
        opts.follow_redirect = true;
        let orig: SocketAddr = "203.0.113.7:4433".parse().unwrap();
        let dest = super::resolve_dokodemo_tcp_dest(
            &opts,
            None,
            Some(80),
            Some(orig),
            Some("sni.example.com"),
        )
        .unwrap();
        assert_eq!(dest.port().value(), 4433);
        match dest.address() {
            Address::IPv4(v4) => assert_eq!(v4.octets(), [203, 0, 113, 7]),
            other => panic!("expected original dst IPv4, got {other:?}"),
        }
    }

    #[test]
    fn resolve_dokodemo_follow_redirect_falls_back_to_predefined() {
        // 非 Linux / 非 REDIRECT 连接：无 original_dst、无 TLS → predefined
        let mut opts = tcp_opts();
        opts.follow_redirect = true;
        let dest = super::resolve_dokodemo_tcp_dest(&opts, None, Some(80), None, None)
            .unwrap();
        assert_eq!(dest.port().value(), 80);
        match dest.address() {
            Address::IPv4(v4) => assert_eq!(v4.octets(), [10, 0, 0, 1]),
            other => panic!("expected predefined IPv4, got {other:?}"),
        }
    }

    #[test]
    fn resolve_dokodemo_port_map_skipped_when_follow_redirect() {
        // Go：portMap 分支在 !FollowRedirect 内，两者互斥
        let mut opts = tcp_opts();
        opts.follow_redirect = true;
        opts.port_map
            .insert("80".to_string(), "192.168.99.1:9090".to_string());
        let dest = super::resolve_dokodemo_tcp_dest(&opts, None, Some(80), None, None)
            .unwrap();
        assert_eq!(dest.port().value(), 80);
        match dest.address() {
            Address::IPv4(v4) => assert_eq!(v4.octets(), [10, 0, 0, 1]),
            other => panic!("expected predefined IPv4, got {other:?}"),
        }
    }

    /// dokodemo settings：address/port 可选（Go rewriteAddress/rewritePort 独立可选）。
    #[test]
    fn parse_dokodemo_settings_address_port_optional() {
        // 全缺 → dest None（followRedirect 透明代理形态）
        let s = super::parse_dokodemo_settings(br#"{"followRedirect":true}"#).unwrap();
        assert!(s.dest.is_none(), "no address/port → dest None");
        assert!(s.follow_redirect);
        // 只给 address → port=0（serve 侧回填本地端口）
        let s = super::parse_dokodemo_settings(br#"{"address":"10.1.2.3"}"#).unwrap();
        let d = s.dest.expect("address-only should build dest");
        assert_eq!(d.port().value(), 0);
        // address+port 齐全（既有形态不回归）
        let s = super::parse_dokodemo_settings(br#"{"address":"example.com","port":443}"#).unwrap();
        let d = s.dest.expect("full form should build dest");
        assert_eq!(d.port().value(), 443);
        assert!(matches!(d.address(), Address::Domain(_)));
    }

    /// 非 follow_redirect 且无 predefined：回填本机回环 + 本地端口（Go dokodemo.go:86-100）。
    #[test]
    fn resolve_dokodemo_backfills_loopback_when_no_predefined() {
        let mut opts = tcp_opts();
        opts.dest = None;
        let dest = super::resolve_dokodemo_tcp_dest(
            &opts,
            Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            Some(1080),
            None,
            None,
        )
        .unwrap();
        assert_eq!(dest.port().value(), 1080, "port 回填本地监听端口");
        match dest.address() {
            Address::IPv4(v4) => assert_eq!(v4.octets(), [127, 0, 0, 1]),
            other => panic!("expected loopback IPv4, got {other:?}"),
        }
        // v6 监听 → ::1
        let dest = super::resolve_dokodemo_tcp_dest(
            &opts,
            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            Some(1080),
            None,
            None,
        )
        .unwrap();
        assert!(matches!(dest.address(), Address::IPv6(_)));
    }

    /// follow_redirect 且 original/SNI/rewrite 皆缺 → None（无有效目标，跳过 dispatch）。
    #[test]
    fn resolve_dokodemo_follow_redirect_without_any_target_returns_none() {
        let mut opts = tcp_opts();
        opts.dest = None;
        opts.follow_redirect = true;
        assert!(super::resolve_dokodemo_tcp_dest(&opts, None, Some(80), None, None).is_none());
    }


    #[test]
    fn parse_dokodemo_settings_port_map() {
        let settings = serde_json::json!({
            "address": "1.2.3.4", "port": 80,
            "portMap": { "80": "192.168.99.1:9090", "443": ":8443" }
        });
        let data = serde_json::to_vec(&settings).unwrap();
        let s = super::parse_dokodemo_settings(&data).unwrap();
        assert_eq!(s.port_map.len(), 2);
        assert_eq!(s.port_map.get("80").unwrap(), "192.168.99.1:9090");
    }

    #[test]
    fn parse_dokodemo_settings_invalid_port_map_value() {
        // Go infra/conf 校验 SplitHostPort 失败 → 配置错误
        let settings = serde_json::json!({
            "address": "1.2.3.4", "port": 80,
            "portMap": { "80": "no-colon-here" }
        });
        let data = serde_json::to_vec(&settings).unwrap();
        let err = super::parse_dokodemo_settings(&data).unwrap_err();
        assert!(err.to_string().contains("portMap"), "got: {err}");
    }

    /// i09：捕获 dispatch 收到的 dest（TCP），并回写标记确认链路。
    #[derive(Debug)]
    struct DestCaptureDispatch {
        dest: parking_lot::Mutex<Option<Destination>>,
    }

    impl xray_app_dispatcher::DispatchHandler for DestCaptureDispatch {
        fn tag(&self) -> &str {
            "dest-capture"
        }

        fn dispatch(
            &self,
            dest: &Destination,
            link: Link,
        ) -> xray_app_dispatcher::default::PinFuture<()> {
            *self.dest.lock() = Some(dest.clone());
            Box::pin(async move {
                let Link { mut writer, mut reader } = link;
                let marker = b"ok".to_vec();
                let mut mb = xray_buf::multi::MultiBuffer::new();
                mb.merge_bytes(&marker);
                let _ = writer.write_multi_buffer(mb).await;
                // drain 入站：socket 带未读数据关闭会触发 RST，客户端读标记前连接被重置
                loop {
                    match reader.read_multi_buffer().await {
                        Ok(mb) if mb.is_empty() => break,
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
            })
        }
    }

    /// userLevel 生效：policy_for_level(UserLevel).timeout.handshake → serve_http
    /// 首请求超时断开。对应 Go proxy/http/server.go:47-51 policy() +
    /// :112 SetReadDeadline(Timeouts.Handshake)。
    #[tokio::test]
    async fn serve_http_handshake_timeout_from_user_level_policy() {
        use tokio::io::AsyncReadExt;

        struct FixedHandshakePolicy(std::time::Duration);
        impl xray_features::policy::PolicyManager for FixedHandshakePolicy {
            fn policy_for_level(&self, _level: u32) -> xray_features::policy::Policy {
                let mut p = xray_features::policy::Policy::default();
                p.timeout.handshake = self.0;
                p
            }
            fn for_system(&self) -> xray_features::policy::SystemStats {
                xray_features::policy::SystemStats::default()
            }
        }

        let ohm = Arc::new(SimpleOhm::new());
        let bridge = Arc::new(DestCaptureDispatch {
            dest: parking_lot::Mutex::new(None),
        }) as Arc<dyn xray_app_dispatcher::DispatchHandler>;
        ohm.set_default(bridge);

        let listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        ).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = HttpServerConfig::default();
        config.user_level = 3;
        let pm: Arc<dyn xray_features::policy::PolicyManager> =
            Arc::new(FixedHandshakePolicy(std::time::Duration::from_millis(120)));
        let handshake_timeout = Some(pm.policy_for_level(config.user_level).timeout.handshake);
        tokio::spawn(serve_http(
            listener,
            ohm,
            Arc::new(config),
            handshake_timeout,
        ));

        // 客户端连接后保持静默：超时到期 → 服务端断开 → 客户端读到 EOF。
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let t0 = std::time::Instant::now();
        let mut buf = [0u8; 16];
        let n = client.read(&mut buf).await.unwrap();
        let elapsed = t0.elapsed();
        assert_eq!(n, 0, "expected EOF after handshake timeout");
        assert!(
            elapsed >= std::time::Duration::from_millis(100),
            "disconnect should come from timeout, not immediate: {elapsed:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "timeout too slow: {elapsed:?}"
        );
    }

    /// socks 握手限时行为测试：客户端连上后保持静默，handshake_timeout 到期
    /// → 服务端断开 → 客户端读到 EOF（Go proxy/socks SetReadDeadline 语义）。
    /// None 时不限时由既有握手 e2e 覆盖。
    #[tokio::test]
    async fn serve_socks5_handshake_timeout_disconnects_silent_client() {
        use tokio::io::AsyncReadExt;

        let ohm = Arc::new(SimpleOhm::new());
        let bridge = Arc::new(DestCaptureDispatch {
            dest: parking_lot::Mutex::new(None),
        }) as Arc<dyn xray_app_dispatcher::DispatchHandler>;
        ohm.set_default(bridge);

        let listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        ).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = Arc::new(parse_socks_server_config(b"{}").unwrap());
        tokio::spawn(serve_socks5(
            listener,
            ohm,
            config,
            Some(std::time::Duration::from_millis(120)),
        ));

        // 客户端连接后不发任何字节：超时到期 → 服务端断开 → EOF。
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let t0 = std::time::Instant::now();
        let mut buf = [0u8; 16];
        let n = client.read(&mut buf).await.unwrap();
        let elapsed = t0.elapsed();
        assert_eq!(n, 0, "expected EOF after socks handshake timeout");
        assert!(
            elapsed >= std::time::Duration::from_millis(100),
            "disconnect should come from timeout, not immediate: {elapsed:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "timeout too slow: {elapsed:?}"
        );
    }

    /// i09 e2e：dokodemo TCP port_map——按监听端口改写 dest（Go dokodemo.go:101-109）。
    #[tokio::test]
    async fn dokodemo_tcp_port_map_dispatch_e2e() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let ohm = Arc::new(SimpleOhm::new());
        let capture = Arc::new(DestCaptureDispatch {
            dest: parking_lot::Mutex::new(None),
        });
        ohm.set_default(capture.clone() as Arc<dyn DispatchHandler>);

        let listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        ).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let opts = DokodemoTcpOptions {
            dest: Some(Destination::tcp(
                Address::IPv4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                Port::new(80),
            )),
            port_map: [(port.to_string(), "192.168.99.1:9090".to_string())]
                .into_iter()
                .collect(),
            follow_redirect: false,
            tls: None,
        };
        tokio::spawn(async move {
            let _ = serve_dokodemo(listener, ohm, opts).await;
        });

        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 2];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ok");

        let dest = capture.dest.lock().clone().expect("dest captured");
        assert_eq!(dest.port().value(), 9090, "port should be port_map-mapped");
        match dest.address() {
            Address::IPv4(v4) => assert_eq!(v4.octets(), [192, 168, 99, 1]),
            other => panic!("expected mapped IPv4, got {other:?}"),
        }
    }

    /// i09 e2e：dokodemo + TLS + followRedirect——客户端 SNI 覆盖 dest.address
    /// （Go dokodemo.go:122-132）。
    #[tokio::test]
    async fn dokodemo_tls_sni_override_e2e() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};


        static PROVIDER: std::sync::Once = std::sync::Once::new();
        PROVIDER.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });

        #[derive(Debug)]
        struct NoVerify;
        impl rustls::client::danger::ServerCertVerifier for NoVerify {
            fn verify_server_cert(
                &self,
                _end_entity: &rustls::pki_types::CertificateDer<'_>,
                _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                _server_name: &rustls::pki_types::ServerName<'_>,
                _ocsp_response: &[u8],
                _now: rustls::pki_types::UnixTime,
            ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                message: &[u8],
                cert: &rustls::pki_types::CertificateDer<'_>,
                dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                rustls::crypto::verify_tls12_signature(
                    message,
                    cert,
                    dss,
                    &rustls::crypto::ring::default_provider().signature_verification_algorithms,
                )
            }
            fn verify_tls13_signature(
                &self,
                message: &[u8],
                cert: &rustls::pki_types::CertificateDer<'_>,
                dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                rustls::crypto::verify_tls13_signature(
                    message,
                    cert,
                    dss,
                    &rustls::crypto::ring::default_provider().signature_verification_algorithms,
                )
            }
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms
                    .supported_schemes()
            }
        }

        // 1. 证书 SAN = 期望 SNI 域名
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["sni.example.com".to_string()])
            .unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let stream_settings = serde_json::json!({
            "security": "tls",
            "tlsSettings": { "cert": cert.pem(), "key": key_pair.serialize_pem() }
        });
        let tls = super::build_tls_acceptor(Some(&stream_settings))
            .unwrap()
            .expect("tls acceptor");

        // 2. serve_dokodemo：predefined dest 1.2.3.4:80 + follow_redirect（SNI 门控）
        let ohm = Arc::new(SimpleOhm::new());
        let capture = Arc::new(DestCaptureDispatch {
            dest: parking_lot::Mutex::new(None),
        });
        ohm.set_default(capture.clone() as Arc<dyn DispatchHandler>);
        let listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        ).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let opts = DokodemoTcpOptions {
            dest: Some(Destination::tcp(
                Address::IPv4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
                Port::new(80),
            )),
            port_map: HashMap::new(),
            follow_redirect: true,
            tls: Some(tls),
        };
        tokio::spawn(async move {
            let _ = serve_dokodemo(listener, ohm, opts).await;
        });

        // 3. 客户端 TLS 握手带 SNI sni.example.com
        let client_cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
        let sock = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("sni.example.com")
            .unwrap()
            .to_owned();
        let mut tls_client = connector.connect(server_name, sock).await.unwrap();

        tls_client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 2];
        tls_client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ok");

        // 4. dispatch dest.address 应为 SNI 域名（port 保持 predefined）
        let dest = capture.dest.lock().clone().expect("dest captured");
        assert_eq!(dest.port().value(), 80, "SNI 只覆盖 address");
        match dest.address() {
            Address::Domain(d) => assert_eq!(d, "sni.example.com"),
            other => panic!("expected SNI domain, got {other:?}"),
        }
    }

    /// i09 e2e：followRedirect 但无 NAT/非 Linux——回落 predefined dest。
    #[tokio::test]
    async fn dokodemo_follow_redirect_falls_back_to_predefined_e2e() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let ohm = Arc::new(SimpleOhm::new());
        let capture = Arc::new(DestCaptureDispatch {
            dest: parking_lot::Mutex::new(None),
        });
        ohm.set_default(capture.clone() as Arc<dyn DispatchHandler>);
        let listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        ).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let opts = DokodemoTcpOptions {
            dest: Some(Destination::tcp(
                Address::IPv4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                Port::new(443),
            )),
            port_map: HashMap::new(),
            follow_redirect: true,
            tls: None,
        };
        tokio::spawn(async move {
            let _ = serve_dokodemo(listener, ohm, opts).await;
        });

        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 2];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ok");

        // 直连（无 iptables REDIRECT）：get_original_dst 失败/不可用 → predefined
        let dest = capture.dest.lock().clone().expect("dest captured");
        assert_eq!(dest.port().value(), 443);
        match dest.address() {
            Address::IPv4(v4) => assert_eq!(v4.octets(), [10, 0, 0, 1]),
            other => panic!("expected predefined IPv4, got {other:?}"),
        }
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
    fn build_vless_validator_email_less_clients_counted_and_auth_enforced() {
        // 生产最小配置形态：client 无 email（users=0 复现形态）。
        let ua = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let ub = "66ad4540-b58c-4ad2-9926-ea63445a9b57";
        let settings = serde_json::json!({
            "clients": [{ "id": ua, "level": 0 }, { "id": ub }],
            "decryption": "none",
        });
        let data = serde_json::to_vec(&settings).unwrap();
        let validator = super::build_vless_validator(&data).unwrap();
        use xray_proxy_vless::Validator as VlessValidatorTrait;
        // 启动日志口径：UUID 可认证用户数 = 2（get_count 只数 email 表 → 0）
        assert_eq!(VlessValidatorTrait::get_uuid_count(&*validator), 2);
        assert_eq!(VlessValidatorTrait::get_count(&*validator), 0);
        // 合法 UUID 均可解析出用户；未注册 UUID 拒绝（认证语义）
        let a = xray_common::uuid::UUID::parse(ua).expect("uuid a");
        let b = xray_common::uuid::UUID::parse(ub).expect("uuid b");
        assert!(VlessValidatorTrait::get(&*validator, &a).is_some());
        assert!(VlessValidatorTrait::get(&*validator, &b).is_some());
        let bad = xray_common::uuid::UUID::parse("d342d11e-d424-4583-b36e-524ab1f0afa4").expect("uuid bad");
        assert!(VlessValidatorTrait::get(&*validator, &bad).is_none());
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
    fn build_trojan_users_with_flow_still_builds() {
        // Trojan Flow 已移除（Go trojan.go:134-136 硬报错）；Rust warn + 不阻断：
        // 带 flow 的 client 仍正常入表（触发文案断言见 outbound 侧 helper 测试）。
        let settings = serde_json::json!({
            "clients": [{ "password": "secret", "email": "alice", "flow": "xtls-rprx-vision" }],
        });
        let data = serde_json::to_vec(&settings).unwrap();
        let users = super::build_trojan_users(&data).unwrap();
        assert_eq!(users.len(), 1, "flow field should not block user build");
    }
    #[test]
    fn build_trojan_users_empty_clients() {
        let settings = serde_json::json!({});
        let data = serde_json::to_vec(&settings).unwrap();
        let users = super::build_trojan_users(&data).unwrap();
        assert!(users.is_empty());
    }

    /// Go infra/conf/trojan.go:115-116 + 124-126：`users` 与 `clients` 是 alias。
    /// 本测验证：当 JSON 只提供 `users`（无 `clients`）时也能解析。
    #[test]
    fn build_trojan_users_parses_users_alias() {
        let settings = serde_json::json!({
            "users": [{ "password": "secret", "email": "alice", "level": 2 }],
        });
        let data = serde_json::to_vec(&settings).unwrap();
        let users = super::build_trojan_users(&data).unwrap();
        assert_eq!(users.len(), 1);
        let expected_account = TrojanMemoryAccount::new("secret");
        let expected_user = TrojanMemoryUser::new("alice", 2, expected_account);
        assert!(users.contains_key(&expected_user.key_hash()));
    }

    /// Go trojan.go:154-155 + 188-190：dest 数字 N → "localhost:N"，type 缺省推导 tcp。
    #[test]
    fn build_trojan_fallbacks_numeric_dest_becomes_localhost() {
        let settings = serde_json::json!({
            "fallbacks": [{ "dest": 8080 }]
        });
        let data = serde_json::to_vec(&settings).unwrap();
        let policy = super::build_trojan_fallbacks(&data).unwrap().expect("one fallback");
        let fb = policy.decide("", "", "").expect("wildcard fallback");
        assert_eq!(fb.dest, "localhost:8080");
        assert_eq!(fb.r#type, "tcp");
    }

    /// Go trojan.go:196-198：dest 缺失且 type 缺省 → 报错（不再回退 127.0.0.1:80）。
    #[test]
    fn build_trojan_fallbacks_missing_dest_is_error() {
        let settings = serde_json::json!({ "fallbacks": [{ "name": "sni" }] });
        let data = serde_json::to_vec(&settings).unwrap();
        let err = super::build_trojan_fallbacks(&data).unwrap_err();
        assert!(err.to_string().contains("dest"), "error should mention dest: {err}");
    }

    /// Go trojan.go:191-193：host:port 字符串 → type tcp；既有行为不回归。
    #[test]
    fn build_trojan_fallbacks_host_port_dest_derives_tcp() {
        let settings = serde_json::json!({
            "fallbacks": [{ "dest": "127.0.0.1:8080", "xver": 1 }]
        });
        let data = serde_json::to_vec(&settings).unwrap();
        let policy = super::build_trojan_fallbacks(&data).unwrap().expect("one fallback");
        let fb = policy.decide("", "", "").expect("wildcard fallback");
        assert_eq!(fb.dest, "127.0.0.1:8080");
        assert_eq!(fb.r#type, "tcp");
        assert_eq!(fb.xver, 1);
    }

    /// Go trojan.go:180-186：`@@` 前缀 + type 缺省 → unix + 抽象套接字 padding。
    #[test]
    fn build_trojan_fallbacks_abstract_unix_dest_derives_unix() {
        let settings = serde_json::json!({
            "fallbacks": [{ "dest": "@@haproxy" }]
        });
        let data = serde_json::to_vec(&settings).unwrap();
        let policy = super::build_trojan_fallbacks(&data).unwrap().expect("one fallback");
        let fb = policy.decide("", "", "").expect("wildcard fallback");
        assert_eq!(fb.r#type, "unix");
        #[cfg(unix)]
        assert!(fb.dest.starts_with('\0'), "abstract socket should be NUL-padded");
    }

    /// Go infra/conf/trojan.go:182-186：fallback.dest 以 `@@` 开头（unix）→ 108 字节 NUL padding。
    /// 非 unix 平台（包括 Windows）→ 原样返回。
    #[test]
    fn apply_unix_abstract_padding_double_at_prefix() {
        let got = super::apply_unix_abstract_padding("@@my-abstract-socket");
        #[cfg(unix)]
        {
            // 首字节必须是 NUL（Linux abstract namespace 标识），后续紧跟 "@my-abstract-socket"
            // — Go copy(fullAddr, fb.Dest[1:]) 跳过了首个 '@'。
            assert_eq!(got.as_bytes()[0], 0, "first byte should be NUL");
            assert!(got.starts_with("\0@my-abstract-socket"), "expected NUL+@my-... got {got:?}");
            assert_eq!(got.len(), 108, "must pad to 108 bytes (syscall.RawSockaddrUnix.Path)");
        }
        #[cfg(not(unix))]
        {
            assert_eq!(got, "@@my-abstract-socket", "non-unix should passthrough");
        }
    }

    /// 单 `@` 开头（普通 unix 路径）→ 不做 padding，原样返回。
    #[test]
    fn apply_unix_abstract_padding_single_at_passthrough() {
        let got = super::apply_unix_abstract_padding("@/tmp/sock");
        assert_eq!(got, "@/tmp/sock", "single @ is not abstract namespace");
    }

    /// 普通 host:port → 不做 padding，原样返回。
    #[test]
    fn apply_unix_abstract_padding_plain_dest_passthrough() {
        let got = super::apply_unix_abstract_padding("127.0.0.1:8080");
        assert_eq!(got, "127.0.0.1:8080");
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

    /// alterId>0 的 legacy VMess 不支持（AEAD-only）：启动即报错，不静默忽略。
    #[test]
    fn build_vmess_validator_alter_id_nonzero_fails() {
        let settings = serde_json::json!({
            "clients": [{ "id": "66ad4540-b58c-4ad2-9926-ea63445a9b57", "alterId": 64 }]
        });
        let data = serde_json::to_vec(&settings).unwrap();
        let err = match super::build_vmess_validator(&data) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("alterId=64 should be rejected"),
        };
        assert!(err.contains("alterId"), "unexpected error: {err}");
    }

    /// 字符串形式 alterId（老配置生成器输出）同样拒绝。
    #[test]
    fn build_vmess_validator_alter_id_string_fails() {
        let settings = serde_json::json!({
            "clients": [{ "id": "66ad4540-b58c-4ad2-9926-ea63445a9b57", "alterId": "64" }]
        });
        let data = serde_json::to_vec(&settings).unwrap();
        assert!(super::build_vmess_validator(&data).is_err());
    }

    /// alterId==0 走现有 AEAD 路径，validator 正常构建。
    #[test]
    fn build_vmess_validator_alter_id_zero_ok() {
        let settings = serde_json::json!({
            "clients": [{ "id": "66ad4540-b58c-4ad2-9926-ea63445a9b57", "alterId": 0 }]
        });
        let data = serde_json::to_vec(&settings).unwrap();
        let validator = super::build_vmess_validator(&data).unwrap();
        use xray_proxy_vmess::Validator as VmessValidatorTrait;
        assert_eq!(VmessValidatorTrait::count(&*validator), 1);
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

    /// `users` 主键（Go http.go:26）+ `accounts` 旧名回退 + 双键并存 users 优先。
    #[test]
    fn parse_http_config_users_alias_and_priority() {
        let data = serde_json::json!({
            "users": [{ "user": "alice", "pass": "p1" }]
        });
        let cfg = super::parse_http_config(&serde_json::to_vec(&data).unwrap()).unwrap();
        assert!(cfg.has_account("alice", "p1"), "users[] should populate accounts");

        // clients…不对，http 的旧键是 accounts：只给 accounts 仍解析（兼容）
        let data = serde_json::json!({
            "accounts": [{ "user": "bob", "pass": "p2" }]
        });
        // http 的旧键是 accounts：只给 accounts 仍解析（兼容）
        let cfg = super::parse_http_config(&serde_json::to_vec(&data).unwrap()).unwrap();
        assert!(cfg.has_account("bob", "p2"), "accounts[] fallback should still work");

        // 双键并存：users 优先（任务规定模式；Go 单键场景不受影响）
        let data = serde_json::json!({
            "users": [{ "user": "winner", "pass": "wp" }],
            "accounts": [{ "user": "loser", "pass": "lp" }]
        });
        let cfg = super::parse_http_config(&serde_json::to_vec(&data).unwrap()).unwrap();
        assert!(cfg.has_account("winner", "wp"), "users takes priority");
        assert!(!cfg.has_account("loser", "lp"), "accounts ignored when users present");
    }


    #[test]
    fn parse_http_config_transparent_and_user_level() {
        // 键名/零值默认对齐 Go infra/conf/http.go:28-29（Transparent json:"allowTransparent"、UserLevel json:"userLevel"）。
        let settings = serde_json::json!({
            "allowTransparent": true,
            "userLevel": 7
        });
        let data = serde_json::to_vec(&settings).unwrap();
        let cfg = super::parse_http_config(&data).unwrap();
        assert!(cfg.allow_transparent);
        assert_eq!(cfg.user_level, 7);
    }

    #[test]
    fn parse_http_config_transparent_defaults_off() {
        // Go Build() 直接透传，缺省即零值（false/0）。
        let cfg = super::parse_http_config(br#"{"userLevel":0}"#).unwrap();
        assert!(!cfg.allow_transparent);
        assert_eq!(cfg.user_level, 0);
    }

    #[test]
    fn parse_dokodemo_dest_ipv4() {
        let settings = serde_json::json!({ "address": "192.168.1.1", "port": 8080 });
        let data = serde_json::to_vec(&settings).unwrap();
        let dest = super::parse_dokodemo_settings(&data).unwrap().dest.unwrap();
        assert!(matches!(dest.address(), Address::IPv4(_)));
        assert_eq!(dest.port().value(), 8080);
    }

    #[test]
    fn parse_dokodemo_dest_domain() {
        let settings = serde_json::json!({ "address": "example.com", "port": 443 });
        let data = serde_json::to_vec(&settings).unwrap();
        let dest = super::parse_dokodemo_settings(&data).unwrap().dest.unwrap();
        assert!(matches!(dest.address(), Address::Domain(_)));
        assert_eq!(dest.port().value(), 443);
    }

    /// Go parity：只给 port（缺 address）→ dest None（rewrite 缺省回填在 serve 侧）。
    #[test]
    fn parse_dokodemo_port_only_dest_none() {
        let settings = serde_json::json!({ "port": 80 });
        let data = serde_json::to_vec(&settings).unwrap();
        let s = super::parse_dokodemo_settings(&data).unwrap();
        assert!(s.dest.is_none());
    }

    /// Go parity：只给 address → dest Some 且 port=0（serve 侧回填本地端口）。
    #[test]
    fn parse_dokodemo_address_only_port_zero() {
        let settings = serde_json::json!({ "address": "1.2.3.4" });
        let data = serde_json::to_vec(&settings).unwrap();
        let s = super::parse_dokodemo_settings(&data).unwrap();
        let d = s.dest.expect("address-only should build dest");
        assert_eq!(d.port().value(), 0);
    }

    #[test]
    fn parse_dokodemo_settings_tcp_only() {
        let settings = serde_json::json!({ "address": "1.2.3.4", "port": 80, "network": "tcp" });
        let data = serde_json::to_vec(&settings).unwrap();
        let s = super::parse_dokodemo_settings(&data).unwrap();
        assert!(s.allow_tcp);
        assert!(!s.allow_udp);
        assert!(!s.follow_redirect);
        assert!(s.dest.as_ref().unwrap().is_tcp());
    }

    #[test]
    fn parse_dokodemo_settings_udp_only() {
        let settings = serde_json::json!({ "address": "1.2.3.4", "port": 53, "network": "udp" });
        let data = serde_json::to_vec(&settings).unwrap();
        let s = super::parse_dokodemo_settings(&data).unwrap();
        assert!(!s.allow_tcp);
        assert!(s.allow_udp);
        assert!(s.dest.as_ref().unwrap().is_udp());
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
