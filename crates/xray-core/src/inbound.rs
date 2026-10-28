// L3 静态闸存量登记（bd a5r4j/lzzja 切片；W4 面 3+6 后实盘 2026-10-27）：
// **生产面已清零**——tokio::spawn 生产 2 处（监控壳外层 1 + tun 1）均已逐点
// `#[allow]` + 理由登记；tokio::time::Instant::now 生产 0 处；std::time::Instant::now
// 生产 1 处（ss2022 会话惰性清扫锚点，逐点登记）。
// **测试面 52 处 tokio::spawn + 4 处 std Instant + 2 处 tokio Instant 留在
// `mod tests` 的 inner allow**（测试计时/并发夹具不得改语义；tokio::test 自有
// runtime，FxScope 化无生命周期收益）。
// W4 已迁：batch1 13 处 + batch2 6 处（UDP associate + UDS 每连接 5）+ W4 8 处
//（mux link 4 → arm scope / SS 泵 1 → conn scope / 监控壳内层 1 → arm scope /
// reality vision 2 → redline 受控口）生产 spawn → arm PluginContext（bd 39hko）。
//! SOCKS5 inbound listener：接收连接 → SOCKS5 握手 → dispatcher 分发。
//!
//! 对应 Go `app/proxyman/inbound/always.go::handle_connection` + `proxy/socks/server.go`。
//! 这里实现最小端到端切片：TCP accept → socks5 handshake → SocksAddr → Destination →
//! `DispatchHandler::dispatch(dest, link)`。
//!
//! 不含：sniffing（协议嗅探）、UDP associate、多 inbound 注册管理（由 proxyman::InboundManager
//! 负责）。

// P1-B: vless/trojan inbound 集成
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use skeleton_infra::memgov::{BoundedRegistry, Eviction};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    net::{TcpStream, UdpSocket},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use xray_app_dispatcher::{
    DispatchHandler, OutboundHandlerManager, UdpDispatchSession, default::SimpleOhm,
};
use xray_app_proxyman::ProxymanError;
use xray_buf::io::{Reader, Writer, new_reader, new_readv_reader, new_writer};
use xray_common::{
    net::{address::Address, destination::Destination, network::Network, port::Port},
    uuid::UUID,
};
use xray_conf::{BuiltConfig, BuiltInbound};
// trait 唯一消费点是下方 TUN 臂的 `handler.start()`——随该臂同门控，否则
// darwin 等无 TUN 平台 trait 无消费者 → unused_imports 在 deny(warnings) 下硬错。
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "windows"
))]
use xray_features::inbound::InboundHandler;
// W4 面 6：budget/deadline 统一走 xray_frame::deadline::Budget（Tokio 源保 advance
// 语义）；vision 装配 spawn 走面 5 受控入口（redline 台账，坑约束 ⑫ 调用形态治理）；
// SS 泵归每连接 ConnScope（两级 scope 模型，方案 §2 面 6）。
use xray_frame::PluginContext;
// 注：redline 走 `redline::spawn_unchecked` 全路径调用形态（不 alias）——
// `tests/redline_sites.rs` 的 CI 门按字面量核对调用集合，alias 会让本文件对门隐形。
use xray_frame::{
    deadline::Budget,
    redline::{self, RedlineSite},
};
// zx7: mux inbound 检测
use xray_mux::client::{MUX_COOL_ADDRESS, MUX_COOL_PORT};
use xray_proto::xray::{
    common::protocol::User as ProtoUser, core::InboundHandlerConfig as ProtoInboundConfig,
    proxy::vless::Account as VlessProtoAccount,
};
use xray_proxy_blackhole::ResponseConfig as BlackholeResponseConfig;
use xray_proxy_dns::{Config as DnsConfig, DnsInbound, DnsOutbound, Handler as DnsHandler};
// tdy: http + dokodemo inbound 集成
use xray_proxy_http::ServerConfig as HttpServerConfig;
use xray_proxy_http::server::{
    HandshakeResult, build_forwarded_request, extract_request_path, http_server_handshake,
    request_keep_alive, resolve_request_host, serialize_go_response_head,
};
use xray_proxy_socks::{
    ServerConfig,
    protocol::{Host, SocksAddr, decode_udp_packet, encode_udp_packet},
    relay::TempUdpRelay,
    server::{SocksRequest, socks_handshake},
};
use xray_proxy_ss::config::MemoryAccount as SsConfigMemoryAccount;
// 补全协议 inbound 注册
use xray_proxy_ss::{CipherType as SsCipherType, SsInbound};
use xray_proxy_trojan::{
    MemoryAccount as TrojanMemoryAccount, MemoryUser as TrojanMemoryUser,
    fallback::{Fallback, FallbackPolicy},
};
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "windows"
))]
use xray_proxy_tun::{StackOptions, Tun, TunInboundHandler};
use xray_proxy_vless::{
    MemoryAccount as VlessMemoryAccount, MemoryUser as VlessMemoryUser,
    MemoryValidator as VlessMemoryValidator, Validator as VlessValidator, VlessInboundOptions,
};
use xray_proxy_vmess::{
    MemoryAccount as VmessMemoryAccount, MemoryUser as VmessMemoryUser,
    TimedUserValidator as VmessTimedUserValidator, Validator as VmessValidator, VmessError,
};
use xray_proxy_wireguard::DeviceConfig;
use xray_transport::{
    finalmask::MaybeTcpMaskConn, link::Link, system_listener::InboundTcpListener,
};
use xray_transport_hysteria::quinn_adapter::QuinnListenerFactory;

/// accept 错误退避：fd 耗尽（EMFILE/ENFILE）时睡眠 500ms 再重试——否则 accept 立即
/// 失败-continue 构成忙旋 + warn 日志洪水（audit 高并发 HC-2，意图对齐 0bb4176d 与
/// ws register.rs 样板）。判别用大小写不敏感 `contains("too many")`：样板的小写匹配
/// 对 glibc 大写 "Too many open files" 永不命中（静默失效）；kind 判别不可用的原因：
/// `ErrorKind::ProcessFdQuotaExceeded/SystemFdQuotaExceeded` 仍属 unstable
/// io_error_more（1.98.0-nightly 实测 E0599）。其他错误不睡眠，维持原行为。
async fn accept_fd_backoff(e: &std::io::Error) {
    if e.to_string().to_lowercase().contains("too many") {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

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
    udp_idle: std::time::Duration,
    plugin_ctx: Arc<PluginContext>,
) -> std::io::Result<()> {
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;

    tracing::info!(
        addr = %listener.local_addr()?,
        "socks5 inbound listening"
    );

    loop {
        // finalmask.tcp：accept 后立即套上（wire 最外层；未配 mask → Plain 直通）
        let (stream, peer) = match listener.accept_masked().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "socks5 accept failed");
                accept_fd_backoff(&e).await;
                continue;
            },
        };

        let handler = Arc::clone(&handler);
        let config = Arc::clone(&config);
        // scope 生命周期锚：连接任务存活期间 arm scope 不 drop（裸 spawn
        // detach 语义等价；SsConnection `_ctx` 自持同款）
        let task_ctx = Arc::clone(&plugin_ctx);
        let conn_ctx = Arc::clone(&plugin_ctx);
        plugin_ctx
            .spawn(async move {
                let _ctx = task_ctx;
                if let Err(e) = handle_connection(
                    stream,
                    peer,
                    &config,
                    &handler,
                    handshake_timeout,
                    udp_idle,
                    conn_ctx,
                )
                .await
                {
                    // Go proxyman/worker.go:124：连接结束错误统一 LogInfo("connection ends")。
                    tracing::info!(peer = %peer, error = %e, "socks5 connection ended with error");
                }
            })
            .expect("arm FxScope is never closed");
    }
}

/// 入站连接元数据提取（txno④ + txno-splice）。
///
/// 对应 Go `session.Inbound` 的三块元数据：`Conn`（raw fd，session.go:52-53）、
/// `Local`（本地地址）、`CanSpliceCopy`（raw 传输判定，socks server.go:69/73-75）。
/// [`handle_connection`] 泛型于具体流类型（TCP `TcpStream` / UDS
/// `Box<dyn Connection>`），本 trait 把「是否裸 TCP / 能否 dup / 本地地址」
/// 抹平成统一入口。
trait InboundConnMeta {
    /// 裸 TCP 时返回 dup 克隆（Go `session.Inbound.Conn`）；非 raw 返回 `None`。
    fn splice_raw_clone(&self) -> Option<TcpStream>;
    /// 入站本地地址（Go `session.Inbound.Local`）。
    fn inbound_local(&self) -> Option<SocketAddr>;
    /// 是否裸 TCP（Go `proxy.IsRAWTransportWithoutSecurity`，proxy.go:802-809）。
    fn is_raw_inbound(&self) -> bool;
    /// 消费流拆为 (Reader, Writer)，按流类型分发（对应 Go `buf.NewReader`
    /// io.go:113-145 的类型分派）：裸 TCP 走 readv 聚合读（syscall.Conn →
    /// ReadVReader 分支，env 闸门 `xray.buf.readv` 关时工厂内部自动退回顺序
    /// 读）；非 TCP 流（UDS `Box<dyn Connection>`，无 syscall.Conn）退回顺序读
    /// （SingleReader 分支，行为与历史一致）。
    fn into_link_io(self) -> (Box<dyn Reader>, Box<dyn Writer>);
}

impl InboundConnMeta for TcpStream {
    fn splice_raw_clone(&self) -> Option<TcpStream> {
        xray_transport::connection::dup_tcp_stream(self)
    }

    fn inbound_local(&self) -> Option<SocketAddr> {
        self.local_addr().ok()
    }

    fn is_raw_inbound(&self) -> bool {
        true
    }

    fn into_link_io(self) -> (Box<dyn Reader>, Box<dyn Writer>) {
        let (rd, wr) = self.into_split();
        (new_readv_reader(rd), new_writer(wr))
    }
}

impl InboundConnMeta for Box<dyn xray_transport::connection::Connection> {
    fn splice_raw_clone(&self) -> Option<TcpStream> {
        // Connection::is_raw_tcp 缺省 false：TLS/包装层天然拒绝，与 Go 同
        if self.is_raw_tcp() { self.raw_tcp_clone() } else { None }
    }

    fn inbound_local(&self) -> Option<SocketAddr> {
        self.local_addr().ok().flatten()
    }

    fn is_raw_inbound(&self) -> bool {
        self.is_raw_tcp()
    }

    fn into_link_io(self) -> (Box<dyn Reader>, Box<dyn Writer>) {
        let (rd, wr) = tokio::io::split(self);
        (new_reader(rd), new_writer(wr))
    }
}

/// finalmask.tcp 包装后的裸 TCP 入站连接（bd dppv 余项：socks/mixed/http/
/// dokodemo/dns 五类裸 TCP 入站复用同一套 serve 逻辑）。
///
/// mask 生效时 wire 字节已非明文：raw fd 克隆会绕过解伪装链，故
/// [`Self::splice_raw_clone`] / [`Self::is_raw_inbound`] 一律按「不可 splice」；
/// 读侧退回顺序读（readv 只对真 socket 有意义）。
impl InboundConnMeta for MaybeTcpMaskConn<TcpStream> {
    fn splice_raw_clone(&self) -> Option<TcpStream> {
        xray_transport::connection::dup_tcp_stream(self.plain()?)
    }

    fn inbound_local(&self) -> Option<SocketAddr> {
        self.plain()?.local_addr().ok()
    }

    fn is_raw_inbound(&self) -> bool {
        self.plain().is_some()
    }

    fn into_link_io(self) -> (Box<dyn Reader>, Box<dyn Writer>) {
        match self {
            Self::Plain(c) => c.into_link_io(),
            Self::Masked(m) => {
                let (rd, wr) = tokio::io::split(m);
                (new_reader(rd), new_writer(wr))
            },
        }
    }
}

/// 首字节嗅探用的预读包装（mixed 靠第 1 字节分流 socks 与 HTTP）。
///
/// mask 生效时底层是密文套壳、拿不到 socket `peek`，故把读到的明文留在
/// `peeked`、由 [`tokio::io::AsyncRead`] 优先回放；未配 mask 时 peek 直通
/// `TcpStream::peek`，不产生任何缓冲（行为与 dppv 之前逐字节一致）。
struct PeekAhead {
    conn: MaybeTcpMaskConn<TcpStream>,
    peeked: Vec<u8>,
}

impl PeekAhead {
    fn new(conn: MaybeTcpMaskConn<TcpStream>) -> Self {
        Self { conn, peeked: Vec::new() }
    }

    /// 预读明文（语义同 `TcpStream::peek`：字节不消费，EOF 返回 0）。
    async fn peek(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(c) = self.conn.plain() {
            return c.peek(buf).await;
        }
        if self.peeked.is_empty() && !buf.is_empty() {
            let mut tmp = vec![0u8; buf.len()];
            let n = self.conn.read(&mut tmp).await?;
            self.peeked.extend_from_slice(&tmp[..n]);
        }
        let n = self.peeked.len().min(buf.len());
        buf[..n].copy_from_slice(&self.peeked[..n]);
        Ok(n)
    }
}

impl AsyncRead for PeekAhead {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.peeked.is_empty() {
            let n = this.peeked.len().min(buf.remaining());
            buf.put_slice(&this.peeked[..n]);
            this.peeked.drain(..n);
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut this.conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for PeekAhead {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().conn).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().conn).poll_shutdown(cx)
    }
}

impl InboundConnMeta for PeekAhead {
    fn splice_raw_clone(&self) -> Option<TcpStream> {
        self.conn.splice_raw_clone()
    }

    fn inbound_local(&self) -> Option<SocketAddr> {
        self.conn.inbound_local()
    }

    fn is_raw_inbound(&self) -> bool {
        self.conn.is_raw_inbound()
    }

    fn into_link_io(self) -> (Box<dyn Reader>, Box<dyn Writer>) {
        if self.peeked.is_empty() {
            return self.conn.into_link_io();
        }
        // 预读过明文：必须连缓冲一起交给读侧回放，不能直接拆底层 conn。
        let (rd, wr) = tokio::io::split(self);
        (new_reader(rd), new_writer(wr))
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
    udp_idle: std::time::Duration,
    plugin_ctx: Arc<PluginContext>,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static + InboundConnMeta,
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
                ));
            },
        }
    };

    match socks_req {
        SocksRequest::UdpAssociate(_, relay_socket) => {
            // UDP relay：spawn pump，保持 TCP 控制连接直到客户端断开
            // handler 是 &Arc 引用，spawn 的 future 需 'static —— spawn 前 clone
            let udp_handler = Arc::clone(handler);
            // 来源过滤（bd wq16g）：只接受客户端地址，其余来源丢弃
            let relay = temp_udp_relay(relay_socket, peer);
            // scope 生命周期锚：relay 任务存活期间 arm scope 不 drop（裸 spawn
            // detach 语义等价；Spawned::abort 保持控制连接断开即终止 relay）
            let relay_ctx = Arc::clone(&plugin_ctx);
            let relay = plugin_ctx
                .spawn(async move {
                    let _ctx = relay_ctx;
                    let _ = handle_udp_associate(relay, udp_handler, udp_idle).await;
                })
                .expect("arm FxScope is never closed");
            // SOCKS5 UDP ASSOCIATE 语义：TCP 控制连接存在期间 relay 有效。
            // 读到 EOF/错误（客户端关闭控制连接）即终止 relay。
            let mut drop_buf = [0u8; 64];
            let _ = stream.read(&mut drop_buf).await;
            relay.abort();
            Ok(())
        },
        SocksRequest::TcpConnect(addr) => {
            // 2. SocksAddr → Destination
            let dest = socks_addr_to_destination(&addr, Network::TCP);
            // access log（bd 4uu）：from=客户端源地址（对应 Go socks server ctx
            // ContextWithAccessMessage{From: conn.RemoteAddr()}）；email 留空（无认证），
            // inbound_tag 由 InboundDispatchHandler 补齐。
            // txno：local=入站本地地址（Go session.Inbound.Local，④ portal 写侧）；
            // conn/can_splice_copy=splice 元数据（Go socks server.go:69 `2` + :73-75
            // 非 raw 翻 3 + :154-156 握手完成翻 1——dispatch 时点即已 1，Go
            // inbound.Conn 同点挂接）。raw fd 在 split 前取出（dup 克隆）。
            let access = {
                let (conn, can) = if stream.is_raw_inbound() {
                    (
                        stream.splice_raw_clone().map(Arc::new),
                        xray_common::platform::splice::CAN_SPLICE_COPY_YES,
                    )
                } else {
                    (None, xray_common::platform::splice::CAN_SPLICE_COPY_NEVER)
                };
                xray_app_dispatcher::AccessContext {
                    from: peer.to_string(),
                    local: stream.inbound_local().map(|a| a.to_string()).unwrap_or_default(),
                    conn,
                    can_splice_copy: can,
                    ..Default::default()
                }
            };
            // 3. 拆流 → Link：按流类型分发（InboundConnMeta::into_link_io）——
            // 裸 TCP 接 readv 聚合读（bd 4vkp，对齐 Go NewReader syscall.Conn
            // 分支）；UDS Box<dyn Connection> 退回顺序读；env 闸门
            // xray.buf.readv 关时工厂内部退回顺序读（行为同前）。
            let (reader, writer) = stream.into_link_io();
            let link = Link::new(reader, writer);
            // 4. dispatch（zx7: mux.cool dest 转给 mux ServerWorker）
            if is_mux_destination(&dest) {
                tracing::info!(
                    "socks: mux.cool destination detected, spawning mux inbound handler"
                );
                // W4 面 6：carrier 与 inbound（arm）同寿命 → arm scope 托管
                //（方案 §2 面 6：两级 scope 下 mux link 归 arm scope）。
                plugin_ctx
                    .spawn(handle_mux_inbound_link(link, Arc::clone(handler), None))
                    .expect("arm FxScope is never closed");
                return Ok(());
            }
            let _ = handler.dispatch_with_access(&dest, link, access).await;
            Ok(())
        },
    }
}

/// 检测 dest 是否为 mux.cool 多路复用信令目的地（zx7）。
///
/// 当客户端配置了 mux，会把目标设为 `v1.mux.cool:9527`，
/// inbound 收到后应转给 mux `ServerWorker` 解帧。
pub fn is_mux_destination(dest: &Destination) -> bool {
    matches!(dest.address(), Address::Domain(d) if d == MUX_COOL_ADDRESS)
        && dest.port().value() == MUX_COOL_PORT
}

/// 处理 mux.cool 入站连接：创建 ServerWorker，循环读帧，为每个子 session dispatch。
///
/// 对应 Go `mux.Server.OnTransport(link.Reader, link.Writer)`。socks/http 在
/// 协议层内联调用；wiring 的 [`crate::wiring::MuxCarrierHandler`] 装饰器对
/// 其余 inbound（vless/trojan/ss/…）统一按 destination 判定调用。
/// `allowed_network`：入站会话允许的网络（Go `ContextWithAllowedNetwork` →
/// server.go:189-192 消费）；Some 时 New 帧网络不匹配 → 错误 → 整条 carrier 拆除。
pub(crate) async fn handle_mux_inbound_link(
    link: Link,
    handler: Arc<dyn xray_app_dispatcher::DispatchHandler>,
    allowed_network: Option<Network>,
) {
    #[allow(unused_imports)] // 存量清零批次
    use xray_buf::{reader::BufferedReader, writer::BufferedWriter};
    use xray_mux::worker::{DispatchHandlerAdapter, ServerWorker};
    let adapter = Arc::new(DispatchHandlerAdapter::new(handler));
    let worker = match allowed_network {
        Some(net) => ServerWorker::new(adapter).with_allowed_network(net),
        None => ServerWorker::new(adapter),
    };

    // 包装 link reader/writer 为 BufferedReader/BufferedWriter
    let mut reader = BufferedReader::new(link.reader);
    let link_writer: Arc<tokio::sync::Mutex<Option<Box<dyn xray_buf::io::Writer>>>> =
        Arc::new(tokio::sync::Mutex::new(Some(link.writer)));

    // 启动 Go monitor 语义（60s 空载关 carrier，无 KeepAlive 帧）
    let monitor_h = worker.spawn_monitor(link_writer.clone());

    // 主帧处理循环
    loop {
        match worker.process_frame(&mut reader, &link_writer).await {
            Ok(true) => continue,
            Ok(false) => break, // 干净 EOF
            Err(e) => {
                // 整条 carrier 连同全部子会话在此拆除（bd txhn：warn 级曾使
                // loss+RTT 下的载体死亡在 ERROR 过滤的日志里完全不可见）
                tracing::error!(error = %e, "mux frame processing error, tearing down carrier");
                break;
            },
        }
    }

    worker.close();
    monitor_h.abort();
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
    SocksAddr { host, port: dest.port().value() }
}

/// ASSOCIATE 的 relay socket → 带来源过滤的 [`TempUdpRelay`]。
///
/// Go `protocol.go:211-219` 两条分支：请求地址为域名/未指定 IP → (TCP 对端 IP,
/// 端口 0，首包锁定)；否则 (请求 IP, 请求端口)。`SocksRequest::UdpAssociate` 只
/// 带 BND 地址、不带请求地址，故此处固定走第一条分支——同一台机器的其它源端口
/// 由首包锁定后同样被拒（bd wq16g）。
fn temp_udp_relay(relay_socket: UdpSocket, peer: SocketAddr) -> TempUdpRelay {
    TempUdpRelay::new(relay_socket, SocketAddr::new(peer.ip().to_canonical(), 0))
}

/// SOCKS5 UDP ASSOCIATE relay pump。
///
/// 对应 Go `proxy/socks/server.go::handleUDPPayload`。所有数据报经
/// [`UdpDispatchSession`] 走 dispatcher（routing 规则选 outbound），域名目标
/// 原样透传由 outbound 解析。当客户端 TCP 控制连接关闭时，调用方 abort 本
/// task 终止 relay。
///
/// 收包/回包走 [`TempUdpRelay`]（对齐 Go `TempUDPConn`）：来源不匹配的数据报
/// 在 `recv_filtered` 内被丢弃，响应固定回发 expected 地址——任意主机发一个
/// SOCKS5 UDP 帧即可注入/劫持的口子由此关闭（bd wq16g）。
async fn handle_udp_associate(
    relay: TempUdpRelay,
    handler: Arc<dyn DispatchHandler>,
    idle: std::time::Duration,
) -> std::io::Result<()> {
    let mut session = UdpDispatchSession::new(handler);
    // 收包缓冲走堆（栈数组会把本 future 撑到 64KiB，构造期在调用方 poll 栈上留
    // 同尺寸临时量 → 击穿 2MiB 线程栈；与全仓 UDP 缓冲的 vec! 形态同款）。
    let mut buf = vec![0u8; 65535];
    // UDP associate 空闲时限（Go server.go:171-175 `tempUDPConn.SetTimeout(
    // plcy.Timeouts.ConnectionIdle)`）：任一方向有活动即续期。
    // W4 面 3：取时统一走 Budget::tokio()（Tokio 源内部 = tokio Instant，pause 可推进不变）。
    let mut idle_deadline = Budget::tokio().deadline(idle);
    loop {
        tokio::select! {
            // 构造式：同体积于裸 `tokio::time::timeout`（方案面 3 + PM 2026-10-27 栈足迹回归口径：
            // async-fn 形态在巨型 future/裸 await 测试（本函数在 tests 里被非装箱 await）内会加厚栈帧）。
            _ = xray_frame::deadline::timeout(
                std::future::pending::<()>(),
                idle_deadline.remaining(),
            ) => {
                tracing::debug!(?idle, "socks udp relay idle timeout");
                return Ok(());
            }
            v = relay.recv_filtered(&mut buf[..]) => {
                let n = match v {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::debug!(error = %e, "socks udp relay recv failed");
                        continue;
                    }
                };
                // 只在被接受的数据报上续期（对齐 Go：被丢弃的来源不 c.Timer.Update()）
                idle_deadline = Budget::tokio().deadline(idle);
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
                idle_deadline = Budget::tokio().deadline(idle);
                let (source, payload) = match r {
                    Ok(Some(v)) => v,
                    Ok(None) => return Ok(()), // outbound 关闭，会话结束
                    Err(e) => {
                        // qyn8：recv 错误结束会话（对齐 Go read 错误语义与
                        // trojan/tun 先例）；continue 会与滞留坏帧构成忙旋
                        tracing::debug!(error = %e, "socks udp dispatch recv failed");
                        return Ok(());
                    }
                };
                // 编码响应帧（BND.ADDR = 响应来源地址），回发 expected（客户端）
                let resp = encode_udp_packet(&destination_to_socks_addr(&source), &payload);
                if relay.send_to_expected(&resp).await.is_err() {
                    tracing::debug!("socks udp send_to client failed");
                }
            }
        }
    }
}

/// 关闭前排空时限（对齐 xray-proxy-http server.rs `CLOSE_DRAIN_TIMEOUT`）。
const HTTP_CLOSE_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

/// HTTP 关闭路径优雅收尾：先 shutdown 写向（让已写响应先出去），再短排空读向。
///
/// Windows `closesocket` 在接收缓冲有未读数据时以 RST 复位连接，客户端会丢弃
/// 发送缓冲中在途的最后响应（400 / 503 / close 定界的尾响应）——读空接收缓冲
/// 后再 drop 才是干净 FIN（语义与 xray-proxy-http server.rs `graceful_close`
/// 同款；Unix 上 close 无此 RST 行为，多一次排空无害，保持全平台一致）。
///
/// 仅用于 stream 仍在手的退出路径；CONNECT 隧道分支 stream 已被
/// `into_link_io` 消耗，隧道关闭语义归 dispatch 桥，不在此处理。
async fn http_graceful_close<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
    use tokio::io::AsyncWriteExt;
    if stream.shutdown().await.is_err() {
        return;
    }
    let _ = tokio::time::timeout(HTTP_CLOSE_DRAIN_TIMEOUT, async {
        let mut sink = [0u8; 4096];
        loop {
            match stream.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {},
            }
        }
    })
    .await;
}

/// Mixed proxy inbound(V2RayN / Go xray `mixed` 协议 = socks + http 复合 listener)。
///
/// 单 listener 每连接 peek 1 字节嗅探:0x05 → SOCKS5;ASCII 字母开头 → HTTP。
/// 对应 Go `proxy/mixed/mixed.go` 同一 listener 上 mux socks 与 http 两个 handler。
/// 握手限时由 [`handshake_timeout_for`] 提供（policy 或 Go SessionDefault 60s 兜底）。
pub(crate) async fn serve_mixed(
    listener: InboundTcpListener,
    ohm: Arc<SimpleOhm>,
    socks_cfg: Arc<ServerConfig>,
    http_cfg: Arc<HttpServerConfig>,
    handshake_timeout: Option<std::time::Duration>,
    udp_idle: std::time::Duration,
    plugin_ctx: Arc<PluginContext>,
) -> std::io::Result<()> {
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;
    tracing::info!(addr = %listener.local_addr()?, "mixed (socks+http) inbound listening");
    loop {
        // finalmask.tcp：accept 后立即套上（mask 在协议嗅探之前——嗅探读到的是明文）
        let (stream, peer) = match listener.accept_masked().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "mixed accept failed");
                accept_fd_backoff(&e).await;
                continue;
            },
        };
        let mut stream = PeekAhead::new(stream);
        let handler = Arc::clone(&handler);
        let socks_cfg = Arc::clone(&socks_cfg);
        let http_cfg = Arc::clone(&http_cfg);
        // scope 生命周期锚（裸 spawn detach 语义等价）；克隆体供 UDP 分支嵌套 spawn
        let task_ctx = Arc::clone(&plugin_ctx);
        plugin_ctx
            .spawn(async move {
                let ctx = task_ctx;
                // 1 字节 sniff(带超时避免恶意 client 占资源)
                let mut sniff = [0u8; 1];
                let read_res = match handshake_timeout {
                    Some(d) => tokio::time::timeout(d, stream.peek(&mut sniff)).await,
                    None => Ok(stream.peek(&mut sniff).await),
                };
                let n = match read_res {
                    Ok(Ok(n)) => n,
                    _ => return,
                };
                if n == 0 {
                    return;
                }
                if sniff[0] == 0x05 || sniff[0] == 0x04 {
                    // SOCKS 路径（0x05 = SOCKS5 / 0x04 = SOCKS4；握手与 sniff/http
                    // 段共用同一限时）。版本分派在库层 `socks_handshake` 内按首字节
                    // 完成（Go `handshake4`/`handshake5` 同款），此处只做入口分流。
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
                            // bd 2b1c：access 带 from（process/source 规则 + access log 来源）
                            let access = http_inbound_access(&stream, peer);
                            // 拆流按连接类型分发（裸 TCP → readv 聚合读；mask 生效 →
                            // 顺序读，见 InboundConnMeta）
                            let (reader, writer) = stream.into_link_io();
                            let link = Link::new(reader, writer);
                            if is_mux_destination(&dest) {
                                // W4 面 6：carrier 归 arm scope（与 inbound 同寿命）。
                                ctx.spawn(handle_mux_inbound_link(link, handler, None))
                                    .expect("arm FxScope is never closed");
                            } else {
                                let _ = handler.dispatch_with_access(&dest, link, access).await;
                            }
                        },
                        Ok(SocksRequest::UdpAssociate(_, relay_socket)) => {
                            // UDP relay：spawn pump + 保持 TCP 控制连接（对齐独立 socks
                            // inbound 的 handle_connection UDP 分支与 Go server.go UDP
                            // 语义——此前丢弃 relay socket = 假成功，bd csya）
                            let udp_handler = Arc::clone(&handler);
                            // 来源过滤（bd wq16g）：只接受客户端地址，其余来源丢弃
                            let temp_udp = temp_udp_relay(relay_socket, peer);
                            let relay = ctx
                                .spawn(async move {
                                    let _ =
                                        handle_udp_associate(temp_udp, udp_handler, udp_idle).await;
                                })
                                .expect("arm FxScope is never closed");
                            // 控制连接 EOF/错误（客户端关闭）即终止 relay
                            let mut drop_buf = [0u8; 64];
                            let _ = stream.read(&mut drop_buf).await;
                            relay.abort();
                        },
                        Err(e) => tracing::debug!(error = %e, "mixed socks handshake failed"),
                    }
                } else if sniff[0].is_ascii_alphabetic() {
                    // HTTP 路径(简化版:仅 CONNECT + plain,无 mux 派生)
                    // keep-alive 回环（对齐 serve_http）：首包已 peek 判定为 HTTP，
                    // 第二轮起直接读下一请求头，不再 sniff；CONNECT 升级即终结循环。
                    loop {
                        let handshake_fut = http_server_handshake(&mut stream, &http_cfg);
                        let hs = match handshake_timeout {
                            Some(d) => match tokio::time::timeout(d, handshake_fut).await {
                                Ok(r) => r,
                                // 超时/失败收尾先排空（Windows 防 RST 丢已写响应）
                                Err(_) => {
                                    http_graceful_close(&mut stream).await;
                                    return;
                                },
                            },
                            None => handshake_fut.await,
                        };
                        let hs = match hs {
                            Ok(v) => v,
                            Err(_) => {
                                http_graceful_close(&mut stream).await;
                                return;
                            },
                        };
                        // bd 2b1c：access 带 from（process/source 规则 + access log 来源）
                        let access = http_inbound_access(&stream, peer);
                        if hs.method != "CONNECT" {
                            // P1-1：此分支此前只处理一个请求就断连，与响应头写出的
                            // keep-alive 承诺矛盾；plain 处置语义与 serve_http 同款。
                            match handle_plain_http(&mut stream, &hs, Arc::clone(&handler), access)
                                .await
                            {
                                PlainOutcome::NextRequest => continue,
                                PlainOutcome::Close => {
                                    http_graceful_close(&mut stream).await;
                                    return;
                                },
                            }
                        }
                        let dest = hs.dest;
                        let (reader, writer) = stream.into_link_io();
                        let link = Link::new(reader, writer);
                        if is_mux_destination(&dest) {
                            // W4 面 6：carrier 归 arm scope（与 inbound 同寿命）。
                            ctx.spawn(handle_mux_inbound_link(link, handler, None))
                                .expect("arm FxScope is never closed");
                        } else {
                            let _ = handler.dispatch_with_access(&dest, link, access).await;
                        }
                        return;
                    }
                } else {
                    tracing::debug!(first_byte = sniff[0], "mixed: unknown first byte, closing");
                }
            })
            .expect("arm FxScope is never closed");
    }
}

/// HTTP proxy inbound 服务入口。
///
/// 接受连接 → http_server_handshake → CONNECT 隧道 dispatch 或 plain HTTP 代理转发。
/// plain HTTP 按响应可定界性与客户端 close 语义回循环读下一请求（keep-alive
/// 复用，Go `Start` 循环）；CONNECT 隧道仍一次即终结。`handshake_timeout` 对应
/// Go `proxy/http/server.go:112`
/// `conn.SetReadDeadline(policy().Timeouts.Handshake)`（policy 来自
/// `ForLevel(UserLevel)`，见 spawn_one_inbound http 分支）；None 时不限时。
pub async fn serve_http(
    listener: InboundTcpListener,
    ohm: Arc<SimpleOhm>,
    config: Arc<HttpServerConfig>,
    handshake_timeout: Option<std::time::Duration>,
    plugin_ctx: Arc<PluginContext>,
) -> std::io::Result<()> {
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;
    tracing::info!(addr = %listener.local_addr()?, "http proxy inbound listening");
    loop {
        // finalmask.tcp：accept 后立即套上（mask 在 HTTP 握手之前）
        let (mut stream, peer) = match listener.accept_masked().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "http accept failed");
                accept_fd_backoff(&e).await;
                continue;
            },
        };
        let handler = Arc::clone(&handler);
        let config = Arc::clone(&config);
        // scope 生命周期锚（裸 spawn detach 语义等价）
        let task_ctx = Arc::clone(&plugin_ctx);
        plugin_ctx
            .spawn(async move {
                let ctx = task_ctx;
                // Go Process 的 Start 循环：keep-alive 连接逐请求回环读请求头。
                loop {
                    // 1. handshake（按 userLevel 对应 policy 的 handshake 超时限制，
                    // 超时即断开——对应 Go SetReadDeadline 到期后 ReadRequest 超时错误；
                    // Go 每轮回到 Start 重设 deadline，这里每轮请求头读取都限时）
                    let handshake_fut = http_server_handshake(&mut stream, &config);
                    let hs = match handshake_timeout {
                        Some(d) => match tokio::time::timeout(d, handshake_fut).await {
                            Ok(r) => r,
                            Err(_) => {
                                tracing::debug!("http handshake timeout, closing connection");
                                http_graceful_close(&mut stream).await;
                                return;
                            },
                        },
                        None => handshake_fut.await,
                    };
                    let hs = match hs {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::debug!(error = %e, "http handshake failed");
                            http_graceful_close(&mut stream).await;
                            return;
                        },
                    };
                    // 2. Plain HTTP proxy（GET/POST 等）
                    // bd 2b1c：access 必须带 from（process/source 规则 + access log 来源）
                    let access = http_inbound_access(&stream, peer);
                    if hs.method != "CONNECT" {
                        // ft58 S1 keep-alive：成功转发后不关连接，按响应可定界性与客户端
                        // close 语义回循环读下一请求（Go server.go Start + errWaitAnother；
                        // 连接语义为 HTTP/1.1 默认 keep-alive，客户端 close token 收尾关闭）。
                        // 本改动将由 xray-frame HTTP 插件化继承，届时按插件形态调整。
                        match handle_plain_http(&mut stream, &hs, Arc::clone(&handler), access)
                            .await
                        {
                            PlainOutcome::NextRequest => continue,
                            PlainOutcome::Close => {
                                http_graceful_close(&mut stream).await;
                                return;
                            },
                        }
                    }
                    // 3. CONNECT：拆 stream → Link → dispatch（隧道内不再是 HTTP 请求
                    // 边界，隧道结束即关连接，不回循环——对齐 Go handleConnect return）
                    let dest = hs.dest;
                    let (reader, writer) = stream.into_link_io();
                    let link = Link::new(reader, writer);
                    // zx7: mux.cool dest 转给 mux ServerWorker（stub）
                    if is_mux_destination(&dest) {
                        tracing::info!(
                            "http: mux.cool destination detected, spawning mux inbound handler"
                        );
                        // W4 面 6：carrier 归 arm scope（与 inbound 同寿命）。
                        ctx.spawn(handle_mux_inbound_link(link, handler, None))
                            .expect("arm FxScope is never closed");
                        return;
                    }
                    let _ = handler.dispatch_with_access(&dest, link, access).await;
                    return;
                }
            })
            .expect("arm FxScope is never closed");
    }
}

/// HTTP/mixed inbound 连接元数据 → AccessContext。
///
/// bd 2b1c：此前 HTTP 路径 dispatch 不带 access，from 为空 → process/source
/// 规则永不命中、access log 缺来源。socks 分支同款见 handle_connection。
fn http_inbound_access<S: InboundConnMeta>(
    stream: &S,
    peer: std::net::SocketAddr,
) -> xray_app_dispatcher::AccessContext {
    let conn = stream.splice_raw_clone().map(Arc::new);
    xray_app_dispatcher::AccessContext {
        from: peer.to_string(),
        local: stream.inbound_local().map(|a| a.to_string()).unwrap_or_default(),
        conn,
        // mask 生效时 wire 已非明文（raw fd 克隆绕过解伪装链）→ 不可 splice
        can_splice_copy: if stream.is_raw_inbound() {
            xray_common::platform::splice::CAN_SPLICE_COPY_YES
        } else {
            xray_common::platform::splice::CAN_SPLICE_COPY_NEVER
        },
        ..Default::default()
    }
}

/// plain HTTP keep-alive 连接处置（对应 Go `handlePlainHTTP` 返回值语义）。
enum PlainOutcome {
    /// 响应已完整回写且可定界、客户端未要求关闭 → 回循环读下一请求
    /// （Go `errWaitAnother` + `goto Start`）。
    NextRequest,
    /// 断链退出（协议错误/客户端断开/响应不可定界/close token）。
    Close,
}

/// 请求体形态（下一请求字节不得被吞——吞多吞少都流水线错位）。
enum RequestBodyPlan {
    None,
    Length(u64),
    Chunked,
}

/// 请求定界形态 + 转发用 headers（对齐 Go `fixLength`/`parseTransferEncoding`
/// 的请求走私加固）：
/// - 多值 Content-Length 值不一致 / 非纯十进制 / 超 `i64::MAX` → Err（Go `ReadRequest` 报错 →
///   断链）；
/// - 值相同的重复 CL → 折叠为一条转发（Go dedupe，issue 16490）；
/// - chunked 生效 → 转发前删除 CL（RFC 9112 §6.3 中间件义务，即 Go `fixLength` 里的
///   `header.Del("Content-Length")`），防 CL.TE 走私。
fn plan_request_framing(
    headers: &HashMap<String, Vec<String>>,
) -> Result<(RequestBodyPlan, HashMap<String, Vec<String>>), ()> {
    let chunked = transfer_encoding_chunked(headers)?;
    let content_length = framed_content_length(headers)?;
    let mut forward = headers.clone();
    if chunked {
        forward.remove("content-length");
        return Ok((RequestBodyPlan::Chunked, forward));
    }
    let Some(length) = content_length else { return Ok((RequestBodyPlan::None, forward)) };
    if let Some(values) = forward.get_mut("content-length") {
        // 值一致性已由 framed_content_length 校验 → 折叠为一条
        values.truncate(1);
    }
    Ok((RequestBodyPlan::Length(length), forward))
}

/// Transfer-Encoding 是否为 chunked（对齐 Go `parseTransferEncoding`）：只接受
/// 单个头值且 trim 后等于 `chunked`；多值 / 多编码栈（`gzip, chunked`）/ 未知
/// 编码 → Err（Go 在该走私敏感面保持严格，报 `unsupportedTEError` 断链）。
fn transfer_encoding_chunked(headers: &HashMap<String, Vec<String>>) -> Result<bool, ()> {
    match headers.get("transfer-encoding") {
        None => Ok(false),
        Some(values) => match values.as_slice() {
            [value] if value.trim().eq_ignore_ascii_case("chunked") => Ok(true),
            _ => Err(()),
        },
    }
}

/// Content-Length 语义值（请求/响应共用）。对齐 Go `parseContentLength`：纯十进制、
/// 无符号、≤ `i64::MAX`（Go `ParseUint(…, 63)`）；多个头值必须一致（RFC 7230
/// §3.3.2 走私加固，不一致即拒）。缺失 → `Ok(None)`。
fn framed_content_length(headers: &HashMap<String, Vec<String>>) -> Result<Option<u64>, ()> {
    let Some(values) = headers.get("content-length") else { return Ok(None) };
    let mut length: Option<u64> = None;
    for value in values {
        let parsed = parse_content_length_value(value)?;
        if length.is_some_and(|prev| prev != parsed) {
            return Err(());
        }
        length = Some(parsed);
    }
    Ok(length)
}

/// 单个 Content-Length 值。Go `strconv.ParseUint(value, 10, 63)` 等价：空串 /
/// 带符号 / 非数字 / 超 `i64::MAX` 全拒（`str::parse::<u64>` 恰好接受 `+5`，
/// 故先逐字节校验数字）。
fn parse_content_length_value(value: &str) -> Result<u64, ()> {
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    match value.parse::<u64>() {
        Ok(n) if n <= i64::MAX as u64 => Ok(n),
        _ => Err(()),
    }
}

/// plain HTTP 读上游响应失败/响应头非法的 503（对齐 Go handlePlainHTTP 503 分支：
/// Close=true + 双 close 头 + Content-Length 0；字节与 xray-proxy-http server.rs
/// 同名常量一致）。
const RESPONSE_SERVICE_UNAVAILABLE: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
    Connection: close\r\n\
    Proxy-Connection: close\r\n\
    Content-Length: 0\r\n\r\n";

/// 上游响应头解析结果。
struct ResponseHead {
    /// 原始状态行（回写时原样保留）。
    status_line: String,
    code: u16,
    /// headers（key 全小写，同名多值保留）。
    headers: HashMap<String, Vec<String>>,
    /// 头块之后已到达的 body 前缀（pipe 按块到达，头后多余字节不可丢弃）。
    leftover: Vec<u8>,
}

const MAX_RESPONSE_HEAD_BYTES: usize = 64 * 1024;

/// 处理 plain HTTP 代理请求（GET/POST 等），keep-alive 语义。
///
/// 对应 Go `proxy/http/server.go::handlePlainHTTP`。每请求经 dispatch 拨一条新
/// 上游链路（Go `Dispatch` per request），转发头强制 `connection: close`（上游
/// 响应完即关）。请求体按 Content-Length / chunked 边界精确转发（多余字节属
/// 下一请求）；响应按可定界性回写连接语义头：Content-Length 定界或无 body
/// （HEAD/204/304）→ 可续连（Go `response.ContentLength >= 0` 分支）；chunked /
/// close 定界 → close 头断链（Go `response.Close = true`）。返回是否回循环。
async fn handle_plain_http<S>(
    client: &mut S,
    hs: &HandshakeResult,
    handler: Arc<dyn DispatchHandler>,
    access: xray_app_dispatcher::AccessContext,
) -> PlainOutcome
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    use xray_buf::io::{Reader as BufReader, Writer as BufWriter};

    // 1. 转发请求构建（绝对 URL → 相对 path，移除 hop-by-hop headers，强制 close）
    let (body_plan, mut forward_headers) = match plan_request_framing(&hs.headers) {
        Ok(plan) => plan,
        Err(()) => {
            tracing::debug!("http: malformed Content-Length/Transfer-Encoding, closing connection");
            return PlainOutcome::Close;
        },
    };
    let path = extract_request_path(&hs.target);
    // Go `handlePlainHTTP`：`request.Host = request.URL.Host`（绝对 URI 的 host
    // 优先，origin-form 时即 Host 头）→ 转发请求的 Host 头用同一个值。
    if let Some(host) = resolve_request_host(&hs.target, &forward_headers) {
        forward_headers.insert("host".into(), vec![host]);
    }
    let request_head = build_forwarded_request(&hs.method, &path, &forward_headers);

    // 2. 创建 pipe 对，dispatch：生产 DefaultDispatcher::dispatch_link 内部 spawn
    //    后台任务后立即返回（link 由后台持有）；no-handler/后台 dial 失败表现为 下行零字节结束 →
    //    下方统一回 503 兜底。
    let (up_r, mut up_w) = xray_buf::pipe::new();
    let (mut dn_r, dn_w) = xray_buf::pipe::new();
    let link =
        Link::new(Box::new(up_r) as Box<dyn BufReader>, Box::new(dn_w) as Box<dyn BufWriter>);
    let dest = hs.dest.clone();
    handler.dispatch_with_access(&dest, link, access).await;

    let (mut client_read, mut client_write) = tokio::io::split(client);

    // 3. requestDone：头 + 请求体边界精确转发
    if let Err(e) =
        forward_request_phase(&mut client_read, &mut up_w, &request_head, body_plan).await
    {
        // 错误路径也要关上游写向（pipe Writer 裸 drop 不传播 EOF 到 dispatch 桥）。
        up_w.shutdown();
        return match e {
            // 客户端侧读失败（body 长度不符 / 客户端断开）→ Go `http.ReadRequest`
            // 失败语义：断链不回响应。
            RequestForwardError::Client(err) => {
                tracing::debug!(error = %err, "http: client request read failed, closing connection");
                PlainOutcome::Close
            },
            // 上游侧写失败（上游已断开 / 拨号失败）→ Go `responseDone` 失败语义：
            // 回 503（Go 的请求写进缓冲区成功，失败发生在读响应阶段）。
            RequestForwardError::Upstream(err) => {
                tracing::debug!(error = %err, "http: upstream write failed, replying 503");
                let _ = client_write.write_all(RESPONSE_SERVICE_UNAVAILABLE).await;
                PlainOutcome::Close
            },
        };
    }

    // 4. responseDone —— 上游写侧的半关**推迟到响应阶段结束之后**（Go `handlePlainHTTP` 写完
    //    request 不半关；`defer common.Close(link.Writer)` 在响应读完后才关）。请求发完立刻
    //    `shutdown(SHUT_WR)` 会让不少 CDN 判 "请求未完成"直接关连接不回响应（bd os438：微信图床
    //    503）。
    let outcome = relay_response_phase(&mut dn_r, &mut client_write, hs).await;
    up_w.shutdown();
    outcome
}

/// 请求转发阶段的失败来源（决定回 503 还是断链）。
#[derive(Debug)]
enum RequestForwardError {
    /// 客户端侧读失败（请求体长度不符 / 客户端中途断开）。
    Client(std::io::Error),
    /// 上游侧写失败（上游已关闭 / 拨号失败）。
    Upstream(std::io::Error),
}

/// 上行阶段：转发请求头 + 请求体（CL 定长 / chunked 逐帧，到边界即止）。
/// 客户端中途断开/帧错位 → [`RequestForwardError::Client`]；上游写失败 →
/// [`RequestForwardError::Upstream`]（两者处置不同：断链 vs 503）。
async fn forward_request_phase<R>(
    client_read: &mut R,
    up_w: &mut xray_buf::pipe::Writer,
    request_head: &[u8],
    body_plan: RequestBodyPlan,
) -> Result<(), RequestForwardError>
where
    R: AsyncRead + Unpin,
{
    pipe_write_all(up_w, request_head).await.map_err(RequestForwardError::Upstream)?;
    match body_plan {
        RequestBodyPlan::None => {},
        RequestBodyPlan::Length(n) => relay_exact_request_body(client_read, up_w, n).await?,
        RequestBodyPlan::Chunked => relay_chunked_request_body(client_read, up_w).await?,
    }
    Ok(())
}

/// 下行阶段：读响应头（1xx 透传 / 101 切协议）→ 按可定界性与客户端 close 语义
/// 回写头 + 精确透传 body。零字节断流 / 头非法 / CL·TE 非法 → 503 兜底
/// （Go responseDone err 分支）。
async fn relay_response_phase<W>(
    dn_r: &mut xray_buf::pipe::Reader,
    client_write: &mut W,
    hs: &HandshakeResult,
) -> PlainOutcome
where
    W: AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let Some(head) = read_response_head(dn_r, client_write).await else {
        // Go `responseDone` err 分支：读响应失败（上游拨号失败/断流/头非法）→ 503。
        tracing::debug!(target = %hs.target, "http: no usable upstream response, replying 503");
        let _ = client_write.write_all(RESPONSE_SERVICE_UNAVAILABLE).await;
        return PlainOutcome::Close;
    };

    // 101 Switching Protocols：协议已切换，头块原样交客户端（Upgrade /
    // Connection: Upgrade 是切换的必需语义，RFC 7230 §6.7，不得当 hop-by-hop
    // 剥掉），随后是裸隧道字节流直至任一端断开（无 HTTP 定界语义）。
    if head.code == 101 {
        if client_write.write_all(&serialize_raw_response_head(&head)).await.is_err() {
            return PlainOutcome::Close;
        }
        let _ = copy_until_eof_from_pipe(dn_r, client_write, head.leftover).await;
        return PlainOutcome::Close;
    }

    let (content_length, chunked) =
        match (framed_content_length(&head.headers), transfer_encoding_chunked(&head.headers)) {
            (Ok(content_length), Ok(chunked)) => (content_length, chunked),
            // 与请求侧同款走私加固：多值 CL 不一致 / 非法值 / 未知 TE → 503
            _ => {
                let _ = client_write.write_all(RESPONSE_SERVICE_UNAVAILABLE).await;
                return PlainOutcome::Close;
            },
        };

    // 可定界 = CL 合法声明（含 leftover 不超长——上游超额多发即协议违规不可续）
    // 或无 body（HEAD/204/304）；chunked / close 定界不可续
    let bodyless = hs.method == "HEAD" || head.code == 204 || head.code == 304;
    let cl_ok = content_length.is_none_or(|n| head.leftover.len() as u64 <= n);
    let reusable = !chunked && cl_ok && (bodyless || content_length.is_some());
    // Go `response.ContentLength`（readTransfer/fixLength 语义）：chunked → -1；
    // HEAD → 声明的 CL（无则 0）；204/304 → 0；其余 → 声明的 CL（无则 -1）。
    // `>= 0` ⇔ Go 回 keep-alive 三头且 `response.Close = false`。
    let effective_cl: Option<u64> = if chunked {
        None
    } else if bodyless {
        Some(if hs.method == "HEAD" { content_length.unwrap_or(0) } else { 0 })
    } else {
        content_length
    };
    // 响应头的连接语义只看**响应自身**（Go `response.ContentLength >= 0` →
    // keep-alive 三头），与请求的 Connection 头无关。
    let response_keep_alive = reusable;
    // 客户端连接复用（Go `Process`）：只要请求带 `Proxy-Connection: keep-alive`
    // 且响应可定界（Go `result == errWaitAnother`）就回循环读下一请求
    // ——Go 实测：同时带 `Connection: close` 也照样复用（Go 只看 Proxy-Connection）。
    let reuse_connection = response_keep_alive && request_keep_alive(&hs.headers);
    let head_bytes = serialize_go_response_head(
        &head.status_line,
        head.code,
        &head.headers,
        effective_cl,
        chunked,
    );
    if client_write.write_all(&head_bytes).await.is_err() {
        return PlainOutcome::Close;
    }

    let body_ok = if bodyless {
        true
    } else if let (false, Some(n)) = (chunked, content_length) {
        // CL 定界：精确转发 n 字节（Go `response.Body` = LimitReader(r, n)）
        copy_exact_n_from_pipe(dn_r, client_write, n, head.leftover).await.is_ok()
    } else {
        // chunked / close 定界：转发头已带 connection: close，上游回完即关，
        // 透传到断流为止（chunked 帧原样到达，客户端按 transfer-encoding 解析）
        copy_until_eof_from_pipe(dn_r, client_write, head.leftover).await.is_ok()
    };
    if body_ok && reuse_connection { PlainOutcome::NextRequest } else { PlainOutcome::Close }
}

/// 从客户端定长转发 n 字节请求体到上游 pipe。提前 EOF → Err（静默截断不可接受）。
async fn relay_exact_request_body<R>(
    client_read: &mut R,
    up_w: &mut xray_buf::pipe::Writer,
    mut remaining: u64,
) -> Result<(), RequestForwardError>
where
    R: AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 8192];
    while remaining > 0 {
        let want = buf.len().min(remaining as usize);
        let read = client_read.read(&mut buf[..want]).await.map_err(RequestForwardError::Client)?;
        if read == 0 {
            return Err(RequestForwardError::Client(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "client closed mid request body",
            )));
        }
        pipe_write_all(up_w, &buf[..read]).await.map_err(RequestForwardError::Upstream)?;
        remaining -= read as u64;
    }
    Ok(())
}

/// chunked 请求体逐帧转发（帧字节原样透传，不解码重编码——转发头保留
/// transfer-encoding，与 Go ReadRequest 解码 + request.Write 重编码线路上等价）。
/// 到终止块为止，不多读一字节：多余字节属流水线上的下一请求。
async fn relay_chunked_request_body<R>(
    client_read: &mut R,
    up_w: &mut xray_buf::pipe::Writer,
) -> Result<(), RequestForwardError>
where
    R: AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    loop {
        let size_line = read_client_line(client_read).await.map_err(RequestForwardError::Client)?;
        let size = u64::from_str_radix(size_line.split(';').next().unwrap_or_default().trim(), 16)
            .map_err(|_| {
                RequestForwardError::Client(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "malformed chunk size",
                ))
            })?;
        pipe_write_all(up_w, size_line.as_bytes()).await.map_err(RequestForwardError::Upstream)?;
        pipe_write_all(up_w, b"\r\n").await.map_err(RequestForwardError::Upstream)?;
        if size == 0 {
            // trailer 段透传到空行
            loop {
                let line =
                    read_client_line(client_read).await.map_err(RequestForwardError::Client)?;
                pipe_write_all(up_w, line.as_bytes())
                    .await
                    .map_err(RequestForwardError::Upstream)?;
                pipe_write_all(up_w, b"\r\n").await.map_err(RequestForwardError::Upstream)?;
                if line.is_empty() {
                    return Ok(());
                }
            }
        }
        relay_exact_request_body(client_read, up_w, size).await?;
        let mut crlf = [0u8; 2];
        client_read.read_exact(&mut crlf).await.map_err(RequestForwardError::Client)?;
        pipe_write_all(up_w, &crlf).await.map_err(RequestForwardError::Upstream)?;
    }
}

/// 读一行（到 CRLF，不含 CRLF）。请求体阶段 EOF 一律错误（半途断开 = 协议失败）。
async fn read_client_line<R>(client_read: &mut R) -> std::io::Result<String>
where
    R: AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    const MAX_LINE_BYTES: usize = 16 * 1024;
    let mut buf: Vec<u8> = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        if client_read.read(&mut byte).await? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "client closed mid request body",
            ));
        }
        if byte[0] == b'\n' {
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
            return Ok(String::from_utf8_lossy(&buf).into_owned());
        }
        if buf.len() >= MAX_LINE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "chunk size line too long",
            ));
        }
        buf.push(byte[0]);
    }
}

/// pipe 写入小片段（头行/CRLF 等）。
async fn pipe_write_all(up_w: &mut xray_buf::pipe::Writer, data: &[u8]) -> std::io::Result<()> {
    let mut mb = xray_buf::multi::MultiBuffer::new();
    mb.merge_bytes(data);
    up_w.write_multi_buffer(mb)
        .await
        .map_err(|_| std::io::Error::other("upstream pipe write failed"))
}

/// 解析头块（不含结尾空行）为 (状态行, 状态码, headers)。状态行非法 / 存在无
/// 冒号的头行 → None（对齐 Go `textproto` 严格语义：坏头行整条响应作废走 503，
/// 静默跳过会让 `Transfer-Encoding : chunked` 这类畸形行被忽略而按 CL 定界）。
fn parse_head_block(block: &[u8]) -> Option<(String, u16, HashMap<String, Vec<String>>)> {
    let text = String::from_utf8_lossy(block);
    let mut lines = text.split("\r\n");
    let status_line = lines.next()?.to_string();
    let code = status_line.split_whitespace().nth(1)?.parse::<u16>().ok()?;
    let mut headers: HashMap<String, Vec<String>> = HashMap::new();
    for line in lines {
        let (k, v) = line.split_once(':')?;
        headers.entry(k.trim().to_ascii_lowercase()).or_default().push(v.trim().to_string());
    }
    Some((status_line, code, headers))
}

/// 从下行 pipe 读响应头（字节精确，头后多余字节随 leftover 返回）。
/// 1xx 中间响应头块原样透传给客户端后继续读最终响应（对齐 Go
/// `readResponseAndHandle100Continue`）。零字节断流/头块超限/中途断流/状态行
/// 非法 → None（调用方 503 兜底）。
async fn read_response_head<W>(
    dn_r: &mut xray_buf::pipe::Reader,
    client_write: &mut W,
) -> Option<ResponseHead>
where
    W: AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let mut acc: Vec<u8> = Vec::with_capacity(1024);
    loop {
        if let Some(head_end) = acc.windows(4).position(|w| w == b"\r\n\r\n") {
            let (status_line, code, headers) = parse_head_block(&acc[..head_end])?;
            if (100..200).contains(&code) && code != 101 {
                // 1xx 中间响应（100-continue/102/103）：原样透传头块，继续读最终响应。
                // 101 是终态协议切换响应，不是中间响应——走上层裸隧道分支。
                client_write.write_all(&acc[..head_end + 4]).await.ok()?;
                acc.drain(..head_end + 4);
                continue;
            }
            let leftover = acc[head_end + 4..].to_vec();
            return Some(ResponseHead { status_line, code, headers, leftover });
        }
        if acc.len() > MAX_RESPONSE_HEAD_BYTES {
            return None;
        }
        match dn_r.read_multi_buffer().await {
            Ok(mb) if !mb.is_empty() => {
                for b in mb.iter() {
                    acc.extend_from_slice(b.bytes());
                }
            },
            _ => return None, // 零字节断流 / pipe 中断
        }
    }
}

/// 101 头块原样回写（不过滤 hop-by-hop、不改连接语义头）：`Upgrade` 与
/// `Connection: Upgrade` 本身是协议切换的必要载荷（RFC 7230 §6.7），
/// 剥掉后客户端无法完成升级。
fn serialize_raw_response_head(head: &ResponseHead) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(head.status_line.as_bytes());
    buf.extend_from_slice(b"\r\n");
    for (key, values) in &head.headers {
        for value in values {
            buf.extend_from_slice(key.as_bytes());
            buf.extend_from_slice(b": ");
            buf.extend_from_slice(value.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }
    }
    buf.extend_from_slice(b"\r\n");
    buf
}

/// 定长透传响应 body：先写头块捎带的 leftover 前缀，再从 pipe 读满剩余。
/// 上游提前断流 → Err（静默截断不可接受）。
async fn copy_exact_n_from_pipe<W>(
    dn_r: &mut xray_buf::pipe::Reader,
    client_write: &mut W,
    n: u64,
    leftover: Vec<u8>,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let mut remaining = n;
    let take = leftover.len().min(remaining as usize);
    client_write.write_all(&leftover[..take]).await?;
    remaining -= take as u64;
    while remaining > 0 {
        match dn_r.read_multi_buffer().await {
            Ok(mb) if !mb.is_empty() => {
                for b in mb.iter() {
                    let bytes = b.bytes();
                    let take = bytes.len().min(remaining as usize);
                    client_write.write_all(&bytes[..take]).await?;
                    remaining -= take as u64;
                    if remaining == 0 {
                        break;
                    }
                }
            },
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "upstream closed mid response body",
                ));
            },
        }
    }
    Ok(())
}

/// close/chunked 定界响应透传：leftover 前缀 + 读到断流为止
/// （转发头已带 connection: close，上游回完即关，EOF 即响应终点）。
async fn copy_until_eof_from_pipe<W>(
    dn_r: &mut xray_buf::pipe::Reader,
    client_write: &mut W,
    leftover: Vec<u8>,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    if !leftover.is_empty() {
        client_write.write_all(&leftover).await?;
    }
    while let Ok(mb) = dn_r.read_multi_buffer().await {
        if mb.is_empty() {
            break;
        }
        let mut data = Vec::new();
        for b in mb.iter() {
            data.extend_from_slice(b.bytes());
        }
        if client_write.write_all(&data).await.is_err() {
            break;
        }
    }
    Ok(())
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
/// 2. TLS 握手 SNI 覆盖 address（port 保持 rewrite 值，缺省 0；Go dokodemo.go:122-132， 仅在未被
///    original_dst 覆盖时）
///
/// 两者皆缺 → `None`：调用方拒连（对齐 Go dokodemo.go:137
/// `unable to get destination`）。FollowRedirect 分支**不回落 predefined
/// dest**——transparent 场景 predefined 拿不到原始目标时静默转发固定地址，
/// 排障方向被误导。
///
/// `follow_redirect=false`：predefined dest 回填（address 缺省 → 本机回环、
/// port 缺省 → 本地端口，Go dokodemo.go:86-100）+ `port_map`（:101-109）。
/// 返回 `None` = 无有效目标（仅 follow_redirect 且 original/SNI 皆缺时）。
fn resolve_dokodemo_tcp_dest(
    opts: &DokodemoTcpOptions,
    local_ip: Option<std::net::IpAddr>,
    local_port: Option<u16>,
    original_dst: Option<SocketAddr>,
    tls_sni: Option<&str>,
) -> Option<Destination> {
    if opts.follow_redirect {
        if let Some(orig) = original_dst {
            return Some(Destination::tcp(socketaddr_to_address(orig), Port::new(orig.port())));
        }
        // SNI 覆盖 address；port 基底 = rewrite port（Go：dest.Port 初值不变）。
        if let Some(sni) = tls_sni.filter(|s| !s.is_empty()) {
            let port = opts.dest.as_ref().map_or(0, |d| d.port().value());
            return Some(Destination::tcp(Address::Domain(sni.to_string()), Port::new(port)));
        }
        // 拿不到原始目标 → 拒连（Go dokodemo.go:137 unable to get destination）。
        return None;
    }
    // follow_redirect=false：rewrite 缺省回填（Go dokodemo.go:86-100）：
    // address → 本机回环（依监听地址族选 v4/v6），port → 本地监听端口。
    let mut dest = opts
        .dest
        .clone()
        .unwrap_or_else(|| Destination::tcp(loopback_addr(local_ip), Port::new(0)));
    if dest.port().value() == 0 {
        if let Some(lp) = local_port {
            dest = Destination::tcp(dest.address().clone(), Port::new(lp));
        }
    }
    // port_map：值 "host:port"，host/port 均可空（Go dokodemo.go:101-109，
    // SplitHostPort 错误已在 parse 阶段校验，此处容错跳过）。
    if let Some(lp) = local_port {
        if let Some(mapping) = opts.port_map.get(&lp.to_string()) {
            if let Some((host, port_str)) = mapping.rsplit_once(':') {
                if !port_str.is_empty() {
                    if let Ok(p) = port_str.parse::<u16>() {
                        dest = Destination::tcp(dest.address().clone(), Port::new(p));
                    }
                }
                let host = host.trim_start_matches('[').trim_end_matches(']');
                if !host.is_empty() {
                    dest = Destination::tcp(parse_address_str(host), dest.port());
                }
            }
        }
    }
    Some(dest)
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
    plugin_ctx: Arc<PluginContext>,
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
    // mask 生效时 conn 的 local_addr 随 TcpStream 进了 dyn 包装，拿不到：
    // 回退 listener 自身地址（wildcard bind 时略异于 conn 实际地址，够 port_map/
    // followRedirect 判定用）。
    // shortcut: masked + wildcard bind 的 local_addr 精度，等 MaybeTcpMaskConn 暴露
    // 地址再补。
    let listener_local = listener.local_addr().ok();
    loop {
        // finalmask.tcp：accept 后立即套上（mask 在 TLS 握手之前）
        let (stream, _peer) = match listener.accept_masked().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "dokodemo accept failed");
                accept_fd_backoff(&e).await;
                continue;
            },
        };
        let handler = Arc::clone(&handler);
        let opts = opts.clone();
        // scope 生命周期锚（裸 spawn detach 语义等价）
        let task_ctx = Arc::clone(&plugin_ctx);
        plugin_ctx
            .spawn(async move {
                let _ctx = task_ctx;
                let conn_local =
                    stream.plain().and_then(|c| c.local_addr().ok()).or(listener_local);
            let local_ip = conn_local.map(|a| a.ip());
            let local_port = conn_local.map(|a| a.port());

            // follow_redirect：Linux 下从 accept 的 fd 查 SO_ORIGINAL_DST。
            // Go 由 TPROXY listener 在 transport 层写入 session ctx（Go dokodemo.go
            // L113-121），普通 listener 不查——无 ctx 即拒连。Rust 直连 socket 上
            // getsockopt 在内核 conntrack 跟踪回环/直连流量时"成功"返回 current dst
            // == 本端地址（未 NAT ⇒ original == current），恰为 listener 端口，
            // 会把普通连接误判成透明代理流量（CI ubuntu 首跑实证：dispatch 到
            // 127.0.0.1:<ephemeral>）。过滤 original == 本端地址：与 Go 普通
            // listener 无 OriginalDest 的可观测行为等价；真实 REDIRECT 的
            // original ≠ 本端不受影响。
            #[cfg(target_os = "linux")]
            let original_dst = if opts.follow_redirect {
                use std::os::fd::AsRawFd;
                // mask 生效时 fd 藏在 dyn 包装内（Go 侧 mask conn 同样丢了
                // syscall.Conn）→ 拿不到原始目标，按无 OriginalDest 处理。
                stream
                    .plain()
                    .and_then(|c| xray_transport::sockopt::get_original_dst(c.as_raw_fd()).ok())
                    .filter(|orig| Some(*orig) != conn_local)
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
                        match resolve_dokodemo_tcp_dest(
                            &opts,
                            local_ip,
                            local_port,
                            original_dst,
                            sni,
                        ) {
                            Some(dest) => {
                                let (read_half, write_half) = tokio::io::split(tls_stream);
                                let link = Link::new(new_reader(read_half), new_writer(write_half));
                                let _ = handler.dispatch(&dest, link).await;
                            },
                            None => tracing::warn!(
                                "dokodemo: no valid destination (followRedirect without original dst/SNI), rejecting connection (Go dokodemo.go:137)"
                            ),
                        }
                    },
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "dokodemo TLS accept failed");
                    },
                    Err(_) => {
                        tracing::debug!("dokodemo TLS accept timeout");
                    },
                }
            } else {
                match resolve_dokodemo_tcp_dest(&opts, local_ip, local_port, original_dst, None) {
                    Some(dest) => {
                        // 拆流按连接类型分发（裸 TCP → readv 聚合读；mask 生效 → 顺序读）
                        let (reader, writer) = stream.into_link_io();
                        let link = Link::new(reader, writer);
                        let _ = handler.dispatch(&dest, link).await;
                    },
                    None => tracing::warn!(
                        "dokodemo: no valid destination (followRedirect without original dst/SNI), rejecting connection (Go dokodemo.go:137)"
                    ),
                }
            }
            })
            .expect("arm FxScope is never closed");
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
    // finalmask.udp（bd 05js，Go udp/hub.go:61-62 FinalMask.ListenPacket；None = 未配置）
    udpmask: Option<xray_transport::finalmask::UdpmaskManager>,
    plugin_ctx: Arc<PluginContext>,
) -> std::io::Result<()> {
    use xray_transport::udp::hub::ReceiveOriginalDestination;
    let hub = xray_transport::udp::hub::UdpHub::listen(
        bind_addr,
        &[Box::new(ReceiveOriginalDestination(follow_redirect))],
        udpmask,
    )
    .await?;
    serve_dokodemo_udp_on(hub, handler, dest, plugin_ctx).await
}

/// 已建 `UdpHub` 的 dokodemo UDP 服务循环（测试/组合入口）。
pub async fn serve_dokodemo_udp_on(
    hub: xray_transport::udp::hub::UdpHub,
    handler: Arc<dyn DispatchHandler>,
    dest: Option<Destination>,
    plugin_ctx: Arc<PluginContext>,
) -> std::io::Result<()> {
    let local = hub.local_addr().ok();
    let local_port = local.as_ref().map(|a| a.port());
    let mut dest = dest
        .unwrap_or_else(|| Destination::udp(loopback_addr(local.map(|a| a.ip())), Port::new(0)));
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
    // W4 面 3：取时统一走 Budget::tokio()（Tokio 源内部 = tokio Instant，pause 可推进不变）。
    let mut cleanup_at = Budget::tokio().deadline(DOKODEMO_UDP_IDLE);
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
                        let relay_handler = Arc::clone(&handler);
                        let relay_hub = Arc::clone(&hub);
                        let ctx_pin = Arc::clone(&plugin_ctx);
                        plugin_ctx
                            .spawn(async move {
                                // scope 生命周期锚：peer 会话任务存活期间 arm scope 不 drop
                                let _ctx = ctx_pin;
                                dokodemo_peer_relay(
                                    peer,
                                    rx,
                                    relay_handler,
                                    first_dest,
                                    relay_hub,
                                    overridden,
                                )
                                .await;
                            })
                            .expect("arm FxScope is never closed");
                        e.insert(PeerSession { tx, last_active: Budget::tokio() })
                    }
                };
                entry.last_active = Budget::tokio();
                if entry.tx.send((dest_override, pkt.payload)).await.is_err() {
                    tracing::debug!("dokodemo udp peer session closed; packet dropped");
                }
            }
            // 构造式（同上：本函数在 tests 里被非装箱 await）。
            _ = xray_frame::deadline::timeout(
                std::future::pending::<()>(),
                cleanup_at.remaining(),
            ) => {
                // 丢弃 idle / 已关会话：tx drop → peer task 退出 → link/fake socket 释放
                peers.retain(|_, p| {
                    !p.tx.is_closed() && p.last_active.elapsed() < DOKODEMO_UDP_IDLE
                });
                cleanup_at = Budget::tokio().deadline(DOKODEMO_UDP_IDLE);
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
    /// 最近活动锚（W4 面 3：Budget = tokio Instant 预算句柄，elapsed 语义同原）。
    last_active: Budget,
}

/// 单 peer UDP 会话任务：入站队列 → [`UdpDispatchSession`] → 响应回发本 peer。
///
/// 响应路径（对齐 Go dokodemo.go:158-176 PacketWriter）：
/// - 非 TPROXY：响应经监听 socket（hub）回发（Go `SequentialWriter{conn}`）。
/// - TPROXY（Linux）：响应源为 IP 时经 fakeudp 伪造源地址回发（per 源缓存， Go
///   `w.conns`）；源伪造不可用时丢弃该响应（Go 同款 LogInfo+continue）。
async fn dokodemo_peer_relay(
    peer: SocketAddr,
    mut rx: tokio::sync::mpsc::Receiver<(Option<Destination>, Vec<u8>)>,
    handler: Arc<dyn DispatchHandler>,
    default_dest: Destination,
    hub: Arc<xray_transport::udp::hub::UdpHub>,
    overridden: bool,
) {
    let mut session = UdpDispatchSession::new(handler);
    #[allow(unused_mut)] // fake_cache 仅 linux cfg 分支被 &mut 借用，非 linux 构建下 mut 冗余
    let mut fake_cache: HashMap<(std::net::IpAddr, u16), Arc<tokio::net::UdpSocket>> =
        HashMap::new();
    loop {
        tokio::select! {
            r = rx.recv() => {
                match r {
                    Some((dest, payload)) => {
                        let d = dest.as_ref().unwrap_or(&default_dest);
                        if session.send_packet(d, &payload).await.is_err() {
                            tracing::info!(
                                dest = %d, len = payload.len(),
                                "dokodemo udp dispatch send failed"
                            );
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
                                    tracing::info!(
                                        peer = %peer, len = payload.len(),
                                        "dokodemo udp fakeudp send_to client failed"
                                    );
                                }
                            }
                            None => {
                                if hub.send_to(&payload, peer).await.is_err() {
                                    tracing::info!(
                                        peer = %peer, len = payload.len(),
                                        "dokodemo udp send_to client failed"
                                    );
                                }
                            }
                        }
                    }
                    Ok(None) => return, // outbound 关闭，会话结束
                    Err(e) => {
                        // qyn8：recv 错误结束会话（Go read 错误语义），
                        // continue 与滞留坏帧构成忙旋
                        tracing::debug!(error = %e, "dokodemo udp dispatch recv failed");
                        return;
                    }
                }
            }
        }
    }
}

/// TPROXY 响应回发 socket：按响应源（IP）取/建 fakeudp 透明 socket。
///
/// - 响应源为 IP：`fakeudp` bind 到该源地址（per 源缓存，Go `w.conns` 同键）。
/// - 创建失败（需 CAP_NET_ADMIN）或源为域名（无法 bind）：返回 `None`，调用 方丢弃该响应（Go
///   PacketWriter 创建失败 LogInfo+drop 同款降级）。
///
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
        },
        Err(e) => {
            tracing::warn!(error = %e, "dokodemo TPROXY fakeudp create failed; response dropped");
            None
        },
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
    // W4 面 6：泵任务归每连接 scope（两级 scope 模型，方案 §2 面 6 步 2）。
    plugin_ctx: Arc<PluginContext>,
) where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    // connection scope：scope 的 Arc 由泵任务持有（任务内持 Arc 锚，既有先例
    // `let _ctx = Arc::clone(&plugin_ctx)` 同款）——本函数返回（dispatch 结束）
    // 后 scope 不被提前 close，泵自然死亡（对端关/断流 break）后计数归零，
    // Drop → close（cancel 对已终局任务无害）；arm scope close（停机）经父闸
    // 级联取消泵任务。语义 = 原裸 spawn detach + 停机级联（面 6 收益）。
    let conn_scope = Arc::new(plugin_ctx.conn_scope());
    let pump_scope = Arc::clone(&conn_scope);
    // 单 task select! 串行推进：SSStream 共享 nonce 计数器不可并发持有 read/write &mut。
    conn_scope
        .spawn(async move {
            let _scope = pump_scope;
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
        })
        .expect("fresh connection scope gate is never closed");
    let (client_rd, client_wr) = tokio::io::split(client_io);
    let link = Link::new(new_reader(client_rd), new_writer(client_wr));
    let _ = handler.dispatch(&dest, link).await;
    // 本函数返回后 scope 由泵任务的 Arc 锚维活（见上），泵退出即收账。
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
    // W4 面 6：泵任务归每连接 scope（构造宿 = 本 pipeline 的调用方 arm ctx）。
    plugin_ctx: Arc<PluginContext>,
) where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // 首包读超时：静默连接占位防护；transport 分支共用本函数，一并覆盖。
    let handshake = match tokio::time::timeout(handshake_timeout, ib.handle_conn(stream)).await {
        Ok(r) => r.map(|(header, ss_stream)| (header.address, header.port, ss_stream)),
        Err(_) => {
            tracing::debug!("ss legacy inbound handshake timeout");
            return;
        },
    };
    match handshake {
        Ok((address, port, ss_stream)) => {
            let dest = Destination::new(address, Port::new(port), Network::TCP);
            spawn_ss_pump(ss_stream, dest, handler, plugin_ctx).await;
        },
        Err(e) => {
            tracing::debug!(error = %e, "ss inbound handshake failed");
        },
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
    // finalmask.udp（bd 05js，Go udp/hub.go:61-62 FinalMask.ListenPacket；None = 未配置）
    udpmask: Option<xray_transport::finalmask::UdpmaskManager>,
    plugin_ctx: Arc<PluginContext>,
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
                // finalmask.udp（bd 05js，Go udp/hub.go:71-77 WrapPacketConnServer）：
                // recv 侧 decode、回包 send_to 侧 encode；未配置 → 裸 socket 原样。
                let udp: Option<Arc<dyn xray_transport::finalmask::UdpIo>> = match udpmask {
                    Some(mgr) if !mgr.udpmasks.is_empty() => {
                        match mgr.wrap_packet_conn_server(Box::new(sock)) {
                            Ok(wrapped) => Some(Arc::from(wrapped)),
                            Err(e) => {
                                tracing::warn!(
                                    error = %e, port, "ss udp mask wrap failed, udp relay disabled"
                                );
                                None
                            },
                        }
                    },
                    _ => Some(Arc::new(sock)),
                };
                if let Some(udp) = udp {
                    let handler = Arc::clone(&handler);
                    // scope 生命周期锚 + 嵌套 relay serve 的 spawn 句柄（克隆体各自再锚）
                    let task_ctx = Arc::clone(&plugin_ctx);
                    plugin_ctx
                        .spawn(async move {
                            let ctx = task_ctx;
                            let _ = match flavor {
                                SsUdpFlavor::Legacy(ib) => {
                                    serve_ss_udp(udp, ib, handler, Arc::clone(&ctx)).await
                                },
                                SsUdpFlavor::Ss2022 { kind, server_psk, users } => {
                                    serve_ss2022_udp(
                                        udp,
                                        kind,
                                        server_psk,
                                        users,
                                        handler,
                                        Arc::clone(&ctx),
                                    )
                                    .await
                                },
                            };
                        })
                        .expect("arm FxScope is never closed");
                }
            },
            Err(e) => tracing::warn!(error = %e, port, "ss udp bind failed, udp relay disabled"),
        }
    }
    tracing::info!(addr = %listener.local_addr()?, "ss inbound listening");
    loop {
        // finalmask.tcp：accept 后立即套上（wire 最外层，ss 握手在其内；
        // 未配 mask → Plain 直通，与原 accept 路径逐字节一致）
        let (stream, _peer) = match listener.accept_masked().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "ss accept failed");
                accept_fd_backoff(&e).await;
                continue;
            },
        };
        let handler = Arc::clone(&handler);
        let mode = inbound.clone();
        // scope 生命周期锚（裸 spawn detach 语义等价）
        let task_ctx = Arc::clone(&plugin_ctx);
        plugin_ctx
            .spawn(async move {
                let _ctx = Arc::clone(&task_ctx);
                ss_mode_conn_pipeline(mode, handler, stream, handshake_timeout, task_ctx).await;
            })
            .expect("arm FxScope is never closed");
    }
}

/// SS inbound 单条连接 pipeline（按 [`SsInboundMode`] 分派）。
///
/// raw TCP accept loop（[`serve_ss`]）与 transport inbound（ws/grpc/kcp 等 hub
/// 解包后的明文流）共用：握手限时 → handle_conn → spawn_ss_pump → dispatch。
pub(crate) async fn ss_mode_conn_pipeline<C>(
    mode: SsInboundMode,
    handler: std::sync::Arc<dyn DispatchHandler>,
    stream: C,
    // Legacy / Ss2022 单用户的握手限时；Multi / Relay 保持既有 DEFAULT_HANDSHAKE_TIMEOUT
    handshake_timeout: std::time::Duration,
    // W4 面 6：泵任务归每连接 scope（构造宿 = 本 pipeline 的调用方 arm ctx）。
    plugin_ctx: Arc<PluginContext>,
) where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    match mode {
        SsInboundMode::Legacy(ib) => {
            ss_legacy_pipeline(ib, handler, stream, handshake_timeout, plugin_ctx).await;
        },
        SsInboundMode::Ss2022(ib) => {
            let handshake = tokio::time::timeout(handshake_timeout, ib.handle_conn(stream)).await;
            let handshake = match handshake {
                Ok(r) => r
                    .map(|resp| (resp.address, resp.port, resp.stream))
                    .map_err(|e| std::io::Error::other(e.to_string())),
                Err(_) => {
                    tracing::debug!("ss2022 inbound handshake timeout");
                    return;
                },
            };
            if let Ok((address, port, ss_stream)) = handshake {
                let dest = Destination::new(address, Port::new(port), Network::TCP);
                spawn_ss_pump(ss_stream, dest, handler, plugin_ctx).await;
            } else if let Err(e) = handshake {
                tracing::debug!(error = %e, "ss inbound handshake failed");
            }
        },
        SsInboundMode::Ss2022Multi(ib) => {
            let handshake =
                tokio::time::timeout(DEFAULT_HANDSHAKE_TIMEOUT, ib.handle_conn(stream)).await;
            let handshake = match handshake {
                Ok(r) => r
                    .map(|resp| (resp.address, resp.port, resp.stream))
                    .map_err(|e| std::io::Error::other(e.to_string())),
                Err(_) => {
                    tracing::debug!("ss2022 multi inbound handshake timeout");
                    return;
                },
            };
            if let Ok((address, port, ss_stream)) = handshake {
                let dest = Destination::new(address, Port::new(port), Network::TCP);
                spawn_ss_pump(ss_stream, dest, handler, plugin_ctx).await;
            } else if let Err(e) = handshake {
                tracing::debug!(error = %e, "ss inbound handshake failed");
            }
        },
        SsInboundMode::Ss2022Relay(ib) => {
            // relay：身份匹配 + 剥 identity header，字节原样桥（无 chunk 解密）
            let handshake =
                tokio::time::timeout(DEFAULT_HANDSHAKE_TIMEOUT, ib.handle_conn_relay(stream)).await;
            let handshake = match handshake {
                Ok(v) => v,
                Err(_) => {
                    tracing::debug!("ss2022 relay inbound handshake timeout");
                    return;
                },
            };
            let Ok((_addr, port, prefix, tcp)) = handshake else {
                tracing::debug!("ss2022 relay inbound handshake failed");
                return;
            };
            let dest = Destination::new(_addr, Port::new(port), Network::TCP);
            let (r, w) = tokio::io::split(tcp);
            let link = Link::new(new_reader(SsRelayReader::new(prefix, r)), new_writer(w));
            let _ = handler.dispatch(&dest, link).await;
        },
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
    server_sessions: &mut HashMap<
        u64,
        (Arc<xray_proxy_ss::ss2022::packet::ServerUdpSession2022>, std::time::Instant),
    >,
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
/// 回包由 `ss_udp_client_relay` 用发起用户的 account `encode_udp_packet`
/// 后 send_to 客户端。
pub async fn serve_ss_udp(
    udp: Arc<dyn xray_transport::finalmask::UdpIo>,
    ib: Arc<SsInbound>,
    handler: Arc<dyn DispatchHandler>,
    plugin_ctx: Arc<PluginContext>,
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
            },
        };
        // ponytail: 收包时顺带清扫已退出（60s 空闲淘汰）会话的残留 sender；
        // O(clients)/包，海量并发 UDP 客户端时换后台定时清扫
        clients.retain(|_, tx| !tx.is_closed());
        let (header, payload) = match decode_udp_packet(ib.validator(), &buf[..n]) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, "ss udp decode failed (unknown user?)");
                continue;
            },
        };
        let dest = Destination::new(header.address.clone(), Port::new(header.port), Network::UDP);
        let item = (dest, payload, header.user.account.clone());
        let tx = clients.entry(client).or_insert_with(|| {
            let (tx, rx) = tokio::sync::mpsc::channel(16);
            let relay_udp = Arc::clone(&udp);
            let relay_handler = Arc::clone(&handler);
            let ctx_pin = Arc::clone(&plugin_ctx);
            plugin_ctx
                .spawn(async move {
                    // scope 生命周期锚：client 会话任务存活期间 arm scope 不 drop
                    let _ctx = ctx_pin;
                    ss_udp_client_relay(relay_udp, client, rx, relay_handler).await;
                })
                .expect("arm FxScope is never closed");
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
/// - up：主循环 decode 后的 (dest, payload) → [`UdpDispatchSession::send_packet`] （首包懒建
///   dispatch link，域名目标原样透传由 outbound 解析）
/// - down：`recv_packet` 回包 → 发起用户 account `encode_udp_packet` → send_to 客户端
///
/// 60s 双向无活动自动退出（Go `CancelAfterInactivity(1min)`）。
async fn ss_udp_client_relay(
    udp: Arc<dyn xray_transport::finalmask::UdpIo>,
    client: SocketAddr,
    mut rx: tokio::sync::mpsc::Receiver<SsUdpItem>,
    handler: Arc<dyn DispatchHandler>,
) {
    use xray_proxy_ss::protocol::encode_udp_packet_into;
    let mut session = UdpDispatchSession::new(handler);
    // 回包加密 account：跟随最近请求的用户（Go 按 client NAT entry 记 user）
    let mut account: Option<xray_proxy_ss::config::MemoryAccount> = None;
    // 回包帧编码 scratch（每包复用，AUDIT-PERF-003）
    let mut enc = Vec::with_capacity(2048);
    // W4 面 3：取时统一走 Budget::tokio()（Tokio 源内部 = tokio Instant，pause 可推进不变）。
    let mut idle = Budget::tokio().deadline(SS_UDP_IDLE_TIMEOUT);
    loop {
        tokio::select! {
            item = rx.recv() => {
                match item {
                    Some((dest, payload, acct)) => {
                        account = Some(acct);
                        if session.send_packet(&dest, &payload).await.is_err() {
                            break;
                        }
                        idle = Budget::tokio().deadline(SS_UDP_IDLE_TIMEOUT);
                    }
                    None => break, // 主循环丢弃本 entry（会话被替换）
                }
            }
            r = session.recv_packet() => {
                match r {
                    Ok(Some((source, payload))) => {
                        if let Some(acct) = &account {
                            if encode_udp_packet_into(
                                acct,
                                source.address(),
                                source.port().value(),
                                &payload,
                                &mut enc,
                            )
                            .is_ok()
                            {
                                let _ = udp.send_to(&enc, client).await;
                            }
                        }
                        idle = Budget::tokio().deadline(SS_UDP_IDLE_TIMEOUT);
                    }
                    Ok(None) => break, // outbound 关闭，会话结束
                    Err(e) => {
                        // qyn8：recv 错误结束会话（Go read 错误语义），
                        // continue 与滞留坏帧构成忙旋
                        tracing::debug!(error = %e, "ss udp dispatch recv failed");
                        break;
                    }
                }
            }
            // 构造式（同上：巨型 select 环）。
            _ = xray_frame::deadline::timeout(
                std::future::pending::<()>(),
                idle.remaining(),
            ) => break, // 60s 空闲淘汰
        }
    }
}

/// SS-2022 UDP relay 入口（Go `MultiService.newPacket` + `udpNat`）。
///
/// recv_from → `server_decode_header`（ECB 头 + EIH 用户识别）→ 按 client
/// sessionId 分发到 per-session NAT entry（`ServerUdpSession2022` +
/// `ss2022_udp_client_relay`，Go `udpNat` cone 会话模型）。回包由 relay
/// task 用该会话的 server sessionId/cipher `encode` 后 send_to 客户端。
///
/// `users` 空 = 单用户（AEAD key 直接从 server PSK 派生）。
pub async fn serve_ss2022_udp(
    udp: Arc<dyn xray_transport::finalmask::UdpIo>,
    kind: xray_proxy_ss::ss2022::key::CipherKind2022,
    server_psk: Vec<u8>,
    users: Vec<([u8; 16], Vec<u8>)>,
    handler: Arc<dyn DispatchHandler>,
    plugin_ctx: Arc<PluginContext>,
) -> std::io::Result<()> {
    use xray_proxy_ss::ss2022::packet::{ServerUdpSession2022, server_decode_header};

    tracing::info!(addr = %udp.local_addr()?, "ss2022 udp relay listening");
    let mut buf = vec![0u8; 65_536];
    type Item = (Destination, Vec<u8>, SocketAddr);
    let mut sessions: HashMap<u64, tokio::sync::mpsc::Sender<Item>> = HashMap::new();
    let mut server_sessions: HashMap<u64, (Arc<ServerUdpSession2022>, std::time::Instant)> =
        HashMap::new();
    loop {
        let (n, client) = match udp.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "ss2022 udp recv failed");
                continue;
            },
        };
        // ponytail: 收包时顺带清扫已退出（60s 空闲淘汰）会话的残留 sender；
        // O(sessions)/包，海量并发 UDP 客户端时换后台定时清扫
        sessions.retain(|_, tx| !tx.is_closed());
        // bd 29nk：顺带惰性清扫超龄（500s 无活动）AEAD 会话——表此前只增不删，
        // 海量 UDP 客户端下是内存泄漏；对齐 Go sing udpSessions LRU 淘汰。
        // L3 台账（713x6 判定）：std 墙钟取时位，`serve_ss2022_udp` 无 ctx 形参
        // （生产调用点在 legacy inbound spawn 区，收口归 bd 39hko）→ 保留 + 逐点
        // allow 登记。面 3 迁的是 tokio 虚拟钟预算面（Budget），此处为 std 墙钟
        // 惰性清扫锚点 = 面 2（compat clock）域，不在本波范围。
        #[allow(
            clippy::disallowed_methods,
            reason = "std 墙钟取时（ss2022 会话 500s 惰性清扫锚点）：serve_ss2022_udp 无 ctx 形参，收口归 bd 39hko；面 3 迁的是 tokio 虚拟钟预算面"
        )]
        let now = std::time::Instant::now();
        sweep_expired_ss2022_sessions(&mut server_sessions, now);
        // 1. ECB 解头 + EIH 用户识别（chacha：整包一次 XChaCha 解开， body 明文随 hdr.chacha_plain
        //    交付）
        let hdr = match server_decode_header(kind, &server_psk, &users, &buf[..n]) {
            Ok(h) => h,
            Err(e) => {
                tracing::debug!(error = %e, "ss2022 udp decode header failed (unknown user?)");
                continue;
            },
        };
        let sid = hdr.session_id;
        #[allow(clippy::map_entry)] // 存量清零批次
        // 2. 查/建 per-sessionId NAT entry
        if !server_sessions.contains_key(&sid) {
            match ServerUdpSession2022::new(kind, hdr.aead_psk.to_vec(), sid) {
                Ok(s) => {
                    server_sessions.insert(sid, (Arc::new(s), now + SS2022_UDP_SESSION_LIFETIME));
                },
                Err(e) => {
                    tracing::debug!(error = %e, "ss2022 udp session init failed");
                    continue;
                },
            }
        }
        // 命中即刷新存活期（sing WithUpdateAgeOnGet 语义）。
        let Some((session, deadline)) = server_sessions.get_mut(&sid) else {
            continue;
        };
        *deadline = now + SS2022_UDP_SESSION_LIFETIME;
        let session = Arc::clone(session);
        // 3. AEAD 解 body + 解析目标（重放/时间戳校验在 decode 内）
        let decoded = match &hdr.chacha_plain {
            Some(plain) => session.decode_chacha_body(plain, hdr.packet_id),
            None => session.decode_body(&hdr.hdr, hdr.packet_id, &buf[16 + hdr.eih_len..n]),
        };
        let (address, port, payload) = match decoded {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, "ss2022 udp decode body failed");
                continue;
            },
        };
        let dest = Destination::new(address, Port::new(port), Network::UDP);
        // 4. 分发到 relay task（首包懒建）
        let tx = sessions.entry(sid).or_insert_with(|| {
            let (tx, rx) = tokio::sync::mpsc::channel(16);
            let relay_udp = Arc::clone(&udp);
            let relay_handler = Arc::clone(&handler);
            let relay_session = Arc::clone(&session);
            let ctx_pin = Arc::clone(&plugin_ctx);
            plugin_ctx
                .spawn(async move {
                    // scope 生命周期锚：session relay 存活期间 arm scope 不 drop
                    let _ctx = ctx_pin;
                    ss2022_udp_client_relay(relay_udp, client, relay_session, rx, relay_handler)
                        .await;
                })
                .expect("arm FxScope is never closed");
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
/// - down：`recv_packet` 回包 → [`ServerUdpSession2022::encode`] → send_to
///   客户端（最新源地址，随每包更新）
///
/// 60s 双向无活动自动退出。
async fn ss2022_udp_client_relay(
    udp: Arc<dyn xray_transport::finalmask::UdpIo>,
    mut client: SocketAddr,
    session: Arc<xray_proxy_ss::ss2022::packet::ServerUdpSession2022>,
    mut rx: tokio::sync::mpsc::Receiver<(Destination, Vec<u8>, SocketAddr)>,
    handler: Arc<dyn DispatchHandler>,
) {
    let mut dispatch = UdpDispatchSession::new(handler);
    // 回包帧编码 scratch（每包复用，AUDIT-PERF-003）
    let mut enc = Vec::with_capacity(2048);
    let mut plain = Vec::with_capacity(2048);
    // W4 面 3：取时统一走 Budget::tokio()（Tokio 源内部 = tokio Instant，pause 可推进不变）。
    let mut idle = Budget::tokio().deadline(SS_UDP_IDLE_TIMEOUT);
    loop {
        tokio::select! {
            item = rx.recv() => {
                match item {
                    Some((dest, payload, src)) => {
                        client = src;
                        if dispatch.send_packet(&dest, &payload).await.is_err() {
                            break;
                        }
                        idle = Budget::tokio().deadline(SS_UDP_IDLE_TIMEOUT);
                    }
                    None => break, // 主循环丢弃本 entry（会话被替换）
                }
            }
            r = dispatch.recv_packet() => {
                match r {
                    Ok(Some((source, payload))) => {
                        if session
                            .encode_into(
                                source.address(),
                                source.port().value(),
                                &payload,
                                &mut enc,
                                &mut plain,
                            )
                            .is_ok()
                        {
                            let _ = udp.send_to(&enc, client).await;
                        }
                        idle = Budget::tokio().deadline(SS_UDP_IDLE_TIMEOUT);
                    }
                    Ok(None) => break, // outbound 关闭，会话结束
                    Err(e) => {
                        tracing::debug!(error = %e, "ss2022 udp dispatch recv failed");
                        continue; // 坏帧跳过（与 SOCKS relay 一致）
                    }
                }
            }
            // 构造式（同上：巨型 select 环）。
            _ = xray_frame::deadline::timeout(
                std::future::pending::<()>(),
                idle.remaining(),
            ) => break, // 60s 空闲淘汰
        }
    }
}

/// hysteria `TcpDispatcher` → xray `DispatchHandler` 适配器（rxw）。
///
/// InterStreamConn 用现成 `HysteriaConn` 包装成 Connection 后按 dispatch Link 桥接。
#[derive(Debug)]
pub(crate) struct HysteriaTcpDispatch(pub(crate) Arc<dyn xray_app_dispatcher::DispatchHandler>);

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
    plugin_ctx: Arc<PluginContext>,
) -> std::io::Result<()> {
    // UDP task：Linux gnu 走 recvmmsg 批收（bd yblz），其余平台 recv_from 单收。
    let udp_inbound = Arc::clone(&inbound);
    let udp_handle = plugin_ctx
        .spawn({
            // scope 生命周期锚：loop 任务存活期间 arm scope 不 drop（detach 等价）
            let ctx_pin = Arc::clone(&plugin_ctx);
            async move {
                let _ctx = ctx_pin;
                dns_udp_recv_loop(udp, udp_inbound).await
            }
        })
        .expect("arm FxScope is never closed");
    // TCP accept loop
    let tcp_inbound = Arc::clone(&inbound);
    // scope 生命周期锚（loop 任务）+ 嵌套 per-conn spawn 句柄（克隆体各自再锚）
    let loop_ctx = Arc::clone(&plugin_ctx);
    let conn_ctx = Arc::clone(&plugin_ctx);
    let tcp_handle = plugin_ctx
        .spawn(async move {
            let _ctx = loop_ctx;
            loop {
                // finalmask.tcp：accept 后立即套上（mask 在 DNS 帧之前）
                match tcp.accept_masked().await {
                    Ok((conn, _peer)) => {
                        let inbound = Arc::clone(&tcp_inbound);
                        let task_ctx = Arc::clone(&conn_ctx);
                        conn_ctx
                            .spawn(async move {
                                let _ctx = task_ctx;
                                if let Err(e) = inbound.handle_conn(conn).await {
                                    tracing::debug!(error = %e, "dns tcp conn failed");
                                }
                            })
                            .expect("arm FxScope is never closed");
                    },
                    Err(e) => {
                        tracing::warn!(error = %e, "dns tcp accept failed");
                        accept_fd_backoff(&e).await;
                    },
                }
            }
        })
        .expect("arm FxScope is never closed");
    // 等待任一 task 结束（正常情况不会结束）
    tokio::select! {
        r = udp_handle.join() => {
            r.map_err(|e| std::io::Error::other(format!("dns udp task: {e}")))
        }
        r = tcp_handle.join() => {
            r.map_err(|e| std::io::Error::other(format!("dns tcp task: {e}")))
        }
    }
}

/// DNS 单批 recvmmsg 上限（msgvec 长度）：足够摊薄 syscall 开销且有界。
#[cfg(all(target_os = "linux", target_env = "gnu"))]
const DNS_UDP_RECV_BATCH: usize = 16;

/// DNS UDP 单包缓冲（常规 MTU；超长 query 由 MSG_TRUNC 检出丢弃）。
#[cfg(all(target_os = "linux", target_env = "gnu"))]
const DNS_UDP_PACKET_BUF: usize = 1500;

/// DNS UDP 收包循环（Linux gnu）：`recvmmsg(2)` 一次 syscall 批量收多 query。
///
/// bd yblz：单 socket 多 client query 在内核排队时，批收把 N 次 recv_from
/// 合并为一次 syscall，降低 DNS p99。缓冲组预分配一次循环复用（无
/// per-query 分配）。非阻塞 + MSG_DONTWAIT：收空（WouldBlock）回
/// [`dns_udp_recv_loop`] 外圈 `readable()` 等新就绪。musl/uclibc 的 libc
/// 未导出 recvmmsg 函数，走下方 recv_from 回退版。
#[cfg(all(target_os = "linux", target_env = "gnu"))]
async fn dns_udp_recv_loop(udp: UdpSocket, inbound: Arc<DnsInbound>) {
    use std::os::fd::AsRawFd;

    let mut batch = DnsUdpRecvBatch::new();
    let fd = udp.as_raw_fd();
    loop {
        if let Err(e) = udp.readable().await {
            tracing::warn!(error = %e, "dns udp readable failed");
            return;
        }
        loop {
            // namelen 是内核写回字段，每轮还原容量，否则下轮长地址被截断。
            for m in batch.msgs.iter_mut() {
                m.msg_hdr.msg_namelen =
                    std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            }
            // SAFETY: fd 在 udp 存活期内有效；msgs 的 msg_name/msg_iov 指向
            // batch 的固定堆地址（Box 构造后不移动），各缓冲容量已预填。
            let n = unsafe {
                libc::recvmmsg(
                    fd,
                    batch.msgs.as_mut_ptr(),
                    DNS_UDP_RECV_BATCH as libc::c_uint,
                    libc::MSG_DONTWAIT,
                    std::ptr::null_mut(),
                )
            };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                match e.kind() {
                    std::io::ErrorKind::WouldBlock => break, // 本轮收空
                    std::io::ErrorKind::Interrupted => continue,
                    _ => {
                        tracing::warn!(error = %e, "dns udp recvmmsg failed");
                        return;
                    },
                }
            }
            let n = usize::try_from(n).unwrap_or_default();
            for i in 0..n {
                // MSG_TRUNC：query 超过单包缓冲被截断，报文不完整，丢弃。
                if (batch.msgs[i].msg_hdr.msg_flags & libc::MSG_TRUNC) != 0 {
                    tracing::debug!("dns udp query too large, dropped");
                    continue;
                }
                let Some(peer) = sockaddr_storage_to_addr(&batch.addrs[i]) else {
                    continue;
                };
                let len = usize::try_from(batch.msgs[i].msg_len).unwrap_or_default();
                let packet = &batch.bufs[i][..len];
                match inbound.handle_packet(packet).await {
                    Ok(Some(resp)) => {
                        if let Err(e) = udp.send_to(&resp, peer).await {
                            tracing::debug!(error = %e, "dns udp send failed");
                        }
                    },
                    Ok(None) => {}, // Drop: 不响应
                    Err(e) => {
                        tracing::debug!(error = %e, "dns udp handle_packet failed");
                    },
                }
            }
            if n < DNS_UDP_RECV_BATCH {
                break; // 未收满，回外圈等新就绪
            }
        }
    }
}

/// DNS UDP 收包循环（非 Linux gnu 平台）：`recv_from` 单包收。
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
async fn dns_udp_recv_loop(udp: UdpSocket, inbound: Arc<DnsInbound>) {
    let mut buf = [0u8; 1500];
    loop {
        match udp.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                match inbound.handle_packet(&buf[..len]).await {
                    Ok(Some(resp)) => {
                        if let Err(e) = udp.send_to(&resp, peer).await {
                            tracing::debug!(error = %e, "dns udp send failed");
                        }
                    },
                    Ok(None) => {}, // Drop: 不响应
                    Err(e) => {
                        tracing::debug!(error = %e, "dns udp handle_packet failed");
                    },
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "dns udp recv failed");
            },
        }
    }
}

/// recvmmsg 批收缓冲组：预分配一次循环复用。
///
/// Box 固定堆地址后填充 msg_name/msg_iov 自引用指针；构造后整体不移动。
#[cfg(all(target_os = "linux", target_env = "gnu"))]
struct DnsUdpRecvBatch {
    /// 各 slot 收包数据缓冲。
    bufs: Box<[[u8; DNS_UDP_PACKET_BUF]]>,
    /// 各 slot 发送方地址（内核写回）。
    addrs: Box<[libc::sockaddr_storage]>,
    /// iovec 数组：仅经 msg_hdr.msg_iov 指针间接访问。
    #[allow(dead_code)]
    // iovs 仅经 msgs[i].msg_hdr.msg_iov 指针间接引用，字段持所有权保地址固定
    iovs: Box<[libc::iovec]>,
    /// recvmmsg 消息向量（msg_len 为内核写回的各包实际长度）。
    msgs: Box<[libc::mmsghdr]>,
}
// SAFETY: msgs 的 msg_name/msg_iov 与 iovs 的 iov_base 均指向本结构自身
// Box 固定的堆缓冲（构造后不移动），无别名可变访问；整批仅在收包 task
// 内使用，不跨线程共享。裸指针使类型默认 !Send，但所有权语义实为
// 自包含——跨 .await 持有（handle_packet）不产生数据竞争。
#[cfg(all(target_os = "linux", target_env = "gnu"))]
unsafe impl Send for DnsUdpRecvBatch {}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
impl DnsUdpRecvBatch {
    /// 零值分配，地址固定后填充自引用指针。
    fn new() -> Self {
        // SAFETY: sockaddr_storage/mmsghdr 是 POD，全零为合法待填充状态
        // （msg_control 恒 null = 不取 ancillary，与 recv_from 语义一致）。
        let mut bufs: Box<[[u8; DNS_UDP_PACKET_BUF]]> =
            vec![[0u8; DNS_UDP_PACKET_BUF]; DNS_UDP_RECV_BATCH].into_boxed_slice();
        let mut addrs: Box<[libc::sockaddr_storage]> =
            vec![unsafe { std::mem::zeroed() }; DNS_UDP_RECV_BATCH].into_boxed_slice();
        let mut iovs: Box<[libc::iovec]> =
            vec![libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 }; DNS_UDP_RECV_BATCH]
                .into_boxed_slice();
        let mut msgs: Box<[libc::mmsghdr]> =
            // SAFETY: mmsghdr 为 POD，全零为合法待填充态（msg_control 恒 null = 不取 ancillary）
            vec![unsafe { std::mem::zeroed() }; DNS_UDP_RECV_BATCH].into_boxed_slice();

        for i in 0..DNS_UDP_RECV_BATCH {
            iovs[i].iov_base = bufs[i].as_mut_ptr().cast();
            iovs[i].iov_len = DNS_UDP_PACKET_BUF;
            msgs[i].msg_hdr.msg_name = std::ptr::addr_of_mut!(addrs[i]).cast();
            msgs[i].msg_hdr.msg_namelen =
                std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            msgs[i].msg_hdr.msg_iov = std::ptr::addr_of_mut!(iovs[i]);
            msgs[i].msg_hdr.msg_iovlen = 1;
        }
        Self { bufs, addrs, iovs, msgs }
    }
}

/// 解析内核写回的 `sockaddr_storage` 为 `SocketAddr`（按 ss_family 判别）。
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn sockaddr_storage_to_addr(ss: &libc::sockaddr_storage) -> Option<std::net::SocketAddr> {
    match ss.ss_family as libc::c_int {
        libc::AF_INET => {
            // SAFETY: ss_family == AF_INET 保证布局为 sockaddr_in。
            let a = unsafe { &*(ss as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>() };
            Some(std::net::SocketAddr::from(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)),
                u16::from_be(a.sin_port),
            )))
        },
        libc::AF_INET6 => {
            // SAFETY: ss_family == AF_INET6 保证布局为 sockaddr_in6。
            let a = unsafe { &*(ss as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>() };
            Some(std::net::SocketAddr::from(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from(a.sin6_addr.s6_addr),
                u16::from_be(a.sin6_port),
                a.sin6_flowinfo,
                a.sin6_scope_id,
            )))
        },
        _ => None,
    }
}

/// 遍历 BuiltConfig 的 inbounds，经 [`InboundRuntime`] spawn listener tasks。
///
/// 返回每个 inbound 的 JoinHandle（用于优雅关闭）。启动失败的入站带 tag 上抛
/// （对齐 Go：入站创建失败 → core 启动失败退出）。
pub async fn spawn_inbounds(
    built: &BuiltConfig,
    runtime: &Arc<InboundRuntime>,
) -> std::io::Result<Vec<JoinHandle<()>>> {
    let mut handles = Vec::new();
    for ib in &built.inbounds {
        // bd 0z7u：绑定失败带 tag 上下文 ERROR 日志后 fatal（对齐 Go xray
        // 入站创建失败 → core 启动失败退出；裸 io::Error 无 tag 无法定位）。
        if let Some(handle) = runtime.start_inbound(ib).await.map_err(|e| {
            tracing::error!(tag = %ib.tag, protocol = %ib.entry.kind, error = %e, "inbound bind failed, aborting startup");
            std::io::Error::other(format!("inbound `{}` ({}) start failed: {e}", ib.tag, ib.entry.kind))
        })? {
            handles.push(handle);
        }
    }
    // bd 0z7u：启动结束入站绑定汇总（哪些 tag 成功在监听）。
    tracing::info!(
        listening = handles.len(),
        tags = ?built.inbounds.iter().map(|ib| ib.tag.as_str()).collect::<Vec<_>>(),
        "inbound bind summary"
    );
    Ok(handles)
}

/// 单入站的 ohm 视图（方案 B）。
///
/// 生产链经 DefaultDispatcher（sniffing + stats + routing）：每个 inbound 一份 ohm
/// 快照，default 替换为携带该 inbound sniffing 配置与 tag 的 wrapper；master ohm 的
/// default 保持真实出站（避免递归）。wrapper 外再包 MuxCarrierHandler（Go
/// always.go:89 mux.NewServer 装饰器）：v1.mux.cool carrier 由 mux ServerWorker 接管，
/// 子会话回 wrapper。
fn per_inbound_ohm(
    ohm: &Arc<SimpleOhm>,
    dispatcher: Option<&Arc<xray_app_dispatcher::DefaultDispatcher>>,
    ib: &BuiltInbound,
) -> Arc<SimpleOhm> {
    dispatcher
        .map(|d| {
            let snap = Arc::new(ohm.snapshot());
            let sniff = crate::wiring::sniffing_request_from_json(ib.sniffing_json.as_ref());
            let inbound_handler: Arc<dyn xray_app_dispatcher::DispatchHandler> =
                Arc::new(crate::wiring::InboundDispatchHandler::new(Arc::clone(d), sniff, &ib.tag));
            snap.set_default(Arc::new(crate::wiring::MuxCarrierHandler::new(inbound_handler)));
            snap
        })
        .unwrap_or_else(|| Arc::clone(ohm))
}

// ===========================================================================
// gRPC inbound 运行时（bd jezb）
// ===========================================================================

/// gRPC inbound 用户管理后端（`AlterInbound` 的 AddUser/RemoveUser 与
/// `GetInboundUsers` 的协议侧接线点）。
///
/// 对应 Go `handler.(proxy.UserManager)`：协议实现了即支持用户增删查，未实现时
/// 调用方按 [`ProxymanError::NotUserManager`] 明确拒绝（不静默成功）。
pub trait ApiUserManager: Send + Sync {
    fn add_user(&self, user: &ProtoUser) -> Result<(), ProxymanError>;
    fn remove_user(&self, email: &str) -> Result<(), ProxymanError>;
    fn get_user(&self, email: &str) -> Option<ProtoUser>;
    fn list_users(&self) -> Vec<ProtoUser>;
}

/// shadowsocks（legacy AEAD）用户管理适配：委托 [`SsInbound::server`] 的 validator。
///
/// validator 的 `Arc` 与 serve loop 共享，运行时增删对后续连接立即生效。
struct SsUserManager(Arc<SsInbound>);

impl ApiUserManager for SsUserManager {
    fn add_user(&self, user: &ProtoUser) -> Result<(), ProxymanError> {
        // Account 载荷沿用仓库既有约定（TypedMessage.value = account JSON，
        // 与 CLI `api add-user` 一致）。
        let account = user
            .account
            .as_ref()
            .ok_or_else(|| ProxymanError::UserParse("ss add_user requires account".into()))?;
        let js: serde_json::Value = serde_json::from_slice(&account.value)
            .map_err(|e| ProxymanError::UserParse(format!("ss account is not JSON: {e}")))?;
        let password = js
            .get("password")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ProxymanError::UserParse("ss account requires password".into()))?;
        let method =
            js.get("method").or_else(|| js.get("cipher")).and_then(|v| v.as_str()).unwrap_or("");
        let cipher = ss_cipher_from_str(method)
            .ok_or_else(|| ProxymanError::UserParse(format!("unknown ss method: {method}")))?;
        let account = xray_proxy_ss::config::MemoryAccount::from_proto(
            &xray_proto::xray::proxy::shadowsocks::Account {
                password: password.to_string(),
                cipher_type: cipher.as_i32(),
                iv_check: false,
            },
        )
        .map_err(|e| ProxymanError::UserParse(e.to_string()))?;
        self.0
            .server()
            .add_user(xray_proxy_ss::validator::MemoryUser {
                email: user.email.clone(),
                level: user.level,
                account,
            })
            .map_err(|e| ProxymanError::UserParse(e.to_string()))
    }

    fn remove_user(&self, email: &str) -> Result<(), ProxymanError> {
        self.0.server().remove_user(email).map_err(|e| ProxymanError::UserParse(e.to_string()))
    }

    /// account 不回填：ss validator 不保留原始 account 载荷（email/level 之外
    /// 无对应关系），GetInboundUsers 因此只回 email+level（Go 回完整 account）。
    fn get_user(&self, email: &str) -> Option<ProtoUser> {
        self.0.server().get_user(email).map(|u| user_proto(&u.email, u.level))
    }

    fn list_users(&self) -> Vec<ProtoUser> {
        self.0
            .server()
            .validator
            .get_all()
            .into_iter()
            .map(|u| user_proto(&u.email, u.level))
            .collect()
    }
}

/// (email, level) → proto `User`（account 不回填，见 [`SsUserManager::get_user`]）。
fn user_proto(email: &str, level: u32) -> ProtoUser {
    ProtoUser { level, email: email.to_string(), account: None }
}

struct InboundSlot {
    /// proxy_settings 的 type_url（`xray.proxy.{kind}.Config`），ListInbounds 回填。
    proxy_type_url: String,
    /// 单入站取消令牌——shutdown token 的子令牌，RemoveInbound 只停这一个。
    cancel: CancellationToken,
    users: Option<Arc<dyn ApiUserManager>>,
}

/// 生产注册表容量上界（xiuvr-3a）：配置文件 inbound 数量工程上远小于此；
/// 超限 `Eviction::Reject` fail-closed（insert Err 显式上抛），不静默淘汰。
const INBOUND_REGISTRY_CAP: usize = 1024;

/// 生产 inbound 运行时（bd jezb）：gRPC `HandlerService` 的 inbound 域后端。
///
/// 持有真实 ohm / dispatcher / policy 与实例 shutdown token，使 `AddInbound` 走与
/// 配置期完全相同的 `spawn_one_inbound` 路径起 listener（bind 失败原样上抛），
/// `RemoveInbound` 通过 per-inbound 令牌单独停一个入站。
pub struct InboundRuntime {
    ohm: Arc<SimpleOhm>,
    dispatcher: Option<Arc<xray_app_dispatcher::DefaultDispatcher>>,
    /// dispatcher 装配时注入的 policy manager（http inbound 按 userLevel 查
    /// handshake 超时等 per-level 策略）。
    policy: Option<Arc<dyn xray_features::policy::PolicyManager>>,
    shutdown: CancellationToken,
    /// 宿主 arm scope 登记表（bd a9xgp：Instance 建一份，经本件注入各 inbound
    /// arm 的 `PluginContext`；`Instance::close` 逆序显式关停全部 arm）。
    arm_scopes: Arc<xray_frame::ArmScopeRegistry>,
    /// 已启动入站（tag → slot；xiuvr-3a：udf `BoundedRegistry` 承载——BTreeMap
    /// 确定序 = tag 升序，ListInbounds 顺序稳定；上界 fail-closed 不静默淘汰）。
    slots: parking_lot::RwLock<BoundedRegistry<String, InboundSlot>>,
}

impl InboundRuntime {
    #[must_use]
    pub fn new(
        ohm: Arc<SimpleOhm>,
        dispatcher: Option<Arc<xray_app_dispatcher::DefaultDispatcher>>,
        shutdown: CancellationToken,
        arm_scopes: Arc<xray_frame::ArmScopeRegistry>,
    ) -> Self {
        let policy = dispatcher.as_ref().and_then(|d| d.policy_manager.clone());
        Self {
            ohm,
            dispatcher,
            policy,
            shutdown,
            arm_scopes,
            slots: parking_lot::RwLock::new(BoundedRegistry::new(
                INBOUND_REGISTRY_CAP,
                Eviction::Reject,
            )),
        }
    }

    /// 宿主 arm scope 登记表（装配期接线 inbound arm `PluginContext` 用）。
    pub fn arm_scopes(&self) -> &Arc<xray_frame::ArmScopeRegistry> {
        &self.arm_scopes
    }

    /// 启动一个 inbound 并登记（配置期与 gRPC AddInbound 共用同一路径）。
    ///
    /// # Errors
    ///
    /// tag 已存在或 listener 绑定/协议配置失败——错误原样返回，不静默跳过。
    pub async fn start_inbound(
        &self,
        ib: &BuiltInbound,
    ) -> std::io::Result<Option<JoinHandle<()>>> {
        if self.contains(&ib.tag) {
            return Err(std::io::Error::other(format!("existing tag found: {}", ib.tag)));
        }
        let cancel = self.shutdown.child_token();
        let type_url = format!("xray.proxy.{}.Config", ib.entry.kind);
        // 满表 fail-closed：insert Err 显式上抛（上界 INBOUND_REGISTRY_CAP，配置
        // 面工程上不可达），不静默淘汰（xiuvr-3a D3）。
        self.slots
            .write()
            .insert(
                ib.tag.clone(),
                InboundSlot { proxy_type_url: type_url, cancel: cancel.clone(), users: None },
            )
            .map_err(|e| std::io::Error::other(format!("inbound registry full: {e}")))?;
        let per_ohm = per_inbound_ohm(&self.ohm, self.dispatcher.as_ref(), ib);
        match spawn_one_inbound(ib, per_ohm, self.policy.clone(), cancel, Some(self)).await {
            Ok(handle) => Ok(handle),
            Err(e) => {
                self.slots.write().remove(&ib.tag);
                Err(e)
            },
        }
    }

    /// tag 是否已登记（对应 Go `ihm.GetHandler` 的存在性检查）。
    #[must_use]
    pub fn contains(&self, tag: &str) -> bool {
        self.slots.read().get(&tag.to_string()).is_some()
    }

    /// 停止并注销一个入站。对应 Go `ihm.RemoveHandler`。
    ///
    /// # Errors
    ///
    /// tag 不存在 → [`ProxymanError::HandlerNotFound`]。
    pub fn remove_inbound(&self, tag: &str) -> Result<(), ProxymanError> {
        let slot = self.slots.write().remove(&tag.to_string());
        match slot {
            Some(s) => {
                s.cancel.cancel();
                Ok(())
            },
            None => Err(ProxymanError::HandlerNotFound(tag.to_string())),
        }
    }

    /// 已启动入站的 (tag, proxy_settings type_url)，tag 升序（BTreeMap 确定序）。
    #[must_use]
    pub fn list(&self) -> Vec<(String, String)> {
        self.slots
            .read()
            .iter()
            .map(|(tag, slot)| (tag.clone(), slot.proxy_type_url.clone()))
            .collect()
    }

    /// 取入站的用户管理器。
    ///
    /// # Errors
    ///
    /// tag 不存在 → [`ProxymanError::HandlerNotFound`]；协议不支持用户管理 →
    /// [`ProxymanError::NotUserManager`]（Go 类型断言失败的等价语义）。
    pub fn user_manager(&self, tag: &str) -> Result<Arc<dyn ApiUserManager>, ProxymanError> {
        let slots = self.slots.read();
        let slot = slots.get(&tag.to_string());
        let slot = slot.ok_or_else(|| ProxymanError::HandlerNotFound(tag.to_string()))?;
        slot.users.clone().ok_or(ProxymanError::NotUserManager)
    }

    /// 协议 handler 启动时登记用户管理器（当前仅 shadowsocks legacy 走这条）。
    ///
    /// 槽位在 spawn 前已插入，缺失说明调用方未登记 tag（编程错误）。
    fn register_user_manager(&self, tag: &str, users: Arc<dyn ApiUserManager>) {
        let mut slots = self.slots.write();
        let Some(mut slot) = slots.remove(&tag.to_string()) else {
            tracing::warn!(tag = %tag, "user manager registered for unknown inbound");
            return;
        };
        slot.users = Some(users);
        // 键刚被 remove，insert 恒成功（不触发淘汰）；Err 仅为理论竞态留痕。
        if slots.insert(tag.to_string(), slot).is_err() {
            tracing::error!(tag = %tag, "inbound registry insert failed after remove");
        }
    }
}

/// proto `InboundHandlerConfig`（gRPC AddInbound）→ [`BuiltInbound`]。
///
/// TypedMessage 约定与 CLI（`api_exec::build_inbound_configs`）一致：
/// - `proxy_settings.type`：`xray.proxy.{protocol}.Config`，value = settings JSON
/// - `receiver_settings.value`：`{"listen","port","streamSettings","sniffing"}` JSON
pub fn built_inbound_from_proto(cfg: &ProtoInboundConfig) -> Result<BuiltInbound, ProxymanError> {
    let type_url = cfg.proxy_settings.as_ref().map(|m| m.r#type.as_str()).unwrap_or_default();
    let kind =
        type_url.strip_prefix("xray.proxy.").and_then(|s| s.strip_suffix(".Config")).ok_or_else(
            || ProxymanError::Other(format!("unsupported inbound proxy_settings type: {type_url}")),
        )?;
    let settings = cfg.proxy_settings.as_ref().map(|m| m.value.as_slice()).unwrap_or_default();
    let data = serde_json::to_vec(
        &serde_json::from_slice::<serde_json::Value>(settings)
            .map_err(|e| ProxymanError::Other(format!("inbound proxy_settings: {e}")))?,
    )
    .map_err(|e| ProxymanError::Other(e.to_string()))?;
    let receiver: serde_json::Value = match cfg.receiver_settings.as_ref() {
        Some(m) if !m.value.is_empty() => serde_json::from_slice(&m.value)
            .map_err(|e| ProxymanError::Other(format!("inbound receiver_settings: {e}")))?,
        _ => serde_json::Value::Null,
    };
    let port = match receiver.get("port") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(
            v.as_u64()
                .and_then(|p| u16::try_from(p).ok())
                .ok_or_else(|| ProxymanError::Other(format!("invalid inbound port: {v}")))?,
        ),
    };
    Ok(BuiltInbound {
        entry: xray_conf::BuiltEntry { kind: kind.to_string(), data },
        tag: cfg.tag.clone(),
        port,
        listen: receiver.get("listen").and_then(|v| v.as_str()).map(String::from),
        stream_settings_json: receiver.get("streamSettings").cloned(),
        sniffing_json: receiver.get("sniffing").cloned(),
    })
}

/// inbound arm scope 停机排空预算（bd a9xgp）。
///
/// 保守默认 = 5s，对齐 xray-frame `DEFAULT_SHUTDOWN_TIMEOUT`（P0-8 拍板）与
/// `shutdown_bridge::DEFAULT_CLOSE_TIMEOUT` 同族停机档。语义：cancel 广播后
/// 至多等 5s 收净 arm 托管任务，超时剩余任务已被 abort 兜底（udf
/// `FxScope::shutdown_timeout` close_and_take，零残留）——**停机永不无限等**。
/// 排空在后台监视任务进行，不阻塞 `Instance::close` 同步段（close 只做逆序
/// 广播，在途连接毫秒级终止）。
const ARM_SCOPE_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// spawn 一个 inbound serve task，监听 shutdown_token 实现优雅关闭。
///
/// token cancel 时取消 serve future（drop listener，accept 循环终止）。
/// 对应 Go 有序关闭的"先停 accept"阶段。
///
/// W4 面 6：serve 任务本体托管 arm scope（任务记账 + in_flight + 停机级联，
/// bd 39hko）；panic 监督语义（51d50459）逐字保留——FxScope catch_unwind 把
/// serve future 的 panic 归一 `TaskError::Panicked`，外层壳 join 判别后 error! 留痕，
/// listener 随 panic 的 future drop 释放，等价原 `JoinError::is_panic()` 路径。
///
/// bd a9xgp（停机掉在途连接）：本函数是全部 inbound arm 的**唯一构造漏斗**
/// （arm_builders 各构造函数 + transport/unix 分支均经此 spawn），在此集中完成
/// ①登记（arm scope 句柄入宿主登记表，`Instance::close` 逆序显式 close）与
/// ②停机监视（token cancel → 关 arm scope 父闸广播 → `ConnScope` 级联取消
/// 在途连接 → arm 托管任务有界排空）。
pub(crate) fn spawn_inbound_serve(
    arm: &Arc<PluginContext>,
    tag: String,
    shutdown_token: CancellationToken,
    fut: impl Future<Output = std::io::Result<()>> + Send + 'static,
) -> JoinHandle<()> {
    // ①登记（bd a9xgp）：arm scope 句柄入宿主登记表（装配序）；未接线 ctx
    // （独立装配配方/测试 ctx）跳过——停机级联由 token 监视 + Drop 兜底。
    if let Some(registry) = arm.arm_registry() {
        registry.register(tag.as_str(), Arc::clone(arm.arm_scope()));
    }
    // 停机监视令牌（先于 inner 克隆：shutdown_token 本体随 inner future move）。
    let watch_token = shutdown_token.clone();
    // 内层：serve + shutdown select —— 托管 arm scope。
    let inner = arm
        .spawn({
            let tag_inner = tag.clone();
            async move {
                tokio::select! {
                    r = fut => {
                        if let Err(e) = r {
                            tracing::error!(tag = %tag_inner, error = %e, "inbound stopped");
                        }
                    }
                    _ = shutdown_token.cancelled() => {
                        tracing::info!(tag = %tag_inner, "inbound shutting down (graceful)");
                    }
                }
            }
        })
        .expect("arm FxScope is never closed");
    // 外层壳：JoinHandle 外返契约（InboundRuntime → spawn_inbounds → functions.rs
    // 消费链，改返回类型超出本波文件面）+ panic 监督（51d50459 语义保留）+ 停机
    // 监视（bd a9xgp）。例外登记（W4 面 6）：JoinHandle 外返契约，与 tun 保留同源。
    //
    // **arm scope 生命周期锚（关键）**：serve 任务本体登记在 arm scope 的
    // JoinSet 内，而 JoinSet 随 `FxScope` drop 即 abort 全部在途任务。arm
    // scope 的 `Arc<PluginContext>` 强引用只存在于 arm_builders 构造函数的
    // 形参里 → 构造函数返回即销毁 → scope drop → serve 任务被立刻 abort →
    // listener 随 future drop 释放 → 入站静默失效（端口不再 listen 而进程存活）。
    // 故外层壳持一份 `Arc<PluginContext>` 锚，覆盖 inner 任务存活期
    // （既有同款先例：`let _ctx = task_ctx;` 生命周期锚）。
    //
    // **停机监视臂（bd a9xgp）**：token cancel（实例停机 / per-inbound remove）
    // → `ArmScope::shutdown_timeout` 关父闸 + watch 广播 → `ConnScope` 级联取消
    // 在途连接（SS 泵等）→ arm 托管任务 abort_all + 超时兜底排空。监视与 panic
    // 监督同壳承载，零新增任务。
    let arm_anchor = Arc::clone(arm);
    #[allow(
        clippy::disallowed_methods,
        reason = "监控壳外层：JoinHandle 外返契约（InboundRuntime→functions.rs 消费链，超出本波文件面）；panic 监督语义（51d50459）+ 停机级联监视（bd a9xgp）同壳承载，serve 任务本体已迁 arm scope"
    )]
    tokio::spawn(async move {
        let arm = arm_anchor;
        tokio::select! {
            _ = watch_token.cancelled() => {
                arm.arm_scope().shutdown_timeout(ARM_SCOPE_DRAIN_TIMEOUT).await
                    .unwrap_or_else(|e| drain_warn(&tag, e));
            }
            joined = inner.join() => {
                if let Err(skeleton_infra::fx::TaskError::Panicked(_)) = joined {
                    tracing::error!(
                        tag = %tag,
                        "inbound serve task panicked — 监听已停止，该端口不再接受连接"
                    );
                }
                // select! 双臂同就绪随机裁决（serve 与监视令牌同听一个 token，
                // join 可先就绪）——join 臂胜出时停机排空必须兜底，禁把级联
                // 押在裁决随机性上（a9xgp 修复首跑即踩中）。token 已取消 =
                // 停机形态 → 幂等排空；token 未取消 = listener 自然终局，保留
                // 既有「连接任务不随 listener 死亡」的 detach 语义不排空。
                if watch_token.is_cancelled() {
                    arm.arm_scope().shutdown_timeout(ARM_SCOPE_DRAIN_TIMEOUT).await
                        .unwrap_or_else(|e| drain_warn(&tag, e));
                }
            }
        }
    })
}

/// 停机排空超时留痕（超时档已到 = 剩余任务已被 abort 兜底，仅日志面）。
fn drain_warn(tag: &str, e: skeleton_infra::fx::TaskError) {
    tracing::warn!(tag = %tag, error = %e, "arm scope drain timed out; residual tasks aborted");
}

/// 从 inbound streamSettings 构建 TLS acceptor（security=tls 时）。
///
/// 对应 Go inbound listener 的 `tls.ConfigFromStreamSettings` → `tls.NewListener`。
/// serve 函数 accept 后先做 TLS handshake 再处理协议数据。
pub(crate) fn build_tls_acceptor(
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
/// 来源：Go xtls/reality `tls.go:259` `config.MaxTimeDiff == 0 || time.Since(...).Abs() <=
/// MaxTimeDiff`。
pub(crate) struct RealityInboundConfig {
    server_private_key: [u8; 32],
    /// t38j：SNI 白名单（非空，parse 层硬错保证）；精确匹配，供 server_tls 前置门。
    server_names: Vec<String>,
    short_ids: Vec<[u8; 8]>,
    max_diff: u32,
    pub(crate) fallback_dest: String,
    xver: u8,
    /// fs0o：客户端版本门（字节序字典序比较；空 = 不限）。
    min_client_ver: Vec<u8>,
    max_client_ver: Vec<u8>,
    /// bd frxi：启动期 CCS 探测开关（缺省 Disabled 保持现行为）。
    max_useless_records: xray_reality::MaxUselessRecordsSetting,
    /// bd tce2：TLS acceptor 选择（缺省 Rustls 保持现行为）。
    server_acceptor: xray_reality::ServerAcceptorSetting,
}

// Debug 脱敏（bd 99kd）：server_private_key 是 REALITY 服务端长期密钥，
// 禁止经 derive(Debug) 落入 tracing/panic 输出。
impl std::fmt::Debug for RealityInboundConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityInboundConfig")
            .field("server_private_key", &"[REDACTED]")
            .field("server_names", &self.server_names)
            .field("short_ids", &self.short_ids)
            .field("max_diff", &self.max_diff)
            .field("fallback_dest", &self.fallback_dest)
            .field("xver", &self.xver)
            .field("min_client_ver", &self.min_client_ver)
            .field("max_client_ver", &self.max_client_ver)
            .field("max_useless_records", &self.max_useless_records)
            .field("server_acceptor", &self.server_acceptor)
            .finish()
    }
}

pub(crate) fn parse_reality_config(
    settings: &xray_transport::dialer::StreamSettings,
) -> std::io::Result<RealityInboundConfig> {
    let json = settings
        .security_json
        .as_ref()
        .ok_or_else(|| std::io::Error::other("reality inbound requires realitySettings"))?;
    // t38j：serverNames 非空硬错（Go transport_security.go:94-96 `empty "serverNames"`
    // 拒启）；白名单供 server_tls 做 SNI 前置门（xtls/reality tls.go:211）。
    let mut server_names = Vec::new();
    if let Some(arr) = json.get("serverNames").and_then(|x| x.as_array()) {
        for v in arr {
            let Some(name) = v.as_str() else {
                return Err(std::io::Error::other(
                    "reality: invalid serverNames entry (need string)",
                ));
            };
            server_names.push(name.to_string());
        }
    }
    if server_names.is_empty() {
        return Err(std::io::Error::other("reality: empty \"serverNames\""));
    }
    let key_str = json
        .get("privateKey")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| std::io::Error::other("reality: empty privateKey"))?;
    let key = base64_url_decode(key_str)
        .and_then(|k| <[u8; 32]>::try_from(k).ok())
        .ok_or_else(|| std::io::Error::other("reality: invalid privateKey (need base64 32B)"))?;
    // 257w：shortIds 校验收紧对齐 Go transport_security.go:135-147——空数组拒启、
    // 单项 >16 拒启、奇数长度/非法 hex 拒启（原实现右补零+失败 continue+空数组
    // 默认全零放行，全部放宽于 Go）。合法项左对齐补零到 8 字节（Go hex.Decode
    // 写入 make([]byte,8)；"" 解码为空 → 全零 short_id）。
    let sid_arr = json
        .get("shortIds")
        .and_then(|x| x.as_array())
        .ok_or_else(|| std::io::Error::other("reality: empty \"shortIds\""))?;
    if sid_arr.is_empty() {
        return Err(std::io::Error::other("reality: empty \"shortIds\""));
    }
    let mut short_ids = Vec::with_capacity(sid_arr.len());
    for (i, sid) in sid_arr.iter().enumerate() {
        let Some(hex) = sid.as_str() else {
            return Err(std::io::Error::other(format!(
                "reality: invalid \"shortIds[{i}]\" (need hex string)"
            )));
        };
        if hex.len() > 16 {
            return Err(std::io::Error::other(format!(
                "reality: too long \"shortIds[{i}]\": {hex}"
            )));
        }
        let bytes = hex::decode(hex).map_err(|_| {
            std::io::Error::other(format!("reality: invalid \"shortIds[{i}]\": {hex}"))
        })?;
        let mut id = [0u8; 8];
        id[..bytes.len()].copy_from_slice(&bytes);
        short_ids.push(id);
    }

    // dest/target：int（端口→localhost:port，Go uint16 边界）或字符串 host:port；
    // 缺省 localhost:443（Go conf 层 Dest==nil 跳过整块 target 配置，Rust 无
    // nil 表示——登记差异）。
    let dest_raw =
        json.get("target").or_else(|| json.get("dest")).cloned().unwrap_or(serde_json::Value::Null);
    let fallback_dest = match dest_raw.as_u64() {
        Some(port @ 0..=65_535) => format!("localhost:{port}"),
        Some(_) => {
            return Err(std::io::Error::other(
                "reality: invalid numeric \"target\" (need uint16 port)",
            ));
        },
        None => match dest_raw {
            serde_json::Value::String(s) => s,
            serde_json::Value::Null => "localhost:443".to_string(),
            _ => {
                return Err(std::io::Error::other(format!(
                    "reality: invalid \"target\": {dest_raw}"
                )));
            },
        },
    };

    // xver（Go transport_security.go:84-86）：仅 0/1/2；负数/非整数/越界
    // 一律拒启，不钳制。
    let xver = match json.get("xver") {
        None | Some(serde_json::Value::Null) => 0u8,
        Some(x) => match x.as_u64() {
            Some(n @ 0..=2) => n as u8,
            Some(_) => {
                return Err(std::io::Error::other(
                    "reality: invalid PROXY protocol version, \"xver\" only accepts 0, 1, 2",
                ));
            },
            None => {
                return Err(std::io::Error::other(
                    "reality: invalid \"xver\" (need unsigned integer)",
                ));
            },
        },
    };
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
    let max_diff_ms = json.get("maxTimeDiff").and_then(|x| x.as_u64()).unwrap_or(0);
    // 秒级 floor 除法逐字复现 Go 语义（reality tls.go:259
    // `time.Since(ClientTime).Abs() <= MaxTimeDiff`，ClientTime 为 Unix 秒）：
    // |Δt_秒 + 小数部分| ≤ N 毫秒 ⟺ 允许的整秒差恰为 {0..N/1000}（floor），
    // 进位（ceil）会放行 Go 拒绝的 N+1 秒差（wfx8-7 核对结论：floor 正确）。
    // try_from 防 u64→u32 静默回绕（异常巨值按"放行全部整秒差"的上界钳制）。
    let max_diff = u32::try_from(max_diff_ms / 1000).unwrap_or(u32::MAX);
    let parse_ver =
        |s: &str| -> Vec<u8> { s.split('.').filter_map(|p| p.trim().parse::<u8>().ok()).collect() };
    let min_client_ver =
        json.get("minClientVer").and_then(|x| x.as_str()).map(parse_ver).unwrap_or_default();
    let max_client_ver =
        json.get("maxClientVer").and_then(|x| x.as_str()).map(parse_ver).unwrap_or_default();

    // 票 037f：Go 有 Rust 无的 realitySettings 键——有意图值一律配置层硬错，
    // 不静默丢（对齐 bd 5std 惯例；关闭值/缺省放行，不破 Go 兼容配置）。
    // - show（transport_security.go:29）：REALITY 握手 debug 打印
    //   （transport/internet/reality/reality.go:102-285 fmt.Printf），Rust 无 等价 trace 点。非
    //   bool 类型手误按「已设置」拒（bd zl5t 惯例）。
    if let Some(v) = json.get("show") {
        match v {
            serde_json::Value::Null | serde_json::Value::Bool(false) => {},
            _ => {
                return Err(std::io::Error::other(
                    "reality: \"show\": true is not supported by this build (REALITY handshake \
                     debug tracing is not implemented); remove the key",
                ));
            },
        }
    }
    // - masterKeyLog（:28）：REALITY acceptor 无 NSS keylog 挂点
    //   （xray-reality::open_key_log_writer 无生产 caller）。空串/"none" = Go
    //   KeyLogWriterFromConfig 的关闭语义，放行。
    if let Some(v) = json.get("masterKeyLog") {
        let set = match v {
            serde_json::Value::Null => false,
            serde_json::Value::String(s) => !s.is_empty() && s != "none",
            _ => true,
        };
        if set {
            return Err(std::io::Error::other(
                "reality: \"masterKeyLog\" is not supported by this build (no keylog hook on \
                 the REALITY acceptor); remove the key (tlsSettings.masterKeyLog works for \
                 plain TLS)",
            ));
        }
    }
    // - limitFallbackUpload/Download（:42-43）：fallback 限速器未实现； 全零对象/缺省 = Go
    //   无限制语义，放行。
    for lf_key in ["limitFallbackUpload", "limitFallbackDownload"] {
        if let Some(v) = json.get(lf_key) {
            let active = v.as_object().is_some_and(|o| {
                ["afterBytes", "bytesPerSec", "burstBytesPerSec"]
                    .iter()
                    .any(|k| o.get(*k).and_then(|x| x.as_u64()).unwrap_or(0) > 0)
            });
            if active || (!v.is_null() && !v.is_object()) {
                return Err(std::io::Error::other(format!(
                    "reality: \"{lf_key}\" is not supported by this build (fallback rate \
                     limiting is not implemented); remove the key"
                )));
            }
        }
    }
    // - type（:32）与 unix 形态 target/dest（:68-84 '@'/'/' 前缀推导 unix， 含 Linux @@
    //   抽象套接字）：Rust reality fallback 拨号仅支持 host:port。
    if let Some(t) = json.get("type").and_then(|x| x.as_str()) {
        if !t.eq_ignore_ascii_case("tcp") {
            return Err(std::io::Error::other(format!(
                "reality: unsupported \"type\": {t} (only \"tcp\" fallback targets are \
                 implemented; unix targets are Go-only)"
            )));
        }
    }
    if fallback_dest.starts_with('@') || fallback_dest.starts_with('/') {
        return Err(std::io::Error::other(
            "reality: unix socket fallback targets are not implemented in this build \
             (target/dest starting with '@' or '/'); use a host:port target",
        ));
    }

    Ok(RealityInboundConfig {
        server_private_key: key,
        server_names,
        short_ids,
        max_diff,
        fallback_dest,
        xver,
        min_client_ver,
        max_client_ver,
        // bd frxi：realitySettings.maxUselessRecords 三态（缺省/true/数值）。
        max_useless_records: xray_reality::MaxUselessRecordsSetting::from_json(
            json.get("maxUselessRecords"),
        )
        .map_err(std::io::Error::other)?,
        // bd tce2：realitySettings.serverAcceptor（"rustls" 默认 / "btls" opt-in）。
        server_acceptor: xray_reality::ServerAcceptorSetting::from_json(json.get("serverAcceptor"))
            .map_err(std::io::Error::other)?,
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

/// VLESS + REALITY inbound：accept → server_tls 验证。
///
/// - Verified：TLS 流走 VLESS 协议处理
/// - Invalid：原连接 + ClientHello record fallback 到 dest（PROXY protocol xver）
pub(crate) async fn serve_reality_vless(
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

    // bd frxi：配置启用探测时，listener 启动即 spawn CCS tier + dest 记录
    // 长度两路探测写 ProbeTable（Go tcp/hub.go:79
    // `go goreality.DetectPostHandshakeRecordsLens(...)` 等价，Go 无条件跑；
    // Rust 侧 opt-in）。探测在后台进行，不阻塞 accept 循环；握手期经
    // ProbeContext 查表，未就绪/失败的 key 走配置 fallback。
    let probe_ctx = if cfg.max_useless_records.is_enabled() {
        let table = xray_reality::probe::ProbeTable::new();
        xray_reality::probe::detect_max_useless_records(
            table.clone(),
            cfg.fallback_dest.clone(),
            cfg.server_names.clone(),
            "tcp".to_string(),
            cfg.xver,
        );
        xray_reality::probe::detect_post_handshake_record_lens(
            table.clone(),
            cfg.fallback_dest.clone(),
            cfg.server_names.clone(),
            "tcp".to_string(),
            cfg.xver,
        );
        tracing::info!(dest = %cfg.fallback_dest, "reality maxUselessRecords probe started");
        Some(xray_reality::server::ProbeContext {
            table,
            dest: cfg.fallback_dest.clone(),
            fallback: cfg.max_useless_records,
        })
    } else {
        None
    };

    // tcpSettings.header 伪装头（Go hub.go:85-95 authConfig；reality 解包后应用，
    // hub.go:106-120）。无 header → None 零开销直通。
    let header = listener.header_auth().cloned();
    loop {
        // finalmask.tcp 在 accept 后立即套上（wire 最外层，reality 握手在其内）。
        let (stream, peer) = match listener.accept_masked().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "reality inbound accept failed");
                accept_fd_backoff(&e).await;
                continue;
            },
        };
        let handler = Arc::clone(&handler);
        let validator = Arc::clone(&validator);
        let options = options.clone();
        let header = header.clone();
        let key = cfg.server_private_key;
        let names = cfg.server_names.clone();
        let ids = cfg.short_ids.clone();
        let max_diff = cfg.max_diff;
        let dest = cfg.fallback_dest.clone();
        let xver = cfg.xver;
        let min_ver = cfg.min_client_ver.clone();
        let max_ver = cfg.max_client_ver.clone();
        let probe_ctx = probe_ctx.clone();
        // bd tce2：serverAcceptor="btls" 走 BoringSSL 握手（含 26zn 后握手记录
        // 模仿消费）；默认 rustls 路径行为不变。
        let use_btls = matches!(cfg.server_acceptor, xray_reality::ServerAcceptorSetting::Btls);
        // W4 面 6 步 2 / 面 5：vision 装配任务走受控逃逸口（台账
        // RedlineSite::VisionSpliceSpawn）；spawn 语义逐字等价，红线本体
        //（splice 装配三件套）零改动（坑约束 ⑫）。
        redline::spawn_unchecked(RedlineSite::VisionSpliceSpawn, async move {
            // bd e0ni/39824：vision splice 装配对齐 serve_vless 三件套——①accept
            // 后 dup 裸 TCP；②握手入口垫 RecordFramer（记录对齐读，「DIRECT 帧 +
            // 其后裸流」合流入站时裸尾留内核缓冲，不被 rustls deframer 拉走）；
            // ③raw 克隆传入 handle_vless_connection。缺任意一环：客户端 DIRECT
            // 帧后切裸 socket 直写（Go proxy.go switchToDirectCopy），服务端无
            // raw 通道 → 从 rustls 安全层读端到端明文 → AEAD open 失败 → fatal
            // bad_record_mac，隧道死。
            // mask 生效时 wire 字节非明文，裸 socket 克隆不可直接 splice → None
            // （splice 关闭，走常规 TLS 读；未配 finalmask 时与原路径逐字节一致）。
            let raw_tcp = stream.plain().and_then(xray_transport::connection::dup_tcp_stream);
            let framer = xray_transport::record_framer::RecordFramer::new(stream);
            let outcome = if use_btls {
                #[cfg(not(target_os = "ios"))]
                {
                    xray_reality::server::server_tls_btls(
                        framer,
                        &key,
                        &ids,
                        max_diff,
                        &min_ver,
                        &max_ver,
                        &names,
                        probe_ctx.as_ref(),
                    )
                    .await
                }
                #[cfg(target_os = "ios")]
                {
                    // iOS 无注入 FFI（配置解析层已拒 serverAcceptor=btls），
                    // 此处运行时防御性回落 rustls（零功能损失）。
                    server_tls(
                        framer,
                        &key,
                        &ids,
                        max_diff,
                        &min_ver,
                        &max_ver,
                        &names,
                        probe_ctx.as_ref(),
                    )
                    .await
                }
            } else {
                server_tls(
                    framer,
                    &key,
                    &ids,
                    max_diff,
                    &min_ver,
                    &max_ver,
                    &names,
                    probe_ctx.as_ref(),
                )
                .await
            };
            match outcome {
                Ok(RealityServerOutcome::Verified { tls, max_useless_records }) => {
                    // bd frxi：探测值随连接交付（Go tls.go:436 写 hs.c.MaxUselessRecords
                    // 由定制 BoringSSL record 循环消费；rustls 无 record 层消费点，
                    // mygg 后握手记录模仿落地前仅可观察）。
                    tracing::debug!(peer = %peer, max_useless_records, "reality verified with probe result");
                    // lwep（Go inbound.go:577-579）：REALITY 验证通过即 rustls TLS1.3，
                    // XRV 的外层 TLS1.3 门恒真。
                    let mut options = options;
                    if let Some(o) = options.as_mut() {
                        o.outer_tls13 = true;
                    }
                    // Go hub.go:106-120：authConfig.Server 套在 reality 解包之后
                    // （伪装头消费在 TLS 隧道内、协议层之前）。
                    let io =
                        xray_transport::headers::conn::maybe_wrap_server(tls, header.as_deref());
                    if let Err(e) = xray_proxy_vless::handle_vless_connection(
                        io,
                        &handler,
                        &validator,
                        options.clone(),
                        raw_tcp,
                    )
                    .await
                    {
                        // Go vless inbound.go:522：拒绝 AtInfo + RemoteAddr。
                        tracing::info!(peer = %peer, error = %e, "reality vless connection ended with error");
                    }
                },
                Ok(RealityServerOutcome::Invalid { conn, record, reason }) => {
                    // 非 REALITY 客户端（如浏览器/探测器）→ 透明转发到 fallback dest
                    tracing::debug!(error = ?reason, dest = %dest, "reality verify failed, fallback");
                    let _ = fallback_to_dest(conn, &record, &dest, peer, local, xver).await;
                },
                Err(e) => {
                    tracing::warn!(error = ?e, "reality tls handshake error");
                },
            }
        });
    }
}

/// Trojan + REALITY inbound：accept → server_tls 验证。
///
/// - Verified：REALITY TLS 流走 Trojan 协议处理（`serve_trojan_conn`）
/// - Invalid：原连接 + ClientHello record fallback 到 dest（PROXY protocol xver）
///
/// 对齐 Go：trojan inbound 的 `iConn` 已是 `*reality.Conn`（transport 层包装，
/// server.go:378-382 经 `realityConn.ConnectionState()` 取 SNI/ALPN 供
/// fallback 匹配）。Rust 侧 REALITY 验证在 inbound 层完成（tcp hub 不包装
/// security），`RealityTlsStream` 暂无 SNI/ALPN 查询口，`tls_name`/`tls_alpn`
/// 传空——与 transport 分支 `serve_trojan_conn` 调用点既有行为一致。
///
/// 此前的缺陷（39436 战役）：trojan 分支 `security=reality` 误走
/// `build_tls_acceptor` → 标准 rustls（自签证书）而非 REALITY——客户端
/// REALITY 证书校验必败（"received real certificate"），握手后服务端把
/// TLS record 当裸 trojan header 读，`failed to read user hash: peer closed`。
pub(crate) async fn serve_reality_trojan(
    listener: InboundTcpListener,
    ohm: Arc<SimpleOhm>,
    users: HashMap<String, TrojanMemoryUser>,
    fb_policy: Option<Arc<FallbackPolicy>>,
    cfg: RealityInboundConfig,
    handshake_timeout: std::time::Duration,
) -> std::io::Result<()> {
    use xray_reality::server::{RealityServerOutcome, fallback_to_dest, server_tls};

    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;
    let local = listener.local_addr()?;
    tracing::info!(addr = %local, users = users.len(), "trojan+reality inbound listening");

    let validator = Arc::new(xray_proxy_trojan::Validator::new());
    for (_, user) in users {
        if let Err(e) = validator.add(user) {
            tracing::warn!(error = %e, "skip duplicate user during trojan+reality inbound init");
        }
    }

    // bd frxi：探测上下文（Go tcp/hub.go:79 无条件跑，Rust 侧 opt-in）；
    // 与 serve_reality_vless 同构，probe 结果随连接交付。
    let probe_ctx = if cfg.max_useless_records.is_enabled() {
        let table = xray_reality::probe::ProbeTable::new();
        xray_reality::probe::detect_max_useless_records(
            table.clone(),
            cfg.fallback_dest.clone(),
            cfg.server_names.clone(),
            "tcp".to_string(),
            cfg.xver,
        );
        xray_reality::probe::detect_post_handshake_record_lens(
            table.clone(),
            cfg.fallback_dest.clone(),
            cfg.server_names.clone(),
            "tcp".to_string(),
            cfg.xver,
        );
        tracing::info!(dest = %cfg.fallback_dest, "reality maxUselessRecords probe started");
        Some(xray_reality::server::ProbeContext {
            table,
            dest: cfg.fallback_dest.clone(),
            fallback: cfg.max_useless_records,
        })
    } else {
        None
    };

    // tcpSettings.header 伪装头（Go hub.go:85-95 authConfig；reality 解包后应用，
    // hub.go:106-120）。无 header → None 零开销直通。
    let header = listener.header_auth().cloned();
    loop {
        // finalmask.tcp 在 accept 后立即套上（wire 最外层，reality 握手在其内）。
        let (stream, peer) = match listener.accept_masked().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "trojan+reality inbound accept failed");
                accept_fd_backoff(&e).await;
                continue;
            },
        };
        let handler = Arc::clone(&handler);
        let validator = Arc::clone(&validator);
        let fb_policy = fb_policy.clone();
        let header = header.clone();
        let key = cfg.server_private_key;
        let names = cfg.server_names.clone();
        let ids = cfg.short_ids.clone();
        let max_diff = cfg.max_diff;
        let dest = cfg.fallback_dest.clone();
        let xver = cfg.xver;
        let min_ver = cfg.min_client_ver.clone();
        let max_ver = cfg.max_client_ver.clone();
        let probe_ctx = probe_ctx.clone();
        let use_btls = matches!(cfg.server_acceptor, xray_reality::ServerAcceptorSetting::Btls);
        // W4 面 6 步 2 / 面 5：vision 装配任务走受控逃逸口（台账
        // RedlineSite::VisionSpliceSpawn）；spawn 语义逐字等价，红线本体零改动。
        redline::spawn_unchecked(RedlineSite::VisionSpliceSpawn, async move {
            let outcome = if use_btls {
                #[cfg(not(target_os = "ios"))]
                {
                    xray_reality::server::server_tls_btls(
                        stream,
                        &key,
                        &ids,
                        max_diff,
                        &min_ver,
                        &max_ver,
                        &names,
                        probe_ctx.as_ref(),
                    )
                    .await
                }
                #[cfg(target_os = "ios")]
                {
                    // iOS 无注入 FFI（配置解析层已拒 serverAcceptor=btls），
                    // 此处运行时防御性回落 rustls（零功能损失）。
                    server_tls(
                        stream,
                        &key,
                        &ids,
                        max_diff,
                        &min_ver,
                        &max_ver,
                        &names,
                        probe_ctx.as_ref(),
                    )
                    .await
                }
            } else {
                server_tls(
                    stream,
                    &key,
                    &ids,
                    max_diff,
                    &min_ver,
                    &max_ver,
                    &names,
                    probe_ctx.as_ref(),
                )
                .await
            };
            match outcome {
                Ok(RealityServerOutcome::Verified { tls, .. }) => {
                    // Go hub.go:106-120：authConfig.Server 套在 reality 解包之后
                    // （伪装头消费在 TLS 隧道内、协议层之前）。
                    let io =
                        xray_transport::headers::conn::maybe_wrap_server(tls, header.as_deref());
                    xray_proxy_trojan::serve_trojan_conn(
                        io,
                        validator,
                        handler,
                        fb_policy,
                        peer,
                        local,
                        String::new(),
                        String::new(),
                        handshake_timeout,
                    )
                    .await;
                },
                Ok(RealityServerOutcome::Invalid { conn, record, reason }) => {
                    // 非 REALITY 客户端（浏览器/探测器）→ 透明转发到 fallback dest
                    tracing::debug!(error = ?reason, dest = %dest, "trojan+reality verify failed, fallback");
                    let _ = fallback_to_dest(conn, &record, &dest, peer, local, xver).await;
                },
                Err(e) => {
                    tracing::warn!(error = ?e, "trojan+reality tls handshake error");
                },
            }
        });
    }
}

/// settings.protocol 是否由 transport listener 承载（非裸 TCP）。
///
/// 对应 Go `tcp_hub.go::ListenTCP` 按 protocolName 查注册表；`tcp`/`raw`
/// 走既有 serve_* 直连路径（TLS accept + fallback SNI/ALPN 提取在该层完成）。
/// 别名表与 `xray_transport::dialer::protocol_settings_key` 一致。
pub(crate) fn is_transport_listener_protocol(protocol: &str) -> bool {
    matches!(
        protocol,
        "ws" | "websocket"
            | "grpc"
            | "h2"
            | "http"
            | "kcp"
            | "mkcp"
            | "httpupgrade"
            | "splithttp"
            | "xhttp"
    )
}

/// 裸 TCP 入站的 `finalmask.tcp` 伪装链（Go `tcp/hub.go` WrapListener）。
///
/// 未配置 / `tcp` 空数组 → `None`：listener 不注入 mask，accept 路径零包装。
///
/// # Errors
/// mask 配置非法（未知类型 / xmc 派生失败等）时返回 `io::Error`——启动即失败，
/// 与 Go 配置构建期报错一致（不做静默降级）。
pub(crate) fn inbound_tcpmask(
    settings: &xray_transport::dialer::StreamSettings,
) -> std::io::Result<Option<Arc<xray_transport::finalmask::TcpmaskManager>>> {
    let mgr = xray_transport::finalmask::build_tcpmask_manager_from_json(
        settings.finalmask_json.as_ref(),
    )?;
    Ok((!mgr.tcpmasks.is_empty()).then(|| Arc::new(mgr)))
}

/// UDP relay 入站的 `finalmask.udp` 伪装链（bd 05js，Go udp/hub.go:61-62
/// `FinalMask.ListenPacket`：UdpHub/裸 socket 在 recv/send 两侧逐包包装）。
///
/// 未配置 / `udp` 空数组 → `None`：零包装，行为不变。
///
/// # Errors
/// mask 配置非法时返回 `io::Error`——启动即失败，与 Go 一致（不静默降级）。
pub(crate) fn inbound_udpmask(
    settings: &xray_transport::dialer::StreamSettings,
) -> std::io::Result<Option<xray_transport::finalmask::UdpmaskManager>> {
    let mgr = xray_transport::finalmask::build_udpmask_manager_from_json(
        settings.finalmask_json.as_ref(),
    )?;
    Ok((!mgr.udpmasks.is_empty()).then_some(mgr))
}

/// 经 listener_registry 启动 transport inbound（ws/grpc/kcp/httpupgrade/splithttp）。
///
/// 对应 Go `proxyman` worker 对 `internet.ListenTCP` 的调用：TLS/security
/// 由 transport hub 内部完成（grpc/ws hub 自带 accept_tls），上层 ConnHandler
/// 收到的已是协议解包后的明文 conn。listener 移入 pending future 保活，
/// shutdown abort 时随 task drop。
pub(crate) async fn spawn_transport_listener_inbound(
    arm: &Arc<PluginContext>,
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
    Ok(Some(spawn_inbound_serve(arm, tag.to_string(), shutdown_token, async move {
        let _listener = listener;
        std::future::pending::<()>().await;
        Ok(())
    })))
}

/// `Box<dyn Connection>` 的 peer/local 地址（transport 解包层丢失时用 bind 地址兜底）。
pub(crate) fn transport_conn_addrs(
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
pub(crate) fn handshake_timeout_for(
    policy: &Option<std::sync::Arc<dyn xray_features::policy::PolicyManager>>,
    level: u32,
) -> std::time::Duration {
    policy
        .as_ref()
        .map(|pm| pm.policy_for_level(level).timeout.handshake)
        .unwrap_or(DEFAULT_HANDSHAKE_TIMEOUT)
}

/// 把 ss inbound 的 validator 登记进 gRPC 用户管理面。
///
/// shortcut: 仅 legacy AEAD 模式（用户表可增删查）；ss2022 单/多用户/中继模式的
/// 用户面未接线，gRPC 用户操作按 `NotUserManager` 明确拒绝。
pub(crate) fn register_ss_user_manager(
    api: Option<&InboundRuntime>,
    tag: &str,
    mode: &SsInboundMode,
) {
    let (Some(api), SsInboundMode::Legacy(ss)) = (api, mode) else {
        return;
    };
    api.register_user_manager(tag, Arc::new(SsUserManager(Arc::clone(ss))));
}

/// 按协议种类启动单个 inbound listener。
///
/// `api` 非 None 时把协议侧用户管理器登记进 [`InboundRuntime`]（gRPC
/// AlterInbound/GetInboundUsers 才有的动态用户面）。
pub(crate) async fn spawn_one_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
    policy: Option<Arc<dyn xray_features::policy::PolicyManager>>,
    shutdown_token: CancellationToken,
    api: Option<&InboundRuntime>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    // TUN inbound 不需要 port/addr，提前处理
    // Windows 侧设备（tun-rs wintun）、netstack（smoltcp）、路由/DNS（sysroute）、
    // WFP 泄漏阻断均已实现并真机验证（bd cv3w/ijn7），故与 Go `tun_windows.go` 对齐开放。
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "windows"
    ))]
    if ib.entry.kind.as_str() == "tun" {
        let options = parse_tun_inbound_config(&ib.entry.data)?;
        let dispatch = ohm.get_default_handler().ok_or_else(|| {
            std::io::Error::other("tun inbound requires a default outbound handler")
        })?;
        let handler = TunInboundHandler::new(&ib.tag, options, dispatch)
            .await
            .map_err(|e| std::io::Error::other(format!("tun inbound: {e}")))?;
        tracing::info!(tag = %ib.tag, "tun inbound listening");
        // W4 面 6 例外登记（方案 §2 面 6「不可迁残余 1」）：本函数对外**返回
        // JoinHandle**（调用方 InboundRuntime 契约），改为 scope 托管 = 改公开
        // 契约 + 4 平台门控臂（linux/android/freebsd/windows），收益（1 处 spawn
        // 记账）远小于风险 → 保留裸 spawn，逐点理由登记。
        #[allow(
            clippy::disallowed_methods,
            reason = "tun inbound serve 对外返回 JoinHandle（公开契约 + 4 平台门控），改 scope 托管 = 改公开契约；方案 §2 面 6 不可迁残余 1 已举证保留"
        )]
        let handle = tokio::spawn(async move {
            if let Err(e) = handler.start().await {
                tracing::error!(error = ?e, "tun inbound stopped");
            }
        });
        return Ok(Some(handle));
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "windows"
    )))]
    if ib.entry.kind.as_str() == "tun" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TUN inbound is only supported on Linux/Android/FreeBSD/Windows",
        ));
    }
    // sockopt 数值/类型启动期硬错（Go 解码期语义；tcp/unix 监听分支共用）。
    xray_transport::dialer::StreamSettings::validate_sockopt_json(
        ib.stream_settings_json.as_ref(),
    )?;

    let listen = ib.listen.as_deref().unwrap_or("0.0.0.0");
    // vodx：unix 路径监听（Go system_listener.go:118 UnixAddr 分支）走 UDS
    // listener；端口语义不适用，须在 port 解析前分派。判别与 xray-conf
    // Address::is_unix_path 一致（'/' 绝对路径 / '@' abstract）。
    if is_unix_listen_path(listen) {
        return spawn_unix_inbound(ib, ohm, policy, shutdown_token, listen, api).await;
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
        },
    };
    let addr = parse_listen_addr(listen, port)?.to_string();
    // e7le/finalmask.tcp：入站 sockopt 与 tcpmask 装配随臂构造逻辑迁入
    // arm_builders::inbound（各 builder 内 settings.socket_options() 同值）。
    let settings =
        xray_transport::dialer::StreamSettings::from_json(ib.stream_settings_json.as_ref());

    // T4.2 phase 4 / W1-1a：构造走 xray-frame PluginRegistry（唯一路径，旧 match
    // 已删）。注册表值转发 phase 1 同一构造函数；未命中 = 未支持协议，显式 warn
    // 跳过（不静默构造）。
    if let Some(builder) = crate::arm_registry::lookup_inbound_builder(ib.entry.kind.as_str()) {
        // bd a9xgp：宿主 arm scope 登记表注入（停机级联；api 缺省 = 独立/测试
        // 构造，不接线，级联由 token 监视 + Drop 兜底）。
        let mut plugin_ctx = crate::arm_builders::arm_plugin_ctx(ib.entry.kind.as_str());
        if let Some(api) = api {
            plugin_ctx = plugin_ctx.with_arm_registry(Arc::clone(api.arm_scopes()));
        }
        return builder(crate::arm_builders::InboundCtx {
            ib,
            ohm,
            policy,
            shutdown_token,
            addr: &addr,
            settings: &settings,
            api,
            plugin_ctx,
        })
        .await;
    }
    tracing::warn!(
        tag = %ib.tag,
        protocol = %ib.entry.kind,
        "inbound protocol not yet supported, skipping"
    );
    Ok(None)
}

/// listen 地址是否为 unix domain socket 路径。
///
/// 判别与 `xray_conf` `Address::is_unix_path` 一致：`/` 开头为文件系统路径，
/// `@` 开头为 Linux abstract socket。
fn is_unix_listen_path(listen: &str) -> bool {
    listen.starts_with('/') || listen.starts_with('@')
}

/// 入站 listen 地址归一化为 [`SocketAddr`]（Go 语义对齐：infra/conf xray.go:144
/// anyip 分支 + port 恒取 inbound.port 字段）。
///
/// - `""` / `"::"` → `[::]:port`（IPv6 any，Linux 默认双栈）
/// - `"0.0.0.0"` → `0.0.0.0:port`（IPv4 any）
/// - 已是合法 SocketAddr（含端口）→ 直用
/// - 其余先按裸 IP 补端口（IPv6 加方括号），再按 `{addr}:{port}` 字面兜底；
///   全失败报错（错误信息保留原文）。
fn parse_listen_addr(addr: &str, port: u16) -> std::io::Result<SocketAddr> {
    let addr = addr.trim();
    if addr.is_empty() || addr == "::" {
        return Ok(SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), port));
    }
    if addr == "0.0.0.0" {
        return Ok(SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), port));
    }
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok(sa);
    }
    // 裸 IPv6 须加方括号：字面拼接 "::1:18923" 会被解析器当作整体 IPv6 拒绝。
    let candidate = if addr.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{addr}]:{port}")
    } else {
        format!("{addr}:{port}")
    };
    candidate.parse().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("parse listen addr {addr:?}: {e}"),
        )
    })
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
                accept_fd_backoff(&e).await;
            },
        }
    }
}

/// unix 路径 inbound：UDS listener + UnixConnection accept（bd vodx）。
///
/// 对应 Go `DefaultListener.Listen` 的 `*net.UnixAddr` 分支
/// （transport/internet/system_listener.go:118）。Go 侧 TCP 类代理经
/// `net.Conn` 抽象天然支持 UDS。
///
/// transport 协议（ws/grpc/kcp/…）经 [`spawn_unix_transport_inbound`] 分派到
/// listener_registry unix 注册表，security 同 TCP 路径一样由 hub 内部完成。
/// 裸 TCP 协议的 serve 层为 TcpStream 特化，仅接线已有泛型/`Connection`
/// 入口的协议（socks/vless/vmess/trojan/ss），其余显式报错；该 serve 栈无
/// TLS accept 层，security=tls/reality 在此形态不可行——只对该形态显式报
/// 错（Go unix listen 可包 TLS 的语义由 hub 路径提供）。
#[cfg(unix)]
async fn spawn_unix_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
    policy: Option<Arc<dyn xray_features::policy::PolicyManager>>,
    shutdown_token: CancellationToken,
    listen: &str,
    api: Option<&InboundRuntime>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    use xray_transport::system_listener::listen_unix_system;

    // L2 能力句柄：UDS 分支与 transport 分支同源（arm_plugin_ctx 派发点构造）。
    // bd a9xgp：宿主登记表接线（api 缺省 = 独立构造不接线）。
    let mut ctx_builder = crate::arm_builders::arm_plugin_ctx(ib.entry.kind.as_str());
    if let Some(api) = api {
        ctx_builder = ctx_builder.with_arm_registry(Arc::clone(api.arm_scopes()));
    }
    let plugin_ctx = std::sync::Arc::new(ctx_builder);
    // 各协议 arm 的 `move` 闭包会把 plugin_ctx 搬走；末尾 spawn_inbound_serve
    // 仍需一句柄（同一 PluginContext 实例）→ 提前留一份克隆
    // （E0382：Unix 构建红点，Windows 编译不到本函数故本地不复现）。
    let serve_ctx = Arc::clone(&plugin_ctx);
    let settings =
        xray_transport::dialer::StreamSettings::from_json(ib.stream_settings_json.as_ref());
    if is_transport_listener_protocol(&settings.protocol) {
        return spawn_unix_transport_inbound(
            ib,
            ohm,
            policy,
            shutdown_token,
            listen,
            settings,
            api,
        )
        .await;
    }
    match settings.security.as_str() {
        "" | "none" => {},
        other => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!(
                    "uds inbound '{}': security='{other}' not supported over unix socket",
                    ib.tag
                ),
            ));
        },
    }
    // 协议支持矩阵前置：不支持 UDS 的协议在 bind 前显式报错（fail-fast，
    // 对齐 Go inbound 创建失败即启动失败的语义）。
    const UDS_SUPPORTED_PROTOCOLS: &[&str] = &["socks", "vless", "vmess", "trojan", "shadowsocks"];
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
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;
    // UDS 无 SocketAddr；对齐 Go UnixConnWrapper.RemoteAddr 的 0.0.0.0:0。
    let unspecified = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

    let serve: std::pin::Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>> = match ib
        .entry
        .kind
        .as_str()
    {
        "socks" => {
            let config = Arc::new(parse_socks_server_config(&ib.entry.data)?);
            let handshake_timeout = Some(handshake_timeout_for(&policy, config.user_level));
            let udp_idle = policy
                .as_ref()
                .map(|pm| pm.policy_for_level(config.user_level).timeout.connection_idle)
                .unwrap_or(xray_features::policy::TimeoutPolicy::default().connection_idle);
            Box::pin(serve_unix_listener(listener, {
                let handler = Arc::clone(&handler);
                Arc::new(move |conn| {
                    let handler = Arc::clone(&handler);
                    let config = Arc::clone(&config);
                    // scope 生命周期锚：连接任务存活期间 arm scope 不 drop
                    let task_ctx = Arc::clone(&plugin_ctx);
                    let conn_ctx = Arc::clone(&plugin_ctx);
                    plugin_ctx
                        .spawn(async move {
                            let _ctx = task_ctx;
                            let peer = conn.remote_addr().ok().flatten().unwrap_or(unspecified);
                            if let Err(e) = handle_connection(
                                conn,
                                peer,
                                &config,
                                &handler,
                                handshake_timeout,
                                udp_idle,
                                conn_ctx,
                            )
                            .await
                            {
                                tracing::info!(
                                    peer = %peer,
                                    error = %e,
                                    "socks5 (uds) connection ended with error"
                                );
                            }
                        })
                        .expect("arm FxScope is never closed");
                })
            }))
        },
        "vless" => {
            let validator: Arc<dyn VlessValidator> = build_vless_validator(&ib.entry.data)?;
            let decryption = build_vless_decryption(&ib.entry.data, plugin_ctx.clone())?;
            let options =
                VlessInboundOptions { decryption: decryption.clone(), ..Default::default() };
            let fallbacks = build_vless_fallbacks(&ib.entry.data)?;
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
                    // scope 生命周期锚：连接任务存活期间 arm scope 不 drop
                    let task_ctx = Arc::clone(&plugin_ctx);
                    plugin_ctx
                        .spawn(async move {
                            let _ctx = task_ctx;
                            let (peer, local) = transport_conn_addrs(conn.as_ref(), unspecified);
                            if let Err(e) = xray_proxy_vless::handle_connection_with_fallback(
                                conn,
                                &handler,
                                &validator,
                                fallbacks,
                                peer,
                                local,
                                String::new(),
                                String::new(),
                                Some(options),
                                None,
                            )
                            .await
                            {
                                tracing::info!(
                                    peer = %peer,
                                    error = %e,
                                    "vless (uds) connection ended with error"
                                );
                            }
                        })
                        .expect("arm FxScope is never closed");
                })
            }))
        },
        "vmess" => {
            let validator = build_vmess_validator(&ib.entry.data)?;
            let history = Arc::new(xray_proxy_vmess::SessionHistory::new());
            // security 已 gate 为 none → 与裸 TCP 分支同为 drain 语义。
            let is_drain = !settings.is_tls();
            tracing::info!(tag = %ib.tag, "vmess (uds) inbound listening");
            let hs_timeout = handshake_timeout_for(&policy, 0);
            Box::pin(serve_unix_listener(listener, {
                let handler = Arc::clone(&handler);
                Arc::new(move |conn| {
                    let handler = Arc::clone(&handler);
                    let validator = Arc::clone(&validator);
                    let history = Arc::clone(&history);
                    // scope 生命周期锚：连接任务存活期间 arm scope 不 drop
                    let task_ctx = Arc::clone(&plugin_ctx);
                    plugin_ctx
                        .spawn(async move {
                            let _ctx = task_ctx;
                            let (peer, _local) = transport_conn_addrs(conn.as_ref(), unspecified);
                            if let Err(e) = xray_proxy_vmess::handle_vmess_connection(
                                conn, &handler, &validator, &history, is_drain, hs_timeout,
                            )
                            .await
                            {
                                tracing::info!(
                                    peer = %peer,
                                    error = %e,
                                    "vmess (uds) connection ended with error"
                                );
                            }
                        })
                        .expect("arm FxScope is never closed");
                })
            }))
        },
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
            let hs_timeout = handshake_timeout_for(&policy, 0);
            Box::pin(serve_unix_listener(listener, {
                let handler = Arc::clone(&handler);
                Arc::new(move |conn| {
                    let handler = Arc::clone(&handler);
                    let validator = Arc::clone(&validator);
                    let fallbacks = fallbacks.clone();
                    // scope 生命周期锚：连接任务存活期间 arm scope 不 drop
                    let task_ctx = Arc::clone(&plugin_ctx);
                    plugin_ctx
                        .spawn(async move {
                            let _ctx = task_ctx;
                            let (peer, local) = transport_conn_addrs(conn.as_ref(), unspecified);
                            xray_proxy_trojan::serve_trojan_conn(
                                conn,
                                validator,
                                handler,
                                fallbacks,
                                peer,
                                local,
                                String::new(),
                                String::new(),
                                hs_timeout,
                            )
                            .await;
                        })
                        .expect("arm FxScope is never closed");
                })
            }))
        },
        "shadowsocks" => {
            let inbound = match parse_ss_inbound_config(&ib.entry.data)? {
                SsInboundMode::Legacy(ss_ib) => ss_ib,
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        format!("uds inbound '{}': ss2022 not supported over unix socket", ib.tag),
                    ));
                },
            };
            tracing::info!(tag = %ib.tag, "shadowsocks (uds) inbound listening");
            Box::pin(serve_unix_listener(listener, {
                let handler = Arc::clone(&handler);
                Arc::new(move |conn| {
                    let handler = Arc::clone(&handler);
                    let inbound = Arc::clone(&inbound);
                    let hs_timeout = handshake_timeout_for(&policy, 0);
                    // scope 生命周期锚：连接任务存活期间 arm scope 不 drop
                    let task_ctx = Arc::clone(&plugin_ctx);
                    plugin_ctx
                        .spawn(async move {
                            let _ctx = Arc::clone(&task_ctx);
                            ss_legacy_pipeline(
                                inbound,
                                handler,
                                conn,
                                hs_timeout,
                                Arc::clone(&task_ctx),
                            )
                            .await;
                        })
                        .expect("arm FxScope is never closed");
                })
            }))
        },
        _ => unreachable!("uds protocol support checked above"),
    };

    Ok(Some(spawn_inbound_serve(&serve_ctx, ib.tag.clone(), shutdown_token, serve)))
}

/// transport 协议 + unix 路径 inbound（bd lfrg 收尾）。
///
/// 对应 Go `tcp_hub.go::ListenUnix`（:31-50）：unix listen 后 security 仍由
/// transport hub 内部完成（`build_tls_config`/accept 循环与 TCP 监听共用同一
/// 份代码，TLS 同样可包，以 Go 为准不设「security != none 即拒」门）；on_conn
/// 复用 [`crate::arm_builders::inbound`] 各协议 transport 分支的唯一构造。
/// listener 移入 pending future 保活（与 [`spawn_transport_listener_inbound`]
/// 同骨架），shutdown abort 时随 task drop。
///
/// 协议覆盖 = arm_builders 有 transport 分支的四种 inbound（vless/trojan/
/// vmess/shadowsocks）；其余 kind 显式 Unsupported。未注册 unix 监听的
/// transport 协议（如 kcp）由 listener_registry 报 Go 对齐的 NotFound。
#[cfg(unix)]
async fn spawn_unix_transport_inbound(
    ib: &BuiltInbound,
    ohm: Arc<SimpleOhm>,
    policy: Option<Arc<dyn xray_features::policy::PolicyManager>>,
    shutdown_token: CancellationToken,
    listen: &str,
    settings: xray_transport::dialer::StreamSettings,
    api: Option<&InboundRuntime>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    use crate::arm_builders::inbound::{
        ss_transport_on_conn, trojan_transport_on_conn, vless_transport_on_conn,
        vmess_transport_on_conn,
    };

    // UDS 无 SocketAddr；对齐 Go UnixConnWrapper.RemoteAddr 的 0.0.0.0:0。
    let fallback_addr = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
    let on_conn = match ib.entry.kind.as_str() {
        "vless" => {
            let validator: Arc<dyn VlessValidator> = build_vless_validator(&ib.entry.data)?;
            // L2 能力句柄：与 spawn_unix_inbound 同源（arm_plugin_ctx 派发点构造）。
            // bd a9xgp：宿主登记表接线（api 缺省 = 独立构造不接线）。
            let mut ctx_builder = crate::arm_builders::arm_plugin_ctx(ib.entry.kind.as_str());
            if let Some(api) = api {
                ctx_builder = ctx_builder.with_arm_registry(Arc::clone(api.arm_scopes()));
            }
            let plugin_ctx = std::sync::Arc::new(ctx_builder);
            let decryption = build_vless_decryption(&ib.entry.data, plugin_ctx)?;
            let options = VlessInboundOptions {
                decryption: decryption.clone(),
                handshake_timeout: Some(handshake_timeout_for(&policy, 0)),
                ..Default::default()
            };
            vless_transport_on_conn(ib, &ohm, &settings, validator, options, fallback_addr, listen)
        },
        "trojan" => {
            let users = build_trojan_users(&ib.entry.data)?;
            let fallbacks = build_trojan_fallbacks(&ib.entry.data)?;
            trojan_transport_on_conn(
                ib,
                &ohm,
                &policy,
                &settings,
                users,
                fallbacks,
                fallback_addr,
                listen,
            )
        },
        "vmess" => {
            let validator = build_vmess_validator(&ib.entry.data)?;
            vmess_transport_on_conn(ib, &ohm, &policy, &settings, validator, fallback_addr, listen)
        },
        "shadowsocks" => ss_transport_on_conn(ib, &ohm, &policy, api, &settings, listen),
        other => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "uds inbound '{}': transport protocol '{}' not supported for inbound kind '{other}' over unix socket",
                ib.tag, settings.protocol
            ),
        )),
    }?;
    // sockopt 先取（trustedXForwardedFor 等，Go socketSettings 对 unix 分支
    // 同样生效）；settings 随后移入 registry。
    let sockopt = settings.socket_options();
    let listener =
        xray_transport::listener_registry::listen_unix(listen, settings, sockopt, on_conn).await?;
    tracing::info!(tag = %ib.tag, path = %listen, "transport inbound listening (unix)");
    // L2 能力句柄：监听保活任务同 transport 分支同源（arm_plugin_ctx 派发点构造）。
    // bd a9xgp：宿主登记表接线（api 缺省 = 独立构造不接线）。
    let mut ctx_builder = crate::arm_builders::arm_plugin_ctx(ib.entry.kind.as_str());
    if let Some(api) = api {
        ctx_builder = ctx_builder.with_arm_registry(Arc::clone(api.arm_scopes()));
    }
    let arm_ctx = std::sync::Arc::new(ctx_builder);
    Ok(Some(spawn_inbound_serve(&arm_ctx, ib.tag.clone(), shutdown_token, async move {
        let _listener = listener;
        std::future::pending::<()>().await;
        Ok(())
    })))
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
    api: Option<&InboundRuntime>,
) -> std::io::Result<Option<JoinHandle<()>>> {
    let _ = (ohm, policy, shutdown_token, listen, api);
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!("unix socket inbound '{}' is only supported on unix platforms", ib.tag),
    ))
}

/// 从 inbound entry.data（JSON）解析 SOCKS 服务端配置。
///
/// 字段对齐 Go `infra/conf/socks.go::SocksServerConfig`：
/// `{"auth":"password","users":[{"user":"u","pass":"p"}],"udp":true,"userLevel":0}`。
/// `users`/`accounts` 同义（Go 两个字段都收）；`ip`（Go `Host`，UDP relay 绑定
/// 地址，`xray-proxy-socks` UDP ASSOCIATE 消费）解析为 proto `IPOrDomain`。
/// `pub(crate)`：P3-2 对拍测试（tests_config_parity）跨模块消费，语义零变化。
pub(crate) fn parse_socks_server_config(data: &[u8]) -> std::io::Result<ServerConfig> {
    if data.is_empty() {
        return Ok(ServerConfig::default());
    }
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("socks inbound settings JSON: {e}")))?;

    let mut cfg = ServerConfig::default();
    if v.get("auth").and_then(|x| x.as_str()) == Some("password") {
        cfg.auth_type = xray_proxy_socks::config::AuthType::Password;
    }
    // accounts 在场则覆盖 users（Go socks.go:54-56 `if v.Accounts != nil`——
    // 与 Go 相反的旧优先级 users→accounts 已修正）。
    if let Some(users) = v.get("accounts").or_else(|| v.get("users")).and_then(|x| x.as_array()) {
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

/// JSON 格式：`{"clients":[{"id":"uuid","flow":"","email":""}],"decryption":"none"}`。
/// 对每个 client 构造最小 `ProtoAccount`（id+flow+encryption=none）→
/// `MemoryAccount::from_proto_account`。
pub(crate) fn build_vless_validator(
    data: &[u8],
) -> std::io::Result<std::sync::Arc<dyn VlessValidator>> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("vless inbound settings JSON: {e}")))?;
    let validator = VlessMemoryValidator::new();
    // settings 级 flow 校验（Go infra/conf/vless.go:57-73 XRV）：仅空 /
    // xtls-rprx-vision 合法，非法值整 inbound 拒启；空值作为 client 缺省继承。
    let settings_flow = v.get("flow").and_then(|x| x.as_str()).unwrap_or("");
    if !settings_flow.is_empty() && settings_flow != xray_proxy_vless::FLOW_XRV {
        return Err(std::io::Error::other(format!(
            "VLESS \"settings.flow\" doesn't support \"{settings_flow}\" in this version"
        )));
    }
    // settings 级 testseed（Go VLessInboundConfig.Testseed，json `testseed`）。
    let cfg_testseed: Vec<u32> = v
        .get("testseed")
        .and_then(|s| s.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_u64().map(|n| n as u32)).collect::<Vec<u32>>())
        .unwrap_or_default();
    fn user_testseed(c: &serde_json::Value) -> Vec<u32> {
        c.get("testseed")
            .and_then(|s| s.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_u64().map(|n| n as u32)).collect::<Vec<u32>>())
            .unwrap_or_default()
    }
    // users/clients 双读（FieldAudit P1：Go vless.go:46-48 `if c.Clients != nil
    // { c.Users = c.Clients }`——clients 键在场（非 null，含空数组）完全覆盖
    // users，否则 users 为合法别名。生产 xr.json 全部 users 形态，只读 clients
    // → 0 用户全拒）。
    let client_list = v
        .get("clients")
        .filter(|c| !c.is_null())
        .or_else(|| v.get("users"))
        .and_then(|c| c.as_array());
    if let Some(clients) = client_list {
        for c in clients {
            let id = c.get("id").and_then(|x| x.as_str()).unwrap_or("");
            let email = c.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let level = c.get("level").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
            // client 级 flow（Go vless.go:71-78）：空则继承 settings.flow，
            // 非空非法拒启（vision 静默降级根除）。
            let flow = match c.get("flow").and_then(|x| x.as_str()).unwrap_or("") {
                "" => settings_flow.to_string(),
                f if f == xray_proxy_vless::FLOW_XRV => f.to_string(),
                f => {
                    return Err(std::io::Error::other(format!(
                        "VLESS users: \"flow\" doesn't support \"{f}\" in this version"
                    )));
                },
            };
            // user 级 testseed 不足 4 个 → settings 级覆盖（Go vless.go:80-82）。
            let mut testseed = user_testseed(c);
            if testseed.len() < 4 {
                testseed = cfg_testseed.clone();
            }
            let proto = VlessProtoAccount {
                id: id.to_string(),
                flow,
                encryption: "none".to_string(),
                testseed,
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
/// `"none"` → `None`（无 ENC 层）；`"mlkem768x25519plus.<mode>.<seconds>s.<keys>"` →
/// 初始化 [`xray_proxy_vless::encryption::ServerInstance`]（私钥 32B=X25519 /
/// 64B=ML-KEM-768 seed）。缺省/空串/非法非 none 值拒启（Go vless.go:152-159
/// conf 层 Build 同为 error）；ENC 启用时 fallbacks 在场互斥拒启。
pub(crate) fn build_vless_decryption(
    data: &[u8],
    plugin_ctx: std::sync::Arc<xray_frame::PluginContext>,
) -> std::io::Result<Option<std::sync::Arc<xray_proxy_vless::encryption::ServerInstance>>> {
    use xray_proxy_vless::encryption::{
        ServerInstance as EncServerInstance, parse_server_decryption,
    };
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("vless inbound settings JSON: {e}")))?;
    let raw = v.get("decryption").and_then(|d| d.as_str()).unwrap_or("");
    let Some(p) = parse_server_decryption(raw) else {
        if raw.is_empty() {
            // Go vless.go:155-157：decryption 缺省/空串拒启——必须显式 "none"，
            // 不再 unwrap_or("none") 静默兜底。
            return Err(std::io::Error::other(
                "VLESS settings: please add/set \"decryption\":\"none\" to every settings",
            ));
        }
        if raw != "none" {
            return Err(std::io::Error::other(format!(
                "VLESS settings: unsupported \"decryption\": {raw}"
            )));
        }
        return Ok(None);
    };
    // Go vless.go:161-163：ENC 解密启用时 fallbacks 互斥（字段在场即拒，
    // 对齐 Go c.Fallbacks != nil）。
    if v.get("fallbacks").is_some() {
        return Err(std::io::Error::other(
            "VLESS settings: \"fallbacks\" can not be used together with \"decryption\"",
        ));
    }
    let mut inst = EncServerInstance::new();
    let key_count = p.keys.len();
    inst.init(p.keys, p.xor_mode, p.seconds_from, p.seconds_to, &p.padding, plugin_ctx)
        .map_err(|e| std::io::Error::other(format!("vless decryption init: {e}")))?;
    tracing::info!(
        seconds_from = p.seconds_from,
        seconds_to = p.seconds_to,
        keys = key_count,
        "vless enc decryption enabled"
    );
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
        if dest.starts_with("@@") {
            let mut buf = [0u8; UNIX_PATH_MAX];
            let src = &dest.as_bytes()[1..]; // Go trojan.go:196 Dest[1:]: 跳过首个 @，保留第二个
            let copy_len = src.len().min(UNIX_PATH_MAX - 1);
            buf[1..1 + copy_len].copy_from_slice(&src[..copy_len]);
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
/// 对每个 client：`MemoryAccount::new(password)`（内部计算 hex(sha224)）→ MemoryUser → key_hash
/// 入表。
/// `pub(crate)`：P3-2 对拍测试（tests_config_parity）跨模块消费，语义零变化。
pub(crate) fn build_trojan_users(
    data: &[u8],
) -> std::io::Result<HashMap<String, TrojanMemoryUser>> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("trojan inbound settings JSON: {e}")))?;
    let mut users = HashMap::new();
    // Go infra/conf/trojan.go:124-126：`if c.Clients != nil { c.Users = c.Clients }`
    // — 若 `clients` 字段存在则覆盖 `users`，否则 fall back 到 `users`。
    let client_list = v.get("clients").or_else(|| v.get("users")).and_then(|c| c.as_array());
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
/// - `type` 缺省时按 dest 形态推导（:177-194）：`@`/`/` 前缀 → unix （`@@` 抽象套接字做 108 字节
///   NUL padding），`host:port` → tcp；
/// - dest 缺失/null 且 `type` 也缺省 → 报错（:196-198；不再回退 127.0.0.1:80）， 与 Go
///   一致：fallbacks 配置错误 = inbound 启动失败。
///
/// `pub(crate)`：P3-2 对拍测试（tests_config_parity）跨模块消费，语义零变化。
pub(crate) fn build_trojan_fallbacks(
    data: &[u8],
) -> std::io::Result<Option<std::sync::Arc<FallbackPolicy>>> {
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
    if list.is_empty() { Ok(None) } else { Ok(Some(FallbackPolicy::from_list(&list))) }
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
        },
        None => false,
    }
}

/// 从 inbound entry.data（JSON）解析 VLESS `fallbacks` 数组 → FallbackPolicy。
///
/// 对齐 Go `infra/conf/vless.go:170-211`（VLessInboundFallback 消费段）：
/// - `dest` 数字（uint16 范围）→ `"localhost:N"`；字符串原样；
/// - `path` 必须为空或以 `/` 开头；
/// - type 推导（serve-ws-none → serve；`/`/`@` 前缀 → unix；纯数字 → localhost:N；host:port →
///   tcp）失败（含 dest 缺失）→ 拒启；
/// - `xver` 仅 0/1/2，负数/非整数/越界一律拒启，不钳制；
/// - unix / serve 目标本构建运行面未实现（恒 TcpStream 拨号）→ 显式拒启。
///
/// 空数组或字段缺失返回 `Ok(None)`（维持无 fallback 的直连路径）。
pub(crate) fn build_vless_fallbacks(
    data: &[u8],
) -> std::io::Result<Option<std::sync::Arc<xray_proxy_vless::FallbackPolicy>>> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("vless inbound settings JSON: {e}")))?;
    let Some(fbs) = v.get("fallbacks").and_then(|f| f.as_array()) else {
        return Ok(None);
    };
    let mut policy = xray_proxy_vless::FallbackPolicy::new();
    for (i, fb) in fbs.iter().enumerate() {
        let name = fb.get("name").and_then(|x| x.as_str()).unwrap_or("");
        let alpn = fb.get("alpn").and_then(|x| x.as_str()).unwrap_or("");
        let path = fb.get("path").and_then(|x| x.as_str()).unwrap_or("");
        if !path.is_empty() && !path.starts_with('/') {
            return Err(std::io::Error::other(
                "VLESS fallbacks: \"path\" must be empty or start with \"/\"",
            ));
        }
        // xver（Go vless.go:209-211 + uint64 解码期硬错）。
        let xver = match fb.get("xver") {
            None | Some(serde_json::Value::Null) => 0u8,
            Some(x) => match x.as_u64() {
                Some(n @ 0..=2) => n as u8,
                Some(_) => {
                    return Err(std::io::Error::other(
                        "VLESS fallbacks: invalid PROXY protocol version, \"xver\" only accepts 0, 1, 2",
                    ));
                },
                None => {
                    return Err(std::io::Error::other(format!(
                        "VLESS fallbacks[{i}]: invalid \"xver\" (need unsigned integer)"
                    )));
                },
            },
        };
        // dest（Go vless.go:170-183 json.RawMessage 数字优先）。
        let mut dest = match fb.get("dest") {
            Some(serde_json::Value::Number(n)) => match n.as_u64() {
                Some(port @ 0..=65_535) => format!("localhost:{port}"),
                _ => {
                    return Err(std::io::Error::other(format!(
                        "VLESS fallbacks[{i}]: invalid numeric \"dest\" (need uint16 port)"
                    )));
                },
            },
            Some(serde_json::Value::String(s)) => s.clone(),
            None | Some(serde_json::Value::Null) => String::new(),
            Some(other) => {
                return Err(std::io::Error::other(format!(
                    "VLESS fallbacks[{i}]: invalid \"dest\": {other}"
                )));
            },
        };
        // type 推导（Go vless.go:186-202）；Rust 运行面仅支持 tcp。
        let mut fb_type = fb.get("type").and_then(|x| x.as_str()).unwrap_or("").to_string();
        if fb_type.is_empty() && !dest.is_empty() {
            if dest == "serve-ws-none" {
                fb_type = "serve".into();
            } else if dest.starts_with('/') || dest.starts_with('@') {
                fb_type = "unix".into();
            } else {
                if dest.parse::<i64>().is_ok() {
                    dest = format!("localhost:{dest}");
                }
                if looks_like_host_port(&dest) {
                    fb_type = "tcp".into();
                }
            }
        }
        if fb_type.is_empty() || dest.is_empty() {
            return Err(std::io::Error::other(
                "VLESS fallbacks: please fill in a valid value for every \"dest\"",
            ));
        }
        if fb_type != "tcp" {
            return Err(std::io::Error::other(format!(
                "VLESS fallbacks[{i}]: fallback type \"{fb_type}\" is not supported by this build (only \"tcp\")"
            )));
        }
        policy.add(name, alpn, path, xray_proxy_vless::FallbackDest::new(dest, xver));
    }
    if policy.is_empty() { Ok(None) } else { Ok(Some(std::sync::Arc::new(policy))) }
}
/// 从 inbound entry.data（JSON）解析 http inbound 配置 → HttpServerConfig。
///
/// JSON 格式：`{"users":[{"user":"u","pass":"p"}],"allowTransparent":true,"userLevel":3}`。
/// `users`/`accounts` 同义（Go http.go:26-27 两个字段都收），users 优先。
/// 字段名/零值默认对齐 Go
/// infra/conf/http.go:25-30（Transparent→AllowTransparent、UserLevel→UserLevel）。
/// `pub(crate)`：P3-2 对拍测试（tests_config_parity）跨模块消费，语义零变化。
pub(crate) fn parse_http_config(data: &[u8]) -> std::io::Result<HttpServerConfig> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("http inbound settings JSON: {e}")))?;
    let mut config = HttpServerConfig::default();
    if let Some(accounts) = v.get("users").or_else(|| v.get("accounts")).and_then(|c| c.as_array())
    {
        for a in accounts {
            let user = a.get("user").and_then(|x| x.as_str()).unwrap_or("");
            let pass = a.get("pass").and_then(|x| x.as_str()).unwrap_or("");
            if !user.is_empty() {
                config.accounts.insert(user.to_string(), pass.to_string());
            }
        }
    }
    config.allow_transparent = v.get("allowTransparent").and_then(|c| c.as_bool()).unwrap_or(false);
    config.user_level = v.get("userLevel").and_then(|c| c.as_u64()).unwrap_or(0) as u32;
    Ok(config)
}

/// 解析后的完整 dokodemo 设置。
/// `pub(crate)`：P3-2 对拍测试（tests_config_parity）跨模块消费，语义零变化。
#[derive(Debug)]
pub(crate) struct DokodemoInboundSettings {
    /// 预定义目标（TCP 和 UDP 各一份，网络类型不同）。address/port 均可缺省
    /// （Go `RewriteAddress`/`RewritePort` 独立可选）；仅 address 给出时 port=0，
    /// 由 serve 侧回填本地端口（Go dokodemo.go:86-100）。
    pub(crate) dest: Option<Destination>,
    /// 是否允许 TCP。
    pub(crate) allow_tcp: bool,
    /// 是否允许 UDP。
    pub(crate) allow_udp: bool,
    /// 是否跟随 iptables REDIRECT 原始目标（透明代理）。
    pub(crate) follow_redirect: bool,
    /// 端口映射：监听端口字符串 → "host:port"。
    pub(crate) port_map: HashMap<String, String>,
}

/// 从 inbound entry.data（JSON）解析完整 dokodemo 设置。
/// JSON 格式：`{"address":"1.2.3.4","port":80,"network":"tcp,udp","followRedirect":true}`。
/// `network` 可选（默认 `"tcp"`）；`followRedirect` 可选（默认 `false`）；
/// `address`/`port` 可选（Go dokodemo.go:26-31：address→RewriteAddress、
/// port→RewritePort 独立生效；followRedirect 透明代理时目标取 SO_ORIGINAL_DST）。
/// `pub(crate)`：P3-2 对拍测试（tests_config_parity）跨模块消费，语义零变化。
pub(crate) fn parse_dokodemo_settings(data: &[u8]) -> std::io::Result<DokodemoInboundSettings> {
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
/// `pub(crate)`：P3-2 对拍测试（tests_config_parity）跨模块消费，语义零变化。
pub(crate) fn build_vmess_validator(
    data: &[u8],
) -> std::io::Result<std::sync::Arc<VmessTimedUserValidator>> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("vmess inbound settings JSON: {e}")))?;
    let validator = VmessTimedUserValidator::new();
    // Go VMessDefaultConfig：{"default":{"level":N}}，user 未显式给 level 时的默认值。
    let default_level =
        v.get("default").and_then(|d| d.get("level")).and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    // users/clients 双读（FieldAudit P1：Go vmess.go:73-75 `if c.Clients != nil
    // { c.Users = c.Clients }`——clients 键在场（非 null，含空数组）完全覆盖
    // users，否则 users 为合法别名。只读 clients → users 形态 0 用户全拒）。
    let client_list = v
        .get("clients")
        .filter(|c| !c.is_null())
        .or_else(|| v.get("users"))
        .and_then(|c| c.as_array());
    if let Some(clients) = client_list {
        for c in clients {
            let id = c.get("id").and_then(|x| x.as_str()).unwrap_or("");
            let email = c.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let level =
                c.get("level").and_then(|x| x.as_u64()).unwrap_or(u64::from(default_level)) as u32;
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
pub(crate) fn parse_ss_inbound_config(data: &[u8]) -> std::io::Result<SsInboundMode> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("ss inbound settings JSON: {e}")))?;

    // SS-2022 检测：method 以 "2022-blake3-" 开头
    let method = v.get("method").and_then(|x| x.as_str()).unwrap_or("aes-128-gcm");
    if method.starts_with("2022-blake3-") {
        return parse_ss2022_inbound_config(method, &v);
    }

    // Legacy SS AEAD
    use xray_proto::xray::proxy::shadowsocks::Account as ProtoAccount;
    if let Some(clients) = v.get("users").or_else(|| v.get("clients")).and_then(|c| c.as_array()) {
        let mut users = Vec::new();
        for c in clients {
            let password = c.get("password").and_then(|x| x.as_str()).unwrap_or("");
            let email = c.get("email").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let c_method = c.get("method").and_then(|x| x.as_str()).unwrap_or("aes-128-gcm");
            let cipher = ss_cipher_from_str(c_method).ok_or_else(|| {
                std::io::Error::other(format!("unsupported ss cipher: {c_method}"))
            })?;
            let proto = ProtoAccount {
                password: password.to_string(),
                cipher_type: cipher.as_i32(),
                iv_check: false,
            };
            let account = SsConfigMemoryAccount::from_proto(&proto)
                .map_err(|e| std::io::Error::other(format!("ss account parse: {e}")))?;
            users.push(xray_proxy_ss::validator::MemoryUser::new(email, account));
        }
        if users.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ss inbound: no users",
            ));
        }
        return Ok(SsInboundMode::Legacy(Arc::new(SsInbound::with_users(users))));
    }

    // Legacy 单用户
    let password = v.get("password").and_then(|x| x.as_str()).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "ss inbound: missing password")
    })?;
    let cipher = ss_cipher_from_str(method)
        .ok_or_else(|| std::io::Error::other(format!("unsupported ss cipher: {method}")))?;
    let proto = ProtoAccount {
        password: password.to_string(),
        cipher_type: cipher.as_i32(),
        iv_check: false,
    };
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
fn parse_ss2022_inbound_config(
    method: &str,
    v: &serde_json::Value,
) -> std::io::Result<SsInboundMode> {
    use xray_proxy_ss::ss2022::{
        MultiUserInbound, RelayDestination, RelayInbound, Ss2022Inbound, Ss2022User,
        key::psk_from_base64,
    };

    let server_psk = v.get("password").and_then(|x| x.as_str()).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "ss2022 inbound: missing server PSK")
    })?;

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
                // Go 真值：conf 层 `net.ParseAddress` 对 IP 字面量产 `IPAddress`
                // （infra/conf/shadowsocks.go:176 + common/net/address.go:91-94）。
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

    // users/clients 双读（Go shadowsocks.go:46-47,54-56）
    let users_arr = v.get("users").or_else(|| v.get("clients")).and_then(|c| c.as_array());

    // 中继模式（Go 形）：首元素带 address → 按 relay destination 解析
    // （Go shadowsocks.go:130 判定 + :162-175 构建；address/port 主键，
    // server/server_port 为 Rust 旧名回退，不作为判定依据）。
    if let Some(user_list) = users_arr {
        let go_relay =
            user_list.first().is_some_and(|u| u.get("address").and_then(|x| x.as_str()).is_some());
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ss2022 multi: no users",
            ));
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
pub(crate) fn parse_hysteria_inbound_config(
    data: &[u8],
    bind_addr: std::net::SocketAddr,
    finalmask_json: Option<&serde_json::Value>,
) -> std::io::Result<(
    xray_proxy_hysteria::HysteriaConfig,
    Arc<dyn xray_transport_hysteria::hub::HysteriaListenerFactory>,
)> {
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
    let server_name =
        v.get("server_name").and_then(|x| x.as_str()).unwrap_or("hysteria").to_string();
    // 真实 quinn server adapter：自签证书（或配置 cert/key PEM），ALPN h3 由 listen() 设置
    xray_common::ensure_default_crypto_provider();
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
    // UDP 混淆 salamander/gecko：streamSettings.finalmask.udp[]（对应 Go UdpmaskManager，
    // settings.packetSize 切 Gecko 分片模式）
    let obfs = xray_transport_hysteria::salamander_socket::parse_udp_obfs(finalmask_json)?;
    let factory: Arc<dyn xray_transport_hysteria::hub::HysteriaListenerFactory> =
        Arc::new(QuinnListenerFactory::new(Arc::new(server_config)).with_obfs(obfs));
    Ok((config, factory))
}

/// 构造 hysteria QUIC server 用的 rustls `ServerConfig`。
///
/// JSON 可选 `cert`/`key`（PEM）；缺省时用自签证书（测试场景）。ALPN h3 由
/// [`QuinnListenerFactory::listen`] 设置，这里不重复。
fn build_hysteria_tls_server_config(
    v: &serde_json::Value,
) -> std::io::Result<rustls::ServerConfig> {
    use rustls::pki_types::PrivateKeyDer;
    let (cert_der, key_der) = if let (Some(cert_str), Some(key_str)) =
        (v.get("cert").and_then(|x| x.as_str()), v.get("key").and_then(|x| x.as_str()))
    {
        let mut cert_reader = std::io::BufReader::new(cert_str.as_bytes());
        #[allow(clippy::useless_conversion)] // 存量清零批次
        let cert_pem = rustls_pemfile::certs(&mut cert_reader)
            .into_iter()
            .next()
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
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| std::io::Error::other(format!("rcgen self_signed: {e}")))?;
        (
            cert.der().clone(),
            PrivateKeyDer::try_from(key_pair.serialize_der())
                .map_err(|e| std::io::Error::other(format!("rcgen key der: {e}")))?,
        )
    };
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| std::io::Error::other(format!("rustls server config: {e}")))
}

/// 从 inbound entry.data（JSON）解析 anytls TLS acceptor + 认证密码。
///
/// JSON 格式：`{"cert":"...","key":"...","password":"..."}`（cert/key 为 PEM）。
/// cert/key 缺省时用自签名证书（仅测试场景）；password 缺省时不校验客户端认证帧。
pub(crate) fn parse_anytls_tls_acceptor(
    data: &[u8],
) -> std::io::Result<(tokio_rustls::TlsAcceptor, Option<String>)> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    // cert/key 与自签两条路径都构造 rustls ServerConfig，进程级 provider 必须先装
    // （CI 场景 si 带 cert/key，走 cert 分支——漏装则启动期 panic）。
    xray_common::ensure_default_crypto_provider();
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("anytls inbound settings JSON: {e}")))?;
    // 尝试从配置读证书
    let (cert_der, key_der) = if let (Some(cert_str), Some(key_str)) =
        (v.get("cert").and_then(|x| x.as_str()), v.get("key").and_then(|x| x.as_str()))
    {
        let mut cert_reader = std::io::BufReader::new(cert_str.as_bytes());
        #[allow(clippy::useless_conversion)] // 存量清零批次
        let cert_pem = rustls_pemfile::certs(&mut cert_reader)
            .into_iter()
            .next()
            .ok_or_else(|| std::io::Error::other("no cert in PEM"))?
            .map_err(|e| std::io::Error::other(format!("parse cert PEM: {e}")))?;
        let mut key_reader = std::io::BufReader::new(key_str.as_bytes());
        let key_pem = rustls_pemfile::private_key(&mut key_reader)
            .map_err(|e| std::io::Error::other(format!("parse key PEM: {e}")))?
            .ok_or_else(|| std::io::Error::other("no key in PEM"))?;
        (cert_pem, key_pem)
    } else {
        // ponytail: 无证书配置时用自签名证书（仅测试场景）
        xray_common::ensure_default_crypto_provider();
        let key_pair = rcgen::KeyPair::generate()
            .map_err(|e| std::io::Error::other(format!("rcgen keypair: {e}")))?;
        let params = rcgen::CertificateParams::new(vec!["localhost".into()])
            .map_err(|e| std::io::Error::other(format!("rcgen params: {e}")))?;
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| std::io::Error::other(format!("rcgen self_signed: {e}")))?;
        (
            #[allow(clippy::useless_conversion)] // 存量清零批次
            CertificateDer::from(cert.der().clone()),
            PrivateKeyDer::try_from(key_pair.serialize_der())
                .map_err(|e| std::io::Error::other(format!("rcgen key der: {e}")))?,
        )
    };
    #[allow(clippy::useless_conversion)] // 同上：既有接线形态
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.into()], key_der)
        .map_err(|e| std::io::Error::other(format!("rustls server config: {e}")))?;
    let password =
        v.get("password").and_then(|x| x.as_str()).filter(|s| !s.is_empty()).map(String::from);
    Ok((tokio_rustls::TlsAcceptor::from(Arc::new(config)), password))
}

/// 从 inbound entry.data + streamSettings 解析 naive 入站配置。
///
/// settings：`{"users":[{"name":"...","pass":"..."}]}`（sing-box naive 惯例，
/// interop_ci.py 同款）；TLS 必配（naive 本义是 HTTPS 前置代理）——证书缺失
/// 回退自签，ALPN 默认含 h2。
pub(crate) fn parse_naive_inbound_settings(
    data: &[u8],
    stream_json: Option<&serde_json::Value>,
) -> std::io::Result<(xray_transport_naive::NaiveInboundConfig, std::sync::Arc<rustls::ServerConfig>)>
{
    let auth = xray_transport_naive::NaiveInboundConfig::from_settings_json(data)?;
    let settings = xray_transport::dialer::StreamSettings::from_json(stream_json);
    let tls_config = xray_tls::server_config::build_server_config(
        &settings.security,
        settings.security_json.as_ref(),
    )?
    .ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("naive inbound requires tls security, got: {}", settings.security),
        )
    })?;
    Ok((auth, tls_config))
}

/// 从 inbound entry.data（JSON）解析 wireguard inbound 配置。
///
/// 复用 outbound 侧 [`parse_wireguard_config`] 的归一化（Go
/// infra/conf/wireguard.go inbound/outbound 共用 Build：base64/hex 密钥、
/// allowedIPs 缺省全路由、address 缺省 bogon 双栈、PSK/keepAlive/level/email，
/// bd ttni）；inbound 额外读 `port`（UDP 监听端口，缺省 51820）。
/// `pub(crate)`：P3-2 对拍测试（tests_config_parity）跨模块消费，语义零变化。
pub(crate) fn parse_wireguard_inbound_config(data: &[u8]) -> std::io::Result<(DeviceConfig, u16)> {
    let config = crate::outbound::parse_wireguard_config(data)
        .map_err(|e| std::io::Error::other(format!("wireguard inbound settings: {e}")))?;
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("wireguard inbound settings JSON: {e}")))?;
    let port = v.get("port").and_then(|x| x.as_u64()).unwrap_or(51820);
    let port = u16::try_from(port).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "wireguard inbound port out of u16 range",
        )
    })?;
    Ok((config, port))
}

/// 从 inbound entry.data（JSON）解析 dns inbound 配置。
///
/// JSON 格式：`{"servers":["8.8.8.8:53"]}` 或空对象。
/// 返回 (Handler, DnsOutbound)。`idle_timeout` 由装配层从 policy 注入（G14）。
pub(crate) fn parse_dns_inbound_config(
    data: &[u8],
    tag: &str,
    idle_timeout: std::time::Duration,
) -> std::io::Result<(DnsHandler, DnsOutbound)> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("dns inbound settings JSON: {e}")))?;
    let handler = DnsHandler::init(&DnsConfig::default(), idle_timeout);
    // 解析上游 DNS 服务器列表
    let servers: Vec<(std::net::IpAddr, u16)> = v
        .get("servers")
        .and_then(|x| x.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| {
                    s.as_str().and_then(|addr| {
                        let (ip, port) = addr.rsplit_once(':')?;
                        let ip: std::net::IpAddr = ip.parse().ok()?;
                        let port: u16 = port.parse().ok()?;
                        Some((ip, port))
                    })
                })
                .collect()
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
pub(crate) fn parse_loopback_config(data: &[u8]) -> std::io::Result<String> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("loopback inbound settings JSON: {e}")))?;
    let inbound_tag = v
        .get("inboundTag")
        .and_then(|x| x.as_str())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "loopback: missing inboundTag")
        })?
        .to_string();
    Ok(inbound_tag)
}

/// 从 inbound entry.data（JSON）解析 tuic inbound 配置。
///
/// JSON 格式：`{"uuid":"...","password":"...","serverName":"...",
/// "certificate":"<PEM>","certificateKey":"<PEM>",
/// "congestion_control":"cubic","brutal_up_bps":10485760}`（票 ieik⑥：证书键接线，
/// 缺省 rcgen 自签；票 7ykg：CC 配置面，对称 s8ti outbound）。
pub(crate) fn parse_tuic_inbound_config(
    data: &[u8],
    addr: &str,
    stream_settings_json: Option<&serde_json::Value>,
) -> std::io::Result<xray_proxy_tuic::TuicInboundHandler> {
    let s = parse_tuic_inbound_settings(data, addr)?;
    // QUIC 端点缓冲：streamSettings.sockopt 的 receiveBufferSize/sendBufferSize
    // （缺省 = QUIC 系端点默认 8MB 下限语义，bind_udp_endpoint）。
    let sockopt =
        xray_transport::dialer::StreamSettings::from_json(stream_settings_json).socket_options();
    let config = xray_proxy_tuic::TuicInboundConfig {
        listen: s.bind_addr,
        server_name: s.server_name,
        uuid: s.uuid,
        password: s.password,
        cert_der: s.cert_der,
        key_der: s.key_der,
        congestion_control: s.congestion_control,
        brutal_up_bps: s.brutal_up_bps,
        sockopt,
    };
    xray_proxy_tuic::TuicInboundHandler::new("", config)
        .map_err(|e| std::io::Error::other(format!("tuic inbound: {e}")))
}

/// tuic inbound 解析结果（对称 outbound `TuicOutboundSettings`，测试可断言）。
/// `pub(crate)`：P3-2 对拍测试（tests_config_parity）跨模块消费，语义零变化。
pub(crate) struct TuicInboundSettings {
    pub(crate) bind_addr: std::net::SocketAddr,
    pub(crate) server_name: String,
    pub(crate) uuid: uuid::Uuid,
    pub(crate) password: String,
    pub(crate) cert_der: Option<Vec<u8>>,
    pub(crate) key_der: Option<Vec<u8>>,
    /// None = 未配置（crate 层不预装，quinn 默认 CUBIC，零行为变化）。
    pub(crate) congestion_control: Option<xray_proxy_tuic::CongestionControl>,
    pub(crate) brutal_up_bps: u64,
}

/// `pub(crate)`：P3-2 对拍测试（tests_config_parity）跨模块消费，语义零变化。
pub(crate) fn parse_tuic_inbound_settings(
    data: &[u8],
    addr: &str,
) -> std::io::Result<TuicInboundSettings> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("tuic inbound settings JSON: {e}")))?;
    let uuid_str = v.get("uuid").and_then(|x| x.as_str()).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "tuic: missing uuid")
    })?;
    let uuid = uuid::Uuid::parse_str(uuid_str)
        .map_err(|e| std::io::Error::other(format!("tuic invalid uuid: {e}")))?;
    let password = v.get("password").and_then(|x| x.as_str()).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "tuic: missing password")
    })?;
    let server_name = v.get("serverName").and_then(|x| x.as_str()).unwrap_or("tuic").to_string();
    let bind_addr: std::net::SocketAddr = addr.parse().map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("tuic parse addr: {e}"))
    })?;
    // 票 ieik⑥：certificate/certificateKey（PEM 内容）→ 真实证书；缺省 rcgen 自签
    let cert_der = match v.get("certificate").and_then(|x| x.as_str()) {
        Some(pem) => Some(tuic_pem_first_cert_der(pem)?),
        None => None,
    };
    let key_der = match v.get("certificateKey").and_then(|x| x.as_str()) {
        Some(pem) => Some(tuic_pem_key_der(pem)?),
        None => None,
    };
    // 票 7ykg：服务端 CC（对称 s8ti outbound 解析）。官方 tuic-server 缺省 "cubic"，
    // 白名单与带宽校验同 outbound。
    let congestion_name = v.get("congestion_control").and_then(|x| x.as_str()).unwrap_or("cubic");
    let congestion_control = xray_proxy_tuic::CongestionControl::from_name(congestion_name)
        .map(Some)
        .ok_or_else(|| std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "invalid tuic inbound congestion_control: {congestion_name} (valid: bbr, cubic, new_reno, hysteria_bbr, hysteria_brutal)"
            ),
        ))?;
    let brutal_up_bps = v.get("brutal_up_bps").and_then(|x| x.as_u64()).unwrap_or(0);
    if congestion_control == Some(xray_proxy_tuic::CongestionControl::HysteriaBrutal)
        && brutal_up_bps == 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "tuic inbound congestion_control=hysteria_brutal requires brutal_up_bps (> 0)",
        ));
    }
    Ok(TuicInboundSettings {
        bind_addr,
        server_name,
        uuid,
        password: password.to_string(),
        cert_der,
        key_der,
        congestion_control,
        brutal_up_bps,
    })
}

/// PEM 文本 → 首张证书 DER（tuic inbound certificate 键）。
fn tuic_pem_first_cert_der(pem: &str) -> std::io::Result<Vec<u8>> {
    let mut rd = std::io::BufReader::new(pem.as_bytes());
    let cert = rustls_pemfile::certs(&mut rd)
        .next()
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "tuic certificate: no cert in PEM")
        })?
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("tuic certificate PEM: {e}"),
            )
        })?;
    Ok(cert.to_vec())
}

/// PEM 文本 → 私钥 DER（tuic inbound certificateKey 键；PKCS8/SEC1/RSA 皆可）。
fn tuic_pem_key_der(pem: &str) -> std::io::Result<Vec<u8>> {
    let mut rd = std::io::BufReader::new(pem.as_bytes());
    rustls_pemfile::private_key(&mut rd)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("tuic certificateKey PEM: {e}"),
            )
        })?
        .map(|k| k.secret_der().to_vec())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "tuic certificateKey: no key in PEM",
            )
        })
}

/// TUN 配置占位设备——满足 StackOptions.tun 存在性校验。
///
/// TunInboundHandler::new 校验 options.tun.is_some()，但 start() 内部
/// 直接 TunDevice::create 硬编码参数，不使用 options.tun 的设备。
/// 因此配置解析阶段只需提供占位。
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "windows"
))]
struct TunPlaceholder;

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "windows"
))]
impl Tun for TunPlaceholder {
    fn start(&self) -> xray_proxy_tun::Result<()> {
        Ok(())
    }

    fn close(&self) -> xray_proxy_tun::Result<()> {
        Ok(())
    }

    fn name(&self) -> xray_proxy_tun::Result<String> {
        Ok("placeholder".into())
    }

    fn index(&self) -> xray_proxy_tun::Result<i32> {
        Ok(0)
    }
}

/// 从 inbound entry.data（JSON）解析 TUN inbound 配置 → StackOptions。
///
/// JSON 字段与默认值对齐 Go `infra/conf/tun.go::TunConfig.Build`
/// （name/mtu/gateway/dns/userLevel/autoSystemRoutingTable/autoOutboundsInterface
/// + Rust 扩展 idleTimeout）；解析实现在 `xray_proxy_tun::config`（全平台可测）。
///
/// `pub(crate)`：P3-2 对拍测试（tests_config_parity）跨模块消费，语义零变化。
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "windows"
))]
pub(crate) fn parse_tun_inbound_config(data: &[u8]) -> std::io::Result<StackOptions> {
    let mut opts = StackOptions::parse_json(data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}")))?;
    opts.tun = Some(Box::new(TunPlaceholder));
    Ok(opts)
}

/// 从 inbound entry.data（JSON）解析 blackhole inbound 响应配置。
///
/// JSON 格式：`{"response":{"type":"none"}}` 或 `{"response":{"type":"http"}}`。
/// 缺省时默认 None。
pub(crate) fn parse_blackhole_inbound_response(data: &[u8]) -> BlackholeResponseConfig {
    if data.is_empty() {
        return BlackholeResponseConfig::None;
    }
    let v: serde_json::Value = serde_json::from_slice(data).unwrap_or_default();
    let response_type =
        v.get("response").and_then(|r| r.get("type")).and_then(|t| t.as_str()).unwrap_or("none");
    match response_type {
        "http" => BlackholeResponseConfig::Http403,
        _ => BlackholeResponseConfig::None,
    }
}

/// 从 inbound entry.data（JSON）解析 freedom inbound 预定义目标地址。
///
/// JSON 格式：`{"address":"1.2.3.4","port":80}`（address+port 必填）。
/// 类似 dokodemo 的配置格式。
pub(crate) fn parse_freedom_inbound_dest(data: &[u8]) -> std::io::Result<Destination> {
    let v: serde_json::Value = serde_json::from_slice(data)
        .map_err(|e| std::io::Error::other(format!("freedom inbound settings JSON: {e}")))?;
    let address_str = v.get("address").and_then(|x| x.as_str()).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "freedom inbound: missing address")
    })?;
    let port = v.get("port").and_then(|x| x.as_u64()).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "freedom inbound: missing port")
    })? as u16;
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
    // 测试面 L3 静态闸存量登记（bd a5r4j/lzzja）：本模块 52 处 tokio::spawn
    // （并发夹具 / 端到端 pump）+ 4 处 std Instant + 2 处 tokio Instant（测试
    // 计时与 deadline 夹具）——测试计时与并发编排不得改语义；tokio::test 自有
    // runtime，FxScope 化无生命周期收益 → 模块级 inner allow 登记（生产面
    // 已逐点收口，见文件头台账注释）。
    #![allow(
        clippy::disallowed_methods,
        reason = "测试面存量 52 处 tokio::spawn + 4 处 std Instant + 2 处 tokio Instant：测试计时/并发夹具不得改语义，tokio::test 自有 runtime 无 FxScope 生命周期收益"
    )]
    use std::net::Ipv4Addr;

    /// 测试范式 ctx（生产注入来自装配根；仅测试面可直接构造）。
    fn test_plugin_ctx(kind: &'static str) -> std::sync::Arc<xray_frame::PluginContext> {
        std::sync::Arc::new(xray_frame::PluginContext::for_plugin(kind))
    }

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;

    /// bd m1oa：inbound dispatch 失败必须留痕。`DispatchHandler::dispatch`
    /// 返回 `()`（错误不走返回通道），可观测面在
    /// [`crate::wiring::InboundDispatchHandler`] 的 `dispatch_link` Err 分支
    /// ——warn 一行带 inbound tag 与丢弃原因（Go 对照 worker.go:123-125
    /// `LogInfoInner(ctx, err, "connection ends")`：错误留痕、连接照常关闭）。
    /// 锁定该行为：dispatcher 无 ohm 的同步失败必产生含 tag 的 warn。
    #[test]
    fn dispatch_link_failure_warns_with_tag_and_reason() {
        // WarnCapture 模式取自 outbound.rs（原始来源 xray-tls）。
        #[derive(Clone, Default)]
        struct WarnCapture(Arc<parking_lot::Mutex<Vec<String>>>);
        impl tracing::Subscriber for WarnCapture {
            fn enabled(&self, meta: &tracing::Metadata<'_>) -> bool {
                meta.level() <= &tracing::Level::WARN
            }

            fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }

            fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

            fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {
            }

            fn event(&self, event: &tracing::Event<'_>) {
                struct Fmt(String);
                impl tracing::field::Visit for Fmt {
                    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                        self.0.push_str(&format!("{}={value} ", field.name()));
                    }

                    fn record_debug(
                        &mut self,
                        field: &tracing::field::Field,
                        value: &dyn std::fmt::Debug,
                    ) {
                        self.0.push_str(&format!("{}={value:?} ", field.name()));
                    }
                }
                let mut v = Fmt(String::new());
                event.record(&mut v);
                self.0.lock().push(v.0);
            }

            fn enter(&self, _span: &tracing::span::Id) {}

            fn exit(&self, _span: &tracing::span::Id) {}
        }

        let handler = Arc::new(crate::wiring::InboundDispatchHandler::new(
            Arc::new(xray_app_dispatcher::default::DefaultDispatcher::new()),
            xray_app_dispatcher::default::SniffingRequest::default(),
            "ss-in",
        ));
        let capture = WarnCapture::default();
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        tracing::subscriber::with_default(capture.clone(), || {
            rt.block_on(async {
                let dest = Destination::new(
                    Address::Domain("example.com".into()),
                    Port::new(443),
                    Network::TCP,
                );
                let (up_r, up_w) = xray_buf::pipe::new();
                let link = Link::new(Box::new(up_r), Box::new(up_w));
                handler.dispatch(&dest, link).await;
            });
        });
        let warns = capture.0.lock();
        assert!(
            warns.iter().any(|w| w.contains("dispatch_link failed") && w.contains("ss-in")),
            "dispatch failure must warn with inbound tag + reason, got: {warns:?}"
        );
    }

    /// bd b8i 对称面：不支持平台（Windows/macOS 等）tun inbound →
    /// `spawn_one_inbound` 返回 Unsupported 硬错误（对齐 Go 不支持平台
    /// NewTun 失败 → inbound 创建失败的 fail-fast 语义）。
    /// 支持平台分支见 outbound.rs `register_tun_outbound`（Linux 侧对称）。
    // Windows 已支持（bd cv3w）：仅 macOS/iOS/其它平台走 Unsupported fail-fast。
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd",
        target_os = "windows"
    )))]
    #[tokio::test]
    async fn tun_inbound_rejected_on_unsupported_platform() {
        let ib = BuiltInbound {
            entry: xray_conf::BuiltEntry { kind: "tun".to_string(), data: b"{}".to_vec() },
            tag: "tun-in".to_string(),
            port: None,
            listen: None,
            stream_settings_json: None,
            sniffing_json: None,
        };
        let err = spawn_one_inbound(
            &ib,
            Arc::new(SimpleOhm::new()),
            None,
            CancellationToken::new(),
            None,
        )
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
            entry: xray_conf::BuiltEntry { kind: "socks".to_string(), data: b"{}".to_vec() },
            tag: "uds-win".to_string(),
            port: None,
            listen: Some("/tmp/xray-uds-win.sock".to_string()),
            stream_settings_json: None,
            sniffing_json: None,
        };
        let err = spawn_one_inbound(
            &ib,
            Arc::new(SimpleOhm::new()),
            None,
            CancellationToken::new(),
            None,
        )
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
                    },
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
            entry: xray_conf::BuiltEntry { kind: "socks".to_string(), data: b"{}".to_vec() },
            tag: "uds-e2e".to_string(),
            port: None,
            listen: Some(sock_path.to_string_lossy().into_owned()),
            stream_settings_json: None,
            sniffing_json: None,
        };
        let handle = spawn_one_inbound(&ib, Arc::clone(&ohm), None, CancellationToken::new(), None)
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

    // ===== bd lfrg：transport 协议 unix 监听接入生产 inbound 路径 =====

    /// TCP echo server（freedom 出站的真实目的地）。
    #[cfg(unix)]
    async fn spawn_echo_server() -> std::net::SocketAddr {
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
                    },
                }
            }
        });
        echo_addr
    }

    /// freedom 出站 SimpleOhm（与 [`unix_socket_socks_inbound_e2e`] 同装配）。
    #[cfg(unix)]
    fn freedom_ohm() -> Arc<SimpleOhm> {
        let ohm = Arc::new(SimpleOhm::new());
        ohm.set_default(Arc::new(xray_app_dispatcher::default::DialBridge::new(
            "freedom",
            xray_proxy_freedom::make_freedom_dial_fn(),
        )) as Arc<dyn xray_app_dispatcher::DispatchHandler>);
        ohm
    }

    #[cfg(unix)]
    const VLESS_TEST_UUID: &str = "d342d11e-d424-4583-b36e-524ab1f0afa4";

    /// vless inbound settings：单用户 + decryption none。
    #[cfg(unix)]
    fn vless_entry_data() -> Vec<u8> {
        format!(r#"{{"clients":[{{"id":"{VLESS_TEST_UUID}"}}],"decryption":"none"}}"#).into_bytes()
    }

    /// 生产 VLESS 客户端编码器穿任意 IO：请求头 → 响应头 → 载荷 echo 往返
    /// （freedom → echo server）。httpupgrade/TLS 流等已升级后的字节流直接用。
    #[cfg(unix)]
    async fn vless_echo_roundtrip<S>(mut stream: S, dest: std::net::SocketAddr)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        use xray_common::net::address::Address;
        let uuid = xray_common::uuid::UUID::parse(VLESS_TEST_UUID).unwrap();
        let v4 = match dest.ip() {
            std::net::IpAddr::V4(v4) => Address::from_ipv4_bytes(v4.octets()),
            _ => unreachable!("echo binds ipv4"),
        };
        xray_proxy_vless::encoding::client::encode_request_header(
            &mut stream,
            xray_proxy_vless::encoding::VERSION,
            &uuid,
            xray_proxy_vless::encoding::VlessCommand::Tcp,
            Some(&v4),
            Some(dest.port()),
            &xray_proxy_vless::encoding::empty_addons(),
        )
        .await
        .unwrap();
        let addons = xray_proxy_vless::encoding::decode_response_header(
            &mut stream,
            xray_proxy_vless::encoding::VERSION,
        )
        .await
        .unwrap();
        assert_eq!(addons.flow, "", "no flow addons expected");
        let payload = b"uds roundtrip payload";
        stream.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, payload, "echo through unix transport inbound");
    }

    /// 测试用 RFC6455 客户端（binary 帧）：握手 accept key 校验复用 ws hub
    /// 同一 handshake 模块；[`Self::recv`] 聚合分帧（容忍服务端响应头/数据合帧）。
    #[cfg(unix)]
    struct TestWsClient<S> {
        inner: S,
        pending: Vec<u8>,
    }

    #[cfg(unix)]
    impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> TestWsClient<S> {
        async fn handshake(mut inner: S, path: &str) -> Self {
            use xray_transport_websocket::handshake::{
                compute_accept_key, generate_client_key_for_testing,
            };
            let key = generate_client_key_for_testing();
            let req = format!(
                "GET {path} HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\
                 Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\
                 Sec-WebSocket-Key: {key}\r\n\r\n"
            );
            inner.write_all(req.as_bytes()).await.unwrap();
            let mut buf: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 512];
            loop {
                let n = inner.read(&mut chunk).await.unwrap();
                assert!(n > 0, "EOF during ws handshake");
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..pos]).into_owned();
                    assert!(head.starts_with("HTTP/1.1 101"), "ws handshake failed: {head}");
                    assert!(
                        head.contains(&compute_accept_key(&key)),
                        "Sec-WebSocket-Accept mismatch: {head}"
                    );
                    break;
                }
            }
            Self { inner, pending: Vec::new() }
        }

        async fn send(&mut self, data: &[u8]) {
            assert!(data.len() < 126, "test-only: short frames");
            let mask = [0x2au8, 0x4b, 0x19, 0x7e];
            let mut frame = Vec::with_capacity(6 + data.len());
            frame.push(0x82); // FIN | binary
            frame.push(0x80 | data.len() as u8); // MASK | len
            frame.extend_from_slice(&mask);
            frame.extend(data.iter().zip(mask.iter().cycle()).map(|(b, m)| b ^ m));
            self.inner.write_all(&frame).await.unwrap();
        }

        /// 读恰好 `want` 字节（服务器帧不掩码；首字节 = vless 响应头时按流聚合）。
        async fn recv(&mut self, want: usize) -> Vec<u8> {
            while self.pending.len() < want {
                let mut hdr = [0u8; 2];
                self.inner.read_exact(&mut hdr).await.unwrap();
                assert_eq!(hdr[0] & 0x0f, 0x2, "expected binary frame, got {:#x}", hdr[0]);
                assert_eq!(hdr[1] & 0x80, 0, "server frames must be unmasked");
                let mut len = (hdr[1] & 0x7f) as usize;
                if len == 126 {
                    let mut ext = [0u8; 2];
                    self.inner.read_exact(&mut ext).await.unwrap();
                    len = u16::from_be_bytes(ext) as usize;
                }
                let mut payload = vec![0u8; len];
                self.inner.read_exact(&mut payload).await.unwrap();
                self.pending.extend_from_slice(&payload);
            }
            self.pending.drain(..want).collect()
        }
    }

    /// bd lfrg（unix 端到端）：vless + ws 经 `spawn_one_inbound` unix 分派 →
    /// `listen_unix`（ws hub，生产 on_conn）→ RFC6455 握手 → vless 握手 →
    /// freedom → echo 收发字节。证明 transport-unix 接线被主分派入口真实调用。
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socket_vless_ws_inbound_e2e() {
        xray_transport_websocket::register::register_unix_listener().unwrap();

        let echo_addr = spawn_echo_server().await;
        let ohm = freedom_ohm();
        let sock_path =
            std::env::temp_dir().join(format!("xray-uds-vless-ws-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock_path);
        let ib = BuiltInbound {
            entry: xray_conf::BuiltEntry { kind: "vless".to_string(), data: vless_entry_data() },
            tag: "vless-ws-uds".to_string(),
            port: None,
            listen: Some(sock_path.to_string_lossy().into_owned()),
            stream_settings_json: Some(serde_json::json!({
                "network": "ws",
                "security": "none",
                "wsSettings": { "path": "/ws" }
            })),
            sniffing_json: None,
        };
        let handle = spawn_one_inbound(&ib, ohm, None, CancellationToken::new(), None)
            .await
            .unwrap()
            .expect("vless+ws unix inbound should spawn");

        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let uds = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
            let mut ws = TestWsClient::handshake(uds, "/ws").await;

            // vless 请求头（生产编码器）→ 响应头 → 载荷 echo 往返
            let uuid = xray_common::uuid::UUID::parse(VLESS_TEST_UUID).unwrap();
            let mut req = Vec::new();
            let v4 = match echo_addr.ip() {
                std::net::IpAddr::V4(v4) => v4.octets(),
                _ => unreachable!("echo binds ipv4"),
            };
            xray_proxy_vless::encoding::client::encode_request_header(
                &mut req,
                xray_proxy_vless::encoding::VERSION,
                &uuid,
                xray_proxy_vless::encoding::VlessCommand::Tcp,
                Some(&xray_common::net::address::Address::from_ipv4_bytes(v4)),
                Some(echo_addr.port()),
                &xray_proxy_vless::encoding::empty_addons(),
            )
            .await
            .unwrap();
            ws.send(&req).await;
            assert_eq!(ws.recv(2).await, vec![0, 0], "vless response [ver=0][addons=0]");
            ws.send(b"hello vless-ws-uds!").await;
            assert_eq!(ws.recv(19).await, b"hello vless-ws-uds!".to_vec());
        })
        .await
        .expect("vless+ws unix e2e timed out");
        handle.abort();
        let _ = std::fs::remove_file(&sock_path);
    }

    /// bd lfrg（unix 端到端）：vless + httpupgrade 同路径分派 →
    /// `listen_unix`（httpupgrade hub）→ 生产 [`HttpUpgradeClient`] 握手 →
    /// 生产 vless on_conn → freedom → echo。
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socket_vless_httpupgrade_inbound_e2e() {
        xray_transport_httpupgrade::register::register_unix_listener().unwrap();

        let echo_addr = spawn_echo_server().await;
        let ohm = freedom_ohm();
        let sock_path =
            std::env::temp_dir().join(format!("xray-uds-vless-hu-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock_path);
        let ib = BuiltInbound {
            entry: xray_conf::BuiltEntry { kind: "vless".to_string(), data: vless_entry_data() },
            tag: "vless-hu-uds".to_string(),
            port: None,
            listen: Some(sock_path.to_string_lossy().into_owned()),
            stream_settings_json: Some(serde_json::json!({
                "network": "httpupgrade",
                "security": "none",
                "httpupgradeSettings": { "path": "/hu", "host": "localhost" }
            })),
            sniffing_json: None,
        };
        let handle = spawn_one_inbound(&ib, ohm, None, CancellationToken::new(), None)
            .await
            .unwrap()
            .expect("vless+httpupgrade unix inbound should spawn");

        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let uds = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
            let client = xray_transport_httpupgrade::client::HttpUpgradeClient::new(
                "localhost".to_string(),
                xray_transport_httpupgrade::config::Config {
                    path: "/hu".into(),
                    ..Default::default()
                },
            );
            let (conn, _leftover) = client.dial_over_io(uds).await.expect("httpupgrade 握手失败");
            vless_echo_roundtrip(conn, echo_addr).await;
        })
        .await
        .expect("vless+httpupgrade unix e2e timed out");
        handle.abort();
        let _ = std::fs::remove_file(&sock_path);
    }

    /// bd lfrg（unix + TLS 端到端）：security=tls 的 unix 监听不再被
    /// 「security != none 即拒」门拦截，TLS accept 由 hub 内部完成（对齐 Go
    /// unix listen 照样可包 TLS）：自签证书 → vless+ws+TLS over UDS 全链路。
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socket_vless_ws_tls_inbound_e2e() {
        xray_transport_websocket::register::register_unix_listener().unwrap();
        xray_common::ensure_default_crypto_provider();

        // 自签证书落盘（Go certificates[].certificateFile/keyFile 形态）
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_path =
            std::env::temp_dir().join(format!("xray-uds-tls-cert-{}.pem", std::process::id()));
        let key_path =
            std::env::temp_dir().join(format!("xray-uds-tls-key-{}.pem", std::process::id()));
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

        let echo_addr = spawn_echo_server().await;
        let ohm = freedom_ohm();
        let sock_path =
            std::env::temp_dir().join(format!("xray-uds-vless-ws-tls-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock_path);
        let ib = BuiltInbound {
            entry: xray_conf::BuiltEntry { kind: "vless".to_string(), data: vless_entry_data() },
            tag: "vless-ws-tls-uds".to_string(),
            port: None,
            listen: Some(sock_path.to_string_lossy().into_owned()),
            stream_settings_json: Some(serde_json::json!({
                "network": "ws",
                "security": "tls",
                "tlsSettings": { "certificates": [{
                    "certificateFile": cert_path.to_string_lossy(),
                    "keyFile": key_path.to_string_lossy(),
                }] },
                "wsSettings": { "path": "/wstls" }
            })),
            sniffing_json: None,
        };
        let handle = spawn_one_inbound(&ib, ohm, None, CancellationToken::new(), None)
            .await
            .unwrap()
            .expect("vless+ws+tls unix inbound should spawn (security gate removed)");

        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            // UDS → rustls（信任自签证书）→ WS 升级 → vless
            let uds = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert.cert.der().clone()).unwrap();
            let mut client_cfg =
                rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
            client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
            let connector: tokio_rustls::TlsConnector = Arc::new(client_cfg).into();
            let tls = connector
                .connect("localhost".try_into().unwrap(), uds)
                .await
                .expect("tls handshake over uds failed");
            let mut ws = TestWsClient::handshake(tls, "/wstls").await;

            let uuid = xray_common::uuid::UUID::parse(VLESS_TEST_UUID).unwrap();
            let mut req = Vec::new();
            let v4 = match echo_addr.ip() {
                std::net::IpAddr::V4(v4) => v4.octets(),
                _ => unreachable!("echo binds ipv4"),
            };
            xray_proxy_vless::encoding::client::encode_request_header(
                &mut req,
                xray_proxy_vless::encoding::VERSION,
                &uuid,
                xray_proxy_vless::encoding::VlessCommand::Tcp,
                Some(&xray_common::net::address::Address::from_ipv4_bytes(v4)),
                Some(echo_addr.port()),
                &xray_proxy_vless::encoding::empty_addons(),
            )
            .await
            .unwrap();
            ws.send(&req).await;
            assert_eq!(ws.recv(2).await, vec![0, 0], "vless response [ver=0][addons=0]");
            ws.send(b"hello vless-ws-tls-uds!").await;
            assert_eq!(ws.recv(23).await, b"hello vless-ws-tls-uds!".to_vec());
        })
        .await
        .expect("vless+ws+tls unix e2e timed out");
        handle.abort();
        let _ = std::fs::remove_file(&sock_path);
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
    }

    /// bd lfrg（接线证明 + fail-visible 文案）：transport 协议 + unix 分派确已
    /// 进入 `listener_registry::listen_unix`——未注册 unix 监听的协议（kcp；
    /// Go kcp hub 为 UDP 面，同样无 unix 监听）返回 Go 对齐的 NotFound 文案。
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socket_transport_unregistered_protocol_fail_visible() {
        let ohm = freedom_ohm();
        let ib = BuiltInbound {
            entry: xray_conf::BuiltEntry { kind: "vless".to_string(), data: vless_entry_data() },
            tag: "vless-kcp-uds".to_string(),
            port: None,
            listen: Some("/tmp/xray-uds-vless-kcp.sock".into()),
            stream_settings_json: Some(serde_json::json!({
                "network": "kcp",
                "security": "none"
            })),
            sniffing_json: None,
        };
        let err =
            spawn_one_inbound(&ib, ohm, None, CancellationToken::new(), None).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound, "got: {err}");
        assert!(
            err.to_string().contains("kcp unix listener not registered"),
            "error must mirror Go unix-not-registered text, got: {err}"
        );
    }

    /// bd lfrg（接线面）：vless + grpc unix → `listen_unix` 命中 grpc hub 的
    /// unix 注册（grpc/h2/http 同 fn 注册），h2 server 真实建立——spawn 成功
    /// 证配置面进到已注册 unix hub；gRPC 数据面客户端需 h2 依赖（不在本批
    /// 依赖面），数据面证据见 xray-transport-grpc 自有 unix 往返测试。
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socket_vless_grpc_inbound_spawns() {
        xray_transport_grpc::register::register_unix_listener().unwrap();

        let ohm = freedom_ohm();
        let sock_path =
            std::env::temp_dir().join(format!("xray-uds-vless-grpc-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock_path);
        let ib = BuiltInbound {
            entry: xray_conf::BuiltEntry { kind: "vless".to_string(), data: vless_entry_data() },
            tag: "vless-grpc-uds".to_string(),
            port: None,
            listen: Some(sock_path.to_string_lossy().into_owned()),
            stream_settings_json: Some(serde_json::json!({
                "network": "grpc",
                "security": "none",
                "grpcSettings": { "serviceName": "GunService" }
            })),
            sniffing_json: None,
        };
        let handle = spawn_one_inbound(&ib, ohm, None, CancellationToken::new(), None)
            .await
            .unwrap()
            .expect("vless+grpc unix inbound should spawn via registered hub");
        // listener 已 bind：UDS 建连被受理。
        let _uds = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
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
            },
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
        use xray_app_dispatcher::default::DialBridge;
        use xray_proxy_freedom::make_freedom_dial_fn;
        #[allow(unused_imports)] // 存量清零批次
        use xray_proxy_hysteria::TcpDispatcher as _;
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
            fn read<'a>(
                &'a self,
                buf: &'a mut [u8],
            ) -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<usize>> + Send + 'a>>
            {
                Box::pin(async {
                    use tokio::io::AsyncReadExt as _;
                    self.r.lock().await.read(buf).await
                })
            }

            fn write<'a>(
                &'a self,
                buf: &'a [u8],
            ) -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<usize>> + Send + 'a>>
            {
                Box::pin(async {
                    use tokio::io::AsyncWriteExt as _;
                    self.w.lock().await.write(buf).await
                })
            }

            // 代 FixBehavior 补：QuicStream trait 新增 poll_write（bd HysteriaConn
            // 零分配路径）后 mock 未跟上。tokio Mutex try_lock 是同步 API，
            // 满足“锁内无 await”的 trait 约束；被占即 Pending。
            fn poll_write(
                &self,
                cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                use tokio::io::AsyncWrite as _;
                let mut w = match self.w.try_lock() {
                    Ok(w) => w,
                    Err(_) => return std::task::Poll::Pending,
                };
                std::pin::Pin::new(&mut *w).poll_write(cx, buf)
            }

            fn cancel_read(&self, _code: u64) {}

            fn close(&self) -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>> {
                Box::pin(async { Ok(()) })
            }

            fn local_addr(&self) -> std::net::SocketAddr {
                self.local
            }

            fn remote_addr(&self) -> std::net::SocketAddr {
                self.remote
            }
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
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&rbuf[..n], payload);
        drop(client);
        // 留时间给桥收尾（read EOF → 关闭）
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    /// agb：SS-2022 UDP inbound → dispatch → 回环 e2e（多用户 EIH，
    /// MarkerUdpDispatch 验证真正经 dispatch link，模式同 ss_udp_dispatch_roundtrip）。
    #[tokio::test]
    async fn ss2022_udp_dispatch_roundtrip() {
        use xray_proxy_ss::ss2022::{
            key::{CipherKind2022, psk_identity},
            packet::ClientUdpSession2022,
        };

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
            test_plugin_ctx("shadowsocks"),
        ));

        // 2. client：2022 UDP 帧 → relay（目标任意，marker handler 不打真实包）
        let client_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client_sock.connect(relay_addr).await.unwrap();
        let client =
            ClientUdpSession2022::new(CipherKind2022::Aes256Gcm, vec![ipsk, upsk]).unwrap();
        let frame = client.encode(&Address::IPv4(Ipv4Addr::LOCALHOST), 53, b"ping").unwrap();
        client_sock.send(&frame).await.unwrap();

        // 3. 收回帧并 decode 出标记 payload
        let mut rbuf = vec![0u8; 2048];
        let n =
            tokio::time::timeout(std::time::Duration::from_secs(5), client_sock.recv(&mut rbuf))
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
        use xray_proxy_ss::ss2022::{key::CipherKind2022, packet::ServerUdpSession2022};

        let mk = |sid: u64| {
            Arc::new(
                ServerUdpSession2022::new(CipherKind2022::Aes256Gcm, vec![7u8; 32], sid).unwrap(),
            )
        };
        let now = std::time::Instant::now();
        let mut table: HashMap<u64, (Arc<ServerUdpSession2022>, std::time::Instant)> =
            HashMap::new();
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
        let mut empty: HashMap<u64, (Arc<ServerUdpSession2022>, std::time::Instant)> =
            HashMap::new();
        assert_eq!(sweep_expired_ss2022_sessions(&mut empty, now), 0);
    }

    /// agb：SS-2022 UDP inbound → freedom UDP dispatch → 真 echo 回环 e2e
    /// （FreedomDispatchBridge 的 UDP 分支走 udp::relay，DialBridge 仅 TCP）。
    #[tokio::test]
    async fn ss2022_udp_inbound_dispatch_to_freedom_e2e() {
        use xray_app_dispatcher::default::DialBridge;
        use xray_proxy_freedom::{dispatcher::FreedomDispatchBridge, make_freedom_dial_fn};
        use xray_proxy_ss::ss2022::{
            key::{CipherKind2022, psk_identity},
            packet::ClientUdpSession2022,
        };

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
        let handler: Arc<dyn xray_app_dispatcher::DispatchHandler> =
            Arc::new(FreedomDispatchBridge::from_bridge(
                test_plugin_ctx("freedom"),
                Arc::new(DialBridge::new("freedom", make_freedom_dial_fn())),
            ));
        tokio::spawn(serve_ss2022_udp(
            Arc::new(relay),
            CipherKind2022::Aes256Gcm,
            ipsk.clone(),
            users,
            handler,
            test_plugin_ctx("shadowsocks"),
        ));

        // 3. client：2022 UDP 帧 → serve → freedom dispatch → echo → 回帧
        let client_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client_sock.connect(relay_addr).await.unwrap();
        let client =
            ClientUdpSession2022::new(CipherKind2022::Aes256Gcm, vec![ipsk, upsk]).unwrap();

        let payload = b"ss2022-udp-dispatch-e2e".to_vec();
        let frame = client.encode(&Address::IPv4(echo_v4), echo_addr.port(), &payload).unwrap();
        client_sock.send(&frame).await.unwrap();

        let mut rbuf = vec![0u8; 65_535];
        let n =
            tokio::time::timeout(std::time::Duration::from_secs(5), client_sock.recv(&mut rbuf))
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
        use base64::Engine as _;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use xray_app_dispatcher::default::DialBridge;
        use xray_proxy_freedom::{dispatcher::FreedomDispatchBridge, make_freedom_dial_fn};
        use xray_proxy_ss::ss2022::key::{CipherKind2022, psk_identity};
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
        let echo_handler: Arc<dyn xray_app_dispatcher::DispatchHandler> =
            Arc::new(FreedomDispatchBridge::from_bridge(
                test_plugin_ctx("freedom"),
                Arc::new(DialBridge::new("freedom", make_freedom_dial_fn())),
            ));
        tokio::spawn(serve_ss2022_udp(
            Arc::new(relay),
            CipherKind2022::Aes256Gcm,
            ipsk.clone(),
            users,
            echo_handler,
            test_plugin_ctx("shadowsocks"),
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
        let ss_bridge =
            Arc::new(DialBridge::new("ss2022-out", xray_proxy_ss::make_ss_dial_fn(cfg)));

        // 4. dispatch link：duplex 承载 XUDP 帧流（模拟 inbound 侧）
        let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
        let dest =
            Destination::new(Address::IPv4(echo_v4), Port::new(echo_addr.port()), Network::UDP);
        let (srv_rd, srv_wr) = tokio::io::split(server_io);
        tokio::spawn(async move {
            ss_bridge
                .dispatch(
                    &dest,
                    xray_transport::link::Link::new(
                        xray_buf::io::new_reader(srv_rd),
                        xray_buf::io::new_writer(srv_wr),
                    ),
                )
                .await;
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

    /// SS-2022 chacha 单用户 UDP 全链 e2e（v26.9.30 对齐：chacha UDP 解封）：
    /// parse（chacha 单 PSK）→ pump_ss2022_udp（XChaCha 24B nonce 帧）→
    /// serve_ss2022_udp（chacha_plain 整包解密）→ freedom → echo → 回程。
    #[tokio::test]
    async fn ss2022_chacha_udp_outbound_inbound_roundtrip_e2e() {
        use base64::Engine as _;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use xray_app_dispatcher::default::DialBridge;
        use xray_proxy_freedom::{dispatcher::FreedomDispatchBridge, make_freedom_dial_fn};
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

        // 2. SS-2022 server（inbound 侧，chacha 单用户：users 空）
        let psk: Vec<u8> = (0x40..0x60u8).collect();
        let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_port = relay.local_addr().unwrap().port();
        let echo_handler: Arc<dyn xray_app_dispatcher::DispatchHandler> =
            Arc::new(FreedomDispatchBridge::from_bridge(
                test_plugin_ctx("freedom"),
                Arc::new(DialBridge::new("freedom", make_freedom_dial_fn())),
            ));
        tokio::spawn(serve_ss2022_udp(
            Arc::new(relay),
            xray_proxy_ss::ss2022::key::CipherKind2022::ChaCha20Poly1305,
            psk.clone(),
            Vec::new(),
            echo_handler,
            test_plugin_ctx("shadowsocks"),
        ));

        // 3. SS-2022 outbound（chacha 单 PSK 密码）
        let b64 = base64::engine::general_purpose::STANDARD;
        let cfg_json = format!(
            r#"{{"servers":[{{"address":"127.0.0.1","port":{relay_port},
            "method":"2022-blake3-chacha20-poly1305",
            "password":"{}"}}]}}"#,
            b64.encode(&psk),
        );
        let cfg = std::sync::Arc::new(xray_proxy_ss::parse_ss_config(cfg_json.as_bytes()).unwrap());
        assert!(cfg.ss2022.is_some(), "chacha 2022 method should route to ss2022 params");
        let ss_bridge =
            Arc::new(DialBridge::new("ss2022-chacha-out", xray_proxy_ss::make_ss_dial_fn(cfg)));

        // 4. dispatch link：duplex 承载 XUDP 帧流
        let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
        let dest =
            Destination::new(Address::IPv4(echo_v4), Port::new(echo_addr.port()), Network::UDP);
        let (srv_rd, srv_wr) = tokio::io::split(server_io);
        tokio::spawn(async move {
            ss_bridge
                .dispatch(
                    &dest,
                    xray_transport::link::Link::new(
                        xray_buf::io::new_reader(srv_rd),
                        xray_buf::io::new_writer(srv_wr),
                    ),
                )
                .await;
        });

        // 5. XUDP 帧 → chacha UDP pump → inbound → freedom → echo → 回帧
        let payload = b"ss2022-chacha-udp-e2e".to_vec();
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
                .expect("chacha response within 5s")
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
        let cfg =
            parse_socks_server_config(br#"{"accounts":[{"user":"bob","pass":"p2"}]}"#).unwrap();
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
        assert_eq!(addr.address, Some(ProtoAddr::Ip(vec![127, 0, 0, 9])), "ipv4 → 4-byte Ip");
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

    /// bd ttni：wireguard 入站复用 outbound 归一化——base64 密钥/PSK 归一为
    /// hex、allowedIPs 保留、level/email 透传；归一化后密钥能走既有 Tunnel 链
    /// （旧实现 hex-only，base64 secret 进 Tunnel 必然 decode 失败）。
    #[test]
    fn parse_wireguard_inbound_config_base64_keys_normalize() {
        use base64::Engine as _;
        let secret_b64 = base64::engine::general_purpose::STANDARD.encode([0x11u8; 32]);
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode([0x22u8; 32]);
        let psk_b64 = base64::engine::general_purpose::STANDARD.encode([0x33u8; 32]);
        let data = format!(
            r#"{{"secretKey": "{}", "address": ["10.0.0.1/32"], "port": 51820,
                "peers": [{{"publicKey": "{}", "preSharedKey": "{}",
                "allowedIPs": ["10.0.0.2/32"], "endpoint": "203.0.113.9:51820",
                "level": 2, "email": "u@wg"}}]}}"#,
            secret_b64, pub_b64, psk_b64
        );
        let (config, port) = parse_wireguard_inbound_config(data.as_bytes()).unwrap();
        assert_eq!(port, 51820);
        assert_eq!(config.secret_key, "11".repeat(32), "base64 secret 归一化为 hex");
        let peer = &config.peers[0];
        assert_eq!(peer.public_key, "22".repeat(32));
        assert_eq!(peer.pre_shared_key, "33".repeat(32), "PSK 归一化");
        assert_eq!(peer.allowed_ips, vec!["10.0.0.2/32"], "allowedIPs 保留");
        assert_eq!(peer.email, "u@wg");
        assert_eq!(peer.level, 2);
        // 归一化后的密钥必须能走既有 Tunnel 链（hex decode 成功）
        xray_proxy_wireguard::Tunnel::from_config(&config, peer)
            .expect("normalized keys feed the existing tunnel chain");
    }

    /// bd 7v0k③：peers 空允许解析（Go 官方空配置 + API 建户另票）。
    #[test]
    fn parse_wireguard_inbound_config_empty_peers_allowed() {
        let secret = "aa".repeat(32);
        let data = format!(r#"{{"secretKey": "{}"}}"#, secret);
        let (config, port) = parse_wireguard_inbound_config(data.as_bytes()).unwrap();
        assert!(config.peers.is_empty(), "空 peers 允许启动");
        assert_eq!(port, 51820);
        // address 缺省 → bogon 双栈（7v0k①）
        assert_eq!(config.endpoint, vec!["10.0.0.1", "fd59:7153:2388:b5fd::1"]);
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
        use xray_proxy_ss::{
            config::MemoryAccount as SsAccount,
            protocol::{decode_udp_packet, encode_udp_packet},
        };

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
            let _ =
                serve_ss_udp(Arc::new(relay), ib_clone, handler, test_plugin_ctx("shadowsocks"))
                    .await;
        });

        // 2. client：encode 一个 UDP 包发给 relay（目标任意，dispatch 标记 handler 不打真实包）
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let packet =
            encode_udp_packet(&account, &Address::IPv4(Ipv4Addr::LOCALHOST), 53, b"ping").unwrap();
        client.send_to(&packet, relay_addr).await.unwrap();

        // 3. 收回包并解密（发起用户 account 可解出标记 payload）
        let mut rbuf = vec![0u8; 2048];
        let (n, _from) =
            tokio::time::timeout(std::time::Duration::from_secs(5), client.recv_from(&mut rbuf))
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
        let key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key);
        let json = serde_json::json!({
            "privateKey": key_b64,
            "serverNames": ["example.com"],
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
        assert_eq!(cfg.server_names, vec!["example.com".to_string()]);
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
        // dest 为 int 端口 → localhost:port；缺省 xver=0/maxTimeDiff=0（Go 兼容：禁用时间窗）。
        // 257w 后 serverNames/shortIds 均为必填（Go :94/:135 拒启），fixture 显式给出。
        let json = serde_json::json!({
            "privateKey": key_b64,
            "serverNames": ["a.example.com"],
            "shortIds": ["01"],
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
        // 左对齐补零（Go hex.Decode → make([]byte,8)）："01" → [0x01,0,...]
        assert_eq!(cfg.short_ids, vec![[0x01, 0, 0, 0, 0, 0, 0, 0]]);
    }

    #[test]
    fn parse_reality_config_rejects_missing_key() {
        let settings = xray_transport::dialer::StreamSettings {
            security: "reality".to_string(),
            security_json: Some(serde_json::json!({"serverNames": ["a.com"]})),
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
            "serverNames": ["a.com"],
            "shortIds": ["01"],
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

    /// t38j：空/缺失 serverNames 拒启（Go transport_security.go:94-96）。
    #[test]
    fn parse_reality_config_rejects_empty_server_names() {
        use base64::Engine as _;
        let key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        for names in [serde_json::json!([]), serde_json::json!("not-an-array")] {
            let json = serde_json::json!({
                "privateKey": key_b64,
                "serverNames": names,
                "shortIds": ["01"],
            });
            let settings = xray_transport::dialer::StreamSettings {
                security: "reality".to_string(),
                security_json: Some(json),
                ..xray_transport::dialer::StreamSettings::tcp()
            };
            let err = parse_reality_config(&settings).unwrap_err();
            assert!(
                err.to_string().contains("serverNames"),
                "expected empty serverNames error, got: {err}"
            );
        }
    }

    /// 257w：shortIds 三重硬错（Go transport_security.go:135-147）——空数组/
    /// 过长/奇数或非法 hex 均拒启；非字符串项同拒。
    #[test]
    fn parse_reality_config_rejects_bad_short_ids() {
        use base64::Engine as _;
        let key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        let cases = [
            serde_json::json!([]),                     // 空数组
            serde_json::json!(["0123456789abcdef00"]), // >16 字符
            serde_json::json!(["abc"]),                // 奇数长度
            serde_json::json!(["zz"]),                 // 非法 hex
            serde_json::json!([42]),                   // 非字符串项
        ];
        for short_ids in cases {
            let json = serde_json::json!({
                "privateKey": key_b64,
                "serverNames": ["a.com"],
                "shortIds": short_ids,
            });
            let settings = xray_transport::dialer::StreamSettings {
                security: "reality".to_string(),
                security_json: Some(json),
                ..xray_transport::dialer::StreamSettings::tcp()
            };
            let err = parse_reality_config(&settings).unwrap_err();
            assert!(err.to_string().contains("shortIds"), "expected shortIds error, got: {err}");
        }
    }

    /// 票 037f：Go 有 Rust 无的 realitySettings 键——有意图值配置层硬错指名键；
    /// 关闭值/缺省放行（Go 兼容配置不破）。
    #[test]
    fn parse_reality_config_rejects_unsupported_go_keys() {
        use base64::Engine as _;
        let key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        // 有意图值 → 拒，文案指名键。（dest 仅在 target 缺席时被读取，
        // dest case 需移除基底 target。）
        let build = |extra: &serde_json::Value, drop_target: bool| {
            let mut obj = serde_json::json!({
                "privateKey": key_b64,
                "serverNames": ["a.com"],
                "shortIds": ["ab"],
                "target": "example.com:443",
            });
            {
                let base = obj.as_object_mut().expect("object literal");
                if drop_target {
                    base.remove("target");
                }
                if let Some(patch) = extra.as_object() {
                    for (k, v) in patch {
                        base.insert(k.clone(), v.clone());
                    }
                }
            }
            xray_transport::dialer::StreamSettings {
                security: "reality".to_string(),
                security_json: Some(obj),
                ..xray_transport::dialer::StreamSettings::tcp()
            }
        };
        let cases: Vec<(serde_json::Value, &str, bool)> = vec![
            (serde_json::json!({ "show": true }), "show", false),
            (serde_json::json!({ "masterKeyLog": "keys.log" }), "masterKeyLog", false),
            (
                serde_json::json!({ "limitFallbackUpload": { "afterBytes": 1024 } }),
                "limitFallbackUpload",
                false,
            ),
            (
                serde_json::json!({ "limitFallbackDownload": { "bytesPerSec": 8 } }),
                "limitFallbackDownload",
                false,
            ),
            (serde_json::json!({ "type": "unix" }), "type", false),
            (serde_json::json!({ "target": "@@reality-fallback" }), "unix socket", false),
            (serde_json::json!({ "dest": "/run/reality.sock" }), "unix socket", true),
        ];
        for (extra, needle, drop_target) in cases {
            let err = parse_reality_config(&build(&extra, drop_target))
                .err()
                .unwrap_or_else(|| panic!("case {needle:?}: must reject, got Ok"));
            assert!(err.to_string().contains(needle), "expected error naming {needle}, got: {err}");
        }

        // 关闭值/缺省 → 放行（Go 兼容配置零回归）。
        for extra in [
            serde_json::json!({ "show": false }),
            serde_json::json!({ "masterKeyLog": "none" }),
            serde_json::json!({ "limitFallbackUpload": {} }),
            serde_json::json!({ "type": "tcp" }),
            serde_json::json!({}),
        ] {
            parse_reality_config(&build(&extra, false))
                .unwrap_or_else(|e| panic!("closed/absent values must pass, got: {e}"));
        }
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
                    },
                }
            }
        });

        // 2. 配置 dispatcher：freedom outbound → SimpleOhm default
        let ohm = Arc::new(SimpleOhm::new());
        let dial_fn = make_freedom_dial_fn();
        let bridge =
            std::sync::Arc::new(xray_app_dispatcher::default::DialBridge::new("freedom", dial_fn))
                as std::sync::Arc<dyn xray_app_dispatcher::DispatchHandler>;
        ohm.set_default(bridge);

        // 3. 起 SOCKS5 inbound
        let socks_listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        )
        .await
        .unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        let config = Arc::new(ServerConfig::default());
        let ohm_clone = Arc::clone(&ohm);
        tokio::spawn(async move {
            let _ = serve_socks5(
                socks_listener,
                ohm_clone,
                config,
                None,
                std::time::Duration::from_secs(300),
                test_plugin_ctx("socks"),
            )
            .await;
        });

        // 4. SOCKS5 client：连 socks5 → handshake → 请求 echo server → 写数据 → 读 echo
        let mut client = TcpStream::connect(socks_addr).await.unwrap();
        // 握手：版本 5，1 method，no-auth(0)
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
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

    /// 4vkp：socks 独立入站 TCP 裸流接 readv（InboundConnMeta::into_link_io
    /// TcpStream 分支）。单缓冲阶段（current=1）读满 8KB 扩到 2 后，一次
    /// read_multi_buffer 把剩余 16KB 聚合进 2 个缓冲——对齐 Go NewReader
    /// syscall.Conn → ReadVReader 分支。若回退 new_reader（顺序读），第二读
    /// 只能拿单缓冲 8KB，第二组断言失败。
    #[tokio::test]
    async fn socks_tcp_inbound_reader_aggregates_payload_single_read() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            // 3 个满缓冲：首读必读满 8192 → IsFull 扩容分支确定性触发
            s.write_all(&vec![0xABu8; 8192 * 3]).await.unwrap();
            s.shutdown().await.unwrap();
        });

        let (sock, _) = listener.accept().await.unwrap();
        let (mut reader, _writer) = sock.into_link_io();

        let mb =
            tokio::time::timeout(std::time::Duration::from_secs(5), reader.read_multi_buffer())
                .await
                .expect("read timeout")
                .expect("read ok");
        assert_eq!(mb.len(), 8192, "首读（current=1）单缓冲");

        let mb =
            tokio::time::timeout(std::time::Duration::from_secs(5), reader.read_multi_buffer())
                .await
                .expect("read timeout")
                .expect("read ok");
        assert_eq!(mb.len(), 16 * 1024, "第二读应单次 readv 聚合 2 缓冲");
        assert_eq!(mb.buffer_count(), 2);

        let mb =
            tokio::time::timeout(std::time::Duration::from_secs(5), reader.read_multi_buffer())
                .await
                .expect("read timeout")
                .expect("read ok");
        assert!(mb.is_empty(), "对端 shutdown → EOF 空 MultiBuffer");
        client.await.unwrap();
    }

    /// 4vkp：分片到达边界不回归——残片先到时 reader 立即短读返回已到达字节
    /// （不等满缓冲），后续分片按到达序完整重组（readv 短读语义）。
    #[tokio::test]
    async fn socks_tcp_inbound_reader_fragmented_arrival_boundary() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            s.write_all(b"HEADA").await.unwrap();
            s.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            s.write_all(b"YLOAD-BYTES").await.unwrap();
            s.shutdown().await.unwrap();
        });

        let (sock, _) = listener.accept().await.unwrap();
        let (mut reader, _writer) = sock.into_link_io();

        let mb =
            tokio::time::timeout(std::time::Duration::from_secs(5), reader.read_multi_buffer())
                .await
                .expect("read timeout")
                .expect("read ok");
        assert_eq!(mb.to_vec(), b"HEADA", "残片短读：只返回已到达字节");

        let mb =
            tokio::time::timeout(std::time::Duration::from_secs(5), reader.read_multi_buffer())
                .await
                .expect("read timeout")
                .expect("read ok");
        assert_eq!(mb.to_vec(), b"YLOAD-BYTES", "后续分片按序完整到达");

        let mb =
            tokio::time::timeout(std::time::Duration::from_secs(5), reader.read_multi_buffer())
                .await
                .expect("read timeout")
                .expect("read ok");
        assert!(mb.is_empty(), "EOF 空 MultiBuffer");
        client.await.unwrap();
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
        use xray_proxy_vless::encoding::{
            VlessCommand,
            client::{decode_response_header, encode_request_header},
        };
        use xray_transport::{
            dialer::{StreamSettings, dial_with_settings},
            sockopt::SocketOptions,
        };

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
                    },
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
        let proto_account = VlessProtoAccount {
            id: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
            ..Default::default()
        };
        let account = VlessMemoryAccount::from_proto_account(&proto_account).unwrap();
        validator.add(VlessMemoryUser::new("e2e-user", 0, account)).unwrap();

        // 4. serve_reality_vless
        let server_secret = x25519_dalek::StaticSecret::from([0x99u8; 32]);
        let server_public = x25519_dalek::PublicKey::from(&server_secret);
        let short_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let reality_cfg = RealityInboundConfig {
            server_private_key: server_secret.to_bytes(),
            // 客户端 SNI=reality.local（下方 settings），白名单含它 → SNI 门放行。
            server_names: vec!["reality.local".to_string()],
            short_ids: vec![short_id],
            max_diff: 43200,
            fallback_dest: format!("127.0.0.1:{}", echo_addr.port()),
            xver: 0,
            min_client_ver: Vec::new(),
            max_client_ver: Vec::new(),
            max_useless_records: xray_reality::MaxUselessRecordsSetting::Disabled,
            server_acceptor: xray_reality::ServerAcceptorSetting::Rustls,
        };
        let rl = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        )
        .await
        .unwrap();
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

    /// F3（bd 8q0d）：REALITY 入站 `tcpSettings.header` 伪装头接线回归。
    ///
    /// 装配处 `with_header_auth` 注入 → serve_reality_vless 读 `header_auth()`
    /// → Verified 后对 reality 解包流套 `maybe_wrap_server`（Go hub.go:106-120
    /// `authConfig.Server` 套在 `reality.Server` 之后）。客户端对称 `wrap_client`
    /// 首写前置伪装 GET。
    ///
    /// 修前行为：服务端把伪装 GET 字节直接喂 VLESS 解析（首字节 'G' 非合法
    /// VLESS version）→ 请求头解码失败连接被关 → `decode_response_header`
    /// 读 EOF，本测试红。
    #[tokio::test]
    async fn vless_reality_inbound_applies_tcp_header_auth() {
        // rustls 全局 provider（并行测试只装一次）
        static PROVIDER: std::sync::Once = std::sync::Once::new();
        PROVIDER.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
        use base64::Engine as _;
        use xray_proxy_vless::encoding::{
            VlessCommand,
            client::{decode_response_header, encode_request_header},
        };
        use xray_transport::{
            dialer::{StreamSettings, dial_with_settings},
            sockopt::SocketOptions,
        };

        // 1. echo server（VLESS 数据目标）
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = match echo_listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    },
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
        let proto_account = VlessProtoAccount {
            id: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
            ..Default::default()
        };
        let account = VlessMemoryAccount::from_proto_account(&proto_account).unwrap();
        validator.add(VlessMemoryUser::new("e2e-user", 0, account)).unwrap();

        // 4. serve_reality_vless + tcpSettings.header（默认 chrome 伪装请求）
        let server_secret = x25519_dalek::StaticSecret::from([0x42u8; 32]);
        let server_public = x25519_dalek::PublicKey::from(&server_secret);
        let short_id = [2u8, 4, 6, 8, 1, 3, 5, 7];
        let reality_cfg = RealityInboundConfig {
            server_private_key: server_secret.to_bytes(),
            // 客户端 SNI=reality.local（下方 settings），白名单含它 → SNI 门放行。
            server_names: vec!["reality.local".to_string()],
            short_ids: vec![short_id],
            max_diff: 43200,
            fallback_dest: format!("127.0.0.1:{}", echo_addr.port()),
            xver: 0,
            min_client_ver: Vec::new(),
            max_client_ver: Vec::new(),
            max_useless_records: xray_reality::MaxUselessRecordsSetting::Disabled,
            server_acceptor: xray_reality::ServerAcceptorSetting::Rustls,
        };
        let header_json = serde_json::json!({"header": {"type": "http"}});
        let server_auth =
            xray_transport::headers::conn::auth_from_json(Some(&header_json)).unwrap().unwrap();
        let rl = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        )
        .await
        .unwrap()
        .with_header_auth(Some(server_auth));
        let rl_addr = rl.local_addr().unwrap();
        let ohm_c = Arc::clone(&ohm);
        let val_c = Arc::clone(&validator) as Arc<dyn VlessValidator>;
        tokio::spawn(async move {
            let _ = serve_reality_vless(rl, ohm_c, val_c, reality_cfg, None).await;
        });

        // 5. client：tcp+reality dial → wrap_client（首写前置伪装 GET）→ VLESS 请求 → echo
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
        let conn = dial_with_settings("tcp", &dest, &SocketOptions::default(), &settings)
            .await
            .expect("tcp+reality dial should succeed");
        let client_auth =
            xray_transport::headers::conn::auth_from_json(Some(&header_json)).unwrap().unwrap();
        let mut conn = xray_transport::headers::conn::wrap_client(conn, &client_auth);

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

        let payload = b"hello vless+reality+header!";
        conn.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        conn.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, payload, "vless over reality with tcpSettings.header should echo");
    }

    /// 39824 修 A 回归共享脚手架：REALITY+vision 入站（serve_reality_vless，
    /// 修 A 三件套：dup + RecordFramer + raw 通道）+ capture 型 echo + flow=XRV
    /// validator + 已完成 REALITY 握手的客户端连接 + 客户端侧裸流克隆
    /// （Go 客户端 UnwrapRawConn 后的 rawConn 形态）。
    #[allow(clippy::type_complexity)] // 测试脚手架元组
    async fn spawn_reality_vision_harness() -> (
        Box<dyn xray_transport::connection::Connection>,
        tokio::net::TcpStream,
        u16,
        std::sync::Arc<parking_lot::Mutex<Vec<u8>>>,
        UUID,
    ) {
        static PROVIDER: std::sync::Once = std::sync::Once::new();
        PROVIDER.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
        use base64::Engine as _;
        use xray_transport::dialer::StreamSettings;

        // 1. capture 型 echo（记录收到的全部字节）
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        let received = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let received_c = Arc::clone(&received);
        tokio::spawn(async move {
            let Ok((mut sock, _)) = echo_listener.accept().await else {
                return;
            };
            let mut buf = [0u8; 4096];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => received_c.lock().extend_from_slice(&buf[..n]),
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

        // 3. validator（flow=xtls-rprx-vision 账号）
        let validator = Arc::new(VlessMemoryValidator::new());
        let test_uuid = UUID::parse("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let proto_account = VlessProtoAccount {
            id: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
            flow: xray_proxy_vless::FLOW_XRV.to_string(),
            ..Default::default()
        };
        let account = VlessMemoryAccount::from_proto_account(&proto_account).unwrap();
        validator.add(VlessMemoryUser::new("vision-user", 0, account)).unwrap();

        // 4. serve_reality_vless（options=Some → Verified 分支置 outer_tls13）
        let server_secret = x25519_dalek::StaticSecret::from([0x42u8; 32]);
        let server_public = x25519_dalek::PublicKey::from(&server_secret);
        let short_id = [4u8, 3, 9, 8, 2, 7, 1, 6];
        let reality_cfg = RealityInboundConfig {
            server_private_key: server_secret.to_bytes(),
            server_names: vec!["reality.local".to_string()],
            short_ids: vec![short_id],
            max_diff: 43200,
            fallback_dest: format!("127.0.0.1:{echo_port}"),
            xver: 0,
            min_client_ver: Vec::new(),
            max_client_ver: Vec::new(),
            max_useless_records: xray_reality::MaxUselessRecordsSetting::Disabled,
            server_acceptor: xray_reality::ServerAcceptorSetting::Rustls,
        };
        let rl = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        )
        .await
        .unwrap();
        let rl_addr = rl.local_addr().unwrap();
        let ohm_c = Arc::clone(&ohm);
        let val_c = Arc::clone(&validator) as Arc<dyn VlessValidator>;
        tokio::spawn(async move {
            let _ = serve_reality_vless(
                rl,
                ohm_c,
                val_c,
                reality_cfg,
                Some(xray_proxy_vless::VlessInboundOptions::default()),
            )
            .await;
        });

        // 5. 客户端：TCP 连接 → 握手前 dup 裸流克隆（Go 客户端
        // switchToDirectCopy 的 rawConn 等价物）→ REALITY over u_client 指纹
        let mut settings = StreamSettings::tcp();
        settings.security = "reality".to_string();
        settings.security_json = Some(serde_json::json!({
            "serverName": "reality.local",
            "publicKey": base64::engine::general_purpose::STANDARD.encode(server_public.to_bytes()),
            "shortId": hex::encode(short_id),
            "fingerprint": "chrome"
        }));
        let tcp = tokio::net::TcpStream::connect(rl_addr).await.unwrap();
        let raw_dup = xray_transport::connection::dup_tcp_stream(&tcp)
            .expect("dup_tcp_stream must succeed on a fresh loopback socket");
        let conn = xray_transport::connection::TcpConnection::new(tcp);
        let reality_conn = xray_reality::register::handshake_over(Box::new(conn), &settings)
            .await
            .expect("reality handshake should succeed");
        (reality_conn, raw_dup, echo_port, received, test_uuid)
    }

    /// 轮询等待 capture echo 收到目标字节（超时 panic，附已收内容）。
    async fn wait_for_echo_received(received: &Arc<parking_lot::Mutex<Vec<u8>>>, needle: &[u8]) {
        for _ in 0..100 {
            if received.lock().windows(needle.len()).any(|w| w == needle) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!(
            "echo never received expected bytes; got: {}",
            String::from_utf8_lossy(&received.lock())
        );
    }

    /// 构造完整 TLS app-data record（客户端内层 0x17 批次）。
    fn build_vision_app_record(payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(payload.len() + 5);
        buf.extend_from_slice(&[0x17, 0x03, 0x03]);
        buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    /// 39824 修 A 回归（debugger 阶段 tmp_repro_no_raw_channel_dies_on_client_splice
    /// 的正向化）：REALITY+vision 入站必须提供裸流通道。Go 形态客户端在安全层
    /// 内发 [UUID Continue 帧][DIRECT 帧] 后切裸 socket 直写（Go proxy.go
    /// switchToDirectCopy：UnwrapRawConn + rawConn.Write）——服务端必须经 raw
    /// 通道把裸字节送达目标。修复前装配（无 dup/framer/raw）：裸字节被 rustls
    /// 当下一条隧道记录 AEAD 解密 → fatal bad_record_mac 断链，目标永远收不到
    /// （公网 :39824 下载 0.0 的第一现场）。
    #[tokio::test]
    async fn reality_vision_inbound_delivers_raw_upstream_after_client_direct() {
        use rand::SeedableRng;
        use xray_proxy_vless::encryption::vision::{DEFAULT_PADDING_SEED, xtls_padding};

        let (mut reality_conn, mut raw_dup, echo_port, received, test_uuid) =
            spawn_reality_vision_harness().await;

        // VLESS 请求头（flow=XRV）走外层 REALITY/TLS conn
        let addons = xray_proxy_vless::encoding::EncAddons {
            flow: xray_proxy_vless::FLOW_XRV.to_string(),
            seed: Vec::new(),
        };
        xray_proxy_vless::encoding::client::encode_request_header(
            &mut reality_conn,
            0,
            &test_uuid,
            xray_proxy_vless::encoding::VlessCommand::Tcp,
            Some(&Address::IPv4(std::net::Ipv4Addr::LOCALHOST)),
            Some(echo_port),
            &addons,
        )
        .await
        .unwrap();

        // Go 客户端上行帧序列：首帧 Continue 带 uuid（内层 TLS 批次），随后
        // DIRECT 帧（splice 触发，content 空）
        let first = build_vision_app_record(b"GET / HTTP/1.1\r\n\r\n");
        let mut frame_continue = Vec::new();
        xtls_padding(
            Some(&first),
            xray_proxy_vless::encryption::vision::COMMAND_PADDING_CONTINUE,
            &mut Some(test_uuid.as_bytes().to_vec()),
            true,
            &DEFAULT_PADDING_SEED,
            &mut rand::rngs::StdRng::from_os_rng(),
            &mut frame_continue,
        );
        let mut frame_direct = Vec::new();
        xtls_padding(
            Some(&[]),
            xray_proxy_vless::encryption::vision::COMMAND_PADDING_DIRECT,
            &mut None,
            true,
            &DEFAULT_PADDING_SEED,
            &mut rand::rngs::StdRng::from_os_rng(),
            &mut frame_direct,
        );
        reality_conn.write_all(&frame_continue).await.unwrap();
        reality_conn.write_all(&frame_direct).await.unwrap();
        reality_conn.flush().await.unwrap();

        // 客户端切裸 socket 直写（同一 TCP 连接的 dup 克隆，字节级等价
        // Go rawConn.Write）
        raw_dup.write_all(b"raw-upstream-payload").await.unwrap();
        raw_dup.flush().await.unwrap();

        // 目标必须收到裸写字节（修复前：服务端 AEAD 解密失败断链，收不到）
        wait_for_echo_received(&received, b"raw-upstream-payload").await;
    }

    /// 39824 修 A framer 接线回归：DIRECT 帧 TLS 记录与裸尾背靠背（同/相邻
    /// TCP 段）入站时，记录对齐读把裸尾留在内核缓冲交 raw 通道完整送达——
    /// 修复前 rustls deframer 贪婪 recv 把裸尾拉进 TLS 层（完整记录形态 →
    /// DecryptError 断链；半记录 → 滞留不可达），字节永久丢失（bd jeu9
    /// Linux CI body=0B 形态）。
    #[tokio::test]
    async fn reality_vision_inbound_delivers_coalesced_raw_tail() {
        use rand::SeedableRng;
        use xray_proxy_vless::encryption::vision::{DEFAULT_PADDING_SEED, xtls_padding};

        let (mut reality_conn, mut raw_dup, echo_port, received, test_uuid) =
            spawn_reality_vision_harness().await;

        let addons = xray_proxy_vless::encoding::EncAddons {
            flow: xray_proxy_vless::FLOW_XRV.to_string(),
            seed: Vec::new(),
        };
        xray_proxy_vless::encoding::client::encode_request_header(
            &mut reality_conn,
            0,
            &test_uuid,
            xray_proxy_vless::encoding::VlessCommand::Tcp,
            Some(&Address::IPv4(std::net::Ipv4Addr::LOCALHOST)),
            Some(echo_port),
            &addons,
        )
        .await
        .unwrap();

        let first = build_vision_app_record(b"GET / HTTP/1.1\r\n\r\n");
        let mut frame_continue = Vec::new();
        xtls_padding(
            Some(&first),
            xray_proxy_vless::encryption::vision::COMMAND_PADDING_CONTINUE,
            &mut Some(test_uuid.as_bytes().to_vec()),
            true,
            &DEFAULT_PADDING_SEED,
            &mut rand::rngs::StdRng::from_os_rng(),
            &mut frame_continue,
        );
        let mut frame_direct = Vec::new();
        xtls_padding(
            Some(&[]),
            xray_proxy_vless::encryption::vision::COMMAND_PADDING_DIRECT,
            &mut None,
            true,
            &DEFAULT_PADDING_SEED,
            &mut rand::rngs::StdRng::from_os_rng(),
            &mut frame_direct,
        );
        // DIRECT 帧上线后立即（零 sleep）背靠背裸写两段：TCP 侧帧记录与裸尾
        // 大概率合并/相邻段到达，服务端 framer + raw 通道必须完整保序送达。
        reality_conn.write_all(&frame_continue).await.unwrap();
        reality_conn.write_all(&frame_direct).await.unwrap();
        reality_conn.flush().await.unwrap();
        raw_dup.write_all(b"coalesced-tail-A").await.unwrap();
        raw_dup.write_all(b"coalesced-tail-B").await.unwrap();
        raw_dup.flush().await.unwrap();

        wait_for_echo_received(&received, b"coalesced-tail-A").await;
        wait_for_echo_received(&received, b"coalesced-tail-B").await;
    }

    /// 39436 回归锁定：trojan + tcp + reality inbound 必须走 REALITY 验证路径
    /// （serve_reality_trojan），不得误装配标准 rustls。
    ///
    /// 缺陷形态（修复前）：`spawn_one_inbound` trojan 分支 `security=reality`
    /// 落入 `build_tls_acceptor` → 标准自签证书 TLS——REALITY 客户端证书校验
    /// 必败（"received real certificate"），服务端把 TLS record 当裸 trojan
    /// header 读，`failed to read user hash: peer closed`。VPS 生产实测：
    /// Go 同配置 204+6.19MB/s 通，Rust 回环 dial failed。
    ///
    /// 本测试从函数级复刻该装配（serve_reality_trojan）：REALITY dial →
    /// trojan header → freedom → echo 回环。修复前该函数不存在（编译红）；
    /// 修复后装配层已接线（inbound.rs trojan 分支 security=reality 分派）。
    #[tokio::test]
    async fn trojan_reality_inbound_e2e() {
        static PROVIDER: std::sync::Once = std::sync::Once::new();
        PROVIDER.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
        use base64::Engine as _;
        use xray_proxy_trojan::protocol::{Network as TrojanNetwork, write_request_header};
        use xray_transport::{
            dialer::{StreamSettings, dial_with_settings},
            sockopt::SocketOptions,
        };

        // 1. echo server（trojan 数据目标）
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
                    },
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

        // 3. trojan users
        let account = TrojanMemoryAccount::new("trojan-reality-39436-pass");
        let user = TrojanMemoryUser::new("reality-e2e@trojan", 0, account.clone());
        let mut users = HashMap::new();
        users.insert(user.key_hash(), user);

        // 4. serve_reality_trojan（修复后的装配路径）
        let server_secret = x25519_dalek::StaticSecret::from([0x77u8; 32]);
        let server_public = x25519_dalek::PublicKey::from(&server_secret);
        let short_id = [9u8, 8, 7, 6, 5, 4, 3, 2];
        let reality_cfg = RealityInboundConfig {
            server_private_key: server_secret.to_bytes(),
            // 客户端 SNI=reality.local（下方 settings），白名单含它 → SNI 门放行。
            server_names: vec!["reality.local".to_string()],
            short_ids: vec![short_id],
            max_diff: 43200,
            fallback_dest: format!("127.0.0.1:{}", echo_addr.port()),
            xver: 0,
            min_client_ver: Vec::new(),
            max_client_ver: Vec::new(),
            max_useless_records: xray_reality::MaxUselessRecordsSetting::Disabled,
            server_acceptor: xray_reality::ServerAcceptorSetting::Rustls,
        };
        let rl = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        )
        .await
        .unwrap();
        let rl_addr = rl.local_addr().unwrap();
        let ohm_c = Arc::clone(&ohm);
        tokio::spawn(async move {
            let _ = serve_reality_trojan(
                rl,
                ohm_c,
                users,
                None,
                reality_cfg,
                std::time::Duration::from_secs(30),
            )
            .await;
        });

        // 5. client：tcp+reality dial → trojan header + payload → echo 回读
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
            .expect("tcp+reality dial should succeed against trojan+reality inbound");

        // trojan 请求头（TCP → echo）+ payload 一次写入
        let mut header = Vec::with_capacity(128);
        write_request_header(
            &mut header,
            &account,
            TrojanNetwork::Tcp,
            &Address::IPv4(std::net::Ipv4Addr::LOCALHOST),
            echo_addr.port(),
        )
        .unwrap();
        let payload = b"hello trojan+reality!";
        header.extend_from_slice(payload);
        conn.write_all(&header).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        conn.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, payload, "trojan over reality should echo");
    }

    #[test]
    fn socks_addr_to_destination_ipv4() {
        let addr = SocksAddr { host: Host::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), port: 8080 };
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
        let addr = SocksAddr { host: Host::Domain("example.com".to_string()), port: 443 };
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

    /// csya：mixed inbound 的 socks 分支 UDP ASSOCIATE 必须真接线（spawn relay
    /// pump + 保持控制连接）。此前回成功响应后丢弃 relay socket = 假成功，
    /// UDP 查询黑洞——本测通过 mixed TCP 入口走完整握手 + relay 往返锁死该语义。
    #[tokio::test]
    async fn mixed_socks_udp_associate_roundtrip() {
        let ohm = Arc::new(SimpleOhm::new());
        ohm.set_default(Arc::new(MarkerUdpDispatch { marker: b"via-mixed-dispatch" })
            as Arc<dyn xray_app_dispatcher::DispatchHandler>);

        let listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        )
        .await
        .unwrap();
        let addr = listener.local_addr().unwrap();
        let socks_cfg = Arc::new(parse_socks_server_config(br#"{"udp":true}"#).unwrap());
        let http_cfg = Arc::new(HttpServerConfig::default());
        tokio::spawn(async move {
            let _ = serve_mixed(
                listener,
                ohm,
                socks_cfg,
                http_cfg,
                Some(std::time::Duration::from_secs(5)),
                std::time::Duration::from_secs(300),
                test_plugin_ctx("mixed"),
            )
            .await;
        });

        // 1. TCP 控制连接：SOCKS5 noauth 握手 + CMD_UDP_ASSOCIATE
        let mut ctrl = tokio::net::TcpStream::connect(addr).await.unwrap();
        ctrl.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method_resp = [0u8; 2];
        ctrl.read_exact(&mut method_resp).await.unwrap();
        assert_eq!(method_resp, [0x05, 0x00]);
        ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.unwrap();
        let mut reply = [0u8; 10];
        ctrl.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x00, "UDP ASSOCIATE must succeed");
        let relay_addr = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            u16::from_be_bytes([reply[8], reply[9]]),
        );

        // 2. 往 relay 发 SOCKS5 UDP 帧；MarkerUdpDispatch 标记帧经 relay 返回 （假成功路径下 relay
        //    socket 已被丢弃，此步超时）
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = SocksAddr { host: Host::Ipv4(Ipv4Addr::new(8, 8, 8, 8)), port: 53 };
        client.send_to(&encode_udp_packet(&target, b"ping"), relay_addr).await.unwrap();

        let mut rbuf = [0u8; 1500];
        let (n, _) =
            tokio::time::timeout(std::time::Duration::from_secs(5), client.recv_from(&mut rbuf))
                .await
                .expect("mixed udp relay must roundtrip via dispatcher")
                .unwrap();
        let (_src, payload) = decode_udp_packet(&rbuf[..n]).unwrap();
        assert_eq!(payload, b"via-mixed-dispatch");
    }

    /// z8i0：plain HTTP 上游被 dispatch 层立即中断（dial 失败/no handler 形态）
    /// → 客户端收到 503 并关闭（对齐 Go handlePlainHTTP 读不到响应回 503
    /// Service Unavailable）。
    #[tokio::test]
    async fn plain_http_dispatch_error_returns_503() {
        struct FailingDispatch;
        impl std::fmt::Debug for FailingDispatch {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("FailingDispatch")
            }
        }
        impl xray_app_dispatcher::DispatchHandler for FailingDispatch {
            fn tag(&self) -> &str {
                "failing"
            }

            fn dispatch(
                &self,
                _dest: &Destination,
                link: xray_transport::link::Link,
            ) -> xray_app_dispatcher::default::PinFuture<()> {
                // dispatcher 错误路径关闭下行（对齐 default.rs missing-tag/reject 的
                // outbound_writer.shutdown()——pipe Writer 裸 drop 不传播关闭）
                link.writer.shutdown();
                drop(link);
                Box::pin(async {})
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();

        let hs = HandshakeResult {
            dest: Destination::tcp(Address::IPv4(Ipv4Addr::new(1, 2, 3, 4)), Port::new(80)),
            method: "GET".into(),
            target: "http://1.2.3.4/".into(),
            http_version: xray_proxy_http::server::HttpVersion::H11,
            headers: HashMap::new(),
        };
        tokio::spawn(async move {
            handle_plain_http(
                &mut server,
                &hs,
                Arc::new(FailingDispatch),
                xray_app_dispatcher::AccessContext::default(),
            )
            .await;
        });

        let mut buf = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), client.read_to_end(&mut buf))
            .await
            .expect("503 within 5s")
            .unwrap();
        let resp = String::from_utf8_lossy(&buf);
        assert!(resp.starts_with("HTTP/1.1 503"), "got: {resp}");
        assert!(resp.contains("Connection: close"), "got: {resp}");
    }

    /// z8i0：dispatch Ok 但目标零响应即关闭（后台 dial 失败形态）→ 客户端
    /// 仍收到 503 兜底；已写出响应字节后断流则不再补 503（HTTP 单响应）。
    #[tokio::test]
    async fn plain_http_silent_upstream_returns_503() {
        struct DropLinkDispatch;
        impl std::fmt::Debug for DropLinkDispatch {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("DropLinkDispatch")
            }
        }
        impl xray_app_dispatcher::DispatchHandler for DropLinkDispatch {
            fn tag(&self) -> &str {
                "drop-link"
            }

            fn dispatch(
                &self,
                _dest: &Destination,
                link: xray_transport::link::Link,
            ) -> xray_app_dispatcher::default::PinFuture<()> {
                Box::pin(async move {
                    // bridge 存活片刻（上行请求头写入 pipe），随后不回任何响应即
                    // 显式关闭下行（pipe Writer 裸 drop 不传播关闭）
                    let keep = link;
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    keep.writer.shutdown();
                })
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();

        let hs = HandshakeResult {
            dest: Destination::tcp(Address::IPv4(Ipv4Addr::new(1, 2, 3, 4)), Port::new(80)),
            method: "GET".into(),
            target: "http://1.2.3.4/".into(),
            http_version: xray_proxy_http::server::HttpVersion::H11,
            headers: HashMap::new(),
        };
        tokio::spawn(async move {
            handle_plain_http(
                &mut server,
                &hs,
                Arc::new(DropLinkDispatch),
                xray_app_dispatcher::AccessContext::default(),
            )
            .await;
        });

        let mut buf = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), client.read_to_end(&mut buf))
            .await
            .expect("503 within 5s")
            .unwrap();
        let resp = String::from_utf8_lossy(&buf);
        assert!(resp.starts_with("HTTP/1.1 503"), "got: {resp}");
    }

    /// bd os438：请求发完**不得**立刻 half-close 上游写侧（`shutdown(SHUT_WR)`）。
    /// 微信图床等 CDN 把"请求未完成 + FIN"判为拒回 → 零字节响应 → 我们合成 503。
    /// 上游在回响应前先探一次 EOF：收到 FIN 即说明代理提前半关。
    #[tokio::test]
    async fn plain_http_does_not_half_close_upstream_before_response() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let saw_eof = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&saw_eof);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            let mut acc = Vec::new();
            while !acc.windows(4).any(|w| w == b"\r\n\r\n") {
                let mut b = [0u8; 4096];
                match sock.read(&mut b).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => acc.extend_from_slice(&b[..n]),
                }
            }
            // 探 EOF：代理若已 half-close（FIN），read 立即返回 0；未半关则挂起
            // → 300ms 超时（窗口 ≥ 100ms，判定不依赖竞态：FIN 要么已到要么没到）。
            let mut probe = [0u8; 16];
            if let Ok(Ok(0)) =
                tokio::time::timeout(std::time::Duration::from_millis(300), sock.read(&mut probe))
                    .await
            {
                flag.store(true, Ordering::SeqCst);
            }
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
            let _ = sock.shutdown().await;
        });

        let proxy_addr = spawn_http_proxy_for_test().await;
        let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!(
            "GET http://127.0.0.1:{}/x HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            upstream_addr.port(),
            upstream_addr.port()
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let (status, _head, body) = read_http_response_for_test(&mut client).await;
        assert_eq!(status, 200);
        assert_eq!(body, b"ok");
        assert!(
            !saw_eof.load(Ordering::SeqCst),
            "proxy must not half-close upstream before the response (bd os438)"
        );
    }

    /// bd x23tr：上游先回 1xx 中间响应再回最终响应 → 1xx 原样透传后**继续读**
    /// 最终响应（Go `readResponseAndHandle100Continue`）。本测同时锁定 Go
    /// v26.10.17 的最终响应字节布局（Content-Length 先写 + 其余头 canonical
    /// 排序 + keep-alive 三头）。
    #[tokio::test]
    async fn plain_http_1xx_then_final_response_matches_go_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            let mut acc = Vec::new();
            while !acc.windows(4).any(|w| w == b"\r\n\r\n") {
                let mut b = [0u8; 4096];
                match sock.read(&mut b).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => acc.extend_from_slice(&b[..n]),
                }
            }
            let _ = sock.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await;
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").await;
            let _ = sock.shutdown().await;
        });

        let proxy_addr = spawn_http_proxy_for_test().await;
        let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!(
            "GET http://127.0.0.1:{}/x HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            upstream_addr.port(),
            upstream_addr.port()
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), client.read_to_end(&mut buf))
            .await
            .expect("response within 5s")
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&buf),
            "HTTP/1.1 100 Continue\r\n\r\n\
             HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\
             Connection: keep-alive\r\nKeep-Alive: timeout=60\r\n\
             Proxy-Connection: keep-alive\r\n\r\nhello"
        );
    }

    /// bd g3mvq：重复 Host 头必须拒收（Go `http.ReadRequest`："too many Host
    /// headers" → 读请求失败 → **断链不回响应**）。重复 Host 是请求走私面
    /// （首个 Host 决定路由、第二个到达上游）。
    #[tokio::test]
    async fn plain_http_duplicate_host_header_is_rejected_without_response() {
        let proxy_addr = spawn_http_proxy_for_test().await;
        let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(
                b"GET http://127.0.0.1:1/x HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\
                  Host: evil.example\r\n\r\n",
            )
            .await
            .unwrap();
        let mut buf = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), client.read_to_end(&mut buf))
            .await
            .expect("close within 5s")
            .unwrap();
        assert!(
            buf.is_empty(),
            "duplicate Host must be rejected without any response, got: {:?}",
            String::from_utf8_lossy(&buf)
        );
    }

    /// Go `Process`：客户端连接复用 = 请求带 `Proxy-Connection: keep-alive`
    /// 且响应可定界；未宣告则响应后即关连接（Go v26.10.17 实测）。
    #[tokio::test]
    async fn plain_http_without_proxy_keep_alive_closes_after_response() {
        let (proxy, upstream, _conns) = spawn_http_proxy_harness_for_test().await;
        let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let req = format!(
            "GET http://127.0.0.1:{}/x HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            upstream.port(),
            upstream.port()
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let (status, _head, _body) = read_http_response_for_test(&mut client).await;
        assert_eq!(status, 200);
        let mut trailing = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), client.read_to_end(&mut trailing))
            .await
            .expect("EOF within 5s")
            .unwrap();
        assert!(
            trailing.is_empty(),
            "connection must close after the response without Proxy-Connection: keep-alive (Go parity), got {trailing:?}"
        );
    }

    /// bd e0gos：上游不可达（拨号失败 / 上游读端已关）→ 回 **503**（Go
    /// `responseDone` 失败语义），不是断链（Go 的请求写进缓冲区成功，失败
    /// 发生在读响应阶段 → 503）。
    #[tokio::test]
    async fn plain_http_upstream_gone_returns_503() {
        struct DeadUpstreamDispatch;
        impl std::fmt::Debug for DeadUpstreamDispatch {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("DeadUpstreamDispatch")
            }
        }
        impl xray_app_dispatcher::DispatchHandler for DeadUpstreamDispatch {
            fn tag(&self) -> &str {
                "dead-upstream"
            }

            fn dispatch(
                &self,
                _dest: &Destination,
                link: xray_transport::link::Link,
            ) -> xray_app_dispatcher::default::PinFuture<()> {
                Box::pin(async move {
                    // 上游不可达 = 链路两端立即消失（生产里 dial 失败后 dispatch 桥
                    // 就是丢 link）：下行零字节断流 → 代理必须回 503，不能挂住。
                    let xray_transport::link::Link { reader, writer } = link;
                    writer.shutdown();
                    drop(reader);
                })
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();

        let hs = HandshakeResult {
            dest: Destination::tcp(Address::IPv4(Ipv4Addr::new(1, 2, 3, 4)), Port::new(80)),
            method: "GET".into(),
            target: "http://1.2.3.4/".into(),
            http_version: xray_proxy_http::server::HttpVersion::H11,
            headers: HashMap::new(),
        };
        tokio::spawn(async move {
            handle_plain_http(
                &mut server,
                &hs,
                Arc::new(DeadUpstreamDispatch),
                xray_app_dispatcher::AccessContext::default(),
            )
            .await;
        });

        let mut buf = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), client.read_to_end(&mut buf))
            .await
            .expect("503 within 5s")
            .unwrap();
        let resp = String::from_utf8_lossy(&buf);
        assert!(resp.starts_with("HTTP/1.1 503"), "got: {resp}");
    }

    /// bd e0gos：空 Host 头 + 绝对 URI → Go 用 URI 的 host（`request.Host =
    /// request.URL.Host`）→ 正常转发 200；不是断链。
    #[tokio::test]
    async fn plain_http_empty_host_header_uses_absolute_uri_host() {
        let (proxy, upstream, _conns) = spawn_http_proxy_harness_for_test().await;
        let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let req = format!("GET http://127.0.0.1:{}/x HTTP/1.1\r\nHost:\r\n\r\n", upstream.port());
        client.write_all(req.as_bytes()).await.unwrap();
        let (status, _head, _body) = read_http_response_for_test(&mut client).await;
        assert_eq!(status, 200, "empty Host header must fall back to the absolute URI host");
    }

    /// bd e0gos：绝对 URI 的 host 决定**路由**与转发的 Host 头（Go
    /// `request.Host = request.URL.Host`）——客户端给的 Host 头不参与选路
    /// （否则是请求走私面）。
    #[tokio::test]
    async fn plain_http_absolute_uri_host_wins_over_host_header() {
        let (proxy, upstream, _conns) = spawn_http_proxy_harness_for_test().await;
        let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
        // Host 头指向关闭端口（19999），URI 指向真实上游 → 必须按 URI 路由 → 200
        let req = format!(
            "GET http://127.0.0.1:{}/x HTTP/1.1\r\nHost: 127.0.0.1:19999\r\n\r\n",
            upstream.port()
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let (status, _head, _body) = read_http_response_for_test(&mut client).await;
        assert_eq!(status, 200, "absolute URI host must win over the Host header");
    }

    /// bd 971x5：mixed 入站的 1 字节分流必须认 SOCKS4（0x04）——库层
    /// `socks_handshake` 已实现 `handshake4`（Go `handshake4` 同款），此前
    /// mixed 分流只有 0x05 / ASCII 两支 → SOCKS4 直接复位。
    #[tokio::test]
    async fn mixed_socks4_connect_is_accepted() {
        let (upstream, _conns) = spawn_http_upstream_for_test().await;
        let ohm = Arc::new(SimpleOhm::new());
        ohm.set_default(Arc::new(DialDispatch) as Arc<dyn xray_app_dispatcher::DispatchHandler>);

        let listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        )
        .await
        .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_mixed(
            listener,
            ohm,
            Arc::new(ServerConfig::default()),
            Arc::new(HttpServerConfig::default()),
            Some(std::time::Duration::from_secs(5)),
            std::time::Duration::from_secs(300),
            test_plugin_ctx("mixed"),
        ));

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        // SOCKS4 CONNECT：VER=0x04 CMD=0x01 DSTPORT(2BE) DSTIP(4) USERID\0
        let port = upstream.port().to_be_bytes();
        client.write_all(&[0x04, 0x01, port[0], port[1], 127, 0, 0, 1, 0x00]).await.unwrap();
        let mut reply = [0u8; 8];
        tokio::time::timeout(std::time::Duration::from_secs(5), client.read_exact(&mut reply))
            .await
            .expect("SOCKS4 reply within 5s")
            .unwrap();
        assert_eq!(reply[0], 0x00, "SOCKS4 reply VN must be 0");
        assert_eq!(reply[1], 90, "SOCKS4 CONNECT must be granted (rep=90)");
    }

    /// ft58 S1 测试桩：按 dest 真实拨号上游，双向桥接 link ↔ 上游连接。
    /// 桥接在后台任务跑（对齐生产 dispatch_link 立即返回）；EOF 方向传播必须
    /// 显式 shutdown（pipe Writer 裸 drop 不传播关闭）。
    struct DialDispatch;
    impl std::fmt::Debug for DialDispatch {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("DialDispatch")
        }
    }
    impl xray_app_dispatcher::DispatchHandler for DialDispatch {
        fn tag(&self) -> &str {
            "dial"
        }

        fn dispatch(
            &self,
            dest: &Destination,
            link: Link,
        ) -> xray_app_dispatcher::default::PinFuture<()> {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            use xray_buf::{
                io::{Reader as _, Writer as _},
                multi::MultiBuffer,
            };
            let port = dest.port().value();
            let ip = dest
                .address()
                .ip()
                .unwrap_or_else(|| panic!("test dest must be an IP, got {:?}", dest));
            Box::pin(async move {
                let Ok(upstream) = tokio::net::TcpStream::connect((ip, port)).await else {
                    link.writer.shutdown();
                    return;
                };
                // 桥接 spawn 后立即返回（对齐生产 dispatch_link——内联 join 会与
                // handle_plain_http「dispatch 返回后才写请求」互等死锁）
                tokio::spawn(async move {
                    let (mut up_r, mut up_w) = upstream.into_split();
                    let mut lr = link.reader;
                    let mut lw = link.writer;
                    let up_task = async {
                        loop {
                            match lr.read_multi_buffer().await {
                                Ok(mb) if mb.is_empty() => break,
                                Ok(mb) => {
                                    let mut data = Vec::new();
                                    for b in mb.iter() {
                                        data.extend_from_slice(b.bytes());
                                    }
                                    if up_w.write_all(&data).await.is_err() {
                                        break;
                                    }
                                },
                                Err(_) => break,
                            }
                        }
                        let _ = up_w.shutdown().await;
                    };
                    let down_task = async {
                        let mut buf = vec![0u8; 8192];
                        loop {
                            match up_r.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    let mut mb = MultiBuffer::new();
                                    mb.merge_bytes(&buf[..n]);
                                    if lw.write_multi_buffer(mb).await.is_err() {
                                        break;
                                    }
                                },
                            }
                        }
                        lw.shutdown();
                    };
                    tokio::join!(up_task, down_task);
                });
            })
        }
    }

    /// ft58 S1 测试桩：解析缓冲中的一个完整 HTTP 请求（头 + CL/chunked body）。
    /// 不完整 → None（调用方继续读）。返回 (方法, path, body, 请求带 close
    /// token?, 消费字节数)。
    fn parse_http_request_for_test(acc: &[u8]) -> Option<(String, String, Vec<u8>, bool, usize)> {
        let head_end = acc.windows(4).position(|w| w == b"\r\n\r\n")?;
        let head = String::from_utf8_lossy(&acc[..head_end]).into_owned();
        let mut lines = head.split("\r\n");
        let request_line = lines.next()?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next()?.to_string();
        let target = parts.next()?.to_string();
        let mut chunked = false;
        let mut wants_close = false;
        let mut content_len = 0usize;
        for line in lines {
            let lower = line.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("content-length:") {
                content_len = v.trim().parse().ok()?;
            }
            if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
                chunked = true;
            }
            for key in ["connection:", "proxy-connection:"] {
                if let Some(v) = lower.strip_prefix(key) {
                    if v.split(',').any(|t| t.trim() == "close") {
                        wants_close = true;
                    }
                }
            }
        }
        let path = target
            .strip_prefix("http://")
            .and_then(|rest| rest.find('/').map(|i| &rest[i..]))
            .unwrap_or(&target)
            .to_string();
        let mut consumed = head_end + 4;
        let mut body = Vec::new();
        if chunked {
            let mut off = consumed;
            loop {
                let rest = acc.get(off..)?;
                let line_end = rest.windows(2).position(|w| w == b"\r\n")? + off;
                let size_line = String::from_utf8_lossy(&acc[off..line_end]).into_owned();
                let size = usize::from_str_radix(
                    size_line.split(';').next().unwrap_or_default().trim(),
                    16,
                )
                .ok()?;
                off = line_end + 2;
                if size == 0 {
                    // 终止块：trailer 段透传到空行
                    loop {
                        let rest = acc.get(off..)?;
                        let line_end = rest.windows(2).position(|w| w == b"\r\n")? + off;
                        let empty = line_end == off;
                        off = line_end + 2;
                        if empty {
                            break;
                        }
                    }
                    break;
                }
                body.extend_from_slice(acc.get(off..off + size)?);
                off += size + 2;
            }
            consumed = off;
        } else if content_len > 0 {
            body.extend_from_slice(acc.get(consumed..consumed + content_len)?);
            consumed += content_len;
        }
        Some((method, path, body, wants_close, consumed))
    }

    /// ft58 S1 测试桩：本地 HTTP 上游。单连接逐请求解析响应，GET 回 200+path、
    /// POST 回 200+请求体；请求带 close token 或连接 EOF 时关连接（对齐真实
    /// 上游收到转发头强制 `connection: close` 后的行为）。返回 (地址, accept 计数)。
    async fn spawn_http_upstream_for_test()
    -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let conns = Arc::new(AtomicUsize::new(0));
        let conns_task = Arc::clone(&conns);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { break };
                conns_task.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let mut acc: Vec<u8> = Vec::new();
                    loop {
                        let (method, path, body, wants_close, consumed) = loop {
                            if let Some(done) = parse_http_request_for_test(&acc) {
                                break done;
                            }
                            let mut b = [0u8; 4096];
                            match sock.read(&mut b).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => acc.extend_from_slice(&b[..n]),
                            }
                        };
                        acc.drain(..consumed);
                        let body = if method == "GET" { path.into_bytes() } else { body };
                        let resp =
                            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                        if sock.write_all(resp.as_bytes()).await.is_err()
                            || sock.write_all(&body).await.is_err()
                        {
                            return;
                        }
                        if wants_close {
                            return;
                        }
                    }
                });
            }
        });
        (addr, conns)
    }

    /// ft58 S1 测试读代理响应：头块 + Content-Length 精确读完（keep-alive 下
    /// 不能多读一字节）。返回 (状态码, 头文本, body)。
    async fn read_http_response_for_test(
        sock: &mut tokio::net::TcpStream,
    ) -> (u16, String, Vec<u8>) {
        let mut acc: Vec<u8> = Vec::new();
        let head_end = loop {
            if let Some(p) = acc.windows(4).position(|w| w == b"\r\n\r\n") {
                break p;
            }
            let mut b = [0u8; 4096];
            let n = sock.read(&mut b).await.unwrap();
            assert!(n > 0, "EOF while reading response head");
            acc.extend_from_slice(&b[..n]);
        };
        let head = String::from_utf8_lossy(&acc[..head_end]).into_owned();
        let status: u16 = head
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("bad status line: {head}"));
        let content_len: usize = head
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .and_then(|v| v.trim().parse().ok())
            })
            .unwrap_or(0);
        let mut body = acc[head_end + 4..].to_vec();
        while body.len() < content_len {
            let mut b = [0u8; 4096];
            let n = sock.read(&mut b).await.unwrap();
            assert!(n > 0, "EOF while reading response body");
            body.extend_from_slice(&b[..n]);
        }
        body.truncate(content_len);
        (status, head, body)
    }

    /// ft58 S1 公共装配：本地 HTTP 上游 + serve_http 实例。
    /// 返回 (代理地址, 上游地址, 上游 accept 连接计数)。
    async fn spawn_http_proxy_harness_for_test()
    -> (std::net::SocketAddr, std::net::SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        let (upstream, conns) = spawn_http_upstream_for_test().await;
        let proxy_addr = spawn_http_proxy_for_test().await;
        (proxy_addr, upstream, conns)
    }

    /// serve_http 实例（上游由 DialDispatch 按请求 dest 现拨，脚本化响应桩只需
    /// 监听自己的地址即可）。
    async fn spawn_http_proxy_for_test() -> std::net::SocketAddr {
        let ohm = Arc::new(SimpleOhm::new());
        ohm.set_default(Arc::new(DialDispatch) as Arc<dyn xray_app_dispatcher::DispatchHandler>);
        let listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        )
        .await
        .unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(serve_http(
            listener,
            ohm,
            Arc::new(HttpServerConfig::default()),
            Some(std::time::Duration::from_secs(5)),
            test_plugin_ctx("http"),
        ));
        proxy_addr
    }

    /// 脚本化上游：按 CL/chunked 定界精确解析一条请求，记录**请求头块原文**
    /// 后回 `200` + 请求体回显并关闭（转发头强制 connection: close）。
    /// 返回 (地址, 捕获的请求头块)。
    async fn spawn_capturing_http_upstream_for_test()
    -> (std::net::SocketAddr, Arc<std::sync::Mutex<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = Arc::new(std::sync::Mutex::new(String::new()));
        let cap = Arc::clone(&captured);
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            let mut acc: Vec<u8> = Vec::new();
            let mut head_end: Option<usize> = None;
            let (_, _, body, _, _) = loop {
                if head_end.is_none() {
                    head_end = acc.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4);
                }
                if let Some(done) = parse_http_request_for_test(&acc) {
                    break done;
                }
                let mut b = [0u8; 4096];
                match sock.read(&mut b).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => acc.extend_from_slice(&b[..n]),
                }
            };
            let head_end = head_end.expect("request head must be complete");
            *cap.lock().unwrap() = String::from_utf8_lossy(&acc[..head_end]).into_owned();
            let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            if sock.write_all(resp.as_bytes()).await.is_err()
                || sock.write_all(&body).await.is_err()
            {
                return;
            }
            let _ = sock.shutdown().await;
        });
        (addr, captured)
    }

    /// 脚本化上游：读到请求头结束即回写给定原始响应字节，随后关闭。
    async fn spawn_raw_response_upstream_for_test(response: &'static [u8]) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            let mut acc: Vec<u8> = Vec::new();
            loop {
                if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                let mut b = [0u8; 4096];
                match sock.read(&mut b).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => acc.extend_from_slice(&b[..n]),
                }
            }
            let _ = sock.write_all(response).await;
            let _ = sock.shutdown().await;
        });
        addr
    }

    /// 连接语义以 Go v26.10.17 实测为基准（探针
    /// `reports/audit-2026-10-28/tmp/http_keepalive_ref.py`，同一份 mixed+freedom
    /// 配置跑 Go 内核）：响应头**恒**回 keep-alive 三头（Go `ContentLength >= 0`
    /// 分支，与请求的任何连接头、HTTP 版本无关）；连接复用**只看**请求的
    /// `Proxy-Connection: keep-alive`（Go `Process`）——`Connection:` 头与 1.0/1.1
    /// 版本均不参与（bd g3mvq：此前按 RFC 版本分叉与 Go 反向，1.1 无头被错误续连
    /// 且第二个响应被拼进首个 body）。
    #[tokio::test]
    async fn http_connection_semantics_match_go_26_10_17() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        struct Case {
            name: &'static str,
            version: &'static str,
            extra: &'static str,
            expect_reuse: bool,
        }
        let cases = [
            Case { name: "1.1-无连接头", version: "HTTP/1.1", extra: "", expect_reuse: false },
            Case {
                name: "1.1-Connection: close",
                version: "HTTP/1.1",
                extra: "Connection: close\r\n",
                expect_reuse: false,
            },
            Case {
                name: "1.1-Connection: keep-alive",
                version: "HTTP/1.1",
                extra: "Connection: keep-alive\r\n",
                expect_reuse: false,
            },
            Case {
                name: "1.1-Proxy-Connection: keep-alive",
                version: "HTTP/1.1",
                extra: "Proxy-Connection: keep-alive\r\n",
                expect_reuse: true,
            },
            Case {
                // Go 只看 Proxy-Connection：Connection: close 不取消复用
                name: "1.1-close+Proxy-Connection: keep-alive",
                version: "HTTP/1.1",
                extra: "Connection: close\r\nProxy-Connection: keep-alive\r\n",
                expect_reuse: true,
            },
            Case { name: "1.0-无连接头", version: "HTTP/1.0", extra: "", expect_reuse: false },
            Case {
                name: "1.0-Proxy-Connection: keep-alive",
                version: "HTTP/1.0",
                extra: "Proxy-Connection: keep-alive\r\n",
                expect_reuse: true,
            },
        ];
        for case in cases {
            let (proxy, upstream, _conns) = spawn_http_proxy_harness_for_test().await;
            let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
            let base = format!("http://127.0.0.1:{}/", upstream.port());
            let req = format!(
                "GET {base}f5 {}\r\nHost: 127.0.0.1:{}\r\n{}\r\n",
                case.version,
                upstream.port(),
                case.extra
            );
            client.write_all(req.as_bytes()).await.unwrap();

            let (status, head, body) = read_http_response_for_test(&mut client).await;
            assert_eq!(status, 200, "[{}]", case.name);
            assert_eq!(body, b"/f5", "[{}]", case.name);
            // Go 实测逐字节布局（响应头不受请求连接头/版本影响）
            assert_eq!(
                head,
                "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: keep-alive\r\n\
                 Keep-Alive: timeout=60\r\nProxy-Connection: keep-alive",
                "[{}]",
                case.name
            );

            if case.expect_reuse {
                let second = format!(
                    "GET {base}f5-second {}\r\nHost: 127.0.0.1:{}\r\n{}\r\n",
                    case.version,
                    upstream.port(),
                    case.extra
                );
                client.write_all(second.as_bytes()).await.unwrap();
                let (status2, _head2, body2) = read_http_response_for_test(&mut client).await;
                assert_eq!(status2, 200, "[{}]", case.name);
                assert_eq!(body2, b"/f5-second", "[{}]", case.name);
            } else {
                // Go：未宣告 Proxy-Connection: keep-alive → 响应后即断（graceful drain 后 FIN）
                let mut eof = [0u8; 64];
                let n =
                    tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut eof))
                        .await
                        .unwrap_or_else(|_| panic!("[{}] EOF within 5s", case.name))
                        .unwrap();
                assert_eq!(n, 0, "[{}] must close after response", case.name);
            }
        }
    }

    /// ft58 S1：同一客户端连接上连续两个 plain HTTP 代理请求均成功且回包正确
    /// （keep-alive 复用，Go 语义 = 请求带 `Proxy-Connection: keep-alive`；
    /// 改动前每请求即关连接，第二请求必 EOF）；第三个请求不带该头（带
    /// `Connection: close`）→ 响应后服务端收尾关闭（EOF 干净）。
    #[tokio::test]
    async fn http_keep_alive_reuses_connection_between_requests() {
        let (proxy, upstream, upstream_conns) = spawn_http_proxy_harness_for_test().await;
        let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let upstream_port = upstream.port();
        let base = format!("http://127.0.0.1:{upstream_port}/");

        client
            .write_all(
                format!(
                    "GET {base}first HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\
                     Proxy-Connection: keep-alive\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let (status, head, body) = read_http_response_for_test(&mut client).await;
        assert_eq!(status, 200, "first request: {head}");
        assert_eq!(body, b"/first");

        // 同一连接第二请求（改动前此处 EOF/断链）
        client
            .write_all(
                format!(
                    "GET {base}second HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\
                     Proxy-Connection: keep-alive\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let (status, head, body) = read_http_response_for_test(&mut client).await;
        assert_eq!(status, 200, "second request: {head}");
        assert_eq!(body, b"/second");

        // 未宣告 proxy keep-alive → 响应可读且随后干净 EOF
        client
            .write_all(
                format!("GET {base}third HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let (status, head, body) = read_http_response_for_test(&mut client).await;
        assert_eq!(status, 200, "third request: {head}");
        assert_eq!(body, b"/third");
        let mut rest = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), client.read_to_end(&mut rest))
            .await
            .expect("server must close after a request without Proxy-Connection: keep-alive")
            .unwrap();
        assert!(rest.is_empty(), "no extra bytes after close: {rest:?}");

        // 上游每请求一条新链路（对齐 Go handlePlainHTTP Dispatch per request）
        assert_eq!(
            upstream_conns.load(std::sync::atomic::Ordering::Relaxed),
            3,
            "one fresh upstream connection per request"
        );
    }

    /// P1-1：mixed 入站的 HTTP 分支同样要 keep-alive——首包 sniff 判 HTTP 后，
    /// 同一 TCP 连接上两个 plain 请求都必须成功（改动前单请求即断，第二个 EOF）。
    #[tokio::test]
    async fn mixed_http_keep_alive_reuses_connection_between_requests() {
        let (upstream, _conns) = spawn_http_upstream_for_test().await;
        let ohm = Arc::new(SimpleOhm::new());
        ohm.set_default(Arc::new(DialDispatch) as Arc<dyn xray_app_dispatcher::DispatchHandler>);
        let listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        )
        .await
        .unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(serve_mixed(
            listener,
            ohm,
            Arc::new(ServerConfig::default()),
            Arc::new(HttpServerConfig::default()),
            Some(std::time::Duration::from_secs(5)),
            std::time::Duration::from_secs(5),
            test_plugin_ctx("mixed"),
        ));

        let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        let upstream_port = upstream.port();
        let base = format!("http://127.0.0.1:{upstream_port}/");
        for path in ["first", "second"] {
            client
                .write_all(
                    format!(
                        "GET {base}{path} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\
                         Proxy-Connection: keep-alive\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let (status, head, body) = read_http_response_for_test(&mut client).await;
            assert_eq!(status, 200, "mixed keep-alive request {path}: {head}");
            assert_eq!(body, format!("/{path}").as_bytes(), "upstream body echo for {path}");
        }
    }

    /// ft58 S1：Content-Length 请求体必须精确消费后才读下一请求——POST+body 与
    /// 下一 GET 一次流水线写入，body 若被吞多/吞少第二请求必然错位。
    #[tokio::test]
    async fn http_keep_alive_consumes_content_length_body_before_next_request() {
        let (proxy, upstream, _conns) = spawn_http_proxy_harness_for_test().await;
        let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let upstream_port = upstream.port();
        let base = format!("http://127.0.0.1:{upstream_port}/");
        let payload = "hello-proxy-body";
        let post = format!(
            "POST {base}upload HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\
             Proxy-Connection: keep-alive\r\nContent-Length: {}\r\n\r\n{payload}",
            payload.len()
        );
        let get = format!(
            "GET {base}after-post HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\
             Proxy-Connection: keep-alive\r\n\r\n"
        );
        client.write_all(format!("{post}{get}").as_bytes()).await.unwrap();

        let (status, head, body) = read_http_response_for_test(&mut client).await;
        assert_eq!(status, 200, "post response: {head}");
        assert_eq!(body, payload.as_bytes(), "upstream must echo the body");
        let (status, head, body) = read_http_response_for_test(&mut client).await;
        assert_eq!(status, 200, "request after body must not be misaligned: {head}");
        assert_eq!(body, b"/after-post");
    }

    /// ft58 S1：chunked 请求体逐帧消费到终止块后才读下一请求（帧原样转发，
    /// 转发头保留 transfer-encoding，与 Go ReadRequest 解码 + request.Write
    /// 重编码线路上等价）。
    #[tokio::test]
    async fn http_keep_alive_consumes_chunked_body_before_next_request() {
        let (proxy, upstream, _conns) = spawn_http_proxy_harness_for_test().await;
        let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let upstream_port = upstream.port();
        let base = format!("http://127.0.0.1:{upstream_port}/");
        // 7 字节 + 2 字节两帧（非整缓冲对齐），终止块带空 trailer
        let post = format!(
            "POST {base}chunked HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\
             Proxy-Connection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n7\r\nchunk-1\r\n2\r\nd!\r\n0\r\n\r\n"
        );
        let get = format!(
            "GET {base}after-chunked HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\
             Proxy-Connection: keep-alive\r\n\r\n"
        );
        client.write_all(format!("{post}{get}").as_bytes()).await.unwrap();

        let (status, head, body) = read_http_response_for_test(&mut client).await;
        assert_eq!(status, 200, "chunked post response: {head}");
        assert_eq!(body, b"chunk-1d!", "chunked body must be decoded by upstream");
        let (status, head, body) = read_http_response_for_test(&mut client).await;
        assert_eq!(status, 200, "request after chunked body must not be misaligned: {head}");
        assert_eq!(body, b"/after-chunked");
    }

    /// 构造 header map（同名多值逐条 push，模拟线上重复头）。
    fn framing_headers(pairs: &[(&str, &str)]) -> HashMap<String, Vec<String>> {
        let mut headers: HashMap<String, Vec<String>> = HashMap::new();
        for (key, value) in pairs {
            headers.entry((*key).to_string()).or_default().push((*value).to_string());
        }
        headers
    }

    /// F8：请求定界走私加固（对齐 Go `fixLength`/`parseTransferEncoding`，
    /// net/http/transfer.go:661）。多值 CL 不一致、非法 CL 值、非单一 chunked
    /// TE 全部拒绝（Go 侧 `ReadRequest` 报错 → 断链）。
    #[test]
    fn request_framing_rejects_conflicting_content_length_and_bad_values() {
        assert!(
            plan_request_framing(&framing_headers(&[
                ("content-length", "5"),
                ("content-length", "6"),
            ]))
            .is_err()
        );
        // 空 / 负数 / 带符号 / 非数字 / 超 i64::MAX（Go ParseUint(…, 63) 全拒）
        for bad in ["", " -1", "+5", "abc", "12a", "9223372036854775808"] {
            assert!(
                plan_request_framing(&framing_headers(&[("content-length", bad)])).is_err(),
                "Content-Length {bad:?} must be rejected"
            );
        }
        // TE：多个头 / 多编码栈 / 未知编码 → 拒绝
        assert!(
            plan_request_framing(&framing_headers(&[
                ("transfer-encoding", "chunked"),
                ("transfer-encoding", "chunked"),
            ]))
            .is_err()
        );
        assert!(
            plan_request_framing(&framing_headers(&[("transfer-encoding", "gzip, chunked")]))
                .is_err()
        );
        assert!(
            plan_request_framing(&framing_headers(&[("transfer-encoding", "identity")])).is_err()
        );
    }

    /// F8：值相同的重复 CL 折叠为一条；chunked 与 CL 并存时 chunked 生效且转发
    /// 头删除 CL（RFC 9112 §6.3 中间件义务，防 CL.TE 走私；对齐 Go
    /// `fixLength` 的 `header.Del("Content-Length")`）。
    #[test]
    fn request_framing_dedupes_content_length_and_drops_it_for_chunked() {
        let headers = framing_headers(&[("content-length", "42"), ("content-length", "42")]);
        let (plan, forward) = plan_request_framing(&headers).unwrap();
        assert!(matches!(plan, RequestBodyPlan::Length(42)));
        assert_eq!(forward.get("content-length"), Some(&vec!["42".to_string()]));

        let headers = framing_headers(&[("content-length", "5"), ("transfer-encoding", "chunked")]);
        let (plan, forward) = plan_request_framing(&headers).unwrap();
        assert!(matches!(plan, RequestBodyPlan::Chunked));
        assert!(!forward.contains_key("content-length"), "chunked 生效时 CL 必须删除");
        assert_eq!(forward.get("transfer-encoding"), Some(&vec!["chunked".to_string()]));
    }

    /// F8：坏头行（无冒号）不再被静默跳过——整条响应作废走 503（Go textproto
    /// 严格语义）。静默跳过会让畸形行被忽略而按 CL 定界，留下走私空间。
    #[test]
    fn parse_head_block_rejects_header_line_without_colon() {
        // 头块契约：不含结尾空行（`\r\n\r\n` 已被调用方切掉，最后一行无尾随 CRLF）
        assert!(parse_head_block(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nbogus").is_none());
        let (_, code, headers) = parse_head_block(b"HTTP/1.1 200 OK\r\nContent-Length: 5")
            .expect("well-formed head must parse");
        assert_eq!(code, 200);
        assert_eq!(headers.get("content-length"), Some(&vec!["5".to_string()]));
    }

    /// F8：多值 CL 不一致的请求直接被拒——客户端读到 EOF、零响应字节，且不
    /// 触发任何上游拨号（对齐 Go `ReadRequest` 失败后不回包断链）。
    #[tokio::test]
    async fn http_conflicting_duplicate_content_length_closes_connection() {
        let (proxy, upstream, upstream_conns) = spawn_http_proxy_harness_for_test().await;
        let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let upstream_port = upstream.port();
        client
            .write_all(
                format!(
                    "POST http://127.0.0.1:{upstream_port}/smuggle HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhelloX"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut resp = Vec::new();
        let mut buf = [0u8; 4096];
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match client.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => resp.extend_from_slice(&buf[..n]),
                    // Windows：关闭时仍有未读客户端字节（body）→ RST 而非 FIN
                    // （F6 已知项，不在本修复范围）；协议层判定只看「无响应字节」。
                    Err(_) => break,
                }
            }
        })
        .await
        .expect("malformed request must end the connection");
        assert!(
            resp.is_empty(),
            "no response bytes on framing error: {:?}",
            String::from_utf8_lossy(&resp)
        );
        assert_eq!(
            upstream_conns.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "framing error must be rejected before dispatch"
        );
    }

    /// F8：值相同的重复 CL 转发时只留一条（上游收到的头块里只有一次
    /// content-length，body 按该长度转发一次）。
    #[tokio::test]
    async fn http_identical_duplicate_content_length_is_forwarded_once() {
        let (upstream, captured) = spawn_capturing_http_upstream_for_test().await;
        let proxy = spawn_http_proxy_for_test().await;
        let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let upstream_port = upstream.port();
        client
            .write_all(
                format!(
                    "POST http://127.0.0.1:{upstream_port}/dup HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let (status, head, body) = read_http_response_for_test(&mut client).await;
        assert_eq!(status, 200, "{head}");
        assert_eq!(body, b"hello", "body forwarded once per Content-Length");

        let forwarded = captured.lock().unwrap().to_ascii_lowercase();
        assert_eq!(
            forwarded.matches("content-length:").count(),
            1,
            "duplicate Content-Length must be collapsed: {forwarded}"
        );
    }

    /// F8（CL.TE）：CL 与 `Transfer-Encoding: chunked` 并存 → chunked 生效、
    /// 转发头删除 CL，chunked 帧原样到达上游（不出现「两者都信」）。
    #[tokio::test]
    async fn http_content_length_with_chunked_drops_length_on_forward() {
        let (upstream, captured) = spawn_capturing_http_upstream_for_test().await;
        let proxy = spawn_http_proxy_for_test().await;
        let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let upstream_port = upstream.port();
        client
            .write_all(
                format!(
                    "POST http://127.0.0.1:{upstream_port}/te HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nContent-Length: 999\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let (status, head, body) = read_http_response_for_test(&mut client).await;
        assert_eq!(status, 200, "{head}");
        assert_eq!(body, b"hello", "chunked body must reach upstream");

        let forwarded = captured.lock().unwrap().to_ascii_lowercase();
        assert!(forwarded.contains("transfer-encoding: chunked"), "{forwarded}");
        assert!(
            !forwarded.contains("content-length"),
            "Content-Length must be dropped when chunked: {forwarded}"
        );
    }

    /// F4：101 Switching Protocols 头块原样交给客户端（`Upgrade` 与
    /// `Connection: Upgrade` 不被当 hop-by-hop 剥掉，RFC 7230 §6.7），随后是
    /// 裸隧道字节流直到上游断开。
    #[tokio::test]
    async fn http_101_switching_protocols_keeps_upgrade_headers() {
        let upstream = spawn_raw_response_upstream_for_test(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n\x00tunnel-bytes",
        )
        .await;
        let proxy = spawn_http_proxy_for_test().await;
        let mut client = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let upstream_port = upstream.port();
        client
            .write_all(
                format!(
                    "GET http://127.0.0.1:{upstream_port}/ws HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut resp = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), client.read_to_end(&mut resp))
            .await
            .expect("101 + tunnel bytes then EOF")
            .unwrap();

        let text = String::from_utf8_lossy(&resp).to_ascii_lowercase();
        assert!(text.starts_with("http/1.1 101 switching protocols\r\n"), "{text}");
        assert!(text.contains("upgrade: websocket"), "Upgrade must survive: {text}");
        assert!(text.contains("connection: upgrade"), "Connection: Upgrade must survive: {text}");
        assert!(resp.ends_with(b"\x00tunnel-bytes"), "tunnel bytes must pass through: {resp:?}");
    }

    /// b2e：SOCKS UDP ASSOCIATE relay 经 dispatcher（UdpDispatchSession）。
    #[tokio::test]
    async fn socks_udp_dispatch_roundtrip() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let handler: Arc<dyn xray_app_dispatcher::DispatchHandler> =
            Arc::new(MarkerUdpDispatch { marker: b"via-dispatch" });
        // 客户端先 bind：expected 取客户端地址（来源过滤，bd wq16g）
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay = TempUdpRelay::new(relay, client.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = handle_udp_associate(relay, handler, std::time::Duration::from_secs(300)).await;
        });

        // 客户端 → relay socket：SOCKS5 UDP 请求帧（目标仅作路由地址，不打真实包）
        let target = SocksAddr { host: Host::Ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)), port: 53 };
        client.send_to(&encode_udp_packet(&target, b"ping"), relay_addr).await.unwrap();

        // 响应必须是 MarkerUdpDispatch 写回的标记帧（raw 直连路径给不出）
        let mut rbuf = [0u8; 1500];
        let (n, _) =
            tokio::time::timeout(std::time::Duration::from_secs(5), client.recv_from(&mut rbuf))
                .await
                .expect("response via dispatcher within 5s")
                .unwrap();
        let (_src, payload) = decode_udp_packet(&rbuf[..n]).unwrap();
        assert_eq!(payload, b"via-dispatch");
    }

    /// wq16g 夹具：每收一帧原样回显（来源 = 请求 target），用来观测某数据报
    /// 是否真的被 relay 放行到 dispatch。
    #[derive(Debug)]
    struct EchoUdpDispatch;

    impl xray_app_dispatcher::DispatchHandler for EchoUdpDispatch {
        fn tag(&self) -> &str {
            "echo-udp-dispatch"
        }

        fn dispatch(
            &self,
            dest: &Destination,
            link: Link,
        ) -> xray_app_dispatcher::default::PinFuture<()> {
            let source = Destination::udp(dest.address().clone(), dest.port());
            Box::pin(async move {
                let Link { mut reader, mut writer, .. } = link;
                while let Ok(mb) = reader.read_multi_buffer().await {
                    let flat = mb.to_vec();
                    let mut cursor = std::io::Cursor::new(&flat[..]);
                    let mut pr = xray_xudp::packet::PacketReader::new(&mut cursor);
                    while let Ok(Some(pkt)) = pr.read_packet() {
                        let (data, _) = pkt.into_parts();
                        let mut frame = Vec::with_capacity(data.len() + 64);
                        let mut pw = xray_xudp::packet::PacketWriter::new(
                            &mut frame,
                            source.clone(),
                            [0u8; 8],
                        );
                        let _ = pw.write_packet(&data);
                        drop(pw);
                        let mut mb = xray_buf::multi::MultiBuffer::new();
                        mb.merge_bytes(&frame);
                        let _ = writer.write_multi_buffer(mb).await;
                    }
                }
            })
        }
    }

    /// 读一个 relay 回发的 SOCKS5 UDP 响应帧的 payload（5s 上限）。
    async fn recv_relay_payload(sock: &UdpSocket) -> Vec<u8> {
        let mut rbuf = [0u8; 1500];
        let (n, _) =
            tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv_from(&mut rbuf))
                .await
                .expect("relay response within 5s")
                .unwrap();
        decode_udp_packet(&rbuf[..n]).unwrap().1.to_vec()
    }

    /// 静默观察窗：窗口内收到任何数据报即判定「被转发」。
    const DROP_WINDOW: std::time::Duration = std::time::Duration::from_millis(300);

    /// 断言 `sock` 在 [`DROP_WINDOW`] 内收不到任何数据报。
    async fn assert_dropped(sock: &UdpSocket, why: &str) {
        let mut rbuf = [0u8; 1500];
        let got = tokio::time::timeout(DROP_WINDOW, sock.recv_from(&mut rbuf)).await;
        assert!(got.is_err(), "{why}");
    }

    fn udp_test_frame(payload: &[u8]) -> Vec<u8> {
        let target = SocksAddr { host: Host::Ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)), port: 53 };
        encode_udp_packet(&target, payload)
    }

    /// wq16g：relay 只接受客户端源**端口**——同 IP 不同端口的冒充帧必须被丢弃
    /// （不转发到 dispatch，也不改写 expected）。
    ///
    /// 判别器：冒充包若被放行，dispatch 会回显并把结果发给 expected（客户端）
    /// 或 last_client（冒充方，修前语义），两侧都能观测到——两个方向都断言为空。
    #[tokio::test]
    async fn socks_udp_associate_drops_foreign_source_port() {
        let relay_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_sock.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let impostor = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert_ne!(client.local_addr().unwrap(), impostor.local_addr().unwrap());
        let handler: Arc<dyn xray_app_dispatcher::DispatchHandler> = Arc::new(EchoUdpDispatch);
        let relay = TempUdpRelay::new(relay_sock, client.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = handle_udp_associate(relay, handler, std::time::Duration::from_secs(300)).await;
        });

        // 1. 合法来源：转发 + 回显
        client.send_to(&udp_test_frame(b"legit-1"), relay_addr).await.unwrap();
        assert_eq!(recv_relay_payload(&client).await, b"legit-1");

        // 2. 冒充来源（同 IP、别的端口）：不得转发（两侧都收不到回显）
        impostor.send_to(&udp_test_frame(b"evil"), relay_addr).await.unwrap();
        assert_dropped(&impostor, "foreign source port must not receive relay responses").await;
        assert_dropped(&client, "foreign frame must not be forwarded to dispatch (no echo)").await;

        // 3. expected 未被冒充包改写：客户端仍能正常往返
        client.send_to(&udp_test_frame(b"legit-2"), relay_addr).await.unwrap();
        assert_eq!(recv_relay_payload(&client).await, b"legit-2");
    }

    /// wq16g：来源**IP** 不匹配（不同主机）的帧即使最先到达也不得被接受，
    /// 更不能抢占 expected 的端口锁定（生产装配 `temp_udp_relay` 的同款路径：
    /// expected = TCP 对端 IP + 端口 0，首包锁定）。
    #[tokio::test]
    async fn socks_udp_associate_drops_foreign_ip_before_port_lock() {
        let relay_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_sock.local_addr().unwrap();
        // 冒充主机在同机另一个回环 IP（127.0.0.2 ≠ 127.0.0.1）
        let impostor = match UdpSocket::bind(("127.0.0.2", 0)).await {
            Ok(s) => s,
            Err(_) => UdpSocket::bind(("127.0.0.3", 0)).await.expect("bind 127.0.0.2/3"),
        };
        let handler: Arc<dyn xray_app_dispatcher::DispatchHandler> = Arc::new(EchoUdpDispatch);
        // 生产形态：expected = 客户端 IP + 端口 0
        let relay = temp_udp_relay(relay_sock, "127.0.0.1:9".parse().unwrap());
        tokio::spawn(async move {
            let _ = handle_udp_associate(relay, handler, std::time::Duration::from_secs(300)).await;
        });

        // 1. 冒充包先到：丢弃，且不得锁定端口
        impostor.send_to(&udp_test_frame(b"evil"), relay_addr).await.unwrap();
        assert_dropped(&impostor, "foreign source ip must be dropped").await;

        // 2. 合法客户端随后发：正常往返（端口由首包锁定）
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&udp_test_frame(b"legit"), relay_addr).await.unwrap();
        assert_eq!(recv_relay_payload(&client).await, b"legit");
    }

    /// UDP associate 空闲时限（Go server.go:171-175 SetTimeout(ConnectionIdle)）：
    /// 静默 relay 在 idle 到期后自行退出（task 结束）；活动续期——每次收发包
    /// 重置 deadline，持续活动下不退出。
    #[tokio::test]
    async fn socks_udp_associate_idle_timeout_expires_silent_relay() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let handler: Arc<dyn xray_app_dispatcher::DispatchHandler> =
            Arc::new(MarkerUdpDispatch { marker: b"idle" });
        let task = tokio::spawn(async move {
            let relay = TempUdpRelay::new(relay, "127.0.0.1:0".parse().unwrap());
            let _ =
                handle_udp_associate(relay, handler, std::time::Duration::from_millis(150)).await;
        });
        // 不发任何包：150ms 空闲后 relay 必须退出
        tokio::time::timeout(std::time::Duration::from_secs(3), task)
            .await
            .expect("silent relay must exit on idle timeout")
            .ok();
    }

    /// 留存 link 的 dispatch（完成但不关链路）：UdpDispatchSession 的会话
    /// 持续存活（对齐慢速真实上游），recv_packet 永不就绪，relay 只被
    /// recv_from 活动 / idle 超时驱动。
    struct KeepLinkDispatch {
        keepers: Arc<parking_lot::Mutex<Vec<Link>>>,
    }
    impl std::fmt::Debug for KeepLinkDispatch {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("KeepLinkDispatch")
        }
    }
    impl xray_app_dispatcher::DispatchHandler for KeepLinkDispatch {
        fn tag(&self) -> &str {
            "keep-link"
        }

        fn dispatch(
            &self,
            _dest: &Destination,
            link: Link,
        ) -> xray_app_dispatcher::default::PinFuture<()> {
            self.keepers.lock().push(link);
            Box::pin(async move {})
        }
    }

    /// 活动续期：每 60ms 一包（短于 150ms idle），relay 在 >400ms 观察窗内
    /// 保持存活；停发后再在 idle 内退出。
    #[tokio::test]
    async fn socks_udp_associate_idle_timeout_renews_on_activity() {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let handler: Arc<dyn xray_app_dispatcher::DispatchHandler> =
            Arc::new(KeepLinkDispatch { keepers: Arc::new(parking_lot::Mutex::new(Vec::new())) });
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay = TempUdpRelay::new(relay, client.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let _ =
                handle_udp_associate(relay, handler, std::time::Duration::from_millis(150)).await;
        });
        let target = SocksAddr { host: Host::Ipv4(std::net::Ipv4Addr::new(8, 8, 8, 8)), port: 53 };
        let t0 = std::time::Instant::now();
        while t0.elapsed() < std::time::Duration::from_millis(400) {
            let _ = client.send_to(&encode_udp_packet(&target, b"ping"), relay_addr).await;
            tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        }
        assert!(!task.is_finished(), "active relay must survive beyond one idle window");
        // 停发：idle 内退出
        tokio::time::timeout(std::time::Duration::from_secs(3), task)
            .await
            .expect("relay must exit after activity stops")
            .ok();
    }

    /// b2e：dokodemo UDP inbound 经 dispatcher（固定 dest）。
    #[tokio::test]
    async fn dokodemo_udp_dispatch_roundtrip() {
        let hub =
            xray_transport::udp::hub::UdpHub::listen("127.0.0.1:0".parse().unwrap(), &[], None)
                .await
                .unwrap();
        let local = hub.local_addr().unwrap();
        let handler: Arc<dyn xray_app_dispatcher::DispatchHandler> =
            Arc::new(MarkerUdpDispatch { marker: b"dokodemo-via-dispatch" });
        let dest =
            Destination::udp(Address::IPv4(std::net::Ipv4Addr::new(8, 8, 8, 8)), Port::new(53));
        tokio::spawn(async move {
            let _ =
                serve_dokodemo_udp_on(hub, handler, Some(dest), test_plugin_ctx("dokodemo")).await;
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"ping", local).await.unwrap();
        let mut rbuf = [0u8; 1500];
        let (n, _) =
            tokio::time::timeout(std::time::Duration::from_secs(5), client.recv_from(&mut rbuf))
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
        let hub =
            xray_transport::udp::hub::UdpHub::listen("127.0.0.1:0".parse().unwrap(), &[], None)
                .await
                .unwrap();
        let local = hub.local_addr().unwrap();
        let handler: Arc<dyn xray_app_dispatcher::DispatchHandler> =
            Arc::new(CounterUdpDispatch { counter: std::sync::atomic::AtomicU32::new(0) });
        let dest =
            Destination::udp(Address::IPv4(std::net::Ipv4Addr::new(8, 8, 8, 8)), Port::new(53));
        tokio::spawn(async move {
            let _ =
                serve_dokodemo_udp_on(hub, handler, Some(dest), test_plugin_ctx("dokodemo")).await;
        });

        let client_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client_a.send_to(b"from-a", local).await.unwrap();
        client_b.send_to(b"from-b", local).await.unwrap();

        async fn recv_marker(sock: &UdpSocket) -> String {
            let mut rbuf = [0u8; 1500];
            let (n, _) =
                tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv_from(&mut rbuf))
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
        opts.port_map.insert("80".to_string(), "192.168.99.1:9090".to_string());
        let dest = super::resolve_dokodemo_tcp_dest(&opts, None, Some(80), None, None).unwrap();
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
        let dest = super::resolve_dokodemo_tcp_dest(&opts, None, Some(80), None, None).unwrap();
        assert_eq!(dest.port().value(), 5353);
        match dest.address() {
            Address::IPv4(v4) => assert_eq!(v4.octets(), [10, 0, 0, 1]),
            other => panic!("expected predefined IPv4, got {other:?}"),
        }
    }

    #[test]
    fn resolve_dokodemo_port_map_domain_host() {
        let mut opts = tcp_opts();
        opts.port_map.insert("80".to_string(), "example.org:".to_string());
        let dest = super::resolve_dokodemo_tcp_dest(&opts, None, Some(80), None, None).unwrap();
        assert_eq!(dest.port().value(), 80);
        match dest.address() {
            Address::Domain(d) => assert_eq!(d, "example.org"),
            other => panic!("expected Domain, got {other:?}"),
        }
    }

    #[test]
    fn resolve_dokodemo_port_map_no_match_uses_predefined() {
        let mut opts = tcp_opts();
        opts.port_map.insert("443".to_string(), "192.168.99.1:9090".to_string());
        let dest = super::resolve_dokodemo_tcp_dest(&opts, None, Some(80), None, None).unwrap();
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
        let dest =
            super::resolve_dokodemo_tcp_dest(&opts, None, Some(80), None, Some("sni.example.com"))
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
    fn resolve_dokodemo_follow_redirect_rejects_without_original_dst() {
        // 非 Linux / 非 REDIRECT 连接：无 original_dst、无 SNI → 拒连
        // （对齐 Go dokodemo.go:137 unable to get destination；不回落 predefined）。
        let mut opts = tcp_opts();
        opts.follow_redirect = true;
        assert!(
            super::resolve_dokodemo_tcp_dest(&opts, None, Some(80), None, None).is_none(),
            "followRedirect 拿不到原始目标必须拒连，不得回落 predefined dest"
        );
    }

    #[test]
    fn resolve_dokodemo_follow_redirect_skips_port_map_and_rejects() {
        // Go：portMap 分支在 !FollowRedirect 内（互斥）；无 original dst/SNI → 拒连。
        let mut opts = tcp_opts();
        opts.follow_redirect = true;
        opts.port_map.insert("80".to_string(), "192.168.99.1:9090".to_string());
        assert!(super::resolve_dokodemo_tcp_dest(&opts, None, Some(80), None, None).is_none());
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

    /// dokodemo 专用 capture：先等上行 payload 真正落到服务端（≥expect 字节或流
    /// 提前结束）再回 `ok`。dokodemo 无握手、accept 即 dispatch；若不等 payload，
    /// `ok` 会在客户端 sudoku 桥接任务（wrap_conn_client 的 spawn+duplex）落盘前
    /// 回到客户端，wire_sent 断言读到空——高负载下的确定性竞态。因果保证：服务端
    /// socket 收到字节 ⇒ 同一批字节必已经过客户端 tap 的 poll_write（先记账后落
    /// socket），wire 断言因此有 happens-before，不靠 sleep。
    #[derive(Debug)]
    struct PayloadGateDispatch {
        expect: usize,
    }

    impl xray_app_dispatcher::DispatchHandler for PayloadGateDispatch {
        fn tag(&self) -> &str {
            "payload-gate"
        }

        fn dispatch(
            &self,
            _dest: &Destination,
            link: Link,
        ) -> xray_app_dispatcher::default::PinFuture<()> {
            let expect = self.expect;
            Box::pin(async move {
                let Link { mut writer, mut reader } = link;
                let mut seen = 0usize;
                while seen < expect {
                    match reader.read_multi_buffer().await {
                        // EOF：照旧回写标记，让 wire 断言失败可见而非挂死
                        Ok(mb) if mb.is_empty() => break,
                        Ok(mb) => seen += mb.len(),
                        Err(_) => break,
                    }
                }
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
        let bridge = Arc::new(DestCaptureDispatch { dest: parking_lot::Mutex::new(None) })
            as Arc<dyn xray_app_dispatcher::DispatchHandler>;
        ohm.set_default(bridge);

        let listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        )
        .await
        .unwrap();
        let addr = listener.local_addr().unwrap();
        let config = HttpServerConfig { user_level: 3, ..Default::default() };
        let pm: Arc<dyn xray_features::policy::PolicyManager> =
            Arc::new(FixedHandshakePolicy(std::time::Duration::from_millis(120)));
        let handshake_timeout = Some(pm.policy_for_level(config.user_level).timeout.handshake);
        tokio::spawn(serve_http(
            listener,
            ohm,
            Arc::new(config),
            handshake_timeout,
            test_plugin_ctx("http"),
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
        assert!(elapsed < std::time::Duration::from_secs(2), "timeout too slow: {elapsed:?}");
    }

    /// socks 握手限时行为测试：客户端连上后保持静默，handshake_timeout 到期
    /// → 服务端断开 → 客户端读到 EOF（Go proxy/socks SetReadDeadline 语义）。
    /// None 时不限时由既有握手 e2e 覆盖。
    #[tokio::test]
    async fn serve_socks5_handshake_timeout_disconnects_silent_client() {
        use tokio::io::AsyncReadExt;

        let ohm = Arc::new(SimpleOhm::new());
        let bridge = Arc::new(DestCaptureDispatch { dest: parking_lot::Mutex::new(None) })
            as Arc<dyn xray_app_dispatcher::DispatchHandler>;
        ohm.set_default(bridge);

        let listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        )
        .await
        .unwrap();
        let addr = listener.local_addr().unwrap();
        let config = Arc::new(parse_socks_server_config(b"{}").unwrap());
        tokio::spawn(serve_socks5(
            listener,
            ohm,
            config,
            Some(std::time::Duration::from_millis(120)),
            std::time::Duration::from_secs(300),
            test_plugin_ctx("socks"),
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
        assert!(elapsed < std::time::Duration::from_secs(2), "timeout too slow: {elapsed:?}");
    }

    /// i09 e2e：dokodemo TCP port_map——按监听端口改写 dest（Go dokodemo.go:101-109）。
    #[tokio::test]
    async fn dokodemo_tcp_port_map_dispatch_e2e() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let ohm = Arc::new(SimpleOhm::new());
        let capture = Arc::new(DestCaptureDispatch { dest: parking_lot::Mutex::new(None) });
        ohm.set_default(capture.clone() as Arc<dyn DispatchHandler>);

        let listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        )
        .await
        .unwrap();
        let port = listener.local_addr().unwrap().port();
        let opts = DokodemoTcpOptions {
            dest: Some(Destination::tcp(
                Address::IPv4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                Port::new(80),
            )),
            port_map: [(port.to_string(), "192.168.99.1:9090".to_string())].into_iter().collect(),
            follow_redirect: false,
            tls: None,
        };
        tokio::spawn(async move {
            let _ = serve_dokodemo(listener, ohm, opts, test_plugin_ctx("dokodemo")).await;
        });

        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
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
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
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
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
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
        let params = rcgen::CertificateParams::new(vec!["sni.example.com".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let stream_settings = serde_json::json!({
            "security": "tls",
            "tlsSettings": { "cert": cert.pem(), "key": key_pair.serialize_pem() }
        });
        let tls = super::build_tls_acceptor(Some(&stream_settings)).unwrap().expect("tls acceptor");

        // 2. serve_dokodemo：predefined dest 1.2.3.4:80 + follow_redirect（SNI 门控）
        let ohm = Arc::new(SimpleOhm::new());
        let capture = Arc::new(DestCaptureDispatch { dest: parking_lot::Mutex::new(None) });
        ohm.set_default(capture.clone() as Arc<dyn DispatchHandler>);
        let listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        )
        .await
        .unwrap();
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
            let _ = serve_dokodemo(listener, ohm, opts, test_plugin_ctx("dokodemo")).await;
        });

        // 3. 客户端 TLS 握手带 SNI sni.example.com
        let client_cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
        let sock = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let server_name =
            rustls::pki_types::ServerName::try_from("sni.example.com").unwrap().to_owned();
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

    /// i09 e2e：followRedirect 但无 NAT/非 Linux——拿不到原始目标 → 拒连
    /// （Go dokodemo.go:137 unable to get destination；不回落 predefined dest）。
    #[tokio::test]
    async fn dokodemo_follow_redirect_rejects_without_original_dst_e2e() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let ohm = Arc::new(SimpleOhm::new());
        let capture = Arc::new(DestCaptureDispatch { dest: parking_lot::Mutex::new(None) });
        ohm.set_default(capture.clone() as Arc<dyn DispatchHandler>);
        let listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        )
        .await
        .unwrap();
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
            let _ = serve_dokodemo(listener, ohm, opts, test_plugin_ctx("dokodemo")).await;
        });

        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(b"ping").await.unwrap();

        // 直连（无 iptables REDIRECT）：拿不到原始目标 → 拒连——dest 永不 dispatch，
        // 连接被关闭（EOF），而非静默转发 predefined dest。
        for _ in 0..50 {
            if capture.dest.lock().is_some() {
                panic!("followRedirect 无原始目标时不得 dispatch 到任何 dest");
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let mut buf = [0u8; 2];
        let n = client.read(&mut buf).await.unwrap_or(0);
        assert_eq!(n, 0, "连接应被关闭（EOF），而非转发 predefined dest");
        assert!(capture.dest.lock().is_none());
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
        let user =
            VlessValidatorTrait::get(&*validator, &parsed_uuid).expect("user should be registered");
        assert_eq!(user.email, "alice@example.com");
    }

    /// FieldAudit P1 回归：users 形态（生产 xr.json 全族形态）必须可达——
    /// Go vless.go:46-48 users 为 clients 合法别名，只读 clients = 0 用户全拒。
    #[test]
    fn build_vless_validator_accepts_users_alias() {
        let uuid = "66ad4540-b58c-4ad2-9926-ea63445a9b57";
        let settings =
            serde_json::json!({ "users": [{ "id": uuid, "email": "alice@example.com" }] });
        let data = serde_json::to_vec(&settings).unwrap();
        let validator = super::build_vless_validator(&data).unwrap();
        use xray_proxy_vless::Validator as VlessValidatorTrait;
        assert_eq!(VlessValidatorTrait::get_uuid_count(&*validator), 1);
    }

    /// clients+users 同场：Go 覆盖语义 = clients 完全取代 users（vless.go:46-48）。
    #[test]
    fn build_vless_validator_clients_override_users_when_both_present() {
        let ua = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let ub = "66ad4540-b58c-4ad2-9926-ea63445a9b57";
        let uc = "d342d11e-d424-4583-b36e-524ab1f0afa4";
        let settings = serde_json::json!({
            "users": [{ "id": ua }, { "id": ub }],
            "clients": [{ "id": uc }],
        });
        let data = serde_json::to_vec(&settings).unwrap();
        let validator = super::build_vless_validator(&data).unwrap();
        use xray_proxy_vless::Validator as VlessValidatorTrait;
        assert_eq!(VlessValidatorTrait::get_uuid_count(&*validator), 1, "clients wins");
        let uc_uuid = xray_common::uuid::UUID::parse(uc).unwrap();
        assert!(VlessValidatorTrait::get(&*validator, &uc_uuid).is_some(), "client registered");
        let ua_uuid = xray_common::uuid::UUID::parse(ua).unwrap();
        assert!(VlessValidatorTrait::get(&*validator, &ua_uuid).is_none(), "users dropped");
    }

    /// `"clients": null` 不覆盖 users（Go JSON null → nil slice，不触发覆盖分支）。
    #[test]
    fn build_vless_validator_null_clients_falls_back_to_users() {
        let uuid = "66ad4540-b58c-4ad2-9926-ea63445a9b57";
        let settings = serde_json::json!({ "clients": null, "users": [{ "id": uuid }], });
        let data = serde_json::to_vec(&settings).unwrap();
        let validator = super::build_vless_validator(&data).unwrap();
        use xray_proxy_vless::Validator as VlessValidatorTrait;
        assert_eq!(VlessValidatorTrait::get_uuid_count(&*validator), 1);
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
        let bad = xray_common::uuid::UUID::parse("d342d11e-d424-4583-b36e-524ab1f0afa4")
            .expect("uuid bad");
        assert!(VlessValidatorTrait::get(&*validator, &bad).is_none());
    }

    /// 8i4c：testseed 两级流转（Go vless.go:80-82）——user 级 ≥4 个生效；
    /// 不足 4 个（含缺省）时 settings 级覆盖；两侧都缺 → 空（运行时兜底默认）。
    #[test]
    fn build_vless_validator_testseed_user_over_settings_fallback() {
        let ua = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let ub = "66ad4540-b58c-4ad2-9926-ea63445a9b57";
        let uc = "d342d11e-d424-4583-b36e-524ab1f0afa4";
        let settings = serde_json::json!({
            "clients": [
                { "id": ua, "testseed": [1, 2, 3, 4, 5] },   // user 级 ≥4 → 原样
                { "id": ub, "testseed": [9] },               // user 级 <4 → settings 级覆盖
                { "id": uc },                                 // user 级缺省 → settings 级覆盖
            ],
            "testseed": [7, 8, 9, 10],
            "decryption": "none",
        });
        let data = serde_json::to_vec(&settings).unwrap();
        let validator = super::build_vless_validator(&data).unwrap();
        use xray_proxy_vless::Validator as VlessValidatorTrait;
        let seed_of = |id: &str| {
            let uuid = xray_common::uuid::UUID::parse(id).unwrap();
            VlessValidatorTrait::get(&*validator, &uuid)
                .expect("user registered")
                .account
                .testseed
                .clone()
        };
        assert_eq!(seed_of(ua), vec![1, 2, 3, 4, 5], "user-level seed wins when >= 4");
        assert_eq!(seed_of(ub), vec![7, 8, 9, 10], "short user seed overridden by settings");
        assert_eq!(seed_of(uc), vec![7, 8, 9, 10], "missing user seed falls back to settings");
    }

    #[test]
    fn build_vless_validator_invalid_json() {
        let bad = b"not a json";
        let err = super::build_vless_validator(bad);
        assert!(err.is_err(), "invalid JSON should error");
    }

    /// 3hsv①：decryption 缺省/空串拒启（Go vless.go:155-157），不再
    /// unwrap_or("none") 静默兜底。
    #[test]
    fn vless_decryption_missing_or_empty_rejected() {
        for json in [br#"{}"#.as_slice(), br#"{"decryption":""}"#] {
            let err = super::build_vless_decryption(json, test_plugin_ctx("vless"))
                .err()
                .expect("must reject");
            assert!(
                err.to_string().contains("please add/set"),
                "expected empty-decryption hard error, got: {err}"
            );
        }
    }

    /// 3hsv①：decryption="none" 与 fallbacks 共存合法；ENC 解密启用时与
    /// fallbacks 互斥（Go vless.go:161-163）。
    #[tokio::test]
    async fn vless_decryption_fallbacks_mutual_exclusion() {
        use base64::Engine as _;
        let keys = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        let enc = format!(r#"{{"decryption":"mlkem768x25519plus.native.1000s.{keys}"}}"#);
        // ENC + 无 fallbacks → 合法（初始化成功）。
        assert!(super::build_vless_decryption(enc.as_bytes(), test_plugin_ctx("vless")).is_ok());
        // ENC + fallbacks 在场 → 拒启。
        let enc_fb =
            format!(r#"{{"decryption":"mlkem768x25519plus.native.1000s.{keys}","fallbacks":[]}}"#);
        let err = super::build_vless_decryption(enc_fb.as_bytes(), test_plugin_ctx("vless"))
            .err()
            .expect("must reject");
        assert!(
            err.to_string().contains("can not be used together"),
            "expected mutual-exclusion hard error, got: {err}"
        );
        // none + fallbacks → 合法。
        let ok = br#"{"decryption":"none","fallbacks":[]}"#;
        assert!(super::build_vless_decryption(ok, test_plugin_ctx("vless")).is_ok());
    }

    /// 3hsv②：settings.flow 非法值拒启（Go vless.go:57-66）。
    #[test]
    fn vless_settings_flow_invalid_rejected() {
        let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let json = format!(r#"{{"clients":[{{"id":"{uuid}"}}],"flow":"xtls-rprx-vision-44"}}"#);
        let err = super::build_vless_validator(json.as_bytes()).err().expect("must reject");
        assert!(
            err.to_string().contains("settings.flow"),
            "expected settings.flow hard error, got: {err}"
        );
    }

    /// 3hsv②：client flow 为空时继承 settings.flow；非空非法拒启
    /// （Go vless.go:71-78）。
    #[test]
    fn vless_client_flow_inherits_settings_and_validates() {
        use xray_proxy_vless::Validator as VlessValidatorTrait;
        let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
        // 空 client flow + settings.flow=vision → 继承 vision。
        let json = format!(
            r#"{{"clients":[{{"id":"{uuid}"}}],"flow":"xtls-rprx-vision","decryption":"none"}}"#
        );
        let validator = super::build_vless_validator(json.as_bytes()).unwrap();
        let u = xray_common::uuid::UUID::parse(uuid).unwrap();
        let user = VlessValidatorTrait::get(&*validator, &u).expect("user registered");
        assert_eq!(user.account.flow, "xtls-rprx-vision", "client inherits settings.flow");
        // client flow 非法 → 拒启。
        let bad = format!(r#"{{"clients":[{{"id":"{uuid}","flow":"xtls-rprx-direct"}}]}}"#);
        let err = super::build_vless_validator(bad.as_bytes()).err().expect("must reject");
        assert!(
            err.to_string().contains("\"flow\" doesn't support"),
            "expected client flow hard error, got: {err}"
        );
    }

    /// 3hsv③：fallbacks 数字 dest → localhost:N（Go vless.go:177-179）。
    #[test]
    fn vless_fallbacks_numeric_dest_maps_to_localhost() {
        let json = br#"{"decryption":"none","fallbacks":[{"dest":8080}]}"#;
        let policy = super::build_vless_fallbacks(json).unwrap().expect("policy built");
        let d = policy.find("", "", "").expect("default entry");
        assert_eq!(d.dest, "localhost:8080");
        assert_eq!(d.xver, 0);
    }

    /// 3hsv③：dest 缺失/无法推导 type → 拒启（Go vless.go:206-208）；
    /// 合法 host:port 通过。
    #[test]
    fn vless_fallbacks_missing_dest_rejected_valid_tcp_ok() {
        let bad = br#"{"decryption":"none","fallbacks":[{"alpn":"h2"}]}"#;
        #[allow(clippy::err_expect)] // 存量清零批次
        let err = super::build_vless_fallbacks(bad).err().expect("must reject");
        assert!(
            err.to_string().contains("please fill in a valid value"),
            "expected missing-dest hard error, got: {err}"
        );
        let ok = br#"{"decryption":"none","fallbacks":[{"dest":"127.0.0.1:80","xver":1}]}"#;
        let policy = super::build_vless_fallbacks(ok).unwrap().expect("policy built");
        let d = policy.find("", "", "").unwrap();
        assert_eq!(d.dest, "127.0.0.1:80");
        assert_eq!(d.xver, 1);
    }

    /// 3hsv③：xver 非法值/负数/非整数一律拒启不钳制（Go vless.go:209-211 +
    /// uint64 解码期硬错）。
    #[test]
    fn vless_fallbacks_xver_invalid_rejected() {
        let cases: Vec<serde_json::Value> = vec![
            serde_json::json!({"dest":"127.0.0.1:80","xver":3}),
            serde_json::json!({"dest":"127.0.0.1:80","xver":-1}),
            serde_json::json!({"dest":"127.0.0.1:80","xver":"1"}),
        ];
        for fb in cases {
            let json = serde_json::json!({"decryption":"none","fallbacks":[fb]});
            let data = serde_json::to_vec(&json).unwrap();
            #[allow(clippy::err_expect)] // 存量清零批次
            let err = super::build_vless_fallbacks(&data).err().expect("must reject");
            assert!(err.to_string().contains("xver"), "expected xver hard error, got: {err}");
        }
    }

    /// 3hsv③：unix / serve（serve-ws-none）目标本构建运行面未实现 → 显式
    /// 拒启（此前静默放过、运行期 TcpStream 拨号必炸）。
    #[test]
    fn vless_fallbacks_unsupported_type_rejected() {
        let cases = [
            r#"{"decryption":"none","fallbacks":[{"dest":"/run/xray.sock"}]}"#,
            r#"{"decryption":"none","fallbacks":[{"dest":"serve-ws-none"}]}"#,
        ];
        for json in cases {
            #[allow(clippy::err_expect)] // 存量清零批次
            let err = super::build_vless_fallbacks(json.as_bytes()).err().expect("must reject");
            assert!(
                err.to_string().contains("not supported"),
                "expected unsupported-type hard error, got: {err}"
            );
        }
    }

    /// REALITY 同型：xver >2/负数拒启不钳制（Go transport_security.go:84-86）。
    #[test]
    fn parse_reality_config_rejects_bad_xver_and_port_dest() {
        use base64::Engine as _;
        let key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        let mk = |extra: serde_json::Value| {
            let mut json = serde_json::json!({
                "privateKey": key_b64,
                "serverNames": ["a.com"],
                "shortIds": ["01"],
            });
            if let (Some(o), Some(e)) = (json.as_object_mut(), extra.as_object()) {
                o.extend(e.clone());
            }
            xray_transport::dialer::StreamSettings {
                security: "reality".to_string(),
                security_json: Some(json),
                ..Default::default()
            }
        };
        for extra in [
            serde_json::json!({"xver": 3}),
            serde_json::json!({"xver": -1}),
            serde_json::json!({"dest": 70_000}),
        ] {
            #[allow(clippy::err_expect)] // 存量清零批次
            let err = super::parse_reality_config(&mk(extra)).err().expect("must reject");
            assert!(
                err.to_string().contains("xver") || err.to_string().contains("target"),
                "expected xver/target hard error, got: {err}"
            );
        }
    }

    /// uasr③：accounts 在场覆盖 users（Go socks.go:54-56），旧实现优先级
    /// 相反。
    #[test]
    fn parse_socks_server_config_accounts_override_users() {
        let json =
            br#"{"users":[{"user":"alice","pass":"p1"}],"accounts":[{"user":"bob","pass":"p2"}]}"#;
        let cfg = super::parse_socks_server_config(json).unwrap();
        assert!(cfg.has_account("bob", "p2"), "accounts must win");
        assert!(!cfg.has_account("alice", "p1"), "users must be overridden");
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
        // 键名/零值默认对齐 Go infra/conf/http.go:28-29（Transparent
        // json:"allowTransparent"、UserLevel json:"userLevel"）。
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
        let settings =
            serde_json::json!({ "address": "1.2.3.4", "port": 53, "network": "tcp,udp" });
        let data = serde_json::to_vec(&settings).unwrap();
        let s = super::parse_dokodemo_settings(&data).unwrap();
        assert!(s.allow_tcp);
        assert!(s.allow_udp);
    }

    #[test]
    fn parse_dokodemo_settings_follow_redirect() {
        let settings =
            serde_json::json!({ "address": "1.2.3.4", "port": 80, "followRedirect": true });
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
            Port::new(80), // 不是 9527
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

    /// FieldAudit P1 回归：users 形态（生产 xr.json 全族形态）必须可达——
    /// Go vmess.go:73-75 users 为 clients 合法别名。
    #[test]
    fn build_vmess_validator_accepts_users_alias() {
        let uuid = "66ad4540-b58c-4ad2-9926-ea63445a9b57";
        let settings = serde_json::json!({ "users": [{ "id": uuid, "email": "alice" }] });
        let data = serde_json::to_vec(&settings).unwrap();
        let validator = super::build_vmess_validator(&data).unwrap();
        use xray_proxy_vmess::Validator as VmessValidatorTrait;
        assert_eq!(VmessValidatorTrait::count(&*validator), 1);
    }

    /// clients+users 同场：Go 覆盖语义 = clients 完全取代 users（vmess.go:73-75）。
    #[test]
    fn build_vmess_validator_clients_override_users_when_both_present() {
        let ua = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let ub = "66ad4540-b58c-4ad2-9926-ea63445a9b57";
        let uc = "d342d11e-d424-4583-b36e-524ab1f0afa4";
        let settings = serde_json::json!({
            "users": [{ "id": ua }, { "id": ub }],
            "clients": [{ "id": uc }],
        });
        let data = serde_json::to_vec(&settings).unwrap();
        let validator = super::build_vmess_validator(&data).unwrap();
        use xray_proxy_vmess::Validator as VmessValidatorTrait;
        assert_eq!(VmessValidatorTrait::count(&*validator), 1, "clients wins");
    }

    /// `"clients": null` 不覆盖 users（Go JSON null → nil slice，不触发覆盖分支）。
    #[test]
    fn build_vmess_validator_null_clients_falls_back_to_users() {
        let uuid = "66ad4540-b58c-4ad2-9926-ea63445a9b57";
        let settings = serde_json::json!({ "clients": null, "users": [{ "id": uuid }] });
        let data = serde_json::to_vec(&settings).unwrap();
        let validator = super::build_vmess_validator(&data).unwrap();
        use xray_proxy_vmess::Validator as VmessValidatorTrait;
        assert_eq!(VmessValidatorTrait::count(&*validator), 1);
    }

    #[test]
    fn build_vmess_validator_empty_clients() {
        let settings = serde_json::json!({});
        let data = serde_json::to_vec(&settings).unwrap();
        let validator = super::build_vmess_validator(&data).unwrap();
        use xray_proxy_vmess::Validator as VmessValidatorTrait;
        assert_eq!(VmessValidatorTrait::count(&*validator), 0);
    }

    const TUIC_INBOUND_TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn tuic_inbound_json(extra: &str) -> String {
        format!(r#"{{"uuid":"{TUIC_INBOUND_TEST_UUID}","password":"pw"{extra}}}"#)
    }

    /// listen 地址归一化：Go anyip 语义（listen="::"/空 → 双栈 any）+ 裸 IP 补端口。
    #[test]
    fn parse_listen_addr_normalizes_go_semantics() {
        let p = |a: &str| super::parse_listen_addr(a, 18923).map(|sa| sa.to_string());
        assert_eq!(p("").unwrap(), "[::]:18923");
        assert_eq!(p("  ").unwrap(), "[::]:18923");
        assert_eq!(p("::").unwrap(), "[::]:18923");
        assert_eq!(p("0.0.0.0").unwrap(), "0.0.0.0:18923");
        // 已含端口直用（port 参数忽略）
        assert_eq!(p("127.0.0.1:1").unwrap(), "127.0.0.1:1");
        assert_eq!(p("[::]:1").unwrap(), "[::]:1");
        // 裸 IP 补端口：IPv6 须加方括号（裸拼接 "::1:18923" 无法解析）
        assert_eq!(p("::1").unwrap(), "[::1]:18923");
        assert_eq!(p("127.0.0.1").unwrap(), "127.0.0.1:18923");
        // 域名/非法串报错且错误信息保留原文
        assert!(p("example.com").is_err());
        let err = super::parse_listen_addr("bad addr!", 1).unwrap_err();
        assert!(err.to_string().contains("bad addr!"), "err: {err}");
    }

    /// 票 7ykg：官方 tuic-server 缺省 congestion_control="cubic"（服务端形态，
    /// 对称 outbound 侧官方 tuic-client 缺省 bbr）。
    #[test]
    fn parse_tuic_inbound_settings_defaults_official_server() {
        let s =
            super::parse_tuic_inbound_settings(tuic_inbound_json("").as_bytes(), "127.0.0.1:8443")
                .unwrap();
        assert_eq!(s.congestion_control, Some(xray_proxy_tuic::CongestionControl::Cubic));
        assert_eq!(s.brutal_up_bps, 0);
        assert_eq!(s.server_name, "tuic");
    }

    #[test]
    fn parse_tuic_inbound_settings_invalid_cc_rejected() {
        let json = tuic_inbound_json(r#","congestion_control":"bbrv3""#);
        assert!(super::parse_tuic_inbound_settings(json.as_bytes(), "127.0.0.1:8443").is_err());
    }

    /// 票 7ykg：hysteria 变体解析；brutal 必须显式带 brutal_up_bps（对称 s8ti outbound）。
    #[test]
    fn parse_tuic_inbound_settings_hysteria_cc_variants() {
        let json = tuic_inbound_json(r#","congestion_control":"hysteria_bbr""#);
        let s = super::parse_tuic_inbound_settings(json.as_bytes(), "127.0.0.1:8443").unwrap();
        assert_eq!(s.congestion_control, Some(xray_proxy_tuic::CongestionControl::HysteriaBbr));
        assert_eq!(s.brutal_up_bps, 0);

        let json = tuic_inbound_json(
            r#","congestion_control":"hysteria_brutal","brutal_up_bps":10485760"#,
        );
        let s = super::parse_tuic_inbound_settings(json.as_bytes(), "127.0.0.1:8443").unwrap();
        assert_eq!(s.congestion_control, Some(xray_proxy_tuic::CongestionControl::HysteriaBrutal));
        assert_eq!(s.brutal_up_bps, 10_485_760);

        // hysteria_brutal 无带宽 → 解析期拒绝（crate 层的 0 回落 BBR 只保护编程构造路径）。
        let json = tuic_inbound_json(r#","congestion_control":"hysteria_brutal""#);
        assert!(super::parse_tuic_inbound_settings(json.as_bytes(), "127.0.0.1:8443").is_err());
        // 既有三臂不受 brutal_up_bps 影响（配了也忽略）。
        let json = tuic_inbound_json(r#","congestion_control":"bbr","brutal_up_bps":10485760"#);
        let s = super::parse_tuic_inbound_settings(json.as_bytes(), "127.0.0.1:8443").unwrap();
        assert_eq!(s.congestion_control, Some(xray_proxy_tuic::CongestionControl::Bbr));
    }

    /// 票 ieik⑥：certificate/certificateKey PEM → TuicInboundConfig cert/key DER。
    /// rcgen 生成自签证书 → 解析出的 DER 能被 rustls 接受（build_server_config 路径）。
    #[test]
    fn tuic_inbound_pem_cert_key_parse() {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["tuic.test".to_string()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, "tuic.test");
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        let cert_der = super::tuic_pem_first_cert_der(&cert_pem).unwrap();
        let key_der = super::tuic_pem_key_der(&key_pem).unwrap();
        assert!(!cert_der.is_empty());
        assert!(!key_der.is_empty());
        // DER 能被 rustls 证书/私钥构造接受（TuicInboundConfig.build_server_config 用法）
        let _ = rustls::pki_types::CertificateDer::from(cert_der);
        let _ = rustls::pki_types::PrivatePkcs8KeyDer::from(key_der);

        // 坏输入显式报错（不静默回落自签）
        assert!(super::tuic_pem_first_cert_der("not a pem").is_err());
        assert!(super::tuic_pem_key_der("not a pem").is_err());
    }

    // ===== bd dppv 余项：finalmask.tcp 覆盖 socks/mixed/http/dokodemo/dns 裸 TCP 入站 =====

    use std::sync::Mutex;

    use xray_transport::finalmask::{AsyncIo, TcpmaskManager};

    /// sudoku mask（padding 缺省 0 ⇒ 上行 wire 恒为 4 hint 字节/明文字节）。
    fn sudoku_mask() -> Arc<TcpmaskManager> {
        Arc::new(
            xray_transport::finalmask::build_tcpmask_manager_from_json(Some(&serde_json::json!({
                "tcp": [{ "type": "sudoku", "settings": {} }]
            })))
            .expect("sudoku mask 构建"),
        )
    }

    /// wire 抓包层：记录真正落到 socket 的字节（发送/接收两向）。
    ///
    /// 断言「mask 头是否在 wire 最外层」只能看 socket 字节——协议层的读写都已被
    /// mask 链解过一层。
    struct WireTap {
        inner: tokio::net::TcpStream,
        sent: Arc<Mutex<Vec<u8>>>,
        recv: Arc<Mutex<Vec<u8>>>,
    }

    impl AsyncRead for WireTap {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let this = self.get_mut();
            let before = buf.filled().len();
            let poll = std::pin::Pin::new(&mut this.inner).poll_read(cx, buf);
            if let std::task::Poll::Ready(Ok(())) = &poll {
                this.recv.lock().unwrap().extend_from_slice(&buf.filled()[before..]);
            }
            poll
        }
    }

    impl AsyncWrite for WireTap {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            let poll = std::pin::Pin::new(&mut this.inner).poll_write(cx, buf);
            if let std::task::Poll::Ready(Ok(n)) = &poll {
                this.sent.lock().unwrap().extend_from_slice(&buf[..*n]);
            }
            poll
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    /// 入站测试客户端：`mask` Some 时套客户端同一条 mask 链（等价真实客户端）。
    struct MaskClient {
        io: Box<dyn AsyncIo>,
        sent: Arc<Mutex<Vec<u8>>>,
        recv: Arc<Mutex<Vec<u8>>>,
    }

    impl MaskClient {
        async fn write(&mut self, data: &[u8]) {
            self.io.write_all(data).await.expect("client write");
        }

        async fn read_exact(&mut self, buf: &mut [u8]) {
            tokio::time::timeout(std::time::Duration::from_secs(5), self.io.read_exact(buf))
                .await
                .expect("client read 超时（mask 或协议握手卡住）")
                .expect("client read");
        }

        async fn read_some(&mut self, buf: &mut [u8]) -> usize {
            tokio::time::timeout(std::time::Duration::from_secs(5), self.io.read(buf))
                .await
                .expect("client read 超时（mask 或协议握手卡住）")
                .expect("client read")
        }

        fn wire_sent(&self) -> Vec<u8> {
            self.sent.lock().unwrap().clone()
        }

        fn wire_recv(&self) -> Vec<u8> {
            self.recv.lock().unwrap().clone()
        }
    }

    async fn connect_tapped(addr: SocketAddr, mask: Option<Arc<TcpmaskManager>>) -> MaskClient {
        let raw = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let sent = Arc::new(Mutex::new(Vec::new()));
        let recv = Arc::new(Mutex::new(Vec::new()));
        let tap = WireTap { inner: raw, sent: Arc::clone(&sent), recv: Arc::clone(&recv) };
        let io: Box<dyn AsyncIo> = match &mask {
            Some(m) => m.wrap_conn_client(Box::new(tap)).expect("client mask"),
            None => Box::new(tap),
        };
        MaskClient { io, sent, recv }
    }

    /// 断言 wire 首部：配 mask → 不是原协议头且被编码扩张；未配 → 逐字节等于协议头。
    fn assert_wire(wire: &[u8], plain: &[u8], masked: bool, what: &str) {
        assert!(wire.len() >= plain.len(), "{what}: wire 太短 {wire:02x?}");
        if masked {
            assert_ne!(
                &wire[..plain.len()],
                plain,
                "{what}: 配 mask 时 wire 首字节必须是 mask 头（实际 {wire:02x?}）"
            );
            assert!(
                wire.len() > plain.len(),
                "{what}: sudoku 必须扩张 wire 字节（4 hint/byte），实际 {wire:02x?}"
            );
        } else {
            assert_eq!(&wire[..plain.len()], plain, "{what}: 未配 mask 时 wire 必须是原协议头");
        }
    }

    fn capture_ohm() -> Arc<SimpleOhm> {
        let ohm = Arc::new(SimpleOhm::new());
        ohm.set_default(Arc::new(DestCaptureDispatch { dest: parking_lot::Mutex::new(None) })
            as Arc<dyn xray_app_dispatcher::DispatchHandler>);
        ohm
    }

    async fn masked_listener(masked: bool, mask: &Arc<TcpmaskManager>) -> InboundTcpListener {
        InboundTcpListener::bind("127.0.0.1:0", xray_transport::sockopt::SocketOptions::default())
            .await
            .expect("bind")
            .with_tcpmask_manager(masked.then(|| Arc::clone(mask)))
    }

    /// socks 入站：配 mask → 客户端 mask 解包后握手成功，wire 首字节是 mask 头；
    /// 不配 mask → wire 首字节就是 0x05 协议头（行为逐字节不变）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn socks_inbound_wears_finalmask() {
        let mask = sudoku_mask();
        for masked in [false, true] {
            let listener = masked_listener(masked, &mask).await;
            let addr = listener.local_addr().unwrap();
            tokio::spawn(serve_socks5(
                listener,
                capture_ohm(),
                Arc::new(ServerConfig::default()),
                Some(std::time::Duration::from_secs(5)),
                std::time::Duration::from_secs(5),
                test_plugin_ctx("socks"),
            ));

            let mut client = connect_tapped(addr, masked.then(|| Arc::clone(&mask))).await;
            let greeting = [0x05u8, 0x01, 0x00];
            client.write(&greeting).await;
            let mut resp = [0u8; 2];
            client.read_exact(&mut resp).await;
            assert_eq!(resp, [0x05, 0x00], "socks5 方法协商必须成功（masked={masked}）");
            assert_wire(&client.wire_sent(), &greeting, masked, "socks 入站");
            // 回程同样走 mask（sudoku 服务端为 packed 编码，长度非固定倍率）
            let wire_recv = client.wire_recv();
            assert!(!wire_recv.is_empty(), "服务端必须有回程字节");
            if masked {
                assert_ne!(&wire_recv[..2], &resp, "回程 wire 首字节也必须是 mask 头");
            } else {
                assert_eq!(wire_recv, resp.to_vec(), "未配 mask 时回程就是原协议字节");
            }
        }
    }

    /// mixed 入站（peek 首字节分流）：mask 在嗅探之前，明文首字节经 PeekAhead
    /// 回放给握手——配 mask 握手成功且 wire 首字节是 mask 头。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn mixed_inbound_wears_finalmask() {
        let mask = sudoku_mask();
        for masked in [false, true] {
            let listener = masked_listener(masked, &mask).await;
            let addr = listener.local_addr().unwrap();
            tokio::spawn(serve_mixed(
                listener,
                capture_ohm(),
                Arc::new(ServerConfig::default()),
                Arc::new(HttpServerConfig::default()),
                Some(std::time::Duration::from_secs(5)),
                std::time::Duration::from_secs(5),
                test_plugin_ctx("mixed"),
            ));

            let mut client = connect_tapped(addr, masked.then(|| Arc::clone(&mask))).await;
            let greeting = [0x05u8, 0x01, 0x00];
            client.write(&greeting).await;
            let mut resp = [0u8; 2];
            client.read_exact(&mut resp).await;
            assert_eq!(resp, [0x05, 0x00], "mixed socks 分支必须成功（masked={masked}）");
            assert_wire(&client.wire_sent(), &greeting, masked, "mixed 入站");
        }
    }

    /// http 入站：配 mask → CONNECT 握手成功且 wire 首字节是 mask 头（'C' 不再是
    /// wire 首字节）；不配 → wire 直接是 `CONNECT ...`。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn http_inbound_wears_finalmask() {
        let mask = sudoku_mask();
        for masked in [false, true] {
            let listener = masked_listener(masked, &mask).await;
            let addr = listener.local_addr().unwrap();
            tokio::spawn(serve_http(
                listener,
                capture_ohm(),
                Arc::new(HttpServerConfig::default()),
                Some(std::time::Duration::from_secs(5)),
                test_plugin_ctx("http"),
            ));

            let mut client = connect_tapped(addr, masked.then(|| Arc::clone(&mask))).await;
            let req = b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: h\r\n\r\n";
            client.write(req).await;
            let mut resp = [0u8; 64];
            let n = client.read_some(&mut resp).await;
            assert!(
                resp[..n].starts_with(b"HTTP/1.1 200"),
                "CONNECT 必须回 200（masked={masked}）：{:?}",
                String::from_utf8_lossy(&resp[..n])
            );
            assert_wire(&client.wire_sent(), req, masked, "http 入站");
        }
    }

    /// dokodemo 入站（无握手协议，直接 dispatch）：配 mask → dispatch 收到的
    /// 明文原样，wire 首字节是 mask 头。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dokodemo_inbound_wears_finalmask() {
        let mask = sudoku_mask();
        for masked in [false, true] {
            let listener = masked_listener(masked, &mask).await;
            let addr = listener.local_addr().unwrap();
            let ohm = Arc::new(SimpleOhm::new());
            ohm.set_default(Arc::new(PayloadGateDispatch { expect: b"hi".len() })
                as Arc<dyn xray_app_dispatcher::DispatchHandler>);
            tokio::spawn(serve_dokodemo(
                listener,
                ohm,
                DokodemoTcpOptions {
                    dest: Some(Destination::tcp(
                        Address::Domain("example.com".into()),
                        Port::new(80),
                    )),
                    port_map: HashMap::new(),
                    follow_redirect: false,
                    tls: None,
                },
                test_plugin_ctx("dokodemo"),
            ));

            let mut client = connect_tapped(addr, masked.then(|| Arc::clone(&mask))).await;
            client.write(b"hi").await;
            let mut resp = [0u8; 2];
            client.read_exact(&mut resp).await;
            assert_eq!(&resp, b"ok", "dispatch 链路必须通（masked={masked}）");
            assert_wire(&client.wire_sent(), b"hi", masked, "dokodemo 入站");
        }
    }

    /// dns 入站 TCP：配 mask → 2B 长度前缀帧循环照常工作（Return 规则应答），
    /// wire 首字节是 mask 头。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dns_inbound_wears_finalmask() {
        let mask = sudoku_mask();
        let mut query = vec![0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in ["example", "com"] {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        let mut frame = vec![(query.len() >> 8) as u8, query.len() as u8];
        frame.extend_from_slice(&query);

        for masked in [false, true] {
            let cfg = DnsConfig {
                rule: vec![xray_proxy_dns::DnsRuleConfig {
                    action: xray_proxy_dns::RuleAction::Return,
                    q_type: vec![1],
                    ..Default::default()
                }],
                ..Default::default()
            };
            let handler = DnsHandler::init(&cfg, std::time::Duration::from_secs(5));
            let outbound = DnsOutbound::new_with_servers(
                "unused",
                &[(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 5353)],
            )
            .expect("dns outbound");
            let inbound = Arc::new(DnsInbound::new("dns-mask", handler, outbound));
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let listener = masked_listener(masked, &mask).await;
            let addr = listener.local_addr().unwrap();
            tokio::spawn(serve_dns(udp, listener, inbound, test_plugin_ctx("dns")));

            let mut client = connect_tapped(addr, masked.then(|| Arc::clone(&mask))).await;
            client.write(&frame).await;
            let mut len_buf = [0u8; 2];
            client.read_exact(&mut len_buf).await;
            let mut resp = vec![0u8; u16::from_be_bytes(len_buf) as usize];
            client.read_exact(&mut resp).await;
            assert_eq!(&resp[..2], &[0xAB, 0xCD], "响应 ID 必须与查询一致（masked={masked}）");
            assert_wire(&client.wire_sent(), &frame, masked, "dns 入站");
        }
    }

    /// TOCTOU 加固：bind(:0)→drop→spawn_one_inbound 之间端口可能被并行测试/
    /// 其他进程抢占（Windows 10048 / Unix EADDRINUSE）——占用时换端口重试至
    /// 多 5 次。返回实际绑定端口与 serve 句柄。
    async fn spawn_one_inbound_retrying(
        build: impl Fn(u16) -> BuiltInbound,
        ohm: Arc<SimpleOhm>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        for _ in 0..5 {
            let port = xray_common::testing::pick_free_ports(1).await[0];
            match spawn_one_inbound(
                &build(port),
                Arc::clone(&ohm),
                None,
                CancellationToken::new(),
                None,
            )
            .await
            {
                Ok(Some(handle)) => return (port, handle),
                Ok(None) => panic!("inbound spawn returned no handle"),
                Err(e) if xray_common::testing::is_addr_in_use_err(&e) => continue,
                Err(e) => panic!("inbound spawn: {e}"),
            }
        }
        panic!("inbound spawn: EADDRINUSE persisted across 5 port retries");
    }

    /// bd 7wor：ss 入站 finalmask 端到端（装配注入 → accept 解伪装 → ss 握手 →
    /// dispatch）。接线前 masked 腿：服务端把 sudoku 编码字节当 ss AEAD 解，
    /// 握手永不成 → 客户端超时（红）；接线后双腿全通（绿）。masked 腿 wire
    /// 字节数必须大于明文腿（同逻辑流 sudoku 恒扩张），证 mask 真在 wire 上。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ss_inbound_wears_finalmask() {
        use xray_proxy_ss::{client::Client, config::MemoryAccount as SsAccount};
        use xray_transport::finalmask::AsyncIo;

        let mask = sudoku_mask();
        let users_json =
            br#"{"users":[{"method":"aes-128-gcm","password":"ss-fm-pass"}]}"#.to_vec();
        let stream_json = serde_json::json!({
            "network": "tcp",
            "finalmask": { "tcp": [ { "type": "sudoku", "settings": {} } ] }
        });

        let mut wire_lens = [0usize; 2];
        for (i, masked) in [false, true].into_iter().enumerate() {
            // 每腿独立空闲端口（serve_ss 会顺手绑同端口 UDP relay，旧腿的
            // detached UDP task 退出前不释放，复用端口会撞 bind）。
            // TOCTOU 加固：占用时换端口重试。
            let ohm = Arc::new(SimpleOhm::new());
            let capture = Arc::new(DestCaptureDispatch { dest: parking_lot::Mutex::new(None) });
            ohm.set_default(Arc::clone(&capture) as Arc<dyn xray_app_dispatcher::DispatchHandler>);

            let (port, handle) = spawn_one_inbound_retrying(
                |port| BuiltInbound {
                    entry: xray_conf::BuiltEntry {
                        kind: "shadowsocks".into(),
                        data: users_json.clone(),
                    },
                    tag: "ss-fm".into(),
                    port: Some(port),
                    listen: Some("127.0.0.1".into()),
                    stream_settings_json: masked.then(|| stream_json.clone()),
                    sniffing_json: None,
                },
                ohm,
            )
            .await;

            // 客户端：tap 在 mask 链内层记 wire 字节；客户端按配置套同一条 mask。
            let raw = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let sent = Arc::new(Mutex::new(Vec::new()));
            let recv = Arc::new(Mutex::new(Vec::new()));
            let tap = WireTap { inner: raw, sent: Arc::clone(&sent), recv: Arc::clone(&recv) };
            let io: Box<dyn AsyncIo> = match masked.then(|| Arc::clone(&mask)) {
                Some(m) => m.wrap_conn_client(Box::new(tap)).expect("client mask"),
                None => Box::new(tap),
            };

            let account = SsAccount::from_proto(&xray_proto::xray::proxy::shadowsocks::Account {
                password: "ss-fm-pass".into(),
                cipher_type: SsCipherType::Aes128Gcm.as_i32(),
                iv_check: false,
            })
            .unwrap();
            let client = Client::new(account, "127.0.0.1".into(), port);

            // 整段限时：红形态 = 服务端解不开 mask → 无响应 → 此处超时。
            let run = async {
                let mut ss = client
                    .dial_target_for_proxy_on(io, &Address::Domain("example.com".into()), 80)
                    .await
                    .expect("ss dial_target");
                ss.write_chunk(b"hi").await.expect("write body");
                let resp = ss.read_chunk().await.expect("read resp").expect("resp chunk");
                assert_eq!(&resp, b"ok", "dispatch 回写必须原样到达（masked={masked}）");
            };
            tokio::time::timeout(std::time::Duration::from_secs(10), run)
                .await
                .expect("ss+finalmask 链路超时（mask 未接线或服务端未解伪装）");

            let dest = capture.dest.lock().clone().expect("dispatch dest captured");
            assert!(
                matches!(dest.address(), Address::Domain(d) if d == "example.com"),
                "dispatch dest 必须是明文目标（masked={masked}）：{dest:?}"
            );
            wire_lens[i] = sent.lock().unwrap().len();
            handle.abort();
        }
        assert!(
            wire_lens[1] > wire_lens[0],
            "masked wire（{}B）必须大于明文 wire（{}B）：sudoku 恒扩张",
            wire_lens[1],
            wire_lens[0]
        );
    }

    /// bd 05js：ss UDP relay 入站 finalmask 端到端（装配注入 → 同端口 UDP socket
    /// WrapPacketConnServer → recv decode → dispatch → 回包 encode → 客户端
    /// wrap_packet_conn_client decode）。接线前 masked 腿：服务端把 mkcp-legacy
    /// 帧当 ss AEAD 解，decode 恒败 → 无回包（红 = timeout）；接线后双腿全通。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ss_inbound_udp_wears_finalmask() {
        use xray_common::net::address::Address;
        use xray_proxy_ss::{
            config::MemoryAccount as SsAccount,
            protocol::{decode_udp_packet, encode_udp_packet},
            validator::{MemoryUser, Validator},
        };
        use xray_transport::finalmask::{UdpIo, build_udpmask_manager_from_json};

        let users_json =
            br#"{"users":[{"method":"aes-128-gcm","password":"ss-fm-pass"}]}"#.to_vec();
        let stream_json = serde_json::json!({
            "network": "tcp",
            "finalmask": { "udp": [ { "type": "mkcp-legacy", "settings": {} } ] }
        });
        let account = SsAccount::from_proto(&xray_proto::xray::proxy::shadowsocks::Account {
            password: "ss-fm-pass".into(),
            cipher_type: SsCipherType::Aes128Gcm.as_i32(),
            iv_check: false,
        })
        .unwrap();

        for masked in [false, true] {
            // 每腿独立空闲端口（serve_ss 同端口绑 UDP relay，旧腿 detached task
            // 退出前不释放，复用端口会撞 bind）。TOCTOU 加固：占用时换端口重试。
            let ohm = Arc::new(SimpleOhm::new());
            ohm.set_default(Arc::new(MarkerUdpDispatch { marker: b"ss-udp-fm" })
                as Arc<dyn xray_app_dispatcher::DispatchHandler>);

            let (port, handle) = spawn_one_inbound_retrying(
                |port| BuiltInbound {
                    entry: xray_conf::BuiltEntry {
                        kind: "shadowsocks".into(),
                        data: users_json.clone(),
                    },
                    tag: "ss-udp-fm".into(),
                    port: Some(port),
                    listen: Some("127.0.0.1".into()),
                    stream_settings_json: masked.then(|| stream_json.clone()),
                    sniffing_json: None,
                },
                ohm,
            )
            .await;
            // Windows UDP：服务端 relay 未就绪时发包 → ICMP port unreachable
            // 滞留，本腿 recv 报 ConnectionReset(10054)。等 UDP relay 绑定完成。
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;

            // 客户端：masked 腿按同配置 wrap（send encode / recv decode 对称）
            let raw = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay = std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                port,
            );
            let client_io: Box<dyn UdpIo> = if masked {
                build_udpmask_manager_from_json(stream_json.get("finalmask"))
                    .expect("udp manager")
                    .wrap_packet_conn_client(Box::new(raw))
                    .expect("client mask")
            } else {
                Box::new(raw)
            };

            let packet = encode_udp_packet(
                &account,
                &Address::IPv4(std::net::Ipv4Addr::LOCALHOST),
                53,
                b"ping",
            )
            .expect("encode udp packet");
            client_io.send_to(&packet, relay).await.expect("send to ss udp relay");

            // 整段限时：红形态 = 服务端解不开 mask → 无 dispatch 无回包 → 超时。
            let mut rbuf = vec![0u8; 2048];
            let (n, _from) = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                client_io.recv_from(&mut rbuf),
            )
            .await
            .expect("ss udp finalmask 链路超时（mask 未接线或服务端未解伪装）")
            .expect("recv from ss udp relay");

            let validator = Validator::new();
            validator.add(MemoryUser::new("u@ss.fm", account.clone())).expect("add user");
            let (_header, data) = decode_udp_packet(&validator, &rbuf[..n]).expect("decode resp");
            assert_eq!(data, b"ss-udp-fm", "dispatch 回写必须原样到达（masked={masked}）");
            handle.abort();
        }
    }

    /// bd 05js：dokodemo UDP 入站 finalmask 端到端（装配注入 → UdpHub::listen
    /// WrapPacketConnServer，Go udp/hub.go:61-62 FinalMask.ListenPacket）。接线前
    /// masked 腿：hub recv 循环把 mkcp-legacy 帧当明文 payload 转发错乱 → 无回包
    /// （红 = timeout）；接线后双腿全通。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dokodemo_inbound_udp_wears_finalmask() {
        use xray_transport::finalmask::{UdpIo, build_udpmask_manager_from_json};

        let stream_json = serde_json::json!({
            "network": "tcp",
            "finalmask": { "udp": [ { "type": "mkcp-legacy", "settings": {} } ] }
        });

        for masked in [false, true] {
            // TOCTOU 加固：占用时换端口重试。
            let ohm = Arc::new(SimpleOhm::new());
            ohm.set_default(Arc::new(MarkerUdpDispatch { marker: b"dokodemo-udp-fm" })
                as Arc<dyn xray_app_dispatcher::DispatchHandler>);

            let (port, handle) = spawn_one_inbound_retrying(
                |port| BuiltInbound {
                    entry: xray_conf::BuiltEntry {
                        kind: "dokodemo".into(),
                        // network:"udp" → 仅 UDP relay（dispatch dest 固定 8.8.8.8:53，
                        // marker handler 不打真实包）
                        data: br#"{"address":"8.8.8.8","port":53,"network":"udp"}"#.to_vec(),
                    },
                    tag: "dok-udp-fm".into(),
                    port: Some(port),
                    listen: Some("127.0.0.1".into()),
                    stream_settings_json: masked.then(|| stream_json.clone()),
                    sniffing_json: None,
                },
                ohm,
            )
            .await;

            let raw = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay = std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                port,
            );
            let client_io: Box<dyn UdpIo> = if masked {
                build_udpmask_manager_from_json(stream_json.get("finalmask"))
                    .expect("udp manager")
                    .wrap_packet_conn_client(Box::new(raw))
                    .expect("client mask")
            } else {
                Box::new(raw)
            };

            client_io.send_to(b"query", relay).await.expect("send to dokodemo udp");

            let mut rbuf = vec![0u8; 2048];
            // 30s：Linux CI 高负载下 spawn 最重的 inbound 测试，10s 有调度饥饿误报。
            let recv = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                client_io.recv_from(&mut rbuf),
            )
            .await;
            // serve 任务可能在无 tracing subscriber 的测试环境里静默死亡（bind/
            // 装配失败只见 tracing::error）——裸 timeout 会把这种死亡伪装成链路
            // 超时。超时时先验尸再报错。
            let recv = match recv {
                Ok(r) => r,
                Err(_) if handle.is_finished() => panic!(
                    "dokodemo inbound serve task 提前退出（bind/装配失败，Linux CI 资源受限典型），masked={masked}"
                ),
                Err(_) => panic!(
                    "dokodemo udp finalmask 链路超时（mask 未接线或服务端未解伪装），masked={masked}"
                ),
            };
            let (n, _from) = recv.expect("recv from dokodemo udp");
            assert_eq!(
                &rbuf[..n],
                b"dokodemo-udp-fm",
                "dispatch 回写必须原样到达（masked={masked}）"
            );
            handle.abort();
        }
    }

    /// bd 99kd：REALITY inbound 配置 Debug 不得泄露 server_private_key。
    #[test]
    fn reality_inbound_config_debug_redacts_private_key() {
        let cfg = RealityInboundConfig {
            server_private_key: [0xAB; 32],
            server_names: vec!["example.com".to_string()],
            short_ids: vec![[1u8; 8]],
            max_diff: 0,
            fallback_dest: "example.com:443".to_string(),
            xver: 0,
            min_client_ver: Vec::new(),
            max_client_ver: Vec::new(),
            max_useless_records: xray_reality::MaxUselessRecordsSetting::Disabled,
            server_acceptor: xray_reality::ServerAcceptorSetting::Rustls,
        };
        let s = format!("{cfg:?}");
        assert!(!s.contains("171"), "private key bytes leaked: {s}");
        assert!(s.contains("server_private_key: \"[REDACTED]\""), "must be redacted: {s}");
        assert!(s.contains("example.com:443"), "non-secret fields must stay readable: {s}");
    }

    /// bd wsiq 同类失效兜底：serve future panic → 该 future 持有的 listener 随
    /// drop 释放 → 端口不再 listen 而进程存活（原始 panic 行之外无结构化痕迹）。
    /// 监控包裹后：panic 被转成 error! 留痕，且外层句柄正常结束（不挂死）。
    #[tokio::test]
    async fn spawn_inbound_serve_survives_panicking_future() {
        let token = CancellationToken::new();
        let handle = spawn_inbound_serve(
            &test_plugin_ctx("panic-probe"),
            "panic-probe".to_string(),
            token,
            async {
                panic!("simulated panic inside inbound serve");
            },
        );
        let joined = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
        assert!(joined.is_ok(), "serve 句柄不应挂死（panic 后必须收敛）");
    }

    /// W4 面 6 验收（方案 §6 G6 的 xray-core 半）：连接级 scope 的两条消费契约。
    /// ①`spawn_ss_pump` 同款 Arc 锚——泵任务持 scope 克隆，宿主函数返回（局部
    /// `Arc` 释放）后任务不得被提前 close 掉；②一个连接 scope 关闭不杀 sibling。
    #[tokio::test]
    async fn conn_scope_anchor_survives_host_return_and_spares_siblings() {
        let arm = test_plugin_ctx("w4-conn-scope");
        // ①锚语义：scope 局部句柄 drop 后任务仍在跑。
        let scope = std::sync::Arc::new(arm.conn_scope());
        let anchor = std::sync::Arc::clone(&scope);
        let anchored = scope
            .spawn(async move {
                let _anchor = anchor;
                std::future::pending::<()>().await;
            })
            .expect("连接 scope 可 spawn");
        drop(scope);
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        assert!(!anchored.is_finished(), "宿主返回后泵任务不得被提前 close");

        // ②sibling 隔离：关掉 A 的连接 scope，B 的任务不受影响。
        let conn_a = arm.conn_scope();
        let conn_b = arm.conn_scope();
        let a = conn_a.spawn(std::future::pending::<()>()).expect("连接 scope 可 spawn");
        let b = conn_b.spawn(std::future::pending::<()>()).expect("连接 scope 可 spawn");
        conn_a.close();
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        assert!(a.is_finished(), "本连接结束 → 本连接任务结束");
        assert!(!b.is_finished(), "sibling 连接任务不得被连坐");
        conn_b.close();
    }

    // ── xiuvr-3a 阶段 2：影子注册表双跑对照（零行为改变；阶段 4 删影子）──

    fn xiuvr3a_runtime() -> InboundRuntime {
        InboundRuntime::new(
            Arc::new(SimpleOhm::new()),
            None,
            CancellationToken::new(),
            Arc::new(xray_frame::ArmScopeRegistry::new()),
        )
    }

    fn xiuvr3a_inbound(kind: &str, tag: &str, settings: serde_json::Value) -> BuiltInbound {
        BuiltInbound {
            entry: xray_conf::BuiltEntry {
                kind: kind.to_string(),
                data: serde_json::to_vec(&settings).expect("settings serialize"),
            },
            tag: tag.to_string(),
            port: Some(0),
            listen: Some("127.0.0.1".to_string()),
            stream_settings_json: None,
            sniffing_json: None,
        }
    }

    /// 生命周期全操作回归（xiuvr-3a 切 BoundedRegistry 后）：登记/查询/摘除/
    /// 回滚的派生不变量（start Ok ⇒ contains=true；Err ⇒ contains=false）。
    #[tokio::test]
    async fn xiuvr3a_registry_behaviour_lifecycle() {
        let rt = xiuvr3a_runtime();

        // 空表：三查询全对照（contains/list/user_manager）
        assert!(!rt.contains("nope"));
        assert!(rt.list().is_empty());
        assert!(matches!(rt.user_manager("nope"), Err(ProxymanError::HandlerNotFound(_))));

        // 未支持 kind：登记成功 + warn skip（Ok(None)）→ 槽位留存（既有行为），
        // 派生一致性：start 返回 Ok ⇒ contains 必 true。
        let res = rt
            .start_inbound(&xiuvr3a_inbound("no-such-proto", "t-unsup", serde_json::json!({})))
            .await
            .expect("unsupported kind must warn-skip, not error");
        assert!(res.is_none(), "unsupported kind must not spawn a serve task");
        assert!(rt.contains("t-unsup"), "slot stays registered after warn-skip");
        assert!(matches!(rt.user_manager("t-unsup"), Err(ProxymanError::NotUserManager)));

        // 摘除配对：命中一次后二次摘除 = HandlerNotFound（miss 路径也对照）。
        rt.remove_inbound("t-unsup").expect("registered tag must remove");
        assert!(!rt.contains("t-unsup"));
        assert!(matches!(rt.remove_inbound("t-unsup"), Err(ProxymanError::HandlerNotFound(_))));

        // 畸形 settings（非法 JSON）经 loopback builder：parse_loopback_config
        // `?` 上抛 → start_inbound Err → 回滚 ⇒ contains 必 false。
        let bad = BuiltInbound {
            entry: xray_conf::BuiltEntry {
                kind: "loopback".to_string(),
                data: b"not json".to_vec(),
            },
            tag: "t-bad".to_string(),
            port: Some(0),
            listen: Some("127.0.0.1".to_string()),
            stream_settings_json: None,
            sniffing_json: None,
        };
        assert!(rt.start_inbound(&bad).await.is_err(), "malformed settings must fail");
        assert!(!rt.contains("t-bad"), "failed spawn must roll back the slot");
    }

    /// xiuvr-3a：切 BoundedRegistry 后注册表行为回归——全部 19 键 × 3 配置变体
    /// （最小 / 带 streamSettings / 畸形）。
    ///
    /// 独立硬编码期望（防"两路一起错"）：
    /// - 畸形（data = 非法 JSON）逐键硬锚：blackhole 的 response 解析吞错取 默认（Go 兼容语义）→ Ok
    ///   登记；其余 18 键 builder parse `?` 上抛 → Err 回滚。
    /// - 派生不变量（与成败无关恒成立）：start Ok ⇒ contains=true 且可摘除； Err ⇒ contains=false。
    /// - D1 落地回归：list() 恒 tag 升序（BTreeMap 确定序）。
    #[tokio::test]
    async fn xiuvr3a_registry_behaviour_matrix_19kinds_x3variants() {
        /// 阶段 1 权威全集（arm_builders INBOUND_CTORS 18 + tun 特殊分支）。
        const KINDS: [&str; 19] = [
            "socks",
            "mixed",
            "vless",
            "trojan",
            "vmess",
            "http",
            "dokodemo",
            "shadowsocks",
            "hysteria",
            "hysteria2",
            "anytls",
            "tuic",
            "naive",
            "wireguard",
            "dns",
            "loopback",
            "blackhole",
            "freedom",
            "tun",
        ];
        let rt = xiuvr3a_runtime();

        fn minimal_settings(kind: &str) -> serde_json::Value {
            match kind {
                "dokodemo" => serde_json::json!({"address": "1.2.3.4", "port": 80}),
                "loopback" => serde_json::json!({"inboundTag": "in-main"}),
                _ => serde_json::json!({}),
            }
        }

        /// 启动后按派生不变量断言登记状态，Ok 路径清理。
        async fn assert_start_then_clean(
            rt: &InboundRuntime,
            kind: &str,
            tag: &str,
            ib: &BuiltInbound,
        ) {
            let res = rt.start_inbound(ib).await;
            match res {
                Ok(_) => {
                    assert!(rt.contains(tag), "{kind}: Ok ⇒ slot registered");
                    if let Err(e) = rt.remove_inbound(tag) {
                        panic!("{kind}: registered tag must remove, got {e}");
                    }
                },
                Err(_) => {
                    assert!(!rt.contains(tag), "{kind}: Err ⇒ slot rolled back");
                },
            }
            assert!(!rt.contains(tag), "{kind}: table must be empty after cleanup");
        }

        // 变体 1：最小配置（成败混合，派生不变量逐键成立）。
        for kind in KINDS {
            let tag = format!("t-min-{kind}");
            let ib = xiuvr3a_inbound(kind, &tag, minimal_settings(kind));
            assert_start_then_clean(&rt, kind, &tag, &ib).await;
        }
        assert!(rt.list().is_empty(), "variant 1 leaves no residue");

        // 变体 2：最小 + streamSettings（registry 语义与协议解析同构对照）。
        for kind in KINDS {
            let tag = format!("t-stream-{kind}");
            let mut ib = xiuvr3a_inbound(kind, &tag, minimal_settings(kind));
            ib.stream_settings_json = Some(serde_json::json!({"network": "tcp"}));
            assert_start_then_clean(&rt, kind, &tag, &ib).await;
        }
        assert!(rt.list().is_empty(), "variant 2 leaves no residue");

        // 变体 3：畸形（非法 JSON）——逐键硬编码期望。
        for kind in KINDS {
            let tag = format!("t-bad-{kind}");
            let mut ib = xiuvr3a_inbound(kind, &tag, serde_json::json!({}));
            ib.entry.data = b"not json".to_vec();
            let res = rt.start_inbound(&ib).await;
            if kind == "blackhole" {
                assert!(res.is_ok(), "blackhole swallows parse errors (Go-compat default)");
                if let Err(e) = rt.remove_inbound(&tag) {
                    panic!("blackhole: Ok ⇒ registered, remove failed: {e}");
                }
            } else {
                assert!(res.is_err(), "{kind}: illegal JSON must err at parse");
                assert!(!rt.contains(&tag), "{kind}: Err ⇒ slot rolled back");
            }
        }
        assert!(rt.list().is_empty(), "variant 3 leaves no residue");

        // D1 落地回归——list() 恒 tag 升序（插 zz 再插 aa，输出 aa,zz）。
        let _ = rt
            .start_inbound(&xiuvr3a_inbound("blackhole", "zz-order", serde_json::json!({})))
            .await
            .expect("blackhole minimal registers");
        let _ = rt
            .start_inbound(&xiuvr3a_inbound("blackhole", "aa-order", serde_json::json!({})))
            .await
            .expect("blackhole minimal registers");
        let tags: Vec<String> = rt.list().into_iter().map(|(tag, _)| tag).collect();
        assert_eq!(tags, vec!["aa-order", "zz-order"], "list() must be tag-ascending (D1)");
        rt.remove_inbound("aa-order").expect("cleanup");
        rt.remove_inbound("zz-order").expect("cleanup");
        assert!(rt.list().is_empty());
    }
}
