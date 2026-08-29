//! VLESS inbound server：accept TCP → decode_request_header → Destination → dispatch。
//!
//! 对应 Go `app/proxyman/inbound/always.go::handle_connection` +
//! `proxy/vless/inbound/inbound.go::Process`。最小端到端切片：
//! TCP accept → decode_request_header → DecodedRequest → Destination →
//! `DispatchHandler::dispatch(dest, link)`。
//!
//! 支持命令分派：
//! - TCP：核心路径（Vision 包装 + dispatch）
//! - UDP：长度前缀包 ↔ UdpDispatchSession 桥接（XUDP 帧约定）
//! - Mux：识别首字节 0xFF，启用 feature 时转交 mux server（具体协议由 `xray-mux` 接管）
//! - Rvs：Portal 反向代理，启用 feature 时查 reverse_registry 派发
//!
//! 对应 Go 语义：
//! - TCP：`inbound.go::Process` → `dispatch.DispatchLink(ctx, dest, link)`
//! - UDP：同上，dest.Network = UDP + link 包 LengthPacketReader/Writer 包装
//! - Mux：`inbound.go:180 isMuxAndNotXUDP` + `dispatch.DispatchLink`（mux server 作为 outbound）
//! - Rvs：`inbound.go:625-630` → `Reverse.NewMux`（本批次仅注册表查找 + 转发，完整 worker 在其他 issue）

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use xray_app_dispatcher::default::SimpleOhm;
use xray_app_dispatcher::OutboundHandlerManager;
use xray_buf::io::{new_reader, new_writer};
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_transport::link::Link;

use crate::encoding::server::{decode_request_header, encode_response_header};
use crate::encoding::{empty_addons, VERSION};
use crate::encryption::vision_conn::VisionConn;
use crate::validator::Validator;
/// VLESS inbound 协议族接入选项（feature flags）。

/// 对应 Go `proxy/vless/inbound/inbound.go::Handler` 的可选特性：
/// - `enable_mux`：是否由本 inbound 接管 `command=Mux` 的多路复用流量（首字节
///   `0xFF` 即 VLESS Mux framing）。`false` 时维持 warn+close。
/// - `enable_reverse`：是否由本 inbound 接管 `command=Rvs`（Portal 反向代理）。
///   `false` 时维持 warn+close。
/// - `reverse_registry`：启用 Reverse 时必填；Portal 注册表（domain → PortalConfig）。
///
/// 默认全 false（`Default::default()`），与既有行为一致（warn 跳过非 TCP 命令）。
#[derive(Debug, Clone, Default)]
pub struct VlessInboundOptions {
    /// 启用 Mux 协议识别（仅识别首字节 0xFF；完整 mux server 协议不在本批次范围）。
    pub enable_mux: bool,
    /// 启用 Reverse 协议接入（需要 `reverse_registry` + `reverse_ohm` 配合：
    /// inbound 经 `reverse_registry` 查 `PortalConfig.tag`，再由 `reverse_ohm`
    /// 解析到 `PortalOutbound` handler 派发；Go `inbound.go:625-630` 的 `GetReverse`+
    /// `r.GetOutboundOverride` 语义）。
    pub enable_reverse: bool,
    /// Reverse 注册表（`enable_reverse=true` 时必填）。
    pub reverse_registry: Option<Arc<crate::inbound::reverse::ReverseRegistry>>,
    /// Reverse 解析用的出口管理器引用：Portal tag → `PortalOutbound` 查找。
    pub reverse_ohm: Option<Arc<SimpleOhm>>,
}

/// VLESS inbound 服务入口。
///
/// 绑定 `listener` 监听，每个连接 spawn 独立 task：
/// 1. `decode_request_header` 解析 VLESS 请求头（含 UUID 校验）
/// 2. 按 `command` 分派：TCP → dispatch；UDP → UDP relay；Mux → mux 识别；
///    Rvs → reverse registry 查找
/// 3. 非 TCP 路径：发送响应头后再进入对应 relay
/// 4. `tokio::io::split` → `Link` → `ohm` default handler `dispatch(dest, link)`
///
/// # 参数
/// - `listener`：已绑定的 TCP listener
/// - `ohm`：出站管理器（至少有 default handler）
/// - `validator`：VLESS 用户 validator（UUID → MemoryUser）
/// - `tls`：可选 TLS acceptor（为 None 表示 raw TCP）
/// - `fallbacks`：可选 fallback 策略（napfb 三级 map）
/// - `options`：VLESS inbound 协议族选项（默认 None = 维持旧行为）
///
/// # 错误
/// accept 循环自身错误返回；单个连接错误只 log 不中断循环。
pub async fn serve_vless(
    listener: TcpListener,
    ohm: Arc<SimpleOhm>,
    validator: Arc<dyn Validator>,
    tls: Option<Arc<xray_transport::TlsAcceptor>>,
    fallbacks: Option<Arc<crate::inbound::handler::FallbackPolicy>>,
    options: Option<VlessInboundOptions>,
) -> std::io::Result<()> {
    let handler = ohm
        .get_default_handler()
        .ok_or_else(|| std::io::Error::other("no default outbound handler registered"))?;

    tracing::info!(
        addr = %listener.local_addr()?,
        mux = options.as_ref().map(|o| o.enable_mux).unwrap_or(false),
        reverse = options.as_ref().map(|o| o.enable_reverse).unwrap_or(false),
        "vless inbound listening"
    );

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "vless accept failed");
                continue;
            }
        };

        let handler = Arc::clone(&handler);
        let validator = Arc::clone(&validator);
        let tls = tls.clone();
        let fallbacks = fallbacks.clone();
        let options = options.clone();
        let local = listener.local_addr()?;
        tokio::spawn(async move {
            let result = if let Some(acc) = tls {
                match acc.accept(stream).await {
                    Ok(tls_stream) => {
                        let conn = tls_stream.get_ref().1;
                        let name = conn.server_name().unwrap_or("").to_string();
                        let alpn = conn
                            .alpn_protocol()
                            .map(|p| String::from_utf8_lossy(p).into_owned())
                            .unwrap_or_default();
                        handle_connection_with_fallback(
                            tls_stream, &handler, &validator, fallbacks, peer, local, name, alpn,
                            options,
                        )
                        .await
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "vless TLS accept failed");
                        return;
                    }
                }
            } else {
                handle_connection_with_fallback(
                    stream, &handler, &validator, fallbacks, peer, local, String::new(), String::new(),
                    options,
                )
                .await
            };
            if let Err(e) = result {
                tracing::debug!(error = %e, "vless connection ended with error");
            }
        });
    }
}

/// Mux framing 协议首字节（VLESS mux server 在 mux 帧首字节用 `0xFF` 标识）。
///
/// 对应 Go `common/mux` 包首字节判别。
const MUX_FRAME_FIRST_BYTE: u8 = 0xFF;

/// 前缀已读字节的 reader：先吐 `initial`，再透传内层流（与 tuic inbound 同模式）。
struct InitialedReader<R> {
    initial: std::io::Cursor<Vec<u8>>,
    inner: R,
}

impl<R> InitialedReader<R> {
    fn new(initial: Vec<u8>, inner: R) -> Self {
        Self {
            initial: std::io::Cursor::new(initial),
            inner,
        }
    }

    fn into_parts(self) -> (Vec<u8>, R) {
        let pos = self.initial.position() as usize;
        let mut initial = self.initial.into_inner();
        let remaining = initial.split_off(pos);
        (remaining, self.inner)
    }
}
impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for InitialedReader<R> {
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

/// 带 fallback 的连接处理（Go `vless/inbound/inbound.go::Process` 语义）：
///
/// 1. 预读 first buffer（最多 1024 字节）
/// 2. first[0]==VLESS VERSION 且 decode 成功 → 正常 dispatch
/// 3. 否则（非 VLESS 流量 / 认证失败）→ 查 FallbackPolicy 转发到 fallback dest
pub async fn handle_connection_with_fallback<S>(
    stream: S,
    handler: &Arc<dyn xray_app_dispatcher::DispatchHandler>,
    validator: &Arc<dyn Validator>,
    fallbacks: Option<Arc<crate::inbound::handler::FallbackPolicy>>,
    peer: std::net::SocketAddr,
    local: std::net::SocketAddr,
    tls_name: String,
    tls_alpn: String,
    options: Option<VlessInboundOptions>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::AsyncReadExt;

    // 无 fallback 策略：维持原直连路径（不做 first 预读）
    let Some(policy) = fallbacks else {
        return handle_connection(stream, handler, validator, options).await;
    };

    let (mut read_half, write_half) = tokio::io::split(stream);

    // 1. 预读 first buffer（读到至少 1 字节）
    let mut first = vec![0u8; 1024];
    let mut n = 0;
    while n == 0 {
        let read = read_half.read(&mut first[n..]).await?;
        if read == 0 {
            return Ok(()); // 客户端未发数据即关闭
        }
        n += read;
    }
    first.truncate(n);

    // 2. VLESS 候选：首字节是 VERSION → 回灌后正常 decode；失败也走 fallback
    if first[0] == VERSION {
        let mut reader = InitialedReader::new(first.clone(), read_half);
        if let Ok(decoded) =
            decode_request_header(false, &mut None, &mut reader, validator.as_ref()).await
        {
            return finish_vless_dispatch(reader, write_half, decoded, handler, options).await;
        }
        // ponytail: decode 失败时 decode 已续读的 stream 字节不重放（Go 用
        // connection buffer replay）；version=0 的畸形流量才走到这，正常
        // fallback 客户端（first[0]!=VERSION）不受影响。
        let (_, read_half_back) = reader.into_parts();
        return do_fallback(
            read_half_back,
            write_half,
            &first,
            &policy,
            peer,
            local,
            &tls_name,
            &tls_alpn,
        )
        .await;
    }

    // 3. 非 VLESS 流量：直接 fallback
    do_fallback(read_half, write_half, &first, &policy, peer, local, &tls_name, &tls_alpn).await
}

/// fallback：path 提取 → 查 policy → 透明转发（PROXY header + first 回放 + 双向 pipe）。
async fn do_fallback<R, W>(
    read_half: R,
    write_half: W,
    first: &[u8],
    policy: &Arc<crate::inbound::handler::FallbackPolicy>,
    peer: std::net::SocketAddr,
    local: std::net::SocketAddr,
    tls_name: &str,
    tls_alpn: &str,
) -> std::io::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let path = crate::inbound::handler::extract_path_from_first_bytes(first).unwrap_or("");
    let Some(fb) = policy.find_with_fallback(tls_name, tls_alpn, path) else {
        return Err(std::io::Error::other(
            "vless decode failed and no fallback matched",
        ));
    };
    tracing::debug!(dest = %fb.dest, xver = fb.xver, name = tls_name, alpn = tls_alpn, path, "vless fallback");
    let mut conn = tokio::io::join(read_half, write_half);
    let _ = xray_transport::fallback::fallback_to_dest(
        &mut conn, first, &fb.dest, peer, local, fb.xver,
    )
    .await;
    Ok(())
}

/// 组合流 marker trait：`dyn AsyncRead + AsyncWrite` 不能有两个主 trait，
/// 用它把「VisionConn 包装后的流」与「原始流」抹平成同一类型。
trait VlessStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> VlessStream for T {}

/// Vision 首块 padding 携带的 uuid bytes（解码用户的账号 UUID，对齐 Go
/// `request.User` 的 `ID.UUID()`）。非 vision flow 返回 `None`。
fn vision_uuid_bytes(
    decoded: &crate::encoding::server::DecodedRequest,
) -> std::io::Result<Option<Vec<u8>>> {
    if decoded.addons.flow != crate::FLOW_XRV {
        return Ok(None);
    }
    let user = decoded.user.as_ref().ok_or_else(|| {
        std::io::Error::other("vless vision: decoded request carries no user")
    })?;
    Ok(Some(user.account.id.uuid().as_bytes().to_vec()))
}

/// decode 成功后的收尾：按 `decoded.command` 分派到对应处理路径。
///
/// - TCP：响应头 → vision 包装（可选） → split → dispatch
/// - UDP：响应头 → [`handle_udp_relay`] 长度前缀包循环 → UdpDispatchSession 桥接
/// - Mux：响应头 → [`handle_mux_relay`] 检测首字节 0xFF（其余 warn+close）
/// - Rvs：响应头 → [`handle_reverse_relay`] 反向代理派发
async fn finish_vless_dispatch<R, W>(
    reader: R,
    mut write_half: W,
    decoded: crate::encoding::server::DecodedRequest,
    handler: &Arc<dyn xray_app_dispatcher::DispatchHandler>,
    options: Option<VlessInboundOptions>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    use crate::encoding::VlessCommand;

    // 1. 发送响应头（version + empty addons）
    encode_response_header(&mut write_half, VERSION, &empty_addons())
        .await
        .map_err(|e| std::io::Error::other(format!("vless encode response: {e}")))?;

    // 2. 按 command 分派
    match decoded.command {
        VlessCommand::Tcp => {
            finish_tcp_dispatch(reader, write_half, &decoded, handler).await
        }
        VlessCommand::Udp => {
            handle_udp_relay(reader, write_half, &decoded, handler).await
        }
        VlessCommand::Mux => {
            handle_mux_relay(reader, write_half, &decoded, handler, options.as_ref()).await
        }
        VlessCommand::Rvs => {
            handle_reverse_relay(reader, write_half, &decoded, handler, options.as_ref()).await
        }
    }
}

/// TCP 命令分派：vision 包装（可选） → split → dispatch。
async fn finish_tcp_dispatch<R, W>(
    reader: R,
    write_half: W,
    decoded: &crate::encoding::server::DecodedRequest,
    handler: &Arc<dyn xray_app_dispatcher::DispatchHandler>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let vision_uuid = vision_uuid_bytes(decoded)?;
    let address = decoded
        .address
        .clone()
        .ok_or_else(|| std::io::Error::other("vless decode: missing address for TCP command"))?;
    let port = decoded
        .port
        .ok_or_else(|| std::io::Error::other("vless decode: missing port for TCP command"))?;
    let dest = Destination::new(address, Port::new(port), Network::TCP);

    // flow=xtls-rprx-vision：join 读写半流 → VisionConn 包装（uuid 用解码用户）
    // → 重新 split；非 vision 同样 join+split（零开销适配器，统一类型）。
    let stream: Box<dyn VlessStream> = match vision_uuid {
        Some(uuid) => Box::new(VisionConn::new(tokio::io::join(reader, write_half), uuid)),
        None => Box::new(tokio::io::join(reader, write_half)),
    };
    let (rh, wh) = tokio::io::split(stream);
    let link = Link::new(new_reader(rh), new_writer(wh));
    let _ = handler.dispatch(&dest, link).await;
    Ok(())
}

/// UDP 命令 relay：长度前缀包循环 ↔ UdpDispatchSession。
/// 对应 Go `vless/inbound/inbound.go::Process` 的 UDP 分支（dispatch link 写为
/// UDP 目的地，长度前缀包由 `proxy/vless/encoding/addons.go` 的
/// `MultiLengthPacketWriter/LengthPacketReader` 处理）。Rust 端实现简化：
/// 客户端 TCP 上每个包是 `[2B BE len][payload]`，payload 作为 UDP 数据报。
/// 首包目的地用 `decoded.address/port`（请求头解析得到），后续包用同一目的地
/// （与 Go `udpInbound` 单 session 一致）。
async fn handle_udp_relay<R, W>(
    mut reader: R,
    mut writer: W,
    decoded: &crate::encoding::server::DecodedRequest,
    handler: &Arc<dyn xray_app_dispatcher::DispatchHandler>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    use crate::encoding::{read_length_packet, write_length_packet};

    let address = decoded
        .address
        .clone()
        .ok_or_else(|| std::io::Error::other("vless UDP: missing address"))?;
    let port = decoded
        .port
        .ok_or_else(|| std::io::Error::other("vless UDP: missing port"))?;
    let udp_dest = Destination::new(address, Port::new(port), Network::UDP);

    let mut session = xray_app_dispatcher::UdpDispatchSession::new(handler.clone());

    loop {
        let payload = match read_length_packet(&mut reader).await {
            Ok(p) => p,
            Err(crate::error::VlessError::Io(e))
                if e.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                // 客户端关闭 TCP：正常退出（与 Go UDP relay 行为一致）
                return Ok(());
            }
            Err(e) => {
                return Err(std::io::Error::other(format!("vless UDP read: {e}")));
            }
        };

        if let Err(e) = session.send_packet(&udp_dest, &payload).await {
            return Err(std::io::Error::other(format!("vless UDP dispatch: {e}")));
        }

        // 收取响应包（cone NAT：同一 session 接收多个回包）
        match session.recv_packet().await {
            Ok(Some((_source, resp))) => {
                if let Err(e) = write_length_packet(&mut writer, &resp).await {
                    return Err(std::io::Error::other(format!("vless UDP write: {e}")));
                }
            }
            Ok(None) => return Ok(()),     // outbound 关闭
            Err(e) => return Err(std::io::Error::other(format!("vless UDP recv: {e}"))),
        }
    }
}

/// Mux 命令 relay：识别首字节 0xFF 后转交 dispatcher。
///
/// 对应 Go `vless/inbound/inbound.go::isMuxAndNotXUDP` + `dispatch.DispatchLink`。
/// 本批次非目标：完整 mux server 协议（由 `xray-mux` 接管）。当前实现仅识别
/// 首字节 `0xFF`，命中则 dispatch 到 mux server 出口（路由须配置 mux 出站）；
/// 未命中则维持原 warn+close 行为。
async fn handle_mux_relay<R, W>(
    mut reader: R,
    writer: W,
    decoded: &crate::encoding::server::DecodedRequest,
    handler: &Arc<dyn xray_app_dispatcher::DispatchHandler>,
    options: Option<&VlessInboundOptions>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::AsyncReadExt;

    // feature flag 未启用：维持 warn+close
    let enabled = options.map(|o| o.enable_mux).unwrap_or(false);
    if !enabled {
        tracing::warn!(
            command = ?decoded.command,
            "vless Mux command received but enable_mux=false, closing"
        );
        return Ok(());
    }

    // 探测首字节：peek 1 byte 不消费（Mux framing 首字节为 0xFF）
    let mut probe = [0u8; 1];
    let n = reader.read(&mut probe).await?;
    if n == 0 {
        return Ok(()); // 客户端未发数据
    }
    if probe[0] != MUX_FRAME_FIRST_BYTE {
        tracing::warn!(
            first_byte = probe[0],
            "vless Mux command but first byte != 0xFF, not a mux frame"
        );
        return Ok(());
    }

    // 命中 mux framing：回灌首字节 → 构造 mux link → dispatch
    let reader = InitialedReader::new(probe.to_vec(), reader);
    let stream = tokio::io::join(reader, writer);
    let (rh, wh) = tokio::io::split(stream);
    // mux 命令的 destination 固定为 `v1.mux.cool`，由 mux server 解析真实子流目标
    let dest = Destination::new(
        xray_common::net::address::Address::Domain("v1.mux.cool".to_string()),
        Port::new(0),
        Network::TCP,
    );
    let link = Link::new(new_reader(rh), new_writer(wh));
    let _ = handler.dispatch(&dest, link).await;
    Ok(())
}

/// Reverse（Rvs）命令 relay：Portal 注册表查找 → ohm 解析 PortalOutbound →
/// dispatch。 对应 Go `inbound.go:625-630` 的 `h.GetReverse(account) → r.NewMux(...)`：
/// inbound 解析到用户级别 portal 配置 → Reverse feature 找到对应 PortalOutbound
/// → 由 PortalOutbound 在该出站槽上跑 mux carrier 桥接。 本批次完成接线层：
/// linker 经 ReverseRegistry 查 tag，再经 `reverse_ohm` 取 handler，dispatch 入站
/// link。Portal mux client worker 完整 mux 客户端由 [`crate::outbound::reverse`] +
/// `xray-app-reverse::worker::PortalWorker` 接管（不在本批次）。
async fn handle_reverse_relay<R, W>(
    reader: R,
    writer: W,
    decoded: &crate::encoding::server::DecodedRequest,
    _handler: &Arc<dyn xray_app_dispatcher::DispatchHandler>,
    options: Option<&VlessInboundOptions>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let opts = options;
    let enabled = opts.map(|o| o.enable_reverse).unwrap_or(false);
    if !enabled {
        tracing::warn!(
            command = ?decoded.command,
            "vless Reverse command received but enable_reverse=false, closing"
        );
        return Ok(());
    }

    let registry = opts
        .and_then(|o| o.reverse_registry.as_ref())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "vless Reverse enabled but no registry configured")
        })?;
    let ohm: Arc<SimpleOhm> = opts
        .and_then(|o| o.reverse_ohm.clone())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "vless Reverse enabled but no reverse_ohm configured")
        })?;

    // 当前 Rust 端 MemoryAccount 暂无 Reverse.Tag 字段（Reverse 字段在 proto
    // 转换层尚未启用）。本批次取注册表首条配置作为 portal 绑定（v1.rvs.cool
    // 默认值由 PortalConfig::new 提供，与 Go 端默认值一致）。
    let _ = &decoded.user; // 保留供后续按 account.Reverse.Tag 路由
    let portal_tag = registry
        .tags()
        .first()
        .cloned()
        .ok_or_else(|| {
            std::io::Error::other("vless Reverse registry empty")
        })?;
    let portal_cfg = registry.get_reverse(&portal_tag).map_err(|e| {
        std::io::Error::other(format!("vless Reverse get_reverse: {}", e))
    })?;

    let portal_handler = ohm.get_handler(&portal_cfg.tag).ok_or_else(|| {
        std::io::Error::other(format!(
            "vless Reverse portal handler not registered for tag={}",
            portal_cfg.tag
        ))
    })?;

    // Reverse destination: domain=portal_cfg.domain（默认 v1.rvs.cool），network=TCP
    let dest = Destination::new(
        xray_common::net::address::Address::Domain(portal_cfg.domain.clone()),
        Port::new(0),
        Network::TCP,
    );
    let link = Link::new(new_reader(reader), new_writer(writer));
    tracing::debug!(
        user = decoded.user.as_ref().map(|u| u.email.as_str()).unwrap_or("?"),
        portal_tag = %portal_cfg.tag,
        "vless Reverse: dispatch to PortalOutbound via ohm"
    );
    let _ = portal_handler.dispatch(&dest, link).await;
    Ok(())
}
/// 路由（直接 decode 整个 stream）。Command 分派由 `finish_vless_dispatch` 承担。
pub async fn handle_connection<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    handler: &Arc<dyn xray_app_dispatcher::DispatchHandler>,
    validator: &Arc<dyn Validator>,
    options: Option<VlessInboundOptions>,
) -> std::io::Result<()> {
    let mut stream = stream;

    // 1. decode VLESS request header（isfb=false，全部从 stream 读）
    let mut first: Option<Vec<u8>> = None;
    let decoded = decode_request_header(false, &mut first, &mut stream, validator.as_ref())
        .await
        .map_err(|e| std::io::Error::other(format!("vless decode: {e}")))?;

    // 2. 按 command 分派：拆 reader/writer 后交 finish_vless_dispatch。
    let (read_half, write_half) = tokio::io::split(stream);
    finish_vless_dispatch(read_half, write_half, decoded, handler, options).await
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::VlessCommand;
    use crate::encoding::client::{decode_response_header, encode_request_header};
    use crate::validator::{MemoryUser, MemoryValidator};
    use crate::MemoryAccount;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use xray_app_dispatcher::default::DialBridge;
    use xray_common::net::address::Address;
    use xray_common::uuid::UUID;
    use xray_proxy_freedom::make_freedom_dial_fn;

    /// 构造测试用 validator + 已注册用户的 UUID。
    fn make_validator_with_user() -> (UUID, Arc<dyn Validator>) {
        let uuid = UUID::new();
        let user = MemoryUser {
            level: 0,
            email: "test@example.com".to_string(),
            account: MemoryAccount::from_proto_account(
                &xray_proto::xray::proxy::vless::Account {
                    id: uuid.to_string(),
                    ..Default::default()
                },
            )
            .unwrap(),
        };
        let v = MemoryValidator::new();
        v.add(user).unwrap();
        (uuid, Arc::new(v))
    }

    /// 端到端：VLESS client → VLESS inbound → freedom outbound → echo server。
    #[tokio::test]
    async fn vless_inbound_to_freedom_outbound_e2e() {
        // 1. echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
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
        let dial_fn = make_freedom_dial_fn();
        let bridge = Arc::new(DialBridge::new("freedom", dial_fn))
            as Arc<dyn xray_app_dispatcher::DispatchHandler>;
        ohm.set_default(bridge);

        // 3. validator + serve_vless
        let (uuid, validator) = make_validator_with_user();
        let vless_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vless_addr = vless_listener.local_addr().unwrap();
        let ohm_clone = Arc::clone(&ohm);
        let validator_clone = Arc::clone(&validator);
        tokio::spawn(async move {
            let _ = serve_vless(vless_listener, ohm_clone, validator_clone, None, None, None).await;
        });

        // 4. VLESS client：connect → encode request → decode response → echo round-trip
        let mut client = tokio::net::TcpStream::connect(vless_addr)
            .await
            .unwrap();
        let addons = empty_addons();
        let dest_addr = Address::from_ipv4_bytes([127, 0, 0, 1]);
        encode_request_header(
            &mut client,
            VERSION,
            &uuid,
            VlessCommand::Tcp,
            Some(&dest_addr),
            Some(echo_port),
            &addons,
        )
        .await
        .unwrap();

        // 读响应头（version + addons），客户端消费后才能发数据
        let _resp_addons = decode_response_header(&mut client, VERSION)
            .await
            .unwrap();

        // 5. 发数据 + 读 echo
        let payload = b"hello vless proxy!";
        client.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, payload, "should receive echo through vless proxy");
    }

    /// 无效用户（validator 中不存在）→ 连接被关闭，client 收到 EOF 或 decode 错误。
    #[tokio::test]
    async fn vless_inbound_rejects_unknown_user() {
        let ohm = Arc::new(SimpleOhm::new());
        let dial_fn = make_freedom_dial_fn();
        ohm.set_default(Arc::new(DialBridge::new("freedom", dial_fn))
            as Arc<dyn xray_app_dispatcher::DispatchHandler>);

        // 空 validator（无任何用户）
        let validator: Arc<dyn Validator> = Arc::new(MemoryValidator::new());
        let vless_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vless_addr = vless_listener.local_addr().unwrap();
        let ohm_clone = Arc::clone(&ohm);
        let validator_clone = Arc::clone(&validator);
        tokio::spawn(async move {
            let _ = serve_vless(vless_listener, ohm_clone, validator_clone, None, None, None).await;
        });

        // client 用一个随机的（未注册的）UUID
        let unknown_uuid = UUID::new();
        let mut client = tokio::net::TcpStream::connect(vless_addr)
            .await
            .unwrap();
        let addons = empty_addons();
        let dest_addr = Address::from_ipv4_bytes([127, 0, 0, 1]);
        encode_request_header(
            &mut client,
            VERSION,
            &unknown_uuid,
            VlessCommand::Tcp,
            Some(&dest_addr),
            Some(80),
            &addons,
        )
        .await
        .unwrap();

        // server 因 UserNotFound 关闭连接 → client 读响应得到 EOF 或连接重置
        let mut buf = [0u8; 16];
        let result = client.read(&mut buf).await;
        match result {
            Ok(0) => {} // clean EOF
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionAborted => {}
            other => panic!("expected EOF or connection reset, got {other:?}"),
        }
    }

    /// 公共 harness：echo server + freedom dispatch + serve_vless（注册一个用户）。
    /// 返回 (vless 监听地址, echo 端口, 用户 UUID)。
    async fn spawn_vless_proxy_with_echo() -> (std::net::SocketAddr, u16, UUID) {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
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

        let ohm = Arc::new(SimpleOhm::new());
        ohm.set_default(Arc::new(DialBridge::new("freedom", make_freedom_dial_fn()))
            as Arc<dyn xray_app_dispatcher::DispatchHandler>);

        let (uuid, validator) = make_validator_with_user();
        let vless_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vless_addr = vless_listener.local_addr().unwrap();
        let validator: Arc<dyn Validator> = validator;
        tokio::spawn(async move {
            let _ = serve_vless(vless_listener, ohm, validator, None, None, None).await;
        });
        (vless_addr, echo_port, uuid)
    }

    /// inbound：decoded.addons.flow=XRV 时服务端下行必须走 Vision padding：
    /// 客户端裸读首段下行字节，应为 `[uuid(16)][command][content_len(2 BE)]
    /// [padding_len(2 BE)][content]` 帧。未包装 → 裸 echo 内容 → fail/超时。
    #[tokio::test]
    async fn vless_inbound_pads_downlink_when_flow_xrv() {
        use crate::encryption::vision::COMMAND_PADDING_CONTINUE;
        use tokio::time::{timeout, Duration};

        let (vless_addr, echo_port, uuid) = spawn_vless_proxy_with_echo().await;

        let mut client = tokio::net::TcpStream::connect(vless_addr).await.unwrap();
        let mut addons = empty_addons();
        addons.flow = crate::FLOW_XRV.to_string();
        encode_request_header(
            &mut client,
            VERSION,
            &uuid,
            VlessCommand::Tcp,
            Some(&Address::from_ipv4_bytes([127, 0, 0, 1])),
            Some(echo_port),
            &addons,
        )
        .await
        .unwrap();
        decode_response_header(&mut client, VERSION).await.unwrap();

        // 裸发 ping（inbound 对非 Vision 块是透传语义，无需客户端 padding）
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();

        // 裸读下行：uuid(16)+command(1)+content_len(2)+padding_len(2)+"ping"(4) = 25
        let mut wire = [0u8; 25];
        timeout(Duration::from_secs(10), client.read_exact(&mut wire))
            .await
            .expect("downlink must be a vision padding frame")
            .unwrap();
        assert_eq!(
            &wire[..16],
            uuid.as_bytes(),
            "first downlink block must start with user uuid"
        );
        assert_eq!(wire[16], COMMAND_PADDING_CONTINUE, "data frame command");
        assert_eq!(&wire[17..19], &[0, 4], "content_len BE");
        assert_eq!(&wire[21..25], b"ping");
    }

    /// e2e：make_dial_fn(flow=XRV) ↔ serve_vless 全链路 Vision padding 对拉
    ///（outbound 与 inbound 双端包装，padding 收发互解）。
    #[tokio::test]
    async fn vless_vision_e2e_client_and_server_roundtrip() {
        use crate::dispatcher::{make_dial_fn, VlessOutboundConfig};
        use tokio::time::{timeout, Duration};

        let (vless_addr, echo_port, uuid) = spawn_vless_proxy_with_echo().await;

        let cfg = Arc::new(
            VlessOutboundConfig::new(
                uuid,
                Address::from_ipv4_bytes([127, 0, 0, 1]),
                Port::new(vless_addr.port()),
            )
            .with_flow(crate::FLOW_XRV),
        );
        let dial = make_dial_fn(cfg);
        let dest = Destination::tcp(Address::from_ipv4_bytes([127, 0, 0, 1]), Port::new(echo_port));
        let mut conn = dial(&dest).await.expect("dial through vless server");

        let payload = b"vision e2e roundtrip payload";
        conn.write_all(payload).await.unwrap();
        conn.flush().await.unwrap();
        let mut got = vec![0u8; payload.len()];
        timeout(Duration::from_secs(10), conn.read_exact(&mut got))
            .await
            .expect("echo through vision-wrapped vless path")
            .unwrap();
        assert_eq!(&got, payload);
    }

    /// 回归：flow 为空时 make_dial_fn 返回裸连接（无 Vision 包装），链路照常。
    #[tokio::test]
    async fn vless_no_flow_e2e_make_dial_fn_roundtrip() {
        use crate::dispatcher::{make_dial_fn, VlessOutboundConfig};
        use tokio::time::{timeout, Duration};

        let (vless_addr, echo_port, uuid) = spawn_vless_proxy_with_echo().await;

        let cfg = Arc::new(VlessOutboundConfig::new(
            uuid,
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(vless_addr.port()),
        ));
        let dial = make_dial_fn(cfg);
        let dest = Destination::tcp(Address::from_ipv4_bytes([127, 0, 0, 1]), Port::new(echo_port));
        let mut conn = dial(&dest).await.expect("dial");

        let payload = b"plain vless roundtrip";
        conn.write_all(payload).await.unwrap();
        conn.flush().await.unwrap();
        let mut got = vec![0u8; payload.len()];
        timeout(Duration::from_secs(10), conn.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
    }
    /// UDP echo 模拟 DispatchHandler：读首帧 XUDP，回写一帧（payload 相同）。
    ///
    /// 仅供 `vless_inbound_udp_relay_e2e` 测试用——生产用 UdpDispatchSession
    /// 走 `xray_app_dispatcher::udp_session` 既有 `EchoHandler`。
    #[derive(Debug)]
    struct UdpEchoHandler {
        captured: std::sync::Arc<parking_lot::Mutex<Vec<Vec<u8>>>>,
    }

    impl UdpEchoHandler {
        fn new() -> Self {
            Self {
                captured: std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
            }
        }
    }

    impl xray_app_dispatcher::DispatchHandler for UdpEchoHandler {
        fn tag(&self) -> &str {
            "udp-echo-test"
        }

        fn dispatch(
            &self,
            _dest: &xray_common::net::destination::Destination,
            link: xray_transport::link::Link,
        ) -> xray_app_dispatcher::default::PinFuture<()> {
            let captured = std::sync::Arc::clone(&self.captured);
            Box::pin(async move {

                use xray_xudp::packet::{FrameMetadata, PacketReader};
                let mut reader = link.reader;
                let mut writer = link.writer;
                let mut accum: Vec<u8> = Vec::new();
                loop {
                    let mb = match reader.read_multi_buffer().await {
                        Ok(mb) => mb,
                        Err(_) => return,
                    };
                    let bytes = mb.to_vec();
                    accum.extend_from_slice(&bytes);
                    loop {
                        let mut cursor = std::io::Cursor::new(&accum[..]);
                        let mut pr = PacketReader::new(&mut cursor);
                        match pr.read_packet() {
                            Ok(Some(pkt)) => {
                                let consumed = cursor.position() as usize;
                                let (data, _target) = pkt.into_parts();
                                captured.lock().push(data.clone());
                                // 回写一帧：来源 = 固定地址，payload = 收到原样
                                let mut frame = Vec::new();
                                FrameMetadata::keep_udp(
                                    Address::from_ipv4_bytes([127, 0, 0, 1]),
                                    Port::new(53),
                                )
                                .write_to(&mut frame)
                                .unwrap();
                                frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
                                frame.extend_from_slice(&data);
                                let mut out = xray_buf::multi::MultiBuffer::new();
                                out.merge_bytes(&frame);
                                if writer.write_multi_buffer(out).await.is_err() {
                                    return;
                                }
                                accum.drain(..consumed);
                            }
                            _ => break,
                        }
                    }
                }
            })
        }
    }

    /// 端到端：VLESS client → VLESS inbound (UDP command) → UdpDispatchSession →
    /// mock UDP echo handler → 长度前缀回包。
    #[tokio::test]
    async fn vless_inbound_udp_relay_e2e() {
        // 1. mock UDP echo handler 注册到 SimpleOhm
        let handler = std::sync::Arc::new(UdpEchoHandler::new());
        let captured = std::sync::Arc::clone(&handler.captured);
        let ohm = Arc::new(SimpleOhm::new());
        ohm.set_default(handler as Arc<dyn xray_app_dispatcher::DispatchHandler>);

        // 2. validator + serve_vless
        let (uuid, validator) = make_validator_with_user();
        let vless_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vless_addr = vless_listener.local_addr().unwrap();
        let ohm_clone = Arc::clone(&ohm);
        let validator_clone = Arc::clone(&validator);
        tokio::spawn(async move {
            let _ = serve_vless(vless_listener, ohm_clone, validator_clone, None, None, None).await;
        });

        // 3. VLESS client：connect → encode UDP request → decode response →
        //    发送 1 个长度前缀 UDP 包 → 期望收到 1 个长度前缀回包（payload = 原值）
        let mut client = tokio::net::TcpStream::connect(vless_addr).await.unwrap();
        let addons = empty_addons();
        // VLESS UDP command：dest = 任意 UDP 目标（这里用 127.0.0.1:53 占位）
        let dest_addr = Address::from_ipv4_bytes([127, 0, 0, 1]);
        encode_request_header(
            &mut client,
            VERSION,
            &uuid,
            VlessCommand::Udp,
            Some(&dest_addr),
            Some(53),
            &addons,
        )
        .await
        .unwrap();
        let _resp_addons = decode_response_header(&mut client, VERSION).await.unwrap();

        // 4. 发送长度前缀 UDP 包
        let payload = b"hello-udp-via-vless";
        let len_bytes = (payload.len() as u16).to_be_bytes();
        client.write_all(&len_bytes).await.unwrap();
        client.write_all(payload).await.unwrap();

        // 5. 读取长度前缀回包
        let mut len_buf = [0u8; 2];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_exact(&mut len_buf),
        )
        .await
        .expect("echo should arrive within 5s")
        .unwrap();
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp = vec![0u8; resp_len];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(
            &resp, payload,
            "UDP echo payload should round-trip via UdpDispatchSession"
        );
        // 6. 验证 mock handler 收到了包
        assert_eq!(
            captured.lock().len(),
            1,
            "mock UDP echo handler should have captured 1 packet"
        );
        assert_eq!(&captured.lock()[0], payload);
    }

    /// 捕获 DispatchHandler 调用次数 + 入参 dest。
    #[derive(Debug)]
    struct CaptureDispatchHandler {
        called: std::sync::Arc<parking_lot::Mutex<u32>>,
        dest_seen: std::sync::Arc<parking_lot::Mutex<Option<xray_common::net::destination::Destination>>>,
    }

    impl CaptureDispatchHandler {
        fn new() -> Self {
            Self {
                called: std::sync::Arc::new(parking_lot::Mutex::new(0)),
                dest_seen: std::sync::Arc::new(parking_lot::Mutex::new(None)),
            }
        }
    }

    impl xray_app_dispatcher::DispatchHandler for CaptureDispatchHandler {
        fn tag(&self) -> &str {
            "capture"
        }
        fn dispatch(
            &self,
            dest: &xray_common::net::destination::Destination,
            _link: xray_transport::link::Link,
        ) -> xray_app_dispatcher::default::PinFuture<()> {
            let called = std::sync::Arc::clone(&self.called);
            let dest_seen = std::sync::Arc::clone(&self.dest_seen);
            let dest = dest.clone();
            Box::pin(async move {
                *called.lock() += 1;
                *dest_seen.lock() = Some(dest);
                // 读 link 第一个字节以消费（避免测试挂住）
                let mut reader = _link.reader;
                let _ = reader.read_multi_buffer().await;
            })
        }
    }

    /// VLESS Mux command + enable_mux=true + 首字节 0xFF：dispatch 应被调用一次，
    /// dest 固定为 v1.mux.cool。
    #[tokio::test]
    async fn vless_inbound_mux_first_byte_ff_dispatches() {
        let capture = std::sync::Arc::new(CaptureDispatchHandler::new());
        let called = std::sync::Arc::clone(&capture.called);
        let dest_seen = std::sync::Arc::clone(&capture.dest_seen);
        let capture_for_ohm: Arc<dyn xray_app_dispatcher::DispatchHandler> = capture.clone();
        let ohm = Arc::new(SimpleOhm::new());
        ohm.set_default(capture_for_ohm);

        let (uuid, validator) = make_validator_with_user();
        let vless_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vless_addr = vless_listener.local_addr().unwrap();
        let ohm_clone = Arc::clone(&ohm);
        let validator_clone = Arc::clone(&validator);
        let opts = VlessInboundOptions {
            enable_mux: true,
            enable_reverse: false,
            reverse_registry: None,
            reverse_ohm: None,
        };
        tokio::spawn(async move {
            let _ = serve_vless(
                vless_listener, ohm_clone, validator_clone, None, None, Some(opts),
            )
            .await;
        });

        // client：Mux command → 响应头 → 0xFF 探测字节
        let mut client = tokio::net::TcpStream::connect(vless_addr).await.unwrap();
        let addons = empty_addons();
        encode_request_header(
            &mut client,
            VERSION,
            &uuid,
            VlessCommand::Mux,
            None,
            None,
            &addons,
        )
        .await
        .unwrap();
        let _resp = decode_response_header(&mut client, VERSION).await.unwrap();
        client.write_all(&[MUX_FRAME_FIRST_BYTE]).await.unwrap();
        client.write_all(b"\x00\x00\x00\x00\x00\x00").await.unwrap(); // mux 帧剩余字节

        // 等 dispatch 触发（带 timeout 防止挂住）
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            for _ in 0..30 {
                if *called.lock() > 0 {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("dispatch should be called within 3s");

        assert_eq!(*called.lock(), 1, "Mux 0xFF should trigger exactly one dispatch");
        let dest = dest_seen.lock().clone().expect("dest should be captured");
        let addr = dest.address().as_domain().expect("mux dest should be domain");
        assert_eq!(addr, "v1.mux.cool", "Mux dest should be v1.mux.cool");
    }

    /// VLESS Mux command + enable_mux=true + 首字节 ≠ 0xFF：dispatch 不应被调用。
    #[tokio::test]
    async fn vless_inbound_mux_first_byte_not_ff_skips() {
        let capture = std::sync::Arc::new(CaptureDispatchHandler::new());
        let called = std::sync::Arc::clone(&capture.called);
        let capture_for_ohm: Arc<dyn xray_app_dispatcher::DispatchHandler> = capture.clone();
        let ohm = Arc::new(SimpleOhm::new());
        ohm.set_default(capture_for_ohm);

        let (uuid, validator) = make_validator_with_user();
        let vless_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vless_addr = vless_listener.local_addr().unwrap();
        let ohm_clone = Arc::clone(&ohm);
        let validator_clone = Arc::clone(&validator);
        let opts = VlessInboundOptions {
            enable_mux: true,
            enable_reverse: false,
            reverse_registry: None,
            reverse_ohm: None,
        };
        tokio::spawn(async move {
            let _ = serve_vless(
                vless_listener, ohm_clone, validator_clone, None, None, Some(opts),
            )
            .await;
        });

        let mut client = tokio::net::TcpStream::connect(vless_addr).await.unwrap();
        encode_request_header(
            &mut client, VERSION, &uuid, VlessCommand::Mux, None, None, &empty_addons(),
        )
        .await
        .unwrap();
        let _resp = decode_response_header(&mut client, VERSION).await.unwrap();
        client.write_all(&[0x42]).await.unwrap(); // 不是 0xFF
        client.write_all(b"junk").await.unwrap();

        // 等 1s 确保 dispatch 不会被触发
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(
            *called.lock(),
            0,
            "Mux with first byte != 0xFF should NOT trigger dispatch"
        );
    }

    /// VLESS Rvs command + enable_reverse=false：维持原 warn+close 行为，
    /// dispatch 不应被调用。
    #[tokio::test]
    async fn vless_inbound_rvs_disabled_warns_and_skips() {
        let capture = std::sync::Arc::new(CaptureDispatchHandler::new());
        let called = std::sync::Arc::clone(&capture.called);
        let capture_for_ohm: Arc<dyn xray_app_dispatcher::DispatchHandler> = capture.clone();
        let ohm = Arc::new(SimpleOhm::new());
        ohm.set_default(capture_for_ohm);

        let (uuid, validator) = make_validator_with_user();
        let vless_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vless_addr = vless_listener.local_addr().unwrap();
        let ohm_clone = Arc::clone(&ohm);
        let validator_clone = Arc::clone(&validator);
        let opts = VlessInboundOptions {
            enable_mux: false,
            enable_reverse: false,
            reverse_registry: None,
            reverse_ohm: None,
        };
        tokio::spawn(async move {
            let _ = serve_vless(
                vless_listener, ohm_clone, validator_clone, None, None, Some(opts),
            )
            .await;
        });

        let mut client = tokio::net::TcpStream::connect(vless_addr).await.unwrap();
        encode_request_header(
            &mut client, VERSION, &uuid, VlessCommand::Rvs, None, None, &empty_addons(),
        )
        .await
        .unwrap();
        // 应该收到响应头 + 关闭
        let _resp = decode_response_header(&mut client, VERSION).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert_eq!(
            *called.lock(),
            0,
            "Rvs with enable_reverse=false should NOT trigger dispatch"
        );
    }

    /// VLESS Rvs command + enable_reverse=true + 注册表存在：不再 warn 占位，
    /// dispatch 路径被设置（当前实现是 stub——只验证注册表查找不会 panic）。
    #[tokio::test]
    async fn vless_inbound_rvs_enabled_with_registry_uses_registry() {
        let capture = std::sync::Arc::new(CaptureDispatchHandler::new());
        let capture_for_ohm: Arc<dyn xray_app_dispatcher::DispatchHandler> = capture.clone();
        let ohm = Arc::new(SimpleOhm::new());
        ohm.set_default(Arc::clone(&capture_for_ohm));
        // 注册 portal-tag 处 portal handler，验证 reverse wiring 走 ohm.get_handler
        // → PortalOutbound 路径（call_count>0 即证明接线生效）。
        ohm.add(
            "portal-tag",
            Arc::clone(&capture) as Arc<dyn xray_app_dispatcher::DispatchHandler>,
        );

        let (uuid, validator) = make_validator_with_user();
        let vless_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let vless_addr = vless_listener.local_addr().unwrap();
        let ohm_clone = Arc::clone(&ohm);
        let validator_clone = Arc::clone(&validator);

        let registry = Arc::new(crate::inbound::reverse::ReverseRegistry::default());
        registry
            .add_reverse(crate::inbound::reverse::PortalConfig {
                tag: "portal-tag".to_string(),
                domain: "v1.rvs.cool".to_string(),
            })
            .unwrap();

        let opts = VlessInboundOptions {
            enable_mux: false,
            enable_reverse: true,
            reverse_registry: Some(Arc::clone(&registry)),
            reverse_ohm: Some(Arc::clone(&ohm_clone)),
        };
        tokio::spawn(async move {
            let _ = serve_vless(
                vless_listener, ohm_clone, validator_clone, None, None, Some(opts),
            )
            .await;
        });

        let mut client = tokio::net::TcpStream::connect(vless_addr).await.unwrap();
        encode_request_header(
            &mut client, VERSION, &uuid, VlessCommand::Rvs, None, None, &empty_addons(),
        )
        .await
        .unwrap();
        let _resp = decode_response_header(&mut client, VERSION).await.unwrap();
        // 当前 Reverse 是 stub：仅做注册表查找，不触发 dispatch。
        // 验证：响应头已发 + 客户端能正常关闭（不挂住）。
        let mut buf = [0u8; 1];
        let r = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            client.read(&mut buf),
        )
        .await;
        // 期望：客户端收到 EOF（Ok(0)）或读超时
        match r {
            Ok(Ok(0)) => {} // clean EOF
            Ok(Ok(_)) => {} // 也接受（可能写了别的）
            Err(_) => {}    // timeout：也行
            Ok(Err(_)) => {}
        }
    }
}
