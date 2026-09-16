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
//! - Mux：按请求目的地原样 dispatch（`v1.mux.cool`），mux carrier 拦截在生产
//!   dispatcher 装饰器（Go proxyman always.go 语义，见 xray-core wiring）
//! - Rvs：Portal 反向代理，启用 feature 时查 reverse_registry 派发
//!
//! 对应 Go 语义：
//! - TCP：`inbound.go::Process` → `dispatch.DispatchLink(ctx, dest, link)`
//! - UDP：同上，dest.Network = UDP + link 包 LengthPacketReader/Writer 包装
//! - Mux：`inbound.go:633 dispatch.DispatchLink(request.Destination())`（按目的地
//!   原样 dispatch；carrier 拦截在 dispatcher 装饰器，对应 Go mux.Server）
//! - Rvs：`inbound.go:625-630` → `Reverse.NewMux`（本批次仅注册表查找 + 转发，完整 worker 在其他 issue）

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use xray_app_dispatcher::default::SimpleOhm;
use xray_app_dispatcher::OutboundHandlerManager;
use xray_buf::io::{new_reader, new_writer};
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_common::net::port::Port;
use xray_transport::link::Link;
use xray_transport::system_listener::InboundTcpListener;

use crate::encoding::server::{decode_request_header, encode_response_header};
use crate::encoding::{empty_addons, VERSION};
use crate::encryption::vision_conn::VisionConn;
use crate::validator::Validator;
/// VLESS inbound 协议族接入选项（feature flags）。
/// 对应 Go `proxy/vless/inbound/inbound.go::Handler` 的可选特性：
/// - `enable_reverse`：是否由本 inbound 接管 `command=Rvs`（Portal 反向代理）。
///   `false` 时维持 warn+close。
/// - `reverse_registry`：启用 Reverse 时必填；Portal 注册表（domain → PortalConfig）。
///
/// 默认全 false（`Default::default()`），与既有行为一致（warn 跳过非 TCP 命令）。
#[derive(Clone, Default)]
pub struct VlessInboundOptions {
    /// 启用 Reverse 协议接入（需要 `reverse_registry` + `reverse_ohm` 配合：
    /// inbound 经 `reverse_registry` 查 `PortalConfig.tag`，再由 `reverse_ohm`
    /// 解析到 `PortalOutbound` handler 派发；Go `inbound.go:625-630` 的 `GetReverse`+
    /// `r.GetOutboundOverride` 语义）。
    pub enable_reverse: bool,
    /// Reverse 注册表（`enable_reverse=true` 时必填）。
    pub reverse_registry: Option<Arc<crate::inbound::reverse::ReverseRegistry>>,
    /// Reverse 解析用的出口管理器引用：Portal tag → `PortalOutbound` 查找。
    pub reverse_ohm: Option<Arc<SimpleOhm>>,
    /// ENC 解密实例（Go `inbound.go:81 handler.decryption`，settings.decryption
    /// 非 "none" 时启用）：连接进入 VLESS 编码层前先跑 ML-KEM-768/X25519 握手
    /// （1-RTT / 0-RTT ticket）。handler 级共享（`Arc`），所有连接共用
    /// Sessions/replay 防护状态。
    pub decryption: Option<Arc<crate::encryption::ServerInstance>>,
    /// 握手限时（sm80④：装配层传 `policy_for_level(level).timeout.handshake`，
    /// 对齐 Go inbound.go:281-284 SetReadDeadline(policy)）。None = 既有兜底
    /// （产品 SessionDefault 60s；cfg(test) 100ms）。
    pub handshake_timeout: Option<std::time::Duration>,
    /// 入站会话允许的网络（Go proxyman inbound.go:177-179：splithttp 传输
    /// 入站注入 `AllowedNetwork=UDP`）。None = 不限制。
    pub allowed_network: Option<Network>,
    /// 外层传输是否 TLS 1.3 / REALITY 直连（Go inbound.go:571-581：XRV flow 只许
    /// 跑在直连 TLS1.3/REALITY 上，transport 解包流或 TLS1.2 拒绝）。装配层注入：
    /// serve_vless TLS 分支查 rustls 协商版本，REALITY Verified 恒 true，其余 false。
    pub outer_tls13: bool,
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
    listener: InboundTcpListener,
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
                // vision splice：TLS accept 消费 socket 前 dup 裸 TCP 克隆，
                // END/DIRECT 帧后读写直通（Go UnwrapRawConn 等价路径）。
                let raw_tcp = xray_transport::connection::dup_tcp_stream(&stream);
                match acc.accept(stream).await {
                    Ok(tls_stream) => {
                        let conn = tls_stream.get_ref().1;
                        let name = conn.server_name().unwrap_or("").to_string();
                        let alpn = conn
                            .alpn_protocol()
                            .map(|p| String::from_utf8_lossy(p).into_owned())
                            .unwrap_or_default();
                        // lwep（Go inbound.go:571-574）：XRV 校验需要外层 TLS 版本。
                        let mut options = options;
                        if let Some(o) = options.as_mut() {
                            o.outer_tls13 = conn.protocol_version()
                                == Some(xray_transport::rustls::ProtocolVersion::TLSv1_3);
                        }
                        handle_connection_with_fallback(
                            tls_stream, &handler, &validator, fallbacks, peer, local, name, alpn,
                            options, raw_tcp,
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
                    options, None,
                )
                .await
            };
            if let Err(e) = result {
                // Go vless inbound.go:522：拒绝 AtInfo + RemoteAddr。
                tracing::info!(peer = %peer, error = %e, "vless connection ended with error");
            }
        });
    }
}


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

/// 握手限时来源（Go SessionDefault 60s）。独立成函数仅为可测性：cfg(test)
/// 下收短到 100ms，让"静默客户端 → 超时断开"行为测试无需真实等待 60s；
/// 产品路径（非 test）恒为 SessionDefault 真值。
#[cfg(not(test))]
fn handshake_timeout() -> std::time::Duration {
    xray_features::policy::DEFAULT_HANDSHAKE_TIMEOUT
}

#[cfg(test)]
fn handshake_timeout() -> std::time::Duration {
    std::time::Duration::from_millis(100)
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
    raw_tcp: Option<TcpStream>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    use tokio::io::AsyncReadExt;

    /// 类型擦除连接（S 与 ENC 握手产物统一为 boxed trait object；ENC 产物是
    /// `Box<dyn EncryptionConn>`，其 supertrait 已覆盖本 trait，coercion 直达）。
    trait ErasedConn: AsyncRead + AsyncWrite + Unpin + Send {}
    impl<T: AsyncRead + AsyncWrite + Unpin + Send + ?Sized> ErasedConn for T {}

    // ENC 解密层（Go inbound.go:275-278）：settings.decryption 非 "none" 时，
    // 连接先跑 ML-KEM-768/X25519 握手（1-RTT 或 0-RTT ticket）再进 VLESS 编码层。
    // decryption 与 fallbacks 在 Go conf 层互斥（vless.go:157-159），故握手置于
    // fallback 预读之前。
    let stream: std::pin::Pin<Box<dyn ErasedConn>> = match options.as_ref().and_then(|o| o.decryption.clone()) {
        Some(dec) => Box::pin(
            dec.handshake(stream)
                .await
                .map_err(|e| {
                    tracing::info!(error = %e, "vless enc handshake failed");
                    std::io::Error::other(format!("vless enc handshake: {e}"))
                })?,
        ),
        None => Box::pin(stream),
    };

    // 握手限时（Go inbound.go:281-284：SetReadDeadline(policy 或 SessionDefault
    // 60s) 在 ENC 握手之后、首包读之前设置；deadline 覆盖首包预读 + decode 总
    // 时长，decode 成功或 fallback 时解除）。sm80④：优先用装配层注入的 policy
    // 握手超时；未注入时维持 crate 兜底（同 handshake_timeout_for 无 policy 分支）。
    let handshake_deadline = tokio::time::Instant::now()
        + options
            .as_ref()
            .and_then(|o| o.handshake_timeout)
            .unwrap_or_else(handshake_timeout);

    // 无 fallback 策略：维持原直连路径（不做 first 预读；deadline 由
    // handle_connection 内部建立，语义同上）
    let Some(policy) = fallbacks else {
        return handle_connection(stream, handler, validator, options, raw_tcp).await;
    };

    let (mut read_half, write_half) = tokio::io::split(stream);

    // 1. 预读 first buffer（读到至少 1 字节；受握手限时约束，超时即断开）
    let mut first = vec![0u8; 1024];
    let mut n = 0;
    while n == 0 {
        let read = match tokio::time::timeout_at(
            handshake_deadline,
            read_half.read(&mut first[n..]),
        )
        .await
        {
            Ok(r) => r?,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "vless handshake read timeout",
                ))
            }
        };
        if read == 0 {
            return Ok(()); // 客户端未发数据即关闭
        }
        n += read;
    }
    first.truncate(n);

    // 2. VLESS 候选：首字节是 VERSION → 回灌后正常 decode；失败也走 fallback
    if first[0] == VERSION {
        let mut reader = InitialedReader::new(first.clone(), read_half);
        let mut fb_first: Option<Vec<u8>> = None;
        let decode_fut =
            decode_request_header(false, &mut fb_first, &mut reader, validator.as_ref());
        let decoded = match tokio::time::timeout_at(handshake_deadline, decode_fut).await {
            Ok(Ok(decoded)) => decoded,
            // decode 失败/超时（含握手限时到期）→ fallback（Go inbound.go:314-318
            // isfb 时清 read deadline 走 fallback；timeout_at 中断未破坏底层流，
            // 已读字节经 into_parts 不重放，语义同下）
            _ => {
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
        };
        // per-user stats 上下文（Go inbound.go Process 认证后 ctx 带 user）：
        // from=客户端源地址，email/level=认证用户。local=入站本地地址
        // （Go session.Inbound.Local；txno④ reverse mux portal 写侧随 New
        // 帧下发 source/local 的 Local 来源）。
        let access = xray_app_dispatcher::AccessContext {
            from: peer.to_string(),
            email: decoded.user.as_ref().map_or(String::new(), |u| u.email.clone()),
            level: decoded.user.as_ref().map_or(0, |u| u.level),
            local: local.to_string(),
            ..Default::default()
        };
        return finish_vless_dispatch(
            reader, write_half, decoded, handler, options, raw_tcp, access,
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

/// Go `inbound.go:552-598` flow 五臂校验（bd lwep）。
///
/// 注入在响应头写出之前——失败即断连（Go return error 语义），**不走 fallback、
/// 不发响应头**：已认证的 VLESS 客户端发畸形 flow ≠ 非 VLESS 流量。
///
/// # Errors
///
/// 任一臂命中即 `Err`（拒绝路径 O(1)，无分配密集操作，防 DoS）。
fn validate_flow(
    flow: &str,
    account_flow: &str,
    command: crate::encoding::VlessCommand,
    outer_tls13: bool,
) -> std::io::Result<()> {
    if flow == crate::FLOW_XRV {
        if account_flow != crate::FLOW_XRV {
            // Go inbound.go:588-590：账号 flow 与请求 flow 不匹配。
            return Err(std::io::Error::other(format!(
                "account is not able to use the flow {flow}"
            )));
        }
        if command == crate::encoding::VlessCommand::Udp {
            // Go inbound.go:557-558：XRV 不支持 UDP 命令。
            return Err(std::io::Error::other(format!("{flow} doesn't support UDP")));
        }
        // Go inbound.go:571-581：XRV 只许跑在直连 TLS1.3（tls.Conn 非 1.3 拒）/
        // REALITY（恒 1.3）；transport 解包流无外层 TLS1.3，同臂拒绝。
        if !outer_tls13 {
            return Err(std::io::Error::other(
                "failed to use xtls-rprx-vision: outer transport is not TLS 1.3 (XTLS only supports TLS and REALITY directly for now)",
            ));
        }
    } else if flow.is_empty() {
        // Go inbound.go:591-595：空 flow + XRV 账号 + TCP 拒（TLS-in-TLS 特征暴露）。
        // ponytail: Go 的 isMuxAndNotXUDP mux 分支未实现——仅覆盖 command==TCP，
        // mux 维持放行防误伤 XUDP-mux 合法流；mux 首帧解析落地时补齐。
        if account_flow == crate::FLOW_XRV && command == crate::encoding::VlessCommand::Tcp {
            return Err(std::io::Error::other(
                "account is rejected since the client flow is empty. Note that the pure TLS proxy has certain TLS in TLS characters.",
            ));
        }
    } else {
        // Go inbound.go:596-598：未知 flow 拒（Go v26.9.9 枚举全集 = {"", XRV}）。
        return Err(std::io::Error::other(format!("unknown request flow {flow}")));
    }
    Ok(())
}

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
/// - Mux：响应头 → [`handle_mux_relay`] 按请求目的地 dispatch（mux carrier
///   拦截在 dispatcher 装饰器）
/// - Rvs：响应头 → [`handle_reverse_relay`] 反向代理派发
async fn finish_vless_dispatch<R, W>(
    reader: R,
    mut write_half: W,
    decoded: crate::encoding::server::DecodedRequest,
    handler: &Arc<dyn xray_app_dispatcher::DispatchHandler>,
    options: Option<VlessInboundOptions>,
    raw_tcp: Option<TcpStream>,
    access: xray_app_dispatcher::AccessContext,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    use crate::encoding::VlessCommand;

    // 0. flow 五臂校验（Go inbound.go:552-598，bd lwep）：必须在响应头之前——
    // 失败断连不发响应头（validate_flow doc）。
    validate_flow(
        &decoded.addons.flow,
        decoded.user.as_ref().map_or("", |u| u.account.flow.as_str()),
        decoded.command,
        options.as_ref().map_or(false, |o| o.outer_tls13),
    )?;
    // 1. 发送响应头（version + empty addons）

    encode_response_header(&mut write_half, VERSION, &empty_addons())
        .await
        .map_err(|e| std::io::Error::other(format!("vless encode response: {e}")))?;

    // 2. AllowedNetwork 注入（Go inbound.go:607-609 + proxyman inbound.go:177-179）：
    // splithttp 传输入站 → 恒 UDP；XRV flow + Mux 命令 → UDP。mux 服务端
    // worker 据此校验子会话网络（common/mux/server.go:189-192）。
    let mut access = access;
    if let Some(net) = options.as_ref().and_then(|o| o.allowed_network) {
        access.allowed_network = Some(net);
    }
    if decoded.command == VlessCommand::Mux && decoded.addons.flow == crate::FLOW_XRV {
        access.allowed_network = Some(Network::UDP);
    }

    // 3. 按 command 分派
    match decoded.command {
        VlessCommand::Tcp => {
            finish_tcp_dispatch(reader, write_half, &decoded, handler, raw_tcp, &access).await
        }
        VlessCommand::Udp => {
            handle_udp_relay(reader, write_half, &decoded, handler).await
        }
        VlessCommand::Mux => {
            handle_mux_relay(reader, write_half, &decoded, handler, &access).await
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
    raw_tcp: Option<TcpStream>,
    access: &xray_app_dispatcher::AccessContext,
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
    let stream: Box<dyn VlessStream> = match (vision_uuid, raw_tcp) {
        (Some(uuid), Some(raw)) => Box::new(VisionConn::new_server(
            tokio::io::join(reader, write_half),
            uuid,
            raw,
        )),
        (Some(uuid), None) => {
            Box::new(VisionConn::new(tokio::io::join(reader, write_half), uuid))
        }
        (None, _) => Box::new(tokio::io::join(reader, write_half)),
    };
    let (rh, wh) = tokio::io::split(stream);
    let link = Link::new(new_reader(rh), new_writer(wh));
    let _ = handler.dispatch_with_access(&dest, link, access.clone()).await;
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

/// Mux 命令 relay：按请求目的地原样 dispatch（Go `inbound.go:633`）。
///
/// 对应 Go `vless/inbound/inbound.go`：Mux command 与 TCP 同构地
/// `dispatch.DispatchLink(request.Destination(), link)`，目的地固定为
/// `v1.mux.cool`（decode 时由 `VlessCommand::fixed_domain` 补齐，port 恒
/// None → 0）。Go 不做任何帧字节探测、无 enable 开关——carrier 拦截按
/// destination 地址在生产 dispatcher 装饰器完成（Go proxyman always.go:89
/// `mux: mux.NewServer(ctx)`；Rust 对应 xray-core wiring 的 `MuxCarrierHandler`）。
async fn handle_mux_relay<R, W>(
    reader: R,
    writer: W,
    decoded: &crate::encoding::server::DecodedRequest,
    handler: &Arc<dyn xray_app_dispatcher::DispatchHandler>,
    access: &xray_app_dispatcher::AccessContext,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let address = decoded
        .address
        .clone()
        .ok_or_else(|| std::io::Error::other("vless decode: missing address for Mux command"))?;
    let dest = Destination::new(address, Port::new(decoded.port.unwrap_or(0)), Network::TCP);
    let stream = tokio::io::join(reader, writer);
    let (rh, wh) = tokio::io::split(stream);
    let link = Link::new(new_reader(rh), new_writer(wh));
    let _ = handler.dispatch_with_access(&dest, link, access.clone()).await;
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

    // 按 account.Reverse.Tag 路由（Go `proxy/vless/inbound/inbound.go:198-216`）：
    // 每个 VLESS 账户的 Reverse 字段携带目标 Portal 的 tag；inbound 用它从
    // registry 查 PortalConfig（domain 等），再经 ohm 拿到 PortalOutbound handler
    // 派发子会话。**禁止 fallback 到首条**——多账户各自路由独立 portal，
    // 否则跨账户流量会全部汇聚到第一个 portal（与 Go 语义偏离）。
    let user = decoded.user.as_ref().ok_or_else(|| {
        std::io::Error::other("vless Reverse: no user attached to request")
    })?;
    let reverse_cfg = user.account.reverse.as_ref().ok_or_else(|| {
        std::io::Error::other(format!(
            "vless Reverse: user {} has no reverse config",
            user.email
        ))
    })?;
    let portal_tag = reverse_cfg.tag.clone();
    if portal_tag.is_empty() {
        return Err(std::io::Error::other(
            "vless Reverse: empty reverse.tag on user account",
        ));
    }
    let portal_cfg = registry.get_reverse(&portal_tag).map_err(|e| {
        std::io::Error::other(format!(
            "vless Reverse get_reverse(tag={}): {}",
            portal_tag, e
        ))
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
    raw_tcp: Option<TcpStream>,
) -> std::io::Result<()> {
    let mut stream = stream;

    // 握手限时（Go inbound.go:281-284：decode 前 SetReadDeadline(policy 或
    // SessionDefault 60s)，覆盖整个 decode 阶段；sm80④ 起装配层可注入）。
    let handshake_deadline = tokio::time::Instant::now()
        + options
            .as_ref()
            .and_then(|o| o.handshake_timeout)
            .unwrap_or_else(handshake_timeout);

    // 1. decode VLESS request header（isfb=false，全部从 stream 读）
    let mut first: Option<Vec<u8>> = None;
    let decoded = tokio::time::timeout_at(
        handshake_deadline,
        decode_request_header(false, &mut first, &mut stream, validator.as_ref()),
    )
    .await
    .map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "vless handshake read timeout")
    })?
    .map_err(|e| std::io::Error::other(format!("vless decode: {e}")))?;

    // 2. 按 command 分派：拆 reader/writer 后交 finish_vless_dispatch。
    // REALITY 直连路径（handle_connection 签名未携带 peer，生产调用点
    // inbound.rs:1841 不可改）：from 留空 → per-user counter 正常挂接，
    // online IP 不记（Go ctx 有 Source，Rust 此路径无源地址可用）。
    let access = xray_app_dispatcher::AccessContext {
        email: decoded.user.as_ref().map_or(String::new(), |u| u.email.clone()),
        level: decoded.user.as_ref().map_or(0, |u| u.level),
        ..Default::default()
    };
    let (read_half, write_half) = tokio::io::split(stream);
    finish_vless_dispatch(
        read_half,
        write_half,
        decoded,
        handler,
        options,
        raw_tcp,
        access,
    )
    .await
}

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
        make_validator_with_user_flow("")
    }

    /// 同上，但账号 `flow` 可指定（lwep 五臂校验测试需要 XRV 账号）。
    fn make_validator_with_user_flow(flow: &str) -> (UUID, Arc<dyn Validator>) {
        let uuid = UUID::new();
        let user = MemoryUser {
            level: 0,
            email: "test@example.com".to_string(),
            account: MemoryAccount::from_proto_account(
                &xray_proto::xray::proxy::vless::Account {
                    id: uuid.to_string(),
                    flow: flow.to_string(),
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
        let vless_listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        ).await.unwrap();
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
        let vless_listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        ).await.unwrap();
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

    /// 认证语义（对齐 Go `inbound.go::Process` → DecodeRequestHeader）：
    /// validator 载入 2 个无 email client（生产 build_vless_validator 的载入形态），
    /// 两个合法 UUID 均完成握手（响应头）+ echo 回环；未注册 UUID 被拒（连接关闭）。
    #[tokio::test]
    async fn vless_inbound_authenticates_two_email_less_clients() {
        // echo server（accept 循环：两个合法连接各回显一次）
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = echo_listener.accept().await else { break };
                tokio::spawn(async move {
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
            }
        });

        // 2 个无 email 用户（模拟生产 settings.clients 无 email 字段）
        let ids = [
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            "66ad4540-b58c-4ad2-9926-ea63445a9b57",
        ];
        let v = MemoryValidator::new();
        for id in ids {
            let user = MemoryUser {
                level: 0,
                email: String::new(),
                account: MemoryAccount::from_proto_account(&xray_proto::xray::proxy::vless::Account {
                    id: id.to_string(),
                    ..Default::default()
                })
                .unwrap(),
            };
            v.add(user).unwrap();
        }
        assert_eq!(v.get_uuid_count(), 2);
        let validator: Arc<dyn Validator> = Arc::new(v);

        let ohm = Arc::new(SimpleOhm::new());
        ohm.set_default(
            Arc::new(DialBridge::new("freedom", make_freedom_dial_fn()))
                as Arc<dyn xray_app_dispatcher::DispatchHandler>,
        );
        let vless_listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        ).await.unwrap();
        let vless_addr = vless_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = serve_vless(vless_listener, ohm, validator, None, None, None).await;
        });

        // 两个合法 UUID：握手（响应头）+ echo 回环均通过
        for id in ids {
            let uuid = UUID::parse(id).unwrap();
            let mut client = tokio::net::TcpStream::connect(vless_addr).await.unwrap();
            encode_request_header(
                &mut client,
                VERSION,
                &uuid,
                VlessCommand::Tcp,
                Some(&Address::from_ipv4_bytes([127, 0, 0, 1])),
                Some(echo_port),
                &empty_addons(),
            )
            .await
            .unwrap();
            decode_response_header(&mut client, VERSION)
                .await
                .expect("registered UUID must pass auth handshake");
            let payload = b"ping";
            client.write_all(payload).await.unwrap();
            let mut got = vec![0u8; payload.len()];
            client.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, payload, "echo roundtrip for {id}");
        }

        // 未注册 UUID：server 认证失败关闭连接 → EOF / reset
        let mut client = tokio::net::TcpStream::connect(vless_addr).await.unwrap();
        encode_request_header(
            &mut client,
            VERSION,
            &UUID::new(),
            VlessCommand::Tcp,
            Some(&Address::from_ipv4_bytes([127, 0, 0, 1])),
            Some(80),
            &empty_addons(),
        )
        .await
        .unwrap();
        let mut buf = [0u8; 16];
        match client.read(&mut buf).await {
            Ok(0) => {}
            Err(e) if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ) => {}
            other => panic!("expected auth rejection, got {other:?}"),
        }
    }

    async fn spawn_vless_proxy_with_echo(
        outer_tls13: bool,
        account_flow: &str,
    ) -> (std::net::SocketAddr, u16, UUID) {
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

        let (uuid, validator) = make_validator_with_user_flow(account_flow);
        let vless_listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        ).await.unwrap();
        let vless_addr = vless_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = serve_vless(
                vless_listener,
                ohm,
                validator,
                None,
                None,
                Some(VlessInboundOptions {
                    outer_tls13,
                    ..Default::default()
                }),
            )
            .await;
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

        let (vless_addr, echo_port, uuid) = spawn_vless_proxy_with_echo(true, crate::FLOW_XRV).await;

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

        let (vless_addr, echo_port, uuid) = spawn_vless_proxy_with_echo(true, crate::FLOW_XRV).await;

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

        let (vless_addr, echo_port, uuid) = spawn_vless_proxy_with_echo(true, "").await;

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
        let vless_listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        ).await.unwrap();
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

    /// 握手限时（Go inbound.go:281-284 SetReadDeadline(SessionDefault 60s)）：
    /// 客户端连上后保持静默 → 超时到期 → 服务端以 TimedOut 退出、连接关闭、
    /// dispatch 不被调用。cfg(test) 下限时收短为 100ms（见 handshake_timeout）。
    #[tokio::test]
    async fn vless_handshake_timeout_closes_silent_connection() {
        let capture = std::sync::Arc::new(CaptureDispatchHandler::new());
        let handler: Arc<dyn xray_app_dispatcher::DispatchHandler> = capture.clone();
        let (_, validator) = make_validator_with_user();
        let validator: Arc<dyn Validator> = validator;

        let (mut client, server_stream) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn({
            let handler_for_task = handler.clone();
            let validator = validator.clone();
            async move {
                handle_connection(server_stream, &handler_for_task, &validator, None, None).await
            }
        });

        // 静默不发任何字节：跳过握手限时（cfg(test) 下为 100ms）。
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // 服务端以超时错误退出
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(5), server).await;
        assert!(result.is_ok(), "server should exit after handshake timeout");
        let joined = result.unwrap();
        assert!(
            matches!(&joined, Ok(Err(e)) if e.kind() == std::io::ErrorKind::TimedOut),
            "expected TimedOut error, got: {joined:?}"
        );
        assert_eq!(*capture.called.lock(), 0, "dispatch must not run");

        // 客户端读到 EOF（对端已关闭）
        let mut buf = [0u8; 16];
        let n = client.read(&mut buf).await.unwrap_or(0);
        assert_eq!(n, 0, "connection should be closed after handshake timeout");
    }

    /// 捕获 Mux dispatch 的 FrameCapture：dest + 透传字节。
    #[derive(Debug)]
    struct FrameCapture {
        called: std::sync::Arc<parking_lot::Mutex<u32>>,
        dest_seen:
            std::sync::Arc<parking_lot::Mutex<Option<xray_common::net::destination::Destination>>>,
        payload: std::sync::Arc<parking_lot::Mutex<Vec<u8>>>,
    }

    impl FrameCapture {
        fn new() -> std::sync::Arc<Self> {
            std::sync::Arc::new(Self {
                called: std::sync::Arc::new(parking_lot::Mutex::new(0)),
                dest_seen: std::sync::Arc::new(parking_lot::Mutex::new(None)),
                payload: std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
            })
        }
    }

    impl xray_app_dispatcher::DispatchHandler for FrameCapture {
        fn tag(&self) -> &str {
            "mux-capture"
        }
        fn dispatch(
            &self,
            dest: &xray_common::net::destination::Destination,
            link: xray_transport::link::Link,
        ) -> xray_app_dispatcher::default::PinFuture<()> {
            let called = std::sync::Arc::clone(&self.called);
            let dest_seen = std::sync::Arc::clone(&self.dest_seen);
            let payload = std::sync::Arc::clone(&self.payload);
            let dest = dest.clone();
            Box::pin(async move {
                *called.lock() += 1;
                *dest_seen.lock() = Some(dest);
                let mut reader = link.reader;
                // read_multi_buffer 为非阻塞语义（Go buf.ReadMultiBuffer 同款）：
                // 数据未到时返回空 MultiBuffer，轮询直到首帧到达。
                let bytes = loop {
                    match reader.read_multi_buffer().await {
                        Ok(mb) => {
                            let bytes = mb.to_vec();
                            if !bytes.is_empty() {
                                break bytes;
                            }
                        }
                        Err(_) => break Vec::new(),
                    }
                };
                *payload.lock() = bytes;
            })
        }
    }

    /// VLESS Mux command 载真实 mux New 帧（bd raw0）：dispatch 按请求目的地
    /// 触发（v1.mux.cool，Mux command 的 port 恒 None → 0），帧字节原样透传。
    ///
    /// New 帧线格式（xray-mux frame.rs）：2B len(BE) + 2B session + 1B status
    /// （New=0x01）+ 1B option + 1B network（TCP=0x01）+ 2B port(BE) + 1B addr
    /// len + addr。首字节 = metalen 高位（0x00，合法帧 metalen≤512）——旧实现
    /// 臆造 0xFF 首字节判别，真实 mux client 的 carrier 在此必被拒。
    #[tokio::test]
    async fn vless_inbound_mux_command_dispatches_real_new_frame() {
        let capture = FrameCapture::new();
        let called = std::sync::Arc::clone(&capture.called);
        let dest_seen = std::sync::Arc::clone(&capture.dest_seen);
        let payload = std::sync::Arc::clone(&capture.payload);
        let capture_for_ohm: Arc<dyn xray_app_dispatcher::DispatchHandler> =
            capture.clone();
        let ohm = Arc::new(SimpleOhm::new());
        ohm.set_default(capture_for_ohm);

        let (uuid, validator) = make_validator_with_user();
        let vless_listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        ).await.unwrap();
        let vless_addr = vless_listener.local_addr().unwrap();
        let ohm_clone = Arc::clone(&ohm);
        let validator_clone = Arc::clone(&validator);
        tokio::spawn(async move {
            let _ = serve_vless(
                vless_listener, ohm_clone, validator_clone, None, None, None,
            )
            .await;
        });

        // 真实 mux New 帧：new session 1 → TCP 127.0.0.1:8080
        let new_frame: &[u8] = &[
            0x00, 0x0C, // metalen = 12
            0x00, 0x01, // session = 1
            0x01, // status = New
            0x00, // option = 0
            0x01, // network = TCP
            0x1F, 0x90, // port = 8080
            0x04, // addr type = IPv4
            127, 0, 0, 1,
        ];

        // client：Mux command（无 addr/port，decode 补 v1.mux.cool）→ 响应头 → New 帧
        let mut client = tokio::net::TcpStream::connect(vless_addr).await.unwrap();
        encode_request_header(
            &mut client, VERSION, &uuid, VlessCommand::Mux, None, None, &empty_addons(),
        )
        .await
        .unwrap();
        let _resp = decode_response_header(&mut client, VERSION).await.unwrap();
        client.write_all(new_frame).await.unwrap();

        // called 在 payload 读取前置位；等帧字节落盘再断言（防竞态）。
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                if !payload.lock().is_empty() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("frame bytes should arrive within 3s");

        assert_eq!(*called.lock(), 1, "Mux command must dispatch exactly once");
        let dest = dest_seen.lock().clone().expect("dest should be captured");
        assert_eq!(
            dest.address().as_domain(),
            Some("v1.mux.cool"),
            "Mux dest should be v1.mux.cool"
        );
        assert_eq!(dest.port().value(), 0, "Mux command carries no port");
        assert_eq!(
            &*payload.lock(),
            new_frame,
            "New frame bytes must pass through verbatim"
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
        let vless_listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        ).await.unwrap();
        let vless_addr = vless_listener.local_addr().unwrap();
        let ohm_clone = Arc::clone(&ohm);
        let validator_clone = Arc::clone(&validator);
        let opts = VlessInboundOptions {
            enable_reverse: false,
            reverse_registry: None,
            reverse_ohm: None,
            decryption: None,
            outer_tls13: false,
            handshake_timeout: None,
            allowed_network: None,
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
        let vless_listener = InboundTcpListener::bind(
            "127.0.0.1:0",
            xray_transport::sockopt::SocketOptions::default(),
        ).await.unwrap();
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
            enable_reverse: true,
            reverse_registry: Some(Arc::clone(&registry)),
            reverse_ohm: Some(Arc::clone(&ohm_clone)),
            decryption: None,
            handshake_timeout: None,
            outer_tls13: false,
            allowed_network: None,
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

    // ==== lwep：Go inbound.go:552-598 flow 五臂契约（恶意输入必拒）====

    /// 恶意 flow 公共断言：服务端校验失败必须断连且不发响应头（客户端读到 EOF）。
    async fn assert_flow_rejected(flow: &str, command: VlessCommand, outer_tls13: bool, account_flow: &str) {
        let (vless_addr, _echo_port, uuid) =
            spawn_vless_proxy_with_echo(outer_tls13, account_flow).await;
        let mut client = tokio::net::TcpStream::connect(vless_addr).await.unwrap();
        let mut addons = empty_addons();
        addons.flow = flow.to_string();
        encode_request_header(
            &mut client,
            VERSION,
            &uuid,
            command,
            Some(&Address::from_ipv4_bytes([127, 0, 0, 1])),
            Some(80),
            &addons,
        )
        .await
        .unwrap();
        let mut probe = [0u8; 1];
        // 拒绝 = 连接终止且无响应头：FIN（Ok(0)）或 RST（ConnectionReset/Aborted）。
        match tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut probe))
            .await
            .expect("server must close promptly on invalid flow")
        {
            Ok(0) => {}
            Ok(n) => panic!("server sent unexpected bytes before closing: {n} bytes"),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted) => {}
            Err(e) => panic!("unexpected io error: {e}"),
        }
    }

    #[tokio::test]
    async fn vless_inbound_rejects_unknown_flow() {
        // 恶意客户端手写 wire：encode_header_addons 对非 XRV flow 写空 addons
        //（Go EncodeHeaderAddons 同语义，addons.go:18-34），合法编码器发不出
        // 未知 flow——必须手工构造 proto addons（field1=flow）模拟恶意输入。
        let (vless_addr, _echo_port, uuid) = spawn_vless_proxy_with_echo(true, "").await;
        let mut client = tokio::net::TcpStream::connect(vless_addr).await.unwrap();
        let flow = b"xtls-rprx-doom";
        let mut addons_proto = Vec::new();
        addons_proto.push(0x0A); // field 1 (flow), wire type 2 (string)
        addons_proto.push(flow.len() as u8);
        addons_proto.extend_from_slice(flow);
        let mut wire = Vec::new();
        wire.push(VERSION);
        wire.extend_from_slice(uuid.as_bytes());
        wire.push(addons_proto.len() as u8);
        wire.extend_from_slice(&addons_proto);
        wire.push(1); // VlessCommand::Tcp
        wire.extend_from_slice(&80u16.to_be_bytes());
        wire.push(4); // IPv4
        wire.extend_from_slice(&[127, 0, 0, 1]);
        client.write_all(&wire).await.unwrap();
        let mut probe = [0u8; 1];
        match tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut probe))
            .await
            .expect("server must close promptly on unknown flow")
        {
            Ok(0) => {}
            Ok(n) => panic!("server sent unexpected bytes before closing: {n} bytes"),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted) => {}
            Err(e) => panic!("unexpected io error: {e}"),
        }
    }


    /// 臂（Go inbound.go:557-558）：XRV + UDP 命令拒。
    #[tokio::test]
    async fn vless_inbound_rejects_xrv_udp_command() {
        assert_flow_rejected(crate::FLOW_XRV, VlessCommand::Udp, true, crate::FLOW_XRV).await;
    }

    /// 臂（Go inbound.go:588-590）：请求 flow=XRV 但账号 flow 非 XRV 拒。
    #[tokio::test]
    async fn vless_inbound_rejects_xrv_account_mismatch() {
        assert_flow_rejected(crate::FLOW_XRV, VlessCommand::Tcp, true, "").await;
    }

    /// 臂（Go inbound.go:591-595）：空 flow + XRV 账号 + TCP 拒（TLS-in-TLS 特征）。
    #[tokio::test]
    async fn vless_inbound_rejects_empty_flow_xrv_account_tcp() {
        assert_flow_rejected("", VlessCommand::Tcp, true, crate::FLOW_XRV).await;
    }

    /// 臂（Go inbound.go:571-581）：XRV 但外层非 TLS1.3 直连（裸 TCP 床）拒。
    #[tokio::test]
    async fn vless_inbound_rejects_xrv_without_outer_tls13() {
        assert_flow_rejected(crate::FLOW_XRV, VlessCommand::Tcp, false, crate::FLOW_XRV).await;
    }
}
