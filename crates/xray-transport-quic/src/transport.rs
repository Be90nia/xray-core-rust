//! QUIC transport: quinn-based bi-stream tunnel.
//!
//! 对应 Go `transport/internet/quic/dialer.go` + `transport/internet/quic/hub.go`。
//!
//! ## 拨号流程
//!
//! 1. `xray_tls::client_config::build_client_config` 构建客户端 rustls config
//! 2. `quinn::crypto::rustls::QuicClientConfig::try_from` 转为 QUIC 客户端配置
//! 3. `quinn::Endpoint::client("0.0.0.0:0")` 绑定临时 UDP socket
//! 4. `endpoint.connect_with(cfg, socket_addr, server_name)` 拨号
//! 5. `connection.open_bi()` 打开双向 stream
//! 6. `tokio::io::duplex(64*1024)` 桥接 (SendStream, RecvStream) ↔ DuplexConn
//!
//! ## 监听流程
//!
//! 1. `xray_tls::server_config::build_server_config` 构建服务端 rustls config
//! 2. `quinn::Endpoint::server(server_config, addr)` 绑定 UDP socket
//! 3. spawn accept loop：每个 QUIC 连接 → 内层 accept_bi loop → handler
//!
//! ## DNS
//!
//! quinn 需要 `SocketAddr`（不做 DNS）；若 dest 是域名，用 `tokio::net::lookup_host` 解析。

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use xray_common::net::destination::Destination;
use xray_transport::{
    connection::Connection,
    dialer::StreamSettings,
    handshake_gate::HandshakeGate,
    listener_registry::{ConnHandler, TransportListener},
    sockopt::SocketOptions,
};

/// QUIC 应用层握手窗（rd8yj①）：`incoming.await`（quinn 握手）超过此窗未完成即
/// 放弃该连接。quinn 侧无独立握手超时——`max_idle_timeout`（本 crate 缺省 300s，
/// 见 config.rs）只对空闲期生效，攻击者持续发包即可无限续命，必须在应用层补闸。
///
/// 取 8s = Go 侧唯一显式 QUIC 握手窗（26.10.17 `app/dns/nameserver_quic.go:27`
/// `const handshakeTimeout = time.Second * 8`，喂 quic-go `HandshakeIdleTimeout`）；
/// TCP-TLS 族的 4s（`tls_handshake_gate::TLS_HANDSHAKE_TIMEOUT`）刻意不沿用：
/// QUIC Initial 走 UDP 往返且需 PTO 重传容忍，Go QUIC 族实取 8s。
pub const QUIC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);

/// 主动拨号 QUIC 连接。对应 Go `quic::Dial`。
///
/// `settings.security` 必须为 `"tls"`（QUIC 强制 TLS）；否则返回 `InvalidInput`。
pub async fn dial(
    dest: &Destination,
    settings: &StreamSettings,
    sockopt: &SocketOptions,
) -> io::Result<Box<dyn Connection>> {
    // 1. TLS client config（QUIC 强制 TLS，无 None 兜底）。
    let sni = dest.address().to_string();
    let tls_cfg = xray_tls::client_config::build_client_config(
        &settings.security,
        settings.security_json.as_ref(),
        &sni,
    )?
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUIC requires security=tls (got none/unsupported)",
        )
    })?;

    // fhsf：拨号外层 timeout 包装。quinn connect 内部超时仅握手阶段；DNS 解析 hang /
    // 黑洞下 `connect_with(...).await` 永不返回——必须外层 tokio::time::timeout 兜底。
    // 对齐 hysteria crate QuinnHysteriaTransport::dial_and_authenticate（同样包装）。
    let dial_timeout = std::time::Duration::from_secs(16);
    let addr_str = format!("{}:{}", dest.address(), dest.port().value());
    let socket_addr = tokio::time::timeout(dial_timeout, tokio::net::lookup_host(&addr_str))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("quic DNS lookup timeout for {addr_str}"),
            )
        })?
        .map_err(|e| io::Error::other(format!("quic DNS resolution: {e}")))?
        .next()
        .ok_or_else(|| {
            io::Error::other(format!("DNS resolution returned no addr for {addr_str}"))
        })?;

    // 3. QUIC 特有配置（congestion 等）。
    let qc = crate::config::QuicConfig::from_json(settings.transport_json.as_ref())?;
    // 4. rustls ClientConfig → quinn ClientConfig（+ congestion control TransportConfig）。
    let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from((*tls_cfg).clone())
        .map_err(|e| io::Error::other(format!("rustls→quic client: {e}")))?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client));
    client_config.transport_config(Arc::new(qc.build_transport_config()));

    // 4. Endpoint + connect（外层 timeout 覆盖 DNS+握手+鉴权整段）。
    // GSO 默认开（quinn-udp 构造期探测 UDP_SEGMENT，内核不支持自动回退单段）；
    // disableGSO=true 时经 NoGsoSocket 钳单段（见 udp_gso 模块 doc）。
    // bd jzwib：endpoint 按 (GSO, 缓冲) 进程内复用——每连接新 bind 会让 socket 账面
    // 严重低估真实内核占用（见 [`shared_client_endpoint`]）。
    let endpoint = shared_client_endpoint(qc.disable_gso, sockopt)
        .map_err(|e| io::Error::other(format!("quinn bind: {e}")))?;
    let connecting = endpoint
        .connect_with(client_config, socket_addr, &sni)
        .map_err(|e| io::Error::other(format!("quinn connect initiate: {e}")))?;
    let conn = tokio::time::timeout(dial_timeout, connecting)
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("quic handshake timeout after {dial_timeout:?}"),
            )
        })?
        .map_err(|e| io::Error::other(format!("quinn handshake: {e}")))?;

    let local = endpoint.local_addr().ok();
    let remote = conn.remote_address();
    // endpoint 必须保持存活——否则连接立即关闭。放进桥接任务里持有。
    let (send, recv) = conn.open_bi().await.map_err(io_err)?;
    Ok(Box::new(QuicConn::new(send, recv, local, Some(remote), endpoint)))
}

/// 进程级客户端 QUIC endpoint 复用（bd jzwib）。
///
/// 原实现每条出站连接各自 `make_endpoint` 新 bind 一个 UDP socket：QUIC 系 socket 缺省
/// 抬到 8 MiB 内核缓冲（[`xray_transport::sockopt::bind_udp_endpoint`]，×2 内核记账
/// = 16 MiB/端点账面），而内存账本按「**QUIC 端点数**」入算 ⇒ 6 条并发就吃掉 96 MiB
/// 预算却只记 1 份（审计 2026-11-07 perf-memory N1）。
///
/// quinn `Endpoint` 天生承载多条连接（同 hysteria/TUIC 出站按配置复用的口径），故按
/// `(disableGSO, receiveBufferSize, sendBufferSize)` 复用同一 endpoint：
/// 每个 socket 配置最终只有 1 个 socket，账面「端点数」成为真实上界（只多记不少记）。
fn shared_client_endpoint(
    disable_gso: bool,
    sockopt: &SocketOptions,
) -> io::Result<quinn::Endpoint> {
    type Key = (bool, i32, i32);
    static ENDPOINTS: std::sync::LazyLock<
        parking_lot::Mutex<std::collections::HashMap<Key, quinn::Endpoint>>,
    > = std::sync::LazyLock::new(|| parking_lot::Mutex::new(std::collections::HashMap::new()));

    let key = (disable_gso, sockopt.receive_buffer_size, sockopt.send_buffer_size);
    let mut map = ENDPOINTS.lock();
    if let Some(ep) = map.get(&key) {
        return Ok(ep.clone());
    }
    let ep = crate::udp_gso::make_endpoint(
        None,
        std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
        disable_gso,
        sockopt,
    )?;
    map.insert(key, ep.clone());
    Ok(ep)
}

/// 监听 QUIC 入站连接。对应 Go `quic::Listen`。
///
/// accept loop：每个 QUIC 连接 → 内层 `accept_bi` loop → 每个新 bi-stream 调用 `handler`。
/// 这与 Go xray-core `hub.go` 一致：一个 QUIC 连接可承载多个 bi-stream。
pub async fn listen(
    addr: SocketAddr,
    settings: &StreamSettings,
    sockopt: &SocketOptions,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    let endpoint = make_server_endpoint(addr, settings, sockopt)?;
    let local = endpoint.local_addr()?;

    // endpoint clone 给 listener 句柄；本体 move 进 accept task。
    let listener_endpoint = endpoint.clone();
    // rd8yj①：每监听握手并发闸 + 应用层握手窗（见 [`spawn_quic_accept`]）。
    // 闸容量 = MAX_INFLIGHT_HANDSHAKES，预算依据见其常量注释（handshake_gate 家族口径）。
    let gate = HandshakeGate::new(xray_transport::handshake_gate::effective_inflight_limit());
    spawn_quic_accept(endpoint, gate, handler);

    Ok(Box::new(QuicListener { local, endpoint: listener_endpoint }))
}

/// 构建监听 endpoint（TLS + quicSettings transport config；`listen` 与测试共用）。
fn make_server_endpoint(
    addr: SocketAddr,
    settings: &StreamSettings,
    sockopt: &SocketOptions,
) -> io::Result<quinn::Endpoint> {
    let tls_cfg = xray_tls::server_config::build_server_config(
        &settings.security,
        settings.security_json.as_ref(),
    )?
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUIC server requires security=tls (got none/unsupported)",
        )
    })?;

    // QUIC 特有配置（congestion 等）。
    let qc = crate::config::QuicConfig::from_json(settings.transport_json.as_ref())?;
    let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from((*tls_cfg).clone())
        .map_err(|e| io::Error::other(format!("rustls→quic server: {e}")))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
    server_config.transport_config(Arc::new(qc.build_transport_config()));
    // 同 dial：GSO 默认开，disableGSO=true 走 NoGsoSocket 单段路径。
    crate::udp_gso::make_endpoint(Some(server_config), addr, qc.disable_gso, sockopt)
        .map_err(|e| io::Error::other(format!("quinn bind: {e}")))
}

/// accept 泵 + 每连接握手闸（rd8yj①）。
///
/// - **并发闸**：满即 fail-fast 丢弃该 Incoming（**不排队**——排队 = 内存与请求数
///   同涨，`handshake_gate` 家族纪律）；许可决策在 accept 循环同步完成，超额连接 不 spawn
///   任务。QUIC 侧静默丢弃 = 对端收不到回应。
/// - **握手窗**：per-conn 以 [`QUIC_HANDSHAKE_TIMEOUT`] 罩 `incoming.await`， 超时放弃——「发
///   Initial 不完成握手」的连接最多占在途名额一个窗的时间。
fn spawn_quic_accept(endpoint: quinn::Endpoint, gate: Arc<HandshakeGate>, handler: ConnHandler) {
    #[allow(
        clippy::disallowed_methods,
        reason = "②豁免（bd kwevg · §3.5.6）：数据面连接任务（QUIC accept 泵）；任务必须长于组件（进程级/数据面逐包泵/公开契约外返），不迁托管口"
    )]
    tokio::spawn(async move {
        loop {
            let incoming = match endpoint.accept().await {
                Some(c) => c,
                None => break, // endpoint closed
            };
            let Some(permit) = gate.try_admit() else {
                gate.record_reject("quic");
                drop(incoming);
                continue;
            };
            let g = Arc::clone(&gate);
            let h = handler.clone();
            #[allow(
                clippy::disallowed_methods,
                reason = "②豁免（bd kwevg · §3.5.6）：数据面连接任务（每连接握手+stream 泵）；任务必须长于组件（进程级/数据面逐包泵/公开契约外返），不迁托管口"
            )]
            tokio::spawn(async move {
                let conn = match tokio::time::timeout(QUIC_HANDSHAKE_TIMEOUT, incoming).await {
                    Ok(Ok(c)) => c,
                    Ok(Err(_)) => return, // 握手协议层失败（对端放弃/参数错）
                    Err(_) => {
                        // rd8yj①：握手窗超时——Incoming 被 drop 即静默丢弃，
                        // 许可随 task 结束归还（行为断言见 tests）。
                        g.record_failure("quic", &"handshake window timeout");
                        return;
                    },
                };
                drop(permit); // 握手完成即让位；已建连接的活性归 idle 超时管
                let local = conn.local_ip().map(|ip| SocketAddr::new(ip, 0));
                let remote = conn.remote_address();
                // 每个 QUIC 连接上接受任意数量的 bi-stream，每个 stream 都作为独立 Connection
                // 上报。
                while let Ok((send, recv)) = conn.accept_bi().await {
                    let c = QuicConn::new(send, recv, local, Some(remote), ());
                    h(Box::new(c));
                }
            });
        }
    });
}

/// quinn (SendStream, RecvStream) + tokio DuplexStream 桥接的 Connection。
///
/// 设计与 [`xray_transport_grpc::transport::DuplexConn`] 一致：
/// - 写方向：DuplexStream → quinn SendStream
/// - 读方向：quinn RecvStream → DuplexStream
/// - `extra` 持有 endpoint（dial 路径）或 `()`（listen 路径，endpoint 在外层 task 持有）
struct QuicConn<E> {
    inner: tokio::io::DuplexStream,
    _extra: E,
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
}

impl<E: Send + Sync + Unpin> QuicConn<E> {
    /// 构造桥接：spawn 双向 copy task 把 quinn (send, recv) ↔ DuplexStream。
    fn new(
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        local: Option<SocketAddr>,
        remote: Option<SocketAddr>,
        extra: E,
    ) -> Self {
        let (client, server) = tokio::io::duplex(64 * 1024);
        #[allow(
            clippy::disallowed_methods,
            reason = "②豁免（bd kwevg · §3.5.6）：数据面桥接 copy 泵（quinn↔DuplexStream）；任务必须长于组件（进程级/数据面逐包泵/公开契约外返），不迁托管口"
        )]
        tokio::spawn(async move {
            let (mut rd, mut wr) = tokio::io::split(server);
            // s: 读 duplex-write 半边 → 写到 quinn send；EOF 时 finish() 半关闭
            let s = async {
                // read_buf 直写 BytesMut spare capacity（免中间栈 buffer），freeze 后
                // owned Bytes move 给 quinn——原 `vec![0u8; 32K] + copy_from_slice`
                // 的第二次 32KB memcpy 消除。reserve 保证每轮读预算（spare 为 0 时
                // read_buf 返回 Ok(0) 会被误判 EOF）。
                // 不走 xray_buf 池（bd 0ux3t C19 判定）：`write_chunk` 把块所有权交给
                // quinn（重传要持有），池无 hook 收回；池化 = 每 chunk 多一次 32KB
                // memcpy 换一次更便宜的 malloc，负优化。
                let mut buf = BytesMut::with_capacity(32 * 1024);
                loop {
                    buf.reserve(32 * 1024);
                    let n = rd.read_buf(&mut buf).await?;
                    if n == 0 {
                        let _ = send.finish();
                        break;
                    }
                    send.write_chunk(buf.split().freeze()).await.map_err(io_err)?;
                }
                Ok::<_, io::Error>(())
            };
            // r: 读 quinn recv → 写到 duplex-read 半边
            let r = async {
                // 池化读 scratch（bd 0ux3t C19）：下行 `write_all` 拷贝，scratch 不
                // 逃逸 ⇒ 泵结束时 `release` 回池（归零点在本块末）。
                let mut buf = xray_buf::alloc::alloc(32 * 1024);
                buf.resize(32 * 1024, 0);
                let res = async {
                    loop {
                        match recv.read(&mut buf).await {
                            Ok(Some(n)) => wr.write_all(&buf[..n]).await?,
                            Ok(None) => break,
                            Err(e) => return Err(io_err(e)),
                        }
                    }
                    Ok::<_, io::Error>(())
                }
                .await;
                xray_buf::alloc::release(buf);
                res
            };
            let _ = tokio::try_join!(s, r);
        });
        Self { inner: client, _extra: extra, local, remote }
    }
}

impl<E: Send + Sync + Unpin> AsyncRead for QuicConn<E> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<E: Send + Sync + Unpin> AsyncWrite for QuicConn<E> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<E: Send + Sync + Unpin> Connection for QuicConn<E> {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.remote)
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.local)
    }
}

/// QUIC listener 句柄。endpoint clone 与 accept task 共享（quinn Endpoint 内部 Arc）。
struct QuicListener {
    local: SocketAddr,
    endpoint: quinn::Endpoint,
}

impl TransportListener for QuicListener {
    fn close(&self) -> io::Result<()> {
        crate::LOG.info(format!("QUIC listener close addr={}", self.local));
        // 立即关闭 QUIC 栈：accept 循环收到 None 退出，活跃连接全部断开，
        // UDP socket 释放（对齐 Go hysteria/hub.go Close=listener+transport+pktConn）。
        self.endpoint.close(quinn::VarInt::from_u32(0), b"listener closed");
        Ok(())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

fn io_err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ensure_provider() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// bd jzwib 契约：同 `(GSO, 收/发缓冲)` 配置的客户端 endpoint 必须**复用同一个
    /// UDP socket**。每连接新 bind 会让内存账本（按 QUIC 端点数 × 16MiB 入算）严重
    /// 低估真实内核占用（6 条并发 = 96MiB 却只记 1 份）。
    #[tokio::test]
    async fn client_endpoint_is_shared_per_config() {
        let a = shared_client_endpoint(false, &SocketOptions::default()).unwrap();
        let b = shared_client_endpoint(false, &SocketOptions::default()).unwrap();
        assert_eq!(
            a.local_addr().unwrap(),
            b.local_addr().unwrap(),
            "同配置两次取 endpoint 必须是同一 socket（复用）"
        );

        // 缓冲配置不同的 key 各自独立（不能把语义不同的 socket 混用）。
        let c = shared_client_endpoint(
            false,
            &SocketOptions { send_buffer_size: 1 << 20, ..Default::default() },
        )
        .unwrap();
        assert_ne!(a.local_addr().unwrap(), c.local_addr().unwrap());
    }

    /// 服务端 StreamSettings：显式配一张自签证书。
    ///
    /// 波2 起 `xray_tls::server_config::build_server_config` 对齐 Go 语义——
    /// 未配证书**不再现生成 rcgen 自签**，握手直接报
    /// `no server certificate chain resolved`（Go: `tls: no certificates configured`）。
    /// 因此 QUIC 服务端测试必须自带证书，否则测的是「缺证书」而不是传输本身。
    fn tls_server_settings() -> StreamSettings {
        let (cert, key) = xray_tls::certificate::generate_self_signed_cert(&["127.0.0.1"])
            .expect("self-signed cert");
        StreamSettings {
            protocol: "quic".into(),
            security: "tls".into(),
            security_json: Some(serde_json::json!({
                "certificates": [{ "certificate": cert, "key": key }]
            })),
            ..Default::default()
        }
    }

    /// quinn 客户端连指定地址（allowInsecure 跳过自签验证，1s idle timeout 快速失败）。
    #[allow(unused_variables)] // addr 保留供未来 allowInsecure 分支判定
    fn quinn_client_connect(addr: SocketAddr) -> quinn::Endpoint {
        let client_tls = xray_tls::client_config::build_client_config(
            "tls",
            Some(&serde_json::json!({"allowInsecure": true})),
            "127.0.0.1",
        )
        .unwrap()
        .expect("client tls config");
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(1_000))));
        let mut quic_cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
        ));
        quic_cfg.transport_config(Arc::new(transport));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quic_cfg);
        endpoint
    }

    /// close() 必须真实关闭 endpoint（票 4kjs 回归锚）：close 前可连通，close 后
    /// 新 QUIC 握手失败。修复前 close() 仅日志，endpoint 永远存活，connect 一直成功。
    #[tokio::test]
    async fn close_rejects_new_connections() {
        ensure_provider();
        let settings = tls_server_settings();
        let handler: ConnHandler = Arc::new(|_| {});
        let listener =
            listen("127.0.0.1:0".parse().unwrap(), &settings, &Default::default(), handler)
                .await
                .expect("listen");
        let addr = listener.local_addr().unwrap();

        // close 前连通（证明服务活着，排除假阳性）。
        let ep = quinn_client_connect(addr);
        let pre = ep.connect(addr, "127.0.0.1").unwrap().await;
        assert!(pre.is_ok(), "pre-close connect should succeed: {:?}", pre.err());

        listener.close().unwrap();

        // close 后新握手必须失败（server 不再回应 Initial）。
        let post = ep.connect(addr, "127.0.0.1").unwrap().await;
        assert!(post.is_err(), "post-close connect must fail");
        ep.close(0u32.into(), b"test done");
    }

    /// echo 回显 handler：读到什么写回什么，EOF/错误即退。
    fn echo_handler() -> ConnHandler {
        Arc::new(|conn| {
            #[allow(clippy::disallowed_methods, reason = "测试：echo handler 任务")]
            tokio::spawn(async move {
                let mut conn = conn;
                let mut buf = vec![0u8; 16 * 1024];
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
        })
    }

    /// GSO 开关 × 分段边界端到端：listen 全链路消费 quicSettings.disableGSO
    /// （JSON → QuicConfig → make_endpoint 接线证明），客户端发 128 KiB
    /// （>64 段 × ~1452B，quinn 多段 Transmit / UDP_SEGMENT 内核分段的
    /// 边界场景，sing-box #4222 类错分段在此暴露）回环 echo 校验字节完整。
    async fn echo_roundtrip_with(disable_gso: bool) {
        ensure_provider();
        let mut settings = tls_server_settings();
        settings.transport_json = Some(serde_json::json!({ "disableGSO": disable_gso }));
        let listener =
            listen("127.0.0.1:0".parse().unwrap(), &settings, &Default::default(), echo_handler())
                .await
                .expect("listen");
        let addr = listener.local_addr().unwrap();

        let ep = quinn_client_connect(addr);
        let payload: Vec<u8> = (0..(128 * 1024)).map(|i| i as u8).collect();
        let work = async {
            let conn = ep.connect(addr, "127.0.0.1").unwrap().await.unwrap();
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            send.write_all(&payload).await.unwrap();
            send.finish().unwrap();
            let mut echoed = vec![0u8; payload.len()];
            recv.read_exact(&mut echoed).await.unwrap();
            echoed
        };
        let echoed = tokio::time::timeout(std::time::Duration::from_secs(10), work)
            .await
            .expect("echo roundtrip within 10s");
        assert_eq!(echoed, payload, "128 KiB echo must be byte-exact");
        ep.close(0u32.into(), b"test done");
    }

    /// 禁用 GSO（NoGsoSocket 单段路径）链路仍通、分段边界正确。
    #[tokio::test]
    async fn echo_roundtrip_gso_disabled() {
        echo_roundtrip_with(true).await;
    }

    /// 默认路径（Linux GSO 开，非 Linux 单段）回归保护：接线不得破坏现状。
    #[tokio::test]
    async fn echo_roundtrip_gso_default() {
        echo_roundtrip_with(false).await;
    }

    // ---- rd8yj①：握手并发闸 + 应用层握手窗 ----

    /// 永挂式证书验证器：进入 `verify_server_cert` 即挂起——模拟「Initial 合法发出
    /// （服务器接纳并回飞行包）、Finished 永不到达」的慢速/恶意客户端。真实 quinn
    /// 客户端路径，握手永远无法完成 ⇒ 服务器端唯一退路 = 应用层握手窗超时。
    ///
    /// trait 要 `Debug + Send + Sync`：entered 走 tokio oneshot，hold 用
    /// AtomicBool + sleep 自旋（礼貌驻留，测试收尾置位即退）。
    #[derive(Debug)]
    struct ParkedVerifier {
        entered: parking_lot::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: Arc<std::sync::atomic::AtomicBool>,
    }

    impl rustls::client::danger::ServerCertVerifier for ParkedVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            if let Some(entered) = self.entered.lock().take() {
                let _ = entered.send(());
            }
            while !self.release.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(rustls::Error::General("parked verifier released".into()))
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
            ]
        }
    }

    /// 测试收尾守卫：无论断言过红，Drop 都解除验证器自旋——否则 panic 路径下
    /// quinn 驱动线程永远卡在自旋里，测试进程 runtime drop 卡死。
    struct ReleaseGuard(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for ReleaseGuard {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// 行为断言（rd8yj①）：握手在途名额必须在握手窗超时后**真实释放**——
    /// 许可被占满整窗、窗后回到可再取（不是只看日志）。
    ///
    /// 客户端走真实 quinn 路径 + 永挂验证器 ⇒ 服务器接纳后握手永远无法完成，
    /// 名额唯一的让出途径就是 [`QUIC_HANDSHAKE_TIMEOUT`] 超时放弃该连接。
    /// 把窗改大（如 60s）/删掉超时 ⇒ 释放探针在 20s 截止后必红。
    ///
    /// 结构纪律：**先清理、后断言**——panic 只允许发生在解除验证器自旋并关闭
    /// endpoint 之后（否则 panic 路径下阻塞式 poll 卡死 worker，进程挂死）。
    // worker 4 起：永挂验证器自旋会占死一个 worker（阻塞式 poll 内 spin），
    // 剩余 worker 供服务端驱动/accept 泵/echo 客户端并行使用。
    // 测试耗时断言用 std 即时读数（墙钟差），非生产时钟取用（nn8os 2b 同款豁免）。
    #[allow(clippy::disallowed_methods, reason = "测试耗时断言配套，非生产时钟取用")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn handshake_gate_releases_quota_after_window_timeout() {
        ensure_provider();
        let endpoint = make_server_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            &tls_server_settings(),
            &Default::default(),
        )
        .expect("make server endpoint");
        let addr = endpoint.local_addr().unwrap();
        let keepalive = endpoint.clone(); // endpoint 本体 move 进 accept 泵，clone 保活
        let gate = HandshakeGate::new(1); // 容量 1：单名额可观测占用/释放
        spawn_quic_accept(endpoint, Arc::clone(&gate), echo_handler());

        // 永挂验证器 + 完成信号（entered ⇒ 服务器已接纳该连接并回过飞行包）。
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let _release_guard = ReleaseGuard(Arc::clone(&release)); // panic 安全收尾
        let mut client_tls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ParkedVerifier {
                entered: parking_lot::Mutex::new(Some(entered_tx)),
                release: Arc::clone(&release),
            }))
            .with_no_client_auth();
        // 服务端缺省 ALPN = ["h2","http/1.1"]（server_config parse_alpn 缺省）；
        // 不设 ALPN 会在证书验证之前就被 ALPN 协商拒掉，验证器永远到不了。
        client_tls.alpn_protocols = vec![b"h2".to_vec()];
        let quinn_client = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
        ));
        // 客户端 transport 用缺省（idle 30s > 窗 8s），排除 idle 抢先关连的假阳性。
        let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        ep.set_default_client_config(quinn_client);
        // 不 await Connecting：Initial 由 endpoint 驱动发出，握手卡死在验证器。
        let _connecting = ep.connect(addr, "localhost").unwrap();

        // 客户端收到服务器飞行包（= 验证器被唤起）⇒ 服务器侧接纳已发生、名额已被占。
        tokio::time::timeout(Duration::from_secs(15), entered_rx)
            .await
            .expect("verifier must be reached within 15s (stall not established)")
            .expect("entered channel");
        let admitted_at = std::time::Instant::now();

        // 释放观测窗口与生产窗解耦（固定 20s）：窗改大/删掉 ⇒ released_at = None。
        let mut released_at = None;
        while admitted_at.elapsed() < Duration::from_secs(20) {
            if gate.try_admit().is_some() {
                released_at = Some(std::time::Instant::now());
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // ---- 清理先行（此时不得有任何 panic）：解除自旋 + 关两端 endpoint ----
        release.store(true, std::sync::atomic::Ordering::SeqCst);
        drop(_connecting);
        tokio::time::sleep(Duration::from_millis(200)).await;
        ep.close(0u32.into(), b"test done");
        keepalive.close(0u32.into(), b"test done");

        // ---- 断言（全部在清理之后，panic 不再阻塞 runtime 收尾）----
        // 名额释放后的可复用性由既有 echo_roundtrip_* 测试（经 listen() 同一闸接线）
        // 覆盖；本测试只钉「释放确实发生 + 占满整窗」两个行为断言。
        let released_at = released_at
            .expect("握手窗超时后名额必须被释放（连接放弃、许可归还）——闸失效或窗被改大/删掉");
        let held_for = released_at.duration_since(admitted_at);
        assert!(
            held_for >= QUIC_HANDSHAKE_TIMEOUT - Duration::from_secs(1),
            "名额仅被占 {held_for:?}（窗 = {QUIC_HANDSHAKE_TIMEOUT:?}）——提前让位 = 闸未按窗工作"
        );
    }
}
