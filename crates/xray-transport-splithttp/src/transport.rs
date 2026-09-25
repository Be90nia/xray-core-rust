//! SplitHTTP transport 监听入口（生产 listener）。
//!
//! 对应 Go `transport/internet/splithttp/hub.go::ListenXH`（449-582 行）：
//! - **isH3 判定**（hub.go:469）：`tlsSettings.alpn == ["h3"]` → UDP + QUIC + h3 server
//! - **TCP**（hub.go:536-545）：accept → 可选 TLS（hub.go:553-556）/ REALITY（hub.go:558-560） →
//!   hyper auto（h1 + h2c，hub.go:565-567）→ [`crate::hub::handler::handle_request`]
//! - **unix**（hub.go:472-480 `port == 0` → `ListenUnix`）：不支持——Rust 生产入口
//!   `listen_splithttp` 只分 h3/TCP，`SocketAddr` 无法承载 unix 路径。
//!
//! Go 的 `requestHandler.ServeHTTP` 与传输无关（同一 handler 服务 h1/h2/h3 三路），
//! 本文件把 hub handler 接到 h3/TCP 两种监听形态上。

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use base64::Engine as _;
use bytes::{Buf as _, Bytes};
use http_body_util::BodyExt as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use xray_transport::{
    connection::Connection,
    dialer::StreamSettings,
    fallback::fallback_to_dest,
    listener_registry::{ConnHandler, TransportListener},
    sockopt::SocketOptions,
};

use crate::{
    config::Config,
    hub::{
        HubConnHandler, ServerConn, SessionMap,
        handler::{self, HandlerContext},
    },
};

/// h1 请求头读取超时。对应 Go hub.go:570 `ReadHeaderTimeout: time.Second * 4`。
const READ_HEADER_TIMEOUT: Duration = Duration::from_secs(4);

/// duplex bridge 缓冲。与 `hub::handler::DUPLEX_BUF` 对齐（64 KiB）。
const DUPLEX_BUF: usize = 64 * 1024;

/// SplitHTTP 监听入口（listener registry 注册的目标）。
///
/// 镜像 Go `ListenXH`：isH3（alpn==["h3"]）走 QUIC，其余走 TCP + TLS/REALITY 包装。
pub async fn listen_splithttp(
    addr: SocketAddr,
    settings: &StreamSettings,
    sockopt: &SocketOptions,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    let config =
        Arc::new(crate::register::parse_splithttp_config(settings.transport_json.as_ref())?);
    let tls_cfg = xray_tls::server_config::build_server_config(
        &settings.security,
        settings.security_json.as_ref(),
    )?;

    // isH3：Go hub.go:469 — `len(NextProtos) == 1 && NextProtos[0] == "h3"`。
    // REALITY 不进 H3（Go REALITY config 无 NextProtos，且 hub.go:558 只包装 tcp/unix
    // listener），故限定 security == "tls"。
    let is_h3 = settings.security == "tls"
        && tls_cfg
            .as_ref()
            .is_some_and(|c| c.alpn_protocols.len() == 1 && c.alpn_protocols[0] == b"h3");

    if is_h3 {
        let tls = tls_cfg.expect("is_h3 implies Some");
        listen_h3(addr, tls, &config, sockopt, handler).await
    } else {
        // Tcpmask（Go splithttp/hub.go:547-549：`!isH3 && TcpmaskManager != nil`
        // 才 WrapListener——H3/QUIC 分支不接 Tcpmask）。空 manager = 恒等。
        let tcpmask = Some(Arc::new(xray_transport::finalmask::build_tcpmask_manager_from_json(
            settings.finalmask_json.as_ref(),
        )?));
        listen_tcp(
            addr,
            &settings.security,
            tls_cfg,
            settings.security_json.as_ref(),
            &config,
            tcpmask,
            handler,
        )
        .await
    }
}

async fn listen_tcp(
    addr: SocketAddr,
    security: &str,
    tls_cfg: Option<Arc<rustls::ServerConfig>>,
    security_json: Option<&serde_json::Value>,
    config: &Arc<Config>,
    tcpmask: Option<Arc<xray_transport::finalmask::TcpmaskManager>>,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    let tcp = tokio::net::TcpListener::bind(addr).await?;
    let local = tcp.local_addr()?;
    // REALITY listener：Go hub.go:558-560 `goreality.NewListener`。
    let reality = reality_server_config(security, security_json)?;
    // bd frxi：配置启用探测时 spawn CCS 探测写 ProbeTable（Go tcp/hub.go:79
    // `go goreality.DetectPostHandshakeRecordsLens` 等价；Rust 侧 opt-in）。
    let reality_probe =
        reality.as_ref().filter(|rc| rc.max_useless_records.is_enabled()).map(|rc| {
            let table = xray_reality::probe::ProbeTable::new();
            xray_reality::probe::detect_max_useless_records(
                table.clone(),
                rc.fallback_dest.clone(),
                rc.server_names.clone(),
                "tcp".to_string(),
                rc.xver,
            );
            xray_reality::probe::detect_post_handshake_record_lens(
                table.clone(),
                rc.fallback_dest.clone(),
                rc.server_names.clone(),
                "tcp".to_string(),
                rc.xver,
            );
            tracing::info!(dest = %rc.fallback_dest, "reality maxUselessRecords probe started");
            Arc::new(xray_reality::server::ProbeContext {
                table,
                dest: rc.fallback_dest.clone(),
                fallback: rc.max_useless_records,
            })
        });
    let ctx = build_context(config, local, handler);
    tracing::info!(%local, "listening TCP for XHTTP");

    let accept_task = tokio::spawn(async move {
        loop {
            let (stream, peer) = match tcp.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let _ = stream.set_nodelay(true);
            // Tcpmask wrap（Go hub.go:546-549 WrapListener：mask 在 TLS/REALITY
            // 之内、最贴近 wire；wrap 失败丢连接继续 accept）。
            let stream: Box<dyn xray_transport::connection::Connection> = match tcpmask.as_ref() {
                Some(m) => {
                    match xray_transport::finalmask::wrap_conn_server_into_connection(
                        m,
                        Box::new(xray_transport::connection::TcpConnection::new(stream)),
                    ) {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::debug!(error = %e, "XHTTP tcpmask wrap failed");
                            continue;
                        },
                    }
                },
                None => Box::new(xray_transport::connection::TcpConnection::new(stream)),
            };
            let ctx = Arc::clone(&ctx);
            let tls = tls_cfg.clone();
            let rc = reality.clone();
            let probe = reality_probe.clone();
            tokio::spawn(async move {
                handle_accepted_stream(stream, peer, local, tls, rc, probe, ctx).await;
            });
        }
    });
    Ok(Box::new(SplithttpListener {
        local,
        tcp_abort: Some(accept_task.abort_handle()),
        h3_endpoint: None,
    }))
}

/// 单个已 accept 的流：REALITY / TLS 包装 → h1+h2c HTTP 服务。
///
/// Go hub.go:551-560：TLS 与 REALITY 互斥包装（security 二选一），
/// hub.go:564-578：同一 http.Server 同时处理明文 HTTP/1.1 与 h2c。
async fn handle_accepted_stream<S>(
    stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    tls: Option<Arc<rustls::ServerConfig>>,
    reality: Option<RealityServerConfig>,
    probe: Option<Arc<xray_reality::server::ProbeContext>>,
    ctx: Arc<HandlerContext>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if let Some(rc) = reality {
        serve_reality_conn(stream, peer, local, rc, probe, ctx).await;
    } else if let Some(tc) = tls {
        // Go hub.go:553-556 `gotls.NewListener`
        if let Ok(tls_stream) = tokio_rustls::TlsAcceptor::from(tc).accept(stream).await {
            serve_http_conn(tls_stream, peer, ctx).await;
        }
    } else {
        serve_http_conn(stream, peer, ctx).await;
    }
}

/// h1 + h2c 自动协商的 HTTP 服务。对应 Go hub.go:564-578
/// （`protocols.SetHTTP1(true)` + `SetUnencryptedHTTP2(true)` 的 http.Server）。
async fn serve_http_conn<S>(stream: S, peer: SocketAddr, ctx: Arc<HandlerContext>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let io = TokioIo::new(stream);
    let svc = service_fn(move |req| {
        let ctx = Arc::clone(&ctx);
        async move { Ok::<_, std::convert::Infallible>(handler::handle_request(req, peer, &ctx).await) }
    });
    let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(READ_HEADER_TIMEOUT);
    // r2lq：默认 ALPN=["h2","http/1.1"]（xray-tls server_config.rs:246）时协商
    // 走 h2；无显式 .http2() 时 h2 路径落默认 Builder（Time::Empty），依赖 timer
    // 的路径 panic / 行为不完整。Go hub.go:564-578 同一 http.Server 启 h1+h2。
    builder.http2().timer(hyper_util::rt::TokioTimer::new());
    // ponytail: Go hub.go:571 MaxHeaderBytes（GetNormalizedServerMaxHeaderBytes）无
    // hyper 字节级对应（仅 max_headers 条数），默认值即 Go 默认 1MiB 量级，未接入。
    let _ = builder.serve_connection(io, svc).await;
}

// ===== REALITY（Go hub.go:558-560 goreality.NewListener 的 Rust 等价物） =====

/// REALITY 服务端配置（`realitySettings` JSON）。
#[derive(Clone)]
struct RealityServerConfig {
    private_key: [u8; 32],
    /// t38j：SNI 白名单（非空，parse 层硬错保证）；精确匹配，供 server_tls 前置门。
    server_names: Vec<String>,
    short_ids: Vec<[u8; 8]>,
    max_time_diff: u32,
    /// fs0o: 客户端 TLS legacy_version 最小版本门控（字节字典序）；
    /// `Vec::new()`=不限制（兼容旧配置）。
    min_client_ver: Vec<u8>,
    /// fs0o: 客户端 TLS legacy_version 最大版本门控。
    max_client_ver: Vec<u8>,
    fallback_dest: String,
    xver: u8,
    /// bd frxi：启动期 CCS 探测开关（缺省 Disabled 保持现行为）。
    max_useless_records: xray_reality::MaxUselessRecordsSetting,
    /// bd tce2：TLS acceptor 选择（缺省 Rustls 保持现行为）。
    server_acceptor: xray_reality::ServerAcceptorSetting,
}

/// security == "reality" 时解析服务端 REALITY 配置，否则返回 None。
fn reality_server_config(
    security: &str,
    json: Option<&serde_json::Value>,
) -> io::Result<Option<RealityServerConfig>> {
    if security != "reality" {
        return Ok(None);
    }
    let json = json.ok_or_else(|| io::Error::other("reality: missing realitySettings"))?;
    let key_str = json
        .get("privateKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| io::Error::other("reality: missing privateKey"))?;
    let private_key = <[u8; 32]>::try_from(base64_url_decode(key_str)?)
        .map_err(|_| io::Error::other("reality: privateKey must be 32 bytes"))?;
    // t38j：serverNames 非空硬错（Go transport_security.go:94-96），
    // 与 xray-core inbound.rs 的 parse_reality_config 同语义（同族路径对齐）。
    let mut server_names = Vec::new();
    if let Some(arr) = json.get("serverNames").and_then(|x| x.as_array()) {
        for v in arr {
            let Some(name) = v.as_str() else {
                return Err(io::Error::other("reality: invalid serverNames entry (need string)"));
            };
            server_names.push(name.to_string());
        }
    }
    if server_names.is_empty() {
        return Err(io::Error::other("reality: empty \"serverNames\""));
    }

    // 257w 同族：shortIds 三重硬错对齐 Go transport_security.go:135-147
    // （空数组/过长/奇数或非法 hex 拒启），合法项左对齐补零 8 字节。
    let sid_arr = json
        .get("shortIds")
        .and_then(|x| x.as_array())
        .ok_or_else(|| io::Error::other("reality: empty \"shortIds\""))?;
    if sid_arr.is_empty() {
        return Err(io::Error::other("reality: empty \"shortIds\""));
    }
    let mut short_ids = Vec::with_capacity(sid_arr.len());
    for (i, sid) in sid_arr.iter().enumerate() {
        let Some(hex) = sid.as_str() else {
            return Err(io::Error::other(format!(
                "reality: invalid \"shortIds[{i}]\" (need hex string)"
            )));
        };
        if hex.len() > 16 {
            return Err(io::Error::other(format!("reality: too long \"shortIds[{i}]\": {hex}")));
        }
        let bytes = hex::decode(hex)
            .map_err(|_| io::Error::other(format!("reality: invalid \"shortIds[{i}]\": {hex}")))?;
        let mut id = [0u8; 8];
        id[..bytes.len()].copy_from_slice(&bytes);
        short_ids.push(id);
    }

    // dest/target：int（端口→localhost:port）或字符串 host:port
    let dest_raw =
        json.get("target").or_else(|| json.get("dest")).cloned().unwrap_or(serde_json::Value::Null);
    let fallback_dest = match dest_raw.as_u64() {
        Some(port) => format!("localhost:{port}"),
        None => dest_raw.as_str().unwrap_or("localhost:443").to_string(),
    };
    let xver = json.get("xver").and_then(|x| x.as_u64()).unwrap_or(0).min(2) as u8;
    // bd frxi：realitySettings.maxUselessRecords 三态（缺省/true/数值）。
    let max_useless_records =
        xray_reality::MaxUselessRecordsSetting::from_json(json.get("maxUselessRecords"))
            .map_err(io::Error::other)?;
    // bd tce2：realitySettings.serverAcceptor（"rustls" 默认 / "btls" opt-in）。
    let server_acceptor =
        xray_reality::ServerAcceptorSetting::from_json(json.get("serverAcceptor"))
            .map_err(io::Error::other)?;
    // mldsa65Seed：后量子签名未实现（cz5x）。配置在场即显式报错，
    // 不静默忽略——避免运营者误以为 PQC 已生效。
    if let Some(seed) = json.get("mldsa65Seed").and_then(|x| x.as_str()) {
        if !seed.is_empty() {
            return Err(io::Error::other(
                "reality: mldsa65Seed configured but ML-DSA-65 signing is not implemented \
                 in Rust (remove mldsa65Seed or use a Go server)",
            ));
        }
    }
    // maxTimeDiff：Go 默认 0（禁用），单位毫秒 → 转换为秒传给 verify。
    // 之前注入 43200 + 按秒解释 = 三重语义偏差（详见 docs/audit/crypto.md）。
    let max_time_diff_ms = json.get("maxTimeDiff").and_then(|x| x.as_u64()).unwrap_or(0);
    let max_time_diff = (max_time_diff_ms / 1000) as u32;

    // fs0o: 解析 minClientVer/maxClientVer（"26.3.27" → `[26, 3, 27]`）。
    // 镜像 Go `infra/conf/transport_security.go` 103-130：split(".") → u8 数组。
    let parse_version = |key: &str| -> io::Result<Vec<u8>> {
        let Some(s) = json.get(key).and_then(|v| v.as_str()) else {
            return Ok(Vec::new());
        };
        let mut v = Vec::new();
        for (i, part) in s.split('.').enumerate() {
            if i >= 3 {
                return Err(io::Error::other(format!(
                    "reality: invalid {key}: too many segments (max 3)"
                )));
            }
            let n: u64 = part.parse().map_err(|e| {
                io::Error::other(format!("reality: invalid {key} segment '{part}': {e}"))
            })?;
            if n > 255 {
                return Err(io::Error::other(format!("reality: {key} segment {n} > 255")));
            }
            v.push(n as u8);
        }
        Ok(v)
    };
    let min_client_ver = parse_version("minClientVer")?;
    let max_client_ver = parse_version("maxClientVer")?;

    Ok(Some(RealityServerConfig {
        private_key,
        server_names,
        short_ids,
        max_time_diff,
        min_client_ver,
        max_client_ver,
        fallback_dest,
        xver,
        max_useless_records,
        server_acceptor,
    }))
}

/// REALITY 握手：Verified → h1/h2c 服务；Invalid → 透明转发 fallback dest。
///
/// 镜像 Go `goreality.NewListener`（xtls/reality 库内置 fallback），Rust 侧组合
/// `xray_reality::server::server_tls` + `fallback_to_dest`（与 xray-core inbound
/// 的 VLESS+REALITY 路径同构）。
async fn serve_reality_conn<S>(
    stream: S,
    peer: SocketAddr,
    local: SocketAddr,
    rc: RealityServerConfig,
    probe: Option<Arc<xray_reality::server::ProbeContext>>,
    ctx: Arc<HandlerContext>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use xray_reality::server::{RealityServerOutcome, server_tls};

    // bd tce2：serverAcceptor="btls" 走 BoringSSL 握手（含 26zn 后握手记录
    // 模仿消费）；默认 rustls 路径行为不变。
    let outcome = if matches!(rc.server_acceptor, xray_reality::ServerAcceptorSetting::Btls) {
        #[cfg(not(target_os = "ios"))]
        {
            xray_reality::server::server_tls_btls(
                stream,
                &rc.private_key,
                &rc.short_ids,
                rc.max_time_diff,
                &rc.min_client_ver,
                &rc.max_client_ver,
                &rc.server_names,
                probe.as_deref(),
            )
            .await
        }
        #[cfg(target_os = "ios")]
        {
            xray_reality::server::server_tls(
                stream,
                &rc.private_key,
                &rc.short_ids,
                rc.max_time_diff,
                &rc.min_client_ver,
                &rc.max_client_ver,
                &rc.server_names,
                probe.as_deref(),
            )
            .await
        }
    } else {
        server_tls(
            stream,
            &rc.private_key,
            &rc.short_ids,
            rc.max_time_diff,
            &rc.min_client_ver,
            &rc.max_client_ver,
            &rc.server_names,
            probe.as_deref(),
        )
        .await
    };
    match outcome {
        Ok(RealityServerOutcome::Verified { tls, max_useless_records }) => {
            // bd frxi：探测值随连接交付（rustls 无 record 层消费点，
            // mygg 后握手记录模仿落地前仅可观察）。
            tracing::debug!(peer = %peer, max_useless_records, "reality verified with probe result");
            serve_http_conn(tls, peer, ctx).await
        },
        Ok(RealityServerOutcome::Invalid { conn, record, reason }) => {
            tracing::debug!(error = ?reason, dest = %rc.fallback_dest, "splithttp reality fallback");
            let _ = fallback_to_dest(conn, &record, &rc.fallback_dest, peer, local, rc.xver).await;
        },
        Err(e) => tracing::warn!(error = %e, "splithttp reality handshake error"),
    }
}

/// base64 RawURL 解码（无 padding，兼容 std 变体）。
fn base64_url_decode(s: &str) -> io::Result<Vec<u8>> {
    let normalized = s.replace('+', "-").replace('/', "_");
    let normalized = normalized.trim_end_matches('=');
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(normalized)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s))
        .map_err(|e| io::Error::other(format!("reality: base64 privateKey: {e}")))
}

// ===== H3（Go hub.go:481-535：UDP + QUIC + http3.Server） =====

/// H3 监听：UDP socket + QUIC endpoint + h3 server accept 循环。
///
/// `quinn::Endpoint::server` 等价 Go `ListenSystemPacket` + `quic.ListenEarly` 的组合。
/// ponytail: Go QuicParams（hub.go:498-514 InitStreamReceiveWindow/BBR 等）未在 Rust
/// 配置层建模，用 quinn 默认 TransportConfig；接入时在此覆盖 transport_config。
/// ListenEarly 的 0-RTT 接受同样依赖 rustls max_early_data_size，未启用。
async fn listen_h3(
    addr: SocketAddr,
    tls: Arc<rustls::ServerConfig>,
    config: &Arc<Config>,
    sockopt: &SocketOptions,
    handler: ConnHandler,
) -> io::Result<Box<dyn TransportListener>> {
    let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from((*tls).clone())
        .map_err(|e| io::Error::other(format!("rustls→quic server: {e}")))?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
    let std_sock = xray_transport::sockopt::bind_udp_endpoint(addr, sockopt)?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        std_sock,
        Arc::new(quinn::TokioRuntime),
    )?;
    let local = endpoint.local_addr()?;
    // endpoint clone 给 listener 句柄；本体 move 进 accept task。
    let ctx = build_context(config, local, handler);
    tracing::info!(%local, "listening QUIC for XHTTP/3");

    let listener_endpoint = endpoint.clone();
    let accept_task = tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let ctx = Arc::clone(&ctx);
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(_) => return,
                };
                serve_h3_conn(conn, ctx).await;
            });
        }
    });
    Ok(Box::new(SplithttpListener { local, tcp_abort: None, h3_endpoint: Some(listener_endpoint) }))
}

/// 单个 QUIC 连接：h3 server handshake → accept 请求循环。
async fn serve_h3_conn(conn: quinn::Connection, ctx: Arc<HandlerContext>) {
    let mut h3_conn =
        match h3::server::Connection::new(h3_quinn::Connection::new(conn.clone())).await {
            Ok(c) => c,
            Err(_) => return,
        };
    while let Ok(Some(resolver)) = h3_conn.accept().await {
        let ctx = Arc::clone(&ctx);
        let conn = conn.clone();
        let peer = conn.remote_address();
        tokio::spawn(async move {
            let Ok((req, stream)) = resolver.resolve_request().await else {
                return;
            };
            let task = tokio::spawn(serve_h3_request(req, stream, peer, Arc::clone(&ctx)));
            // 连接终结（客户端断开 / idle / error）必须强制终结该连接上的全部
            // 请求——对齐 Go hub.go:394-398 `request.Context().Done()` 中断
            // handler + `defer conn.Close()`：abort 触发 response body（含
            // SessionDropGuard）drop，会话删除 + queue.close + ServerConn 上行
            // EOF 级联，hub copy / forward / dispatcher 桥全链解体。否则
            // response body 循环滞留至永久（实测 100%/conn 死锁，s12 泄漏根因）。
            let closer = conn.clone();
            tokio::spawn(async move {
                let _ = closer.closed().await;
                task.abort();
            });
        });
    }
}

/// h3 服务端请求流（bidi）。split 后 send/recv 两半分属不同 task。
type H3ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// 单个 h3 请求：请求体桥接为 `ReqBody` 喂给 hub handler，响应帧序列发回。
///
/// 对应 Go `http3.Server{Handler: requestHandler}`——同一 handler 服务 h1/h2/h3。
/// stream-up 需边收上传 body 边发响应，故 split（h3 RequestStream::split 官方支持）。
async fn serve_h3_request(
    req: http::Request<()>,
    stream: H3ServerStream,
    peer: SocketAddr,
    ctx: Arc<HandlerContext>,
) {
    let (send_half, recv_half) = stream.split();
    let (parts, ()) = req.into_parts();
    let req = http::Request::from_parts(parts, H3RecvBody { stream: recv_half });

    let resp = handler::handle_request(req, peer, &ctx).await;

    let (parts, mut body) = resp.into_parts();
    let mut send = send_half;
    if send.send_response(http::Response::from_parts(parts, ())).await.is_err() {
        return;
    }
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else { break };
        if let Ok(data) = frame.into_data() {
            if send.send_data(data).await.is_err() {
                return;
            }
        }
    }
    let _ = send.finish().await;
}

/// h3 请求体 → `http_body::Body` 桥接。
///
/// `poll_recv_data` 是注册函数（非 async），可直接在 `poll_frame` 里调用。
struct H3RecvBody {
    stream: h3::server::RequestStream<h3_quinn::RecvStream, Bytes>,
}

impl hyper::body::Body for H3RecvBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, io::Error>>> {
        match self.stream.poll_recv_data(cx) {
            Poll::Ready(Ok(Some(mut chunk))) => {
                let n = chunk.remaining();
                Poll::Ready(Some(Ok(hyper::body::Frame::data(chunk.copy_to_bytes(n)))))
            },
            Poll::Ready(Ok(None)) => Poll::Ready(None),
            Poll::Ready(Err(e)) => {
                Poll::Ready(Some(Err(io::Error::other(format!("h3 recv_data: {e}")))))
            },
            Poll::Pending => Poll::Pending,
        }
    }
}

// ===== hub handler ↔ listener registry 适配 =====

/// 构造 hub handler 上下文（镜像 `HubListener::serve` 的构造）。
fn build_context(
    config: &Arc<Config>,
    local: SocketAddr,
    handler: ConnHandler,
) -> Arc<HandlerContext> {
    Arc::new(HandlerContext {
        config: Arc::clone(config),
        host: config.host.clone(),
        base_path: config.normalized_path(),
        local_addr: local,
        sessions: Arc::new(SessionMap::new()),
        conn_handler: Arc::new(ConnHandlerAdapter(handler)),
        max_buffered_posts: config.normalized_sc_max_buffered_posts() as usize,
        sc_max_each_post_bytes: config.normalized_sc_max_each_post_bytes().to as usize,
    })
}

/// `ConnHandler`（registry 的 `Arc<dyn Fn(Box<dyn Connection>)>`）→ `HubConnHandler`。
///
/// `ServerConn` 的 box 字段非 `Sync`，不满足 `Connection: Sync` 约束，故沿用
/// duplex bridge 模式：`tokio::io::duplex` 一端交 registry handler（`DuplexConn`），
/// 另一端与 `ServerConn` 的 reader/writer 双向 copy。
struct ConnHandlerAdapter(ConnHandler);

impl HubConnHandler for ConnHandlerAdapter {
    fn add_conn(&self, conn: ServerConn) {
        let (client, server) = tokio::io::duplex(DUPLEX_BUF);
        let remote = conn.remote_addr;
        let local = conn.local_addr;
        (self.0)(Box::new(DuplexConn { inner: client, remote: Some(remote), local: Some(local) }));
        tokio::spawn(async move {
            let ServerConn { reader: mut up, writer: mut down, .. } = conn;
            let (mut rd, mut wr) = tokio::io::split(server);
            // 上行（客户端上传 → dispatcher 读）/ 下行（dispatcher 写 → HTTP 响应）
            let a = tokio::io::copy(&mut up, &mut wr);
            let b = tokio::io::copy(&mut rd, &mut down);
            let _ = tokio::join!(a, b);
        });
    }
}

/// duplex 半部，满足 `Connection: AsyncRead + AsyncWrite + Send + Sync + Unpin`。
struct DuplexConn {
    inner: tokio::io::DuplexStream,
    remote: Option<SocketAddr>,
    local: Option<SocketAddr>,
}

impl AsyncRead for DuplexConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for DuplexConn {
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

impl Connection for DuplexConn {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.remote)
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(self.local)
    }
}

/// listener 句柄。对应 Go `Listener`（h3listener/listener 二选一）。
/// 两条监听形态各持一个关闭句柄：TCP 分支 abort accept task（TcpListener drop
/// 释放端口），H3 分支直接关 QUIC endpoint（对齐 Go tr.Close()）。
struct SplithttpListener {
    local: SocketAddr,
    tcp_abort: Option<tokio::task::AbortHandle>,
    h3_endpoint: Option<quinn::Endpoint>,
}

impl TransportListener for SplithttpListener {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn close(&self) -> io::Result<()> {
        tracing::info!("splithttp listener close addr={}", self.local);
        if let Some(task) = &self.tcp_abort {
            task.abort();
        }
        if let Some(ep) = &self.h3_endpoint {
            ep.close(quinn::VarInt::from_u32(0), b"listener closed");
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpStream,
    };

    use super::*;
    fn ensure_provider() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// echo 型 ConnHandler：每收到 ServerConn 即写一条下行消息后放弃（触发响应 body EOF）。
    fn greeting_handler() -> (ConnHandler, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&count);
        let h: ConnHandler = Arc::new(move |conn: Box<dyn Connection>| {
            c.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut conn = conn;
                let _ = conn.write_all(b"hello-from-server").await;
                let _ = conn.flush().await;
                // drop → 下行 EOF → 响应 body 结束
            });
        });
        (h, count)
    }

    fn plain_settings() -> StreamSettings {
        StreamSettings { protocol: "splithttp".into(), ..Default::default() }
    }

    /// h1 客户端接入（stream-one）：明文 HTTP/1.1 GET → 200 + 下行数据。
    /// 验证 hyper auto 的 h1 兼容（Go hub.go:566 SetHTTP1(true)）。
    ///
    /// padding：Go 服务端对空 padding 恒 400（hub.go:141-148 + IsPaddingValid ""
    /// → false 无豁免），真实客户端恒携带 `?x_padding=`（FillStreamRequest，默认
    /// range 100..1000）——裸请求须同样携带，否则测的是 Go 会拒的非协议行为。
    #[tokio::test]
    async fn h1_client_stream_one_roundtrip() {
        let (handler, count) = greeting_handler();
        let listener = listen_splithttp(
            "127.0.0.1:0".parse().unwrap(),
            &plain_settings(),
            &SocketOptions::default(),
            handler,
        )
        .await
        .expect("listen");
        let addr = listener.local_addr().unwrap();

        let mut tcp = TcpStream::connect(addr).await.expect("connect");
        // 100 个 'X'：默认 xPaddingBytes range 100..1000 的下界（repeat-x 按字节计长）。
        tcp.write_all(
            format!(
                "GET /?x_padding={} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                "X".repeat(100)
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut resp = Vec::new();
        tcp.read_to_end(&mut resp).await.unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(text.contains("200"), "h1 status line missing: {text}");
        assert!(text.contains("hello-from-server"), "h1 stream-one download missing: {text}");
        assert_eq!(count.load(Ordering::SeqCst), 1, "handler should see 1 conn");
    }

    /// H3 server 接收：alpn=["h3"] → QUIC listener；quinn+h3 客户端 GET stream-one。
    #[tokio::test]
    async fn h3_server_receives_stream_one() {
        ensure_provider();
        let (handler, count) = greeting_handler();
        let mut settings = plain_settings();
        settings.security = "tls".into();
        settings.security_json = Some(serde_json::json!({ "alpn": ["h3"] }));
        let listener = listen_splithttp(
            "127.0.0.1:0".parse().unwrap(),
            &settings,
            &SocketOptions::default(),
            handler,
        )
        .await
        .expect("listen h3");
        let addr = listener.local_addr().unwrap();

        // quinn + h3 客户端（自签证书 → allowInsecure）
        let client_tls = xray_tls::client_config::build_client_config(
            "tls",
            Some(&serde_json::json!({"allowInsecure": true, "alpn": ["h3"]})),
            "127.0.0.1",
        )
        .unwrap()
        .expect("client tls config");
        let quic_cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
        ));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quic_cfg);
        let conn = endpoint.connect(addr, "127.0.0.1").unwrap().await.expect("quic connect");
        let (mut driver, mut send_req) =
            h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let req = http::Request::builder()
            .method("GET")
            // padding：Go 服务端对空 padding 恒 400（IsPaddingValid），真实客户端
            // （FillStreamRequest）恒携带；与 h1 roundtrip 同理。
            .uri(format!("/?x_padding={}", "X".repeat(100)))
            .header("host", format!("127.0.0.1:{}", addr.port()))
            .body(())
            .unwrap();
        let mut stream = send_req.send_request(req).await.unwrap();
        stream.finish().await.unwrap();

        let resp = stream.recv_response().await.expect("h3 response");
        assert_eq!(resp.status(), 200);
        let mut got = Vec::new();
        loop {
            match stream.recv_data().await {
                Ok(Some(mut chunk)) => {
                    let n = chunk.remaining();
                    got.extend_from_slice(&chunk.copy_to_bytes(n));
                },
                Ok(None) => break,
                Err(e) => panic!("h3 recv_data: {e}"),
            }
        }
        assert_eq!(got, b"hello-from-server");
        assert_eq!(count.load(Ordering::SeqCst), 1, "handler should see 1 conn");
        drop(send_req);
        drop(endpoint);
    }

    /// REALITY listener 创建 + 非 REALITY 流量 fallback：
    /// 垃圾字节 ClientHello → Invalid → 透明转发 dest（goreality.NewListener 语义）。
    #[tokio::test]
    async fn reality_listener_creation_and_fallback() {
        ensure_provider();
        // fallback dest listener
        let fb = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fb_addr = fb.local_addr().unwrap();
        let (fb_tx, fb_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut s, _) = fb.accept().await.expect("fallback accept");
            let mut buf = vec![0u8; 128];
            let n = s.read(&mut buf).await.unwrap_or(0);
            buf.truncate(n);
            let _ = fb_tx.send(buf);
        });

        let (handler, count) = greeting_handler();
        let mut settings = plain_settings();
        settings.security = "reality".into();
        settings.security_json = Some(serde_json::json!({
            "privateKey": base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode([7u8; 32]),
            "serverNames": ["localhost"],
            "shortIds": [""],
            "dest": format!("127.0.0.1:{}", fb_addr.port()),
            "xver": 0,
        }));
        let listener = listen_splithttp(
            "127.0.0.1:0".parse().unwrap(),
            &settings,
            &SocketOptions::default(),
            handler,
        )
        .await
        .expect("reality listener created");
        let addr = listener.local_addr().unwrap();

        // 非 REALITY 客户端：垃圾字节 → 验证失败 → fallback 转发原文
        let mut tcp = TcpStream::connect(addr).await.expect("connect");
        // 构造可完整读取但解析必失败的 ClientHello record（content_type=0x16, len=5）：
        // read_tls_record Ok → parse_client_hello Err → Invalid → fallback 转发 record 原文。
        // （纯随机垃圾若 length 字段 >16384 会让 read_tls_record 直接 Err，走 handshake
        // error 分支不 fallback——与 Go goreality 读错误即断连一致。）
        let garbage: &[u8] = &[0x16, 0x03, 0x01, 0x00, 0x05, b'G', b'A', b'R', b'B', b'A'];
        tcp.write_all(garbage).await.unwrap();
        let _ = tcp.shutdown().await;
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), fb_rx)
            .await
            .expect("fallback within 5s")
            .expect("fallback channel open");
        assert!(got.starts_with(garbage), "fallback should receive original record, got {got:?}");
        assert_eq!(count.load(Ordering::SeqCst), 0, "fallback conn must not reach dispatcher");
    }
    /// TCP 分支：close() abort accept task → TcpListener drop → 端口释放
    /// （票 4kjs 回归锚：修复前 close 仅日志，连接一直成功）。
    #[tokio::test]
    async fn close_rejects_new_tcp_connections() {
        let (handler, _count) = greeting_handler();
        let listener = listen_splithttp(
            "127.0.0.1:0".parse().unwrap(),
            &plain_settings(),
            &SocketOptions::default(),
            handler,
        )
        .await
        .expect("listen");
        let addr = listener.local_addr().unwrap();

        listener.close().unwrap();

        // abort → socket drop 是异步的：轮询直至 connect 被拒。
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match TcpStream::connect(addr).await {
                Err(_) => break,
                Ok(_) => {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "close 后端口仍接受连接（accept task 未终止）"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                },
            }
        }
    }

    /// H3 分支：close() 关 QUIC endpoint → 新 QUIC 握手失败（对齐 Go tr.Close()）。
    #[tokio::test]
    async fn close_rejects_new_h3_connections() {
        ensure_provider();
        let (handler, _count) = greeting_handler();
        let mut settings = plain_settings();
        settings.security = "tls".into();
        settings.security_json = Some(serde_json::json!({ "alpn": ["h3"] }));
        let listener = listen_splithttp(
            "127.0.0.1:0".parse().unwrap(),
            &settings,
            &SocketOptions::default(),
            handler,
        )
        .await
        .expect("listen h3");
        let addr = listener.local_addr().unwrap();

        listener.close().unwrap();

        let client_tls = xray_tls::client_config::build_client_config(
            "tls",
            Some(&serde_json::json!({"allowInsecure": true, "alpn": ["h3"]})),
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

        let result = endpoint.connect(addr, "127.0.0.1").unwrap().await;
        assert!(result.is_err(), "post-close h3 connect must fail");
        endpoint.close(0u32.into(), b"test done");
    }
}
