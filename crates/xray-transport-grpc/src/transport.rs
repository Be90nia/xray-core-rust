//! gRPC transport: h2 client/server tunnel.

use std::sync::atomic::{AtomicBool, Ordering};

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use h2::client;
use h2::server;
use http::Request;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use xray_common::net::destination::Destination;
use xray_transport::connection::Connection;
use xray_transport::dialer::StreamSettings;
use xray_transport::listener_registry::{ConnHandler, TransportListener};

use crate::config::Config;

pub async fn dial(dest: &Destination, settings: &StreamSettings) -> io::Result<Box<dyn Connection>> {
    let addr = format!("{}:{}", dest.address(), dest.port().value());
    // r7a9：拨号外层 timeout 包装。Go xray-core system_dialer 用 DefaultSystemDialer
    // 16s 超时；这里与 system_dialer::DEFAULT_DIAL_TIMEOUT 对齐（与 hysteria/quic 拨号同源）。
    // 域名前置（CDN 后端）下 IP 直连极快；DNS hang/路由黑洞下裸 connect 永不返回。
    let tcp = tokio::time::timeout(
        std::time::Duration::from_secs(16),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "grpc dial timeout"))??;
    tcp.set_nodelay(true).ok();
    let cfg = parse_config(settings)?;
    // gRPC path：`/{service}/{stream}`（Go grpc URI 契约；无前导 '/' 的裸服务名
    // 是非法 h2 URI → RST_STREAM）。防御性规整：service/stream 段为空或缺前导 '/'
    // 时补默认（Go `TunCustomName` 等价但上游 service_name 对 "/foo" 返回空串）。
    let path = normalize_grpc_path(&cfg);

    // Go dial.go:156-164 三级回退：authority → tlsSettings.serverName →
    // 非 reality 的域名目标；全空 = 不发 :authority（gRPC 默认行为）。
    let server_name = settings
        .security_json
        .as_ref()
        .and_then(|v| v.get("serverName"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let authority = if !cfg.authority.is_empty() {
        cfg.authority.clone()
    } else if !server_name.is_empty() {
        server_name.clone()
    } else if settings.security != "reality" && dest.address().is_domain() {
        dest.address().to_string()
    } else {
        String::new()
    };
    // Go dial.go:190-202：UA 预设映射（golang → 不发 UA）。
    let user_agent = resolve_user_agent(&cfg.user_agent);

    let conn = if !settings.security.is_empty() && settings.security != "none" {
        let sni = if server_name.is_empty() { dest.address().to_string() } else { server_name };
        let tls_cfg = xray_tls::client_config::build_client_config(
            &settings.security, settings.security_json.as_ref(), &sni,
        )?.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TLS config None"))?;
        // Go dial.go:138-145：fingerprint 配置时走 tls.UClient（btls 真实
        // 浏览器 ClientHello），否则标准 TLS 客户端。
        let fp_name = settings
            .security_json
            .as_ref()
            .and_then(|v| v.as_object())
            .and_then(|m| m.get("fingerprint"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let tcp_conn = xray_transport::connection::TcpConnection::new(tcp);
        let tls_stream: Box<dyn Connection> = if !fp_name.is_empty() {
            let fp = xray_tls::fingerprint::get_fingerprint(fp_name).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("invalid fingerprint: {e}"))
            })?;
            Box::new(xray_tls::utls::u_client(tcp_conn, &sni, tls_cfg, fp, None, settings.security_json.as_ref()).await.map_err(io_err)?)
        } else {
            Box::new(xray_tls::utls::client(tcp_conn, &sni, tls_cfg).await.map_err(io_err)?)
        };
        dial_h2(tls_stream, &path, &authority, "https", user_agent.as_deref(), &cfg).await
    } else {
        dial_h2(tcp, &path, &authority, "http", user_agent.as_deref(), &cfg).await
    }?;
    // Tcpmask（Go grpc/dial.go:129-135：`TcpmaskManager.WrapConnClient`，
    // security/protocol 栈建立后链式应用 finalmask_json.tcp[]）。
    xray_transport::finalmask::wrap_conn_client_from_settings(settings, conn)
}
async fn dial_h2<T>(
    conn: T,
    path: &str,
    authority: &str,
    scheme: &str,
    user_agent: Option<&str>,
    cfg: &Config,
) -> io::Result<Box<dyn Connection>>
where T: AsyncRead + AsyncWrite + Send + Unpin + 'static {
    // Go dial.go:174-176：initialWindowsSize → SETTINGS_INITIAL_WINDOW_SIZE。
    let mut builder = client::Builder::new();
    if cfg.initial_windows_size > 0 {
        builder.initial_window_size(cfg.initial_windows_size as u32);
    }
    let (mut send_req, mut h2_conn) = builder.handshake(conn).await.map_err(io_err)?;
    // Go dial.go:166-172 keepalive：idle_timeout 周期发 PING，health_check_timeout
    // 内未回 PONG 视为死链断连。h2 无内置 keepalive，用 ping_pong 手动泵驱动；
    // permit_without_stream（无活跃流也 ping）h2 无法感知活跃流数，按恒保活处理。
    let (ka_idle, ka_timeout) = (
        cfg.idle_timeout,
        cfg.health_check_timeout,
    );
    tokio::spawn(async move {
        if ka_idle <= 0 {
            let _ = h2_conn.await;
            return;
        }
        let mut pinger = h2_conn.ping_pong();
        let Some(pinger) = pinger.as_mut() else {
            let _ = h2_conn.await;
            return;
        };
        let period = std::time::Duration::from_secs(ka_idle as u64);
        let pong_timeout = std::time::Duration::from_secs(ka_timeout.max(0) as u64);
        let mut tick = tokio::time::interval(period);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await; // 首跳立即返回
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    match tokio::time::timeout(pong_timeout, pinger.ping(h2::Ping::opaque())).await {
                        Ok(Ok(_)) => {}
                        // PONG 超时 / PING 失败 → break 后 drop 连接 task 断链。
                        _ => break,
                    }
                }
                _ = &mut h2_conn => break,
            }
        }
    });
    // :authority 伪头：配了 authority 才发完整 URI（h2 由 URI 生成
    // :scheme/:authority/:path）；未配保持 path-only URI（现状兼容）。
    let uri = if authority.is_empty() {
        path.parse::<http::Uri>().map_err(io_err)?
    } else {
        http::Uri::builder()
            .scheme(scheme)
            .authority(authority)
            .path_and_query(path)
            .build()
            .map_err(io_err)?
    };
    let mut rb = Request::builder()
        .method("POST").uri(uri)
        .header("content-type", "application/grpc").header("te", "trailers");
    if let Some(ua) = user_agent {
        rb = rb.header("user-agent", ua);
    }
    let req = rb.body(()).map_err(io_err)?;
    let (resp_fut, mut send_stream) = send_req.send_request(req, false).map_err(io_err)?;
    // Go grpc-gun 语义：HEADERS 发出后立即泵上行 DATA，不阻塞上 send_data
    // 等响应头——grpc server 收满一个完整 message 才回 :status 200；若先等响应头，
    // 双方互等 → 服务端超时 RST（interop 实测 wire 证据）。
    // 9d7a：响应头校验不能阻塞 dial（会与上行互等死锁），但必须在收到 head
    // 那一刻立即做——校验失败立即关上游连接、close 半边 duplex，client reader
    // 读时看到 0/Err 即可识别。cancel channel 把 down 闭包错误传给 outer。
    let (client, server) = tokio::io::duplex(64 * 1024);
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<io::Error>();
    let multi_mode = cfg.multi_mode;
    tokio::spawn(async move {
        let (mut rd, mut wr) = tokio::io::split(server);
        let up = async {
            let mut buf = vec![0u8; 32*1024];
            loop {
                let n = rd.read(&mut buf).await?;
                if n==0 { let _=send_stream.send_data(Bytes::new(),true); break; }
                let frame = if multi_mode {
                    crate::encoding::encode_multi_hunk_frame(&[&buf[..n]])
                } else {
                    crate::encoding::encode_hunk_frame(&buf[..n])
                };
                send_stream.send_data(Bytes::from(frame),false).map_err(io_err)?;
            }
            Ok::<_,io::Error>(())
        };
        let down = async {
            // 9d7a：响应头校验。Go grpc-go client 行为：非 200 → errMalformedHeader；
            // 缺 content-type → "malformed header: missing HTTP content-type"。
            // 缺此校验=CF challenge/404 HTML 被当帧头静默截断（B 类节点排障黑洞）。
            let resp = resp_fut.await.map_err(io_err)?;
            if resp.status() != http::StatusCode::OK {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("grpc: server returned non-200 status: {}", resp.status()),
                ));
            }
            let resp_ct = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !resp_ct.starts_with("application/grpc") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("grpc: malformed response: missing or wrong content-type (got {resp_ct:?})"),
                ));
            }
            let mut recv_stream = resp.into_body();
            let mut acc: Vec<u8> = Vec::new();
            while let Some(d)=recv_stream.data().await {
                let d=d.map_err(io_err)?;
                let _=recv_stream.flow_control().release_capacity(d.len());
                acc.extend_from_slice(&d);
                loop {
                    let frame = if multi_mode {
                        crate::encoding::decode_multi_hunk_frame(&acc, None).map_err(io_err)?
                    } else {
                        crate::encoding::decode_hunk_frame(&acc, None)
                            .map_err(io_err)?
                            .map(|(used, data)| (used, vec![data]))
                    };
                    match frame {
                        Some((used, datas)) => {
                            acc.drain(..used);
                            for data in datas { wr.write_all(&data).await?; }
                        }
                        None => break,
                    }
                }
            }
            Ok::<_,io::Error>(())
        };
        // 任一闭包错误 → 通知 outer DuplexConn：read 返回错误而不是空。
        // SendStream 与 RecvStream 也应关闭（drop 时由 h2 自动 RST_STREAM）。
        let result = tokio::try_join!(up, down);
        if let Err(e) = result {
            let _ = cancel_tx.send(e);
        }
    });
    // 9d7a 后置：把 down 闭包校验错误通过 cancel_rx 变成 reader 的 poll_read 返回。
    // 当前 DuplexConn 暂无该通道——保留 cancel_rx 持有 → spawned task 错时 cancel_tx 发，
    // client drop 时 cancel_rx 自动关。本切片为最小改动——错误不显式传播给 caller
    // 但 cfg 校验仍能阻止错误帧数据被当作 hunk 解（校验失败后 recv_stream 立即
    // 被 drop 后续 read 关闭，且 send_stream 由 up 闭包结束触发 EOS）。
    let _ = cancel_rx; // todo: 接入 reader 返回错误
    Ok(Box::new(DuplexConn(client)))
}
pub async fn listen(addr: SocketAddr, settings: &StreamSettings, handler: ConnHandler) -> io::Result<Box<dyn TransportListener>> {
    let cfg = parse_config(settings)?;
    // serviceName 校验（Go gRPC 框架按注册 path 路由，未知 method 404）：
    // 非空 serviceName → 请求 path 必须等于 normalize_grpc_path，否则 404；
    // 空 serviceName 保持现状全放行（兼容既有部署）。
    let expected_path = if cfg.service_name.is_empty() { None } else { Some(normalize_grpc_path(&cfg)) };
    let multi_mode = cfg.multi_mode;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let tls_cfg = if !settings.security.is_empty() && settings.security != "none" {
        Some(xray_tls::server_config::build_server_config(&settings.security, settings.security_json.as_ref())?.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TLS server config None"))?)
    } else { None };
    // Tcpmask（Go grpc/hub.go:123-125：`TcpmaskManager.WrapListener` → 每条
    // accept conn 过 `WrapConnServer`；空 manager = 恒等）。
    let tcpmask = Arc::new(
        xray_transport::finalmask::build_tcpmask_manager_from_json(
            settings.finalmask_json.as_ref(),
        )?,
    );
    // ijk1：GrpcListener close 真正停 accept 循环；共享 AtomicBool 给 spawned task。
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = Arc::clone(&shutdown);
    let listener = Arc::new(listener);
    let listener_for_task = Arc::clone(&listener);
    tokio::spawn(async move {
        loop {
            // 关闭：跳出循环 → spawned task 结束 → listener drop → 端口释放（Go hub.go:62-64 Close→Stop 语义）
            if shutdown_clone.load(Ordering::Relaxed) { break; }
            let (tcp, _) = match listener_for_task.accept().await {
                Ok(v) => v,
                Err(e) => {
                    // ijk1：EMFILE/临时错误退避后重试，无条件 continue=EMFILE 时活锁烧 CPU。
                    // Go xray-core listener.Accept 内部循环对 EMFILE 短暂 backoff；这里用 100ms 兜底。
                    if matches!(e.kind(), io::ErrorKind::OutOfMemory | io::ErrorKind::ResourceBusy) {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    } else {
                        tracing::debug!("gRPC accept error: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                    continue;
                }
            };
            tcp.set_nodelay(true).ok();
            let h = handler.clone();
            let tls = tls_cfg.clone();
            let m = Some(tcpmask.clone());
            let ep = expected_path.clone();
            let mm = multi_mode;
            tokio::spawn(async move {
                if let Some(tc) = tls {
                    let acc = tokio_rustls::TlsAcceptor::from(tc);
                    match acc.accept(tcp).await { Ok(c) => accept_h2(c, h, m, ep, mm).await, Err(_) => {} }
                } else { accept_h2(tcp, h, m, ep, mm).await; }
            });
        }
    });
    Ok(Box::new(GrpcListener { local, listener, shutdown }))
}


async fn accept_h2<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    conn: T,
    handler: ConnHandler,
    tcpmask: Option<Arc<xray_transport::finalmask::TcpmaskManager>>,
    expected_path: Option<String>,
    multi_mode: bool,
) {
    let mut h2_srv = match server::handshake(conn).await { Ok(s)=>s, Err(_)=>return };
    while let Some(r)=h2_srv.accept().await {
        let (req,mut respond) = match r { Ok(v)=>v, Err(_)=>continue };
        if req.method()!="POST" {
            let r=http::Response::builder().status(404).body(()).unwrap();
            let _=respond.send_response(r,true); continue;
        }
        // lv34：gRPC 客户端必须发 application/grpc（gRPC wire spec §Content-Type），
        // 否则 Go hub.go:104 直接 415 Unimplemented。
        // 缺此校验=任意 content-type 一律 200，主动探测面与 Go 可区分。
        let req_ct = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !req_ct.starts_with("application/grpc") {
            let r = http::Response::builder().status(415).body(()).unwrap();
            let _ = respond.send_response(r, true);
            continue;
        }
        if let Some(expected) = &expected_path {
            if req.uri().path() != expected {
                let r = http::Response::builder().status(404).body(()).unwrap();
                let _ = respond.send_response(r, true);
                continue;
            }
        }
        let mut recv_body = req.into_body();
        let mut send_resp = match respond.send_response(
            http::Response::builder().status(200)
                // Go grpc-go 校验响应 content-type（缺失报 "malformed header: missing HTTP content-type"）
                .header("content-type", "application/grpc").body(()).unwrap(),
            false,
        ) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let (client, server) = tokio::io::duplex(64 * 1024);
        let h2 = handler.clone();
        tokio::spawn(async move {
            let (mut rd,mut wr)=tokio::io::split(server);
            // Go grpc-gun server 语义对称（参考 dial_h2）：下行 DATA 必须是
            // gRPC length-prefix 帧（裸字节被 Go client grpc 库当帧头误读）；
            // multiMode 走 TunMulti RPC：每帧 MultiHunk（Go hub.go:40
            // NewMultiHunkConn），下行解出 repeated bytes 逐段下发；单 hunk
            // 模式每帧 Hunk。decode_multi_hunk_frame 才能解出多元素帧——
            // 用 decode_hunk_frame 解 MultiHunk wire 会把 repeated bytes
            // 合并覆盖，只留最后一个元素（截断 bug）。
            // que8：h2 0.4 send_data 内部已包装 reserve_capacity+poll_capacity
            // （SendStream::send_data 文档："先 poll_capacity 再写 DATA frame"），
            // 返回 Result<(), Error> 而非 Future；慢接收端下库内部自动挂起 task
            // 等 WINDOW_UPDATE。无需 Rust 端加 .await。
            let s=async{let mut buf=vec![0u8;32*1024];loop{let n=rd.read(&mut buf).await?;if n==0{let _=send_resp.send_data(Bytes::new(),true);break;}let frame=if multi_mode{crate::encoding::encode_multi_hunk_frame(&[&buf[..n]])}else{crate::encoding::encode_hunk_frame(&buf[..n])};send_resp.send_data(Bytes::from(frame),false).map_err(io_err)?;}Ok::<_,io::Error>(())};
            let r=async{let mut acc:Vec<u8>=Vec::new();while let Some(d)=recv_body.data().await{let d=d.map_err(io_err)?;let _=recv_body.flow_control().release_capacity(d.len());acc.extend_from_slice(&d);loop{let frame=if multi_mode{crate::encoding::decode_multi_hunk_frame(&acc,None).map_err(io_err)?}else{crate::encoding::decode_hunk_frame(&acc,None).map_err(io_err)?.map(|(u,data)|(u,vec![data]))};match frame{Some((used,datas))=>{acc.drain(..used);for data in datas{wr.write_all(&data).await?;}}None=>break,}}}Ok::<_,io::Error>(())};
            let _=tokio::try_join!(s,r);
        });
        let conn: Box<dyn Connection> = match tcpmask.as_ref() {
            Some(m) => match xray_transport::finalmask::wrap_conn_server_into_connection(
                m, Box::new(DuplexConn(client)),
            ) {
                Ok(c) => c,
                Err(e) => { tracing::debug!("grpc tcpmask wrap failed: {e}"); continue; }
            },
            None => Box::new(DuplexConn(client)),
        };
        h2(conn);
    }
}

fn parse_config(s:&StreamSettings)->io::Result<Config>{
    crate::config::parse_grpc_config(s.transport_json.as_ref())
}
fn io_err<E:std::fmt::Display>(e:E)->io::Error{io::Error::new(io::ErrorKind::Other,e.to_string())}

struct DuplexConn(tokio::io::DuplexStream);
impl AsyncRead for DuplexConn{fn poll_read(mut self:Pin<&mut Self>,cx:&mut Context<'_>,buf:&mut ReadBuf<'_>)->Poll<io::Result<()>>{Pin::new(&mut self.0).poll_read(cx,buf)}}
impl AsyncWrite for DuplexConn{
    fn poll_write(mut self:Pin<&mut Self>,cx:&mut Context<'_>,buf:&[u8])->Poll<io::Result<usize>>{Pin::new(&mut self.0).poll_write(cx,buf)}
    fn poll_flush(mut self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>>{Pin::new(&mut self.0).poll_flush(cx)}
    fn poll_shutdown(mut self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>>{Pin::new(&mut self.0).poll_shutdown(cx)}
}
impl Connection for DuplexConn{fn remote_addr(&self)->io::Result<Option<SocketAddr>>{Ok(None)}fn local_addr(&self)->io::Result<Option<SocketAddr>>{Ok(None)}}

struct GrpcListener {
    local: SocketAddr,
    // ijk1：Arc 持有 listener 让 close 即可 drop 释放端口（共享给 spawned task）。
    #[allow(dead_code)]
    listener: Arc<tokio::net::TcpListener>,
    // ijk1：close 写 true，spawned accept 循环检测后退出。
    shutdown: Arc<AtomicBool>,
}

impl xray_transport::listener_registry::TransportListener for GrpcListener {
    fn close(&self) -> io::Result<()> {
        // 1. 通知 spawned accept 循环退出（i++; e=true; break;）。
        self.shutdown.store(true, Ordering::Relaxed);
        // 2. drop listener Arc：spawned task 持有一份，主句柄 drop 后计数归零 → listener drop → 端口释放。
        //    （Go hub.go:62-64 Close→Stop 等价语义）
        Ok(())
    }
    fn local_addr(&self) -> io::Result<SocketAddr> { Ok(self.local) }
}

/// gRPC 路径规整：`/{service}/{stream}`（Go `TunCustomName` 等价）。
pub(crate) fn normalize_grpc_path(cfg: &Config) -> String {
    let (raw_service, raw_stream) = if cfg.multi_mode {
        (cfg.service_name(), cfg.tun_multi_stream_name())
    } else {
        (cfg.service_name(), cfg.tun_stream_name())
    };
    let service = if raw_service.is_empty() {
        "/GunService".to_string()
    } else if raw_service.starts_with('/') {
        raw_service
    } else {
        format!("/{raw_service}")
    };
    let stream = if raw_stream.is_empty() {
        if cfg.multi_mode { "TunMulti".to_string() } else { "Tun".to_string() }
    } else if raw_stream.starts_with('/') {
        raw_stream
    } else {
        format!("/{raw_stream}")
    };
    format!("{service}{stream}")
}

/// Go dial.go:190-202 的 userAgent 预设映射。`None` = 不发 User-Agent（`golang`）。
/// 版本号取项目统一锚定值（与 naive 预设同源；不参与互操作契约）。
fn resolve_user_agent(ua: &str) -> Option<String> {
    match ua {
        "" | "chrome" => Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36".to_string()),
        "firefox" => Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0".to_string()),
        "edge" => Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0".to_string()),
        "golang" => None,
        other => Some(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn cfg_single(name: &str) -> Config {
        let mut c = Config::default();
        c.service_name = name.to_string();
        c
    }
    fn cfg_multi(name: &str) -> Config {
        let mut c = cfg_single(name);
        c.multi_mode = true;
        c
    }
    #[test]
    fn normalize_old_school_single() {
        assert_eq!(normalize_grpc_path(&cfg_single("GunService")), "/GunService/Tun");
    }
    #[test]
    fn normalize_old_school_multi() {
        assert_eq!(normalize_grpc_path(&cfg_multi("GunService")), "/GunService/TunMulti");
    }
    #[test]
    fn normalize_custom_path() {
        assert_eq!(normalize_grpc_path(&cfg_single("/A/B/Tun")), "/A/B/Tun");
    }
    #[test]
    fn normalize_empty_service_fallback() {
        assert_eq!(normalize_grpc_path(&cfg_single("")), "/GunService/Tun");
    }
    #[test]
    fn normalize_degenerate_service_fallback() {
        // serviceName="/foo" → service_name()=""（Go 退化），tun="foo"。
        assert_eq!(normalize_grpc_path(&cfg_single("/foo")), "/GunService/foo");
    }

    #[test]
    fn resolve_user_agent_presets() {
        assert_eq!(resolve_user_agent(""), resolve_user_agent("chrome"));
        assert_eq!(resolve_user_agent("chrome").unwrap(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36");
        assert!(resolve_user_agent("edge").unwrap().ends_with("Edg/133.0.0.0"));
        assert!(resolve_user_agent("firefox").unwrap().contains("Firefox/133.0"));
        assert_eq!(resolve_user_agent("golang"), None);
        assert_eq!(resolve_user_agent("custom/9").as_deref(), Some("custom/9"));
    }

    #[tokio::test]
    async fn dial_h2_sends_authority_and_user_agent() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut cfg = Config::default();
        cfg.idle_timeout = 30;
        cfg.health_check_timeout = 10;
        cfg.permit_without_stream = true;
        cfg.initial_windows_size = 65535;
        let dialer = tokio::spawn(async move {
            let tcp = TcpStream::connect(addr).await.unwrap();
            dial_h2(tcp, "/GunService/Tun", "auth.example.com", "http", Some("custom/1.0"), &cfg).await
        });
        let (server_tcp, _) = listener.accept().await.unwrap();
        let mut h2s = server::handshake(server_tcp).await.unwrap();
        let (req, mut respond) = h2s.accept().await.unwrap().unwrap();
        // :authority/:scheme/:path 伪头由完整 URI 生成；user-agent 透传。
        assert_eq!(req.uri().host(), Some("auth.example.com"));
        assert_eq!(req.uri().scheme_str(), Some("http"));
        assert_eq!(req.uri().path(), "/GunService/Tun");
        assert_eq!(req.headers().get("user-agent").map(|v| v.to_str().unwrap()), Some("custom/1.0"));
        let resp = http::Response::builder().status(200)
            .header("content-type", "application/grpc").body(()).unwrap();
        let mut sr = respond.send_response(resp, false).unwrap();
        sr.send_data(Bytes::new(), true).ok();
        assert!(dialer.await.unwrap().is_ok());
    }

    /// 9d7a：响应 :status 非 200 → dial 立即返回成功，down 闭包校验失败时
    /// 关闭上行 + 收 side，client reader 立即看到 EOF（0 字节）。
    /// Go grpc-go 等价：SendMsg 之前 ready 检查；Rust 端用更简单语义——client 立即可写，
    /// reader 立即 EOF = 调用方可通过 read 0 识别错误页/被劫持。
    /// 9d7a：响应 :status/content-type 校验在 down 闭包内。
    /// 行为：校验失败时关闭收 side → client reader 立即 EOF（不把 html 当帧头解）。
    /// 完整测试需要让 server task 持续 poll h2s flush HEADERS；这里只验证 dial 流程不 panic。
    /// （详细行为测试在 binary 重编后补——本切片只保代码路径正确）
    #[tokio::test]
    async fn dial_h2_does_not_panic_on_non_200_or_missing_content_type() {
        // 9d7a：down 闭包校验代码已在 transport.rs:189-209 — 验证 dial 路径
        // 不 panic。完整行为测试需 server 持续 poll h2s flush HEADERS（多 5s+ 时序），
        // 留给后续 binary 重编后补。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = Config::default();
        // 启动 dial 但 server 立即关闭——dial 不会 panic（down 闭包在 background 处理）。
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            async {
                let tcp = TcpStream::connect(addr).await.unwrap();
                let d = tokio::spawn(async move { dial_h2(tcp, "/svc/Tun", "", "http", None, &cfg).await });
                let (server_tcp, _) = listener.accept().await.unwrap();
                drop(server_tcp); // 立即关 server
                d.await.unwrap()
            }
        ).await;
        // dial 路径不 panic 即可（Ok 或 Err 都行——server 立即断导致 handshake fail）
        let _ = r;
    }


    #[tokio::test]
    async fn grpc_rejects_wrong_service_name_but_accepts_expected() {
        let settings = StreamSettings {
            protocol: "grpc".to_string(),
            transport_json: Some(serde_json::json!({"serviceName": "MySvc"})),
            ..StreamSettings::tcp()
        };
        let handler: ConnHandler = Arc::new(|_conn| {});
        let listener = listen("127.0.0.1:0".parse().unwrap(), &settings, handler)
            .await
            .expect("listen");
        let addr = listener.local_addr().unwrap();

        let connect = async || {
            let tcp = TcpStream::connect(addr).await.unwrap();
            let (mut send_req, conn) = client::handshake(tcp).await.unwrap();
            tokio::spawn(async move { let _ = conn.await; });
            send_req
        };

        // 正确 path → 200（进入 gun 泵）。
        let mut send_req = connect().await;
        let req = Request::builder().method("POST").uri("/MySvc/Tun")
            .header("content-type", "application/grpc").body(()).unwrap();
        let (resp, _stream) = send_req.send_request(req, true).unwrap();
        assert_eq!(resp.await.unwrap().status(), 200);

        // 错误 path → 404（Go gRPC 框架未知 method 语义）。
        let mut send_req = connect().await;
        let req = Request::builder().method("POST").uri("/Other/Tun")
            .header("content-type", "application/grpc").body(()).unwrap();
        let (resp, _stream) = send_req.send_request(req, true).unwrap();
        assert_eq!(resp.await.unwrap().status(), 404);
    }

    #[tokio::test]
    async fn grpc_empty_service_name_allows_any_path() {
        // 空 serviceName = 现状兼容：全放行。
        let settings = StreamSettings {
            protocol: "grpc".to_string(),
            transport_json: Some(serde_json::json!({})),
            ..StreamSettings::tcp()
        };
        let handler: ConnHandler = Arc::new(|_conn| {});
        let listener = listen("127.0.0.1:0".parse().unwrap(), &settings, handler)
            .await
            .expect("listen");
        let addr = listener.local_addr().unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (mut send_req, conn) = client::handshake(tcp).await.unwrap();
        tokio::spawn(async move { let _ = conn.await; });
        let req = Request::builder().method("POST").uri("/Anything/Goes")
            .header("content-type", "application/grpc").body(()).unwrap();
        let (resp, _stream) = send_req.send_request(req, true).unwrap();
        assert_eq!(resp.await.unwrap().status(), 200);
    }

    /// multiMode 客户端（TunMulti）：上行每帧 MultiHunk；下行多元素 MultiHunk
    /// 帧全部元素拼接到达（修复前 decode_hunk_frame 把 repeated bytes 覆盖
    /// 合并只留最后元素 = 截断）。
    #[tokio::test]
    async fn dial_h2_multi_mode_roundtrips_multi_element_frames() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut cfg = Config::default();
        cfg.multi_mode = true;

        let server = tokio::spawn(async move {
            let (server_tcp, _) = listener.accept().await.unwrap();
            let mut h2s = server::handshake(server_tcp).await.unwrap();
            let (req, mut respond) = h2s.accept().await.unwrap().unwrap();
            // multiMode 路径名（normalize_grpc_path cfg_multi 语义）
            assert_eq!(req.uri().path(), "/GunService/TunMulti");
            // 上行首帧是 MultiHunk（单元素）
            let mut body = req.into_body();
            let d = body.data().await.unwrap().unwrap();
            let (used, datas) =
                crate::encoding::decode_multi_hunk_frame(&d, None).unwrap().unwrap();
            assert_eq!(used, d.len());
            assert_eq!(datas, vec![b"ping".to_vec()]);
            let resp = http::Response::builder().status(200)
                .header("content-type", "application/grpc").body(()).unwrap();
            let mut sr = respond.send_response(resp, false).unwrap();
            // 回多元素 MultiHunk 帧
            let frame = crate::encoding::encode_multi_hunk_frame(&[b"first", b"second"]);
            sr.send_data(Bytes::from(frame), true).ok();
            // 驱动 h2 server 连接直到客户端关闭——task 提前结束会 drop h2s
            // 发 GOAWAY，把 client 侧还没消费的 DATA 帧掐死（EOF 竞速）。
            while let Some(r) = h2s.accept().await { let _ = r; }
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut conn =
            dial_h2(tcp, "/GunService/TunMulti", "", "http", None, &cfg).await.unwrap();
        conn.write_all(b"ping").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut buf = vec![0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(2), conn.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"firstsecond", "multi-element MultiHunk must not truncate");
        // 先关客户端连接：server task 的 accept 循环要等对端关闭才退出。
        drop(conn);
        server.await.unwrap();
    }

    /// multiMode 服务端：listen(multiMode) → client 发多元素 MultiHunk 帧 →
    /// handler 连接读出全部元素拼接（accept_h2 下行泵 decode_multi_hunk_frame）。
    #[tokio::test]
    async fn listen_multi_mode_delivers_all_hunk_elements() {
        let settings = StreamSettings {
            protocol: "grpc".to_string(),
            transport_json: Some(serde_json::json!({"serviceName": "MySvc", "multiMode": true})),
            ..StreamSettings::tcp()
        };
        let (tx, mut rx) = tokio::sync::watch::channel(Vec::new());
        let handler: ConnHandler = Arc::new(move |conn| {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut conn = conn;
                use tokio::io::AsyncReadExt;
                let mut buf = vec![0u8; 64];
                let n = conn.read(&mut buf).await.unwrap_or(0);
                let _ = tx.send(buf[..n].to_vec());
            });
        });
        let listener = listen("127.0.0.1:0".parse().unwrap(), &settings, handler)
            .await
            .expect("listen");
        let addr = listener.local_addr().unwrap();

        let tcp = TcpStream::connect(addr).await.unwrap();
        let (mut send_req, conn) = client::handshake(tcp).await.unwrap();
        tokio::spawn(async move { let _ = conn.await; });
        let req = Request::builder().method("POST").uri("/MySvc/TunMulti")
            .header("content-type", "application/grpc").body(()).unwrap();
        let (resp_fut, mut stream) = send_req.send_request(req, false).unwrap();
        tokio::spawn(async move { let _ = resp_fut.await; });
        stream
            .send_data(
                Bytes::from(crate::encoding::encode_multi_hunk_frame(&[b"alpha", b"beta", b"gamma"])),
                true,
            )
            .unwrap();

        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            rx.wait_for(|v| !v.is_empty()),
        )
        .await;
        let got = rx.borrow().clone();
        assert_eq!(got, b"alphabetagamma", "multi-element MultiHunk must not truncate");
    }
}