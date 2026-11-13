//! h3 请求面——Go `client.go:233-303` 的 `http3.Transport` 分支。
//!
//! `tlsSettings.alpn == ["h3"]` 时由 [`Config::h3`](crate::config::Config::h3) 标记，
//! 此后 storage 请求（会话 WAL 与 token/直连面）走 QUIC，而不是 hyper 的 h2/h1。
//! Go 的判据是 `slices.Equal(tlsConfig.NextProtocol, []string{"h3"})`——只问"是否
//! 单独是 h3"，因为 TCP 上没有服务端会用 h3 ALPN 应答（client.go:234 注释）。
//!
//! ## 与 splithttp `h3_client::H3Conn` 的分工（§3.5.2）
//!
//! 不复用其请求面：那是 splithttp 会话专用（`RequestMeta`/packet-up 语义 + 其
//! `Config`），本件是通用 `method/headers/body → status/body`（对象存储后端用）。
//! 共享的是 quic crate 的 CC 桥与窗口常量；QUIC/h3 装配按 Go xdrive 逐段对齐：
//!
//! | Go | Rust |
//! |---|---|
//! | `quic.Config{窗口/idle/keepalive}`（client.go:240-256） | [`H3Params::transport_config`] |
//! | `case "", "bbr", "reno":` 校验（:259-267） | [`apply_h3_cc`] |
//! | `http3.Transport.Dial` + `dial(ctx,"udp",addr)`（:269-297） | [`H3Client::connect`] / [`H3Client::resolve`] |
//! | `context.AfterFunc(connCtx, qconn.CloseWithError…)`（:296） | [`H3Conn::drop`] 显式关连接 |
//!
//! 归属：QUIC/h3 连接编排是协议方向件、单消费方（Go 亦内联在 `client.go`，无独立
//! 文件）⇒ `udf-promotion-candidate`（第二消费方出现时上浮）。

use std::{collections::BTreeMap, io, net::SocketAddr, sync::Arc, time::Duration};

use bytes::{Buf as _, Bytes};
use http::{Request, StatusCode};
use rustls::ClientConfig as RustlsClientConfig;
use xray_common::net::address::Address;
use xray_transport::memory_settings::QuicParamsConfig;

use crate::client::{ClientCore, OutRequest, REQUEST_PROGRESS_CHUNK, StallGuard, with_stall};

/// h3 单独 ALPN（Go `client.go:235` 的触发值；quinn 握手只协商一个）。
const H3_ALPN: &[u8] = b"h3";

/// quinn 客户端 Endpoint 缺省 bind（v4/v6 各一，对应 Go `net.ListenUDP("", nil)`）。
const BIND_V4: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
const BIND_V6: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0);

/// h3 SendRequest 类型（h3-quinn 承载，`Bytes` 载荷——同 splithttp 别名）。
type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// h3 装配参数（一次校验、逐单元共享）：池单元的工厂闭包不可失败，故把唯一
/// 可失败点（TLS 缺失 / quicParams 非法）提到 [`H3Params::new`]。
pub(crate) struct H3Params {
    tls: Arc<RustlsClientConfig>,
    fronting: Option<(Address, u16)>,
    quic_params: Option<QuicParamsConfig>,
    /// QUIC PING 周期（Go `h3KeepAlive`：只在 `xmux.hKeepAlivePeriod > 0` 时设置；
    /// h3 缺省**不发** keep-alive，见 client.go:130 注释）。
    keepalive: Option<Duration>,
}

/// h3 客户端：按 origin（`host:port`）懒建连接并复用（Go `http3.Transport` 的每
/// origin 一条连接；连接随 [`H3Conn`] 最后一个引用 drop 关闭）。
pub(crate) struct H3Client {
    params: Arc<H3Params>,
    conns: tokio::sync::Mutex<BTreeMap<String, Arc<H3Conn>>>,
}

/// 一条 h3 连接：quinn 连接 + h3 请求发送半（`send_request` 需 &mut ⇒ Mutex）。
struct H3Conn {
    /// 连接级任务账本（§3.5.6 ①类：driver 任务寿命 = 本连接；连接关闭即自终）。
    scope: xray_frame::scope::ComponentScope,
    send_req: tokio::sync::Mutex<H3SendRequest>,
    quinn: quinn::Connection,
}

impl Drop for H3Conn {
    fn drop(&mut self) {
        // quinn Endpoint 句柄在 connect 返回前已 drop，且 Endpoint drop 不终结连接
        //（splithttp H3Conn 同款实测）：不显式关，服务端只能干等 idle 超时
        //（Go client.go:296 `context.AfterFunc(connCtx, qconn.CloseWithError)`）。
        // 先关闸（拒新任务）再关连接 ⇒ driver 的 poll_close 随连接终结返回。
        self.scope.close_gate();
        self.quinn.close(quinn::VarInt::from_u32(0), b"client conn dropped");
    }
}

impl H3Params {
    /// 从客户端核取参数（`h3` 为真但无 TLS 设置 ⇒ 硬错：h3 恒 TLS）。
    pub(crate) fn new(core: &ClientCore) -> io::Result<Self> {
        let Some(tls) = core.tls.as_ref() else {
            return Err(invalid("xdrive h3 needs \"tlsSettings\" with \"alpn\": [\"h3\"]"));
        };
        Ok(Self {
            tls: Arc::clone(tls),
            fronting: core.fronting.clone(),
            quic_params: core.quic_params.clone(),
            keepalive: core.h3_keepalive,
        })
    }

    /// quinn `TransportConfig`（Go client.go:240-256 的 `quic.Config` 映射）。
    ///
    /// 窗口缺省沿用 quic crate 的 16MB 流窗 / 32MB 连接窗（bd wz2b W4：quinn 缺省
    /// 1.25MB 流窗在高 BDP 下钉带宽）；`quicParams` 显式值优先，`Max` 优先于
    /// `Init`（quinn 单窗 = Go 的增长上限，同 splithttp `build_h3_transport_config`）。
    fn transport_config(&self) -> io::Result<quinn::TransportConfig> {
        let mut cfg = quinn::TransportConfig::default();
        let (mut stream_win, mut conn_win) = (
            xray_transport_quic::config::DEFAULT_STREAM_RECEIVE_WINDOW,
            xray_transport_quic::config::DEFAULT_CONNECTION_RECEIVE_WINDOW,
        );
        if let Some(qp) = self.quic_params.as_ref() {
            if qp.init_stream_receive_window > 0 {
                stream_win = qp.init_stream_receive_window;
            }
            if qp.max_stream_receive_window > 0 {
                stream_win = qp.max_stream_receive_window;
            }
            if qp.init_connection_receive_window > 0 {
                conn_win = qp.init_connection_receive_window;
            }
            if qp.max_connection_receive_window > 0 {
                conn_win = qp.max_connection_receive_window;
            }
        }
        cfg.stream_receive_window(varint(stream_win, "streamReceiveWindow")?);
        cfg.receive_window(varint(conn_win, "connectionReceiveWindow")?);
        if let Some(n) =
            self.quic_params.as_ref().map(|qp| qp.max_incoming_streams).filter(|n| *n > 0)
        {
            let n = u64::try_from(n).map_err(|_| invalid("maxIncomingStreams out of u64 range"))?;
            cfg.max_concurrent_bidi_streams(varint(n, "maxIncomingStreams")?);
        }
        // Go: `MaxIdleTimeout: time.Duration(qp.MaxIdleTimeout) * time.Second`——0 交底层
        // 缺省（quinn 30s = quic-go 30s），负数 = 禁用。
        match self.quic_params.as_ref().map_or(0, |qp| qp.max_idle_timeout) {
            0 => {},
            secs if secs > 0 => {
                cfg.max_idle_timeout(Some(
                    quinn::IdleTimeout::try_from(Duration::from_secs(secs.unsigned_abs()))
                        .map_err(|e| invalid(&format!("maxIdleTimeout: {e}")))?,
                ));
            },
            _ => {
                cfg.max_idle_timeout(None);
            },
        }
        cfg.keep_alive_interval(self.keepalive);
        if self.quic_params.as_ref().is_some_and(|qp| qp.disable_gso) {
            cfg.enable_segmentation_offload(false);
        }
        let slot = xray_transport_quic::congestion_swappable::install_swappable_cc(&mut cfg);
        apply_h3_cc(&slot, self.quic_params.as_ref())?;
        Ok(cfg)
    }
}

impl H3Client {
    pub(crate) fn new(params: Arc<H3Params>) -> Self {
        Self { params, conns: tokio::sync::Mutex::new(BTreeMap::new()) }
    }

    /// 一条请求：method/headers/body → status/body（Go `RoundTrip` 的全量缓冲形态，
    /// 与 [`crate::client::service_round_trip`] 的 h2/h1 面同语义同停滞口径）。
    ///
    /// # Errors
    /// 非 https 目标、建连/流错误、或 `stall` 内无字节推进（[`crate::client::err_stalled`]）。
    pub(crate) async fn round_trip(
        &self,
        req: OutRequest,
        stall: Duration,
    ) -> io::Result<(StatusCode, Bytes)> {
        let uri = req.uri.clone();
        // Go http3.Transport 只发 https URL（h3 恒 TLS）；http 目标在此 fail-visible。
        if uri.scheme_str() != Some("https") {
            return Err(invalid(&format!("h3 requires an https destination, got {uri}")));
        }
        let host = uri.host().ok_or_else(|| invalid("bad address"))?.to_string();
        let port = uri.port_u16().unwrap_or(443);
        let guard = Arc::new(StallGuard::new(xray_frame::compat::clock()));

        let conn = with_stall(self.conn(&host, port), &guard, stall).await?;

        let mut builder = Request::builder().method(req.method).uri(uri);
        for (key, value) in req.headers {
            // 伪头与 URI 同源：显式 host/content-length 会与 :authority 冲突。
            if key.eq_ignore_ascii_case("host") || key.eq_ignore_ascii_case("content-length") {
                continue;
            }
            builder = builder.header(key, value);
        }
        let request = builder.body(()).map_err(io::Error::other)?;
        let body = req.body.unwrap_or_default();

        let mut send_req = conn.send_req.lock().await;
        let mut stream = with_stall(
            async { send_req.send_request(request).await.map_err(h3_err("send_request")) },
            &guard,
            stall,
        )
        .await?;
        drop(send_req);

        // 请求体按 16KiB 帧推进（Go `progressBody.Read` 上限；与 h2 路径同节拍）。
        let mut pos = 0;
        while pos < body.len() {
            let end = (pos + REQUEST_PROGRESS_CHUNK).min(body.len());
            let chunk = body.slice(pos..end);
            pos = end;
            with_stall(
                async { stream.send_data(chunk).await.map_err(h3_err("send_data")) },
                &guard,
                stall,
            )
            .await?;
            guard.bump();
        }
        with_stall(async { stream.finish().await.map_err(h3_err("finish")) }, &guard, stall)
            .await?;

        let response = with_stall(
            async { stream.recv_response().await.map_err(h3_err("recv_response")) },
            &guard,
            stall,
        )
        .await?;
        guard.bump();
        let status = response.status();

        let mut payload = Vec::new();
        loop {
            let chunk = with_stall(
                async { stream.recv_data().await.map_err(h3_err("recv_data")) },
                &guard,
                stall,
            )
            .await?;
            match chunk {
                Some(data) => {
                    payload.extend_from_slice(data.chunk());
                    guard.bump();
                },
                None => break,
            }
        }
        Ok((status, payload.into()))
    }

    /// 取（必要时建立）origin 连接。握手失败不落缓存（下次重试）。
    async fn conn(&self, host: &str, port: u16) -> io::Result<Arc<H3Conn>> {
        let key = format!("{host}:{port}");
        if let Some(conn) = self.conns.lock().await.get(&key) {
            if conn.quinn.close_reason().is_none() {
                return Ok(Arc::clone(conn));
            }
        }
        let conn = Arc::new(self.connect(host, port).await?);
        let mut conns = self.conns.lock().await;
        // 并发建连竞态：保留先插入者，多出的一条随 Arc drop 关闭。
        Ok(Arc::clone(conns.entry(key).or_insert(conn)))
    }

    /// QUIC 握手 + h3 会话（Go `http3.Transport.Dial`，client.go:269-297）。
    async fn connect(&self, host: &str, port: u16) -> io::Result<H3Conn> {
        let mut tls = (*self.params.tls).clone();
        tls.alpn_protocols = vec![H3_ALPN.to_vec()];
        let mut cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls)
                .map_err(|e| io::Error::other(format!("QuicClientConfig: {e}")))?,
        ));
        cfg.transport_config(Arc::new(self.params.transport_config()?));

        let addr = self.resolve(host, port).await?;
        let bind = if addr.is_ipv4() { BIND_V4 } else { BIND_V6 };
        let sock = xray_transport::sockopt::bind_udp_endpoint(
            bind,
            &xray_transport::sockopt::SocketOptions::default(),
        )
        .map_err(|e| io::Error::other(format!("quinn Endpoint: {e}")))?;
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            sock,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|e| io::Error::other(format!("quinn Endpoint: {e}")))?;
        endpoint.set_default_client_config(cfg);

        // SNI = URL host（Go `tlsConfig.GetTLSConfig(tls.WithDestination(host))`：fronting
        // 只覆盖拨号目标，不改 SNI）。
        let quinn_conn = endpoint
            .connect(addr, host)
            .map_err(|e| io::Error::other(format!("quinn connect initiate: {e}")))?
            .await
            .map_err(|e| io::Error::other(format!("quinn connect: {e}")))?;
        let (mut driver, send_req) = h3::client::new(h3_quinn::Connection::new(quinn_conn.clone()))
            .await
            .map_err(|e| io::Error::other(format!("h3::client::new: {e}")))?;
        // ①类托管：driver 是连接级任务（寿命 = 本 QUIC 连接），挂连接自有账本。
        let scope = xray_frame::scope::ComponentScope::new("xdrive-h3-conn");
        scope
            .spawn(async move {
                let _ = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
            })
            .map_err(|e| io::Error::other(format!("h3 driver spawn: {e}")))?;
        Ok(H3Conn { scope, send_req: tokio::sync::Mutex::new(send_req), quinn: quinn_conn })
    }

    /// 拨号目标解析：fronting 覆盖地址（端口 0 = 沿用 URL 端口），同 TCP 连接器语义。
    async fn resolve(&self, host: &str, port: u16) -> io::Result<SocketAddr> {
        let (addr, port) = match self.params.fronting.as_ref() {
            Some((address, fronting_port)) => {
                (address.clone(), if *fronting_port != 0 { *fronting_port } else { port })
            },
            None => (Address::new_domain(host), port),
        };
        if let Some(ip) = addr.ip() {
            return Ok(SocketAddr::new(ip, port));
        }
        let name = addr.as_domain().unwrap_or_default();
        tokio::net::lookup_host((name, port))
            .await
            .map_err(|e| io::Error::other(format!("failed to dial to dest: {e}")))?
            .next()
            .ok_or_else(|| {
                io::Error::other(format!("failed to dial to dest: no address for {host}"))
            })
    }
}

/// 拥塞控制（Go client.go:259-268）：h3 只接受 `""`/`bbr`/`reno`，其余（含 `brutal`
/// 与 `force-brutal`）硬错——brutal 是给 Hysteria 服务端的，不是给普通服务用的。
///
/// `""`/`reno` 不装算法（Go 两个空 case 体 ⇒ quic-go 缺省 CUBIC）；`bbr` 装 BBR。
/// 转调上浮实现
/// [`apply_quic_params_cc`](xray_transport_quic::congestion_swappable::apply_quic_params_cc)
/// （G7：全仓唯一 CC 翻译件，本侧语义 = `CcSemantics::XdriveH3`）。
fn apply_h3_cc(
    slot: &xray_transport_quic::congestion_swappable::HysteriaCCSlot,
    quic_params: Option<&QuicParamsConfig>,
) -> io::Result<()> {
    use xray_transport_quic::congestion_swappable::{CcSemantics, apply_quic_params_cc};

    apply_quic_params_cc(slot, quic_params, CcSemantics::XdriveH3)
        .map_err(|e| invalid(&e.to_string()))
}

fn h3_err(stage: &'static str) -> impl Fn(h3::error::StreamError) -> io::Error + Copy + Send {
    move |e| io::Error::other(format!("h3 {stage}: {e}"))
}

fn varint(value: u64, what: &str) -> io::Result<quinn::VarInt> {
    quinn::VarInt::from_u64(value).map_err(|e| invalid(&format!("{what} VarInt: {e}")))
}

fn invalid(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, why.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h3_cc_matches_go_switch() {
        use xray_transport_quic::congestion_swappable::HysteriaCCSlot;

        // Go `case "", "bbr", "reno":` 放行；`""`/`reno` 保持底层缺省（CUBIC）。
        let slot = HysteriaCCSlot::new();
        for congestion in ["", "reno"] {
            let qp = QuicParamsConfig { congestion: congestion.to_string(), ..Default::default() };
            apply_h3_cc(&slot, Some(&qp)).unwrap();
            assert!(!slot.has_active(), "{congestion:?} must keep the quinn default CC");
        }
        // `bbr` 装 BBR（走 fallback 通道，非 hysteria active）。
        let qp = QuicParamsConfig { congestion: "BBR".to_string(), ..Default::default() };
        apply_h3_cc(&slot, Some(&qp)).unwrap();
        assert!(slot.is_bbr(), "bbr（大小写不敏感）must install BBR");

        // 其余一律硬错（Go：brutal 是 Hysteria 的东西，不是给普通服务用的）。
        for congestion in ["brutal", "force-brutal", "cubic"] {
            let qp = QuicParamsConfig { congestion: congestion.to_string(), ..Default::default() };
            let err = apply_h3_cc(&slot, Some(&qp)).unwrap_err();
            assert!(
                err.to_string().contains("unsupported congestion control over h3"),
                "{congestion}: {err}"
            );
        }
        // quicParams 缺失 = 底层缺省。
        apply_h3_cc(&slot, None).unwrap();
    }

    #[tokio::test]
    async fn non_https_is_rejected() {
        // 明文目标在拨号前就拒（不会真去建连）。
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls = RustlsClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let params =
            H3Params { tls: Arc::new(tls), fronting: None, quic_params: None, keepalive: None };
        let client = H3Client::new(Arc::new(params));
        let req = OutRequest {
            method: http::Method::GET,
            uri: "http://127.0.0.1:1/x".parse().expect("uri"),
            headers: Vec::new(),
            body: None,
        };
        let err = client.round_trip(req, Duration::from_secs(1)).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("https"), "{err}");
    }
}
