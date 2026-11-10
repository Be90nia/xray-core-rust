//! HysteriaTransport 的 quinn 实现（5lb 切片1b）。
//!
//! 用 quinn 拨号 QUIC + h3 crate 发 HTTP/3 POST /auth 完成认证。
//!
//! ## 协议流程
//!
//! 1. quinn 拨号 QUIC（ALPN=`h3`）
//! 2. h3 client 发 POST `https://hysteria/auth`：
//!    - Headers: `Hysteria-Auth`/`Hysteria-CC-RX`/`Hysteria-Padding`
//!    - Body: 空
//! 3. 期望 status=233（StatusAuthOK）；Response Headers 含 `Hysteria-UDP`/`Hysteria-CC-RX`
//! 4. 返回 `Arc<dyn QuicConn>`（QuinnQuicConn），后续 `open_stream` 直接用 quinn open_bi
//!
//! 参考：librarian 调研 hyproxy/hysteria 1.x 协议 + Xray Go
//! `transport/internet/hysteria/dialer.go`。

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, LazyLock},
    time::Duration,
};

use quinn::{
    ClientConfig as QuinnClientConfig, Connection as QuinnConnection, Endpoint,
    crypto::rustls::QuicClientConfig,
};
use rustls::client::{ClientSessionMemoryCache, ClientSessionStore};

use crate::salamander_socket::UdpObfs;

/// 进程级 hysteria client TLS 会话缓存，容量 128 对齐 Go `globalSessionCache`
/// （`transport/internet/tls/config.go:24` `tls.NewLRUClientSessionCache(128)`）。
///
/// 0-RTT（Go `tr.DialEarly` parity）依赖跨拨号的会话票据：rustls builder 默认的
/// resumption store 随 ClientConfig 新建，而本 crate 每次拨号新建 config，票据无法
/// 存续，`into_0rtt` 永远拿不到密钥。所有拨号共享此 store 后，二次连接即可 0-RTT。
static GLOBAL_CLIENT_SESSION_STORE: LazyLock<Arc<ClientSessionMemoryCache>> =
    LazyLock::new(|| Arc::new(ClientSessionMemoryCache::new(128)));

use crate::{
    conn::{QuicConn, QuicStream},
    dialer::{DialDestination, HysteriaTransport, QuicConfig},
    quinn_adapter::{QuinnQuicConn, QuinnQuicStream},
};

/// Hysteria auth URL（POST 目标）。
const AUTH_URL: &str = "https://hysteria/auth";
/// Auth 成功状态码（Go `StatusAuthOK = 233`）。
const STATUS_AUTH_OK: u16 = 233;
/// Auth padding 最小/最大字节数。
const AUTH_PADDING_MIN: usize = 256;
const AUTH_PADDING_MAX: usize = 2048;

/// 连接进入 connected 的时限（Go parity：quic-go `HandshakeIdleTimeout` 默认 5s，
/// `internal/protocol/params.go` `DefaultHandshakeIdleTimeout`；`handshakeTimeout() = 2 * 它`）。
///
/// hysteria dialer 不覆盖该值——Go `dialer.go` 的 `&quic.Config{...}` 只设
/// `MaxIdleTimeout`，故同场景 Go 5s 报错。quinn 无独立握手窗，本 crate 只下发
/// `max_idle_timeout`（默认 30s）⇒ 服务端不应答时会静默烧满 30s 才以
/// 「h3 recv_response: Connection error: Timeout」显现（真实 CI 症状，bd gqpck）。
///
/// **只约束「握手完成」，不约束 h3 auth**：0-RTT 与 1-RTT 一视同仁（0-RTT 只是提前发
/// 数据，握手仍在后台完成）；auth 段与 Go 一致仅受 `max_idle_timeout` 约束（用户
/// 100% 复刻铁律，防回退测试 `slow_auth_response_beyond_handshake_window_still_succeeds`）。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// 握手窗超时（0-RTT / 1-RTT 两型入口共用）。
fn handshake_timeout_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!(
            "phase=handshake hysteria QUIC handshake timeout after {HANDSHAKE_TIMEOUT:?} (Go quic-go HandshakeIdleTimeout default)"
        ),
    )
}

/// 握手窗：`connected` 类 future 必须 5s 内 resolve，否则报握手超时。
/// 0-RTT / 1-RTT 两型入口共用（Go quic-go `HandshakeIdleTimeout` 对二者一视同仁）。
async fn within_handshake_window<F: Future>(connected: F) -> Result<F::Output, io::Error> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, connected).await.map_err(|_| handshake_timeout_error())
}

/// 给既有错误补阶段标注（不改变错误类别与时长；CI 再出 30s Timeout 时可区分卡在握手还是 auth）。
fn annotate_phase(phase: &str, e: io::Error) -> io::Error {
    io::Error::new(e.kind(), format!("phase={phase} {e}"))
}

/// quinn + h3 实现的 [`HysteriaTransport`]。
pub struct QuinnHysteriaTransport {
    client_config: QuinnClientConfig,
    bind_addr: SocketAddr,
    /// UDP 混淆（salamander / gecko，对应 Go dialer.go:170 `udpmaskManager`，None = 不包装）。
    obfs: Option<UdpObfs>,
    /// QUIC 端点 UDP socket 选项（缓冲调谐消费；默认空 = Go quic-go `wrapConn`
    /// 8MB 下限语义，见 [`xray_transport::sockopt::bind_udp_endpoint`]）。
    sockopt: xray_transport::sockopt::SocketOptions,
}

impl QuinnHysteriaTransport {
    /// 构造。
    ///
    /// # 参数
    /// - `tls_config`：rustls 客户端配置（不含 ALPN）。ALPN=h3 自动追加。
    /// - `bind_addr`：本地 UDP bind 地址（0.0.0.0:0 表示任意）。
    pub fn new(mut tls_config: rustls::ClientConfig, bind_addr: SocketAddr) -> io::Result<Self> {
        // ponytail: hysteria 协议固定 ALPN=h3（librarian 调研证实）
        tls_config.alpn_protocols = vec![b"h3".to_vec()];
        // 0-RTT 前提：rustls enable_early_data 默认 false，而 quinn 的
        // QuicClientConfig::try_from 不补（仅 quinn 内部构造路径置 true，见
        // vendor/quinn-proto/src/crypto/rustls.rs TryFrom impl）——不置 true 则
        // ClientHello 不带 early_data 扩展，into_0rtt 恒 Err。Resumption::disabled()
        // 时无 PSK 可用，此标志不改变恒 1-RTT 的禁用语义。
        tls_config.enable_early_data = true;
        // 会话票据共享（0-RTT/DialEarly parity 前提，见 GLOBAL_CLIENT_SESSION_STORE）。
        // pwh6 `enableSessionResumption=false` 时 xray_tls 已置 `Resumption::disabled()`
        // （store=NoClientSessionStorage），此处尊重禁用不覆盖——该 transport 恒走 1-RTT。
        // Debug 字符串检测与 xray-tls client_config.rs 测试先例同款（Resumption 无 pub 字段）。
        if !format!("{:?}", tls_config.resumption).contains("NoClientSessionStorage") {
            tls_config.resumption = rustls::client::Resumption::store(Arc::clone(
                &GLOBAL_CLIENT_SESSION_STORE,
            )
                as Arc<dyn ClientSessionStore>);
        }
        let quic = QuicClientConfig::try_from(Arc::new(tls_config))
            .map_err(|e| io::Error::other(format!("quinn QuicClientConfig: {e}")))?;
        Ok(Self {
            client_config: QuinnClientConfig::new(Arc::new(quic)),
            bind_addr,
            obfs: None,
            sockopt: xray_transport::sockopt::SocketOptions::default(),
        })
    }

    /// 注入 UDP 混淆（salamander / gecko；builder 风格，None = 不包装）。
    #[must_use]
    pub fn with_obfs(mut self, obfs: Option<UdpObfs>) -> Self {
        self.obfs = obfs;
        self
    }

    /// 注入 QUIC 端点 socket 选项（UDP 缓冲调谐；builder 风格）。
    #[must_use]
    pub fn with_sockopt(mut self, sockopt: xray_transport::sockopt::SocketOptions) -> Self {
        self.sockopt = sockopt;
        self
    }
}

impl HysteriaTransport for QuinnHysteriaTransport {
    fn dial_and_authenticate(
        &self,
        dest: &DialDestination,
        quic_config: &QuicConfig,
        auth_token: &str,
        brutal_down_bps: u64,
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<Arc<dyn QuicConn>>> + Send>> {
        let dest_addr = dest.udp_addr;
        let host = dest.host.clone();
        let mut client_config = self.client_config.clone();
        let bind_addr = self.bind_addr;
        let auth_token = auth_token.to_string();
        let quic_cfg = quic_config.clone();
        let obfs = self.obfs.clone();
        let sockopt = self.sockopt.clone();
        Box::pin(async move {
            // 1. quinn endpoint（transport config 含可热切换 CC factory，auth 后协商）
            let (transport_cfg, cc_slot) =
                crate::quinn_adapter::build_hysteria_transport_config(&quic_cfg);
            client_config.transport_config(Arc::new(transport_cfg));
            // obfs：UDP socket 包混淆（salamander XOR / gecko 分片）后经 abstract
            // socket 交给 quinn（对应 Go dialer.go:170-179 pktConn 包装后再建 quic.Transport）
            let mut endpoint = match &obfs {
                Some(kind) => kind.client_endpoint(bind_addr, &sockopt).await?,
                None => {
                    let std_sock = xray_transport::sockopt::bind_udp_endpoint(bind_addr, &sockopt)?;
                    Endpoint::new(
                        quinn::EndpointConfig::default(),
                        None,
                        std_sock,
                        Arc::new(quinn::TokioRuntime),
                    )
                    .map_err(|e| io::Error::other(format!("quinn endpoint: {e}")))?
                },
            };
            endpoint.set_default_client_config(client_config);

            let connecting = endpoint
                .connect(dest_addr, &host)
                .map_err(|e| io::Error::other(format!("quinn connect initiate: {e}")))?;

            // 2./3. QUIC 拨号 + h3 auth（Go dialer.go:154 `tr.DialEarly` parity）：
            // store 有会话票据时 into_0rtt 立即返回连接，h3 auth 在 0-RTT 中发出（省 1-RTT）；
            // 首连/禁用 resumption 时 Err → 正常等 1-RTT。0-RTT 被服务端拒绝时 auth 流报
            // ZeroRttRejected，dial 失败交上层重连——与 Go quic-go Err0RTTRejected → dial
            // 返回 err → clientManager 重连同型，不加额外重试。
            //
            // 握手窗与 auth 段按 Go 语义分开（用户 100% 复刻铁律）：
            // - **连接进入 connected**：受 [`HANDSHAKE_TIMEOUT`]（5s，quic-go
            //   `HandshakeIdleTimeout` 默认）约束——0-RTT 与 1-RTT 一视同仁（0-RTT 只是
            //   提前发数据，握手仍在后台完成，quic-go 的超时照样计）。
            // - **h3 POST /auth 的应答**：不受 5s 窗，只受 `max_idle_timeout`（30s）约束 —— Go
            //   该段同样无专门窗 ⇒ auth 慢应答（>5s）不得被截断。
            // 错误路径带 `phase=handshake` / `phase=auth` 标注：CI 再出 30s Timeout 时可
            // 区分卡在哪一段（不改超时时长）。
            let (conn, h3_keepalive) = match connecting.into_0rtt() {
                Ok((conn, zero_rtt)) => {
                    crate::LOG.debug("hysteria dialing with 0-RTT attempt");
                    // 0-RTT：auth 请求随 early data 发出，握手仍在后台完成 ⇒ 握手窗必须与
                    // auth **并发**跑（先等握手再发 auth 会丢掉 0-RTT 提前发请求的语义）。
                    // `zero_rtt`（into_0rtt 返回的 future）恰在握手完成时 resolve ⇒
                    // - 握手先完成 ⇒ 转 auth（无握手段窗）；
                    // - auth 先完成 ⇒ 应答以握手完成为前提，握手必然已完成，直接采信；
                    // - 5s 内握手没完成 ⇒ 整个 dial 报握手超时（Go 同款）。
                    // 0-RTT 是否被服务端接受与既有行为一致地不检查（诊断 §5.2 另立票）。
                    // 内层块收窄 auth/handshake 对 conn 的借用，块结束即放行 conn 的 move。
                    let h3 = {
                        let auth = authenticate_via_h3(&conn, &auth_token, brutal_down_bps);
                        tokio::pin!(auth);
                        tokio::pin!(zero_rtt);
                        let handshake = within_handshake_window(&mut zero_rtt);
                        tokio::pin!(handshake);
                        tokio::select! {
                            hs = &mut handshake => match hs {
                                // 握手完成 ⇒ 转 auth（无握手段窗；idle 30s 兜底，Go 同）
                                Ok(_) => {
                                    let r = auth.await;
                                    r.map_err(|e| annotate_phase("auth", e))
                                },
                                // 握手窗先到 ⇒ Go 同款握手超时
                                Err(e) => Err(e),
                            },
                            // auth 先完成 ⇒ 握手必已完成
                            a = &mut auth => a.map_err(|e| annotate_phase("auth", e)),
                        }
                    };
                    (conn, h3?)
                },
                Err(connecting) => {
                    // 1-RTT：`connecting.await` 即握手等待，套同一握手窗
                    let conn = match within_handshake_window(connecting).await {
                        // 已带 phase=handshake 标注
                        Err(e) => return Err(e),
                        Ok(conn) => conn,
                    };
                    let conn = conn.map_err(|e| {
                        annotate_phase("handshake", io::Error::other(format!("quinn connect: {e}")))
                    })?;
                    let h3 = authenticate_via_h3(&conn, &auth_token, brutal_down_bps)
                        .await
                        .map_err(|e| annotate_phase("auth", e))?;
                    (conn, h3)
                },
            };

            // 3.5 CC 协商（Go dialer.go:229-243 switch）：
            // down = 响应 Hysteria-CC-RX（服务端下行容量）。
            if let Err(e) = crate::congestion::quinn_bridge::apply_negotiated(
                &cc_slot,
                &quic_cfg.congestion,
                &quic_cfg.bbr_profile,
                quic_cfg.brutal_up,
                h3_keepalive.cc_rx_down,
                quic_cfg.brutal_disable_loss_compensation,
            ) {
                crate::LOG.warn(format!(
                    "error={e} hysteria congestion negotiation failed, keeping default"
                ));
            }

            // 4. 包装返回：endpoint 必须保活（drop 会关闭 QUIC 连接），h3 保活项挂在 conn 上。
            // ponytail: Arc<QuinnQuicConn> → Arc<dyn QuicConn> 需 explicit cast
            let quic_conn = QuinnQuicConn::new(conn)
                .with_endpoint(endpoint)
                .with_cc_slot(cc_slot)
                .with_h3_keepalive(Box::new(h3_keepalive));
            Ok(Arc::new(quic_conn) as Arc<dyn QuicConn>)
        })
    }

    fn open_stream(
        &self,
        conn: &Arc<dyn QuicConn>,
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<Arc<dyn QuicStream>>> + Send>> {
        let conn = Arc::clone(conn);
        Box::pin(async move {
            let qconn = conn
                .as_quinn_connection()
                .ok_or_else(|| io::Error::other("transport: not a quinn-backed QuicConn"))?;
            let (send, recv) = qconn
                .open_bi()
                .await
                .map_err(|e| io::Error::other(format!("quinn open_bi: {e}")))?;
            let local = conn.local_addr();
            let remote = conn.remote_addr();
            Ok(Arc::new(QuinnQuicStream::new(send, recv, local, remote)) as Arc<dyn QuicStream>)
        })
    }
}

/// 用 h3 + h3-quinn 发 POST /auth 验证服务端。
///
/// 返回一个 `Box<dyn Any + Send>` 保活项，调用方必须持有到 QUIC 连接生命周期结束。
///
/// # h3 保活机制
///
/// h3 0.0.8 的客户端 `Connection`（driver）必须持续 `poll_close` 才能推进 HTTP/3
/// control / QPACK stream。`SendRequest::drop` 在成为最后一个 sender 时会发起
/// `H3_NO_ERROR` 关闭整条 QUIC 连接。hysteria 认证后要用同一条 QUIC 连接开 raw bidi
/// stream，因此这里：
/// 1. spawn 后台 task 持续 `poll_close` 驱动 h3 连接；
/// 2. 额外 clone 一份 `SendRequest`（sender_count 由 2 减到 1，不触发关闭），与 driver task 的
///    JoinHandle 一同返回给调用方保活，直到 conn drop。
async fn authenticate_via_h3(
    conn: &QuinnConnection,
    auth_token: &str,
    brutal_down_bps: u64,
) -> io::Result<H3Keepalive> {
    let h3_conn = h3_quinn::Connection::new(conn.clone());
    let (mut driver, mut send_req) = h3::client::new(h3_conn)
        .await
        .map_err(|e| io::Error::other(format!("h3 client new: {e}")))?;

    let padding = random_auth_padding();
    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(AUTH_URL)
        .header("Hysteria-Auth", auth_token)
        // Go dialer.go:203 请求头发 BrutalDown（客户端下行容量），非 BrutalUp
        .header("Hysteria-CC-RX", brutal_down_bps.to_string())
        .header("Hysteria-Padding", padding)
        .body(())
        .expect("static request build");

    let mut stream = send_req
        .send_request(req)
        .await
        .map_err(|e| io::Error::other(format!("h3 send_request: {e}")))?;
    stream.finish().await.map_err(|e| io::Error::other(format!("h3 stream finish: {e}")))?;

    let resp = stream
        .recv_response()
        .await
        .map_err(|e| io::Error::other(format!("h3 recv_response: {e}")))?;

    if resp.status().as_u16() != STATUS_AUTH_OK {
        return Err(io::Error::other(format!(
            "hysteria auth failed: status {} (expected {})",
            resp.status(),
            STATUS_AUTH_OK
        )));
    }

    // 解析响应头（Go dialer.go:224-225）：
    // - Hysteria-UDP：服务端是否启用 UDP（strconv.FormatBool 编码）
    // - Hysteria-CC-RX：服务端 BrutalDown → 客户端 UseBrutal(min(BrutalUp, down)) 的 down
    let udp_enabled = resp
        .headers()
        .get("Hysteria-UDP")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);
    let cc_rx_down = resp
        .headers()
        .get("Hysteria-CC-RX")
        .and_then(|v| v.to_str().ok())
        .map(|s| if s.eq_ignore_ascii_case("auto") { 0 } else { s.parse::<u64>().unwrap_or(0) })
        .unwrap_or(0);
    // drop request stream（sender_count 仍由 send_req 维持）
    drop(stream);

    // 持续 poll h3 driver：推进 control/QPACK stream（读取服务端 SETTINGS、QPACK encoder 流）。
    // h3 官方测试在 client_fut 中 tokio::join! 同等 driver future；hysteria 用独立 task
    // 保活+推进，直到连接关闭（poll_close 返回）。
    #[allow(
        clippy::disallowed_methods,
        reason = "②豁免（bd kwevg · §3.5.6）：数据面连接任务（h3 driver 保活）；driver 句柄在握（driver_task 随宿主 drop/显式 abort 收口），socket 关闭驱动即退，寿命不越所属连接，不迁托管口"
    )]
    let driver_task = tokio::spawn(async move {
        use std::future::poll_fn;
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
    });
    let send_req_keepalive = send_req.clone();

    Ok(H3Keepalive { driver_task, send_req: send_req_keepalive, udp_enabled, cc_rx_down })
}

/// h3 auth 保活项 + 协商结果。
///
/// driver/send_req 必须持有到 QUIC 连接生命周期结束（见 `authenticate_via_h3` 文档）；
/// udp_enabled/cc_rx_down 是服务端响应头解析结果，供拥塞控制选择
/// （Go：`UseBrutal(conn, min(BrutalUp, down))`，down=0 或 BrutalUp=0 时退 BBR）。
pub struct H3Keepalive {
    #[allow(dead_code)] // driver/send_req 刻意持有到 QUIC 连接终期（drop 即 H3_NO_ERROR 关连接）
    pub driver_task: tokio::task::JoinHandle<()>,
    #[allow(dead_code)] // 同 driver_task：保活项，本体无需读取
    pub send_req: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    /// 服务端 Hysteria-UDP 响应头（是否启用 UDP relay）。
    pub udp_enabled: bool,
    /// 服务端 Hysteria-CC-RX 响应头（服务端下行容量，Brutal 协商用）。
    pub cc_rx_down: u64,
}

/// 生成随机 auth padding（256~2048 字节，hex 编码）。
fn random_auth_padding() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let len = rng.random_range(AUTH_PADDING_MIN..=AUTH_PADDING_MAX);
    let bytes: Vec<u8> = (0..len).map(|_| rng.random::<u8>()).collect();
    hex::encode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 确保 rustls CryptoProvider 在并行测试中只初始化一次
    fn ensure_crypto_provider() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[test]
    fn random_auth_padding_length_in_range() {
        for _ in 0..20 {
            let p = random_auth_padding();
            let byte_len = p.len() / 2;
            assert!(
                (AUTH_PADDING_MIN..=AUTH_PADDING_MAX).contains(&byte_len),
                "padding byte len {byte_len} not in range"
            );
            assert!(p.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn new_sets_alpn_h3_and_constructs() {
        ensure_crypto_provider();
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let t = QuinnHysteriaTransport::new(tls, "127.0.0.1:0".parse().unwrap());
        assert!(t.is_ok());
    }

    /// 0-RTT 测试共用验证器：auth == "test-secret" ⇒ "user"。
    struct TestValidator;
    impl crate::hub::AuthValidator for TestValidator {
        fn validate(&self, auth: &str) -> Option<String> {
            if auth == "test-secret" { Some("user".into()) } else { None }
        }

        fn count(&self) -> usize {
            1
        }
    }

    /// 慢验证器（防回退测试用）：auth 应答延迟 `delay` 才返回。
    /// `AuthValidator::validate` 是 sync trait ⇒ 只能阻塞；测试跑在 multi_thread(2) 上，
    /// 阻塞单个 worker 不冻结客户端任务（真实墙钟，模拟「服务端 auth 慢应答」）。
    struct SlowValidator(std::time::Duration);
    impl crate::hub::AuthValidator for SlowValidator {
        fn validate(&self, auth: &str) -> Option<String> {
            if auth == "test-secret" {
                std::thread::sleep(self.0);
                Some("user".into())
            } else {
                None
            }
        }

        fn count(&self) -> usize {
            1
        }
    }

    /// 0-RTT 测试共用：自签证书（SAN = `sni`）+ QuinnListenerFactory server（auth="test-secret"）。
    /// 返回 (server_addr, listener, client_trust_anchors)；listener 须保活至断言结束。
    ///
    /// `sni` 由用例传入且**各用例唯一**：进程级 [`GLOBAL_CLIENT_SESSION_STORE`] 的 key
    /// 只有 ServerName，而 `take_tls13_ticket` 取出即删 ⇒ 公有 SNI 会让并行用例互抢票据
    /// （bd pfq9s H-B2）。证书 SAN 同步用该名，客户端走真实校验路径即可通过。
    async fn spawn_auth_server(
        sni: &str,
        validator: Arc<dyn crate::hub::AuthValidator>,
    ) -> io::Result<(SocketAddr, Arc<dyn crate::hub::HysteriaQuicListener>, rustls::RootCertStore)>
    {
        let cert = rcgen::generate_simple_self_signed(vec![sni.into()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der =
            rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
        let server_tls = rustls::server::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        let mut trust = rustls::RootCertStore::empty();
        // 自签证书自身作根（免去 dangerous verifier）
        trust.add(cert.cert.der().clone()).unwrap();

        let factory = crate::quinn_adapter::QuinnListenerFactory::new(Arc::new(server_tls));
        let proto_config = Arc::new(crate::proto_config::Config::default());
        let quic_params = Arc::new(xray_proto::xray::transport::internet::QuicParams::default());
        let validator = Some(validator);
        use crate::hub::HysteriaListenerFactory as _;
        let (stream_tx, _stream_rx) =
            tokio::sync::mpsc::unbounded_channel::<Arc<crate::conn::InterStreamConn>>();
        let on_new_conn: Arc<dyn Fn(Arc<crate::conn::InterStreamConn>) + Send + Sync> =
            Arc::new(move |s| {
                let _ = stream_tx.send(s);
            });
        let listener = factory
            .listen(
                "127.0.0.1:0".parse().unwrap(),
                proto_config,
                quic_params,
                crate::hub::MasqType::NotFound,
                validator,
                on_new_conn,
                None,
            )
            .await
            .expect("listen should succeed");
        let addr = listener.local_addr();
        Ok((addr, listener, trust))
    }

    /// 回退臂：resumption 禁用（enableSessionResumption=false 语义）时 into_0rtt 恒 Err，
    /// 拨号必须完整走 1-RTT 并认证成功——共享 store 注入不得破坏禁用语义。
    #[tokio::test]
    async fn resumption_disabled_transport_dials_via_1rtt_fallback() {
        ensure_crypto_provider();
        const SNI: &str = "localhost-resumption-disabled";
        let (addr, _listener, trust) =
            spawn_auth_server(SNI, Arc::new(TestValidator)).await.unwrap();

        let client_tls =
            rustls::ClientConfig::builder().with_root_certificates(trust).with_no_client_auth();
        // xray_tls 对 enableSessionResumption=false 的等价形态：Resumption::disabled()
        let client_tls = {
            let mut c = client_tls;
            c.resumption = rustls::client::Resumption::disabled();
            c
        };
        let transport = QuinnHysteriaTransport::new(client_tls, "0.0.0.0:0".parse().unwrap())
            .expect("transport");

        let dest = DialDestination { udp_addr: addr, host: SNI.into() };
        let qc = crate::dialer::QuicConfig::default_for_hysteria();
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            transport.dial_and_authenticate(&dest, &qc, "test-secret", 0),
        )
        .await
        .expect("no hang")
        .expect("1-RTT fallback dial + auth should succeed");
    }

    /// 握手窗 Go parity（bd gqpck）：对端 UDP socket 在但从不回包 ⇒ 必须在
    /// [`HANDSHAKE_TIMEOUT`]（Go quic-go `HandshakeIdleTimeout` 默认 5s）内报
    /// `TimedOut` 且错误文本指明握手窗；不得烧满 30s `max_idle_timeout` 后才以
    /// 「h3 recv_response: Connection error: Timeout」显现（真实 CI 症状）。
    ///
    /// 虚拟时钟（`start_paused` + 自动推进）：不真等 5s。
    #[tokio::test(start_paused = true)]
    async fn dial_reports_handshake_timeout_within_go_parity_window() {
        ensure_crypto_provider();
        // 假服务端：绑定但从不读/回包。端口未绑定会回 ICMP port unreachable，
        // connect 会立刻失败 ⇒ 测不到「静默窗」。
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind silent server");
        let addr = silent.local_addr().expect("silent server addr");

        let client_tls = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let transport = QuinnHysteriaTransport::new(client_tls, "0.0.0.0:0".parse().unwrap())
            .expect("transport");
        let dest = DialDestination { udp_addr: addr, host: "localhost-silent".into() };
        let qc = crate::dialer::QuicConfig::default_for_hysteria();

        let started = tokio::time::Instant::now();
        let err = transport
            .dial_and_authenticate(&dest, &qc, "test-secret", 0)
            .await
            .err()
            .expect("服务端静默必须报错而非挂到 idle 超时");
        let elapsed = started.elapsed();

        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "error={err}");
        assert!(
            err.to_string().contains("QUIC handshake"),
            "错误须点名 QUIC handshake（不是 h3 idle Timeout）：{err}"
        );
        assert!(err.to_string().contains("phase=handshake"), "错误须带握手阶段标注：{err}");
        assert!(
            elapsed >= HANDSHAKE_TIMEOUT && elapsed < HANDSHAKE_TIMEOUT * 2,
            "握手窗应在 {HANDSHAKE_TIMEOUT:?} 触发（Go parity），实测 {elapsed:?}"
        );
    }

    /// 0-RTT 分支「connected 窗」逻辑单测：永不 resolve 的假 future 必须在
    /// [`HANDSHAKE_TIMEOUT`] 报 `phase=handshake` 超时——不依赖真 QUIC（Main 口径：
    /// 集成层只测两型入口的收场，窗逻辑本身由本单测钉住）。
    #[tokio::test(start_paused = true)]
    async fn handshake_window_helper_times_out_pending_future() {
        let started = tokio::time::Instant::now();
        let err = within_handshake_window(std::future::pending::<bool>())
            .await
            .expect_err("永不 connected 必须在握手窗报超时");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "error={err}");
        assert!(err.to_string().contains("phase=handshake"), "error={err}");
        assert_eq!(started.elapsed(), HANDSHAKE_TIMEOUT, "窗值必须精确等于 5s");
    }

    /// 握手窗对 **0-RTT 入口**同样成立（Go：`HandshakeIdleTimeout` 对 0-RTT 的后台握手
    /// 照样计）：先与真服务端完成一次拨号播种票据（store 只按 ServerName 键），再对
    /// 「绑定但静默」的假服务端用**同一 SNI** 拨号 ⇒ `into_0rtt` 命中票据走 0-RTT 分支，
    /// 握手在后台 ⇒ 必须在 [`HANDSHAKE_TIMEOUT`] 内报 `phase=handshake` 超时。
    ///
    /// 注：若 rustls 票据不可复用而回退 1-RTT，本用例退化为上一用例的复检（断言不变）；
    /// 0-RTT 分支与 1-RTT 分支共用同一 [`HANDSHAKE_TIMEOUT`] 与错误构造。
    #[tokio::test(start_paused = true)]
    async fn zero_rtt_dial_handshake_window_fires_within_go_parity_window() {
        ensure_crypto_provider();
        const SNI: &str = "localhost-0rtt-window";
        let (addr, _listener, trust) =
            spawn_auth_server(SNI, Arc::new(TestValidator)).await.unwrap();
        let dest = DialDestination { udp_addr: addr, host: SNI.into() };
        let qc = crate::dialer::QuicConfig::default_for_hysteria();

        let client_tls =
            rustls::ClientConfig::builder().with_root_certificates(trust).with_no_client_auth();
        let transport = QuinnHysteriaTransport::new(client_tls, "0.0.0.0:0".parse().unwrap())
            .expect("transport");

        // ① 播种票据（连接保活到用例尾，见 second_dial_uses_0rtt_* 的 H-B1 注释）
        let seed = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            transport.dial_and_authenticate(&dest, &qc, "test-secret", 0),
        )
        .await
        .expect("no hang")
        .expect("seeding dial should succeed");

        // ② 假服务端：绑定但静默；同 SNI ⇒ into_0rtt 命中票据
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind silent server");
        let silent_addr = silent.local_addr().expect("silent server addr");
        let silent_dest = DialDestination { udp_addr: silent_addr, host: SNI.into() };

        let started = tokio::time::Instant::now();
        let err = transport
            .dial_and_authenticate(&silent_dest, &qc, "test-secret", 0)
            .await
            .err()
            .expect("静默服务端下 0-RTT 握手必须 5s 内报错");
        let elapsed = started.elapsed();

        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "error={err}");
        assert!(
            err.to_string().contains("phase=handshake"),
            "0-RTT 入口的超时须带握手阶段标注：{err}"
        );
        assert!(
            elapsed <= HANDSHAKE_TIMEOUT + std::time::Duration::from_millis(500),
            "总耗时必须 ≤ 握手窗 + 500ms 容差（不得烧满 idle 30s），实测 {elapsed:?}"
        );

        seed.close_with_error(crate::config::CLOSE_ERR_CODE_OK, "test done");
    }

    /// 防回退（用户「100% 复刻」铁律）：**auth 段不得被握手段 5s 窗约束**——Go 的
    /// h3 POST /auth 应答只受 `MaxIdleTimeout`（30s）约束。服务端在握手完成后延迟 6s
    /// 才回 /auth ⇒ 拨号必须成功；若有人把 auth 罩回 5s 窗，本用例以 TimedOut 红。
    ///
    /// 慢响应型必须走真实墙钟（暂停时钟下真实完成窗口会被 timer 跳步吞掉）⇒ 本用例
    /// 真实耗时 ~6s；延迟用阻塞 sleep（`AuthValidator::validate` 是 sync trait），跑在
    /// multi_thread(2) 上只冻一个 worker。
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slow_auth_response_beyond_handshake_window_still_succeeds() {
        ensure_crypto_provider();
        const SNI: &str = "localhost-slow-auth";
        const AUTH_DELAY: Duration = Duration::from_secs(6);
        let (addr, _listener, trust) =
            spawn_auth_server(SNI, Arc::new(SlowValidator(AUTH_DELAY))).await.unwrap();

        let client_tls =
            rustls::ClientConfig::builder().with_root_certificates(trust).with_no_client_auth();
        let transport = QuinnHysteriaTransport::new(client_tls, "0.0.0.0:0".parse().unwrap())
            .expect("transport");
        let dest = DialDestination { udp_addr: addr, host: SNI.into() };
        let qc = crate::dialer::QuicConfig::default_for_hysteria();

        let started = xray_frame::compat::clock().now_instant();
        let _conn = tokio::time::timeout(
            Duration::from_secs(25),
            transport.dial_and_authenticate(&dest, &qc, "test-secret", 0),
        )
        .await
        .expect("no hang")
        .expect("慢 auth（6s > 5s 握手窗）必须成功——auth 段不得被握手窗截断");
        let elapsed = started.elapsed();

        assert!(
            elapsed >= AUTH_DELAY,
            "拨号应等待服务端 {AUTH_DELAY:?} 慢应答（证明 auth 段无 5s 截断），实测 {elapsed:?}"
        );
    }

    /// 0-RTT 臂：首次拨号为会话缓存播种票据；二次拨号 into_0rtt 可用且服务端接受
    /// （quinn 服务端默认处理 0-RTT），0-RTT 路径上 h3 auth 完整走通。
    #[tokio::test]
    async fn second_dial_uses_0rtt_after_first_dial_seeds_ticket() {
        ensure_crypto_provider();
        const SNI: &str = "localhost-0rtt-seed";
        let (addr, _listener, trust) =
            spawn_auth_server(SNI, Arc::new(TestValidator)).await.unwrap();
        let dest = DialDestination { udp_addr: addr, host: SNI.into() };
        let qc = crate::dialer::QuicConfig::default_for_hysteria();

        let client_tls =
            rustls::ClientConfig::builder().with_root_certificates(trust).with_no_client_auth();
        let transport = Arc::new(
            QuinnHysteriaTransport::new(client_tls, "0.0.0.0:0".parse().unwrap())
                .expect("transport"),
        );

        // 首连：播种票据（无票据时 into_0rtt Err → 1-RTT，成功即回退无损）。
        // **必须保活到本用例结束**：NewSessionTicket 由服务端在握手完成后异步发出，实测
        // 落到共享 store 比本函数的返回**晚 1.4–2.1ms**（bd pfq9s 探针，5/5 次）；连接一旦
        // drop 即关闭 QUIC，晚到的票据再也进不了 store（H-B1）。
        let seed = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            transport.dial_and_authenticate(&dest, &qc, "test-secret", 0),
        )
        .await
        .expect("no hang")
        .expect("first dial + auth should succeed");

        // 白盒：与 dial_and_authenticate 同构的 client config（共享 store + 同 transport
        // config——传输参数与首连一致才不会被服务端拒 0-RTT），直接断言 into_0rtt 状态。
        // 票据唯一来源是上面**保活的播种连接**：探测连接握手完成后立刻 close，而 NST 比
        // 握手完成晚到（实测 dial 返回后 1.4–2.1ms，bd pfq9s 探针）⇒ 探测连接收不到票据。
        // 故这里只是**确定性等待条件**：轮询到 store 里有票为止。
        let probe = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                let mut cfg = transport.client_config.clone();
                // TransportConfig 不可 Clone，每轮重建（构造便宜，保证 0-RTT 传输参数与首连一致）
                let (transport_cfg, _cc) =
                    crate::quinn_adapter::build_hysteria_transport_config(&qc);
                cfg.transport_config(Arc::new(transport_cfg));
                let mut ep = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
                ep.set_default_client_config(cfg);
                let connecting = ep.connect(addr, SNI).expect("connect initiate");
                match connecting.into_0rtt() {
                    Ok((conn, zero_rtt)) => break (conn, zero_rtt),
                    Err(connecting) => {
                        let conn = connecting.await.expect("probe 1-RTT connect");
                        conn.close(0u32.into(), b"probe waiting for ticket");
                    },
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("0-RTT should become available once the session ticket lands");
        let (_probe_conn, zero_rtt) = probe;
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(15), zero_rtt)
                .await
                .expect("handshake completes"),
            "server should accept 0-RTT"
        );

        // 二连：0-RTT 路径上 h3 POST /auth 完整走通
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            transport.dial_and_authenticate(&dest, &qc, "test-secret", 0),
        )
        .await
        .expect("no hang")
        .expect("second dial (0-RTT) + auth should succeed");

        seed.close_with_error(crate::config::CLOSE_ERR_CODE_OK, "test done");
    }
}
