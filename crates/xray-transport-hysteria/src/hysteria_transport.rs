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
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, LazyLock},
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

            // 2. QUIC 拨号（Go dialer.go:154 `tr.DialEarly` parity）：store 有会话票据时 into_0rtt
            //    立即返回连接，h3 auth 在 0-RTT 中发出（省 1-RTT）；首连/禁用 resumption 时 Err →
            //    正常等 1-RTT。0-RTT 被服务端拒绝时 auth 流报 ZeroRttRejected，dial
            //    失败交上层重连——与 Go quic-go Err0RTTRejected → dial 返回 err → clientManager
            //    重连同型，不加额外重试。
            let connecting = endpoint
                .connect(dest_addr, &host)
                .map_err(|e| io::Error::other(format!("quinn connect initiate: {e}")))?;
            let conn = match connecting.into_0rtt() {
                Ok((conn, _zero_rtt)) => {
                    tracing::debug!("hysteria dialing with 0-RTT attempt");
                    conn
                },
                Err(connecting) => {
                    connecting.await.map_err(|e| io::Error::other(format!("quinn connect: {e}")))?
                },
            };

            // 3. h3 client 发 POST /auth，返回保活项（driver + SendRequest）防止 h3 关闭 QUIC
            //    连接。
            let h3_keepalive = authenticate_via_h3(&conn, &auth_token, brutal_down_bps).await?;

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
                tracing::warn!(error = %e, "hysteria congestion negotiation failed, keeping default");
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
    #[allow(dead_code)]
    pub driver_task: tokio::task::JoinHandle<()>,
    #[allow(dead_code)]
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

    /// 0-RTT 测试共用：自签证书 + QuinnListenerFactory server（auth="test-secret"）。
    /// 返回 (server_addr, listener, client_trust_anchors)；listener 须保活至断言结束。
    async fn spawn_auth_server()
    -> io::Result<(SocketAddr, Arc<dyn crate::hub::HysteriaQuicListener>, rustls::RootCertStore)>
    {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
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
        struct TestValidator;
        impl crate::hub::AuthValidator for TestValidator {
            fn validate(&self, auth: &str) -> Option<String> {
                if auth == "test-secret" { Some("user".into()) } else { None }
            }

            fn count(&self) -> usize {
                1
            }
        }
        let validator: Option<Arc<dyn crate::hub::AuthValidator>> = Some(Arc::new(TestValidator));
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
        let (addr, _listener, trust) = spawn_auth_server().await.unwrap();

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

        let dest = DialDestination { udp_addr: addr, host: "localhost".into() };
        let qc = crate::dialer::QuicConfig::default_for_hysteria();
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            transport.dial_and_authenticate(&dest, &qc, "test-secret", 0),
        )
        .await
        .expect("no hang")
        .expect("1-RTT fallback dial + auth should succeed");
    }

    /// 0-RTT 臂：首次拨号为会话缓存播种票据；二次拨号 into_0rtt 可用且服务端接受
    /// （quinn 服务端默认处理 0-RTT），0-RTT 路径上 h3 auth 完整走通。
    #[tokio::test]
    async fn second_dial_uses_0rtt_after_first_dial_seeds_ticket() {
        ensure_crypto_provider();
        let (addr, _listener, trust) = spawn_auth_server().await.unwrap();
        let dest = DialDestination { udp_addr: addr, host: "localhost".into() };
        let qc = crate::dialer::QuicConfig::default_for_hysteria();

        let client_tls =
            rustls::ClientConfig::builder().with_root_certificates(trust).with_no_client_auth();
        let transport = Arc::new(
            QuinnHysteriaTransport::new(client_tls, "0.0.0.0:0".parse().unwrap())
                .expect("transport"),
        );

        // 首连：播种票据（无票据时 into_0rtt Err → 1-RTT，成功即回退无损）
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            transport.dial_and_authenticate(&dest, &qc, "test-secret", 0),
        )
        .await
        .expect("no hang")
        .expect("first dial + auth should succeed");

        // 白盒：与 dial_and_authenticate 同构的 client config（共享 store + 同 transport
        // config——传输参数与首连一致才不会被服务端拒 0-RTT），直接断言 into_0rtt 状态。
        // NewSessionTicket 在握手完成后由服务端异步发出，auth 响应返回时可能仍在路上；
        // 轮询重拨直至票据落入共享 store（确定性等待条件，非时序假设）。每次探测连接
        // 本身也会收取票据，加速落库。
        let probe = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                let mut cfg = transport.client_config.clone();
                // TransportConfig 不可 Clone，每轮重建（构造便宜，保证 0-RTT 传输参数与首连一致）
                let (transport_cfg, _cc) =
                    crate::quinn_adapter::build_hysteria_transport_config(&qc);
                cfg.transport_config(Arc::new(transport_cfg));
                let mut ep = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
                ep.set_default_client_config(cfg);
                let connecting = ep.connect(addr, "localhost").expect("connect initiate");
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
    }
}
