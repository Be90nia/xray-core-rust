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
//! 参考：librarian 调研 hyproxy/hysteria 1.x 协议 + Xray Go `transport/internet/hysteria/dialer.go`。

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig as QuinnClientConfig, Connection as QuinnConnection, Endpoint};

use crate::conn::{QuicConn, QuicStream};
use crate::dialer::{DialDestination, HysteriaTransport, QuicConfig};
use crate::quinn_adapter::{QuinnQuicConn, QuinnQuicStream};

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
        let quic = QuicClientConfig::try_from(Arc::new(tls_config))
            .map_err(|e| io::Error::other(format!("quinn QuicClientConfig: {e}")))?;
        Ok(Self {
            client_config: QuinnClientConfig::new(Arc::new(quic)),
            bind_addr,
        })
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
        Box::pin(async move {
            // 1. quinn endpoint（transport config 含可热切换 CC factory，auth 后协商）
            let (transport_cfg, cc_slot) =
                crate::quinn_adapter::build_hysteria_transport_config(&quic_cfg);
            client_config.transport_config(Arc::new(transport_cfg));
            let mut endpoint = Endpoint::client(bind_addr)
                .map_err(|e| io::Error::other(format!("quinn endpoint: {e}")))?;
            endpoint.set_default_client_config(client_config);

            // 2. QUIC 拨号
            let conn = endpoint
                .connect(dest_addr, &host)
                .map_err(|e| io::Error::other(format!("quinn connect initiate: {e}")))?
                .await
                .map_err(|e| io::Error::other(format!("quinn connect: {e}")))?;

            // 3. h3 client 发 POST /auth，返回保活项（driver + SendRequest）防止 h3 关闭 QUIC 连接。
            let h3_keepalive = authenticate_via_h3(&conn, &auth_token, brutal_down_bps).await?;

            // 3.5 CC 协商（Go dialer.go:229-243 switch）：
            // down = 响应 Hysteria-CC-RX（服务端下行容量）。
            if let Err(e) = crate::congestion::quinn_bridge::apply_negotiated(
                &cc_slot,
                &quic_cfg.congestion,
                &quic_cfg.bbr_profile,
                quic_cfg.brutal_up,
                h3_keepalive.cc_rx_down,
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
/// 2. 额外 clone 一份 `SendRequest`（sender_count 由 2 减到 1，不触发关闭），与
///    driver task 的 JoinHandle 一同返回给调用方保活，直到 conn drop。
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
    stream
        .finish()
        .await
        .map_err(|e| io::Error::other(format!("h3 stream finish: {e}")))?;

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
        .and_then(|s| s.parse::<u64>().ok())
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

    Ok(H3Keepalive {
        driver_task,
        send_req: send_req_keepalive,
        udp_enabled,
        cc_rx_down,
    })
}

/// h3 auth 保活项 + 协商结果。
///
/// driver/send_req 必须持有到 QUIC 连接生命周期结束（见 [`authenticate_via_h3`] 文档）；
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
        ONCE.call_once(|| { let _ = rustls::crypto::ring::default_provider().install_default(); });
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
}
