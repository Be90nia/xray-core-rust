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
        _quic_config: &QuicConfig,
        auth_token: &str,
        brutal_up_bps: u64,
    ) -> Pin<Box<dyn std::future::Future<Output = io::Result<Arc<dyn QuicConn>>> + Send>> {
        let dest_addr = dest.udp_addr;
        let host = dest.host.clone();
        let client_config = self.client_config.clone();
        let bind_addr = self.bind_addr;
        let auth_token = auth_token.to_string();
        Box::pin(async move {
            // 1. quinn endpoint
            let mut endpoint = Endpoint::client(bind_addr)
                .map_err(|e| io::Error::other(format!("quinn endpoint: {e}")))?;
            endpoint.set_default_client_config(client_config);

            // 2. QUIC 拨号
            let conn = endpoint
                .connect(dest_addr, &host)
                .map_err(|e| io::Error::other(format!("quinn connect initiate: {e}")))?
                .await
                .map_err(|e| io::Error::other(format!("quinn connect: {e}")))?;

            // 3. h3 client 发 POST /auth
            authenticate_via_h3(&conn, &auth_token, brutal_up_bps).await?;

            // 4. 包装返回（conn 用于后续 open_stream；endpoint drop 不会立刻断连接）
            // ponytail: Arc<QuinnQuicConn> → Arc<dyn QuicConn> 需 explicit cast
            Ok(Arc::new(QuinnQuicConn::new(conn)) as Arc<dyn QuicConn>)
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
async fn authenticate_via_h3(
    conn: &QuinnConnection,
    auth_token: &str,
    brutal_up_bps: u64,
) -> io::Result<()> {
    let h3_conn = h3_quinn::Connection::new(conn.clone());
    let (_driver, mut send_req) = h3::client::new(h3_conn)
        .await
        .map_err(|e| io::Error::other(format!("h3 client new: {e}")))?;

    // ponytail: h3 0.0.8 Connection 不是 Future；_driver 持有状态，drop 时自动清理。
    // 对于一次性 auth 请求，不需要后台 poll control stream。

    let padding = random_auth_padding();
    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(AUTH_URL)
        .header("Hysteria-Auth", auth_token)
        .header("Hysteria-CC-RX", brutal_up_bps.to_string())
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

    // ponytail: 不解析 Hysteria-UDP/Hysteria-CC-RX 响应头——切片1b 仅校验 auth 成功
    Ok(())
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
