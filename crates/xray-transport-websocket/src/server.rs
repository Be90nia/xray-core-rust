//! WebSocket 服务端：TCP/TLS 监听 + Upgrade + early data 提取。
//!
//! 对应 Go `transport/internet/websocket/hub.go` 的 `ListenWS` +
//! `requestHandler.ServeHTTP`。Rust 端用 `tokio-tungstenite::accept_hdr_async`
//! 拦截 HTTP Upgrade 请求，校验 Host / Path，提取 `Sec-WebSocket-Protocol`
//! header 中的 early data（base64 RawURL 编码）。
//!
//! # 流程
//!
//! 1. `WsListener::bind` 绑 TcpListener
//! 2. `accept()` 收一条 TCP 连接（+ 可选 TLS 包装）
//! 3. `accept_hdr_async` 触发握手，callback 内：
//!    - 校验 `Sec-WebSocket-Key` → 自动由 tungstenite 处理
//!    - 校验 Host / Path → 不匹配返回 `404` 拒绝
//!    - 提取 `Sec-WebSocket-Protocol` base64 → early data
//!    - 回写 `Sec-WebSocket-Protocol` 响应头（必须回写客户端才认）
//! 4. 把握手完成的 `WebSocketStream` + early data 包装为 `WsConnWithEarlyData`

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use tokio::net::TcpListener as TokioTcpListener;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::http::{HeaderMap, StatusCode};

use xray_transport::connection::Connection;

use crate::config::Config;
use crate::error::{Result, WsError};
use crate::ws_bridge::WsConnection;

/// 服务端 accept 出的连接 + 服务端从 `Sec-WebSocket-Protocol` 解出的 early data。
///
/// early data 对应 Go `extraReader`（连接首批字节，调用方需先消费再进入帧循环）。
pub struct AcceptedConn {
    /// 字节流包装的 WS 连接。
    pub conn: Box<dyn Connection>,
    /// 解码后的 early data（可能为空）。
    pub early_data: Vec<u8>,
    /// TCP peer 地址。
    pub remote: SocketAddr,
}

/// WebSocket 服务端监听器。
///
/// 对应 Go `Listener`（`hub.go`）。本结构持有 TcpListener + WS 配置；
/// TLS 包装由调用方在 `accept` 后注入（ponytail：避免 listener 持 TLS acceptor
/// 让数据流走 trait object）。
pub struct WsListener {
    listener: TokioTcpListener,
    configs: Vec<Arc<Config>>,
}

impl WsListener {
    /// 绑定到 `addr`，使用单个 WS 配置（host/path/heartbeat）。
    pub async fn bind(addr: SocketAddr, config: Arc<Config>) -> Result<Self> {
        Self::bind_multi(addr, vec![config]).await
    }

    /// 绑定到 `addr`，使用多个 WS 配置实现多 path 路由。
    ///
    /// 一个 TCP 端点接受多个 path，握手时按 (host, path) 匹配找到对应 config。
    /// 对应 Go 多个 requestHandler 共享一个 listener（Go 实际是单 path/server）。
    pub async fn bind_multi(addr: SocketAddr, configs: Vec<Arc<Config>>) -> Result<Self> {
        if configs.is_empty() {
            return Err(WsError::InvalidUpgradeRequest {
                reason: "no WS configs provided".into(),
            });
        }
        let listener = TokioTcpListener::bind(addr)
            .await
            .map_err(WsError::Io)?;
        Ok(Self { listener, configs })
    }

    /// 本地地址。
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener
            .local_addr()
            .map_err(WsError::Io)
    }

/// 接受一条新连接，完成 WS 握手 + 校验 host/path + 提取 early data。
    ///
    /// **不支持 TLS**：明文 ws:// only。TLS 场景请用 [`accept_tls`](Self::accept_tls)。
    pub async fn accept(&self) -> Result<AcceptedConn> {
        let (mut tcp, remote) = self.listener.accept().await.map_err(WsError::Io)?;
        let local = tcp.local_addr().ok();
        let remote = self.parse_proxy_protocol(&mut tcp, remote).await?;
        Self::ws_handshake(tcp, remote, local, &self.configs).await
    }

    /// 接受一条新连接，先做 TLS 握手再 WS 握手。
    ///
    /// 流程：TCP accept → PROXY protocol（可选）→ TLS accept → WS handshake。
    /// 对应 Go `tls.NewListener(l, tlsConfig)` 包装 TCP listener。
    pub async fn accept_tls(
        &self,
        tls_config: Arc<tokio_rustls::rustls::ServerConfig>,
    ) -> Result<AcceptedConn> {
        let (mut tcp, remote) = self.listener.accept().await.map_err(WsError::Io)?;
        let local = tcp.local_addr().ok();
        let remote = self.parse_proxy_protocol(&mut tcp, remote).await?;
        // TLS 握手。
        let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
        let tls_stream = acceptor
            .accept(tcp)
            .await
            .map_err(|e| WsError::HandshakeFailed(format!("tls accept: {e}")))?;
        Self::ws_handshake(tls_stream, remote, local, &self.configs).await
    }

    /// 解析 PROXY protocol（如果启用），返回真实客户端地址。
    async fn parse_proxy_protocol(
        &self,
        tcp: &mut tokio::net::TcpStream,
        original: SocketAddr,
    ) -> Result<SocketAddr> {
        if self.configs.iter().any(|c| c.accept_proxy_protocol) {
            Ok(read_proxy_protocol(tcp).await?.unwrap_or(original))
        } else {
            Ok(original)
        }
    }

    /// 在已建立的流上做 WS 握手 + 多 path 路由 + early data + XFF + 心跳 ping。
    ///
    /// 多 path：在 `configs` 中按 (host, path) 匹配，找到的 config 决定 heartbeat_period。
    /// XFF：从 `X-Forwarded-For` header 提取首个 IP 覆盖 remote（port=0，对齐 Go）。
    async fn ws_handshake<S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static>(
        stream: S,
        remote: SocketAddr,
        local: Option<SocketAddr>,
        configs: &[Arc<Config>],
    ) -> Result<AcceptedConn> {
        let configs_arc: Arc<[Arc<Config>]> = Arc::from(configs);
        let early_data_slot: Arc<std::sync::Mutex<Vec<u8>>> = Arc::default();
        let xff_slot: Arc<std::sync::Mutex<Option<IpAddr>>> = Arc::default();
        let matched_idx_slot: Arc<std::sync::Mutex<Option<usize>>> = Arc::default();

        let ed_cb = Arc::clone(&early_data_slot);
        let xff_cb = Arc::clone(&xff_slot);
        let matched_cb = Arc::clone(&matched_idx_slot);
        let configs_cb = Arc::clone(&configs_arc);

        let callback = move |req: &Request, resp: Response| {
            let headers = req.headers();
            let req_path = req.uri().path();
            let req_host = headers
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            // 1. 多 path 路由：找到匹配的 config（host 空放行/非空严格匹配 + path 严格匹配）。
            let matched = configs_cb.iter().position(|c| {
                let host_ok = c.host.is_empty() || c.host == req_host;
                let path_ok = req_path == c.normalized_path();
                host_ok && path_ok
            });
            let Some(idx) = matched else {
                let denied = tokio_tungstenite::tungstenite::http::Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Some("no matching host/path".into()))
                    .unwrap();
                return Err(denied);
            };
            if let Ok(mut g) = matched_cb.lock() {
                *g = Some(idx);
            }

            // 2. Early data 提取：Sec-WebSocket-Protocol (base64 RawURL no pad)。
            let mut response = resp;
            if let Some(ed_header) = extract_early_data(headers) {
                if let Ok(val) = tokio_tungstenite::tungstenite::http::HeaderValue::from_str(&ed_header.raw) {
                    response
                        .headers_mut()
                        .insert("Sec-WebSocket-Protocol", val);
                }
                if let Ok(mut guard) = ed_cb.lock() {
                    *guard = ed_header.bytes;
                }
            }

            // 3. X-Forwarded-For 提取（对应 Go hub.go: ParseXForwardedFor）。
            if let Some(ip) = extract_xff(headers) {
                if let Ok(mut guard) = xff_cb.lock() {
                    *guard = Some(ip);
                }
            }

            Ok(response)
        };

        let ws_stream = accept_hdr_async(stream, callback)
            .await
            .map_err(|e| WsError::HandshakeFailed(format!("accept_hdr_async: {e}")))?;

        let early_data = early_data_slot
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        let xff_ip = xff_slot.lock().ok().and_then(|mut g| g.take());
        let matched_idx = matched_idx_slot.lock().ok().and_then(|mut g| g.take());

        // 4. Remote 决定：XFF 覆盖（port=0，对齐 Go forwardedAddrs[0]）。
        let final_remote = xff_ip
            .map(|ip| SocketAddr::new(ip, 0))
            .unwrap_or(remote);

        // 5. 匹配 config 的 heartbeat_period 启动 ping。
        let heartbeat_secs = matched_idx
            .and_then(|i| configs.get(i))
            .map(|c| c.heartbeat_period)
            .unwrap_or(0);

        let mut conn = WsConnection::from_stream(ws_stream, Some(final_remote), local);
        if heartbeat_secs > 0 {
            conn.start_heartbeat(Duration::from_secs(heartbeat_secs as u64));
        }
        if !early_data.is_empty() {
            conn.read_buf.extend(&early_data);
        }
        Ok(AcceptedConn {
            conn: Box::new(conn) as Box<dyn Connection>,
            early_data,
            remote: final_remote,
        })
    }
}
/// 解析出的 early data（原始 header 字符串 + 解码后字节）。
struct EarlyDataHeader {
    raw: String,
    bytes: Vec<u8>,
}

/// 从 `Sec-WebSocket-Protocol` header 解出 early data。
///
/// 对齐 Go `replacer = strings.NewReplacer("+", "-", "/", "_", "=", "")` +
/// `base64.RawURLEncoding.DecodeString`。Go 用 RawURLEncoding 但 replacer
/// 兼容标准 base64 客户端（把 +/= 替换为 -_ 空）。Rust 端用 URL_SAFE_NO_PAD
/// 直接解码（与 client.rs 编码端对称），不匹配返回 None。
fn extract_early_data(headers: &HeaderMap) -> Option<EarlyDataHeader> {
    let raw = headers.get("Sec-WebSocket-Protocol")?.to_str().ok()?;
    if raw.is_empty() {
        return None;
    }
    // 兼容 Go replacer：标准 base64 → RawURL。
    let normalized: String = raw.chars().map(|c| match c {
        '+' => '-',
        '/' => '_',
        '=' => '\0', // 移除 padding
        _ => c,
    }).filter(|c| *c != '\0').collect();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&normalized)
        .ok()?;
    if bytes.is_empty() {
        return None;
    }
    Some(EarlyDataHeader {
        raw: raw.to_string(),
        bytes,
    })
}

/// 从 `X-Forwarded-For` header 提取首个 IP（最原始客户端）。
///
/// 对应 Go `common/protocol/http.ParseXForwardedFor`：取逗号分隔列表的第一个，
/// trim 空白后解析为 IP。无效或缺失返回 None。
fn extract_xff(headers: &HeaderMap) -> Option<IpAddr> {
    let val = headers.get("X-Forwarded-For")?.to_str().ok()?;
    let first = val.split(',').next()?.trim();
    first.parse::<IpAddr>().ok()
}

/// 读 PROXY protocol v1/v2 header，返回真实客户端地址。
///
/// 在 `WsListener::accept` 中，若 `config.accept_proxy_protocol == true`，
/// 在 WS 握手前先读 PROXY header 拿真实客户端地址（覆盖 TCP remote）。
/// 对应 HAProxy PROXY protocol spec v1/v2。
async fn read_proxy_protocol<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<Option<SocketAddr>> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
    use tokio::io::AsyncReadExt;

    // 读前 6 字节判断 v1/v2。
    let mut sig = [0u8; 6];
    reader.read_exact(&mut sig).await?;

    const V2_SIG: [u8; 6] = [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D];
    const V1_PREFIX: [u8; 6] = *b"PROXY ";

    if sig == V2_SIG {
        // v2：补齐 signature(6) + ver_cmd(1) + fam(1) + length(2)
        let mut rest = [0u8; 10];
        reader.read_exact(&mut rest).await?;
        let fam = rest[7];
        let length = u16::from_be_bytes([rest[8], rest[9]]) as usize;
        let mut payload = vec![0u8; length];
        reader.read_exact(&mut payload).await?;

        let af = fam >> 4; // 地址族：1=INET 2=INET6
        match af {
            1 => {
                if payload.len() < 12 {
                    return Ok(None);
                }
                let src = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
                let sport = u16::from_be_bytes([payload[8], payload[9]]);
                Ok(Some(SocketAddr::V4(SocketAddrV4::new(src, sport))))
            }
            2 => {
                if payload.len() < 36 {
                    return Ok(None);
                }
                let mut src = [0u8; 16];
                src.copy_from_slice(&payload[0..16]);
                let sport = u16::from_be_bytes([payload[32], payload[33]]);
                Ok(Some(SocketAddr::V6(SocketAddrV6::new(
                    src.into(),
                    sport,
                    0,
                    0,
                ))))
            }
            _ => Ok(None), // UNSPEC/UNIX/UNKNOWN
        }
    } else if sig == V1_PREFIX {
        // v1：已读 "PROXY "，继续读直到 \r\n
        let mut line = Vec::from(&b"PROXY "[..]);
        let mut byte = [0u8; 1];
        loop {
            reader.read_exact(&mut byte).await?;
            line.push(byte[0]);
            if line.ends_with(b"\r\n") {
                break;
            }
            if line.len() > 107 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "proxy protocol v1 too long",
                ));
            }
        }
        let text = std::str::from_utf8(&line)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "proxy protocol v1 not utf8"))?;
        // "PROXY TCP4 src dst sport dport\r\n"
        let parts: Vec<&str> = text.trim_end().split_whitespace().collect();
        if parts.len() >= 6 {
            let sport: u16 = parts[4].parse().unwrap_or(0);
            match parts[1] {
                "TCP4" => {
                    if let Ok(ip) = parts[2].parse::<Ipv4Addr>() {
                        return Ok(Some(SocketAddr::V4(SocketAddrV4::new(ip, sport))));
                    }
                }
                "TCP6" => {
                    if let Ok(ip) = parts[2].parse::<Ipv6Addr>() {
                        return Ok(Some(SocketAddr::V6(SocketAddrV6::new(ip, sport, 0, 0))));
                    }
                }
                _ => {}
            }
        }
        Ok(None) // UNKNOWN 或解析失败
    } else {
        // 非 PROXY protocol：调用方保证启用时有 header，当错误处理
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected proxy protocol header",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_early_data_decodes_url_safe_no_pad() {
        // 客户端编码：URL_SAFE_NO_PAD("hello") = "aGVsbG8"
        let mut h = HeaderMap::new();
        h.insert("Sec-WebSocket-Protocol", "aGVsbG8".parse().unwrap());
        let ed = extract_early_data(&h).expect("decoded");
        assert_eq!(ed.bytes, b"hello");
        assert_eq!(ed.raw, "aGVsbG8");
    }

    #[test]
    fn extract_early_data_accepts_standard_base64_with_replacer() {
        // 标准 base64("hi!") = "aGkh"（no pad），含 +/= 时：("??") = "Pz8="
        let mut h = HeaderMap::new();
        h.insert("Sec-WebSocket-Protocol", "Pz8=".parse().unwrap());
        let ed = extract_early_data(&h).expect("decoded via replacer");
        assert_eq!(ed.bytes, b"??");
    }

    #[test]
    fn extract_early_data_empty_returns_none() {
        let mut h = HeaderMap::new();
        h.insert("Sec-WebSocket-Protocol", "".parse().unwrap());
        assert!(extract_early_data(&h).is_none());
    }

    #[test]
    fn extract_early_data_missing_header_returns_none() {
        let h = HeaderMap::new();
        assert!(extract_early_data(&h).is_none());
    }

    #[test]
    fn extract_early_data_invalid_base64_returns_none() {
        let mut h = HeaderMap::new();
        h.insert("Sec-WebSocket-Protocol", "@@@invalid".parse().unwrap());
        assert!(extract_early_data(&h).is_none());
    }

    #[tokio::test]
    async fn read_proxy_protocol_v1_tcp4() {
        let header = b"PROXY TCP4 1.2.3.4 5.6.7.8 1234 80\r\n";
        let mut reader = &header[..];
        let addr = read_proxy_protocol(&mut reader).await.unwrap();
        assert_eq!(
            addr,
            Some("1.2.3.4:1234".parse::<SocketAddr>().unwrap())
        );
    }

    #[tokio::test]
    async fn read_proxy_protocol_v1_tcp6() {
        let header = b"PROXY TCP6 2001:db8::1 2001:db8::2 1234 80\r\n";
        let mut reader = &header[..];
        let addr = read_proxy_protocol(&mut reader).await.unwrap();
        assert_eq!(
            addr,
                       Some("[2001:db8::1]:1234".parse::<SocketAddr>().unwrap())
        );
    }

    #[tokio::test]
    async fn read_proxy_protocol_v1_unknown_returns_none() {
        let header = b"PROXY UNKNOWN\r\n";
        let mut reader = &header[..];
        let addr = read_proxy_protocol(&mut reader).await.unwrap();
        assert_eq!(addr, None);
    }

    #[tokio::test]
    async fn read_proxy_protocol_v2_tcp4() {
        let mut header = vec![
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, // sig(12)
            0x21, // ver(2)+cmd(1=PROXY)
            0x11, // af(1=INET)+proto(1=STREAM)
            0x00, 0x0C, // length=12
        ];
        header.extend_from_slice(&[1, 2, 3, 4]); // src
        header.extend_from_slice(&[5, 6, 7, 8]); // dst
        header.extend_from_slice(&[0x04, 0xD2]); // sport=1234
        header.extend_from_slice(&[0x00, 0x50]); // dport=80
        let mut reader = &header[..];
        let addr = read_proxy_protocol(&mut reader).await.unwrap();
        assert_eq!(
            addr,
            Some("1.2.3.4:1234".parse::<SocketAddr>().unwrap())
        );
    }

    #[tokio::test]
    async fn read_proxy_protocol_v2_tcp6() {
        let mut header = vec![
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
            0x21, 0x21, // af(2=INET6)+proto(STREAM)
            0x00, 0x24, // length=36
        ];
        let mut src = [0u8; 16];
        src[0] = 0x20; src[1] = 0x01; src[2] = 0x0d; src[3] = 0xb8;
        // 2001:db8::1
        src[15] = 0x01;
        header.extend_from_slice(&src); // src
        header.extend_from_slice(&[0u8; 16]); // dst
        header.extend_from_slice(&[0x04, 0xD2]); // sport=1234
        header.extend_from_slice(&[0x00, 0x50]); // dport=80
        let mut reader = &header[..];
        let addr = read_proxy_protocol(&mut reader).await.unwrap();
        assert_eq!(
            addr,
            Some("[2001:db8::1]:1234".parse::<SocketAddr>().unwrap())
        );
    }

    #[tokio::test]
    async fn read_proxy_protocol_not_proxy_returns_err() {
        let header = b"GET / HT";
        let mut reader = &header[..];
        let result = read_proxy_protocol(&mut reader).await;
        assert!(result.is_err());
    }
    #[tokio::test]
    async fn accept_tls_completes_ws_handshake() {
        // 1. 自签证书
        let cert_params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = cert_params.self_signed(&key_pair).unwrap();
        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();

        // 2. rustls ServerConfig
        let key = rustls::pki_types::PrivateKeyDer::try_from(key_der).unwrap();
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(cert_der.clone())],
                key,
            )
            .unwrap();
        let tls_config = std::sync::Arc::new(server_config);

        // 3. 启动 WsListener + accept_tls
        let ws_config = std::sync::Arc::new(crate::config::Config::default());
        let listener = WsListener::bind("127.0.0.1:0".parse().unwrap(), ws_config)
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            // accept_tls 应成功完成 TLS + WS 握手
            listener.accept_tls(tls_config).await
        });

        // 4. 客户端：TCP + TLS + WS connect
        // 构造信任自签证书的 client config
        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(rustls::pki_types::CertificateDer::from(cert_der))
            .unwrap();
        let client_config = std::sync::Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        );

        // tokio-tungstenite connect_async wss:// 需要原生 TLS connector
        // ponytail: 直接用 tokio-rustls 手动 TLS 后 tungstenite client_handshake
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let tls_stream = connector
            .connect("localhost".try_into().unwrap(), tcp)
            .await
            .unwrap();

        // WS 客户端握手
        use tokio_tungstenite::client_async;
        let ws_request = http::Request::builder()
            .method("GET")
            .uri(format!("ws://localhost:{}/", addr.port()))
            .header("Host", format!("localhost:{}", addr.port()))
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .body(())
            .unwrap();
        let (_ws_client, _resp) = client_async(ws_request, tls_stream).await.unwrap();

        // 5. 服务端 accept_tls 完成
        let accepted = server_handle.await.unwrap().unwrap();
        assert_eq!(accepted.remote.ip(), std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
    }

    // --- extract_xff 单元测试 ---

    #[test]
    fn extract_xff_single_ipv4() {
        let mut h = HeaderMap::new();
        h.insert("X-Forwarded-For", "203.0.113.5".parse().unwrap());
        let ip = extract_xff(&h).expect("parsed");
        assert_eq!(ip, IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 5)));
    }

    #[test]
    fn extract_xff_chain_takes_first() {
        let mut h = HeaderMap::new();
        h.insert(
            "X-Forwarded-For",
            "1.2.3.4, 5.6.7.8, 9.10.11.12".parse().unwrap(),
        );
        let ip = extract_xff(&h).expect("parsed");
        assert_eq!(ip, IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn extract_xff_ipv6() {
        let mut h = HeaderMap::new();
        h.insert("X-Forwarded-For", "2001:db8::1".parse().unwrap());
        let ip = extract_xff(&h).expect("parsed");
        assert!(matches!(ip, IpAddr::V6(_)));
    }

    #[test]
    fn extract_xff_missing_returns_none() {
        let h = HeaderMap::new();
        assert!(extract_xff(&h).is_none());
    }

    #[test]
    fn extract_xff_invalid_returns_none() {
        let mut h = HeaderMap::new();
        h.insert("X-Forwarded-For", "not-an-ip".parse().unwrap());
        assert!(extract_xff(&h).is_none());
    }

    // --- 多 path 路由 E2E ---

    #[tokio::test]
    async fn bind_multi_routes_by_path_and_rejects_unknown() {
        use tokio_tungstenite::client_async;
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;

        let cfg1 = Arc::new(Config {
            path: "/foo".into(),
            ..Default::default()
        });
        let cfg2 = Arc::new(Config {
            path: "/bar".into(),
            ..Default::default()
        });
        let listener = Arc::new(
            WsListener::bind_multi("127.0.0.1:0".parse().unwrap(), vec![cfg1, cfg2])
                .await
                .unwrap(),
        );
        let addr = listener.local_addr().unwrap();

        // /foo 匹配。
        let l1 = Arc::clone(&listener);
        let s1 = tokio::spawn(async move { l1.accept().await });
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!("ws://127.0.0.1:{}/foo", addr.port())
            .into_client_request()
            .unwrap();
        let (_ws, _resp) = client_async(req, tcp).await.expect("/foo should match");
        let _ = s1.await.unwrap().unwrap();

        // /bar 匹配。
        let l2 = Arc::clone(&listener);
        let s2 = tokio::spawn(async move { l2.accept().await });
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!("ws://127.0.0.1:{}/bar", addr.port())
            .into_client_request()
            .unwrap();
        let (_ws, _resp) = client_async(req, tcp).await.expect("/bar should match");
        let _ = s2.await.unwrap().unwrap();

        // /baz 不匹配 → 握手失败。
        let l3 = Arc::clone(&listener);
        let s3 = tokio::spawn(async move { l3.accept().await });
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!("ws://127.0.0.1:{}/baz", addr.port())
            .into_client_request()
            .unwrap();
        let result = client_async(req, tcp).await;
        assert!(result.is_err(), "/baz should not match");
        assert!(s3.await.unwrap().is_err(), "server accept should fail too");
    }

    // --- XFF 覆盖 E2E ---

    #[tokio::test]
    async fn xff_header_overrides_remote_addr() {
        use tokio_tungstenite::client_async;
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;

        let cfg = Arc::new(Config::default());
        let listener = Arc::new(
            WsListener::bind("127.0.0.1:0".parse().unwrap(), cfg)
                .await
                .unwrap(),
        );
        let addr = listener.local_addr().unwrap();

        let l = Arc::clone(&listener);
        let server = tokio::spawn(async move { l.accept().await });

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut req = format!("ws://127.0.0.1:{}/", addr.port())
            .into_client_request()
            .unwrap();
        req.headers_mut()
            .insert("X-Forwarded-For", "203.0.113.5".parse().unwrap());
        let (_ws, _resp) = client_async(req, tcp).await.unwrap();

        let accepted = server.await.unwrap().unwrap();
        assert_eq!(
            accepted.remote.ip(),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
        assert_eq!(accepted.remote.port(), 0, "XFF override sets port to 0");
    }
}
