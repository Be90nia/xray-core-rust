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

use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine;
use tokio::net::TcpListener as TokioTcpListener;
use tokio::io::AsyncRead;
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
    config: Arc<Config>,
}

impl WsListener {
    /// 绑定到 `addr`，使用给定 WS 配置（host/path/heartbeat）。
    pub async fn bind(addr: SocketAddr, config: Arc<Config>) -> Result<Self> {
        let listener = TokioTcpListener::bind(addr)
            .await
            .map_err(|e| WsError::Io(e))?;
        Ok(Self { listener, config })
    }

    /// 本地地址。
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener
            .local_addr()
            .map_err(WsError::Io)
    }

    /// 接受一条新连接，完成 WS 握手 + 校验 host/path + 提取 early data。
    ///
    /// **不支持 TLS**：明文 ws:// only。TLS 包装应由调用方在传入 `TcpStream`
    /// 之前先 accept TLS（典型场景：外层 nginx/Caddy 终止 TLS，内部明文 WS）。
    /// 切片2 follow-up 可加 `accept_tls(Arc<ServerConfig>)` 变体。
    pub async fn accept(&self) -> Result<AcceptedConn> {
        let (mut tcp, remote) = self.listener.accept().await.map_err(WsError::Io)?;
        let local = tcp
            .local_addr()
            .ok();

        // PROXY protocol 解析（如果启用）：在 WS 握手前读 PROXY header，
        // 拿真实客户端地址覆盖 TCP remote（对齐 Go acceptProxyProtocol）。
        let remote = if self.config.accept_proxy_protocol {
            read_proxy_protocol(&mut tcp)
                .await
                .map_err(WsError::Io)?
                .unwrap_or(remote)
        } else {
            remote
        };

        // 用 callback 在握手过程中拿 Request 头，做 host/path 校验 + early data 提取。
        // ponytail: callback 通过 Mutex<Vec<u8>> 收集 early data（多线程 callback 不会并发，
        // 但 Mutex 满足 callback FnMut 的 Send + Sync 要求）。
        let expected_host = self.config.host.clone();
        let expected_path = self.config.normalized_path();
        let early_data_slot: Arc<std::sync::Mutex<Vec<u8>>> = Arc::default();
        let slot_clone = Arc::clone(&early_data_slot);

        let callback = move |req: &Request, resp: Response| {
            let headers = req.headers();
            // 1. Host 校验：空配置放行；非空严格匹配（对齐 Go IsValidHTTPHost）。
            if !expected_host.is_empty() {
                let req_host = headers
                    .get(http::header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if req_host != expected_host {
                    let denied = tokio_tungstenite::tungstenite::http::Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Some("host mismatch".into()))
                        .unwrap();
                    return Err(denied);
                }
            }
            // 2. Path 校验。
            let req_path = req.uri().path();
            if req_path != expected_path {
                let denied = tokio_tungstenite::tungstenite::http::Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Some("path mismatch".into()))
                    .unwrap();
                return Err(denied);
            }
            // 3. Early data 提取：Sec-WebSocket-Protocol (base64 RawURL no pad)。
            let mut response = resp;
            if let Some(ed_header) = extract_early_data(headers) {
                // 必须把原 header 回写响应（对齐 Go responseHeader.Set）。
                if let Ok(val) = tokio_tungstenite::tungstenite::http::HeaderValue::from_str(&ed_header.raw) {
                    response
                        .headers_mut()
                        .insert("Sec-WebSocket-Protocol", val);
                }
                // 把解码后的字节塞进 slot，握手后由调用方消费。
                if let Ok(mut guard) = slot_clone.lock() {
                    *guard = ed_header.bytes;
                }
            }
            Ok(response)
        };

        let ws_stream = accept_hdr_async(tcp, callback)
            .await
            .map_err(|e| WsError::HandshakeFailed(format!("accept_hdr_async: {e}")))?;

        let early_data = early_data_slot
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();

        let mut conn = WsConnection::from_stream(ws_stream, Some(remote), local);
        // 若有 early data：让 conn 的 read_buf 先吐这些字节，调用方先读到。
        // ponytail: 直接塞 read_buf，poll_read 优先消费。
        if !early_data.is_empty() {
            conn.read_buf.extend(&early_data);
        }
        Ok(AcceptedConn {
            conn: Box::new(conn) as Box<dyn Connection>,
            early_data,
            remote,
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
}
