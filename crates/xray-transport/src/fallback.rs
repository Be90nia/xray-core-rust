//! 通用 fallback 转发：把客户端连接透明转发到备用 dest（带 PROXY protocol header）。
//!
//! 服务于 VLESS/Trojan/REALITY 等 inbound 的 fallback 路由
//! （Go `proxy/trojan/server.go::fallback` line 454-549 / vless `napfb`）。

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncWrite};

/// PROXY protocol 版本（对应 Go `fb.Xver`）。
///
/// - `0`：不发送 PROXY header。
/// - `1`：文本协议 `PROXY TCP4/6 src dst sport dport\r\n`。
/// - `2`：二进制协议（HAProxy v2 signature + addrs）。
///
/// `src` = 客户端地址（connection.RemoteAddr），`dst` = 服务端地址（connection.LocalAddr）。
pub fn encode_proxy_header(xver: u8, src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    match xver {
        1 => encode_proxy_v1(src, dst),
        2 => encode_proxy_v2(src, dst),
        _ => Vec::new(),
    }
}

/// PROXY protocol v1（文本）。
fn encode_proxy_v1(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => {
            format!("PROXY TCP4 {} {} {} {}\r\n", s.ip(), d.ip(), s.port(), d.port()).into_bytes()
        }
        (SocketAddr::V6(s), SocketAddr::V6(d)) => {
            format!("PROXY TCP6 {} {} {} {}\r\n", s.ip(), d.ip(), s.port(), d.port()).into_bytes()
        }
        // 地址族不匹配（极少见）→ UNKNOWN
        _ => b"PROXY UNKNOWN\r\n".to_vec(),
    }
}

/// PROXY protocol v2（二进制）。
fn encode_proxy_v2(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    // 12 字节 signature
    const SIG: &[u8] = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";
    let mut buf = Vec::with_capacity(16 + 36);
    buf.extend_from_slice(SIG);
    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => {
            // 0x21=v2+PROXY, 0x11=AF_INET+STREAM, 0x000C=12 字节 addr
            buf.extend_from_slice(&[0x21, 0x11, 0x00, 0x0C]);
            buf.extend_from_slice(&s.ip().octets());
            buf.extend_from_slice(&d.ip().octets());
            buf.extend_from_slice(&s.port().to_be_bytes());
            buf.extend_from_slice(&d.port().to_be_bytes());
        }
        (SocketAddr::V6(s), SocketAddr::V6(d)) => {
            // 0x21=v2+PROXY, 0x21=AF_INET6+STREAM, 0x0024=36 字节 addr
            buf.extend_from_slice(&[0x21, 0x21, 0x00, 0x24]);
            buf.extend_from_slice(&s.ip().octets());
            buf.extend_from_slice(&d.ip().octets());
            buf.extend_from_slice(&s.port().to_be_bytes());
            buf.extend_from_slice(&d.port().to_be_bytes());
        }
        // 地址族不匹配 → v2+LOCAL+UNSPEC+UNSPEC+0（不传递地址信息）
        _ => buf.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]),
    }
    buf
}

/// fallback 转发：dial `dest` → 写 PROXY header + `first`（已读出的首字节）→ 双向 pipe。
///
/// - `conn`：客户端连接（协议识别失败需 fallback）。
/// - `first`：已从 `conn` 读出的字节（PROXY header 之后、双向 pipe 之前写给 dest）。
/// - `dest`：目标地址字符串（如 `"127.0.0.1:8080"`）。
/// - `src`/`dst`：客户端/服务端地址（PROXY protocol 用）。
/// - `xver`：PROXY protocol 版本（0/1/2）。
pub async fn fallback_to_dest<RW>(
    mut conn: RW,
    first: &[u8],
    dest: &str,
    src: SocketAddr,
    dst: SocketAddr,
    xver: u8,
) -> std::io::Result<()>
where
    RW: AsyncRead + AsyncWrite + Unpin,
{
    use tokio::io::{AsyncWriteExt, copy_bidirectional};
    use tokio::net::TcpStream;

    let mut dest_conn = TcpStream::connect(dest).await?;

    // 1. 写 PROXY protocol header（xver 0 则跳过）
    let proxy_header = encode_proxy_header(xver, src, dst);
    if !proxy_header.is_empty() {
        dest_conn.write_all(&proxy_header).await?;
    }
    // 2. 写已读出的 first buffer（如 ClientHello record，dest 需要完整 TLS 流）
    if !first.is_empty() {
        dest_conn.write_all(first).await?;
    }
    // 3. 双向 pipe（conn ↔ dest）
    copy_bidirectional(&mut conn, &mut dest_conn).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_proxy_header_xver0_empty() {
        let src: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let dst: SocketAddr = "127.0.0.1:80".parse().unwrap();
        assert!(encode_proxy_header(0, src, dst).is_empty());
    }

    #[test]
    fn encode_proxy_v1_tcp4() {
        let src: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let dst: SocketAddr = "9.10.11.12:80".parse().unwrap();
        let got = encode_proxy_header(1, src, dst);
        assert_eq!(got, b"PROXY TCP4 1.2.3.4 9.10.11.12 5678 80\r\n");
    }

    #[test]
    fn encode_proxy_v1_tcp6() {
        let src: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let dst: SocketAddr = "[2001:db8::2]:80".parse().unwrap();
        let got = encode_proxy_header(1, src, dst);
        assert_eq!(got, b"PROXY TCP6 2001:db8::1 2001:db8::2 443 80\r\n");
    }

    #[test]
    fn encode_proxy_v2_tcp4() {
        let src: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let dst: SocketAddr = "9.10.11.12:80".parse().unwrap();
        let got = encode_proxy_header(2, src, dst);
        const SIG: &[u8] = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";
        assert_eq!(&got[..12], SIG);
        assert_eq!(&got[12..16], &[0x21, 0x11, 0x00, 0x0C]);
        assert_eq!(&got[16..20], &[1, 2, 3, 4]); // src ip
        assert_eq!(&got[20..24], &[9, 10, 11, 12]); // dst ip
        assert_eq!(&got[24..28], &[0x16, 0x2E, 0x00, 0x50]); // 5678=0x162E, 80=0x50
        assert_eq!(got.len(), 28);
    }

    #[test]
    fn encode_proxy_v2_tcp6() {
        let src: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let dst: SocketAddr = "[2001:db8::2]:80".parse().unwrap();
        let got = encode_proxy_header(2, src, dst);
        const SIG: &[u8] = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";
        assert_eq!(&got[..12], SIG);
        assert_eq!(got.len(), 16 + 36);
    }

    /// fallback_to_dest 端到端：回显 dest 收到 first + 后续双向数据。
    #[tokio::test]
    async fn fallback_to_dest_pipes_first_and_stream() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = echo.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let (mut client, mut server_side) = tokio::io::duplex(1024);
        let src: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let dst: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let task = tokio::spawn(async move {
            fallback_to_dest(&mut server_side, b"HELLO-FIRST", &dest_addr.to_string(), src, dst, 0)
                .await
                .unwrap();
        });

        client.write_all(b"HELLO-FIRST").await.unwrap();
        client.flush().await.unwrap();
        let mut got = vec![0u8; 11];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(got, b"HELLO-FIRST");
        drop(client);
        let _ = task.await;
    }
}
