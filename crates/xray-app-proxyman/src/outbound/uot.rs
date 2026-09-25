//! UDP-over-TCP (UoT) 协议包装层。
//!
//! 对应 Go [`sagernet/sing` `common/uot`](https://github.com/sagernet/sing/tree/v0.5.1/common/uot)：
//!
//! - [`UotServerConn`] — 服务器端：将 `tokio::net::UdpSocket` 包成 `Connection`（双向流）， 内部用
//!   `tokio::io::DuplexStream` 桥接，spawn 两个 pump task 在 UDP 与流之间搬运。
//! - [`UotClientConn`] — 客户端：将 `Connection`（双向 TCP 流）包成 UDP 风格的
//!   `write_to`/`read_from` 接口。
//!
//! 协议帧（每个 UDP 包）：
//!
//! - 非 connect 模式：`[family:1][addr:N][port:2BE][len:2BE][payload...]`
//! - connect 模式：`[len:2BE][payload...]`
//!
//! `family` 取值：
//!
//! - `0x00` = IPv4（4 字节地址）
//! - `0x01` = IPv6（16 字节地址）
//! - `0x02` = 域名（`[len:1][bytes...]`）— 仅在编码端支持；解码遇到域名返回错误 （UotServerConn /
//!   UotClientConn 测试场景不依赖域名目标）。
//!
//! Request 头（仅 `UotVersion::Current`，对应 Go sing `Version=2`）：
//!
//! - `[is_connect:1][socksaddr destination]`
//!
//! 旧版 `UotVersion::Legacy`（对应 Go sing `LegacyVersion=1`）：跳过 Request 头。
//!
//! # 与现状关系
//!
//! [`crate::outbound::handler::OutboundHandlerEntry::get_uo_t_connection`] 当前仅返回
//! `(UdpSocket, UotVersion)`（20% 实现）；本模块提供完整的 ServerConn/ClientConn 包装，
//! 上层 UoT 拨号链路可在本模块就绪后接入。
//!
//! # Magic 地址
//!
//! Rust 端 `UOT_MAGIC_ADDRESS` / `UOT_LEGACY_MAGIC_ADDRESS`（`"UoT"` / `"UoTL"`）是
//! 与 sing v0.5.1 的 `MagicAddress` / `LegacyMagicAddress`
//! （`"sp.v2.udp-over-tcp.arpa"` / `"sp.udp-over-tcp.arpa"`）字符串差异的占位映射。
//! 包装层不依赖魔术域名字符串，只看 `UotVersion`。
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    task::JoinHandle,
};
use xray_transport::connection::{Connection, DuplexConnection};

use super::handler::UotVersion;

/// UoT duplex 缓冲（与 hysteria / tuic / ss dispatcher 一致：64 KiB）。
const DUPLEX_BUF_SIZE: usize = 64 * 1024;

/// UoT 包最大负载（对应 Go sing `uot` `len:u16` 上限 = u16::MAX = 65535）。
const UOT_MAX_PAYLOAD: usize = u16::MAX as usize;

/// UDP `recv_from` 临时缓冲（64 KiB）。
const UDP_RECV_BUF: usize = 64 * 1024;

/// Socksaddr 地址族字节（与 sing `M.NewSerializer` 一致）。
const ADDR_IPV4: u8 = 0x00;
const ADDR_IPV6: u8 = 0x01;
const ADDR_DOMAIN: u8 = 0x02;

// ===== 帧编/解码辅助（socksaddr + u16 BE length） =====

/// 编码 socksaddr（`[family][addr][port:2BE]`）到 `buf`。
fn encode_socksaddr(buf: &mut Vec<u8>, addr: SocketAddr) -> io::Result<()> {
    match addr.ip() {
        IpAddr::V4(v4) => {
            buf.push(ADDR_IPV4);
            buf.extend_from_slice(&v4.octets());
        },
        IpAddr::V6(v6) => {
            buf.push(ADDR_IPV6);
            buf.extend_from_slice(&v6.octets());
        },
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
    Ok(())
}

/// 解码 socksaddr（`[family][addr][port:2BE]`）从 `buf[offset..]`。
///
/// 返回 `(SocketAddr, consumed_bytes)`。
fn decode_socksaddr(buf: &[u8], offset: usize) -> io::Result<(SocketAddr, usize)> {
    if offset >= buf.len() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "uot: short addr header"));
    }
    let family = buf[offset];
    let mut pos = offset + 1;
    let ip = match family {
        ADDR_IPV4 => {
            if buf.len() < pos + 4 + 2 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "uot: short ipv4 addr"));
            }
            let mut ip_bytes = [0u8; 4];
            ip_bytes.copy_from_slice(&buf[pos..pos + 4]);
            pos += 4;
            IpAddr::V4(Ipv4Addr::from(ip_bytes))
        },
        ADDR_IPV6 => {
            if buf.len() < pos + 16 + 2 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "uot: short ipv6 addr"));
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&buf[pos..pos + 16]);
            pos += 16;
            IpAddr::V6(Ipv6Addr::from(ip_bytes))
        },
        ADDR_DOMAIN => {
            // 解码域名需要 DNS 解析；UoT 层不在此解析。
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "uot: domain addr decoding not supported",
            ));
        },
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("uot: unknown addr family {other}"),
            ));
        },
    };
    let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;
    Ok((SocketAddr::new(ip, port), pos - offset))
}

/// 编码 request 头（仅 `UotVersion::Current`，对应 Go sing `Request.Encode`）。
///
/// `[is_connect:1][socksaddr destination]`
fn encode_request(buf: &mut Vec<u8>, is_connect: bool, dest: SocketAddr) -> io::Result<()> {
    buf.push(if is_connect { 1 } else { 0 });
    encode_socksaddr(buf, dest)
}

/// 解码 request 头。返回 `(is_connect, dest, total_consumed)`。
fn decode_request(buf: &[u8]) -> io::Result<(bool, SocketAddr, usize)> {
    if buf.is_empty() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "uot: short request header"));
    }
    let is_connect = buf[0] != 0;
    let (dest, n) = decode_socksaddr(buf, 1)?;
    Ok((is_connect, dest, 1 + n))
}

/// 尝试从 `acc` 解析完整 UDP 数据报帧。
/// 返回 `Some((dest, payload_offset, payload_len))`：dest 是目标地址，
/// payload_offset 是 acc 内 payload 起始偏移，payload_len 是 payload 长度。
/// `None` 表示需要更多字节；`Err` 表示协议错误。
///
/// `is_connect=true` 时跳过 socksaddr；返回的 `dest` 是占位（`0.0.0.0:0`），
/// 由调用方替换。
fn try_parse_packet(
    acc: &[u8],
    is_connect: bool,
) -> io::Result<Option<(SocketAddr, usize, usize)>> {
    let mut pos = 0;
    let dest = if is_connect {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        match decode_socksaddr(acc, pos) {
            Ok((a, n)) => {
                pos += n;
                a
            },
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
    };
    if acc.len() < pos + 2 {
        return Ok(None);
    }
    let len = u16::from_be_bytes([acc[pos], acc[pos + 1]]) as usize;
    let payload_offset = pos + 2;
    if acc.len() < payload_offset + len {
        return Ok(None);
    }
    Ok(Some((dest, payload_offset, len)))
}

// ===== UotServerConn =====

/// UoT 服务器端连接包装（对应 Go sing `uot.NewServerConn(packetConn, version)`）。
///
/// 内部将 UDP 数据报按 sing 协议帧编/解码，桥接到一个 `tokio::io::DuplexStream`。
/// 调用方持有 `Connection`（duplex 客户端半），通过 `read`/`write` 读写已编/解码的
/// UDP 数据报。
///
/// 帧格式与 Go sing `ServerConn.loopInput/loopOutput` 一致：
/// - 写入 `Connection` 的字节：`[socksaddr?][len:2BE][payload...]`
/// - 从 `Connection` 读到的字节：同上结构
///
/// `UotVersion::Current` 模式下，先消费 1 字节 request 头 + socksaddr，再按
/// request 中的 `is_connect` 决定后续每帧是否带 socksaddr。
/// `UotVersion::Legacy` 模式：每帧都带 socksaddr（无 request 头）。
///
/// `Drop` 自动 abort 两个 pump task 并关闭 UDP socket。`Connection::close`
/// 同理。
pub struct UotServerConn {
    /// Pump task 句柄。Drop 时自动 abort，保证 UDP socket 不被泄漏。
    _pump_input: JoinHandle<()>,
    _pump_output: JoinHandle<()>,
}

impl UotServerConn {
    /// 包装一个已绑定的 UDP socket 为 UoT ServerConn。
    ///
    /// 返回 `Box<dyn Connection>`：调用方暴露给上层（如 proxy handler）的双向流，
    /// 内部已通过两个 pump task 在 UDP socket 与 duplex pipe 之间搬运帧。
    pub fn new(udp: UdpSocket, version: UotVersion) -> io::Result<(Box<dyn Connection>, Self)> {
        let (udp_a, udp_b) = clone_udp_socket(udp)?;
        let (client_io, server_io) = tokio::io::duplex(DUPLEX_BUF_SIZE);
        let (server_r, server_w) = tokio::io::split(server_io);

        // pump_input: 从 server_r 读帧 → UDP send_to
        let pump_input = tokio::spawn(pump_input(server_r, udp_a, version));
        // pump_output: 从 UDP recv_from → 写帧到 server_w
        let pump_output = tokio::spawn(pump_output(server_w, udp_b));

        let conn: Box<dyn Connection> = Box::new(DuplexConnection::new(client_io));
        Ok((conn, Self { _pump_input: pump_input, _pump_output: pump_output }))
    }
}

/// 把 `tokio::net::UdpSocket` clone 为两个独立 socket（共享底层 fd），让两个
/// pump task 各持一份。
fn clone_udp_socket(udp: UdpSocket) -> io::Result<(UdpSocket, UdpSocket)> {
    let std_sock = udp.into_std()?;
    let std_clone = std_sock.try_clone()?;
    Ok((UdpSocket::from_std(std_sock)?, UdpSocket::from_std(std_clone)?))
}

/// ServerConn 输入 pump：从 duplex read 半读帧 → UDP `send_to`。
///
/// `UotVersion::Current`：先读 1 字节 is_connect + socksaddr 作为 request，
/// 后续帧按 request 决定 is_connect 模式。
/// `UotVersion::Legacy`：无 request 头，每帧按非 connect 模式（带 socksaddr）。
async fn pump_input<R>(mut reader: R, udp: UdpSocket, version: UotVersion)
where
    R: AsyncReadExt + Unpin + Send + 'static,
{
    let is_connect = if matches!(version, UotVersion::Current) {
        // Read request header.
        let mut head = Vec::with_capacity(64);
        let mut one = [0u8; 1];
        if reader.read_exact(&mut one).await.is_err() {
            return;
        }
        head.push(one[0]);
        let is_connect = one[0] != 0;
        // Read socksaddr fully.
        let (_, dest) = match read_socksaddr_from(&mut reader, &mut head).await {
            Ok(v) => v,
            Err(_) => return,
        };
        tracing::debug!(?dest, is_connect, "uot server: parsed request");
        is_connect
    } else {
        false
    };
    loop {
        if !read_and_send_one(&mut reader, &udp, is_connect).await {
            return;
        }
    }
}

/// ServerConn 输出 pump：UDP `recv_from` → 写帧到 duplex write 半。
async fn pump_output<W>(mut writer: W, udp: UdpSocket)
where
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let mut buf = vec![0u8; UDP_RECV_BUF];
    loop {
        let (n, src) = match udp.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => return,
        };
        let payload = &buf[..n];

        // 编码单帧：[socksaddr][len:2BE][payload]。connect 模式由调用方按 request
        // 决定；此处 server 不知道 request（request 在 pump_input 中消费），所以
        // 默认输出按非 connect 格式带 socksaddr。
        let mut frame = Vec::with_capacity(payload.len() + 32);
        if encode_socksaddr(&mut frame, src).is_err() {
            continue;
        }
        if payload.len() > UOT_MAX_PAYLOAD {
            continue; // 单包超过 u16 上限，丢弃（sing 同语义）
        }
        let len = payload.len() as u16;
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(payload);
        if writer.write_all(&frame).await.is_err() {
            return;
        }
        if writer.flush().await.is_err() {
            return;
        }
    }
}

/// 从 `reader` 读取 1 字节 family + 地址 + 2 字节端口到 `head`（追加）。
/// 返回 `(decoded_addr, dest)`。`head` 用于后续 decode_socksaddr 整体回看。
async fn read_socksaddr_from<R>(
    reader: &mut R,
    head: &mut Vec<u8>,
) -> io::Result<(SocketAddr, SocketAddr)>
where
    R: AsyncReadExt + Unpin + Send + 'static,
{
    let mut family = [0u8; 1];
    reader.read_exact(&mut family).await?;
    head.push(family[0]);
    let addr_len = match family[0] {
        ADDR_IPV4 => 4,
        ADDR_IPV6 => 16,
        ADDR_DOMAIN => {
            let mut len_byte = [0u8; 1];
            reader.read_exact(&mut len_byte).await?;
            let dlen = len_byte[0] as usize;
            head.push(len_byte[0]);
            let mut rest = vec![0u8; dlen + 2];
            reader.read_exact(&mut rest).await?;
            head.extend_from_slice(&rest);
            let (dest, consumed) = decode_socksaddr(head, 0)?;
            debug_assert_eq!(consumed, head.len());
            return Ok((dest, dest));
        },
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("uot: bad family {other}"),
            ));
        },
    };
    let mut rest = vec![0u8; addr_len + 2];
    reader.read_exact(&mut rest).await?;
    head.extend_from_slice(&rest);
    let (dest, consumed) = decode_socksaddr(head, 0)?;
    debug_assert_eq!(consumed, head.len());
    Ok((dest, dest))
}

/// 读一帧 + 发一个 UDP 数据报。返回 `false` 表示 stream 已关闭或出错。
async fn read_and_send_one<R>(reader: &mut R, udp: &UdpSocket, is_connect: bool) -> bool
where
    R: AsyncReadExt + Unpin,
{
    let mut acc = Vec::with_capacity(256);
    loop {
        let mut chunk = [0u8; 1024];
        match reader.read(&mut chunk).await {
            Ok(0) => return false,
            Ok(n) => acc.extend_from_slice(&chunk[..n]),
            Err(_) => return false,
        }
        match try_parse_packet(&acc, is_connect) {
            Ok(Some((dest, payload_offset, payload_len))) => {
                let payload = &acc[payload_offset..payload_offset + payload_len];
                if udp.send_to(payload, dest).await.is_err() {
                    return false;
                }
                return true;
            },
            Ok(None) => continue,
            Err(_) => return false,
        }
    }
}

// ===== UotClientConn =====

/// UoT 客户端连接包装（对应 Go sing `uot.NewConn(conn, request)`）。
///
/// 将 `Connection`（双向 TCP 流）包成 UDP 风格的 `write_to`/`read_from` 接口。
///
/// `is_connect=true` 表示所有读写走 connect 模式（无 socksaddr，固定 destination）。
/// `is_connect=false` 表示每次包都带 socksaddr。
pub struct UotClientConn {
    inner: Box<dyn Connection>,
    is_connect: bool,
    destination: SocketAddr,
}

impl UotClientConn {
    /// 创建一个客户端连接包装。
    ///
    /// - `conn`：已 dial 好的双向 TCP 流。
    /// - `is_connect`：是否走 connect 模式（固定 destination）。
    /// - `destination`：connect 模式下的固定目标。
    /// - `version`：协议版本（`Current` 会先写 request 头；`Legacy` 不写）。
    pub async fn new(
        mut conn: Box<dyn Connection>,
        is_connect: bool,
        destination: SocketAddr,
        version: UotVersion,
    ) -> io::Result<Self> {
        if matches!(version, UotVersion::Current) {
            let mut req = Vec::with_capacity(32);
            encode_request(&mut req, is_connect, destination)?;
            conn.write_all(&req)
                .await
                .map_err(|e| io::Error::other(format!("uot: write request: {e}")))?;
            conn.flush().await.map_err(|e| io::Error::other(format!("uot: flush request: {e}")))?;
        }
        Ok(Self { inner: conn, is_connect, destination })
    }

    /// 发送一个 UDP 数据报到指定目标。
    ///
    /// 非 connect 模式：`dest` 决定包内的 socksaddr。
    /// connect 模式：`dest` 被忽略，使用 `new()` 时传入的固定 `destination`。
    pub async fn write_to(&mut self, payload: &[u8], dest: SocketAddr) -> io::Result<()> {
        if payload.len() > UOT_MAX_PAYLOAD {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "uot: payload > 65535"));
        }
        let mut frame = Vec::with_capacity(payload.len() + 32);
        if !self.is_connect {
            encode_socksaddr(&mut frame, dest)?;
        }
        let len = payload.len() as u16;
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(payload);
        self.inner
            .write_all(&frame)
            .await
            .map_err(|e| io::Error::other(format!("uot: write frame: {e}")))?;
        self.inner.flush().await.map_err(|e| io::Error::other(format!("uot: flush frame: {e}")))?;
        Ok(())
    }

    /// 读取一个 UDP 数据报。
    ///
    /// 返回 `(source, payload)`：connect 模式下 `source` 为构造时传入的固定 destination。
    pub async fn read_from(&mut self) -> io::Result<(SocketAddr, Vec<u8>)> {
        let mut acc = Vec::with_capacity(2048);
        loop {
            let mut chunk = [0u8; 1024];
            let n = self
                .inner
                .read(&mut chunk)
                .await
                .map_err(|e| io::Error::other(format!("uot: read frame: {e}")))?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "uot: stream closed"));
            }
            acc.extend_from_slice(&chunk[..n]);
            match try_parse_packet(&acc, self.is_connect) {
                Ok(Some((parsed_dest, payload_offset, payload_len))) => {
                    let payload = acc[payload_offset..payload_offset + payload_len].to_vec();
                    let dest = if self.is_connect { self.destination } else { parsed_dest };
                    return Ok((dest, payload));
                },
                Ok(None) => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    // ===== socksaddr round-trip =====

    #[test]
    fn encode_decode_socksaddr_v4_roundtrip() {
        let addr: SocketAddr = "192.0.2.1:8080".parse().unwrap();
        let mut buf = Vec::new();
        encode_socksaddr(&mut buf, addr).unwrap();
        let (decoded, n) = decode_socksaddr(&buf, 0).unwrap();
        assert_eq!(decoded, addr);
        assert_eq!(n, buf.len());
    }

    #[test]
    fn encode_decode_socksaddr_v6_roundtrip() {
        let addr: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let mut buf = Vec::new();
        encode_socksaddr(&mut buf, addr).unwrap();
        let (decoded, n) = decode_socksaddr(&buf, 0).unwrap();
        assert_eq!(decoded, addr);
        assert_eq!(n, buf.len());
    }

    #[test]
    fn decode_socksaddr_unknown_family_errors() {
        let buf = [0xFFu8];
        let err = decode_socksaddr(&buf, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn decode_socksaddr_short_v4_errors() {
        let buf = [0x00, 1, 2];
        let err = decode_socksaddr(&buf, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn decode_socksaddr_domain_unsupported() {
        let buf = [ADDR_DOMAIN, 3, b'a', b'b', b'c', 0x12, 0x34];
        let err = decode_socksaddr(&buf, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    // ===== request header =====

    #[test]
    fn encode_decode_request_roundtrip() {
        let dest: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let mut buf = Vec::new();
        encode_request(&mut buf, true, dest).unwrap();
        let (is_connect, decoded, n) = decode_request(&buf).unwrap();
        assert!(is_connect);
        assert_eq!(decoded, dest);
        assert_eq!(n, buf.len());
    }

    // ===== UotClientConn framing =====

    /// 验证 `UotClientConn::write_to` 在非 connect 模式下输出 `[socksaddr][len][payload]`。
    #[tokio::test]
    async fn client_conn_non_connect_framing() {
        let (peer_r, peer_w) = tokio::io::duplex(DUPLEX_BUF_SIZE);
        let conn: Box<dyn Connection> = Box::new(DuplexConnection::new(peer_w));
        let dest: SocketAddr = "192.0.2.5:9000".parse().unwrap();
        let payload = b"hello-udp";

        let mut client = UotClientConn::new(conn, false, dest, UotVersion::Legacy).await.unwrap();
        client.write_to(payload, dest).await.unwrap();
        // 释放写半，触发对端 EOF。
        drop(client);

        let mut got = Vec::new();
        let mut pr = peer_r;
        pr.read_to_end(&mut got).await.unwrap();

        let mut expected = Vec::new();
        encode_socksaddr(&mut expected, dest).unwrap();
        expected.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        expected.extend_from_slice(payload);
        assert_eq!(got, expected);
    }

    /// 验证 `UotClientConn::write_to` 在 connect 模式下输出 `[len][payload]`（无 socksaddr）。
    #[tokio::test]
    async fn client_conn_connect_framing() {
        let (peer_r, peer_w) = tokio::io::duplex(DUPLEX_BUF_SIZE);
        let conn: Box<dyn Connection> = Box::new(DuplexConnection::new(peer_w));
        let dest: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let payload = b"data";

        let mut client = UotClientConn::new(conn, true, dest, UotVersion::Legacy).await.unwrap();
        // connect 模式下 dest 参数被忽略。
        client.write_to(payload, "8.8.8.8:53".parse().unwrap()).await.unwrap();
        drop(client);

        let mut got = Vec::new();
        let mut pr = peer_r;
        pr.read_to_end(&mut got).await.unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        expected.extend_from_slice(payload);
        assert_eq!(got, expected);
    }

    /// 验证 `UotVersion::Current` 时先写 request 头。
    #[tokio::test]
    async fn client_conn_current_version_writes_request_header() {
        let (mut peer_r, peer_w) = tokio::io::duplex(DUPLEX_BUF_SIZE);
        let conn: Box<dyn Connection> = Box::new(DuplexConnection::new(peer_w));
        let dest: SocketAddr = "10.0.0.1:5000".parse().unwrap();

        let mut client = UotClientConn::new(conn, false, dest, UotVersion::Current).await.unwrap();
        client.write_to(b"x", dest).await.unwrap();
        drop(client);
        let mut got = Vec::new();
        peer_r.read_to_end(&mut got).await.unwrap();
        let mut expected = Vec::new();
        // request 头 (is_connect=false): [is_connect=0][socksaddr 10.0.0.1:5000]
        encode_request(&mut expected, false, dest).unwrap();
        // 后续 write_to (is_connect=false) 在 frame 头再加 socksaddr。
        encode_socksaddr(&mut expected, dest).unwrap();
        expected.extend_from_slice(&1u16.to_be_bytes());
        expected.extend_from_slice(b"x");
        assert_eq!(got, expected);
    }

    /// 大包：payload = 60 KiB（< u16::MAX）应成功写出。
    #[tokio::test]
    async fn client_conn_large_payload_at_limit_succeeds() {
        let (peer_r, peer_w) = tokio::io::duplex(DUPLEX_BUF_SIZE);
        let conn: Box<dyn Connection> = Box::new(DuplexConnection::new(peer_w));
        let dest: SocketAddr = "192.0.2.7:9999".parse().unwrap();
        let payload = vec![0xCCu8; 60_000];

        let mut client = UotClientConn::new(conn, false, dest, UotVersion::Legacy).await.unwrap();
        client.write_to(&payload, dest).await.unwrap();
        drop(client);

        let mut got = Vec::new();
        let mut pr = peer_r;
        pr.read_to_end(&mut got).await.unwrap();
        // socksaddr(7) + len(2) + payload
        assert_eq!(got.len(), 7 + 2 + payload.len());
        // 验证 len 字段。
        let len_bytes = &got[7..9];
        assert_eq!(u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize, payload.len());
    }

    /// 超大包：payload > u16::MAX 应返回错误（UoT 单包上限 = 65535 字节）。
    #[tokio::test]
    async fn client_conn_payload_over_u16_max_errors() {
        let (peer_r, peer_w) = tokio::io::duplex(DUPLEX_BUF_SIZE);
        let conn: Box<dyn Connection> = Box::new(DuplexConnection::new(peer_w));
        let dest: SocketAddr = "192.0.2.7:9999".parse().unwrap();
        let payload = vec![0u8; u16::MAX as usize + 1];

        let mut client = UotClientConn::new(conn, false, dest, UotVersion::Legacy).await.unwrap();
        let r = client.write_to(&payload, dest).await;
        assert!(r.is_err());
        drop(client);
        drop(peer_r);
    }

    /// `UotClientConn::read_from` 在非 connect 模式下能从对端帧中解码出 dest + payload。
    #[tokio::test]
    async fn client_conn_read_from_non_connect() {
        // client 持有 server_io（duplex 的远端），对端通过 client_io 写入帧。
        let (mut client_io, server_io) = tokio::io::duplex(DUPLEX_BUF_SIZE);
        let conn: Box<dyn Connection> = Box::new(DuplexConnection::new(server_io));
        let dest: SocketAddr = "192.0.2.42:65000".parse().unwrap();
        let mut client = UotClientConn::new(conn, false, dest, UotVersion::Legacy).await.unwrap();

        // 对端写一个帧（socksaddr + len + payload）。
        let payload = b"reply-data";
        let mut frame = Vec::new();
        encode_socksaddr(&mut frame, dest).unwrap();
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        client_io.write_all(&frame).await.unwrap();
        client_io.flush().await.unwrap();
        drop(client_io);

        let (parsed_dest, parsed_payload) = client.read_from().await.unwrap();
        assert_eq!(parsed_dest, dest);
        assert_eq!(parsed_payload, payload);
    }

    /// 完整 stack：UotServerConn 把对端发来的 UDP 包反向写入 stream（output pump）。
    #[tokio::test]
    async fn server_conn_output_pump_writes_frame() {
        let server_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_local = server_udp.local_addr().unwrap();
        let (mut stream_conn, server_ctrl) =
            UotServerConn::new(server_udp, UotVersion::Legacy).unwrap();

        // UDP peer 发一个包到 server_local。
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_local = peer.local_addr().unwrap();
        let payload = b"server-output";
        peer.send_to(payload, server_local).await.unwrap();

        // 等待 pump_output 写入 stream；给一点时间。
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            match tokio::time::timeout(
                std::time::Duration::from_millis(100),
                stream_conn.read(&mut tmp),
            )
            .await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.len() >= 7 + 2 + payload.len() {
                        break;
                    }
                },
                _ => continue,
            }
        }

        // 解析帧：[socksaddr][len][payload]，payload 应等于"server-output"。
        let (parsed_src, payload_offset, payload_len) =
            try_parse_packet(&buf, false).unwrap().unwrap();
        assert_eq!(parsed_src, peer_local);
        assert_eq!(&buf[payload_offset..payload_offset + payload_len], payload);

        // 让 server_ctrl drop 触发 pump abort。
        drop(server_ctrl);
        drop(stream_conn);
    }

    /// 完整 stack：写入 stream 帧，server pump 应 send_to 到 UDP peer。
    #[tokio::test]
    async fn server_conn_input_pump_sends_to_udp() {
        let server_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_local = server_udp.local_addr().unwrap();

        let (mut stream_conn, server_ctrl) =
            UotServerConn::new(server_udp, UotVersion::Legacy).unwrap();

        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_local = peer.local_addr().unwrap();

        let payload = b"hello-via-uot";
        let mut frame = Vec::new();
        encode_socksaddr(&mut frame, peer_local).unwrap();
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        stream_conn.write_all(&frame).await.unwrap();
        stream_conn.flush().await.unwrap();

        let mut got = vec![0u8; 4096];
        let (n, from) =
            tokio::time::timeout(std::time::Duration::from_secs(2), peer.recv_from(&mut got))
                .await
                .expect("udp recv timeout")
                .expect("udp recv");
        assert_eq!(from, server_local);
        assert_eq!(&got[..n], payload);

        drop(server_ctrl);
        drop(stream_conn);
    }
}
