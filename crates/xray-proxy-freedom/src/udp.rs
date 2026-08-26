//! Freedom UDP relay——XUDP 帧流 ↔ 原始 UDP 数据报。
//!
//! 对应 Go `proxy/freedom/freedom.go` 的 UDP 分支：
//! - **request** 方向：[`xray_xudp::packet::PacketReader`] 从 link.reader 读 XUDP 帧，
//!   提取 (dest, payload)，通过 [`UdpSocket::send_to`] 发往目标。
//! - **response** 方向：[`UdpSocket::recv_from`] 读回 UDP 响应，用
//!   [`xray_xudp::packet::PacketWriter`] 封装为 XUDP 帧写回 link.writer。
//!
//! ## link 语义
//!
//! dispatcher 给 freedom 的 `link` 是一条**字节流**——对 UDP 目标，inbound 侧
//! （如 SOCKS UDP associate / dokodemo / tun）已将每个 UDP 数据报封装为 XUDP 帧
//! 写入流。freedom 的职责就是拆帧 → 真实 UDP socket → 装帧回写。
//!
//! ## ponytail: 单连接单 dest
//!
//! 每次 dispatch 创建一个 `UdpSocket`，所有帧都发往从首帧或原始 dest 解析出的目标。
//! 真实 Xray 对 Keep 帧的 `udp_target` 字段做 per-packet 路由（不同 dest），当前也支持
//! 但共享同一 socket（NAT 下 per-dest 用同一本地端口）。

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;

use xray_buf::io::{Reader, Writer};
use xray_buf::multi::MultiBuffer;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::port::Port;
use xray_transport::link::Link;
use xray_xudp::packet::{PacketError, PacketReader, PacketWriter};

/// XUDP GlobalID 长度（与 Go `xudp` 一致，私有常量 GLOBAL_ID_LEN=8）。
const GLOBAL_ID_LEN: usize = 8;

/// UDP recv 缓冲区大小（单包最大 65535 字节）。
const RECV_BUF_SIZE: usize = 65535;

/// Freedom UDP relay 主入口（无 noises）。
pub async fn relay(dest: &Destination, link: Link) -> io::Result<()> {
    relay_with_noises(dest, link, &[]).await
}

/// Freedom UDP relay 主入口（首包前注入 noises，对齐 Go `NoisePacketWriter`）。
///
/// 解析目标地址 → 绑定 UDP socket → 双向并发转发 XUDP 帧与 UDP 数据报。
/// 任一方向结束（EOF / 错误）时整体返回。
pub async fn relay_with_noises(
    dest: &Destination,
    link: Link,
    noises: &[crate::config::Noise],
) -> io::Result<()> {
    let Link { mut reader, mut writer } = link;

    // 1. 解析目标地址（Domain → IP）
    let default_target = resolve_socket_addr(dest).await?;

    // 2. 绑定 UDP socket（与目标同族）
    let bind_addr = match default_target {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let sock = Arc::new(UdpSocket::bind(bind_addr).await?);

    // 3. GlobalID（随机 8 字节，对应 Go xudp.NewPacketWriter 的 GlobalID）
    let global_id: [u8; GLOBAL_ID_LEN] = rand::random();

    // 4. 响应 pump: socket.recv_from → XUDP 帧 → link.writer
    let resp_sock = Arc::clone(&sock);
    let resp_global_id = global_id;
    let resp_task = tokio::spawn(async move {
        pump_response(&resp_sock, resp_global_id, &mut writer).await
    });

    // 5. 请求 pump: link.reader → XUDP 帧 → socket.send_to
    //    noises 在首个真实数据报前注入（对齐 Go NoisePacketWriter 首写触发）
    let mut noises = if noises.is_empty() { None } else { Some(noises.to_vec()) };
    let req_result = pump_request(&sock, default_target, &mut reader, &mut noises).await;

    // 请求方向结束（link EOF），等待响应方向也结束
    let _ = resp_task.await;

    req_result
}

/// 将目标 Destination 解析为 SocketAddr。
///
/// IP 地址直接转换；Domain 通过系统 DNS 解析。
async fn resolve_socket_addr(dest: &Destination) -> io::Result<SocketAddr> {
    let port = dest.port().value();
    match dest.address() {
        Address::IPv4(ip) => Ok(SocketAddr::new(IpAddr::V4(*ip), port)),
        Address::IPv6(ip) => Ok(SocketAddr::new(IpAddr::V6(*ip), port)),
        Address::Domain(domain) => {
            let lookup = format!("{}:{}", domain, port);
            tokio::net::lookup_host(&lookup)
                .await?
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "DNS resolve failed"))
        }
    }
}

/// 请求方向：从 link.reader 读 XUDP 帧 → socket.send_to。
///
/// 对应 Go `freedom.Process` UDP 分支的 `request` goroutine +
/// `xudp.NewPacketReader(link.Reader)`。
async fn pump_request(
    sock: &UdpSocket,
    default_target: SocketAddr,
    reader: &mut Box<dyn Reader>,
    noises: &mut Option<Vec<crate::config::Noise>>,
) -> io::Result<()> {
    let mut accum: Vec<u8> = Vec::new();
    loop {
        // 尽量从 accum 解析完整帧
        let mut made_progress = true;
        while made_progress {
            made_progress = parse_and_send(sock, &mut accum, default_target, noises).await?;
        }
        // 读更多字节
        match reader.read_multi_buffer().await {
            Ok(mb) => {
                if mb.is_empty() {
                    return Ok(()); // EOF
                }
                accum.extend_from_slice(&mb.to_vec());
            }
            Err(_) => return Ok(()), // 读错误视作 EOF
        }
    }
}

/// 从 accum 前端解析一个 XUDP 帧，成功则 send_to 并返回 true（有进展）。
/// 帧不完整（UnexpectedEof）或 accum 为空返回 false。致命错误返回 Err。
async fn parse_and_send(
    sock: &UdpSocket,
    accum: &mut Vec<u8>,
    default_target: SocketAddr,
    noises: &mut Option<Vec<crate::config::Noise>>,
) -> io::Result<bool> {
    if accum.is_empty() {
        return Ok(false);
    }

    // 用 Cursor + 同步 PacketReader 解析一帧
    let (result, consumed) = {
        let mut cursor = std::io::Cursor::new(&accum[..]);
        let mut pr = PacketReader::new(&mut cursor);
        let r = pr.read_packet();
        let pos = cursor.position() as usize;
        (r, pos)
    };

    match result {
        Ok(Some(pkt)) => {
            accum.drain(..consumed);
            let (data, udp_target) = pkt.into_parts();
            let target = udp_target
                .as_ref()
                .and_then(dest_to_socket_addr)
                .unwrap_or(default_target);
            // 首个真实数据报前发送 noises（对齐 Go NoisePacketWriter.WriteMultiBuffer：
            // 噪声包发往同一目标，applyTo 按目标 IP 族过滤，写后按 delay 睡眠）
            if let Some(ns) = noises.take() {
                send_noises(sock, target, &ns).await?;
            }
            sock.send_to(&data, target).await?;
            Ok(true)
        }
        Ok(None) => Ok(false), // 流内干净结束，但 accum 可能有残留 → 等更多数据
        Err(PacketError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
    }
}

/// 依次发送 noise 包到 `target`（对应 Go `NoisePacketWriter` 噪声循环 :691-724）。
async fn send_noises(
    sock: &UdpSocket,
    target: SocketAddr,
    noises: &[crate::config::Noise],
) -> io::Result<()> {
    use rand::RngCore;
    for n in noises {
        let is_v4 = target.is_ipv4();
        match n.apply_to.as_str() {
            "ipv4" if !is_v4 => continue,
            "ipv6" if is_v4 => continue,
            _ => {}
        }
        // 用户指定 packet 或随机长度噪声（[length_min, length_max) 半开，对齐 Go RandBetween）
        let packet: Vec<u8> = if !n.packet.is_empty() {
            n.packet.clone()
        } else {
            let mut buf = vec![0u8; crate::fragment::rand_between(n.length_min, n.length_max) as usize];
            rand::rng().fill_bytes(&mut buf);
            buf
        };
        sock.send_to(&packet, target).await?;
        if n.delay_min != 0 || n.delay_max != 0 {
            tokio::time::sleep(std::time::Duration::from_millis(
                crate::fragment::rand_between(n.delay_min, n.delay_max),
            ))
            .await;
        }
    }
    Ok(())
}

/// 响应方向：socket.recv_from → XUDP 帧 → link.writer。
///
/// 对应 Go `freedom.Process` UDP 分支的 `response` goroutine +
/// `xudp.NewPacketWriter(link.Writer, ctx)`。帧来源地址 = recv_from 的真实
/// peer（multi-dest 会话下客户端才能区分各目标的响应来源）。
async fn pump_response(
    sock: &UdpSocket,
    global_id: [u8; GLOBAL_ID_LEN],
    writer: &mut Box<dyn Writer>,
) -> io::Result<()> {
    let mut buf = vec![0u8; RECV_BUF_SIZE];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        if n == 0 {
            continue;
        }
        // 帧来源 = 响应真实来源
        let source = Destination::udp(
            match peer.ip() {
                IpAddr::V4(v) => Address::IPv4(v),
                IpAddr::V6(v) => Address::IPv6(v),
            },
            Port::new(peer.port()),
        );
        // 用同步 PacketWriter 装帧
        let mut frame = Vec::with_capacity(n + 64);
        let mut pw = PacketWriter::new(&mut frame, source, global_id);
        if pw.write_packet(&buf[..n]).is_err() {
            return Ok(());
        }
        drop(pw);

        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&frame);
        if writer.write_multi_buffer(mb).await.is_err() {
            return Ok(()); // writer 关闭
        }
    }
}
/// Destination → SocketAddr（仅 IP 地址，Domain 返回 None）。
fn dest_to_socket_addr(dest: &Destination) -> Option<SocketAddr> {
    let port = dest.port().value();
    match dest.address() {
        Address::IPv4(ip) => Some(SocketAddr::new(IpAddr::V4(*ip), port)),
        Address::IPv6(ip) => Some(SocketAddr::new(IpAddr::V6(*ip), port)),
        Address::Domain(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_common::net::address::Address;
    use xray_common::net::network::Network;
    use xray_common::net::port::Port;

    /// 构造 IPv4 UDP Destination。
    fn udp_dest(ip: &str, port: u16) -> Destination {
        let addr = Address::from_ipv4_bytes(ip.parse::<std::net::Ipv4Addr>().unwrap().octets());
        Destination::new(addr, Port::new(port), Network::UDP)
    }

    /// 端到端：freedom UDP relay 把 XUDP 帧 → UDP echo server → XUDP 帧回写。
    #[tokio::test]
    async fn udp_relay_echo_roundtrip() {
        // 1. 启动 UDP echo server
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut buf = vec![0u8; RECV_BUF_SIZE];
            loop {
                match echo.recv_from(&mut buf).await {
                    Ok((n, peer)) => {
                        let _ = echo.send_to(&buf[..n], peer).await;
                    }
                    Err(_) => break,
                }
            }
        });

        // 2. 构造 link（pipe 对）：client 写 XUDP 帧 → freedom relay → UDP server
        //    freedom relay 回写 XUDP 帧 → client 读
        let pipe_opt = xray_buf::pipe::PipeOption::default();
        let (up_r, up_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let (dn_r, dn_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let link = Link::new(
            Box::new(up_r) as Box<dyn Reader>,
            Box::new(dn_w) as Box<dyn Writer>,
        );

        let dest = udp_dest("127.0.0.1", echo_addr.port());
        let relay_task = tokio::spawn(async move {
            relay(&dest, link).await
        });

        // 3. client 写一个 XUDP 帧
        let mut client_writer = Box::new(up_w) as Box<dyn Writer>;
        let global_id: [u8; GLOBAL_ID_LEN] = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut frame = Vec::new();
        {
            let mut pw = PacketWriter::new(
                &mut frame,
                udp_dest("127.0.0.1", echo_addr.port()),
                global_id,
            );
            pw.write_packet(b"hello-udp").unwrap();
        }
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&frame);
        client_writer.write_multi_buffer(mb).await.unwrap();

        // 4. client 读回 echo（XUDP 帧）
        let mut client_reader = Box::new(dn_r) as Box<dyn Reader>;
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client_reader.read_multi_buffer(),
        )
        .await
        .expect("timeout reading echo")
        .expect("read ok");

        let resp_bytes = resp.to_vec();
        // 解析回包 XUDP 帧
        let mut pr = PacketReader::new(std::io::Cursor::new(&resp_bytes[..]));
        let pkt = pr.read_packet().expect("parse response frame").expect("non-empty");
        assert_eq!(pkt.data(), b"hello-udp");

        // 关闭 client writer 让 relay 的 request pump 收到 EOF
        drop(client_writer);

        // relay 应正常结束
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            relay_task,
        )
        .await;

        echo_task.abort();
    }

    /// 多包往返：连续写多个 XUDP 帧，验证都能 echo 回来。
    #[tokio::test]
    async fn udp_relay_multiple_packets() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut buf = vec![0u8; RECV_BUF_SIZE];
            loop {
                match echo.recv_from(&mut buf).await {
                    Ok((n, peer)) => {
                        let _ = echo.send_to(&buf[..n], peer).await;
                    }
                    Err(_) => break,
                }
            }
        });

        let pipe_opt = xray_buf::pipe::PipeOption::default();
        let (up_r, up_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let (dn_r, dn_w) = xray_buf::pipe::new_with_option(pipe_opt);
        let link = Link::new(
            Box::new(up_r) as Box<dyn Reader>,
            Box::new(dn_w) as Box<dyn Writer>,
        );

        let dest = udp_dest("127.0.0.1", echo_addr.port());
        let relay_task = tokio::spawn(async move { relay(&dest, link).await });

        let mut client_writer = Box::new(up_w) as Box<dyn Writer>;
        let global_id: [u8; GLOBAL_ID_LEN] = [0xAA; GLOBAL_ID_LEN];
        let dest_frame = udp_dest("127.0.0.1", echo_addr.port());

        // 写 3 个包到一个帧缓冲
        let mut combined = Vec::new();
        {
            let mut pw = PacketWriter::new(&mut combined, dest_frame.clone(), global_id);
            pw.write_packet(b"one").unwrap();
            pw.write_packet(b"two").unwrap();
            pw.write_packet(b"three").unwrap();
        }
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&combined);
        client_writer.write_multi_buffer(mb).await.unwrap();

        // 读回响应，累积字节（帧可能跨 read_multi_buffer），直到解析出 3 个包或超时
        let mut client_reader = Box::new(dn_r) as Box<dyn Reader>;
        let mut collected = Vec::new();
        let mut payloads = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while payloads.len() < 3 {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                panic!("timeout: only got {} packets", payloads.len());
            }
            match tokio::time::timeout(remaining, client_reader.read_multi_buffer()).await {
                Ok(Ok(mb)) if !mb.is_empty() => collected.extend_from_slice(&mb.to_vec()),
                _ => {}
            }
            // 尝试从累积字节解析完整帧
            let mut pr = PacketReader::new(std::io::Cursor::new(&collected[..]));
            payloads.clear();
            while let Ok(Some(pkt)) = pr.read_packet() {
                payloads.push(pkt.data().to_vec());
            }
        }
        assert_eq!(payloads, vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]);

        drop(client_writer);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), relay_task).await;
        echo_task.abort();
    }

    #[test]
    fn dest_to_socket_addr_ipv4() {
        let d = udp_dest("127.0.0.1", 8080);
        let sa = dest_to_socket_addr(&d).unwrap();
        assert_eq!(sa.port(), 8080);
        assert!(sa.is_ipv4());
    }

    #[test]
    fn dest_to_socket_addr_domain_returns_none() {
        let d = Destination::new(
            Address::Domain("example.com".into()),
            Port::new(443),
            Network::UDP,
        );
        assert!(dest_to_socket_addr(&d).is_none());
    }
}
