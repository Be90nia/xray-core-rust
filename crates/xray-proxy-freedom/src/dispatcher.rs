//! Freedom outbound → DialBridge 适配器（阶段 1 切片 1e）。
//!
//! Freedom 是直连代理——直接拨号到目标，无中间服务器。所以 DialFn 闭包不需要
//! 捕获任何 client 配置，直接调 [`dial_system`] 返回 [`Connection`]。
//!
//! `dial_system` 已返回 `Box<dyn Connection>`，无需 wrapper。
//!
//! [`DialBridge`]: xray_app_dispatcher::default::DialBridge
//! [`DialFn`]: xray_app_dispatcher::default::DialFn
//! [`Connection`]: xray_transport::connection::Connection

use xray_app_dispatcher::default::DialFn;
use xray_common::net::destination::Destination;
use xray_transport::connection::Connection;
use xray_transport::sockopt::SocketOptions;
use xray_transport::system_dialer::dial_system;

use crate::config::Config;

/// 构造 Freedom 的 DialFn 闭包（默认配置）。
///
/// 等价 [`make_dial_fn_with_config`] 传入 `Config::default()`。保留无参签名以兼容既有调用方。
#[must_use]
pub fn make_dial_fn() -> DialFn {
    make_dial_fn_with_config(Config::default())
}

/// 构造 Freedom 的 DialFn 闭包（携带解析后的 [`Config`]）。
///
/// 当前 dial 路径消费 SocketOptions 默认值与 `fragment`（TCP 分片包装，
/// 对齐 Go :410-418）；domainStrategy 解析已存入 Config，DNS 策略拨号路径
/// 未消费。noises 由 [`FreedomDispatchBridge::with_noises`] 接入 UDP 路径。
/// ponytail: domain_strategy 当前解析即存储，dial 未消费。
///
/// # Panics
///
/// 不会 panic；错误以 `Err(String)` 返回。
pub fn make_dial_fn_with_config(config: Config) -> DialFn {
    let fragment = config.fragment;
    Arc::new(move |dest: &Destination| {
        let dest = dest.clone();
        let fragment = fragment.clone();
        Box::pin(async move {
            let sockopt = SocketOptions::default();
            let conn: Box<dyn Connection> = dial_system(&dest, &sockopt)
                .await
                .map_err(|e| format!("freedom dial: {e}"))?;
            // fragment 配置存在时 dial 后包 writer（对齐 Go :410-418）
            let conn: Box<dyn Connection> = match fragment {
                Some(f) => Box::new(crate::fragment::FragmentConnection::new(conn, f)),
                None => conn,
            };
            Ok(conn)
        })
    })
}

use std::sync::Arc;

use xray_app_dispatcher::DispatchHandler;
use xray_app_dispatcher::default::{DialBridge, PinFuture};

use xray_common::net::network::Network;
use xray_transport::link::Link;

/// Freedom dispatch handler——在 TCP DialBridge 之上增加 UDP relay。
///
/// 对应 Go `proxy/freedom/freedom.go::Handler`：TCP 走 `dial_system` 流桥接
/// （委托内部 [`DialBridge`]，fragment 配置经 [`make_dial_fn_with_config`]
/// 包装 writer）；UDP 走 [`crate::udp::relay_with_noises`]（XUDP 帧 ↔ 原始
/// 数据报，noises 首包前注入，对齐 Go `NoisePacketWriter`）。
///
/// **代理链**：仅 TCP 支持代理链（通过内部 DialBridge）；UDP 直连目标，
/// 不支持代理链（与 Go freedom 一致——freedom 是直连出口）。
pub struct FreedomDispatchBridge {
    tag: String,
    tcp: Arc<DialBridge>,
    noises: Vec<crate::config::Noise>,
    /// sendThrough 源地址规格（bd 7zc）。UDP 分支拨号前解析并设 DIAL_SRC
    /// （TCP 分支的源 bind 由 outbound 侧 dial_fn 包装层处理）。
    send_through: Option<xray_transport::system_dialer::SendThroughSpec>,
}

impl FreedomDispatchBridge {
    /// 从已构造的 TCP [`DialBridge`] 包装。保留 `dial_bridge` 的 Arc 以便代理链 Phase 2 注入。
    #[must_use]
    pub fn from_bridge(dial_bridge: Arc<DialBridge>) -> Self {
        let tag = dial_bridge.tag().to_string();
        Self { tag, tcp: dial_bridge, noises: Vec::new(), send_through: None }
    }

    /// 设置 UDP 路径首包前注入的 noises（对齐 Go `NoisePacketWriter` 写入时机）。
    #[must_use]
    pub fn with_noises(mut self, noises: Vec<crate::config::Noise>) -> Self {
        self.noises = noises;
        self
    }

    /// 设置 sendThrough 源地址（对齐 Go SenderConfig.Via 的 UDP 分支：
    /// system_dialer.go:59-84 ListenPacket 绑源地址）。
    #[must_use]
    pub fn with_send_through(
        mut self,
        spec: xray_transport::system_dialer::SendThroughSpec,
    ) -> Self {
        self.send_through = Some(spec);
        self
    }
}

impl std::fmt::Debug for FreedomDispatchBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FreedomDispatchBridge")
            .field("tag", &self.tag)
            .finish_non_exhaustive()
    }
}

impl DispatchHandler for FreedomDispatchBridge {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn dispatch(&self, dest: &Destination, link: Link) -> PinFuture<()> {
        if dest.network() == Network::UDP {
            let tag = self.tag.clone();
            let dest = dest.clone();
            let send_through = self.send_through.clone();
            let noises = self.noises.clone();
            Box::pin(async move {
                // bd 7zc：sendThrough → DIAL_SRC scope → relay bind 源地址
                // （对应 Go DialSystem UDP 分支 src 传递）。
                let result = match send_through.as_ref().and_then(|s| s.resolve()) {
                    Some(ip) => {
                        xray_transport::system_dialer::DIAL_SRC
                            .scope(Some(ip), crate::udp::relay_with_noises(&dest, link, &noises))
                            .await
                    }
                    None => crate::udp::relay_with_noises(&dest, link, &noises).await,
                };
                if let Err(e) = result {
                    tracing::warn!(tag = %tag, "freedom udp relay ended: {e}");
                }
            })
        } else {
            // TCP：委托内部 DialBridge（fragment 经 DialFn 包装，代理链在 bridge 内）
            self.tcp.dispatch(dest, link)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use xray_app_dispatcher::default::{DefaultDispatcher, DialBridge, SimpleOhm, SniffingRequest};
    use xray_buf::io::{Reader, Writer};
    use xray_buf::multi::MultiBuffer;
    use xray_common::net::address::Address;
    use xray_common::net::network::Network;
    use xray_common::net::port::Port;

    #[tokio::test]
    async fn dispatcher_e2e_freedom_to_echo() {
        // echo server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        // dispatcher + DialBridge(freedom)
        let ohm = SimpleOhm::new();
        ohm.set_default(Arc::new(DialBridge::new("freedom-out", make_dial_fn())));
        let mut dispatcher = DefaultDispatcher::new();
        dispatcher.ohm = Some(Arc::new(ohm));

        let dest = Destination::new(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(echo_addr.port()),
            Network::TCP,
        );
        let inbound = dispatcher
            .dispatch(&dest, &SniffingRequest::default(), None, None)
            .expect("dispatch returns inbound Link");

        let mut w = inbound.writer;
        let mut r = inbound.reader;

        let payload = b"hello freedom via dispatcher";
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(payload);
        w.write_multi_buffer(mb).await.unwrap();

        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            r.read_multi_buffer(),
        )
        .await
        .expect("timeout")
        .unwrap();

        assert_eq!(resp.to_vec(), payload);
        w.shutdown();
    }

    /// bd g35 验收 3：UDP dest 经 DefaultDispatcher → FreedomDispatchBridge →
    /// freedom udp relay（XUDP 帧 ↔ UDP 数据报）直发语义回归（b2e）。
    #[tokio::test]
    async fn dispatcher_e2e_freedom_udp_direct() {
        use tokio::net::UdpSocket;
        use xray_xudp::packet::{PacketReader, PacketWriter};

        // 1. UDP echo server
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match echo.recv_from(&mut buf).await {
                    Ok((n, peer)) => {
                        let _ = echo.send_to(&buf[..n], peer).await;
                    }
                    Err(_) => break,
                }
            }
        });

        // 2. dispatcher + FreedomDispatchBridge（TCP DialBridge + UDP relay）
        let tcp_bridge = Arc::new(DialBridge::new("freedom-out", make_dial_fn()));
        let ohm = SimpleOhm::new();
        ohm.set_default(Arc::new(FreedomDispatchBridge::from_bridge(tcp_bridge)));
        let mut dispatcher = DefaultDispatcher::new();
        dispatcher.ohm = Some(Arc::new(ohm));

        // 3. dispatch UDP dest → inbound Link
        let dest = Destination::new(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(echo_addr.port()),
            Network::UDP,
        );
        let inbound = dispatcher
            .dispatch(&dest, &SniffingRequest::default(), None, None)
            .expect("dispatch returns inbound Link");
        let mut w = inbound.writer;
        let mut r = inbound.reader;

        // 4. 写 XUDP New 帧 → freedom 拆帧 send_to → echo → 回帧
        let mut frame = Vec::new();
        {
            let mut pw = PacketWriter::new(&mut frame, dest.clone(), [0x22; 8]);
            pw.write_packet(b"udp-direct").unwrap();
        }
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&frame);
        w.write_multi_buffer(mb).await.unwrap();

        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            r.read_multi_buffer(),
        )
        .await
        .expect("timeout reading udp echo");

        // 读错误（EOF）也算失败——必须拿到回帧
        let resp = resp.expect("read ok");
        let resp_bytes = resp.to_vec();
        let mut pr = PacketReader::new(std::io::Cursor::new(&resp_bytes[..]));
        let pkt = pr.read_packet().unwrap().expect("echo frame");
        assert_eq!(pkt.data(), b"udp-direct");
        w.shutdown();
        echo_task.abort();
    }

    /// bd 7zc：sendThrough → freedom UDP relay 以指定源 IP bind（对齐 Go
    /// system_dialer.go:59-84 UDP ListenPacket 绑 srcAddr）。echo server 记录
    /// recv_from 的 peer，断言源 IP 为 127.0.0.2（loopback /8 内非默认源）。
    #[tokio::test]
    async fn dispatcher_e2e_freedom_udp_send_through_binds_source() {
        use std::net::IpAddr;
        use tokio::net::UdpSocket;
        use xray_transport::system_dialer::SendThroughSpec;
        use xray_xudp::packet::PacketWriter;

        // 1. UDP echo server：记录首个 peer 源 IP
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let peer_ip = Arc::new(parking_lot::Mutex::new(None::<IpAddr>));
        let recorder = Arc::clone(&peer_ip);
        let echo_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match echo.recv_from(&mut buf).await {
                    Ok((n, peer)) => {
                        if recorder.lock().is_none() {
                            *recorder.lock() = Some(peer.ip());
                        }
                        let _ = echo.send_to(&buf[..n], peer).await;
                    }
                    Err(_) => break,
                }
            }
        });

        // 2. FreedomDispatchBridge + sendThrough=127.0.0.2
        let tcp_bridge = Arc::new(DialBridge::new("freedom-via", make_dial_fn()));
        let bridge = FreedomDispatchBridge::from_bridge(tcp_bridge)
            .with_send_through(SendThroughSpec::Fixed("127.0.0.2".parse().unwrap()));
        let ohm = SimpleOhm::new();
        ohm.set_default(Arc::new(bridge));
        let mut dispatcher = DefaultDispatcher::new();
        dispatcher.ohm = Some(Arc::new(ohm));

        // 3. dispatch UDP dest → 写 XUDP 帧 → relay 以 127.0.0.2 bind 后 send_to
        let dest = Destination::new(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(echo_addr.port()),
            Network::UDP,
        );
        let inbound = dispatcher
            .dispatch(&dest, &SniffingRequest::default(), None, None)
            .expect("dispatch returns inbound Link");
        let mut w = inbound.writer;

        let mut frame = Vec::new();
        {
            let mut pw = PacketWriter::new(&mut frame, dest.clone(), [0x33; 8]);
            pw.write_packet(b"via-127.0.0.2").unwrap();
        }
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&frame);
        w.write_multi_buffer(mb).await.unwrap();

        // 等 echo 记录 peer（轮询 3s）
        let expected: IpAddr = "127.0.0.2".parse().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while peer_ip.lock().is_none() && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(*peer_ip.lock(), Some(expected), "UDP 源 IP 应为 sendThrough 指定的 127.0.0.2");
        echo_task.abort();
    }

    /// bd v2q：fragment 配置经 make_dial_fn_with_config → DialBridge TCP 路径端到端。
    /// tlshello 模式：客户端发一条 TLS record，服务端字节级解析应看到多条重组
    /// record（分片发生在 wire 上，与 TCP 分段无关），payload 重组 == 原文，
    /// 且回程（读路径透传）不受分片影响。
    #[tokio::test]
    async fn dispatcher_tcp_fragment_tlshello_e2e() {
        use crate::config::Fragment;

        // echo server：全量回显并保留收到的原始字节
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut all = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        all.extend_from_slice(&buf[..n]);
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            all
        });

        let config = Config {
            fragment: Some(Fragment {
                packets_from: 0,
                packets_to: 1,
                length_min: 4,
                length_max: 4,
                interval_min: 0,
                interval_max: 0,
                max_split_min: 0,
                max_split_max: 0,
            }),
            ..Config::default()
        };
        let ohm = SimpleOhm::new();
        ohm.set_default(Arc::new(DialBridge::new(
            "freedom-frag",
            make_dial_fn_with_config(config),
        )));
        let mut dispatcher = DefaultDispatcher::new();
        dispatcher.ohm = Some(Arc::new(ohm));

        let dest = Destination::new(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(addr.port()),
            Network::TCP,
        );
        let inbound = dispatcher
            .dispatch(&dest, &SniffingRequest::default(), None, None)
            .expect("dispatch returns inbound Link");
        let mut w = inbound.writer;
        let mut r = inbound.reader;

        // 一条完整 TLS handshake record：type=22 + version 3,1 + len=12 + payload
        let payload: Vec<u8> = (0..12u8).collect();
        let mut record = vec![22u8, 3, 1, 0, payload.len() as u8];
        record.extend_from_slice(&payload);
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(&record);
        w.write_multi_buffer(mb).await.unwrap();

        // 回程透传：echo 回来的字节 == 服务端收到的字节
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            r.read_multi_buffer(),
        )
        .await
        .expect("timeout")
        .expect("read ok");

        w.shutdown();
        let received = server.await.unwrap();
        assert_eq!(resp.to_vec(), received, "down path transparent to fragmentation");

        // 字节级解析：单条 record 被重组为多条小 record
        let mut records = Vec::new();
        let mut i = 0;
        while i + 5 <= received.len() {
            let l = ((received[i + 3] as usize) << 8) | received[i + 4] as usize;
            assert!(i + 5 + l <= received.len(), "truncated record at {i}");
            records.push((received[i], received[i + 5..i + 5 + l].to_vec()));
            i += 5 + l;
        }
        assert_eq!(i, received.len(), "no trailing garbage");
        assert!(records.len() >= 3, "fragmented on the wire: {} records", records.len());
        assert!(records.iter().all(|(t, _)| *t == 22), "record type preserved");
        let data: Vec<u8> = records.iter().flat_map(|(_, p)| p.clone()).collect();
        assert_eq!(data, payload, "reassembled handshake == original");
    }
}
