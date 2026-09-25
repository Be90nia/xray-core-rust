//! 中央 UDP dispatch session（bd b2e）。
//!
//! 对应 Go `transport/internet/udp/dispatcher.go`：每个 inbound UDP 会话
//! 创建一个 [`UdpDispatchSession`]，所有数据报经 [`DispatchHandler::dispatch`]
//! 走 routing 规则选择 outbound，不再直连 raw socket。
//!
//! ## Link 语义（与 freedom outbound 的 XUDP 帧约定一致）
//!
//! - `link.reader`：XUDP 帧流（session 写入请求帧，outbound 拆帧发送）
//! - `link.writer`：XUDP 帧流（outbound 装帧写入响应，session 拆帧收回包）
//!
//! ## cone NAT
//!
//! 单 session 只建立一个 dispatch link（首包目标决定 routing 与 outbound
//! default target）；后续帧在帧头携带各自真实目标，由 outbound 侧（如
//! freedom）从同一 socket 发出——天然 cone NAT，与 Go `udp.Dispatcher`
//! 单 connEntry 模型一致。
//!
//! ## ponytail: 无内置空闲超时
//!
//! Go `CancelAfterInactivity(1min)` 的会话淘汰由调用方生命周期管理
//! （SOCKS relay task 随 TCP 控制连接 abort；session drop → duplex 关闭 →
//! outbound relay EOF 退出）。若后续出现长生命周期无控制连接的 UDP 入站
//! （tun/fakeDNS），再补 idle deadline。

use std::{io, sync::Arc};

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use xray_buf::io::{new_reader, new_writer};
use xray_common::net::destination::Destination;
use xray_transport::link::Link;
use xray_xudp::packet::{FrameMetadata, PacketError, PacketReader};

use crate::DispatchHandler;

/// duplex 单方向缓冲上限（单包 65535 + 帧头，留多包裕量）。
const DUPLEX_BUF: usize = 256 * 1024;

/// 单个 UDP 数据报上限。
const MAX_DATAGRAM: usize = 65535;

/// 已建立的 dispatch link 状态。
struct Inner {
    /// 首包目标（决定 routing 与 outbound default target）。
    dest: Destination,
    /// inbound → outbound 请求帧流写端。
    req: DuplexStream,
    /// outbound → inbound 响应帧流读端。
    resp: DuplexStream,
    /// 响应方向半帧累积缓冲。
    accum: Vec<u8>,
    /// 首帧 GlobalID（随机 8 字节，对应 Go xudp）。
    global_id: [u8; 8],
    /// 是否已发送 New 帧。
    new_sent: bool,
}

/// UDP dispatch 会话：inbound 包流 ↔ dispatcher XUDP 帧 Link 桥。
///
/// 用法（inbound UDP relay 循环）：
/// 1. `send_packet(&dest, payload)` 转发客户端数据报（首包懒建立 dispatch link）
/// 2. `recv_packet()` 收取 outbound 响应数据报（来源, payload），写回客户端
pub struct UdpDispatchSession {
    dispatcher: Arc<dyn DispatchHandler>,
    inner: Option<Inner>,
}

impl UdpDispatchSession {
    /// 创建会话。`dispatcher` 为生产路由 handler 或任意支持 UDP 目标的
    /// [`DispatchHandler`]（outbound 侧须按 XUDP 帧约定消费 link，如 freedom）。
    pub fn new(dispatcher: Arc<dyn DispatchHandler>) -> Self {
        Self { dispatcher, inner: None }
    }

    /// 发送一个 UDP 数据报。
    ///
    /// 首包懒建立 dispatch link：两条 duplex 管道 + 后台 `dispatch(dest, link)`。
    /// 首帧 XUDP `New`（含随机 GlobalID），后续 `Keep`（帧头带各自真实目标，
    /// 由 outbound per-packet 路由）。
    pub async fn send_packet(&mut self, dest: &Destination, payload: &[u8]) -> io::Result<()> {
        // 零长/超长静默跳过 = Go xudp PacketWriter 同款（xudp.go:100
        // `length == 0 || length+666 > buf.Size → continue`，iq1o 核对）。
        // 空 datagram 不进 dispatch link，响应侧照发语义不受影响。
        if payload.is_empty() || payload.len() > MAX_DATAGRAM {
            return Ok(());
        }
        if self.inner.is_none() {
            self.establish(dest.clone());
        }
        let inner = self.inner.as_mut().expect("established above");

        let mut frame = Vec::with_capacity(payload.len() + 666);
        let meta = if inner.new_sent {
            FrameMetadata::keep_udp(dest.address().clone(), dest.port())
        } else {
            inner.new_sent = true;
            FrameMetadata::new_udp(dest.address().clone(), dest.port(), inner.global_id)
        };
        meta.write_to(&mut frame)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        inner.req.write_all(&frame).await
    }

    /// 接收一个响应数据报 `(来源, payload)`。
    ///
    /// `Ok(None)`：outbound 已关闭（会话结束）。未建立 link（尚未发包）时
    /// 永久挂起——供 `select!` 与 inbound socket 读竞争。
    pub async fn recv_packet(&mut self) -> io::Result<Option<(Destination, Vec<u8>)>> {
        let inner = match self.inner.as_mut() {
            Some(i) => i,
            None => {
                std::future::pending::<()>().await;
                unreachable!()
            },
        };
        loop {
            if !inner.accum.is_empty() {
                let mut cursor = std::io::Cursor::new(&inner.accum[..]);
                let mut pr = PacketReader::new(&mut cursor);
                let r = pr.read_packet();
                let consumed = cursor.position() as usize;
                match r {
                    Ok(Some(pkt)) => {
                        inner.accum.drain(..consumed);
                        let (data, target) = pkt.into_parts();
                        let source = target.unwrap_or_else(|| inner.dest.clone());
                        return Ok(Some((source, data)));
                    },
                    Ok(None) => {}, // 帧不完整，等更多数据
                    Err(PacketError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {},
                    Err(e) => {
                        // qyn8：协议解析错误先 drain 已消费的坏帧字节再报错。
                        // 解析错误发生时 cursor 至少消费了 2B 长度头，不 drain
                        // 则坏帧永久滞留 accum，容忍型调用方 continue 即在同一
                        // 字节上无限 Err（同步忙旋 100% CPU）。传输层错误不经
                        // 此路径（resp.read 的 io Err 由下方 `?` 直接传播）。
                        inner.accum.drain(..consumed);
                        return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
                    },
                }
            }
            let mut buf = [0u8; MAX_DATAGRAM];
            let n = inner.resp.read(&mut buf).await?;
            if n == 0 {
                return Ok(None); // outbound 关闭
            }
            inner.accum.extend_from_slice(&buf[..n]);
        }
    }

    /// 建立到 outbound 的 dispatch link（两条 duplex：请求/响应）。
    fn establish(&mut self, dest: Destination) {
        let (req_local, req_link) = tokio::io::duplex(DUPLEX_BUF);
        let (resp_link, resp_local) = tokio::io::duplex(DUPLEX_BUF);
        let link = Link::new(new_reader(req_link), new_writer(resp_link));
        let udp_dest = Destination::udp(dest.address().clone(), dest.port());
        let dispatcher = Arc::clone(&self.dispatcher);
        tokio::spawn(async move {
            dispatcher.dispatch(&udp_dest, link).await;
        });
        self.inner = Some(Inner {
            dest,
            req: req_local,
            resp: resp_local,
            accum: Vec::new(),
            global_id: rand::random(),
            new_sent: false,
        });
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use xray_common::net::{address::Address, port::Port};

    use super::*;

    /// Echo handler：读首帧 → 验证 target → 回写一帧（来源 = 请求 target）。
    struct EchoHandler;

    impl std::fmt::Debug for EchoHandler {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("EchoHandler")
        }
    }

    impl DispatchHandler for EchoHandler {
        fn tag(&self) -> &str {
            "echo"
        }

        fn dispatch(&self, dest: &Destination, link: Link) -> crate::default::PinFuture<()> {
            let dest = dest.clone();
            Box::pin(async move {
                use xray_buf::io::Reader;
                // 读首帧（XUDP New 帧）
                let mut reader = link.reader;
                let mb = match reader.read_multi_buffer().await {
                    Ok(mb) => mb,
                    Err(_) => return,
                };
                let bytes = mb.to_vec();
                let mut cursor = std::io::Cursor::new(&bytes[..]);
                let mut pr = PacketReader::new(&mut cursor);
                let pkt = match pr.read_packet() {
                    Ok(Some(p)) => p,
                    _ => return,
                };
                let (data, target) = pkt.into_parts();
                let echo_from = target.unwrap_or(dest);
                // 回写一帧（来源 = 请求目标）
                let mut frame = Vec::new();
                let meta =
                    FrameMetadata::new_udp(echo_from.address().clone(), echo_from.port(), [0u8; 8]);
                meta.write_to(&mut frame).unwrap();
                frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
                frame.extend_from_slice(&data);
                let mut out = xray_buf::multi::MultiBuffer::new();
                out.merge_bytes(&frame);
                use xray_buf::io::Writer;
                let mut writer = link.writer;
                let _ = writer.write_multi_buffer(out).await;
            })
        }
    }

    fn udp_dest(ip: [u8; 4], port: u16) -> Destination {
        Destination::udp(Address::IPv4(Ipv4Addr::from(ip)), Port::new(port))
    }

    #[tokio::test]
    async fn send_recv_roundtrip() {
        let mut session = UdpDispatchSession::new(Arc::new(EchoHandler));
        let dest = udp_dest([8, 8, 4, 4], 53);
        session.send_packet(&dest, b"dns-query").await.expect("send failed");

        let (source, payload) =
            session.recv_packet().await.expect("recv failed").expect("session ended");
        assert_eq!(payload, b"dns-query");
        assert_eq!(source, dest, "echo source should carry per-packet target");
    }

    #[tokio::test]
    async fn second_packet_uses_keep_frame_with_target() {
        #[derive(Debug)]
        struct CaptureHandler(std::sync::Arc<parking_lot::Mutex<Vec<(Destination, Vec<u8>)>>>);

        impl DispatchHandler for CaptureHandler {
            fn tag(&self) -> &str {
                "capture"
            }

            fn dispatch(&self, _dest: &Destination, link: Link) -> crate::default::PinFuture<()> {
                let captured = std::sync::Arc::clone(&self.0);
                Box::pin(async move {
                    use xray_buf::io::{Reader, Writer};
                    let mut reader = link.reader;
                    let mut writer = link.writer;
                    let mut accum: Vec<u8> = Vec::new();
                    loop {
                        let mb = match reader.read_multi_buffer().await {
                            Ok(mb) => mb,
                            Err(_) => break,
                        };
                        accum.extend_from_slice(&mb.to_vec());
                        loop {
                            let mut cursor = std::io::Cursor::new(&accum[..]);
                            let mut pr = PacketReader::new(&mut cursor);
                            match pr.read_packet() {
                                Ok(Some(pkt)) => {
                                    let consumed = cursor.position() as usize;
                                    let (data, target) = pkt.into_parts();
                                    if let Some(t) = target {
                                        captured.lock().push((t, data));
                                        // 每捕获一包回一帧（Keep，来源 = 固定地址）
                                        let mut frame = Vec::new();
                                        FrameMetadata::keep_udp(
                                            Address::IPv4(Ipv4Addr::new(1, 1, 1, 1)),
                                            Port::new(53),
                                        )
                                        .write_to(&mut frame)
                                        .unwrap();
                                        frame.extend_from_slice(&1u16.to_be_bytes());
                                        frame.extend_from_slice(b"x");
                                        let mut out = xray_buf::multi::MultiBuffer::new();
                                        out.merge_bytes(&frame);
                                        if writer.write_multi_buffer(out).await.is_err() {
                                            break;
                                        }
                                    }
                                    accum.drain(..consumed);
                                },
                                _ => break,
                            }
                        }
                    }
                })
            }
        }

        let store = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let handler: std::sync::Arc<dyn DispatchHandler> =
            std::sync::Arc::new(CaptureHandler(std::sync::Arc::clone(&store)));
        let mut session = UdpDispatchSession::new(handler);
        let d1 = udp_dest([8, 8, 8, 8], 53);
        let d2 = udp_dest([1, 0, 0, 1], 53);
        session.send_packet(&d1, b"first").await.unwrap();
        session.send_packet(&d2, b"second").await.unwrap();
        // 收两个回包（清空响应管道）
        let _ = session.recv_packet().await.unwrap();
        let _ = session.recv_packet().await.unwrap();
        let got = store.lock();
        assert_eq!(got.len(), 2, "both packets should reach outbound");
        assert_eq!(got[0].0, d1);
        assert_eq!(got[1].0, d2, "Keep frame must carry real per-packet target");
        assert_eq!(got[1].1, b"second");
    }

    #[tokio::test]
    async fn recv_before_send_pends() {
        // 未建立 link 时 recv_packet 挂起（不 panic、不返回）
        let mut session = UdpDispatchSession::new(Arc::new(EchoHandler));
        let r =
            tokio::time::timeout(std::time::Duration::from_millis(50), session.recv_packet()).await;
        assert!(r.is_err(), "recv before send must pend");
    }

    /// qyn8：只写坏帧且保持写端打开的 handler。
    #[derive(Debug)]
    struct BadFrameHandler;

    impl DispatchHandler for BadFrameHandler {
        fn tag(&self) -> &str {
            "badframe"
        }

        fn dispatch(&self, _dest: &Destination, link: Link) -> crate::default::PinFuture<()> {
            Box::pin(async move {
                use xray_buf::io::Writer;
                let mut out = xray_buf::multi::MultiBuffer::new();
                // 坏帧：长度头声明 body_len=3 < MIN_META_LEN(4) → MetadataTooShort
                out.merge_bytes(&[0x00u8, 0x03]);
                let mut writer = link.writer;
                let _ = writer.write_multi_buffer(out).await;
                // 保持写端打开：EOF 会把忙旋误判成正常关会话
                std::future::pending::<()>().await;
            })
        }
    }

    #[tokio::test]
    async fn bad_frame_errs_once_then_blocks() {
        // qyn8 回归：坏帧 → recv_packet Err；Err 分支 drain 坏帧后 accum 前进，
        // 下一次 recv 阻塞等新数据。修复前坏帧滞留 accum，重解析同一字节无限
        // Err（调用方 continue 即同步忙旋 100% CPU）。
        let mut session = UdpDispatchSession::new(Arc::new(BadFrameHandler));
        let dest = udp_dest([8, 8, 4, 4], 53);
        session.send_packet(&dest, b"ping").await.expect("send failed");

        let err = session.recv_packet().await.expect_err("bad frame must err");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let spin =
            tokio::time::timeout(std::time::Duration::from_millis(150), session.recv_packet())
                .await;
        assert!(
            spin.is_err(),
            "recv_packet must block after draining bad frame (busy-spin regression)"
        );
    }
}
