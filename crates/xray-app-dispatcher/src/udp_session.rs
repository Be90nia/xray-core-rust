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
        #[allow(
            clippy::disallowed_methods,
            reason = "ctx 不可达：dispatcher 生产依赖图无 PluginContext（xray-frame 仅 dev-dependency）；UDP dispatch 会话任务，FxScope 迁移收口见 bd 39hko"
        )]
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
                // q1r4q：首帧直接在 MultiBuffer 片段链上解析——PacketReader 本就
                // 泛型 over R: Read，ChainCursor 把片段链暴露为流，免 to_vec 摊平
                //（原 P1 收口点：UDP 小包 relay bench，oracle §7 Phase 1）。
                let bufs = mb.into_buffers();
                let mut cursor = ChainCursor::new(&bufs);
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

    /// q1r4q：把不连续 Buffer 片段链暴露为 `io::Read`，让 `PacketReader`
    /// （`R: Read` 泛型）跨片段解析，免 to_vec 摊平拷贝。持 `&[Buffer]`
    /// 单一借用（而非 Vec<&[u8]> scratch）：解析尝试之间会 advance/drain
    /// `accum`，单借用随解析块结束即失效，不与突变冲突。
    struct ChainCursor<'a> {
        bufs: &'a [xray_buf::buffer::Buffer],
        idx: usize,
        off: usize,
        /// 全局已消费字节数（帧累积消费 advance/drain 的依据）。
        pos: usize,
    }

    impl<'a> ChainCursor<'a> {
        fn new(bufs: &'a [xray_buf::buffer::Buffer]) -> Self {
            Self { bufs, idx: 0, off: 0, pos: 0 }
        }
    }

    impl io::Read for ChainCursor<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            // 跳过耗尽的片段（含零长片段）
            while self.idx < self.bufs.len() && self.off >= self.bufs[self.idx].len() {
                self.idx += 1;
                self.off = 0;
            }
            if out.is_empty() || self.idx == self.bufs.len() {
                return Ok(0); // EOF：read_exact 转 UnexpectedEof（半帧语义不变）
            }
            let cur = self.bufs[self.idx].bytes();
            let n = cur.len().saturating_sub(self.off).min(out.len());
            out[..n].copy_from_slice(&cur[self.off..self.off + n]);
            self.off += n;
            self.pos += n;
            Ok(n)
        }
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
                    // q1r4q：Buffer 片段链累积（原 Vec 连续化 + to_vec+extend 双拷贝，
                    // P1 收口点：udp relay bench 轮次）
                    let mut accum: Vec<_> = Vec::new();
                    loop {
                        let mb = match reader.read_multi_buffer().await {
                            Ok(mb) => mb,
                            Err(_) => break,
                        };
                        accum.extend(mb.into_buffers());
                        loop {
                            let (r, consumed) = {
                                let mut cursor = ChainCursor::new(&accum);
                                let mut pr = PacketReader::new(&mut cursor);
                                let r = pr.read_packet();
                                (r, cursor.pos)
                            };
                            match r {
                                Ok(Some(pkt)) => {
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
                                    // 消费已解析前缀：整 Buffer 弹出、半 Buffer advance
                                    //（指针级前进，免字节级 drain 搬移；qyn8 语义不变）
                                    let mut left = consumed;
                                    let mut done = 0;
                                    while left > 0 {
                                        let l = accum[done].len();
                                        if l <= left {
                                            done += 1;
                                            left -= l;
                                        } else {
                                            accum[done].advance(left);
                                            left = 0;
                                        }
                                    }
                                    accum.drain(..done);
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

    /// q1r4q 回归钉：同一 UDP 帧流按不同分段方式（单段/碎片边界任意错位）
    /// 经片段链重组解析，结果逐字节相同（帧数/载荷/target 全等）。
    #[test]
    fn chain_parse_reassembly_is_segmentation_invariant() {
        let build_frame = |payload: &[u8], ip: [u8; 4]| -> Vec<u8> {
            let mut f = Vec::new();
            FrameMetadata::new_udp(udp_dest(ip, 53).address().clone(), Port::new(53), [7u8; 8])
                .write_to(&mut f)
                .unwrap();
            f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            f.extend_from_slice(payload);
            f
        };
        let mut stream = build_frame(b"first-payload", [8, 8, 8, 8]);
        stream.extend_from_slice(&build_frame(b"p2", [1, 0, 0, 1]));

        let to_bufs = |chunks: &[&[u8]]| -> Vec<xray_buf::buffer::Buffer> {
            // from_vec = Frozen 语义：非池来源永不回池，无假池污染面
            chunks.iter().map(|c| xray_buf::buffer::Buffer::from_vec(c.to_vec())).collect()
        };
        let parse_all = |bufs: &[xray_buf::buffer::Buffer]| -> Vec<(Vec<u8>, Option<Destination>)> {
            let mut cursor = ChainCursor::new(bufs);
            let mut pr = PacketReader::new(&mut cursor);
            let mut got = Vec::new();
            while let Ok(Some(pkt)) = pr.read_packet() {
                got.push(pkt.into_parts());
            }
            got
        };

        let whole = parse_all(&to_bufs(&[&stream]));
        assert_eq!(whole.len(), 2, "两条帧都应解出");

        // 3 字节碎片：片段边界与帧边界错位
        let frags: Vec<&[u8]> = stream.chunks(3).collect();
        assert_eq!(parse_all(&to_bufs(&frags)), whole, "3 字节碎片重组必须逐字节一致");

        // 1 字节 + 剩余：切进 2B 长度头内部
        let head1 = [&stream[..1], &stream[1..]];
        assert_eq!(parse_all(&to_bufs(&head1)), whole, "1 字节分段重组必须逐字节一致");

        // 对半切
        let half = stream.len() / 2;
        let halves = [&stream[..half], &stream[half..]];
        assert_eq!(parse_all(&to_bufs(&halves)), whole, "对半分段重组必须逐字节一致");
    }

    // ── q1r4q 分配取证：线程归属计数分配器（libtest 并行下他线程分配不串扰）──

    use std::{
        alloc::{GlobalAlloc, Layout, System},
        cell::Cell,
    };

    thread_local! {
        static THREAD_ALLOCS: Cell<usize> = const { Cell::new(0) };
    }

    struct CountingAlloc;

    unsafe impl GlobalAlloc for CountingAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // try_with：TLS 析构期分配无法归属任何线程，跳过记账（分配器内禁 panic）
            let _ = THREAD_ALLOCS.try_with(|c| c.set(c.get() + 1));
            // SAFETY: 透传 System，布局合法性由 GlobalAlloc 契约保证
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: 指针/布局配对由 GlobalAlloc 契约保证
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    #[global_allocator]
    static Q1R4Q_ALLOC: CountingAlloc = CountingAlloc;

    /// q1r4q 分配取证：同一帧流上旧路径（to_vec 摊平 + Cursor）与新路径
    /// （片段链直读）的每包堆分配次数对比。数据帧到达本身（池化 Buffer
    /// 移交）在两路径下都零分配，已在窗口外构造以排除干扰。
    // lib.rs:8 的 warn(print_stdout) 排在 :7 test 级 allow 之后将其覆盖，
    // 本测试取证数字须打印——按仓规显式 allow + 理由。
    #[allow(clippy::print_stdout)]
    #[test]
    fn chain_parse_allocs_per_packet_drop() {
        const PACKETS: usize = 128;
        let mut stream = Vec::new();
        for i in 0..PACKETS {
            let mut f = Vec::new();
            FrameMetadata::new_udp(
                udp_dest([10, 0, 0, (i % 254 + 1) as u8], 53).address().clone(),
                Port::new(53),
                [i as u8; 8],
            )
            .write_to(&mut f)
            .unwrap();
            f.extend_from_slice(&16u16.to_be_bytes());
            f.extend_from_slice(&[0u8; 16]);
            stream.extend_from_slice(&f);
        }

        let before = THREAD_ALLOCS.with(|c| c.get());
        // 旧路径（改前 CaptureHandler 每读一轮）：to_vec 摊平 + Cursor 重扫
        for _ in 0..PACKETS {
            let flat = stream.clone(); // ≙ mb.to_vec()：整帧堆分配 + 拷贝
            let mut cursor = std::io::Cursor::new(&flat[..]);
            let mut pr = PacketReader::new(&mut cursor);
            assert!(pr.read_packet().is_ok_and(|o| o.is_some()));
        }
        let old_allocs = THREAD_ALLOCS.with(|c| c.get()) - before;

        // 新路径（改后）：到达帧 = Buffer 移交（窗口外预构造），链上直读
        let arrived: Vec<_> =
            (0..PACKETS).map(|_| xray_buf::buffer::Buffer::from_vec(stream.clone())).collect();
        let mut bufs: Vec<xray_buf::buffer::Buffer> = Vec::new();
        let before = THREAD_ALLOCS.with(|c| c.get());
        for buf in arrived {
            bufs.clear();
            bufs.push(buf);
            let parsed = {
                let mut cursor = ChainCursor::new(&bufs);
                let mut pr = PacketReader::new(&mut cursor);
                pr.read_packet().is_ok_and(|o| o.is_some())
            };
            assert!(parsed);
        }
        let new_allocs = THREAD_ALLOCS.with(|c| c.get()) - before;

        let old_pp = old_allocs / PACKETS;
        let new_pp = new_allocs / PACKETS;
        println!("q1r4q per-packet allocs: old(to_vec+Cursor)={old_pp} new(chain)={new_pp}");
        assert_eq!(old_pp, 3, "旧路径每包 3 次分配（to_vec + reader scratch + 载荷 Vec）");
        assert_eq!(new_pp, 2, "新路径每包 2 次分配（摊平分配已删，剩 scratch + 载荷）");
    }
}
