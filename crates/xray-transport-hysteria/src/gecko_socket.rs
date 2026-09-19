//! # Gecko UDP 混淆 socket 包装（bd a9r8）
//!
//! 对应 Go `transport/internet/hysteria/dialer.go:170-179` + `hub.go:324-331`：
//! QUIC 的 UDP socket 在交给 `quic.Transport` 前用 `udpmaskManager` 包 Gecko——
//! 在 Salamander BLAKE2b-256 XOR（`[8B salt][XOR(payload, BLAKE2b-256(PSK||salt))]`）
//! 之上，把 QUIC 长头包（首字节顶位 set）拆成 2-8 个带 5B frame header 的分片，
//! 接收端按 `(src, msgID)` 重组；短头包只过 XOR 透传。
//!
//! 变换本体（分片/重组/上限/GC）全部复用 `xray_transport::finalmask::salamander_gecko`
//! 的 [`GeckoConn`]（rpn-B 已落地并测试），本模块只做异步 `UdpIo` → quinn
//! poll 式 [`AsyncUdpSocket`] 的桥接：
//!
//! - 发送 `try_send`：把 datagram 推给发送 driver task（有界队列，满载即丢——
//!   QUIC 按 UDP 语义容忍丢包，对齐 `PacketIoConn` fire-and-forget 先例），
//!   driver 经 `GeckoConn::send_to` 变换后写底层 socket。
//! - 接收 `poll_recv`：driver 持续 `GeckoConn::recv_from`（内部分片重组直到
//!   凑齐一包），完整包经 unbounded channel 交给 poll_recv 零阻塞取出。
//! - 生命周期：两个 driver task 都持有 `Arc<GeckoConn>`；`GeckoSocket` drop 时
//!   发送队列关闭 + watch 信号触发，driver 退出 → `GeckoConn` 归还 → GC task
//!   被 abort，底层 socket 引用归零自动关闭。
//!
//! GSO/GRO/ECN 不透传（同 `crate::salamander_socket::SalamanderSocket`）：
//! `may_fragment()` 保持默认 true，quinn 关闭路径 MTU 探测（Gecko 分片每包
//! 带 salt+header 开销，不探测更稳妥）。

use std::{
    io,
    io::IoSliceMut,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
};

use bytes::Bytes;
use parking_lot::Mutex;
use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use xray_transport::finalmask::salamander_gecko::{GeckoConfig, GeckoConn};
use xray_transport::finalmask::{UDP_SIZE, UdpIo};

/// 发送队列容量：driver 消费不及时丢新包（QUIC 容忍），杜绝无界增长。
/// 对齐 `finalmask::PACKET_QUEUE_CAP` 的 UDP 语义先例。
const SEND_QUEUE_CAP: usize = 128;

/// 包 Gecko 变换的 quinn UDP socket。
///
/// 经 [`quinn::Endpoint::new_with_abstract_socket`] 注入；构造用 [`GeckoSocket::bind`]。
pub struct GeckoSocket {
    io: Arc<UdpSocket>,
    send_tx: mpsc::Sender<(Bytes, SocketAddr)>,
    recv_rx: Mutex<mpsc::Receiver<(Bytes, SocketAddr)>>,
    /// 收/发两方向队列满载丢弃累计包数（对齐 finalmask PacketIoConn 先例）。
    dropped: Arc<AtomicU64>,
    /// drop 时唤醒接收 driver 退出（sender 归零 → `changed()` 返回 Err）。
    _closed_tx: watch::Sender<()>,
}

impl std::fmt::Debug for GeckoSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeckoSocket")
            .field("local", &self.io.local_addr().ok())
            .finish_non_exhaustive()
    }
}

impl GeckoSocket {
    /// bind UDP socket 并包 Gecko 混淆。
    ///
    /// 必须在 tokio runtime 上下文内调用（socket 经
    /// [`xray_transport::sockopt::bind_udp_endpoint`] 创建后转 tokio + driver task
    /// spawn）。PSK/分片参数校验在 [`GeckoConn::new`]（同 Go `NewGeckoConnClient`）。
    pub async fn bind(
        config: &GeckoConfig,
        bind_addr: SocketAddr,
        sockopt: &xray_transport::sockopt::SocketOptions,
    ) -> io::Result<Arc<Self>> {
        let std_sock = xray_transport::sockopt::bind_udp_endpoint(bind_addr, sockopt)?;
        let io = Arc::new(UdpSocket::from_std(std_sock)?);
        let conn = Arc::new(GeckoConn::new(config, Box::new(io.clone()))?);

        let (send_tx, send_rx) = mpsc::channel::<(Bytes, SocketAddr)>(SEND_QUEUE_CAP);
        // 收向同样有界：读端消费不过来时丢新包（内核 UDP 缓冲满即丢的同语义），
        // 计数可观测，杜绝 unbounded 无背压增长（bd cf0r）。
        let (recv_tx, recv_rx) = mpsc::channel::<(Bytes, SocketAddr)>(SEND_QUEUE_CAP);
        let (closed_tx, closed_rx) = watch::channel(());
        let dropped = Arc::new(AtomicU64::new(0));

        spawn_send_driver(conn.clone(), send_rx);
        spawn_recv_driver(conn, recv_tx, closed_rx, Arc::clone(&dropped));

        Ok(Arc::new(Self { io, send_tx, recv_rx: Mutex::new(recv_rx), dropped, _closed_tx: closed_tx }))
    }

    /// 构造注入 quinn 用的 endpoint（client 侧，`server_config = None`）。
    pub fn client_endpoint(self: &Arc<Self>) -> io::Result<quinn::Endpoint> {
        crate::salamander_socket::endpoint_with_socket(None, self.clone())
    }

    /// 构造注入 quinn 用的 endpoint（server 侧）。
    pub fn server_endpoint(
        self: &Arc<Self>,
        server_config: quinn::ServerConfig,
    ) -> io::Result<quinn::Endpoint> {
        crate::salamander_socket::endpoint_with_socket(Some(server_config), self.clone())
    }
}

/// 发送 driver：GeckoConn::send_to 变换（长头分片/短头透传 + XOR）后写 socket。
///
/// 所有 `GeckoSocket` clone drop → send_tx 归零 → `recv()` 返回 None → 退出。
fn spawn_send_driver(conn: Arc<GeckoConn>, mut send_rx: mpsc::Receiver<(Bytes, SocketAddr)>) {
    tokio::spawn(async move {
        while let Some((buf, addr)) = send_rx.recv().await {
            // 发送失败（socket 已死）只丢当前包；后续包同样失败，QUIC 按丢包处理
            let _ = conn.send_to(&buf, addr).await;
        }
        // conn 在此 drop（最后一个 Arc，若接收 driver 已先退出）
    });
}

/// 接收 driver：持续 GeckoConn::recv_from（内联重组循环），完整包交 poll_recv。
///
/// 退出条件：`GeckoSocket` drop（watch sender 归零）、socket 错误、或
/// 接收端归零（channel send 失败）。
fn spawn_recv_driver(
    conn: Arc<GeckoConn>,
    recv_tx: mpsc::Sender<(Bytes, SocketAddr)>,
    mut closed_rx: watch::Receiver<()>,
    dropped: Arc<AtomicU64>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_SIZE];
        loop {
            tokio::select! {
                biased;
                _ = closed_rx.changed() => break,
                res = conn.recv_from(&mut buf) => match res {
                    Ok((n, addr)) => {
                        let pkt = Bytes::copy_from_slice(&buf[..n]);
                        match recv_tx.try_send((pkt, addr)) {
                            Ok(()) => {},
                            // 读端消费不过来：丢新包（UDP 语义）+ 计数（cf0r 对齐
                            // finalmask PacketIoConn 有界+丢弃先例）
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                let total = dropped.fetch_add(1, Ordering::Relaxed) + 1;
                                tracing::debug!(dropped = total, "gecko recv queue full, packet dropped");
                            },
                            Err(mpsc::error::TrySendError::Closed(_)) => break,
                        }
                    },
                    Err(_) => break,
                },
            }
        }
    });
}

impl AsyncUdpSocket for GeckoSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        // 写就绪语义跟底层 socket（driver 消费速度受 socket 制约），
        // 给 quinn 自然背压；队列满载时 try_send 丢包不阻塞。
        Box::pin(crate::salamander_socket::WritablePoller::new(self.io.clone()))
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if transmit.segment_size.is_some() {
            // max_transmit_segments()==1 时 quinn 不应构造多段 Transmit
            return Err(io::Error::other(
                "gecko socket: multi-segment (GSO) transmit unsupported",
            ));
        }
        match self.send_tx.try_send((Bytes::copy_from_slice(transmit.contents), transmit.destination)) {
            Ok(()) => Ok(()),
            // 队列满：丢包（UDP 缓冲满即丢的内核语义；QUIC 重传兜底）+ 计数
            Err(mpsc::error::TrySendError::Full(_)) => {
                let total = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::debug!(dropped = total, "gecko send queue full, packet dropped");
                Ok(())
            },
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(io::Error::other("gecko socket: send driver stopped"))
            },
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut rx = self.recv_rx.lock();
        match rx.poll_recv(cx) {
            Poll::Ready(Some((data, addr))) => {
                let len = data.len().min(bufs[0].len());
                bufs[0][..len].copy_from_slice(&data[..len]);
                meta[0] =
                    RecvMeta { addr, len, stride: len, ecn: None, dst_ip: None };
                Poll::Ready(Ok(1))
            },
            // 所有 GeckoSocket 已 drop
            Poll::Ready(None) => Poll::Ready(Err(io::Error::other("gecko socket closed"))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noop_cx() -> Context<'static> {
        Context::from_waker(std::task::Waker::noop())
    }

    fn gecko_cfg(psk: &str, min: u32, max: u32) -> GeckoConfig {
        GeckoConfig { password: psk.into(), min_packet_size: min, max_packet_size: max }
    }

    /// 从 quinn 缓冲轮询收一包（500ms 预算）。
    async fn poll_one(sock: &Arc<GeckoSocket>, buf: &mut [u8]) -> Option<(usize, SocketAddr)> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(500);
        loop {
            let mut iovs = [IoSliceMut::new(buf)];
            let mut metas = [RecvMeta::default()];
            let mut cx = noop_cx();
            if let Poll::Ready(r) = sock.poll_recv(&mut cx, &mut iovs, &mut metas) {
                r.unwrap();
                return Some((metas[0].len, metas[0].addr));
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    }

    /// 先经 poller 等写就绪（生产路径 quinn 同样先 poll_writable 再 try_send）。
    async fn wait_writable(sock: &Arc<GeckoSocket>) {
        let mut poller = sock.clone().create_io_poller();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(500);
        loop {
            let mut cx = noop_cx();
            if let Poll::Ready(r) = poller.as_mut().poll_writable(&mut cx) {
                r.unwrap();
                return;
            }
            assert!(tokio::time::Instant::now() < deadline, "socket never writable");
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    }

    async fn try_send_to(sock: &Arc<GeckoSocket>, plain: &[u8], dest: SocketAddr) {
        wait_writable(sock).await;
        sock.try_send(&Transmit {
            destination: dest,
            ecn: None,
            contents: plain,
            segment_size: None,
            src_ip: None,
        })
        .unwrap();
    }

    #[tokio::test]
    async fn long_header_fragments_and_reassembles_roundtrip() {
        let a = GeckoSocket::bind(&gecko_cfg("shared-psk-1", 512, 1200), "127.0.0.1:0".parse().unwrap(), &Default::default())
            .await
            .unwrap();
        let b = GeckoSocket::bind(&gecko_cfg("shared-psk-1", 512, 1200), "127.0.0.1:0".parse().unwrap(), &Default::default())
            .await
            .unwrap();

        // QUIC 长头形态：顶位 set；1200B（> 默认 max_pkt=1200 分片阈值形态）
        let mut plain = vec![0u8; 1200];
        plain[0] = 0xC3;
        for (i, byte) in plain.iter_mut().enumerate().skip(1) {
            *byte = (i % 251) as u8;
        }
        try_send_to(&a, &plain, b.local_addr().unwrap()).await;

        let mut buf = vec![0u8; 64 * 1024];
        let (n, addr) = poll_one(&b, &mut buf).await.expect("reassembled packet not delivered");
        assert_eq!(addr, a.local_addr().unwrap());
        assert_eq!(n, plain.len(), "reassembled length must match original");
        assert_eq!(&buf[..n], &plain, "wrap/unwrap must be symmetric");

        // 短头包同链路透传
        let short = b"\x45short-header-packet";
        try_send_to(&a, short, b.local_addr().unwrap()).await;
        let mut buf2 = vec![0u8; 64 * 1024];
        let (n2, _) = poll_one(&b, &mut buf2).await.expect("short packet not delivered");
        assert_eq!(&buf2[..n2], short);
    }

    #[tokio::test]
    async fn long_header_writes_multiple_wire_datagrams() {
        let sock =
            GeckoSocket::bind(&gecko_cfg("unit-test-psk", 512, 1200), "127.0.0.1:0".parse().unwrap(), &Default::default())
                .await
                .unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap()).await.unwrap();

        let mut plain = vec![0u8; 1200];
        plain[0] = 0xC3;
        try_send_to(&sock, &plain, peer.local_addr().unwrap()).await;

        // 读 wire：分片数随机 [2,8]，逐帧剥 salt+XOR 后按 decode_frame 校验并重组。
        // 这是与 xray_transport::finalmask::salamander_gecko 帧 primitives 的字节级对拍：
        // GeckoSocket 发出的 wire 包必须能被同一套 Go 对齐的 encode/decode 原语解开。
        let obfs = xray_transport::finalmask::salamander::SalamanderObfuscator::new(b"unit-test-psk")
            .unwrap();
        let mut wire = vec![0u8; 64 * 1024];
        let mut frames: Vec<(u8, u8, Vec<u8>)> = Vec::new(); // (chunk_idx, total, payload)
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(300);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(std::time::Duration::from_millis(30), peer.recv(&mut wire))
                .await
            {
                Ok(Ok(n)) => {
                    let mut plain_buf = vec![0u8; n];
                    let payload_len = obfs.deobfuscate(&wire[..n], &mut plain_buf);
                    assert!(payload_len > 0, "wire packet must deobfuscate");
                    let (h, start, end) =
                        xray_transport::finalmask::salamander_gecko::decode_frame(
                            &plain_buf[..payload_len],
                        )
                        .expect("wire packet must be a valid gecko frame");
                    frames.push((
                        h.chunk_idx,
                        h.total_chunks,
                        plain_buf[start..end].to_vec(),
                    ));
                },
                _ => break,
            }
        }
        assert!(frames.len() >= 2, "long-header packet must be split into ≥2 wire datagrams");
        let total = frames[0].1;
        assert!(frames.iter().all(|(_, t, _)| *t == total), "all frames must share total_chunks");
        let mut idxs: Vec<u8> = frames.iter().map(|(i, _, _)| *i).collect();
        idxs.sort_unstable();
        assert_eq!(idxs, (0..total).collect::<Vec<u8>>(), "chunks must cover [0, total)");
        let mut reassembled = Vec::new();
        frames.sort_by_key(|(i, _, _)| *i);
        for (_, _, chunk) in &frames {
            reassembled.extend_from_slice(chunk);
        }
        assert_eq!(reassembled, plain, "frame-level reassembly must match original packet");

        // 短头：单 wire 包透传
        let short = b"\x40short-header".to_vec();
        try_send_to(&sock, &short, peer.local_addr().unwrap()).await;
        let n = tokio::time::timeout(std::time::Duration::from_millis(300), peer.recv(&mut wire))
            .await
            .expect("short packet not received")
            .unwrap();
        // wire = salt + XOR(plain)，长度只多 salt
        assert_eq!(n, short.len() + 8, "short header must stay a single datagram (+salt)");
    }

    #[tokio::test]
    async fn psk_mismatch_never_yields_plaintext() {
        let a = GeckoSocket::bind(&gecko_cfg("psk-client-side", 512, 1200), "127.0.0.1:0".parse().unwrap(), &Default::default())
            .await
            .unwrap();
        let b = GeckoSocket::bind(&gecko_cfg("psk-server-side", 512, 1200), "127.0.0.1:0".parse().unwrap(), &Default::default())
            .await
            .unwrap();

        let plain = b"\x40top-secret-payload-must-not-leak";
        try_send_to(&a, plain, b.local_addr().unwrap()).await;

        let mut buf = vec![0u8; 64 * 1024];
        // 错 PSK：解出的垃圾可能透传（短头形态）或被当分片丢弃——都不应还原明文
        if let Some((n, _)) = poll_one(&b, &mut buf).await {
            assert_ne!(&buf[..n], &plain[..], "mismatched PSK must not yield plaintext");
        }
    }
}
