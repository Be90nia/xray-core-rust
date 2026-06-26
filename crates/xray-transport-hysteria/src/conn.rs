//! Hysteria 连接抽象 —— interConn（QUIC stream TCP 客户端） + InterConn
//! （UDP session 抽象） + UdpSessionManager（QUIC datagram 多路复用）。
//!
//! Go 源：`transport/internet/hysteria/conn.go`。
//!
//! # IO 边界（trait + stub）
//!
//! QUIC stream / conn 操作通过 [`QuicStream`] / [`QuicConn`] trait 抽象。
//! 上层（quinn adapter）实现此 trait。hysteria 内部独立可测的部分是
//! InterConn 状态机 + UdpSessionManager 的 id 分配 + 清理逻辑。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::{mpsc, Mutex as TokioMutex};

use crate::config::{UDP_MESSAGE_CHAN_SIZE, IDLE_CLEANUP_INTERVAL};
use crate::error::Result;

/// QUIC stream 抽象（对应 Go `*quic.Stream`）。
///
/// 异步方法用 `Pin<Box<dyn Future>>` 表达（避免引入 async_trait crate）。
pub trait QuicStream: Send + Sync + std::fmt::Debug {
    /// 读数据到 buf，返回字节数。
    fn read<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<usize>> + Send + 'a>>;

    /// 写数据。
    fn write<'a>(
        &'a self,
        buf: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<usize>> + Send + 'a>>;

    /// 取消读（对应 Go `stream.CancelRead(code)`）。
    fn cancel_read(&self, code: u64);

    /// 关闭（对应 Go `stream.Close()`）。
    fn close(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>>;

    /// 本地地址。
    fn local_addr(&self) -> SocketAddr;

    /// 远端地址。
    fn remote_addr(&self) -> SocketAddr;
}

/// QUIC conn 抽象（对应 Go `*quic.Conn`）。
pub trait QuicConn: Send + Sync {
    /// 发送 datagram（对应 Go `conn.SendDatagram`）。
    fn send_datagram<'a>(
        &'a self,
        data: &'a [u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send + 'a>>;

    /// 接收 datagram（对应 Go `conn.ReceiveDatagram`）。
    fn receive_datagram(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<Vec<u8>>> + Send>,
    >;

    /// 关闭（对应 Go `conn.CloseWithError`）。
    fn close_with_error(&self, code: u64, reason: &str);

    /// 本地地址。
    fn local_addr(&self) -> SocketAddr;

    /// 远端地址。
    fn remote_addr(&self) -> SocketAddr;
}

/// QUIC stream 包装的 TCP-style 连接（对应 Go `interConn`）。
///
/// client 模式下首包需在数据前加 `FrameTypeTCPRequest` 前缀（QUIC varint 编码）。
#[derive(Debug)]
pub struct InterStreamConn {
    stream: Arc<dyn QuicStream>,
    local: SocketAddr,
    remote: SocketAddr,
    /// client 模式（首包加 frame type 前缀）。
    client_first: Mutex<bool>,
}

impl InterStreamConn {
    /// 构造（对应 Go `interConn{}` 字面量）。
    pub fn new(stream: Arc<dyn QuicStream>, local: SocketAddr, remote: SocketAddr, client: bool) -> Self {
        Self {
            stream,
            local,
            remote,
            client_first: Mutex::new(client),
        }
    }

    /// 读（对应 Go `Read`）。
    pub async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf).await
    }

    /// 写（对应 Go `Write`）。
    ///
    /// client 模式首包：写 `varint(FrameTypeTCPRequest) ++ buf`。
    pub async fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        let need_prefix = {
            let mut g = self.client_first.lock();
            let was = *g;
            *g = false;
            was
        };
        if need_prefix {
            let mut payload = Vec::with_capacity(8 + buf.len());
            // ponytail: 编码 QUIC varint 0x401（双字节形式：0b01xx_xxxx_xxxx_xxxx）。
            payload.extend_from_slice(&encode_varint(crate::config::FrameTypeTCPRequest));
            payload.extend_from_slice(buf);
            self.stream.write(&payload).await.map(|_| buf.len())
        } else {
            self.stream.write(buf).await
        }
    }

    /// 关闭（对应 Go `Close`）。
    pub async fn close(&self) -> std::io::Result<()> {
        self.stream.cancel_read(0);
        self.stream.close().await
    }

    /// 本地地址。
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// 远端地址。
    #[must_use]
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote
    }
}

/// 编码 QUIC varint（对应 Go `quicvarint.Append(nil, v)`）。
///
/// 0x401 在 0b01xx_xxxx_xxxx_xxxx 范围（2 字节形式：前缀 01）。
#[must_use]
pub fn encode_varint(v: u64) -> Vec<u8> {
    if v < (1 << 6) {
        vec![v as u8]
    } else if v < (1 << 14) {
        vec![((v >> 8) as u8) | 0b0100_0000, v as u8]
    } else if v < (1 << 30) {
        vec![
            ((v >> 24) as u8) | 0b1000_0000,
            (v >> 16) as u8,
            (v >> 8) as u8,
            v as u8,
        ]
    } else {
        vec![
            ((v >> 56) as u8) | 0b1100_0000,
            (v >> 48) as u8,
            (v >> 40) as u8,
            (v >> 32) as u8,
            (v >> 24) as u8,
            (v >> 16) as u8,
            (v >> 8) as u8,
            v as u8,
        ]
    }
}

/// UDP session 抽象（对应 Go `InterConn`）。
///
/// 通过 QUIC datagram 多路复用，每个 UDP flow 一个 InterConn，由 UdpSessionManager 分发。
pub struct InterConn {
    local: SocketAddr,
    remote: SocketAddr,
    id: u32,
    /// 接收队列（QUIC datagram 投递到此）。
    recv_rx: TokioMutex<mpsc::Receiver<Vec<u8>>>,
    /// 接收 tx 用于关闭信号。
    recv_tx_close: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    /// 最后活跃时间。
    last_active: Mutex<Instant>,
    /// 是否已关闭。
    closed: Mutex<bool>,
    /// 写回调（QUIC conn.SendDatagram）。
    write_fn: Mutex<Option<Arc<dyn Fn(&[u8]) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>> + Send + Sync>>>,
    /// 关闭回调（清理 UdpSessionManager 中的 entry）。
    close_fn: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl std::fmt::Debug for InterConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterConn")
            .field("local", &self.local)
            .field("remote", &self.remote)
            .field("id", &self.id)
            .field("closed", &self.closed.lock().clone())
            .finish_non_exhaustive()
    }
}

impl InterConn {
    /// 构造（对应 Go `&InterConn{...}`）。
    pub fn new(local: SocketAddr, remote: SocketAddr, id: u32, chan_size: usize) -> Self {
        let (tx, rx) = mpsc::channel(chan_size);
        Self {
            local,
            remote,
            id,
            recv_rx: TokioMutex::new(rx),
            recv_tx_close: Mutex::new(Some(tx)),
            last_active: Mutex::new(Instant::now()),
            closed: Mutex::new(false),
            write_fn: Mutex::new(None),
            close_fn: Mutex::new(None),
        }
    }

    /// 最后活跃时间（对应 Go `Time()`）。
    pub fn last_active(&self) -> Instant {
        *self.last_active.lock()
    }

    /// 标记活跃（对应 Go `Update()`）。
    pub fn touch(&self) {
        *self.last_active.lock() = Instant::now();
    }

    /// 读（对应 Go `Read`）。
    ///
    /// 从 channel 取一个 datagram，前 4 字节是 session id（写时已注入），
    /// 读时剥除。返回有效 payload 长度。
    pub async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let data = self.recv_rx.lock().await.recv().await.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "closed")
        })?;
        if buf.len() < data.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "short buffer",
            ));
        }
        buf[..data.len()].copy_from_slice(&data);
        self.touch();
        Ok(data.len())
    }

    /// 写（对应 Go `Write`）。
    ///
    /// 注入 4 字节大端 session id 前缀，调 write_fn。
    pub async fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        if *self.closed.lock() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed",
            ));
        }
        let mut payload = Vec::with_capacity(4 + buf.len());
        payload.extend_from_slice(&self.id.to_be_bytes());
        payload.extend_from_slice(buf);
        let write_fn = self.write_fn.lock().clone();
        if let Some(f) = write_fn {
            f(&payload).await?;
        }
        self.touch();
        Ok(buf.len())
    }

    /// 关闭（对应 Go `Close`）。
    pub async fn close(&self) -> std::io::Result<()> {
        // 关闭 channel + 调 close_fn
        if let Some(tx) = self.recv_tx_close.lock().take() {
            drop(tx);
        }
        let mut closed = self.closed.lock();
        if *closed {
            return Ok(());
        }
        *closed = true;
        drop(closed);
        if let Some(f) = self.close_fn.lock().clone() {
            f();
        }
        Ok(())
    }

    /// 设置写回调。
    pub fn set_write_fn<F, Fut>(&self, f: F)
    where
        F: Fn(&[u8]) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = std::io::Result<()>> + Send + 'static,
    {
        *self.write_fn.lock() = Some(Arc::new(move |b: &[u8]| Box::pin(f(b))));
    }

    /// 设置关闭回调。
    pub fn set_close_fn<F: Fn() + Send + Sync + 'static>(&self, f: F) {
        *self.close_fn.lock() = Some(Arc::new(f));
    }

    /// 投递一个 datagram 到接收 channel（对应 Go `udpSessionManager.feed`）。
    pub fn feed(&self, data: Vec<u8>) {
        let tx = self.recv_tx_close.lock().clone();
        if let Some(tx) = tx {
            let _ = tx.try_send(data);
        }
    }

    /// 是否已关闭。
    #[must_use]
    pub fn is_closed(&self) -> bool {
        *self.closed.lock()
    }

    /// 本地地址。
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// 远端地址。
    #[must_use]
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote
    }

    /// Session ID。
    #[must_use]
    pub fn id(&self) -> u32 {
        self.id
    }
}

/// UdpSessionManager —— QUIC datagram 多路复用 UDP session（对应 Go
/// `udpSessionManager`）。
///
/// 每个 QUIC conn 一个 manager，接收 datagram → 按 session id 路由到 InterConn。
pub struct UdpSessionManager {
    inner: Arc<TokioMutex<UdpSessionInner>>,
    /// 后台清理任务句柄。
    #[allow(dead_code)]
    clean_handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// 后台 recv 任务句柄。
    #[allow(dead_code)]
    run_handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

struct UdpSessionInner {
    sessions: std::collections::HashMap<u32, Arc<InterConn>>,
    next_id: u32,
    closed: bool,
    /// 接收 datagram 后，对新 session id 调用（注入到 dispatcher）。
    on_new_session: Option<Arc<dyn Fn(Arc<InterConn>) + Send + Sync>>,
    udp_idle_timeout: Duration,
}

impl std::fmt::Debug for UdpSessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSessionManager").finish_non_exhaustive()
    }
}

impl UdpSessionManager {
    /// 构造（对应 Go `&udpSessionManager{...}`）。
    pub fn new(
        udp_idle_timeout: Duration,
        on_new_session: Option<Arc<dyn Fn(Arc<InterConn>) + Send + Sync>>,
    ) -> Arc<Self> {
        let inner = Arc::new(TokioMutex::new(UdpSessionInner {
            sessions: std::collections::HashMap::new(),
            next_id: 1,
            closed: false,
            on_new_session,
            udp_idle_timeout,
        }));
        Arc::new(Self {
            inner,
            clean_handle: tokio::sync::Mutex::new(None),
            run_handle: tokio::sync::Mutex::new(None),
        })
    }

    /// 启动后台清理 + recv 任务（对应 Go `go udpSM.clean(); go udpSM.run()`）。
    pub async fn start(self: &Arc<Self>, conn: Arc<dyn QuicConn>, local: SocketAddr, remote: SocketAddr) {
        let inner = Arc::clone(&self.inner);
        let timeout = {
            let g = self.inner.lock().await;
            g.udp_idle_timeout
        };
        let clean_inner = Arc::clone(&self.inner);
        let clean_handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(IDLE_CLEANUP_INTERVAL);
            loop {
                ticker.tick().await;
                let to_close = {
                    let g = clean_inner.lock().await;
                    if g.closed {
                        return;
                    }
                    let now = Instant::now();
                    let mut out = Vec::new();
                    for (id, sess) in &g.sessions {
                        if now.duration_since(sess.last_active()) > timeout {
                            out.push(*id);
                        }
                    }
                    out
                };
                for id in to_close {
                    let sess = {
                        let mut g = clean_inner.lock().await;
                        g.sessions.remove(&id)
                    };
                    if let Some(s) = sess {
                        let _ = s.close().await;
                    }
                }
            }
        });

        let run_inner = Arc::clone(&self.inner);
        let run_conn = Arc::clone(&conn);
        let run_local = local;
        let run_remote = remote;
        let run_handle = tokio::spawn(async move {
            loop {
                let datagram = match run_conn.receive_datagram().await {
                    Ok(d) => d,
                    Err(_) => break,
                };
                if datagram.len() < 4 {
                    continue;
                }
                let id = u32::from_be_bytes([datagram[0], datagram[1], datagram[2], datagram[3]]);
                run_inner.lock().await.feed(id, datagram, run_local, run_remote);
            }
            run_inner.lock().await.close_all().await;
        });

        *self.clean_handle.lock().await = Some(clean_handle);
        *self.run_handle.lock().await = Some(run_handle);
    }

    /// 创建一个新 UDP session（对应 Go `udpSessionManager.udp()`）。
    ///
    /// 仅 client 端使用（生成新 id）。server 端在 `feed` 路径自动创建。
    pub async fn create_session(self: &Arc<Self>, conn: Arc<dyn QuicConn>, local: SocketAddr, remote: SocketAddr) -> Result<Arc<InterConn>> {
        let mut g = self.inner.lock().await;
        if g.closed {
            return Err(crate::error::HysteriaError::ConnectionClosed);
        }
        let id = g.next_id;
        g.next_id = g.next_id.wrapping_add(1);
        let sess = Arc::new(InterConn::new(local, remote, id, UDP_MESSAGE_CHAN_SIZE));
        // 设置 write_fn 调 conn.send_datagram
        let conn_for_write = Arc::clone(&conn);
        sess.set_write_fn(move |payload: &[u8]| {
            let conn = Arc::clone(&conn_for_write);
            let payload = payload.to_vec();
            Box::pin(async move { conn.send_datagram(&payload).await })
        });
        let inner_for_close = Arc::clone(&self.inner);
        let id_for_close = id;
        sess.set_close_fn(move || {
            // ponytail: 在 close_fn 中 try_lock，避免循环死锁
            if let Ok(mut g) = inner_for_close.try_lock() {
                g.sessions.remove(&id_for_close);
            }
        });
        g.sessions.insert(id, Arc::clone(&sess));
        Ok(sess)
    }

    /// 关闭所有 session + 标记 closed（对应 Go `udpSessionManager.run()` 末尾）。
    pub async fn close_all(&self) {
        self.inner.lock().await.close_all().await;
    }

    /// 当前活跃 session 数。
    pub async fn session_count(&self) -> usize {
        self.inner.lock().await.sessions.len()
    }
}

impl UdpSessionInner {
    fn feed(&mut self, id: u32, datagram: Vec<u8>, local: SocketAddr, remote: SocketAddr) {
        // 已存在的 session：投递
        if let Some(sess) = self.sessions.get(&id) {
            // 剥除前 4 字节 session id
            sess.feed(datagram[4..].to_vec());
            return;
        }
        // 新 id（server 路径）：创建 InterConn 并 on_new_session
        let on_new = self.on_new_session.clone();
        let sess = Arc::new(InterConn::new(local, remote, id, UDP_MESSAGE_CHAN_SIZE));
        sess.feed(datagram[4..].to_vec());
        self.sessions.insert(id, Arc::clone(&sess));
        if let Some(f) = on_new {
            f(sess);
        }
    }

    async fn close_all(&mut self) {
        self.closed = true;
        let sessions: Vec<_> = self.sessions.drain().map(|(_, v)| v).collect();
        for s in sessions {
            let _ = s.close().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_varint_one_byte() {
        assert_eq!(encode_varint(0x3F), vec![0x3F]);
    }

    #[test]
    fn encode_varint_frame_type_tcp_request() {
        // FrameTypeTCPRequest = 0x401 → 2 字节形式：0b01_000100_00000001 = 0x44 0x01
        let v = encode_varint(0x401);
        assert_eq!(v, vec![0x44, 0x01]);
    }

    #[test]
    fn encode_varint_two_byte_boundary() {
        assert_eq!(encode_varint(0x3FFF).len(), 2);
    }

    #[test]
    fn encode_varint_four_bytes() {
        assert_eq!(encode_varint(0x4000).len(), 4);
    }

    #[test]
    fn encode_varint_eight_bytes() {
        assert_eq!(encode_varint(0x4000_0000).len(), 8);
    }

    #[test]
    fn inter_stream_conn_constructs() {
        // 用 mock stream 验证构造
        #[derive(Debug)]
        struct MockStream {
            local: SocketAddr,
            remote: SocketAddr,
        }
        impl QuicStream for MockStream {
            fn read<'a>(
                &'a self,
                _buf: &'a mut [u8],
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<usize>> + Send + 'a>> {
                Box::pin(async { Ok(0) })
            }
            fn write<'a>(
                &'a self,
                buf: &'a [u8],
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<usize>> + Send + 'a>> {
                let len = buf.len();
                Box::pin(async move { Ok(len) })
            }
            fn cancel_read(&self, _code: u64) {}
            fn close(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>> {
                Box::pin(async { Ok(()) })
            }
            fn local_addr(&self) -> SocketAddr {
                self.local
            }
            fn remote_addr(&self) -> SocketAddr {
                self.remote
            }
        }
        let local: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let stream: Arc<dyn QuicStream> = Arc::new(MockStream { local, remote });
        let c = InterStreamConn::new(stream, local, remote, false);
        assert_eq!(c.local_addr(), local);
        assert_eq!(c.remote_addr(), remote);
    }

    #[tokio::test]
    async fn inter_conn_create_and_close() {
        let local: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let conn = InterConn::new(local, remote, 42, UDP_MESSAGE_CHAN_SIZE);
        assert_eq!(conn.id(), 42);
        assert!(!conn.is_closed());
        let _ = conn.close().await;
        assert!(conn.is_closed());
    }

    #[tokio::test]
    async fn inter_conn_read_returns_fed_data() {
        let local: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let conn = Arc::new(InterConn::new(local, remote, 1, UDP_MESSAGE_CHAN_SIZE));
        conn.feed(vec![1, 2, 3, 4]);
        let mut buf = [0u8; 16];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf[..4], &[1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn inter_conn_write_with_id_prefix_and_callback() {
        let local: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let conn = InterConn::new(local, remote, 100, UDP_MESSAGE_CHAN_SIZE);
        let captured: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let cap_clone = Arc::clone(&captured);
        conn.set_write_fn(move |payload: &[u8]| {
            let cap = Arc::clone(&cap_clone);
            let payload = payload.to_vec();
            Box::pin(async move {
                cap.lock().extend_from_slice(&payload);
                Ok(())
            })
        });
        let n = conn.write(&[10, 20, 30]).await.unwrap();
        assert_eq!(n, 3);
        let got = captured.lock().clone();
        // 前 4 字节是 session id (100 big-endian)
        assert_eq!(&got[..4], &[0, 0, 0, 100]);
        assert_eq!(&got[4..], &[10, 20, 30]);
    }

    #[tokio::test]
    async fn udp_session_manager_create_assigns_incrementing_ids() {
        let local: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
        // 用 NoopConn 避免真实 QUIC
        struct NoopConn {
            local: SocketAddr,
            remote: SocketAddr,
        }
        impl QuicConn for NoopConn {
            fn send_datagram<'a>(
                &'a self,
                _data: &'a [u8],
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send + 'a>> {
                Box::pin(async { Ok(()) })
            }
            fn receive_datagram(
                &self,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<u8>>> + Send>> {
                Box::pin(async {
                    std::future::pending::<()>().await;
                    unreachable!()
                })
            }
            fn close_with_error(&self, _code: u64, _reason: &str) {}
            fn local_addr(&self) -> SocketAddr {
                self.local
            }
            fn remote_addr(&self) -> SocketAddr {
                self.remote
            }
        }
        let conn: Arc<dyn QuicConn> = Arc::new(NoopConn { local, remote });
        let mgr = UdpSessionManager::new(Duration::from_secs(60), None);
        let s1 = mgr.create_session(Arc::clone(&conn), local, remote).await.unwrap();
        let s2 = mgr.create_session(Arc::clone(&conn), local, remote).await.unwrap();
        assert_eq!(s1.id(), 1);
        assert_eq!(s2.id(), 2);
        assert_eq!(mgr.session_count().await, 2);
    }

    #[test]
    fn inter_conn_touch_updates_last_active() {
        let local: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let remote: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let conn = InterConn::new(local, remote, 1, 8);
        let before = conn.last_active();
        std::thread::sleep(Duration::from_millis(5));
        conn.touch();
        let after = conn.last_active();
        assert!(after > before);
    }
}
