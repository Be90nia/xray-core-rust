//! # Inbound UDP-over-TCP relay
//!
//! 对应 Go `transport/internet/udp/dispatcher.go` 的 NAT session 部分（入站视角）。
//!
//! trojan / vmess / shadowsocks 入站把客户端的 UDP-over-TCP 帧拆成一个个数据报后，
//! 需要为每个**目标地址**维护一个 UDP socket：发往该目标的数据报走同一 socket，
//! 该 socket 收到的回包再回写给客户端。本模块封装「per-destination socket + 回包通道」
//! 这一无协议无关逻辑，协议特定的帧编解码（trojan `[addr][len][CRLF][payload]`、
//! SS 加密包等）留在各 proxy crate。
//!
//! 设计：
//! - 每个 `UdpRelay` 绑定一次入站连接（连接级生命周期）。
//! - `send_to(dest, payload, resp_tx)` 懒创建连接到 `dest` 的 UDP socket，并 spawn reader + idle
//!   timer task。
//! - 每 session 维护 `last_refresh` 时间戳（Go `CancelAfterInactivity` 等价，默认 60s）；reader
//!   收到包 / `send_to` 重发均刷新；timer task 滑动检查超时后中止 reader 并从 map 移除该项（防
//!   socket 泄漏）。
//! - 连接结束时调用 [`UdpRelay::close`] 中止所有 reader / timer task。

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Weak},
    time::{Duration, Instant},
};

use tokio::{
    net::UdpSocket,
    sync::{Mutex, mpsc},
    task::JoinHandle,
};

/// UDP 接收缓冲（单包最大 64 KiB）。
const RECV_BUF: usize = 65_535;

/// Per-dest 空闲超时。
///
/// 对齐 Go `transport/internet/udp/dispatcher.go:102`：
/// `signal.CancelAfterInactivity(ctx, entry.terminate, time.Minute)` —— Go 硬编码
/// 60s，**不读 policy**（ConnectionIdle 在 Go 全库唯一消费者是 wireguard
/// client.go:175；singbridge 是另一处硬编码 300s）。故保持 60s 不接 policy——
/// 接 policy 属 Go 没有的行为差异。需自定义时用 [`UdpRelay::with_idle_timeout`]。
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// 单个目标地址的 UDP 中继会话：连接到 `dest` 的 socket + reader task + timer task。
struct Session {
    sock: Arc<UdpSocket>,
    reader: JoinHandle<()>,
    timer: JoinHandle<()>,
    last_refresh: Arc<parking_lot::Mutex<Instant>>,
}

/// 连接级 UDP 中继：为每个目标地址维护一个 UDP socket。
///
/// 由入站 UDP-over-TCP 路径创建，连接结束后调用 [`UdpRelay::close`]。
pub struct UdpRelay {
    /// 自弱引用，供后台 task 通过 `weak.upgrade()` 拿到 `Arc<UdpRelay>` 移除自身。
    /// `Arc::new_cyclic` 在构造时一次性填入。
    self_weak: Weak<Self>,
    sessions: Mutex<HashMap<SocketAddr, Session>>,
    /// 空闲超时；`Duration::ZERO` = 禁用空闲淘汰（永久持有）。
    idle_timeout: Duration,
}

impl UdpRelay {
    /// 创建空的中继表，使用默认 60s 空闲超时（对齐 Go 行为）。
    #[must_use]
    pub fn new() -> Arc<Self> {
        Self::with_idle_timeout(DEFAULT_IDLE_TIMEOUT)
    }

    /// 自定义空闲超时。`Duration::ZERO` = 禁用（保留历史行为用于测试 / 策略回退）。
    #[must_use]
    pub fn with_idle_timeout(idle_timeout: Duration) -> Arc<Self> {
        Arc::new_cyclic(|weak| Self {
            self_weak: weak.clone(),
            sessions: Mutex::new(HashMap::new()),
            idle_timeout,
        })
    }

    /// 把 `payload` 作为 UDP 数据报发往 `dest`。
    ///
    /// 首次发往 `dest` 时绑定本地临时 socket、`connect(dest)`，并 spawn reader +
    /// timer task。后续发往同一 `dest` 复用 socket 并刷新活动计时。
    ///
    /// # Errors
    /// socket bind / connect / send 失败时返回 `io::Error`。
    pub async fn send_to(
        self: &Arc<Self>,
        dest: SocketAddr,
        payload: &[u8],
        resp_tx: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
    ) -> std::io::Result<()> {
        let sock = {
            let mut sessions = self.sessions.lock().await;
            if let Some(s) = sessions.get(&dest) {
                *s.last_refresh.lock() = Instant::now();
                Arc::clone(&s.sock)
            } else {
                let bind_addr: &str = match dest {
                    SocketAddr::V4(_) => "0.0.0.0:0",
                    SocketAddr::V6(_) => "[::]:0",
                };
                let sock = UdpSocket::bind(bind_addr).await?;
                sock.connect(dest).await?;
                let sock = Arc::new(sock);
                let last_refresh = Arc::new(parking_lot::Mutex::new(Instant::now()));
                let (reader, timer) = spawn_session(
                    Arc::clone(&sock),
                    dest,
                    resp_tx,
                    Weak::clone(&self.self_weak),
                    self.idle_timeout,
                    Arc::clone(&last_refresh),
                );
                sessions
                    .insert(dest, Session { sock: Arc::clone(&sock), reader, timer, last_refresh });
                sock
            }
        };
        sock.send(payload).await?;
        Ok(())
    }

    /// 关闭中继：中止所有 reader / timer task、释放全部 socket。
    ///
    /// 连接结束时调用，避免空闲 socket 泄漏。
    pub async fn close(&self) {
        let mut sessions = self.sessions.lock().await;
        for (_, s) in sessions.drain() {
            // timer/reader task 直接 abort 兜底（task 卡在 recv/sleep 上立即回收）。
            s.reader.abort();
            s.timer.abort();
        }
    }

    /// 当前活跃的目标会话数。
    pub async fn len(&self) -> usize {
        self.sessions.lock().await.len()
    }

    /// 是否无活跃会话。
    pub async fn is_empty(&self) -> bool {
        self.sessions.lock().await.is_empty()
    }

    /// 配置的空闲超时（用于测试断言）。
    #[must_use]
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }
}

/// 每个 socket 的回包 reader + 空闲计时器。
///
/// - reader: `recv → channel`，socket 出错 / 被 abort 时退出；每次成功 recv 刷新 `last_refresh`
///   时间戳。
/// - timer: 滑动 idle 检查——睡到「上次刷新 + idle_timeout」，醒来后复查时间戳，
///   有新刷新则继续睡；真超时后回收：升级 `Weak<UdpRelay>` 移除本 session 并 `abort()` reader
///   让其本地 `Arc<UdpSocket>` 立即 drop（关闭 socket）。
///
/// ponytail: 纯时间戳排序，无唤醒通道——刷新写入先于 timer 判定读取即生效；
/// 判定读取之后到达的刷新存在微秒级误杀窗口（Go timer.Stop 同类 race），实测无害。
fn spawn_session(
    sock: Arc<UdpSocket>,
    dest: SocketAddr,
    resp_tx: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
    relay: Weak<UdpRelay>,
    idle_timeout: Duration,
    last_refresh: Arc<parking_lot::Mutex<Instant>>,
) -> (JoinHandle<()>, JoinHandle<()>) {
    let last_refresh_for_reader = Arc::clone(&last_refresh);
    let sock_for_timer = Arc::clone(&sock);

    // reader: 持续 recv，recv 出错 → 退出；每次成功 recv 刷新 last_refresh。
    // reader 退出时不主动改 map——交给 timer task 统一回收（避免并发删除）。
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            match sock.recv(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    *last_refresh_for_reader.lock() = Instant::now();
                    if resp_tx.send((dest, buf[..n].to_vec())).is_err() {
                        break; // 调用方已停止接收
                    }
                },
            }
        }
    });

    // timer: 睡到「上次刷新 + idle_timeout」，醒来复查时间戳——期间有刷新则重算
    // 继续睡；真超时后统一回收：升级 weak → 锁 map → 若 entry 仍是本 sock 则移除
    // + `abort reader`（reader 任务内本地 sock Arc 立即 drop，关闭 socket）。
    // `Arc::ptr_eq` 防 close→新建同名 dest 后被旧 timer 误删（移除前 ptr 比对）。
    let timer = tokio::spawn(async move {
        loop {
            let since = last_refresh.lock().elapsed();
            if since >= idle_timeout {
                break;
            }
            tokio::time::sleep(idle_timeout - since).await;
        }
        if let Some(relay) = relay.upgrade() {
            let mut sessions = relay.sessions.lock().await;
            // 仅当 entry 仍是本 session 的 sock 时才回收——防 close→新建同名
            // dest 后被旧 timer 误删（移除前 ptr 比对）。
            let entry = match sessions.get(&dest) {
                Some(entry) if Arc::ptr_eq(&entry.sock, &sock_for_timer) => sessions.remove(&dest),
                _ => None,
            };
            drop(sessions);
            if let Some(entry) = entry {
                entry.reader.abort();
            }
        }
    });

    (reader, timer)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use tokio::net::UdpSocket;

    use super::*;

    /// 端到端：UdpRelay.send_to 把数据报投递到目标 UDP echo，回包经 channel 回来。
    #[tokio::test]
    async fn relay_roundtrips_to_udp_echo() {
        // echo UDP server
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; RECV_BUF];
            while let Ok((n, peer)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..n], peer).await;
            }
        });

        let relay = UdpRelay::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        relay.send_to(echo_addr, b"ping", tx).await.expect("send_to");

        let (src, data) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timed out waiting for echo")
            .expect("channel closed");
        assert_eq!(src, echo_addr);
        assert_eq!(&data, b"ping");

        // 复用同一 session：第二次发送不新建 socket
        assert_eq!(relay.len().await, 1);
        relay.close().await;
        assert_eq!(relay.len().await, 0);
    }

    /// 老化：闲置的 session 在 idle_timeout 后被回收（map 项移除）。
    #[tokio::test]
    async fn relay_evicts_idle_session() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_running = Arc::new(AtomicBool::new(true));
        let echo_running2 = Arc::clone(&echo_running);
        tokio::spawn(async move {
            let mut buf = vec![0u8; RECV_BUF];
            while echo_running2.load(Ordering::Relaxed) {
                match echo.recv_from(&mut buf).await {
                    Ok((n, peer)) => {
                        let _ = echo.send_to(&buf[..n], peer).await;
                    },
                    Err(_) => break,
                }
            }
        });

        let relay = UdpRelay::with_idle_timeout(Duration::from_millis(200));
        let (tx, mut rx) = mpsc::unbounded_channel();
        relay.send_to(echo_addr, b"ping", tx).await.expect("send_to");

        let _ = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timed out waiting for echo")
            .expect("channel closed");
        assert_eq!(relay.len().await, 1);

        // 等 idle 超时（200ms）+ 裕量（timer 1s polling + map lock + abort）
        tokio::time::sleep(Duration::from_millis(800)).await;

        assert_eq!(relay.len().await, 0, "idle session should be evicted after timeout");

        echo_running.store(false, Ordering::Relaxed);
    }

    /// 活跃 dest 不受影响：在超时前持续刷新活动，session 不被淘汰。
    #[tokio::test]
    async fn relay_keeps_active_session() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_running = Arc::new(AtomicBool::new(true));
        let echo_running2 = Arc::clone(&echo_running);
        tokio::spawn(async move {
            let mut buf = vec![0u8; RECV_BUF];
            while echo_running2.load(Ordering::Relaxed) {
                match echo.recv_from(&mut buf).await {
                    Ok((n, peer)) => {
                        let _ = echo.send_to(&buf[..n], peer).await;
                    },
                    Err(_) => break,
                }
            }
        });

        // 200ms 超时，每 100ms 发包 → 持续刷新活动
        let relay = UdpRelay::with_idle_timeout(Duration::from_millis(200));
        let (tx, mut rx) = mpsc::unbounded_channel();
        relay.send_to(echo_addr, b"ping", tx.clone()).await.expect("send_to");

        for i in 0..5 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            relay
                .send_to(echo_addr, format!("ping-{i}").as_bytes(), tx.clone())
                .await
                .expect("send_to keepalive");
            let _ = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;
            assert_eq!(relay.len().await, 1, "active session must not be evicted (round {i})");
        }

        // 停发 → 等超时 → 被淘汰
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert_eq!(relay.len().await, 0);

        echo_running.store(false, Ordering::Relaxed);
        relay.close().await;
    }

    #[test]
    fn default_idle_timeout_matches_go() {
        // Go udp/dispatcher.go:102 硬编码 time.Minute（非 policy）——见
        // DEFAULT_IDLE_TIMEOUT 文档。钉住 60s：防止被"接 policy 300s"的
        // 错误前提改动（Go 无此行为）。
        assert_eq!(DEFAULT_IDLE_TIMEOUT, Duration::from_secs(60));
    }
}
