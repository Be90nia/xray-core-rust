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
//! - `send_to(dest, payload, resp_tx)` 懒创建连接到 `dest` 的 UDP socket，并 spawn
//!   reader + idle timer task。
//! - 每个 session 配一个 [`xray_common::signal::ActivityTimer`]（Go
//!   `CancelAfterInactivity` 等价，默认 60s）；reader 收到包 / `send_to` 重发均刷新；
//!   超时后 timer task 中止 reader 并从 map 移除该项（防 socket 泄漏）。
//! - 连接结束时调用 [`UdpRelay::close`] 中止所有 reader / timer task。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use xray_common::signal::ActivityTimer;

/// UDP 接收缓冲（单包最大 64 KiB）。
const RECV_BUF: usize = 65_535;

/// Per-dest 空闲超时（Go `signal.CancelAfterInactivity(1 * time.Minute)` 等价）。
///
/// ponytail: hardcode 60s，未暴露 policy 配置化入口（与 issue Non-goals 一致）。
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// 单个目标地址的 UDP 中继会话：连接到 `dest` 的 socket + reader task + timer task。
struct Session {
    sock: Arc<UdpSocket>,
    reader: JoinHandle<()>,
    timer: JoinHandle<()>,
    activity: Arc<ActivityTimer>,
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
                s.activity.update_activity();
                Arc::clone(&s.sock)
            } else {
                let bind_addr: &str = match dest {
                    SocketAddr::V4(_) => "0.0.0.0:0",
                    SocketAddr::V6(_) => "[::]:0",
                };
                let sock = UdpSocket::bind(bind_addr).await?;
                sock.connect(dest).await?;
                let sock = Arc::new(sock);
                let (reader, timer, activity) = spawn_session(
                    Arc::clone(&sock),
                    dest,
                    resp_tx,
                    Weak::clone(&self.self_weak),
                    self.idle_timeout,
                );
                sessions.insert(
                    dest,
                    Session {
                        sock: Arc::clone(&sock),
                        reader,
                        timer,
                        activity,
                    },
                );
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
            // 先 cancel activity（让 timer task 立即退出），再 abort reader /
            // timer handle 兜底（防止 task 卡在别的 .await 上）。
            s.activity.cancel();
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
/// - reader: `recv → channel`，socket 出错 / activity cancelled 时退出。
/// - timer: `ActivityTimer::run`；超时后升级 `Weak<UdpRelay>` 移除本 session，
///   并 `abort()` reader 让其本地 `Arc<UdpSocket>` 立即 drop（关闭 socket）。
fn spawn_session(
    sock: Arc<UdpSocket>,
    dest: SocketAddr,
    resp_tx: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
    relay: Weak<UdpRelay>,
    idle_timeout: Duration,
) -> (JoinHandle<()>, JoinHandle<()>, Arc<ActivityTimer>) {
    let activity = Arc::new(ActivityTimer::new(idle_timeout));
    let activity_for_reader = Arc::clone(&activity);
    let activity_for_timer = Arc::clone(&activity);
    // timer 用 sock 的 clone 做 ptr_eq 比对；reader 独占 sock 的 recv。
    let sock_for_timer = Arc::clone(&sock);

    // reader: 持续 recv，recv 出错 → 退出；每次成功 recv 刷新 activity。
    // reader 退出时不主动改 map——交给 timer task 统一回收（避免 reader 与 timer
    // 并发删除）。
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; RECV_BUF];
        let mut done = activity_for_reader.done();
        loop {
            tokio::select! {
                res = sock.recv(&mut buf) => {
                    match res {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            activity_for_reader.update_activity();
                            if resp_tx.send((dest, buf[..n].to_vec())).is_err() {
                                break; // 调用方已停止接收
                            }
                        }
                    }
                }
                _ = done.wait() => {
                    // timer 已 cancel（超时 / close），reader 退出
                    break;
                }
            }
        }
    });

    // timer: 阻塞到超时 / cancel。run() 返回后（无论是 timeout 还是 close 触发的
    // cancel）：统一回收——升级 weak → 锁 map → 若 entry 仍是本 sock 则
    // `abort reader` + 移除项。abort reader 让 reader 任务内本地 sock Arc 立即
    // drop（关闭 socket）。`Arc::ptr_eq` 防 close→新建同名 dest 后被旧 timer 误删。
    let timer = tokio::spawn(async move {
        // 单独 timer 拥有 `activity_for_timer` 的独占所有权用于 run()。
        let unique = match Arc::try_unwrap(activity_for_timer) {
            Ok(t) => t,
            Err(arc) => {
                // 极端 fallback：reader 还持 activity 的引用 → 用 0 超时让
                // run() 立即返回。后续回收逻辑统一执行。
                drop(arc);
                ActivityTimer::new(Duration::ZERO)
            }
        };
        let mut timer = unique;
        timer.run().await;
        if let Some(relay) = relay.upgrade() {
            let mut sessions = relay.sessions.lock().await;
            // 仅当 entry 仍是本 session 的 sock 时才回收——防 close→新建同名
            // dest 后被旧 timer 误删（移除前 ptr 比对）。
            let entry = match sessions.get(&dest) {
                Some(entry) if Arc::ptr_eq(&entry.sock, &sock_for_timer) => {
                    sessions.remove(&dest)
                }
                _ => None,
            };
            drop(sessions);
            if let Some(entry) = entry {
                entry.reader.abort();
            }
        }
    });

    (reader, timer, activity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use tokio::net::UdpSocket;

    /// 端到端：UdpRelay.send_to 把数据报投递到目标 UDP echo，回包经 channel 回来。
    #[tokio::test]
    async fn relay_roundtrips_to_udp_echo() {
        // echo UDP server
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; RECV_BUF];
            loop {
                match echo.recv_from(&mut buf).await {
                    Ok((n, peer)) => {
                        let _ = echo.send_to(&buf[..n], peer).await;
                    }
                    Err(_) => break,
                }
            }
        });

        let relay = UdpRelay::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        relay
            .send_to(echo_addr, b"ping", tx)
            .await
            .expect("send_to");

        let (src, data) = tokio::time::timeout(Duration::from_secs(2), rx.recv())
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
                    }
                    Err(_) => break,
                }
            }
        });

        let relay = UdpRelay::with_idle_timeout(Duration::from_millis(200));
        let (tx, mut rx) = mpsc::unbounded_channel();
        relay
            .send_to(echo_addr, b"ping", tx)
            .await
            .expect("send_to");

        let _ = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out waiting for echo")
            .expect("channel closed");
        assert_eq!(relay.len().await, 1);

        // 等 idle 超时（200ms）+ 裕量（timer 1s polling + map lock + abort）
        tokio::time::sleep(Duration::from_millis(800)).await;

        assert_eq!(
            relay.len().await,
            0,
            "idle session should be evicted after timeout"
        );

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
                    }
                    Err(_) => break,
                }
            }
        });

        // 200ms 超时，每 100ms 发包 → 持续刷新活动
        let relay = UdpRelay::with_idle_timeout(Duration::from_millis(200));
        let (tx, mut rx) = mpsc::unbounded_channel();
        relay
            .send_to(echo_addr, b"ping", tx.clone())
            .await
            .expect("send_to");

        for i in 0..5 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            relay
                .send_to(echo_addr, format!("ping-{i}").as_bytes(), tx.clone())
                .await
                .expect("send_to keepalive");
            let _ = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;
            assert_eq!(
                relay.len().await,
                1,
                "active session must not be evicted (round {i})"
            );
        }

        // 停发 → 等超时 → 被淘汰
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert_eq!(relay.len().await, 0);

        echo_running.store(false, Ordering::Relaxed);
        relay.close().await;
    }
}
