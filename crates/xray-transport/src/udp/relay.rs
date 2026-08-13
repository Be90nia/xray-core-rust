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
//!   一个 reader task 把收到的数据报 `(dest, data)` 投递到 `resp_tx`。
//! - 连接结束时调用 [`UdpRelay::close`] 中止所有 reader、释放 socket。
//!
//! ponytail: 暂不做 per-dest 空闲超时淘汰（Go 1min）。当 NAT 表膨胀或长连接泄漏时
//! 再加 idle eviction + 容量上限。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

/// UDP 接收缓冲（单包最大 64 KiB）。
const RECV_BUF: usize = 65_535;

/// 单个目标地址的 UDP 中继会话：连接到 `dest` 的 socket + 回包 reader task。
struct Session {
    sock: Arc<UdpSocket>,
    reader: JoinHandle<()>,
}

/// 连接级 UDP 中继：为每个目标地址维护一个 UDP socket。
///
/// 由入站 UDP-over-TCP 路径创建，连接结束后调用 [`UdpRelay::close`]。
pub struct UdpRelay {
    sessions: Mutex<HashMap<SocketAddr, Session>>,
}

impl UdpRelay {
    /// 创建空的中继表。
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            sessions: Mutex::new(HashMap::new()),
        })
    }

    /// 把 `payload` 作为 UDP 数据报发往 `dest`。
    ///
    /// 首次发往 `dest` 时绑定本地临时 socket、`connect(dest)`，并 spawn reader task
    /// 把该 socket 收到的数据报以 `(dest, data)` 投递到 `resp_tx`（供调用方按协议
    /// 帧格式编码后回写客户端）。后续发往同一 `dest` 复用 socket。
    ///
    /// # Errors
    /// socket bind / connect / send 失败时返回 `io::Error`。
    pub async fn send_to(
        &self,
        dest: SocketAddr,
        payload: &[u8],
        resp_tx: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
    ) -> std::io::Result<()> {
        let sock = {
            let mut sessions = self.sessions.lock().await;
            if let Some(s) = sessions.get(&dest) {
                Arc::clone(&s.sock)
            } else {
                let bind_addr: &str = match dest {
                    SocketAddr::V4(_) => "0.0.0.0:0",
                    SocketAddr::V6(_) => "[::]:0",
                };
                let sock = UdpSocket::bind(bind_addr).await?;
                sock.connect(dest).await?;
                let sock = Arc::new(sock);
                let reader = spawn_reader(Arc::clone(&sock), dest, resp_tx);
                sessions.insert(dest, Session { sock: Arc::clone(&sock), reader });
                sock
            }
        };
        sock.send(payload).await?;
        Ok(())
    }

    /// 关闭中继：中止所有 reader task、释放全部 socket。
    ///
    /// 连接结束时调用，避免空闲 socket 泄漏（reader 持有 socket + sender 的 Arc，
    /// 不主动中止会一直驻留）。
    pub async fn close(&self) {
        let mut sessions = self.sessions.lock().await;
        for (_, s) in sessions.drain() {
            s.reader.abort();
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
}

/// 每个 socket 的回包 reader：recv → `(dest, data)` 投递到 channel。
/// socket 关闭 / channel 关闭时退出。
fn spawn_reader(
    sock: Arc<UdpSocket>,
    dest: SocketAddr,
    resp_tx: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            match sock.recv(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if resp_tx.send((dest, buf[..n].to_vec())).is_err() {
                        break; // 调用方已停止接收
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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

        let (src, data) = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
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
}
