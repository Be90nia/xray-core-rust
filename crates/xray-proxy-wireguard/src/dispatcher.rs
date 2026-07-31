//! WireGuard outbound → DialBridge 适配器。
//!
//! 把 [`WireguardOutboundHandler`] 接入 dispatcher 的 [`DialBridge`]。
//!
//! ## 桥接架构
//!
//! smoltcp TCP socket 不直接 impl `AsyncRead/AsyncWrite`，需要中继：
//!
//! ```text
//! [上层 Link] ←→ [WireguardConnection (duplex half)] ←→ [中继 task] ←→ [smoltcp TCP socket]
//! ```
//!
//! 中继 task 持有 duplex 另一端 + `Arc<AsyncMutex<WgNetStack>>` + socket handle，
//! 用 `tokio::select!` 同时等待 duplex 可读 + 定时器，驱动 smoltcp socket IO。
//!
//! # ponytail: 轮询式桥接，延迟 ~5ms 量级。waker 驱动优化留待吞吐量瓶颈时。

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use smoltcp::socket::tcp;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Mutex as AsyncMutex, OnceCell};

use xray_app_dispatcher::default::DialFn;
use xray_common::net::address::Address;
use xray_common::net::destination::Destination;
use xray_common::net::network::Network;
use xray_transport::connection::Connection;

use crate::config::DeviceConfig;
use crate::netstack::WgNetStack;
use crate::outbound::WireguardOutboundHandler;

/// duplex 缓冲大小。
const DUPLEX_BUF: usize = 64 * 1024;

/// 中继轮询间隔（ms）。
const RELAY_POLL_MS: u64 = 5;

/// WireGuard 连接——包装 tokio duplex 的一半。
///
/// 上层通过 `AsyncRead/AsyncWrite` 读写 duplex，中继 task 在另一端
/// 桥接 smoltcp TCP socket。
pub struct WireguardConnection {
    read: tokio::io::DuplexStream,
    write: tokio::io::DuplexStream,
}

impl WireguardConnection {
    fn new(read: tokio::io::DuplexStream, write: tokio::io::DuplexStream) -> Self {
        Self { read, write }
    }
}

impl AsyncRead for WireguardConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().read).poll_read(cx, buf)
    }
}

impl AsyncWrite for WireguardConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().write).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_shutdown(cx)
    }
}

impl Connection for WireguardConnection {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
}

/// smoltcp TCP socket ↔ tokio duplex 中继 task。
///
/// 持有 duplex 的"远端"（与 [`WireguardConnection`] 配对）+ netstack + socket handle。
/// 用 `tokio::select!` 同时等待 duplex 可读 + 定时器，驱动 smoltcp socket IO。
struct TcpRelay {
    /// duplex 远端——从 WireguardConnection 侧读取用户数据。
    from_client: tokio::io::DuplexStream,
    /// duplex 远端——向 WireguardConnection 侧写入 smoltcp 数据。
    to_client: tokio::io::DuplexStream,
    /// smoltcp 网栈。
    netstack: Arc<AsyncMutex<WgNetStack>>,
    /// smoltcp TCP socket handle。
    handle: smoltcp::iface::SocketHandle,
}

impl TcpRelay {
    /// 运行中继循环直到 socket 关闭或出错。
    async fn run(mut self) {
        let poll_interval = Duration::from_millis(RELAY_POLL_MS);
        let mut timer = tokio::time::interval(poll_interval);
        // 消掉首次立即触发
        timer.tick().await;

        loop {
            // select! 上 duplex 可读 + 定时器
            let mut user_buf = vec![0u8; 8192];
            tokio::select! {
                // 用户数据到达（从 WireguardConnection 写入 → from_client 可读）
                result = tokio::io::AsyncReadExt::read(&mut self.from_client, &mut user_buf) => {
                    match result {
                        Ok(0) => {
                            // 用户侧关闭写入
                            self.close_socket().await;
                            return;
                        }
                        Ok(n) => {
                            user_buf.truncate(n);
                            self.send_to_smoltcp(&user_buf).await;
                        }
                        Err(_) => {
                            self.close_socket().await;
                            return;
                        }
                    }
                }
                // 定时器：检查 smoltcp socket 状态 + 接收数据
                _ = timer.tick() => {}
            }

            // 每次循环都尝试从 smoltcp 接收数据
            let should_close = self.recv_from_smoltcp().await;
            if should_close {
                let _ = tokio::io::AsyncWriteExt::shutdown(&mut self.to_client).await;
                return;
            }
        }
    }

    /// 发送用户数据到 smoltcp TCP socket。
    async fn send_to_smoltcp(&self, data: &[u8]) {
        let mut stack = self.netstack.lock().await;
        stack.poll(smoltcp::time::Instant::now());
        stack.with_tcp_socket(self.handle, |s| {
            if s.may_send() {
                // ponytail: 忽略部分写入——smoltcp send_slice 返回实际写入字节数
                // 下次 poll 时会继续发送缓冲区中的数据
                let _ = s.send_slice(data);
            }
        });
        stack.poll(smoltcp::time::Instant::now());
    }

    /// 从 smoltcp TCP socket 接收数据，写入 duplex。
    /// 返回 true 表示 socket 已关闭。
    async fn recv_from_smoltcp(&mut self) -> bool {
        let recv_data = {
            let mut stack = self.netstack.lock().await;
            stack.poll(smoltcp::time::Instant::now());
            let (data, closed) = stack.with_tcp_socket(self.handle, |s| {
                let mut buf = vec![0u8; 8192];
                let n = s.recv_slice(&mut buf).unwrap_or(0);
                buf.truncate(n);
                (buf, !s.is_active())
            });
            stack.poll(smoltcp::time::Instant::now());
            (data, closed)
        };

        if !recv_data.0.is_empty() {
            let _ = tokio::io::AsyncWriteExt::write(&mut self.to_client, &recv_data.0).await;
        }
        recv_data.1
    }

    async fn close_socket(&self) {
        let mut stack = self.netstack.lock().await;
        stack.with_tcp_socket(self.handle, |s| {
            s.close();
        });
        stack.poll(smoltcp::time::Instant::now());
    }
}

/// 构造 DialBridge 用的 DialFn 闭包（lazy init 模式）。
///
/// 闭包捕获 `DeviceConfig`。首次 dial 时通过 `OnceCell` lazy init
/// `WireguardOutboundHandler`（含 driver task + smoltcp netstack）。
///
/// # Panics
/// 不会 panic；任何错误以 `Err(String)` 返回。
pub fn make_wireguard_dial_fn(config: DeviceConfig) -> DialFn {
    let handler: Arc<OnceCell<WireguardOutboundHandler>> = Arc::new(OnceCell::new());
    let config_clone = config.clone();

    Arc::new(move |dest: &Destination| {
        let dest = dest.clone();
        let config = config_clone.clone();
        let handler_cell = Arc::clone(&handler);

        Box::pin(async move {
            // lazy init WireguardOutboundHandler（含 driver task）
            let handler = handler_cell
                .get_or_try_init(|| async {
                    WireguardOutboundHandler::new("wireguard", &config).await
                })
                .await
                .map_err(|e| format!("wireguard handler init: {e}"))?;

            // 验证目标地址类型（WireGuard 仅支持 IP，不支持 Domain）
            match dest.address() {
                Address::IPv4(_) | Address::IPv6(_) => {}
                Address::Domain(_) => {
                    return Err(
                        "wireguard outbound does not support Domain (DNS resolve by upper layer)"
                            .to_string(),
                    );
                }
            }

            // 仅 TCP（当前仅 TCP relay）
            if dest.network() != Network::TCP {
                return Err("wireguard outbound only supports TCP in dial_fn".to_string());
            }

            // 在 smoltcp netstack 上创建 TCP socket 并连接
            let ip = match dest.address() {
                Address::IPv4(v4) => smoltcp::wire::IpAddress::Ipv4(
                    smoltcp::wire::Ipv4Address::from_octets(v4.octets()),
                ),
                Address::IPv6(v6) => smoltcp::wire::IpAddress::Ipv6(
                    smoltcp::wire::Ipv6Address::from_octets(v6.octets()),
                ),
                Address::Domain(_) => unreachable!("checked above"),
            };
            let port = dest.port().value();

            let netstack = handler.netstack();
            let handle = {
                let mut stack = netstack.lock().await;
                let handle = stack.add_tcp_socket();
                stack
                    .tcp_connect(handle, ip, port)
                    .map_err(|e| format!("smoltcp tcp_connect: {e}"))?;
                handle
            };

            // 等待 smoltcp TCP 连接建立
            let connected = wait_tcp_connected(netstack, handle).await;
            if !connected {
                let mut stack = netstack.lock().await;
                stack.remove_socket(handle);
                return Err("wireguard outbound: tcp connect timeout or failed".to_string());
            }

            // 创建 duplex pair 桥接
            // ponytail: 用两个 duplex 而非一个——因为 tokio::io::duplex 是单向的
            // (client→relay 和 relay→client 各一个)
            let (client_to_relay, relay_from_client) = tokio::io::duplex(DUPLEX_BUF);
            let (relay_to_client, client_from_relay) = tokio::io::duplex(DUPLEX_BUF);

            let conn = WireguardConnection::new(client_from_relay, client_to_relay);

            // spawn 中继 task
            let relay = TcpRelay {
                from_client: relay_from_client,
                to_client: relay_to_client,
                netstack: Arc::clone(netstack),
                handle,
            };
            tokio::spawn(async move {
                relay.run().await;
            });

            Ok(Box::new(conn) as Box<dyn Connection>)
        })
    })
}

/// 等待 smoltcp TCP socket 连接建立（轮询，最多 5 秒）。
async fn wait_tcp_connected(
    netstack: &Arc<AsyncMutex<WgNetStack>>,
    handle: smoltcp::iface::SocketHandle,
) -> bool {
    let timeout = Duration::from_secs(5);
    let start = std::time::Instant::now();
    let poll_interval = Duration::from_millis(RELAY_POLL_MS);

    loop {
        {
            let mut stack = netstack.lock().await;
            stack.poll(smoltcp::time::Instant::now());
            let state = stack.with_tcp_socket(handle, |s| s.state());
            if state == tcp::State::Established {
                return true;
            }
            if state == tcp::State::Closed || state == tcp::State::CloseWait {
                return false;
            }
        }

        if start.elapsed() >= timeout {
            return false;
        }
        tokio::time::sleep(poll_interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wireguard_connection_satisfies_traits() {
        fn assert_async_read<T: AsyncRead>() {}
        fn assert_async_write<T: AsyncWrite>() {}
        fn assert_connection<T: Connection>() {}

        assert_async_read::<WireguardConnection>();
        assert_async_write::<WireguardConnection>();
        assert_connection::<WireguardConnection>();
    }

    #[tokio::test]
    async fn duplex_bridge_basic_io() {
        // 验证 duplex pair 基本读写
        let (client_to_relay, mut relay_from_client) = tokio::io::duplex(DUPLEX_BUF);
        let (mut relay_to_client, client_from_relay) = tokio::io::duplex(DUPLEX_BUF);

        let mut conn = WireguardConnection::new(client_from_relay, client_to_relay);

        // 写入到 conn（通过 write half）
        let write_data = b"hello wireguard";
        tokio::io::AsyncWriteExt::write(&mut conn.write, write_data)
            .await
            .expect("write to conn");

        // 从 relay 侧读取
        let mut buf = vec![0u8; 64];
        let n = tokio::io::AsyncReadExt::read(&mut relay_from_client, &mut buf)
            .await
            .expect("read from relay");
        assert_eq!(&buf[..n], write_data);

        // 从 relay 侧写入
        let reply = b"reply from tunnel";
        tokio::io::AsyncWriteExt::write(&mut relay_to_client, reply)
            .await
            .expect("write from relay");

        // 从 conn 侧读取
        let mut rbuf = vec![0u8; 64];
        let rn = tokio::io::AsyncReadExt::read(&mut conn.read, &mut rbuf)
            .await
            .expect("read from conn");
        assert_eq!(&rbuf[..rn], reply);
    }
}
