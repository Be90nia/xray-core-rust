//! TUIC outbound → DialBridge 适配器（阶段 1 切片 1b）。
//!
//! 把 [`TuicClient`] 接入 dispatcher 的 [`DialBridge`]：[`make_dial_fn`]
//! 闭包内部把 [`Destination`] 转 tuic [`Address`] 后调 [`TuicClient::dial`]。
//!
//! ## Connection wrapper
//!
//! [`TuicConn`] 直接暴露 quinn `SendStream` / `RecvStream`（quinn 0.11
//! 错误类型不兼容 tokio io::Error，刻意不 impl AsyncRead/AsyncWrite）。
//! 这里用 `tokio::io::duplex + spawn pump` 桥接到 AsyncRead+AsyncWrite，
//! 与 anytls 的 AnytlsConn 同模式。
//!
//! [`DialBridge`]: xray_app_dispatcher::default::DialBridge
//! [`DialFn`]: xray_app_dispatcher::default::DialFn
//! [`Connection`]: xray_transport::connection::Connection

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

use xray_app_dispatcher::default::DialFn;
use xray_common::net::address::Address as XrayAddress;
use xray_common::net::destination::Destination;
use xray_transport::connection::Connection;

use crate::client::{TuicClient, TuicConn};
use crate::protocol::Address;

/// TUIC duplex 缓冲（与 anytls 一致：64 KiB）。
const DUPLEX_BUF_SIZE: usize = 64 * 1024;

/// TUIC 连接包装：内部用 `tokio::io::duplex` 桥接 quinn SendStream/RecvStream。
///
/// `_pump` 字段保证桥接 task 生命周期与连接一致——drop 时自动 abort。
pub struct TuicConnection {
    inner: DuplexStream,
    _pump: tokio::task::JoinHandle<()>,
}

impl AsyncRead for TuicConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TuicConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Connection for TuicConnection {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
}

/// Destination → tuic protocol Address 转换。
pub fn dest_to_tuic_address(dest: &Destination) -> Result<Address, String> {
    let port = dest.port().value();
    match dest.address() {
        XrayAddress::IPv4(ip) => Ok(Address::Ipv4(*ip, port)),
        XrayAddress::IPv6(ip) => Ok(Address::Ipv6(*ip, port)),
        XrayAddress::Domain(d) => Ok(Address::Domain(d.clone(), port)),
    }
}

/// 构造 DialBridge 用的 DialFn 闭包。
///
/// 闭包捕获 `Arc<TuicClient>`，每次调用：
/// 1. 把 [`Destination`] 转 tuic [`Address`]（同步）
/// 2. `client.dial(addr)` 拨号到 TUIC 服务端
/// 3. spawn pump 桥接 quinn streams → duplex
/// 4. 返回 [`TuicConnection`]（impl [`Connection`]）
///
/// # Panics
///
/// 不会 panic；任何错误以 `Err(String)` 返回。
pub fn make_dial_fn(client: Arc<TuicClient>) -> DialFn {
    client.start_heartbeat(HEARTBEAT_INTERVAL);
    Arc::new(move |dest: &Destination| {
        let client = Arc::clone(&client);
        let addr = match dest_to_tuic_address(dest) {
            Ok(a) => a,
            Err(e) => {
                return Box::pin(async move { Err(e) });
            }
        };
        Box::pin(async move {
            let conn = tokio::time::timeout(Duration::from_secs(30), client.dial(addr))
                .await
                .map_err(|_| "tuic dial: timed out".to_string())?
                .map_err(|e| format!("tuic dial: {e}"))?;
            Ok(Box::new(TuicConnection::from_conn(conn)) as Box<dyn Connection>)
        })
    })
}

/// 构造 DialBridge 用的 DialFn 闭包（lazy init 模式）。
///
/// 闭包捕获连接参数。首次 dial 时通过 `OnceCell` lazy init
/// `TuicClient`（含 QUIC 连接 + 认证），后续复用。
///
/// # Panics
///
/// 不会 panic；任何错误以 `Err(String)` 返回。
/// `server_addr` 为 `host:port` 或 `ip:port`；域名在首次 dial 时经
/// `ToSocketAddrs` 系统 DNS 解析（bd #17：真实节点 address 是域名）。
pub fn make_dial_fn_lazy(
    server_addr: String,
    server_name: String,
    uuid: uuid::Uuid,
    password: String,
    rustls_config: Arc<rustls::ClientConfig>,
    options: crate::client::TuicConnectOptions,
) -> DialFn {
    use tokio::sync::OnceCell;
    let client: Arc<OnceCell<Arc<TuicClient>>> = Arc::new(OnceCell::new());
    let pool = crate::pool::QuinnConnectionPool::new();
    let heartbeat = options.heartbeat;

    Arc::new(move |dest: &Destination| {
        let server_addr_log = server_addr.clone();
        let client_cell = Arc::clone(&client);
        let server_addr = server_addr.clone();
        let server_name = server_name.clone();
        let uuid = uuid;
        let password = password.clone();
        let rustls_config = Arc::clone(&rustls_config);
        let pool = pool.clone();
        let options = options.clone();
        let addr = match dest_to_tuic_address(dest) {
            Ok(a) => a,
            Err(e) => {
                return Box::pin(async move { Err(e) });
            }
        };
        Box::pin(async move {
            // lazy init TuicClient（含 QUIC 连接 + 认证），后续复用；init 即挂周期心跳。
            let c = client_cell
                .get_or_try_init(|| async {
                    let c = TuicClient::connect_with(
                        server_addr,
                        &server_name,
                        uuid,
                        &password,
                        rustls_config,
                        options,
                        pool,
                    )
                    .await
                    .map_err(|e| format!("tuic connect: {e}"))?;
                    let c = Arc::new(c);
                    c.start_heartbeat(heartbeat);
                    Ok::<Arc<TuicClient>, String>(c)
                })
                .await
                .inspect_err(|e| tracing::warn!(server = %server_addr_log, "tuic client init failed: {e}"))?;
            let conn = match tokio::time::timeout(Duration::from_secs(30), c.dial(addr.clone())).await
            {
                Ok(Ok(conn)) => conn,
                Ok(Err(e)) => {
                    tracing::warn!(target = ?addr, "tuic dial failed: {e}");
                    return Err(format!("tuic dial: {e}"));
                }
                Err(_) => {
                    tracing::warn!(target = ?addr, "tuic dial timed out");
                    return Err("tuic dial: timed out".to_string());
                }
            };
            Ok(Box::new(TuicConnection::from_conn(conn)) as Box<dyn Connection>)
        })
    })
}

/// 心跳周期（官方 tuic client 默认 3s）。
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);

impl TuicConnection {
    /// 从 TuicConn 构造：拆 send/recv，spawn pump，返回 duplex 客户端包装。
    fn from_conn(conn: TuicConn) -> Self {
        let (client_io, server_io) = tokio::io::duplex(DUPLEX_BUF_SIZE);
        let pump = tokio::spawn(pump_streams(conn.send, conn.recv, server_io));
        Self {
            inner: client_io,
            _pump: pump,
        }
    }
}

/// 双向桥接 quinn SendStream/RecvStream 与 duplex 的 server 端。
///
/// 任一方向 EOF 或出错都终止。up 结束前调 `send.finish()` 通知对端写方向关闭；
/// down 结束前调 `wr.shutdown()` 通知 duplex client 读端 EOF。
async fn pump_streams(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    server_io: DuplexStream,
) {
    let (mut rd, mut wr) = tokio::io::split(server_io);

    // up: duplex rd → quinn send（数据从本地 outbound 写向 TUIC 服务端）
    let up = async move {
        let mut buf = vec![0u8; 8 * 1024];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = send.write_all(&buf[..n]).await {
                        tracing::debug!("tuic pump up send error: {e}");
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("tuic pump up read error: {e}");
                    break;
                }
            }
        }
        // 通知 TUIC server：客户端写方向已关闭
        let _ = send.finish();
    };

    // down: quinn recv → duplex wr（数据从 TUIC 服务端读到本地 outbound）
    let down = async move {
        let mut buf = vec![0u8; 8 * 1024];
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    if n == 0 {
                        continue;
                    }
                    if let Err(e) = wr.write_all(&buf[..n]).await {
                        tracing::debug!("tuic pump down write error: {e}");
                        break;
                    }
                }
                Ok(None) => break, // stream ended
                Err(e) => {
                    tracing::debug!("tuic pump down read error: {e}");
                    break;
                }
            }
        }
        // 通知 duplex client：TUIC server 读方向已结束
        let _ = wr.shutdown().await;
    };

    tokio::join!(up, down);
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_common::net::network::Network;
    use xray_common::net::port::Port;

    use std::net::Ipv6Addr;

    #[test]
    fn dest_to_tuic_ipv4() {
        let d = Destination::new(
            XrayAddress::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(8080),
            Network::TCP,
        );
        let a = dest_to_tuic_address(&d).unwrap();
        match a {
            Address::Ipv4(ip, p) => {
                assert_eq!(ip.octets(), [127, 0, 0, 1]);
                assert_eq!(p, 8080);
            }
            _ => panic!("expected Ipv4"),
        }
    }

    #[test]
    fn dest_to_tuic_ipv6() {
        let d = Destination::new(
            XrayAddress::from_ipv6_bytes(Ipv6Addr::LOCALHOST.octets()),
            Port::new(443),
            Network::TCP,
        );
        let a = dest_to_tuic_address(&d).unwrap();
        match a {
            Address::Ipv6(ip, p) => {
                assert_eq!(ip, Ipv6Addr::LOCALHOST);
                assert_eq!(p, 443);
            }
            _ => panic!("expected Ipv6"),
        }
    }

    #[test]
    fn dest_to_tuic_domain() {
        let d = Destination::new(
            XrayAddress::new_domain("example.com"),
            Port::new(443),
            Network::TCP,
        );
        let a = dest_to_tuic_address(&d).unwrap();
        match a {
            Address::Domain(s, p) => {
                assert_eq!(s, "example.com");
                assert_eq!(p, 443);
            }
            _ => panic!("expected Domain"),
        }
    }
}
