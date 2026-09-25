//! AnyTLS outbound → DialBridge 适配器（阶段 1 切片 1a）。
//!
//! 把 [`AnytlsClient`] 接入 dispatcher 的 [`DialBridge`]：提供
//! [`make_dial_fn`] 闭包，内部把 [`Destination`] 转 [`SocksAddr`] 后调
//! [`AnytlsClient::dial`]。
//!
//! ## Connection wrapper
//!
//! [`AnytlsConn`] 已 impl `AsyncRead + AsyncWrite + Unpin`，但缺
//! [`Connection`] trait 要求的 `remote_addr` / `local_addr`。anytls session
//! 池不暴露底层 socket 地址，故 [`AnytlsConnection`] 这两个方法返 `Ok(None)`。
//! dispatcher bridge 不用这两个地址做转发决策，仅日志层用。
//!
//! [`DialBridge`]: xray_app_dispatcher::default::DialBridge
//! [`DialFn`]: xray_app_dispatcher::default::DialFn
//! [`Connection`]: xray_transport::connection::Connection

use std::{
    io,
    net::{SocketAddr, SocketAddrV6},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use xray_app_dispatcher::default::DialFn;
use xray_common::net::{address::Address, destination::Destination};
use xray_transport::connection::Connection;

use crate::{
    client::{AnytlsClient, AnytlsConn},
    socks::SocksAddr,
};

/// AnytlsConn + Connection trait 实现。
///
/// `remote_addr` / `local_addr` 返 `None`：anytls session 池不暴露底层
/// socket 地址，dispatcher bridge 不依赖这两个字段做转发。
pub struct AnytlsConnection {
    inner: AnytlsConn,
}

impl AnytlsConnection {
    /// 包装已有 AnytlsConn。
    #[must_use]
    pub fn new(inner: AnytlsConn) -> Self {
        Self { inner }
    }
}

impl AsyncRead for AnytlsConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for AnytlsConnection {
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

impl Connection for AnytlsConnection {
    fn remote_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }
}

/// Destination → SocksAddr 转换。
///
/// IPv6 用 SocketAddrV6 包装（flowinfo/scope_id 设 0，与 SOCKS5 编码无关）。
fn dest_to_socks(dest: &Destination) -> Result<SocksAddr, String> {
    let port = dest.port().value();
    match dest.address() {
        Address::IPv4(ip) => Ok(SocksAddr::ipv4(*ip, port)),
        Address::IPv6(ip) => Ok(SocksAddr::Ipv6(SocketAddrV6::new(*ip, port, 0, 0))),
        Address::Domain(d) => Ok(SocksAddr::domain(d.clone(), port)),
    }
}

/// 构造 DialBridge 用的 DialFn 闭包。
///
/// 闭包捕获 `Arc<AnytlsClient>`，每次调用：
/// 1. 把 [`Destination`] 转 [`SocksAddr`]（同步）
/// 2. `client.dial(&socks)` 拨号到 AnyTLS 服务端
/// 3. 包装返回 [`AnytlsConnection`]（impl [`Connection`]）
///
/// # Panics
///
/// 不会 panic；任何错误（包括 dest 解析、dial 失败）以 `Err(String)` 返回。
pub fn make_dial_fn(client: Arc<AnytlsClient>) -> DialFn {
    Arc::new(move |dest: &Destination| {
        let client = Arc::clone(&client);
        // 同步解析 dest → socks，避免借用 dest 进 'static future
        let socks = match dest_to_socks(dest) {
            Ok(s) => s,
            Err(e) => {
                return Box::pin(async move { Err(e) });
            },
        };
        Box::pin(async move {
            let conn = client.dial(&socks).await.map_err(|e| format!("anytls dial: {e}"))?;
            Ok(Box::new(AnytlsConnection::new(conn)) as Box<dyn Connection>)
        })
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use xray_common::net::{network::Network, port::Port};

    use super::*;

    #[test]
    fn dest_to_socks_ipv4() {
        let d = Destination::new(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(8080),
            Network::TCP,
        );
        let s = dest_to_socks(&d).unwrap();
        match s {
            SocksAddr::Ipv4(a) => {
                assert_eq!(a.ip().octets(), [127, 0, 0, 1]);
                assert_eq!(a.port(), 8080);
            },
            _ => panic!("expected Ipv4"),
        }
    }

    #[test]
    fn dest_to_socks_ipv6() {
        let d = Destination::new(
            Address::from_ipv6_bytes(Ipv6Addr::LOCALHOST.octets()),
            Port::new(443),
            Network::TCP,
        );
        let s = dest_to_socks(&d).unwrap();
        match s {
            SocksAddr::Ipv6(a) => {
                assert_eq!(a.ip(), &Ipv6Addr::LOCALHOST);
                assert_eq!(a.port(), 443);
            },
            _ => panic!("expected Ipv6"),
        }
    }

    #[test]
    fn dest_to_socks_domain() {
        let d = Destination::new(Address::new_domain("example.com"), Port::new(443), Network::TCP);
        let s = dest_to_socks(&d).unwrap();
        match s {
            SocksAddr::Domain(h, p) => {
                assert_eq!(h, "example.com");
                assert_eq!(p, 443);
            },
            _ => panic!("expected Domain"),
        }
    }
}
