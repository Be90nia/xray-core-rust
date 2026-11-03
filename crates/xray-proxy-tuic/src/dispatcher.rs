//! TUIC outbound → DialBridge 适配器（阶段 1 切片 1b）。
//!
//! 把 [`TuicClient`] 接入 dispatcher 的 [`DialBridge`]：[`make_dial_fn`]
//! 闭包内部把 [`Destination`] 转 tuic [`Address`] 后调 [`TuicClient::dial`]。
//!
//! ## Connection wrapper
//!
//! [`TuicConn`] 直接暴露 quinn `SendStream` / `RecvStream`；quinn 0.11 给两者
//! 各 impl 了 tokio `AsyncWrite` / `AsyncRead`（poll 式，错误映射成 io::Error），
//! 所以 [`TuicConnection`] 逐方法委托即可——零中转缓冲、零托管任务。
//! （旧实现是 `tokio::io::duplex + spawn pump`：每方向 2 次额外 memcpy + 1 个
//! 任务 + 一次调度往返。）
//!
//! [`DialBridge`]: xray_app_dispatcher::default::DialBridge
//! [`DialFn`]: xray_app_dispatcher::default::DialFn
//! [`Connection`]: xray_transport::connection::Connection

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, LazyLock},
    task::{Context, Poll},
    time::Duration,
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use xray_app_dispatcher::default::DialFn;
use xray_common::net::{address::Address as XrayAddress, destination::Destination};
use xray_frame::{LogFacade, PluginContext, deadline::Budget};
use xray_transport::connection::Connection;

use crate::{
    client::{TuicClient, TuicConn},
    protocol::Address,
};

/// 出站泵诊断门面（nn8os 2b 同型处置：tracing 宏 → LogFacade——本项目工具链上
/// `disallowed_macros` 对 proc-macro 不认任何 allow（fn/stmt/文件顶三形态实测
/// 无效），迁移为唯一关红路径。域 = "tuic"，target `xray_frame::tuic` +
/// mask_secrets。只在拨号失败/pump 错误分支发射；pump 循环外取一次引用
/// （坑约束⑫热路径零每包开销）。
static DISPATCH_LOG: LazyLock<LogFacade> = LazyLock::new(|| LogFacade::new("tuic", vec![]));

/// TUIC 连接包装：直接委托 quinn `SendStream` / `RecvStream`。
///
/// quinn 的流本身是 poll 式的，不需要中转缓冲也不需要桥接任务。
pub struct TuicConnection {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl AsyncRead for TuicConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 全限定：quinn 另有 inherent `poll_read(&mut self, cx, &mut [u8])`，裸调用会选错
        <quinn::RecvStream as AsyncRead>::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for TuicConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // 全限定：inherent `SendStream::poll_write` 返回 `WriteError`，不走 io::Error 映射
        <quinn::SendStream as AsyncWrite>::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        <quinn::SendStream as AsyncWrite>::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // quinn 的 poll_shutdown = `SendStream::finish()`（通知对端写方向关闭）
        <quinn::SendStream as AsyncWrite>::poll_shutdown(Pin::new(&mut self.send), cx)
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
/// `ctx` 已无消费方（委托路径不再 spawn 任务），保留形参只因装配面签名不变。
pub fn make_dial_fn(client: Arc<TuicClient>, _ctx: Arc<PluginContext>) -> DialFn {
    client.start_heartbeat(HEARTBEAT_INTERVAL);
    Arc::new(move |dest: &Destination| {
        let client = Arc::clone(&client);
        let addr = match dest_to_tuic_address(dest) {
            Ok(a) => a,
            Err(e) => {
                return Box::pin(async move { Err(e) });
            },
        };
        Box::pin(async move {
            let conn = Budget::tokio()
                .deadline(Duration::from_secs(30))
                .timeout(client.dial(addr))
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
    _ctx: Arc<PluginContext>,
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
            },
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
                .inspect_err(|e| {
                    DISPATCH_LOG
                        .warn(format!("tuic client init failed: {e} server={server_addr_log}"))
                })?;
            let conn = match Budget::tokio()
                .deadline(Duration::from_secs(30))
                .timeout(c.dial(addr.clone()))
                .await
            {
                Ok(Ok(conn)) => conn,
                Ok(Err(e)) => {
                    DISPATCH_LOG.warn(format!("tuic dial failed: {e} target={addr:?}"));
                    return Err(format!("tuic dial: {e}"));
                },
                Err(_) => {
                    DISPATCH_LOG.warn(format!("tuic dial timed out target={addr:?}"));
                    return Err("tuic dial: timed out".to_string());
                },
            };
            Ok(Box::new(TuicConnection::from_conn(conn)) as Box<dyn Connection>)
        })
    })
}

/// 心跳周期（官方 tuic client 默认 3s）。
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);

impl TuicConnection {
    /// 从 TuicConn 构造：拆 send/recv 后直接持有（不再桥接）。
    fn from_conn(conn: TuicConn) -> Self {
        Self { send: conn.send, recv: conn.recv }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use xray_common::net::{network::Network, port::Port};

    use super::*;

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
            },
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
            },
            _ => panic!("expected Ipv6"),
        }
    }

    #[test]
    fn dest_to_tuic_domain() {
        let d =
            Destination::new(XrayAddress::new_domain("example.com"), Port::new(443), Network::TCP);
        let a = dest_to_tuic_address(&d).unwrap();
        match a {
            Address::Domain(s, p) => {
                assert_eq!(s, "example.com");
                assert_eq!(p, 443);
            },
            _ => panic!("expected Domain"),
        }
    }
}
