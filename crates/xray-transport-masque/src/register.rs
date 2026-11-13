//! MASQUE transport 注册管线（`xray_transport` dialer/listener 注册表）。
//!
//! B4 形态（规划 §5 B4.5）：聚合口 `xray_core::register::register_all_transports()`
//! 调用 [`register_dialer`]/[`register_listener`]。函数幂等（bd k2tq1
//! `ignore_already_exists`）。
//!
//! - **dialer**：真实实现——拨 CONNECT-IP 隧道（`crate::dialer::dial`，含 finalmask/TLS/establish）→
//!   `PacketStreamConn` 字节流适配（Go `masque.Conn` 的 `Read/Write = ReadPacket/WritePacket`
//!   裸透传语义）。 消费方 = 通用 transport 管线（如 `vless over masque`）；**proxy 层
//!   `xray-proxy-masque` 不走本表**——它需要强类型 `ConnectIpSession`（Go 用 类型断言
//!   `.(*masque.Conn)` 的地方，Rust 等价形态 = 直接调 `crate::dialer::dial`，语义等价）。
//! - **listener**：hub 装配（`crate::hub::listen_masque`）+ 认证委托 + 协议桥 （bd anygg G2）。gate
//!   = 进程级共享 users 闸（`hub::shared_auth_gate`，由 proxy 层 `xray_proxy_masque::server::serve`
//!   注册）；本进程无 masque users 源 时按 Go `hub.go:53` ServeHTTP 语义放行（transport
//!   层无认证，协议层自认证 ——VLESS UUID 与 ws/grpc 同列）。acceptor =
//!   [`HandlerAcceptor`]：隧道升级 （CONNECT-IP 会话）→ ADDRESS_REQUEST 回应（本仓 dialer
//!   `establish` 协商 契约；缺省段地址 inert）→ [`PacketStreamConn`] 裸流适配 → `ConnHandler`
//!   （协议 listener，如 VLESS inbound worker）。生产装配入口 = arm_builders
//!   `inbound:masque`（gate/acceptor 由 proxy users 表一体提供，不经本注册表）。

use std::{io, sync::Arc};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use xray_common::net::destination::Destination;
use xray_frame::scope::ComponentScope;
use xray_transport::{
    connection::Connection,
    dialer::{StreamSettings, TransportDialFn, register_transport_dialer},
    ignore_already_exists,
    listener_registry::{ConnHandler, TransportListenFn, register_transport_listener},
    sockopt::SocketOptions,
};

use crate::{
    connect::ConnectIpSession,
    hub::{GateGrant, TunnelGate},
};

/// transport 协议注册名（Go `TransportProtocol` 名单同款全小写；
/// `xray_transport::dialer::protocol_settings_key` 的 `"masqueSettings"` 同源）。
pub const MASQUE_PROTOCOL: &str = "masque";

/// 注册 MASQUE transport dialer。幂等（重复注册忽略 `AlreadyExists`）。
pub fn register_dialer() -> io::Result<()> {
    let dialer: TransportDialFn = Arc::new(move |dest: &Destination, sockopt, settings| {
        let dest = dest.clone();
        let sockopt = sockopt.clone();
        let settings = settings.clone();
        Box::pin(async move {
            let config = crate::config::Config::from_json(settings.transport_json.as_ref())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            let session = crate::dialer::dial(&dest, &sockopt, &settings, &config)
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            // 透传模式（bd anygg G2）：注册表 dialer 服务通用 transport 管线，
            // 载荷 = 协议裸字节（如 VLESS 流）——入站免 IP 验证；proxy 形态走
            // `dialer::dial` 直取会话（验证语义不变）。
            let mut session = session;
            session.set_passthrough();
            PacketStreamConn::spawn(session)
        })
    });
    ignore_already_exists(register_transport_dialer(MASQUE_PROTOCOL, dialer))
}

/// 注册 MASQUE transport listener。幂等（重复注册忽略 `AlreadyExists`）。
///
/// 认证委托（bd anygg G2）：gate = 进程级共享 users 闸（`hub::register_shared_auth_gate`
/// 的注册面，proxy 层 `serve()` 装配时写入）；本进程无 masque users 源时按 Go
/// `hub.go:53` ServeHTTP 语义放行——transport 层无认证，协议层自认证（VLESS UUID
/// 与 ws/grpc 同列）。`handler` = 已注册的协议 listener（arm_builders
/// `spawn_transport_listener_inbound` 经 `listen_tcp` 查表传入）。
pub fn register_listener() -> io::Result<()> {
    let listen_fn: TransportListenFn = Arc::new(
        move |addr: std::net::SocketAddr,
              settings: StreamSettings,
              sockopt: SocketOptions,
              handler: ConnHandler| {
            Box::pin(async move {
                let gate: TunnelGate = crate::hub::shared_auth_gate().unwrap_or_else(|| {
                    // 无注册面 = 无凭据源：放行（Go transport 无认证语义；见函数文档）。
                    Arc::new(|_| Ok(GateGrant { email: String::new(), level: 0, extra: None }))
                });
                let acceptor: Arc<dyn crate::hub::TunnelAcceptor> = Arc::new(HandlerAcceptor {
                    handler: Arc::clone(&handler),
                    scope: ComponentScope::new("masque-transport-tunnels"),
                });
                crate::hub::listen_masque(addr, &settings, &sockopt, gate, acceptor).await
            })
        },
    );
    ignore_already_exists(register_transport_listener(MASQUE_PROTOCOL, listen_fn))
}

/// transport 形态的隧道接受器：把升级后的隧道（CONNECT-IP 会话）适配成裸字节流
/// 交给协议 listener（`ConnHandler`，如 VLESS inbound worker）。
///
/// 会话装配序（Go `ServerConn.Accept` → `masque.Conn` 透传语义）：accept 等
/// upgraded IO → [`ConnectIpSession::server_session`] 胶囊会话 → 地址协商回应泵
/// （见 [`next_transport_addr`]）+ [`PacketStreamConn`] 裸流适配（dialer 侧同一份
/// 实现，无第二副本）→ `handler`。
///
/// spawn 归属（§3.5.6 ①类）：自持 [`ComponentScope`]（寿命 = 本 acceptor——随
/// hub listener 持有；scope 不回指 acceptor，无自引用环），关闸后 spawn 失败 =
/// 隧道丢弃 + WARN（proxy `ServerAcceptor` 同语义）。
struct HandlerAcceptor {
    handler: ConnHandler,
    scope: ComponentScope,
}

impl crate::hub::TunnelAcceptor for HandlerAcceptor {
    fn add_tunnel(&self, conn: crate::hub::ServerConn) {
        let handler = Arc::clone(&self.handler);
        let scope = self.scope.clone();
        let spawned = scope.clone().spawn(async move {
            let stream = match conn.accept().await {
                Ok(s) => s,
                Err(e) => {
                    crate::LOG.warn(format!("masque: transport tunnel accept failed: {e}"));
                    return;
                },
            };
            let mut session = ConnectIpSession::server_session(stream);
            // 透传模式（bd anygg G2）：transport 形态载荷 = 协议裸字节（如 VLESS
            // 流）而非 IP 包——入站免 IP 验证（proxy 形态 server_session 不开启）。
            session.set_passthrough();
            // 地址协商回应泵：本仓 dialer `establish` 发 ADDRESS_REQUEST 并阻塞等
            // 分配（Go `dialer.go establish` 直译）；transport 形态无地址池 → 缺省
            // 段计数分配（地址 inert，见 [`next_transport_addr`] 文档）。writer/
            // request_rx 均为会话的克隆面，与数据泵（PacketStreamConn 的收发泵）
            // 并行不互斥；泵寿命 = 会话（request_rx 随会话读泵退出关闭）。
            let mut request_rx = match session.take_request_rx() {
                Some(rx) => rx,
                None => {
                    crate::LOG.warn("masque: transport tunnel missing request channel");
                    return;
                },
            };
            let mut writer = match session.writer() {
                Ok(w) => w,
                Err(e) => {
                    crate::LOG.warn(format!("masque: transport tunnel writer unavailable: {e}"));
                    return;
                },
            };
            let responder = scope.spawn(async move {
                while let Some(entries) = request_rx.recv().await {
                    let assigned: Vec<crate::capsule::AssignedAddress> = entries
                        .iter()
                        .map(|e| crate::capsule::AssignedAddress {
                            request_id: e.request_id,
                            prefix: crate::capsule::IpPrefix {
                                addr: next_transport_addr(e.prefix.addr.is_ipv4()),
                                prefix_len: if e.prefix.addr.is_ipv4() { 32 } else { 128 },
                            },
                        })
                        .collect();
                    if writer.respond_assignments(assigned).is_err() {
                        return;
                    }
                }
            });
            let _ = responder;
            let stream = match PacketStreamConn::spawn(session) {
                Ok(c) => c,
                Err(e) => {
                    crate::LOG.warn(format!("masque: tunnel stream adapt failed: {e}"));
                    return;
                },
            };
            handler(stream);
        });
        if spawned.is_err() {
            crate::LOG.warn("masque: scope closed at shutdown, tunnel dropped");
        }
    }
}

/// transport 形态缺省分配段计数器（隧道序号）。
static NEXT_TRANSPORT_ADDR: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// transport 形态缺省分配地址：v4 = 198.18.0.0/15（RFC 2544 benchmark 段）、
/// v6 = 2001:db8::/32（RFC 3849 documentation 段），按隧道序号取址，回绕无租约
/// 语义。字节透传形态地址 **inert**——不参与任何路由/地址归属决策（那是 proxy
/// 形态的 IP 栈职责），仅满足本仓 dialer `establish` 的「等首个含本端地址的
/// 分配」协商契约；Go transport 形态无可用对等物（其 connectip 亦不自动回应，
/// 消费方 `ReceiveAddressRequest`+`Respond` 为 proxy 层职责），无 Go 兼容约束。
fn next_transport_addr(is_v4: bool) -> std::net::IpAddr {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let n = NEXT_TRANSPORT_ADDR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let o = n % 131_072; // /15 容量 2×256×256；回绕仅意味着地址复用（inert）
    if is_v4 {
        IpAddr::V4(Ipv4Addr::new(
            198,
            18 + ((o >> 16) as u8),
            ((o >> 8) & 0xff) as u8,
            (o & 0xff) as u8,
        ))
    } else {
        IpAddr::V6(Ipv6Addr::new(
            0x2001,
            0xdb8,
            (o >> 16) as u16,
            (o & 0xffff) as u16,
            0,
            0,
            0,
            (n & 0xffff) as u16,
        ))
    }
}

/// `ConnectIpSession` ↔ 字节流适配（Go `masque.Conn` 裸透传语义）。
///
/// 双泵经一条全双工 duplex 桥：下行 `recv_packet → duplex 写`；上行
/// `duplex 读 → send_packet`。ICMP 回灌写回下行（Go `Conn.Write` 的
/// PacketTooBigError 对裸流不可表达——透传形态下回灌包原样进下行，与
/// Go `Read` 读到 ICMP 包一致）。
struct PacketStreamConn {
    duplex: tokio::io::DuplexStream,
    pump: tokio::task::JoinHandle<()>,
}

impl PacketStreamConn {
    /// 建适配并 spawn 双泵。必须 tokio runtime 内调用。
    fn spawn(mut session: crate::connect::ConnectIpSession) -> io::Result<Box<dyn Connection>> {
        let (client_side, mut relay_side) = tokio::io::duplex(64 * 1024);
        // ②豁免（§3.5.6 ②-数据面逐包泵）：裸流适配双泵（duplex ↔ 会话收发），
        // 坑约束⑫；寿命 = 本 Connection 句柄——duplex 端随句柄关闭，泵读到 0 即自终。
        #[allow(
            clippy::disallowed_methods,
            reason = "②豁免（§3.5.6 ②-数据面逐包泵）：PacketStreamConn 裸流双泵，坑约束⑫；寿命 = Connection 句柄（duplex 关闭 ⇒ 泵读 0 自终，不停机编排面）"
        )]
        let pump = tokio::spawn(async move {
            let mut buf = vec![0u8; crate::connect::MIN_PACKET_SIZE.max(2048)];
            loop {
                tokio::select! {
                    biased;
                    pkt = session.recv_packet() => match pkt {
                        Ok(p) => {
                            if relay_side.write_all(&p).await.is_err() {
                                return;
                            }
                        },
                        Err(_) => return,
                    },
                    read = relay_side.read(&mut buf) => match read {
                        Ok(0) | Err(_) => {
                            session.close();
                            return;
                        },
                        Ok(n) => {
                            if let Ok(Some(icmp)) = session.send_packet(&buf[..n]).await {
                                let _ = relay_side.write_all(&icmp).await;
                            }
                        },
                    },
                }
            }
        });
        Ok(Box::new(Self { duplex: client_side, pump }))
    }
}

impl tokio::io::AsyncRead for PacketStreamConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let duplex = std::pin::Pin::new(&mut self.duplex);
        duplex.poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for PacketStreamConn {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let duplex = std::pin::Pin::new(&mut self.duplex);
        duplex.poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let duplex = std::pin::Pin::new(&mut self.duplex);
        duplex.poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let duplex = std::pin::Pin::new(&mut self.duplex);
        duplex.poll_shutdown(cx)
    }
}

impl Connection for PacketStreamConn {
    fn remote_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        Ok(None)
    }

    fn local_addr(&self) -> io::Result<Option<std::net::SocketAddr>> {
        Ok(None)
    }
}

impl Drop for PacketStreamConn {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_dialer_is_idempotent_and_lookupable() {
        register_dialer().expect("first register_dialer should succeed");
        register_dialer().expect("duplicate register_dialer should be idempotent");
        assert!(
            xray_transport::dialer::get_transport_dialer(MASQUE_PROTOCOL).is_some(),
            "masque dialer should be registered under {MASQUE_PROTOCOL}"
        );
    }

    #[test]
    fn register_listener_is_idempotent_and_lookupable() {
        register_listener().expect("first register_listener should succeed");
        register_listener().expect("duplicate register_listener should be idempotent");
        assert!(
            xray_transport::listener_registry::get_transport_listener(MASQUE_PROTOCOL).is_some(),
            "masque listener should be registered under {MASQUE_PROTOCOL}"
        );
    }
}
