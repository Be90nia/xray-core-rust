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
//! - **listener**：hub 装配（`crate::hub::listen_masque`）+ 内置缺省 gate。 gate 缺省 = 恒
//!   [`GateDeny::Auth`] 拒——transport 注册表形态拿不到 proxy 层 users 表（Go 的 handler 参数天然是
//!   proxy worker，Rust `ConnHandler` 无扩展槽），无凭据面的裸监听 fail-closed（401
//!   逐请求拒绝）优于假开放。 生产装配入口 = arm_builders `inbound:masque`（gate 由 users
//!   表提供）。

use std::{io, sync::Arc};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use xray_common::net::destination::Destination;
use xray_transport::{
    connection::Connection,
    dialer::{StreamSettings, TransportDialFn, register_transport_dialer},
    ignore_already_exists,
    listener_registry::{ConnHandler, TransportListenFn, register_transport_listener},
    sockopt::SocketOptions,
};

use crate::hub::{GateDeny, TunnelGate};

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
            PacketStreamConn::spawn(session)
        })
    });
    ignore_already_exists(register_transport_dialer(MASQUE_PROTOCOL, dialer))
}

/// 注册 MASQUE transport listener。幂等（重复注册忽略 `AlreadyExists`）。
///
/// 缺省 gate 恒拒（模块注释 §listener）；`handler` 参数在缺省 gate 下不消费，
/// 形态保留 = 注册表签名契约（通用管线存在性探测 + fail-closed）。
pub fn register_listener() -> io::Result<()> {
    let listen_fn: TransportListenFn = Arc::new(
        move |addr: std::net::SocketAddr,
              settings: StreamSettings,
              sockopt: SocketOptions,
              _handler: ConnHandler| {
            Box::pin(async move {
                // 缺省 gate：无 users 面（transport 注册表形态拿不到 proxy 层
                // 凭据）→ 恒 401（fail-closed，见模块注释）。
                let gate: TunnelGate = Arc::new(|_| Err(GateDeny::Auth));
                let acceptor: Arc<dyn crate::hub::TunnelAcceptor> = Arc::new(NoopAcceptor);
                crate::hub::listen_masque(addr, &settings, &sockopt, gate, acceptor).await
            })
        },
    );
    ignore_already_exists(register_transport_listener(MASQUE_PROTOCOL, listen_fn))
}

/// 缺省 gate 的隧道接受器：gate 恒拒，`add_tunnel` 永不触达（fail-closed 留档）。
struct NoopAcceptor;

impl crate::hub::TunnelAcceptor for NoopAcceptor {
    fn add_tunnel(&self, _conn: crate::hub::ServerConn) {}
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
