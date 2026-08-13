//! Freedom outbound → DialBridge 适配器（阶段 1 切片 1e）。
//!
//! Freedom 是直连代理——直接拨号到目标，无中间服务器。所以 DialFn 闭包不需要
//! 捕获任何 client 配置，直接调 [`dial_system`] 返回 [`Connection`]。
//!
//! `dial_system` 已返回 `Box<dyn Connection>`，无需 wrapper。
//!
//! [`DialBridge`]: xray_app_dispatcher::default::DialBridge
//! [`DialFn`]: xray_app_dispatcher::default::DialFn
//! [`Connection`]: xray_transport::connection::Connection

use xray_app_dispatcher::default::DialFn;
use xray_common::net::destination::Destination;
use xray_transport::connection::Connection;
use xray_transport::sockopt::SocketOptions;
use xray_transport::system_dialer::dial_system;

use crate::config::Config;

/// 构造 Freedom 的 DialFn 闭包（默认配置）。
///
/// 等价 [`make_dial_fn_with_config`] 传入 `Config::default()`。保留无参签名以兼容既有调用方。
#[must_use]
pub fn make_dial_fn() -> DialFn {
    make_dial_fn_with_config(Config::default())
}

/// 构造 Freedom 的 DialFn 闭包（携带解析后的 [`Config`]）。
///
/// 当前 dial 路径仅消费 SocketOptions 默认值；domainStrategy/fragment/noises
/// 已解析并存入 Config，待 DNS 解析 + fragment/noise 拨号路径接入后使用。
/// ponytail: domain_strategy/fragment/noises 当前解析即存储，dial 未消费。
///
/// # Panics
///
/// 不会 panic；错误以 `Err(String)` 返回。
pub fn make_dial_fn_with_config(_config: Config) -> DialFn {
    Arc::new(move |dest: &Destination| {
        let dest = dest.clone();
        Box::pin(async move {
            let sockopt = SocketOptions::default();
            let conn: Box<dyn Connection> = dial_system(&dest, &sockopt)
                .await
                .map_err(|e| format!("freedom dial: {e}"))?;
            Ok(conn)
        })
    })
}

use std::sync::Arc;

use xray_app_dispatcher::DispatchHandler;
use xray_app_dispatcher::default::{DialBridge, PinFuture};

use xray_common::net::network::Network;
use xray_transport::link::Link;

/// Freedom dispatch handler——在 TCP DialBridge 之上增加 UDP relay。
///
/// 对应 Go `proxy/freedom/freedom.go::Handler`：TCP 走 `dial_system` 流桥接
/// （委托内部 [`DialBridge`]），UDP 走 [`crate::udp::relay`]（XUDP 帧 ↔ 原始数据报）。
///
/// **代理链**：仅 TCP 支持代理链（通过内部 DialBridge）；UDP 直连目标，
/// 不支持代理链（与 Go freedom 一致——freedom 是直连出口）。
pub struct FreedomDispatchBridge {
    tag: String,
    tcp: Arc<DialBridge>,
}

impl FreedomDispatchBridge {
    /// 从已构造的 TCP [`DialBridge`] 包装。保留 `dial_bridge` 的 Arc 以便代理链 Phase 2 注入。
    #[must_use]
    pub fn from_bridge(dial_bridge: Arc<DialBridge>) -> Self {
        let tag = dial_bridge.tag().to_string();
        Self { tag, tcp: dial_bridge }
    }
}

impl std::fmt::Debug for FreedomDispatchBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FreedomDispatchBridge")
            .field("tag", &self.tag)
            .finish_non_exhaustive()
    }
}

impl DispatchHandler for FreedomDispatchBridge {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn dispatch(&self, dest: &Destination, link: Link) -> PinFuture<()> {
        if dest.network() == Network::UDP {
            let tag = self.tag.clone();
            let dest = dest.clone();
            Box::pin(async move {
                if let Err(e) = crate::udp::relay(&dest, link).await {
                    tracing::warn!(tag = %tag, "freedom udp relay ended: {e}");
                }
            })
        } else {
            // TCP：委托内部 DialBridge（保留代理链 / fragment / noise 等既有行为）
            self.tcp.dispatch(dest, link)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use xray_app_dispatcher::default::{DefaultDispatcher, DialBridge, SimpleOhm, SniffingRequest};
    use xray_buf::io::{Reader, Writer};
    use xray_buf::multi::MultiBuffer;
    use xray_common::net::address::Address;
    use xray_common::net::network::Network;
    use xray_common::net::port::Port;

    #[tokio::test]
    async fn dispatcher_e2e_freedom_to_echo() {
        // echo server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        // dispatcher + DialBridge(freedom)
        let ohm = SimpleOhm::new();
        ohm.set_default(Arc::new(DialBridge::new("freedom-out", make_dial_fn())));
        let mut dispatcher = DefaultDispatcher::new();
        dispatcher.ohm = Some(Arc::new(ohm));

        let dest = Destination::new(
            Address::from_ipv4_bytes([127, 0, 0, 1]),
            Port::new(echo_addr.port()),
            Network::TCP,
        );
        let inbound = dispatcher
            .dispatch(&dest, &SniffingRequest::default(), None, None)
            .expect("dispatch returns inbound Link");

        let mut w = inbound.writer;
        let mut r = inbound.reader;

        let payload = b"hello freedom via dispatcher";
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(payload);
        w.write_multi_buffer(mb).await.unwrap();

        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            r.read_multi_buffer(),
        )
        .await
        .expect("timeout")
        .unwrap();

        assert_eq!(resp.to_vec(), payload);
        w.shutdown();
    }
}
