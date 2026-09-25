//! TUN 出站 → DialBridge 适配器。
//!
//! TUN outbound 语义：通过系统拨号器直连目标（与 freedom 相同）。
//! TUN 设备的路由由 OS 级别处理（iptables/nftables 将流量导向 TUN 接口），
//! outbound 层只需 dial 目标地址即可。
//!
//! Go 中 TUN 也是 inbound-only（`proxy/tun/tun.go` 仅定义 Tun 接口），
//! Rust 为对称性提供 outbound dial_fn。
//!
//! [`DialBridge`]: xray_app_dispatcher::default::DialBridge
//! [`DialFn`]: xray_app_dispatcher::default::DialFn

use std::sync::Arc;

use xray_app_dispatcher::default::DialFn;
use xray_common::net::destination::Destination;
use xray_transport::{connection::Connection, sockopt::SocketOptions, system_dialer::dial_system};

/// 构造 TUN 的 DialFn 闭包。
///
/// 闭包无状态——每次调用直接 `dial_system(dest)`。
/// TUN 设备路由由 OS 级别处理，outbound 层不感知 TUN 设备。
///
/// # Panics
///
/// 不会 panic；错误以 `Err(String)` 返回。
pub fn make_tun_dial_fn() -> DialFn {
    Arc::new(|dest: &Destination| {
        let dest = dest.clone();
        Box::pin(async move {
            let sockopt = SocketOptions::default();
            let conn: Box<dyn Connection> =
                dial_system(&dest, &sockopt).await.map_err(|e| format!("tun dial: {e}"))?;
            Ok(conn)
        })
    })
}
