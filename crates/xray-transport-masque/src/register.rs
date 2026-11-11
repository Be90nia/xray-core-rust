//! MASQUE transport 注册管线（`xray_transport` dialer/listener 注册表）。
//!
//! B1 形态（规划 §5 B1.4）：本批只提供注册管线本身——dial/listen 的实际实现分别在
//! B2（`h2.rs`/`connect.rs`）与 B4（`hub.rs`）落地，届时由聚合口
//! `xray_core::register::register_all_transports()`（`crates/xray-core/src/register.rs:102`）
//! 以具体实现调用 [`register_dialer`]/[`register_listener`]。
//! **本批不接聚合口**（避免半成品进生产）；函数幂等（bd k2tq1 `ignore_already_exists`）。

use std::io;

use xray_transport::{
    dialer::{TransportDialFn, register_transport_dialer},
    ignore_already_exists,
    listener_registry::{TransportListenFn, register_transport_listener},
};

/// transport 协议注册名（Go `TransportProtocol` 名单同款全小写；
/// `xray_transport::dialer::protocol_settings_key` 的 `"masqueSettings"` 同源）。
pub const MASQUE_PROTOCOL: &str = "masque";

/// 注册 MASQUE transport dialer。幂等（重复注册忽略 `AlreadyExists`）。
///
/// `dial` 由调用方（聚合口，B4 起）提供；B2 落地 `crate::dialer::dial` 后由
/// 聚合口包装成 [`TransportDialFn`] 传入。
pub fn register_dialer(dial: TransportDialFn) -> io::Result<()> {
    ignore_already_exists(register_transport_dialer(MASQUE_PROTOCOL, dial))
}

/// 注册 MASQUE transport listener。幂等（重复注册忽略 `AlreadyExists`）。
///
/// `listen` 由调用方（聚合口，B4 起）提供；B4 落地 `crate::hub` 后由聚合口包装传入。
pub fn register_listener(listen: TransportListenFn) -> io::Result<()> {
    ignore_already_exists(register_transport_listener(MASQUE_PROTOCOL, listen))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use xray_common::net::destination::Destination;
    use xray_transport::{
        dialer::StreamSettings, listener_registry::ConnHandler, sockopt::SocketOptions,
    };

    use super::*;

    // 全局注册表测试专用哑元：本批无实现，拨号/监听一律返回 Unsupported。
    fn dummy_dial() -> TransportDialFn {
        Arc::new(|_dest: &Destination, _sockopt: &SocketOptions, _settings: &StreamSettings| {
            Box::pin(async { Err(io::Error::other("masque dial lands in B2")) })
        })
    }

    fn dummy_listen() -> TransportListenFn {
        Arc::new(
            |_addr: std::net::SocketAddr,
             _settings: StreamSettings,
             _sockopt: SocketOptions,
             _handler: ConnHandler| {
                Box::pin(async { Err(io::Error::other("masque listener lands in B4")) })
            },
        )
    }

    #[test]
    fn register_dialer_is_idempotent_and_lookupable() {
        register_dialer(dummy_dial()).expect("first register_dialer should succeed");
        register_dialer(dummy_dial())
            .expect("duplicate register_dialer should be idempotent (ignore_already_exists)");
        assert!(
            xray_transport::dialer::get_transport_dialer(MASQUE_PROTOCOL).is_some(),
            "masque dialer should be registered under {MASQUE_PROTOCOL}"
        );
    }

    #[test]
    fn register_listener_is_idempotent_and_lookupable() {
        register_listener(dummy_listen()).expect("first register_listener should succeed");
        register_listener(dummy_listen())
            .expect("duplicate register_listener should be idempotent");
        assert!(
            xray_transport::listener_registry::get_transport_listener(MASQUE_PROTOCOL).is_some(),
            "masque listener should be registered under {MASQUE_PROTOCOL}"
        );
    }
}
