//! Hysteria transport dialer + listener 注册（骨架）。
//!
//! dialer: [`crate::dialer::HysteriaDialerFactory`] 是 trait stub，等待 quinn/h3 adapter。
//! listener: [`crate::hub::HysteriaListenerFactory`] 是 trait stub，等待 quinn/h3 adapter。
//! 两者均返回 `Unsupported`，让 `streamSettings.network = "hysteria"` 命中本 crate。
//!
//! 待切片2 补全 factory 注入后，替换占位为真实拨号/监听。

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use xray_transport::dialer::{TransportDialFn, register_transport_dialer};
use xray_transport::listener_registry::{
    TransportListenFn, TransportListener,
    register_transport_listener,
};

use crate::PROTOCOL_NAME;

/// 注册 Hysteria transport dialer 占位。
///
/// 幂等：重复注册的 `AlreadyExists` 被忽略。
pub fn register_dialer() -> io::Result<()> {
    let stub: TransportDialFn = Arc::new(|_dest, _sockopt, _settings| {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "hysteria transport dialer not yet implemented (waiting HysteriaDialerFactory + quinn adapter, slice 2)",
            ))
        })
    });
    let _ = register_transport_dialer(PROTOCOL_NAME, stub);
    Ok(())
}

/// 注册 Hysteria transport listener 占位。
///
/// 幂等：重复注册的 `AlreadyExists` 被忽略。
pub fn register_listener() -> io::Result<()> {
    let stub: TransportListenFn = Arc::new(|_addr, _settings, _sockopt, _handler| {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "hysteria transport listening not yet implemented (waiting HysteriaListenerFactory + quinn adapter, slice 2)",
            ))
        })
    });
    let _ = register_transport_listener(PROTOCOL_NAME, stub);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_dialer_is_idempotent() {
        register_dialer().expect("first register ok");
        register_dialer().expect("second register ok (idempotent)");
    }
}
