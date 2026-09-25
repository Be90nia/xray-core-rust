//! QUIC transport dialer + listener 注册。
//!
//! 对应 Go `transport/internet/quic/dialer.go::init()` 中的
//! `internet.RegisterTransportDialer(protocolName, Dial(...))` 和
//! `transport/internet/quic/hub.go::init()` 中的
//! `internet.RegisterTransportListener(protocolName, Listen(...))`。
//!
//! 协议名 `"quic"`（对应 `xray_transport::dialer::protocol_settings_key("quic")` →
//! `"quicSettings"`）。

use std::{io, sync::Arc};

use xray_transport::{
    dialer::{TransportDialFn, register_transport_dialer},
    listener_registry::{TransportListenFn, register_transport_listener},
};

/// 注册 QUIC transport dialer。
///
/// 幂等：重复调用忽略 `AlreadyExists`（对齐 Go `init()` 在测试中多次执行的容错）。
pub fn register_dialer() -> io::Result<()> {
    let dialer: TransportDialFn = Arc::new(move |dest, sockopt, settings| {
        let dest = dest.clone();
        let sockopt = sockopt.clone();
        let settings = settings.clone();
        Box::pin(async move { crate::transport::dial(&dest, &settings, &sockopt).await })
    });
    let _ = register_transport_dialer("quic", dialer);
    Ok(())
}

/// 注册 QUIC transport listener。
///
/// 幂等：重复调用忽略 `AlreadyExists`。
pub fn register_listener() -> io::Result<()> {
    let listen_fn: TransportListenFn = Arc::new(move |addr, settings, sockopt, handler| {
        let settings = settings.clone();
        let sockopt = sockopt.clone();
        let handler = handler.clone();
        Box::pin(async move { crate::transport::listen(addr, &settings, &sockopt, handler).await })
    });
    let _ = register_transport_listener("quic", listen_fn);
    Ok(())
}

#[cfg(test)]
mod tests {
    use xray_transport::dialer::get_transport_dialer;

    use super::*;

    #[test]
    fn register_dialer_registers_quic() {
        register_dialer().unwrap();
        assert!(get_transport_dialer("quic").is_some());
    }
}
