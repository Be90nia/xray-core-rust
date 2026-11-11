//! xdrive transport dialer + listener 注册。对应 Go `xdrive.go::init()` 的
//! `internet.RegisterTransportDialer(protocolName, Dial)` /
//! `internet.RegisterTransportListener(protocolName, Serve)`。
//!
//! 进程启动时调用一次（`xray-core/src/register.rs::register_all_transports`）；
//! 幂等——重复注册的 `AlreadyExists` 被忽略（bd k2tq1：禁 `let _ =`）。

use std::{io, net::SocketAddr, sync::Arc};

use xray_transport::{
    dialer::{StreamSettings, TransportDialFn, register_transport_dialer},
    ignore_already_exists,
    listener_registry::{ConnHandler, TransportListenFn, register_transport_listener},
    sockopt::SocketOptions,
};

use crate::xdrive::{dial, serve};

/// 注册 xdrive transport dialer（协议名单名 `"xdrive"`；Go 无别名）。
///
/// # Errors
/// 首次注册失败（表满等）上抛；重复注册忽略 `AlreadyExists`。
pub fn register_dialer() -> io::Result<()> {
    let dialer: TransportDialFn = Arc::new(move |dest, sockopt: &SocketOptions, settings| {
        // TransportDialFn 返回 'static future，进入 async block 前先拿所有权。
        let dest = dest.clone();
        let sockopt = sockopt.clone();
        let settings = settings.clone();
        Box::pin(async move { dial(&dest, &sockopt, &settings).await })
    });
    ignore_already_exists(register_transport_dialer("xdrive", dialer))
}

/// 注册 xdrive transport listener。
///
/// # Errors
/// 首次注册失败上抛；重复注册忽略 `AlreadyExists`。
pub fn register_listener() -> io::Result<()> {
    let listen_fn: TransportListenFn = Arc::new(
        move |addr: SocketAddr, settings: StreamSettings, sockopt, handler: ConnHandler| {
            Box::pin(async move { serve(addr, settings, sockopt, handler).await })
        },
    );
    ignore_already_exists(register_transport_listener("xdrive", listen_fn))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 注册幂等（Go init 多次执行容错）；注册表可见（接线契约）。
    #[test]
    fn registration_is_idempotent_and_visible() {
        register_dialer().unwrap();
        register_dialer().unwrap();
        register_listener().unwrap();
        register_listener().unwrap();
        assert!(
            xray_transport::dialer::get_transport_dialer("xdrive").is_some(),
            "xdrive dialer must be registered"
        );
        assert!(
            xray_transport::listener_registry::get_transport_listener("xdrive").is_some(),
            "xdrive listener must be registered"
        );
    }
}
