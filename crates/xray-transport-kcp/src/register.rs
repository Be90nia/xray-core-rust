//! mKCP transport dialer + listener 注册（骨架）。
//!
//! dialer: [`crate::dialer::KcpDialerFactory`] 是 trait stub，等待外部 IO 注入。
//! listener: [`crate::listener::KcpListenerFactory`] 是 trait stub，等待外部 IO 注入。
//! 两者均返回 `Unsupported`，让 `streamSettings.network = "mkcp"` 命中本 crate。
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

/// 注册 mKCP transport dialer 占位。
///
/// 幂等：重复注册的 `AlreadyExists` 被忽略。
/// 协议名同时注册 `"mkcp"`（Go 标准）和 `"kcp"`（部分客户端配置简写）。
pub fn register_dialer() -> io::Result<()> {
    let stub: TransportDialFn = Arc::new(|_dest, _sockopt, _settings| {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "kcp transport dialer not yet implemented (waiting KcpDialerFactory injection, slice 2)",
            ))
        })
    });
    // ponytail: 重复注册忽略——主代理与测试可能并发触发注册
    let _ = register_transport_dialer(PROTOCOL_NAME, stub.clone());
    let _ = register_transport_dialer("kcp", stub);
    Ok(())
}

/// 注册 mKCP transport listener 占位。
///
/// 幂等：重复注册的 `AlreadyExists` 被忽略。
/// 协议名同时注册 `"mkcp"`（Go 标准）和 `"kcp"`（部分客户端配置简写）。
pub fn register_listener() -> io::Result<()> {
    let stub: TransportListenFn = Arc::new(|_addr, _settings, _sockopt, _handler| {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "kcp transport listening not yet implemented (waiting KcpListenerFactory injection, slice 2)",
            ))
        })
    });
    let _ = register_transport_listener(PROTOCOL_NAME, stub.clone());
    let _ = register_transport_listener("kcp", stub);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_dialer_is_idempotent() {
        // 第一次成功，第二次 AlreadyExists 被忽略（返回 Ok）
        register_dialer().expect("first register ok");
        register_dialer().expect("second register ok (idempotent)");
    }
}
