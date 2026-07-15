//! mKCP transport dialer 注册（骨架）。
//!
//! 当前 [`crate::dialer::KcpDialerFactory`] 是 trait stub，等待外部 IO 注入
//! （UDP/TLS）。此 [`register_dialer`] 注册一个返回 `Unsupported` 错误的占位
//! dialer，让 `streamSettings.network = "mkcp"` 能命中本 crate 的代码路径，
//! 而不是 fallback 到裸 TCP（功能坏）。
//!
//! 待切片2 补全 `KcpDialerFactory` 注入后，替换占位为真实拨号。

use std::io;
use std::sync::Arc;

use xray_transport::dialer::{TransportDialFn, register_transport_dialer};

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
