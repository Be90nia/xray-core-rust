//! Hysteria transport dialer 注册（骨架）。
//!
//! 当前 [`crate::dialer::HysteriaDialerFactory`] 是 trait stub，等待 quinn/h3
//! adapter 注入。此 [`register_dialer`] 注册一个返回 `Unsupported` 错误的占位
//! dialer，让 `streamSettings.network = "hysteria"` 能命中本 crate 的代码路径。
//!
//! 待切片2 补全 `HysteriaDialerFactory` 注入后，替换占位为真实拨号。

use std::io;
use std::sync::Arc;

use xray_transport::dialer::{TransportDialFn, register_transport_dialer};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_dialer_is_idempotent() {
        register_dialer().expect("first register ok");
        register_dialer().expect("second register ok (idempotent)");
    }
}
