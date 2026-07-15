//! SplitHTTP transport dialer 注册（骨架）。
//!
//! 当前 [`crate::dialer::PacketUpConn`] (`SplitConn<Box<dyn AsyncRead + Send +
//! Unpin>, DuplexStream>`) 不满足 `Sync` bound——`Box<dyn AsyncRead + Send +
//! Unpin>` 不是 `Sync`，无法 impl [`Connection`]（要求 `Send + Sync + Unpin`）。
//!
//! 此 [`register_dialer`] 注册返回 `Unsupported` 的占位 dialer，让
//! `streamSettings.network = "splithttp"` 能命中本 crate 的代码路径，
//! 而不是 fallback 到裸 TCP。待切片 co1（splithttp client 补全）将
//! `PacketUpConn` 的 reader 改为 `Sync` 类型后，替换占位为真实拨号。
//!
//! 协议名同时注册 `"splithttp"`（Go 标准）和 `"xhttp"`（用户配置简写）。

use std::io;
use std::sync::Arc;

use xray_transport::dialer::{TransportDialFn, register_transport_dialer};

/// 注册 SplitHTTP transport dialer 占位。幂等。
pub fn register_dialer() -> io::Result<()> {
    let stub: TransportDialFn = Arc::new(|_dest, _sockopt, _settings| {
        Box::pin(async {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "splithttp transport dialer not yet wired (waiting PacketUpConn Sync bound fix in slice co1)",
            ))
        })
    });
    let _ = register_transport_dialer("splithttp", stub.clone());
    let _ = register_transport_dialer("xhttp", stub);
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
