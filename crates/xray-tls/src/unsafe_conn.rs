//! TLS 连接延迟关闭包装。
//!
//! 翻译自 Go `transport/internet/tls/tls.go` 中的 `tlsCloseTimeout` 常量与
//! `Conn.Close()`/`UConn.Close()` 方法。
//!
//! # 原因
//! Go 的 `tls.Conn.Close()` 在调用者未完整读 peer 的 close_notify alert 时会
//! 阻塞 ~250ms。Xray 的业务逻辑在卸载该包装时，为了快速释放资源，会先在
//! 250ms 后强制关闭底层 net.Conn。
//!
//! # 现状
//! Rust 端等接入 rustls 后实现。rustls 的 close_notify 处理与 Go 不同，可能
//! 不需此包装，但保留为占位以便 1:1 翻译。

use std::time::Duration;

/// Go 端常量 `tlsCloseTimeout = 250 * time.Millisecond`。
///
/// 包装类型在调用底层 `close()` 后等该时长再强制关闭原始连接。
pub const TLS_CLOSE_TIMEOUT: Duration = Duration::from_millis(250);

// ============================================================
// 测试
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_matches_go() {
        assert_eq!(TLS_CLOSE_TIMEOUT, Duration::from_millis(250));
    }
}
