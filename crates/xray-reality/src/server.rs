//! REALITY 服务端。
//!
//! 翻译自 Go `transport/internet/reality/reality.go` 的 `Server`/`Conn` 部分。
//!
//! # 现状（重要）
//! **实际握手 BLOCKED on watfaq-rustls**。服务端 REALITY 状态机（解析 ClientHello
//! session_id、校验 short_id/timestamp、fallback 处理）依赖 `xtls/reality` Rust
//! 等价品。n9e ADR 4.3 🔒 LOCKED 选定 watfaq-rustls 为首选实现。
//!
//! **纯密码学算法已提取到 [`crate::crypto`] 模块**，独立可测。
//!
//! 切片2 留待（依赖 watfaq-rustls 决策）：
//! - 接入 watfaq-rustls 服务端 REALITY 状态机
//! - 解析 ClientHello.SessionId[:16] 还原 [version, timestamp, short_id]
//! - 校验 short_id ∈ short_ids map
//! - 校验 `|now - sessionId.timestamp| ≤ max_time_diff`
//! - fallback 处理（HTTP/2 PROXY protocol、xver 0/1/2、dest 字符串/整数）
//! - limit_fallback 限速（依赖 [`crate::config::LimitFallback`]）

use crate::config::RealityConfig;
use crate::error::RealityError;

/// 创建 REALITY 服务端连接。
///
/// 对应 Go `Server(c net.Conn, config *reality.Config) (net.Conn, error)`。
///
/// **未实现**——等接入 xtls/reality 等价品后实现。当前返回 [`RealityError::UtlsRequired`]。
pub fn server<C>(_inner: C, _config: RealityConfig) -> Result<(), RealityError> {
    Err(RealityError::UtlsRequired)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_stub_returns_utls_required() {
        let cfg = RealityConfig::default();
        let err = server::<()>((), cfg).unwrap_err();
        assert!(matches!(err, RealityError::UtlsRequired));
    }
}
