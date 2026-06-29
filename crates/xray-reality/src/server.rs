//! REALITY 服务端。
//!
//! 翻译自 Go `transport/internet/reality/reality.go` 的 `Server`/`Conn` 部分。
//!
//! # 现状（重要）
//! **实际握手未实现**。`Server` 函数依赖 `github.com/xtls/reality` 库
//! （服务端 REALITY 状态机），Rust 端无等价品。本模块只翻译**配置数据结构
//! 与签名**。
//!
//! 切片2 留待：
//! - 接入 xtls/reality Rust 等价品（服务端状态机）
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
