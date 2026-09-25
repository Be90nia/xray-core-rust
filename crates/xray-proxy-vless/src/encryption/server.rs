//! 加密服务端握手（占位）。
//!
//! 对应 Go 版本 `encryption/server.go`。完整实现依赖 `mlkem-768` decap + X25519 +
//! replay 防护 + 票据管理（每分钟清理过期），这些组件 Rust 生态尚不完整，
//! 本文件仅提供 trait + 数据结构骨架。
//!
//! 详见 [`crate::encryption::ServerInstance`]。

#[cfg(test)]
mod tests {
    use crate::{encryption::ServerInstance, error::VlessError};

    #[test]
    fn server_init_empty_keys_rejected() {
        let mut s = ServerInstance::new();
        let err = s.init(Vec::new(), 0, 0, 0, "").unwrap_err();
        assert!(matches!(err, VlessError::Other(ref msg) if msg.contains("empty")));
    }

    #[test]
    fn server_init_duplicate_rejected() {
        let mut s = ServerInstance::new();
        s.init(vec![vec![0xABu8; 32]], 0, 0, 0, "").unwrap();
        let err = s.init(vec![vec![0xCDu8; 32]], 0, 0, 0, "").unwrap_err();
        assert!(matches!(err, VlessError::Other(ref msg) if msg.contains("already initialized")));
    }
}
