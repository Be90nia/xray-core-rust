//! 加密服务端握手（占位）。
//!
//! 对应 Go 版本 `encryption/server.go`。完整实现依赖 `mlkem-768` decap + X25519 +
//! replay 防护 + 票据管理（每分钟清理过期），这些组件 Rust 生态尚不完整，
//! 本文件仅提供 trait + 数据结构骨架。
//!
//! 详见 [`crate::encryption::ServerInstance`]。

#[cfg(test)]
mod tests {
    use crate::encryption::ServerInstance;

    #[test]
    fn server_instance_can_construct() {
        let s = ServerInstance::new();
        assert!(s.private_key.is_empty());
        assert!(s.decap_key.is_empty());
    }
}
