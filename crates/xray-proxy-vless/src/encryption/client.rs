//! 加密客户端握手（占位）。
//!
//! 对应 Go 版本 `encryption/client.go`。完整实现依赖 `mlkem-768` + X25519 ECDH +
//! 0-RTT 票据缓存，这些组件 Rust 生态尚不完整，本文件仅提供 trait + 数据结构骨架。
//!
//! 详见 [`crate::encryption::ClientInstance`]。

// 当前所有逻辑封装在 super::ClientInstance 中，本文件保留模块声明以便未来扩展。

#[cfg(test)]
mod tests {
    use crate::encryption::ClientInstance;

    #[test]
    fn client_instance_can_construct() {
        let c = ClientInstance::new();
        assert!(c.remote_pub.is_empty());
        assert!(c.local_pub.is_empty());
        assert!(!c.xor_mode);
    }
}
