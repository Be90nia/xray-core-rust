//! VLESS XTLS Vision 加密层。
//!
//! 对应 Go 版本 `proxy/vless/encryption/`。该层提供：
//!
//! - 客户端 [`ClientInstance`]：发起加密握手，0-RTT 数据，X25519/ML-KEM-768 + AES-CTR
//! - 服务端 [`ServerInstance`]：解密握手，replay 防护
//! - [`EncryptionConn`] trait：封装后的加密连接（实现 [`tokio::io::AsyncRead`] +
//!   [`tokio::io::AsyncWrite`]）
//!
//! # 当前状态（trait + stub）
//!
//! Go 端实现依赖以下 Rust 生态尚不完整的组件：
//!
//! 1. **`mlkem-768`**：后量子密钥封装（`crypto/mlkem`，Rust 标准/常用 crate 缺失）。
//! 2. **`unsafe.Pointer` 提取 TLS conn 私有字段**：Go 用反射拿 `tls.Conn.input/rawInput`
//!    做 splice copy，Rust 没有等价物（也不应做）。
//! 3. **TLS 1.3 record header 伪装**：需要可注入的 fake-write，依赖完整 transport 链路。
//!
//! 因此本模块仅声明 trait + 数据结构骨架，所有 IO 操作返回
//! [`VlessError::NotImplemented`]。等上层 transport 链路 + Rust 加密 crate 接入后
//! 再注入实现。

use crate::error::{Result, VlessError};

pub mod client;
pub mod common;
pub mod server;
pub mod xor;

/// XTLS Vision 加密会话包装的连接 trait。
///
/// 实现者承担：
/// - 异步读 / 写（自动加密/解密）
/// - 0-RTT 早期数据
/// - AEAD 自动轮换（Nonce 达到 `MaxNonce` 时重新派生）
///
/// 对应 Go 的 `encryption.CommonConn`。
pub trait EncryptionConn: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {
    /// 关闭连接，刷新内部缓冲。
    fn close(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>>;
}

/// 客户端加密实例（对应 Go 的 `ClientInstance`）。
///
/// 持有 X25519 静态公钥 + ML-KEM-768 封装密钥 + 0-RTT 票据缓存。
/// `init()` 完成密钥派生；`handshake()` 与服务端协商出会话密钥并返回
/// `Box<dyn EncryptionConn>`。
#[derive(Debug, Default)]
pub struct ClientInstance {
    /// 远端公钥（X25519，32 字节），未配置时为空。
    pub remote_pub: Vec<u8>,
    /// 自身静态公钥（X25519）。
    pub local_pub: Vec<u8>,
    /// 是否启用 XOR 模式（XorMode=2，Go 端旧版兼容）。
    pub xor_mode: bool,
}

impl ClientInstance {
    /// 创建空实例。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 初始化密钥（占位）。
    ///
    /// 实际实现需要 X25519 + ML-KEM-768；当前返回 `NotImplemented`。
    pub async fn init(&mut self) -> Result<()> {
        Err(VlessError::NotImplemented(
            "ClientInstance::init requires X25519+ML-KEM-768".into(),
        ))
    }

    /// 与服务端握手（占位）。
    pub async fn handshake<C>(
        &mut self,
        _conn: C,
    ) -> Result<Box<dyn EncryptionConn>>
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let _ = _conn;
        Err(VlessError::NotImplemented(
            "ClientInstance::handshake requires full encryption stack".into(),
        ))
    }
}

/// 服务端加密实例（对应 Go 的 `ServerInstance`）。
#[derive(Debug, Default)]
pub struct ServerInstance {
    /// X25519 私钥。
    pub private_key: Vec<u8>,
    /// ML-KEM-768 解封装密钥。
    pub decap_key: Vec<u8>,
}

impl ServerInstance {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn init(&mut self) -> Result<()> {
        Err(VlessError::NotImplemented(
            "ServerInstance::init requires X25519+ML-KEM-768".into(),
        ))
    }

    pub async fn handshake<C>(
        &mut self,
        _conn: C,
    ) -> Result<Box<dyn EncryptionConn>>
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let _ = _conn;
        Err(VlessError::NotImplemented(
            "ServerInstance::handshake requires full encryption stack".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn client_init_not_implemented() {
        let mut c = ClientInstance::new();
        let err = c.init().await.unwrap_err();
        assert!(matches!(err, VlessError::NotImplemented(_)));
    }

    #[tokio::test]
    async fn server_init_not_implemented() {
        let mut s = ServerInstance::new();
        let err = s.init().await.unwrap_err();
        assert!(matches!(err, VlessError::NotImplemented(_)));
    }

    #[test]
    fn client_default_xor_mode_off() {
        let c = ClientInstance::default();
        assert!(!c.xor_mode);
    }
}
