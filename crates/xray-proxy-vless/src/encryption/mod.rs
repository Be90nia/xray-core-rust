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

pub mod aead;

pub mod common_conn;

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

/// 客户端加密实例（对应 Go `ClientInstance`）。
///
/// 持有 X25519 静态公钥 + ML-KEM-768 封装密钥数组。
/// [`ClientInstance::init`] 解析公钥并算 blake3 hash + relay 长度；
/// [`ClientInstance::handshake`] 与服务端协商会话密钥（阶段 A stub）。
#[derive(Debug, Default)]
pub struct ClientInstance {
    /// 远端公钥数组（每个元素：32B=X25519 pub，1184B=ML-KEM-768 encap key）。
    pub nfs_pkeys: Vec<Vec<u8>>,
    /// 扁平化公钥字节（CTR XOR 用，对应 Go `NfsPKeysBytes`）。
    pub nfs_pkeys_flat: Vec<u8>,
    /// 每个公钥的 blake3 hash（对应 Go `Hash32s`）。
    pub hash32s: Vec<[u8; 32]>,
    /// relay chain 总长度（对应 Go `RelaysLength`）。
    pub relays_length: usize,
    /// XOR 模式（0=off, 1=XOR relays, 2=XorConn）。
    pub xor_mode: u32,
    /// 0-RTT ticket 有效秒数。
    pub seconds: u32,
    /// padding 配置（阶段 A 简化，默认空）。
    pub padding_lens: Vec<common::PaddingTriple>,
    pub padding_gaps: Vec<common::PaddingTriple>,
}

impl ClientInstance {
    /// 创建空实例。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 初始化：解析公钥数组，算 blake3 hash，计算 relay 长度。
    ///
    /// 对应 Go `ClientInstance.Init(nfsPKeysBytes, xorMode, seconds, padding)`：
    /// 每个公钥按长度分类——32B→X25519 pub（relay += 32+32），
    /// 其他→ML-KEM-768 encap key（relay += 1088+32）。末尾 `RelaysLength -= 32`。
    ///
    /// # Errors
    /// padding 配置解析失败（阶段 A 不会，`parse_padding` 始终返回空）返回 [`VlessError`]。
    pub fn init(
        &mut self,
        nfs_pkeys: Vec<Vec<u8>>,
        xor_mode: u32,
        seconds: u32,
        padding: &str,
    ) -> Result<()> {
        self.xor_mode = xor_mode;
        self.seconds = seconds;
        let (padding_lens, padding_gaps) = common::parse_padding(padding)?;
        self.padding_lens = padding_lens;
        self.padding_gaps = padding_gaps;

        self.nfs_pkeys_flat.clear();
        self.hash32s.clear();
        let mut relays: i64 = 0;
        for pk in &nfs_pkeys {
            let hash = blake3::hash(pk);
            self.hash32s.push(*hash.as_bytes());
            self.nfs_pkeys_flat.extend_from_slice(pk);
            if pk.len() == 32 {
                relays += 32 + 32; // X25519 pub(32) + hash32 slot
            } else {
                relays += 1088 + 32; // ML-KEM-768 ct(1088) + hash32 slot
            }
        }
        relays -= 32; // Go: 末尾减（最后一段无下段 hash）
        self.relays_length = relays.max(0) as usize;
        self.nfs_pkeys = nfs_pkeys;
        Ok(())
    }

    /// 与服务端握手（阶段 A stub：relay chain 加密 + pfsKeyExchange 待实现）。
    ///
    /// # Errors
    /// 当前返回 [`VlessError::NotImplemented`]。
    pub async fn handshake<C>(
        &mut self,
        _conn: C,
    ) -> Result<Box<dyn EncryptionConn>>
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let _ = _conn;
        Err(VlessError::NotImplemented(
            "ClientInstance::handshake: relay chain + pfsKeyExchange 待实现".into(),
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

    #[test]
    fn client_init_parses_keys_and_relay_length() {
        let mut c = ClientInstance::new();
        // 一个 X25519 pub (32B) + 一个 ML-KEM-768 encap key (1184B)
        let pkeys = vec![vec![0xABu8; 32], vec![0xCDu8; 1184]];
        c.init(pkeys, 1, 300, "").unwrap();
        assert_eq!(c.hash32s.len(), 2);
        // (32+32) + (1088+32) - 32 = 1152
        assert_eq!(c.relays_length, 1152);
        assert_eq!(c.xor_mode, 1);
        assert_eq!(c.seconds, 300);
        assert_eq!(c.nfs_pkeys_flat.len(), 32 + 1184);
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
        assert_eq!(c.xor_mode, 0);
    }
}
