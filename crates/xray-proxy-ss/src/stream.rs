//! SS 流式 AEAD body，对应 Go `common/crypto/auth.go` 的 AuthenticationWriter/Reader。
//!
//! # Wire format
//!
//! 每个 chunk = `[sealed_size(2+tag)][sealed_payload(len+tag)]`
//! - size chunk 明文 = `BE u16 (payload.len + tag_size)`
//! - nonce 序列：`[0xFF;n]` → increment → `[0;n]`（首帧 size）→ `[1,0,...]`（首帧 payload）
//!   → `[2,0,...]`（body size）→ `[3,0,...]`（body payload）...
//!
//! # 设计
//!
//! 不实现 `AsyncRead`/`AsyncWrite` trait（Pin 复杂，SS chunk 天然是分帧语义）。
//! 提供 `write_chunk`/`read_chunk`/`flush`/`shutdown` 四个 async 方法，桥接时用循环。

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::MemoryAccount;
use crate::error::{Result, SsError};

/// SS 流式 AEAD 读写器。
///
/// 持有底层连接（`AsyncRead + AsyncWrite`）+ AEAD cipher + nonce 状态。
/// 每次 `write_chunk`/`read_chunk` 消耗 2 个 nonce（size + payload）。
pub struct SSStream<C> {
    inner: C,
    aead: Box<dyn xray_crypto::aead::AeadCipher + Send + Sync>,
    nonce: Vec<u8>,
    tag_size: usize,
}

impl<C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> SSStream<C> {
    /// 通用构造：传入初始 nonce 状态。
    ///
    /// # Errors
    /// - [`SsError::UnsupportedCipher`]：None cipher 不支持流式 AEAD。
    /// - 透传 AEAD 初始化错误。
    pub fn new(inner: C, account: &MemoryAccount, iv: &[u8], initial_nonce: Vec<u8>) -> Result<Self> {
        let aead = account
            .cipher
            .create_aead(&account.key, iv)?
            .ok_or(SsError::UnsupportedCipher)?;
        let tag_size = aead.tag_size();
        Ok(Self {
            inner,
            aead,
            nonce: initial_nonce,
            tag_size,
        })
    }

    /// client 端构造：nonce 从 `[0xFF;n]` 开始。
    ///
    /// 第一次 `write_chunk` 前 increment → `[0;n]`（首帧 size）→ `[1,0,...]`（首帧 payload）。
    /// 首帧 plaintext 应为 addr+port（SS 地址格式）。
    /// # Errors
    /// - 透传 [`Self::new`] 错误。
    pub fn new_client(inner: C, account: &MemoryAccount, iv: &[u8]) -> Result<Self> {
        // nonce_size = aead.nonce_size()，但此处还没创建 aead。
        // AES-GCM/ChaCha20-Poly1305 的 nonce 都是 12；XChaCha20 是 24。
        // 用 iv_size 推断：AES/ChaCha = 16/32（iv）→ aead nonce = 12；
        //                 XChaCha = 32（iv）→ aead nonce = 24。
        // 更稳妥：直接用 account 的 cipher 类型决定。
        let nonce_size = ss_nonce_size(account);
        Self::new(inner, account, iv, vec![0xFFu8; nonce_size])
    }

    /// server body 构造：首帧已由 `decode_tcp_request_header` 消耗（nonce `[0;n]`+`[1,0,...]`），
    /// body 从 `[2,0,...]` 开始。初始 nonce = `[1,0,...]`，第一次 increment → `[2,0,...]`。
    /// # Errors
    /// - 透传 [`Self::new`] 错误。
    pub fn new_server_body(inner: C, account: &MemoryAccount, iv: &[u8]) -> Result<Self> {
        let nonce_size = ss_nonce_size(account);
        let mut initial = vec![0u8; nonce_size];
        if nonce_size > 0 {
            initial[0] = 1;
        }
        Self::new(inner, account, iv, initial)
    }

    /// LE increment（byte[0]++，进位），对应 Go `GenerateIncreasingNonce`。
    fn increment_nonce(&mut self) {
        for b in &mut self.nonce {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
    }

    /// 写一个 SS chunk：`[sealed_size(2+tag)][sealed_payload(len+tag)]`。
    ///
    /// plaintext 通常是一段应用层数据（HTTP 请求、TLS record 等）。
    /// 客户端的**第一个** `write_chunk` 应传 addr+port（SS 地址格式），作为首帧。
    ///
    /// # Errors
    /// - [`SsError::InsufficientData`]：plaintext 过大（u16 溢出）。
    /// - [`SsError::AeadSeal`]：AEAD 加密失败。
    /// - [`SsError::Io`]：底层写失败。
    pub async fn write_chunk(&mut self, plaintext: &[u8]) -> Result<()> {
        // seal size chunk
        self.increment_nonce();
        let plain_size = u16::try_from(plaintext.len() + self.tag_size)
            .map_err(|_| SsError::InsufficientData(plaintext.len()))?;
        let sealed_size = self
            .aead
            .seal(&self.nonce, &[], &plain_size.to_be_bytes())
            .map_err(|e| SsError::AeadSeal(e.to_string()))?;

        // seal payload chunk
        self.increment_nonce();
        let sealed_payload = self
            .aead
            .seal(&self.nonce, &[], plaintext)
            .map_err(|e| SsError::AeadSeal(e.to_string()))?;

        self.inner.write_all(&sealed_size).await?;
        self.inner.write_all(&sealed_payload).await?;
        Ok(())
    }

    /// flush 底层连接。
    /// # Errors
    /// - 透传 IO 错误。
    pub async fn flush(&mut self) -> Result<()> {
        self.inner.flush().await?;
        Ok(())
    }

    /// 关闭写方向（发送 TCP FIN）。
    /// # Errors
    /// - 透传 IO 错误。
    pub async fn shutdown(&mut self) -> Result<()> {
        self.inner.shutdown().await?;
        Ok(())
    }

    /// 读一个 SS chunk，返回 plaintext。
    ///
    /// 返回 `Ok(None)` 表示流结束（inner EOF 或读到 0 长度 chunk）。
    ///
    /// # Errors
    /// - [`SsError::AeadOpen`]：AEAD 解密失败（tag 不匹配 / 数据损坏）。
    /// - [`SsError::Io`]：底层读失败（含 UnexpectedEof）。
    pub async fn read_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        // 读 size chunk（2 + tag_size = 18B for AES-GCM/ChaCha20）
        let size_wire_len = 2 + self.tag_size;
        let mut size_buf = vec![0u8; size_wire_len];
        match self.inner.read_exact(&mut size_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(SsError::from(e)),
        }

        // open size chunk
        self.increment_nonce();
        let size_plain = self
            .aead
            .open(&self.nonce, &[], &size_buf)
            .map_err(|e| SsError::AeadOpen(e.to_string()))?;
        if size_plain.len() < 2 {
            return Err(SsError::InsufficientData(size_plain.len()));
        }
        let payload_len = u16::from_be_bytes([size_plain[0], size_plain[1]]) as usize;

        // 0 长度 = 流结束标记
        if payload_len == 0 {
            return Ok(None);
        }

        // 读 payload chunk
        let mut payload_buf = vec![0u8; payload_len];
        self.inner.read_exact(&mut payload_buf).await?;

        // open payload
        self.increment_nonce();
        let plaintext = self
            .aead
            .open(&self.nonce, &[], &payload_buf)
            .map_err(|e| SsError::AeadOpen(e.to_string()))?;

        Ok(Some(plaintext))
    }

    /// 获取底层连接的不可变引用。
    #[must_use]
    pub fn get_ref(&self) -> &C {
        &self.inner
    }

    /// 获取底层连接的可变引用。
    #[must_use]
    pub fn get_mut(&mut self) -> &mut C {
        &mut self.inner
    }

    /// 消费 SSStream，返回底层连接。
    #[must_use]
    pub fn into_inner(self) -> C {
        self.inner
    }
}

/// 根据 account 的 cipher 类型返回 aead nonce 大小。
///
/// - AES-128/256-GCM、ChaCha20-Poly1305：12
/// - XChaCha20-Poly1305：24
fn ss_nonce_size(account: &MemoryAccount) -> usize {
    match account.cipher_type {
        crate::config::CipherType::XChaCha20Poly1305 => 24,
        _ => 12,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CipherType;
    use tokio::io::duplex;
    use xray_proto::xray::proxy::shadowsocks::Account as ProtoAccount;

    fn make_account(ct: CipherType, password: &str) -> MemoryAccount {
        let p = ProtoAccount {
            password: password.to_string(),
            cipher_type: ct.as_i32(),
            iv_check: false,
        };
        MemoryAccount::from_proto(&p).expect("account")
    }

    /// 生成随机 IV（长度 = cipher.iv_size()）。
    fn random_iv(account: &MemoryAccount) -> Vec<u8> {
        let n = account.cipher.iv_size() as usize;
        (0..n).map(|_| rand::random()).collect()
    }

    /// client ↔ server 回环：创建一对 SSStream（共享 aead key/iv），互写互读。
    async fn roundtrip_pair(
        ct: CipherType,
    ) -> (SSStream<tokio::io::DuplexStream>, SSStream<tokio::io::DuplexStream>) {
        let account = make_account(ct, "test-password");
        let iv = random_iv(&account);

        // duplex：client_half ↔ server_half（tokio 内部连接）
        let (client_half, server_half) = duplex(8 * 1024);

        // client 端：nonce 从 [0xFF;n] 开始
        let client_stream = SSStream::new_client(client_half, &account, &iv).expect("client");
        // server 端：模拟 decode_tcp_request_header 已消耗首帧 nonce
        // 但这里我们测试 body roundtrip，server 从 [0xFF;n] 开始（双向独立）
        let server_account = make_account(ct, "test-password");
        let server_stream = SSStream::new_client(server_half, &server_account, &iv).expect("server");

        (client_stream, server_stream)
    }

    #[tokio::test]
    async fn write_read_single_chunk_aes_128() {
        let (mut client, mut server) = roundtrip_pair(CipherType::Aes128Gcm).await;

        let payload = b"hello shadowsocks stream";
        client.write_chunk(payload).await.expect("write");
        client.flush().await.expect("flush");

        let received = server.read_chunk().await.expect("read");
        assert_eq!(received.as_deref(), Some(payload.as_slice()));
    }

    #[tokio::test]
    async fn write_read_single_chunk_aes_256() {
        let (mut client, mut server) = roundtrip_pair(CipherType::Aes256Gcm).await;

        let payload = b"aes-256-gcm stream test payload";
        client.write_chunk(payload).await.expect("write");
        client.flush().await.expect("flush");

        let received = server.read_chunk().await.expect("read");
        assert_eq!(received.as_deref(), Some(payload.as_slice()));
    }

    #[tokio::test]
    async fn write_read_single_chunk_chacha20() {
        let (mut client, mut server) = roundtrip_pair(CipherType::ChaCha20Poly1305).await;

        let payload = b"chacha20-poly1305 stream payload";
        client.write_chunk(payload).await.expect("write");
        client.flush().await.expect("flush");

        let received = server.read_chunk().await.expect("read");
        assert_eq!(received.as_deref(), Some(payload.as_slice()));
    }

    #[tokio::test]
    async fn write_read_single_chunk_xchacha20() {
        let (mut client, mut server) = roundtrip_pair(CipherType::XChaCha20Poly1305).await;

        let payload = b"xchacha20-poly1305 stream payload";
        client.write_chunk(payload).await.expect("write");
        client.flush().await.expect("flush");

        let received = server.read_chunk().await.expect("read");
        assert_eq!(received.as_deref(), Some(payload.as_slice()));
    }

    #[tokio::test]
    async fn multiple_chunks_roundtrip() {
        let (mut client, mut server) = roundtrip_pair(CipherType::Aes128Gcm).await;

        let chunks: &[&[u8]] = &[
            b"first chunk",
            b"second chunk with more data",
            b"third",
        ];

        for chunk in chunks {
            client.write_chunk(chunk).await.expect("write");
        }
        client.flush().await.expect("flush");

        for expected in chunks {
            let received = server.read_chunk().await.expect("read");
            assert_eq!(received.as_deref(), Some(*expected));
        }
    }

    #[tokio::test]
    async fn bidirectional_roundtrip() {
        // client → server + server → client
        let (mut client, mut server) = roundtrip_pair(CipherType::Aes256Gcm).await;

        // client 写
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        client.write_chunk(req).await.expect("client write");
        client.flush().await.expect("client flush");

        // server 读
        let received = server.read_chunk().await.expect("server read");
        assert_eq!(received.as_deref(), Some(req.as_slice()));

        // server 写响应
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        server.write_chunk(resp).await.expect("server write");
        server.flush().await.expect("server flush");

        // client 读响应
        let received = client.read_chunk().await.expect("client read");
        assert_eq!(received.as_deref(), Some(resp.as_slice()));
    }

    #[tokio::test]
    async fn large_payload_roundtrip() {
        let (mut client, mut server) = roundtrip_pair(CipherType::Aes128Gcm).await;

        // 4KB payload（单 chunk）
        let payload = vec![0xABu8; 4096];
        client.write_chunk(&payload).await.expect("write");
        client.flush().await.expect("flush");

        let received = server.read_chunk().await.expect("read");
        assert_eq!(received.as_deref(), Some(payload.as_slice()));
    }

    #[tokio::test]
    async fn eof_on_close_returns_none() {
        let (mut client, mut server) = roundtrip_pair(CipherType::Aes128Gcm).await;

        // client 关闭写方向
        client.shutdown().await.expect("shutdown");

        // server 读到 EOF → None
        let received = server.read_chunk().await.expect("read");
        assert!(received.is_none());
    }

    #[test]
    fn server_body_initial_nonce_state() {
        // new_server_body 初始 nonce = [1,0,...]，第一次 increment → [2,0,...]
        // 模拟 decode_tcp_request_header 已消耗首帧 nonce [0;n]+[1,0,...]
        let account = make_account(CipherType::Aes128Gcm, "password");
        let iv = random_iv(&account);
        let (_a, b) = tokio::io::duplex(64);
        let mut stream = SSStream::new_server_body(b, &account, &iv).expect("server body");

        // 初始 [1,0,...]
        assert_eq!(stream.nonce[0], 1);
        assert_eq!(stream.nonce[1..], vec![0u8; 11]);

        // increment → [2,0,...]（body 首个 size chunk）
        stream.increment_nonce();
        assert_eq!(stream.nonce[0], 2);
        assert_eq!(stream.nonce[1..], vec![0u8; 11]);
    }

    #[test]
    fn nonce_increment_le_carry() {
        // 测试 LE increment 进位
        let account = make_account(CipherType::Aes128Gcm, "p");
        let iv = random_iv(&account);
        let (_duplex_a, duplex_b) = tokio::io::duplex(64);
        let mut stream = SSStream::new_client(duplex_b, &account, &iv).expect("stream");

        // 初始 [0xFF; 12]
        assert_eq!(stream.nonce, vec![0xFFu8; 12]);

        // increment → [0; 12]
        stream.increment_nonce();
        assert_eq!(stream.nonce, vec![0u8; 12]);

        // increment → [1, 0, ...]
        stream.increment_nonce();
        assert_eq!(stream.nonce[0], 1);
        assert_eq!(stream.nonce[1..], vec![0u8; 11]);

        // 设 nonce[0] = 0xFF，increment → [0, 1, 0, ...]（进位）
        stream.nonce[0] = 0xFF;
        stream.increment_nonce();
        assert_eq!(stream.nonce[0], 0);
        assert_eq!(stream.nonce[1], 1);
        assert_eq!(stream.nonce[2..], vec![0u8; 10]);
    }
}
