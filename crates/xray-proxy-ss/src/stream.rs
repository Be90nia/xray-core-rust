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
    /// 非空 = 下次 `read_chunk` 前先读 server response 的新 IV 并 rekey aead
    /// （Go `WriteTCPResponse` 模式）。见 [`Client::dial_target_for_proxy`]。
    response_rekey: Option<MemoryAccount>,
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
            response_rekey: None,
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

    /// SS-2022 通用构造：传入已派生的 AEAD + nonce_size。
    ///
    /// nonce 从 `[0xFF;n]` 开始，第一次 increment → `[0;n]`（与 SS-2022 规范一致）。
    /// 用于 SS-2022（blake3 subkey）等非 MemoryAccount 构造场景。
    #[must_use]
    pub fn new_with_aead(
        inner: C,
        aead: Box<dyn xray_crypto::aead::AeadCipher + Send + Sync>,
        nonce_size: usize,
    ) -> Self {
        let tag_size = aead.tag_size();
        Self {
            inner,
            aead,
            nonce: vec![0xFFu8; nonce_size],
            tag_size,
            response_rekey: None,
        }
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
    /// 超过单块上限时自动分块（对应 Go `AuthenticationWriter.writeStream` 按
    /// `buf.Size(8192) - tag - 2` 分块），调用方无需关心大小。
    /// 空输入不产生任何 chunk（size=0 是流结束标记，不能由本方法发出）。
    ///
    /// # Errors
    /// - [`SsError::AeadSeal`]：AEAD 加密失败。
    /// - [`SsError::Io`]：底层写失败。
    pub async fn write_chunk(&mut self, plaintext: &[u8]) -> Result<()> {
        // 8192 = Go buf.Size；tag_size+2 是 size chunk 的 wire 开销。
        let max_payload = 8192 - self.tag_size - 2;
        for part in plaintext.chunks(max_payload.max(1)) {
            self.write_single_chunk(part).await?;
        }
        Ok(())
    }

    /// 写单个（已保证 ≤ 块上限的）chunk。
    async fn write_single_chunk(&mut self, plaintext: &[u8]) -> Result<()> {
        // seal size chunk
        self.increment_nonce();
        let plain_size = u16::try_from(plaintext.len())
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

    /// 写一个 raw chunk（直接 seal，无 size prefix）。
    ///
    /// 用于 SS-2022 header chunk（fixed-header + variable-header），
    /// 对应 Go `shadowaead.Writer.WriteChunk`。
    ///
    /// 与 `write_chunk` 的区别：只 seal 一次（不分 size/payload），nonce 只 increment 一次。
    pub async fn write_raw_chunk(&mut self, plaintext: &[u8]) -> Result<()> {
        self.increment_nonce();
        let sealed = self
            .aead
            .seal(&self.nonce, &[], plaintext)
            .map_err(|e| SsError::AeadSeal(e.to_string()))?;
        self.inner.write_all(&sealed).await?;
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

    /// SS-2022 通用构造：传入已派生的 AEAD + 初始 nonce。
    ///
    /// 用于手动 seal header 后，body 阶段接管 SSStream 的场景。
    #[must_use]
    pub fn new_with_aead_and_nonce(
        inner: C,
        aead: Box<dyn xray_crypto::aead::AeadCipher + Send + Sync>,
        initial_nonce: Vec<u8>,
    ) -> Self {
        let tag_size = aead.tag_size();
        Self { inner, aead, nonce: initial_nonce, tag_size, response_rekey: None }
    }

    /// 读一个 SS chunk，返回 plaintext。
    ///
    /// 返回 `Ok(None)` 表示流结束（inner EOF 或读到 0 长度 chunk）。
    ///
    /// # Errors
    /// - [`SsError::AeadOpen`]：AEAD 解密失败（tag 不匹配 / 数据损坏）。
    /// - [`SsError::Io`]：底层读失败（含 UnexpectedEof）。
    pub async fn read_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        // lazy rekey：Go server response 以新 IV 开头（`WriteTCPResponse`），且只在
        // server 有响应数据时才发出。dial 后立即读 IV 会与「server 等 client body、
        // client 等 server IV」互等死锁，故延迟到第一次 read_chunk 时读取。
        if let Some(account) = self.response_rekey.take() {
            self.rekey_for_response(&account).await?;
        }

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

        // 读 payload chunk：wire = payload_len (ciphertext) + tag_size
        let wire_len = payload_len + self.tag_size;
        let mut payload_buf = vec![0u8; wire_len];
        self.inner.read_exact(&mut payload_buf).await?;

        // open payload
        self.increment_nonce();
        let plaintext = self
            .aead
            .open(&self.nonce, &[], &payload_buf)
            .map_err(|e| SsError::AeadOpen(e.to_string()))?;

        Ok(Some(plaintext))
    }

    /// 读一个 raw chunk（直接 open，无 size prefix），指定 wire 长度。
    ///
    /// 用于 SS-2022 响应的 header chunk（fixed + variable），
    /// 对应 Go `shadowaead.Reader.ReadWithLength`。
    pub async fn read_raw_chunk(&mut self, wire_len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; wire_len];
        self.inner.read_exact(&mut buf).await?;
        self.increment_nonce();
        let plaintext = self
            .aead
            .open(&self.nonce, &[], &buf)
            .map_err(|e| SsError::AeadOpen(e.to_string()))?;
        Ok(plaintext)
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

    /// 标记流为「读 Go 风格 server response」：第一次 `read_chunk` 前先读 IV 并 rekey。
    ///
    /// 对应 [`Client::dial_target_for_proxy`] 的 lazy rekey 模式。
    pub fn mark_response_rekey(&mut self, account: MemoryAccount) {
        self.response_rekey = Some(account);
    }

    /// 读 server response 的 IV + 用新 IV 派生新 aead + 重置 nonce 到 `[0xFF;n]`。
    ///
    /// 对应 Go `proxy/shadowsocks/protocol.go::ReadTCPResponse`（行165-189）：
    /// server 在 TCP response 开头写**新**随机 IV（行196-202 `WriteTCPResponse`），
    /// client 必须先读这个 IV，再用它派生 aead（HKDF-SHA1 subkey）才能解密
    /// 后续 size/payload chunks。读完后 nonce 计数器回到 `[0xFF;n]`，下一次
    /// `read_chunk` 第一次 increment → `[0;n]`（response 首帧 size）。
    ///
    /// # Errors
    /// - [`SsError::Io`]：底层读 IV 失败。
    /// - 透传 AEAD 派生错误。
    pub async fn rekey_for_response(&mut self, account: &MemoryAccount) -> Result<()> {
        let iv_size = account.cipher.iv_size() as usize;
        let mut iv = vec![0u8; iv_size];
        self.inner.read_exact(&mut iv).await?;
        let aead = account
            .cipher
            .create_aead(&account.key, &iv)?
            .ok_or(SsError::UnsupportedCipher)?;
        let tag_size = aead.tag_size();
        let nonce_size = aead.nonce_size();
        self.aead = aead;
        self.tag_size = tag_size;
        self.nonce = vec![0xFFu8; nonce_size];
        Ok(())
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

    /// 单块上限 = 8192 - tag(16) - 2 = 8174。跨块 payload 自动分块，读侧多 chunk 重组。
    /// 注意：duplex 缓冲仅 8KB，写端 20KB 会阻塞，读端必须 spawn 并发收。
    #[tokio::test]
    async fn multi_chunk_split_roundtrip() {
        let (mut client, mut server) = roundtrip_pair(CipherType::Aes128Gcm).await;

        let reader = tokio::spawn(async move {
            let mut received = Vec::new();
            for _ in 0..3 {
                let chunk = server.read_chunk().await.expect("read").expect("chunk");
                received.extend_from_slice(&chunk);
            }
            received
        });

        // 20000 = 3 块（8174 + 8174 + 3652）
        let payload = vec![0xCDu8; 20_000];
        client.write_chunk(&payload).await.expect("write");
        client.flush().await.expect("flush");

        assert_eq!(reader.await.expect("reader task"), payload);
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

    /// 模拟 Go `WriteTCPResponse`：server 生成新 IV 并写入 wire，后跟加密 chunks。
    /// 对应 Go `proxy/shadowsocks/protocol.go::WriteTCPResponse` (行191-205) + `auth.go::seal`。
    ///
    /// 写入 `[新 IV (iv_size 字节)][size_chunk (2+tag)][payload_chunk (plain_len+tag)]`。
    async fn write_go_style_response(
        writer: &'_ mut tokio::io::DuplexStream,
        account: &MemoryAccount,
        plaintext: &[u8],
    ) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        let iv_size = account.cipher.iv_size() as usize;
        let new_iv: Vec<u8> = (0..iv_size).map(|_| rand::random()).collect();
        writer.write_all(&new_iv).await?;

        let aead = account
            .cipher
            .create_aead(&account.key, &new_iv)
            .expect("aead")
            .expect("aead");
        let tag_size = aead.tag_size();

        // nonce: [0xFF;n] increment → [0;n] (size)
        let mut nonce = vec![0xFFu8; aead.nonce_size()];
        for b in &mut nonce {
            *b = b.wrapping_add(1);
            if *b != 0 { break; }
        }
        let plain_size = u16::try_from(plaintext.len()).unwrap();
        let sealed_size = aead.seal(&nonce, &[], &plain_size.to_be_bytes()).unwrap();
        writer.write_all(&sealed_size).await?;

        // nonce increment → [1, 0, ...] (payload)
        for b in &mut nonce {
            *b = b.wrapping_add(1);
            if *b != 0 { break; }
        }
        let sealed_payload = aead.seal(&nonce, &[], plaintext).unwrap();
        writer.write_all(&sealed_payload).await?;
        writer.flush().await?;
        let _ = tag_size; // suppress unused if branches
        Ok(())
    }

    /// **RED 失败测试**：模拟 Go server→client wire (IV + chunk)，
    /// 验证 client 必须 rekey 后才能解密 server response。
    ///
    /// Root cause: Go `ReadTCPResponse` (proxy/shadowsocks/protocol.go:165-189)
    /// 读 IV + 用 IV 派生新 aead + 起始 nonce `[0xFF;n]`。Rust `SSStream` 当前
    /// 直接 read size chunk，没读 IV — wire format 不兼容。
    #[tokio::test]
    async fn read_chunk_after_rekey_decrypts_go_style_response() {
        let account = make_account(CipherType::Aes128Gcm, "interop-ss-password");
        let iv = random_iv(&account);

        let (client_half, mut server_half) = duplex(8 * 1024);
        // client: write first frame (addr+port) 占位
        let mut client = SSStream::new_client(client_half, &account, &iv).expect("client");
        let header = vec![0x01u8, 127, 0, 0, 1, 0, 80];
        client.write_chunk(&header).await.expect("write header");
        client.flush().await.expect("flush header");

        // 模拟 Go server：写 response (IV + chunk) 到 server_half → client_half 读
        let payload = b"hello ss interop test!";
        write_go_style_response(&mut server_half, &account, payload).await.expect("write resp");

        // **修复点**：client 必须先 rekey (读 IV + 派生新 aead + 重置 nonce)
        // 后才能 read_chunk 解密 server response。
        client.rekey_for_response(&account).await.expect("rekey");

        let got = client.read_chunk().await.expect("read_chunk");
        let got = got.expect("non-empty chunk");
        assert_eq!(got, payload, "decrypted response should match original payload");
    }

    /// **辅助**：多个 cipher 的 wire compat sanity（防止 AES-128 修好后 ChaCha/AES-256 又坏）。
    #[tokio::test]
    async fn read_response_rekey_all_ciphers() {
        for ct in [
            CipherType::Aes128Gcm,
            CipherType::Aes256Gcm,
            CipherType::ChaCha20Poly1305,
        ] {
            let account = make_account(ct, "interop-ss-password");
            let iv = random_iv(&account);

            let (client_half, mut server_half) = duplex(8 * 1024);
            let mut client = SSStream::new_client(client_half, &account, &iv).expect("client");
            client.write_chunk(&[0x01, 127, 0, 0, 1, 0, 80]).await.expect("write");
            client.flush().await.expect("flush");

            write_go_style_response(&mut server_half, &account, b"PING").await.expect("write resp");
            client.rekey_for_response(&account).await.expect("rekey");

            let got = client.read_chunk().await.expect("read").expect("non-empty");
            assert_eq!(got, b"PING", "{:?}: roundtrip mismatch", ct);
        }
    }
}


