//! VMess body chunk 同步编解码（对应 Go `crypto.AuthenticationWriter/Reader`）。
//!
//! # 设计
//!
//! VMess body 用 chunk framing 传输：每个 chunk 格式
//! ```text
//! [2B size][encrypted_payload][padding]
//! ```
//! - `2B size`：BE u16，值为 `encrypted_payload.len() + padding.len()`
//!   - 默认明文（PlainChunkSizeParser）
//!   - RequestOptionChunkMasking 时与 SHAKE128 流异或（ShakeSizeParser）
//! - `encrypted_payload`：AEAD seal(plaintext)（AES-128-GCM 默认）
//! - `padding`：默认无；RequestOptionGlobalPadding 时随机长度
//!
//! 流终止：写 size=0 的 chunk。
//!
//! # 实现范围
//!
//! 同步 IO（`std::io::Read/Write`），复用 `xray_crypto::aead::AeadCipher` trait。
//! 支持 PlainChunkSizeParser + NoPadding（默认）+ ShakeSizeParser + ShakePadding（chunk masking）
//! 两条路径。AuthenticatedLength 留 follow-up。

use std::io::{Read, Write};

use xray_crypto::aead::AeadCipher;

use crate::encoding::{ChunkNonceGenerator, PlainChunkSizeParser, ShakeSizeParser};

/// 默认 chunk payload 上限（VMess 用 0x3FFF = 16383，对应 2B length 字段最高位 0）。
const DEFAULT_PAYLOAD_SIZE: usize = 8192;


/// size 字段字节数（Plain / Shake 都是 2B）。
const SIZE_FIELD_BYTES: usize = 2;

// ============================================================================
// SizeParser trait（同步、可状态化）
// ============================================================================

/// chunk size 编解码器（同步、可能持状态，如 ShakeSizeParser）。
pub trait SizeParser {
    /// 编码 size 到 2B out。
    fn encode(&mut self, size: u16, out: &mut [u8; 2]);

    /// 从 2B input 解码 size。
    fn decode(&mut self, input: &[u8; 2]) -> u16;

    /// 下一个 padding 长度（0 表示无 padding）。
    fn next_padding_len(&mut self) -> u16 {
        0
    }
}

/// 明文 BE u16 size parser，无 padding。
pub struct PlainSizeParser;
impl SizeParser for PlainSizeParser {
    fn encode(&mut self, size: u16, out: &mut [u8; 2]) {
        PlainChunkSizeParser::encode(size, out);
    }
    fn decode(&mut self, input: &[u8; 2]) -> u16 {
        PlainChunkSizeParser::decode(input)
    }
}

/// SHAKE128 流异或 size parser + Shake padding。
pub struct ShakeSizeParserAdapter {
    inner: ShakeSizeParser,
}
impl ShakeSizeParserAdapter {
    #[must_use]
    pub fn new(nonce: &[u8]) -> Self {
        Self {
            inner: ShakeSizeParser::new(nonce),
        }
    }
}
impl SizeParser for ShakeSizeParserAdapter {
    fn encode(&mut self, size: u16, out: &mut [u8; 2]) {
        self.inner.encode_mut(size, out);
    }
    fn decode(&mut self, input: &[u8; 2]) -> u16 {
        self.inner.decode_mut(input)
    }
    fn next_padding_len(&mut self) -> u16 {
        self.inner.next_padding_len_mut()
    }
}

// ============================================================================
// NonceGenerator trait（同步、可状态化）
// ============================================================================

/// chunk nonce 生成器（每次 seal/open 一个 chunk 调一次）。
pub trait ChunkNonce {
    /// 生成下一个 nonce（自增 count）。
    fn next(&mut self) -> Vec<u8>;
}

/// 包装 `ChunkNonceGenerator` 为 `ChunkNonce`。
pub struct ChunkNonceAdapter {
    inner: ChunkNonceGenerator,
}
impl ChunkNonceAdapter {
    #[must_use]
    pub fn new(iv: &[u8], nonce_size: usize) -> Self {
        Self {
            inner: ChunkNonceGenerator::new(iv, nonce_size),
        }
    }
}
impl ChunkNonce for ChunkNonceAdapter {
    fn next(&mut self) -> Vec<u8> {
        self.inner.next()
    }
}

// ============================================================================
// encode_chunk_stream：把明文 data 编码为 chunk 流写入 writer
// ============================================================================

/// 把明文 data 编码为 chunk 流写入 writer。
///
/// 算法（对应 Go `AuthenticationWriter.WriteMultiBuffer` Stream 模式）：
/// 1. 按 `payload_chunk_size = DEFAULT_PAYLOAD_SIZE - tag - size_field - max_padding` 分块
/// 2. 每块 seal + 写入
/// 3. 写入终止 chunk（size = 0 + tag）
///
/// # Errors
///
/// - IO 错误
/// - AEAD 加密失败
pub fn encode_chunk_stream<W: Write>(
    writer: &mut W,
    data: &[u8],
    cipher: &dyn AeadCipher,
    nonce_gen: &mut dyn ChunkNonce,
    size_parser: &mut dyn SizeParser,
) -> std::io::Result<()> {
    let max_padding = usize::from(size_parser_max_padding_hint(size_parser));
    let payload_chunk_size = DEFAULT_PAYLOAD_SIZE
        .saturating_sub(cipher.tag_size())
        .saturating_sub(SIZE_FIELD_BYTES)
        .saturating_sub(max_padding);

    if payload_chunk_size == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "payload_chunk_size underflow",
        ));
    }

    // 分块编码
    let mut start = 0usize;
    while start < data.len() {
        let end = (start + payload_chunk_size).min(data.len());
        let chunk = &data[start..end];
        write_one_chunk(writer, chunk, cipher, nonce_gen, size_parser)?;
        start = end;
    }

    // 写入终止 chunk：seal 空数据（带 tag）
    write_one_chunk(writer, &[], cipher, nonce_gen, size_parser)?;
    writer.flush()?;
    Ok(())
}

/// 写单个 chunk：[2B size][encrypted][padding]。
fn write_one_chunk<W: Write>(
    writer: &mut W,
    data: &[u8],
    cipher: &dyn AeadCipher,
    nonce_gen: &mut dyn ChunkNonce,
    size_parser: &mut dyn SizeParser,
) -> std::io::Result<()> {
    let nonce = nonce_gen.next();
    let sealed = cipher
        .seal(&nonce, &[], data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    let padding_size = usize::from(size_parser.next_padding_len());
    let encrypted_size = sealed.len(); // = data.len() + TAG_SIZE
    let size_value = u16::try_from(encrypted_size + padding_size).unwrap_or(u16::MAX);

    let mut size_field = [0u8; 2];
    size_parser.encode(size_value, &mut size_field);
    writer.write_all(&size_field)?;
    writer.write_all(&sealed)?;
    if padding_size > 0 {
        let mut pad = vec![0u8; padding_size];
        // 随机 padding（ ponytail: 用 rand 直接，不引 crate）
        use rand::RngCore;
        rand::rng().fill_bytes(&mut pad);
        writer.write_all(&pad)?;
    }
    Ok(())
}

// ============================================================================
// decode_chunk_stream：从 reader 读取并解码 chunk 流，返回所有明文
// ============================================================================

/// 从 reader 读取 chunk 流并解码，返回拼接后的所有明文。
///
/// 算法（对应 Go `AuthenticationReader.ReadMultiBuffer`）：
/// 1. 读 2B size_field
/// 2. 解码 size = encrypted_payload_size + padding_size
/// 3. 读 size 字节
/// 4. padding_size 由 size_parser.next_padding_len() 给出（与 encoder 同步）
/// 5. AEAD open 前 (size - padding_size) 字节，丢弃 padding
/// 6. plaintext 为空 → 流结束（终止 chunk）
///
/// # Errors
///
/// - IO 错误（含 EOF）
/// - AEAD 解密失败
pub fn decode_chunk_stream<R: Read>(
    reader: &mut R,
    cipher: &dyn AeadCipher,
    nonce_gen: &mut dyn ChunkNonce,
    size_parser: &mut dyn SizeParser,
) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    loop {
        // mask 流顺序对齐 Go auth.go:127-131 readSize：先 NextPaddingLen 再 Decode。
        // ShakeSizeParser 的 SHAKE128 流必须 encoder/decoder 同序消费，否则流错位。
        let padding_size = usize::from(size_parser.next_padding_len());

        let mut size_field = [0u8; 2];
        reader.read_exact(&mut size_field)?;
        let total_size = size_parser.decode(&size_field);

        // ponytail: PlainChunkSizeParser 不会输出 size==0，但 Go 端 AuthenticationReader
        // 也检查 size==0 → EOF，这里保持一致
        if total_size == 0 {
            return Ok(output);
        }

        let ciphertext_size = usize::from(total_size).saturating_sub(padding_size);

        let mut ciphertext = vec![0u8; usize::from(total_size)];
        reader.read_exact(&mut ciphertext)?;

        // padding 跟在 ciphertext 之后
        let ciphertext_only = &ciphertext[..ciphertext_size];

        // 终止 chunk：ciphertext 是 seal([]) → 解密后为空
        let nonce = nonce_gen.next();
        let plaintext = cipher
            .open(&nonce, &[], ciphertext_only)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        // 终止 chunk：解密后 plaintext 为空 → 流结束
        // （Go 端 AuthenticationWriter::write_multi_buffer 对空输入 seal([]) 写终止）
        if plaintext.is_empty() {
            return Ok(output);
        }
        output.extend_from_slice(&plaintext);
    }
}

// ============================================================================
// 辅助：SizeParser 最大 padding 提示（用于计算 payload_chunk_size）
// ============================================================================

/// 返回 size_parser 可能的最大 padding 长度（用于 payload 分块）。
/// PlainSizeParser=0，ShakeSizeParser=64。
fn size_parser_max_padding_hint(_p: &dyn SizeParser) -> u16 {
    // ponytail: trait object 不能直接调关联常量，统一返回 64（ShakeSizeParser 上限）
    // PlainSizeParser 实际为 0，差 64B 不影响正确性，仅 payload_chunk_size 略小
    64
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use xray_crypto::aead::{Aes128Gcm, ChaCha20Poly1305Aead};
    use crate::encoding::NoOpAuthenticator;

    fn make_cipher() -> Aes128Gcm {
        Aes128Gcm::new(&[0x42u8; 16]).expect("aes")
    }

    fn make_nonce_gen() -> ChunkNonceAdapter {
        ChunkNonceAdapter::new(&[0xAAu8; 16], 12)
    }

    #[test]
    fn plain_roundtrip_empty() {
        let cipher_w = make_cipher();
        let cipher_r = Aes128Gcm::new(&[0x42u8; 16]).expect("aes");
        let mut nw = make_nonce_gen();
        let mut nr = make_nonce_gen();
        let mut sp_w = PlainSizeParser;
        let mut sp_r = PlainSizeParser;

        let mut buf: Vec<u8> = Vec::new();
        encode_chunk_stream(&mut buf, b"", &cipher_w, &mut nw, &mut sp_w).expect("encode");
        assert!(!buf.is_empty()); // 至少有终止 chunk

        let decoded = decode_chunk_stream(&mut &buf[..], &cipher_r, &mut nr, &mut sp_r).expect("decode");
        assert!(decoded.is_empty());
    }

    #[test]
    fn plain_roundtrip_small() {
        let cipher_w = make_cipher();
        let cipher_r = Aes128Gcm::new(&[0x42u8; 16]).expect("aes");
        let mut nw = make_nonce_gen();
        let mut nr = make_nonce_gen();
        let mut sp_w = PlainSizeParser;
        let mut sp_r = PlainSizeParser;

        let data = b"hello vmess body chunk";
        let mut buf: Vec<u8> = Vec::new();
        encode_chunk_stream(&mut buf, data, &cipher_w, &mut nw, &mut sp_w).expect("encode");

        let decoded = decode_chunk_stream(&mut &buf[..], &cipher_r, &mut nr, &mut sp_r).expect("decode");
        assert_eq!(decoded, data);
    }

    #[test]
    fn plain_roundtrip_large_multi_chunk() {
        let cipher_w = make_cipher();
        let cipher_r = Aes128Gcm::new(&[0x42u8; 16]).expect("aes");
        let mut nw = make_nonce_gen();
        let mut nr = make_nonce_gen();
        let mut sp_w = PlainSizeParser;
        let mut sp_r = PlainSizeParser;

        // payload_chunk_size ≈ 8192 - 16 - 2 - 64 = 8110；写 20000 字节 → 3 个 chunk
        let data: Vec<u8> = (0..20000).map(|i| (i % 251) as u8).collect();
        let mut buf: Vec<u8> = Vec::new();
        encode_chunk_stream(&mut buf, &data, &cipher_w, &mut nw, &mut sp_w).expect("encode");

        let decoded = decode_chunk_stream(&mut &buf[..], &cipher_r, &mut nr, &mut sp_r).expect("decode");
        assert_eq!(decoded, data);
    }

    #[test]
    fn shake_roundtrip_with_padding() {
        let cipher_w = make_cipher();
        let cipher_r = Aes128Gcm::new(&[0x42u8; 16]).expect("aes");
        let mut nw = ChunkNonceAdapter::new(&[0xAAu8; 16], 12);
        let mut nr = ChunkNonceAdapter::new(&[0xAAu8; 16], 12);
        let mut sp_w = ShakeSizeParserAdapter::new(&[0x11u8; 16]);
        let mut sp_r = ShakeSizeParserAdapter::new(&[0x11u8; 16]);

        let data = b"shake padded payload for vmess chunk masking";
        let mut buf: Vec<u8> = Vec::new();
        encode_chunk_stream(&mut buf, data, &cipher_w, &mut nw, &mut sp_w).expect("encode");

        let decoded = decode_chunk_stream(&mut &buf[..], &cipher_r, &mut nr, &mut sp_r).expect("decode");
        assert_eq!(decoded, data);
    }

    #[test]
    fn decode_wrong_key_fails() {
        let cipher_w = Aes128Gcm::new(&[0x42u8; 16]).expect("aes");
        let cipher_r = Aes128Gcm::new(&[0x99u8; 16]).expect("aes"); // 不同 key
        let mut nw = make_nonce_gen();
        let mut nr = make_nonce_gen();
        let mut sp_w = PlainSizeParser;
        let mut sp_r = PlainSizeParser;

        let mut buf: Vec<u8> = Vec::new();
        encode_chunk_stream(&mut buf, b"secret", &cipher_w, &mut nw, &mut sp_w).expect("encode");

        let err = decode_chunk_stream(&mut &buf[..], &cipher_r, &mut nr, &mut sp_r).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn noop_authenticator_seal_open_preserves_bytes() {
        // 验证 NoOpAuthenticator 行为（chunk stream NONE 模式用）
        let pt = b"hello";
        let sealed = NoOpAuthenticator::seal(pt);
        let opened = NoOpAuthenticator::open(&sealed);
        assert_eq!(pt.as_slice(), opened.as_slice());
        assert_eq!(NoOpAuthenticator::overhead(), 0);
    }

    #[test]
    fn cipher_aes128gcm_seal_open_roundtrip() {
        // 验证 Aes128Gcm 基础接口
        let c = Aes128Gcm::new(&[1u8; 16]).expect("aes");
        let nonce = vec![0u8; 12];
        let sealed = c.seal(&nonce, &[], b"test").expect("seal");
        assert_eq!(sealed.len(), 4 + c.tag_size());
        let opened = c.open(&nonce, &[], &sealed).expect("open");
        assert_eq!(opened, b"test");
    }

    #[test]
    fn chacha20poly1305_roundtrip() {
        // 验证 ChaCha20-Poly1305 通过 &dyn AeadCipher 泛化路径 round-trip
        let cipher_w = ChaCha20Poly1305Aead::new(&[0x42u8; 32]).expect("chacha");
        let cipher_r = ChaCha20Poly1305Aead::new(&[0x42u8; 32]).expect("chacha");
        let mut nw = ChunkNonceAdapter::new(&[0xAAu8; 16], 12);
        let mut nr = ChunkNonceAdapter::new(&[0xAAu8; 16], 12);
        let mut sp_w = PlainSizeParser;
        let mut sp_r = PlainSizeParser;

        let data = b"chacha20 poly1305 vmess body";
        let mut buf: Vec<u8> = Vec::new();
        encode_chunk_stream(&mut buf, data, &cipher_w, &mut nw, &mut sp_w).expect("encode");

        let decoded =
            decode_chunk_stream(&mut &buf[..], &cipher_r, &mut nr, &mut sp_r).expect("decode");
        assert_eq!(decoded, data);
    }

    #[test]
    fn chacha20poly1305_multi_cipher_dispatch() {
        // 验证同一 encode/decode 函数可 dispatch 不同 cipher（Aes128Gcm vs ChaCha20）
        let aes_w = Aes128Gcm::new(&[0x42u8; 16]).expect("aes");
        let aes_r = Aes128Gcm::new(&[0x42u8; 16]).expect("aes");
        let data = b"dispatch test";
        let mut buf: Vec<u8> = Vec::new();
        let mut nw = ChunkNonceAdapter::new(&[0xAAu8; 16], 12);
        let mut nr = ChunkNonceAdapter::new(&[0xAAu8; 16], 12);
        let mut sp_w = PlainSizeParser;
        let mut sp_r = PlainSizeParser;
        encode_chunk_stream(&mut buf, data, &aes_w, &mut nw, &mut sp_w).expect("aes encode");
        let decoded =
            decode_chunk_stream(&mut &buf[..], &aes_r, &mut nr, &mut sp_r).expect("aes decode");
        assert_eq!(decoded, data);

        // ChaCha20 独立流
        let chacha_w = ChaCha20Poly1305Aead::new(&[0x99u8; 32]).expect("chacha");
        let chacha_r = ChaCha20Poly1305Aead::new(&[0x99u8; 32]).expect("chacha");
        let mut buf2: Vec<u8> = Vec::new();
        let mut nw2 = ChunkNonceAdapter::new(&[0xBBu8; 16], 12);
        let mut nr2 = ChunkNonceAdapter::new(&[0xBBu8; 16], 12);
        encode_chunk_stream(&mut buf2, data, &chacha_w, &mut nw2, &mut sp_w).expect("chacha encode");
        let decoded2 =
            decode_chunk_stream(&mut &buf2[..], &chacha_r, &mut nr2, &mut sp_r).expect("chacha decode");
        assert_eq!(decoded2, data);
    }
}
