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
//! 支持 Plain + Shake + AEAD（AuthenticatedLength）三条路径。

use std::io::{Read, Write};

use xray_crypto::aead::{AeadCipher, Aes128Gcm, ChaCha20Poly1305Aead, NoOpAeadCipher};
use xray_crypto::authenticator::{Authenticator, BytesGenerator, DynamicAEADAuthenticator};
use xray_crypto::chunk::{AEADChunkSizeParser, ChunkSizeDecoder, ChunkSizeEncoder};

use crate::encoding::{AUTHENTICATED_LENGTH_PATH, ChunkNonceGenerator, ShakeSizeParser, generate_chacha20poly1305_key};

use std::sync::Mutex;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use xray_common::protocol::SecurityType;

use crate::aead;
use crate::error::{Result, VmessError};

/// 默认 chunk payload 上限（VMess 用 0x3FFF = 16383，对应 2B length 字段最高位 0）。
const DEFAULT_PAYLOAD_SIZE: usize = 8192;



// ============================================================================
// SizeParser trait（同步、可状态化）
// ============================================================================

/// chunk size 编解码器（同步、可能持状态，如 ShakeSizeParser）。
///
/// `size_bytes()` 返回 wire 上 size 字段的长度：
/// - Plain / Shake = 2
/// - AEAD（AuthenticatedLength）= 2 + overhead（如 AES-GCM = 18）
pub trait SizeParser {
    /// 返回编码后 size 字段的字节数。
    fn size_bytes(&self) -> usize {
        2
    }

    /// 编码 size 到 out（长度 ≥ `size_bytes()`）。
    fn encode(&mut self, size: u16, out: &mut [u8]);

    /// 从 input 解码 size（长度 ≥ `size_bytes()`）。
    fn decode(&mut self, input: &[u8]) -> u16;

    /// 下一个 padding 长度（0 表示无 padding）。
    fn next_padding_len(&mut self) -> u16 {
        0
    }
}

/// 明文 BE u16 size parser，无 padding。
pub struct PlainSizeParser;
impl SizeParser for PlainSizeParser {
    fn encode(&mut self, size: u16, out: &mut [u8]) {
        let bytes = size.to_be_bytes();
        if out.len() >= 2 {
            out[0] = bytes[0];
            out[1] = bytes[1];
        }
    }
    fn decode(&mut self, input: &[u8]) -> u16 {
        if input.len() >= 2 {
            u16::from_be_bytes([input[0], input[1]])
        } else { 0 }
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
    fn encode(&mut self, size: u16, out: &mut [u8]) {
        let mut buf = [0u8; 2];
        self.inner.encode_mut(size, &mut buf);
        if out.len() >= 2 {
            out[0] = buf[0];
            out[1] = buf[1];
        }
    }
    fn decode(&mut self, input: &[u8]) -> u16 {
        if input.len() >= 2 {
            let buf = [input[0], input[1]];
            self.inner.decode_mut(&buf)
        } else { 0 }
    }
    fn next_padding_len(&mut self) -> u16 {
        self.inner.next_padding_len_mut()
    }
}

/// AEAD 加密的 size parser（VMess `RequestOptionAuthenticatedLength`）。
///
/// 对应 Go `AEADSizeParser` = `crypto.AEADChunkSizeParser` wrapper。
/// size 字段用 AEAD 加密：wire = seal(2B plaintext) → 2 + tag 字节。
/// size 值含 overhead（与 xray-crypto `AEADChunkSizeParser` 语义一致）。
pub struct AEADSizeParserAdapter {
    inner: AEADChunkSizeParser,
}

impl AEADSizeParserAdapter {
    /// 从 `Box<dyn Authenticator>` 创建 AEAD size parser。
    ///
    /// 调用方负责构造 Authenticator：
    /// - key = `KDF16(bodyKey, "auth_len")`
    /// - nonce = `GenerateChunkNonce(bodyIV, nonceSize)`
    #[must_use]
    pub fn new(auth: Box<dyn Authenticator>) -> Self {
        Self {
            inner: AEADChunkSizeParser::new(auth),
        }
    }
}

impl SizeParser for AEADSizeParserAdapter {
    fn size_bytes(&self) -> usize {
        ChunkSizeEncoder::size_bytes(&self.inner) as usize
    }

    fn encode(&mut self, size: u16, out: &mut [u8]) {
        ChunkSizeEncoder::encode(&self.inner, size, out);
    }

    fn decode(&mut self, input: &[u8]) -> u16 {
        ChunkSizeDecoder::decode(&self.inner, input).unwrap_or(0)
    }
}

/// 构造 AuthenticatedLength 的 AEAD size parser（对应 Go `NewAEADSizeParser(NewAEADAuthenticator(...))`）。
///
/// key 始终用 request_body_key 派生（KDF16 "auth_len"），iv 始终用 request_body_iv。
/// 这两个参数在 encode/decode 双向都相同（Go 端也是这样）。
///
/// # Errors
///
/// - [`VmessError::Crypto`]：AEAD cipher 创建失败
/// - [`VmessError::Other`]：security 类型不支持
pub fn make_authenticated_length_size_parser(
    key: &[u8; 16],
    iv: &[u8; 16],
    security: SecurityType,
) -> Result<AEADSizeParserAdapter> {
    let auth_key = aead::kdf16(key, &[AUTHENTICATED_LENGTH_PATH]);
    let nonce_gen = generate_chunk_nonce_bytes(iv, 12);
    let cipher: Box<dyn AeadCipher + Send + Sync> = match security {
        SecurityType::Aes128Gcm => Box::new(Aes128Gcm::new(&auth_key)?),
        SecurityType::Chacha20Poly1305 => {
            let k32 = generate_chacha20poly1305_key(&auth_key);
            Box::new(ChaCha20Poly1305Aead::new(&k32)?)
        }
        other => {
            return Err(VmessError::Other(format!(
                "authenticated_length: unsupported security {:?}",
                other
            )))
        }
    };
    let auth = DynamicAEADAuthenticator::new(cipher, nonce_gen, None);
    Ok(AEADSizeParserAdapter::new(Box::new(auth)))
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

/// 构造 chunk nonce 的 `BytesGenerator`（对应 Go `GenerateChunkNonce(iv, size)`）。
///
/// 包装 `ChunkNonceGenerator` 为 `Fn() -> Vec<u8>` 闭包，用 `Mutex` 提供内部可变性。
pub fn generate_chunk_nonce_bytes(iv: &[u8], nonce_size: usize) -> BytesGenerator {
    let nonce_gen = Mutex::new(ChunkNonceGenerator::new(iv, nonce_size));
    Box::new(move || nonce_gen.lock().expect("nonce gen poisoned").next())
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
    global_padding: bool,
    no_termination: bool,
) -> std::io::Result<()> {
    let max_padding = usize::from(size_parser_max_padding_hint(size_parser));
    let payload_chunk_size = DEFAULT_PAYLOAD_SIZE
        .saturating_sub(cipher.tag_size())
        .saturating_sub(size_parser.size_bytes())
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
        write_one_chunk(writer, chunk, cipher, nonce_gen, size_parser, global_padding)?;
        start = end;
    }

    // 写入终止 chunk：seal 空数据（带 tag）。NoTerminationSignal 时跳过。
    if !no_termination {
        write_one_chunk(writer, &[], cipher, nonce_gen, size_parser, global_padding)?;
        writer.flush()?;
    }
    Ok(())
}

/// 写单个 chunk：[size_field][encrypted][padding]。
fn write_one_chunk<W: Write>(
    writer: &mut W,
    data: &[u8],
    cipher: &dyn AeadCipher,
    nonce_gen: &mut dyn ChunkNonce,
    size_parser: &mut dyn SizeParser,
    global_padding: bool,
) -> std::io::Result<()> {
    let nonce = nonce_gen.next();
    let sealed = cipher
        .seal(&nonce, &[], data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    let padding_size = if global_padding { usize::from(size_parser.next_padding_len()) } else { 0 };
    let encrypted_size = sealed.len(); // = data.len() + TAG_SIZE
    let size_value = u16::try_from(encrypted_size + padding_size).unwrap_or(u16::MAX);

    let sb = size_parser.size_bytes();
    let mut size_field = vec![0u8; sb];
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

/// 读 size 字段，对齐 Go `io.ReadFull` 的 EOF 语义：
/// - 0 字节即 EOF（chunk 边界干净关闭）→ `Ok(false)`（调用方按流结束处理）
/// - 读到部分字节后 EOF → `Err`（截断 chunk，真实错误）
fn read_size_field_or_eof<R: Read>(reader: &mut R, size_field: &mut [u8]) -> std::io::Result<bool> {
    let mut filled = 0usize;
    while filled < size_field.len() {
        match reader.read(&mut size_field[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(false);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "early eof in chunk size field",
                ));
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// [`read_size_field_or_eof`] 的 async 版。
async fn read_size_field_or_eof_async<R: AsyncRead + Unpin>(
    reader: &mut R,
    size_field: &mut [u8],
) -> std::io::Result<bool> {
    use tokio::io::AsyncReadExt;
    let mut filled = 0usize;
    while filled < size_field.len() {
        match reader.read(&mut size_field[filled..]).await {
            Ok(0) => {
                if filled == 0 {
                    return Ok(false);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "early eof in chunk size field",
                ));
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}


/// 从 reader 读取 chunk 流并解码，返回拼接后的所有明文。
///
/// 算法（对应 Go `AuthenticationReader.ReadMultiBuffer`）：
/// 1. 读 size_field（长度 = `size_parser.size_bytes()`）
/// 2. 解码 size = encrypted_payload_size + padding_size
/// 3. 读 size 字节
/// 4. padding_size 由 size_parser.next_padding_len() 给出（与 encoder 同步）
/// 5. AEAD open 前 (size - padding_size) 字节，丢弃 padding
/// 6. plaintext 为空 → 流结束（终止 chunk）
/// 7. size_field 起点处干净 EOF（0 字节）→ 流结束
///    （Go 端 `buf.Copy` 吞 `io.EOF`；服务端在请求无 CHUNK_STREAM 时
///    不写终止 chunk，靠 EOF 结束流——对齐 Go 客户端语义）
///
/// # Errors
///
/// - IO 错误（chunk 边界干净 EOF 除外——那是正常流结束）
/// - AEAD 解密失败
pub fn decode_chunk_stream<R: Read>(
    reader: &mut R,
    cipher: &dyn AeadCipher,
    nonce_gen: &mut dyn ChunkNonce,
    size_parser: &mut dyn SizeParser,
    global_padding: bool,
) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    loop {
        // SHAKE128 流顺序对齐 Go auth.go:127-131 readSize：先 NextPaddingLen 再 Decode。
        // ShakeSizeParser 的 SHAKE128 流必须 encoder/decoder 同序消费，否则流错位。
        // global_padding=false 时两端都不调 NextPaddingLen，流仍同步（只靠 encode/decode 推进）。
        let padding_size = if global_padding { usize::from(size_parser.next_padding_len()) } else { 0 };

        let sb = size_parser.size_bytes();
        let mut size_field = vec![0u8; sb];
        match read_size_field_or_eof(reader, &mut size_field) {
            Ok(true) => {}
            Ok(false) => {
                // chunk 边界干净 EOF = 对端关闭流（Go buf.Copy 吞 io.EOF 视为正常结束）。
                // Go 服务端在请求无 CHUNK_STREAM option 时不写终止 chunk，靠 EOF 结束响应流。
                return Ok(output);
            }
            Err(e) => return Err(e),
        }
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
// async 版本（tokio::io::AsyncRead/AsyncWrite）
// ============================================================================

/// 把明文 data 编码为 chunk 流异步写入 writer。
///
/// 逻辑与 [`encode_chunk_stream`] 相同，IO 用 `tokio::io::AsyncWrite`。
/// AEAD seal/open 是 CPU 密集型操作，不涉及 IO，直接调用同步 API。
///
/// # Errors
///
/// - IO 错误
/// - AEAD 加密失败
pub async fn encode_chunk_stream_async<W: AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
    cipher: &dyn AeadCipher,
    nonce_gen: &mut dyn ChunkNonce,
    size_parser: &mut dyn SizeParser,
    global_padding: bool,
    no_termination: bool,
) -> std::io::Result<()> {
    let max_padding = usize::from(size_parser_max_padding_hint(size_parser));
    let payload_chunk_size = DEFAULT_PAYLOAD_SIZE
        .saturating_sub(cipher.tag_size())
        .saturating_sub(size_parser.size_bytes())
        .saturating_sub(max_padding);

    if payload_chunk_size == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "payload_chunk_size underflow",
        ));
    }

    let mut start = 0usize;
    while start < data.len() {
        let end = (start + payload_chunk_size).min(data.len());
        let chunk = &data[start..end];
        write_one_chunk_async(writer, chunk, cipher, nonce_gen, size_parser, global_padding).await?;
        start = end;
    }

    if !no_termination {
        write_one_chunk_async(writer, &[], cipher, nonce_gen, size_parser, global_padding).await?;
        writer.flush().await?;
    }
    Ok(())
}

/// 写单个 chunk（async 版）：[size_field][encrypted][padding]。
async fn write_one_chunk_async<W: AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
    cipher: &dyn AeadCipher,
    nonce_gen: &mut dyn ChunkNonce,
    size_parser: &mut dyn SizeParser,
    global_padding: bool,
) -> std::io::Result<()> {
    let nonce = nonce_gen.next();
    let sealed = cipher
        .seal(&nonce, &[], data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    let padding_size = if global_padding { usize::from(size_parser.next_padding_len()) } else { 0 };
    let encrypted_size = sealed.len();
    let size_value = u16::try_from(encrypted_size + padding_size).unwrap_or(u16::MAX);

    let sb = size_parser.size_bytes();
    let mut size_field = vec![0u8; sb];
    size_parser.encode(size_value, &mut size_field);
    writer.write_all(&size_field).await?;
    writer.write_all(&sealed).await?;
    if padding_size > 0 {
        let mut pad = vec![0u8; padding_size];
        use rand::RngCore;
        rand::rng().fill_bytes(&mut pad);
        writer.write_all(&pad).await?;
    }
    Ok(())
}

/// 从 reader 异步读取 chunk 流并解码，返回拼接后的所有明文。
///
/// 逻辑与 [`decode_chunk_stream`] 相同（含 chunk 边界干净 EOF = 流结束语义），
/// IO 用 `tokio::io::AsyncRead`。
///
/// # Errors
///
/// - IO 错误（chunk 边界干净 EOF 除外——那是正常流结束）
/// - AEAD 解密失败
pub async fn decode_chunk_stream_async<R: AsyncRead + Unpin>(
    reader: &mut R,
    cipher: &dyn AeadCipher,
    nonce_gen: &mut dyn ChunkNonce,
    size_parser: &mut dyn SizeParser,
    global_padding: bool,
) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    loop {
        let padding_size = if global_padding { usize::from(size_parser.next_padding_len()) } else { 0 };

        let sb = size_parser.size_bytes();
        let mut size_field = vec![0u8; sb];
        match read_size_field_or_eof_async(reader, &mut size_field).await {
            Ok(true) => {}
            Ok(false) => {
                // chunk 边界干净 EOF = 对端关闭流（Go buf.Copy 吞 io.EOF 视为正常结束）。
                // Go 服务端在请求无 CHUNK_STREAM option 时不写终止 chunk，靠 EOF 结束响应流。
                return Ok(output);
            }
            Err(e) => return Err(e),
        }
        let total_size = size_parser.decode(&size_field);

        if total_size == 0 {
            return Ok(output);
        }

        let ciphertext_size = usize::from(total_size).saturating_sub(padding_size);

        let mut ciphertext = vec![0u8; usize::from(total_size)];
        reader.read_exact(&mut ciphertext).await?;

        let ciphertext_only = &ciphertext[..ciphertext_size];

        let nonce = nonce_gen.next();
        let plaintext = cipher
            .open(&nonce, &[], ciphertext_only)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

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
        encode_chunk_stream(&mut buf, b"", &cipher_w, &mut nw, &mut sp_w, false, false).expect("encode");
        assert!(!buf.is_empty()); // 至少有终止 chunk

        let decoded = decode_chunk_stream(&mut &buf[..], &cipher_r, &mut nr, &mut sp_r, false).expect("decode");
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
        encode_chunk_stream(&mut buf, data, &cipher_w, &mut nw, &mut sp_w, false, false).expect("encode");

        let decoded = decode_chunk_stream(&mut &buf[..], &cipher_r, &mut nr, &mut sp_r, false).expect("decode");
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
        encode_chunk_stream(&mut buf, &data, &cipher_w, &mut nw, &mut sp_w, false, false).expect("encode");

        let decoded = decode_chunk_stream(&mut &buf[..], &cipher_r, &mut nr, &mut sp_r, false).expect("decode");
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
        encode_chunk_stream(&mut buf, data, &cipher_w, &mut nw, &mut sp_w, false, false).expect("encode");

        let decoded = decode_chunk_stream(&mut &buf[..], &cipher_r, &mut nr, &mut sp_r, false).expect("decode");
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
        encode_chunk_stream(&mut buf, b"secret", &cipher_w, &mut nw, &mut sp_w, false, false).expect("encode");

        let err = decode_chunk_stream(&mut &buf[..], &cipher_r, &mut nr, &mut sp_r, false).unwrap_err();
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
        encode_chunk_stream(&mut buf, data, &cipher_w, &mut nw, &mut sp_w, false, false).expect("encode");

        let decoded =
            decode_chunk_stream(&mut &buf[..], &cipher_r, &mut nr, &mut sp_r, false).expect("decode");
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
        encode_chunk_stream(&mut buf, data, &aes_w, &mut nw, &mut sp_w, false, false).expect("aes encode");
        let decoded =
            decode_chunk_stream(&mut &buf[..], &aes_r, &mut nr, &mut sp_r, false).expect("aes decode");
        assert_eq!(decoded, data);

        // ChaCha20 独立流
        let chacha_w = ChaCha20Poly1305Aead::new(&[0x99u8; 32]).expect("chacha");
        let chacha_r = ChaCha20Poly1305Aead::new(&[0x99u8; 32]).expect("chacha");
        let mut buf2: Vec<u8> = Vec::new();
        let mut nw2 = ChunkNonceAdapter::new(&[0xBBu8; 16], 12);
        let mut nr2 = ChunkNonceAdapter::new(&[0xBBu8; 16], 12);
        encode_chunk_stream(&mut buf2, data, &chacha_w, &mut nw2, &mut sp_w, false, false).expect("chacha encode");
        let decoded2 =
            decode_chunk_stream(&mut &buf2[..], &chacha_r, &mut nr2, &mut sp_r, false).expect("chacha decode");
        assert_eq!(decoded2, data);
    }

    #[test]
    fn aead_size_parser_roundtrip() {
    // 验证 AEADSizeParserAdapter（AuthenticatedLength）完整 encode→decode round-trip
    // size 字段从 2B 变为 2+16=18B（AEAD 加密）
    use xray_crypto::aead::Aes128Gcm as CryptoAes128Gcm;
    use xray_crypto::authenticator::{generate_static_bytes, AEADAuthenticator};

    fn make_aead_sp() -> AEADSizeParserAdapter {
        let cipher = CryptoAes128Gcm::new(&[0u8; 16]).expect("aes");
        let auth: Box<dyn Authenticator> = Box::new(AEADAuthenticator::new(
            cipher,
            generate_static_bytes(vec![0u8; 12]),
            None,
        ));
        AEADSizeParserAdapter::new(auth)
    }

    let cipher_w = make_cipher();
    let cipher_r = Aes128Gcm::new(&[0x42u8; 16]).expect("aes");
    let mut nw = make_nonce_gen();
    let mut nr = make_nonce_gen();
    let mut sp_w = make_aead_sp();
    let mut sp_r = make_aead_sp();

    // 验证 size_bytes = 2 + 16 = 18
    assert_eq!(sp_w.size_bytes(), 18);

    let data = b"aead authenticated length payload for vmess";
    let mut buf: Vec<u8> = Vec::new();
    encode_chunk_stream(&mut buf, data, &cipher_w, &mut nw, &mut sp_w, false, false).expect("encode");

    let decoded = decode_chunk_stream(&mut &buf[..], &cipher_r, &mut nr, &mut sp_r, false).expect("decode");
    assert_eq!(decoded, data);
    }

    #[test]
    fn aead_size_parser_size_field_is_18_bytes() {
    // 验证 AEAD size 字段编码后是 18 字节（2 plaintext + 16 tag）
    use xray_crypto::aead::Aes128Gcm as CryptoAes128Gcm;
    use xray_crypto::authenticator::{generate_static_bytes, AEADAuthenticator};

    let cipher = CryptoAes128Gcm::new(&[0u8; 16]).expect("aes");
    let auth: Box<dyn Authenticator> = Box::new(AEADAuthenticator::new(
        cipher,
        generate_static_bytes(vec![0u8; 12]),
        None,
    ));
    let mut sp = AEADSizeParserAdapter::new(auth);

    let mut out = vec![0u8; 18];
    sp.encode(100 + 16, &mut out); // size 含 overhead（100 payload + 16 tag）

    // 解码验证 round-trip
    let decoded = sp.decode(&out);
    assert_eq!(decoded, 100 + 16);
    assert_eq!(sp.size_bytes(), 18);
    }

    #[test]
    fn authenticated_length_dynamic_nonce_roundtrip() {
        // 验证 make_authenticated_length_size_parser（KDF16 + DynamicAEADAuthenticator + ChunkNonceGenerator via Mutex）
        let cipher_w = make_cipher();
        let cipher_r = Aes128Gcm::new(&[0x42u8; 16]).expect("aes");
        let mut nw = make_nonce_gen();
        let mut nr = make_nonce_gen();
        let mut sp_w = make_authenticated_length_size_parser(&[0x42u8; 16], &[0xAAu8; 16], SecurityType::Aes128Gcm).expect("make sp");
        let mut sp_r = make_authenticated_length_size_parser(&[0x42u8; 16], &[0xAAu8; 16], SecurityType::Aes128Gcm).expect("make sp");

        assert_eq!(sp_w.size_bytes(), 18);

        let data = b"authenticated length dynamic nonce payload";
        let mut buf: Vec<u8> = Vec::new();
        encode_chunk_stream(&mut buf, data, &cipher_w, &mut nw, &mut sp_w, false, false).expect("encode");

        let decoded = decode_chunk_stream(&mut &buf[..], &cipher_r, &mut nr, &mut sp_r, false).expect("decode");
        assert_eq!(decoded, data);
    }

    #[tokio::test]
    async fn async_plain_roundtrip() {
        let cipher_w = make_cipher();
        let cipher_r = Aes128Gcm::new(&[0x42u8; 16]).expect("aes");
        let mut nw = make_nonce_gen();
        let mut nr = make_nonce_gen();
        let mut sp_w = PlainSizeParser;
        let mut sp_r = PlainSizeParser;

        let data = b"async chunk stream test payload";
        let mut buf: Vec<u8> = Vec::new();
        encode_chunk_stream_async(&mut buf, data, &cipher_w, &mut nw, &mut sp_w, false, false)
            .await
            .expect("encode");

        let decoded = decode_chunk_stream_async(&mut &buf[..], &cipher_r, &mut nr, &mut sp_r, false)
            .await
            .expect("decode");
        assert_eq!(decoded, data);
    }

    #[tokio::test]
    async fn async_authenticated_length_roundtrip() {
        let cipher_w = make_cipher();
        let cipher_r = Aes128Gcm::new(&[0x42u8; 16]).expect("aes");
        let mut nw = make_nonce_gen();
        let mut nr = make_nonce_gen();
        let mut sp_w = make_authenticated_length_size_parser(&[0x42u8; 16], &[0xAAu8; 16], SecurityType::Aes128Gcm).expect("make sp");
        let mut sp_r = make_authenticated_length_size_parser(&[0x42u8; 16], &[0xAAu8; 16], SecurityType::Aes128Gcm).expect("make sp");

        let data = b"async authenticated length payload";
        let mut buf: Vec<u8> = Vec::new();
        encode_chunk_stream_async(&mut buf, data, &cipher_w, &mut nw, &mut sp_w, false, false)
            .await
            .expect("encode");

        let decoded = decode_chunk_stream_async(&mut &buf[..], &cipher_r, &mut nr, &mut sp_r, false)
            .await
            .expect("decode");
        assert_eq!(decoded, data);
    }

    #[tokio::test]
    async fn async_no_termination_signal_skips_termination_chunk() {
        // NoTerminationSignal=true：encode 不写终止 chunk，decode 靠 EOF 结束
        let cipher_w = make_cipher();
        let cipher_r = Aes128Gcm::new(&[0x42u8; 16]).expect("aes");
        let mut nw = make_nonce_gen();
        let mut nr = make_nonce_gen();
        let mut sp_w = PlainSizeParser;
        let mut sp_r = PlainSizeParser;

        let data = b"no term signal payload";
        let mut buf: Vec<u8> = Vec::new();
        encode_chunk_stream_async(&mut buf, data, &cipher_w, &mut nw, &mut sp_w, false, true)
            .await
            .expect("encode");
        // 没有终止 chunk：buf 只有数据 chunk

        let decoded = decode_chunk_stream_async(&mut &buf[..], &cipher_r, &mut nr, &mut sp_r, false)
            .await
            .expect("decode via EOF");
        assert_eq!(decoded, data);
    }

    #[test]
    fn global_padding_disabled_skips_padding_with_shake_parser() {
        // global_padding=false + ShakeSizeParser：不写 padding，SHAKE128 流仍同步
        let cipher_w = make_cipher();
        let cipher_r = Aes128Gcm::new(&[0x42u8; 16]).expect("aes");
        let mut nw = ChunkNonceAdapter::new(&[0xAAu8; 16], 12);
        let mut nr = ChunkNonceAdapter::new(&[0xAAu8; 16], 12);
        let mut sp_w = ShakeSizeParserAdapter::new(&[0x11u8; 16]);
        let mut sp_r = ShakeSizeParserAdapter::new(&[0x11u8; 16]);

        let data = b"shake without global padding";
        let mut buf: Vec<u8> = Vec::new();
        encode_chunk_stream(&mut buf, data, &cipher_w, &mut nw, &mut sp_w, false, false).expect("encode");

        // 验证 encode+decode round-trip 正确（无 padding，SHAKE128 流同步）
        let decoded = decode_chunk_stream(&mut &buf[..], &cipher_r, &mut nr, &mut sp_r, false).expect("decode");
        assert_eq!(decoded, data);
    }

    #[test]
    fn global_padding_enabled_with_shake_parser_roundtrip() {
        // global_padding=true + ShakeSizeParser：写 padding，decode 消费 padding
        let cipher_w = make_cipher();
        let cipher_r = Aes128Gcm::new(&[0x42u8; 16]).expect("aes");
        let mut nw = ChunkNonceAdapter::new(&[0xAAu8; 16], 12);
        let mut nr = ChunkNonceAdapter::new(&[0xAAu8; 16], 12);
        let mut sp_w = ShakeSizeParserAdapter::new(&[0x11u8; 16]);
        let mut sp_r = ShakeSizeParserAdapter::new(&[0x11u8; 16]);

        let data = b"shake with global padding enabled";
        let mut buf: Vec<u8> = Vec::new();
        encode_chunk_stream(&mut buf, data, &cipher_w, &mut nw, &mut sp_w, true, false).expect("encode");

        let decoded = decode_chunk_stream(&mut &buf[..], &cipher_r, &mut nr, &mut sp_r, true).expect("decode");
        assert_eq!(decoded, data);
    }
}
