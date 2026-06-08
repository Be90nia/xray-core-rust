//! Chunk-based size encoding and stream I/O.
//!
//! 对应 Go 版本 `common/crypto/chunk.go`，提供分块大小编解码和流式读写。

use crate::authenticator::Authenticator;
use crate::aead::CryptoError;
use xray_buf::io::{self, Writer};
use xray_buf::buffer::Buffer;
use xray_buf::reader::BufferedReader;
use xray_buf::multi::MultiBuffer;

// ========== ChunkSizeDecoder ==========

/// 分块大小解码器。
///
/// 对应 Go 版本的 `ChunkSizeDecoder` 接口。
pub trait ChunkSizeDecoder: Send + Sync {
    /// 返回编码后的大小字节数。
    fn size_bytes(&self) -> i32;

    /// 从字节解码出大小值。
    fn decode(&self, b: &[u8]) -> Result<u16, CryptoError>;
}

// ========== ChunkSizeEncoder ==========

/// 分块大小编码器。
///
/// 对应 Go 版本的 `ChunkSizeEncoder` 接口。
pub trait ChunkSizeEncoder: Send + Sync {
    /// 返回编码后的大小字节数。
    fn size_bytes(&self) -> i32;

    /// 将大小值编码到字节缓冲区。
    ///
    /// 对应 Go 的 `Encode(size uint16, b []byte) []byte`。
    /// 将编码结果写入 `b` 的前 `size_bytes()` 字节。
    fn encode(&self, size: u16, b: &mut [u8]);
}

// ========== PaddingLengthGenerator ==========

/// 填充长度生成器。
///
/// 对应 Go 版本的 `PaddingLengthGenerator` 接口。
pub trait PaddingLengthGenerator: Send + Sync {
    /// 返回最大填充长度。
    fn max_padding_len(&self) -> u16;

    /// 返回下一个填充长度。
    fn next_padding_len(&self) -> u16;
}

// ========== PlainChunkSizeParser ==========

/// 明文分块大小解析器（2字节大端序）。
///
/// 对应 Go 版本的 `PlainChunkSizeParser`。
/// 零大小结构体，与 Go 的 `struct{}` 一致。
pub struct PlainChunkSizeParser;

impl ChunkSizeDecoder for PlainChunkSizeParser {
    fn size_bytes(&self) -> i32 {
        2
    }

    fn decode(&self, b: &[u8]) -> Result<u16, CryptoError> {
        if b.len() < 2 {
            return Err(CryptoError::EncryptionError(
                "insufficient bytes for chunk size".into(),
            ));
        }
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
}

impl ChunkSizeEncoder for PlainChunkSizeParser {
    fn size_bytes(&self) -> i32 {
        2
    }

    fn encode(&self, size: u16, b: &mut [u8]) {
        let bytes = size.to_be_bytes();
        b[0] = bytes[0];
        b[1] = bytes[1];
    }
}

// ========== AEADChunkSizeParser ==========

/// AEAD 加密的分块大小解析器。
///
/// 对应 Go 版本的 `AEADChunkSizeParser`。
/// 将大小值用 AEAD 加密后传输。
/// 使用 `Box<dyn Authenticator>` 支持动态分发。
pub struct AEADChunkSizeParser {
    auth: Box<dyn Authenticator>,
}

impl AEADChunkSizeParser {
    /// 创建新的 AEAD 分块大小解析器。
    pub fn new(auth: Box<dyn Authenticator>) -> Self {
        Self { auth }
    }
}

impl ChunkSizeDecoder for AEADChunkSizeParser {
    fn size_bytes(&self) -> i32 {
        2 + self.auth.overhead() as i32
    }

    fn decode(&self, b: &[u8]) -> Result<u16, CryptoError> {
        let decrypted = self.auth.open(&mut [], b)?;
        if decrypted.len() < 2 {
            return Err(CryptoError::EncryptionError(
                "decrypted chunk size too short".into(),
            ));
        }
        let size = u16::from_be_bytes([decrypted[0], decrypted[1]]);
        Ok(size + self.auth.overhead() as u16)
    }
}

impl ChunkSizeEncoder for AEADChunkSizeParser {
    fn size_bytes(&self) -> i32 {
        2 + self.auth.overhead() as i32
    }

    fn encode(&self, size: u16, b: &mut [u8]) {
        let plain_size = size - self.auth.overhead() as u16;
        let bytes = plain_size.to_be_bytes();
        let sealed = match self.auth.seal(&mut [], &bytes) {
            Ok(s) => s,
            Err(_) => return,
        };
        let len = sealed.len().min(b.len());
        b[..len].copy_from_slice(&sealed[..len]);
    }
}

// ========== ChunkStreamReader ==========

pub struct ChunkStreamReader<'a> {
    size_decoder: Box<dyn ChunkSizeDecoder>,
    reader: &'a mut BufferedReader,
    size_buffer: Vec<u8>,
    left_over_size: i32,
    max_num_chunk: u32,
    num_chunk: u32,
}

impl<'a> ChunkStreamReader<'a> {
    pub fn new(
        size_decoder: Box<dyn ChunkSizeDecoder>,
        reader: &'a mut BufferedReader,
    ) -> Self {
        Self::with_chunk_count(size_decoder, reader, 0)
    }

    pub fn with_chunk_count(
        size_decoder: Box<dyn ChunkSizeDecoder>,
        reader: &'a mut BufferedReader,
        max_num_chunk: u32,
    ) -> Self {
        let sb = size_decoder.size_bytes() as usize;
        Self {
            size_decoder,
            reader,
            size_buffer: vec![0u8; sb],
            left_over_size: 0,
            max_num_chunk,
            num_chunk: 0,
        }
    }

    async fn read_size(&mut self) -> Result<u16, CryptoError> {
        let n = self.reader.read(&mut self.size_buffer).await;
        if n < self.size_buffer.len() {
            return Err(CryptoError::EncryptionError(
                "insufficient bytes for chunk size".into(),
            ));
        }
        self.size_decoder.decode(&self.size_buffer)
    }

    pub async fn read_multi_buffer(&mut self) -> io::Result<MultiBuffer> {
        let mut size = self.left_over_size;
        if size == 0 {
            self.num_chunk += 1;
            if self.max_num_chunk > 0 && self.num_chunk > self.max_num_chunk {
                return Err(io::Error::Eof);
            }
            let next_size = self.read_size().await.map_err(|_| io::Error::Eof)?;
            if next_size == 0 {
                return Err(io::Error::Eof);
            }
            size = next_size as i32;
        }
        self.left_over_size = size;

        let mb = self.reader.read_at_most(size as usize).await?;
        if !mb.is_empty() {
            self.left_over_size -= mb.len() as i32;
            return Ok(mb);
        }
        Err(io::Error::Eof)
    }
}

// ========== ChunkStreamWriter ==========

pub struct ChunkStreamWriter<'a> {
    size_encoder: Box<dyn ChunkSizeEncoder>,
    writer: &'a mut dyn Writer,
}

impl<'a> ChunkStreamWriter<'a> {
    pub fn new(
        size_encoder: Box<dyn ChunkSizeEncoder>,
        writer: &'a mut dyn Writer,
    ) -> Self {
        Self { size_encoder, writer }
    }

    pub async fn write_multi_buffer(&mut self, mb: MultiBuffer) -> io::Result<()> {
        const SLICE_SIZE: usize = 8192;
        let mb_len = mb.len();
        let mut mb2_write = MultiBuffer::with_capacity(mb_len / 8192 + mb_len / SLICE_SIZE + 2);
        let mut remaining = mb;

        loop {
            let slice = remaining.split_size(SLICE_SIZE);
            let mut size_buf = Buffer::new();
            let sb = self.size_encoder.size_bytes() as usize;
            let writable = size_buf.writable_bytes();
            self.size_encoder.encode(slice.len() as u16, &mut writable[..sb]);
            size_buf.advance_write(sb);
            mb2_write.push(size_buf);
            for buf in slice.into_buffers() {
                mb2_write.push(buf);
            }
            if remaining.is_empty() {
                break;
            }
        }

        self.writer.write_multi_buffer(mb2_write).await
    }
}

// ========== NoPadding ==========

pub struct NoPadding;

impl PaddingLengthGenerator for NoPadding {
    fn max_padding_len(&self) -> u16 { 0 }
    fn next_padding_len(&self) -> u16 { 0 }
}

// ========== ShufflePadding ==========

pub struct ShufflePadding {
    max_padding_len: u16,
}

impl ShufflePadding {
    pub fn new(max_padding_len: u16) -> Self {
        Self { max_padding_len }
    }
}

impl PaddingLengthGenerator for ShufflePadding {
    fn max_padding_len(&self) -> u16 { self.max_padding_len }
    fn next_padding_len(&self) -> u16 {
        if self.max_padding_len == 0 { return 0; }
        crate::rand_between(0, self.max_padding_len as i64) as u16
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticator::{
        generate_aead_nonce_with_size, generate_static_bytes, AEADAuthenticator,
    };
    use crate::aead::Aes128Gcm;

    #[test]
    fn test_plain_chunk_size_parser_size_bytes() {
        let parser = PlainChunkSizeParser;
        assert_eq!(ChunkSizeEncoder::size_bytes(&parser), 2);
        assert_eq!(ChunkSizeDecoder::size_bytes(&parser), 2);
    }

    #[test]
    fn test_plain_chunk_size_encode_decode() {
        let parser = PlainChunkSizeParser;
        let mut buf = [0u8; 2];
        parser.encode(0x1234, &mut buf);
        assert_eq!(buf, [0x12, 0x34]);
        let decoded = parser.decode(&buf).unwrap();
        assert_eq!(decoded, 0x1234);
    }

    #[test]
    fn test_plain_chunk_size_decode_insufficient() {
        let parser = PlainChunkSizeParser;
        assert!(parser.decode(&[0x12]).is_err());
    }

    #[test]
    fn test_plain_chunk_size_roundtrip() {
        let parser = PlainChunkSizeParser;
        for size in [0u16, 1, 100, 8192, 65535] {
            let mut buf = [0u8; 2];
            parser.encode(size, &mut buf);
            assert_eq!(parser.decode(&buf).unwrap(), size);
        }
    }

    fn make_aead_parser() -> AEADChunkSizeParser {
        let cipher = Aes128Gcm::new(&[0u8; 16]).unwrap();
        let auth: Box<dyn Authenticator> = Box::new(AEADAuthenticator::new(
            cipher, generate_static_bytes(vec![0u8; 12]), None,
        ));
        AEADChunkSizeParser::new(auth)
    }

    fn make_aead_parser_pair() -> (AEADChunkSizeParser, AEADChunkSizeParser) {
        let c1 = Aes128Gcm::new(&[0u8; 16]).unwrap();
        let a1: Box<dyn Authenticator> = Box::new(AEADAuthenticator::new(
            c1, generate_static_bytes(vec![0u8; 12]), None,
        ));
        let c2 = Aes128Gcm::new(&[0u8; 16]).unwrap();
        let a2: Box<dyn Authenticator> = Box::new(AEADAuthenticator::new(
            c2, generate_static_bytes(vec![0u8; 12]), None,
        ));
        (AEADChunkSizeParser::new(a1), AEADChunkSizeParser::new(a2))
    }

    #[test]
    fn test_aead_chunk_size_parser_size_bytes() {
        let parser = make_aead_parser();
        assert_eq!(ChunkSizeEncoder::size_bytes(&parser), 18);
        assert_eq!(ChunkSizeDecoder::size_bytes(&parser), 18);
    }

    #[test]
    fn test_aead_chunk_size_encode_decode_roundtrip() {
        let (encoder, decoder) = make_aead_parser_pair();
        let sb = ChunkSizeEncoder::size_bytes(&encoder) as usize;
        let size: u16 = 100 + 16;
        let mut buf = vec![0u8; sb];
        encoder.encode(size, &mut buf);
        let decoded = decoder.decode(&buf).unwrap();
        assert_eq!(decoded, size);
    }

    #[test]
    fn test_aead_chunk_size_encode_decode_multiple() {
        let c1 = Aes128Gcm::new(&[0u8; 16]).unwrap();
        let a1: Box<dyn Authenticator> = Box::new(AEADAuthenticator::new(
            c1, generate_aead_nonce_with_size(12), None,
        ));
        let encoder = AEADChunkSizeParser::new(a1);
        let c2 = Aes128Gcm::new(&[0u8; 16]).unwrap();
        let a2: Box<dyn Authenticator> = Box::new(AEADAuthenticator::new(
            c2, generate_aead_nonce_with_size(12), None,
        ));
        let decoder = AEADChunkSizeParser::new(a2);
        let sb = ChunkSizeEncoder::size_bytes(&encoder) as usize;
        for payload in [0u16, 1, 100, 8192] {
            let size = payload + 16;
            let mut buf = vec![0u8; sb];
            encoder.encode(size, &mut buf);
            let decoded = decoder.decode(&buf).unwrap();
            assert_eq!(decoded, size);
        }
    }

    #[test]
    fn test_aead_chunk_size_decode_garbage() {
        let decoder = make_aead_parser();
        let garbage = vec![0xFFu8; 18];
        assert!(decoder.decode(&garbage).is_err());
    }

    #[test]
    fn test_no_padding() {
        let p = NoPadding;
        assert_eq!(p.max_padding_len(), 0);
        assert_eq!(p.next_padding_len(), 0);
    }

    #[test]
    fn test_shuffle_padding_zero() {
        let p = ShufflePadding::new(0);
        assert_eq!(p.max_padding_len(), 0);
        assert_eq!(p.next_padding_len(), 0);
    }

    #[test]
    fn test_shuffle_padding_in_range() {
        let p = ShufflePadding::new(255);
        assert_eq!(p.max_padding_len(), 255);
        for _ in 0..100 {
            let len = p.next_padding_len();
            assert!(len <= 255);
        }
    }
}
