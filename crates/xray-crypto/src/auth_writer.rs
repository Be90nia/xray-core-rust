//! Authenticated writer wrapper
//!
//! 对应 Go 版本 `common/crypto/auth.go` 中的 `AuthenticationWriter`，
//! 提供基于 AEAD 的认证加密写入能力。
//!
//! # 核心类型
//!
//! - [`AuthenticationWriter`] — 认证加密写入器
//!
//! # 工作模式
//!
//! - **Stream 模式**: 将数据按 payloadSize 分块，每块 seal 加密后写入， 最后写入 0 长度终止标记
//! - **Packet 模式**: 逐个 Buffer 独立 seal 加密后写入
//!
//! # 数据格式
//!
//! 每个加密块格式: `[size_bytes][encrypted_payload][padding]`
//!
//! - `size_bytes`: ChunkSizeEncoder 编码的长度（含 overhead + padding）
//! - `encrypted_payload`: AEAD 密文（len + overhead）
//! - `padding`: 随机填充字节

use xray_buf::{
    buffer::Buffer,
    io::{self, Writer},
    multi::MultiBuffer,
};
use xray_common::protocol::TransferType;

use crate::{
    aead::CryptoError,
    authenticator::Authenticator,
    chunk::{ChunkSizeEncoder, PaddingLengthGenerator},
};

/// 默认缓冲区大小 (8KB)，对应 Go 的 `buf.Size`。
const DEFAULT_SIZE: usize = 8192;

// ========== AuthenticationWriter ==========

/// 认证加密写入器。
///
/// 对应 Go 版本的 `AuthenticationWriter`。
/// 将明文数据通过 AEAD seal 加密后写入底层 Writer。
///
/// # 字段
///
/// - `auth`: 认证加密器（提供 Seal/Open）
/// - `writer`: 底层异步写入器
/// - `size_encoder`: 分块大小编码器（明文或 AEAD 加密）
/// - `transfer_type`: 传输类型（Stream/Packet）
/// - `padding`: 填充长度生成器
pub struct AuthenticationWriter<'a> {
    auth: Box<dyn Authenticator>,
    writer: &'a mut dyn Writer,
    size_encoder: Box<dyn ChunkSizeEncoder>,
    transfer_type: TransferType,
    padding: Box<dyn PaddingLengthGenerator>,
}

impl<'a> AuthenticationWriter<'a> {
    /// 创建新的认证加密写入器。
    ///
    /// 对应 Go 的 `NewAuthenticationWriter`。
    pub fn new(
        auth: Box<dyn Authenticator>,
        writer: &'a mut dyn Writer,
        size_encoder: Box<dyn ChunkSizeEncoder>,
        transfer_type: TransferType,
        padding: Box<dyn PaddingLengthGenerator>,
    ) -> Self {
        Self { auth, writer, size_encoder, transfer_type, padding }
    }

    /// 加密单个数据块。
    ///
    /// 对应 Go 的 `AuthenticationWriter.seal(b []byte) (*buf.Buffer, error)`。
    ///
    /// # 逻辑
    ///
    /// 1. encryptedSize = len(b) + auth.overhead()
    /// 2. paddingSize = padding.next_padding_len()
    /// 3. sizeBytes = size_encoder.size_bytes()
    /// 4. totalSize = sizeBytes + encryptedSize + paddingSize
    /// 5. 如果 totalSize > DEFAULT_SIZE → 返回错误
    /// 6. 编码 size(encryptedSize + paddingSize) 到前 sizeBytes 字节
    /// 7. seal 加密 payload 到 encryptedSize 字节
    /// 8. 填充 paddingSize 随机字节
    fn seal(&self, data: &[u8]) -> Result<Buffer, CryptoError> {
        let encrypted_size = data.len() + self.auth.overhead();
        let padding_size = self.padding.next_padding_len() as usize;
        let size_bytes = self.size_encoder.size_bytes() as usize;
        let total_size = size_bytes + encrypted_size + padding_size;

        if total_size > DEFAULT_SIZE {
            return Err(CryptoError::EncryptionError(format!(
                "seal: total size {} exceeds buffer size {}",
                total_size, DEFAULT_SIZE
            )));
        }

        let mut eb = Buffer::with_capacity(total_size);

        // 1. 编码 size (encryptedSize + paddingSize) 到前 sizeBytes 字节
        let size_value = (encrypted_size + padding_size) as u16;
        {
            let writable = eb.writable_bytes();
            self.size_encoder.encode(size_value, &mut writable[..size_bytes]);
        }
        eb.advance_write(size_bytes);

        // 2. seal 加密 payload
        let sealed = self.auth.seal(&mut [], data)?;
        {
            let writable = eb.writable_bytes();
            let seal_len = sealed.len().min(writable.len());
            writable[..seal_len].copy_from_slice(&sealed[..seal_len]);
        }
        eb.advance_write(sealed.len());

        // 3. 填充 padding 随机字节
        if padding_size > 0 {
            let writable = eb.writable_bytes();
            crate::rand_bytes_between(&mut writable[..padding_size], 0, 255);
            eb.advance_write(padding_size);
        }

        Ok(eb)
    }

    /// Stream 模式写入。
    ///
    /// 对应 Go 的 `AuthenticationWriter.writeStream(mb MultiBuffer) error`。
    ///
    /// # 逻辑
    ///
    /// 1. 计算 payloadSize = DEFAULT_SIZE - overhead - sizeBytes - maxPadding
    /// 2. 按 payloadSize 分块 split_bytes
    /// 3. 每块 seal 加密
    /// 4. 一次性写入所有加密块
    async fn write_stream(&mut self, mut mb: MultiBuffer) -> io::Result<()> {
        let max_padding = self.padding.max_padding_len() as usize;
        let payload_size = DEFAULT_SIZE
            - self.auth.overhead()
            - self.size_encoder.size_bytes() as usize
            - max_padding;

        let mut mb2_write = MultiBuffer::new();

        while !mb.is_empty() {
            let chunk = mb.split_bytes(payload_size);
            let chunk_data = chunk.to_vec();
            match self.seal(&chunk_data) {
                Ok(encrypted_buf) => mb2_write.push(encrypted_buf),
                Err(_) => {
                    return Err(io::Error::WriteError("seal failed in write_stream".into()));
                },
            }
        }

        self.writer.write_multi_buffer(mb2_write).await
    }

    /// Packet 模式写入。
    ///
    /// 对应 Go 的 `AuthenticationWriter.writePacket(mb MultiBuffer) error`。
    ///
    /// # 逻辑
    ///
    /// 1. 逐个 Buffer seal 加密
    /// 2. 跳过空 Buffer 和 seal 失败的 Buffer
    /// 3. 如果没有有效数据，直接返回 Ok
    /// 4. 一次性写入所有加密块
    async fn write_packet(&mut self, mb: MultiBuffer) -> io::Result<()> {
        let mut mb2_write = MultiBuffer::new();

        for buf in mb.into_buffers() {
            if buf.is_empty() {
                continue;
            }
            if let Ok(encrypted_buf) = self.seal(buf.bytes()) {
                mb2_write.push(encrypted_buf);
            }
        }

        if mb2_write.is_empty() {
            return Ok(());
        }

        self.writer.write_multi_buffer(mb2_write).await
    }

    /// 写入多缓冲区数据。
    ///
    /// 对应 Go 的 `AuthenticationWriter.WriteMultiBuffer(mb MultiBuffer) error`。
    ///
    /// # 逻辑
    ///
    /// - 如果 mb 为空: seal([]) → 写入 0 长度终止标记
    /// - Stream 模式: write_stream
    /// - Packet 模式: write_packet
    pub async fn write_multi_buffer(&mut self, mb: MultiBuffer) -> io::Result<()> {
        if mb.is_empty() {
            // 写入 0 长度终止标记
            let terminator = self
                .seal(&[])
                .map_err(|e| io::Error::WriteError(format!("seal terminator failed: {e}")))?;
            let mb_term = MultiBuffer::from_buffer(terminator);
            return self.writer.write_multi_buffer(mb_term).await;
        }

        match self.transfer_type {
            TransferType::Stream => self.write_stream(mb).await,
            TransferType::Packet => self.write_packet(mb).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{future::Future, pin::Pin};

    use super::*;
    use crate::{
        aead::Aes128Gcm,
        authenticator::{AEADAuthenticator, generate_aead_nonce_with_size},
        chunk::{NoPadding, PlainChunkSizeParser, ShufflePadding},
    };

    /// 辅助: 创建测试用 Authenticator（递增 nonce）
    fn make_auth() -> Box<dyn Authenticator> {
        let cipher = Aes128Gcm::new(&[0u8; 16]).unwrap();
        Box::new(AEADAuthenticator::new(cipher, generate_aead_nonce_with_size(12), None))
    }

    /// 辅助: 创建测试用 ChunkSizeEncoder
    fn make_size_encoder() -> Box<dyn ChunkSizeEncoder> {
        Box::new(PlainChunkSizeParser)
    }

    /// 辅助: 创建 Buffer
    fn make_buffer(data: &[u8]) -> Buffer {
        Buffer::from_vec(data.to_vec())
    }

    /// 辅助: 收集写入数据的 Writer mock
    struct VecWriter {
        data: Vec<u8>,
    }

    impl VecWriter {
        fn new() -> Self {
            Self { data: Vec::new() }
        }
    }

    impl Writer for VecWriter {
        fn write_multi_buffer(
            &mut self,
            mb: MultiBuffer,
        ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
            Box::pin(async move {
                for buf in mb.into_buffers() {
                    self.data.extend_from_slice(buf.bytes());
                }
                Ok(())
            })
        }
    }

    // ========== 测试 1: seal 基本功能 ==========

    #[test]
    fn test_seal_basic() {
        let auth = make_auth();
        let size_encoder = make_size_encoder();
        let padding: Box<dyn PaddingLengthGenerator> = Box::new(NoPadding);
        let mut vec_writer = VecWriter::new();

        let aw = AuthenticationWriter::new(
            auth,
            &mut vec_writer,
            size_encoder,
            TransferType::Stream,
            padding,
        );

        let result = aw.seal(b"hello");
        assert!(result.is_ok());
        let buf = result.unwrap();
        // size_bytes(2) + encrypted(5 + 16) + padding(0) = 23
        assert_eq!(buf.len(), 23);
    }

    // ========== 测试 2: seal 空数据（终止标记）==========

    #[test]
    fn test_seal_empty() {
        let auth = make_auth();
        let size_encoder = make_size_encoder();
        let padding: Box<dyn PaddingLengthGenerator> = Box::new(NoPadding);
        let mut vec_writer = VecWriter::new();

        let aw = AuthenticationWriter::new(
            auth,
            &mut vec_writer,
            size_encoder,
            TransferType::Stream,
            padding,
        );

        let result = aw.seal(&[]);
        assert!(result.is_ok());
        let buf = result.unwrap();
        // size_bytes(2) + encrypted(0 + 16) + padding(0) = 18
        assert_eq!(buf.len(), 18);
    }

    // ========== 测试 3: seal 超大数据报错 ==========

    #[test]
    fn test_seal_size_too_large() {
        let auth = make_auth();
        let size_encoder = make_size_encoder();
        let padding: Box<dyn PaddingLengthGenerator> = Box::new(NoPadding);
        let mut vec_writer = VecWriter::new();

        let aw = AuthenticationWriter::new(
            auth,
            &mut vec_writer,
            size_encoder,
            TransferType::Stream,
            padding,
        );

        // 构造超大数据: DEFAULT_SIZE - size_bytes(2) - overhead(16) + 1 = 8175
        let big_data = vec![0u8; DEFAULT_SIZE - 2 - 16 + 1];
        let result = aw.seal(&big_data);
        assert!(result.is_err());
    }

    // ========== 测试 4: seal 带 padding ==========

    #[test]
    fn test_seal_with_padding() {
        let auth = make_auth();
        let size_encoder = make_size_encoder();
        let padding: Box<dyn PaddingLengthGenerator> = Box::new(ShufflePadding::new(16));
        let mut vec_writer = VecWriter::new();

        let aw = AuthenticationWriter::new(
            auth,
            &mut vec_writer,
            size_encoder,
            TransferType::Stream,
            padding,
        );

        let result = aw.seal(b"test");
        assert!(result.is_ok());
        let buf = result.unwrap();
        // size_bytes(2) + encrypted(4 + 16) + padding(0..16)
        // 长度在 [22, 38] 范围内
        assert!(buf.len() >= 22);
        assert!(buf.len() <= 38);
    }

    // ========== 测试 5: write_multi_buffer 空数据写入终止标记 ==========

    #[tokio::test]
    async fn test_write_multi_buffer_empty() {
        let auth = make_auth();
        let size_encoder = make_size_encoder();
        let padding: Box<dyn PaddingLengthGenerator> = Box::new(NoPadding);
        let mut vec_writer = VecWriter::new();

        let mut aw = AuthenticationWriter::new(
            auth,
            &mut vec_writer,
            size_encoder,
            TransferType::Stream,
            padding,
        );

        let mb = MultiBuffer::new();
        let result = aw.write_multi_buffer(mb).await;
        assert!(result.is_ok());
        // 终止标记: size_bytes(2) + encrypted(0+16) = 18 字节
        assert_eq!(vec_writer.data.len(), 18);
    }

    // ========== 测试 6: Stream 模式写入小数据 ==========

    #[tokio::test]
    async fn test_write_stream_small() {
        let auth = make_auth();
        let size_encoder = make_size_encoder();
        let padding: Box<dyn PaddingLengthGenerator> = Box::new(NoPadding);
        let mut vec_writer = VecWriter::new();

        let mut aw = AuthenticationWriter::new(
            auth,
            &mut vec_writer,
            size_encoder,
            TransferType::Stream,
            padding,
        );

        let mb = MultiBuffer::from_buffer(make_buffer(b"hello world"));
        let result = aw.write_multi_buffer(mb).await;
        assert!(result.is_ok());
        assert!(!vec_writer.data.is_empty());
    }

    // ========== 测试 7: Packet 模式写入 ==========

    #[tokio::test]
    async fn test_write_packet() {
        let auth = make_auth();
        let size_encoder = make_size_encoder();
        let padding: Box<dyn PaddingLengthGenerator> = Box::new(NoPadding);
        let mut vec_writer = VecWriter::new();

        let mut aw = AuthenticationWriter::new(
            auth,
            &mut vec_writer,
            size_encoder,
            TransferType::Packet,
            padding,
        );

        let mut mb = MultiBuffer::new();
        mb.push(make_buffer(b"packet1"));
        mb.push(make_buffer(b"packet2"));
        let result = aw.write_multi_buffer(mb).await;
        assert!(result.is_ok());
        // 两个 packet 各自 seal: 2 * (2 + 7 + 16) = 50
        assert!(!vec_writer.data.is_empty());
    }

    // ========== 测试 8: Packet 模式跳过空 Buffer ==========

    #[tokio::test]
    async fn test_write_packet_skip_empty() {
        let auth = make_auth();
        let size_encoder = make_size_encoder();
        let padding: Box<dyn PaddingLengthGenerator> = Box::new(NoPadding);
        let mut vec_writer = VecWriter::new();

        let mut aw = AuthenticationWriter::new(
            auth,
            &mut vec_writer,
            size_encoder,
            TransferType::Packet,
            padding,
        );

        let mut mb = MultiBuffer::new();
        mb.push(Buffer::new()); // 空 Buffer
        mb.push(make_buffer(b"data"));
        mb.push(Buffer::new()); // 空 Buffer
        let result = aw.write_multi_buffer(mb).await;
        assert!(result.is_ok());
        // 只有 1 个有效 packet 被 seal
        assert!(!vec_writer.data.is_empty());
    }

    // ========== 测试 9: Packet 模式全部空 Buffer 写入终止标记 ==========

    #[tokio::test]
    async fn test_write_packet_all_empty() {
        let auth = make_auth();
        let size_encoder = make_size_encoder();
        let padding: Box<dyn PaddingLengthGenerator> = Box::new(NoPadding);
        let mut vec_writer = VecWriter::new();

        let mut aw = AuthenticationWriter::new(
            auth,
            &mut vec_writer,
            size_encoder,
            TransferType::Packet,
            padding,
        );

        // MultiBuffer with only empty Buffers is considered empty (is_empty() == true)
        // so write_multi_buffer writes a terminator instead
        let mut mb = MultiBuffer::new();
        mb.push(Buffer::new());
        mb.push(Buffer::new());
        let result = aw.write_multi_buffer(mb).await;
        assert!(result.is_ok());
        // 写入终止标记: size_bytes(2) + encrypted(0+16) = 18
        assert_eq!(vec_writer.data.len(), 18);
    }

    // ========== 测试 10: Stream 模式大数据分块 ==========

    #[tokio::test]
    async fn test_write_stream_large_data() {
        let auth = make_auth();
        let size_encoder = make_size_encoder();
        let padding: Box<dyn PaddingLengthGenerator> = Box::new(NoPadding);
        let mut vec_writer = VecWriter::new();

        let mut aw = AuthenticationWriter::new(
            auth,
            &mut vec_writer,
            size_encoder,
            TransferType::Stream,
            padding,
        );

        // payloadSize = 8192 - 16 - 2 - 0 = 8174
        // 写入 10000 字节，应分成 2 个 chunk
        let big_data = vec![0xABu8; 10000];
        let mb = MultiBuffer::from_buffer(make_buffer(&big_data));
        let result = aw.write_multi_buffer(mb).await;
        assert!(result.is_ok());
        // chunk1: 8174 字节 -> seal -> 2 + 8174 + 16 = 8192
        // chunk2: 1826 字节 -> seal -> 2 + 1826 + 16 = 1844
        // 总计: 8192 + 1844 = 10036
        assert_eq!(vec_writer.data.len(), 10036);
    }

    // ========== 测试 11: seal 输出大小字段正确性 ==========

    #[test]
    fn test_seal_size_field_encoding() {
        let auth = make_auth();
        let size_encoder = make_size_encoder();
        let padding: Box<dyn PaddingLengthGenerator> = Box::new(NoPadding);
        let mut vec_writer = VecWriter::new();

        let aw = AuthenticationWriter::new(
            auth,
            &mut vec_writer,
            size_encoder,
            TransferType::Stream,
            padding,
        );

        let result = aw.seal(b"hello").unwrap();
        let bytes = result.bytes();
        // 前 2 字节是 BE u16 编码的 size = encryptedSize + paddingSize = 21 + 0 = 21
        let size_val = u16::from_be_bytes([bytes[0], bytes[1]]);
        assert_eq!(size_val, 21); // 5 + 16 = 21
    }

    // ========== 测试 12: Stream 模式精确单块数据 ==========

    #[tokio::test]
    async fn test_write_stream_exact_single_chunk() {
        let auth = make_auth();
        let size_encoder = make_size_encoder();
        let padding: Box<dyn PaddingLengthGenerator> = Box::new(NoPadding);
        let mut vec_writer = VecWriter::new();

        let mut aw = AuthenticationWriter::new(
            auth,
            &mut vec_writer,
            size_encoder,
            TransferType::Stream,
            padding,
        );

        // payloadSize = 8192 - 16 - 2 = 8174
        // 精确写入一个 payloadSize 的数据
        let data = vec![0x42u8; 8174];
        let mb = MultiBuffer::from_buffer(make_buffer(&data));
        let result = aw.write_multi_buffer(mb).await;
        assert!(result.is_ok());
        // 1 个 chunk: 2 + 8174 + 16 = 8192
        assert_eq!(vec_writer.data.len(), 8192);
    }
}
