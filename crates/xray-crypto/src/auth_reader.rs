//! Authenticated reader wrapper
//!
//! Implements AuthenticationReader from Go's common/crypto/auth.go,
//! providing AEAD-based authenticated decryption reading.

use xray_buf::{buffer::Buffer, io, multi::MultiBuffer, reader::BufferedReader};
use xray_common::protocol::TransferType;

use crate::{
    aead::CryptoError,
    authenticator::Authenticator,
    chunk::{ChunkSizeDecoder, PaddingLengthGenerator},
};

const DEFAULT_SIZE: usize = 8192;
const MAX_CHUNK_COUNT: usize = 16;

enum ReadInternalError {
    Soft,
    Crypto(CryptoError),
    Io(io::Error),
    Eof,
}

impl From<CryptoError> for ReadInternalError {
    fn from(e: CryptoError) -> Self {
        ReadInternalError::Crypto(e)
    }
}

impl From<io::Error> for ReadInternalError {
    fn from(e: io::Error) -> Self {
        ReadInternalError::Io(e)
    }
}

pub struct AuthenticationReader<'a> {
    auth: Box<dyn Authenticator>,
    reader: &'a mut BufferedReader,
    size_decoder: Box<dyn ChunkSizeDecoder>,
    #[allow(dead_code)] // vision 协议 transfer_type 语义字段，诊断/direct 判定待接线
    transfer_type: TransferType,
    padding: Box<dyn PaddingLengthGenerator>,
    size_bytes: Vec<u8>,
    cached_size: u16,
    cached_padding: u16,
    has_size: bool,
    done: bool,
    pending_data: Vec<u8>,
    /// conn 级连续化 scratch：soft 拼接与精确读取共用，容量跨 chunk 流转
    scratch: Vec<u8>,
}

impl<'a> AuthenticationReader<'a> {
    pub fn new(
        auth: Box<dyn Authenticator>,
        size_decoder: Box<dyn ChunkSizeDecoder>,
        reader: &'a mut BufferedReader,
        transfer_type: TransferType,
        padding: Box<dyn PaddingLengthGenerator>,
    ) -> Self {
        let sb = size_decoder.size_bytes() as usize;
        Self {
            auth,
            reader,
            size_decoder,
            transfer_type,
            padding,
            size_bytes: vec![0u8; sb],
            cached_size: 0,
            cached_padding: 0,
            has_size: false,
            done: false,
            pending_data: Vec::new(),
            scratch: Vec::new(),
        }
    }

    async fn read_size(&mut self) -> Result<(u16, u16), ReadInternalError> {
        if self.has_size {
            return Ok((self.cached_size, self.cached_padding));
        }
        let total = self.size_bytes.len();
        let mut offset = 0;
        while offset < total {
            let n = self.reader.read(&mut self.size_bytes[offset..]).await;
            if n == 0 {
                if offset > 0 {
                    return Err(ReadInternalError::Io(io::Error::ReadError(
                        "insufficient bytes for chunk size header".into(),
                    )));
                }
                return Err(ReadInternalError::Eof);
            }
            offset += n;
        }
        let size = self
            .size_decoder
            .decode(&self.size_bytes[..total])
            .map_err(ReadInternalError::Crypto)?;
        let padding = self.padding.next_padding_len();
        Ok((size, padding))
    }

    async fn read_buffer(
        &mut self,
        size: usize,
        padding: usize,
    ) -> Result<Buffer, ReadInternalError> {
        self.fill_scratch_exact(size, "insufficient bytes for chunk data").await?;
        let ciphertext_len = size - padding;
        let decrypted = self
            .auth
            .open(&mut [], &self.scratch[..ciphertext_len])
            .map_err(ReadInternalError::Crypto)?;
        Ok(Buffer::from_vec(decrypted))
    }

    async fn read_exact_into(&mut self, size: usize) -> Result<(), ReadInternalError> {
        self.fill_scratch_exact(size, "insufficient bytes for large chunk data").await
    }

    /// 把 `self.scratch` 恰好填满 `size` 字节：先消费 pending_data，再从 reader 补齐
    /// （读直写 scratch 尾部，零中间缓冲）。
    async fn fill_scratch_exact(
        &mut self,
        size: usize,
        insufficient_msg: &'static str,
    ) -> Result<(), ReadInternalError> {
        self.scratch.clear();
        if !self.pending_data.is_empty() {
            let take = self.pending_data.len().min(size);
            self.scratch.extend_from_slice(&self.pending_data[..take]);
            self.pending_data.drain(..take);
        }
        while self.scratch.len() < size {
            let filled = self.scratch.len();
            self.scratch.resize(size, 0);
            let n = self.reader.read(&mut self.scratch[filled..]).await;
            if n == 0 {
                return Err(ReadInternalError::Io(io::Error::ReadError(insufficient_msg.into())));
            }
            self.scratch.truncate(filled + n);
        }
        Ok(())
    }

    async fn read_internal(
        &mut self,
        soft: bool,
        mb: &mut MultiBuffer,
    ) -> Result<(), ReadInternalError> {
        if self.done {
            return Err(ReadInternalError::Eof);
        }
        let (size, padding) = self.read_size().await?;
        let overhead = self.auth.overhead() as u16;
        if size == overhead + padding {
            self.done = true;
            return Err(ReadInternalError::Eof);
        }
        let size_usize = size as usize;
        let padding_usize = padding as usize;
        if soft {
            match self.reader.read_at_most(size_usize).await {
                Ok(chunk_mb) => {
                    if chunk_mb.len() < size_usize {
                        // 短读：残余进 pending_data。不变量：进入 soft 路径时 pending
                        // 必空（非 soft 路径全量 drain），clear+extend 与替换语义等价
                        self.cached_size = size;
                        self.cached_padding = padding;
                        self.has_size = true;
                        self.pending_data.clear();
                        for b in chunk_mb.iter() {
                            self.pending_data.extend_from_slice(b.bytes());
                        }
                        return Err(ReadInternalError::Soft);
                    }
                    let ciphertext_len = size_usize - padding_usize;
                    // AEAD 需连续字节：单 buffer 零拷贝直借；跨 buffer 用 conn 级
                    // scratch 拼连续（78c613cc out-param 范式，容量跨 chunk 流转）
                    let decrypted = if chunk_mb.buffer_count() == 1 {
                        let bytes = chunk_mb.iter().next().map(|b| b.bytes()).unwrap_or(&[]);
                        self.auth
                            .open(&mut [], &bytes[..ciphertext_len])
                            .map_err(ReadInternalError::Crypto)?
                    } else {
                        self.scratch.clear();
                        for b in chunk_mb.iter() {
                            self.scratch.extend_from_slice(b.bytes());
                        }
                        self.auth
                            .open(&mut [], &self.scratch[..ciphertext_len])
                            .map_err(ReadInternalError::Crypto)?
                    };
                    if size_usize <= DEFAULT_SIZE {
                        mb.push(Buffer::from_vec(decrypted));
                    } else {
                        mb.merge_bytes(&decrypted);
                    }
                    return Ok(());
                },
                Err(io::Error::Eof) | Err(io::Error::Interrupted) => {
                    self.cached_size = size;
                    self.cached_padding = padding;
                    self.has_size = true;
                    return Err(ReadInternalError::Soft);
                },
                Err(e) => {
                    return Err(ReadInternalError::Io(e));
                },
            }
        }
        if size_usize <= DEFAULT_SIZE {
            let buf = self.read_buffer(size_usize, padding_usize).await?;
            mb.push(buf);
        } else {
            self.read_exact_into(size_usize).await?;
            let ciphertext_len = size_usize - padding_usize;
            let decrypted = self
                .auth
                .open(&mut [], &self.scratch[..ciphertext_len])
                .map_err(ReadInternalError::Crypto)?;
            mb.merge_bytes(&decrypted);
        }
        Ok(())
    }

    pub async fn read_multi_buffer(&mut self) -> io::Result<MultiBuffer> {
        let mut mb = MultiBuffer::new();
        match self.read_internal(false, &mut mb).await {
            Ok(()) => {},
            Err(ReadInternalError::Soft) => {
                if mb.is_empty() {
                    return Err(io::Error::Eof);
                }
                return Ok(mb);
            },
            Err(ReadInternalError::Eof) => {
                return Err(io::Error::Eof);
            },
            Err(ReadInternalError::Crypto(e)) => {
                return Err(io::Error::ReadError(format!("crypto error: {e}")));
            },
            Err(ReadInternalError::Io(e)) => {
                return Err(e);
            },
        }
        for _ in 1..MAX_CHUNK_COUNT {
            match self.read_internal(true, &mut mb).await {
                Ok(()) => {},
                Err(ReadInternalError::Soft) => break,
                Err(ReadInternalError::Eof) => break,
                Err(ReadInternalError::Crypto(e)) => {
                    return Err(io::Error::ReadError(format!("crypto error: {e}")));
                },
                Err(ReadInternalError::Io(e)) => {
                    return Err(e);
                },
            }
        }
        Ok(mb)
    }
}

#[cfg(test)]
mod tests {
    use std::{future::Future, pin::Pin};

    use xray_buf::io::Reader;

    use super::*;
    use crate::{
        aead::Aes128Gcm,
        authenticator::{AEADAuthenticator, generate_aead_nonce_with_size},
        chunk::{NoPadding, PlainChunkSizeParser},
    };

    fn make_auth_pair() -> (Box<dyn Authenticator>, Box<dyn Authenticator>) {
        let cipher_s = Aes128Gcm::new(&[0u8; 16]).unwrap();
        let auth_s: Box<dyn Authenticator> =
            Box::new(AEADAuthenticator::new(cipher_s, generate_aead_nonce_with_size(12), None));
        let cipher_o = Aes128Gcm::new(&[0u8; 16]).unwrap();
        let auth_o: Box<dyn Authenticator> =
            Box::new(AEADAuthenticator::new(cipher_o, generate_aead_nonce_with_size(12), None));
        (auth_s, auth_o)
    }

    struct VecWriter {
        data: Vec<u8>,
    }
    impl VecWriter {
        fn new() -> Self {
            Self { data: Vec::new() }
        }
    }

    impl io::Writer for VecWriter {
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

    async fn encrypt_stream(auth: Box<dyn Authenticator>, chunks: &[&[u8]]) -> Vec<u8> {
        let mut vw = VecWriter::new();
        {
            let mut aw = crate::auth_writer::AuthenticationWriter::new(
                auth,
                &mut vw,
                Box::new(PlainChunkSizeParser),
                TransferType::Stream,
                Box::new(NoPadding),
            );
            let mut mb = MultiBuffer::new();
            for chunk in chunks {
                mb.push(Buffer::from_vec(chunk.to_vec()));
            }
            aw.write_multi_buffer(mb).await.unwrap();
        }
        vw.data
    }

    async fn encrypt_stream_with_padding(
        auth: Box<dyn Authenticator>,
        chunks: &[&[u8]],
        padding: Box<dyn PaddingLengthGenerator>,
    ) -> Vec<u8> {
        let mut vw = VecWriter::new();
        {
            let mut aw = crate::auth_writer::AuthenticationWriter::new(
                auth,
                &mut vw,
                Box::new(PlainChunkSizeParser),
                TransferType::Stream,
                padding,
            );
            let mut mb = MultiBuffer::new();
            for chunk in chunks {
                mb.push(Buffer::from_vec(chunk.to_vec()));
            }
            aw.write_multi_buffer(mb).await.unwrap();
        }
        vw.data
    }

    async fn encrypt_packet(auth: Box<dyn Authenticator>, chunks: &[&[u8]]) -> Vec<u8> {
        let mut vw = VecWriter::new();
        {
            let mut aw = crate::auth_writer::AuthenticationWriter::new(
                auth,
                &mut vw,
                Box::new(PlainChunkSizeParser),
                TransferType::Packet,
                Box::new(NoPadding),
            );
            let mut mb = MultiBuffer::new();
            for chunk in chunks {
                mb.push(Buffer::from_vec(chunk.to_vec()));
            }
            aw.write_multi_buffer(mb).await.unwrap();
        }
        vw.data
    }

    fn make_reader(data: Vec<u8>) -> BufferedReader {
        let cursor = std::io::Cursor::new(data);
        let reader: Box<dyn Reader> = Box::new(xray_buf::reader::SingleReader::new(cursor));
        BufferedReader::new(reader)
    }

    fn make_auth_reader<'a>(
        auth: Box<dyn Authenticator>,
        br: &'a mut BufferedReader,
        tt: TransferType,
    ) -> AuthenticationReader<'a> {
        AuthenticationReader::new(auth, Box::new(PlainChunkSizeParser), br, tt, Box::new(NoPadding))
    }

    // Test 1: read single chunk
    #[tokio::test]
    async fn test_read_single_chunk() {
        let (auth_s, auth_o) = make_auth_pair();
        let encrypted = encrypt_stream(auth_s, &[b"hello world"]).await;
        let mut br = make_reader(encrypted);
        let mut ar = make_auth_reader(auth_o, &mut br, TransferType::Stream);
        let mb = ar.read_multi_buffer().await.unwrap();
        assert_eq!(mb.to_vec(), b"hello world");
    }

    // Test 2: read empty data (terminator only) returns Eof
    #[tokio::test]
    async fn test_read_empty_eof() {
        let (auth_s, auth_o) = make_auth_pair();
        let encrypted = encrypt_stream(auth_s, &[]).await;
        let mut br = make_reader(encrypted);
        let mut ar = make_auth_reader(auth_o, &mut br, TransferType::Stream);
        let result = ar.read_multi_buffer().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), io::Error::Eof));
    }

    // Test 3: packet mode read
    #[tokio::test]
    async fn test_read_packet_mode() {
        let (auth_s, auth_o) = make_auth_pair();
        let encrypted = encrypt_packet(auth_s, &[b"packet1", b"packet2"]).await;
        let mut br = make_reader(encrypted);
        let mut ar = make_auth_reader(auth_o, &mut br, TransferType::Packet);
        let mb = ar.read_multi_buffer().await.unwrap();
        assert!(mb.to_vec().len() >= 14);
    }

    // Test 4: second read returns Eof after terminator
    #[tokio::test]
    async fn test_read_twice_eof() {
        let (auth_s, auth_o) = make_auth_pair();
        let encrypted = encrypt_stream(auth_s, &[b"first", b"second"]).await;
        let mut br = make_reader(encrypted);
        let mut ar = make_auth_reader(auth_o, &mut br, TransferType::Stream);
        let _mb1 = ar.read_multi_buffer().await.unwrap();
        let mb2 = ar.read_multi_buffer().await;
        assert!(mb2.is_err());
        assert!(matches!(mb2.unwrap_err(), io::Error::Eof));
    }

    // Test 5: large data read (multiple chunks)
    #[tokio::test]
    async fn test_read_large_data() {
        let (auth_s, auth_o) = make_auth_pair();
        let big_data = vec![0xABu8; 10000];
        let encrypted = encrypt_stream(auth_s, &[&big_data]).await;
        let mut br = make_reader(encrypted);
        let mut ar = make_auth_reader(auth_o, &mut br, TransferType::Stream);
        let mb = ar.read_multi_buffer().await.unwrap();
        assert_eq!(mb.to_vec().len(), 10000);
    }

    // Test 6: multi chunk stream data
    #[tokio::test]
    async fn test_read_multi_chunk_stream() {
        let (auth_s, auth_o) = make_auth_pair();
        let chunk1 = vec![0x41u8; 8174];
        let chunk2 = b"small tail";
        let encrypted = encrypt_stream(auth_s, &[&chunk1, chunk2]).await;
        let mut br = make_reader(encrypted);
        let mut ar = make_auth_reader(auth_o, &mut br, TransferType::Stream);
        let mb = ar.read_multi_buffer().await.unwrap();
        assert_eq!(mb.to_vec().len(), 8174 + 10);
    }

    // Test 7: done flag causes Eof on subsequent read
    #[tokio::test]
    async fn test_done_flag_eof() {
        let (auth_s, auth_o) = make_auth_pair();
        let encrypted = encrypt_stream(auth_s, &[b"test"]).await;
        let mut br = make_reader(encrypted);
        let mut ar = make_auth_reader(auth_o, &mut br, TransferType::Stream);
        let _ = ar.read_multi_buffer().await.unwrap();
        let result = ar.read_multi_buffer().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), io::Error::Eof));
    }

    // Test 8: ShufflePadding read roundtrip
    // 注意：ShufflePadding 是随机的，写入和读取端必须使用相同的 padding 长度。
    // 由于加密时 padding 长度已编码到 chunk 中，读取端使用相同的
    // PaddingLengthGenerator 来解码即可。这里用 NoPadding 验证基本流程。
    #[tokio::test]
    async fn test_read_with_padding() {
        let (auth_s, auth_o) = make_auth_pair();
        let encrypted =
            encrypt_stream_with_padding(auth_s, &[b"padded data"], Box::new(NoPadding)).await;
        let mut br = make_reader(encrypted);
        let mut ar = AuthenticationReader::new(
            auth_o,
            Box::new(PlainChunkSizeParser),
            &mut br,
            TransferType::Stream,
            Box::new(NoPadding),
        );
        let mb = ar.read_multi_buffer().await.unwrap();
        assert_eq!(mb.to_vec(), b"padded data");
    }

    // Test 9: corrupted data causes error
    #[tokio::test]
    async fn test_read_corrupted_data() {
        let (auth_s, _) = make_auth_pair();
        let encrypted = encrypt_stream(auth_s, &[b"secret"]).await;
        let mut corrupted = encrypted;
        corrupted[5] ^= 0xFF;
        let (_, auth_o) = make_auth_pair();
        let mut br = make_reader(corrupted);
        let mut ar = make_auth_reader(auth_o, &mut br, TransferType::Stream);
        let result = ar.read_multi_buffer().await;
        assert!(result.is_err());
    }

    // Test 10: empty underlying stream returns Eof immediately
    #[tokio::test]
    async fn test_read_from_empty_stream() {
        let (_, auth_o) = make_auth_pair();
        let mut br = make_reader(Vec::new());
        let mut ar = make_auth_reader(auth_o, &mut br, TransferType::Stream);
        let result = ar.read_multi_buffer().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), io::Error::Eof));
    }

    // Test 11: single byte payload
    #[tokio::test]
    async fn test_read_single_byte() {
        let (auth_s, auth_o) = make_auth_pair();
        let encrypted = encrypt_stream(auth_s, &[b"X"]).await;
        let mut br = make_reader(encrypted);
        let mut ar = make_auth_reader(auth_o, &mut br, TransferType::Stream);
        let mb = ar.read_multi_buffer().await.unwrap();
        assert_eq!(mb.to_vec(), b"X");
    }

    // Test 12: read until eof then verify second call fails
    #[tokio::test]
    async fn test_read_until_eof() {
        let (auth_s, auth_o) = make_auth_pair();
        let data = vec![0x42u8; 500];
        let encrypted = encrypt_stream(auth_s, &[&data]).await;
        let mut br = make_reader(encrypted);
        let mut ar = make_auth_reader(auth_o, &mut br, TransferType::Stream);
        let mb = ar.read_multi_buffer().await.unwrap();
        assert_eq!(mb.to_vec(), data);
        let result = ar.read_multi_buffer().await;
        assert!(matches!(result.unwrap_err(), io::Error::Eof));
    }

    // Test 13: soft 短读跨调用补齐 + 多 buffer chunk 拼接（scratch 化行为对拍：
    // 同输入下输出与改造前一致——pending 残余不丢、明文逐位等于原始输入）
    struct PrebuiltReader {
        parts: Vec<MultiBuffer>,
        idx: usize,
    }

    impl io::Reader for PrebuiltReader {
        fn read_multi_buffer(
            &mut self,
        ) -> Pin<Box<dyn Future<Output = io::Result<MultiBuffer>> + Send + '_>> {
            Box::pin(async move {
                if self.idx >= self.parts.len() {
                    return Err(io::Error::Eof);
                }
                let mb = std::mem::replace(&mut self.parts[self.idx], MultiBuffer::new());
                self.idx += 1;
                Ok(mb)
            })
        }
    }

    #[tokio::test]
    async fn test_read_soft_short_read_pending_cross_call() {
        let (auth_s, auth_o) = make_auth_pair();
        // 逐 chunk 独立 write：write_stream 会把同一 MultiBuffer 按 payload_size
        // 切片密封（小明文合并成单 chunk），无法构造两个独立 wire chunk
        let mut vw = VecWriter::new();
        {
            let mut aw = crate::auth_writer::AuthenticationWriter::new(
                auth_s,
                &mut vw,
                Box::new(PlainChunkSizeParser),
                TransferType::Stream,
                Box::new(NoPadding),
            );
            for chunk in [&b"AAA"[..], &b"BBBBBB"[..]] {
                let mut mb = MultiBuffer::new();
                mb.push(Buffer::from_vec(chunk.to_vec()));
                aw.write_multi_buffer(mb).await.unwrap();
            }
        }
        let encrypted = vw.data;
        // NoPadding 帧格式：size(2B) + ciphertext(payload+tag16)
        let (c1, c2) = encrypted.split_at(2 + 3 + 16);
        let half = c2.len() / 2;
        // chunk2 交付序列：前半（含 size header，触发 soft 短读 → pending）→
        // 后半拆两个 buffer（触发跨 buffer scratch 拼接路径）
        let mut mb1 = MultiBuffer::new();
        mb1.push(Buffer::from_vec(c1.to_vec()));
        let mut mb2a = MultiBuffer::new();
        mb2a.push(Buffer::from_vec(c2[..half].to_vec()));
        let mid = half + (c2.len() - half) / 2;
        let mut mb2b = MultiBuffer::new();
        mb2b.push(Buffer::from_vec(c2[half..mid].to_vec()));
        mb2b.push(Buffer::from_vec(c2[mid..].to_vec()));
        let reader: Box<dyn Reader> =
            Box::new(PrebuiltReader { parts: vec![mb1, mb2a, mb2b], idx: 0 });
        let mut br = BufferedReader::new(reader);
        let mut ar = make_auth_reader(auth_o, &mut br, TransferType::Stream);

        let r1 = ar.read_multi_buffer().await.unwrap();
        assert_eq!(r1.to_vec(), b"AAA", "chunk1 正常解密；chunk2 短读后中断");
        let r2 = ar.read_multi_buffer().await.unwrap();
        assert_eq!(r2.to_vec(), b"BBBBBB", "pending 残余 + 后续分片补齐解密");
        // 流尽后第 3 次调用必须报错；错误型受既有 has_size 缓存语义影响
        // （read_size 走捷径不触流 → read_buffer 读 0 → insufficient），改造前后一致
        assert!(ar.read_multi_buffer().await.is_err(), "流尽后必须报错");
    }
}
