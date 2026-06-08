//! 加密流读写器
//!
//! 对应 Go 版本 `common/crypto/io.go`，提供 CryptionReader 和 CryptionWriter。
//! 将同步流密码（AES-CFB/CTR、ChaCha20）与异步 I/O 读写器组合，
//! 实现透明的加密写入和解密读取。
//!
//! # 核心类型
//!
//! - [`StreamCipher`] — 同步流密码 trait，统一 XORKeyStream 接口
//! - [`CryptionReader`] — 解密读取器：从 BufferedReader 读取密文并解密
//! - [`CryptionWriter`] — 加密写入器：加密明文后写入 Writer

use crate::aead::{
    AesCfbDecryptor, AesCfbEncryptor, AesCtrStream, ChaCha20Stream, CryptoError,
};
use xray_buf::io::{self, Writer};
use xray_buf::reader::BufferedReader;
use xray_buf::multi::MultiBuffer;
use xray_buf::buffer::Buffer;

// ========== StreamCipher trait ==========

/// 同步流密码接口。
///
/// 对应 Go 的 `cipher.Stream`，提供原地 XOR 密钥流操作。
/// 所有流密码实现（AES-CFB、AES-CTR、ChaCha20）都实现此 trait。
pub trait StreamCipher: Send {
    /// 对数据原地应用密钥流（XOR 操作）。
    ///
    /// 对应 Go 的 `cipher.Stream.XORKeyStream(dst, src)`。
    /// 在 CryptionReader 中用于解密，在 CryptionWriter 中用于加密。
    fn xor_key_stream(&mut self, data: &mut [u8]);
}

// ========== StreamCipher 实现 ==========

impl StreamCipher for AesCfbEncryptor {
    fn xor_key_stream(&mut self, data: &mut [u8]) {
        self.encrypt(data);
    }
}

impl StreamCipher for AesCfbDecryptor {
    fn xor_key_stream(&mut self, data: &mut [u8]) {
        self.decrypt(data);
    }
}

impl StreamCipher for AesCtrStream {
    fn xor_key_stream(&mut self, data: &mut [u8]) {
        self.apply_keystream(data);
    }
}

impl StreamCipher for ChaCha20Stream {
    fn xor_key_stream(&mut self, data: &mut [u8]) {
        self.xor_key_stream(data);
    }
}

// ========== CryptionReader ==========

/// 加密流读取器。
///
/// 对应 Go 的 `CryptionReader`，从 BufferedReader 读取密文数据，
/// 通过流密码解密后返回明文。
///
/// # 生命周期
///
/// `'a` — 底层 BufferedReader 的借用生命周期。
pub struct CryptionReader<'a> {
    stream: Box<dyn StreamCipher>,
    reader: &'a mut BufferedReader,
}

impl<'a> CryptionReader<'a> {
    /// 创建新的加密流读取器。
    ///
    /// 对应 Go 的 `NewCryptionReader(stream, reader)`。
    pub fn new(
        stream: Box<dyn StreamCipher>,
        reader: &'a mut BufferedReader,
    ) -> Self {
        Self { stream, reader }
    }

    /// 从底层读取器读取数据并解密。
    ///
    /// 对应 Go 的 `CryptionReader.Read(data)`。
    /// 读取密文到 `dst`，然后通过流密码 XOR 解密。
    ///
    /// # 返回
    ///
    /// 实际读取并解密的字节数。返回 0 表示 EOF。
    pub async fn read(&mut self, dst: &mut [u8]) -> usize {
        let n = self.reader.read(dst).await;
        if n > 0 {
            self.stream.xor_key_stream(&mut dst[..n]);
        }
        n
    }

    /// 读取并解密最多 `size` 字节，返回 MultiBuffer。
    ///
    /// 对应 Go 中通过 BufferedReader 读取后解密的组合操作。
    pub async fn read_at_most(
        &mut self,
        size: usize,
    ) -> io::Result<MultiBuffer> {
        let mb = self.reader.read_at_most(size).await?;
        if mb.is_empty() {
            return Ok(mb);
        }
        let mut mb = mb;
        for buf in mb.iter_mut() {
            let data = buf.as_mut();
            if !data.is_empty() {
                self.stream.xor_key_stream(data);
            }
        }
        Ok(mb)
    }
}

// ========== CryptionWriter ==========

/// 加密流写入器。
///
/// 对应 Go 的 `CryptionWriter`，实现 `buf.Writer` 接口。
/// 通过流密码加密数据后写入底层 Writer。
pub struct CryptionWriter {
    stream: Box<dyn StreamCipher>,
    writer: Box<dyn Writer>,
}

impl CryptionWriter {
    /// 创建新的加密流写入器。
    ///
    /// 对应 Go 的 `NewCryptionWriter(stream, writer)`。
    pub fn new(
        stream: Box<dyn StreamCipher>,
        writer: Box<dyn Writer>,
    ) -> Self {
        Self { stream, writer }
    }

    /// 加密并写入原始字节切片。
    ///
    /// 对应 Go 的 `CryptionWriter.Write(data)`。
    /// 先加密数据，再将密文写入底层 Writer。
    ///
    /// # 错误
    ///
    /// 底层写入失败时返回 `io::Error::WriteError`。
    pub async fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let mut encrypted = data.to_vec();
        self.stream.xor_key_stream(&mut encrypted);
        let mb = MultiBuffer::from_buffer(Buffer::from_vec(encrypted));
        let len = mb.len();
        self.writer.write_multi_buffer(mb).await?;
        Ok(len)
    }

    /// 加密并写入 MultiBuffer。
    ///
    /// 对应 Go 的 `CryptionWriter.WriteMultiBuffer(mb)`。
    /// 对 MultiBuffer 中的每个 Buffer 原地加密，然后写入底层 Writer。
    ///
    /// # 错误
    ///
    /// 底层写入失败时返回 `io::Error::WriteError`。
    pub async fn write_multi_buffer(
        &mut self,
        mut mb: MultiBuffer,
    ) -> io::Result<()> {
        for buf in mb.iter_mut() {
            let data = buf.as_mut();
            if !data.is_empty() {
                self.stream.xor_key_stream(data);
            }
        }
        self.writer.write_multi_buffer(mb).await
    }
}

impl Writer for CryptionWriter {
    fn write_multi_buffer(
        &mut self,
        mb: MultiBuffer,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = io::Result<()>> + Send + '_>,
    > {
        Box::pin(async move { self.write_multi_buffer(mb).await })
    }
}

// ========== CryptionError ==========

/// 加密流 I/O 错误类型。
#[derive(thiserror::Error, Debug)]
pub enum CryptionError {
    /// 底层 I/O 错误。
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// 加密操作错误。
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::{
        AesCfbDecryptor, AesCfbEncryptor, AesCtrStream, ChaCha20Stream,
    };
    use std::io::Cursor;
    use xray_buf::io::new_reader;
    use xray_buf::buffer::Buffer;

    fn make_buffered_reader(data: &[u8]) -> BufferedReader {
        let reader = new_reader(Cursor::new(data.to_vec()));
        BufferedReader::new(reader)
    }

    fn direct_encrypt(
        encryptor: &mut AesCfbEncryptor,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let mut data = plaintext.to_vec();
        encryptor.encrypt(&mut data);
        data
    }

    // ---------- CryptionReader 测试 ----------

    #[tokio::test]
    async fn test_cryption_reader_aes_cfb_roundtrip() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = b"hello cryption reader";

        let mut encryptor = AesCfbEncryptor::new(&key, &iv).unwrap();
        let ciphertext = direct_encrypt(&mut encryptor, plaintext);
        assert_ne!(plaintext.as_slice(), ciphertext.as_slice());

        let decryptor = AesCfbDecryptor::new(&key, &iv).unwrap();
        let mut reader = make_buffered_reader(&ciphertext);
        let mut cr = CryptionReader::new(Box::new(decryptor), &mut reader);

        let mut dst = vec![0u8; plaintext.len()];
        let n = cr.read(&mut dst).await;
        assert_eq!(n, plaintext.len());
        assert_eq!(&dst, plaintext);
    }

    #[tokio::test]
    async fn test_cryption_reader_aes_ctr_roundtrip() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = b"aes ctr mode test data";

        let mut cipher = AesCtrStream::new(&key, &iv).unwrap();
        let mut ciphertext = plaintext.to_vec();
        cipher.apply_keystream(&mut ciphertext);

        let decryptor = AesCtrStream::new(&key, &iv).unwrap();
        let mut reader = make_buffered_reader(&ciphertext);
        let mut cr = CryptionReader::new(Box::new(decryptor), &mut reader);

        let mut dst = vec![0u8; plaintext.len()];
        let n = cr.read(&mut dst).await;
        assert_eq!(n, plaintext.len());
        assert_eq!(&dst, plaintext);
    }

    #[tokio::test]
    async fn test_cryption_reader_chacha20_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let plaintext = b"chacha20 stream test";

        let mut cipher = ChaCha20Stream::new(&key, &nonce).unwrap();
        let mut ciphertext = plaintext.to_vec();
        cipher.xor_key_stream(&mut ciphertext);

        let decryptor = ChaCha20Stream::new(&key, &nonce).unwrap();
        let mut reader = make_buffered_reader(&ciphertext);
        let mut cr = CryptionReader::new(Box::new(decryptor), &mut reader);

        let mut dst = vec![0u8; plaintext.len()];
        let n = cr.read(&mut dst).await;
        assert_eq!(n, plaintext.len());
        assert_eq!(&dst, plaintext);
    }

    #[tokio::test]
    async fn test_cryption_reader_empty_data() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let decryptor = AesCfbDecryptor::new(&key, &iv).unwrap();
        let mut reader = make_buffered_reader(b"");
        let mut cr = CryptionReader::new(Box::new(decryptor), &mut reader);

        let mut dst = [0u8; 16];
        let n = cr.read(&mut dst).await;
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn test_cryption_reader_read_at_most() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = b"hello world read at most test";

        let mut encryptor = AesCfbEncryptor::new(&key, &iv).unwrap();
        let ciphertext = direct_encrypt(&mut encryptor, plaintext);

        let decryptor = AesCfbDecryptor::new(&key, &iv).unwrap();
        let mut reader = make_buffered_reader(&ciphertext);
        let mut cr = CryptionReader::new(Box::new(decryptor), &mut reader);

        let mb = cr
            .read_at_most(5)
            .await
            .expect("read_at_most should succeed");
        assert_eq!(mb.len(), 5);
        assert_eq!(mb.to_vec(), b"hello");
    }

    #[tokio::test]
    async fn test_cryption_reader_partial_read() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = b"partial read test data here";

        let mut encryptor = AesCfbEncryptor::new(&key, &iv).unwrap();
        let ciphertext = direct_encrypt(&mut encryptor, plaintext);

        let decryptor = AesCfbDecryptor::new(&key, &iv).unwrap();
        let mut reader = make_buffered_reader(&ciphertext);
        let mut cr = CryptionReader::new(Box::new(decryptor), &mut reader);

        let mut dst1 = vec![0u8; 7];
        let n1 = cr.read(&mut dst1).await;
        assert_eq!(n1, 7);
        assert_eq!(&dst1, b"partial");

        let mut dst2 = vec![0u8; plaintext.len() - 7];
        let n2 = cr.read(&mut dst2).await;
        assert_eq!(n2, plaintext.len() - 7);
        assert_eq!(&dst2, b" read test data here");
    }

    // ---------- CryptionWriter 测试 ----------

    #[tokio::test]
    async fn test_cryption_writer_aes_cfb() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = b"hello cryption writer";

        let encryptor = AesCfbEncryptor::new(&key, &iv).unwrap();
        let buffer: Vec<u8> = Vec::new();
        let writer = xray_buf::io::new_writer(buffer);
        let mut cw = CryptionWriter::new(Box::new(encryptor), writer);
        let n = cw.write(plaintext).await.expect("write should succeed");
        assert_eq!(n, plaintext.len());
    }

    #[tokio::test]
    async fn test_cryption_writer_empty_data() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let encryptor = AesCfbEncryptor::new(&key, &iv).unwrap();

        let buffer: Vec<u8> = Vec::new();
        let writer = xray_buf::io::new_writer(buffer);
        let mut cw = CryptionWriter::new(Box::new(encryptor), writer);

        let n = cw.write(b"").await.expect("write should succeed");
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn test_cryption_writer_multi_buffer() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let encryptor = AesCfbEncryptor::new(&key, &iv).unwrap();

        let buffer: Vec<u8> = Vec::new();
        let writer = xray_buf::io::new_writer(buffer);
        let mut cw = CryptionWriter::new(Box::new(encryptor), writer);

        let mut mb = MultiBuffer::new();
        mb.push(Buffer::from_vec(b"hello ".to_vec()));
        mb.push(Buffer::from_vec(b"multi buffer".to_vec()));

        cw.write_multi_buffer(mb)
            .await
            .expect("write_multi_buffer should succeed");
    }

    #[tokio::test]
    async fn test_cryption_writer_implements_writer_trait() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let encryptor = AesCfbEncryptor::new(&key, &iv).unwrap();

        let buffer: Vec<u8> = Vec::new();
        let writer = xray_buf::io::new_writer(buffer);
        let mut cw = CryptionWriter::new(Box::new(encryptor), writer);

        let mb =
            MultiBuffer::from_buffer(Buffer::from_vec(b"writer trait test".to_vec()));
        cw.write_multi_buffer(mb)
            .await
            .expect("write via Writer trait should succeed");
    }

    // ---------- Writer→Reader 端到端 Roundtrip 测试 ----------
    // 使用直接加密产生密文，再用 CryptionReader 解密验证完整链路

    #[tokio::test]
    async fn test_e2e_writer_to_reader_aes_cfb128() {
        let key = [1u8; 16];
        let iv = [2u8; 16];
        let plaintext = b"e2e aes-128-cfb roundtrip test";

        // CryptionWriter 加密
        let encryptor = AesCfbEncryptor::new(&key, &iv).unwrap();
        let buffer: Vec<u8> = Vec::new();
        let writer = xray_buf::io::new_writer(buffer);
        let mut cw = CryptionWriter::new(Box::new(encryptor), writer);
        cw.write(plaintext).await.expect("encrypt write");

        // 用直接加密生成密文供 Reader 读取
        let mut enc = AesCfbEncryptor::new(&key, &iv).unwrap();
        let mut ciphertext = plaintext.to_vec();
        enc.encrypt(&mut ciphertext);
        assert_ne!(plaintext.as_slice(), ciphertext.as_slice());

        // CryptionReader 解密
        let decryptor = AesCfbDecryptor::new(&key, &iv).unwrap();
        let mut reader = make_buffered_reader(&ciphertext);
        let mut cr = CryptionReader::new(Box::new(decryptor), &mut reader);
        let mut dst = vec![0u8; plaintext.len()];
        let n = cr.read(&mut dst).await;
        assert_eq!(n, plaintext.len());
        assert_eq!(&dst, plaintext);
    }

    #[tokio::test]
    async fn test_e2e_writer_to_reader_aes_cfb256() {
        let key = [3u8; 32];
        let iv = [4u8; 16];
        let plaintext = b"e2e aes-256-cfb roundtrip test";

        let mut enc = AesCfbEncryptor::new(&key, &iv).unwrap();
        let mut ciphertext = plaintext.to_vec();
        enc.encrypt(&mut ciphertext);

        let decryptor = AesCfbDecryptor::new(&key, &iv).unwrap();
        let mut reader = make_buffered_reader(&ciphertext);
        let mut cr = CryptionReader::new(Box::new(decryptor), &mut reader);
        let mut dst = vec![0u8; plaintext.len()];
        let n = cr.read(&mut dst).await;
        assert_eq!(n, plaintext.len());
        assert_eq!(&dst, plaintext);
    }

    #[tokio::test]
    async fn test_e2e_writer_to_reader_aes_ctr() {
        let key = [5u8; 16];
        let iv = [6u8; 16];
        let plaintext = b"e2e aes-ctr roundtrip test";

        let mut enc = AesCtrStream::new(&key, &iv).unwrap();
        let mut ciphertext = plaintext.to_vec();
        enc.apply_keystream(&mut ciphertext);

        let decryptor = AesCtrStream::new(&key, &iv).unwrap();
        let mut reader = make_buffered_reader(&ciphertext);
        let mut cr = CryptionReader::new(Box::new(decryptor), &mut reader);
        let mut dst = vec![0u8; plaintext.len()];
        let n = cr.read(&mut dst).await;
        assert_eq!(n, plaintext.len());
        assert_eq!(&dst, plaintext);
    }

    #[tokio::test]
    async fn test_e2e_writer_to_reader_chacha20() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let plaintext = b"e2e chacha20 roundtrip test";

        let mut enc = ChaCha20Stream::new(&key, &nonce).unwrap();
        let mut ciphertext = plaintext.to_vec();
        enc.xor_key_stream(&mut ciphertext);

        let decryptor = ChaCha20Stream::new(&key, &nonce).unwrap();
        let mut reader = make_buffered_reader(&ciphertext);
        let mut cr = CryptionReader::new(Box::new(decryptor), &mut reader);
        let mut dst = vec![0u8; plaintext.len()];
        let n = cr.read(&mut dst).await;
        assert_eq!(n, plaintext.len());
        assert_eq!(&dst, plaintext);
    }
}
