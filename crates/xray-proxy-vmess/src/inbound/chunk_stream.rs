//! VMess chunk 流的 MultiBuffer 适配（删「duplex 中转层」）。
//!
//! Go `common/crypto/auth.go` 的 `AuthenticationReader`/`AuthenticationWriter` 直接在
//! `buf.Reader`/`buf.Writer`（MultiBuffer）层做 chunk 解码/编码——`proxy/vmess/inbound`
//! 因此**没有**中转缓冲。本文件是等价物：
//!
//! - [`ChunkReader`]：wire → chunk 帧 → **原地**解密 → 明文 MultiBuffer（0 遍用户态 memcpy）
//! - [`ChunkWriter`]：明文 MultiBuffer → 装帧（复用 [`write_chunk_frame`]，字节序与旧泵逐字节同源）
//!   → wire
//!
//! 旧实现是「wire ↔ chunk 泵 ↔ `tokio::io::duplex` ↔ dispatch link」，每方向固定多 2 遍
//! 用户态 memcpy（写进环 + 读出环）。直挂后：下行 0 遍、上行 1 遍（明文入装帧块）。

use std::{future::Future, pin::Pin};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use xray_buf::{
    buffer::Buffer,
    io::{Error, Reader, Result, Writer},
    multi::MultiBuffer,
};
use xray_crypto::aead::AeadCipher;

use crate::{
    encoding::{
        ChunkNonceGenerator,
        body_chunk::{ChunkFrame, SizeParser, write_chunk_frame},
    },
    inbound::server::BodyCipher,
};

/// 单 chunk 明文上限：8 KiB 池块容量 − AEAD tag（tag 必须与载荷同块相邻，
/// `seal_window` 才成立）。与旧泵的 `plaintext_read_buf` 同一上界。
const PAYLOAD_MAX: usize = 8 * 1024 - 16;

/// 读半：wire 上的 chunk 帧 → 明文 MultiBuffer。
pub(crate) struct ChunkReader<R> {
    stream: R,
    cipher: BodyCipher,
    nonce_gen: ChunkNonceGenerator,
    size_parser: Box<dyn SizeParser + Send>,
    global_padding: bool,
    size_field: Vec<u8>,
}

impl<R> ChunkReader<R> {
    pub(crate) fn new(
        stream: R,
        cipher: BodyCipher,
        iv: [u8; 16],
        size_parser: Box<dyn SizeParser + Send>,
        global_padding: bool,
    ) -> Self {
        Self {
            stream,
            cipher,
            nonce_gen: ChunkNonceGenerator::new(&iv, 12),
            size_parser,
            global_padding,
            size_field: Vec::with_capacity(18),
        }
    }
}

impl<R: AsyncRead + Unpin + Send> Reader for ChunkReader<R> {
    fn read_multi_buffer(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<MultiBuffer>> + Send + '_>> {
        Box::pin(async move {
            // 1. size 字段（Plain/Shake=2B，AuthenticatedLength=18B）
            let sb = self.size_parser.size_bytes();
            self.size_field.resize(sb, 0);
            if self.stream.read_exact(&mut self.size_field).await.is_err() {
                // EOF：交空 MultiBuffer（对齐 `SingleReader` 的 EOF 语义）
                return Ok(MultiBuffer::new());
            }
            // SHAKE128 流消费顺序：next_padding_len → decode（与 encode 侧对称）
            let padding = if self.global_padding {
                usize::from(self.size_parser.next_padding_len())
            } else {
                0
            };
            let total = usize::from(self.size_parser.decode(&self.size_field));
            if total == 0 {
                return Ok(MultiBuffer::new());
            }
            let ct_len = total.saturating_sub(padding);
            // 2. 密文（含 tag）直落池化块 → 原地解密 → 明文即该块数据区（0 遍 memcpy）
            let mut buf = Buffer::new_pooled(ct_len.max(1));
            {
                let dst = buf.writable_bytes();
                if dst.len() < ct_len || self.stream.read_exact(&mut dst[..ct_len]).await.is_err() {
                    return Ok(MultiBuffer::new());
                }
            }
            buf.advance_write(ct_len);
            let nonce = self.nonce_gen.next_ref();
            let plaintext_len =
                match self.cipher.open_in_place(nonce, &[], &mut buf.as_mut()[..ct_len]) {
                    Ok(pt) => pt.len(),
                    Err(e) => {
                        crate::VMESS_LOG
                            .debug(format!("vmess request body chunk open failed error={e}"));
                        return Ok(MultiBuffer::new());
                    },
                };
            if plaintext_len == 0 {
                // 终止 chunk（seal([])）→ 请求 body 结束
                return Ok(MultiBuffer::new());
            }
            buf.resize(plaintext_len);
            // 3. 跳过明文后的 padding 字节（wire 布局：[size][ct‖tag][padding]）
            if padding > 0 {
                let mut pad = [0u8; 64];
                let n = padding.min(pad.len());
                let _ = self.stream.read_exact(&mut pad[..n]).await;
            }
            Ok(MultiBuffer::from_buffer(buf))
        })
    }
}

/// 写半：明文 MultiBuffer → chunk 帧 → wire。
pub(crate) struct ChunkWriter<W> {
    stream: W,
    cipher: BodyCipher,
    nonce_gen: ChunkNonceGenerator,
    size_parser: Box<dyn SizeParser + Send>,
    global_padding: bool,
    no_termination: bool,
    frame: ChunkFrame,
    terminated: std::cell::Cell<bool>,
}

impl<W> ChunkWriter<W> {
    pub(crate) fn new(
        stream: W,
        cipher: BodyCipher,
        iv: [u8; 16],
        size_parser: Box<dyn SizeParser + Send>,
        global_padding: bool,
        no_termination: bool,
    ) -> Self {
        Self {
            stream,
            cipher,
            nonce_gen: ChunkNonceGenerator::new(&iv, 12),
            size_parser,
            global_padding,
            no_termination,
            frame: ChunkFrame::new(),
            terminated: std::cell::Cell::new(false),
        }
    }
}

impl<W: AsyncWrite + Unpin + Send> Writer for ChunkWriter<W> {
    fn write_multi_buffer(
        &mut self,
        mb: MultiBuffer,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            let tag_len = self.cipher.tag_size();
            let mut mb = mb;
            while !mb.is_empty() {
                let cap = self.frame.plaintext_read_buf(tag_len).len().min(PAYLOAD_MAX);
                let piece = mb.split_bytes(cap);
                let n = piece.len();
                if n == 0 {
                    break;
                }
                {
                    let dst = self.frame.plaintext_read_buf(tag_len);
                    piece.copy_to_slice(0, &mut dst[..n]);
                }
                self.frame.commit_plaintext(n);
                let nonce = self.nonce_gen.next_ref();
                write_chunk_frame(
                    &mut self.stream,
                    &mut self.frame,
                    n,
                    &self.cipher,
                    nonce,
                    self.size_parser.as_mut(),
                    self.global_padding,
                )
                .await
                .map_err(|e| Error::WriteError(e.to_string()))?;
                self.frame.clear();
            }
            Ok(())
        })
    }

    /// 终止 chunk（`seal([])`）由 [`Writer::shutdown_flush`] 写（旧泵在明文源 EOF 时写）。
    /// `shutdown` 是同步钩子（无 await 能力），只作语义占位。
    fn shutdown(&self) {}

    fn shutdown_flush(&mut self) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + '_>> {
        Box::pin(async move {
            if !self.terminated.get() {
                self.terminated.set(true);
                if !self.no_termination {
                    self.frame.clear();
                    let nonce = self.nonce_gen.next_ref();
                    write_chunk_frame(
                        &mut self.stream,
                        &mut self.frame,
                        0,
                        &self.cipher,
                        nonce,
                        self.size_parser.as_mut(),
                        self.global_padding,
                    )
                    .await?;
                    self.frame.clear();
                }
            }
            self.stream.flush().await?;
            self.stream.shutdown().await?;
            Ok(())
        })
    }
}

/// 写半包装：`drop` 时关闭底层 pipe。
///
/// `xray-buf::pipe` 的 drop **不**传播 close（只有显式 `shutdown` 才让读端见 EOF）——
/// dispatch 侧直接 drop `link.writer` 时若不兜底，响应方向的读腿会永远挂在
/// `read_multi_buffer` 上（终止 chunk 永不发出 ⇒ 对端挂起）。
pub(crate) struct ClosingPipeWriter {
    inner: xray_buf::pipe::Writer,
}

impl ClosingPipeWriter {
    pub(crate) fn new(inner: xray_buf::pipe::Writer) -> Self {
        Self { inner }
    }
}

impl Drop for ClosingPipeWriter {
    fn drop(&mut self) {
        self.inner.shutdown();
    }
}

impl Writer for ClosingPipeWriter {
    fn write_multi_buffer(
        &mut self,
        mb: MultiBuffer,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move { self.inner.write_multi_buffer(mb).await })
    }

    fn shutdown(&self) {
        self.inner.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;
    use xray_crypto::aead::Aes128Gcm;

    use super::*;
    use crate::encoding::body_chunk::{ChunkFrame, PlainSizeParser};

    fn aes_cipher(key: &[u8; 16]) -> BodyCipher {
        BodyCipher::Aes(Aes128Gcm::new(key).expect("aes key"))
    }

    /// wire 不变量 W1：写半产出的字节与旧泵路径（`write_chunk_frame`）**逐字节相同**。
    ///
    /// 写半内部复用同一份 `write_chunk_frame` ⇒ 结构上不可能漂移；本测试把
    /// 「同一明文 + 同一 nonce 序列 + 同一 size parser」的旧路径字节钉死。
    #[tokio::test]
    async fn chunk_writer_bytes_match_write_chunk_frame() {
        let key = [7u8; 16];
        let iv = [3u8; 16];
        let plaintext = b"vmess chunk wire parity payload";

        let (mut wire_r, wire_w) = tokio::io::duplex(4096);
        let mut writer =
            ChunkWriter::new(wire_w, aes_cipher(&key), iv, Box::new(PlainSizeParser), false, false);
        let mut mb = MultiBuffer::new();
        mb.merge_bytes(plaintext);
        writer.write_multi_buffer(mb).await.expect("write chunk");

        let mut got = vec![0u8; 512];
        let n = wire_r.read(&mut got).await.expect("read wire");

        // 旧路径：同一份 write_chunk_frame + 同一 nonce 序号
        let mut want = Vec::new();
        let mut frame = ChunkFrame::new();
        let mut nonce_gen = ChunkNonceGenerator::new(&iv, 12);
        let mut sp = PlainSizeParser;
        frame.write_plaintext(plaintext);
        write_chunk_frame(
            &mut want,
            &mut frame,
            plaintext.len(),
            &aes_cipher(&key),
            nonce_gen.next_ref(),
            &mut sp,
            false,
        )
        .await
        .expect("write_chunk_frame");

        assert_eq!(&got[..n], &want[..], "写半字节必须与旧泵逐字节相同");
    }

    /// wire 不变量 W2：写半 → 读半往返，明文逐字节相同（多批 + 跨 chunk 边界）。
    #[tokio::test]
    async fn chunk_writer_reader_roundtrip() {
        let key = [9u8; 16];
        let iv = [5u8; 16];
        let (wire_r, wire_w) = tokio::io::duplex(64 * 1024);
        let mut writer =
            ChunkWriter::new(wire_w, aes_cipher(&key), iv, Box::new(PlainSizeParser), false, false);
        let mut reader =
            ChunkReader::new(wire_r, aes_cipher(&key), iv, Box::new(PlainSizeParser), false);

        let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        // 写：分 3 批（跨 chunk 边界）
        let writer_task = tokio::spawn(async move {
            for part in payload.chunks(9_000) {
                let mut mb = MultiBuffer::new();
                mb.merge_bytes(part);
                writer.write_multi_buffer(mb).await.expect("write");
            }
            writer.shutdown_flush().await.expect("flush");
        });

        // 读：直到空 MultiBuffer（终止 chunk / EOF）
        let mut got: Vec<u8> = Vec::new();
        loop {
            let mb = reader.read_multi_buffer().await.expect("read");
            if mb.is_empty() {
                break;
            }
            got.extend_from_slice(&mb.to_vec());
        }
        writer_task.await.expect("writer task");
        assert_eq!(got, expected, "往返明文必须逐字节相同");
    }
}
