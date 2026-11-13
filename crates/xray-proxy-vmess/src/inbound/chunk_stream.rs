//! VMess chunk 流的 MultiBuffer 适配（删「duplex 中转层」）。
//!
//! Go `common/crypto/auth.go` 的 `AuthenticationReader`/`AuthenticationWriter` 直接在
//! `buf.Reader`/`buf.Writer`（MultiBuffer）层做 chunk 解码/编码——`proxy/vmess/inbound`
//! 因此**没有**中转缓冲。本文件是等价物：
//!
//! - [`ChunkReader`]：wire → chunk 帧 → **原地**解密 → 明文 MultiBuffer（0 遍用户态 memcpy）
//! - [`ChunkWriter`]：明文 MultiBuffer → 装帧（原地 seal + 帧头回填）→ 一批帧拼成一段
//!   连续字节，一次单缓冲写落 wire
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
    encoding::{ChunkNonceGenerator, body_chunk::SizeParser},
    inbound::server::BodyCipher,
};

/// 单 chunk 明文上限：8 KiB 池块容量 − AEAD tag（tag 必须与载荷同块相邻，
/// `seal_window` 才成立）。与旧泵的明文读入区同一上界。
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
            if buf.free() < ct_len || buf.read_exact_from(&mut self.stream, ct_len).await.is_err() {
                return Ok(MultiBuffer::new());
            }
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
    /// 批缓冲：整批帧在**同一段连续字节**里（`[size][ct‖tag][padding]` 帧序列紧挨），
    /// `flush` 后 `clear` 复用容量（零 realloc）。
    batch: Vec<u8>,
    terminated: std::cell::Cell<bool>,
}

/// 一批帧数（批缓冲目标 ≈ 64 KiB）。
///
/// 本机 loopback 实测内核态成本：每 8 KiB send ≈ 53µs、每 64 KiB send ≈ 72µs
/// ⇒ **成本随 send 次数走、不随字节走**（8 KiB×8 次 = 424µs vs 64 KiB×1 次 = 72µs）。
/// 攒 8 帧一次写 ⇒ 每 MiB 16 次 send（bd 7choj）。
///
/// 注意：`write_vectored` 传 8 段**不等于**一次大 send（每段仍各自处理，实测无收益），
/// 必须把帧字节拼进同一段连续内存。
const FRAME_BATCH: usize = 8;

impl<W> ChunkWriter<W> {
    pub(crate) fn new(
        stream: W,
        cipher: BodyCipher,
        iv: [u8; 16],
        size_parser: Box<dyn SizeParser + Send>,
        global_padding: bool,
        no_termination: bool,
    ) -> Self {
        // 一批的字节上界：每帧 [size + 明文上限 + tag + padding 上限]
        let frame_wire = size_parser.size_bytes()
            + PAYLOAD_MAX
            + cipher.tag_size()
            + crate::encoding::body_chunk::MAX_PADDING;
        Self {
            stream,
            cipher,
            nonce_gen: ChunkNonceGenerator::new(&iv, 12),
            size_parser,
            global_padding,
            no_termination,
            batch: Vec::with_capacity(FRAME_BATCH * frame_wire),
            terminated: std::cell::Cell::new(false),
        }
    }

    /// 收尾当前帧：原地 AEAD seal 明文区 → 追加 padding → 回填 size 字段。
    ///
    /// 明文已由调用方写进 `batch[off + sb .. off + sb + n]`（size 字段的 `sb` 字节
    /// 占位也在 `off` 处）。SHAKE128 流顺序：`next_padding_len` → `encode`（与 decode 侧对称）。
    #[allow(clippy::too_many_arguments, reason = "批缓冲原位装帧：每项都是本帧构帧参数")]
    fn finish_frame(
        batch: &mut Vec<u8>,
        off: usize,
        n: usize,
        sb: usize,
        tag_len: usize,
        cipher: &BodyCipher,
        nonce: &[u8],
        size_parser: &mut (dyn SizeParser + Send),
        global_padding: bool,
    ) -> Result<()> {
        let padding_size =
            if global_padding { usize::from(size_parser.next_padding_len()) } else { 0 };
        // 先把 tag/padding 区纳入 len（本帧的线上长度：size ‖ 密文 ‖ tag ‖ padding）
        batch.resize(off + sb + n + tag_len + padding_size, 0);
        {
            // 原地 AEAD：载荷 [off+sb, off+sb+n) 覆写为密文，tag 紧随其后（同一段字节）
            let (head, tail) = batch.split_at_mut(off + sb + n);
            let tag: &mut [std::mem::MaybeUninit<u8>] = {
                // SAFETY: `tail[..tag_len]` 是本次 `resize` 已纳入 len 的连续字节区；
                // `MaybeUninit<u8>` 与 `u8` 同布局，seal 会把它整段写满（只写不读）。
                unsafe {
                    std::slice::from_raw_parts_mut(
                        tail.as_mut_ptr().cast::<std::mem::MaybeUninit<u8>>(),
                        tag_len,
                    )
                }
            };
            cipher
                .seal_in_place_with_tag(nonce, &[], &mut head[off + sb..], tag)
                .map_err(|e| Error::WriteError(e.to_string()))?;
        }
        if padding_size > 0 {
            use rand::RngCore;
            rand::rng().fill_bytes(&mut batch[off + sb + n + tag_len..]);
        }
        // size 字段 u16：超出即显式报错（静默回退 u16::MAX 会致收端按 65535 读、错位）
        let size_value = u16::try_from(n + tag_len + padding_size)
            .map_err(|_| Error::WriteError("vmess chunk size exceeds u16".into()))?;
        size_parser.encode(size_value, &mut batch[off..off + sb]);
        Ok(())
    }
}

impl<W: AsyncWrite + Unpin> ChunkWriter<W> {
    /// 发出批缓冲（1 次单缓冲写），随后清空复用容量。
    async fn flush_batch(&mut self) -> Result<()> {
        if self.batch.is_empty() {
            return Ok(());
        }
        self.stream.write_all(&self.batch).await.map_err(|e| Error::WriteError(e.to_string()))?;
        self.batch.clear();
        Ok(())
    }
}

impl<W: AsyncWrite + Unpin + Send> Writer for ChunkWriter<W> {
    fn write_multi_buffer(
        &mut self,
        mb: MultiBuffer,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        // 站点归集（bd 7choj）：本函数的分配 = 每帧装帧开销的唯一候选面。
        Box::pin(xray_common::alloc_site::scope(xray_common::alloc_site::VMESS_FRAME, async move {
            let tag_len = self.cipher.tag_size();
            let sb = self.size_parser.size_bytes();
            let frame_wire = sb
                + PAYLOAD_MAX
                + tag_len
                + if self.global_padding { crate::encoding::body_chunk::MAX_PADDING } else { 0 };
            let batch_limit = FRAME_BATCH * frame_wire;
            // 逐帧装填：游标走过源 Buffer，**不切 MultiBuffer**。
            // `split_bytes` 每帧新建 `Vec<Buffer>`（跨块时另有 `drain().collect()`），
            // 即每帧 2 次堆 churn；bd 7choj 实测这笔 churn 在 Windows 上换来每 MiB
            // 上百次缺页、内核态 +4ms/MiB（吞吐 141 vs 基线 262 MB/s）。
            let mut bufs = mb.into_buffers().into_iter();
            let mut cur = bufs.next();
            loop {
                if self.batch.len() + frame_wire > batch_limit {
                    self.flush_batch().await?;
                }
                let off = self.batch.len();
                // size 字段占位（帧末回填），随后是明文区
                self.batch.resize(off + sb, 0);
                let mut n = 0usize;
                while n < PAYLOAD_MAX {
                    let Some(buf) = cur.as_mut() else { break };
                    if buf.is_empty() {
                        cur = bufs.next();
                        continue;
                    }
                    let take = buf.len().min(PAYLOAD_MAX - n);
                    self.batch.extend_from_slice(&buf.bytes()[..take]);
                    buf.advance(take);
                    n += take;
                }
                if n == 0 {
                    // 源已空：撤掉本帧占位（不留半帧）
                    self.batch.truncate(off);
                    break;
                }
                let nonce = self.nonce_gen.next_ref();
                Self::finish_frame(
                    &mut self.batch,
                    off,
                    n,
                    sb,
                    tag_len,
                    &self.cipher,
                    nonce,
                    self.size_parser.as_mut(),
                    self.global_padding,
                )?;
            }
            self.flush_batch().await
        }))
    }

    /// 终止 chunk（`seal([])`）由 [`Writer::shutdown_flush`] 写（旧泵在明文源 EOF 时写）。
    /// `shutdown` 是同步钩子（无 await 能力），只作语义占位。
    fn shutdown(&self) {}

    fn shutdown_flush(&mut self) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + '_>> {
        Box::pin(async move {
            if !self.terminated.get() {
                self.terminated.set(true);
                if !self.no_termination {
                    // 终止 chunk：明文 0 字节，wire 上只余 size + tag（+ padding）
                    let sb = self.size_parser.size_bytes();
                    let tag_len = self.cipher.tag_size();
                    let off = self.batch.len();
                    self.batch.resize(off + sb, 0);
                    let nonce = self.nonce_gen.next_ref();
                    Self::finish_frame(
                        &mut self.batch,
                        off,
                        0,
                        sb,
                        tag_len,
                        &self.cipher,
                        nonce,
                        self.size_parser.as_mut(),
                        self.global_padding,
                    )
                    .map_err(std::io::Error::other)?;
                }
                self.flush_batch().await.map_err(std::io::Error::other)?;
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
    use crate::encoding::body_chunk::{ChunkFrame, PlainSizeParser, write_chunk_frame};

    fn aes_cipher(key: &[u8; 16]) -> BodyCipher {
        BodyCipher::Aes(Aes128Gcm::new(key).expect("aes key"))
    }

    /// wire 不变量 W1：写半产出的字节与 [`write_chunk_frame`]（单帧参考构帧路径）
    /// **逐字节相同**。写半现在走「攒批连续字节 + 一次 write_all」，本测试把
    /// 「同一明文 + 同一 nonce 序列 + 同一 size parser」的参考字节钉死 ⇒ 攒批不得改 wire。
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
        let mut frame = ChunkFrame::new(2);
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

    /// 帧边界不变式：同一明文按**任意 Buffer 切分**喂入，产出必须与「单块喂入」
    /// 逐字节相同——逐帧装填走游标而非 `split_bytes`，不得改变分帧边界或 nonce 序号。
    #[tokio::test]
    async fn chunk_writer_multibuffer_framing_matches_contiguous() {
        async fn wire_of(parts: &[&[u8]], key: &[u8; 16], iv: [u8; 16]) -> Vec<u8> {
            let (mut wire_r, wire_w) = tokio::io::duplex(64 * 1024);
            let mut writer = ChunkWriter::new(
                wire_w,
                aes_cipher(key),
                iv,
                Box::new(PlainSizeParser),
                false,
                false,
            );
            let mut mb = MultiBuffer::new();
            for p in parts {
                mb.merge_bytes(p);
            }
            writer.write_multi_buffer(mb).await.expect("write chunk");
            writer.shutdown_flush().await.expect("flush");
            let mut out = Vec::new();
            wire_r.read_to_end(&mut out).await.expect("read wire");
            out
        }

        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        let one = wire_of(&[&payload[..]], &key, iv).await;
        let parts: [&[u8]; 4] =
            [&payload[..7], &payload[7..9000], &payload[9000..30001], &payload[30001..]];
        let many = wire_of(&parts, &key, iv).await;
        assert_eq!(one.len(), many.len(), "分块喂入不得改变帧长序列");
        assert_eq!(one, many, "分块喂入不得改变帧边界/nonce 序号");
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
