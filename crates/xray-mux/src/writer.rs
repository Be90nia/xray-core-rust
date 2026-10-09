//! Mux 帧数据写入器
//!
//! 实现 MuxWriter 用于写入 Mux 协议帧数据

use std::{pin::Pin, sync::Arc};

use xray_buf::{
    buffer::Buffer,
    io::{self as buf_io, Writer},
    multi::MultiBuffer,
    writer::BufferedWriter,
};
use xray_common::{bitmask::Bitmask, net::destination::Destination};

use crate::{
    frame::{FrameMetadata, MuxError, OPTION_DATA, OPTION_ERROR, SessionStatus},
    session::TransferType,
};

/// 流式传输分块大小 (8KB)
const STREAM_CHUNK_SIZE: usize = 8 * 1024;

/// Mux 帧写入器
///
/// `global_id` 用 `Option<[u8;8]>` 表达 Go 端 `xudp.GetGlobalID` 在 cone=false
/// 或非 UDP inbound 时返回的全零值（Go 服务端 `if meta.GlobalID != [8]byte{}`
/// 短路跳过 XUDP 路径）。Rust 旧版恒设 `[0;8]`，UDP dest 帧被服务端误判走 XUDP
/// 路径丢弃内联 data。Option 化后 `[0;8]` → None → 仅在显式传入非零时下发。
pub struct MuxWriter {
    dest: Option<Destination>,
    writer: BufferedWriter,
    id: u16,
    followup: bool,
    has_error: bool,
    transfer_type: TransferType,
    global_id: Option<[u8; 8]>,
    /// Reverse-mux 入站元数据（Go `Writer.inbound *session.Inbound`，
    /// writer.go:23）。New 帧写出 source/local（Go frame.go:87-99），与
    /// GlobalID 互斥（frame.go:100 else 分支）。txno④ portal 写侧消费。
    inbound: Option<(Destination, Destination)>,
}

impl MuxWriter {
    /// 创建新的客户端写入器。
    ///
    /// `global_id`：UDP 会话源追踪的 8 字节标识，由 `xudp::global_id(&GlobalIdInput)`
    /// 计算；非 UDP 场景或 cone=false 时传 `None`。
    pub fn new(
        id: u16,
        dest: Destination,
        writer: Box<dyn Writer>,
        transfer_type: TransferType,
        global_id: Option<[u8; 8]>,
    ) -> Self {
        Self {
            id,
            dest: Some(dest),
            writer: BufferedWriter::new(writer),
            followup: false,
            has_error: false,
            transfer_type,
            global_id,
            inbound: None,
        }
    }

    /// 携带 Reverse-mux 入站 source/local（Go `NewWriter(..., inbound)` 的
    /// inbound 参数；client.go:268-271 仅 `IsReverseMuxFromContext` 时传入）。
    #[must_use]
    pub fn with_inbound(mut self, source: Destination, local: Destination) -> Self {
        self.inbound = Some((source, local));
        self
    }

    /// 创建新的响应写入器（服务端从 carrier 写到客户端方向）。
    pub fn new_response_writer(
        id: u16,
        writer: Box<dyn Writer>,
        transfer_type: TransferType,
    ) -> Self {
        Self {
            id,
            dest: None,
            writer: BufferedWriter::new(writer),
            followup: true,
            has_error: false,
            transfer_type,
            global_id: None,
            inbound: None,
        }
    }

    /// 设置全局 ID（用于 UDP 关联会话复用 packet session）。
    pub fn set_global_id(&mut self, id: [u8; 8]) {
        self.global_id = Some(id);
    }

    /// 获取下一帧的元数据
    fn get_next_frame_meta(&mut self) -> FrameMetadata {
        let status = if self.followup {
            SessionStatus::Keep
        } else {
            self.followup = true;
            SessionStatus::New
        };
        let mut meta = FrameMetadata::new(self.id, status, Bitmask::default());
        if let Some(dest) = &self.dest {
            meta.set_target(dest.clone());
        }
        if let Some(gid) = self.global_id {
            meta.set_global_id(gid);
        }
        // Reverse-mux：New 帧携带 source/local（Go frame.go:87-99 写出；
        // Keep 帧不带——Go Writer 的 inbound 虽挂在每帧 meta 上，但 WriteTo
        // 仅 SessionStatusNew 分支序列化它）。
        if status == SessionStatus::New {
            if let Some((source, local)) = &self.inbound {
                meta.set_inbound(source.clone(), local.clone());
            }
        }
        meta
    }

    /// 仅写入元数据帧。
    /// 整帧单次落盘（Go writer.go:62-69 `WriteMultiBuffer({b})` 同形）。
    async fn write_meta_only(&mut self) -> Result<(), MuxError> {
        let meta = self.get_next_frame_meta();
        let mut vec = Vec::new();
        meta.write_to(&mut vec).map_err(|e| MuxError::Io(format!("meta: {:?}", e)))?;
        let mb = MultiBuffer::from_buffer(Buffer::from_vec(vec));
        self.writer
            .write_multi_buffer_direct(mb)
            .await
            .map_err(|e| MuxError::Io(format!("write: {:?}", e)))
    }

    /// 写入元数据+数据帧。
    async fn write_data(&mut self, data: MultiBuffer) -> Result<(), MuxError> {
        let mut meta = self.get_next_frame_meta();
        meta.set_option(OPTION_DATA);
        write_meta_with_frame(&mut self.writer, meta, data).await
    }

    /// 写入 MultiBuffer 数据
    pub async fn write(&mut self, mut mb: MultiBuffer) -> Result<(), MuxError> {
        if mb.is_empty() {
            return self.write_meta_only().await;
        }
        while !mb.is_empty() {
            let chunk = if self.transfer_type == TransferType::Stream {
                mb.split_size(STREAM_CHUNK_SIZE)
            } else {
                match mb.split_first() {
                    Some(b) => {
                        let mut c = MultiBuffer::new();
                        c.push(b);
                        c
                    },
                    None => break,
                }
            };
            self.write_data(chunk).await?;
        }
        Ok(())
    }

    /// 关闭写入器，发送 End 帧（整帧单次落盘）
    pub async fn close(&mut self) -> Result<(), MuxError> {
        let mut option = Bitmask::default();
        if self.has_error {
            option.set(OPTION_ERROR);
        }
        let meta = FrameMetadata::new(self.id, SessionStatus::End, option);
        let mut vec = Vec::new();
        meta.write_to(&mut vec).map_err(|e| MuxError::Io(format!("close meta: {:?}", e)))?;
        let mb = MultiBuffer::from_buffer(Buffer::from_vec(vec));
        self.writer
            .write_multi_buffer_direct(mb)
            .await
            .map_err(|e| MuxError::Io(format!("close write: {:?}", e)))
    }

    pub fn set_error(&mut self) {
        self.has_error = true;
    }

    pub fn id(&self) -> u16 {
        self.id
    }

    pub fn transfer_type(&self) -> TransferType {
        self.transfer_type
    }

    pub fn is_followup(&self) -> bool {
        self.followup
    }

    pub fn has_error(&self) -> bool {
        self.has_error
    }
}

/// 写入元数据+数据帧到底层 Writer。
///
/// 整帧（帧头+全部载荷）经 `write_multi_buffer_direct` 单次落盘——共享
/// carrier 写端的多个 MuxWriter 间帧不可拆分（Go writer.go:71-87 把
/// frame 与 data append 进同一 mb 后一次 `WriteMultiBuffer`；Rust 旧实现
/// 走 `write_multi_buffer_impl` 逐 Buffer 写，帧头先 flush、载荷直写，
/// 两个锁临界区之间会被并发会话的完整帧插隔 → 读端把孤立载荷当前帧头
/// 解析出 `meta_len too large` → 整条 carrier 静默死亡，bd txhn）。
async fn write_meta_with_frame(
    writer: &mut BufferedWriter,
    meta: FrameMetadata,
    data: MultiBuffer,
) -> Result<(), MuxError> {
    let data_len = data.len() as u16;
    // 直序进池化 Buffer（wfx8-3，对齐 Go FrameMetadata.WriteTo(buf.Buffer) 直写
    // 形态）：免每数据帧一次 Vec 分配 + Buffer::from_vec 的二次拷贝。to_bytes
    // 内部的既有分配不在本票范围。
    let meta_bytes = meta.to_bytes().map_err(|e| MuxError::Io(format!("meta: {:?}", e)))?;
    let mut frame = Buffer::new();
    {
        let spare = frame.writable_bytes();
        let n = meta_bytes.len() + 2;
        assert!(n <= spare.len(), "mux meta + length exceeds buffer writable capacity");
        spare[..meta_bytes.len()].copy_from_slice(&meta_bytes);
        spare[meta_bytes.len()..n].copy_from_slice(&data_len.to_be_bytes());
        frame.advance_write(n);
    }
    let mut mb = MultiBuffer::with_capacity(data.buffer_count() + 1);
    mb.push(frame);
    for buf in data.into_buffers() {
        mb.push(buf);
    }
    writer.write_multi_buffer_direct(mb).await.map_err(|e| MuxError::Io(format!("write: {:?}", e)))
}

impl Writer for MuxWriter {
    fn write_multi_buffer<'a>(
        &'a mut self,
        mb: MultiBuffer,
    ) -> Pin<Box<dyn std::future::Future<Output = buf_io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.write(mb).await.map_err(|e| match e {
                MuxError::Io(msg) => buf_io::Error::WriteError(msg),
                other => buf_io::Error::WriteError(format!("{:?}", other)),
            })
        })
    }
}

// ========== 共享写端适配器 ==========

/// 共享写端适配器：多个 [`MuxWriter`] 经由它共写同一底层 writer。
///
/// mux carrier 写端被 worker 的全部 session 复用（Go 中多个 `*Writer`
/// 直接共享同一 `buf.Writer` 指针；Rust 的 `Box<dyn Writer>` 独占所有权，
/// 经此适配器 + `Arc<tokio::sync::Mutex<..>>` 串行化共写）。
pub(crate) struct SharedWriter {
    inner: Arc<tokio::sync::Mutex<Option<Box<dyn Writer>>>>,
}

impl SharedWriter {
    pub(crate) fn new(inner: Arc<tokio::sync::Mutex<Option<Box<dyn Writer>>>>) -> Self {
        Self { inner }
    }
}

impl Writer for SharedWriter {
    fn write_multi_buffer<'a>(
        &'a mut self,
        mb: MultiBuffer,
    ) -> Pin<Box<dyn Future<Output = buf_io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let mut guard = self.inner.lock().await;
            match guard.as_mut() {
                Some(w) => w.write_multi_buffer(mb).await,
                None => Err(buf_io::Error::WriteError("mux carrier writer closed".to_string())),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use xray_buf::io::new_writer;
    use xray_common::net::{address::Address, network::Network, port::Port};

    use super::*;

    fn make_tcp_dest() -> Destination {
        Destination::tcp(Address::Domain("127.0.0.1".to_string()), Port::new(80))
    }

    fn create_mux_writer(tt: TransferType) -> MuxWriter {
        let w = new_writer(Cursor::new(Vec::<u8>::new()));
        MuxWriter::new(1u16, make_tcp_dest(), w, tt, None)
    }

    fn create_response_writer(tt: TransferType) -> MuxWriter {
        let w = new_writer(Cursor::new(Vec::<u8>::new()));
        MuxWriter::new_response_writer(1u16, w, tt)
    }

    #[test]
    fn test_writer_new_initial_state() {
        let w = create_mux_writer(TransferType::Stream);
        assert_eq!(w.id(), 1);
        assert!(!w.is_followup());
        assert!(!w.has_error());
        assert_eq!(w.transfer_type(), TransferType::Stream);
    }

    #[test]
    fn test_response_writer_initial_state() {
        let w = create_response_writer(TransferType::Packet);
        assert!(w.is_followup());
        assert_eq!(w.transfer_type(), TransferType::Packet);
    }

    #[test]
    fn test_get_next_frame_meta_first_is_new() {
        let mut w = create_mux_writer(TransferType::Stream);
        let meta = w.get_next_frame_meta();
        assert_eq!(meta.session_status(), SessionStatus::New);
        assert!(w.is_followup());
    }

    #[test]
    fn test_get_next_frame_meta_subsequent_is_keep() {
        let mut w = create_mux_writer(TransferType::Stream);
        let _ = w.get_next_frame_meta();
        let meta = w.get_next_frame_meta();
        assert_eq!(meta.session_status(), SessionStatus::Keep);
    }

    #[test]
    fn test_response_writer_first_meta_is_keep() {
        let mut w = create_response_writer(TransferType::Stream);
        let meta = w.get_next_frame_meta();
        assert_eq!(meta.session_status(), SessionStatus::Keep);
    }

    #[test]
    fn test_set_error() {
        let mut w = create_mux_writer(TransferType::Stream);
        assert!(!w.has_error());
        w.set_error();
        assert!(w.has_error());
    }

    #[tokio::test]
    async fn test_write_empty_buffer() {
        let mut w = create_mux_writer(TransferType::Stream);
        assert!(w.write(MultiBuffer::new()).await.is_ok());
    }

    #[tokio::test]
    async fn test_write_stream_data() {
        let mut w = create_mux_writer(TransferType::Stream);
        let mut mb = MultiBuffer::new();
        mb.push(Buffer::from_vec(b"hello".to_vec()));
        assert!(w.write(mb).await.is_ok());
    }

    #[tokio::test]
    async fn test_write_packet_data() {
        let mut w = create_mux_writer(TransferType::Packet);
        let mut mb = MultiBuffer::new();
        mb.push(Buffer::from_vec(b"packet".to_vec()));
        assert!(w.write(mb).await.is_ok());
    }

    #[tokio::test]
    async fn test_close_normal() {
        let mut w = create_mux_writer(TransferType::Stream);
        assert!(w.close().await.is_ok());
    }

    #[tokio::test]
    async fn test_close_with_error() {
        let mut w = create_mux_writer(TransferType::Stream);
        w.set_error();
        assert!(w.close().await.is_ok());
    }

    #[test]
    fn test_meta_contains_dest() {
        let mut w = create_mux_writer(TransferType::Stream);
        let meta = w.get_next_frame_meta();
        assert!(meta.target().is_some());
        assert_eq!(meta.target().unwrap().network(), Network::TCP);
    }

    #[test]
    fn test_response_writer_no_dest() {
        let mut w = create_response_writer(TransferType::Stream);
        let meta = w.get_next_frame_meta();
        assert!(meta.target().is_none());
    }

    #[tokio::test]
    async fn test_write_large_stream_splits() {
        let mut w = create_mux_writer(TransferType::Stream);
        let mut mb = MultiBuffer::new();
        mb.push(Buffer::from_vec(vec![0u8; STREAM_CHUNK_SIZE + 100]));
        assert!(w.write(mb).await.is_ok());
    }

    #[tokio::test]
    async fn test_write_multiple_packet_buffers() {
        let mut w = create_mux_writer(TransferType::Packet);
        let mut mb = MultiBuffer::new();
        mb.push(Buffer::from_vec(b"first".to_vec()));
        mb.push(Buffer::from_vec(b"second".to_vec()));
        assert!(w.write(mb).await.is_ok());
    }

    /// bd txhn 回归：共享写端上多个 MuxWriter 并发整帧写入必须帧原子。
    ///
    /// 旧实现帧头经 BufferedWriter 内部缓冲 flush、载荷（> 容量半量）直写，
    /// 两个共享锁临界区之间可被并发会话的完整帧插隔——读端把孤立载荷当
    /// 帧头解析出 `meta_len too large`，整条 carrier 静默死亡、全部子会话
    /// 断流。修后整帧单次落盘（对齐 Go writer.go:71-87），并发下流内帧序
    /// 仍可逐帧解析，载荷不跨会话污染。
    #[tokio::test]
    async fn shared_writer_interleaved_frame_writes_stay_atomic() {
        use std::sync::Arc;

        use tokio::sync::Mutex;
        use xray_buf::{pipe, reader::BufferedReader};

        const SESSIONS: u16 = 2;
        const CHUNKS: usize = 24;
        const CHUNK_LEN: usize = STREAM_CHUNK_SIZE; // > 缓冲半量，走直写分支
        // 各会话独立填充字节：错位时孤儿载荷的前两字节必为 0xA1xx/0xB2xx
        // （> 512），meta_len 合法性断言即刻击穿
        const FILL: [u8; 2] = [0xA1, 0xB2];

        let (raw_r, raw_w) = pipe::new_with_option(xray_buf::pipe::PipeOption {
            limit: 64 * 1024,
            ..Default::default()
        });
        let shared: Arc<Mutex<Option<Box<dyn Writer>>>> =
            Arc::new(Mutex::new(Some(Box::new(raw_w))));
        let mut reader = BufferedReader::new(Box::new(raw_r));

        let mut writers = Vec::new();
        for sid in 1..=SESSIONS {
            let shared = Arc::clone(&shared);
            let fill = FILL[(sid - 1) as usize];
            writers.push(tokio::spawn(async move {
                let mut mw = MuxWriter::new(
                    sid,
                    make_tcp_dest(),
                    Box::new(SharedWriter::new(shared)),
                    TransferType::Stream,
                    None,
                );
                for _ in 0..CHUNKS {
                    let mut mb = MultiBuffer::new();
                    mb.push(Buffer::from_vec(vec![fill; CHUNK_LEN]));
                    mw.write(mb).await.expect("frame write");
                }
            }));
        }

        // 并发解析：帧流量（2×192KB）远超管道上限（64KB），写侧必然在管道
        // 背压点交错挂起——这正是旧实现暴露拆帧窗口的调度形态
        let mut counts = [0usize; (SESSIONS + 1) as usize];
        let mut frames = 0usize;
        let mut head = [0u8; 2];
        // BufferedReader 无 read_exact 原语（client.rs read_frame 同款循环）
        async fn read_exact_local(reader: &mut BufferedReader, dst: &mut [u8]) {
            let mut off = 0;
            while off < dst.len() {
                let n = reader.read(&mut dst[off..]).await;
                assert!(n > 0, "unexpected EOF at offset {off}");
                off += n;
            }
        }
        while frames < SESSIONS as usize * CHUNKS {
            let rd = async {
                let mut off = 0;
                while off < head.len() {
                    let n = reader.read(&mut head[off..]).await;
                    assert!(n > 0, "carrier EOF at frame {frames}");
                    off += n;
                }
            };
            tokio::time::timeout(std::time::Duration::from_secs(30), rd)
                .await
                .expect("frame header read stalled");
            let meta_len = u16::from_be_bytes(head) as usize;
            assert!(
                (4..=512).contains(&meta_len),
                "frame stream desync: bogus meta_len {meta_len} at frame {frames}"
            );
            let mut meta_buf = vec![0u8; meta_len + 2];
            meta_buf[..2].copy_from_slice(&head);
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                read_exact_local(&mut reader, &mut meta_buf[2..]),
            )
            .await
            .expect("meta read stalled");
            let (meta, _) =
                FrameMetadata::read_from_bytes(&meta_buf).expect("parse meta at frame {frames}");
            let sid = meta.session_id();
            assert!((1..=SESSIONS).contains(&sid), "frame stream desync: unknown session {sid}");
            if meta.has_data() {
                let mut len_buf = [0u8; 2];
                tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    read_exact_local(&mut reader, &mut len_buf),
                )
                .await
                .expect("payload len read stalled");
                let payload_len = u16::from_be_bytes(len_buf) as usize;
                assert_eq!(
                    payload_len, CHUNK_LEN,
                    "frame stream desync: payload split at frame {frames}"
                );
                let mut payload = vec![0u8; payload_len];
                tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    read_exact_local(&mut reader, &mut payload),
                )
                .await
                .expect("payload read stalled");
                assert!(
                    payload.iter().all(|&b| b == FILL[(sid - 1) as usize]),
                    "frame stream desync: cross-session payload at frame {frames}"
                );
            }
            counts[sid as usize] += 1;
            frames += 1;
        }
        for t in writers {
            t.await.expect("writer task");
        }
        for sid in 1..=SESSIONS {
            assert_eq!(counts[sid as usize], CHUNKS, "session {sid} frame count");
        }
    }
}
