//! Mux 帧数据读取器
//!
//! 实现 PacketReader 和 StreamReader 用于读取 Mux 协议帧数据

use std::task::Poll;

use xray_buf::{
    buffer::Buffer,
    io::{self as buf_io, Reader},
    multi::MultiBuffer,
    reader::BufferedReader,
};
use xray_common::net::destination::Destination;

use crate::frame::{FrameMetadata, MuxError, SessionStatus};

/// 默认最大数据包大小 (与 xray-buf alloc::DEFAULT_SIZE 一致)
const MAX_PACKET_SIZE: u16 = 8192;

/// PacketReader 读取完整的 Mux 帧数据包
///
/// 每次读取一个完整的帧，包含 u16 长度前缀和实际数据。
/// 对应 Go 源码中的 PacketReader。
pub struct PacketReader {
    reader: BufferedReader,
    eof: bool,
    dest: Option<Destination>,
    /// poll 读状态机阶段（read() 的 poll 形态：2B 长度前缀 → payload 池化 Buffer）
    stage: Option<PacketReadStage>,
}

/// [`PacketReader`] poll 状态机阶段。
enum PacketReadStage {
    /// 读 2B 长度前缀（off = 已读字节数）。
    Len { buf: [u8; 2], off: usize },
    /// 读 payload 进池化 Buffer（size = 目标总长，off = 已写字节数）。
    Payload { data: Buffer, size: usize, off: usize },
}

/// 从 BufferedReader 精确读满 `buf`（调用方栈缓冲直读，无中间分配）。
async fn read_exact_slice(reader: &mut BufferedReader, buf: &mut [u8]) -> Result<(), MuxError> {
    let mut off = 0;
    while off < buf.len() {
        let n = reader.read(&mut buf[off..]).await;
        if n == 0 {
            return Err(MuxError::Io("unexpected EOF".to_string()));
        }
        off += n;
    }
    Ok(())
}

/// 精确读取 n 字节追加进池化 Buffer 可写区。
///
/// 对齐 Go frame.go:126 `ReadFullFrom` 原地读形态：wire → 池化 Buffer，
/// 零中间 Vec、零二次拷贝。
async fn read_exact_into(
    reader: &mut BufferedReader,
    dst: &mut Buffer,
    n: usize,
) -> Result<(), MuxError> {
    let mut remaining = n;
    while remaining > 0 {
        let read_n = {
            let spare = dst.writable_bytes();
            if remaining > spare.len() {
                return Err(MuxError::Io(format!("read {} exceeds buffer capacity", n)));
            }
            reader.read(&mut spare[..remaining]).await
        };
        if read_n == 0 {
            return Err(MuxError::Io("unexpected EOF".to_string()));
        }
        dst.advance_write(read_n);
        remaining -= read_n;
    }
    Ok(())
}

impl PacketReader {
    /// 创建新的 PacketReader
    pub fn new(reader: Box<dyn Reader>, dest: Option<Destination>) -> Self {
        Self { reader: BufferedReader::new(reader), eof: false, dest, stage: None }
    }

    /// 读取一个完整的数据包
    pub async fn read(&mut self) -> Result<MultiBuffer, MuxError> {
        if self.eof {
            return Err(MuxError::Io("EOF".to_string()));
        }
        let mut len_buf = [0u8; 2];
        read_exact_slice(&mut self.reader, &mut len_buf).await?;
        let size = u16::from_be_bytes(len_buf);
        if size > MAX_PACKET_SIZE {
            return Err(MuxError::Io(format!("packet size too large: {}", size)));
        }
        // payload 直读进池化 Buffer（对齐 Go reader.go 池化单读）
        let mut data = Buffer::new();
        read_exact_into(&mut self.reader, &mut data, size as usize).await?;
        self.eof = true;
        let mut mb = MultiBuffer::new();
        mb.push(data);
        Ok(mb)
    }

    pub fn is_eof(&self) -> bool {
        self.eof
    }

    pub fn destination(&self) -> Option<&Destination> {
        self.dest.as_ref()
    }
}

/// StreamReader 读取流式 Mux 帧数据
pub struct StreamReader {
    reader: BufferedReader,
    current_frame: Option<FrameData>,
    session_id: u16,
    /// poll 读状态机阶段（read_next_frame 的 poll 形态拆解）。
    stage: Option<StreamReadStage>,
}

/// [`StreamReader`] poll 状态机阶段（read_next_frame 的分阶段拆解）。
enum StreamReadStage {
    /// 读 2B meta 长度前缀。
    Len2 { buf: [u8; 2], off: usize },
    /// meta 板：len 前缀已写 2B，补读 meta_len。
    Meta { board: Buffer, meta_len: usize },
    /// meta 已解析：分流 session 匹配 / has_data。
    AfterMeta { metadata: FrameMetadata },
    /// session 不匹配：读 2B 尺寸前缀（准备丢弃）。
    SkipLen2 { metadata: FrameMetadata, buf: [u8; 2], off: usize },
    /// session 不匹配：丢弃数据体。
    Discard { buf: Buffer, size: usize, off: usize },
    /// 读 2B payload 尺寸前缀。
    DataLen2 { metadata: FrameMetadata, buf: [u8; 2], off: usize },
    /// 读 payload。
    Payload { metadata: FrameMetadata, data: Buffer, size: usize, off: usize },
    /// 帧读取完成：套用 read() 帧后处理（End/空帧判定）。
    FrameComplete { metadata: FrameMetadata, data: Buffer },
}

struct FrameData {
    metadata: FrameMetadata,
    data: Buffer,
}

impl StreamReader {
    pub fn new(reader: BufferedReader, session_id: u16) -> Self {
        Self { reader, current_frame: None, session_id, stage: None }
    }

    pub fn from_reader(reader: Box<dyn Reader>, session_id: u16) -> Self {
        Self::new(BufferedReader::new(reader), session_id)
    }

    /// 读取下一个帧
    async fn read_next_frame(&mut self) -> Result<Option<FrameData>, MuxError> {
        // 读取 length 前缀 (2 bytes)
        let mut len_buf = [0u8; 2];
        read_exact_slice(&mut self.reader, &mut len_buf).await?;
        let meta_len = u16::from_be_bytes(len_buf) as usize;
        if meta_len > 1024 {
            return Err(MuxError::MetadataTooLong(meta_len));
        }
        // length 前缀 + meta 单板顺序读入后原地解析（Go frame.go:126 池化
        // board；read_from_bytes 需 length 前缀，board.bytes() 天然满足，免
        // concat Vec）
        let mut board = Buffer::new();
        board.write_from(&len_buf);
        read_exact_into(&mut self.reader, &mut board, meta_len).await?;
        let (metadata, _consumed) = FrameMetadata::read_from_bytes(board.bytes())
            .map_err(|e| MuxError::Io(format!("parse meta: {:?}", e)))?;

        if metadata.session_id() != self.session_id {
            if metadata.has_data() {
                let mut size_buf = [0u8; 2];
                read_exact_slice(&mut self.reader, &mut size_buf).await?;
                let size = u16::from_be_bytes(size_buf) as usize;
                let mut discard = Buffer::new();
                read_exact_into(&mut self.reader, &mut discard, size).await?;
            }
            return Ok(None);
        }

        // payload 直读进池化 Buffer，免中间 Vec 与出口二次拷贝
        let data = if metadata.has_data() {
            let mut size_buf = [0u8; 2];
            read_exact_slice(&mut self.reader, &mut size_buf).await?;
            let size = u16::from_be_bytes(size_buf) as usize;
            let mut payload = Buffer::new();
            read_exact_into(&mut self.reader, &mut payload, size).await?;
            payload
        } else {
            Buffer::with_capacity(0)
        };

        Ok(Some(FrameData { metadata, data }))
    }

    /// 读取数据到 MultiBuffer
    pub async fn read(&mut self) -> Result<MultiBuffer, MuxError> {
        loop {
            if let Some(frame) = self.current_frame.as_mut() {
                if !frame.data.is_empty() {
                    // 整帧 payload 所有权转移（池化 Buffer 直出，零拷贝）
                    let mut mb = MultiBuffer::new();
                    mb.push(std::mem::replace(&mut frame.data, Buffer::with_capacity(0)));
                    return Ok(mb);
                }
                let is_end = frame.metadata.session_status() == SessionStatus::End;
                self.current_frame = None;
                if is_end {
                    return Err(MuxError::Io("session ended".to_string()));
                }
                continue;
            }
            match self.read_next_frame().await? {
                Some(frame) => {
                    let is_end = frame.metadata.session_status() == SessionStatus::End;
                    let is_empty = frame.data.is_empty();
                    if is_end && is_empty {
                        return Err(MuxError::Io("session ended".to_string()));
                    }
                    if is_empty && !is_end {
                        continue;
                    }
                    self.current_frame = Some(frame);
                },
                None => continue,
            }
        }
    }

    pub fn session_id(&self) -> u16 {
        self.session_id
    }
}

/// MuxError → buf_io 错误（与旧 boxed-future 形态的映射逐字一致）。
fn map_mux_read_err(e: MuxError) -> buf_io::Error {
    match e {
        MuxError::Io(msg) => buf_io::Error::ReadError(msg),
        other => buf_io::Error::ReadError(format!("{other:?}")),
    }
}

/// 从 BufferedReader poll 精确补读，填满 `buf[off..]`。
/// Pending 时调用方保存 `(buf, off)` 进状态机。
fn poll_exact_slice(
    reader: &mut BufferedReader,
    cx: &mut std::task::Context<'_>,
    buf: &mut [u8],
    off: &mut usize,
) -> Poll<Result<(), MuxError>> {
    while *off < buf.len() {
        match reader.poll_read(&mut buf[*off..], cx) {
            std::task::Poll::Ready(0) => {
                return Poll::Ready(Err(MuxError::Io("unexpected EOF".into())));
            },
            std::task::Poll::Ready(n) => *off += n,
            std::task::Poll::Pending => return std::task::Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
}

/// 从 BufferedReader poll 精确补读 `size - off` 字节进池化 `dst`（已写 off）。
/// Pending 时调用方保存 `(dst, off)` 进状态机（对齐 read_exact_into）。
fn poll_exact_into(
    reader: &mut BufferedReader,
    cx: &mut std::task::Context<'_>,
    dst: &mut Buffer,
    size: usize,
    off: &mut usize,
) -> Poll<Result<(), MuxError>> {
    while *off < size {
        let want = size - *off;
        let n = {
            let spare = dst.writable_bytes();
            if want > spare.len() {
                return Poll::Ready(Err(MuxError::Io(format!(
                    "read {size} exceeds buffer capacity"
                ))));
            }
            match reader.poll_read(&mut spare[..want], cx) {
                std::task::Poll::Ready(n) => n,
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        };
        if n == 0 {
            return Poll::Ready(Err(MuxError::Io("unexpected EOF".into())));
        }
        dst.advance_write(n);
        *off += n;
    }
    Poll::Ready(Ok(()))
}

impl Reader for PacketReader {
    fn poll_read_multi_buffer(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<buf_io::Result<MultiBuffer>> {
        if self.eof {
            return Poll::Ready(Err(buf_io::Error::ReadError("EOF".to_string())));
        }
        loop {
            match self.stage.take() {
                None => self.stage = Some(PacketReadStage::Len { buf: [0u8; 2], off: 0 }),
                Some(PacketReadStage::Len { mut buf, mut off }) => {
                    match poll_exact_slice(&mut self.reader, cx, &mut buf, &mut off) {
                        std::task::Poll::Pending => {
                            self.stage = Some(PacketReadStage::Len { buf, off });
                            return std::task::Poll::Pending;
                        },
                        std::task::Poll::Ready(Err(e)) => {
                            return std::task::Poll::Ready(Err(map_mux_read_err(e)));
                        },
                        std::task::Poll::Ready(Ok(())) => {},
                    }
                    let size = u16::from_be_bytes(buf);
                    if size > MAX_PACKET_SIZE {
                        return std::task::Poll::Ready(Err(map_mux_read_err(MuxError::Io(
                            format!("packet size too large: {size}"),
                        ))));
                    }
                    self.stage = Some(PacketReadStage::Payload {
                        data: Buffer::new(),
                        size: size as usize,
                        off: 0,
                    });
                },
                Some(PacketReadStage::Payload { mut data, size, mut off }) => {
                    match poll_exact_into(&mut self.reader, cx, &mut data, size, &mut off) {
                        std::task::Poll::Pending => {
                            self.stage = Some(PacketReadStage::Payload { data, size, off });
                            return std::task::Poll::Pending;
                        },
                        std::task::Poll::Ready(Err(e)) => {
                            return std::task::Poll::Ready(Err(map_mux_read_err(e)));
                        },
                        std::task::Poll::Ready(Ok(())) => {},
                    }
                    self.eof = true;
                    let mut mb = MultiBuffer::new();
                    mb.push(data);
                    return std::task::Poll::Ready(Ok(mb));
                },
            }
        }
    }
}

impl Reader for StreamReader {
    fn poll_read_multi_buffer(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<buf_io::Result<MultiBuffer>> {
        loop {
            // 1. 现有帧交付（同步，read() 语义）
            if let Some(frame) = self.current_frame.as_mut() {
                if !frame.data.is_empty() {
                    let mut mb = MultiBuffer::new();
                    mb.push(std::mem::replace(&mut frame.data, Buffer::with_capacity(0)));
                    return std::task::Poll::Ready(Ok(mb));
                }
                let is_end = frame.metadata.session_status() == SessionStatus::End;
                self.current_frame = None;
                if is_end {
                    return std::task::Poll::Ready(Err(buf_io::Error::ReadError(
                        "session ended".to_string(),
                    )));
                }
                continue;
            }
            // 2. 帧读取状态机（read_next_frame 的 poll 拆解）
            match self.stage.take() {
                None => self.stage = Some(StreamReadStage::Len2 { buf: [0u8; 2], off: 0 }),
                Some(StreamReadStage::Len2 { mut buf, mut off }) => {
                    match poll_exact_slice(&mut self.reader, cx, &mut buf, &mut off) {
                        std::task::Poll::Pending => {
                            self.stage = Some(StreamReadStage::Len2 { buf, off });
                            return std::task::Poll::Pending;
                        },
                        std::task::Poll::Ready(Err(e)) => {
                            return std::task::Poll::Ready(Err(map_mux_read_err(e)));
                        },
                        std::task::Poll::Ready(Ok(())) => {},
                    }
                    let meta_len = u16::from_be_bytes(buf) as usize;
                    if meta_len > 1024 {
                        return std::task::Poll::Ready(Err(map_mux_read_err(
                            MuxError::MetadataTooLong(meta_len),
                        )));
                    }
                    let mut board = Buffer::new();
                    board.write_from(&buf);
                    self.stage = Some(StreamReadStage::Meta { board, meta_len });
                },
                Some(StreamReadStage::Meta { mut board, meta_len }) => {
                    let mut off = board.len();
                    match poll_exact_into(&mut self.reader, cx, &mut board, meta_len + 2, &mut off)
                    {
                        std::task::Poll::Pending => {
                            self.stage = Some(StreamReadStage::Meta { board, meta_len });
                            return std::task::Poll::Pending;
                        },
                        std::task::Poll::Ready(Err(e)) => {
                            return std::task::Poll::Ready(Err(map_mux_read_err(e)));
                        },
                        std::task::Poll::Ready(Ok(())) => {},
                    }
                    let metadata = match FrameMetadata::read_from_bytes(board.bytes()) {
                        Ok((m, _)) => m,
                        Err(e) => {
                            return std::task::Poll::Ready(Err(map_mux_read_err(MuxError::Io(
                                format!("parse meta: {e:?}"),
                            ))));
                        },
                    };
                    self.stage = Some(StreamReadStage::AfterMeta { metadata });
                },
                Some(StreamReadStage::AfterMeta { metadata }) => {
                    if metadata.session_id() != self.session_id {
                        if metadata.has_data() {
                            self.stage =
                                Some(StreamReadStage::SkipLen2 { metadata, buf: [0u8; 2], off: 0 });
                        } else {
                            // None：read() 语义 = 继续下一帧
                            self.stage = None;
                        }
                    } else if metadata.has_data() {
                        self.stage =
                            Some(StreamReadStage::DataLen2 { metadata, buf: [0u8; 2], off: 0 });
                    } else {
                        // 空数据帧直接完成（read() 帧后处理）
                        self.stage = Some(StreamReadStage::FrameComplete {
                            metadata,
                            data: Buffer::with_capacity(0),
                        });
                    }
                },
                Some(StreamReadStage::SkipLen2 { metadata, mut buf, mut off }) => {
                    match poll_exact_slice(&mut self.reader, cx, &mut buf, &mut off) {
                        std::task::Poll::Pending => {
                            self.stage = Some(StreamReadStage::SkipLen2 { metadata, buf, off });
                            return std::task::Poll::Pending;
                        },
                        std::task::Poll::Ready(Err(e)) => {
                            return std::task::Poll::Ready(Err(map_mux_read_err(e)));
                        },
                        std::task::Poll::Ready(Ok(())) => {},
                    }
                    let size = u16::from_be_bytes(buf) as usize;
                    self.stage =
                        Some(StreamReadStage::Discard { buf: Buffer::new(), size, off: 0 });
                    drop(metadata);
                },
                Some(StreamReadStage::Discard { mut buf, size, mut off }) => {
                    match poll_exact_into(&mut self.reader, cx, &mut buf, size, &mut off) {
                        std::task::Poll::Pending => {
                            self.stage = Some(StreamReadStage::Discard { buf, size, off });
                            return std::task::Poll::Pending;
                        },
                        std::task::Poll::Ready(Err(e)) => {
                            return std::task::Poll::Ready(Err(map_mux_read_err(e)));
                        },
                        std::task::Poll::Ready(Ok(())) => {},
                    }
                    // 丢弃完成 → None：继续下一帧
                    self.stage = None;
                },
                Some(StreamReadStage::DataLen2 { metadata, mut buf, mut off }) => {
                    match poll_exact_slice(&mut self.reader, cx, &mut buf, &mut off) {
                        std::task::Poll::Pending => {
                            self.stage = Some(StreamReadStage::DataLen2 { metadata, buf, off });
                            return std::task::Poll::Pending;
                        },
                        std::task::Poll::Ready(Err(e)) => {
                            return std::task::Poll::Ready(Err(map_mux_read_err(e)));
                        },
                        std::task::Poll::Ready(Ok(())) => {},
                    }
                    let size = u16::from_be_bytes(buf) as usize;
                    self.stage = Some(StreamReadStage::Payload {
                        metadata,
                        data: Buffer::new(),
                        size,
                        off: 0,
                    });
                },
                Some(StreamReadStage::Payload { metadata, mut data, size, mut off }) => {
                    match poll_exact_into(&mut self.reader, cx, &mut data, size, &mut off) {
                        std::task::Poll::Pending => {
                            self.stage =
                                Some(StreamReadStage::Payload { metadata, data, size, off });
                            return std::task::Poll::Pending;
                        },
                        std::task::Poll::Ready(Err(e)) => {
                            return std::task::Poll::Ready(Err(map_mux_read_err(e)));
                        },
                        std::task::Poll::Ready(Ok(())) => {},
                    }
                    self.stage = Some(StreamReadStage::FrameComplete { metadata, data });
                },
                Some(StreamReadStage::FrameComplete { metadata, data }) => {
                    // read() 帧后处理：End+空 → Err；空非 End → 继续读；否则入列
                    let is_end = metadata.session_status() == SessionStatus::End;
                    let is_empty = data.is_empty();
                    self.stage = None;
                    if is_end && is_empty {
                        return std::task::Poll::Ready(Err(buf_io::Error::ReadError(
                            "session ended".to_string(),
                        )));
                    }
                    if is_empty && !is_end {
                        continue;
                    }
                    self.current_frame = Some(FrameData { metadata, data });
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use xray_common::{
        net::{address::Address, network::Network, port::Port},
        serial::write_uint16,
    };

    use super::*;

    fn create_test_reader(data: Vec<u8>) -> Box<dyn Reader> {
        buf_io::new_reader(Cursor::new(data))
    }

    fn make_tcp_dest() -> Destination {
        Destination::tcp(Address::Domain("127.0.0.1".to_string()), Port::new(80))
    }

    fn make_udp_dest() -> Destination {
        Destination::udp(Address::Domain("127.0.0.1".to_string()), Port::new(8080))
    }

    #[tokio::test]
    async fn test_packet_reader_basic() {
        let data = b"hello";
        let mut buf = Vec::new();
        buf.extend_from_slice(&write_uint16(data.len() as u16));
        buf.extend_from_slice(data);
        let mut pr = PacketReader::new(create_test_reader(buf), None);
        let result = pr.read().await.unwrap();
        assert_eq!(result.to_vec(), b"hello");
    }

    #[tokio::test]
    async fn test_packet_reader_eof_on_empty() {
        let mut pr = PacketReader::new(create_test_reader(vec![]), None);
        assert!(pr.read().await.is_err());
    }

    #[tokio::test]
    async fn test_packet_reader_eof_after_first_read() {
        let data = b"test";
        let mut buf = Vec::new();
        buf.extend_from_slice(&write_uint16(data.len() as u16));
        buf.extend_from_slice(data);
        let mut pr = PacketReader::new(create_test_reader(buf), None);
        let _ = pr.read().await.unwrap();
        assert!(pr.is_eof());
        assert!(pr.read().await.is_err());
    }

    #[tokio::test]
    async fn test_packet_reader_with_udp_dest() {
        let data = b"udp data";
        let mut buf = Vec::new();
        buf.extend_from_slice(&write_uint16(data.len() as u16));
        buf.extend_from_slice(data);
        let mut pr = PacketReader::new(create_test_reader(buf), Some(make_udp_dest()));
        assert_eq!(pr.destination().unwrap().network(), Network::UDP);
        let result = pr.read().await.unwrap();
        assert_eq!(result.to_vec(), b"udp data");
    }

    #[tokio::test]
    async fn test_packet_reader_empty_data() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&write_uint16(0));
        let mut pr = PacketReader::new(create_test_reader(buf), None);
        let result = pr.read().await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_packet_reader_max_size() {
        let data = vec![0u8; MAX_PACKET_SIZE as usize];
        let mut buf = Vec::new();
        buf.extend_from_slice(&write_uint16(MAX_PACKET_SIZE));
        buf.extend_from_slice(&data);
        let mut pr = PacketReader::new(create_test_reader(buf), None);
        let result = pr.read().await.unwrap();
        assert_eq!(result.len(), MAX_PACKET_SIZE as usize);
    }

    #[tokio::test]
    async fn test_packet_reader_oversized() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&write_uint16(MAX_PACKET_SIZE + 1));
        let mut pr = PacketReader::new(create_test_reader(buf), None);
        assert!(pr.read().await.is_err());
    }

    #[tokio::test]
    async fn test_packet_reader_truncated_length() {
        let mut pr = PacketReader::new(create_test_reader(vec![0x00]), None);
        assert!(pr.read().await.is_err());
    }

    #[tokio::test]
    async fn test_packet_reader_truncated_data() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&write_uint16(10));
        buf.extend_from_slice(b"hello");
        let mut pr = PacketReader::new(create_test_reader(buf), None);
        assert!(pr.read().await.is_err());
    }

    #[tokio::test]
    async fn test_packet_reader_new_with_cursor() {
        let data = b"hello";
        let mut buf = Vec::new();
        buf.extend_from_slice(&write_uint16(data.len() as u16));
        buf.extend_from_slice(data);
        let mut pr = PacketReader::new(buf_io::new_reader(Cursor::new(buf)), None);
        let result = pr.read().await.unwrap();
        assert_eq!(result.to_vec(), b"hello");
    }

    #[tokio::test]
    async fn test_stream_reader_basic() {
        let sid = 1u16;
        let metadata = FrameMetadata::new_session(sid, make_tcp_dest());
        let data = b"stream data";
        let mut buf = Vec::new();
        metadata.write_to(&mut buf).unwrap();
        buf.extend_from_slice(&write_uint16(data.len() as u16));
        buf.extend_from_slice(data);
        let mut sr = StreamReader::from_reader(create_test_reader(buf), sid);
        let result = sr.read().await.unwrap();
        assert_eq!(result.to_vec(), b"stream data");
    }

    #[tokio::test]
    async fn test_stream_reader_payload_direct_into_pool_buffer() {
        // P1-1 直读路径指纹：payload 必须落在池化 8KB 层 Buffer。旧实现出口
        // Buffer::with_capacity(payload_len) 容量恒等于 payload 长度（绕池）。
        let sid = 7u16;
        let metadata = FrameMetadata::new_session(sid, make_tcp_dest());
        let data = vec![0xA5u8; 4096];
        let mut buf = Vec::new();
        metadata.write_to(&mut buf).unwrap();
        buf.extend_from_slice(&write_uint16(data.len() as u16));
        buf.extend_from_slice(&data);
        let mut sr = StreamReader::from_reader(create_test_reader(buf), sid);
        let result = sr.read().await.unwrap();
        assert_eq!(result.to_vec(), data);
        let buffers = result.into_buffers();
        assert_eq!(buffers.len(), 1);
        assert_eq!(
            buffers[0].capacity(),
            8192,
            "payload 必须直接落池化 8KB 层（wire→池化 Buffer 零中间 Vec）"
        );
    }

    #[tokio::test]
    async fn test_stream_reader_end_frame() {
        let sid = 1u16;
        let end_meta = FrameMetadata::end_session(sid);
        let mut buf = Vec::new();
        end_meta.write_to(&mut buf).unwrap();
        let mut sr = StreamReader::from_reader(create_test_reader(buf), sid);
        assert!(sr.read().await.is_err());
    }

    #[tokio::test]
    async fn test_stream_reader_wrong_session() {
        let metadata = FrameMetadata::new_session(1u16, make_tcp_dest());
        let data = b"wrong";
        let mut buf = Vec::new();
        metadata.write_to(&mut buf).unwrap();
        buf.extend_from_slice(&write_uint16(data.len() as u16));
        buf.extend_from_slice(data);
        let mut sr = StreamReader::from_reader(create_test_reader(buf), 999u16);
        assert!(sr.read().await.is_err());
    }

    #[test]
    fn test_stream_reader_session_id() {
        let sr = StreamReader::from_reader(create_test_reader(vec![]), 42u16);
        assert_eq!(sr.session_id(), 42);
    }
}
