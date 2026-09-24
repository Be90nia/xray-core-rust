//! Mux 帧数据读取器
//!
//! 实现 PacketReader 和 StreamReader 用于读取 Mux 协议帧数据

use std::pin::Pin;

use xray_buf::buffer::Buffer;
use xray_buf::multi::MultiBuffer;
use xray_buf::reader::BufferedReader;
use xray_buf::io::{self as buf_io, Reader};
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
        Self { reader: BufferedReader::new(reader), eof: false, dest }
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

    pub fn is_eof(&self) -> bool { self.eof }
    pub fn destination(&self) -> Option<&Destination> { self.dest.as_ref() }
}

/// StreamReader 读取流式 Mux 帧数据
pub struct StreamReader {
    reader: BufferedReader,
    current_frame: Option<FrameData>,
    session_id: u16,
}

struct FrameData {
    metadata: FrameMetadata,
    data: Buffer,
}

impl StreamReader {
    pub fn new(reader: BufferedReader, session_id: u16) -> Self {
        Self { reader, current_frame: None, session_id }
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
                    if is_empty && !is_end { continue; }
                    self.current_frame = Some(frame);
                }
                None => continue,
            }
        }
    }

    pub fn session_id(&self) -> u16 { self.session_id }
}

impl Reader for PacketReader {
    fn read_multi_buffer<'a>(&'a mut self) -> Pin<Box<dyn std::future::Future<Output = buf_io::Result<MultiBuffer>> + Send + 'a>> {
        Box::pin(async move {
            self.read().await.map_err(|e| match e {
                MuxError::Io(msg) => buf_io::Error::ReadError(msg),
                other => buf_io::Error::ReadError(format!("{:?}", other)),
            })
        })
    }
}

impl Reader for StreamReader {
    fn read_multi_buffer<'a>(&'a mut self) -> Pin<Box<dyn std::future::Future<Output = buf_io::Result<MultiBuffer>> + Send + 'a>> {
        Box::pin(async move {
            self.read().await.map_err(|e| match e {
                MuxError::Io(msg) => buf_io::Error::ReadError(msg),
                other => buf_io::Error::ReadError(format!("{:?}", other)),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use xray_common::net::address::Address;
    use xray_common::net::network::Network;
    use xray_common::net::port::Port;
    use xray_common::serial::write_uint16;

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